"""Trusted control-account updater bootstrap.

The root provisioning boundary supplies one authenticated operator context and
the exact release transport on stdin.  This module is intentionally usable
only from the fixed ``stateport-control`` account in production: it performs
release verification and updater genesis, but never starts a host service or
invokes Podman/systemd.
"""

from __future__ import annotations

import base64
import binascii
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import Any, Mapping

from stateport_release import (
    CosignVerifier,
    PinnedPublicKeyIdentity,
    ReleaseContractError,
    ReleaseVerificationPolicy,
    SUPPORTED_TARGET_IDS,
    canonical_digest,
    canonical_json_bytes,
    embedded_predecessor_index,
    load_release_index,
    to_updater_release_envelope,
    verify_release_index,
)
from stateport_release.execution_host_provisioning import (
    ROOT_COSIGN_PATH,
    ROOT_PUBLIC_KEY_PATH,
    ROOT_TRUST_KEY_FINGERPRINT,
    ROOT_TRUST_KEY_ID,
)

from .engine import UPDATER_VERSION
from .genesis import initialize_installed_updater, validate_genesis_replay
from .models import UPDATE_CHANNELS, UpdatePolicy
from .safe_io import (
    SafeIOError,
    _bounded,
    create_bytes,
    create_json,
    ensure_private_directory,
    read_bytes,
    read_json,
)
from .store import StoreError, UpdateStore


REQUEST_SCHEMA = "stateport.control-updater-bootstrap/v1"
RESULT_SCHEMA = "stateport.control-updater-genesis/v1"
ERROR_SCHEMA = "stateport.control-updater-error/v1"
CONTROL_UID = 65531
CONTROL_GID = 65531
CONTROL_STATE_ROOT = Path("/var/lib/stateport-control/updater")
BOOTSTRAP_COSIGN_PATH = Path(ROOT_COSIGN_PATH)
BOOTSTRAP_PUBLIC_KEY_PATH = Path(ROOT_PUBLIC_KEY_PATH)
INSTALLER_ORIGIN = "https://stateport.invalid/installer/no-checkout"
INSTALLER_VERSION = "0.1.0"
OPERATOR_SCHEMA = "stateport.control-updater-operator/v1"
MAX_REQUEST_BYTES = 64 * 1024 * 1024
MAX_BUNDLES = 256
MAX_IMAGE_MANIFESTS = 128
MAX_IMAGE_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_BUNDLE_BYTES = 4 * 1024 * 1024
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}\Z")
_USER = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}\Z")


class BootstrapRefusal(ValueError):
    """A typed, non-disclosing bootstrap refusal."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _refuse(message: str, code: str = "bootstrap_request_invalid") -> BootstrapRefusal:
    return BootstrapRefusal(code, message)


def _mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise _refuse(f"{label} is not an object")
    return dict(value)


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise _refuse(f"{label} is not a digest")
    return value


def _decode_base64(value: object, *, label: str, maximum: int) -> bytes:
    if not isinstance(value, str) or not value:
        raise _refuse(f"{label} is missing")
    try:
        content = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise _refuse(f"{label} is not valid base64") from exc
    if not content or len(content) > maximum:
        raise _refuse(f"{label} exceeds its bounded size")
    return content


def _operator(value: object) -> dict[str, Any]:
    operator = _mapping(value, "operator")
    if set(operator) != {"user", "uid", "gid"}:
        raise _refuse("operator has an unexpected shape")
    user = operator["user"]
    uid, gid = operator["uid"], operator["gid"]
    if (
        not isinstance(user, str)
        or _USER.fullmatch(user) is None
        or isinstance(uid, bool)
        or not isinstance(uid, int)
        or uid <= 0
        or isinstance(gid, bool)
        or not isinstance(gid, int)
        or gid <= 0
        or uid == CONTROL_UID
        or gid == CONTROL_GID
    ):
        raise _refuse("operator identity is unsupported")
    return {"user": user, "uid": uid, "gid": gid}


def _request(raw: object) -> dict[str, Any]:
    request = _mapping(raw, "bootstrap request")
    expected = {
        "schema",
        "releaseIndex",
        "expectedIndexDigest",
        "expectedSignedPayloadDigest",
        "channel",
        "targetId",
        "actorId",
        "operator",
        "bundles",
        "imageManifests",
    }
    if set(request) != expected or request["schema"] != REQUEST_SCHEMA:
        raise _refuse("bootstrap request has an unexpected shape")
    _digest(request["expectedIndexDigest"], "expected index digest")
    _digest(request["expectedSignedPayloadDigest"], "expected signed payload digest")
    channel = request["channel"]
    if channel not in UPDATE_CHANNELS:
        raise _refuse("bootstrap channel is unsupported")
    if not isinstance(request["targetId"], str) or request["targetId"] not in SUPPORTED_TARGET_IDS:
        raise _refuse("bootstrap target is unsupported")
    if not isinstance(request["actorId"], str) or not 1 <= len(request["actorId"]) <= 128:
        raise _refuse("bootstrap actor is invalid")
    _operator(request["operator"])
    _bounded(request, label="bootstrap request")
    if not isinstance(request["releaseIndex"], Mapping):
        raise _refuse("release index is not an object")
    bundles = request["bundles"]
    if not isinstance(bundles, list) or not bundles or len(bundles) > MAX_BUNDLES:
        raise _refuse("bootstrap signature bundle inventory is invalid")
    for item in bundles:
        entry = _mapping(item, "signature bundle")
        if set(entry) != {"signature", "contentBase64"} or not isinstance(
            entry["signature"], Mapping
        ):
            raise _refuse("signature bundle entry is malformed")
        _decode_base64(entry["contentBase64"], label="signature bundle", maximum=MAX_BUNDLE_BYTES)
    manifests = request["imageManifests"]
    if not isinstance(manifests, list) or len(manifests) > MAX_IMAGE_MANIFESTS:
        raise _refuse("bootstrap image manifest inventory is invalid")
    for item in manifests:
        entry = _mapping(item, "image manifest")
        if set(entry) != {"imageId", "digest", "contentBase64"}:
            raise _refuse("image manifest entry is malformed")
        if not isinstance(entry["imageId"], str) or not entry["imageId"]:
            raise _refuse("image manifest image ID is invalid")
        _digest(entry["digest"], "image manifest digest")
        _decode_base64(
            entry["contentBase64"],
            label="image manifest",
            maximum=MAX_IMAGE_MANIFEST_BYTES,
        )
    return request


def _read_fixed_file(path: Path, *, label: str, maximum: int) -> bytes:
    try:
        observed = path.lstat()
    except OSError as exc:
        raise _refuse(f"{label} is unavailable", "bootstrap_trust_unavailable") from exc
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISREG(observed.st_mode)
        or observed.st_uid != 0
        or observed.st_gid != 0
        or stat.S_IMODE(observed.st_mode) & 0o022
        or observed.st_size > maximum
    ):
        raise _refuse(f"{label} is not a fixed trusted file", "bootstrap_trust_unavailable")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise _refuse(f"{label} could not be read", "bootstrap_trust_unavailable") from exc


def _expected_signatures(index: Any, predecessor: Any | None) -> dict[str, Mapping[str, Any]]:
    values: list[Mapping[str, Any]] = list(index.document["signatures"])
    for image in index.document["signed"]["images"]:
        values.append(image["signature"])
    if predecessor is not None:
        values.extend(predecessor.document["signatures"])
    result: dict[str, Mapping[str, Any]] = {}
    for signature in values:
        bundle = signature.get("bundle") if isinstance(signature, Mapping) else None
        digest = bundle.get("digest") if isinstance(bundle, Mapping) else None
        if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None or digest in result:
            raise _refuse("release signature bundle inventory is ambiguous", "bootstrap_release_invalid")
        result[digest] = signature
    return result


def _stage_inputs(request: Mapping[str, Any], index: Any, predecessor: Any | None, root: Path) -> tuple[Path, dict[str, bytes], dict[str, Mapping[str, Any]]]:
    expected = _expected_signatures(index, predecessor)
    temporary = root / "transport"
    temporary.mkdir(mode=0o700)
    source_by_digest: dict[str, Path] = {}
    for item in request["bundles"]:
        entry = dict(item)
        signature = dict(entry["signature"])
        bundle = signature.get("bundle")
        bundle_digest = bundle.get("digest") if isinstance(bundle, Mapping) else None
        if bundle_digest not in expected or signature != dict(expected[bundle_digest]):
            raise _refuse("bootstrap bundle is not named by the verified release", "bootstrap_release_invalid")
        if bundle_digest in source_by_digest:
            raise _refuse("bootstrap bundle is duplicated", "bootstrap_release_invalid")
        content = _decode_base64(entry["contentBase64"], label="signature bundle", maximum=MAX_BUNDLE_BYTES)
        if "sha256:" + hashlib.sha256(content).hexdigest() != bundle_digest or len(content) != bundle.get("size"):
            raise _refuse("bootstrap bundle digest or size differs", "bootstrap_release_invalid")
        path = temporary / f"bundle-{bundle_digest.removeprefix('sha256:')}.sigstore.json"
        path.write_bytes(content)
        path.chmod(0o600)
        source_by_digest[bundle_digest] = path
    if set(source_by_digest) != set(expected):
        raise _refuse("bootstrap bundle inventory is incomplete", "bootstrap_release_invalid")

    expected_images = {
        str(image["imageId"]): image
        for image in index.document["signed"]["images"]
        if image["signature"].get("subjectKind") == "oci-manifest-blob"
    }
    payloads: dict[str, bytes] = {}
    seen_images: set[str] = set()
    manifest_root = temporary / "image-manifests"
    manifest_root.mkdir(mode=0o700)
    for item in request["imageManifests"]:
        entry = dict(item)
        image_id = entry["imageId"]
        image = expected_images.get(image_id)
        content = _decode_base64(entry["contentBase64"], label="image manifest", maximum=MAX_IMAGE_MANIFEST_BYTES)
        if image is None or image_id in seen_images or entry["digest"] != image["signature"]["subjectDigest"]:
            raise _refuse("bootstrap image manifest is not release-bound", "bootstrap_release_invalid")
        if "sha256:" + hashlib.sha256(content).hexdigest() != entry["digest"]:
            raise _refuse("bootstrap image manifest digest differs", "bootstrap_release_invalid")
        seen_images.add(image_id)
        payloads[image_id] = content
        (manifest_root / f"{entry['digest'].removeprefix('sha256:')}.json").write_bytes(content)
    if seen_images != set(expected_images):
        raise _refuse("bootstrap image manifest inventory is incomplete", "bootstrap_release_invalid")
    return temporary, payloads, expected


def _trust_root(*, channel: str, target_id: str, public_key: bytes, now: datetime) -> dict[str, Any]:
    body = {
        "schema": "stateport.internal-update-trust-root/v1",
        "mode": "pinned-public-key",
        "keyId": ROOT_TRUST_KEY_ID,
        "publicKeyFingerprint": ROOT_TRUST_KEY_FINGERPRINT,
        "publicKeyFingerprintAlgorithm": "sha256-canonical-der-spki",
        "channel": channel,
        "targetId": target_id,
        "publicKeyFileDigest": "sha256:" + hashlib.sha256(public_key).hexdigest(),
        "createdAt": now.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    digest = canonical_digest(body)
    return {
        "trustRootId": f"update_trust_root_{digest.removeprefix('sha256:')[:32]}",
        **body,
        "trustRootDigest": digest,
    }


def _persist_trust(store: UpdateStore, trust_root: Mapping[str, Any], public_key: bytes) -> dict[str, Any]:
    existing_record = _validate_existing_trust(store, trust_root, public_key)
    trust = ensure_private_directory(store.root / "trust")
    record_path = trust / "trust-root.json"
    key_path = trust / f"{ROOT_TRUST_KEY_ID}.pem"
    try:
        if key_path.exists() or key_path.is_symlink():
            if read_bytes(key_path, "pinned update public key", maximum=64 * 1024) != public_key:
                raise _refuse("pinned public key conflicts with existing state", "bootstrap_state_conflict")
        else:
            create_bytes(key_path, public_key, "pinned update public key", maximum=64 * 1024)
    except SafeIOError as exc:
        raise _refuse("pinned public key could not be persisted", "bootstrap_state_conflict") from exc
    if existing_record is None:
        try:
            create_json(record_path, trust_root, "update trust root")
        except SafeIOError as exc:
            raise _refuse("update trust root could not be persisted", "bootstrap_state_conflict") from exc
    return existing_record if existing_record is not None else dict(trust_root)


def _validate_existing_trust(
    store: UpdateStore, trust_root: Mapping[str, Any], public_key: bytes
) -> dict[str, Any] | None:
    trust = store.root / "trust"
    if trust.is_symlink() or (trust.exists() and not trust.is_dir()):
        raise _refuse("update trust directory is unsafe", "bootstrap_state_conflict")
    if not trust.exists():
        return None
    record_path = trust / "trust-root.json"
    existing_record: dict[str, Any] | None = None
    # Validate an existing record before creating a missing key.  A foreign
    # record must remain byte-identical, including when its companion PEM was
    # removed by an interrupted or tampered installation.
    if record_path.exists() or record_path.is_symlink():
        try:
            existing = read_json(record_path, "update trust root")
        except SafeIOError as exc:
            raise _refuse("update trust root is unreadable", "bootstrap_state_conflict") from exc
        if set(existing) != set(trust_root):
            raise _refuse("update trust root has an unexpected shape", "bootstrap_state_conflict")
        existing_body = {
            key: value
            for key, value in existing.items()
            if key not in {"trustRootId", "trustRootDigest"}
        }
        if canonical_digest(existing_body) != existing.get("trustRootDigest"):
            raise _refuse("update trust root digest is invalid", "bootstrap_state_conflict")
        if existing.get("trustRootId") != f"update_trust_root_{str(existing['trustRootDigest']).removeprefix('sha256:')[:32]}":
            raise _refuse("update trust root identity is invalid", "bootstrap_state_conflict")
        comparable = {key: value for key, value in existing_body.items() if key != "createdAt"}
        expected_comparable = {
            key: value
            for key, value in trust_root.items()
            if key not in {"trustRootId", "trustRootDigest", "createdAt"}
        }
        if comparable != expected_comparable:
            raise _refuse("update trust root conflicts with existing state", "bootstrap_state_conflict")
        existing_record = existing
    key_path = trust / f"{ROOT_TRUST_KEY_ID}.pem"
    if key_path.exists() or key_path.is_symlink():
        try:
            if read_bytes(key_path, "pinned update public key", maximum=64 * 1024) != public_key:
                raise _refuse("pinned public key conflicts with existing state", "bootstrap_state_conflict")
        except SafeIOError as exc:
            raise _refuse("pinned public key is unreadable", "bootstrap_state_conflict") from exc
    return existing_record


def _operator_record(operator: Mapping[str, Any], actor_id: str) -> dict[str, Any]:
    return {
        "schema": OPERATOR_SCHEMA,
        "operator": {
            "user": str(operator["user"]),
            "uid": int(operator["uid"]),
            "gid": int(operator["gid"]),
        },
        "actorId": actor_id,
    }


def _validate_existing_operator(store: UpdateStore, expected: Mapping[str, Any]) -> dict[str, Any] | None:
    trust = store.root / "trust"
    if trust.is_symlink() or (trust.exists() and not trust.is_dir()):
        raise _refuse("update trust directory is unsafe", "bootstrap_state_conflict")
    if not trust.exists():
        return None
    path = trust / "operator.json"
    if not path.exists() and not path.is_symlink():
        return None
    try:
        existing = read_json(path, "control updater operator")
    except SafeIOError as exc:
        raise _refuse("control updater operator is unreadable", "bootstrap_state_conflict") from exc
    if existing != dict(expected):
        raise _refuse("control updater operator conflicts with existing state", "bootstrap_state_conflict")
    return existing


def _persist_operator(store: UpdateStore, expected: Mapping[str, Any]) -> dict[str, Any]:
    existing = _validate_existing_operator(store, expected)
    trust = ensure_private_directory(store.root / "trust")
    if existing is not None:
        return existing
    try:
        create_json(trust / "operator.json", expected, "control updater operator")
    except SafeIOError as exc:
        raise _refuse("control updater operator could not be persisted", "bootstrap_state_conflict") from exc
    return dict(expected)


def _open_store_without_foreign_creation(state_root: Path) -> UpdateStore:
    """Refuse a populated path that has no create-only store identity."""

    if state_root.exists() or state_root.is_symlink():
        if state_root.is_symlink() or not state_root.is_dir():
            raise _refuse("control updater state root is unsafe", "bootstrap_state_conflict")
        if any(state_root.iterdir()) and not (state_root / "manifest.json").is_file():
            raise _refuse("control updater state root has no installation identity", "bootstrap_state_conflict")
    try:
        return UpdateStore.create(state_root)
    except StoreError as exc:
        raise _refuse("control updater state root conflicts with existing state", "bootstrap_state_conflict") from exc


def _preflight_existing_store(
    store: UpdateStore,
    *,
    release_id: str,
    index_digest: str,
    signed_digest: str,
    installer_digest: str,
    actor_id: str,
    predecessor: Any | None,
) -> None:
    """Reject foreign existing state before creating any missing trust bytes."""

    if store.status_path.exists() or store.status_path.is_symlink():
        try:
            status = store.status()
        except (StoreError, SafeIOError) as exc:
            raise _refuse("existing updater status is unreadable", "bootstrap_state_conflict") from exc
        current = status.get("current")
        if not isinstance(current, Mapping) or current.get("releaseId") != release_id or current.get("signedPayloadDigest") != signed_digest:
            raise _refuse("existing updater status binds another release", "bootstrap_state_conflict")
    admissions_dir = store.admissions
    if admissions_dir.is_symlink() or (admissions_dir.exists() and not admissions_dir.is_dir()):
        raise _refuse("existing release admissions directory is unsafe", "bootstrap_state_conflict")
    if admissions_dir.exists():
        try:
            with store.transaction() as session:
                admissions = session.list_admissions()
        except (StoreError, SafeIOError) as exc:
            raise _refuse("existing release admission is unreadable", "bootstrap_state_conflict") from exc
        for admission in admissions:
            if (
                admission.get("releaseId") != release_id
                or admission.get("releaseIndexDigest") != index_digest
                or admission.get("signedPayloadDigest") != signed_digest
            ):
                raise _refuse("existing release admission binds another index", "bootstrap_state_conflict")
    releases_dir = store.releases
    if releases_dir.is_symlink() or (releases_dir.exists() and not releases_dir.is_dir()):
        raise _refuse("existing release index directory is unsafe", "bootstrap_state_conflict")
    allowed_indices = {(release_id, index_digest, signed_digest)}
    if predecessor is not None:
        allowed_indices.add(
            (
                str(predecessor.index.release_id),
                str(predecessor.index.index_digest),
                str(predecessor.index.signed_digest),
            )
        )
    if releases_dir.exists():
        for path in sorted(releases_dir.glob("*.release-index.json")):
            try:
                historic = load_release_index(read_bytes(path, "canonical release index"), legacy_predecessor=True)
            except (ReleaseContractError, SafeIOError) as exc:
                raise _refuse("existing release index is unreadable", "bootstrap_state_conflict") from exc
            identity = (historic.release_id, historic.index_digest, historic.signed_digest)
            if identity not in allowed_indices:
                raise _refuse("existing release index binds another release", "bootstrap_state_conflict")
    identity_dir = store.root / "installed-authority" / "identity"
    if identity_dir.is_symlink() or (identity_dir.exists() and not identity_dir.is_dir()):
        raise _refuse("existing installed identity directory is unsafe", "bootstrap_state_conflict")
    if identity_dir.exists():
        for path in sorted(identity_dir.glob("*.json")):
            try:
                identity = read_json(path, "installed identity")
            except SafeIOError as exc:
                raise _refuse("existing installed identity is unreadable", "bootstrap_state_conflict") from exc
            if (
                identity.get("releaseId") != release_id
                or identity.get("releaseIndexDigest") != index_digest
                or identity.get("signedPayloadDigest") != signed_digest
                or identity.get("installerDigest") != installer_digest
                or identity.get("actorId") != actor_id
            ):
                raise _refuse("existing installed identity binds another release", "bootstrap_state_conflict")


def _persist_manifest(store: UpdateStore, digest: str, content: bytes) -> None:
    directory = ensure_private_directory(store.root / "bundles" / "image-manifests")
    path = directory / f"{digest.removeprefix('sha256:')}.json"
    if path.exists() or path.is_symlink():
        try:
            existing = read_bytes(path, "retained image manifest", maximum=MAX_IMAGE_MANIFEST_BYTES)
        except SafeIOError as exc:
            raise _refuse("retained image manifest is unreadable", "bootstrap_state_conflict") from exc
        if existing != content:
            raise _refuse("retained image manifest conflicts with existing state", "bootstrap_state_conflict")
        return
    try:
        create_bytes(path, content, "retained image manifest", maximum=MAX_IMAGE_MANIFEST_BYTES)
    except SafeIOError as exc:
        raise _refuse("retained image manifest could not be persisted", "bootstrap_state_conflict") from exc


def initialize_bootstrap(
    raw_request: Mapping[str, Any],
    *,
    state_root: Path = CONTROL_STATE_ROOT,
    cosign_path: Path = BOOTSTRAP_COSIGN_PATH,
    public_key_path: Path = BOOTSTRAP_PUBLIC_KEY_PATH,
    require_control_identity: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify a root-authenticated request and initialize the control store.

    ``require_control_identity`` is enabled by :func:`main`; the optional
    switch keeps the pure store operation testable in disposable directories.
    """

    request = _request(raw_request)
    if require_control_identity and (
        os.getuid() != CONTROL_UID
        or os.geteuid() != CONTROL_UID
        or os.getgid() != CONTROL_GID
        or os.getegid() != CONTROL_GID
    ):
        raise _refuse("bootstrap must run as the fixed control account", "bootstrap_identity_refused")
    public_key = _read_fixed_file(public_key_path, label="pinned public key", maximum=64 * 1024)
    release_index = dict(request["releaseIndex"])
    try:
        index = load_release_index(canonical_json_bytes(release_index))
    except ReleaseContractError as exc:
        raise _refuse("release index is invalid", "bootstrap_release_invalid") from exc
    if index.index_digest != request["expectedIndexDigest"] or index.signed_digest != request["expectedSignedPayloadDigest"]:
        raise _refuse("release index digest does not match the root binding", "bootstrap_release_invalid")
    target_id = str(request["targetId"])
    targets = [
        target
        for target in index.document["signed"]["targets"]
        if str(target.get("targetId")) == target_id
    ]
    if len(targets) != 1:
        raise _refuse("root target is absent or duplicated in the release", "bootstrap_release_invalid")
    if index.document["signed"]["release"]["channel"] != request["channel"]:
        raise _refuse("release channel does not match the root binding", "bootstrap_release_invalid")
    predecessor = embedded_predecessor_index(index)
    operator = _operator(request["operator"])
    actor_id = str(request["actorId"])
    operator_record = _operator_record(operator, actor_id)
    current_time = now or datetime.now(timezone.utc)
    if current_time.tzinfo is None or current_time.utcoffset() is None:
        raise _refuse("bootstrap clock is not timezone-aware", "bootstrap_release_invalid")

    with tempfile.TemporaryDirectory(prefix="stateport-control-bootstrap-") as temporary:
        temporary_root = Path(temporary)
        transport_root, image_payloads, expected = _stage_inputs(
            request, index, predecessor, temporary_root
        )
        identity = PinnedPublicKeyIdentity(ROOT_TRUST_KEY_FINGERPRINT, ROOT_TRUST_KEY_ID)
        verifier = CosignVerifier(
            cosign=Path(cosign_path),
            public_key=Path(public_key_path),
            identity=identity,
            bundle_root=transport_root,
        )
        for bundle_digest, signature in expected.items():
            verifier.retain_bundle(
                transport_root / f"bundle-{bundle_digest.removeprefix('sha256:')}.sigstore.json",
                signature,
            )
        policy = ReleaseVerificationPolicy(
            expected_channel=str(request["channel"]),
            expected_target=target_id,
            updater_version=str(UPDATER_VERSION),
            accepted_signers=frozenset(),
            accepted_public_keys=frozenset({identity}),
            expected_trust_mode="pinned-public-key",
            now=current_time,
            allow_candidate=True,
            require_transparency_log=False,
        )
        try:
            verified = verify_release_index(
                index,
                policy=policy,
                verifier=verifier,
                predecessor=predecessor,
                local_image_payloads=image_payloads,
            )
        except (ReleaseContractError, OSError, ValueError) as exc:
            raise _refuse("release verification failed", "bootstrap_release_invalid") from exc
        envelope = to_updater_release_envelope(verified)
        signed_artifacts = verified.index.document["signed"].get("artifacts", {})
        installer = signed_artifacts.get("installer") if isinstance(signed_artifacts, Mapping) else None
        installer_digest = installer.get("digest") if isinstance(installer, Mapping) else None
        if _DIGEST.fullmatch(str(installer_digest or "")) is None:
            raise _refuse("verified release has no installer digest", "bootstrap_release_invalid")
        trust_root = _trust_root(
            channel=str(request["channel"]), target_id=target_id, public_key=public_key, now=current_time
        )
        store = _open_store_without_foreign_creation(Path(state_root))
        _preflight_existing_store(
            store,
            release_id=str(verified.index.release_id),
            index_digest=str(verified.index.index_digest),
            signed_digest=str(verified.index.signed_digest),
            installer_digest=str(installer_digest),
            actor_id=actor_id,
            predecessor=verified.authenticated_predecessor,
        )
        _validate_existing_operator(store, operator_record)
        existing_trust = _validate_existing_trust(store, trust_root, public_key)
        try:
            validate_genesis_replay(store, envelope, existing_trust or trust_root, str(installer_digest), actor_id)
        except ValueError as exc:
            raise _refuse("existing genesis records conflict", "bootstrap_state_conflict") from exc
        _persist_operator(store, operator_record)
        trust_root = _persist_trust(store, trust_root, public_key)
        bundle_root = ensure_private_directory(store.root / "bundles")
        persistent_verifier = CosignVerifier(
            cosign=Path(cosign_path),
            public_key=Path(public_key_path),
            identity=identity,
            bundle_root=bundle_root,
        )
        for bundle_digest, signature in expected.items():
            persistent_verifier.retain_bundle(
                transport_root / f"bundle-{bundle_digest.removeprefix('sha256:')}.sigstore.json",
                signature,
            )
        for image_id, content in image_payloads.items():
            image = next(item for item in verified.index.document["signed"]["images"] if str(item["imageId"]) == image_id)
            _persist_manifest(store, str(image["signature"]["subjectDigest"]), content)
        result = initialize_installed_updater(
            store,
            envelope,
            UpdatePolicy(mode="manual", channel=str(request["channel"])),
            verification_policy=policy,
            signature_verifier=persistent_verifier,
            target_id=target_id,
            trust_root=trust_root,
            installer_digest=str(installer_digest),
            installer_origin=INSTALLER_ORIGIN,
            installer_version=INSTALLER_VERSION,
            actor_id=actor_id,
            authenticated_predecessor=verified.authenticated_predecessor,
            clock=lambda: current_time,
        )
    return {
        "schema": RESULT_SCHEMA,
        "status": "initialized",
        "releaseId": str(result.install_trust["releaseId"]),
        "releaseIndexDigest": str(result.install_trust["releaseIndexDigest"]),
        "signedPayloadDigest": str(result.install_trust["signedPayloadDigest"]),
        "installedIdentityDigest": str(result.identity["identityDigest"]),
        "admissionDigest": str(result.admission["admissionDigest"]),
    }


def _read_stdin_request() -> dict[str, Any]:
    payload = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(payload) > MAX_REQUEST_BYTES:
        raise _refuse("bootstrap request exceeds its byte bound")
    try:
        value = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise _refuse("bootstrap request is not valid JSON") from exc
    return _request(value)


def main(argv: list[str] | None = None) -> int:
    if argv is not None and argv:
        print(json.dumps({"schema": ERROR_SCHEMA, "code": "bootstrap_arguments_refused", "status": "not_executed"}, sort_keys=True))
        return 77
    invoked = False
    try:
        request = _read_stdin_request()
        invoked = True
        result = initialize_bootstrap(
            request,
            state_root=CONTROL_STATE_ROOT,
            cosign_path=BOOTSTRAP_COSIGN_PATH,
            public_key_path=BOOTSTRAP_PUBLIC_KEY_PATH,
            require_control_identity=True,
        )
    except Exception:
        print(json.dumps({"schema": ERROR_SCHEMA, "code": "control_updater_bootstrap_refused", "status": "outcome_unknown" if invoked else "not_executed"}, sort_keys=True))
        return 77
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
