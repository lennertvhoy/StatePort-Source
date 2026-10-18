"""Create-only initialization of an installed updater state root.

The anonymous installer and the trusted control-account provisioner share the
same updater genesis contract.  This module owns the part that binds a
verified release to updater status, its admission, installed authority, and
the durable install-trust record.  Callers persist the out-of-band trust root
before calling :func:`initialize_installed_updater`, preserving the installer
effect order while keeping trust-root acquisition outside this package.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from stateport_release import (
    ReleaseVerificationPolicy,
    SignatureVerifier,
    UpdaterReleaseEnvelope,
)

from .authority import UpdateAuthorityError
from .engine import UPDATER_VERSION, UpdateEngine, UpdateError
from .installed import InstalledAuthorityAdapter
from .models import UpdatePolicy
from .safe_io import SafeIOError, create_json, read_json
from .store import StoreError, UpdateStore


INSTALL_TRUST_SCHEMA = "stateport.internal-install-trust/v1"


def _timestamp(clock: Callable[[], datetime]) -> str:
    value = clock().astimezone(timezone.utc).replace(microsecond=0)
    return value.isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class GenesisResult:
    """Durable facts produced by a successful or converged genesis run."""

    store: UpdateStore
    admission: Mapping[str, Any]
    identity: Mapping[str, Any]
    install_trust: Mapping[str, Any]


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = read_json(path, label)
    except SafeIOError as exc:
        raise UpdateAuthorityError("state_unreadable", str(exc)) from exc
    if not isinstance(value, dict):
        raise UpdateAuthorityError("state_unreadable", f"{label} is not an object: {path}")
    return value


def _install_trust_record(trust_root, release_id, index_digest, signed_digest,
                          admission, identity, installer_digest, created_at):
    return {
        "schema": INSTALL_TRUST_SCHEMA,
        "trustRootId": str(trust_root["trustRootId"]),
        "trustRootDigest": str(trust_root["trustRootDigest"]),
        "mode": "pinned-public-key",
        "keyId": str(trust_root["keyId"]),
        "publicKeyFingerprint": str(trust_root["publicKeyFingerprint"]),
        "channel": str(trust_root["channel"]),
        "targetId": str(trust_root["targetId"]),
        "releaseId": release_id,
        "releaseIndexDigest": index_digest,
        "signedPayloadDigest": signed_digest,
        "admissionId": str(admission["admissionId"]),
        "admissionDigest": str(admission["admissionDigest"]),
        "installedIdentityId": str(identity["identityId"]),
        "installedIdentityDigest": str(identity["identityDigest"]),
        "installerDigest": installer_digest,
        "createdAt": created_at,
    }


def validate_genesis_replay(store, envelope, trust_root, installer_digest, actor_id):
    """Read all existing genesis bindings before creating any missing records."""
    release_id = str(envelope.document["release"]["releaseId"])
    index_digest = str(envelope.document["releaseIndexDigest"])
    signed_digest = str(envelope.document["signedPayloadDigest"])
    status_exists = store.status_path.exists() or store.status_path.is_symlink()
    admissions = []
    for path in sorted(store.admissions.glob("*.json")):
        item = _read_json(path, "release admission")
        if (item.get("kind") != "installed-initialize"
                or item.get("releaseId") != release_id
                or item.get("releaseIndexDigest") != index_digest
                or item.get("signedPayloadDigest") != signed_digest):
            raise UpdateAuthorityError("updater_genesis_conflict", "existing admission binds different genesis")
        admissions.append(item)
    if status_exists:
        status = _read_json(store.status_path, "update status")
        current = status.get("current", {})
        if (not isinstance(current, Mapping) or current.get("releaseId") != release_id
                or current.get("signedPayloadDigest") != signed_digest or len(admissions) != 1):
            raise UpdateAuthorityError("updater_genesis_conflict", "existing status has no exact genesis admission")
    adapter = InstalledAuthorityAdapter(store)
    for directory in (adapter.authority_root, adapter.identity_dir):
        if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
            raise UpdateAuthorityError("updater_genesis_conflict", "existing identity directory is unsafe")
    identities = [_read_json(path, "installed identity") for path in sorted(adapter.identity_dir.glob("*.json"))]
    if identities:
        if (len(identities) != 1 or not status_exists or len(admissions) != 1
                or any(identities[0].get(key) != value for key, value in {
                    "releaseId": release_id, "releaseIndexDigest": index_digest,
                    "signedPayloadDigest": signed_digest, "installerDigest": installer_digest,
                    "actorId": actor_id}.items())):
            raise UpdateAuthorityError("updater_genesis_conflict", "existing identity binds different genesis")
        adapter._load_identities()  # validate immutable digest and native store binding
    path = store.root / "trust" / "install-trust.json"
    if path.exists() or path.is_symlink():
        existing = _read_json(path, "install trust record")
        if len(admissions) != 1 or len(identities) != 1 or not status_exists:
            raise UpdateAuthorityError("updater_genesis_conflict", "install trust lacks its genesis records")
        expected = _install_trust_record(trust_root, release_id, index_digest, signed_digest,
                                         admissions[0], identities[0], installer_digest, None)
        if ({key: value for key, value in existing.items() if key != "createdAt"}
                != {key: value for key, value in expected.items() if key != "createdAt"}):
            raise UpdateAuthorityError("updater_genesis_conflict", "existing install trust binds different genesis")


def initialize_installed_updater(
    store: UpdateStore,
    envelope: UpdaterReleaseEnvelope,
    update_policy: UpdatePolicy,
    *,
    verification_policy: ReleaseVerificationPolicy,
    signature_verifier: SignatureVerifier,
    target_id: str,
    trust_root: Mapping[str, Any],
    installer_digest: str,
    installer_origin: str,
    installer_version: str,
    actor_id: str,
    authenticated_predecessor: Any | None = None,
    clock: Callable[[], datetime] | None = None,
) -> GenesisResult:
    """Initialize one installed updater store and converge exact replays.

    ``store`` must already have been created and ``trust_root`` must be the
    create-only record persisted from the operator's pinned key.  The engine
    receives inert host and authority objects because genesis has no host
    effects and claims no update authority.
    """

    validate_genesis_replay(store, envelope, trust_root, installer_digest, actor_id)
    now = clock or (lambda: datetime.now(timezone.utc))
    engine = UpdateEngine(
        store,
        object(),  # genesis performs no host calls
        object(),  # genesis claims no update authority
        verification_policy=verification_policy,
        signature_verifier=signature_verifier,
        updater_version=str(UPDATER_VERSION),
        target_id=target_id,
        clock=now,
    )
    try:
        engine.initialize(envelope, update_policy)
    except UpdateError as exc:
        if exc.code != "already_initialized":
            raise
        existing_status = _read_json(store.status_path, "update status")
        current = existing_status.get("current", {})
        release = envelope.document.get("release", {})
        if (
            current.get("releaseId") != str(release.get("releaseId"))
            or current.get("signedPayloadDigest")
            != envelope.document.get("signedPayloadDigest")
        ):
            raise UpdateAuthorityError(
                "updater_genesis_conflict",
                "existing updater status binds a different release",
            ) from exc


    release = envelope.document.get("release", {})
    release_id = str(release.get("releaseId"))
    index_digest = str(envelope.document.get("releaseIndexDigest"))
    signed_digest = str(envelope.document.get("signedPayloadDigest"))
    admissions: list[dict[str, Any]] = []
    for path in sorted(store.admissions.glob("*.json")):
        item = _read_json(path, "release admission")
        if (
            item.get("kind") == "installed-initialize"
            and item.get("releaseId") == release_id
            and item.get("releaseIndexDigest") == index_digest
            and item.get("signedPayloadDigest") == signed_digest
        ):
            admissions.append(item)
    if len(admissions) != 1:
        raise UpdateAuthorityError(
            "updater_genesis_conflict",
            "updater admissions do not bind the exact genesis release",
        )
    admission = admissions[0]

    if authenticated_predecessor is not None:
        predecessor_index = authenticated_predecessor.index
        predecessor_id = str(predecessor_index.release_id)
        predecessor_bytes = bytes(predecessor_index.canonical_index_bytes)
        release = envelope.document.get("release", {})
        if predecessor_id != str(release.get("releaseId")):
            try:
                with store.transaction() as session:
                    session.save_release_index_bytes(predecessor_id, predecessor_bytes)
            except StoreError as exc:
                raise UpdateAuthorityError(exc.code, str(exc)) from exc

    try:
        identity = InstalledAuthorityAdapter.install(
            store,
            installer_digest=installer_digest,
            installer_origin=installer_origin,
            installer_version=installer_version,
            actor_id=actor_id,
            clock=now,
        )
    except UpdateAuthorityError as exc:
        if exc.code != "installed_identity_exists":
            raise
        adapter = InstalledAuthorityAdapter(store, clock=now)
        identities = [
            _read_json(path, "installed identity record")
            for path in sorted(adapter.identity_dir.glob("*.json"))
        ]
        if (
            len(identities) != 1
            or identities[0].get("releaseId") != release_id
            or identities[0].get("releaseIndexDigest") != index_digest
            or identities[0].get("signedPayloadDigest") != signed_digest
            or identities[0].get("installerDigest") != installer_digest
            or identities[0].get("actorId") != actor_id
        ):
            raise UpdateAuthorityError(
                "updater_genesis_conflict",
                "existing installed authority binds a different release",
            ) from exc
        identity = identities[0]

    install_trust = _install_trust_record(
        trust_root, release_id, index_digest, signed_digest, admission, identity,
        installer_digest, _timestamp(now),
    )
    comparable = {key: value for key, value in install_trust.items() if key != "createdAt"}
    install_trust_path = store.root / "trust" / "install-trust.json"
    if install_trust_path.exists() or install_trust_path.is_symlink():
        existing_trust = _read_json(install_trust_path, "install trust record")
        if {key: value for key, value in existing_trust.items() if key != "createdAt"} != comparable:
            raise UpdateAuthorityError(
                "updater_genesis_conflict",
                "existing install trust record binds a different release",
            )
        install_trust = existing_trust
    else:
        try:
            create_json(install_trust_path, install_trust, "install trust record")
        except SafeIOError as exc:
            raise UpdateAuthorityError(exc.code, str(exc)) from exc

    return GenesisResult(
        store=store,
        admission=admission,
        identity=identity,
        install_trust=install_trust,
    )
