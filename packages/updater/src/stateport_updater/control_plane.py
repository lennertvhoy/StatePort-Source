"""Installed control-plane seam: bind the production trust root to the engine.

The updater wheel ships no signature verifier and no execution host; the
installed deployment injects both through ``ControlPlaneBinding``.  This
module is the production binding factory: ``build(state_root)`` re-derives
the release trust policy from the durable, create-only trust-root record the
installer wrote during genesis, re-verifies the pinned public-key bytes
against the recorded digest, resolves the cosign executable, and constructs
the local Podman host driver.  Nothing here trusts a release artifact, the
environment, or the CLI: the only inputs are the durable trust-root record,
the pinned PEM it names, and operator-controlled environment overrides for
tool and bundle locations.

Every failure is a typed ``UpdateAuthorityError`` and nothing is ever
written: a refused binding means the CLI never reaches the engine.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import shutil
from typing import Any, Callable, Mapping

from stateport_release import (
    CosignVerificationError,
    CosignVerifier,
    PinnedPublicKeyIdentity,
    ReleaseVerificationPolicy,
    canonical_digest,
)

from .authority import UpdateAuthorityError
from .engine import SUPPORTED_TARGET_IDS, UPDATER_VERSION
from .host_local import LocalPodmanHost, _default_quadlet_root
from .installed import ControlPlaneBinding
from .safe_io import SafeIOError, read_bytes, read_json

TRUST_ROOT_SCHEMA = "stateport.internal-update-trust-root/v1"
TRUST_ROOT_FIELDS = frozenset(
    {
        "schema",
        "trustRootId",
        "mode",
        "keyId",
        "publicKeyFingerprint",
        "publicKeyFingerprintAlgorithm",
        "channel",
        "targetId",
        "publicKeyFileDigest",
        "createdAt",
        "trustRootDigest",
    }
)
KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
FINGERPRINT = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_PUBLIC_KEY_BYTES = 64 * 1024


def _invalid(message: str) -> UpdateAuthorityError:
    return UpdateAuthorityError("control_plane_trust_invalid", message)


def _load_trust_root(state_root: Path) -> Mapping[str, Any]:
    record_path = state_root / "trust" / "trust-root.json"
    try:
        record = read_json(record_path, "update trust root record")
    except SafeIOError as exc:
        raise _invalid(f"update trust root record is unreadable: {exc}") from exc
    if not isinstance(record, dict) or set(record.keys()) != TRUST_ROOT_FIELDS:
        raise _invalid("update trust root record has an unexpected shape")
    if record["schema"] != TRUST_ROOT_SCHEMA:
        raise _invalid("update trust root record is not a pinned trust root")
    if record["mode"] != "pinned-public-key":
        raise _invalid("update trust root does not bind pinned-public-key trust")
    if record["publicKeyFingerprintAlgorithm"] != "sha256-canonical-der-spki":
        raise _invalid("update trust root names an unknown fingerprint algorithm")
    for field in (
        "trustRootId",
        "keyId",
        "publicKeyFingerprint",
        "channel",
        "targetId",
        "publicKeyFileDigest",
        "createdAt",
        "trustRootDigest",
    ):
        if not isinstance(record[field], str):
            raise _invalid(f"update trust root field {field} is malformed")
    if KEY_ID.fullmatch(record["keyId"]) is None:
        raise _invalid("update trust root key ID is malformed")
    if FINGERPRINT.fullmatch(record["publicKeyFingerprint"]) is None:
        raise _invalid("update trust root public-key fingerprint is malformed")
    if FINGERPRINT.fullmatch(record["publicKeyFileDigest"]) is None:
        raise _invalid("update trust root public-key file digest is malformed")
    if FINGERPRINT.fullmatch(record["trustRootDigest"]) is None:
        raise _invalid("update trust root digest is malformed")
    body = {
        key: value for key, value in record.items() if key not in {"trustRootId", "trustRootDigest"}
    }
    if canonical_digest(body) != record["trustRootDigest"]:
        raise _invalid("update trust root digest does not match its content")
    expected_id = f"update_trust_root_{record['trustRootDigest'].removeprefix('sha256:')[:32]}"
    if record["trustRootId"] != expected_id:
        raise _invalid("update trust root identity does not match its digest")
    if record["targetId"] not in SUPPORTED_TARGET_IDS:
        raise _invalid("update trust root does not bind the updater target")
    return record


def _pinned_public_key(state_root: Path, record: Mapping[str, Any]) -> Path:
    pem_path = state_root / "trust" / f"{record['keyId']}.pem"
    try:
        pem = read_bytes(pem_path, "pinned update public key", maximum=MAX_PUBLIC_KEY_BYTES)
    except SafeIOError as exc:
        raise _invalid(f"pinned update public key is unreadable: {exc}") from exc
    observed = f"sha256:{hashlib.sha256(pem).hexdigest()}"
    if observed != record["publicKeyFileDigest"]:
        raise _invalid("pinned update public key bytes do not match the trust root")
    return pem_path


def _resolve_cosign() -> Path:
    override = os.environ.get("STATEPORT_COSIGN")
    if override:
        return Path(override)
    found = shutil.which("cosign")
    if found is None:
        raise UpdateAuthorityError(
            "control_plane_cosign_unavailable",
            "no cosign executable is available to the installed updater",
        )
    return Path(found)


def _bundle_root(state_root: Path) -> Path:
    override = os.environ.get("STATEPORT_UPDATER_BUNDLE_ROOT")
    root = Path(override) if override else state_root / "bundles"
    if not root.is_dir() or root.is_symlink():
        raise UpdateAuthorityError(
            "control_plane_bundle_root_unavailable",
            "the installed updater bundle root is unavailable",
        )
    return root


def _quadlet_root() -> Path:
    override = os.environ.get("STATEPORT_QUADLET_ROOT")
    return Path(override) if override else _default_quadlet_root()


def build(state_root: Path) -> ControlPlaneBinding:
    """Build the validated production control-plane binding.

    ``state_root`` is the updater store root the CLI was invoked with; the
    durable trust root lives beneath it at ``trust/trust-root.json`` beside
    the pinned public-key PEM.  The returned binding re-derives every trust
    decision from that record and refuses closed on any deviation.
    """

    state_root = Path(state_root)
    record = _load_trust_root(state_root)
    pem_path = _pinned_public_key(state_root, record)
    identity = PinnedPublicKeyIdentity(
        public_key_fingerprint=record["publicKeyFingerprint"],
        key_id=record["keyId"],
    )
    try:
        bundle_root = _bundle_root(state_root)
        verifier = CosignVerifier(
            cosign=_resolve_cosign(),
            public_key=pem_path,
            identity=identity,
            bundle_root=bundle_root,
        )
    except (CosignVerificationError, OSError) as exc:
        raise _invalid(f"pinned cosign verifier is unavailable: {exc}") from exc
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)
    policy = ReleaseVerificationPolicy(
        expected_channel=record["channel"],
        expected_target=record["targetId"],
        updater_version=UPDATER_VERSION,
        accepted_signers=frozenset(),
        accepted_public_keys=frozenset({identity}),
        expected_trust_mode="pinned-public-key",
        now=clock(),
        allow_candidate=True,
        require_transparency_log=False,
    )
    target_id = str(record["targetId"])
    host = LocalPodmanHost(
        state_root, quadlet_root=_quadlet_root(), clock=clock, target_id=target_id
    )

    def transport_verifier_factory(root: Path) -> CosignVerifier:
        return CosignVerifier(
            cosign=_resolve_cosign(),
            public_key=pem_path,
            identity=identity,
            bundle_root=root,
        )

    return ControlPlaneBinding(
        host=host,
        signature_verifier=verifier,
        verification_policy=policy,
        clock=clock,
        bundle_root=bundle_root,
        transport_verifier_factory=transport_verifier_factory,
    ).validated(expected_target=target_id)
