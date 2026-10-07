"""Control-plane seam coverage: the production binding builds from durable trust."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import sys
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[1]
for source in (
    ROOT,
    ROOT / "packages/release-contracts/src",
    ROOT / "packages/updater/src",
):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from stateport_release import canonical_digest, public_key_der_spki_fingerprint  # noqa: E402
from stateport_release.cosign import CosignVerifier, CosignVerificationError  # noqa: E402
from stateport_updater.authority import UpdateAuthorityError  # noqa: E402
from stateport_updater.engine import TARGET_ID, UPDATER_VERSION, WSL2_TARGET_ID  # noqa: E402
from stateport_updater.host_local import LocalPodmanHost  # noqa: E402
import stateport_updater.control_plane as control_plane  # noqa: E402
from scripts.test_install_no_checkout import TEST_PUBLIC_KEY_PEM  # noqa: E402


pytestmark = pytest.mark.skipif(
    shutil.which("openssl") is None, reason="openssl is required to fingerprint the fixture key"
)

KEY_ID = "alpha-release"


def _durable_trust(
    tmp_path: Path, *, target_id: str = TARGET_ID
) -> tuple[Path, dict[str, Any]]:
    """Write the exact trust layout the installer genesis persists."""

    state_root = tmp_path / "updater"
    trust_dir = state_root / "trust"
    trust_dir.mkdir(parents=True)
    pem = TEST_PUBLIC_KEY_PEM.encode("ascii")
    pem_path = trust_dir / f"{KEY_ID}.pem"
    pem_path.write_bytes(pem)
    pem_path.chmod(0o600)
    body = {
        "schema": "stateport.internal-update-trust-root/v1",
        "mode": "pinned-public-key",
        "keyId": KEY_ID,
        "publicKeyFingerprint": public_key_der_spki_fingerprint(pem_path),
        "publicKeyFingerprintAlgorithm": "sha256-canonical-der-spki",
        "channel": "alpha",
        "targetId": target_id,
        "publicKeyFileDigest": f"sha256:{hashlib.sha256(pem).hexdigest()}",
        "createdAt": "2026-08-01T12:00:00Z",
    }
    digest = canonical_digest(body)
    record = {
        "trustRootId": f"update_trust_root_{digest.removeprefix('sha256:')[:32]}",
        **body,
        "trustRootDigest": digest,
    }
    record_path = trust_dir / "trust-root.json"
    record_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    record_path.chmod(0o600)
    (state_root / "bundles").mkdir()
    (state_root / "bundles").chmod(0o700)
    trust_dir.chmod(0o700)
    state_root.chmod(0o700)
    return state_root, record


@pytest.fixture
def bound(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, dict[str, Any]]:
    state_root, record = _durable_trust(tmp_path)
    cosign = tmp_path / "cosign"
    cosign.write_bytes(b"#!/bin/sh\nexit 0\n")
    cosign.chmod(0o755)
    monkeypatch.setenv("STATEPORT_COSIGN", str(cosign))
    monkeypatch.setenv("STATEPORT_QUADLET_ROOT", str(tmp_path / "quadlets"))
    monkeypatch.delenv("STATEPORT_UPDATER_BUNDLE_ROOT", raising=False)
    return state_root, record


def test_build_binds_policy_verifier_and_host_from_durable_trust(
    bound: tuple[Path, dict[str, Any]],
) -> None:
    state_root, record = bound
    binding = control_plane.build(state_root)

    policy = binding.verification_policy
    assert policy.expected_channel == "alpha"
    assert policy.expected_target == TARGET_ID
    assert policy.updater_version == UPDATER_VERSION
    assert policy.expected_trust_mode == "pinned-public-key"
    assert not policy.accepted_signers
    assert {identity.key_id for identity in policy.accepted_public_keys} == {KEY_ID}
    assert {identity.public_key_fingerprint for identity in policy.accepted_public_keys} == {
        record["publicKeyFingerprint"]
    }
    assert isinstance(binding.host, LocalPodmanHost)
    assert binding.host.root == state_root
    assert binding.host.target_id == TARGET_ID
    assert binding.clock is not None
    assert binding.clock() <= datetime.now(timezone.utc)
    assert binding.transport_verifier_factory is not None
    transient = state_root.parent / "transient-bundles"
    transient.mkdir()
    verifier = binding.transport_verifier_factory(transient)
    assert verifier.bundle_root == transient


def test_build_binds_the_wsl2_target_from_durable_trust(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_root, _record = _durable_trust(tmp_path, target_id=WSL2_TARGET_ID)
    cosign = tmp_path / "cosign"
    cosign.write_bytes(b"#!/bin/sh\nexit 0\n")
    cosign.chmod(0o755)
    monkeypatch.setenv("STATEPORT_COSIGN", str(cosign))
    monkeypatch.setenv("STATEPORT_QUADLET_ROOT", str(tmp_path / "quadlets"))

    binding = control_plane.build(state_root)

    assert binding.verification_policy.expected_target == WSL2_TARGET_ID
    assert binding.host.target_id == WSL2_TARGET_ID


def test_build_refuses_a_tampered_trust_root(bound: tuple[Path, dict[str, Any]]) -> None:
    state_root, record = bound
    tampered = dict(record, channel="stable")
    (state_root / "trust" / "trust-root.json").write_text(
        json.dumps(tampered) + "\n", encoding="utf-8"
    )
    with pytest.raises(UpdateAuthorityError) as failure:
        control_plane.build(state_root)
    assert failure.value.code == "control_plane_trust_invalid"


def test_build_refuses_replaced_public_key_bytes(bound: tuple[Path, dict[str, Any]]) -> None:
    state_root, _record = bound
    pem_path = state_root / "trust" / f"{KEY_ID}.pem"
    pem_path.write_bytes(b"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n")
    pem_path.chmod(0o600)
    with pytest.raises(UpdateAuthorityError) as failure:
        control_plane.build(state_root)
    assert failure.value.code == "control_plane_trust_invalid"


def test_build_refuses_a_symlinked_public_key(bound: tuple[Path, dict[str, Any]]) -> None:
    state_root, _record = bound
    pem_path = state_root / "trust" / f"{KEY_ID}.pem"
    target = state_root / "trust" / "elsewhere.pem"
    target.write_bytes(pem_path.read_bytes())
    pem_path.unlink()
    pem_path.symlink_to(target)
    with pytest.raises(UpdateAuthorityError) as failure:
        control_plane.build(state_root)
    assert failure.value.code == "control_plane_trust_invalid"


def test_build_refuses_without_a_cosign_executable(
    bound: tuple[Path, dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    state_root, _record = bound
    monkeypatch.delenv("STATEPORT_COSIGN")
    monkeypatch.setattr(shutil, "which", lambda name: None)
    with pytest.raises(UpdateAuthorityError) as failure:
        control_plane.build(state_root)
    assert failure.value.code == "control_plane_cosign_unavailable"


def test_local_image_manifest_slot_is_digest_bound_and_small(tmp_path: Path) -> None:
    """Control bootstrap can retain a manifest without transferring an OCI archive."""

    bundle_root = tmp_path / "bundles"
    manifest_root = bundle_root / "image-manifests"
    manifest_root.mkdir(parents=True)
    payload = b'{"schemaVersion":2,"config":{"digest":"sha256:' + b"a" * 64 + b'"}}'
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    path = manifest_root / f"{digest.removeprefix('sha256:')}.json"
    path.write_bytes(payload)
    verifier = object.__new__(CosignVerifier)
    object.__setattr__(verifier, "bundle_root", bundle_root)

    assert verifier.resolve_local_image_manifest("stateport-web", digest) == payload
    path.write_bytes(b"tampered")
    with pytest.raises(CosignVerificationError, match="manifest is tampered"):
        verifier.resolve_local_image_manifest("stateport-web", digest)


def test_build_refuses_a_missing_cosign_override(
    bound: tuple[Path, dict[str, Any]], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    state_root, _record = bound
    monkeypatch.setenv("STATEPORT_COSIGN", str(tmp_path / "no-such-cosign"))
    with pytest.raises(UpdateAuthorityError) as failure:
        control_plane.build(state_root)
    assert failure.value.code == "control_plane_trust_invalid"


def test_build_refuses_without_a_bundle_root(
    bound: tuple[Path, dict[str, Any]], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    state_root, _record = bound
    monkeypatch.setenv("STATEPORT_UPDATER_BUNDLE_ROOT", str(tmp_path / "no-such-bundles"))
    with pytest.raises(UpdateAuthorityError) as failure:
        control_plane.build(state_root)
    assert failure.value.code == "control_plane_bundle_root_unavailable"
