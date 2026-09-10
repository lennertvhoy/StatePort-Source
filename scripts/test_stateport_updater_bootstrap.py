"""Control-account updater bootstrap uses only bounded verified transport."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import base64
import hashlib
import json
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
for source in (ROOT, ROOT / "packages/release-contracts/src", ROOT / "packages/updater/src"):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from stateport_release import canonical_digest, load_release_index  # noqa: E402
from stateport_release.cosign import retain_bundle  # noqa: E402
import stateport_updater.bootstrap as bootstrap  # noqa: E402
from scripts.test_release_contracts import PINNED_KEY, _EphemeralTestVerifier, release_index  # noqa: E402


NOW = datetime(2026, 8, 1, 12, 0, tzinfo=timezone.utc)


def _signature(subject: str, name: str) -> tuple[dict[str, object], bytes]:
    content = (name + "-fixture-bundle").encode("ascii")
    digest = "sha256:" + hashlib.sha256(content).hexdigest()
    return (
        {
            "scheme": "cosign-v3-bundle",
            "subjectDigest": subject,
            "bundle": {
                "uri": f"operator://release/{name}.sigstore.json",
                "digest": digest,
                "size": len(content),
                "mediaType": "application/vnd.sigstore.bundle.v0.3+json",
            },
            "trustMode": "pinned-public-key",
            "publicKeyFingerprint": PINNED_KEY.public_key_fingerprint,
            "publicKeyFingerprintAlgorithm": "sha256-canonical-der-spki",
            "publicKeyId": PINNED_KEY.key_id,
            "transparencyLog": "not-uploaded-private-candidate",
        },
        content,
    )


def _request() -> dict[str, object]:
    document = deepcopy(release_index())
    signed = document["signed"]
    signed["signaturePolicy"]["trustMode"] = "pinned-public-key"
    bundles: list[dict[str, object]] = []
    for image in signed["images"]:
        signature, content = _signature(str(image["digest"]), str(image["imageId"]))
        image["signature"] = signature
        bundles.append(
            {
                "signature": signature,
                "contentBase64": base64.b64encode(content).decode("ascii"),
            }
        )
    signature, content = _signature(canonical_digest(signed), "release-index")
    document["signatures"] = [signature]
    bundles.insert(
        0,
        {"signature": signature, "contentBase64": base64.b64encode(content).decode("ascii")},
    )
    index = load_release_index(bootstrap.canonical_json_bytes(document))
    return {
        "schema": bootstrap.REQUEST_SCHEMA,
        "releaseIndex": document,
        "expectedIndexDigest": index.index_digest,
        "expectedSignedPayloadDigest": index.signed_digest,
        "channel": "alpha",
        "targetId": "linux-amd64-rootless-podman-quadlet",
        "actorId": "operator",
        "operator": {"user": "operator", "uid": 1000, "gid": 1000},
        "bundles": bundles,
        "imageManifests": [],
    }


class _FixtureVerifier:
    """Signature fixtures are contract-shaped; cryptography is intentionally mocked."""

    def __init__(self, *, bundle_root: Path, **_: object) -> None:
        self.bundle_root = Path(bundle_root)
        self.delegate = _EphemeralTestVerifier()

    def retain_bundle(self, source: Path, signature: dict[str, object]) -> Path:
        return retain_bundle(self.bundle_root, source, signature)

    def set_local_image_payloads(self, _payloads: object) -> None:
        return None

    def verify_blob(self, payload: bytes, signature: dict[str, object]) -> object:
        return self.delegate.verify_blob(payload, signature)

    def verify_image(self, reference: str, signature: dict[str, object]) -> object:
        return self.delegate.verify_image(reference, signature)


@pytest.fixture
def fixture_bootstrap(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setattr(bootstrap, "CosignVerifier", _FixtureVerifier)
    monkeypatch.setattr(bootstrap, "ROOT_TRUST_KEY_ID", PINNED_KEY.key_id)
    monkeypatch.setattr(bootstrap, "ROOT_TRUST_KEY_FINGERPRINT", PINNED_KEY.public_key_fingerprint)
    key = tmp_path / "fixture-key.pem"
    key.write_bytes(b"fixture-key")
    monkeypatch.setattr(bootstrap, "_read_fixed_file", lambda *_args, **_kwargs: key.read_bytes())
    return tmp_path


def test_control_bootstrap_real_store_replays_exactly(
    fixture_bootstrap: Path,
) -> None:
    request = _request()
    state_root = fixture_bootstrap / "updater"
    first = bootstrap.initialize_bootstrap(
        request,
        state_root=state_root,
        cosign_path=fixture_bootstrap / "cosign",
        public_key_path=fixture_bootstrap / "key",
        now=NOW,
    )
    before = {
        path.relative_to(state_root).as_posix(): path.read_bytes()
        for path in state_root.rglob("*")
        if path.is_file()
    }
    second = bootstrap.initialize_bootstrap(
        request,
        state_root=state_root,
        cosign_path=fixture_bootstrap / "cosign",
        public_key_path=fixture_bootstrap / "key",
        now=NOW,
    )
    after = {
        path.relative_to(state_root).as_posix(): path.read_bytes()
        for path in state_root.rglob("*")
        if path.is_file()
    }
    assert first == second
    assert first["status"] == "initialized"
    assert before == after
    assert json.loads((state_root / "trust" / "operator.json").read_text(encoding="utf-8")) == {
        "schema": "stateport.control-updater-operator/v1",
        "operator": {"user": "operator", "uid": 1000, "gid": 1000},
        "actorId": "operator",
    }


def _file_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def test_conflicting_trust_record_does_not_recreate_missing_key(
    fixture_bootstrap: Path,
) -> None:
    request = _request()
    state_root = fixture_bootstrap / "updater"
    bootstrap.initialize_bootstrap(
        request, state_root=state_root, cosign_path=fixture_bootstrap / "cosign",
        public_key_path=fixture_bootstrap / "key", now=NOW,
    )
    key_path = state_root / "trust" / f"{PINNED_KEY.key_id}.pem"
    key_path.unlink()
    trust_path = state_root / "trust" / "trust-root.json"
    trust_path.write_text(trust_path.read_text(encoding="utf-8").replace('"channel":"alpha"', '"channel":"stable"'), encoding="utf-8")
    before = _file_bytes(state_root)
    with pytest.raises(bootstrap.BootstrapRefusal):
        bootstrap.initialize_bootstrap(
            request, state_root=state_root, cosign_path=fixture_bootstrap / "cosign",
            public_key_path=fixture_bootstrap / "key", now=NOW,
        )
    assert _file_bytes(state_root) == before
    assert not key_path.exists()


def test_conflicting_installed_identity_does_not_change_store(
    fixture_bootstrap: Path,
) -> None:
    request = _request()
    state_root = fixture_bootstrap / "updater"
    bootstrap.initialize_bootstrap(
        request, state_root=state_root, cosign_path=fixture_bootstrap / "cosign",
        public_key_path=fixture_bootstrap / "key", now=NOW,
    )
    identity_path = next((state_root / "installed-authority" / "identity").glob("*.json"))
    identity = json.loads(identity_path.read_text(encoding="utf-8"))
    identity["releaseId"] = "foreign-release"
    identity_path.write_text(json.dumps(identity, sort_keys=True), encoding="utf-8")
    before = _file_bytes(state_root)
    with pytest.raises(bootstrap.BootstrapRefusal):
        bootstrap.initialize_bootstrap(
            request, state_root=state_root, cosign_path=fixture_bootstrap / "cosign",
            public_key_path=fixture_bootstrap / "key", now=NOW,
        )
    assert _file_bytes(state_root) == before


def test_conflicting_actor_does_not_change_store(fixture_bootstrap: Path) -> None:
    request = _request()
    state_root = fixture_bootstrap / "updater"
    bootstrap.initialize_bootstrap(
        request, state_root=state_root, cosign_path=fixture_bootstrap / "cosign",
        public_key_path=fixture_bootstrap / "key", now=NOW,
    )
    conflicting = deepcopy(request)
    conflicting["actorId"] = "different-actor"
    before = _file_bytes(state_root)
    with pytest.raises(bootstrap.BootstrapRefusal):
        bootstrap.initialize_bootstrap(
            conflicting, state_root=state_root, cosign_path=fixture_bootstrap / "cosign",
            public_key_path=fixture_bootstrap / "key", now=NOW,
        )
    assert _file_bytes(state_root) == before


def test_same_signed_payload_with_different_index_refuses_unchanged(
    fixture_bootstrap: Path,
) -> None:
    request = _request()
    state_root = fixture_bootstrap / "updater"
    bootstrap.initialize_bootstrap(
        request, state_root=state_root, cosign_path=fixture_bootstrap / "cosign",
        public_key_path=fixture_bootstrap / "key", now=NOW,
    )
    conflicting = deepcopy(request)
    signature = conflicting["releaseIndex"]["signatures"][0]
    signature["bundle"]["uri"] = "operator://release/alternate-index.sigstore.json"
    conflicting["bundles"][0]["signature"] = signature
    index = load_release_index(bootstrap.canonical_json_bytes(conflicting["releaseIndex"]))
    assert index.signed_digest == request["expectedSignedPayloadDigest"]
    assert index.index_digest != request["expectedIndexDigest"]
    conflicting["expectedIndexDigest"] = index.index_digest
    before = _file_bytes(state_root)
    with pytest.raises(bootstrap.BootstrapRefusal):
        bootstrap.initialize_bootstrap(
            conflicting, state_root=state_root, cosign_path=fixture_bootstrap / "cosign",
            public_key_path=fixture_bootstrap / "key", now=NOW,
        )
    assert _file_bytes(state_root) == before


def test_symlinked_identity_directory_refuses_unchanged(fixture_bootstrap: Path) -> None:
    request = _request()
    state_root = fixture_bootstrap / "updater"
    bootstrap.initialize_bootstrap(
        request, state_root=state_root, cosign_path=fixture_bootstrap / "cosign",
        public_key_path=fixture_bootstrap / "key", now=NOW,
    )
    identity_dir = state_root / "installed-authority" / "identity"
    backup = state_root / "identity-backup"
    identity_dir.rename(backup)
    identity_dir.symlink_to(backup, target_is_directory=True)
    before = _file_bytes(state_root)
    with pytest.raises(bootstrap.BootstrapRefusal):
        bootstrap.initialize_bootstrap(
            request, state_root=state_root, cosign_path=fixture_bootstrap / "cosign",
            public_key_path=fixture_bootstrap / "key", now=NOW,
        )
    assert _file_bytes(state_root) == before
    assert identity_dir.is_symlink()
    identity_dir.unlink()
    backup.rename(identity_dir)


@pytest.mark.parametrize("mutation", ["index", "bundle", "signature", "uid"])
def test_control_bootstrap_rejects_bad_root_bound_inputs(
    fixture_bootstrap: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    request = _request()
    if mutation == "index":
        request["expectedIndexDigest"] = "sha256:" + "f" * 64
    elif mutation == "bundle":
        request["bundles"][0]["contentBase64"] = base64.b64encode(b"foreign").decode("ascii")
    elif mutation == "signature":
        request["bundles"][0]["signature"]["publicKeyId"] = "foreign-key"
    else:
        monkeypatch.setattr(bootstrap.os, "getuid", lambda: 1000)
        monkeypatch.setattr(bootstrap.os, "geteuid", lambda: 1000)
        monkeypatch.setattr(bootstrap.os, "getgid", lambda: 1000)
        monkeypatch.setattr(bootstrap.os, "getegid", lambda: 1000)
    with pytest.raises(bootstrap.BootstrapRefusal):
        bootstrap.initialize_bootstrap(
            request,
            state_root=fixture_bootstrap / "updater",
            cosign_path=fixture_bootstrap / "cosign",
            public_key_path=fixture_bootstrap / "key",
            require_control_identity=mutation == "uid",
            now=NOW,
        )
    assert not (fixture_bootstrap / "updater").exists()

@pytest.mark.parametrize("mutation", ["install_trust", "missing_admission"])
def test_torn_genesis_refuses_before_missing_trust_writes(fixture_bootstrap: Path, mutation: str) -> None:
    request = _request()
    state_root = fixture_bootstrap / "updater"
    kwargs = dict(state_root=state_root, cosign_path=fixture_bootstrap / "cosign", public_key_path=fixture_bootstrap / "key", now=NOW)
    bootstrap.initialize_bootstrap(request, **kwargs)
    if mutation == "install_trust":
        path = state_root / "trust/install-trust.json"
        content = json.loads(path.read_text())
        content["installerDigest"] = "sha256:" + "f" * 64
        path.write_text(json.dumps(content))
    else:
        for path in (state_root / "release-admissions").glob("*.json"):
            path.unlink()
    (state_root / "trust/operator.json").unlink()
    for path in (state_root / "trust").glob("*.pem"):
        path.unlink()
    before = _file_bytes(state_root)
    with pytest.raises(bootstrap.BootstrapRefusal):
        bootstrap.initialize_bootstrap(request, **kwargs)
    assert _file_bytes(state_root) == before


@pytest.mark.parametrize("invoked", [False, True])
def test_bootstrap_failure_distinguishes_preflight_from_unknown_outcome(tmp_path, monkeypatch, capsys, invoked):
    marker = tmp_path / "durable-effect"
    def request():
        if not invoked:
            raise ValueError("malformed request")
        return {}
    def initialize(*_args, **_kwargs):
        marker.write_text("effect happened")
        raise OSError("response failed after effect")
    monkeypatch.setattr(bootstrap, "_read_stdin_request", request)
    monkeypatch.setattr(bootstrap, "initialize_bootstrap", initialize)
    assert bootstrap.main([]) == 77
    assert marker.exists() is invoked
    assert json.loads(capsys.readouterr().out)["status"] == ("outcome_unknown" if invoked else "not_executed")
