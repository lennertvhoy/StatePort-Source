from __future__ import annotations

import json
from pathlib import Path
import sys
from types import SimpleNamespace

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from infra.qualification import ubuntu2404_stage as stage  # noqa: E402


def test_ubuntu_contract_schemas_are_valid_and_stage_is_executable() -> None:
    for path in (stage.CONFIG_SCHEMA, stage.RECEIPT_SCHEMA):
        schema = json.loads(path.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
    assert stage.CONFIG_FORMAT.endswith("/v1")
    assert (ROOT / "infra/qualification/ubuntu2404_stage.py").read_text().startswith("#!/usr/bin/env python3")


def test_config_rejects_non_ubuntu_coordinates() -> None:
    value = json.loads((ROOT / "infra/qualification/ubuntu2404-config.json").read_text())
    value["guest"]["version"] = 22.04
    with pytest.raises(stage.QualificationRefusal):
        stage.validate_config(value)


def test_missing_real_receipt_refuses_before_qualification(tmp_path: Path) -> None:
    value = json.loads((ROOT / "infra/qualification/ubuntu2404-config.json").read_text())
    value["artifacts"]["releaseIndex"]["path"] = str(tmp_path / "missing")
    with pytest.raises(stage.QualificationRefusal, match="candidate artifact"):
        stage.validate_config(value)


def test_predecessor_sidecar_is_digest_and_path_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release_index = tmp_path / "release-index.json"
    signed_payload = tmp_path / "release-index.signed-payload.json"
    public_key = tmp_path / "release.pub"
    successor_bundle = tmp_path / "release-index.sigstore.json"
    predecessor_root = tmp_path / "predecessor-bundle"
    predecessor_root.mkdir()
    predecessor_bundle = predecessor_root / "release-index.sigstore.json"
    cosign = tmp_path / "cosign"
    for path, content in (
        (release_index, b"index"),
        (signed_payload, b"payload"),
        (public_key, b"public-key"),
        (successor_bundle, b"successor-bundle"),
        (predecessor_bundle, b"predecessor-bundle"),
        (cosign, b"cosign"),
    ):
        path.write_bytes(content)
    digest = lambda path: "sha256:" + __import__("hashlib").sha256(path.read_bytes()).hexdigest()
    successor_signature = {
        "subjectDigest": digest(signed_payload),
        "publicKeyFingerprint": "sha256:" + "a" * 64,
        "publicKeyId": "stateport-test",
    }
    predecessor_signature = {
        "bundle": {"digest": digest(predecessor_bundle)},
    }
    raw = {
        "signatures": [successor_signature],
        "signed": {
            "successor": {"predecessor": {"signature": predecessor_signature}},
            "images": [],
        },
    }
    index = SimpleNamespace(
        document=raw,
        signed_bytes=b"payload",
        index_digest="sha256:" + "c" * 64,
    )
    predecessor = SimpleNamespace(document={"signatures": [predecessor_signature]})

    class Verifier:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def retain_bundle(self, _path: Path, _signature: object) -> None:
            pass

        def verify_blob(self, _payload: bytes, _signature: object) -> None:
            pass

    monkeypatch.setattr(stage, "_load_release_index", lambda _path: raw)
    monkeypatch.setattr(stage, "validate_release_index", lambda *_args, **_kwargs: index)
    monkeypatch.setattr(stage, "embedded_predecessor_index", lambda _index: predecessor)
    monkeypatch.setattr(stage, "signature_bundle_name", lambda _signature: predecessor_bundle.name)
    monkeypatch.setattr(stage, "CosignVerifier", Verifier)
    monkeypatch.setattr(
        stage,
        "verify_release_predecessor",
        lambda *_args, **_kwargs: SimpleNamespace(signature=predecessor_signature),
    )
    config = {
        "artifacts": {"images": {}},
        "verification": {
            "publicKey": {"path": str(public_key), "sha256": digest(public_key)},
            "signatureBundle": {
                "path": str(successor_bundle),
                "sha256": digest(successor_bundle),
            },
            "predecessorSignatureBundle": {
                "path": str(predecessor_bundle),
                "sha256": digest(predecessor_bundle),
            },
            "cosign": {"path": str(cosign), "sha256": digest(cosign)},
            "keyId": "stateport-test",
            "publicKeyFingerprint": "sha256:" + "a" * 64,
        },
    }
    assert stage._verify_signed_release_index(config, release_index, signed_payload) is index
    wrong_root = tmp_path / "wrong-predecessor-root"
    wrong_root.mkdir()
    wrong_bundle = wrong_root / predecessor_bundle.name
    wrong_bundle.write_bytes(predecessor_bundle.read_bytes())
    config["verification"]["predecessorSignatureBundle"]["path"] = str(wrong_bundle)
    with pytest.raises(stage.QualificationRefusal, match="canonical transport path"):
        stage._verify_signed_release_index(config, release_index, signed_payload)


def test_candidate_binds_canonical_index_digest_not_file_bytes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = (b'{"schema":"stateport.release-index/v1","signatures":[],"signed":{}}\n')
    file_digest = "sha256:" + __import__("hashlib").sha256(source).hexdigest()
    canonical_digest = "sha256:" + __import__("hashlib").sha256(source.rstrip()).hexdigest()
    assert file_digest != canonical_digest

    verified = SimpleNamespace(
        index_digest=canonical_digest,
        document={"signed": {}},
    )
    candidate = {"releaseIndexDigest": canonical_digest}
    stage._require_candidate_index_digest(candidate, verified)
    monkeypatch.setattr(stage, "_verify_signed_release_index", lambda *_args: verified)
    config = {"candidate": candidate}
    assert stage._verified_candidate_signed(
        config, tmp_path / "release-index.json", tmp_path / "signed-payload.json"
    ) == {}

    candidate["releaseIndexDigest"] = file_digest
    with pytest.raises(stage.QualificationRefusal, match="canonical release index digest"):
        stage._verified_candidate_signed(
            config, tmp_path / "release-index.json", tmp_path / "signed-payload.json"
        )


def test_validated_candidate_identity_requires_frozen_collections(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = {
        "releaseId": "stateport-alpha-0.1.0-alpha.4",
        "version": "0.1.0-alpha.4",
        "targetId": "linux-amd64-rootless-podman-quadlet",
        "sourceCommit": "a" * 40,
        "sourceTree": "b" * 40,
        "publicSource": {
            "authorityUrl": "https://github.com/lennertvhoy/StatePort-Source.git",
            "ref": "refs/heads/public-main",
            "commit": "c" * 40,
            "tree": "d" * 40,
        },
        "imageDigests": [],
        "installerDigest": "sha256:" + "45" * 32,
        "signedPayloadDigest": "sha256:" + "12" * 32,
    }
    signed = {
        "release": {"releaseId": candidate["releaseId"], "version": candidate["version"]},
        "source": {
            "commit": candidate["sourceCommit"],
            "tree": candidate["sourceTree"],
            "publicSnapshot": candidate["publicSource"],
        },
        "images": (),
        "targets": ({"targetId": candidate["targetId"], "executionContract": {}},),
    }
    config = {
        "candidate": candidate,
        "artifacts": {
            "releaseIndex": {"path": "/index", "sha256": "sha256:" + "01" * 32},
            "signedPayload": {"path": "/payload", "sha256": "sha256:" + "12" * 32},
            "installer": {"path": "/installer", "sha256": candidate["installerDigest"]},
            "executionHostProvisioner": {"path": "/provisioner", "sha256": "sha256:" + "23" * 32},
            "updater": {"path": "/updater", "sha256": "sha256:" + "34" * 32},
            "images": {},
        },
    }
    monkeypatch.setattr(stage, "_digest", lambda path, _label: next(
        item["sha256"] for item in config["artifacts"].values()
        if isinstance(item, dict) and item.get("path") == str(path)
    ))
    monkeypatch.setattr(stage, "_verified_candidate_signed", lambda *_args: signed)

    with pytest.raises(stage.QualificationRefusal, match="updater artifact"):
        stage._validate_candidate_artifacts(config)

    for key in ("images", "targets"):
        signed[key] = []
        with pytest.raises(stage.QualificationRefusal):
            stage._validate_candidate_artifacts(config)
        signed[key] = () if key == "images" else (
            {"targetId": candidate["targetId"], "executionContract": {}},
        )
