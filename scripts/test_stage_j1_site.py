#!/usr/bin/env python3
"""Focused coverage for the J1 qualification site stager."""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import shutil
import sys
import tarfile

import yaml


def _trust_pub(tmp_path: Path) -> Path:
    pub = tmp_path / "qualification-signing.pub"
    pub.write_bytes(b"-----BEGIN PUBLIC KEY-----\n")
    return pub

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import pytest

from qualification import stage_j1_site as stager


def _archive(tmp_path: Path, image_id: str, payload: bytes) -> Path:
    digest = hashlib.sha256(payload).hexdigest()
    archive_path = tmp_path / "archives" / f"{image_id}.oci.tar"
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, mode="w:") as bundle:
        info = tarfile.TarInfo(name=f"blobs/sha256/{digest}")
        info.size = len(payload)
        bundle.addfile(info, io.BytesIO(payload))
    return archive_path


def _candidate(tmp_path: Path, entries: list[dict]) -> Path:
    candidate = tmp_path / "candidate"
    candidate.mkdir(parents=True)
    (candidate / "download-marker").write_text("x", encoding="utf-8")
    (candidate / "compose.release.yaml").write_text("services: {}\n", encoding="utf-8")
    for entry in entries:
        image_id = entry["imageId"]
        payload = json.dumps({"bundle": image_id}).encode()
        (candidate / f"{image_id}.sigstore.json").write_bytes(payload)
        entry["signature"]["bundle"] = {
            "digest": "sha256:" + hashlib.sha256(payload).hexdigest()
        }
    index = {
        "signed": {
            "release": {"version": "0.0.0-j1.27"},
            "images": entries,
        }
    }
    (candidate / "release-index.json").write_text(json.dumps(index), encoding="utf-8")
    (candidate / "bootstrap.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    return candidate


def _bundle(tmp_path: Path) -> Path:
    bundle = tmp_path / ".candidate.source"
    provisioner = b"#!/bin/sh\n# provisioner with rotated pins\n"
    wheel = b"wheel-bytes"
    package_bundle = b"podman-package-bundle"
    for relative, payload in (
        ("provisioning/stateport-execution-host-provision", provisioner),
        ("installer/install.sh", b"#!/bin/sh\n installer\n"),
        ("updater/stateport-updater.whl", wheel),
        ("source/stateport-source.tar", b"tar-bytes"),
        ("notes/release-notes.md", b"notes"),
        ("limitations/known-limitations.md", b"limits"),
        ("packages/podman-package-bundle.tar", package_bundle),
    ):
        path = bundle / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    provenance = {
        "artifacts": {
            "executionHostProvisioner": {
                "path": "provisioning/stateport-execution-host-provision",
                "sha256": hashlib.sha256(provisioner).hexdigest(),
            },
            "updaterWheel": {
                "firstPath": "updater/stateport-updater.whl",
                "firstSha256": hashlib.sha256(wheel).hexdigest(),
            },
            "podmanPackageBundle": {
                "path": "packages/podman-package-bundle.tar",
                "sha256": hashlib.sha256(package_bundle).hexdigest(),
            },
        }
    }
    (bundle / "provenance").mkdir(parents=True, exist_ok=True)
    (bundle / "provenance" / "candidate-provenance.yaml").write_text(
        yaml.safe_dump(provenance, sort_keys=False), encoding="utf-8"
    )
    return bundle


def _entry(image_id: str, payload: bytes, kind: str = "oci-manifest-blob") -> dict:
    return {
        "imageId": image_id,
        "signature": {
            "subjectKind": kind,
            "subjectDigest": "sha256:" + hashlib.sha256(payload).hexdigest(),
        },
    }


def test_stages_image_signature_bundles_with_digest_pin(tmp_path: Path) -> None:
    manifest_payload = b'{"schemaVersion":2}\n'
    _archive(tmp_path, "stateport-web", manifest_payload)
    candidate = _candidate(tmp_path, [_entry("stateport-web", manifest_payload)])
    output = tmp_path / "site-sigs"
    bundle_dir = output / "download" / "0.0.0-j1.27" / "signatures"

    def _stage() -> dict:
        return stager.stage_site(
            candidate=candidate,
            archive_root=tmp_path / "archives",
            version="0.0.0-j1.27",
            output=output,
            candidate_bundle=_bundle(tmp_path),
            trust_public_key=_trust_pub(tmp_path),
        )

    result = _stage()
    staged_file = bundle_dir / "stateport-web.sigstore.json"
    assert staged_file.is_file()
    assert result["stagedSignatures"] == {
        "stateport-web": "sha256:" + hashlib.sha256(staged_file.read_bytes()).hexdigest()
    }
    # A drifted bundle must be refused before anything is staged.
    shutil.rmtree(output)
    (candidate / "stateport-web.sigstore.json").write_bytes(b"drifted")
    with pytest.raises(stager.SiteStagingError, match="drifted"):
        _stage()


def test_stages_manifests_release_tree_and_install_bootstrap(tmp_path: Path) -> None:
    payload = b'{"schemaVersion":2,"manifests":[]}\n'
    _archive(tmp_path, "stateport-web", payload)
    other_payload = b'{"ignored":true}\n'
    _archive(tmp_path, "stateport-api", other_payload)
    candidate = _candidate(
        tmp_path,
        [
            _entry("stateport-web", payload),
            _entry("stateport-api", other_payload, kind="signature-only"),
        ],
    )
    output = tmp_path / "site"
    bundle = _bundle(tmp_path)
    trust_pub = tmp_path / "qualification-signing.pub"
    trust_pub.write_bytes(b"-----BEGIN PUBLIC KEY-----\n")
    result = stager.stage_site(
        candidate=candidate,
        archive_root=tmp_path / "archives",
        version="0.0.0-j1.27",
        output=output,
        candidate_bundle=bundle,
        trust_public_key=trust_pub,
    )
    assert result["slug"] == "j1-27"
    staged = output / "download" / "j1-27-manifests" / "stateport-web.json"
    assert staged.read_bytes() == payload
    assert not (output / "download" / "j1-27-manifests" / "stateport-api.json").exists()
    release_dir = output / "download" / "0.0.0-j1.27"
    assert (release_dir / "download-marker").is_file()
    assert (output / "download" / "install.sh").read_bytes() == (
        release_dir / "bootstrap.sh"
    ).read_bytes()
    for flat in (
        "compose.yaml",
        "stateport-execution-host-provision",
        "stateport-installer",
        "stateport-updater",
        "stateport-source.tar",
        "stateport-podman-package-bundle.tar",
        "release-notes.md",
        "known-limitations.md",
        "stateport-alpha-2026-08-cosign.pub",
    ):
        assert (release_dir / flat).is_file(), flat
    assert result["provenanceVerified"]


def test_refuses_existing_output_missing_archive_and_drifted_blob(tmp_path: Path) -> None:
    payload = b"manifest-bytes"
    _archive(tmp_path, "stateport-web", payload)
    candidate = _candidate(tmp_path, [_entry("stateport-web", payload)])
    output = tmp_path / "site"

    with pytest.raises(stager.SiteStagingError, match="must be a new directory"):
        output.mkdir(parents=True)
        stager.stage_site(
            candidate=candidate,
            archive_root=tmp_path / "archives",
            version="0.0.0-j1.27",
            output=output,
        )

    output2 = tmp_path / "site2"
    bundle = _bundle(tmp_path)
    trust_pub = _trust_pub(tmp_path)
    with pytest.raises(stager.SiteStagingError, match="unavailable"):
        stager.stage_site(
            candidate=candidate,
            archive_root=tmp_path / "absent",
            version="0.0.0-j1.27",
            output=output2,
            candidate_bundle=bundle,
            trust_public_key=trust_pub,
        )

    drifted = tmp_path / "drifted" / "stateport-web.oci.tar"
    drifted.parent.mkdir(parents=True)
    with tarfile.open(drifted, mode="w:") as bundle:
        info = tarfile.TarInfo(name="blobs/sha256/" + "0" * 64)
        info.size = len(payload)
        bundle.addfile(info, io.BytesIO(payload))
    with pytest.raises(stager.SiteStagingError, match="absent"):
        stager.stage_site(
            candidate=candidate,
            archive_root=drifted.parent,
            version="0.0.0-j1.27",
            output=tmp_path / "site3",
        )


def test_slug_accepts_reserved_j1_and_public_alpha_versions() -> None:
    assert stager._slug("0.0.0-j1.27") == "j1-27"
    assert stager._slug("0.1.0-alpha.10") == "alpha10"
    with pytest.raises(stager.SiteStagingError, match="0.1.0-alpha"):
        stager._slug("0.1.0-beta.1")
    with pytest.raises(stager.SiteStagingError, match="unsupported"):
        stager._slug("../../etc")


def test_refuses_staging_version_not_bound_by_signed_index(tmp_path: Path) -> None:
    payload = b"manifest-bytes"
    _archive(tmp_path, "stateport-web", payload)
    candidate = _candidate(tmp_path, [_entry("stateport-web", payload)])
    with pytest.raises(stager.SiteStagingError, match="signed release version"):
        stager.stage_site(
            candidate=candidate,
            archive_root=tmp_path / "archives",
            version="0.0.0-j1.28",
            output=tmp_path / "site-version-mismatch",
            candidate_bundle=_bundle(tmp_path),
            trust_public_key=_trust_pub(tmp_path),
        )
