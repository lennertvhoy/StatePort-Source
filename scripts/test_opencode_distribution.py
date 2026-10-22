"""Deterministic tests for the pinned upstream OpenCode distribution helper.

Network-free: every test either reads the committed pin/lock files or exercises
pure helpers with in-memory tarballs and injected fetchers.
"""

from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import stat
import sys
import tarfile

import pytest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts/prepare_opencode_distribution.py"
spec = importlib.util.spec_from_file_location("prepare_opencode_distribution", MODULE_PATH)
assert spec and spec.loader
distribution = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = distribution
spec.loader.exec_module(distribution)


def _pin() -> dict:
    return distribution.load_pin(ROOT / "config/provider-runtime-inputs.yaml")


def _tgz(member: str, content: bytes) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        info = tarfile.TarInfo(member)
        info.size = len(content)
        info.mode = 0o755
        archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def _script(version: str) -> bytes:
    return f"#!/bin/sh\necho {version}\n".encode("utf-8")


def _fake_pin(tarball: bytes, version: str = "1.18.31") -> dict:
    return {
        "package": "opencode-ai",
        "version": version,
        "npm": {"registry": "https://registry.npmjs.org"},
        "platforms": {
            "glibc": {
                "package": "opencode-linux-x64",
                "tarball": (
                    "https://registry.npmjs.org/opencode-linux-x64/-/"
                    f"opencode-linux-x64-{version}.tgz"
                ),
                "integrity": distribution._sha512_sri(tarball),
                "binaryMember": "package/bin/opencode",
                "os": "linux",
                "cpu": "x64",
            }
        },
    }


# === Pin consistency ===

def test_pin_matches_package_json_and_lock() -> None:
    pin = _pin()
    package = json.loads(
        (ROOT / pin["npm"]["packageJson"]).read_text(encoding="utf-8")
    )
    lock = json.loads(
        (ROOT / pin["npm"]["packageLock"]).read_text(encoding="utf-8")
    )
    assert lock["lockfileVersion"] == 3
    assert package["dependencies"] == {pin["package"]: pin["version"]}
    assert lock["packages"][""]["dependencies"] == package["dependencies"]

    cli = lock["packages"][f"node_modules/{pin['package']}"]
    assert cli["version"] == pin["version"]
    assert cli["integrity"] == pin["npm"]["packageIntegrity"]

    for platform in pin["platforms"].values():
        entry = lock["packages"][f"node_modules/{platform['package']}"]
        assert entry["version"] == pin["version"]
        assert entry["integrity"] == platform["integrity"]
        assert platform["binaryMember"] == "package/bin/opencode"


def test_pin_records_upstream_provenance() -> None:
    pin = _pin()
    assert pin["source"]["repository"] == "https://github.com/anomalyco/opencode"
    assert pin["source"]["tag"] == f"v{pin['version']}"
    assert pin["source"]["tagType"] == "lightweight"
    assert len(pin["source"]["commit"]) == 40
    assert pin["license"]["spdx"] == "MIT"
    assert pin["license"]["packagePath"] == "LICENSE"


def test_pin_tarballs_come_from_pinned_registry() -> None:
    pin = _pin()
    assert pin["npm"]["packageTarball"].startswith(distribution.PINNED_REGISTRY_PREFIX)
    for flavor, platform in pin["platforms"].items():
        resolved = distribution.resolve_platform(pin, flavor)
        assert resolved["tarball"].startswith(distribution.PINNED_REGISTRY_PREFIX)


# === Integrity ===

def test_verify_integrity_accepts_pinned_sha512() -> None:
    data = b"pinned bytes\n"
    distribution.verify_integrity(data, distribution._sha512_sri(data))


def test_verify_integrity_rejects_tampered_and_malformed() -> None:
    data = b"pinned bytes\n"
    with pytest.raises(
        distribution.OpenCodeDistributionError, match="integrity differs"
    ):
        distribution.verify_integrity(data, distribution._sha512_sri(b"other\n"))
    with pytest.raises(
        distribution.OpenCodeDistributionError, match="not a sha512 SRI"
    ):
        distribution.verify_integrity(data, "sha512-not-valid")


# === Flavor selection ===

def test_resolve_platform_rejects_unsupported_flavor() -> None:
    pin = _pin()
    with pytest.raises(
        distribution.OpenCodeDistributionError, match="unsupported flavor"
    ):
        distribution.resolve_platform(pin, "windows")
    with pytest.raises(
        distribution.OpenCodeDistributionError, match="unsupported flavor"
    ):
        distribution.resolve_platform(pin, "")


def test_resolve_platform_rejects_unpinned_registry() -> None:
    pin = _pin()
    pin["platforms"]["glibc"]["tarball"] = (
        "https://evil.example/opencode-linux-x64-1.18.31.tgz"
    )
    with pytest.raises(
        distribution.OpenCodeDistributionError, match="pinned npm registry"
    ):
        distribution.resolve_platform(pin, "glibc")


# === Extraction ===

def test_extract_binary_writes_pinned_member_at_0555(tmp_path: Path) -> None:
    archive = _tgz("package/bin/opencode", b"opencode-binary-bytes")
    binary = distribution.extract_binary(
        archive, tmp_path, "package/bin/opencode"
    )
    assert binary == tmp_path / "opencode"
    assert binary.read_bytes() == b"opencode-binary-bytes"
    assert stat.S_IMODE(binary.stat().st_mode) == 0o555


def test_extract_binary_rejects_absent_or_unsafe_member(tmp_path: Path) -> None:
    archive = _tgz("package/bin/opencode", b"bytes")
    with pytest.raises(
        distribution.OpenCodeDistributionError, match="does not contain"
    ):
        distribution.extract_binary(archive, tmp_path, "package/bin/missing")
    with pytest.raises(
        distribution.OpenCodeDistributionError, match="unsafe"
    ):
        distribution.extract_binary(archive, tmp_path, "../escape")


# === Version verification ===

def test_verify_binary_version_accepts_pin_and_rejects_wrong_output(
    tmp_path: Path,
) -> None:
    good = tmp_path / "good"
    good.write_bytes(_script("1.18.31"))
    good.chmod(0o555)
    assert distribution.verify_binary_version(good, "1.18.31") == "1.18.31"

    wrong = tmp_path / "wrong"
    wrong.write_bytes(_script("9.9.9"))
    wrong.chmod(0o555)
    with pytest.raises(
        distribution.OpenCodeDistributionError, match="reports '9.9.9'"
    ):
        distribution.verify_binary_version(wrong, "1.18.31")


# === End-to-end materialization (injected fetch) ===

def test_materialize_refuses_tampered_tarball(tmp_path: Path) -> None:
    tarball = _tgz("package/bin/opencode", _script("1.18.31"))
    pin = _fake_pin(tarball)
    pin["platforms"]["glibc"]["integrity"] = distribution._sha512_sri(b"tampered")
    calls: list[str] = []

    def fetch(url: str) -> bytes:
        calls.append(url)
        return tarball

    with pytest.raises(
        distribution.OpenCodeDistributionError, match="integrity differs"
    ):
        distribution.materialize(
            pin, "glibc", tmp_path / "out", tmp_path / "cache", fetch=fetch
        )
    assert calls == [pin["platforms"]["glibc"]["tarball"]]
    assert not (tmp_path / "out" / "opencode").exists()


def test_materialize_fails_closed_on_wrong_version(tmp_path: Path) -> None:
    tarball = _tgz("package/bin/opencode", _script("9.9.9"))
    pin = _fake_pin(tarball, version="1.18.31")
    with pytest.raises(
        distribution.OpenCodeDistributionError, match="reports '9.9.9'"
    ):
        distribution.materialize(
            pin,
            "glibc",
            tmp_path / "out",
            tmp_path / "cache",
            fetch=lambda _url: tarball,
        )
    assert not (tmp_path / "out" / "opencode").exists()


def test_materialize_verifies_and_places_binary(tmp_path: Path) -> None:
    tarball = _tgz("package/bin/opencode", _script("1.18.31"))
    pin = _fake_pin(tarball)
    result = distribution.materialize(
        pin,
        "glibc",
        tmp_path / "out",
        tmp_path / "cache",
        fetch=lambda _url: tarball,
    )
    assert result["ok"] is True
    assert result["observedVersion"] == "1.18.31"
    assert result["flavor"] == "glibc"
    binary = Path(result["binary"])
    assert binary == (tmp_path / "out" / "opencode")
    assert stat.S_IMODE(binary.stat().st_mode) == 0o555
    assert result["binarySha256"] == distribution._sha256_bytes(binary.read_bytes())
    assert result["cacheSource"] == "download"

    # A second run reuses the verified cache without another fetch.
    reused = distribution.materialize(
        pin,
        "glibc",
        tmp_path / "out",
        tmp_path / "cache",
        fetch=lambda _url: pytest.fail("cache should avoid a second fetch"),
    )
    assert reused["cacheSource"] == "cache"
