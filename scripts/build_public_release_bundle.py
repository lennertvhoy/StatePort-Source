#!/usr/bin/env python3
"""Build a deterministic, unpublished successor source/release bundle.

This builder is deliberately independent of the signed release assembler.  It
works from one clean frozen Git commit, performs a credential-free read-only
clone/fetch from the declared public authority, and writes only to a new
external directory.  No publication, push, tag, registry, or signing action is
performed here.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from hashlib import md5, sha256
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit
import venv
import zipfile

import yaml

from materialize_public_snapshot import SnapshotBuildError, materialize_snapshot
from release_guard import ReleaseGuardError, require_guard
from validate_candidate_provenance import CandidateProvenanceError, verify_release_tree


ROOT = Path(__file__).resolve().parents[1]
CONTROLLED_GIT_CWD = Path("/")
GIT_SAFE_OPTIONS = (
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.fsmonitorHook=",
    "-c",
    "credential.helper=",
    "-c",
    "core.askPass=",
    "-c",
    "core.sshCommand=",
    "-c",
    "http.proxy=",
    "-c",
    "http.extraHeader=",
)
FORMAT = "stateport.public-release-bundle/v1"
PUBLIC_REF = "refs/heads/public-main"
GIT_BRANCH = "public-main"
RELEASE_VERSION = re.compile(
    r"^(?P<base>[0-9]+\.[0-9]+\.[0-9]+)-"
    r"(?:alpha\.(?P<alpha>[1-9][0-9]*)|j1\.(?P<j1>[0-9]+))$"
)
LOCKED_BUILD_VERSIONS = {"setuptools": "80.10.2", "wheel": "0.45.1"}
HTTPS_URL = re.compile(r"^https://[^\s?#]+$")
OID = re.compile(r"^[0-9a-f]{40}$")
UNTRUSTED_GIT_ENVIRONMENT = frozenset(
    {
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_ASKPASS",
        "GIT_COMMON_DIR",
        "GIT_CREDENTIAL_HELPER",
        "GIT_DIR",
        "GIT_GRAFT_FILE",
        "GIT_HTTP_EXTRAHEADER",
        "GIT_INDEX_FILE",
        "GIT_NAMESPACE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_REPLACE_REF_BASE",
        "GIT_SHALLOW_FILE",
        "GIT_WORK_TREE",
    }
)
PODMAN_PACKAGE_BUNDLE_SCHEMA = "stateport/podman-package-bundle/v2"
PODMAN_PACKAGE_TARGET = "wsl2-ubuntu2404-linux-amd64-rootless-podman-quadlet"
PODMAN_PACKAGE_ROOTFS = {
    "architecture": "amd64",
    "digest": "sha256:9b2f7730dc68227dd04a9f3e5eab86ad85caf556b8606ad94f1f29ff5c4fd3f5",
    "release": "24.04.4",
    "url": "https://releases.ubuntu.com/24.04.4/ubuntu-24.04.4-wsl-amd64.wsl",
}
PODMAN_REQUIRED_PACKAGES = frozenset({
    "aardvark-dns", "catatonit", "conmon", "containers-storage", "dbus-user-session",
    "fuse-overlayfs", "golang-github-containers-common", "golang-github-containers-image",
    "libslirp0", "libsubid4", "netavark", "podman", "python3-venv", "runc", "skopeo",
    "slirp4netns", "stateport-crun", "uidmap",
})
STATEPORT_CRUN_VERSION = "1.28-1stateport1~24.04.1"
STATEPORT_CRUN_UPSTREAM_VERSION = "1.28"
STATEPORT_CRUN_SHA256 = "2aa6b7024a9c9f153895c0d11ae233d3758f54844011c3a039e3e89048d01d42"
STATEPORT_CRUN_SOURCE_URL = (
    "https://github.com/containers/crun/releases/download/1.28/crun-1.28-linux-amd64"
)


def _release_version(value: str) -> re.Match[str]:
    matched = RELEASE_VERSION.fullmatch(value)
    if matched is None:
        raise PublicReleaseBuildError("release version must be an explicit alpha or local qualification version")
    return matched


def _release_notes(version: str) -> bytes:
    _release_version(version)
    return (
        f"# StatePort {version} WSL2 public-test candidate\n\n"
        "This signed candidate is intended for owner testing after publication. "
        "It packages the exact release-locked runtime inputs recorded by the candidate "
        "build and scan evidence. A real Windows 11, WSL2, and Ubuntu 24.04 clean-install "
        "receipt does not yet exist.\n"
    ).encode("utf-8")


def _known_limitations(version: str) -> bytes:
    _release_version(version)
    return (
        "# Known limitations\n\n"
        f"StatePort {version} targets Ubuntu 24.04 running under WSL2 on Windows 11. "
        "WSL1 is refused with `wsl1_substrate_unsupported` before provisioning-plan "
        "emission, install-state creation, receipt creation, or host mutation. Native "
        "Linux remains a separate signed target and does not inherit WSL2 qualification.\n\n"
        "Windows 11, WSL2, and Ubuntu identities remain evidence dimensions rather than "
        "substitutes for the required runtime capabilities. WSL2 is reported as "
        "`compatible_unvalidated` until a clean-install acceptance receipt exists. Human "
        "acceptance, independent security review, stability, and production qualification "
        "are not established.\n"
    ).encode("utf-8")


def _default_candidate_id(version: str, source_commit: str) -> str:
    matched = _release_version(version)
    if matched.group("alpha") is None:
        raise PublicReleaseBuildError("default candidate ID requires an explicit alpha version")
    return f"stateport-alpha{matched.group('alpha')}-{source_commit[:12]}"


class PublicReleaseBuildError(RuntimeError):
    """The local successor bundle could not be built fail-closed."""


@dataclass(frozen=True)
class Artifact:
    path: str
    sha256: str
    bytes: int


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode(
        "utf-8"
    )


def _sha(data: bytes) -> str:
    return sha256(data).hexdigest()


def _locked_inputs_digest(locked_wheels: Sequence[tuple[str, str, int]]) -> str:
    return _sha(
        _canonical_json(
            [
                {"filename": filename, "sha256": digest, "bytes": bytes_count}
                for filename, digest, bytes_count in locked_wheels
            ]
        )
    )


def _build_evidence(
    candidate_tree: str,
    locked_wheels: Sequence[tuple[str, str, int]],
    runtime: Mapping[str, str],
) -> dict[str, object]:
    return {
        "formatVersion": "stateport.updater-build-evidence/v1",
        "sourceTree": candidate_tree,
        "lockedInputsSha256": _locked_inputs_digest(locked_wheels),
        "runtime": dict(runtime),
    }


def _build_evidence_module(evidence: Mapping[str, object]) -> bytes:
    encoded = json.dumps(
        _canonical_json(evidence).decode("utf-8").rstrip("\n"), ensure_ascii=True
    )
    return f"STATEPORT_BUILD_EVIDENCE_JSON = {encoded}\n".encode("ascii")


def _https_authority(value: str, field: str) -> None:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise PublicReleaseBuildError(f"{field} must be an anonymous HTTPS URL")


def _artifact(path: Path, relative: str) -> Artifact:
    if path.is_symlink() or not path.is_file():
        raise PublicReleaseBuildError(f"release artifact is not a regular file: {relative}")
    data = path.read_bytes()
    return Artifact(relative, _sha(data), len(data))


def _podman_package_records(manifest: object) -> dict[str, Mapping[str, object]]:
    if (
        not isinstance(manifest, Mapping)
        or set(manifest) != {"install", "packages", "rootfs", "schema", "sourceDateEpoch", "target"}
        or manifest.get("schema") != PODMAN_PACKAGE_BUNDLE_SCHEMA
        or manifest.get("target") != PODMAN_PACKAGE_TARGET
        or manifest.get("rootfs") != PODMAN_PACKAGE_ROOTFS
        or not isinstance(manifest.get("sourceDateEpoch"), int)
        or int(manifest["sourceDateEpoch"]) < 1
        or not isinstance(manifest.get("packages"), list)
        or not len(PODMAN_REQUIRED_PACKAGES) <= len(manifest["packages"]) <= 128
    ):
        raise PublicReleaseBuildError("Podman package lock has an invalid shape or rootfs identity")
    records: dict[str, Mapping[str, object]] = {}
    filenames: set[str] = set()
    for value in manifest["packages"]:
        if (
            not isinstance(value, Mapping)
            or set(value) != {"architecture", "file", "name", "sha256", "size", "version"}
            or not isinstance(value.get("name"), str)
            or re.fullmatch(r"[a-z0-9][a-z0-9+.-]{0,127}", str(value["name"])) is None
            or value.get("architecture") not in {"all", "amd64"}
            or not isinstance(value.get("file"), str)
            or PurePosixPath(str(value["file"])).name != value["file"]
            or not str(value["file"]).endswith(f"_{value['architecture']}.deb")
            or not isinstance(value.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", str(value["sha256"])) is None
            or not isinstance(value.get("size"), int)
            or not 1 <= int(value["size"]) <= 512 * 1024 * 1024
            or not isinstance(value.get("version"), str)
            or not value["version"]
            or any(character.isspace() for character in str(value["version"]))
            or value["name"] in records
            or value["file"] in filenames
        ):
            raise PublicReleaseBuildError("Podman package lock contains an invalid package record")
        records[str(value["name"])] = value
        filenames.add(str(value["file"]))
    install = manifest.get("install")
    if (
        not PODMAN_REQUIRED_PACKAGES <= set(records)
        or install
        != {
            "packageNames": sorted(records),
            "packageVersions": {
                name: records[name]["version"] for name in sorted(records)
            },
        }
    ):
        raise PublicReleaseBuildError("Podman package lock is not a complete exact install inventory")
    return records


def _podman_package_bundle_metadata(path: Path) -> dict[str, object]:
    if path.is_symlink() or not path.is_file() or not 1 <= path.stat().st_size <= 512 * 1024 * 1024:
        raise PublicReleaseBuildError("Podman package bundle is unavailable, unsafe, or oversized")
    try:
        archive = tarfile.open(path, mode="r:")
    except tarfile.TarError as exc:
        raise PublicReleaseBuildError("Podman package bundle must be an uncompressed tar") from exc
    with archive:
        members = archive.getmembers()
        if not members or len(members) > 256:
            raise PublicReleaseBuildError("Podman package bundle member inventory is invalid")
        normalized: dict[str, tarfile.TarInfo] = {}
        total = 0
        for member in members:
            name = member.name.rstrip("/") if member.isdir() else member.name
            relative = PurePosixPath(name)
            if (
                not name
                or relative.is_absolute()
                or any(part in {"", ".", ".."} for part in relative.parts)
                or relative.parts[0] != "podman-package-bundle"
                or name in normalized
                or not (member.isdir() or member.isfile())
                or bool(getattr(member, "sparse", None))
            ):
                raise PublicReleaseBuildError("Podman package bundle contains an unsafe member")
            total += member.size
            if total > 512 * 1024 * 1024:
                raise PublicReleaseBuildError("Podman package bundle expands beyond its bound")
            normalized[name] = member

        def content(name: str, maximum: int = 1024 * 1024) -> bytes:
            member = normalized.get(name)
            if member is None or not member.isfile() or member.size > maximum:
                raise PublicReleaseBuildError(f"Podman package bundle member is unavailable: {name}")
            stream = archive.extractfile(member)
            if stream is None:
                raise PublicReleaseBuildError(f"Podman package bundle member cannot be read: {name}")
            with stream:
                return stream.read(maximum + 1)

        manifest_bytes = content("podman-package-bundle/manifest.json")
        try:
            manifest = json.loads(manifest_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PublicReleaseBuildError("Podman package bundle manifest is invalid JSON") from exc
        records = _podman_package_records(manifest)
        if manifest_bytes != _canonical_json(manifest):
            raise PublicReleaseBuildError("Podman package bundle manifest is not canonical lock bytes")
        expected_names = {"podman-package-bundle", "podman-package-bundle/SHA256SUMS",
                          "podman-package-bundle/manifest.json", "podman-package-bundle/packages"}
        expected_sums: list[str] = []
        for record in records.values():
            name = f"podman-package-bundle/packages/{record['file']}"
            payload = content(name, 512 * 1024 * 1024)
            if len(payload) != record["size"] or _sha(payload) != record["sha256"]:
                raise PublicReleaseBuildError("Podman package bundle bytes differ from its lock")
            expected_names.add(name)
            expected_sums.append(f"{record['sha256']}  packages/{record['file']}")
        sums = content("podman-package-bundle/SHA256SUMS")
        if sums != ("\n".join(sorted(expected_sums)) + "\n").encode("ascii"):
            raise PublicReleaseBuildError("Podman package bundle checksum inventory is not exact")
        if set(normalized) != expected_names:
            raise PublicReleaseBuildError("Podman package bundle carries an unowned member")
    return {"manifestSha256": _sha(manifest_bytes), "packageCount": len(records),
            "rootfsIdentity": dict(PODMAN_PACKAGE_ROOTFS)}


def _tar_info(name: str, *, size: int = 0, directory: bool = False) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
    info.mode = 0o755 if directory else 0o644
    info.mtime = info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.size = size
    return info


def _deterministic_tar_bytes(
    entries: Sequence[tuple[str, bytes | None, int]], *, epoch: int
) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for name, payload, mode in entries:
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE if payload is None else tarfile.REGTYPE
            info.size = 0 if payload is None else len(payload)
            info.mode = mode
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            info.mtime = epoch
            archive.addfile(info, None if payload is None else io.BytesIO(payload))
    return stream.getvalue()


def _ar_member(name: str, payload: bytes, *, epoch: int) -> bytes:
    archive_name = name + "/"
    if len(archive_name) > 16:
        raise PublicReleaseBuildError(f"Debian ar member name is too long: {name}")
    header = (
        f"{archive_name:<16}{epoch:<12}{0:<6}{0:<6}{'100644':<8}{len(payload):<10}`\n"
    ).encode("ascii")
    if len(header) != 60:
        raise PublicReleaseBuildError("Debian ar member header is malformed")
    return header + payload + (b"\n" if len(payload) % 2 else b"")


def _stateport_crun_deb(binary: bytes, *, epoch: int) -> bytes:
    control = (
        "Package: stateport-crun\n"
        f"Version: {STATEPORT_CRUN_VERSION}\n"
        "Section: admin\n"
        "Priority: optional\n"
        "Architecture: amd64\n"
        "Maintainer: StatePort release engineering <release-engineering@stateport.invalid>\n"
        "Homepage: https://github.com/containers/crun\n"
        "Description: pinned static crun runtime for StatePort confined groups\n"
        " StatePort selects this runtime explicitly for rootless units whose narrow\n"
        " Unix-socket contract requires OCI keep-groups semantics.\n"
    ).encode("utf-8")
    provenance = _json_bytes(
        {
            "architecture": "linux-amd64",
            "binaryPath": "/usr/libexec/stateport/crun",
            "license": "GPL-2.0-or-later",
            "name": "crun",
            "sha256": "sha256:" + STATEPORT_CRUN_SHA256,
            "source": STATEPORT_CRUN_SOURCE_URL,
            "version": STATEPORT_CRUN_UPSTREAM_VERSION,
        }
    )
    copyright_notice = (
        "This package redistributes the official crun 1.28 static Linux AMD64 release binary.\n"
        f"Source: {STATEPORT_CRUN_SOURCE_URL}\n"
        "License: GPL-2.0-or-later\n"
        "Upstream copyright belongs to Giuseppe Scrivano and the crun contributors.\n"
        "The complete corresponding source is available from the upstream release repository.\n"
    ).encode("utf-8")
    data_files = {
        "usr/libexec/stateport/crun": binary,
        "usr/share/doc/stateport-crun/copyright": copyright_notice,
        "usr/share/doc/stateport-crun/runtime-source.json": provenance,
    }
    md5sums = (
        "\n".join(
            f"{md5(payload, usedforsecurity=False).hexdigest()}  {name}"
            for name, payload in sorted(data_files.items())
        )
        + "\n"
    ).encode("ascii")
    control_tar = _deterministic_tar_bytes(
        [
            ("./", None, 0o755),
            ("./control", control, 0o644),
            ("./md5sums", md5sums, 0o644),
        ],
        epoch=epoch,
    )
    data_tar = _deterministic_tar_bytes(
        [
            ("./", None, 0o755),
            ("./usr/", None, 0o755),
            ("./usr/libexec/", None, 0o755),
            ("./usr/libexec/stateport/", None, 0o755),
            ("./usr/libexec/stateport/crun", binary, 0o755),
            ("./usr/share/", None, 0o755),
            ("./usr/share/doc/", None, 0o755),
            ("./usr/share/doc/stateport-crun/", None, 0o755),
            ("./usr/share/doc/stateport-crun/copyright", copyright_notice, 0o644),
            ("./usr/share/doc/stateport-crun/runtime-source.json", provenance, 0o644),
        ],
        epoch=epoch,
    )
    preset = 9 | lzma.PRESET_EXTREME
    members = (
        ("debian-binary", b"2.0\n"),
        ("control.tar.xz", lzma.compress(control_tar, format=lzma.FORMAT_XZ, preset=preset)),
        ("data.tar.xz", lzma.compress(data_tar, format=lzma.FORMAT_XZ, preset=preset)),
    )
    return b"!<arch>\n" + b"".join(
        _ar_member(name, payload, epoch=epoch) for name, payload in members
    )


def build_stateport_crun_package(*, binary: Path, output: Path, epoch: int) -> dict[str, object]:
    """Package the exact upstream static crun binary as a reproducible Debian input."""

    if (
        binary.is_symlink()
        or not binary.is_file()
        or _sha(binary.read_bytes()) != STATEPORT_CRUN_SHA256
    ):
        raise PublicReleaseBuildError("static crun input is absent or differs from the pinned hash")
    version = subprocess.run(
        [str(binary.resolve()), "--version"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        shell=False,
        stdin=subprocess.DEVNULL,
    )
    if version.returncode != 0 or version.stdout.splitlines()[:1] != ["crun version 1.28"]:
        raise PublicReleaseBuildError("static crun input does not report the pinned version")
    if epoch < 1 or output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise PublicReleaseBuildError("stateport-crun output or source epoch is invalid")
    payload = _stateport_crun_deb(binary.read_bytes(), epoch=epoch)
    if payload != _stateport_crun_deb(binary.read_bytes(), epoch=epoch):
        raise PublicReleaseBuildError("stateport-crun package build is not deterministic")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        metadata = subprocess.run(
            ["dpkg-deb", "--field", str(temporary), "Package", "Version", "Architecture"],
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
            shell=False,
            stdin=subprocess.DEVNULL,
        )
        fields = dict(line.split(": ", 1) for line in metadata.stdout.splitlines() if ": " in line)
        if metadata.returncode != 0 or fields != {
            "Package": "stateport-crun",
            "Version": STATEPORT_CRUN_VERSION,
            "Architecture": "amd64",
        }:
            raise PublicReleaseBuildError("generated stateport-crun Debian metadata is invalid")
        os.rename(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
    return {
        "formatVersion": "stateport.runtime-package-build/v1",
        "output": str(output),
        "package": "stateport-crun",
        "version": STATEPORT_CRUN_VERSION,
        "architecture": "amd64",
        "upstreamSha256": STATEPORT_CRUN_SHA256,
        "sha256": _sha(output.read_bytes()),
        "bytes": output.stat().st_size,
    }


def build_podman_package_bundle(*, lock: Path, package_dir: Path, output: Path) -> dict[str, object]:
    """Create one deterministic plain-tar package closure from an exact JSON lock."""

    if lock.is_symlink() or not lock.is_file() or lock.stat().st_size > 1024 * 1024:
        raise PublicReleaseBuildError("Podman package lock is unavailable or unsafe")
    try:
        manifest = json.loads(lock.read_bytes())
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PublicReleaseBuildError("Podman package lock is invalid JSON") from exc
    records = _podman_package_records(manifest)
    if package_dir.is_symlink() or not package_dir.is_dir():
        raise PublicReleaseBuildError("Podman package directory is unavailable or unsafe")
    actual_names = {path.name for path in package_dir.iterdir()
                    if path.is_file() and not path.is_symlink()}
    expected_names = {str(record["file"]) for record in records.values()}
    if actual_names != expected_names or any(
        path.is_symlink() or not path.is_file() for path in package_dir.iterdir()
    ):
        raise PublicReleaseBuildError("Podman package directory does not equal the lock inventory")
    package_bytes: dict[str, bytes] = {}
    for record in records.values():
        package = package_dir / str(record["file"])
        payload = package.read_bytes()
        package_bytes[str(record["file"])] = payload
        if len(payload) != record["size"] or _sha(payload) != record["sha256"]:
            raise PublicReleaseBuildError("Podman package bytes differ from the lock")
        completed = subprocess.run(
            ["dpkg-deb", "--field", str(package), "Package", "Version", "Architecture"],
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
            shell=False,
            stdin=subprocess.DEVNULL,
        )
        fields = dict(line.split(": ", 1) for line in completed.stdout.splitlines() if ": " in line)
        if completed.returncode != 0 or fields != {
            "Package": record["name"],
            "Version": record["version"],
            "Architecture": record["architecture"],
        }:
            raise PublicReleaseBuildError("Podman package Debian metadata differs from the lock")
    if output.exists() or output.is_symlink() or not output.parent.is_dir() or output.parent.is_symlink():
        raise PublicReleaseBuildError("Podman package bundle output must be a new file in a safe directory")
    manifest_bytes = _canonical_json(manifest)
    sums = ("\n".join(sorted(f"{record['sha256']}  packages/{record['file']}"
                              for record in records.values())) + "\n").encode("ascii")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    temporary.unlink()
    try:
        with tarfile.open(temporary, mode="x", format=tarfile.GNU_FORMAT) as archive:
            for name in ("podman-package-bundle", "podman-package-bundle/packages"):
                archive.addfile(_tar_info(name, directory=True))
            for name, payload in (
                ("podman-package-bundle/SHA256SUMS", sums),
                ("podman-package-bundle/manifest.json", manifest_bytes),
            ):
                archive.addfile(_tar_info(name, size=len(payload)), io.BytesIO(payload))
            for record in sorted(records.values(), key=lambda item: str(item["file"])):
                payload = package_bytes[str(record["file"])]
                name = f"podman-package-bundle/packages/{record['file']}"
                archive.addfile(_tar_info(name, size=len(payload)), io.BytesIO(payload))
        with temporary.open("rb") as stream:
            os.fsync(stream.fileno())
        metadata = _podman_package_bundle_metadata(temporary)
        os.rename(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
    return {"formatVersion": "stateport.podman-package-bundle-build/v1", "output": str(output),
            "sha256": _sha(output.read_bytes()), "bytes": output.stat().st_size, **metadata}


def _hermetic_git_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
        }
    )
    return environment


def _git(repository: Path, arguments: Sequence[str], *, text: bool = True) -> str | bytes:
    result = subprocess.run(
        ["git", *GIT_SAFE_OPTIONS, "-C", str(repository), *arguments],
        check=False,
        capture_output=True,
        text=text,
        cwd=CONTROLLED_GIT_CWD,
        env=_hermetic_git_environment(),
    )
    if result.returncode != 0:
        detail = result.stderr.strip() if isinstance(result.stderr, str) else ""
        raise PublicReleaseBuildError(f"Git operation failed: {' '.join(arguments)} {detail}".strip())
    return result.stdout


def _credential_free_git(arguments: Sequence[str], *, cwd: Path | None = None) -> str:
    environment = _hermetic_git_environment()
    environment.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    result = subprocess.run(
        ["git", *GIT_SAFE_OPTIONS, *arguments],
        check=False,
        capture_output=True,
        text=True,
        cwd=CONTROLLED_GIT_CWD,
        env=environment,
    )
    if result.returncode != 0:
        detail = result.stderr.strip()
        raise PublicReleaseBuildError(f"credential-free Git operation failed: {detail}")
    return result.stdout


def _git_blob(source: Path, commit: str, path: str) -> tuple[str, bytes]:
    listing = str(_git(source, ["ls-tree", commit, "--", path])).strip().split()
    if len(listing) != 4 or listing[1] != "blob" or listing[3] != path:
        raise PublicReleaseBuildError(f"frozen source blob is unavailable: {path}")
    data = _git(source, ["cat-file", "blob", listing[2]], text=False)
    assert isinstance(data, bytes)
    return listing[2], data


def _external_new_directory(source: Path, value: Path, field: str) -> Path:
    source = source.resolve(strict=True)
    candidate = value.expanduser().resolve()
    if candidate == source or source in candidate.parents:
        raise PublicReleaseBuildError(f"{field} must be outside the source repository")
    if candidate.exists() or candidate.is_symlink():
        raise PublicReleaseBuildError(f"{field} must be a new directory")
    if not candidate.parent.is_dir() or candidate.parent.is_symlink():
        raise PublicReleaseBuildError(f"{field} parent must be an existing real directory")
    return candidate


def _write_new(path: Path, data: bytes, *, mode: int = 0o644) -> None:
    if path.exists() or path.is_symlink():
        raise PublicReleaseBuildError(f"output already exists: {path}")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(path, mode)


def _copy_new(source: Path, target: Path, *, mode: int | None = None) -> None:
    data = source.read_bytes()
    _write_new(target, data, mode=mode if mode is not None else 0o644)


def _validate_source(source: Path, commit: str) -> tuple[str, int, dict[str, object]]:
    source = source.resolve(strict=True)
    if OID.fullmatch(commit) is None:
        raise PublicReleaseBuildError("source payload must name one exact full commit")
    if str(_git(source, ["status", "--porcelain=v1", "--untracked-files=all"])).strip():
        raise PublicReleaseBuildError("source worktree must be clean")
    observed = str(_git(source, ["rev-parse", "--verify", f"{commit}^{{commit}}"])).strip()
    head = str(_git(source, ["rev-parse", "--verify", "HEAD"])).strip()
    if observed != commit or OID.fullmatch(head) is None:
        raise PublicReleaseBuildError("source payload commit did not resolve exactly")
    try:
        _git(source, ["merge-base", "--is-ancestor", commit, head])
    except PublicReleaseBuildError as exc:
        raise PublicReleaseBuildError(
            "source payload commit must be an ancestor of current controller HEAD"
        ) from exc
    controller_tree = str(_git(source, ["rev-parse", "HEAD^{tree}"])).strip()
    if OID.fullmatch(controller_tree) is None:
        raise PublicReleaseBuildError("source controller tree is not an exact full tree")
    epoch_text = str(_git(source, ["show", "-s", "--format=%ct", commit])).strip()
    if not epoch_text.isdigit():
        raise PublicReleaseBuildError("source commit timestamp is invalid")
    tree = str(_git(source, ["rev-parse", f"{commit}^{{tree}}"])).strip()
    return tree, int(epoch_text), {
        "commit": head,
        "tree": controller_tree,
        "payloadRelationship": "equal" if commit == head else "payload-is-ancestor",
        "buildTool": {
            "path": "scripts/build_public_release_bundle.py",
            "sha256": _sha(Path(__file__).resolve().read_bytes()),
        },
    }


def _clone_frozen_payload_source(source: Path, commit: str, destination: Path) -> Path:
    """Present a validated frozen ancestor as an exact-HEAD source checkout."""

    source = source.resolve(strict=True)
    destination = destination.expanduser().resolve()
    if (
        destination.exists()
        or destination.is_symlink()
        or not destination.parent.is_dir()
        or destination.parent.is_symlink()
    ):
        raise PublicReleaseBuildError("frozen payload clone must be a new safe directory")
    expected_tree = str(_git(source, ["rev-parse", "--verify", f"{commit}^{{tree}}"])).strip()
    result = subprocess.run(
        [
            "git",
            *GIT_SAFE_OPTIONS,
            "clone",
            "--quiet",
            "--no-checkout",
            "--no-hardlinks",
            "--no-tags",
            str(source),
            str(destination),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=CONTROLLED_GIT_CWD,
        env=_hermetic_git_environment(),
    )
    if result.returncode != 0:
        raise PublicReleaseBuildError(
            f"frozen payload clone failed: {result.stderr.strip() or 'Git clone failed'}"
        )
    _git(destination, ["checkout", "--quiet", "--detach", commit])
    _git(destination, ["remote", "remove", "origin"])
    observed_head = str(_git(destination, ["rev-parse", "--verify", "HEAD"])).strip()
    observed_tree = str(_git(destination, ["rev-parse", "--verify", "HEAD^{tree}"])).strip()
    status = str(
        _git(
            destination,
            ["status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none"],
        )
    ).strip()
    if observed_head != commit or observed_tree != expected_tree or status:
        raise PublicReleaseBuildError("frozen payload clone identity or cleanliness mismatched")
    return destination


def _normal_clone_receipt(
    clone_parent: Path, *, authority_url: str, ref: str, commit: str, tree: str
) -> dict[str, object]:
    _https_authority(authority_url, "public Git authority")
    if clone_parent.is_symlink() or not clone_parent.is_dir():
        raise PublicReleaseBuildError("anonymous normal-clone parent is not a directory")
    branch = ref.removeprefix("refs/heads/")
    if not branch or "/" in branch or ".." in branch:
        raise PublicReleaseBuildError("normal-clone ref is not a safe branch name")
    remote_lines = _credential_free_git(["ls-remote", "--heads", authority_url, ref]).splitlines()
    if remote_lines != [f"{commit}\t{ref}"]:
        raise PublicReleaseBuildError("public Git authority did not return the exact requested ref")
    with tempfile.TemporaryDirectory(prefix="stateport-anonymous-clone-", dir=clone_parent) as temporary:
        clone = Path(temporary) / "clone"
        _credential_free_git(
            ["clone", "--quiet", "--no-tags", "--origin", "origin", authority_url, str(clone)]
        )
        _credential_free_git(
            ["-C", str(clone), "fetch", "--quiet", "--no-tags", "--prune", "origin", f"+{ref}:refs/remotes/origin/{branch}"]
        )
        remote = _credential_free_git(["-C", str(clone), "remote", "get-url", "origin"]).strip()
        observed_commit = str(_git(clone, ["rev-parse", "--verify", f"refs/remotes/origin/{branch}"])).strip()
        observed_tree = str(_git(clone, ["rev-parse", "--verify", f"refs/remotes/origin/{branch}^{{tree}}"])).strip()
        if remote != authority_url or observed_commit != commit or observed_tree != tree:
            raise PublicReleaseBuildError("credential-free clone identity does not match authority")
        if str(_git(clone, ["status", "--porcelain=v1", "--untracked-files=all"])).strip():
            raise PublicReleaseBuildError("credential-free clone is dirty")
        _git(clone, ["fsck", "--full", "--strict", "--no-reflogs"])
    if observed_commit != commit or observed_tree != tree:
        raise PublicReleaseBuildError("anonymous normal clone identity does not match candidate")
    payload = {
        "formatVersion": "stateport.anonymous-normal-clone-receipt/v1",
        "url": authority_url,
        "ref": ref,
        "commit": commit,
        "tree": tree,
        "verification": "credential-free-normal-clone-fetch-and-ls-remote",
    }
    canonical = _canonical_json(payload)
    digest = _sha(canonical)
    receipt = {**payload, "receiptId": "clone_receipt_" + digest[:32], "receiptSha256": digest}
    return receipt


def _local_qualification_clone_receipt(
    candidate: Path, *, authority_url: str, ref: str, commit: str, tree: str
) -> dict[str, object]:
    """Verify the materialized qualification ref through a local clone/recovery."""
    _https_authority(authority_url, "local qualification Git authority")
    if candidate.is_symlink() or not candidate.is_dir():
        raise PublicReleaseBuildError("local qualification candidate is not a directory")
    branch = ref.removeprefix("refs/heads/")
    if not branch or "/" in branch or ".." in branch:
        raise PublicReleaseBuildError("local qualification ref is not a safe branch name")
    source = candidate.resolve(strict=True)
    with tempfile.TemporaryDirectory(
        prefix="stateport-local-qualification-clone-", dir=source.parent
    ) as temporary:
        clone = Path(temporary) / "clone"
        _credential_free_git(
            ["clone", "--quiet", "--no-tags", "--origin", "origin", str(source), str(clone)]
        )
        remote = str(
            _credential_free_git(["-C", str(clone), "remote", "get-url", "origin"])
        ).strip()
        observed_commit = str(
            _git(clone, ["rev-parse", "--verify", f"refs/remotes/origin/{branch}"])
        ).strip()
        observed_tree = str(
            _git(clone, ["rev-parse", "--verify", f"refs/remotes/origin/{branch}^{{tree}}"])
        ).strip()
        if remote != str(source) or observed_commit != commit or observed_tree != tree:
            raise PublicReleaseBuildError("local qualification clone identity does not match candidate")
        if str(_git(clone, ["status", "--porcelain=v1", "--untracked-files=all"])).strip():
            raise PublicReleaseBuildError("local qualification clone is dirty")
        _git(clone, ["fsck", "--full", "--strict", "--no-reflogs"])
    payload = {
        "formatVersion": "stateport.local-qualification-clone-receipt/v1",
        "url": authority_url,
        "ref": ref,
        "commit": commit,
        "tree": tree,
        "verification": "local-clone-and-recovery-with-fsck",
    }
    digest = _sha(_canonical_json(payload))
    return {**payload, "receiptId": "clone_receipt_" + digest[:32], "receiptSha256": digest}


def _remote_ref_commit(*, authority_url: str, ref: str) -> str:
    lines = _credential_free_git(["ls-remote", "--heads", authority_url, ref]).splitlines()
    if len(lines) != 1:
        raise PublicReleaseBuildError("public Git authority did not return one exact requested ref")
    observed, observed_ref = lines[0].split("\t", 1)
    if observed_ref != ref or OID.fullmatch(observed) is None:
        raise PublicReleaseBuildError("public Git authority returned an invalid requested ref")
    return observed


def _bind_public_ref(candidate: Path, *, authority_url: str, ref: str, tree: str) -> str:
    commit = _remote_ref_commit(authority_url=authority_url, ref=ref)
    branch = ref.removeprefix("refs/heads/")
    _credential_free_git(
        [
            "-C",
            str(candidate),
            "fetch",
            "--quiet",
            "--no-tags",
            authority_url,
            f"+{ref}:refs/remotes/origin/{branch}",
        ]
    )
    observed_commit = str(_git(candidate, ["rev-parse", f"refs/remotes/origin/{branch}"])).strip()
    observed_tree = str(_git(candidate, ["rev-parse", f"{observed_commit}^{{tree}}"])).strip()
    if observed_commit != commit or observed_tree != tree:
        raise PublicReleaseBuildError("public Git authority tree does not match local materialization")
    _git(candidate, ["update-ref", f"refs/heads/{branch}", observed_commit])
    return commit


def _archive(
    candidate: Path,
    destination: Path,
    *,
    authority_url: str,
    ref: str,
    commit: str,
    tree: str,
    manifest_sha256: str,
    epoch: int,
) -> Artifact:
    identity = {
        "formatVersion": "stateport.public-source-identity/v1",
        "authorityUrl": authority_url,
        "ref": ref,
        "commit": commit,
        "tree": tree,
        "manifestSha256": manifest_sha256,
    }
    files: list[tuple[str, bytes, int]] = []
    for path in sorted(candidate.rglob("*"), key=lambda item: item.relative_to(candidate).as_posix()):
        if not path.is_file() or path.is_symlink() or ".git" in path.relative_to(candidate).parts:
            continue
        relative = path.relative_to(candidate).as_posix()
        files.append((relative, path.read_bytes(), path.stat().st_mode & 0o777))
    files.append(("SOURCE-IDENTITY.json", _json_bytes(identity), 0o644))
    with tarfile.open(destination, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, data, mode in files:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755 if mode & 0o111 else 0o644
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = epoch
            archive.addfile(info, io.BytesIO(data))
    _verify_archive(destination, candidate, identity)
    return _artifact(destination, "source/stateport-source.tar")


def _verify_archive(archive_path: Path, candidate: Path, identity: Mapping[str, object]) -> None:
    expected = {
        path.relative_to(candidate).as_posix(): path.read_bytes()
        for path in candidate.rglob("*")
        if path.is_file() and not path.is_symlink() and ".git" not in path.relative_to(candidate).parts
    }
    expected["SOURCE-IDENTITY.json"] = _json_bytes(identity)
    try:
        with tarfile.open(archive_path, mode="r:") as archive:
            observed: dict[str, bytes] = {}
            for member in archive.getmembers():
                path = PurePosixPath(member.name)
                if (
                    path.is_absolute()
                    or any(part in {"", ".", ".."} for part in path.parts)
                    or not member.isfile()
                    or member.name in observed
                ):
                    raise PublicReleaseBuildError("source archive contains an unsafe entry")
                stream = archive.extractfile(member)
                if stream is None:
                    raise PublicReleaseBuildError("source archive entry is unreadable")
                observed[member.name] = stream.read()
    except tarfile.TarError as exc:
        raise PublicReleaseBuildError("source archive could not be read") from exc
    if observed != expected:
        raise PublicReleaseBuildError("source archive contents do not match candidate and identity")
    embedded = json.loads(observed["SOURCE-IDENTITY.json"])
    if embedded != identity:
        raise PublicReleaseBuildError("source archive embedded Git identity changed")


def _bundle(candidate: Path, destination: Path, *, commit: str, tree: str, ref: str) -> Artifact:
    first = destination.with_name(destination.name + ".first")
    deterministic_pack_options = [
        "-c",
        "pack.window=0",
        "-c",
        "pack.depth=0",
        "-c",
        "pack.threads=1",
        "-c",
        "pack.compression=0",
    ]
    for path in (first, destination):
        _git(candidate, [*deterministic_pack_options, "bundle", "create", str(path), ref])
        listed = str(_git(candidate, ["bundle", "list-heads", str(path)])).strip()
        if listed != f"{commit} {ref}":
            raise PublicReleaseBuildError("Git bundle does not contain the exact candidate ref")
        _git(candidate, ["bundle", "verify", str(path)])
    if first.read_bytes() != destination.read_bytes():
        raise PublicReleaseBuildError("Git bundle is not byte deterministic")
    first.unlink()
    with tempfile.TemporaryDirectory(prefix="stateport-bundle-check-") as temporary:
        recovered = Path(temporary) / "candidate"
        subprocess.run(
            ["git", *GIT_SAFE_OPTIONS, "clone", "--quiet", "--no-checkout", str(destination), str(recovered)],
            check=True,
            capture_output=True,
            cwd=CONTROLLED_GIT_CWD,
            env=_hermetic_git_environment(),
        )
        if str(_git(recovered, ["rev-parse", f"origin/{ref.removeprefix('refs/heads/')}"])).strip() != commit:
            raise PublicReleaseBuildError("Git bundle recovery commit changed")
        if str(_git(recovered, ["rev-parse", f"origin/{ref.removeprefix('refs/heads/')}^{{tree}}"])).strip() != tree:
            raise PublicReleaseBuildError("Git bundle recovery tree changed")
    return _artifact(destination, "source/stateport-public.git.bundle")


def _locked_wheels(wheelhouse: Path, lock: Path) -> list[tuple[str, str, int]]:
    values: list[tuple[str, str, int]] = []
    current: tuple[str, str] | None = None
    for line in lock.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if "==" in stripped:
            package, version = stripped.split("==", 1)
            current = (package.strip(), version.split()[0].strip())
        match = re.search(r"--hash=sha256:([0-9a-f]{64})", stripped)
        if match and current:
            package, version = current
            if LOCKED_BUILD_VERSIONS.get(package) != version:
                raise PublicReleaseBuildError(f"updater build lock has an unexpected tool version: {package}")
            prefix = f"{package.replace('-', '_').lower()}-{version}-"
            matches = sorted(wheelhouse.glob(f"{prefix}*.whl"))
            if len(matches) != 1 or _sha(matches[0].read_bytes()) != match.group(1):
                raise PublicReleaseBuildError(f"locked build wheel is unavailable or changed: {package}")
            _verify_locked_wheel(matches[0], package, version)
            values.append((matches[0].name, match.group(1), matches[0].stat().st_size))
            current = None
    packages = {name.split("-", 1)[0].replace("_", "-") for name, _digest, _size in values}
    if packages != set(LOCKED_BUILD_VERSIONS) or len(values) != len(packages):
        raise PublicReleaseBuildError("updater build lock did not resolve its two pinned wheels")
    return values


def _verify_locked_wheel(path: Path, package: str, version: str) -> None:
    try:
        with zipfile.ZipFile(path) as wheel:
            metadata_paths = [
                name
                for name in wheel.namelist()
                if name == f"{package}-{version}.dist-info/METADATA"
            ]
            if len(metadata_paths) != 1:
                raise PublicReleaseBuildError(f"locked build input is not a real wheel: {path.name}")
            metadata = wheel.read(metadata_paths[0]).decode("utf-8")
    except (OSError, UnicodeError, zipfile.BadZipFile) as exc:
        raise PublicReleaseBuildError(f"locked build input is not a real wheel: {path.name}") from exc
    fields = dict(
        line.split(": ", 1)
        for line in metadata.splitlines()
        if ": " in line and line.split(": ", 1)[0] in {"Name", "Version"}
    )
    if fields.get("Name", "").casefold().replace("-", "_") != package.casefold().replace("-", "_") or fields.get(
        "Version"
    ) != version:
        raise PublicReleaseBuildError(f"locked build wheel metadata does not match {package}=={version}")


def _python_build_environment(
    epoch: int,
    *,
    home: Path | None = None,
    python: Path | None = None,
    temporary: Path | None = None,
) -> dict[str, str]:
    python_bin = python.parent if python is not None else None
    temporary = temporary or Path("/tmp")
    return {
        "HOME": str(home or Path("/nonexistent")),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": f"{python_bin}:/usr/bin:/bin" if python_bin is not None else "/usr/bin:/bin",
        "PIP_CONFIG_FILE": os.devnull,
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_CACHE_DIR": "1",
        "PIP_NO_INDEX": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "SOURCE_DATE_EPOCH": str(epoch),
        "TMPDIR": str(temporary),
        "TZ": "UTC",
    }


def _runtime_identity(python: Path, environment: Mapping[str, str]) -> dict[str, str]:
    identity = subprocess.run(
        [
            str(python),
            "-c",
            "import importlib.metadata as m, json, platform, sys; print(json.dumps({'implementation': platform.python_implementation(), 'python': platform.python_version(), 'pip': m.version('pip'), 'setuptools': m.version('setuptools'), 'wheel': m.version('wheel')}, sort_keys=True))",
        ],
        cwd=Path("/"),
        env=dict(environment),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    try:
        values = json.loads(identity)
    except json.JSONDecodeError as exc:
        raise PublicReleaseBuildError("build runtime identity is not valid JSON") from exc
    pip_version = subprocess.run(
        [str(python), "-m", "pip", "--version"],
        cwd=Path("/"),
        env=dict(environment),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.split()[1]
    if values.get("pip") != pip_version:
        raise PublicReleaseBuildError("pip executable identity does not match installed pip")
    if values.get("setuptools") != LOCKED_BUILD_VERSIONS["setuptools"] or values.get("wheel") != LOCKED_BUILD_VERSIONS["wheel"]:
        raise PublicReleaseBuildError("build runtime tool identity does not match locked versions")
    return {
        "implementation": str(values["implementation"]),
        "pip": str(values["pip"]),
        "pipExecutable": "build-venv/bin/python -m pip",
        "python": str(values["python"]),
        "pythonExecutable": "build-venv/bin/python",
        "setuptools": str(values["setuptools"]),
        "wheel": str(values["wheel"]),
    }


def _build_wheel_once(
    python: Path, *, context: Path, wheelhouse: Path, output: Path, epoch: int, home: Path, temporary: Path
) -> Path:
    output.mkdir(mode=0o700)
    environment = _python_build_environment(epoch, home=home, python=python, temporary=temporary)
    subprocess.run(
        [
            str(python),
            "-m",
            "pip",
            "wheel",
            "--no-index",
            "--no-deps",
            "--no-build-isolation",
            "--find-links",
            str(wheelhouse),
            "--wheel-dir",
            str(output),
            str(context / "packages/updater"),
        ],
        cwd=Path("/"),
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    wheels = sorted(output.glob("stateport_updater-*.whl"))
    if len(wheels) != 1:
        raise PublicReleaseBuildError("updater build did not produce exactly one wheel")
    return wheels[0]


def build_updater_wheel(
    candidate: Path, *, wheelhouse: Path, epoch: int, temporary: Path
) -> tuple[bytes, str, str, list[tuple[str, str, int]], dict[str, object]]:
    lock = candidate / "packages/updater/build-requirements.lock"
    if not lock.is_file() or wheelhouse.is_symlink() or not wheelhouse.is_dir():
        raise PublicReleaseBuildError("locked updater wheelhouse or lock file is unavailable")
    locked = _locked_wheels(wheelhouse, lock)
    candidate_tree = str(_git(candidate, ["rev-parse", "HEAD^{tree}"])).strip()
    context = temporary / "wheel-context"
    shutil.copytree(candidate, context, ignore=shutil.ignore_patterns(".git", "__pycache__"))
    evidence_path = context / "packages/updater/src/stateport_updater/_build_identity.py"
    if evidence_path.exists() or evidence_path.is_symlink():
        raise PublicReleaseBuildError("updater source already contains the reserved build evidence module")
    build_env = temporary / "build-venv"
    home = temporary / "build-home"
    build_tmp = temporary / "build-tmp"
    home.mkdir(mode=0o700)
    build_tmp.mkdir(mode=0o700)
    venv.EnvBuilder(with_pip=False, clear=True).create(build_env)
    python = build_env / "bin/python"
    environment = _python_build_environment(epoch, home=home, python=python, temporary=build_tmp)
    subprocess.run(
        [str(python), "-m", "ensurepip", "--upgrade"],
        cwd=Path("/"),
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [
            str(python),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--find-links",
            str(wheelhouse),
            "--require-hashes",
            "-r",
            str(context / "packages/updater/build-requirements.lock"),
        ],
        cwd=Path("/"),
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    runtime = _runtime_identity(python, environment)
    evidence = _build_evidence(candidate_tree, locked, runtime)
    evidence_path.write_bytes(_build_evidence_module(evidence))
    first = _build_wheel_once(
        python,
        context=context,
        wheelhouse=wheelhouse,
        output=temporary / "wheel-first",
        epoch=epoch,
        home=home,
        temporary=build_tmp,
    )
    second = _build_wheel_once(
        python,
        context=context,
        wheelhouse=wheelhouse,
        output=temporary / "wheel-second",
        epoch=epoch,
        home=home,
        temporary=build_tmp,
    )
    first_bytes = first.read_bytes()
    second_bytes = second.read_bytes()
    if first_bytes != second_bytes:
        raise PublicReleaseBuildError("updater wheel builds are not byte equal")
    return first_bytes, _sha(first_bytes), _sha(second_bytes), locked, evidence


def _source_input_manifest(
    source: Path,
    *,
    commit: str,
    tree: str,
    authority_url: str,
    ref: str,
    detector: Path,
    locked_wheels: Sequence[tuple[str, str, int]],
    policy_path: str,
    podman_package_bundle: Path | None,
    podman_package_metadata: Mapping[str, object] | None,
) -> bytes:
    paths = [
        policy_path,
        "packages/execution-host/src/execution_host/identity-contract.v1.json",
        "packages/execution-host/src/execution_host/identity_contract.py",
        "packages/updater/build-requirements.lock",
        "packages/updater/pyproject.toml",
        "scripts/build_public_release_bundle.py",
        "scripts/export_public_candidate.py",
        "scripts/install_no_checkout.py",
        "scripts/stateport-execution-host-provision",
        "scripts/materialize_public_snapshot.py",
        "scripts/public_snapshot_audit.py",
    ]
    inputs: list[dict[str, object]] = []
    for path in paths:
        blob, data = _git_blob(source, commit, path)
        inputs.append({"path": path, "gitBlob": blob, "sha256": _sha(data), "bytes": len(data)})
    external_inputs: dict[str, object] = {
        "privateDetectorSet": {
            "sha256": _sha(detector.read_bytes()),
            "bytes": detector.stat().st_size,
        },
        "lockedBuildInputsSha256": _locked_inputs_digest(locked_wheels),
        "lockedBuildWheels": [
            {
                "filename": filename,
                "path": f"evidence/locked-build-inputs/{filename}",
                "sha256": digest,
                "bytes": bytes_count,
            }
            for filename, digest, bytes_count in locked_wheels
        ],
    }
    if podman_package_bundle is not None:
        if podman_package_metadata is None:
            raise PublicReleaseBuildError("Podman package bundle metadata is unavailable")
        builder = next(item for item in inputs if item["path"] == "scripts/build_public_release_bundle.py")
        external_inputs["podmanPackageBundle"] = {
            "path": "packages/podman-package-bundle.tar",
            "sha256": _sha(podman_package_bundle.read_bytes()),
            "bytes": podman_package_bundle.stat().st_size,
            "manifestSha256": podman_package_metadata["manifestSha256"],
            "packageCount": podman_package_metadata["packageCount"],
            "rootfsIdentity": podman_package_metadata["rootfsIdentity"],
            "construction": {
                "builderSourcePath": builder["path"],
                "builderGitBlob": builder["gitBlob"],
                "builderSha256": builder["sha256"],
            },
        }
    return _json_bytes(
        {
            "formatVersion": "stateport.candidate-input-manifest/v1",
            "authority": {"url": authority_url, "ref": ref},
            "source": {"commit": commit, "tree": tree},
            "trackedInputs": inputs,
            "externalInputs": external_inputs,
        }
    )


def _release_manifest(root: Path) -> bytes:
    entries: list[dict[str, object]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if not path.is_file() or path.is_symlink() or path.relative_to(root).as_posix() in {
            "bundle-receipt.json",
            "provenance/candidate-provenance.yaml",
            "release-tree-manifest.json",
        }:
            continue
        relative = path.relative_to(root).as_posix()
        item = _artifact(path, relative)
        mode_bits = stat.S_IMODE(path.stat().st_mode)
        if mode_bits not in {0o644, 0o755}:
            raise PublicReleaseBuildError(f"release tree contains an unsupported file mode: {relative}")
        mode = f"{mode_bits:04o}"
        entries.append({"path": item.path, "sha256": item.sha256, "bytes": item.bytes, "mode": mode})
    return _json_bytes(
        {
            "formatVersion": "stateport.release-tree-manifest/v1",
            "excludedPaths": [
                "bundle-receipt.json",
                "provenance/candidate-provenance.yaml",
                "release-tree-manifest.json",
            ],
            "files": entries,
        }
    )


def _validate_release_tree(root: Path, manifest_path: Path) -> None:
    try:
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PublicReleaseBuildError("release-tree manifest is not readable JSON") from exc
    if document.get("formatVersion") != "stateport.release-tree-manifest/v1":
        raise PublicReleaseBuildError("release-tree manifest format is unsupported")
    excluded = document.get("excludedPaths")
    if excluded != [
        "bundle-receipt.json",
        "provenance/candidate-provenance.yaml",
        "release-tree-manifest.json",
    ]:
        raise PublicReleaseBuildError("release-tree manifest has an unexpected exclusion set")
    raw_files = document.get("files")
    if not isinstance(raw_files, list):
        raise PublicReleaseBuildError("release-tree manifest files are not a list")
    actual: dict[str, Artifact] = {}
    actual_modes: dict[str, str] = {}
    for path in root.rglob("*"):
        if path.is_symlink():
            raise PublicReleaseBuildError("release tree contains a symlink")
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            actual[relative] = _artifact(path, relative)
            mode_bits = stat.S_IMODE(path.stat().st_mode)
            if mode_bits not in {0o644, 0o755}:
                raise PublicReleaseBuildError(f"release tree contains an unsupported file mode: {relative}")
            actual_modes[relative] = f"{mode_bits:04o}"
    observed: dict[str, Artifact] = {}
    for item in raw_files:
        if not isinstance(item, Mapping):
            raise PublicReleaseBuildError("release-tree manifest contains an invalid file entry")
        relative = item.get("path")
        if not isinstance(relative, str) or relative in observed or relative in excluded:
            raise PublicReleaseBuildError("release-tree manifest contains an unsafe or duplicate path")
        artifact = actual.get(relative)
        if artifact is None:
            raise PublicReleaseBuildError("release-tree manifest names a missing file")
        if (
            item.get("sha256") != artifact.sha256
            or item.get("bytes") != artifact.bytes
            or item.get("mode") != actual_modes[relative]
        ):
            raise PublicReleaseBuildError(f"release-tree manifest digest or size mismatch: {relative}")
        observed[relative] = artifact
    expected = set(actual) - set(excluded)
    if set(observed) != expected:
        raise PublicReleaseBuildError("release-tree manifest does not cover the final output tree")


def build_release_bundle(
    *,
    source: Path,
    source_commit: str,
    release_version: str,
    source_url: str,
    public_url: str,
    public_clone: Path,
    detector: Path,
    wheelhouse: Path,
    podman_package_bundle: Path | None = None,
    output: Path,
    policy_path: str = "config/public-export-allowlist.v1.yaml",
    candidate_id: str | None = None,
    qualification_local: bool = False,
    qualification_ref: str | None = None,
) -> dict[str, object]:
    version_match = _release_version(release_version)
    if HTTPS_URL.fullmatch(public_url) is None or HTTPS_URL.fullmatch(source_url) is None:
        raise PublicReleaseBuildError("source and public Git authorities must be HTTPS URLs without query text")
    _https_authority(source_url, "source Git authority")
    _https_authority(public_url, "public Git authority")
    if PUBLIC_REF != "refs/heads/public-main":
        raise PublicReleaseBuildError("public candidate ref is not the fixed public-main contract")
    source = source.resolve(strict=True)
    detector = detector.resolve(strict=True)
    wheelhouse = wheelhouse.resolve(strict=True)
    requires_package_bundle = qualification_local or (
        version_match.group("alpha") is not None
        and int(version_match.group("alpha")) >= 11
    )
    podman_package_metadata: Mapping[str, object] | None = None
    if requires_package_bundle:
        if (
            podman_package_bundle is None
            or podman_package_bundle.is_symlink()
            or not podman_package_bundle.is_file()
            or not 1 <= podman_package_bundle.stat().st_size <= 512 * 1024 * 1024
        ):
            raise PublicReleaseBuildError(
                "Alpha.11 and qualification builds require one bounded Podman package bundle"
            )
        podman_package_bundle = podman_package_bundle.resolve(strict=True)
        podman_package_metadata = _podman_package_bundle_metadata(podman_package_bundle)
    elif podman_package_bundle is not None:
        raise PublicReleaseBuildError(
            "Alpha.10 and earlier source bundles must retain their historical artifact inventory"
        )
    tree, epoch, controller = _validate_source(source, source_commit)
    output = _external_new_directory(source, output, "release output")
    candidate_id = candidate_id or _default_candidate_id(release_version, source_commit)
    if re.fullmatch(r"[a-z0-9][a-z0-9-]{2,127}", candidate_id) is None:
        raise PublicReleaseBuildError("candidate ID is not a normalized lowercase identifier")

    with tempfile.TemporaryDirectory(
        prefix="stateport-public-build-", dir=output.parent
    ) as temporary_name:
        temporary = Path(temporary_name)
        payload_source = _clone_frozen_payload_source(
            source, source_commit, temporary / "payload-source"
        )
        candidate = temporary / "candidate"
        evidence = temporary / "evidence"
        try:
            materialization = materialize_snapshot(
                payload_source,
                source_commit,
                policy_path,
                detector,
                candidate,
                evidence,
            )
        except SnapshotBuildError as exc:
            raise PublicReleaseBuildError(str(exc)) from exc
        materialized_commit = str(materialization["candidateHead"])
        candidate_tree = str(materialization["candidateTree"])
        if materialized_commit != str(_git(candidate, ["rev-parse", "HEAD"])).strip():
            raise PublicReleaseBuildError("materialization receipt candidate head drifted")
        if qualification_local:
            if qualification_ref is None or re.fullmatch(
                r"refs/heads/[A-Za-z0-9._/-]+", qualification_ref
            ) is None:
                raise PublicReleaseBuildError(
                    "local qualification builds require an exact qualification ref"
                )
            candidate_ref = qualification_ref
        else:
            candidate_ref = PUBLIC_REF
        if qualification_local:
            _git(candidate, ["branch", "-m", GIT_BRANCH, candidate_ref.removeprefix("refs/heads/")])
            candidate_commit = materialized_commit
        else:
            candidate_commit = _bind_public_ref(
                candidate,
                authority_url=public_url,
                ref=PUBLIC_REF,
                tree=candidate_tree,
            )
        materialization_receipt_path = evidence / "materialization-receipt.json"
        materialization_receipt = json.loads(materialization_receipt_path.read_text(encoding="utf-8"))
        materialization_receipt["candidateHead"] = candidate_commit
        materialization_receipt["candidateTree"] = candidate_tree
        materialization_receipt_path.write_bytes(_json_bytes(materialization_receipt))
        clone_receipt = (
            _local_qualification_clone_receipt(
                candidate,
                authority_url=public_url,
                ref=candidate_ref,
                commit=candidate_commit,
                tree=candidate_tree,
            )
            if qualification_local
            else _normal_clone_receipt(
                public_clone,
                authority_url=public_url,
                ref=candidate_ref,
                commit=candidate_commit,
                tree=candidate_tree,
            )
        )
        manifest = evidence / "public-export-manifest.json"
        rights = evidence / "rights-inventory.yaml"
        manifest_artifact = _artifact(manifest, "source/public-export-manifest.json")
        rights_artifact = _artifact(rights, "source/licensing-inventory.yaml")
        archive_path = temporary / "source.tar"
        archive_artifact = _archive(
            candidate,
            archive_path,
            authority_url=public_url,
            ref=candidate_ref,
            commit=candidate_commit,
            tree=candidate_tree,
            manifest_sha256=manifest_artifact.sha256,
            epoch=epoch,
        )
        bundle_path = temporary / "source.bundle"
        bundle_artifact = _bundle(
            candidate,
            bundle_path,
            commit=candidate_commit,
            tree=candidate_tree,
            ref=candidate_ref,
        )
        installer_blob, installer_data = _git_blob(source, source_commit, "scripts/install_no_checkout.py")
        del installer_blob
        if not installer_data.startswith(b"#!/usr/bin/env python3\n"):
            raise PublicReleaseBuildError("frozen installer is not the expected no-checkout Python artifact")
        provisioner_blob, provisioner_data = _git_blob(
            source, source_commit, "scripts/stateport-execution-host-provision"
        )
        del provisioner_blob
        if not provisioner_data.startswith(b"#!/bin/sh\n"):
            raise PublicReleaseBuildError("frozen execution-host provisioner is not the expected shell artifact")
        wheel_data, first_wheel_sha, second_wheel_sha, locked_wheels, wheel_evidence = build_updater_wheel(
            candidate, wheelhouse=wheelhouse, epoch=epoch, temporary=temporary
        )
        input_manifest_data = _source_input_manifest(
            source,
            commit=source_commit,
            tree=tree,
            authority_url=public_url,
            ref=candidate_ref,
            detector=detector,
            locked_wheels=locked_wheels,
            policy_path=policy_path,
            podman_package_bundle=podman_package_bundle,
            podman_package_metadata=podman_package_metadata,
        )

        output.mkdir(mode=0o700)
        _write_new(output / "installer/install.sh", installer_data, mode=0o755)
        _write_new(
            output / "provisioning/stateport-execution-host-provision",
            provisioner_data,
            mode=0o755,
        )
        _write_new(output / "updater/stateport-updater.whl", wheel_data)
        _write_new(output / "updater/stateport-updater-first.whl", wheel_data)
        _write_new(output / "updater/stateport-updater-second.whl", wheel_data)
        if podman_package_bundle is not None:
            _copy_new(
                podman_package_bundle,
                output / "packages/podman-package-bundle.tar",
            )
        _copy_new(archive_path, output / "source/stateport-source.tar")
        _copy_new(bundle_path, output / "source/stateport-public.git.bundle")
        _copy_new(manifest, output / "source/public-export-manifest.json")
        _copy_new(rights, output / "source/licensing-inventory.yaml")
        for filename, _digest, _bytes_count in locked_wheels:
            _copy_new(
                wheelhouse / filename,
                output / f"evidence/locked-build-inputs/{filename}",
            )
        _write_new(output / "evidence/anonymous-normal-clone-receipt.json", _json_bytes(clone_receipt))
        for evidence_name in (
            "gateway-receipt.json",
            "snapshot-audit.json",
            "exclusion-receipt.json",
            "licensing-receipt.json",
            "materialization-receipt.json",
            "audit-input.json",
        ):
            _copy_new(evidence / evidence_name, output / f"evidence/{evidence_name}")
        _write_new(
            output / "notes/release-notes.md",
            _release_notes(release_version),
        )
        _write_new(
            output / "limitations/known-limitations.md",
            _known_limitations(release_version),
        )
        _write_new(
            output / "sbom/source.cdx.json",
            _json_bytes({"bomFormat": "CycloneDX", "specVersion": "1.5", "status": "placeholder_pending_release_scan"}),
        )
        _write_new(
            output / "scans/source.json",
            _json_bytes({"formatVersion": "stateport.source-scan-placeholder/v1", "status": "placeholder_pending_release_scan"}),
        )
        _write_new(
            output / "signatures/release.sigstore.json",
            _json_bytes({"formatVersion": "stateport.signature-placeholder/v1", "status": "pending_owner_authorized_signing"}),
        )
        _write_new(
            output / "signatures/updater.sigstore.json",
            _json_bytes({"formatVersion": "stateport.signature-placeholder/v1", "status": "pending_owner_authorized_signing"}),
        )
        input_manifest_path = output / "candidate-input-manifest.json"
        _write_new(input_manifest_path, input_manifest_data)
        public_manifest_artifact = _artifact(
            output / "source/public-export-manifest.json", "source/public-export-manifest.json"
        )
        licensing_artifact = _artifact(
            output / "source/licensing-inventory.yaml", "source/licensing-inventory.yaml"
        )
        archive_artifact = _artifact(
            output / "source/stateport-source.tar", "source/stateport-source.tar"
        )
        bundle_artifact = _artifact(
            output / "source/stateport-public.git.bundle", "source/stateport-public.git.bundle"
        )
        installer_artifact = _artifact(output / "installer/install.sh", "installer/install.sh")
        provisioner_artifact = _artifact(
            output / "provisioning/stateport-execution-host-provision",
            "provisioning/stateport-execution-host-provision",
        )
        clone_artifact = _artifact(
            output / "evidence/anonymous-normal-clone-receipt.json",
            "evidence/anonymous-normal-clone-receipt.json",
        )
        wheel_artifact = _artifact(
            output / "updater/stateport-updater.whl", "updater/stateport-updater.whl"
        )
        first_wheel_artifact = _artifact(
            output / "updater/stateport-updater-first.whl", "updater/stateport-updater-first.whl"
        )
        second_wheel_artifact = _artifact(
            output / "updater/stateport-updater-second.whl", "updater/stateport-updater-second.whl"
        )
        input_artifact = _artifact(input_manifest_path, "candidate-input-manifest.json")
        package_bundle_artifact = (
            _artifact(
                output / "packages/podman-package-bundle.tar",
                "packages/podman-package-bundle.tar",
            )
            if podman_package_bundle is not None
            else None
        )
        result = {
            "formatVersion": FORMAT,
            "candidateId": candidate_id,
            "sourceCommit": source_commit,
            "sourceTree": tree,
            "controller": controller,
            "publicCommit": candidate_commit,
            "publicTree": candidate_tree,
            "publicAuthority": public_url,
            "publicRef": candidate_ref,
            "candidateInputManifestSha256": input_artifact.sha256,
            "status": "built_local_unpublished_pending_signing",
        }
        release_manifest_path = output / "release-tree-manifest.json"
        _write_new(release_manifest_path, _release_manifest(output))
        _validate_release_tree(output, release_manifest_path)
        release_manifest_artifact = _artifact(release_manifest_path, "release-tree-manifest.json")
        provenance = {
            "schema": "stateport.candidate-provenance/v2",
            "candidateId": candidate_id,
            "classification": (
                "local_qualification_candidate"
                if qualification_local
                else "public_successor_release_candidate"
            ),
            "authorityClass": (
                "local_qualification_git_authority_and_local_build_evidence"
                if qualification_local
                else "public_git_authority_and_local_build_evidence"
            ),
            "authoritativeForInstallation": False,
            "repository": {
                "authorityUrl": public_url,
                "ref": candidate_ref,
                "commit": candidate_commit,
                "tree": candidate_tree,
                "objectFormat": "sha1",
                "normalCloneVerification": {
                    "status": (
                        "verified_local_qualification_clone"
                        if qualification_local
                        else "verified_anonymous_normal_clone"
                    ),
                    "receiptId": clone_receipt["receiptId"],
                    "receiptSha256": clone_receipt["receiptSha256"],
                    "url": public_url,
                    "ref": candidate_ref,
                    "commit": candidate_commit,
                    "tree": candidate_tree,
                },
            },
            "materialization": {
                "sourceRepository": source_url,
                "sourceCommit": source_commit,
                "sourceTree": tree,
                "materializer": {"gitBlob": _git_blob(source, source_commit, "scripts/materialize_public_snapshot.py")[0], "sha256": _sha(_git_blob(source, source_commit, "scripts/materialize_public_snapshot.py")[1])},
                "exporter": {"gitBlob": _git_blob(source, source_commit, "scripts/export_public_candidate.py")[0], "sha256": _sha(_git_blob(source, source_commit, "scripts/export_public_candidate.py")[1])},
                "policy": {"gitBlob": _git_blob(source, source_commit, policy_path)[0], "sha256": _sha(_git_blob(source, source_commit, policy_path)[1])},
            },
            "artifacts": {
                "publicManifest": {"path": public_manifest_artifact.path, "sha256": public_manifest_artifact.sha256, "bytes": public_manifest_artifact.bytes},
                "licensingInventory": {"path": licensing_artifact.path, "sha256": licensing_artifact.sha256, "bytes": licensing_artifact.bytes},
                "normalCloneReceipt": {"path": clone_artifact.path, "sha256": clone_artifact.sha256, "bytes": clone_artifact.bytes},
                "sourceArchive": {"path": archive_artifact.path, "sha256": archive_artifact.sha256, "bytes": archive_artifact.bytes, "embeddedGitIdentity": {"authorityUrl": public_url, "ref": candidate_ref, "commit": candidate_commit, "tree": candidate_tree, "manifestSha256": public_manifest_artifact.sha256}},
                "gitBundle": {"path": bundle_artifact.path, "sha256": bundle_artifact.sha256, "bytes": bundle_artifact.bytes, "ref": candidate_ref, "commit": candidate_commit, "tree": candidate_tree},
                "installer": {"path": installer_artifact.path, "sha256": installer_artifact.sha256, "bytes": installer_artifact.bytes, "sourceCommit": source_commit, "sourcePath": "scripts/install_no_checkout.py"},
                "executionHostProvisioner": {"path": provisioner_artifact.path, "sha256": provisioner_artifact.sha256, "bytes": provisioner_artifact.bytes, "sourceCommit": source_commit, "sourcePath": "scripts/stateport-execution-host-provision"},
                **(
                    {
                        "podmanPackageBundle": {
                            "path": package_bundle_artifact.path,
                            "sha256": package_bundle_artifact.sha256,
                            "bytes": package_bundle_artifact.bytes,
                        }
                    }
                    if package_bundle_artifact is not None
                    else {}
                ),
                "updaterWheel": {"path": wheel_artifact.path, "sha256": wheel_artifact.sha256, "bytes": wheel_artifact.bytes, "firstPath": first_wheel_artifact.path, "secondPath": second_wheel_artifact.path, "reproducible": True, "firstSha256": first_wheel_sha, "secondSha256": second_wheel_sha, "firstBytes": first_wheel_artifact.bytes, "secondBytes": second_wheel_artifact.bytes, "buildEvidence": {"path": "stateport_updater/_build_identity.py", **wheel_evidence}},
                "candidateInputManifest": {"path": input_artifact.path, "sha256": input_artifact.sha256, "bytes": input_artifact.bytes},
                "releaseTreeManifest": {"path": release_manifest_artifact.path, "sha256": release_manifest_artifact.sha256, "bytes": release_manifest_artifact.bytes},
            },
            "verification": {
                "normalClone": (
                    "verified_local_qualification_clone"
                    if qualification_local
                    else "verified_anonymous_normal_clone"
                ),
                "sourceArchive": "verified_contents_and_embedded_git_identity",
                "gitBundle": "verified_ref_commit_tree_recovery",
                "updaterWheel": "verified_twice_byte_equal_from_locked_inputs",
                "signing": "pending_owner_authorized_signing",
            },
            "retention": {
                "status": "local_candidate_not_published",
                "retainUntil": "explicit_owner_disposition_or_superseding_verified_candidate",
                "deletionRequiresExplicitOwnerApproval": True,
            },
        }
        _write_new(output / "provenance/candidate-provenance.yaml", yaml.safe_dump(provenance, sort_keys=True).encode("utf-8"))
        provenance_artifact = _artifact(
            output / "provenance/candidate-provenance.yaml", "provenance/candidate-provenance.yaml"
        )
        result["releaseTreeManifestSha256"] = release_manifest_artifact.sha256
        result["provenance"] = {
            "path": provenance_artifact.path,
            "sha256": provenance_artifact.sha256,
            "bytes": provenance_artifact.bytes,
        }
        receipt_content = _canonical_json(result)
        bundle_receipt = {
            **result,
            "receiptContentSha256": _sha(receipt_content),
            "receiptContentBytes": len(receipt_content),
        }
        _write_new(output / "bundle-receipt.json", _json_bytes(bundle_receipt))
        try:
            verify_release_tree(provenance, output)
        except CandidateProvenanceError as exc:
            raise PublicReleaseBuildError(f"generated provenance does not bind the release tree: {exc}") from exc
        return result


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    guard_command = sys.argv if argv is None else [str(Path(__file__)), *arguments]
    if arguments[:1] == ["runtime-package"]:
        runtime_parser = argparse.ArgumentParser(
            description="Build the pinned StatePort crun Debian package"
        )
        runtime_parser.add_argument("command", choices=("runtime-package",))
        runtime_parser.add_argument("--binary", type=Path, required=True)
        runtime_parser.add_argument("--output", type=Path, required=True)
        runtime_parser.add_argument("--source-date-epoch", type=int, required=True)
        runtime_args = runtime_parser.parse_args(arguments)
        require_guard("candidate_construction", guard_command)
        result = build_stateport_crun_package(
            binary=runtime_args.binary,
            output=runtime_args.output,
            epoch=runtime_args.source_date_epoch,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if arguments[:1] == ["package-bundle"]:
        package_parser = argparse.ArgumentParser(
            description="Build a deterministic Podman package closure from an exact lock"
        )
        package_parser.add_argument("command", choices=("package-bundle",))
        package_parser.add_argument("--lock", type=Path, required=True)
        package_parser.add_argument("--package-dir", type=Path, required=True)
        package_parser.add_argument("--output", type=Path, required=True)
        package_args = package_parser.parse_args(arguments)
        require_guard("candidate_construction", guard_command)
        result = build_podman_package_bundle(
            lock=package_args.lock,
            package_dir=package_args.package_dir,
            output=package_args.output,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-url", required=True)
    parser.add_argument("--public-url", required=True)
    parser.add_argument("--clone-parent", "--public-clone", dest="clone_parent", type=Path, required=True)
    parser.add_argument("--private-detectors", type=Path, required=True)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    parser.add_argument("--podman-package-bundle", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--candidate-id")
    parser.add_argument("--policy", default="config/public-export-allowlist.v1.yaml")
    args = parser.parse_args(arguments)
    try:
        require_guard(
            "candidate_construction",
            guard_command,
        )
        result = build_release_bundle(
            source=args.source,
            source_commit=args.commit,
            release_version=args.version,
            source_url=args.source_url,
            public_url=args.public_url,
            public_clone=args.clone_parent,
            detector=args.private_detectors,
            wheelhouse=args.wheelhouse,
            podman_package_bundle=args.podman_package_bundle,
            output=args.output,
            policy_path=args.policy,
            candidate_id=args.candidate_id,
        )
    except (ReleaseGuardError, OSError, PublicReleaseBuildError, SnapshotBuildError, subprocess.CalledProcessError, yaml.YAMLError) as exc:
        print(json.dumps({"status": "blocked", "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
