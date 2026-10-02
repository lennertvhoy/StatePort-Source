#!/usr/bin/env python3
"""Materialize the pinned upstream OpenCode platform binary from npm.

This fetches only the exact tarball URL recorded in
``config/provider-runtime-inputs.yaml``, verifies its sha512 SRI integrity (and,
when recorded, the extracted binary's sha256), extracts ``package/bin/opencode``
at mode 0555, and refuses to finish unless the materialized binary reports the
pinned ``opencode --version``.

There is no fallback to ``latest``, to an unpinned URL, or to a cached artifact
whose bytes do not match the pin.  OpenCode is consumed as a maintained upstream
release; this script never builds or patches it.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from typing import Any, Callable, Mapping

import yaml


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUTS = ROOT / "config" / "provider-runtime-inputs.yaml"
DEFAULT_CACHE = (
    Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache")))
    / "stateport"
    / "opencode-distribution"
)
FLAVORS = ("glibc", "musl")
DEFAULT_VERSION_TIMEOUT = 60
PINNED_REGISTRY_PREFIX = "https://registry.npmjs.org/"
_SRI = re.compile(r"^sha512-[A-Za-z0-9+/]{86}==$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
Fetch = Callable[[str], bytes]


class OpenCodeDistributionError(ValueError):
    """The pinned OpenCode distribution does not meet the materialization contract."""


def _sha512_sri(data: bytes) -> str:
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode("ascii")


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def verify_integrity(data: bytes, expected: str, *, label: str = "opencode tarball") -> None:
    """Refuse bytes whose sha512 SRI differs from the pinned value."""

    if not isinstance(expected, str) or _SRI.fullmatch(expected) is None:
        raise OpenCodeDistributionError(f"{label} pin is not a sha512 SRI string")
    if _sha512_sri(data) != expected:
        raise OpenCodeDistributionError(f"{label} integrity differs from the pin")


def load_pin(inputs_path: Path) -> Mapping[str, Any]:
    """Read the reviewed ``opencode:`` block from the provider inputs."""

    try:
        document = yaml.safe_load(Path(inputs_path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise OpenCodeDistributionError(
            f"cannot read pinned provider inputs: {inputs_path}"
        ) from exc
    if not isinstance(document, Mapping):
        raise OpenCodeDistributionError("provider inputs are not a mapping")
    pin = document.get("opencode")
    if not isinstance(pin, Mapping):
        raise OpenCodeDistributionError("provider inputs have no opencode pin")
    for key in ("package", "version", "npm", "platforms"):
        if not pin.get(key):
            raise OpenCodeDistributionError(f"opencode pin is missing {key}")
    if not isinstance(pin["version"], str) or not pin["version"]:
        raise OpenCodeDistributionError("opencode pin version is invalid")
    return pin


def resolve_platform(pin: Mapping[str, Any], flavor: str) -> Mapping[str, Any]:
    """Resolve the exact platform package record for an explicit flavor."""

    if flavor not in FLAVORS:
        raise OpenCodeDistributionError(
            f"unsupported flavor {flavor!r}; supported flavors are {list(FLAVORS)}"
        )
    platforms = pin.get("platforms")
    if not isinstance(platforms, Mapping):
        raise OpenCodeDistributionError("opencode pin platforms are not a mapping")
    platform = platforms.get(flavor)
    if not isinstance(platform, Mapping):
        raise OpenCodeDistributionError(f"opencode pin has no {flavor} platform")
    for key in ("package", "tarball", "integrity", "binaryMember"):
        value = platform.get(key)
        if not isinstance(value, str) or not value:
            raise OpenCodeDistributionError(
                f"opencode {flavor} platform is missing {key}"
            )
    if _SRI.fullmatch(platform["integrity"]) is None:
        raise OpenCodeDistributionError(
            f"opencode {flavor} platform integrity is not a sha512 SRI string"
        )
    tarball = platform["tarball"]
    if not tarball.startswith(PINNED_REGISTRY_PREFIX):
        raise OpenCodeDistributionError(
            "opencode tarball must come from the pinned npm registry"
        )
    if platform["package"] not in tarball:
        raise OpenCodeDistributionError(
            "opencode tarball URL does not identify the pinned platform package"
        )
    return platform


def extract_binary(tarball_bytes: bytes, target_dir: Path, member: str) -> Path:
    """Extract exactly ``member`` to ``target_dir/opencode`` at mode 0555."""

    if not isinstance(member, str) or not member or member.startswith("/"):
        raise OpenCodeDistributionError("opencode binary member path is unsafe")
    if ".." in Path(member).parts:
        raise OpenCodeDistributionError("opencode binary member path is unsafe")
    target_dir = Path(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    destination = target_dir / "opencode"
    try:
        with tarfile.open(fileobj=io.BytesIO(tarball_bytes), mode="r:gz") as archive:
            found = next(
                (entry for entry in archive.getmembers() if entry.name == member), None
            )
            if found is None:
                raise OpenCodeDistributionError(f"tarball does not contain {member}")
            if not found.isfile() or found.issym() or found.islnk():
                raise OpenCodeDistributionError(f"{member} is not a regular file")
            stream = archive.extractfile(found)
            if stream is None:
                raise OpenCodeDistributionError(f"{member} could not be read")
            data = stream.read()
    except (tarfile.TarError, OSError) as exc:
        raise OpenCodeDistributionError(
            "opencode tarball is not a readable gzip archive"
        ) from exc
    temporary = destination.with_name(destination.name + f".tmp-{os.getpid()}")
    temporary.write_bytes(data)
    os.chmod(temporary, 0o555)
    os.replace(temporary, destination)
    return destination


def verify_binary_version(
    binary: Path, expected: str, *, timeout: int = DEFAULT_VERSION_TIMEOUT
) -> str:
    """Run ``opencode --version`` and refuse any value other than the pin."""

    binary = Path(binary)
    if not binary.is_file():
        raise OpenCodeDistributionError("materialized opencode binary is absent")
    try:
        completed = subprocess.run(
            (str(binary), "--version"),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise OpenCodeDistributionError(
            f"pinned opencode binary could not run: {exc}"
        ) from exc
    if completed.returncode != 0:
        raise OpenCodeDistributionError(
            f"pinned opencode binary exited {completed.returncode}"
        )
    observed = (completed.stdout or "").strip() or (completed.stderr or "").strip()
    if observed != expected:
        raise OpenCodeDistributionError(
            f"pinned opencode binary reports {observed!r}, expected {expected!r}"
        )
    return observed


def _default_fetch(url: str, *, timeout: int = 300) -> bytes:
    request = urllib.request.Request(url, headers={"Accept": "application/octet-stream"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def load_tarball(
    pin: Mapping[str, Any],
    platform: Mapping[str, Any],
    cache_dir: Path,
    *,
    fetch: Fetch | None = None,
) -> tuple[bytes, str, str]:
    """Return pinned tarball bytes, cache path, and ``cache``/``download`` origin."""

    fetch = fetch or _default_fetch
    cache_dir = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_path = cache_dir / f"{platform['package']}-{pin['version']}.tgz"
    if cache_path.is_file():
        data = cache_path.read_bytes()
        source = "cache"
    else:
        try:
            data = fetch(platform["tarball"])
        except (OSError, urllib.error.URLError) as exc:
            raise OpenCodeDistributionError(
                f"opencode tarball download failed: {platform['tarball']}"
            ) from exc
        if not isinstance(data, (bytes, bytearray)):
            raise OpenCodeDistributionError("opencode tarball fetch returned non-bytes")
        source = "download"
    verify_integrity(
        data, platform["integrity"], label=f"opencode {platform['package']} tarball"
    )
    if source == "download" and not cache_path.is_file():
        temporary = cache_path.with_name(cache_path.name + f".part-{os.getpid()}")
        temporary.write_bytes(data)
        os.replace(temporary, cache_path)
    return data, str(cache_path), source


def materialize(
    pin: Mapping[str, Any],
    flavor: str,
    target_dir: Path,
    cache_dir: Path,
    *,
    fetch: Fetch | None = None,
    version_timeout: int = DEFAULT_VERSION_TIMEOUT,
) -> dict[str, Any]:
    """Verify, extract, and version-check the pinned platform binary."""

    platform = resolve_platform(pin, flavor)
    version = pin["version"]
    data, cache_path, source = load_tarball(
        pin, platform, cache_dir, fetch=fetch
    )
    target_dir = Path(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix="opencode-dist-", dir=str(target_dir.parent))
    )
    try:
        staged = extract_binary(data, staging, platform["binaryMember"])
        expected_sha = platform.get("observedBinarySha256")
        if expected_sha is not None:
            if not isinstance(expected_sha, str) or _SHA256.fullmatch(expected_sha) is None:
                raise OpenCodeDistributionError("opencode binary sha256 pin is invalid")
            if _sha256_bytes(staged.read_bytes()) != expected_sha:
                raise OpenCodeDistributionError(
                    "opencode binary differs from the pinned sha256"
                )
        observed = verify_binary_version(staged, version, timeout=version_timeout)
        final = target_dir / "opencode"
        os.replace(staged, final)
        os.chmod(final, 0o555)
        binary_sha256 = _sha256_bytes(final.read_bytes())
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return {
        "ok": True,
        "package": pin["package"],
        "version": version,
        "flavor": flavor,
        "platformPackage": platform["package"],
        "tarball": platform["tarball"],
        "integrity": platform["integrity"],
        "binary": str(final),
        "binarySha256": binary_sha256,
        "observedVersion": observed,
        "cachePath": cache_path,
        "cacheSource": source,
        "scope": (
            "pinned upstream bytes only; no version fallback, custom build, "
            "or image publication"
        ),
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--flavor",
        choices=FLAVORS,
        default="glibc",
        help="platform package flavor to materialize (default: glibc)",
    )
    parser.add_argument(
        "--target-dir",
        type=Path,
        required=True,
        help="directory that receives the verified opencode binary at mode 0555",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=DEFAULT_CACHE,
        help=f"tarball cache directory (default: {DEFAULT_CACHE})",
    )
    parser.add_argument(
        "--inputs",
        type=Path,
        default=DEFAULT_INPUTS,
        help=f"pinned provider inputs (default: {DEFAULT_INPUTS})",
    )
    parser.add_argument(
        "--version-timeout",
        type=int,
        default=DEFAULT_VERSION_TIMEOUT,
        help="seconds allowed for opencode --version (default: 60)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        pin = load_pin(args.inputs)
        result = materialize(
            pin,
            args.flavor,
            args.target_dir,
            args.cache_dir,
            version_timeout=args.version_timeout,
        )
    except OpenCodeDistributionError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
