#!/usr/bin/env python3
"""Assemble a checked, scratch-image build context for a custom provider runtime.

This only copies already supplied bytes into a Docker/Podman context.  It does
not execute provider binaries, build an OCI image, publish anything, or admit
the generated context to the disabled custom-OCI release configuration.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Mapping


FORMAT = "stateport.provider-runtime-metadata/v1"
ARTIFACTS = ("codex", "bwrap", "rg")
ARTIFACT_METADATA_KEYS = {"codex": "codex", "bwrap": "bubblewrap", "rg": "ripgrep"}
LICENSES = ("LICENSE", "NOTICE", "BUBBLEWRAP-LICENSE", "BUBBLEWRAP-NOTICE")
PAYLOAD = (*ARTIFACTS, "provider-metadata.json", *LICENSES)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_CODEX_VERSION = re.compile(r"^codex-cli [0-9]+\.[0-9]+\.[0-9]+\+[0-9A-Za-z.-]+$")
_BWRAP_VERSION = re.compile(r"^bubblewrap [0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
_RG_VERSION = re.compile(r"^ripgrep [0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?(?: \(rev [0-9a-f]{7,40}\))?$")


class ProviderContextError(ValueError):
    """The supplied provider bytes do not meet the consumer input contract."""


def _sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _reject_symlink_components(path: Path, label: str) -> None:
    current = path
    while True:
        if current.is_symlink():
            raise ProviderContextError(f"{label} contains a symlink: {path}")
        if current == current.parent:
            return
        current = current.parent


def _require_absolute_regular_file(path: Path, label: str) -> None:
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise ProviderContextError(f"{label} must be an absolute regular file")
    _reject_symlink_components(path, label)
    if not stat.S_ISREG(path.stat().st_mode):
        raise ProviderContextError(f"{label} must be a regular file")


def _require_absolute_directory(path: Path, label: str) -> None:
    if not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise ProviderContextError(f"{label} must be an absolute directory")
    _reject_symlink_components(path, label)


def _json_without_duplicate_keys(raw: bytes) -> Mapping[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ProviderContextError(f"provider metadata repeats key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProviderContextError("provider metadata must be UTF-8 JSON") from exc
    if not isinstance(value, Mapping):
        raise ProviderContextError("provider metadata must be an object")
    return value


def _require_exact_keys(value: Mapping[str, Any], keys: set[str], label: str) -> None:
    if set(value) != keys:
        raise ProviderContextError(f"{label} has unexpected fields")


def _require_string(value: object, label: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or len(value) > 512 or "\x00" in value:
        raise ProviderContextError(f"{label} must be a bounded nonempty string")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise ProviderContextError(f"{label} has an invalid format")
    return value


def validate_metadata(metadata_path: Path, payload_dir: Path) -> tuple[dict[str, Any], dict[str, bytes]]:
    """Validate the exact metadata schema and its supplied payload digests."""

    _require_absolute_regular_file(metadata_path, "metadata")
    _require_absolute_directory(payload_dir, "payload directory")
    metadata_bytes = metadata_path.read_bytes()
    metadata = _json_without_duplicate_keys(metadata_bytes)
    _require_exact_keys(
        metadata,
        {"formatVersion", "version", "bubblewrapVersion", "ripgrepVersion", "source", "artifacts", "licenses"},
        "provider metadata",
    )
    if metadata["formatVersion"] != FORMAT:
        raise ProviderContextError("provider metadata formatVersion is unsupported")
    _require_string(metadata["version"], "provider version", _CODEX_VERSION)
    _require_string(metadata["bubblewrapVersion"], "bubblewrap version", _BWRAP_VERSION)
    _require_string(metadata["ripgrepVersion"], "ripgrep version", _RG_VERSION)

    source = metadata["source"]
    if not isinstance(source, Mapping):
        raise ProviderContextError("provider metadata source must be an object")
    _require_exact_keys(source, {"repository", "commit", "sourceArchiveDigest", "buildContextDigest"}, "provider source")
    if source["repository"] != "https://github.com/openai/codex":
        raise ProviderContextError("provider metadata source repository differs")
    _require_string(source["commit"], "provider source commit", _COMMIT)
    _require_string(source["sourceArchiveDigest"], "provider source archive digest", _DIGEST)
    _require_string(source["buildContextDigest"], "provider build context digest", _DIGEST)

    artifacts = metadata["artifacts"]
    if not isinstance(artifacts, Mapping):
        raise ProviderContextError("provider metadata artifacts must be an object")
    _require_exact_keys(artifacts, set(ARTIFACT_METADATA_KEYS.values()), "provider artifacts")
    payload_bytes = {"provider-metadata.json": metadata_bytes}
    for name, metadata_key in ARTIFACT_METADATA_KEYS.items():
        item = artifacts[metadata_key]
        if not isinstance(item, Mapping):
            raise ProviderContextError(f"provider artifact {metadata_key} must be an object")
        _require_exact_keys(item, {"digest"}, f"provider artifact {metadata_key}")
        expected = _require_string(item["digest"], f"provider artifact {metadata_key} digest", _DIGEST)
        path = payload_dir / name
        _require_absolute_regular_file(path, f"provider artifact {name}")
        if not (path.stat().st_mode & stat.S_IXUSR):
            raise ProviderContextError(f"provider artifact {name} must be executable")
        value = path.read_bytes()
        if _sha256_bytes(value) != expected:
            raise ProviderContextError(f"provider artifact {name} digest differs from metadata")
        payload_bytes[name] = value

    if not isinstance(metadata["licenses"], list) or tuple(metadata["licenses"]) != LICENSES:
        raise ProviderContextError("provider metadata licenses differ from the consumer contract")
    for name in LICENSES:
        path = payload_dir / name
        _require_absolute_regular_file(path, f"provider license {name}")
        payload_bytes[name] = path.read_bytes()
    entries = {path.name for path in payload_dir.iterdir()}
    expected_entries = set((*ARTIFACTS, *LICENSES))
    if entries != expected_entries:
        raise ProviderContextError("payload directory must contain exactly the provider artifacts and licenses")
    return dict(metadata), payload_bytes


def _write_context_file(destination: Path, content: bytes, mode: int) -> None:
    destination.write_bytes(content)
    destination.chmod(mode)
    os.utime(destination, (0, 0), follow_symlinks=False)


def prepare_context(metadata_path: Path, payload_dir: Path, output: Path) -> dict[str, Any]:
    """Copy a verified fixed payload into a fresh deterministic scratch context."""

    metadata, payload_bytes = validate_metadata(metadata_path, payload_dir)
    if not output.is_absolute() or output.exists() or output.is_symlink():
        raise ProviderContextError("output must be an absent absolute path")
    _reject_symlink_components(output, "output")
    _require_absolute_directory(output.parent, "output parent")

    output.mkdir(mode=0o755)
    _write_context_file(output / "provider-metadata.json", payload_bytes["provider-metadata.json"], 0o444)
    for name in ARTIFACTS:
        _write_context_file(output / name, payload_bytes[name], 0o555)
    for name in LICENSES:
        _write_context_file(output / name, payload_bytes[name], 0o444)
    lines = ["FROM scratch", *(f"COPY {name} /out/{name}" for name in PAYLOAD), ""]
    _write_context_file(output / "Containerfile", "\n".join(lines).encode("utf-8"), 0o444)
    return {
        "formatVersion": FORMAT,
        "context": str(output),
        "containerfile": str(output / "Containerfile"),
        "payload": list(PAYLOAD),
        "artifactDigests": {name: _sha256(output / name) for name in ARTIFACTS},
        "source": metadata["source"],
        "scope": "checked bytes only; no executable invocation, OCI build, image digest, publication, or provenance clearance",
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata", type=Path, required=True, help="absolute provider-metadata.json")
    parser.add_argument("--payload-dir", type=Path, required=True, help="absolute directory with fixed binaries and licenses")
    parser.add_argument("--output", type=Path, required=True, help="fresh absolute OCI build-context directory")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    print(json.dumps(prepare_context(args.metadata, args.payload_dir, args.output), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
