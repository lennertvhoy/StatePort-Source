#!/usr/bin/env python3
"""Prepare the explicitly identified downstream Codex build without dependency drift."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import tomllib


HERE = Path(__file__).resolve().parent


def require_hash(path: Path, expected: str) -> None:
    with path.open("rb") as stream:
        observed = hashlib.file_digest(stream, "sha256").hexdigest()
    if observed != expected:
        raise ValueError(f"source integrity mismatch: {path.name}")


def prepare(archive: Path, destination: Path) -> dict:
    lock = json.loads((HERE / "source-build.json").read_text())
    patch = HERE / "proc-mount-compat.patch"
    require_hash(archive, lock["sourceSha256"])
    require_hash(patch, lock["patchSha256"])
    dependency_patch = HERE / "dependency-updates.patch"
    require_hash(dependency_patch, lock["dependencyPatchSha256"])
    # New output only: neither a retry nor a changed source may mutate an
    # existing checkout/build. Python's data filter refuses escaping links.
    destination.mkdir(parents=True, exist_ok=False)
    with tarfile.open(archive, "r:gz") as source:
        source.extractall(destination, filter="data")
    root = destination / ("codex-" + lock["sourceCommit"])
    cargo = root / "codex-rs"
    cargo_lock = cargo / "Cargo.lock"
    require_hash(cargo_lock, lock["upstreamCargoLockSha256"])
    for change in (patch, dependency_patch):
        subprocess.run(["patch", "--batch", "--fuzz=0", "-p1", "-i", str(change)],
                       cwd=root, check=True)
    # Security updates are an exact reviewed patch, never a build-time resolve.
    require_hash(cargo_lock, lock["dependencyCargoLockSha256"])
    before = tomllib.loads(cargo_lock.read_text())
    manifest = cargo / "Cargo.toml"
    original = f'version = "{lock["upstreamVersion"]}"'
    content = manifest.read_text()
    if content.count(original) != 1:
        raise ValueError("upstream workspace version is not unique")
    manifest.write_text(content.replace(original, f'version = "{lock["version"]}"'))
    # Upstream release tags bump Cargo.toml but leave local workspace lock
    # entries at 0.0.0. Update exactly those identities; never resolve newer
    # registry/git dependencies or discard their checksums.
    local_names = {item["name"] for item in before["package"] if "source" not in item}
    chunks = cargo_lock.read_text().split("[[package]]")
    normalized = []
    for index, chunk in enumerate(chunks[1:], 1):
        item = tomllib.loads(chunk)
        if item["name"] not in local_names or "source" in item:
            continue
        if item["version"] != "0.0.0":
            raise ValueError("unexpected upstream local package version")
        chunks[index] = chunk.replace('version = "0.0.0"', f'version = "{lock["version"]}"', 1)
        normalized.append(item["name"])
    cargo_lock.write_text("[[package]]".join(chunks))
    after = tomllib.loads(cargo_lock.read_text())
    if [p for p in before["package"] if "source" in p] != [p for p in after["package"] if "source" in p]:
        raise ValueError("external dependency identities changed")
    receipt = {**lock, "sourceRoot": str(root), "normalizedLocalPackages": sorted(normalized),
               "preparedCargoLockSha256": hashlib.sha256(cargo_lock.read_bytes()).hexdigest(),
               "externalDependenciesUnchanged": False,
               "versionNormalizationPreservedExternalDependencies": True}
    (destination / "source-preparation.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    print(json.dumps(prepare(args.archive, args.destination), indent=2))
