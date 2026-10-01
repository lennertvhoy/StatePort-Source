#!/usr/bin/env python3
"""Emit machine-readable closure evidence from one immutable proof output."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any


def git(root: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=root, text=True, capture_output=True, check=True).stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument("--stateport-root", type=Path, required=True)
    parser.add_argument("--studydd-repository", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    proof: dict[str, Any] = json.loads(args.proof.read_text(encoding="utf-8"))
    stateport_root = args.stateport_root.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    stateport_commit = git(stateport_root, "rev-parse", "HEAD")
    stateport_tree = git(stateport_root, "rev-parse", "HEAD^{tree}")
    repository = git(stateport_root, "remote", "get-url", "origin")
    baseline = proof["baseline"]
    target = proof["target"]
    (output / "proof-identities.json").write_text(
        json.dumps(
            {
                "baseline": {**baseline, "repository": args.studydd_repository},
                "target": {**target, "repository": args.studydd_repository},
                "stateportCandidate": {"repository": repository, "commit": stateport_commit, "tree": stateport_tree},
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (output / "path-action-matrix.json").write_text(
        json.dumps(
            {
                "formatVersion": "stateport.path-action-matrix/v1",
                "counts": proof["pathActionSummary"]["counts"],
                "actions": proof["pathActionSummary"]["actions"],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    with (output / "audit-records.jsonl").open("w", encoding="utf-8") as handle:
        for event in proof["audit"]["events"]:
            handle.write(json.dumps(event, sort_keys=True) + "\n")
    manifest = {
        "formatVersion": "stateport.closure-evidence-manifest/v1",
        "files": sorted(path.name for path in output.iterdir() if path.is_file()),
        "stateportCandidate": {"repository": repository, "commit": stateport_commit, "tree": stateport_tree},
        "instanceBinding": {
            "instanceId": proof["instanceBinding"]["instanceId"],
            "lockDigest": proof["instanceBinding"]["lockDigest"],
            "sourceDigest": proof["instanceBinding"]["sourceDigest"],
        },
        "proofTarget": target["resolvedCommit"],
    }
    (output / "evidence_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
