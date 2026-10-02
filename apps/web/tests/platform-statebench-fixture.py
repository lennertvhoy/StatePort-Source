#!/usr/bin/env python3
"""Seed one disposable verified RunBundle for the real operator browser gate."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


def _source_roots(repo_root: Path) -> None:
    for parent in (repo_root / "packages", repo_root / "apps"):
        for source in sorted(parent.glob("*/src")):
            if source.is_dir():
                sys.path.insert(0, str(source))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    args = parser.parse_args(argv)
    repo_root = args.repo_root.resolve(strict=True)
    _source_roots(repo_root)

    from run_bundle import RunBundleWriter
    from stateport_persistent_app import LocalLayout, PersistentApp
    from stateport_portable_execution import PortableExecutionService

    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    execution = PortableExecutionService(app, repo_root)
    run_id = "operator-browser-proof"
    state_digest = "sha256:" + "7" * 64
    reference = RunBundleWriter(execution.bundle_root / run_id).write(
        manifest={
            "runId": run_id,
            "instanceId": "public-fixture",
            "applicationId": "stateport.synthetic-reference",
            "status": "completed",
        },
        artifacts={
            "execution/agent-run-spec.json": {
                "formatVersion": "stateport.agent-run-spec/v1",
                "runId": run_id,
            },
            "execution/result.json": {
                "canonicalStateUnchanged": True,
                "latencyMs": 12,
                "unauthorizedMutations": 0,
            },
            "execution/engine.json": {
                "engineId": "synthetic",
                "adapterId": "synthetic-action",
            },
            "execution/capability-negotiation.json": {
                "acceptedRun": True,
                "degraded": [
                    {
                        "id": "terminal.sandbox",
                        "status": "unsupported",
                        "reason": "public fixture fallback",
                    }
                ],
            },
            "identities/state-before.json": {"digest": state_digest},
            "identities/state-after.json": {"digest": state_digest},
        },
    )
    execution.store.create(
        {
            "runId": run_id,
            "instanceId": "public-fixture",
            "applicationId": "stateport.synthetic-reference",
            "status": "completed",
            "runBundle": reference,
        }
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
