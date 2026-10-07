from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages/statebench/src"))

from statebench import build_execution_matrix, ingest_run_bundle  # noqa: E402


def _bundle(root: Path, application: str, engine: str, preserved: bool) -> None:
    (root / "execution").mkdir(parents=True)
    (root / "identities").mkdir(parents=True)
    manifest = {"formatVersion": "stateport.run-bundle/v1", "runId": f"run-{application}-{engine}", "applicationId": application, "status": "completed", "contentDigest": "sha256:" + "a" * 64, "files": {}}
    for relative, value in {
        "execution/result.json": {"canonicalStateUnchanged": preserved},
        "execution/engine.json": {"engineId": engine, "adapterId": engine + "-adapter"},
        "execution/capability-negotiation.json": {"acceptedRun": True, "degraded": []},
        "identities/state-before.json": {"digest": "sha256:" + "b" * 64},
        "identities/state-after.json": {"digest": "sha256:" + ("b" if preserved else "c") * 64},
    }.items():
        (root / relative).write_text(json.dumps(value), encoding="utf-8")
    (root / "bundle-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def test_run_bundle_ingestion_preserves_separate_scorecard_dimensions(tmp_path: Path) -> None:
    first = tmp_path / "study"; second = tmp_path / "check"
    _bundle(first, "studydd", "synthetic", True)
    _bundle(second, "checklistdd", "codex", False)
    row = ingest_run_bundle(first)
    assert row["statePreserved"] is True
    matrix = build_execution_matrix([first, second])
    assert matrix["applications"] == ["checklistdd", "studydd"]
    assert matrix["engines"] == ["codex", "synthetic"]
    assert matrix["qualityScore"] is None
    assert "state_preservation" in matrix["scorecards"]
