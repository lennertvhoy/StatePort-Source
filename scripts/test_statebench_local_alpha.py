"""Focused test for the provider-free StateBench workbench command."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_local_workbench_reports_objective_properties_only() -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/statebench_local_alpha.py"),
            "--candidate-commit",
            "a" * 40,
            "--candidate-tree",
            "b" * 40,
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(result.stdout)
    assert report["resultTier"] == "verified"
    assert "model-quality" in report["claimBoundary"]
    assert report["objectiveMetrics"]["statePreservation"] is True


if __name__ == "__main__":
    test_local_workbench_reports_objective_properties_only()
