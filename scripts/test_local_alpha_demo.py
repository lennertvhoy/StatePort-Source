"""Focused smoke test for the provider-free local-alpha proof."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_local_alpha_demo_is_provider_free() -> None:
    studydd_mirror = os.environ.get("STATEPORT_STUDYDD_MIRROR")
    if not studydd_mirror:
        import pytest

        pytest.skip("set STATEPORT_STUDYDD_MIRROR to run the cross-repository demo")
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/demo_local_alpha.py"),
            "--source-profile",
            "builtin:studydd-local-alpha",
            "--source-repository",
            studydd_mirror,
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(result.stdout)
    assert report["providerContacted"] is False
    assert report["credentialsUsed"] is False
    assert report["statepackAndExecution"]["runResultDidNotMutateCanonicalState"] is True
    assert report["upgradePlan"]["conflict"]["blocked"] is True
    assert report["upgradePlan"]["ejection"]["preserved"] is True
    assert report["upgradePlan"]["rollback"]["byteIdentical"] is True
    assert report["upgradePlan"]["idempotentRerun"]["idempotent"] is True
    assert report["stateBench"]["resultTier"] == "verified"
    assert report["stateBench"]["objectiveMetrics"]["manifestValidity"] is True


if __name__ == "__main__":
    test_local_alpha_demo_is_provider_free()
