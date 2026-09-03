"""Focused regressions for the J1 candidate builder compatibility inputs."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts" / "qualification"))

from build_j1_candidate import _compatibility_fields  # noqa: E402


def test_standalone_candidate_keeps_historical_no_predecessor_semantics() -> None:
    fields = _compatibility_fields(None)
    assert fields == {
        "predecessor_index": None,
        "rollback_supported": False,
        "rollback_minimum_version": None,
        "rollback_data_compatible": False,
        "rollback_reason": (
            "Qualification-only candidate has no predecessor semantics."
        ),
    }


def test_predecessor_bound_candidate_declares_exact_rollback_support() -> None:
    predecessor = Path("/retained/candidate-v13/release-index.json")
    fields = _compatibility_fields(predecessor)
    assert fields["predecessor_index"] is predecessor
    assert fields["rollback_supported"] is True
    assert fields["rollback_data_compatible"] is True
    assert fields["rollback_minimum_version"] is None
    assert "predecessor" in str(fields["rollback_reason"])
