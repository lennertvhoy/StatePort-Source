#!/usr/bin/env python3
"""Tests for the StatePort-owned closure evidence reconciliation tooling."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from reconcile_closure_evidence import _path_action_counts, _reconcile_path_actions, reconcile  # noqa: E402


def test_path_action_counts_are_derived_from_actions() -> None:
    actions = [
        {"path": "a", "action": "added"},
        {"path": "b", "action": "modified"},
        {"path": "c", "action": "modified"},
    ]
    assert _path_action_counts(actions) == {
        "added": 1,
        "modified": 2,
        "removed": 0,
        "renamed": 0,
    }
    assert _reconcile_path_actions({"counts": _path_action_counts(actions), "actions": actions})["status"] == "pass"


def test_missing_action_list_is_classified_as_count_disagreement() -> None:
    result = _reconcile_path_actions(
        {
            "counts": {"added": 17, "modified": 22, "removed": 0, "renamed": 0},
            "categories": {"exact-file-added": ["a"]},
        }
    )
    assert result["status"] == "disagreement"
    assert "action list is absent" in result["reason"]


def test_candidate_reconciliation_records_findings_without_inventing_facts() -> None:
    evidence = ROOT / "docs/evidence/2026-07-13-studydd-011-closure-proof"
    report = reconcile(ROOT, evidence, run_tests=False)
    finding_ids = {item["id"] for item in report["findings"]}
    assert report["candidate"]["commit"] == "a60fdf2d7599c148bd377852df0b71cfe2906bf5"
    assert report["candidate"]["tree"]
    assert "canonical-source-binding" in finding_ids
    assert "instance-lock-source-binding" in finding_ids
    assert "audit-records" in finding_ids
    assert "path-action-counts" in finding_ids
    assert report["audit"]["status"] == "missing"


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
    print("PASS")
