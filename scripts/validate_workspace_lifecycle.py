#!/usr/bin/env python3
"""Validate the canonical leased and bounded workspace lifecycle boundary."""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys
from typing import Any

import jsonschema
import yaml


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "packages" / "governed-runner" / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from governed_runner.workspaces import (  # noqa: E402
    REFUSAL_CODES,
    TERMINAL_STATUSES,
    WORKSPACE_METRICS,
    WorkspaceBudget,
)


EXPECTED_REFUSALS = {
    "workspace_budget_exceeded",
    "inventory_unknown",
    "unleased_workspace_present",
    "expired_lease_present",
    "prior_slice_cleanup_incomplete",
    "repository_identity_mismatch",
    "workspace_lock_busy",
    "branch_already_checked_out",
    "slice_already_closed",
    "unsafe_or_dirty_creation_base",
}
EXPECTED_TERMINAL = {
    "integrated_and_removed",
    "rejected_and_removed",
    "archived_and_removed",
    "retained_exception",
}
EXPECTED_METRICS = {
    "worktrees_created",
    "worktrees_removed",
    "worktrees_leaked",
    "branches_created",
    "branches_retired",
    "peak_registered_worktrees",
    "peak_active_writable_worktrees",
    "unclassified_workspace_count",
    "expired_lease_count",
    "cleanup_duration",
    "cleanup_failures",
    "owner_interventions_for_workspace_hygiene",
    "wrong_worktree_incidents",
    "closure_gate_workspace_failures",
}


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.relative_to(ROOT)} must contain a JSON object")
    return value


def validate_workspace_lifecycle(root: Path = ROOT) -> list[str]:
    findings: list[str] = []
    budget_path = root / "config/workspace-lifecycle.v1.yaml"
    lease_schema_path = root / "schemas/workspace-lease.v1.schema.json"
    budget_schema_path = root / "schemas/workspace-budget.v1.schema.json"
    for path in (budget_path, lease_schema_path, budget_schema_path):
        if not path.is_file() or path.is_symlink():
            findings.append(f"missing-or-unsafe:{path.relative_to(root)}")
    if findings:
        return findings
    try:
        budget_value = yaml.safe_load(budget_path.read_text(encoding="utf-8"))
        budget = WorkspaceBudget.from_mapping(budget_value)
        budget_schema = _load_json(budget_schema_path)
        lease_schema = _load_json(lease_schema_path)
        jsonschema.Draft202012Validator.check_schema(budget_schema)
        jsonschema.Draft202012Validator.check_schema(lease_schema)
        jsonschema.Draft202012Validator(budget_schema).validate(budget_value)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, jsonschema.ValidationError, jsonschema.SchemaError) as exc:
        findings.append(f"invalid-contract:{exc}")
        return findings
    expected_budget = {
        "max_registered_worktrees": 8,
        "max_active_writable_worktrees": 3,
        "max_unclassified_worktrees": 0,
        "max_unreconciled_branches": 3,
        "max_expired_leases": 0,
    }
    for name, expected in expected_budget.items():
        if getattr(budget, name) != expected:
            findings.append(f"budget-default:{name} must remain {expected}")
    if set(REFUSAL_CODES) != EXPECTED_REFUSALS:
        findings.append("typed-refusals:required refusal vector changed")
    if set(TERMINAL_STATUSES) != EXPECTED_TERMINAL:
        findings.append("terminal-statuses:required terminal vector changed")
    if set(WORKSPACE_METRICS) != EXPECTED_METRICS:
        findings.append("workspace-metrics:required observation vector changed")

    manager_path = root / "packages/governed-runner/src/governed_runner/workspaces.py"
    cli_path = root / "apps/admin-cli/src/admin_cli/workspaces.py"
    closure_path = root / "scripts/local_closure_gate.py"
    required_source = {
        manager_path: (
            "class WorkspaceLifecycleManager",
            "with self.lifecycle_lock()",
            "def create_workspace(",
            "def export_evidence(",
            "def close_workspace(",
            "def assert_slice_closed(",
            "def assert_repository_closed(",
        ),
        cli_path: ("WorkspaceLifecycleManager", "def workspace_cmd("),
        closure_path: ("assert_repository_closed()", "workspace lifecycle closure failed"),
    }
    for path, markers in required_source.items():
        if not path.is_file():
            findings.append(f"missing-integration:{path.relative_to(root)}")
            continue
        text = path.read_text(encoding="utf-8")
        for marker in markers:
            if marker not in text:
                findings.append(f"missing-integration:{path.relative_to(root)}:{marker}")

    direct_add = re.compile(r"['\"]worktree['\"]\s*,\s*['\"]add['\"]|\bgit\s+worktree\s+add\b")
    allowed = {manager_path.resolve(), (root / "scripts/validate_workspace_lifecycle.py").resolve()}
    for prefix in (root / "apps", root / "packages", root / "scripts"):
        for path in prefix.rglob("*.py"):
            if (
                path.resolve() in allowed
                or path.name.startswith("test_")
                or "tests" in {part.lower() for part in path.parts}
            ):
                continue
            if direct_add.search(path.read_text(encoding="utf-8")):
                findings.append(f"unmanaged-creation-path:{path.relative_to(root)}")

    fixture_path = root / "fixtures/statebench/workspace-lifecycle-incident-2026-07-29.yaml"
    try:
        fixture = yaml.safe_load(fixture_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        findings.append(f"escaped-process-fixture:{exc}")
    else:
        expected = {
            "peak_registered_worktrees": 89,
            "local_branches": 84,
            "owner_intervention_required": True,
            "owner_intervention_should_have_been_required": False,
            "classification": "major_process_incident",
        }
        if not isinstance(fixture, dict) or any(fixture.get(name) != value for name, value in expected.items()):
            findings.append("escaped-process-fixture:incident facts changed")
    return findings


def main() -> int:
    findings = validate_workspace_lifecycle()
    if findings:
        for finding in findings:
            print(f"FAIL: {finding}")
        return 1
    print("PASS: leased bounded workspace lifecycle contracts and integrations are valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
