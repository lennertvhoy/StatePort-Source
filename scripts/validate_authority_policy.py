#!/usr/bin/env python3
"""Validate bounded-delegation policy, schemas, and executable integration."""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any

import jsonschema
import yaml


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "packages" / "governed-runner" / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from governed_runner.authority import AuthorityPolicy  # noqa: E402


EXPECTED_HARD_DENY = {"force_push", "history_rewrite", "disable_safety_gates"}
EXPECTED_ESCALATIONS = {
    "outside_standing_grant",
    "repository_or_runtime_identity_uncertain",
    "safety_gate_failed",
    "unrelated_work_at_risk",
    "sensitive_capability_required",
    "irreversible_or_public_consequence",
    "budget_exceeded",
    "conflicting_policy_rules",
    "result_unverifiable",
}
EXPECTED_SUBAGENT_DENY = {
    "push_integration_branch",
    "update_project_state",
    "merge",
    "tag",
    "public_release",
    "deployment",
    "plan_deployment",
    "apply_deployment",
    "collect_deployment_logs",
    "restart_deployment",
    "remove_deployment_runtime",
    "backup_deployment_data",
    "restore_deployment_data",
    "purge_deployment_data",
    "repository_visibility_change",
    "destructive_remote_action",
    "real_secret_use",
    "modify_authority_policy",
    "close_authority_scope",
    "delegate_subagent",
}


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.relative_to(ROOT)} must contain an object")
    return value


def validate_authority_policy(root: Path = ROOT) -> list[str]:
    findings: list[str] = []
    config = root / "config/authority-policy.v1.yaml"
    schemas = (
        root / "schemas/authority-policy.v1.schema.json",
        root / "schemas/authority-grant.v1.schema.json",
        root / "schemas/authority-action-reservation.v1.schema.json",
        root / "schemas/authority-action-claim.v1.schema.json",
        root / "schemas/authority-action-receipt.v1.schema.json",
    )
    for path in (config, *schemas):
        if not path.is_file() or path.is_symlink():
            findings.append(f"missing-or-unsafe:{path.relative_to(root)}")
    if findings:
        return findings
    try:
        value = yaml.safe_load(config.read_text(encoding="utf-8"))
        (
            policy_schema,
            grant_schema,
            reservation_schema,
            claim_schema,
            receipt_schema,
        ) = (_json(path) for path in schemas)
        for schema in (
            policy_schema,
            grant_schema,
            reservation_schema,
            claim_schema,
            receipt_schema,
        ):
            jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(policy_schema).validate(value)
        policy = AuthorityPolicy.from_mapping(value)
    except (
        OSError,
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
        yaml.YAMLError,
        jsonschema.ValidationError,
        jsonschema.SchemaError,
    ) as exc:
        return [f"invalid-authority-contract:{exc}"]
    if policy.default_profile != "balanced":
        findings.append("default-profile:balanced is required")
    if set(policy.hard_deny) != EXPECTED_HARD_DENY:
        findings.append("hard-deny:non-negotiable action vector changed")
    if set(policy.escalation_conditions) != EXPECTED_ESCALATIONS:
        findings.append("escalations:risk-based escalation vector changed")
    if set(policy.subagent_default_deny) != EXPECTED_SUBAGENT_DENY:
        findings.append("subagent-authority:default-deny vector changed")
    expected_modes = {
        ("guarded", "run_tests"): "auto_with_receipt",
        ("guarded", "edit_scoped_files"): "ask_each_time",
        ("balanced", "edit_scoped_files"): "auto_with_receipt",
        ("balanced", "push_private_branch"): "approve_scope_once",
        ("balanced", "merge"): "ask_each_time",
        ("delegated", "merge"): "auto_with_receipt",
        ("delegated", "deployment"): "ask_each_time",
        ("delegated", "apply_deployment"): "ask_each_time",
    }
    for (profile, action), expected in expected_modes.items():
        if policy.mode_for(profile, action) != expected:
            findings.append(f"profile:{profile}.{action} must remain {expected}")
    required_sources = {
        root / "packages/governed-runner/src/governed_runner/authority.py": (
            "class AuthorityManager",
            "policy_digest",
            "def activate_grant(",
            "def evaluate(",
            "def record_action(",
            "def revoke_grant(",
            "def set_paused(",
            "def close_scope(",
        ),
        root / "apps/admin-cli/src/admin_cli/authority.py": ("def authority_cmd(", "allow-once"),
        root / "apps/admin-cli/src/admin_cli/workspaces.py": (
            "AuthorityManager",
            '"create_managed_worktree"',
            '"export_workspace_evidence"',
            '"retire_owned_worktree"',
        ),
        root / "apps/admin-cli/src/admin_cli/main.py": (
            "def _add_authority_parser(",
            "--grant-id",
            "--authority-state-root",
            "--authority-policy",
        ),
    }
    for path, markers in required_sources.items():
        if not path.is_file():
            findings.append(f"missing-integration:{path.relative_to(root)}")
            continue
        source = path.read_text(encoding="utf-8")
        for marker in markers:
            if marker not in source:
                findings.append(f"missing-integration:{path.relative_to(root)}:{marker}")
    return findings


def main() -> int:
    findings = validate_authority_policy()
    if findings:
        for finding in findings:
            print(f"FAIL: {finding}")
        return 1
    print("PASS: bounded delegation policy, grants, overrides, and receipts are structurally valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
