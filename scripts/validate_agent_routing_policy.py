#!/usr/bin/env python3
"""Validate the bounded, declarative StatePort agent routing policy.

This tool validates configuration only.  It neither selects models nor starts
subagents.  It is intentionally stdlib-only apart from the repository's
safe StateDD YAML parser.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CORE_SRC = ROOT / "packages" / "statedd-core" / "src"
for path in (ROOT / "scripts", CORE_SRC):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from statedd_core.yaml import StateDDYamlError, parse_yaml_text
from statedd_validate_schema import ValidationIssue, validate_json_schema

EXPECTED_ROLES = {
    "scout": ("luna-medium", "read-only"),
    "mechanicalImplementer": ("luna-high", "workspace-write"),
    "defaultImplementer": ("terra-medium", "workspace-write"),
    "complexImplementer": ("terra-high", "workspace-write"),
    "architect": ("sol-xhigh", "read-only"),
    "reviewer": ("sol-xhigh", "read-only"),
    "exceptionalAdjudicator": ("sol-max", "read-only"),
}
REQUIRED_UNCLEAR_CRITERIA = {"ownership", "migration", "recovery", "compatibility"}
REQUIRED_REVIEW_TRIGGERS = {"model-change", "pricing-change", "codex-configuration-change"}
REQUIRED_FULL_RERUN_REASONS = (
    "controlled_benchmark",
    "material_defect",
    "unsafe_execution",
    "irrecoverable_provenance",
    "explicit_human_request",
)


def load_policy(path: Path) -> dict[str, Any]:
    value = parse_yaml_text(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("policy must be a YAML mapping")
    return value


def resolve_local_refs(schema: Any, root: dict[str, Any]) -> Any:
    """Expand this policy schema's local JSON-pointer references.

    The repository-wide lightweight schema checker intentionally implements a
    small JSON Schema subset.  Resolving local references here keeps this
    validator aligned with the published schema without broadening that shared
    checker or adding a JSON Schema dependency.
    """
    if isinstance(schema, list):
        return [resolve_local_refs(item, root) for item in schema]
    if not isinstance(schema, dict):
        return schema
    reference = schema.get("$ref")
    if isinstance(reference, str):
        if not reference.startswith("#/"):
            raise ValueError(f"unsupported non-local schema reference: {reference}")
        target: Any = root
        for segment in reference[2:].split("/"):
            target = target.get(segment) if isinstance(target, dict) else None
            if target is None:
                raise ValueError(f"unresolved schema reference: {reference}")
        return resolve_local_refs(target, root)
    return {key: resolve_local_refs(value, root) for key, value in schema.items()}


def validate_policy_data(data: dict[str, Any], schema: dict[str, Any]) -> list[ValidationIssue]:
    """Return schema and policy-semantic issues for one parsed policy."""
    issues = validate_json_schema(data, resolve_local_refs(schema, schema))
    limits = data.get("limits")
    if not isinstance(limits, dict):
        return issues
    if limits.get("maxThreads") != 4:
        issues.append(ValidationIssue("$.limits.maxThreads", "must be exactly 4"))
    if limits.get("maxDepth") != 1:
        issues.append(ValidationIssue("$.limits.maxDepth", "must be exactly 1"))

    roles = data.get("roles")
    if isinstance(roles, dict):
        for role, (profile, access) in EXPECTED_ROLES.items():
            entry = roles.get(role)
            if isinstance(entry, dict) and entry.get("preferredProfile") != profile:
                issues.append(ValidationIssue(f"$.roles.{role}.preferredProfile", f"must be {profile!r}"))
            if isinstance(entry, dict) and entry.get("access") != access:
                issues.append(ValidationIssue(f"$.roles.{role}.access", f"must be {access!r}"))

    selection = data.get("selection")
    if isinstance(selection, dict) and selection.get("independentReadOnlyRoles") != ["architect", "reviewer"]:
        issues.append(ValidationIssue("$.selection.independentReadOnlyRoles", "must list architect and reviewer exactly once"))

    escalation = data.get("escalation")
    if isinstance(escalation, dict):
        if escalation.get("failedRepairLoops") != 1:
            issues.append(ValidationIssue("$.escalation.failedRepairLoops", "must escalate after the first failed repair loop"))
        criteria = escalation.get("passingTestsUnclear")
        if not isinstance(criteria, list) or set(criteria) != REQUIRED_UNCLEAR_CRITERIA or len(criteria) != len(REQUIRED_UNCLEAR_CRITERIA):
            issues.append(ValidationIssue("$.escalation.passingTestsUnclear", "must contain ownership, migration, recovery, and compatibility"))

    deviation = data.get("routingDeviation")
    if isinstance(deviation, dict):
        if deviation.get("invalidatesOutput") is not False:
            issues.append(ValidationIssue("$.routingDeviation.invalidatesOutput", "a routing deviation must not invalidate output by model identity alone"))
        if deviation.get("requireLedgerEntry") is not True:
            issues.append(ValidationIssue("$.routingDeviation.requireLedgerEntry", "every routing deviation must have a ledger entry"))
        if deviation.get("requireReview") is not True:
            issues.append(ValidationIssue("$.routingDeviation.requireReview", "the resulting output must be reviewed"))
        reasons = deviation.get("fullRerunAllowedOnlyFor")
        if reasons != list(REQUIRED_FULL_RERUN_REASONS):
            issues.append(
                ValidationIssue(
                    "$.routingDeviation.fullRerunAllowedOnlyFor",
                    "must contain only the five ordered evidence-based rerun reasons; model identity is not a rerun reason",
                )
            )

    triggers = data.get("reviewTriggers")
    if not isinstance(triggers, list) or set(triggers) != REQUIRED_REVIEW_TRIGGERS or len(triggers) != len(REQUIRED_REVIEW_TRIGGERS):
        issues.append(ValidationIssue("$.reviewTriggers", "must contain model, pricing, and Codex configuration changes"))
    return issues


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate StatePort's declarative agent routing policy")
    parser.add_argument("policy", nargs="?", type=Path, default=ROOT / "config" / "agent-routing-policy.yaml")
    parser.add_argument("--schema", type=Path, default=ROOT / "schemas" / "agent-routing-policy.schema.json")
    args = parser.parse_args(argv)
    try:
        schema = json.loads(args.schema.read_text(encoding="utf-8"))
        policy = load_policy(args.policy)
        issues = validate_policy_data(policy, schema)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, StateDDYamlError, ValueError) as exc:
        print(f"FAIL: could not validate agent routing policy: {exc}")
        return 1
    if issues:
        print(f"FAIL: agent routing policy has {len(issues)} issue(s)")
        for issue in issues:
            print(f"  - {issue.path}: {issue.message}")
        return 1
    print("PASS: agent routing policy is schema-valid and bounded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
