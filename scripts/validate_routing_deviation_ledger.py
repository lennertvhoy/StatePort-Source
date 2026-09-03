#!/usr/bin/env python3
"""Validate routing-deviation provenance and independent-review claims.

The ledger records what happened; it does not route agents, rerun work, or
grant acceptance.  Validation is intentionally stdlib-only apart from the
repository's safe YAML parser and lightweight JSON Schema checker.
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
from validate_agent_routing_policy import (
    load_policy,
    resolve_local_refs,
    validate_policy_data,
)

FINAL_REVIEW_DISPOSITIONS = {
    "accepted",
    "accepted_with_bounded_followups",
    "rejected_with_reproduced_defects",
}
INDEPENDENT_WORKTREES = {"clean_detached_worktree", "isolated_read_only_worktree"}


def load_ledger(path: Path) -> dict[str, Any]:
    value = parse_yaml_text(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("routing deviation ledger must be a YAML mapping")
    return value


def _validate_inventory(inventory: Any, path: str) -> list[ValidationIssue]:
    if not isinstance(inventory, dict):
        return []
    status = inventory.get("status")
    values = inventory.get("values")
    if not isinstance(values, list):
        return []
    if status == "exact" and not values:
        return [ValidationIssue(path, "an exact inventory must list at least one value")]
    if status in {"none", "unknown_exact"} and values:
        return [ValidationIssue(path, f"a {status} inventory must not imply an exact value list")]
    return []


def validate_ledger_data(
    data: dict[str, Any],
    schema: dict[str, Any],
    policy: dict[str, Any],
) -> list[ValidationIssue]:
    """Return schema and cross-record semantic issues for one ledger."""
    issues = validate_json_schema(data, resolve_local_refs(schema, schema))
    deviation_policy = policy.get("routingDeviation")
    allowed_reasons = (
        set(deviation_policy.get("fullRerunAllowedOnlyFor", ()))
        if isinstance(deviation_policy, dict)
        else set()
    )
    entries = data.get("entries")
    if not isinstance(entries, list):
        return issues

    entry_ids: set[str] = set()
    for index, entry in enumerate(entries):
        path = f"$.entries[{index}]"
        if not isinstance(entry, dict):
            continue
        entry_id = entry.get("entryId")
        if isinstance(entry_id, str):
            if entry_id in entry_ids:
                issues.append(ValidationIssue(f"{path}.entryId", "entry IDs must be unique"))
            entry_ids.add(entry_id)

        if entry.get("intendedProfile") == entry.get("actualProfile"):
            issues.append(ValidationIssue(path, "intended and actual profiles are identical; this is not a routing deviation"))

        cost = entry.get("incrementalCost")
        if isinstance(cost, dict):
            availability = cost.get("availability")
            amount = cost.get("amountMinor")
            currency = cost.get("currency")
            if availability == "available" and (not isinstance(amount, int) or isinstance(amount, bool) or not isinstance(currency, str)):
                issues.append(ValidationIssue(f"{path}.incrementalCost", "available cost requires an integer amountMinor and currency"))
            if availability == "unknown" and (amount is not None or currency is not None):
                issues.append(ValidationIssue(f"{path}.incrementalCost", "unknown cost must not invent an amount or currency"))

        produced = entry.get("producedWork")
        if isinstance(produced, dict):
            issues.extend(_validate_inventory(produced.get("commits"), f"{path}.producedWork.commits"))
            issues.extend(_validate_inventory(produced.get("files"), f"{path}.producedWork.files"))

        rerun = entry.get("rerun")
        if isinstance(rerun, dict):
            occurred = rerun.get("occurred")
            profile = rerun.get("profile")
            trigger = rerun.get("trigger")
            reason = rerun.get("allowedReason")
            worktree = rerun.get("worktreeIsolation")
            compliance = rerun.get("compliance")
            if occurred is False:
                expected = (profile is None and trigger == "not_applicable" and reason is None and worktree == "not_applicable" and compliance == "not_applicable")
                if not expected:
                    issues.append(ValidationIssue(f"{path}.rerun", "a non-rerun must use only not-applicable/null rerun fields"))
            elif occurred is True:
                if not isinstance(profile, str):
                    issues.append(ValidationIssue(f"{path}.rerun.profile", "a rerun must record its actual profile"))
                if compliance == "compliant":
                    if reason not in allowed_reasons or trigger != reason:
                        issues.append(ValidationIssue(f"{path}.rerun", "a compliant rerun must cite one exact policy reason as both trigger and allowedReason"))
                    if trigger == "model_identity_only":
                        issues.append(ValidationIssue(f"{path}.rerun.trigger", "model identity alone cannot authorize a rerun"))
                elif compliance == "historical_noncompliance":
                    if reason is not None:
                        issues.append(ValidationIssue(f"{path}.rerun.allowedReason", "historical noncompliance must not claim an allowed policy reason"))
                else:
                    issues.append(ValidationIssue(f"{path}.rerun.compliance", "an occurred rerun must be compliant or historical_noncompliance"))

        review = entry.get("review")
        if isinstance(review, dict):
            independent = review.get("independent")
            disposition = review.get("disposition")
            if review.get("inspectedCommitOrDiff") is not True:
                issues.append(ValidationIssue(f"{path}.review.inspectedCommitOrDiff", "review must inspect the actual commit or diff"))
            if disposition in FINAL_REVIEW_DISPOSITIONS and independent is not True:
                issues.append(ValidationIssue(f"{path}.review.disposition", "a final acceptance or rejection disposition requires independent review"))
            if independent is True:
                if review.get("access") != "read-only":
                    issues.append(ValidationIssue(f"{path}.review.access", "an independent reviewer must be read-only"))
                if review.get("originalImplementationOwner") is not False:
                    issues.append(ValidationIssue(f"{path}.review.originalImplementationOwner", "an independent reviewer cannot own the original implementation"))
                if review.get("worktreeIsolation") not in INDEPENDENT_WORKTREES:
                    issues.append(ValidationIssue(f"{path}.review.worktreeIsolation", "independent review requires a clean detached or isolated read-only worktree"))
    return issues


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate StatePort's routing deviation ledger")
    parser.add_argument("ledger", nargs="?", type=Path, default=ROOT / "docs" / "operations" / "routing-deviation-ledger.yaml")
    parser.add_argument("--schema", type=Path, default=ROOT / "schemas" / "routing-deviation-ledger.v1.schema.json")
    parser.add_argument("--policy", type=Path, default=ROOT / "config" / "agent-routing-policy.yaml")
    parser.add_argument("--policy-schema", type=Path, default=ROOT / "schemas" / "agent-routing-policy.schema.json")
    args = parser.parse_args(argv)
    try:
        schema = json.loads(args.schema.read_text(encoding="utf-8"))
        policy_schema = json.loads(args.policy_schema.read_text(encoding="utf-8"))
        policy = load_policy(args.policy)
        policy_issues = validate_policy_data(policy, policy_schema)
        if policy_issues:
            print(f"FAIL: routing policy has {len(policy_issues)} issue(s); ledger validation is not authoritative")
            for issue in policy_issues:
                print(f"  - {issue.path}: {issue.message}")
            return 1
        ledger = load_ledger(args.ledger)
        issues = validate_ledger_data(ledger, schema, policy)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, StateDDYamlError, ValueError) as exc:
        print(f"FAIL: could not validate routing deviation ledger: {exc}")
        return 1
    if issues:
        print(f"FAIL: routing deviation ledger has {len(issues)} issue(s)")
        for issue in issues:
            print(f"  - {issue.path}: {issue.message}")
        return 1
    print("PASS: routing deviation ledger is schema-valid and review claims are bounded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
