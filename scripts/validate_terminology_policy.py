#!/usr/bin/env python3
"""Validate StatePort's public naming and compatibility boundary."""
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
from validate_agent_routing_policy import resolve_local_refs

REQUIRED_PUBLIC_NAMES = {
    "StatePort",
    "StateBench",
    "StatePack",
    "StateIR",
    "StateSpec Template",
    "StudyState",
    "ClassState",
    "InfraState",
    "ProjectState",
    "ClientState",
    "LifeState",
    "ChecklistState",
}
REQUIRED_ALIASES = {
    "StateSpec": {"StateDD"},
    "StateSpec Template": {"StateDD Template"},
    "StudyState": {"StudyDD"},
    "ClassState": {"ClassDD"},
    "InfraState": {"InfraDD"},
    "ProjectState": {"ProjectDD"},
    "ClientState": {"ClientDD"},
    "LifeState": {"LifeDD"},
    "ChecklistState": {"ChecklistDD"},
}
REQUIRED_REMAINING_CATEGORIES = {
    "compatibility_alias",
    "machine_identifier",
    "historical_record",
    "legal_text",
    "archived_reference",
}


def load_policy(path: Path) -> dict[str, Any]:
    value = parse_yaml_text(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("terminology policy must be a YAML mapping")
    return value


def validate_policy_data(data: dict[str, Any], schema: dict[str, Any]) -> list[ValidationIssue]:
    issues = validate_json_schema(data, resolve_local_refs(schema, schema))
    products = data.get("products")
    by_name: dict[str, dict[str, Any]] = {}
    if isinstance(products, list):
        for index, product in enumerate(products):
            if not isinstance(product, dict):
                continue
            name = product.get("publicName")
            if not isinstance(name, str):
                continue
            if name in by_name:
                issues.append(ValidationIssue(f"$.products[{index}].publicName", "public product names must be unique"))
            by_name[name] = product
            if name.casefold().endswith("dd"):
                issues.append(ValidationIssue(f"$.products[{index}].publicName", "public product names must not use the legacy DD suffix"))
        missing = REQUIRED_PUBLIC_NAMES - set(by_name)
        extra = set(by_name) - REQUIRED_PUBLIC_NAMES
        if missing or extra:
            issues.append(ValidationIssue("$.products", f"must contain the exact public product set; missing={sorted(missing)}, extra={sorted(extra)}"))

    spec = data.get("portableSpecification")
    if isinstance(spec, dict):
        aliases = set(spec.get("legacyNames", ())) if isinstance(spec.get("legacyNames"), list) else set()
        if aliases != REQUIRED_ALIASES["StateSpec"]:
            issues.append(ValidationIssue("$.portableSpecification.legacyNames", "StateDD must remain the exact StateSpec compatibility alias"))

    for public_name, required_aliases in REQUIRED_ALIASES.items():
        if public_name == "StateSpec":
            continue
        product = by_name.get(public_name)
        if not product:
            continue
        aliases = set(product.get("legacyNames", ())) if isinstance(product.get("legacyNames"), list) else set()
        if aliases != required_aliases:
            issues.append(ValidationIssue(f"$.products.{public_name}.legacyNames", f"must retain exactly {sorted(required_aliases)}"))
        machine = product.get("machineIdentifiers")
        if required_aliases and (not isinstance(machine, list) or not machine):
            issues.append(ValidationIssue(f"$.products.{public_name}.machineIdentifiers", "renamed public products must retain compatibility machine identifiers"))

    compatibility = data.get("compatibility")
    if isinstance(compatibility, dict):
        categories = compatibility.get("allowedRemainingCategories")
        if not isinstance(categories, list) or set(categories) != REQUIRED_REMAINING_CATEGORIES or len(categories) != len(REQUIRED_REMAINING_CATEGORIES):
            issues.append(ValidationIssue("$.compatibility.allowedRemainingCategories", "must list the five exact justified legacy-occurrence categories"))
    return issues


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate StatePort's terminology policy")
    parser.add_argument("policy", nargs="?", type=Path, default=ROOT / "config" / "terminology-policy.yaml")
    parser.add_argument("--schema", type=Path, default=ROOT / "schemas" / "terminology-policy.v1.schema.json")
    args = parser.parse_args(argv)
    try:
        schema = json.loads(args.schema.read_text(encoding="utf-8"))
        policy = load_policy(args.policy)
        issues = validate_policy_data(policy, schema)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, StateDDYamlError, ValueError) as exc:
        print(f"FAIL: could not validate terminology policy: {exc}")
        return 1
    if issues:
        print(f"FAIL: terminology policy has {len(issues)} issue(s)")
        for issue in issues:
            print(f"  - {issue.path}: {issue.message}")
        return 1
    print("PASS: terminology policy preserves public names and compatibility boundaries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
