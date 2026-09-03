#!/usr/bin/env python3
"""Standalone StateSpec schema and cross-file validator for StatePort.

Validates PROJECT_STATE.yaml and PROJECT_DNA.yaml against their JSON schemas,
and checks that the mode in AGENTS.md and the phase in STATUS.md match the
values recorded in PROJECT_STATE.yaml.

Intentionally stdlib-only: no PyYAML, no jsonschema.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

CORE_SRC = REPO_ROOT / "packages" / "statedd-core" / "src"
if str(CORE_SRC) not in sys.path:
    sys.path.insert(0, str(CORE_SRC))

from statedd_core.yaml import StateDDYamlError, parse_yaml_text


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "schemas"
RUNTIME_CONTRACT_SCHEMAS = (
    "workflow-declaration.v1.schema.json",
    "task-manifest.v1.schema.json",
    "runtime-profile.v1.schema.json",
    "context-manifest.v1.schema.json",
    "context-lifecycle.v1.schema.json",
    "agent-profile.v1.schema.json",
    "agent-event.v1.schema.json",
    "run-receipt.v1.schema.json",
    "statebench-real-project.v1.schema.json",
    "functionality-preservation.v1.schema.json",
    "frontend-dynamic-preservation.v1.schema.json",
    "deployment.v1.schema.json",
    "deployment-plan.v1.schema.json",
    "deployment-state.v1.schema.json",
    "deployment-receipt.v1.schema.json",
    "deployment-inspection.v1.schema.json",
    "deployment-evidence.v1.schema.json",
    "instance.v1alpha1.schema.json",
    "lock.v1.schema.json",
    "statespec-schema-registry.v1.schema.json",
    "restore-plan.v1.schema.json",
    "restore-approval.v1.schema.json",
    "restore-receipt.v1.schema.json",
    "recovery-status.v1.schema.json",
)


@dataclass
class ValidationIssue:
    path: str
    message: str


# ---------------------------------------------------------------------------
# Data loading helpers
# ---------------------------------------------------------------------------


def load_data(path: Path) -> Any:
    if path.suffix.lower() == ".json":
        return json.loads(path.read_text(encoding="utf-8"))
    if path.suffix.lower() in {".yaml", ".yml"}:
        return parse_yaml_text(path.read_text(encoding="utf-8"))
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Small JSON Schema subset validator
# ---------------------------------------------------------------------------


def type_matches(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "null":
        return value is None
    return False


def validate_json_schema(value: Any, schema: dict[str, Any], path: str = "$") -> list[ValidationIssue]:
    """Validate the deliberate JSON Schema subset used by repository contracts."""

    def resolve(reference: str) -> dict[str, Any] | None:
        if not reference.startswith("#/$defs/"):
            return None
        definition = schema.get("$defs", {}).get(reference.removeprefix("#/$defs/"))
        return definition if isinstance(definition, dict) else None

    def validate(item: Any, current: dict[str, Any], item_path: str) -> list[ValidationIssue]:
        issues: list[ValidationIssue] = []
        reference = current.get("$ref")
        if isinstance(reference, str):
            resolved = resolve(reference)
            if resolved is None:
                return [ValidationIssue(item_path, f"unsupported or missing schema reference {reference!r}")]
            return validate(item, resolved, item_path)

        expected_type = current.get("type")
        if isinstance(expected_type, list):
            if not any(type_matches(item, expected) for expected in expected_type):
                return [ValidationIssue(item_path, f"expected one of types {expected_type}, got {type(item).__name__}")]
        elif isinstance(expected_type, str) and not type_matches(item, expected_type):
            return [ValidationIssue(item_path, f"expected type {expected_type}, got {type(item).__name__}")]

        if "const" in current and item != current["const"]:
            issues.append(ValidationIssue(item_path, f"expected constant {current['const']!r}, got {item!r}"))
        if "enum" in current and item not in current["enum"]:
            issues.append(ValidationIssue(item_path, f"expected one of {current['enum']}, got {item!r}"))

        if isinstance(item, str):
            for keyword, comparison, label in (("minLength", lambda actual, limit: actual < limit, ">="), ("maxLength", lambda actual, limit: actual > limit, "<=")):
                limit = current.get(keyword)
                if isinstance(limit, int) and comparison(len(item), limit):
                    issues.append(ValidationIssue(item_path, f"expected string length {label} {limit}"))
            pattern = current.get("pattern")
            if isinstance(pattern, str) and not re.search(pattern, item):
                issues.append(ValidationIssue(item_path, f"string does not match pattern {pattern!r}"))

        if isinstance(item, (int, float)) and not isinstance(item, bool):
            minimum = current.get("minimum")
            if isinstance(minimum, (int, float)) and item < minimum:
                issues.append(ValidationIssue(item_path, f"expected number >= {minimum}"))
            maximum = current.get("maximum")
            if isinstance(maximum, (int, float)) and item > maximum:
                issues.append(ValidationIssue(item_path, f"expected number <= {maximum}"))

        if isinstance(item, list):
            for keyword, comparison, label in (("minItems", lambda actual, limit: actual < limit, "at least"), ("maxItems", lambda actual, limit: actual > limit, "at most")):
                limit = current.get(keyword)
                if isinstance(limit, int) and comparison(len(item), limit):
                    issues.append(ValidationIssue(item_path, f"expected {label} {limit} item(s)"))
            if current.get("uniqueItems") is True and len({json.dumps(entry, sort_keys=True) for entry in item}) != len(item):
                issues.append(ValidationIssue(item_path, "array items must be unique"))
            item_schema = current.get("items")
            if isinstance(item_schema, dict):
                for index, entry in enumerate(item):
                    issues.extend(validate(entry, item_schema, f"{item_path}[{index}]"))

        if isinstance(item, dict):
            for keyword, comparison, label in (("minProperties", lambda actual, limit: actual < limit, "at least"), ("maxProperties", lambda actual, limit: actual > limit, "at most")):
                limit = current.get(keyword)
                if isinstance(limit, int) and comparison(len(item), limit):
                    issues.append(ValidationIssue(item_path, f"expected {label} {limit} properties"))
            required = current.get("required", [])
            if isinstance(required, list):
                for key in required:
                    if key not in item:
                        issues.append(ValidationIssue(item_path, f"missing required property {key!r}"))
            properties = current.get("properties", {})
            properties_dict = properties if isinstance(properties, dict) else {}
            for key, property_schema in properties_dict.items():
                if key in item and isinstance(property_schema, dict):
                    issues.extend(validate(item[key], property_schema, f"{item_path}.{key}"))
            additional = current.get("additionalProperties", True)
            if additional is False:
                for key in item:
                    if key not in properties_dict:
                        issues.append(ValidationIssue(f"{item_path}.{key}", "additional property is not allowed"))
            elif isinstance(additional, dict):
                for key, nested in item.items():
                    if key not in properties_dict:
                        issues.extend(validate(nested, additional, f"{item_path}.{key}"))

        all_of = current.get("allOf", [])
        if isinstance(all_of, list):
            for branch in all_of:
                if isinstance(branch, dict):
                    issues.extend(validate(item, branch, item_path))
        one_of = current.get("oneOf")
        if isinstance(one_of, list):
            matches = sum(not validate(item, branch, item_path) for branch in one_of if isinstance(branch, dict))
            if matches != 1:
                issues.append(ValidationIssue(item_path, "expected exactly one matching schema branch"))
        condition = current.get("if")
        if isinstance(condition, dict):
            branch_name = "then" if not validate(item, condition, item_path) else "else"
            branch = current.get(branch_name)
            if isinstance(branch, dict):
                issues.extend(validate(item, branch, item_path))
        return issues

    return validate(value, schema, path)


def load_schema(schema_path: Path) -> dict[str, Any]:
    return json.loads(schema_path.read_text(encoding="utf-8"))


def validate_file(path: Path, schema_path: Path) -> list[ValidationIssue]:
    schema = load_schema(schema_path)
    data = load_data(path)
    return validate_json_schema(data, schema)


# ---------------------------------------------------------------------------
# Cross-file mode / phase consistency checks
# ---------------------------------------------------------------------------


def strip_markdown(text: str) -> str:
    return re.sub(r"[`_*]+", "", text)


def extract_mode_agents(text: str) -> str | None:
    patterns = [
        r"currently operates in:\s*[`_*]*([^`_*#\n]+)[`_*]*",
        r"\bMode:\s*[`_*]*([^`_*#\n]+)[`_*]*",
    ]
    first_match: tuple[int, str] | None = None
    for pattern in patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            value = strip_markdown(match.group(1)).strip()
            if first_match is None or match.start() < first_match[0]:
                first_match = (match.start(), value)
    return first_match[1] if first_match else None


def extract_phase_status(text: str) -> str | None:
    match = re.search(r"Phase:\s*(.*?);", text, re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    phase = strip_markdown(match.group(1)).strip()
    phase = re.sub(r"\s+", "_", phase).lower()
    return phase


def validate_mode_phase(root: Path) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []

    project_state_path = root / "PROJECT_STATE.yaml"
    agents_path = root / "AGENTS.md"
    status_path = root / "STATUS.md"

    # If PROJECT_STATE.yaml is missing or cannot be parsed, the schema-target
    # check in validate_root already reports a single failure. Skip the
    # mode/phase check to avoid a redundant second error.
    if not project_state_path.exists():
        return issues
    try:
        project_state = load_data(project_state_path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, StateDDYamlError):
        return issues
    if not isinstance(project_state, dict):
        return issues

    project = project_state.get("project")
    if not isinstance(project, dict):
        issues.append(ValidationIssue("$.project", "missing or invalid project section"))
        return issues

    state_mode = project.get("mode")
    state_phase = project.get("phase")

    try:
        agents_text = agents_path.read_text(encoding="utf-8")
    except OSError as exc:
        issues.append(ValidationIssue("AGENTS.md", f"could not read file: {exc}"))
    else:
        agents_mode = extract_mode_agents(agents_text)
        if agents_mode is None:
            issues.append(ValidationIssue("AGENTS.md", "could not extract mode"))
        elif state_mode != agents_mode:
            issues.append(
                ValidationIssue(
                    "AGENTS.md",
                    f"mode mismatch: PROJECT_STATE.yaml says {state_mode!r}, AGENTS.md says {agents_mode!r}",
                )
            )

    try:
        status_text = status_path.read_text(encoding="utf-8")
    except OSError as exc:
        issues.append(ValidationIssue("STATUS.md", f"could not read file: {exc}"))
    else:
        status_phase = extract_phase_status(status_text)
        if status_phase is None:
            issues.append(ValidationIssue("STATUS.md", "could not extract phase"))
        elif state_phase != status_phase:
            issues.append(
                ValidationIssue(
                    "STATUS.md",
                    f"phase mismatch: PROJECT_STATE.yaml says {state_phase!r}, STATUS.md says {status_phase!r}",
                )
            )

    return issues


# ---------------------------------------------------------------------------
# CLI and orchestration
# ---------------------------------------------------------------------------


def root_targets(root: Path) -> list[tuple[Path, Path]]:
    return [
        (root / "PROJECT_STATE.yaml", SCHEMA_ROOT / "project_state.schema.json"),
        (root / "PROJECT_DNA.yaml", SCHEMA_ROOT / "project_dna.schema.json"),
        (root / "sources" / "profiles" / "studydd-local-alpha.yaml", SCHEMA_ROOT / "source-contract.v1.schema.json"),
        (root / "sources" / "canonical" / "studydd.yaml", SCHEMA_ROOT / "canonical-source.v1.schema.json"),
    ]


def validate_registered_schema_files() -> list[ValidationIssue]:
    """Keep contract schemas registered without inventing runtime fixtures.

    These are public wire contracts rather than repository state files, so the
    repository gate validates their presence and JSON object shape only. Their
    semantic conformance is exercised by ``test_runtime_contracts.py``.
    """
    issues: list[ValidationIssue] = []
    for name in RUNTIME_CONTRACT_SCHEMAS:
        path = SCHEMA_ROOT / name
        if not path.is_file():
            issues.append(ValidationIssue(name, "missing registered runtime contract schema"))
            continue
        try:
            schema = load_schema(path)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            issues.append(ValidationIssue(name, f"could not parse schema: {exc}"))
            continue
        if not isinstance(schema, dict) or schema.get("type") != "object" or schema.get("additionalProperties") is not False:
            issues.append(ValidationIssue(name, "registered runtime contract schema must be a strict object schema"))
    return issues


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate StatePort StateSpec schemas and cross-file consistency")
    parser.add_argument("root", nargs="?", default=str(ROOT), help="Repo root to validate")
    parser.add_argument("--quiet", action="store_true", help="Only print failures")
    return parser.parse_args(argv[1:])


def print_target_result(label: str, issues: list[ValidationIssue], quiet: bool) -> None:
    if not issues:
        if not quiet:
            print(f"  PASS {label}")
        return
    if label == "mode/phase consistency":
        for issue in issues:
            print(f"FAIL: {issue.message}")
        return
    print(f"  FAIL {label}")
    for issue in issues:
        print(f"    - {issue.path}: {issue.message}")


def validate_root(root: Path, quiet: bool) -> int:
    all_issues: list[tuple[str, list[ValidationIssue]]] = []
    if not quiet:
        print("============================================================")
        print("STATEPORT STATESPEC VALIDATION")
        print("============================================================")

    for path, schema_path in root_targets(root):
        label = path.relative_to(root).as_posix() if path.is_relative_to(root) else str(path)
        if not path.exists():
            issues = [ValidationIssue("$", f"missing required validation target: {label}")]
            all_issues.append((label, issues))
            print_target_result(label, issues, quiet)
            continue
        if not schema_path.exists():
            issues = [ValidationIssue("$", f"missing schema file: {schema_path}")]
            all_issues.append((label, issues))
            print_target_result(label, issues, quiet)
            continue
        try:
            issues = validate_file(path, schema_path)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, StateDDYamlError) as exc:
            issues = [ValidationIssue("$", f"could not parse or validate file: {exc}")]
        if issues:
            all_issues.append((label, issues))
        print_target_result(label, issues, quiet)

    contract_label = "registered runtime contract schemas"
    contract_issues = validate_registered_schema_files()
    if contract_issues:
        all_issues.append((contract_label, contract_issues))
    print_target_result(contract_label, contract_issues, quiet)

    cross_label = "mode/phase consistency"
    try:
        cross_issues = validate_mode_phase(root)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, StateDDYamlError) as exc:
        cross_issues = [ValidationIssue("$", f"could not validate cross-file consistency: {exc}")]
    if cross_issues:
        all_issues.append((cross_label, cross_issues))
    print_target_result(cross_label, cross_issues, quiet)

    if all_issues:
        print(f"FAILED: {sum(len(issues) for _, issues in all_issues)} issue(s) found")
        return 1
    if not quiet:
        print("PASSED: All StateSpec schema checks passed")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv)
    root = Path(args.root).resolve()
    return validate_root(root, args.quiet)


if __name__ == "__main__":
    raise SystemExit(main())
