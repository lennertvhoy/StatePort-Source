"""Individual validation checks for StateDD templates and instances."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from statedd_core import APPROVAL_POLICY_DECISIONS, APPROVAL_POLICY_LEVELS
from statedd_core.yaml import StateDDYamlError, parse_yaml_text
from template_validator.result import ValidationIssue


TEMPLATE_REQUIRED_FILES = [
    "template.yaml",
    "README.md",
    ".statedd/contract.md",
]

INSTANCE_REQUIRED_FILES = [
    "instance.yaml",
    "README.md",
]

TEMPLATE_REQUIRED_TOP_KEYS = {"apiVersion", "kind", "metadata", "spec"}

TEMPLATE_REQUIRED_SPEC_KEYS = {
    "domain",
    "lifecycle",
    "allowedActions",
    "schemas",
    "agentContract",
}

INSTANCE_REQUIRED_TOP_KEYS = {"apiVersion", "kind", "metadata", "spec"}

INSTANCE_REQUIRED_SPEC_KEYS = {"templateRef", "status", "owner"}

ALLOWED_ACTION_LEVELS = {f"L{i}" for i in range(6)}


def _resolve_confined_path(
    relative_to: Path,
    relative_path: str,
    path_label: str,
    confine_to: Path | None = None,
) -> tuple[list[ValidationIssue], Path | None]:
    """Resolve ``relative_path`` against ``relative_to`` and ensure it stays inside ``confine_to``.

    Empty paths, absolute paths, and paths that resolve outside the confinement
    boundary are rejected. Symbolic links are followed during resolution so
    symlink escapes are also caught. When ``confine_to`` is omitted, the path
    must stay inside ``relative_to``.
    """
    if not relative_path:
        return [ValidationIssue(path_label, "path is empty")], None
    if relative_path.startswith("/") or (
        len(relative_path) > 1 and relative_path[1] == ":"
    ):
        return [ValidationIssue(path_label, "absolute paths are not allowed")], None

    boundary = confine_to if confine_to is not None else relative_to
    try:
        boundary_resolved = boundary.resolve()
        candidate = (relative_to / relative_path).resolve()
        if not candidate.is_relative_to(boundary_resolved):
            return [
                ValidationIssue(
                    path_label,
                    "path traversal is not allowed",
                )
            ], None
    except (OSError, ValueError) as exc:
        return [ValidationIssue(path_label, f"invalid path: {exc}")], None

    return [], candidate


def check_required_files(path: Path, required: list[str]) -> list[ValidationIssue]:
    """Ensure each relative path in `required` exists as a file under `path`."""
    issues: list[ValidationIssue] = []
    for name in required:
        target = path / name
        if not target.exists():
            issues.append(ValidationIssue(name, "required file is missing"))
        elif not target.is_file():
            issues.append(ValidationIssue(name, "exists but is not a file"))
    return issues


def check_yaml_parseable(path: Path) -> tuple[list[ValidationIssue], Any]:
    """Parse the file at `path` as StateDD YAML."""
    try:
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        if lines and lines[0].strip() == "---":
            text = "\n".join(lines[1:]) + "\n"
        data = parse_yaml_text(text)
        return [], data
    except StateDDYamlError as exc:
        return [ValidationIssue(path.name, f"YAML parse error: {exc}")], None
    except UnicodeDecodeError as exc:
        return [ValidationIssue(path.name, f"file is not valid UTF-8: {exc}")], None
    except OSError as exc:
        return [ValidationIssue(path.name, f"could not read file: {exc}")], None


def check_required_keys(
    data: dict[str, Any],
    required: set[str],
    path: str,
) -> list[ValidationIssue]:
    """Ensure all keys in `required` are present in the mapping `data`."""
    issues: list[ValidationIssue] = []
    if not isinstance(data, dict):
        return [ValidationIssue(path, "expected a mapping")]
    for key in sorted(required):
        if key not in data:
            issues.append(ValidationIssue(path, f"missing required key '{key}'"))
    return issues


def check_kind(data: dict[str, Any], expected: str) -> list[ValidationIssue]:
    """Ensure `data["kind"]` equals `expected`."""
    if not isinstance(data, dict):
        return [ValidationIssue("kind", "cannot check kind: document is not a mapping")]
    kind = data.get("kind")
    if kind != expected:
        return [
            ValidationIssue(
                "kind",
                f"expected kind '{expected}', got {kind!r}",
            )
        ]
    return []


def check_template_schema(data: dict[str, Any]) -> list[ValidationIssue]:
    """Validate the structure of a parsed template.yaml document."""
    issues: list[ValidationIssue] = []
    issues.extend(check_required_keys(data, TEMPLATE_REQUIRED_TOP_KEYS, ""))
    if not isinstance(data, dict):
        return issues
    issues.extend(check_kind(data, "Template"))

    spec = data.get("spec")
    if not isinstance(spec, dict):
        issues.append(ValidationIssue("spec", "expected a mapping"))
        return issues

    issues.extend(check_required_keys(spec, TEMPLATE_REQUIRED_SPEC_KEYS, "spec"))

    lifecycle = spec.get("lifecycle")
    if "lifecycle" in spec and not isinstance(lifecycle, list):
        issues.append(ValidationIssue("spec.lifecycle", "expected a list"))

    agent_contract = spec.get("agentContract")
    if "agentContract" in spec and not isinstance(agent_contract, dict):
        issues.append(ValidationIssue("spec.agentContract", "expected a mapping"))

    schemas = spec.get("schemas")
    if isinstance(schemas, list):
        for index, schema_path in enumerate(schemas):
            if not isinstance(schema_path, str):
                issues.append(
                    ValidationIssue(
                        f"spec.schemas[{index}]",
                        "schema path must be a string",
                    )
                )
    elif "schemas" in spec:
        issues.append(ValidationIssue("spec.schemas", "expected a list of strings"))

    allowed_actions = spec.get("allowedActions")
    if isinstance(allowed_actions, list):
        action_names: set[str] = set()
        for index, action in enumerate(allowed_actions):
            if not isinstance(action, dict):
                issues.append(
                    ValidationIssue(
                        f"spec.allowedActions[{index}]",
                        "action must be a mapping",
                    )
                )
                continue
            if "name" not in action:
                issues.append(
                    ValidationIssue(
                        f"spec.allowedActions[{index}]",
                        "action missing required key 'name'",
                    )
                )
            elif not isinstance(action["name"], str):
                issues.append(
                    ValidationIssue(
                        f"spec.allowedActions[{index}].name",
                        "action name must be a string",
                    )
                )
            elif not action["name"].strip():
                issues.append(
                    ValidationIssue(
                        f"spec.allowedActions[{index}].name",
                        "action name must be a non-empty string",
                    )
                )
            elif action["name"] in action_names:
                issues.append(
                    ValidationIssue(
                        f"spec.allowedActions[{index}].name",
                        "action names must be unique",
                    )
                )
            else:
                action_names.add(action["name"])
            if "level" not in action:
                issues.append(
                    ValidationIssue(
                        f"spec.allowedActions[{index}]",
                        "action missing required key 'level'",
                    )
                )
            elif not isinstance(action["level"], str):
                issues.append(
                    ValidationIssue(
                        f"spec.allowedActions[{index}].level",
                        "action level must be a string",
                    )
                )
            elif action["level"] not in ALLOWED_ACTION_LEVELS:
                issues.append(
                    ValidationIssue(
                        f"spec.allowedActions[{index}].level",
                        f"action level must be one of {sorted(ALLOWED_ACTION_LEVELS)}",
                    )
                )
    elif "allowedActions" in spec:
        issues.append(
            ValidationIssue("spec.allowedActions", "expected a list of mappings")
        )

    return issues


def check_instance_schema(data: dict[str, Any]) -> list[ValidationIssue]:
    """Validate the structure of a parsed instance.yaml document."""
    issues: list[ValidationIssue] = []
    issues.extend(check_required_keys(data, INSTANCE_REQUIRED_TOP_KEYS, ""))
    if not isinstance(data, dict):
        return issues
    issues.extend(check_kind(data, "Instance"))

    spec = data.get("spec")
    if not isinstance(spec, dict):
        issues.append(ValidationIssue("spec", "expected a mapping"))
        return issues

    issues.extend(check_required_keys(spec, INSTANCE_REQUIRED_SPEC_KEYS, "spec"))

    status = spec.get("status")
    if "status" in spec:
        if not isinstance(status, str) or not status:
            issues.append(
                ValidationIssue("spec.status", "status must be a non-empty string")
            )

    owner = spec.get("owner")
    if isinstance(owner, dict):
        owner_name = owner.get("name")
        if not isinstance(owner_name, str) or not owner_name:
            issues.append(
                ValidationIssue("spec.owner.name", "owner name must be a non-empty string")
            )
        owner_handle = owner.get("handle")
        if not isinstance(owner_handle, str) or not owner_handle:
            issues.append(
                ValidationIssue("spec.owner.handle", "owner handle must be a non-empty string")
            )
    elif "owner" in spec:
        issues.append(ValidationIssue("spec.owner", "expected a mapping"))

    template_ref = spec.get("templateRef")
    if isinstance(template_ref, dict):
        if "id" not in template_ref:
            issues.append(
                ValidationIssue("spec.templateRef", "missing required key 'id'")
            )
        elif not isinstance(template_ref["id"], str) or not template_ref["id"]:
            issues.append(
                ValidationIssue("spec.templateRef.id", "template ref id must be a non-empty string")
            )
        if "path" not in template_ref:
            issues.append(
                ValidationIssue("spec.templateRef", "missing required key 'path'")
            )
        elif not isinstance(template_ref["path"], str) or not template_ref["path"]:
            issues.append(
                ValidationIssue(
                    "spec.templateRef.path",
                    "template ref path must be a non-empty string",
                )
            )
    elif "templateRef" in spec:
        issues.append(ValidationIssue("spec.templateRef", "expected a mapping"))

    approval_policy = spec.get("approvalPolicy")
    if approval_policy is not None:
        if not isinstance(approval_policy, dict):
            issues.append(ValidationIssue("spec.approvalPolicy", "expected a mapping"))
        else:
            for level, decision in approval_policy.items():
                if level not in APPROVAL_POLICY_LEVELS:
                    issues.append(
                        ValidationIssue(
                            f"spec.approvalPolicy.{level}",
                            f"approval level must be one of {list(APPROVAL_POLICY_LEVELS)}",
                        )
                    )
                elif decision not in APPROVAL_POLICY_DECISIONS:
                    issues.append(
                        ValidationIssue(
                            f"spec.approvalPolicy.{level}",
                            "approval decision must be require_explicit_approval",
                        )
                    )

    return issues


def check_schema_files_exist(
    base_path: Path,
    schemas: list[str],
    path_prefix: str = "spec.schemas",
) -> list[ValidationIssue]:
    """Ensure each schema path resolves to a file under `base_path`."""
    issues: list[ValidationIssue] = []
    for schema_path in schemas:
        confinement_issues, target = _resolve_confined_path(
            base_path, schema_path, f"{path_prefix}: {schema_path}"
        )
        issues.extend(confinement_issues)
        if target is None:
            continue
        if not target.exists():
            issues.append(
                ValidationIssue(
                    f"{path_prefix}: {schema_path}",
                    f"referenced file does not exist: {schema_path}",
                )
            )
        elif not target.is_file():
            issues.append(
                ValidationIssue(
                    f"{path_prefix}: {schema_path}",
                    f"referenced path is not a file: {schema_path}",
                )
            )
    return issues


def check_template_ref_resolves(
    instance_path: Path,
    template_ref_path: str,
) -> tuple[list[ValidationIssue], Path | None]:
    """Resolve a relative template reference from an instance directory.

    Template references are confined to the project root, which is assumed to
    be the parent of the ``instances`` directory (i.e. ``instance_path.parent.parent``).
    """
    project_root = instance_path.parent.parent
    confinement_issues, candidate = _resolve_confined_path(
        instance_path,
        template_ref_path,
        "spec.templateRef.path",
        confine_to=project_root,
    )
    if candidate is None:
        return confinement_issues, None

    if not candidate.exists():
        return [
            ValidationIssue(
                "spec.templateRef.path",
                f"template path does not resolve: {candidate}",
            )
        ], None
    if not candidate.is_dir():
        return [
            ValidationIssue(
                "spec.templateRef.path",
                f"template path is not a directory: {candidate}",
            )
        ], None
    return [], candidate
