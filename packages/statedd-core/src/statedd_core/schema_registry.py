"""Portable logical-schema registry and stdlib JSON Schema validation.

The validator intentionally implements only the JSON Schema keywords used by
StatePort's portable StateSpec contracts. Unsupported references fail closed.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from statedd_core.yaml import parse_yaml_text

REGISTRY_FORMAT = "stateport.statespec-schema-registry/v1"
INSTANCE_SCHEMA_ID = "statedd.stateport.io/instance/v1alpha1"
LOCK_SCHEMA_ID = "statedd.stateport.io/lock/v1"
BUILTIN_SCHEMA_IDS = frozenset({INSTANCE_SCHEMA_ID, LOCK_SCHEMA_ID})


@dataclass(frozen=True)
class SchemaIssue:
    path: str
    message: str


class SchemaRegistryError(ValueError):
    """A logical schema registry or referenced schema is unsafe or invalid."""


def _type_matches(value: Any, expected: str) -> bool:
    return {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "boolean": isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "null": value is None,
    }.get(expected, False)


def validate_json_schema(value: Any, schema: Mapping[str, Any], path: str = "$") -> list[SchemaIssue]:
    """Validate the bounded JSON Schema subset used by StateSpec contracts."""

    root = schema

    def resolve(reference: str) -> Mapping[str, Any] | None:
        if not reference.startswith("#/$defs/"):
            return None
        definition = root.get("$defs", {}).get(reference.removeprefix("#/$defs/"))
        return definition if isinstance(definition, dict) else None

    def validate(item: Any, current: Mapping[str, Any], item_path: str) -> list[SchemaIssue]:
        issues: list[SchemaIssue] = []
        reference = current.get("$ref")
        if isinstance(reference, str):
            resolved = resolve(reference)
            if resolved is None:
                return [SchemaIssue(item_path, f"unsupported or missing schema reference {reference!r}")]
            return validate(item, resolved, item_path)

        expected_type = current.get("type")
        if isinstance(expected_type, list):
            if not any(_type_matches(item, expected) for expected in expected_type):
                return [SchemaIssue(item_path, f"expected one of types {expected_type}, got {type(item).__name__}")]
        elif isinstance(expected_type, str) and not _type_matches(item, expected_type):
            return [SchemaIssue(item_path, f"expected type {expected_type}, got {type(item).__name__}")]

        if "const" in current and item != current["const"]:
            issues.append(SchemaIssue(item_path, f"expected constant {current['const']!r}, got {item!r}"))
        if "enum" in current and item not in current["enum"]:
            issues.append(SchemaIssue(item_path, f"expected one of {current['enum']}, got {item!r}"))

        if isinstance(item, str):
            minimum = current.get("minLength")
            maximum = current.get("maxLength")
            if isinstance(minimum, int) and len(item) < minimum:
                issues.append(SchemaIssue(item_path, f"expected string length >= {minimum}"))
            if isinstance(maximum, int) and len(item) > maximum:
                issues.append(SchemaIssue(item_path, f"expected string length <= {maximum}"))
            pattern = current.get("pattern")
            if isinstance(pattern, str) and not re.search(pattern, item):
                issues.append(SchemaIssue(item_path, f"string does not match pattern {pattern!r}"))

        if isinstance(item, (int, float)) and not isinstance(item, bool):
            minimum = current.get("minimum")
            maximum = current.get("maximum")
            if isinstance(minimum, (int, float)) and item < minimum:
                issues.append(SchemaIssue(item_path, f"expected number >= {minimum}"))
            if isinstance(maximum, (int, float)) and item > maximum:
                issues.append(SchemaIssue(item_path, f"expected number <= {maximum}"))

        if isinstance(item, list):
            minimum = current.get("minItems")
            maximum = current.get("maxItems")
            if isinstance(minimum, int) and len(item) < minimum:
                issues.append(SchemaIssue(item_path, f"expected at least {minimum} item(s)"))
            if isinstance(maximum, int) and len(item) > maximum:
                issues.append(SchemaIssue(item_path, f"expected at most {maximum} item(s)"))
            if current.get("uniqueItems") is True:
                encoded = [json.dumps(entry, sort_keys=True, separators=(",", ":")) for entry in item]
                if len(encoded) != len(set(encoded)):
                    issues.append(SchemaIssue(item_path, "array items must be unique"))
            item_schema = current.get("items")
            if isinstance(item_schema, dict):
                for index, entry in enumerate(item):
                    issues.extend(validate(entry, item_schema, f"{item_path}[{index}]"))

        if isinstance(item, dict):
            required = current.get("required", [])
            if isinstance(required, list):
                for key in required:
                    if key not in item:
                        issues.append(SchemaIssue(item_path, f"missing required property {key!r}"))
            properties = current.get("properties", {})
            properties = properties if isinstance(properties, dict) else {}
            for key, nested_schema in properties.items():
                if key in item and isinstance(nested_schema, dict):
                    issues.extend(validate(item[key], nested_schema, f"{item_path}.{key}"))
            additional = current.get("additionalProperties", True)
            for key, nested in item.items():
                if key in properties:
                    continue
                if additional is False:
                    issues.append(SchemaIssue(f"{item_path}.{key}", "additional property is not allowed"))
                elif isinstance(additional, dict):
                    issues.extend(validate(nested, additional, f"{item_path}.{key}"))

        all_of = current.get("allOf")
        if isinstance(all_of, list):
            for branch in all_of:
                if isinstance(branch, dict):
                    issues.extend(validate(item, branch, item_path))
        one_of = current.get("oneOf")
        if isinstance(one_of, list):
            matches = sum(
                not validate(item, branch, item_path)
                for branch in one_of
                if isinstance(branch, dict)
            )
            if matches != 1:
                issues.append(SchemaIssue(item_path, "expected exactly one matching schema branch"))
        any_of = current.get("anyOf")
        if isinstance(any_of, list) and not any(
            not validate(item, branch, item_path)
            for branch in any_of
            if isinstance(branch, dict)
        ):
            issues.append(SchemaIssue(item_path, "expected at least one matching schema branch"))
        condition = current.get("if")
        if isinstance(condition, dict):
            branch = current.get("then" if not validate(item, condition, item_path) else "else")
            if isinstance(branch, dict):
                issues.extend(validate(item, branch, item_path))
        return issues

    return validate(value, schema, path)


def _confined_file(root: Path, relative: str, label: str) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise SchemaRegistryError(f"{label} must be a non-empty relative path")
    unresolved = root / relative
    cursor = root
    for part in Path(relative).parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise SchemaRegistryError(f"{label} traverses a symlink")
    candidate = unresolved.resolve()
    resolved_root = root.resolve()
    if not candidate.is_relative_to(resolved_root):
        raise SchemaRegistryError(f"{label} escapes the repository root")
    if not candidate.is_file():
        raise SchemaRegistryError(f"{label} must resolve to a regular non-symlink file")
    return candidate


@dataclass(frozen=True)
class SchemaRegistry:
    root: Path
    entries: Mapping[str, Mapping[str, Any]]

    def schema(self, logical_id: str) -> Mapping[str, Any]:
        entry = self.entries.get(logical_id)
        if entry is None:
            raise SchemaRegistryError(f"unregistered StateSpec schema ID: {logical_id!r}")
        path = _confined_file(self.root, entry["path"], f"schema {logical_id}")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SchemaRegistryError(f"could not parse schema {logical_id}: {exc}") from exc
        if not isinstance(value, dict) or value.get("$id") != logical_id:
            raise SchemaRegistryError(f"schema {logical_id} has a mismatched $id")
        return value

    def validate(self, logical_id: str, value: Any) -> list[SchemaIssue]:
        return validate_json_schema(value, self.schema(logical_id))


def load_schema_registry(path: Path | str, *, root: Path | str | None = None) -> SchemaRegistry:
    registry_path = Path(path).resolve()
    repository_root = Path(root).resolve() if root is not None else registry_path.parents[1]
    if registry_path.is_symlink() or not registry_path.is_file():
        raise SchemaRegistryError("schema registry must be a regular non-symlink file")
    try:
        value = json.loads(registry_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SchemaRegistryError(f"could not parse schema registry: {exc}") from exc
    if not isinstance(value, dict) or set(value) != {"schema", "entries"}:
        raise SchemaRegistryError("schema registry must contain exactly schema and entries")
    if value.get("schema") != REGISTRY_FORMAT or not isinstance(value.get("entries"), list):
        raise SchemaRegistryError("schema registry format is unsupported")
    entries: dict[str, Mapping[str, Any]] = {}
    for index, entry in enumerate(value["entries"]):
        required = {"id", "path", "documentKind", "discriminator"}
        if not isinstance(entry, dict) or set(entry) != required:
            raise SchemaRegistryError(f"schema registry entry {index} has an invalid shape")
        logical_id = entry.get("id")
        if not isinstance(logical_id, str) or not logical_id or logical_id in entries:
            raise SchemaRegistryError(f"schema registry entry {index} has a duplicate or invalid ID")
        if not isinstance(entry.get("documentKind"), str) or not entry["documentKind"]:
            raise SchemaRegistryError(f"schema registry entry {index} has an invalid document kind")
        discriminator = entry.get("discriminator")
        if (
            not isinstance(discriminator, dict)
            or set(discriminator) != {"field", "value"}
            or not all(isinstance(discriminator[key], str) and discriminator[key] for key in discriminator)
        ):
            raise SchemaRegistryError(f"schema registry entry {index} has an invalid discriminator")
        _confined_file(repository_root, entry.get("path"), f"schema registry entry {index}")
        entries[logical_id] = dict(entry)
    registry = SchemaRegistry(repository_root, entries)
    for logical_id in entries:
        registry.schema(logical_id)
    return registry


def find_builtin_schema_registry() -> SchemaRegistry:
    configured = os.environ.get("STATEPORT_SCHEMA_REGISTRY")
    if configured:
        path = Path(configured)
        return load_schema_registry(path, root=path.resolve().parents[1])
    repository_root = Path(__file__).resolve().parents[4]
    path = repository_root / "config/statespec-schema-registry.v1.json"
    return load_schema_registry(path, root=repository_root)


def load_document(path: Path | str) -> Any:
    document_path = Path(path)
    text = document_path.read_text(encoding="utf-8")
    if document_path.suffix.lower() == ".json":
        return json.loads(text)
    return parse_yaml_text(text)
