#!/usr/bin/env python3
"""Validate StatePort's logical StateSpec schema registry and live fixtures."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "packages/statedd-core/src"
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))

from statedd_core import (  # noqa: E402
    BUILTIN_SCHEMA_IDS,
    INSTANCE_SCHEMA_ID,
    LOCK_SCHEMA_ID,
    SchemaRegistryError,
    create_instance,
    load_schema_registry,
    validate_json_schema,
    validate_lifecycle_lock,
)
from statedd_core.lifecycle import load_template_manifest  # noqa: E402
from statedd_core.schema_registry import load_document  # noqa: E402


class StateSpecSchemaValidationError(ValueError):
    pass


def validate_repository(root: Path) -> dict[str, object]:
    registry_path = root / "config/statespec-schema-registry.v1.json"
    registry = load_schema_registry(registry_path, root=root)
    if set(registry.entries) != set(BUILTIN_SCHEMA_IDS):
        raise StateSpecSchemaValidationError(
            "registry must contain the exact built-in StateSpec schema IDs"
        )

    registry_value = json.loads(registry_path.read_text(encoding="utf-8"))
    registry_schema = json.loads(
        (root / "schemas/statespec-schema-registry.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    meta_issues = validate_json_schema(registry_value, registry_schema)
    if meta_issues:
        raise StateSpecSchemaValidationError(
            "registry schema validation failed: "
            + "; ".join(f"{issue.path}: {issue.message}" for issue in meta_issues)
        )

    observed: set[str] = set()
    manifests = sorted(
        {
            *root.glob("templates/*/.statedd/manifest.yaml"),
            *root.glob("fixtures/templates/*/.statedd/manifest.yaml"),
        }
    )
    for manifest_path in manifests:
        manifest = load_template_manifest(manifest_path.parents[1])
        for asset in manifest.get("assets", []):
            logical_id = asset.get("schema")
            if logical_id is not None:
                if not isinstance(logical_id, str):
                    raise StateSpecSchemaValidationError(
                        f"{manifest_path.relative_to(root)} has a non-string schema ID"
                    )
                registry.schema(logical_id)
                observed.add(logical_id)
        if manifest.get("formatVersion") == "statedd.template-manifest/v2":
            logical_id = manifest["template"].get("instanceSchemaVersion")
            if not isinstance(logical_id, str):
                raise StateSpecSchemaValidationError(
                    f"{manifest_path.relative_to(root)} has no instance schema version"
                )
            registry.schema(logical_id)
            observed.add(logical_id)
    if observed != set(BUILTIN_SCHEMA_IDS):
        raise StateSpecSchemaValidationError(
            f"tracked manifests resolve the wrong schema set: {sorted(observed)}"
        )

    instance = load_document(root / "instances/demo-classdd/instance.yaml")
    instance_issues = registry.validate(INSTANCE_SCHEMA_ID, instance)
    if instance_issues:
        raise StateSpecSchemaValidationError(
            "demo instance schema validation failed: "
            + "; ".join(f"{issue.path}: {issue.message}" for issue in instance_issues)
        )

    generated: list[str] = []
    with tempfile.TemporaryDirectory() as temporary:
        temporary_root = Path(temporary)
        variants = (
            (root / "templates/classdd", False, "v1"),
            (root / "fixtures/templates/lifecycle-v2-minimal", True, "v2-local"),
        )
        for template, allow_fixture, label in variants:
            lock = create_instance(
                template,
                temporary_root / label,
                instance_id=f"schema-{label}",
                name="Schema fixture",
                owner_name="StatePort",
                owner_handle="stateport",
                allow_fixture=allow_fixture,
            )
            issues = registry.validate(LOCK_SCHEMA_ID, lock)
            if issues:
                raise StateSpecSchemaValidationError(
                    f"generated {label} lock schema validation failed: "
                    + "; ".join(f"{issue.path}: {issue.message}" for issue in issues)
                )
            validate_lifecycle_lock(lock)
            generated.append(label)

    return {
        "schema": "stateport.statespec-schema-validation/v1",
        "registry": sorted(registry.entries),
        "manifestCount": len(manifests),
        "observed": sorted(observed),
        "generatedLockVariants": generated,
    }


def main() -> int:
    try:
        result = validate_repository(ROOT)
    except (OSError, UnicodeError, ValueError, SchemaRegistryError) as exc:
        print(f"FAIL: StateSpec schema registry: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
