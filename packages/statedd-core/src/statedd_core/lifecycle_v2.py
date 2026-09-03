"""Deterministic parsing and normalisation for lifecycle manifest v2.

This module is intentionally declarative.  It validates lifecycle intent but
does not resolve Git sources, execute migrations, compose prose, or apply an
upgrade.  Callers must ask ``assert_materializable_v2`` before writing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from statedd_core.lifecycle_errors import LifecycleError
from statedd_core.yaml import StateDDYamlError, parse_yaml_text


MANIFEST_V2_FORMAT = "statedd.template-manifest/v2"
INSTANCE_OVERRIDES_FORMAT = "statedd.instance-overrides/v1"
SOURCE_CLASSES = {"canonical_source", "synthetic_fixture", "compatibility_fixture"}
OWNERS = {"template", "instance", "generated"}
KINDS = {"file", "tree"}
PROVISION_POLICIES = {
    "copy_from_template",
    "create_if_missing",
    "generated_output",
    "composed_output",
    "append_only_state",
    "schema_migration_intent",
    "retire",
}
UPDATE_POLICIES = {
    "replace_if_unmodified",
    "preserve",
    "generated",
    "compose",
    "append_only",
    "schema_migrate",
    "retire",
}
RETIREMENT_POLICIES = {"retain", "remove_if_unmodified"}
SENSITIVITIES = {"public", "internal", "private", "secret"}


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LifecycleError(f"{label} must be a non-empty string")
    return value


def _path(value: Any, label: str) -> str:
    text = _string(value, label)
    if "\\" in text:
        raise LifecycleError(
            f"{label} must use POSIX separators",
            code="unsafe_path",
        )
    candidate = Path(text)
    if candidate.is_absolute() or text.startswith("/") or (len(text) > 1 and text[1] == ":"):
        raise LifecycleError(f"{label} must be a relative path")
    if any(part in {".", ".."} for part in candidate.parts):
        raise LifecycleError(f"{label} must not traverse parent directories")
    return candidate.as_posix()


def _strings(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise LifecycleError(f"{label} must be a list of non-empty strings")
    if len(set(value)) != len(value):
        raise LifecycleError(f"{label} must not contain duplicates")
    return list(value)


def _safe_existing_path(root: Path, relative: str, label: str) -> Path:
    """Return a source file only when no source-path component is a symlink."""
    if root.is_symlink():
        raise LifecycleError("template root symlink is not safe")
    current = root
    for part in Path(relative).parts:
        current = current / part
        if current.is_symlink():
            raise LifecycleError(f"{label} uses a symlink, which is not safe")
    resolved_root = root.resolve()
    resolved = (root / relative).resolve()
    if not resolved.is_relative_to(resolved_root):
        raise LifecycleError(f"{label} escapes its root")
    return resolved


def _module_map(raw_modules: Any, asset_ids: set[str]) -> dict[str, dict[str, Any]]:
    if not isinstance(raw_modules, list) or not raw_modules:
        raise LifecycleError("modules must be a non-empty list")
    modules: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(raw_modules):
        if not isinstance(raw, dict):
            raise LifecycleError(f"modules[{index}] must be a mapping")
        module_id = _string(raw.get("id"), f"modules[{index}].id")
        if module_id in modules:
            raise LifecycleError(f"modules contains duplicate module id {module_id!r}")
        assets = _strings(raw.get("assets", []), f"modules[{index}].assets")
        unknown_assets = sorted(set(assets) - asset_ids)
        if unknown_assets:
            raise LifecycleError(
                f"modules[{index}].assets references unknown assets: {', '.join(unknown_assets)}"
            )
        self_tests = raw.get("selfTests", [])
        if not isinstance(self_tests, list) or any(not isinstance(item, dict) for item in self_tests):
            raise LifecycleError(f"modules[{index}].selfTests must be a list of mappings")
        modules[module_id] = {
            "id": module_id,
            "contractVersion": _string(raw.get("contractVersion"), f"modules[{index}].contractVersion"),
            "dependencies": _strings(raw.get("dependencies", []), f"modules[{index}].dependencies"),
            "conflicts": _strings(raw.get("conflicts", []), f"modules[{index}].conflicts"),
            "capabilities": _strings(raw.get("capabilities", []), f"modules[{index}].capabilities"),
            "assets": sorted(assets),
            "selfTests": sorted((dict(item) for item in self_tests), key=lambda item: str(item.get("id", ""))),
            "order": raw.get("order", 0),
        }
        if isinstance(modules[module_id]["order"], bool) or not isinstance(modules[module_id]["order"], int):
            raise LifecycleError(f"modules[{index}].order must be an integer")
    for module in modules.values():
        for relation in ("dependencies", "conflicts"):
            unknown = sorted(set(module[relation]) - set(modules))
            if unknown:
                raise LifecycleError(
                    f"module {module['id']!r} has unknown {relation}: {', '.join(unknown)}"
                )
    return modules


def resolve_modules(modules: dict[str, dict[str, Any]], selected: list[str]) -> list[str]:
    """Resolve selected modules with stable dependency-first ordering."""
    unknown = sorted(set(selected) - set(modules))
    if unknown:
        raise LifecycleError(f"selectedModules has unknown modules: {', '.join(unknown)}")
    visiting: set[str] = set()
    visited: set[str] = set()
    resolved: list[str] = []

    def visit(module_id: str) -> None:
        if module_id in visiting:
            raise LifecycleError(f"module dependency cycle includes {module_id!r}")
        if module_id in visited:
            return
        visiting.add(module_id)
        for dependency in sorted(
            modules[module_id]["dependencies"], key=lambda item: (modules[item]["order"], item)
        ):
            visit(dependency)
        visiting.remove(module_id)
        visited.add(module_id)
        resolved.append(module_id)

    for module_id in sorted(selected, key=lambda item: (modules[item]["order"], item)):
        visit(module_id)
    selected_set = set(resolved)
    for module_id in resolved:
        conflict = selected_set.intersection(modules[module_id]["conflicts"])
        if conflict:
            raise LifecycleError(
                f"selected modules conflict: {module_id!r} conflicts with {sorted(conflict)[0]!r}"
            )
    return resolved


def _nested(left: str, right: str) -> bool:
    return left == right or left.startswith(right + "/")


def _retirement_policy(raw: dict[str, Any], *, owner: str, provision: str, update: str, label: str) -> str:
    """Normalize the deliberately narrow removal policy.

    Retention is the safe default.  Removal is an opt-in for generated output
    only, and still requires the lifecycle to prove that the generated output
    matches its locked baseline before it can be applied.
    """
    retirement = raw.get("retirementPolicy")
    removal = raw.get("removalPolicy")
    if retirement is not None and removal is not None and retirement != removal:
        raise LifecycleError(f"{label} has conflicting retirementPolicy and removalPolicy")
    value = retirement if retirement is not None else removal
    # ``updatePolicy: retire`` is an existing declarative spelling in the v2
    # vocabulary.  It is accepted only as the same explicit generated-output
    # opt-in; all other uses remain fail-closed.
    if value is None and update == "retire":
        value = "remove_if_unmodified"
    if value is None:
        return "retain"
    if value == "remove":
        value = "remove_if_unmodified"
    if value not in RETIREMENT_POLICIES:
        raise LifecycleError(
            f"{label} must be one of {sorted(RETIREMENT_POLICIES)}"
        )
    if value == "remove_if_unmodified" and (
        owner != "generated" or provision != "generated_output"
    ):
        raise LifecycleError(
            f"{label} removal is allowed only for generated_output assets owned by generated"
        )
    return value


def normalize_manifest_v2(data: dict[str, Any], root: Path) -> dict[str, Any]:
    """Validate a v2 manifest and return its deterministic normal form."""
    if data.get("formatVersion") != MANIFEST_V2_FORMAT:
        raise LifecycleError(f"formatVersion must be {MANIFEST_V2_FORMAT!r}")
    template = data.get("template")
    if not isinstance(template, dict):
        raise LifecycleError("template must be a mapping")
    template_id = _string(template.get("id"), "template.id")
    release_version = _string(template.get("releaseVersion"), "template.releaseVersion")
    statedd_spec_version = _string(template.get("stateddSpecVersion"), "template.stateddSpecVersion")
    instance_schema_version = _string(template.get("instanceSchemaVersion"), "template.instanceSchemaVersion")
    source = data.get("source")
    if not isinstance(source, dict):
        raise LifecycleError("source must be a mapping")
    source_class = source.get("class")
    if source_class not in SOURCE_CLASSES:
        raise LifecycleError(f"source.class must be one of {sorted(SOURCE_CLASSES)}")
    production_eligible = source.get("productionEligible")
    if not isinstance(production_eligible, bool):
        raise LifecycleError("source.productionEligible must be a boolean")
    if source_class != "canonical_source" and production_eligible:
        raise LifecycleError("fixture sources must set productionEligible to false")
    if source_class == "synthetic_fixture" and not template_id.startswith("stateport.fixture."):
        raise LifecycleError("synthetic fixtures must use a stateport.fixture. template id")

    raw_assets = data.get("assets")
    if not isinstance(raw_assets, list) or not raw_assets:
        raise LifecycleError("assets must be a non-empty list")
    raw_by_id: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(raw_assets):
        if not isinstance(raw, dict):
            raise LifecycleError(f"assets[{index}] must be a mapping")
        asset_id = _string(raw.get("id"), f"assets[{index}].id")
        if asset_id in raw_by_id:
            raise LifecycleError(f"assets contains duplicate asset id {asset_id!r}")
        raw_by_id[asset_id] = raw
    modules = _module_map(data.get("modules"), set(raw_by_id))
    selected = _strings(data.get("selectedModules"), "selectedModules")
    resolved_modules = resolve_modules(modules, selected)

    normalized_assets: list[dict[str, Any]] = []
    exact_paths: set[str] = set()
    exact_owners: dict[str, str] = {}
    tree_paths: set[str] = set()
    for index, raw in enumerate(raw_assets):
        asset_id = _string(raw.get("id"), f"assets[{index}].id")
        kind = raw.get("kind")
        if kind not in KINDS:
            raise LifecycleError(f"assets[{index}].kind must be one of {sorted(KINDS)}")
        path = _path(raw.get("path"), f"assets[{index}].path")
        if kind == "file":
            if path in exact_paths:
                if exact_owners[path] != raw.get("owner"):
                    raise LifecycleError(f"assets assigns conflicting owners to exact path {path!r}")
                raise LifecycleError(f"assets contains duplicate exact path {path!r}")
            exact_paths.add(path)
            exact_owners[path] = raw.get("owner")
        else:
            if path in tree_paths:
                raise LifecycleError(f"assets contains duplicate tree path {path!r}")
            tree_paths.add(path)
        owner = raw.get("owner")
        if owner not in OWNERS:
            raise LifecycleError(f"assets[{index}].owner must be one of {sorted(OWNERS)}")
        provision = raw.get("provisionPolicy")
        if provision not in PROVISION_POLICIES:
            raise LifecycleError(f"assets[{index}].provisionPolicy is unsupported")
        update = raw.get("updatePolicy")
        if update not in UPDATE_POLICIES:
            raise LifecycleError(f"assets[{index}].updatePolicy is unsupported")
        required = raw.get("required")
        if not isinstance(required, bool):
            raise LifecycleError(f"assets[{index}].required must be a boolean")
        sensitivity = raw.get("sensitivity")
        if sensitivity not in SENSITIVITIES:
            raise LifecycleError(f"assets[{index}].sensitivity is invalid")
        selectors = _strings(raw.get("selectingModules"), f"assets[{index}].selectingModules")
        if not selectors:
            raise LifecycleError(f"assets[{index}] has no owning module")
        unknown_selectors = sorted(set(selectors) - set(modules))
        if unknown_selectors:
            raise LifecycleError(
                f"assets[{index}].selectingModules has unknown modules: {', '.join(unknown_selectors)}"
            )
        for module_id in selectors:
            if asset_id not in modules[module_id]["assets"]:
                raise LifecycleError(
                    f"asset {asset_id!r} is selected by {module_id!r} but not declared in its assets"
                )
        source_path = raw.get("source")
        if provision == "copy_from_template":
            source_path = _path(source_path, f"assets[{index}].source")
            source_file = _safe_existing_path(root, source_path, f"assets[{index}].source")
            if not source_file.is_file():
                raise LifecycleError(f"manifest source file is missing: {source_path}")
        elif source_path is not None:
            raise LifecycleError(f"assets[{index}].source is only valid for copy_from_template")
        generator = raw.get("generator")
        composer = raw.get("composer")
        if provision == "generated_output" and not isinstance(generator, str):
            raise LifecycleError(f"assets[{index}].generator is required for generated output")
        if provision == "composed_output" and not isinstance(composer, str):
            raise LifecycleError(f"assets[{index}].composer is required for composed output")
        retirement_policy = _retirement_policy(
            raw,
            owner=owner,
            provision=provision,
            update=update,
            label=f"assets[{index}].retirementPolicy",
        )
        schema_id = raw.get("schema")
        if schema_id is not None:
            schema_id = _string(schema_id, f"assets[{index}].schema")
        normalized_assets.append(
            {
                "id": asset_id,
                "path": path,
                "kind": kind,
                "owner": owner,
                "role": _string(raw.get("role"), f"assets[{index}].role"),
                "provisionPolicy": provision,
                "updatePolicy": update,
                "required": required,
                "schema": schema_id,
                "sensitivity": sensitivity,
                "generator": generator,
                "composer": composer,
                "source": source_path,
                "selectingModules": sorted(selectors),
                "retirementPolicy": retirement_policy,
            }
        )
    for module in modules.values():
        for asset_id in module["assets"]:
            if module["id"] not in raw_by_id[asset_id].get("selectingModules", []):
                raise LifecycleError(
                    f"module {module['id']!r} declares asset {asset_id!r} without reciprocal selectingModules"
                )
    for tree in tree_paths:
        if any(_nested(tree, other) or _nested(other, tree) for other in tree_paths if other != tree):
            raise LifecycleError(f"tree paths overlap ambiguously: {tree!r}")
        if any(_nested(path, tree) for path in exact_paths):
            raise LifecycleError(f"exact path overlaps declared tree: {tree!r}")

    selected_set = set(resolved_modules)
    selected_assets = [
        item for item in normalized_assets if selected_set.intersection(item["selectingModules"])
    ]
    files: list[dict[str, Any]] = []
    trees: list[dict[str, Any]] = []
    provision_map = {
        "copy_from_template": "copy",
        "create_if_missing": "create",
        "generated_output": "generate",
    }
    merge_map = {
        "replace_if_unmodified": "replace",
        "preserve": "preserve",
        "generated": "replace",
        "append_only": "append_only",
        "retire": "replace",
    }
    for item in sorted(selected_assets, key=lambda value: (value["path"], value["id"])):
        if item["kind"] == "tree":
            trees.append(item)
            continue
        legacy = dict(item)
        legacy["provision"] = provision_map.get(item["provisionPolicy"], "unsupported")
        legacy["merge"] = merge_map.get(item["updatePolicy"], "unsupported")
        legacy["generation"] = item["generator"] or "none"
        legacy["retirementPolicy"] = item["retirementPolicy"]
        files.append(legacy)
    return {
        "formatVersion": MANIFEST_V2_FORMAT,
        "normalizedFrom": MANIFEST_V2_FORMAT,
        "template": {
            "id": template_id,
            "releaseVersion": release_version,
            "stateddSpecVersion": statedd_spec_version,
            "instanceSchemaVersion": instance_schema_version,
            "manifestFormatVersion": MANIFEST_V2_FORMAT,
        },
        "templateId": template_id,
        "templateVersion": release_version,
        "sourceClass": source_class,
        "productionEligible": production_eligible,
        "modules": [modules[item] for item in resolved_modules],
        "selectedModules": resolved_modules,
        "assets": selected_assets,
        "files": files,
        "trees": trees,
    }


def normalize_manifest_v1(data: dict[str, Any]) -> dict[str, Any]:
    """Add v2-shaped metadata to an already validated v1 representation."""
    result = dict(data)
    result.update(
        {
            "normalizedFrom": "statedd.template-manifest/v1",
            "template": {
                "id": data["templateId"],
                "releaseVersion": data["templateVersion"],
                "stateddSpecVersion": "unknown-v1",
                "instanceSchemaVersion": "unknown-v1",
                "manifestFormatVersion": "statedd.template-manifest/v1",
            },
            "sourceClass": "legacy_local_development",
            "productionEligible": False,
            "modules": [],
            "selectedModules": [],
            "assets": list(data["files"]),
            "trees": [],
            "v2Limitations": [
                "v1 has no module declarations",
                "v1 has no declared source class or production eligibility",
                "v1 has no owned directory trees or explicit ejections",
            ],
        }
    )
    return result


def assert_materializable_v2(
    manifest: dict[str, Any], *, allow_generated_baseline: bool = False
) -> None:
    """Reject declared v2 semantics that the current materializer cannot execute."""
    if manifest.get("formatVersion") != MANIFEST_V2_FORMAT:
        return
    supported_files = {
        ("file", "template", "copy_from_template", "replace_if_unmodified"),
        ("file", "instance", "create_if_missing", "preserve"),
        ("file", "instance", "create_if_missing", "append_only"),
        ("file", "generated", "generated_output", "generated"),
        ("file", "generated", "generated_output", "retire"),
    }
    supported_trees = {
        ("tree", "instance", "create_if_missing", "preserve"),
        ("tree", "instance", "create_if_missing", "append_only"),
        ("tree", "template", "create_if_missing", "preserve"),
    }
    for asset in manifest["assets"]:
        key = (asset["kind"], asset["owner"], asset["provisionPolicy"], asset["updatePolicy"])
        supported = key in (supported_trees if asset["kind"] == "tree" else supported_files)
        if (
            allow_generated_baseline
            and asset["kind"] == "file"
            and asset["provisionPolicy"] == "generated_output"
            and asset["updatePolicy"] == "generated"
            and isinstance(asset.get("generator"), str)
        ):
            # A canonical repository may commit generated compatibility views.
            # StatePort may copy that baseline but never executes arbitrary
            # generator code from the source repository.
            supported = True
        if not supported:
            raise LifecycleError(
                "v2 strategy is declared but not materializable: "
                f"{asset['path']} ({asset['provisionPolicy']}/{asset['updatePolicy']})",
                code="unsupported_strategy",
            )
        if (
            asset["provisionPolicy"] == "generated_output"
            and asset.get("generator") != "materializer"
            and not (
                allow_generated_baseline
                and asset["kind"] == "file"
                and asset["updatePolicy"] == "generated"
                and isinstance(asset.get("generator"), str)
            )
        ):
            raise LifecycleError(
                f"v2 generated asset is not materializable by this materializer: {asset['path']}",
                code="unsupported_strategy",
            )


def assert_production_eligible(manifest: dict[str, Any]) -> None:
    """Reject fixture and legacy manifests from production source selection."""
    if manifest.get("sourceClass") != "canonical_source" or not manifest.get("productionEligible"):
        raise LifecycleError("manifest is not eligible for canonical production source selection")


def assert_fixture_use_allowed(manifest: dict[str, Any], allow_fixture: bool) -> None:
    """Require an explicit development/test opt-in before materialising fixtures."""
    if (
        manifest.get("formatVersion") == MANIFEST_V2_FORMAT
        and manifest.get("sourceClass") in {"synthetic_fixture", "compatibility_fixture"}
        and not allow_fixture
    ):
        raise LifecycleError("synthetic fixtures require explicit test/development opt-in")


def validate_instance_overrides(data: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    """Validate explicit ejections without applying any merge or upgrade."""
    if data.get("formatVersion") != INSTANCE_OVERRIDES_FORMAT:
        raise LifecycleError(f"override formatVersion must be {INSTANCE_OVERRIDES_FORMAT!r}")
    raw_ejections = data.get("ejections", [])
    if not isinstance(raw_ejections, list):
        raise LifecycleError("overrides.ejections must be a list")
    files = {item["path"]: item for item in manifest.get("files", [])}
    ejections: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_ejections):
        if not isinstance(raw, dict):
            raise LifecycleError(f"overrides.ejections[{index}] must be a mapping")
        path = _path(raw.get("path"), f"overrides.ejections[{index}].path")
        if path in seen:
            raise LifecycleError(f"overrides.ejections contains duplicate path {path!r}")
        seen.add(path)
        asset = files.get(path)
        if asset is None or asset.get("owner") != "template":
            raise LifecycleError("an ejection must name a template-owned exact file")
        ejections.append({"path": path, "reason": _string(raw.get("reason"), f"overrides.ejections[{index}].reason")})
    return {"formatVersion": INSTANCE_OVERRIDES_FORMAT, "ejections": sorted(ejections, key=lambda item: item["path"])}


def load_instance_overrides(instance_root: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    """Load optional ejection records from an instance without changing it."""
    path = instance_root / ".statedd" / "overrides.yaml"
    if not path.exists():
        return {"formatVersion": INSTANCE_OVERRIDES_FORMAT, "ejections": []}
    if path.is_symlink():
        raise LifecycleError("instance overrides symlink is not safe")
    try:
        data = parse_yaml_text(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, StateDDYamlError) as exc:
        raise LifecycleError(f"could not read instance overrides: {exc}") from exc
    if not isinstance(data, dict):
        raise LifecycleError("instance overrides must contain a mapping")
    return validate_instance_overrides(data, manifest)
