#!/usr/bin/env python3
"""Validate application-experience and functionality-preservation contracts."""

from __future__ import annotations

import ast
import json
from pathlib import Path
import re
import sys
from typing import Any

import jsonschema
import yaml


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "packages" / "application-experience" / "src"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

from stateport_application_experience import ExperienceRegistry, load_experience_policy  # noqa: E402


PRESERVATION_EXTENSION_FORMAT = "stateport.functionality-preservation-extension/v1"
PRESERVATION_EXTENSION_ROOT = ROOT / "config" / "functionality-preservation.extensions"


def _load_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.relative_to(ROOT)} must contain an object")
    return value


def _merge_preservation_extensions(manifest: dict[str, Any]) -> dict[str, Any]:
    """Merge schema-compatible API operations from bounded extension files.

    The merged manifest is validated by the existing v1 JSON schema, so an
    extension can only add ordinary preservation entries; it cannot weaken or
    replace any base route, control, capability, alias, or API contract.
    """

    operations = manifest.get("apiOperations")
    if not isinstance(operations, list):
        raise ValueError("functionality-preservation apiOperations must be a list")
    if not PRESERVATION_EXTENSION_ROOT.exists():
        return manifest
    if PRESERVATION_EXTENSION_ROOT.is_symlink() or not PRESERVATION_EXTENSION_ROOT.is_dir():
        raise ValueError("functionality-preservation extension root is unsafe")
    for path in sorted(PRESERVATION_EXTENSION_ROOT.glob("*.yaml")):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"preservation extension path is unsafe: {path.relative_to(ROOT)}")
        extension = _load_yaml(path)
        if set(extension) != {"formatVersion", "scope", "apiOperations"}:
            raise ValueError(f"{path.relative_to(ROOT)} has an invalid extension shape")
        if extension["formatVersion"] != PRESERVATION_EXTENSION_FORMAT:
            raise ValueError(f"{path.relative_to(ROOT)} has an unsupported formatVersion")
        scope = extension["scope"]
        items = extension["apiOperations"]
        if not isinstance(scope, str) or not scope.strip():
            raise ValueError(f"{path.relative_to(ROOT)} scope is invalid")
        if not isinstance(items, list) or not items:
            raise ValueError(f"{path.relative_to(ROOT)} apiOperations must be a non-empty list")
        operations.extend(items)
    return manifest


def _safe_repo_file(relative: str) -> Path:
    candidate = ROOT / relative
    if candidate.is_symlink() or not candidate.is_file():
        raise ValueError(f"preservation evidence path is missing or unsafe: {relative}")
    resolved = candidate.resolve()
    resolved.relative_to(ROOT.resolve())
    return resolved


def _api_literals(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return {
        value.value
        for value in ast.walk(tree)
        if isinstance(value, ast.Constant)
        and isinstance(value.value, str)
        and (value.value.startswith("/v1/") or value.value in {"/session", "/health"})
    }


def _path_covers(literal: str, declared: list[str]) -> bool:
    if literal in declared:
        return True
    if literal.endswith("/"):
        return any(item.startswith(literal) for item in declared)
    return any(item.startswith(literal + "/") for item in declared)


# Every literal route path in apps/web/src/App.tsx must be classified by a
# declared preservation route; unclassified routes fail validation, which is
# the React-era equivalent of the old static-HTML hash-link allowlist. The
# app-scoped "settings" path doubles as the advanced-control surface.
ROUTE_CLASSIFICATION: dict[str, set[str]] = {
    "platform": {"platform-hub-route"},
    "settings/provider": {"provider-settings-route"},
    "applications": {"home-route"},
    "catalog": {"catalog-route"},
    "sources": {"platform-route"},
    "sources/:sourceId": {"platform-route"},
    "statebench": {"platform-route"},
    # The `deployments` path literal is shared by the top-level platform
    # deployments surface and the per-instance workbench infrastructure tool;
    # both preservation contracts cover it.
    "deployments": {"platform-deployments-route", "workbench-route"},
    "authority": {"platform-authority-route"},
    "updater": {"platform-updater-route"},
    "preview-routes": {"platform-preview-routes-route"},
    "execution-host": {"platform-execution-host-route"},
    "approvals": {"approvals-route"},
    "approvals/:approvalId": {"approvals-route"},
    "settings": {"settings-route", "advanced-route"},
    "settings/:group": {"settings-route", "advanced-route"},
    "app/:instanceId": {"application-route"},
    "conversation": {"conversation-route"},
    "workbench": {"workbench-route"},
    "files": {"workbench-route"},
    "terminal": {"workbench-route"},
    "orchestration": {"workbench-route"},
    "runs": {"workbench-route"},
    # The same nested path literal is used by the native application receipt
    # surface and the optional Workbench receipt tool; both contracts must be
    # preserved without making either route globally available.
    "receipts": {"application-receipts-route", "workbench-route"},
    "receipts/:receiptId": {"application-receipts-route", "workbench-route"},
    "*": set(),  # explicit NotFound handler, not a product route
}


def _validate_router_surface(manifest: dict[str, Any]) -> None:
    app = (ROOT / "apps" / "web" / "src" / "App.tsx").read_text(encoding="utf-8")
    paths = set(re.findall(r'path="([^"]+)"', app))
    unclassified = sorted(path for path in paths if path not in ROUTE_CLASSIFICATION)
    if unclassified:
        raise ValueError(f"unclassified router paths: {unclassified}")
    declared_routes = {item["id"] for item in manifest["uiRoutes"]}
    covered = set().union(*(ROUTE_CLASSIFICATION[path] for path in paths))
    uncovered = sorted(declared_routes - covered)
    if uncovered:
        raise ValueError(f"declared preservation routes without a router path: {uncovered}")
    unknown_classifications = sorted(covered - declared_routes)
    if unknown_classifications:
        raise ValueError(f"router paths reference undeclared preservation routes: {unknown_classifications}")

    legacy = (ROOT / "apps" / "web" / "src" / "legacyRoutes.ts").read_text(encoding="utf-8")
    block = re.search(r"LEGACY_BARE_ROUTES[^{]*\{(?P<body>.*?)\}", legacy, re.DOTALL)
    if block is None:
        raise ValueError("legacy hash normalization table is missing")
    targets = set(re.findall(r":\s*'(/[^']+)'", block.group("body")))
    router_targets = {f"/{path.split(':')[0].rstrip('/')}" for path in paths if path != "*"}
    unmapped = sorted(target for target in targets if target not in router_targets)
    if unmapped:
        raise ValueError(f"legacy hash aliases resolve to unknown routes: {unmapped}")
    if not re.search(r"platform:\s*'/applications'", legacy):
        raise ValueError("legacy #platform hash must normalize to the application-first home")

    # Preservation aliases are executable compatibility contracts, not prose
    # that may be relabelled deprecated when a replacement frontend lands.
    # Keep both bare aliases and application-scoped aliases declarative so the
    # validator can compare them with the manifest without executing browser
    # code or accepting a NotFound route as a "replacement".
    bare_entries = dict(re.findall(r"^\s*(\w+):\s*'([^']+)'", block.group("body"), re.MULTILINE))
    required_bare = {
        "instances": "/applications",
        "advanced": "/settings",
    }
    missing_bare = {
        key: target
        for key, target in required_bare.items()
        if bare_entries.get(key) != target
    }
    scoped_name_match = re.search(
        r"(LEGACY_(?:SCOPED|INSTANCE)_ROUTES)[^{]*\{(?P<body>.*?)\}",
        legacy,
        re.DOTALL,
    )
    scoped_entries = (
        {}
        if scoped_name_match is None
        else dict(re.findall(r"^\s*(\w+):\s*'([^']*)'", scoped_name_match.group("body"), re.MULTILINE))
    )
    required_scoped = {
        "instance": "",
        "conversation": "/conversation",
        "advanced": "/settings",
        "workbench": "/workbench",
    }
    missing_scoped = {
        key: target
        for key, target in required_scoped.items()
        if scoped_entries.get(key) != target
    }
    scoped_name = None if scoped_name_match is None else scoped_name_match.group(1)
    if missing_bare or missing_scoped or scoped_name is None or legacy.count(scoped_name) < 2:
        raise ValueError(
            "preserved legacy aliases are not implemented; "
            f"bare={missing_bare}, scoped={missing_scoped}"
        )


def _frontend_api_templates() -> set[str]:
    """Normalized endpoint templates declared by the typed HTTP client.

    apps/web/src/client/http/endpoints.ts is the single source of frontend
    paths; `${enc(name)}` segments normalize to `{name}` so they can be
    compared exactly against manifest apiOperations paths.
    """
    source = (ROOT / "apps" / "web" / "src" / "client" / "http" / "endpoints.ts").read_text(encoding="utf-8")
    templates: set[str] = set()
    for literal in re.findall(r"'(/v1/[^']*|/session)'", source):
        templates.add(literal)
    for template in re.findall(r"`(/v1/[^`]*|/session)`", source):
        normalized = re.sub(r"\$\{enc\((\w+)\)\}", r"{\1}", template)
        templates.add(normalized)
    return templates


def validate() -> dict[str, int]:
    manifest_path = ROOT / "config" / "functionality-preservation.v1.yaml"
    manifest = _merge_preservation_extensions(_load_yaml(manifest_path))
    schema = json.loads((ROOT / "schemas" / "functionality-preservation.v1.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(manifest)

    all_items = [*manifest["uiRoutes"], *manifest["userControls"], *manifest["apiOperations"], *manifest["capabilities"], *manifest["legacyAliases"]]
    identifiers = [item["id"] for item in all_items]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("functionality-preservation ids must be globally unique")
    for item in all_items:
        evidence = item["evidence"]
        content = _safe_repo_file(evidence["file"]).read_text(encoding="utf-8")
        if evidence["contains"] not in content:
            raise ValueError(f"preservation evidence is stale for {item['id']}")

    _validate_router_surface(manifest)

    declared_paths = [item["path"] for item in manifest["apiOperations"]]
    service_path = ROOT / "packages" / "persistent-app" / "src" / "stateport_persistent_app" / "service_process.py"
    uncovered_service = sorted(item for item in _api_literals(service_path) if not _path_covers(item, declared_paths))
    if uncovered_service:
        raise ValueError(f"service APIs lack preservation coverage: {uncovered_service}")

    dynamic = _load_yaml(ROOT / "config" / "frontend-dynamic-preservation.v1.yaml")
    dynamic_schema = json.loads((ROOT / "schemas" / "frontend-dynamic-preservation.v1.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(dynamic_schema).validate(dynamic)
    dynamic_items = [*dynamic.get("controls", []), *dynamic.get("operations", []), *dynamic.get("behaviors", [])]
    dynamic_ids = [item.get("id") for item in dynamic_items if isinstance(item, dict)]
    if len(dynamic_items) != len(dynamic_ids) or any(not isinstance(item, str) or not item for item in dynamic_ids) or len(dynamic_ids) != len(set(dynamic_ids)):
        raise ValueError("dynamic frontend preservation identifiers must be unique non-empty strings")
    for item in dynamic_items:
        evidence = item.get("evidence")
        if not isinstance(evidence, dict) or set(evidence) != {"file", "contains"}:
            raise ValueError(f"dynamic frontend evidence is invalid for {item.get('id')}")
        content = _safe_repo_file(str(evidence["file"])).read_text(encoding="utf-8")
        if str(evidence["contains"]) not in content:
            raise ValueError(f"dynamic frontend evidence is stale for {item['id']}")

    # The typed client may only call manifest-covered endpoints. The governed
    # file workspace path builder is generic, so coverage is enforced at the
    # operation level: every file-workspace operation invoked by the client
    # must be a declared dynamic preservation operation.
    file_workspace_prefix = "/v1/instances/{instanceId}/file-workspace/"
    coverage = set(declared_paths)
    uncovered_frontend = sorted(
        item
        for item in _frontend_api_templates()
        if item not in coverage and not item.startswith(file_workspace_prefix)
    )
    if uncovered_frontend:
        raise ValueError(f"frontend API use lacks preservation coverage: {uncovered_frontend}")
    declared_operations = {item["operation"] for item in dynamic.get("operations", [])}
    http_source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / "apps" / "web" / "src" / "client" / "http").glob("*.ts"))
    )
    invoked_operations = set(re.findall(r"(?:getOperation|postOperation)\(\s*instanceId,\s*'(\w+)'", http_source))
    undeclared_operations = sorted(invoked_operations - declared_operations)
    if undeclared_operations:
        raise ValueError(f"frontend file-workspace operations lack preservation coverage: {undeclared_operations}")
    # The current readFile contract returns its exact path, content hash, Git
    # base SHA, read-only state, and encoding in one atomic response. That
    # supersedes a second readFileMetadata round trip without dropping the
    # preserved metadata outcome. Keep this equivalence explicit and narrow:
    # the operation is only covered while readFile is really invoked and the
    # typed response still validates a metadata object.
    equivalent_operations: set[str] = set()
    if "readFile" in invoked_operations and "metadata: z.object({" in http_source:
        equivalent_operations.add("readFileMetadata")
    dynamic_gap_ids = {
        item["id"]
        for item in dynamic_items
        if item["evidence"]["file"] == "docs/design/FRONTEND_FEATURE_MATRIX.md"
    }
    dynamic_gap_ids.update(
        item["id"]
        for item in dynamic.get("operations", [])
        if item["operation"] not in invoked_operations
        and item["operation"] not in equivalent_operations
    )
    surface_gap_ids = {
        item["id"]
        for item in [*manifest["uiRoutes"], *manifest["userControls"], *manifest["capabilities"]]
        if item["status"] == "gap"
    }

    registry = ExperienceRegistry(ROOT)
    policy = load_experience_policy(ROOT / "config" / "application-experience-policy.yaml")
    descriptors = registry.list()
    experience_schema = json.loads((ROOT / "schemas" / "application-experience.v1.schema.json").read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(experience_schema)
    for descriptor in descriptors:
        validator.validate(descriptor)
        resolved = registry.resolve(
            descriptor["applicationId"],
            instance_grants=policy.grants_for(descriptor["applicationId"]),
            operator_permits=policy.operator_permits,
            runtime_capabilities=policy.runtime_capabilities,
            actor_permissions=policy.permissions_for("local_user"),
        )
        if resolved is None or resolved["descriptorIdentity"]["descriptorDigest"] != resolved["installProjection"]["descriptorDigest"]:
            raise ValueError("experience resolution lacks a stable descriptor binding")
        if resolved["installProjection"]["grantsCapabilities"] is not False:
            raise ValueError("experience install projection attempted to grant capabilities")

    return {
        "descriptors": len(descriptors),
        "routes": len(manifest["uiRoutes"]),
        "controls": len(manifest["userControls"]),
        "apis": len(manifest["apiOperations"]),
        "capabilities": len(manifest["capabilities"]),
        "aliases": len(manifest["legacyAliases"]),
        "dynamicControls": len(dynamic["controls"]),
        "dynamicOperations": len(dynamic["operations"]),
        "dynamicBehaviors": len(dynamic["behaviors"]),
        "surfaceGaps": len(surface_gap_ids),
        "dynamicGaps": len(dynamic_gap_ids),
    }


def main() -> int:
    counts = validate()
    print("PASS " + " ".join(f"{key}={value}" for key, value in counts.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
