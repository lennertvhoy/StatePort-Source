"""Command implementations for the StatePort admin CLI."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Callable


_REPO_ROOT = Path(__file__).resolve().parents[4]
for _source in (
    _REPO_ROOT / "packages" / "statedd-core" / "src",
    _REPO_ROOT / "packages" / "template-validator" / "src",
    _REPO_ROOT / "packages" / "execution-host" / "src",
    _REPO_ROOT / "apps" / "runner" / "src",
):
    if str(_source) not in sys.path:
        sys.path.insert(0, str(_source))

from runner import run_instance
from statedd_core import (
    LOCK_FORMAT,
    LifecycleError,
    StateDDYamlError,
    create_instance,
    describe_template_source,
    load_template_manifest,
    resolve_git_source,
    approve_upgrade_plan,
    apply_upgrade,
    parse_yaml_text,
    build_state_ir,
    build_state_pack,
    compare_state_packs,
    inspect_state_pack,
)
from template_validator import ValidationResult, validate_instance, validate_template
from execution_host.contracts import AgentRunSpec, BackendCapabilities, CapabilityRequest, negotiate, portable_export, validate_run_result

# Local-alpha operator commands live in a separate thin module so lifecycle
# command implementations remain reusable and reviewable.
from admin_cli.local_alpha import backup_cmd, catalog_cmd, demo_cmd, doctor_cmd, setup_cmd, persistent_instance_cmd, service_cmd, statepack_cmd

try:
    # These are the lifecycle package's intended public entry points.  The
    # current checkout predates their core implementation, so a local
    # read-only compatibility implementation is installed below when absent.
    from statedd_core import detect_overrides as _public_detect_overrides
except ImportError:
    _public_detect_overrides = None

try:
    from statedd_core import plan_upgrade as _public_plan_upgrade
except ImportError:
    _public_plan_upgrade = None


def _read_mapping(path: Path, label: str) -> dict[str, Any]:
    """Read one StateSpec YAML mapping without changing anything on disk."""
    try:
        value = parse_yaml_text(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, StateDDYamlError, ValueError) as exc:
        raise LifecycleError(f"could not read {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise LifecycleError(f"{label} must contain a mapping")
    return value


def _read_json_mapping(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LifecycleError(f"could not read {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise LifecycleError(f"{label} must contain a mapping")
    return value


def _confined_path(root: Path, relative_path: Any, label: str) -> Path:
    """Resolve a lock/manifest path while enforcing instance/template confinement."""
    if not isinstance(relative_path, str) or not relative_path.strip():
        raise LifecycleError(f"{label} must be a non-empty relative path")
    candidate = Path(relative_path)
    if (
        candidate.is_absolute()
        or relative_path.startswith("/")
        or (len(relative_path) > 1 and relative_path[1] == ":")
        or ".." in candidate.parts
    ):
        raise LifecycleError(f"{label} must be a relative path inside its root")
    resolved_root = root.resolve()
    resolved = (root / relative_path).resolve()
    if not resolved.is_relative_to(resolved_root):
        raise LifecycleError(f"{label} escapes its root")
    return resolved


def _hash_file(path: Path) -> str:
    try:
        return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise LifecycleError(f"could not hash {path}: {exc}") from exc


def _optional_hash(path: Path) -> str | None:
    if not path.exists():
        return None
    if not path.is_file():
        raise LifecycleError(f"materialized path is not a file: {path}")
    return _hash_file(path)


def _load_lock(instance_path: Path) -> dict[str, Any]:
    """Load the immutable lock used by the read-only lifecycle commands."""
    lock_path = _confined_path(instance_path, ".statedd/lock.yaml", "lockfile")
    lock = _read_mapping(lock_path, "lock.yaml")
    if lock.get("formatVersion") != LOCK_FORMAT:
        raise LifecycleError(f"lock formatVersion must be {LOCK_FORMAT!r}")
    template = lock.get("template")
    if not isinstance(template, dict):
        raise LifecycleError("lock.template must be a mapping")
    files = lock.get("files")
    if not isinstance(files, list):
        raise LifecycleError("lock.files must be a list")
    seen: set[str] = set()
    for index, entry in enumerate(files):
        if not isinstance(entry, dict):
            raise LifecycleError(f"lock.files[{index}] must be a mapping")
        path = entry.get("path")
        if not isinstance(path, str) or not path:
            raise LifecycleError(f"lock.files[{index}].path must be a non-empty string")
        if path in seen:
            raise LifecycleError(f"lock.files contains duplicate path {path!r}")
        seen.add(path)
        _confined_path(instance_path, path, f"lock.files[{index}].path")
    return lock


def _lock_file_status(instance_path: Path, entry: dict[str, Any]) -> dict[str, Any]:
    """Return a metadata-only status for one locked file."""
    path = entry["path"]
    target = _confined_path(instance_path, path, f"lock file {path}")
    owner = entry.get("owner")
    expected_hash = entry.get("materializedHash")

    # Generated entries are intentionally not treated as user overrides.  The
    # lock itself is one such entry in the v1 materialiser.
    if owner == "generated":
        return {
            "path": path,
            "owner": owner,
            "status": "generated",
            "expectedHash": expected_hash,
            "actualHash": None,
        }

    actual_hash = _optional_hash(target)
    if owner != "template":
        status = "preserved" if actual_hash is not None else "missing"
    elif actual_hash is None:
        status = "missing"
    elif expected_hash is None:
        status = "untracked"
    elif actual_hash == expected_hash:
        status = "unchanged"
    else:
        status = "modified"
    return {
        "path": path,
        "owner": owner,
        "status": status,
        "expectedHash": expected_hash,
        "actualHash": actual_hash,
    }


def _inspect_overrides_compat(instance_path: Path | str) -> dict[str, Any]:
    """Inspect template-owned drift without modifying the instance."""
    root = Path(instance_path)
    lock = _load_lock(root)
    files = [_lock_file_status(root, entry) for entry in lock["files"]]
    overrides = [
        item
        for item in files
        if item["owner"] == "template"
        and item["status"] in {"modified", "missing", "untracked"}
    ]
    return {
        "ok": True,
        "instance": root.as_posix(),
        "instanceId": lock.get("instanceId"),
        "template": lock.get("template"),
        "hasOverrides": bool(overrides),
        "overrideCount": len(overrides),
        "overrides": overrides,
        "files": files,
    }


def _manifest_file_hash(template_root: Path, item: dict[str, Any]) -> str | None:
    if item.get("provision") != "copy":
        return None
    source = _confined_path(template_root, item.get("source"), f"source {item.get('path')}")
    return _hash_file(source)


def _manifest_revision(template_root: Path, manifest: dict[str, Any]) -> str:
    """Compute the v1 source revision for a plan's target identity."""
    if manifest.get("formatVersion") == "statedd.template-manifest/v2":
        source = describe_template_source(template_root)
        revision = source.get("sourceDigest")
        if not isinstance(revision, str):
            raise LifecycleError("v2 source descriptor has no source digest")
        return revision
    digest = hashlib.sha256()
    digest.update(b"template.yaml\0")
    digest.update(_hash_file(_confined_path(template_root, "template.yaml", "template metadata")).encode("ascii"))
    digest.update(b"\0")
    for item in manifest["files"]:
        digest.update(item["path"].encode("utf-8"))
        digest.update(b"\0")
        source_hash = _manifest_file_hash(template_root, item)
        if source_hash is not None:
            digest.update(source_hash.encode("ascii"))
        else:
            digest.update(
                f"{item['provision']}:{item['generation']}:{item.get('schema') or ''}".encode("utf-8")
            )
        digest.update(b"\0")
    return "sha256:" + digest.hexdigest()


def _load_old_manifest(lock: dict[str, Any]) -> dict[str, Any] | None:
    source_path = lock.get("template", {}).get("sourcePath")
    if not isinstance(source_path, str) or not source_path:
        return None
    source_root = Path(source_path)
    if not source_root.is_dir():
        return None
    try:
        return load_template_manifest(source_root)
    except (LifecycleError, OSError, ValueError):
        # A plan remains useful when an old source checkout was removed; the
        # lock's hashes still provide the previous base for drift detection.
        return None


def _old_base_hash(entry: dict[str, Any]) -> str | None:
    source_hash = entry.get("sourceHash")
    if isinstance(source_hash, str):
        return source_hash
    materialized_hash = entry.get("materializedHash")
    return materialized_hash if isinstance(materialized_hash, str) else None


def _classify_upgrade_file(
    instance_root: Path,
    old_entry: dict[str, Any] | None,
    new_item: dict[str, Any],
    new_hash: str | None,
    old_schema: Any,
) -> dict[str, Any]:
    """Classify one target manifest entry using hashes, never file contents."""
    path = new_item["path"]
    target = _confined_path(instance_root, path, f"upgrade target {path}")
    current_hash = _optional_hash(target)
    owner = new_item["owner"]

    if old_schema != new_item.get("schema") and (
        old_schema is not None or new_item.get("schema") is not None
    ):
        classification = "semantic-migration-required"
        reason = "the declared schema changed"
    elif owner == "generated" or new_item["provision"] == "generate":
        classification = "regenerate"
        reason = "the target is generated by the lifecycle"
    elif new_item["merge"] == "append_only":
        classification = "append-only"
        reason = "the manifest requires append-only handling"
    elif owner == "instance":
        classification = "preserve"
        reason = "instance-owned data is never replaced by a template upgrade"
    elif old_entry is None:
        if current_hash is None:
            classification = "replace"
            reason = "new template-owned file will be added"
        else:
            classification = "conflict"
            reason = "new template-owned file collides with existing instance data"
    else:
        old_base = _old_base_hash(old_entry)
        if current_hash is None:
            classification = "conflict"
            reason = "a previously materialized file is missing from the instance"
        elif new_hash is not None and current_hash == new_hash:
            classification = "preserve"
            reason = "the instance already matches the target template"
        elif old_base is not None and current_hash == old_base:
            classification = "replace"
            reason = "the instance is unchanged from the locked template"
        else:
            classification = "conflict"
            reason = "the instance contains a local change and the target also changes it"

    return {
        "path": path,
        "owner": owner,
        "classification": classification,
        "reason": reason,
        "currentHash": current_hash,
        "targetHash": new_hash,
        "oldHash": _old_base_hash(old_entry) if old_entry else None,
    }


def _plan_upgrade_compat(
    instance_path: Path | str,
    template_path: Path | str,
) -> dict[str, Any]:
    """Build a metadata-only upgrade plan; this function never applies it."""
    instance_root = Path(instance_path)
    template_root = Path(template_path)
    lock = _load_lock(instance_root)
    manifest = load_template_manifest(template_root)
    old_entries = {entry["path"]: entry for entry in lock["files"]}
    old_manifest = _load_old_manifest(lock)
    old_manifest_files = {
        item["path"]: item for item in old_manifest["files"]
    } if old_manifest else {}

    changes: list[dict[str, Any]] = []
    new_paths: set[str] = set()
    for item in manifest["files"]:
        path = item["path"]
        new_paths.add(path)
        changes.append(
            _classify_upgrade_file(
                instance_root,
                old_entries.get(path),
                item,
                _manifest_file_hash(template_root, item),
                old_manifest_files.get(path, {}).get("schema"),
            )
        )

    # A removed template file is retained in a dry-run plan.  It is a conflict
    # only when the instance changed it; deleting anything is never implied.
    for path, old_entry in old_entries.items():
        if path in new_paths or old_entry.get("owner") == "generated":
            continue
        current_hash = _optional_hash(_confined_path(instance_root, path, f"upgrade target {path}"))
        old_base = _old_base_hash(old_entry)
        if old_entry.get("owner") != "template":
            classification = "preserve"
            reason = "removed manifest entry is retained because it is not template-owned"
        elif current_hash is not None and current_hash == old_base:
            classification = "preserve"
            reason = "removed template file is retained by the read-only plan"
        else:
            classification = "conflict"
            reason = "removed template file has local drift and is retained"
        changes.append(
            {
                "path": path,
                "owner": old_entry.get("owner"),
                "classification": classification,
                "reason": reason,
                "currentHash": current_hash,
                "targetHash": None,
                "oldHash": old_base,
            }
        )

    changes.sort(key=lambda item: item["path"])
    counts: dict[str, int] = {}
    for change in changes:
        classification = change["classification"]
        counts[classification] = counts.get(classification, 0) + 1
    blocked = counts.get("conflict", 0) > 0 or counts.get("semantic-migration-required", 0) > 0
    target_revision = _manifest_revision(template_root, manifest)
    return {
        "ok": True,
        "dryRun": True,
        "applied": False,
        "instance": instance_root.as_posix(),
        "from": lock.get("template"),
        "to": {
            "id": manifest["templateId"],
            "version": manifest["templateVersion"],
            "sourcePath": template_root.as_posix(),
            "sourceRevision": target_revision,
        },
        "safe": not blocked,
        "requiresAttention": blocked,
        "summary": counts,
        "changes": changes,
    }


def _detect_overrides_compat(
    instance_path: Path | str,
    template_path: Path | str,
) -> dict[str, Any]:
    """Compatibility detector until the lifecycle package exports its API."""
    template_root = Path(template_path)
    manifest = load_template_manifest(template_root)
    result = _inspect_overrides_compat(instance_path)
    locked_template = result.get("template")
    if isinstance(locked_template, dict) and locked_template.get("id") != manifest["templateId"]:
        raise LifecycleError(
            "instance lock template id does not match the inspection template"
        )
    result["inspectionTemplate"] = {
        "id": manifest["templateId"],
        "version": manifest["templateVersion"],
        "sourcePath": template_root.as_posix(),
    }
    return result


# Keep the names aligned with the lifecycle package's public API.  When core
# grows these exports, the CLI will call them directly without another parser
# change; until then, the fallback is still strictly read-only.
detect_overrides = _public_detect_overrides or _detect_overrides_compat
plan_upgrade = _public_plan_upgrade or _plan_upgrade_compat


def _print_lifecycle_result(result: dict[str, Any]) -> int:
    print(json.dumps(result, indent=2))
    # Core lifecycle reports are successful unless they explicitly carry a
    # false ``ok`` value; ``safe``/``blocked`` describe the plan, not command
    # execution failure.
    return 0 if result.get("ok", True) else 1


def _print_lifecycle_error(exc: Exception) -> int:
    print(json.dumps({"ok": False, "errors": [str(exc)]}, indent=2))
    return 1


def inspect_overrides_cmd(
    instance_path: str,
    template_path: str,
    use_json: bool = True,
) -> int:
    """Print a read-only, metadata-only override inspection as JSON."""
    del use_json  # Lifecycle inspection is structured output like create-instance.
    try:
        return _print_lifecycle_result(detect_overrides(instance_path, template_path))
    except Exception as exc:  # noqa: BLE001 - CLI boundary catch
        return _print_lifecycle_error(exc)


def plan_upgrade_cmd(
    instance_path: str,
    template_path: str,
    use_json: bool = True,
    dry_run: bool = True,
) -> int:
    """Print a read-only upgrade plan; automatic apply is intentionally absent."""
    del use_json, dry_run  # This command is intrinsically a dry run.
    try:
        return _print_lifecycle_result(plan_upgrade(instance_path, template_path))
    except Exception as exc:  # noqa: BLE001 - CLI boundary catch
        return _print_lifecycle_error(exc)


def resolve_source_cmd(
    repository: str,
    requested_ref: str,
    checkout_path: str | None = None,
    expected_commit: str | None = None,
) -> int:
    """Resolve and print one immutable canonical Git source descriptor."""
    try:
        print(json.dumps(resolve_git_source(repository, requested_ref, checkout_path=checkout_path, expected_commit=expected_commit), indent=2, sort_keys=True))
        return 0
    except Exception as exc:  # noqa: BLE001 - CLI boundary catch
        return _print_lifecycle_error(exc)


def approve_upgrade_cmd(plan_path: str, approved_by: str, reason: str = "") -> int:
    try:
        plan = _read_json_mapping(Path(plan_path), "upgrade plan")
        approval = approve_upgrade_plan(plan, approved_by=approved_by, reason=reason)
        print(json.dumps(approval, indent=2, sort_keys=True))
        return 0
    except Exception as exc:  # noqa: BLE001 - CLI boundary catch
        return _print_lifecycle_error(exc)


def apply_upgrade_cmd(
    instance_path: str,
    template_path: str,
    plan_path: str,
    approval_path: str,
    validation_command: list[str] | None = None,
) -> int:
    try:
        plan = _read_json_mapping(Path(plan_path), "upgrade plan")
        approval = _read_json_mapping(Path(approval_path), "upgrade approval")
        return _print_lifecycle_result(
            apply_upgrade(
                instance_path,
                template_path,
                plan=plan,
                approval=approval,
                validation_command=validation_command,
            )
        )
    except Exception as exc:  # noqa: BLE001 - CLI boundary catch
        return _print_lifecycle_error(exc)


# Keep both spellings available to thin wrappers and callers that use the
# noun-first lifecycle terminology.
upgrade_plan_cmd = plan_upgrade_cmd


def _read_pack_json(path: str) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LifecycleError(f"could not read StatePack JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise LifecycleError("StatePack JSON must contain a mapping")
    return value


def context_build_cmd(
    instance_path: str,
    template_path: str | None,
    task: str,
    model: str,
    budget_tokens: int,
    profile: str = "compact",
    selection: str = "eager",
) -> int:
    """Build a disposable StatePack and emit it without writing canonical state."""
    try:
        ir = build_state_ir(instance_path, template_path=template_path)
        pack = build_state_pack(
            ir,
            task=task,
            model=model,
            budget_tokens=budget_tokens,
            profile=profile,
            selection=selection,
        )
        print(json.dumps(pack.to_dict(), indent=2, sort_keys=True))
        return 0
    except Exception as exc:  # noqa: BLE001 - CLI boundary catch
        return _print_lifecycle_error(exc)


def context_inspect_cmd(pack_path: str) -> int:
    try:
        result = inspect_state_pack(_read_pack_json(pack_path))
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result.get("valid") else 1
    except Exception as exc:  # noqa: BLE001 - CLI boundary catch
        return _print_lifecycle_error(exc)


def context_compare_cmd(left_path: str, right_path: str) -> int:
    try:
        left = _read_pack_json(left_path)
        right = _read_pack_json(right_path)
        print(json.dumps(compare_state_packs(left, right), indent=2, sort_keys=True))
        return 0
    except Exception as exc:  # noqa: BLE001 - CLI boundary catch
        return _print_lifecycle_error(exc)


def _read_json_contract(path: str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LifecycleError(f"could not read {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise LifecycleError(f"{label} must contain a JSON object")
    return value


def host_inspect_cmd(capabilities_path: str) -> int:
    try:
        capabilities = BackendCapabilities.from_dict(_read_json_contract(capabilities_path, "capabilities JSON"))
        print(json.dumps(capabilities.to_dict(), indent=2, sort_keys=True))
        return 0
    except Exception as exc:  # noqa: BLE001
        return _print_lifecycle_error(exc)


def run_plan_cmd(instance_path: str, capabilities_path: str, task: str, model: str, template_path: str | None = None) -> int:
    """Build a pack and a deterministic external/manual run plan; do not execute."""
    try:
        capabilities = BackendCapabilities.from_dict(_read_json_contract(capabilities_path, "capabilities JSON"))
        ir = build_state_ir(instance_path, template_path=template_path)
        pack = build_state_pack(ir, task=task, model=model, budget_tokens=1000, profile="compact", selection="eager")
        pack_json = json.dumps(pack.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        pack_digest = "sha256:" + hashlib.sha256(pack_json.encode("utf-8")).hexdigest()
        required = (CapabilityRequest("repositoryInstructions"), CapabilityRequest("nonInteractiveExecution"))
        spec = AgentRunSpec(
            run_id="run:" + hashlib.sha256((ir.instance_id + pack_digest).encode("utf-8")).hexdigest()[:24],
            instance_id=ir.instance_id, source_revision=ir.source_revision, objective=task,
            statepack_reference="inline-statepack:" + pack_digest[7:], statepack_digest=pack_digest,
            required_capabilities=required, optional_capabilities=("tokenTelemetry", "costTelemetry", "changedFileReporting"),
            backend_id=capabilities.backend_id, adapter_id=capabilities.adapter_id, adapter_version=capabilities.adapter_version,
            model_identifier=model, authentication_route_class=capabilities.authentication_route_classes[0],
            permitted_capabilities=capabilities.adapter_permissions, sandbox_profile="external-manual",
            budgets={"token": 1000, "costMinor": 0, "timeSeconds": 0, "steps": 0}, validation_commands=("python3 scripts/validate_repo.py",),
            required_output_artifacts=(), benchmark_configuration={"contextPolicy": "eager", "statepackFormat": pack.manifest["formatVersion"], "model": model, "backend": capabilities.backend_id, "adapter": capabilities.adapter_id, "adapterVersion": capabilities.adapter_version},
            approval_required_level="external_manual", repository_instructions=("Follow repository instructions; do not mutate canonical instance state automatically.",),
        )
        negotiation = negotiate(spec, capabilities)
        if not negotiation["acceptedRun"]:
            raise LifecycleError("capability negotiation rejected run plan")
        print(json.dumps({"statePack": pack.to_dict(), "runSpec": spec.to_dict(), "runSpecDigest": spec.digest, "negotiation": negotiation, "portableExport": portable_export(spec)}, indent=2, sort_keys=True))
        return 0
    except Exception as exc:  # noqa: BLE001
        return _print_lifecycle_error(exc)


def validate_run_result_cmd(result_path: str, run_spec_path: str) -> int:
    try:
        spec = AgentRunSpec.from_dict(_read_json_contract(run_spec_path, "RunSpec JSON"))
        result = validate_run_result(_read_json_contract(result_path, "RunResult JSON"), spec)
        print(json.dumps({"valid": True, "runId": result["runId"], "runSpecDigest": result["runSpecDigest"]}, indent=2, sort_keys=True))
        return 0
    except Exception as exc:  # noqa: BLE001
        return _print_lifecycle_error(exc)


def _print_issues(result: ValidationResult, use_json: bool) -> None:
    """Print a validation result as plain text or JSON."""
    if use_json:
        payload = {
            "valid": result.ok,
            "issues": [
                {"path": issue.path, "message": issue.message}
                for issue in result.issues
            ],
        }
        print(json.dumps(payload, indent=2))
    else:
        if result.ok:
            print("valid")
        else:
            print("invalid")
            for issue in result.issues:
                print(f"  - {issue.path}: {issue.message}")


def _validate_cmd(
    validate: Callable[[Path], ValidationResult],
    path: str,
    use_json: bool,
) -> int:
    """Run a validator against a path and print the result."""
    result = validate(Path(path))
    _print_issues(result, use_json)
    return 0 if result.ok else 1


def validate_template_cmd(path: str, use_json: bool = False) -> int:
    """Validate a StateSpec template folder."""
    return _validate_cmd(validate_template, path, use_json)


def validate_external_template_cmd(path: str, use_json: bool = False) -> int:
    """Validate an external canonical template and emit lifecycle metadata."""
    target = Path(path)
    result = validate_template(target)
    payload: dict[str, Any] = {
        "valid": result.ok,
        "templateId": None,
        "manifestVersion": None,
        "releaseVersion": None,
        "instanceSchemaVersion": None,
        "selectedModules": [],
        "exactFileCount": 0,
        "ownedTreeCount": 0,
        "sourceClass": None,
        "productionEligible": False,
        "digest": None,
        "issues": [
            {"path": issue.path, "message": issue.message}
            for issue in result.issues
        ],
    }
    if result.ok:
        try:
            manifest = load_template_manifest(target)
            source = describe_template_source(target)
            payload.update(
                {
                    "templateId": manifest["templateId"],
                    "manifestVersion": manifest["formatVersion"],
                    "releaseVersion": manifest["templateVersion"],
                    "instanceSchemaVersion": manifest["template"].get(
                        "instanceSchemaVersion", "unknown-v1"
                    ),
                    "selectedModules": list(manifest.get("selectedModules", [])),
                    "exactFileCount": len(manifest.get("files", [])),
                    "ownedTreeCount": len(manifest.get("trees", [])),
                    "sourceClass": manifest.get("sourceClass"),
                    "productionEligible": bool(manifest.get("productionEligible")),
                    "digest": source.get("sourceDigest", source.get("identity")),
                }
            )
        except (LifecycleError, OSError, ValueError) as exc:
            payload["valid"] = False
            payload["issues"].append({"path": ".statedd/manifest.yaml", "message": str(exc)})
    if use_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print("valid" if payload["valid"] else "invalid")
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["valid"] else 1


def validate_instance_cmd(path: str, use_json: bool = False) -> int:
    """Validate a StateSpec instance folder."""
    return _validate_cmd(validate_instance, path, use_json)


def run_instance_cmd(path: str, use_json: bool = False) -> int:
    """Run a StateSpec instance locally and print the result as JSON.

    ``use_json`` is accepted for consistency with the validate commands.
    run-instance always emits structured JSON because SP-001b requires it.
    Unexpected exceptions are caught and returned as structured errors with a
    non-zero exit code rather than leaking Python tracebacks.
    """
    try:
        result = run_instance(Path(path))
        payload = {
            "status": result.status,
            "logs": list(result.logs),
            "errors": list(result.errors),
        }
        ok = result.ok
    except Exception as exc:  # noqa: BLE001 - CLI boundary catch
        payload = {
            "status": "error",
            "logs": [],
            "errors": [f"unexpected runner error: {exc}"],
        }
        ok = False
    print(json.dumps(payload, indent=2))
    return 0 if ok else 1


def create_instance_cmd(
    template_path: str,
    instance_path: str,
    instance_id: str,
    name: str,
    owner_name: str,
    owner_handle: str,
    status: str = "draft",
) -> int:
    """Create an instance, materialise its manifest, and write its lockfile."""
    try:
        lock = create_instance(
            template_path,
            instance_path,
            instance_id=instance_id,
            name=name,
            owner_name=owner_name,
            owner_handle=owner_handle,
            status=status,
        )
    except (LifecycleError, OSError, ValueError) as exc:
        print(json.dumps({"ok": False, "errors": [str(exc)]}, indent=2))
        return 1
    print(json.dumps({"ok": True, "lock": lock}, indent=2))
    return 0
