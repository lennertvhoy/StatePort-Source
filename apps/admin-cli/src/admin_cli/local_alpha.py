"""Thin CLI adapters for the local-alpha operator surfaces."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from diagnostics import Doctor, DoctorConfig
from instance_catalog import InstanceCatalog
from instance_backup import create_backup, read_manifest, restore_backup
from stateport_portable_execution import (
    export_distribution,
    export_portable,
    import_distribution,
    import_portable,
    inspect_distribution,
    preview_distribution,
)
from stateport_persistent_app import LocalLayout, PersistentApp


def _root(value: str) -> Path:
    root = Path(value).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"root is not a directory: {value}")
    return root


def _catalog(root: Path) -> InstanceCatalog:
    data = root / ".stateport"
    data.mkdir(parents=True, exist_ok=True)
    instances_root = root / "instances"
    instances_root.mkdir(parents=True, exist_ok=True)
    return InstanceCatalog(data / "instances.json", instances_root)


def doctor_cmd(args: Any) -> int:
    # Doctor owns expected input validation so failures remain structured.
    # Other local-alpha commands keep the strict existing directory guard.
    root = Path(args.root).expanduser()
    report = Doctor(
        DoctorConfig(root, ui_url=args.ui_url, api_url=args.api_url)
    ).run()
    if args.json:
        print(report.to_json())
    else:
        for item in report.diagnostics:
            print(f"{item.severity.value.upper():8} {item.code.value:12} {item.explanation}")
            if item.details:
                print(f"         details: {json.dumps(item.details, sort_keys=True, ensure_ascii=False)}")
            if item.severity.value in {"warning", "error", "critical"}:
                print(f"         remediation: {item.remediation}")
        print(f"doctor: {'ready' if report.ok else 'issues found'} ({len(report.diagnostics)} checks)")
    return 0 if report.ok else 2


def _print_catalog(value: Any, json_output: bool) -> None:
    if isinstance(value, tuple):
        payload = [item.to_dict() for item in value]
    elif hasattr(value, "to_dict"):
        payload = value.to_dict()
    else:
        payload = value
    if json_output:
        print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    elif isinstance(payload, list):
        for item in payload:
            print(f"{item['instanceId']}  {item['status']:8} {item['pathState']:7} {item['path']}  {item['name']}")
        if not payload:
            print("No local instances registered.")
    else:
        print(json.dumps(payload, sort_keys=True, indent=2))


def catalog_cmd(args: Any) -> int:
    root = _root(args.root)
    catalog = _catalog(root)
    action = args.catalog_command
    if action == "list":
        _print_catalog(catalog.list(include_archived=args.all), args.json)
        return 0
    if action == "inspect":
        _print_catalog(catalog.get(args.instance_id), args.json)
        return 0
    if action in {"register", "import"}:
        method = catalog.register if action == "register" else catalog.import_instance
        _print_catalog(method(args.path, name=args.name, instance_id=args.instance_id), args.json)
        return 0
    if action == "refresh":
        _print_catalog(catalog.refresh(args.instance_id), args.json)
        return 0
    if action == "rename":
        _print_catalog(catalog.rename(args.instance_id, args.name), args.json)
        return 0
    if action in {"archive", "unarchive", "forget"}:
        value = getattr(catalog, action)(args.instance_id)
        _print_catalog(value, args.json)
        return 0
    raise ValueError(f"unsupported catalog command: {action}")


def backup_cmd(args: Any) -> int:
    if args.backup_command == "create":
        result = create_backup(args.instance_path, args.archive_path, archive_format=args.format)
        payload = {
            "archive": str(result.archive_path),
            "format": result.archive_format,
            "archiveDigest": result.archive_digest,
            "archiveFileDigest": result.archive_file_digest,
            "manifest": result.manifest,
        }
    elif args.backup_command == "inspect":
        payload = read_manifest(args.archive_path)
    elif args.backup_command == "restore":
        if not args.dry_run:
            raise ValueError(
                "direct backup restore is dry-run only; use 'stateport instance "
                "restore-plan', 'restore-approve', and 'restore-apply'"
            )
        result = restore_backup(
            args.archive_path,
            args.target_path,
            dry_run=args.dry_run,
            identity_policy=args.identity_policy,
            new_instance_id=args.new_instance_id,
        )
        payload = {
            "archive": str(result.archive_path),
            "target": str(result.target_path),
            "dryRun": result.dry_run,
            "identityPolicy": result.identity_policy,
            "instanceId": result.instance_id,
            "fileCount": result.file_count,
            "archiveDigest": result.archive_digest,
        }
    else:
        raise ValueError(f"unsupported backup command: {args.backup_command}")
    print(json.dumps(payload, sort_keys=True, indent=None if args.json else 2))
    return 0


def setup_cmd(args: Any) -> int:
    """Initialize or inspect only StatePort-owned local metadata."""
    if args.root is None:
        app = PersistentApp()
        if args.setup_command == "init":
            result = app.setup_init(args.source_mirror)
        elif args.setup_command == "status":
            result = app.setup_status()
        elif args.setup_command == "uninstall":
            if not args.confirm:
                raise ValueError("metadata removal requires --confirm; instances and backups are never removed")
            result = app.setup_uninstall()
        else:
            raise ValueError(f"unsupported setup command: {args.setup_command}")
        print(json.dumps(result, sort_keys=True, indent=None if args.json else 2))
        return 0 if result.get("ok", result.get("initialized", True)) else 2
    root = Path(args.root).expanduser().resolve()
    metadata = root / ".stateport"
    config = metadata / "config.json"
    if args.setup_command == "init":
        metadata.mkdir(parents=True, exist_ok=True)
        (metadata / "instances").mkdir(exist_ok=True)
        (metadata / "backups").mkdir(exist_ok=True)
        payload = {"formatVersion": "stateport.local-config/v1", "dataRoot": root.as_posix(), "metadataRoot": metadata.as_posix()}
        temporary = config.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, config)
        result = {"ok": True, "action": "initialized", **payload}
    elif args.setup_command == "status":
        result = {"ok": config.is_file(), "dataRoot": root.as_posix(), "metadataRoot": metadata.as_posix(), "configPresent": config.is_file()}
    elif args.setup_command == "uninstall":
        if not args.confirm:
            raise ValueError("metadata removal requires --confirm; instance files are never removed")
        if metadata.exists():
            import shutil

            shutil.rmtree(metadata)
        result = {"ok": True, "action": "metadata-removed", "dataRootPreserved": root.is_dir(), "instancesPreserved": (root / "instances").exists()}
    else:
        raise ValueError(f"unsupported setup command: {args.setup_command}")
    print(json.dumps(result, sort_keys=True, indent=None if args.json else 2))
    return 0 if result.get("ok", True) else 2


def _persistent_app() -> PersistentApp:
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    return app


def _emit(value: Any, json_output: bool) -> None:
    print(json.dumps(value, sort_keys=True, indent=None if json_output else 2))


def persistent_instance_cmd(args: Any) -> int:
    app = _persistent_app()
    if args.instance_command == "plan-create":
        result = app.plan_create(source_profile=args.source_profile, source_repository=args.source_repository, destination=args.destination, instance_id=args.instance_id, name=args.name, owner_name=args.owner_name, owner_handle=args.owner_handle, target_id=args.target_id, target_title=args.target_title, timezone=args.timezone, learning_goal=args.learning_goal, seed_mode=args.seed_mode, allow_development_candidate=args.allow_development_candidate)
        _emit(result, args.json)
        return 0
    if args.instance_command == "create":
        if args.plan:
            if args.allow_development_candidate:
                raise ValueError("--allow-development-candidate must be recorded in the exact plan and cannot be combined with --plan")
            plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
        else:
            plan = app.plan_create(source_profile=args.source_profile, source_repository=args.source_repository, destination=args.destination, instance_id=args.instance_id, name=args.name, owner_name=args.owner_name, owner_handle=args.owner_handle, target_id=args.target_id, target_title=args.target_title, timezone=args.timezone, learning_goal=args.learning_goal, seed_mode=args.seed_mode, allow_development_candidate=args.allow_development_candidate)
        if not args.json:
            print(json.dumps(plan, sort_keys=True, indent=2))
        if args.approval:
            approval = json.loads(Path(args.approval).read_text(encoding="utf-8"))
        else:
            if not sys.stdin.isatty():
                raise ValueError("non-interactive create requires --approval with an exact plan approval")
            answer = input(f"Type the exact plan digest {plan['planDigest']} to approve: ").strip()
            if answer != plan["planDigest"]:
                raise ValueError("creation approval did not match the exact plan digest")
            approval = app.approve(plan)
        result = app.create(plan, approval)
        _emit(result, args.json)
        return 0
    if args.instance_command == "list":
        _emit({"instances": app.instance_list()}, args.json)
        return 0
    if args.instance_command in {"inspect", "verify"}:
        result = app.inspect(args.instance_id)
        _emit(result, args.json)
        return 0
    if args.instance_command == "import":
        _emit(app.import_instance(args.path), args.json)
        return 0
    if args.instance_command == "backup":
        _emit(app.backup(args.instance_id), args.json)
        return 0
    if args.instance_command == "recovery-status":
        _emit(app.recovery_status(args.instance_id), args.json)
        return 0
    if args.instance_command == "restore-plan":
        _emit(
            app.restore_plan(
                args.instance_id,
                backup_receipt_id=args.backup_receipt,
                destination_instance_id=args.destination_instance_id,
                destination_name=args.name,
            ),
            args.json,
        )
        return 0
    if args.instance_command == "restore-approve":
        _emit(
            app.approve_restore(
                args.instance_id,
                plan_digest=args.plan_digest,
                actor_id=args.actor_id,
                actor_role="local_operator",
            ),
            args.json,
        )
        return 0
    if args.instance_command == "restore-apply":
        _emit(
            app.apply_restore(
                args.instance_id,
                plan_digest=args.plan_digest,
                approval_digest=args.approval_digest,
            ),
            args.json,
        )
        return 0
    if args.instance_command == "export-portable":
        _, instance_root = app._entry(args.instance_id)
        archive = Path(args.archive).expanduser() if args.archive else app.layout.operations_root / "portable" / f"{args.instance_id}.zip"
        _emit(export_portable(instance_root, archive), args.json)
        return 0
    if args.instance_command == "import-portable":
        result = import_portable(args.archive, args.destination, dry_run=args.dry_run, new_instance_id=args.new_instance_id)
        if not args.dry_run:
            result["catalog"] = app.catalog.import_instance(args.destination, instance_id=result["instanceId"])
        _emit(result, args.json)
        return 0
    if args.instance_command == "synthetic-run":
        _emit(app.synthetic_run(args.instance_id), args.json)
        return 0
    if args.instance_command == "import-state-plan":
        _emit(app.import_state_plan(args.source, args.destination_instance, include_history=args.include_history), args.json)
        return 0
    if args.instance_command == "import-state-apply":
        plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
        approval = json.loads(Path(args.approval).read_text(encoding="utf-8"))
        _emit(app.import_state(plan, args.source, approval), args.json)
        return 0
    if args.instance_command == "forget":
        _emit(app.catalog.forget(args.instance_id), args.json)
        return 0
    raise ValueError(f"unsupported persistent instance command: {args.instance_command}")


def statepack_cmd(args: Any) -> int:
    """Preview, export, inspect, or import a StatePack distribution envelope."""

    profiles = args.profile or ("stateport-native", "agent-package", "standalone-web-oci") if hasattr(args, "profile") else ()
    if args.statepack_command == "preview":
        result = preview_distribution(
            args.source,
            profiles=profiles,
            source_identity=args.source_identity,
            schema_identities=args.schema_identity,
        )
    elif args.statepack_command == "export":
        result = export_distribution(
            args.source,
            args.archive,
            profiles=profiles,
            source_identity=args.source_identity,
            schema_identities=args.schema_identity,
        )
    elif args.statepack_command == "inspect":
        result = inspect_distribution(args.archive)
    elif args.statepack_command == "import":
        result = import_distribution(args.archive, args.destination, dry_run=args.dry_run)
    else:
        raise ValueError(f"unsupported StatePack command: {args.statepack_command}")
    _emit(result, args.json)
    return 0


def service_cmd(args: Any) -> int:
    app = _persistent_app()
    if args.service_command == "start":
        result = app.service_start(port=args.port, open_browser=args.open_browser, actor_role=args.actor_role)
    elif args.service_command == "stop":
        result = app.service_stop()
    elif args.service_command == "status":
        result = app.service_status()
    elif args.service_command == "logs":
        path = app.layout.logs_root / "service.log"
        result = {"path": path.as_posix(), "content": path.read_text(encoding="utf-8")[-20000:] if path.is_file() else ""}
    else:
        raise ValueError(f"unsupported service command: {args.service_command}")
    _emit(result, args.json)
    return 0


def demo_cmd(args: Any) -> int:
    if not args.keep:
        raise ValueError("persistent demo requires --keep; cleanup is a separate explicit operation")
    workspace = Path(args.workspace).expanduser()
    if workspace.exists():
        raise ValueError(f"persistent demo workspace already exists: {workspace}")
    app = _persistent_app()
    plan = app.plan_create(
        source_profile="builtin:studydd-local-alpha",
        source_repository=None,
        destination=str(workspace),
        instance_id="studydd-local-alpha",
        name="StudyState local alpha",
        owner_name="Synthetic Owner",
        owner_handle="synthetic-owner",
        target_id="demo-target",
        target_title="StudyState local alpha demo",
        timezone="UTC",
        learning_goal="",
        seed_mode="synthetic-demo",
    )
    result = app.create(plan, app.approve(plan))
    result["persistentDemo"] = True
    result["keptWorkspace"] = workspace.as_posix()
    result["dashboardCommand"] = "stateport service start --open"
    _emit(result, args.json)
    return 0
