"""Entry point for the StatePort admin CLI."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any, Callable

def _ensure_local_paths() -> None:
    """Make local packages importable when the CLI is run without the wrapper."""
    repo_root = Path(__file__).resolve().parents[4]
    src_paths = [
        repo_root / "packages" / "statedd-core" / "src",
        repo_root / "packages" / "template-validator" / "src",
        repo_root / "packages" / "execution-host" / "src",
        repo_root / "packages" / "runtime-contracts" / "src",
        repo_root / "packages" / "external-engine-runtime" / "src",
        repo_root / "packages" / "codex-adapter" / "src",
        repo_root / "packages" / "run-bundle" / "src",
        repo_root / "packages" / "diagnostics" / "src",
        repo_root / "packages" / "instance-catalog" / "src",
        repo_root / "packages" / "instance-backup" / "src",
        repo_root / "apps" / "runner" / "src",
        repo_root / "apps" / "admin-cli" / "src",
        repo_root / "packages" / "persistent-app" / "src",
        repo_root / "packages" / "portable-execution" / "src",
        repo_root / "packages" / "application-experience" / "src",
        repo_root / "packages" / "conversation-service" / "src",
        repo_root / "packages" / "governed-runner" / "src",
        repo_root / "packages" / "deployment" / "src",
    ]
    for src in src_paths:
        if str(src) not in sys.path:
            sys.path.insert(0, str(src))


def _add_validate_parser(
    subparsers: Any,
    name: str,
    help_text: str,
    path_noun: str,
    command: Callable[[str, bool], int],
) -> None:
    parser = subparsers.add_parser(name, help=help_text)
    parser.add_argument("path", help=f"path to the {path_noun} folder")
    parser.add_argument(
        "--json",
        action="store_true",
        help="output the result as JSON",
    )
    parser.set_defaults(func=lambda args: command(args.path, args.json))


def _add_run_instance_parser(
    subparsers: Any, command: Callable[[str, bool], int]
) -> None:
    parser = subparsers.add_parser(
        "run-instance", help="Run a StateSpec instance locally"
    )
    parser.add_argument("path", help="path to the instance folder")
    parser.add_argument(
        "--json",
        action="store_true",
        help="output the result as JSON (run-instance always emits JSON)",
    )
    parser.set_defaults(func=lambda args: command(args.path, args.json))


def _add_create_instance_parser(subparsers: Any, command: Callable[..., int]) -> None:
    parser = subparsers.add_parser(
        "create-instance", help="Create and lock a StateSpec instance"
    )
    parser.add_argument("template_path", help="path to the canonical template folder")
    parser.add_argument("instance_path", help="destination instance folder")
    parser.add_argument("--id", required=True, dest="instance_id")
    parser.add_argument("--name", required=True)
    parser.add_argument("--owner-name", required=True)
    parser.add_argument("--owner-handle", required=True)
    parser.add_argument(
        "--status", choices=("draft", "active", "archived"), default="draft"
    )
    parser.set_defaults(
        func=lambda args: command(
            args.template_path,
            args.instance_path,
            args.instance_id,
            args.name,
            args.owner_name,
            args.owner_handle,
            args.status,
        )
    )


def _add_inspect_overrides_parser(
    subparsers: Any, command: Callable[[str, str, bool], int]
) -> None:
    parser = subparsers.add_parser(
        "inspect-overrides",
        aliases=("override-inspection",),
        help="Inspect template-owned instance drift (read-only)",
    )
    parser.add_argument("instance_path", help="path to the instance folder")
    parser.add_argument(
        "template_path", help="path to the canonical template folder"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="output structured JSON (the lifecycle command always emits JSON)",
    )
    parser.set_defaults(
        func=lambda args: command(args.instance_path, args.template_path, args.json)
    )


def _add_plan_upgrade_parser(
    subparsers: Any, command: Callable[[str, str, bool, bool], int]
) -> None:
    parser = subparsers.add_parser(
        "plan-upgrade",
        aliases=("upgrade-plan",),
        help="Preview a template upgrade without applying it",
    )
    parser.add_argument("instance_path", help="path to the instance folder")
    parser.add_argument(
        "template_path", help="path to the candidate canonical template folder"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="explicitly request the read-only plan (planning is always a dry run)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="output structured JSON (the lifecycle command always emits JSON)",
    )
    parser.set_defaults(
        func=lambda args: command(
            args.instance_path,
            args.template_path,
            args.json,
            args.dry_run,
        )
    )


def _add_source_resolve_parser(subparsers: Any, command: Callable[..., int]) -> None:
    parser = subparsers.add_parser("source-resolve", help="Resolve a canonical Git source to an immutable commit")
    parser.add_argument("repository")
    parser.add_argument("--ref", default="HEAD", dest="requested_ref")
    parser.add_argument("--checkout", default=None, dest="checkout_path")
    parser.add_argument("--expected-commit", default=None)
    parser.set_defaults(func=lambda args: command(args.repository, args.requested_ref, args.checkout_path, args.expected_commit))


def _add_approve_upgrade_parser(subparsers: Any, command: Callable[..., int]) -> None:
    parser = subparsers.add_parser("approve-upgrade", help="Bind operator approval to an exact upgrade plan digest")
    parser.add_argument("plan_path")
    parser.add_argument("--by", required=True, dest="approved_by")
    parser.add_argument("--reason", default="")
    parser.set_defaults(func=lambda args: command(args.plan_path, args.approved_by, args.reason))


def _add_apply_upgrade_parser(subparsers: Any, command: Callable[..., int]) -> None:
    parser = subparsers.add_parser("apply-upgrade", help="Apply an approved upgrade transactionally")
    parser.add_argument("instance_path")
    parser.add_argument("template_path")
    parser.add_argument("--plan", required=True, dest="plan_path")
    parser.add_argument("--approval", required=True, dest="approval_path")
    parser.add_argument("--validate-command", nargs="+", default=None)
    parser.set_defaults(func=lambda args: command(args.instance_path, args.template_path, args.plan_path, args.approval_path, args.validate_command))


def _add_context_build_parser(
    subparsers: Any, command: Callable[..., int]
) -> None:
    parser = subparsers.add_parser(
        "context-build",
        aliases=("build-context",),
        help="Build a disposable StatePack for an instance (read-only)",
    )
    parser.add_argument("instance_path", help="path to the instance folder")
    parser.add_argument("--task", required=True, help="task the context is being built for")
    parser.add_argument("--model", required=True, help="configured model identifier")
    parser.add_argument("--budget", required=True, type=int, dest="budget_tokens")
    parser.add_argument("--template-path", default=None)
    parser.add_argument(
        "--profile", choices=("human", "compact", "ultra", "audit", "task"), default="compact"
    )
    parser.add_argument(
        "--selection", choices=("eager", "compact_context", "modular"), default="eager"
    )
    parser.set_defaults(
        func=lambda args: command(
            args.instance_path,
            args.template_path,
            args.task,
            args.model,
            args.budget_tokens,
            args.profile,
            args.selection,
        )
    )


def _add_context_inspect_parser(
    subparsers: Any, command: Callable[[str], int]
) -> None:
    parser = subparsers.add_parser(
        "context-inspect",
        aliases=("inspect-context",),
        help="Inspect a serialized StatePack without changing it",
    )
    parser.add_argument("pack_path", help="path to a JSON StatePack")
    parser.set_defaults(func=lambda args: command(args.pack_path))


def _add_context_compare_parser(
    subparsers: Any, command: Callable[[str, str], int]
) -> None:
    parser = subparsers.add_parser(
        "context-compare",
        aliases=("compare-context",),
        help="Compare two serialized StatePacks",
    )
    parser.add_argument("left_path", help="path to the first JSON StatePack")
    parser.add_argument("right_path", help="path to the second JSON StatePack")
    parser.set_defaults(func=lambda args: command(args.left_path, args.right_path))


def _add_host_inspect_parser(subparsers: Any, command: Callable[[str], int]) -> None:
    parser = subparsers.add_parser("host", help="Inspect a portable host capability contract")
    nested = parser.add_subparsers(dest="host_command", required=True)
    inspect = nested.add_parser("inspect", help="Validate and normalize BackendCapabilities JSON")
    inspect.add_argument("capabilities_path")
    inspect.set_defaults(func=lambda args: command(args.capabilities_path))


def _add_run_contract_parser(subparsers: Any, plan: Callable[..., int], validate: Callable[..., int]) -> None:
    parser = subparsers.add_parser("run", help="Plan or validate portable run contracts")
    nested = parser.add_subparsers(dest="run_command", required=True)
    plan_parser = nested.add_parser("plan", help="Build StatePack, negotiate a host, and emit a run plan")
    plan_parser.add_argument("instance_path")
    plan_parser.add_argument("--capabilities", required=True, dest="capabilities_path")
    plan_parser.add_argument("--task", default="StatePort portable execution plan")
    plan_parser.add_argument("--model", default="unspecified")
    plan_parser.add_argument("--template-path", default=None)
    plan_parser.set_defaults(func=lambda args: plan(args.instance_path, args.capabilities_path, args.task, args.model, args.template_path))
    result_parser = nested.add_parser("validate-result", help="Validate a RunResult against its exact RunSpec")
    result_parser.add_argument("result_path")
    result_parser.add_argument("--run-spec", required=True, dest="run_spec_path")
    result_parser.set_defaults(func=lambda args: validate(args.result_path, args.run_spec_path))


def _add_doctor_parser(subparsers: Any, command: Callable[..., int]) -> None:
    parser = subparsers.add_parser("doctor", help="Inspect local StatePort readiness without mutation")
    parser.add_argument("--root", default=".", help="confined local StatePort root")
    parser.add_argument("--api-url", default=None)
    parser.add_argument("--ui-url", default=None)
    parser.add_argument("--json", action="store_true")
    parser.set_defaults(func=command)


def _add_catalog_parser(subparsers: Any, command: Callable[..., int]) -> None:
    parser = subparsers.add_parser("catalog", help="Manage the local instance discovery index")
    parser.add_argument("--root", default=".", help="confined local StatePort root")
    nested = parser.add_subparsers(dest="catalog_command", required=True)
    list_parser = nested.add_parser("list", help="list revalidated local entries")
    list_parser.add_argument("--all", action="store_true", help="include archived entries")
    list_parser.add_argument("--json", action="store_true")
    list_parser.set_defaults(func=command)
    inspect = nested.add_parser("inspect", help="inspect one catalog entry")
    inspect.add_argument("instance_id")
    inspect.add_argument("--json", action="store_true")
    inspect.set_defaults(func=command)
    for action, help_text in (("register", "register a known instance directory"), ("import", "import an existing directory read-only")):
        adopt = nested.add_parser(action, help=help_text)
        adopt.add_argument("path")
        adopt.add_argument("--name", default=None)
        adopt.add_argument("--instance-id", default=None)
        adopt.add_argument("--json", action="store_true")
        adopt.set_defaults(func=command)
    refresh = nested.add_parser("refresh", help="revalidate one or all paths")
    refresh.add_argument("instance_id", nargs="?", default=None)
    refresh.add_argument("--json", action="store_true")
    refresh.set_defaults(func=command)
    for action in ("rename", "archive", "unarchive", "forget"):
        item = nested.add_parser(action)
        item.add_argument("instance_id")
        if action == "rename":
            item.add_argument("name")
        item.add_argument("--json", action="store_true")
        item.set_defaults(func=command)


def _add_backup_parser(subparsers: Any, command: Callable[..., int]) -> None:
    parser = subparsers.add_parser("backup", help="Create, inspect, and restore local instance backups")
    nested = parser.add_subparsers(dest="backup_command", required=True)
    create = nested.add_parser("create")
    create.add_argument("instance_path")
    create.add_argument("archive_path")
    create.add_argument("--format", choices=("tar", "zip"), default=None)
    create.add_argument("--json", action="store_true")
    create.set_defaults(func=command)
    inspect = nested.add_parser("inspect")
    inspect.add_argument("archive_path")
    inspect.add_argument("--json", action="store_true")
    inspect.set_defaults(func=command)
    restore = nested.add_parser("restore")
    restore.add_argument("archive_path")
    restore.add_argument("target_path")
    restore.add_argument("--dry-run", action="store_true")
    restore.add_argument("--identity-policy", choices=("preserve", "reidentify"), default="preserve")
    restore.add_argument("--new-instance-id", default=None)
    restore.add_argument("--json", action="store_true")
    restore.set_defaults(func=command)


def _add_setup_parser(subparsers: Any, command: Callable[..., int]) -> None:
    parser = subparsers.add_parser("setup", help="Initialize or inspect StatePort local metadata")
    parser.add_argument("--root", default=None, help="legacy test root; omit for XDG persistent layout")
    parser.add_argument("--source-mirror", default=None, help="explicit local Git mirror for the immutable StudyState profile")
    nested = parser.add_subparsers(dest="setup_command", required=True)
    for action in ("init", "status"):
        item = nested.add_parser(action)
        item.add_argument("--json", action="store_true")
        item.set_defaults(func=command)
    remove = nested.add_parser("uninstall", help="remove StatePort metadata without deleting instances")
    remove.add_argument("--confirm", action="store_true")
    remove.add_argument("--json", action="store_true")
    remove.set_defaults(func=command)


def _add_instance_parser(subparsers: Any, command: Callable[..., int]) -> None:
    parser = subparsers.add_parser("instance", help="Create and operate persistent local applications")
    nested = parser.add_subparsers(dest="instance_command", required=True)
    plan = nested.add_parser("plan-create", help="Plan an exact StudyState application creation")
    plan.add_argument("--source-profile", required=True)
    plan.add_argument("--source-repository", default=None)
    plan.add_argument("--destination", default=None)
    plan.add_argument("--instance-id", required=True)
    plan.add_argument("--name", required=True)
    plan.add_argument("--owner-name", required=True)
    plan.add_argument("--owner-handle", default="local-owner")
    plan.add_argument("--target-id", required=True)
    plan.add_argument("--target-title", default="")
    plan.add_argument("--timezone", default="UTC")
    plan.add_argument("--learning-goal", default="")
    plan.add_argument("--seed-mode", choices=("empty", "synthetic-demo"), default="empty")
    plan.add_argument(
        "--allow-development-candidate",
        action="store_true",
        help="allow this exact non-production source for isolated local testing",
    )
    plan.add_argument("--json", action="store_true")
    plan.set_defaults(func=command)
    create = nested.add_parser("create", help="Create a persistent StudyState application")
    for action in ("source-profile", "source-repository", "destination", "instance-id", "name", "owner-name", "owner-handle", "target-id", "target-title", "timezone", "learning-goal", "seed-mode"):
        option = "--" + action
        kwargs = {"dest": action.replace("-", "_")}
        if action in {"source-profile", "instance-id", "name", "owner-name", "target-id"}:
            kwargs["default"] = None
        else:
            kwargs["default"] = None if action not in {"owner-handle", "target-title", "timezone", "learning-goal", "seed-mode"} else {"owner-handle": "local-owner", "target-title": "", "timezone": "UTC", "learning-goal": "", "seed-mode": "empty"}[action]
        if action == "seed-mode":
            kwargs["choices"] = ("empty", "synthetic-demo")
        create.add_argument(option, **kwargs)
    create.add_argument("--approval", default=None, help="exact approval JSON; omit for interactive confirmation")
    create.add_argument("--plan", default=None, help="exact plan JSON for non-interactive application")
    create.add_argument(
        "--allow-development-candidate",
        action="store_true",
        help="allow this exact non-production source for isolated local testing",
    )
    create.add_argument("--json", action="store_true")
    create.set_defaults(func=command)
    list_parser = nested.add_parser("list")
    list_parser.add_argument("--json", action="store_true")
    list_parser.set_defaults(func=command)
    inspect_import = nested.add_parser("import", help="Import an existing instance read-only after verification")
    inspect_import.add_argument("path")
    inspect_import.add_argument("--json", action="store_true")
    inspect_import.set_defaults(func=command)
    for action in ("inspect", "verify", "backup", "synthetic-run"):
        item = nested.add_parser(action)
        item.add_argument("instance_id")
        item.add_argument("--json", action="store_true")
        item.set_defaults(func=command)
    recovery = nested.add_parser(
        "recovery-status", help="Inspect path-free backup and governed restore status"
    )
    recovery.add_argument("instance_id")
    recovery.add_argument("--json", action="store_true")
    recovery.set_defaults(func=command)
    restore_plan = nested.add_parser(
        "restore-plan", help="Plan a verified backup restore as a new instance"
    )
    restore_plan.add_argument("instance_id", help="source instance identity")
    restore_plan.add_argument("--backup-receipt", required=True)
    restore_plan.add_argument("--destination-instance-id", required=True)
    restore_plan.add_argument("--name", default=None)
    restore_plan.add_argument("--json", action="store_true")
    restore_plan.set_defaults(func=command)
    restore_approve = nested.add_parser(
        "restore-approve", help="Approve one exact stored restore plan"
    )
    restore_approve.add_argument("instance_id", help="source instance identity")
    restore_approve.add_argument("--plan-digest", required=True)
    restore_approve.add_argument("--actor-id", default="local-operator")
    restore_approve.add_argument("--json", action="store_true")
    restore_approve.set_defaults(func=command)
    restore_apply = nested.add_parser(
        "restore-apply", help="Apply one exact approved restore plan"
    )
    restore_apply.add_argument("instance_id", help="source instance identity")
    restore_apply.add_argument("--plan-digest", required=True)
    restore_apply.add_argument("--approval-digest", required=True)
    restore_apply.add_argument("--json", action="store_true")
    restore_apply.set_defaults(func=command)
    portable_export = nested.add_parser("export-portable", help="Export a deterministic engine-independent instance package")
    portable_export.add_argument("instance_id")
    portable_export.add_argument("--archive", default=None)
    portable_export.add_argument("--json", action="store_true")
    portable_export.set_defaults(func=command)
    portable_import = nested.add_parser("import-portable", help="Dry-run or atomically import an instance package")
    portable_import.add_argument("archive")
    portable_import.add_argument("destination")
    portable_import.add_argument("--new-instance-id", default=None)
    portable_import.add_argument("--dry-run", action="store_true")
    portable_import.add_argument("--json", action="store_true")
    portable_import.set_defaults(func=command)
    import_state = nested.add_parser("import-state-plan", help="Plan a read-only private StudyState state import")
    import_state.add_argument("--from", dest="source", required=True)
    import_state.add_argument("--to", dest="destination_instance", required=True)
    import_state.add_argument("--include-history", action="store_true")
    import_state.add_argument("--json", action="store_true")
    import_state.set_defaults(func=command)
    apply_state = nested.add_parser("import-state-apply", help="Apply an exact approved private StudyState state import")
    apply_state.add_argument("--from", dest="source", required=True)
    apply_state.add_argument("--plan", required=True)
    apply_state.add_argument("--approval", required=True)
    apply_state.add_argument("--json", action="store_true")
    apply_state.set_defaults(func=command)
    forget = nested.add_parser("forget")
    forget.add_argument("instance_id")
    forget.add_argument("--json", action="store_true")
    forget.set_defaults(func=command)


def _add_statepack_parser(subparsers: Any, command: Callable[..., int]) -> None:
    parser = subparsers.add_parser("statepack", help="Manage deterministic StatePack distribution envelopes")
    nested = parser.add_subparsers(dest="statepack_command", required=True)
    for action in ("preview", "export"):
        item = nested.add_parser(action, help=f"{action} a public-safe application distribution")
        item.add_argument("source")
        if action == "export":
            item.add_argument("archive")
        item.add_argument("--profile", action="append", choices=("stateport-native", "agent-package", "standalone-web-oci"), default=None)
        item.add_argument("--source-identity", default=None)
        item.add_argument("--schema-identity", action="append", default=[])
        item.add_argument("--json", action="store_true")
        item.set_defaults(func=command)
    inspect = nested.add_parser("inspect", help="verify a StatePack distribution and its complete inventory")
    inspect.add_argument("archive")
    inspect.add_argument("--json", action="store_true")
    inspect.set_defaults(func=command)
    restore = nested.add_parser("import", help="plan or atomically import a StatePack into a new destination")
    restore.add_argument("archive")
    restore.add_argument("destination")
    restore.add_argument("--dry-run", action="store_true")
    restore.add_argument("--json", action="store_true")
    restore.set_defaults(func=command)


def _add_service_parser(subparsers: Any, command: Callable[..., int]) -> None:
    parser = subparsers.add_parser("service", help="Manage the persistent loopback dashboard service")
    nested = parser.add_subparsers(dest="service_command", required=True)
    start = nested.add_parser("start")
    start.add_argument("--port", type=int, default=8790)
    start.add_argument("--open", action="store_true", dest="open_browser")
    start.add_argument("--actor-role", choices=("local_user", "platform_operator"), default="local_user", help="trusted startup role; browser requests cannot change it")
    start.add_argument("--json", action="store_true")
    start.set_defaults(func=command)
    for action in ("stop", "status"):
        item = nested.add_parser(action)
        item.add_argument("--json", action="store_true")
        item.set_defaults(func=command)
    logs = nested.add_parser("logs")
    logs.add_argument("--json", action="store_true")
    logs.set_defaults(func=command)


def _add_demo_parser(subparsers: Any, command: Callable[..., int]) -> None:
    parser = subparsers.add_parser("demo", help="Install a persistent public-safe StudyState demo")
    nested = parser.add_subparsers(dest="demo_command", required=True)
    studydd = nested.add_parser("studydd-local-alpha")
    studydd.add_argument("--workspace", required=True)
    studydd.add_argument("--keep", action="store_true", help="retain the workspace after the command exits")
    studydd.add_argument("--json", action="store_true")
    studydd.set_defaults(func=command)


def _add_deploy_parser(subparsers: Any, command: Callable[..., int]) -> None:
    parser = subparsers.add_parser(
        "deploy", help="Inspect and govern rootless Podman deployments"
    )
    parser.add_argument(
        "--deployment-state-root",
        default=None,
        help="private durable deployment-state root",
    )
    parser.add_argument(
        "--execution-host-socket",
        default=os.environ.get("STATEPORT_EXECUTION_SOCKET"),
        help="confined execution-host socket (default: STATEPORT_EXECUTION_SOCKET)",
    )
    parser.add_argument(
        "--execution-host-grant-id",
        default=os.environ.get("STATEPORT_EXECUTION_GRANT_ID"),
        help="provisioned execution-host grant id (default: STATEPORT_EXECUTION_GRANT_ID)",
    )
    parser.add_argument(
        "--execution-host-grant-digest",
        default=os.environ.get("STATEPORT_EXECUTION_GRANT_DIGEST"),
        help="provisioned execution-host grant digest (default: STATEPORT_EXECUTION_GRANT_DIGEST)",
    )
    parser.add_argument(
        "--execution-host-timeout-seconds",
        type=int,
        default=1200,
        help="bounded deployment request timeout (default: 1200)",
    )
    parser.add_argument("--repository", default=".", help="StatePort control checkout")
    parser.add_argument(
        "--authority-state-root",
        default=None,
        help="operational standing-authority state root",
    )
    parser.add_argument(
        "--authority-policy",
        default=None,
        help="exact tracked authority policy to evaluate",
    )
    parser.add_argument(
        "--grant-id",
        default=None,
        help="standing grant authorizing the deployment action",
    )
    parser.add_argument(
        "--slice-id",
        default=None,
        help="optional exact authority slice scope",
    )
    parser.add_argument("--actor-id", default="local-owner")
    nested = parser.add_subparsers(dest="deploy_command", required=True)

    def output_options(item: Any) -> None:
        item.add_argument("--json", action="store_true")

    inspect = nested.add_parser("inspect", help="inspect a project without side effects")
    inspect.add_argument("project")
    output_options(inspect)
    inspect.set_defaults(func=command)

    plan = nested.add_parser("plan", help="create an exact reviewable deployment plan")
    plan.add_argument("project")
    plan.add_argument("--target", choices=("local",), default="local")
    plan.add_argument("--deployment-id", required=True)
    output_options(plan)
    plan.set_defaults(func=command)

    apply = nested.add_parser("apply", help="approve and apply one exact plan")
    apply.add_argument("deployment")
    apply.add_argument("--accept-plan-digest", required=True)
    output_options(apply)
    apply.set_defaults(func=command)

    status = nested.add_parser("status", help="observe desired, accepted, and runtime state")
    status.add_argument("deployment")
    output_options(status)
    status.set_defaults(func=command)

    logs = nested.add_parser("logs", help="collect bounded redacted deployment logs")
    logs.add_argument("deployment")
    logs.add_argument("--service", default=None)
    logs.add_argument("--tail", type=int, default=200)
    output_options(logs)
    logs.set_defaults(func=command)

    restart = nested.add_parser("restart", help="restart an accepted deployment")
    restart.add_argument("deployment")
    output_options(restart)
    restart.set_defaults(func=command)

    remove = nested.add_parser("remove", help="remove runtime and retain durable data")
    remove.add_argument("deployment")
    output_options(remove)
    remove.set_defaults(func=command)

    plan_purge = nested.add_parser(
        "plan-purge", help="create a separate irreversible data-purge plan"
    )
    plan_purge.add_argument("deployment")
    output_options(plan_purge)
    plan_purge.set_defaults(func=command)

    purge = nested.add_parser("purge-data", help="apply an exact approved data-purge plan")
    purge.add_argument("deployment")
    purge.add_argument("--accept-plan-digest", required=True)
    output_options(purge)
    purge.set_defaults(func=command)


def _add_workspace_parser(subparsers: Any, command: Callable[..., int]) -> None:
    parser = subparsers.add_parser(
        "workspace",
        help="Create and retire bounded, leased StatePort-managed Git workspaces",
    )
    parser.add_argument("--repository", default=".", help="primary repository checkout")
    parser.add_argument("--state-root", default=None, help="operational workspace state root")
    parser.add_argument("--authority-state-root", default=None, help="operational standing-authority state root")
    parser.add_argument("--authority-policy", default=None, help="exact tracked authority policy to evaluate")
    parser.add_argument("--grant-id", default=None, help="standing grant authorizing this operation")
    parser.add_argument("--actor-id", default=None, help="actor executing this operation")
    nested = parser.add_subparsers(dest="workspace_command", required=True)

    inventory = nested.add_parser("inventory", help="audit leases, classifications, worktrees, and budgets")
    inventory.add_argument("--slice-id", default=None)
    inventory.add_argument("--record", action="store_true")
    inventory.set_defaults(func=command)

    classify = nested.add_parser("classify", help="bind known external residue to exact observed state")
    classify.add_argument("worktree")
    classify.add_argument(
        "--classification",
        choices=("primary_creation_base", "external_retained", "historical_retained"),
        required=True,
    )
    classify.add_argument("--reason", required=True)
    classify.add_argument("--head-policy", choices=("exact", "branch_tip"), default="exact")
    classify.add_argument("--expires-at", default=None)
    classify.set_defaults(func=command)

    create = nested.add_parser("create", help="atomically create a branch, worktree, lease, and receipt")
    create.add_argument("--slice-id", required=True)
    create.add_argument("--owner-agent-id", required=True)
    create.add_argument("--branch", required=True)
    create.add_argument("--workspace-name", required=True)
    create.add_argument("--purpose", required=True)
    create.add_argument("--base-ref", default="HEAD")
    create.add_argument("--duration-seconds", type=int, default=None)
    create.set_defaults(func=command)

    lease = nested.add_parser("lease", help="read one validated lease")
    lease.add_argument("lease_id")
    lease.set_defaults(func=command)

    evidence = nested.add_parser("export-evidence", help="export checkout-independent evidence")
    evidence.add_argument("lease_id")
    evidence.add_argument("--test-receipt", action="append", default=[])
    evidence.add_argument("--browser-evidence", action="append", default=[])
    evidence.add_argument("--generated-artifact", action="append", default=[])
    evidence.add_argument("--statebench-trace", action="append", default=[])
    evidence.add_argument("--subagent-result", action="append", default=[])
    evidence.set_defaults(func=command)

    close = nested.add_parser("close", help="classify, retire, and receipt a leased workspace")
    close.add_argument("lease_id")
    close.add_argument("--disposition", choices=("integrated", "rejected", "archived"), required=True)
    close.add_argument("--integration-ref", default=None)
    close.add_argument("--exception-reason", default=None)
    close.add_argument("--exception-expires-at", default=None)
    close.add_argument(
        "--close-slice",
        action="store_true",
        help="prove slice closure and expire its standing grants after workspace retirement",
    )
    close.set_defaults(func=command)

    reconcile = nested.add_parser(
        "reconcile-missing-integrated",
        help="recover evidence and terminalize an externally removed integrated workspace",
    )
    reconcile.add_argument("lease_id")
    reconcile.add_argument("--recovered-ref", required=True)
    reconcile.add_argument("--integration-ref", required=True)
    reconcile.set_defaults(func=command)

    slice_gate = nested.add_parser("assert-slice-closed", help="reject a slice with workspace residue")
    slice_gate.add_argument("--slice-id", required=True)
    slice_gate.set_defaults(func=command)

    repository_gate = nested.add_parser(
        "assert-repository-closed", help="reject repository closure with workspace residue"
    )
    repository_gate.set_defaults(func=command)


def _add_grant_arguments(parser: Any, *, one_time: bool = False) -> None:
    parser.add_argument("--grant-id", required=True)
    parser.add_argument("--profile", choices=("guarded", "balanced", "delegated", "custom"), default="balanced")
    parser.add_argument("--actor-id", required=True, help="agent or operator receiving the grant")
    parser.add_argument("--role", choices=("primary", "subagent", "operator"), default="primary")
    parser.add_argument("--branch-pattern", default=None)
    parser.add_argument("--slice-id", default=None)
    parser.add_argument("--application-id", default=None)
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--path", action="append", default=[], help="repository-relative path scope (defaults to .)")
    parser.add_argument(
        "--deployment-source",
        action="append",
        nargs=2,
        default=[],
        metavar=("REPOSITORY_SHA256", "PROJECT_PATH"),
        help="exact external deployment source repository identity and project path",
    )
    parser.add_argument("--allow", action="append", default=[])
    parser.add_argument("--require-approval", action="append", default=[])
    parser.add_argument("--forbid", action="append", default=[])
    parser.add_argument("--custom-policy", action="append", default=[], metavar="ACTION=MODE")
    parser.add_argument("--owner-directive-id", required=True)
    parser.add_argument("--owner-actor-id", required=True)
    parser.add_argument("--parent-grant-id", default=None)
    parser.add_argument("--can-delegate", action="store_true")
    parser.add_argument("--max-duration-seconds", type=int, default=None)
    parser.add_argument("--max-cost-usd", type=float, default=None)
    parser.add_argument("--network", choices=("denied", "allowlisted", "unrestricted"), default="denied")
    parser.add_argument("--allowed-domain", action="append", default=[])
    parser.add_argument("--provider", action="append", default=[])
    parser.add_argument("--secret-capability", action="append", default=[])
    if not one_time:
        parser.add_argument("--kind", choices=("standing", "one_time"), default="standing")
        parser.add_argument(
            "--expires-when",
            choices=("revoked", "slice_closed", "run_closed", "timestamp", "one_action"),
            default="revoked",
        )
        parser.add_argument("--expires-at", default=None)
        parser.add_argument("--max-actions", type=int, default=None)


def _add_authority_parser(subparsers: Any, command: Callable[..., int]) -> None:
    parser = subparsers.add_parser(
        "authority",
        help="Inspect and manage scoped standing authority, overrides, pauses, and receipts",
    )
    parser.add_argument("--repository", default=".")
    parser.add_argument("--authority-state-root", default=None)
    parser.add_argument("--authority-policy", default=None)
    nested = parser.add_subparsers(dest="authority_command", required=True)

    inspect = nested.add_parser("inspect", help="show effective authority without secret material")
    inspect.set_defaults(func=command)

    grant = nested.add_parser("grant", help="activate a typed standing grant under an owner directive")
    _add_grant_arguments(grant)
    grant.set_defaults(func=command)

    activate = nested.add_parser("activate", help="activate a complete JSON or YAML grant document")
    activate.add_argument("--grant-file", required=True)
    activate.add_argument("--owner-actor-id", required=True)
    activate.set_defaults(func=command)

    allow_once = nested.add_parser("allow-once", help="create a one-action break-glass override")
    allow_once.add_argument("action")
    _add_grant_arguments(allow_once, one_time=True)
    allow_once.set_defaults(func=command)

    evaluate = nested.add_parser("evaluate", help="evaluate an action without executing or consuming authority")
    evaluate.add_argument("action")
    evaluate.add_argument("--actor-id", required=True)
    evaluate.add_argument("--grant-id", default=None)
    evaluate.add_argument("--branch", default=None)
    evaluate.add_argument("--slice-id", default=None)
    evaluate.add_argument("--application-id", default=None)
    evaluate.add_argument("--run-id", default=None)
    evaluate.add_argument("--path", action="append", default=[])
    evaluate.add_argument("--estimated-cost-usd", type=float, default=0.0)
    evaluate.add_argument("--estimated-duration-seconds", type=int, default=0)
    evaluate.add_argument("--domain", action="append", default=[])
    evaluate.add_argument("--provider", default=None)
    evaluate.add_argument("--secret-capability", action="append", default=[])
    evaluate.add_argument("--assurance", action="append", default=[])
    evaluate.set_defaults(func=command)

    revoke = nested.add_parser("revoke", help="revoke a grant immediately")
    revoke.add_argument("grant_id")
    revoke.add_argument("--owner-actor-id", required=True)
    revoke.add_argument("--owner-directive-id", required=True)
    revoke.add_argument("--reason", required=True)
    revoke.set_defaults(func=command)

    for name in ("pause", "resume"):
        control = nested.add_parser(name, help=f"{name} autonomous execution")
        control.add_argument("--owner-actor-id", required=True)
        control.add_argument("--owner-directive-id", required=True)
        control.add_argument("--reason", required=True)
        control.set_defaults(func=command)

    receipt = nested.add_parser("receipt", help="read one integrity-checked action receipt")
    receipt.add_argument("receipt_id")
    receipt.set_defaults(func=command)

    show_grant = nested.add_parser("show-grant", help="read one grant with its effective status")
    show_grant.add_argument("grant_id")
    show_grant.set_defaults(func=command)


def main(argv: list[str] | None = None) -> int:
    _ensure_local_paths()
    from admin_cli.commands import (
        create_instance_cmd,
        run_instance_cmd,
        inspect_overrides_cmd,
        plan_upgrade_cmd,
        context_build_cmd,
        context_inspect_cmd,
        context_compare_cmd,
        host_inspect_cmd,
        run_plan_cmd,
        validate_run_result_cmd,
        validate_instance_cmd,
        validate_template_cmd,
        validate_external_template_cmd,
        resolve_source_cmd,
        approve_upgrade_cmd,
        apply_upgrade_cmd,
        doctor_cmd,
        catalog_cmd,
        backup_cmd,
        setup_cmd,
        persistent_instance_cmd,
        statepack_cmd,
        service_cmd,
        demo_cmd,
    )
    from admin_cli.workspaces import workspace_cmd
    from admin_cli.authority import authority_cmd
    from admin_cli.deployments import deployment_cmd
    from admin_cli.alpha4_runtime import register_exec_workspace_parser

    parser = argparse.ArgumentParser(
        prog="stateport",
        description="StatePort admin CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    _add_validate_parser(
        subparsers,
        "validate-template",
        "Validate a StateSpec template folder",
        "template",
        validate_template_cmd,
    )
    _add_validate_parser(
        subparsers,
        "validate-external-template",
        "Validate an external canonical template and print lifecycle metadata",
        "external template",
        validate_external_template_cmd,
    )
    _add_validate_parser(
        subparsers,
        "validate-instance",
        "Validate a StateSpec instance folder",
        "instance",
        validate_instance_cmd,
    )
    _add_run_instance_parser(subparsers, run_instance_cmd)
    _add_create_instance_parser(subparsers, create_instance_cmd)
    _add_inspect_overrides_parser(subparsers, inspect_overrides_cmd)
    _add_plan_upgrade_parser(subparsers, plan_upgrade_cmd)
    _add_source_resolve_parser(subparsers, resolve_source_cmd)
    _add_approve_upgrade_parser(subparsers, approve_upgrade_cmd)
    _add_apply_upgrade_parser(subparsers, apply_upgrade_cmd)
    _add_context_build_parser(subparsers, context_build_cmd)
    _add_context_inspect_parser(subparsers, context_inspect_cmd)
    _add_context_compare_parser(subparsers, context_compare_cmd)
    _add_host_inspect_parser(subparsers, host_inspect_cmd)
    _add_run_contract_parser(subparsers, run_plan_cmd, validate_run_result_cmd)
    _add_doctor_parser(subparsers, doctor_cmd)
    _add_catalog_parser(subparsers, catalog_cmd)
    _add_backup_parser(subparsers, backup_cmd)
    _add_setup_parser(subparsers, setup_cmd)
    _add_instance_parser(subparsers, persistent_instance_cmd)
    _add_statepack_parser(subparsers, statepack_cmd)
    _add_service_parser(subparsers, service_cmd)
    _add_demo_parser(subparsers, demo_cmd)
    _add_deploy_parser(subparsers, deployment_cmd)
    _add_workspace_parser(subparsers, workspace_cmd)
    _add_authority_parser(subparsers, authority_cmd)
    register_exec_workspace_parser(subparsers)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
