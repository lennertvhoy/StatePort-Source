#!/usr/bin/env python3
"""End-to-end CLI enforcement between standing grants and managed workspaces."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
for source in (
    ROOT / "apps" / "admin-cli" / "src",
    ROOT / "packages" / "governed-runner" / "src",
):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from admin_cli.main import main  # noqa: E402
from governed_runner.authority import AuthorityManager, grant_template  # noqa: E402
from governed_runner.workspaces import WorkspaceLifecycleManager  # noqa: E402


def _run(repository: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _repository(tmp_path: Path) -> Path:
    repository = tmp_path / "repository"
    repository.mkdir()
    _run(repository, "init", "-q")
    _run(repository, "config", "user.email", "workspace-authority@example.invalid")
    _run(repository, "config", "user.name", "Workspace Authority Fixture")
    config = repository / "config"
    config.mkdir()
    for name in ("authority-policy.v1.yaml", "workspace-lifecycle.v1.yaml"):
        shutil.copyfile(ROOT / "config" / name, config / name)
    (repository / "README.md").write_text("fixture\n", encoding="utf-8")
    _run(repository, "add", ".")
    _run(repository, "commit", "-qm", "fixture")
    return repository


def _grant(repository: Path, authority_state: Path) -> dict:
    manager = AuthorityManager(repository, state_root=authority_state)
    grant = grant_template(
        manager,
        grant_id="grant_workspace_fixture",
        profile="balanced",
        actor_id="agent-primary",
        role="primary",
        branch_pattern="agent/*",
        slice_id="BL-WORKSPACE-AUTH-001",
        application_id=None,
        run_id=None,
        paths=["."],
        allow=[],
        require_approval=["merge", "deployment", "real_secret_use"],
        forbid=["force_push", "history_rewrite", "disable_safety_gates"],
        owner_directive_id="OD-WORKSPACE-AUTH-001",
        expires_when="slice_closed",
        max_actions=20,
        max_duration_seconds=21_600,
        max_cost_usd=0.0,
    )
    return manager.activate_grant(grant, owner_actor_id="owner-local")["grant"]


def _prefix(repository: Path, workspace_state: Path, authority_state: Path, *, grant: bool) -> list[str]:
    values = [
        "workspace",
        "--repository",
        str(repository),
        "--state-root",
        str(workspace_state),
        "--authority-state-root",
        str(authority_state),
        "--actor-id",
        "agent-primary",
    ]
    if grant:
        values.extend(["--grant-id", "grant_workspace_fixture"])
    return values


def test_workspace_mutations_require_and_receipt_standing_authority(tmp_path: Path, capsys) -> None:
    repository = _repository(tmp_path)
    workspace_state = tmp_path / "workspace-state"
    authority_state = tmp_path / "authority-state"
    create_args = [
        "create",
        "--slice-id",
        "BL-WORKSPACE-AUTH-001",
        "--owner-agent-id",
        "agent-primary",
        "--branch",
        "agent/workspace-authority",
        "--workspace-name",
        "workspace-authority",
        "--purpose",
        "authority integration fixture",
    ]

    assert main(_prefix(repository, workspace_state, authority_state, grant=False) + create_args) == 2
    denied = json.loads(capsys.readouterr().err)
    assert denied["code"] == "standing_grant_required"
    assert denied["authorityReceipt"]["result"]["status"] == "not_executed"
    assert len(WorkspaceLifecycleManager(repository, state_root=workspace_state).audit()["inventory"]) == 1

    grant = _grant(repository, authority_state)
    assert main(_prefix(repository, workspace_state, authority_state, grant=True) + create_args) == 0
    created = json.loads(capsys.readouterr().out)
    lease_id = created["leaseId"]
    assert created["authorityReceipt"]["authorizedBy"]["id"] == grant["grantId"]
    assert created["authorityReceipt"]["action"] == "create_managed_worktree"
    assert created["authorityReceipt"]["result"]["status"] == "succeeded"

    assert main(
        _prefix(repository, workspace_state, authority_state, grant=True)
        + ["export-evidence", lease_id]
    ) == 0
    exported = json.loads(capsys.readouterr().out)
    assert exported["authorityReceipt"]["action"] == "export_workspace_evidence"
    assert exported["manifestDigest"].startswith("sha256:")

    assert main(
        _prefix(repository, workspace_state, authority_state, grant=True)
        + ["close", lease_id, "--disposition", "rejected", "--close-slice"]
    ) == 0
    closed = json.loads(capsys.readouterr().out)
    assert closed["status"] == "rejected_and_removed"
    assert closed["authorityReceipt"]["action"] == "retire_owned_worktree"
    assert closed["authorityReceipt"]["result"]["resource"]["workspaceReceiptDigest"].startswith("sha256:")
    assert closed["sliceClosure"]["ok"] is True
    assert closed["sliceClosureAuthorityReceipt"]["authorizedBy"]["id"] == grant["grantId"]
    assert closed["sliceClosureAuthorityReceipt"]["action"] == "close_authority_scope"
    assert closed["authorityScopeClosure"]["kind"] == "slice"
    assert AuthorityManager(repository, state_root=authority_state).get_grant(grant["grantId"])["status"] == "expired"
    audit = WorkspaceLifecycleManager(repository, state_root=workspace_state).audit()
    assert audit["counts"]["registeredWorktrees"] == 1
    assert audit["counts"]["activeWritableWorktrees"] == 0
    assert audit["counts"]["unclassifiedWorktrees"] == 0


def test_pause_blocks_new_workspace_before_git_mutation(tmp_path: Path, capsys) -> None:
    repository = _repository(tmp_path)
    workspace_state = tmp_path / "workspace-state"
    authority_state = tmp_path / "authority-state"
    grant = _grant(repository, authority_state)
    AuthorityManager(repository, state_root=authority_state).set_paused(
        paused=True,
        actor_id="owner-local",
        owner_directive_id="OD-PAUSE-WORKSPACE-001",
        reason="fixture pause",
    )
    result = main(
        _prefix(repository, workspace_state, authority_state, grant=True)
        + [
            "create",
            "--slice-id",
            "BL-WORKSPACE-AUTH-001",
            "--owner-agent-id",
            "agent-primary",
            "--branch",
            "agent/paused",
            "--workspace-name",
            "paused",
            "--purpose",
            "must not start",
        ]
    )
    assert result == 2
    denied = json.loads(capsys.readouterr().err)
    assert denied["code"] == "autonomous_execution_paused"
    assert denied["authorityReceipt"]["authorizedBy"]["id"] == grant["grantId"]
    assert _run(repository, "branch", "--list", "agent/paused") == ""


def test_grantless_slice_assertion_cannot_persist_authority_closure(tmp_path: Path, capsys) -> None:
    repository = _repository(tmp_path)
    workspace_state = tmp_path / "workspace-state"
    authority_state = tmp_path / "authority-state"
    result = main(
        _prefix(repository, workspace_state, authority_state, grant=False)
        + ["assert-slice-closed", "--slice-id", "BL-WORKSPACE-AUTH-001"]
    )
    assert result == 2
    denied = json.loads(capsys.readouterr().err)
    assert denied["code"] == "standing_grant_required"
    assert denied["authorityReceipt"]["result"]["status"] == "not_executed"
    manager = AuthorityManager(repository, state_root=authority_state)
    assert list(manager.closures_root.iterdir()) == []
