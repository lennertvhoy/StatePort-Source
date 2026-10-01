#!/usr/bin/env python3
"""Deterministic regressions for the bounded workspace lifecycle authority."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "packages" / "governed-runner" / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from governed_runner.workspaces import (  # noqa: E402
    WORKSPACE_OBSERVATION_SCHEMA,
    WorkspaceBudget,
    WorkspaceLifecycleError,
    WorkspaceLifecycleManager,
    WorkspaceLifecycleRefusal,
)


def _run(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _repo(tmp_path: Path, name: str = "repo") -> Path:
    repo = tmp_path / name
    repo.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    _run(repo, "config", "user.name", "Workspace Fixture")
    _run(repo, "config", "user.email", "workspace@example.invalid")
    (repo / "README.md").write_text("fixture\n", encoding="utf-8")
    config = repo / "config"
    config.mkdir()
    shutil.copyfile(ROOT / "config" / "workspace-lifecycle.v1.yaml", config / "workspace-lifecycle.v1.yaml")
    _run(repo, "add", "README.md", "config/workspace-lifecycle.v1.yaml")
    _run(repo, "commit", "-qm", "fixture")
    return repo


def _manager(
    tmp_path: Path,
    *,
    name: str = "repo",
    repo: Path | None = None,
    clock=None,
    process_observer=None,
    fault_injector=None,
    **budget_changes: object,
) -> WorkspaceLifecycleManager:
    selected = repo or _repo(tmp_path, name)
    budget = replace(WorkspaceBudget(), **budget_changes)
    return WorkspaceLifecycleManager(
        selected,
        state_root=tmp_path / f"{name}-state",
        budget=budget,
        clock=clock,
        process_observer=process_observer,
        fault_injector=fault_injector,
    )


def _create(manager: WorkspaceLifecycleManager, suffix: str = "one", *, slice_id: str = "BL-TEST-001") -> dict:
    return manager.create_workspace(
        slice_id=slice_id,
        owner_agent_id="agent-primary",
        branch=f"agent/fixture-{suffix}",
        workspace_name=f"fixture-{suffix}",
        purpose="deterministic workspace lifecycle fixture",
    )


def _export(manager: WorkspaceLifecycleManager, lease: dict) -> dict:
    return manager.export_evidence(lease["leaseId"])


def test_managed_creation_within_budget_persists_typed_lease(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    lease = _create(manager)
    assert lease["schema"] == "stateport.workspace-lease/v1"
    assert lease["status"] == "active"
    assert Path(lease["worktreePath"]).is_dir()
    assert manager.get_lease(lease["leaseId"]) == lease


def test_creation_refuses_above_registered_worktree_budget(tmp_path: Path) -> None:
    manager = _manager(
        tmp_path,
        max_registered_worktrees=1,
        max_active_writable_worktrees=1,
        max_unreconciled_branches=1,
    )
    with pytest.raises(WorkspaceLifecycleRefusal, match="workspace_budget_exceeded"):
        _create(manager)


def test_creation_refuses_above_active_writable_budget(tmp_path: Path) -> None:
    manager = _manager(tmp_path, max_active_writable_worktrees=1)
    _create(manager, "one")
    with pytest.raises(WorkspaceLifecycleRefusal, match="workspace_budget_exceeded"):
        _create(manager, "two")


def test_creation_refuses_unknown_registered_worktree(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    manual = manager.workspace_root / "manual"
    _run(manager.repository, "worktree", "add", "-q", "-b", "manual/test", str(manual), "HEAD")
    with pytest.raises(WorkspaceLifecycleRefusal, match="unleased_workspace_present"):
        _create(manager)


def test_creation_refuses_expired_lease(tmp_path: Path) -> None:
    start = datetime(2026, 7, 29, 12, tzinfo=timezone.utc)
    manager = _manager(tmp_path, clock=lambda: start)
    manager.create_workspace(
        slice_id="BL-TEST-001",
        owner_agent_id="agent-primary",
        branch="agent/fixture-one",
        workspace_name="fixture-one",
        purpose="expiry fixture",
        duration_seconds=60,
    )
    restarted = WorkspaceLifecycleManager(
        manager.repository,
        state_root=manager.state_root,
        budget=manager.budget,
        clock=lambda: start + timedelta(seconds=61),
    )
    with pytest.raises(WorkspaceLifecycleRefusal, match="expired_lease_present"):
        _create(restarted, "two")


def test_creation_refuses_incomplete_prior_slice(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    _create(manager, slice_id="BL-FIRST-001")
    with pytest.raises(WorkspaceLifecycleRefusal, match="prior_slice_cleanup_incomplete"):
        _create(manager, "two", slice_id="BL-SECOND-001")


def test_concurrent_creation_lock_fails_closed(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    with manager.lifecycle_lock():
        with pytest.raises(WorkspaceLifecycleRefusal, match="workspace_lock_busy"):
            _create(manager)


def test_partial_creation_rolls_back_only_transaction_artifacts(tmp_path: Path) -> None:
    def fail(stage: str) -> None:
        if stage == "after_worktree_add":
            raise RuntimeError("injected failure")

    manager = _manager(tmp_path, fault_injector=fail)
    with pytest.raises(WorkspaceLifecycleError, match="workspace_creation_failed"):
        _create(manager)
    assert len(manager.audit()["inventory"]) == 1
    assert _run(manager.repository, "branch", "--list", "agent/fixture-one") == ""
    receipts = list(manager.receipts_root.glob("failure-*.json"))
    assert len(receipts) == 1
    assert json.loads(receipts[0].read_text())["rollbackCompleted"] is True


def test_repository_and_branch_identity_are_bound_exactly(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    lease = _create(manager)
    assert lease["repositoryIdentity"] == manager.identity.to_dict()
    assert _run(Path(lease["worktreePath"]), "branch", "--show-current") == lease["branch"]
    other_repo = _repo(tmp_path, "other")
    other = _manager(tmp_path, name="other", repo=other_repo)
    with pytest.raises(WorkspaceLifecycleRefusal, match="repository_identity_mismatch"):
        other._require_repository_identity(lease["repositoryIdentity"])


def test_clean_integrated_worktree_is_removed_automatically(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    lease = _create(manager)
    _export(manager, lease)
    receipt = manager.close_workspace(lease["leaseId"], disposition="integrated", integration_ref="main")
    assert receipt["status"] == "integrated_and_removed"
    assert not Path(lease["worktreePath"]).exists()
    assert _run(manager.repository, "branch", "--list", lease["branch"]) == ""


def test_clean_rejected_worktree_is_removed_after_evidence_export(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    lease = _create(manager)
    _export(manager, lease)
    receipt = manager.close_workspace(lease["leaseId"], disposition="rejected")
    assert receipt["status"] == "rejected_and_removed"
    assert not Path(lease["worktreePath"]).exists()


def test_unique_branch_is_archived_before_worktree_removal(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    lease = _create(manager)
    worktree = Path(lease["worktreePath"])
    (worktree / "unique.txt").write_text("durable unique evidence\n", encoding="utf-8")
    _run(worktree, "add", "unique.txt")
    _run(worktree, "commit", "-qm", "unique fixture")
    _export(manager, lease)
    receipt = manager.close_workspace(lease["leaseId"], disposition="archived")
    assert receipt["status"] == "archived_and_removed"
    assert Path(receipt["archiveBundle"]).is_file()
    assert receipt["archiveDigest"].startswith("sha256:")


def test_dirty_tracked_worktree_is_retained_as_exception(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    lease = _create(manager)
    _export(manager, lease)
    (Path(lease["worktreePath"]) / "README.md").write_text("dirty\n", encoding="utf-8")
    receipt = manager.close_workspace(
        lease["leaseId"],
        disposition="rejected",
        exception_reason="human review required",
        exception_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    assert receipt["status"] == "retained_exception"
    assert "dirty_tracked_files" in receipt["classifications"]
    assert Path(lease["worktreePath"]).exists()


def test_untracked_worktree_is_retained_as_exception(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    lease = _create(manager)
    _export(manager, lease)
    (Path(lease["worktreePath"]) / "owner-note.txt").write_text("preserve\n", encoding="utf-8")
    receipt = manager.close_workspace(
        lease["leaseId"],
        disposition="rejected",
        exception_reason="untracked owner content",
        exception_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    assert "untracked_content" in receipt["classifications"]
    assert Path(lease["worktreePath"]).exists()


def test_running_process_worktree_is_retained(tmp_path: Path) -> None:
    manager = _manager(tmp_path, process_observer=lambda _path: [4242])
    lease = _create(manager)
    _export(manager, lease)
    receipt = manager.close_workspace(
        lease["leaseId"],
        disposition="rejected",
        exception_reason="observed running process",
        exception_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    assert "active_processes" in receipt["classifications"]
    assert receipt["worktreeRemoved"] is False


def test_missing_evidence_export_blocks_closure(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    lease = _create(manager)
    with pytest.raises(WorkspaceLifecycleRefusal, match="evidence_export_missing"):
        manager.close_workspace(lease["leaseId"], disposition="rejected")


def _simulate_external_integrated_removal(
    manager: WorkspaceLifecycleManager,
    lease: dict,
    *,
    integrate: bool,
) -> tuple[str, str]:
    worktree = Path(lease["worktreePath"])
    (worktree / "recovered.txt").write_text("retained exact head\n", encoding="utf-8")
    _run(worktree, "add", "recovered.txt")
    _run(worktree, "commit", "-qm", "recovered fixture")
    head = _run(worktree, "rev-parse", "HEAD")
    recovered_ref = f"refs/recovery/{lease['leaseId']}"
    _run(manager.repository, "update-ref", recovered_ref, head)
    if integrate:
        _run(manager.repository, "merge", "--no-ff", "--no-edit", head)
    _run(manager.repository, "worktree", "remove", str(worktree))
    _run(manager.repository, "branch", "-D", lease["branch"])
    return recovered_ref, head


def test_missing_integrated_workspace_can_be_reconciled_from_retained_ref(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    lease = _create(manager)
    recovered_ref, head = _simulate_external_integrated_removal(manager, lease, integrate=True)

    receipt = manager.reconcile_missing_integrated_workspace(
        lease["leaseId"],
        recovered_ref=recovered_ref,
        integration_ref="main",
    )

    assert receipt["status"] == "integrated_and_removed"
    assert receipt["head"] == head
    assert receipt["classifications"] == ["reconciled_after_external_removal"]
    assert Path(receipt["evidenceExportLocation"]).is_file()
    manifest = json.loads(Path(receipt["evidenceExportLocation"]).read_text(encoding="utf-8"))
    assert manifest["head"] == head
    assert Path(manifest["patch"]["storedPath"]).read_text(encoding="utf-8").startswith("diff --git")
    assert manager.get_lease(lease["leaseId"])["cleanupRequired"] is False
    assert manager.reconcile_missing_integrated_workspace(
        lease["leaseId"], recovered_ref=recovered_ref, integration_ref="main"
    ) == receipt
    assert manager.assert_slice_closed("BL-TEST-001")["schema"] == "stateport.workspace-slice-closure/v1"
    observations = [json.loads(line) for line in manager.observations_path.read_text().splitlines()]
    assert observations[-1]["event"] == "workspace_missing_reconciled"


def test_missing_workspace_recovery_refuses_a_live_worktree(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    lease = _create(manager)
    with pytest.raises(WorkspaceLifecycleRefusal, match="still exists"):
        manager.reconcile_missing_integrated_workspace(
            lease["leaseId"], recovered_ref="main", integration_ref="main"
        )


def test_missing_workspace_recovery_refuses_prior_evidence_export(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    lease = _create(manager)
    _export(manager, lease)
    with pytest.raises(WorkspaceLifecycleRefusal, match="without prior evidence export"):
        manager.reconcile_missing_integrated_workspace(
            lease["leaseId"], recovered_ref="main", integration_ref="main"
        )


def test_missing_workspace_recovery_refuses_unintegrated_head(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    lease = _create(manager)
    recovered_ref, _head = _simulate_external_integrated_removal(manager, lease, integrate=False)
    with pytest.raises(WorkspaceLifecycleRefusal, match="not integrated"):
        manager.reconcile_missing_integrated_workspace(
            lease["leaseId"], recovered_ref=recovered_ref, integration_ref="main"
        )
    assert manager.get_lease(lease["leaseId"])["status"] == "active"


def test_missing_workspace_recovery_refuses_a_non_descendant_ref(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    lease = _create(manager)
    _run(manager.repository, "worktree", "remove", lease["worktreePath"])
    _run(manager.repository, "branch", "-D", lease["branch"])
    tree = _run(manager.repository, "rev-parse", "HEAD^{tree}")
    unrelated = _run(manager.repository, "commit-tree", tree, "-m", "unrelated root")
    _run(manager.repository, "update-ref", "refs/recovery/unrelated", unrelated)
    with pytest.raises(WorkspaceLifecycleRefusal, match="does not descend"):
        manager.reconcile_missing_integrated_workspace(
            lease["leaseId"], recovered_ref="refs/recovery/unrelated", integration_ref="main"
        )


def test_head_advance_requires_append_only_evidence_refresh_before_closure(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    lease = _create(manager)
    artifact = tmp_path / "test-receipt.json"
    artifact.write_text("first\n", encoding="utf-8")
    first = manager.export_evidence(
        lease["leaseId"],
        artifacts={"testReceipts": [artifact]},
    )
    first_path = Path(manager.get_lease(lease["leaseId"])["evidenceExportLocation"])
    first_manifest = first_path.read_bytes()
    first_artifact_path = Path(first["artifacts"]["testReceipts"][0]["storedPath"])
    first_artifact = first_artifact_path.read_bytes()

    worktree = Path(lease["worktreePath"])
    (worktree / "repair.txt").write_text("exact-head repair\n", encoding="utf-8")
    _run(worktree, "add", "repair.txt")
    _run(worktree, "commit", "-qm", "repair fixture")
    with pytest.raises(WorkspaceLifecycleRefusal, match="evidence_export_stale"):
        manager.close_workspace(lease["leaseId"], disposition="rejected")

    artifact.write_text("second\n", encoding="utf-8")
    second = manager.export_evidence(
        lease["leaseId"],
        artifacts={"testReceipts": [artifact]},
    )
    refreshed = manager.get_lease(lease["leaseId"])
    second_path = Path(refreshed["evidenceExportLocation"])
    assert second_path == manager.evidence_root / lease["leaseId"] / "revisions" / second["head"] / "manifest.json"
    assert second_path != first_path
    assert first_path.read_bytes() == first_manifest
    assert first_artifact_path.read_bytes() == first_artifact
    assert second["previousManifest"] == {
        "storedPath": first_path.as_posix(),
        "head": first["head"],
        "manifestDigest": first["manifestDigest"],
    }
    assert Path(second["artifacts"]["testReceipts"][0]["storedPath"]).read_text(encoding="utf-8") == "second\n"
    assert manager.export_evidence(lease["leaseId"]) == second

    receipt = manager.close_workspace(lease["leaseId"], disposition="rejected")
    assert receipt["status"] == "rejected_and_removed"
    assert first_path.read_bytes() == first_manifest
    assert second_path.is_file()


def test_evidence_revision_chain_detects_predecessor_tampering(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    lease = _create(manager)
    first = _export(manager, lease)
    first_path = Path(manager.get_lease(lease["leaseId"])["evidenceExportLocation"])
    worktree = Path(lease["worktreePath"])
    (worktree / "repair.txt").write_text("exact-head repair\n", encoding="utf-8")
    _run(worktree, "add", "repair.txt")
    _run(worktree, "commit", "-qm", "repair fixture")
    second = _export(manager, lease)
    assert second["previousManifest"]["manifestDigest"] == first["manifestDigest"]

    first_path.write_text("{}\n", encoding="utf-8")
    with pytest.raises(WorkspaceLifecycleError, match="evidence_integrity_failed"):
        manager.audit()


def test_active_lease_blocks_slice_closure(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    _create(manager)
    with pytest.raises(WorkspaceLifecycleRefusal, match="active_lease_present"):
        manager.assert_slice_closed("BL-TEST-001")


def test_closed_slice_identifier_cannot_create_another_workspace(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    lease = _create(manager)
    _export(manager, lease)
    manager.close_workspace(lease["leaseId"], disposition="rejected")
    closure = manager.assert_slice_closed("BL-TEST-001")

    with pytest.raises(WorkspaceLifecycleRefusal, match="slice_already_closed"):
        _create(manager, "two")

    assert manager.assert_slice_closed("BL-TEST-001") == closure
    assert _run(manager.repository, "branch", "--list", "agent/fixture-two") == ""


def test_malformed_slice_closure_receipt_blocks_creation(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    lease = _create(manager)
    _export(manager, lease)
    manager.close_workspace(lease["leaseId"], disposition="rejected")
    manager.assert_slice_closed("BL-TEST-001")
    receipt_path = manager._receipt_path("slice-closure-BL-TEST-001")
    document = json.loads(receipt_path.read_text(encoding="utf-8"))
    document["schema"] = "stateport.workspace-slice-closure/unknown"
    receipt_path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(WorkspaceLifecycleError, match="receipt_integrity_failed"):
        _create(manager, "two")


def test_historical_slice_reuse_never_returns_a_stale_closure(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    first = _create(manager)
    _export(manager, first)
    manager.close_workspace(first["leaseId"], disposition="rejected")
    manager.assert_slice_closed("BL-TEST-001")
    receipt_path = manager._receipt_path("slice-closure-BL-TEST-001")
    held_receipt = tmp_path / "held-slice-closure.json"
    receipt_path.rename(held_receipt)
    second = _create(manager, "two")
    held_receipt.rename(receipt_path)
    _export(manager, second)
    manager.close_workspace(second["leaseId"], disposition="rejected")

    with pytest.raises(WorkspaceLifecycleRefusal, match="slice_identifier_reused"):
        manager.assert_slice_closed("BL-TEST-001")


def test_unclassified_branch_blocks_repository_closure(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    lease = _create(manager)
    with pytest.raises(WorkspaceLifecycleRefusal, match="unclassified_branch_present"):
        manager.assert_repository_closed()
    assert lease["branch"] in _run(manager.repository, "branch", "--list", lease["branch"])


def test_repeated_closure_is_idempotent(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    lease = _create(manager)
    _export(manager, lease)
    first = manager.close_workspace(lease["leaseId"], disposition="rejected")
    second = manager.close_workspace(lease["leaseId"], disposition="rejected")
    assert first == second


def test_restart_reloads_active_leases_safely(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    lease = _create(manager)
    restarted = WorkspaceLifecycleManager(manager.repository, state_root=manager.state_root, budget=manager.budget)
    assert restarted.get_lease(lease["leaseId"])["status"] == "active"
    assert lease["leaseId"] in restarted.audit(slice_id="BL-TEST-001")["activeLeases"]


def test_malformed_lease_fails_closed(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    lease = _create(manager)
    manager._lease_path(lease["leaseId"]).write_text("{not-json\n", encoding="utf-8")
    with pytest.raises(WorkspaceLifecycleError, match="malformed_lease"):
        manager.audit()


def test_path_traversal_and_symlink_targets_are_rejected(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    with pytest.raises(WorkspaceLifecycleError, match="invalid_contract"):
        manager.create_workspace(
            slice_id="BL-TEST-001",
            owner_agent_id="agent-primary",
            branch="agent/traversal",
            workspace_name="../escape",
            purpose="reject traversal",
        )
    outside = tmp_path / "outside"
    outside.mkdir()
    (manager.workspace_root / "fixture-link").symlink_to(outside, target_is_directory=True)
    with pytest.raises(WorkspaceLifecycleError, match="unsafe_path"):
        manager.create_workspace(
            slice_id="BL-TEST-001",
            owner_agent_id="agent-primary",
            branch="agent/symlink",
            workspace_name="fixture-link",
            purpose="reject symlink",
        )


def test_direct_unmanaged_worktree_is_detected(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    manual = manager.workspace_root / "manual-direct"
    _run(manager.repository, "worktree", "add", "-q", "-b", "manual/direct", str(manual), "HEAD")
    audit = manager.audit()
    assert audit["ok"] is False
    assert manual.as_posix() in next(
        item["items"] for item in audit["violations"] if item["code"] == "unleased_workspace_present"
    )


def test_cleanup_receipt_survives_worktree_removal(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    lease = _create(manager)
    manifest = _export(manager, lease)
    receipt = manager.close_workspace(lease["leaseId"], disposition="rejected")
    receipt_path = Path(manager.get_lease(lease["leaseId"])["cleanupReceipt"])
    assert receipt_path.is_file() and json.loads(receipt_path.read_text()) == receipt
    assert Path(manifest["patch"]["storedPath"]).is_file()
    assert not Path(lease["worktreePath"]).exists()


def test_statebench_observation_records_leaked_workspace_failure(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    lease = _create(manager)
    _export(manager, lease)
    (Path(lease["worktreePath"]) / "residue.txt").write_text("retain\n", encoding="utf-8")
    manager.close_workspace(
        lease["leaseId"],
        disposition="rejected",
        exception_reason="escaped-process regression",
        exception_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    records = [json.loads(line) for line in manager.observations_path.read_text().splitlines()]
    leaked = records[-1]
    assert leaked["schema"] == WORKSPACE_OBSERVATION_SCHEMA
    assert leaked["metrics"]["worktrees_leaked"] == 1
    assert leaked["metrics"]["cleanup_failures"] == 1


def test_duplicate_lease_identity_is_rejected(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    lease = _create(manager)
    duplicate = manager.leases_root / "lease_ffffffffffffffffffffffffffffffff.json"
    shutil.copyfile(manager._lease_path(lease["leaseId"]), duplicate)
    with pytest.raises(WorkspaceLifecycleError, match="filename does not match"):
        manager.audit()
