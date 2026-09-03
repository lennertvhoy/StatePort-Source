from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import os
import shutil
import stat
import subprocess
import sys
import time

import pytest


ROOT = Path(__file__).resolve().parents[1]
for relative in (
    "packages/persistent-app/src",
    "packages/portable-execution/src",
    "packages/execution-host/src",
    "packages/external-engine-runtime/src",
    "packages/codex-adapter/src",
    "packages/run-bundle/src",
    "packages/statedd-core/src",
    "packages/template-validator/src",
    "packages/instance-backup/src",
    "packages/instance-catalog/src",
    "packages/diagnostics/src",
    "packages/statebench/src",
    "packages/governed-runner/src",
):
    sys.path.insert(0, str(ROOT / relative))

from governed_runner import (  # noqa: E402
    InstanceLease,
    digest_snapshot,
    restore_snapshot,
    snapshot_files,
)
from stateport_persistent_app import LocalLayout, PersistentApp  # noqa: E402
from stateport_portable_execution import PortableExecutionError  # noqa: E402
from stateport_portable_execution.runtime import PortableExecutionService  # noqa: E402
import stateport_portable_execution.runtime as portable_runtime  # noqa: E402


def _service(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, suffix: str = "") -> tuple[PortableExecutionService, PersistentApp, Path]:
    root = tmp_path / (suffix or "runtime")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(root / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(root / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(root / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    service = PortableExecutionService(app, ROOT)
    instance_id = "apply-integrity" + (f"-{suffix}" if suffix else "")
    service.install_fixture_instance("checklistdd", instance_id)
    _, instance_root = app._entry(instance_id)
    return service, app, instance_root


def _approved_proposal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, suffix: str = "",
) -> tuple[PortableExecutionService, PersistentApp, Path, str]:
    service, app, instance_root = _service(tmp_path, monkeypatch, suffix)
    instance_id = instance_root.name
    prepared = service.prepare(
        instance_id,
        "checklistdd.complete-item/v1",
        "synthetic",
        {"itemId": "first-item"},
    )
    run_id = prepared["run"]["runId"]
    service.approve_run(run_id)
    service.execute(run_id)
    service.approve_proposal(run_id)
    return service, app, instance_root, run_id


def _persist_applying_recovery_fixture(
    service: PortableExecutionService,
    instance_root: Path,
    run_id: str,
    *, process: subprocess.Popen[bytes] | None = None,
) -> object:
    before = snapshot_files(instance_root)
    key, snapshot_digest = service._persist_apply_snapshot(run_id, before)
    process_record: dict[str, object] = {"phase": "writer", "state": "pending_gate"}
    if process is not None:
        identity = service._process_identity(process.pid)
        assert identity is not None and identity[1] == process.pid
        generation = service._process_generation(process.pid)
        assert generation is not None
        process_record = {
            "phase": "writer", "state": "active", "pid": process.pid,
            "processGroupId": process.pid, "startTimeTicks": identity[0],
            "processGeneration": generation,
        }
    record = service.store.get(run_id)
    assert record is not None and isinstance(record["baseGit"], str)
    service.store.transition(
        run_id, "applying",
        applySupervisor={"pid": 999_999_937, "startTimeTicks": "1"},
        applyProcess=process_record,
        applyTransaction={
            "formatVersion": "stateport.filesystem-transaction/v1",
            "beforeDigest": snapshot_digest,
            "baseGit": record["baseGit"],
            "paths": list(record["proposalPaths"]),
            "sideEffectClassification": "filesystem_transaction",
            "enforcement": "sandboxed_staging_then_trusted_commit",
            "snapshotKey": key,
            "snapshotDigest": snapshot_digest,
            "rollbackStatus": "prepared_fsynced",
        },
    )
    return before


def test_restore_snapshot_fsyncs_all_recreated_files_and_directories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    (source / "nested/empty").mkdir(parents=True)
    (source / "root.txt").write_text("root bytes\n", encoding="utf-8")
    (source / "nested/state.yaml").write_text("durable: true\n", encoding="utf-8")
    snapshot = snapshot_files(source)

    target = tmp_path / "target"
    target.mkdir()
    (target / "obsolete.txt").write_text("remove me\n", encoding="utf-8")
    synced: set[tuple[int, int]] = set()
    real_fsync = os.fsync

    def record_fsync(descriptor: int) -> None:
        info = os.fstat(descriptor)
        synced.add((stat.S_IFMT(info.st_mode), info.st_ino))
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", record_fsync)
    restore_snapshot(target, snapshot)

    assert snapshot_files(target) == snapshot
    expected = {
        (stat.S_IFMT(path.stat().st_mode), path.stat().st_ino)
        for path in (target, *(target / item for item in snapshot.directories))
    }
    expected.update(
        (stat.S_IFMT(path.stat().st_mode), path.stat().st_ino)
        for path in (target / item for item in snapshot.files)
    )
    assert expected <= synced


@pytest.mark.parametrize("failure_mode", ("partial_failure", "extra_path", "malformed_receipt", "wrong_receipt"))
def test_apply_restores_the_complete_snapshot_after_untrusted_writer_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_mode: str,
) -> None:
    service, _app, instance_root, run_id = _approved_proposal(
        tmp_path, monkeypatch, failure_mode,
    )
    before = snapshot_files(instance_root)
    real_run_process = portable_runtime.run_process

    def adversarial_writer(spec, *, cancel_event=None):
        result = real_run_process(spec, cancel_event=cancel_event)
        if "--apply-proposal" not in spec.command:
            return result
        if failure_mode == "partial_failure":
            return replace(result, returncode=17, stderr="writer failed after mutation")
        if failure_mode == "extra_path":
            (instance_root / "state/UNAPPROVED.yaml").write_text("unexpected: true\n", encoding="utf-8")
            return result
        if failure_mode == "malformed_receipt":
            return replace(result, stdout="{malformed")
        payload = __import__("json").loads(result.stdout)
        payload["proposalId"] = "proposal-not-approved"
        return replace(result, stdout=__import__("json").dumps(payload))

    monkeypatch.setattr(portable_runtime, "run_process", adversarial_writer)
    with pytest.raises(PortableExecutionError):
        service.apply_proposal(run_id)

    after = snapshot_files(instance_root)
    assert after == before
    assert digest_snapshot(after) == digest_snapshot(before)
    record = service.inspect(run_id)["run"]
    assert record["status"] == "apply_failed"
    assert record["rollback"]["status"] == "completed"
    assert record["rollback"]["byteIdentical"] is True
    assert not (instance_root / "state/UNAPPROVED.yaml").exists()


def test_apply_requires_the_instance_writer_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, app, instance_root, run_id = _approved_proposal(tmp_path, monkeypatch, "lease")
    before = snapshot_files(instance_root)
    with InstanceLease(app.layout.operations_root / "leases", instance_root, owner="competing-writer"):
        with pytest.raises(PortableExecutionError, match="active writer lease"):
            service.apply_proposal(run_id)
    assert snapshot_files(instance_root) == before
    assert service.inspect(run_id)["run"]["status"] == "state_change_approved"


@pytest.mark.parametrize("phase", ("execute", "apply"))
def test_development_candidate_receipt_is_rechecked_before_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    if phase == "execute":
        service, _app, instance_root = _service(tmp_path, monkeypatch, "receipt-execute")
        prepared = service.prepare(
            instance_root.name,
            "checklistdd.complete-item/v1",
            "synthetic",
            {"itemId": "first-item"},
        )
        run_id = prepared["run"]["runId"]
        service.approve_run(run_id)
    else:
        service, _app, _instance_root, run_id = _approved_proposal(
            tmp_path, monkeypatch, "receipt-apply",
        )
    service.store.update(
        run_id,
        sourceAccessClass="development_candidate",
        sourceAccessReceiptDigest="sha256:" + "a" * 64,
    )

    with pytest.raises(PortableExecutionError, match="no longer authorized"):
        if phase == "execute":
            service.execute(run_id)
        else:
            service.apply_proposal(run_id)

    expected_status = "approved" if phase == "execute" else "state_change_approved"
    assert service.inspect(run_id)["run"]["status"] == expected_status


def test_write_capable_prepare_requires_an_exact_instance_git_head(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _app, instance_root = _service(tmp_path, monkeypatch, "missing-git")
    shutil.rmtree(instance_root / ".git")
    with pytest.raises(PortableExecutionError, match="exact instance Git HEAD"):
        service.prepare(
            instance_root.name,
            "checklistdd.complete-item/v1",
            "synthetic",
            {"itemId": "first-item"},
        )


def test_nested_sandbox_uses_the_running_system_python_and_minimal_devices(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(portable_runtime, "probe_executable", lambda _name: "/usr/bin/bwrap")
    python = PortableExecutionService._sandbox_python_executable()
    assert python == Path(sys.executable).resolve(strict=True).as_posix()
    command = PortableExecutionService._bubblewrap_command(
        source_root=tmp_path / "source",
        instance_root=tmp_path / "instance",
        writable_instance=True,
        working_directory="/application",
        command=(python, "-c", "print('ok')"),
        process_generation="generation." + "a" * 64,
    )
    assert "--proc" not in command
    assert "--dev" not in command
    assert command.count("--dev-bind") == 4
    assert "/usr/local/bin:/usr/bin:/bin" in command
    assert "/usr/local/lib:/usr/lib:/usr/lib64" in command
    assert command[-3:] == (python, "-c", "print('ok')")


def test_successful_apply_binds_git_and_sandbox_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _app, instance_root, run_id = _approved_proposal(
        tmp_path, monkeypatch, "git-bound",
    )
    before_apply = service.inspect(run_id)["run"]
    assert "closureReceipt" not in before_apply
    assert "receiptId" not in before_apply
    before_git = service._git_identity(instance_root)
    assert isinstance(before_git, str)
    result = service.apply_proposal(run_id)["run"]
    assert result["baseGit"] == before_git
    assert result["receipt"]["baseGit"] == result["receipt"]["finalGit"] == before_git
    transaction = result["applyTransaction"]
    assert transaction["baseGit"] == transaction["finalGit"] == before_git
    assert transaction["enforcement"] == "sandboxed_staging_then_trusted_commit"
    assert transaction["sandbox"] == {
        "engine": "bubblewrap",
        "canonicalMount": "absent_from_untrusted_processes",
        "stagingMount": "writable_writer_read_only_validator",
        "sourceMount": "read_only",
        "network": "disabled_namespace",
        "hostHomeMount": "absent",
        "hostContainerSocket": "absent",
        "privileged": False,
    }
    assert result["applySnapshotDisposition"] == "destroyed_after_commit"
    closure = result["closureReceipt"]
    assert result["receiptId"] == closure["receiptId"]
    assert closure["formatVersion"] == "stateport.governed-run-closure-receipt/v1"
    assert closure["status"] == "applied"
    assert closure["runId"] == run_id
    assert closure["instanceId"] == instance_root.name
    assert closure["applicationId"] == result["applicationId"]
    assert closure["proposalDigest"] == result["proposalDigest"]
    assert closure["proposalApprovalDigest"] == result["proposalApproval"]["approvalDigest"]
    assert closure["runSpecDigest"] == result["runSpecDigest"]
    assert closure["baseGit"] == closure["finalGit"] == before_git
    assert closure["canonicalStateBefore"] == result["canonicalStateBefore"]
    assert closure["canonicalStateAfter"] == result["canonicalStateAfter"]
    assert closure["appliedRunBundleDigest"] == result["appliedRunBundle"]["contentDigest"]
    assert closure["validation"]["state"] == "validated"
    assert closure["claimState"] == {
        "applied": True,
        "locallyValidated": True,
        "humanAccepted": False,
        "remotelyAccepted": False,
    }
    assert any(
        event.get("type") == "lifecycle_transition"
        and event.get("toLifecycle") == "CLOSED"
        for event in result["events"]
    )
    assert service.closure_receipts(instance_root.name) == [closure]


def test_persisted_run_closure_receipt_mismatch_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _app, instance_root, run_id = _approved_proposal(
        tmp_path, monkeypatch, "closure-tamper",
    )
    result = service.apply_proposal(run_id)["run"]
    tampered = deepcopy(result["closureReceipt"])
    tampered["canonicalStateAfter"] = "sha256:" + "0" * 64
    service.store.update(
        run_id,
        closureReceipt=tampered,
        receiptId=tampered["receiptId"],
    )

    with pytest.raises(
        PortableExecutionError,
        match="does not match the governed run",
    ):
        service.closure_receipts(instance_root.name)


def test_service_restart_terminates_exact_apply_group_and_restores_fsynced_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, app, instance_root, run_id = _approved_proposal(
        tmp_path, monkeypatch, "crash-recovery",
    )
    generation = "generation." + "f" * 64
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, start_new_session=True,
        env=dict(os.environ, STATEPORT_PROCESS_GENERATION=generation),
    )
    try:
        before = _persist_applying_recovery_fixture(
            service, instance_root, run_id, process=process,
        )
        (instance_root / "state/CHECKLIST.yaml").write_text(
            "partial: crash\n", encoding="utf-8",
        )
        restarted = PortableExecutionService(app, ROOT)
        process.wait(timeout=3)
        recovered = restarted.inspect(run_id)["run"]
        assert recovered["status"] == "apply_failed"
        assert recovered["rollback"]["byteIdentical"] is True
        assert recovered["applyTransaction"]["processRecovery"] == "terminated_exact_process_group"
        assert snapshot_files(instance_root) == before
        key = recovered["applyTransaction"]["snapshotKey"]
        assert not restarted._apply_snapshot_path(key).exists()
    finally:
        if process.poll() is None:
            os.killpg(process.pid, 9)
            process.wait(timeout=3)


def test_restart_records_when_an_interrupted_apply_never_mutated_canonical_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, app, instance_root, run_id = _approved_proposal(
        tmp_path, monkeypatch, "recovery-no-mutation",
    )
    before = _persist_applying_recovery_fixture(service, instance_root, run_id)

    restarted = PortableExecutionService(app, ROOT)
    recovered = restarted.inspect(run_id)["run"]

    assert snapshot_files(instance_root) == before
    assert recovered["status"] == "apply_failed"
    assert recovered["rollback"]["canonicalMutationOccurred"] is False
    assert recovered["rollback"]["recoveryClassification"] == "same_run_no_mutation"
    assert recovered["applyTransaction"]["recoveryClassification"] == "same_run_no_mutation"

    again = PortableExecutionService(app, ROOT)
    assert snapshot_files(instance_root) == before
    assert again.inspect(run_id)["run"] == recovered


def test_restart_preserves_a_newer_sealed_apply_instead_of_restoring_a_stale_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, app, instance_root, stale_run_id = _approved_proposal(
        tmp_path, monkeypatch, "recovery-newer-apply",
    )
    _persist_applying_recovery_fixture(service, instance_root, stale_run_id)

    prepared = service.prepare(
        instance_root.name,
        "checklistdd.complete-item/v1",
        "synthetic",
        {"itemId": "first-item"},
    )
    newer_run_id = prepared["run"]["runId"]
    service.approve_run(newer_run_id)
    service.execute(newer_run_id)
    service.approve_proposal(newer_run_id)
    newer = service.apply_proposal(newer_run_id)["run"]
    newer_state = snapshot_files(instance_root)
    assert newer["lifecycleState"] == "CLOSED"

    restarted = PortableExecutionService(app, ROOT)
    recovered = restarted.inspect(stale_run_id)["run"]

    assert snapshot_files(instance_root) == newer_state
    assert recovered["status"] == "apply_failed"
    assert recovered["rollback"]["canonicalMutationOccurred"] is False
    assert recovered["rollback"]["recoveryClassification"] == "newer_sealed_apply_preserved"
    assert recovered["rollback"]["preservedRunId"] == newer_run_id
    assert recovered["canonicalStateAfter"] == newer["canonicalStateAfter"]

    again = PortableExecutionService(app, ROOT)
    assert snapshot_files(instance_root) == newer_state
    assert again.inspect(stale_run_id)["run"] == recovered


def test_apply_recovery_terminates_descendant_after_session_leader_exits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, app, instance_root, run_id = _approved_proposal(
        tmp_path, monkeypatch, "orphan-descendant",
    )
    generation = "generation." + "1" * 64
    leader = subprocess.Popen(
        [
            sys.executable, "-c",
            "import subprocess,sys; "
            "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],"
            "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
            "print(child.pid,flush=True); sys.stdin.buffer.read(1)",
        ],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, start_new_session=True,
        env=dict(os.environ, STATEPORT_PROCESS_GENERATION=generation),
    )
    assert leader.stdin is not None and leader.stdout is not None
    child_pid = int(leader.stdout.readline().strip())
    try:
        before = _persist_applying_recovery_fixture(
            service, instance_root, run_id, process=leader,
        )
        (instance_root / "state/CHECKLIST.yaml").write_text(
            "partial: crash\n", encoding="utf-8",
        )
        leader.stdin.write("x")
        leader.stdin.flush()
        leader.wait(timeout=3)
        assert Path(f"/proc/{child_pid}").exists()

        restarted = PortableExecutionService(app, ROOT)

        recovered = restarted.inspect(run_id)["run"]
        assert recovered["status"] == "apply_failed"
        assert recovered["rollback"]["byteIdentical"] is True
        assert recovered["applyTransaction"]["processRecovery"] == (
            "terminated_exact_process_group"
        )
        assert snapshot_files(instance_root) == before
        assert not Path(f"/proc/{child_pid}").exists()
    finally:
        if leader.poll() is None:
            os.killpg(leader.pid, 9)
            leader.wait(timeout=3)
        try:
            os.kill(child_pid, 9)
        except ProcessLookupError:
            pass


def test_apply_recovery_terminates_generation_bound_descendant_in_new_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, app, instance_root, run_id = _approved_proposal(
        tmp_path, monkeypatch, "detached-descendant",
    )
    generation = "generation." + "2" * 64
    leader = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import subprocess,sys,time; "
            "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],"
            "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,"
            "start_new_session=True); print(child.pid,flush=True); time.sleep(.5)",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        start_new_session=True,
        env=dict(os.environ, STATEPORT_PROCESS_GENERATION=generation),
    )
    assert leader.stdout is not None
    child_pid = int(leader.stdout.readline().strip())
    try:
        before = _persist_applying_recovery_fixture(
            service, instance_root, run_id, process=leader,
        )
        (instance_root / "state/CHECKLIST.yaml").write_text(
            "partial: detached crash\n", encoding="utf-8",
        )
        leader.wait(timeout=3)
        assert Path(f"/proc/{child_pid}").exists()
        assert service._process_generation(child_pid) == generation

        restarted = PortableExecutionService(app, ROOT)

        recovered = restarted.inspect(run_id)["run"]
        assert recovered["status"] == "apply_failed"
        assert recovered["rollback"]["byteIdentical"] is True
        assert snapshot_files(instance_root) == before
        deadline = time.monotonic() + 2
        while Path(f"/proc/{child_pid}").exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert not Path(f"/proc/{child_pid}").exists()
    finally:
        if leader.poll() is None:
            os.killpg(leader.pid, 9)
            leader.wait(timeout=3)
        try:
            os.kill(child_pid, 9)
        except ProcessLookupError:
            pass


def test_restart_without_a_durable_apply_snapshot_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, app, instance_root, run_id = _approved_proposal(
        tmp_path, monkeypatch, "missing-snapshot",
    )
    before = _persist_applying_recovery_fixture(service, instance_root, run_id)
    record = service.store.get(run_id)
    assert record is not None
    key = record["applyTransaction"]["snapshotKey"]
    service._discard_apply_snapshot(key)
    (instance_root / "state/CHECKLIST.yaml").write_text(
        "unknown: partial\n", encoding="utf-8",
    )
    restarted = PortableExecutionService(app, ROOT)
    recovered = restarted.inspect(run_id)["run"]
    assert recovered["status"] == "interrupted"
    assert recovered["rollback"] == {
        "status": "unknown", "byteIdentical": False,
        "operatorInspectionRequired": True,
    }
    assert snapshot_files(instance_root) != before
    with pytest.raises(PortableExecutionError, match="remains quarantined"):
        restarted.prepare(
            instance_root.name,
            "checklistdd.complete-item/v1",
            "synthetic",
            {"itemId": "first-item"},
        )


def test_quarantine_blocks_an_already_approved_apply_under_the_writer_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, app, instance_root, broken_run = _approved_proposal(
        tmp_path, monkeypatch, "quarantine-write",
    )
    prepared = service.prepare(
        instance_root.name,
        "checklistdd.complete-item/v1",
        "synthetic",
        {"itemId": "first-item"},
    )
    approved_run = prepared["run"]["runId"]
    service.approve_run(approved_run)
    service.execute(approved_run)
    service.approve_proposal(approved_run)
    _persist_applying_recovery_fixture(service, instance_root, broken_run)
    service.store.update(
        broken_run,
        applyProcess={
            "phase": "writer",
            "state": "active",
            "pid": 2,
            "processGroupId": 3,
            "startTimeTicks": "1",
            "processGeneration": "generation." + "a" * 64,
        },
    )
    restarted = PortableExecutionService(app, ROOT)
    assert restarted._instance_requires_operator_recovery(instance_root.name)

    with pytest.raises(PortableExecutionError, match="remains quarantined"):
        restarted.apply_proposal(approved_run)

    assert restarted.store.get(approved_run)["status"] == "state_change_approved"


def test_unresolved_apply_snapshot_survives_repeated_service_restarts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, app, instance_root, run_id = _approved_proposal(
        tmp_path, monkeypatch, "snapshot-retention",
    )
    _persist_applying_recovery_fixture(service, instance_root, run_id)
    record = service.store.get(run_id)
    assert record is not None
    key = record["applyTransaction"]["snapshotKey"]
    snapshot_path = service._apply_snapshot_path(key)
    service.store.update(
        run_id,
        applyProcess={
            "phase": "writer",
            "state": "active",
            "pid": 2,
            "processGroupId": 3,
            "startTimeTicks": "1",
            "processGeneration": "generation." + "b" * 64,
        },
    )

    first = PortableExecutionService(app, ROOT)
    assert first.store.get(run_id)["status"] == "interrupted"
    assert snapshot_path.exists()

    second = PortableExecutionService(app, ROOT)
    assert second.store.get(run_id)["status"] == "interrupted"
    assert snapshot_path.exists()
    assert second._instance_requires_operator_recovery(instance_root.name)


def test_apply_rejects_full_snapshot_drift_without_overwriting_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _app, instance_root, run_id = _approved_proposal(tmp_path, monkeypatch, "drift")
    checklist_before = (instance_root / "state/CHECKLIST.yaml").read_bytes()
    unrelated = instance_root / "operator-note.txt"
    unrelated.write_text("preserve this unrelated change\n", encoding="utf-8")

    with pytest.raises(PortableExecutionError, match="canonical state changed"):
        service.apply_proposal(run_id)

    assert unrelated.read_text(encoding="utf-8") == "preserve this unrelated change\n"
    assert (instance_root / "state/CHECKLIST.yaml").read_bytes() == checklist_before
    assert service.inspect(run_id)["run"]["status"] == "failed"


@pytest.mark.parametrize("proposal_failure", ("multiple", "undeclared_path"))
def test_execute_rejects_ambiguous_or_unauthorized_proposals(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    proposal_failure: str,
) -> None:
    service, app, instance_root = _service(tmp_path, monkeypatch, proposal_failure)
    instance_id = instance_root.name
    prepared = service.prepare(
        instance_id,
        "checklistdd.complete-item/v1",
        "synthetic",
        {"itemId": "first-item"},
    )
    run_id = prepared["run"]["runId"]
    service.approve_run(run_id)
    before = snapshot_files(instance_root)
    real_execute = service._execute_in_staging

    def altered_result(*args, **kwargs):
        result, events, process = real_execute(*args, **kwargs)
        result = deepcopy(result)
        if proposal_failure == "multiple":
            result["stateChangeProposals"].append(deepcopy(result["stateChangeProposals"][0]))
        else:
            result["stateChangeProposals"][0]["operation"]["path"] = "state/UNDECLARED.yaml"
        return result, events, process

    monkeypatch.setattr(service, "_execute_in_staging", altered_result)
    with pytest.raises(PortableExecutionError):
        service.execute(run_id)
    assert snapshot_files(instance_root) == before
    assert service.inspect(run_id)["run"]["status"] == "result_rejected"


def test_apply_rechecks_the_action_contract_and_source_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _app, instance_root, run_id = _approved_proposal(tmp_path, monkeypatch, "identity")
    before = snapshot_files(instance_root)
    monkeypatch.setattr(service, "_actions", lambda _instance_id: {})
    with pytest.raises(PortableExecutionError, match="action contract drifted"):
        service.apply_proposal(run_id)
    assert snapshot_files(instance_root) == before
    assert service.inspect(run_id)["run"]["status"] == "state_change_approved"
