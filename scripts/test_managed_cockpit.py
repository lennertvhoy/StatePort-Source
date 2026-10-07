#!/usr/bin/env python3
"""Public-safe adversarial proof for the managed deterministic fake path."""

from __future__ import annotations

import copy
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import threading
import time

import pytest

ROOT = Path(__file__).resolve().parents[1]
for relative in (
    "packages/runtime-contracts/src",
    "packages/execution-host/src",
    "packages/external-engine-runtime/src",
    "packages/governed-runner/src",
    "packages/run-bundle/src",
):
    sys.path.insert(0, str(ROOT / relative))

import test_agent_native_cockpit as native  # noqa: E402

from execution_host.contracts import AgentRunSpec  # noqa: E402
from governed_runner import (  # noqa: E402
    AgentNativeCockpit,
    AssistedCockpit,
    CockpitError,
    CockpitStateError,
    DeterministicFakeBackend,
    FakeBackendScenario,
    ManagedCockpit,
    OperationalEvidenceStore,
)
from run_bundle import RunBundleError  # noqa: E402
from runtime_contracts import RuntimeProfile, TaskManifest, WorkflowDeclaration  # noqa: E402


EXTERNAL_AGENT = {"id": "human.terra", "classification": "human_controlled"}


def mode_contracts(sha: str, mode: str, *, time_seconds: int = 5):
    workflow, task, runtime, context, agent, spec = native.contracts(sha)
    workflow_data = workflow.to_dict()
    workflow_data["execution"] = {
        "supportedModes": ["agent_native", "assisted", "managed"],
        "defaultMode": "agent_native",
    }
    task_data = task.to_dict()
    task_data["requestedMode"] = mode
    task_data["budgets"]["timeSeconds"] = time_seconds
    runtime_data = runtime.to_dict()
    runtime_data["mode"] = mode
    runtime_data["budgets"]["timeSeconds"] = time_seconds
    spec_data = spec.to_dict()
    spec_data["budgets"]["timeSeconds"] = time_seconds
    spec_data["benchmarkConfiguration"] = {"mode": mode}
    if mode == "managed":
        runtime_data.update(
            {
                "runtimeId": "runtime.managed-fake",
                "harness": {"id": "stateport-managed", "version": "1"},
                "adapter": {"id": "deterministic-fake", "version": "1.0.0"},
                "provider": {"id": "managed-fake", "model": "deterministic.no-model"},
                "reasoning": {"classification": "deterministic"},
                "authentication": {"classification": "not_applicable", "owner": "none"},
                "sandbox": {"profile": "staging_copy_only", "filesystem": "unproven"},
                "network": {"policy": "unproven", "allowlist": []},
                "environmentAllowlist": ["PATH", "LANG"],
                "resume": {"supported": True, "strategy": "best_effort"},
                "capabilityRequirements": {
                    "structuredEvents": "supported",
                    "nonInteractiveExecution": "supported",
                    "cancellation": "supported",
                    "sessionResume": "supported",
                    "changedFileReporting": "supported",
                },
                "degradations": [
                    "container_isolation_unproven",
                    "network_isolation_unproven",
                ],
            }
        )
        spec_data["backend"] = {
            "id": "managed-fake",
            "adapter": {"id": "deterministic-fake", "version": "1.0.0"},
        }
        spec_data["model"] = "deterministic.no-model"
        spec_data["authenticationRouteClass"] = "not_applicable"
        spec_data["sandbox"] = {"profile": "staging_copy_only"}
        spec_data["capabilities"] = {
            "required": [
                {"id": name, "allowPartial": False}
                for name in (
                    "structuredEvents",
                    "nonInteractiveExecution",
                    "cancellation",
                    "sessionResume",
                    "changedFileReporting",
                )
            ],
            "optional": [],
        }
    return (
        WorkflowDeclaration.from_dict(workflow_data),
        TaskManifest.from_dict(task_data),
        RuntimeProfile.from_dict(runtime_data),
        context,
        agent,
        AgentRunSpec.from_dict(spec_data),
    )


def managed_contracts(sha: str, *, time_seconds: int = 5):
    return mode_contracts(sha, "managed", time_seconds=time_seconds)


def blocking_gate_contracts(items, phase: str):
    """Replace one declared gate with a long-running public-safe command."""

    command = [sys.executable, "-c", "import time; time.sleep(30)"]
    workflow, task, runtime, context, agent, spec = items
    workflow_data = workflow.to_dict()
    task_data = task.to_dict()
    spec_data = spec.to_dict()
    if phase == "preflight":
        workflow_data["preflight"].update(
            {"command": command, "timeoutSeconds": 30}
        )
        task_data["preflight"].update(
            {"command": command, "timeoutSeconds": 30}
        )
    elif phase == "verification":
        workflow_data["verify"].update(
            {"command": command, "timeoutSeconds": 30}
        )
        task_data["verification"].update(
            {"command": command, "timeoutSeconds": 30}
        )
        spec_data["validationCommands"] = command
    else:  # pragma: no cover - test helper contract
        raise ValueError("unknown gate phase")
    return (
        WorkflowDeclaration.from_dict(workflow_data),
        TaskManifest.from_dict(task_data),
        runtime,
        context,
        agent,
        AgentRunSpec.from_dict(spec_data),
    )


def cockpit(
    root: Path, scenario: FakeBackendScenario | None = None, *, max_events: int = 512
) -> ManagedCockpit:
    return ManagedCockpit(
        OperationalEvidenceStore(root / "evidence.sqlite", max_events=max_events),
        root / "leases",
        backend=DeterministicFakeBackend(scenario),
        bundle_directory=root / "bundles",
        owner="test-managed",
    )


def prepare(service: ManagedCockpit, items, canonical: Path, staging: Path):
    return service.prepare(
        *items,
        instance_root=canonical,
        staging_root=staging,
        **native.identity_kwargs(),
    )


def _wait_for_pid_to_disappear(pid: int) -> None:
    for _ in range(100):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.01)
    raise AssertionError(f"child process {pid} was not reaped")


def _child_pid(service: ManagedCockpit, run_id: str) -> int:
    journal = service.evidence_store.journal(native.evidence_attempt_id(run_id))
    events = [item for item in journal if item["payload"]["attributes"].get("childPid")]
    assert events
    return int(events[-1]["payload"]["attributes"]["childPid"])


def _bundle_result(root: Path) -> dict[str, object]:
    bundles = list((root / "bundles").iterdir())
    assert len(bundles) == 1
    return json.loads(
        (bundles[0] / "execution/run-result.json").read_text(encoding="utf-8")
    )


def test_managed_success_uses_bounded_redacted_journal_isolated_home_and_common_closure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = FakeBackendScenario(
        event_summary="Bearer public-fixture-value-123456",
        event_attributes={"access_token": "public-fixture-token-value"},
        adapter_metadata={"authorization": "Bearer public-fixture-value-123456"},
    )
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        canonical, staging, sha = native.repository(root)
        items = managed_contracts(sha)
        monkeypatch.setenv(
            "STATEPORT_TEST_SECRET", "must-not-enter-managed-environment"
        )
        service = cockpit(root, scenario)
        job = prepare(service, items, canonical, staging)
        assert (
            service.capabilities().test_only
            and not service.capabilities().production_eligible
        )
        assert service.health().to_dict()["status"] == "healthy"
        outcome = service.start(items[-1].run_id)
        assert (
            outcome.status == "completed"
            and outcome.process
            and outcome.process["cleanup"] == "not_required"
        )
        verified = service.verify(items[-1].run_id)
        assert verified.state == "verified"
        receipt = service.close_managed(items[-1].run_id)
        assert receipt.to_dict()["mode"] == "managed"
        assert receipt.to_dict()["closure"] == {
            "status": "closed",
            "reason": "verified_no_canonical_mutation",
        }
        assert receipt.to_dict()["usage"] == {
            "availability": "unavailable",
            "token": None,
            "costMinor": None,
        }
        assert not job.lease.acquired and not list(staging.glob(".stateport-managed-*"))
        process_rows = service.evidence_store.supervised_processes()
        assert all(item["state"] == "reaped" for item in process_rows)
        assert {item["phase"] for item in process_rows} == {
            "preflight", "backend", "verification",
        }
        assert (canonical / "owned.txt").read_text(encoding="utf-8") == "base\n"

        journal = service.evidence_store.journal(
            native.evidence_attempt_id(items[-1].run_id)
        )
        delta = next(item for item in journal if item["eventType"] == "message.delta")
        assert "[REDACTED]" in delta["payload"]["summary"]
        assert "access_token" not in delta["payload"]["attributes"]
        assert delta["redactionResult"]["status"] == "applied"
        assert (
            "STATEPORT_TEST_SECRET"
            not in delta["payload"]["attributes"]["environmentKeys"]
        )
        assert "HOME" in delta["payload"]["attributes"]["environmentKeys"]
        metadata = service.evidence_store.adapter_metadata(delta["eventId"])
        assert metadata == {"backendId": "managed-fake", "testOnly": True}

        run_result = _bundle_result(root)
        assert run_result["terminationClassification"] == "success"
        assert run_result["failureClassification"] is None
        sandbox = run_result["sandbox"]
        assert sandbox["executionBoundary"] == "staging_copy_only"
        assert sandbox["containerEnforced"] is False
        assert sandbox["networkIsolation"] == "unproven"
        assert sandbox["canonicalAccessIsolation"] == "unproven"
        encoded = json.dumps({"receipt": receipt.to_dict(), "runResult": run_result})
        assert "providerSession" not in encoded and "threadId" not in encoded


def test_managed_timeout_reaps_child_and_closes_with_honest_terminal_outcome() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        canonical, staging, sha = native.repository(root)
        items = managed_contracts(sha, time_seconds=1)
        service = cockpit(root, FakeBackendScenario(delay_seconds=5, spawn_child=True))
        job = prepare(service, items, canonical, staging)
        outcome = service.start(items[-1].run_id)
        assert outcome.status == "timed_out" and outcome.process
        assert outcome.process["cleanup"] in {"terminated", "killed", "already_exited"}
        _wait_for_pid_to_disappear(_child_pid(service, items[-1].run_id))
        receipt = service.close_managed(items[-1].run_id)
        attempt = service.evidence_store.get_attempt(
            native.evidence_attempt_id(items[-1].run_id)
        )
        assert receipt.to_dict()["closure"] == {
            "status": "failed",
            "reason": "runtime_timeout",
        }
        assert attempt["classification"] == "timed_out"
        assert _bundle_result(root)["terminationClassification"] == "timeout"
        assert (
            service.evidence_store.journal(
                native.evidence_attempt_id(items[-1].run_id)
            )[-1]["eventType"]
            == "run.failed"
        )
        assert not job.lease.acquired


@pytest.mark.skipif(not hasattr(os, "fork"), reason="crash recovery proof requires POSIX fork")
def test_restart_reaps_crash_abandoned_process_and_terminalizes_attempt() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        canonical, staging, sha = native.repository(root)
        items = managed_contracts(sha, time_seconds=30)
        run_id = items[-1].run_id
        child = os.fork()
        if child == 0:  # pragma: no cover - the parent asserts durable effects
            try:
                service = cockpit(root, FakeBackendScenario(delay_seconds=30))
                prepare(service, items, canonical, staging)
                service.start(run_id)
            finally:
                os._exit(0)
        try:
            store = OperationalEvidenceStore(root / "evidence.sqlite")
            # Generous poll window: under a fully loaded suite the forked
            # child may wait seconds for a scheduler slot before it can
            # persist. Assertions are unchanged — this only avoids load flakes.
            for _ in range(3000):
                try:
                    processes = store.supervised_processes()
                except Exception:
                    processes = ()
                if any(
                    item["phase"] == "backend" and item["state"] == "active"
                    for item in processes
                ):
                    break
                time.sleep(0.01)
            else:
                raise AssertionError("managed child did not persist its gated process identity")
            os.kill(child, 9)
            os.waitpid(child, 0)
            child = -1

            restarted = cockpit(root)
            assert len(restarted.recovered_attempts) == 1
            recovery = restarted.recovered_attempts[0]
            assert recovery["runId"] == run_id
            assert recovery["classification"] == "interrupted"
            attempt = restarted.evidence_store.get_attempt(
                native.evidence_attempt_id(run_id)
            )
            assert attempt["state"] == "terminal"
            assert attempt["classification"] == "interrupted"
            assert attempt["receipt"]["closure"] == {
                "status": "failed",
                "reason": "supervisor_lost_during_backend",
            }
            assert attempt["receipt"]["first"]["status"] == "failed"
            assert attempt["receipt"]["eventual"]["status"] == "failed"
            backend_process = next(
                item for item in restarted.evidence_store.supervised_processes()
                if item["phase"] == "backend"
            )
            assert backend_process["state"] in {"orphan_terminated", "not_found"}
            assert restarted.evidence_store.managed_recovery_candidates() == ()
        finally:
            if child > 0:
                try:
                    os.kill(child, 9)
                except ProcessLookupError:
                    pass
                os.waitpid(child, 0)


@pytest.mark.skipif(not hasattr(os, "fork"), reason="crash recovery proof requires POSIX fork")
def test_unbound_crash_descendant_quarantines_instance_and_blocks_new_lease() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        canonical, staging, sha = native.repository(root)
        items = managed_contracts(sha, time_seconds=30)
        run_id = items[-1].run_id
        supervisor = os.fork()
        if supervisor == 0:  # pragma: no cover - parent asserts durable effects
            try:
                service = cockpit(
                    root,
                    FakeBackendScenario(
                        delay_seconds=30,
                        spawn_child=True,
                        child_inherits_generation=False,
                    ),
                )
                prepare(service, items, canonical, staging)
                service.start(run_id)
            finally:
                os._exit(0)
        child_pid = process_group = -1
        try:
            store = OperationalEvidenceStore(root / "evidence.sqlite")
            # Generous poll window: under a fully loaded suite the forked
            # child may wait seconds for a scheduler slot before it can
            # persist. Assertions are unchanged — this only avoids load flakes.
            for _ in range(3000):
                try:
                    backend = next(
                        item for item in store.supervised_processes()
                        if item["phase"] == "backend" and item["state"] == "active"
                    )
                    members = store._exact_session_members(
                        int(backend["processGroupId"]), int(backend["pid"]),
                    )
                    child_members = [
                        member for member in (members or ())
                        if member[0] != int(backend["pid"])
                    ]
                except Exception:
                    backend, child_members = None, []
                if backend is not None and child_members:
                    process_group = int(backend["processGroupId"])
                    child_pid = int(child_members[-1][0])
                    break
                time.sleep(0.01)
            else:
                raise AssertionError("unbound managed descendant was not observed")

            os.kill(supervisor, 9)
            os.waitpid(supervisor, 0)
            supervisor = -1
            restarted = cockpit(root)

            backend_row = next(
                item for item in restarted.evidence_store.supervised_processes()
                if item["phase"] == "backend"
            )
            assert backend_row["state"] == "cleanup_failed"
            blockers = restarted.evidence_store.managed_instance_blockers(canonical)
            assert len(blockers) == 1
            assert blockers[0]["runId"] == run_id
            assert "cleanup_failed" in blockers[0]["processStates"]
            assert Path(f"/proc/{child_pid}").exists()
            with pytest.raises(CockpitStateError, match="remains quarantined"):
                prepare(restarted, items, canonical, staging)
        finally:
            if supervisor > 0:
                try:
                    os.kill(supervisor, 9)
                except ProcessLookupError:
                    pass
                os.waitpid(supervisor, 0)
            if process_group > 1:
                try:
                    os.killpg(process_group, 9)
                except ProcessLookupError:
                    pass
            if child_pid > 1:
                _wait_for_pid_to_disappear(child_pid)


@pytest.mark.skipif(not hasattr(os, "fork"), reason="crash recovery proof requires POSIX fork")
@pytest.mark.parametrize("phase", ["preflight", "verification"])
def test_restart_reaps_crash_abandoned_gate_and_terminalizes_attempt(
    phase: str,
) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        canonical, staging, sha = native.repository(root)
        items = blocking_gate_contracts(
            managed_contracts(sha, time_seconds=30), phase,
        )
        run_id = items[-1].run_id
        supervisor = os.fork()
        if supervisor == 0:  # pragma: no cover - parent asserts durable facts
            try:
                service = cockpit(root)
                prepare(service, items, canonical, staging)
                if phase == "verification":
                    service.start(run_id)
                    service.verify(run_id)
            finally:
                os._exit(0)
        gate_pid = -1
        try:
            store = OperationalEvidenceStore(root / "evidence.sqlite")
            # Generous poll window: under a fully loaded suite the forked
            # child may wait seconds for a scheduler slot before it can
            # persist. Assertions are unchanged — this only avoids load flakes.
            for _ in range(3000):
                try:
                    active = next(
                        item for item in store.supervised_processes()
                        if item["phase"] == phase and item["state"] == "active"
                    )
                except Exception:
                    active = None
                if active is not None:
                    gate_pid = int(active["pid"])
                    break
                time.sleep(0.01)
            else:
                raise AssertionError(
                    f"managed {phase} did not persist its gated process identity"
                )
            os.kill(supervisor, 9)
            os.waitpid(supervisor, 0)
            supervisor = -1

            restarted = cockpit(root)
            assert len(restarted.recovered_attempts) == 1
            recovery = restarted.recovered_attempts[0]
            assert recovery["runId"] == run_id
            assert phase in recovery["processPhases"]
            attempt = restarted.evidence_store.get_attempt(
                native.evidence_attempt_id(run_id)
            )
            assert attempt["state"] == "terminal"
            assert attempt["classification"] == "interrupted"
            assert attempt["receipt"]["closure"] == {
                "status": "failed",
                "reason": f"supervisor_lost_during_{phase}",
            }
            process = next(
                item for item in restarted.evidence_store.supervised_processes()
                if item["phase"] == phase
            )
            assert process["state"] in {"orphan_terminated", "not_found"}
            _wait_for_pid_to_disappear(gate_pid)
            assert restarted.evidence_store.managed_recovery_candidates() == ()
        finally:
            if supervisor > 0:
                try:
                    os.kill(supervisor, 9)
                except ProcessLookupError:
                    pass
                os.waitpid(supervisor, 0)


def test_managed_cancellation_reaps_process_group_and_is_idempotently_observable() -> (
    None
):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        canonical, staging, sha = native.repository(root)
        items = managed_contracts(sha, time_seconds=10)
        service = cockpit(root, FakeBackendScenario(delay_seconds=10, spawn_child=True))
        job = prepare(service, items, canonical, staging)
        captured: dict[str, object] = {}

        def run() -> None:
            captured["outcome"] = service.start(items[-1].run_id)

        thread = threading.Thread(target=run)
        thread.start()
        for _ in range(200):
            if service.health().active_runs == 1:
                break
            time.sleep(0.01)
        else:
            raise AssertionError("managed fake process did not become active")
        # Let the deterministic fixture emit its child observation before the
        # cancellation signal so the reaping assertion has an observed PID.
        time.sleep(0.1)
        cancellation = service.cancel(items[-1].run_id)
        assert cancellation.status == "cancellation_requested"
        thread.join(timeout=5)
        assert not thread.is_alive()
        outcome = captured["outcome"]
        assert getattr(outcome, "status") == "cancelled"
        assert service.health().active_runs == 0
        _wait_for_pid_to_disappear(_child_pid(service, items[-1].run_id))
        receipt = service.close_managed(items[-1].run_id)
        attempt = service.evidence_store.get_attempt(
            native.evidence_attempt_id(items[-1].run_id)
        )
        assert receipt.to_dict()["closure"] == {
            "status": "failed",
            "reason": "runtime_cancelled",
        }
        assert attempt["classification"] == "cancelled"
        assert _bundle_result(root)["terminationClassification"] == "cancelled"
        assert (
            service.evidence_store.journal(
                native.evidence_attempt_id(items[-1].run_id)
            )[-1]["eventType"]
            == "run.cancelled"
        )
        assert not job.lease.acquired


def test_managed_resume_is_explicit_snapshot_bound_and_never_an_automatic_retry() -> (
    None
):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        canonical, staging, sha = native.repository(root)
        items = managed_contracts(sha)
        service = cockpit(
            root,
            FakeBackendScenario(start_status="interrupted", resume_status="completed"),
        )
        prepare(service, items, canonical, staging)
        first = service.start(items[-1].run_id)
        assert first.status == "interrupted"
        with pytest.raises(CockpitStateError, match="explicit resume or cancel"):
            service.close_managed(items[-1].run_id)
        resumed = service.resume(items[-1].run_id)
        assert resumed.status == "completed"
        service.verify(items[-1].run_id)
        receipt = service.close_managed(items[-1].run_id)
        assert receipt.to_dict()["closure"]["status"] == "closed"
        assert receipt.to_dict()["first"]["status"] == "failed"
        assert receipt.to_dict()["eventual"]["status"] == "passed"
        bundle_root = next((root / "bundles").iterdir())
        operations = json.loads(
            (bundle_root / "execution/managed-operations.json").read_text(
                encoding="utf-8"
            )
        )
        assert [item["operation"] for item in operations] == ["start", "resume"]

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        canonical, staging, sha = native.repository(root)
        items = managed_contracts(sha)
        service = cockpit(
            root,
            FakeBackendScenario(start_status="interrupted", resume_status="completed"),
        )
        prepare(service, items, canonical, staging)
        service.start(items[-1].run_id)
        (staging / "owned.txt").write_text("snapshot drift\n", encoding="utf-8")
        drift = service.resume(items[-1].run_id)
        assert (
            drift.status == "failed"
            and drift.failure_classification == "snapshot_drift_before_resume"
        )
        receipt = service.close_managed(items[-1].run_id)
        assert receipt.to_dict()["closure"]["status"] == "failed"
        assert receipt.to_dict()["fileChanges"]["changedPaths"] == ["owned.txt"]


def test_managed_staging_diff_uses_existing_report_and_stop_proposal_boundary_only() -> (
    None
):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        canonical, staging, sha = native.repository(root)
        items = managed_contracts(sha)
        service = cockpit(
            root,
            FakeBackendScenario(
                write_path="owned.txt", write_content="proposal only\n"
            ),
        )
        prepare(service, items, canonical, staging)
        assert service.start(items[-1].run_id).status == "completed"
        job = service.verify(items[-1].run_id)
        assert job.report_and_stop and job.report_reason == "pending_governed_proposal"
        assert job.pending_proposal and job.pending_proposal.to_dict()[
            "changedPaths"
        ] == ["owned.txt"]
        receipt = service.close_managed(items[-1].run_id)
        assert receipt.to_dict()["closure"] == {
            "status": "failed",
            "reason": "pending_governed_proposal",
        }
        assert (canonical / "owned.txt").read_text(encoding="utf-8") == "base\n"


def test_managed_start_rejects_drift_and_fake_writes_never_follow_symlinks() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        canonical, staging, sha = native.repository(root)
        items = managed_contracts(sha)
        service = cockpit(root)
        prepare(service, items, canonical, staging)
        (staging / "unowned.txt").write_text("drift\n", encoding="utf-8")
        outcome = service.start(items[-1].run_id)
        assert outcome.failure_classification == "snapshot_drift_before_start"
        receipt = service.close_managed(items[-1].run_id)
        assert receipt.to_dict()["fileChanges"]["changedPaths"] == ["unowned.txt"]
        assert receipt.to_dict()["fileChanges"]["allowed"] is False

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        canonical, staging, sha = native.repository(root)
        outside = root / "outside.txt"
        outside.write_text("preserve\n", encoding="utf-8")
        (canonical / "link.txt").symlink_to(outside)
        native.git(canonical, "add", "link.txt")
        native.git(canonical, "commit", "-qm", "tracked symlink")
        sha = native.git(canonical, "rev-parse", "HEAD")
        shutil.rmtree(staging)
        shutil.copytree(canonical, staging, symlinks=True)
        items = managed_contracts(sha)
        service = cockpit(root, FakeBackendScenario(write_path="link.txt"))
        prepare(service, items, canonical, staging)
        outcome = service.start(items[-1].run_id)
        assert outcome.status == "failed"
        assert outside.read_text(encoding="utf-8") == "preserve\n"
        service.close_managed(items[-1].run_id)


def test_managed_bundle_output_cannot_mutate_a_workspace() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        canonical, staging, sha = native.repository(root)
        items = managed_contracts(sha)
        service = ManagedCockpit(
            OperationalEvidenceStore(root / "evidence.sqlite"),
            root / "leases",
            backend=DeterministicFakeBackend(),
            bundle_directory=canonical / "bundles",
        )
        with pytest.raises(CockpitError, match="canonical workspace"):
            prepare(service, items, canonical, staging)
        assert not (canonical / "bundles").exists()


def test_managed_bundle_creation_failure_releases_the_writer_lease() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        canonical, staging, sha = native.repository(root)
        items = managed_contracts(sha)
        service = cockpit(root)
        job = prepare(service, items, canonical, staging)
        assert service.start(items[-1].run_id).status == "completed"
        assert service.verify(items[-1].run_id).state == "verified"
        destination = root / "bundles" / (
            "managed-" + sha256(items[-1].run_id.encode("utf-8")).hexdigest()
        )
        destination.mkdir()
        with pytest.raises(RunBundleError, match="immutable"):
            service.close_managed(items[-1].run_id)
        assert not job.lease.acquired


def test_managed_fails_closed_on_false_isolation_auth_and_capability_combinations() -> (
    None
):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        canonical, staging, sha = native.repository(root)
        items = list(managed_contracts(sha))
        runtime = items[2].to_dict()
        runtime["network"] = {"policy": "disabled", "allowlist": []}
        items[2] = RuntimeProfile.from_dict(runtime)
        with pytest.raises(CockpitError, match="network isolation as unproven"):
            prepare(cockpit(root), items, canonical, staging)

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        canonical, staging, sha = native.repository(root)
        items = list(managed_contracts(sha))
        runtime = items[2].to_dict()
        runtime["authentication"] = {
            "classification": "operator_authenticated",
            "owner": "operator",
        }
        items[2] = RuntimeProfile.from_dict(runtime)
        with pytest.raises(CockpitError, match="authentication"):
            prepare(cockpit(root), items, canonical, staging)

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        canonical, staging, sha = native.repository(root)
        items = list(managed_contracts(sha))
        runtime = items[2].to_dict()
        runtime["capabilityRequirements"]["sandboxSupport"] = "supported"
        items[2] = RuntimeProfile.from_dict(runtime)
        spec = items[-1].to_dict()
        spec["capabilities"]["required"].append(
            {"id": "sandboxSupport", "allowPartial": False}
        )
        items[-1] = AgentRunSpec.from_dict(spec)
        with pytest.raises(CockpitError, match="capability"):
            prepare(cockpit(root), items, canonical, staging)


def test_managed_journal_bound_fails_closed_without_leaking_a_process() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        canonical, staging, sha = native.repository(root)
        items = managed_contracts(sha)
        service = cockpit(root, max_events=3)
        job = prepare(service, items, canonical, staging)
        outcome = service.start(items[-1].run_id)
        assert outcome.status == "failed"
        assert service.health().active_runs == 0
        assert (
            len(
                service.evidence_store.journal(
                    native.evidence_attempt_id(items[-1].run_id)
                )
            )
            <= 3
        )
        with pytest.raises(Exception):
            service.close_managed(items[-1].run_id)
        assert not job.lease.acquired


def _receipt_shape(value: object) -> object:
    if isinstance(value, dict):
        return {key: _receipt_shape(item) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return ["list"] if value else []
    return type(value).__name__


def _normalize_mode_receipt(receipt: dict[str, object]) -> dict[str, object]:
    normalized = copy.deepcopy(receipt)
    normalized["mode"] = "mode-normalized"
    normalized["runtimeIdentity"] = "mode-normalized"
    digests = normalized["digests"]
    assert isinstance(digests, dict)
    for key in ("taskManifest", "runtimeProfile", "agentRunSpec", "eventJournal"):
        digests[key] = "mode-normalized"
    normalized["references"] = {
        "runResult": {"id": "mode-normalized", "digest": "mode-normalized"},
        "runBundle": {"id": "mode-normalized", "digest": "mode-normalized"},
    }
    journal = normalized["journal"]
    assert isinstance(journal, dict)
    journal.update({"eventCount": 0, "digest": "mode-normalized"})
    return normalized


def test_public_safe_three_mode_parity_uses_one_logical_fixture_and_receipt_contract() -> (
    None
):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "base").mkdir()
        base_canonical, base_staging, sha = native.repository(root / "base")
        receipts: dict[str, dict[str, object]] = {}
        logical_tasks: set[str] = set()
        context_digests: set[str] = set()
        agent_digests: set[str] = set()
        workflow_digests: set[str] = set()
        for mode in ("agent_native", "assisted", "managed"):
            mode_root = root / mode
            mode_root.mkdir()
            canonical, staging = mode_root / "canonical", mode_root / "staging"
            shutil.copytree(base_canonical, canonical, symlinks=True)
            shutil.copytree(base_staging, staging, symlinks=True)
            items = mode_contracts(sha, mode)
            logical_task = items[1].to_dict()
            logical_task.pop("requestedMode")
            logical_tasks.add(json.dumps(logical_task, sort_keys=True))
            workflow_digests.add(items[0].digest)
            context_digests.add(items[3].digest)
            agent_digests.add(items[4].digest)
            if mode == "agent_native":
                service = AgentNativeCockpit(
                    OperationalEvidenceStore(mode_root / "evidence.sqlite"),
                    mode_root / "leases",
                )
                service.prepare(
                    *items,
                    instance_root=canonical,
                    staging_root=staging,
                    **native.identity_kwargs(),
                )
                service.adopt(items[-1].run_id, items[-1])
                service.verify(items[-1].run_id)
                receipt = service.close(
                    items[-1].run_id,
                    run_result=native.result(items[-1]),
                    run_result_id="result.cockpit",
                    run_bundle=native.bundle(mode_root, items[-1]),
                )
            elif mode == "assisted":
                service = AssistedCockpit(
                    OperationalEvidenceStore(mode_root / "evidence.sqlite"),
                    mode_root / "leases",
                )
                job = service.prepare(
                    *items,
                    instance_root=canonical,
                    staging_root=staging,
                    external_agent=EXTERNAL_AGENT,
                    **native.identity_kwargs(),
                )
                assert job.assisted_handoff
                service.adopt(
                    items[-1].run_id,
                    items[-1],
                    job.assisted_handoff,
                    external_agent=EXTERNAL_AGENT,
                )
                service.verify(items[-1].run_id)
                receipt = service.close(
                    items[-1].run_id,
                    run_result=native.result(items[-1]),
                    run_result_id="result.cockpit",
                    run_bundle=native.bundle(mode_root, items[-1]),
                )
            else:
                service = cockpit(mode_root)
                prepare(service, items, canonical, staging)
                assert service.start(items[-1].run_id).status == "completed"
                service.verify(items[-1].run_id)
                receipt = service.close_managed(items[-1].run_id)
            receipts[mode] = receipt.to_dict()

        assert (
            len(logical_tasks)
            == len(workflow_digests)
            == len(context_digests)
            == len(agent_digests)
            == 1
        )
        for field in ("baseGit", "permissions", "verification", "closure"):
            assert (
                len(
                    {
                        json.dumps(receipt[field], sort_keys=True)
                        for receipt in receipts.values()
                    }
                )
                == 1
            )
        shapes = {
            json.dumps(_receipt_shape(value), sort_keys=True)
            for value in receipts.values()
        }
        assert len(shapes) == 1
        normalized = [_normalize_mode_receipt(value) for value in receipts.values()]
        assert normalized[0] == normalized[1] == normalized[2]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
