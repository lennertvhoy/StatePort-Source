#!/usr/bin/env python3
"""Acceptance tests for approval-bound queued container work."""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for relative in (
    "apps/worker/src",
    "packages/governed-runner/src",
    "packages/container-runner/src",
    "packages/approval-gate/src",
    "packages/audit-log/src",
    "packages/quota-engine/src",
    "packages/statedd-core/src",
    "packages/template-validator/src",
    "apps/runner/src",
):
    sys.path.insert(0, str(ROOT / relative))

from approval_gate import ApprovalGate
from audit_log import AuditLog
from container_runner import ExecutionPlan, ExecutorResult
from governed_runner import (
    InstanceLease,
    JobQueue,
    RunLedger,
    digest_snapshot,
    snapshot_files,
)
from quota_engine import QuotaPolicy, UsageLedger
from statedd_core import create_instance
from stateport_worker.service import (
    CONTAINER_ECHO_COMMAND,
    CONTAINER_JOB_PAYLOAD_FORMAT,
    WorkerService,
)


CLASSDD = ROOT / "templates" / "classdd"
RUNNER_IMAGE = "stateport/runner@sha256:" + ("1" * 64)


def _digest(value: dict[str, object]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


class FakeExecutor:
    engine = "podman"
    image = RUNNER_IMAGE
    timeout_seconds = 10

    def __init__(self, *, mutate: bool = False, symlink: bool = False):
        self.mutate = mutate
        self.symlink = symlink
        self.calls = 0

    def execute(self, plan, command, *, approval_id=None):
        self.calls += 1
        assert approval_id
        assert tuple(command) == CONTAINER_ECHO_COMMAND
        if self.mutate:
            target = Path(plan.instance_path) / "state" / "class.yaml"
            target.write_text(target.read_text(encoding="utf-8") + "\n# changed\n", encoding="utf-8")
        if self.symlink:
            target = Path(plan.instance_path) / "state" / "class.yaml"
            target.unlink()
            target.symlink_to("/etc/passwd")
        stdout = json.dumps(
            {
                "ok": True,
                "status": "draft",
                "logs": ["runner started"],
                "errors": [],
            },
            sort_keys=True,
        )
        return ExecutorResult(tuple(command), 0, stdout, "")


def _queued_fixture(
    workspace: Path,
    *,
    approved: bool = True,
) -> tuple[str, str, Path]:
    template = workspace / "template"
    shutil.copytree(CLASSDD, template)
    template_yaml = template / "template.yaml"
    template_yaml.write_text(
        template_yaml.read_text(encoding="utf-8").replace(
            "    - name: read_state\n",
            "    - name: execute_container\n"
            "      level: L3\n"
            "      description: Execute the isolated local runner\n"
            "    - name: read_state\n",
            1,
        ),
        encoding="utf-8",
    )
    instance = workspace / "instance"
    create_instance(
        template,
        instance,
        instance_id="worker-demo",
        name="Worker demo",
        owner_name="Tester",
        owner_handle="@tester",
    )
    instance_yaml = instance / "instance.yaml"
    instance_yaml.write_text(
        instance_yaml.read_text(encoding="utf-8").replace(
            "  status: \"draft\"\n",
            "  status: \"draft\"\n"
            "  grantedCapabilities:\n"
            "    - \"read_state\"\n"
            "    - \"execute_container\"\n",
        ),
        encoding="utf-8",
    )
    operational = workspace / ".stateport"
    run_id = "run:worker-demo"
    plan = ExecutionPlan(
        template.as_posix(),
        instance.as_posix(),
        (operational / "runtime" / run_id).as_posix(),
        run_id,
    ).to_dict()
    plan_digest = _digest(plan)
    template_digest = digest_snapshot(snapshot_files(template))
    command = list(CONTAINER_ECHO_COMMAND)
    approval_gate = ApprovalGate(operational / "approvals.json")
    approval = approval_gate.request(
        operation="execute-run",
        capability="execute_container",
        instance_id="worker-demo",
        actor="user",
        instance_path=instance.as_posix(),
        metadata={
            "runId": run_id,
            "executionPlanDigest": plan_digest,
            "templateDigest": template_digest,
            "containerEngine": "podman",
            "runnerImage": RUNNER_IMAGE,
            "command": command,
            "estimatedCost": 0.1,
        },
    )
    if approved:
        approval_gate.transition(approval.id, "approved", "reviewed")
    job_id = f"job:{approval.id}"
    reservation_id = f"usage:{job_id}"
    UsageLedger(operational / "usage.sqlite3").reserve(
        reservation_id,
        "worker-demo",
        "run",
        QuotaPolicy(runs_per_day=5, monthly_euro_estimate=1.0),
        estimated_cost=0.1,
    )
    payload = {
        "formatVersion": CONTAINER_JOB_PAYLOAD_FORMAT,
        "jobType": "container_echo",
        "runId": run_id,
        "approvalId": approval.id,
        "actor": "user",
        "instanceId": "worker-demo",
        "executionPlan": plan,
        "executionPlanDigest": plan_digest,
        "templateDigest": template_digest,
        "containerEngine": "podman",
        "runnerImage": RUNNER_IMAGE,
        "command": command,
        "usageReservationId": reservation_id,
    }
    JobQueue(operational / "jobs.sqlite3").enqueue(
        idempotency_key=approval.id,
        payload=payload,
        job_id=job_id,
    )
    runs = RunLedger(operational / "runs.json")
    runs.create(
        actor="user",
        instance_id="worker-demo",
        instance_path=instance.as_posix(),
        template_path=template.as_posix(),
        capability="read_state",
        policy={"effectiveCapabilities": ["execute_container", "read_state"]},
        quota={"allowed": True},
        execution_plan=plan,
        estimated_cost=0.1,
        run_id=run_id,
        mode="container_echo",
        command=command,
        container_engine="podman",
        runner_image=RUNNER_IMAGE,
    )
    runs.update(run_id, status="queued", jobId=job_id, approvalId=approval.id)
    return run_id, job_id, instance


def test_worker_completes_approved_job_and_commits_usage() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        run_id, job_id, _ = _queued_fixture(workspace)
        executor = FakeExecutor()
        result = WorkerService(
            workspace,
            executor=executor,
            worker_id="worker-1",
            operator_allowed_capabilities=["read_state", "execute_container"],
        ).run_once()
        assert result is not None and result["status"] == "succeeded"
        assert executor.calls == 1
        run = RunLedger(workspace / ".stateport" / "runs.json").get(run_id)
        assert run is not None and run["status"] == "completed"
        assert run["outcome"]["stateIntegrity"] == "preserved"
        usage = UsageLedger(workspace / ".stateport" / "usage.sqlite3").get(
            f"usage:{job_id}"
        )
        assert usage is not None and usage.status == "committed"
        assert usage.actual_cost == 0.0
        audit = AuditLog(workspace / ".stateport" / "audit.jsonl")
        assert audit.verify() and audit.events[-1].event_type == "job.completed"


def test_worker_rejects_unapproved_job_without_starting_executor() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        run_id, job_id, _ = _queued_fixture(workspace, approved=False)
        executor = FakeExecutor()
        result = WorkerService(
            workspace,
            executor=executor,
            worker_id="worker-1",
            operator_allowed_capabilities=["read_state", "execute_container"],
        ).run_once()
        assert result is not None and result["status"] == "failed"
        assert executor.calls == 0
        run = RunLedger(workspace / ".stateport" / "runs.json").get(run_id)
        assert run is not None and run["status"] == "failed"
        usage = UsageLedger(workspace / ".stateport" / "usage.sqlite3").get(
            f"usage:{job_id}"
        )
        assert usage is not None and usage.status == "committed"


def test_worker_isolates_unexpected_container_writes_and_fails_job() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        run_id, _, instance = _queued_fixture(workspace)
        original = (instance / "state" / "class.yaml").read_bytes()
        executor = FakeExecutor(mutate=True)
        result = WorkerService(
            workspace,
            executor=executor,
            worker_id="worker-1",
            operator_allowed_capabilities=["read_state", "execute_container"],
        ).run_once()
        assert result is not None and result["status"] == "failed"
        assert (instance / "state" / "class.yaml").read_bytes() == original
        run = RunLedger(workspace / ".stateport" / "runs.json").get(run_id)
        assert run is not None and run["status"] == "failed"
        assert run["outcome"]["stateIntegrity"] == "preserved"
        assert run["outcome"]["executionInputIntegrity"] == "isolated_input_modified"
        assert run["outcome"]["filesChanged"] == ["state/class.yaml"]


def test_worker_isolates_unsafe_symlink_replacement_and_fails_job() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        run_id, _, instance = _queued_fixture(workspace)
        original = (instance / "state" / "class.yaml").read_bytes()
        result = WorkerService(
            workspace,
            executor=FakeExecutor(symlink=True),
            worker_id="worker-1",
            operator_allowed_capabilities=["read_state", "execute_container"],
        ).run_once()
        assert result is not None and result["status"] == "failed"
        restored = instance / "state" / "class.yaml"
        assert not restored.is_symlink() and restored.read_bytes() == original
        run = RunLedger(workspace / ".stateport" / "runs.json").get(run_id)
        assert run is not None
        assert run["outcome"]["stateIntegrity"] == "preserved"
        assert run["outcome"]["executionInputIntegrity"] == "isolated_input_modified"
        assert run["outcome"]["filesChanged"] == ["<unsafe-filesystem-entry>"]


def test_worker_rejects_template_changed_after_enqueue() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        run_id, _, _ = _queued_fixture(workspace)
        readme = workspace / "template" / "README.md"
        readme.write_text(readme.read_text(encoding="utf-8") + "\nchanged\n", encoding="utf-8")
        executor = FakeExecutor()
        result = WorkerService(
            workspace,
            executor=executor,
            worker_id="worker-1",
            operator_allowed_capabilities=["read_state", "execute_container"],
        ).run_once()
        assert result is not None and result["status"] == "failed"
        assert executor.calls == 0
        run = RunLedger(workspace / ".stateport" / "runs.json").get(run_id)
        assert run is not None and run["status"] == "failed"


def test_worker_executes_approved_template_snapshot_despite_later_source_change() -> None:
    class SourceChangingExecutor(FakeExecutor):
        def __init__(self, source: Path):
            super().__init__()
            self.source = source
            self.saw_staged_template = False

        def execute(self, plan, command, *, approval_id=None):
            self.saw_staged_template = "/.stateport/staging/" in plan.template_path
            readme = self.source / "README.md"
            readme.write_text(
                readme.read_text(encoding="utf-8") + "\nchanged during execution\n",
                encoding="utf-8",
            )
            return super().execute(plan, command, approval_id=approval_id)

    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        _, _, _ = _queued_fixture(workspace)
        executor = SourceChangingExecutor(workspace / "template")
        result = WorkerService(
            workspace,
            executor=executor,
            worker_id="worker-1",
            operator_allowed_capabilities=["read_state", "execute_container"],
        ).run_once()
        assert result is not None and result["status"] == "succeeded"
        assert executor.saw_staged_template


def test_worker_rejects_executor_not_bound_to_approval() -> None:
    class WrongImageExecutor(FakeExecutor):
        image = "stateport/other@sha256:" + ("2" * 64)

    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        _, _, _ = _queued_fixture(workspace)
        executor = WrongImageExecutor()
        result = WorkerService(
            workspace,
            executor=executor,
            worker_id="worker-1",
            operator_allowed_capabilities=["read_state", "execute_container"],
        ).run_once()
        assert result is not None and result["status"] == "failed"
        assert executor.calls == 0


def test_worker_refreshes_job_lease_around_execution() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        _, _, _ = _queued_fixture(workspace)
        service = WorkerService(
            workspace,
            executor=FakeExecutor(),
            worker_id="worker-1",
            operator_allowed_capabilities=["read_state", "execute_container"],
        )
        original_heartbeat = service.queue.heartbeat
        calls = 0

        def observed_heartbeat(*args, **kwargs):
            nonlocal calls
            calls += 1
            return original_heartbeat(*args, **kwargs)

        service.queue.heartbeat = observed_heartbeat
        result = service.run_once()
        assert result is not None and result["status"] == "succeeded"
        assert calls >= 2


def test_unbound_queue_payload_cannot_fail_or_commit_a_victim_run() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        run_id, job_id, _ = _queued_fixture(workspace)
        queue = JobQueue(workspace / ".stateport" / "jobs.sqlite3")
        queue.cancel(job_id, reason="make malformed job next")
        queue.enqueue(
            idempotency_key="evil",
            job_id="job:evil",
            payload={
                "formatVersion": CONTAINER_JOB_PAYLOAD_FORMAT,
                "runId": run_id,
                "usageReservationId": f"usage:{job_id}",
                "instanceId": "worker-demo",
            },
        )
        executor = FakeExecutor()
        result = WorkerService(
            workspace,
            executor=executor,
            worker_id="worker-1",
            operator_allowed_capabilities=["read_state", "execute_container"],
        ).run_once()
        assert result is not None and result["status"] == "failed"
        assert executor.calls == 0
        run = RunLedger(workspace / ".stateport" / "runs.json").get(run_id)
        usage = UsageLedger(workspace / ".stateport" / "usage.sqlite3").get(
            f"usage:{job_id}"
        )
        assert run is not None and run["status"] == "queued"
        assert usage is not None and usage.status == "active"


def test_busy_instance_lease_requeues_without_consuming_job() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        run_id, job_id, instance = _queued_fixture(workspace)
        executor = FakeExecutor()
        service = WorkerService(
            workspace,
            executor=executor,
            worker_id="worker-1",
            operator_allowed_capabilities=["read_state", "execute_container"],
        )
        with InstanceLease(
            workspace / ".stateport" / "leases",
            instance,
            owner="other-writer",
        ):
            deferred = service.run_once()
        assert deferred is not None and deferred["status"] == "queued"
        assert executor.calls == 0
        run = RunLedger(workspace / ".stateport" / "runs.json").get(run_id)
        usage = UsageLedger(workspace / ".stateport" / "usage.sqlite3").get(
            f"usage:{job_id}"
        )
        assert run is not None and run["status"] == "queued"
        assert usage is not None and usage.status == "active"
        completed = service.run_once()
        assert completed is not None and completed["status"] == "succeeded"


def test_conflicting_precommitted_usage_fails_consistently_without_execution() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        run_id, job_id, _ = _queued_fixture(workspace)
        UsageLedger(workspace / ".stateport" / "usage.sqlite3").commit(
            f"usage:{job_id}", actual_cost=0.1
        )
        executor = FakeExecutor()
        result = WorkerService(
            workspace,
            executor=executor,
            worker_id="worker-1",
            operator_allowed_capabilities=["read_state", "execute_container"],
        ).run_once()
        assert result is not None and result["status"] == "failed"
        assert executor.calls == 0
        run = RunLedger(workspace / ".stateport" / "runs.json").get(run_id)
        job = JobQueue(workspace / ".stateport" / "jobs.sqlite3").get(job_id)
        assert run is not None and run["status"] == "failed"
        assert job is not None and job["status"] == "failed"


def test_terminal_run_finalization_recovers_after_transient_audit_failure() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        run_id, job_id, _ = _queued_fixture(workspace)
        service = WorkerService(
            workspace,
            executor=FakeExecutor(),
            worker_id="worker-1",
            operator_allowed_capabilities=["read_state", "execute_container"],
        )
        original_append_once = service.audit.append_once
        calls = 0

        def fail_once(**kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("synthetic audit outage")
            return original_append_once(**kwargs)

        service.audit.append_once = fail_once
        try:
            service.run_once()
        except Exception as exc:
            assert "finalization" in str(exc)
        else:
            raise AssertionError("transient audit failure must remain retryable")
        queued = JobQueue(workspace / ".stateport" / "jobs.sqlite3").get(job_id)
        assert queued is not None and queued["status"] == "queued"
        completed = service.run_once()
        assert completed is not None and completed["status"] == "succeeded"
        run = RunLedger(workspace / ".stateport" / "runs.json").get(run_id)
        assert run is not None and run["status"] == "completed"


def test_lost_job_lease_does_not_terminalize_run_or_usage() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        run_id, job_id, _ = _queued_fixture(workspace)
        executor = FakeExecutor()
        service = WorkerService(
            workspace,
            executor=executor,
            worker_id="worker-1",
            operator_allowed_capabilities=["read_state", "execute_container"],
        )
        original_heartbeat = service.queue.heartbeat
        calls = 0

        def lose_after_initial_refresh(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls > 1:
                raise RuntimeError("synthetic lease loss")
            return original_heartbeat(*args, **kwargs)

        service.queue.heartbeat = lose_after_initial_refresh
        try:
            service.run_once()
        except Exception as exc:
            assert "heartbeat" in str(exc)
        else:
            raise AssertionError("lost queue lease must stop finalization")
        run = RunLedger(workspace / ".stateport" / "runs.json").get(run_id)
        usage = UsageLedger(workspace / ".stateport" / "usage.sqlite3").get(
            f"usage:{job_id}"
        )
        leased = JobQueue(workspace / ".stateport" / "jobs.sqlite3").get(job_id)
        assert run is not None and run["status"] == "running"
        assert usage is not None and usage.status == "active"
        assert leased is not None and leased["status"] == "leased"
        events = AuditLog(workspace / ".stateport" / "audit.jsonl").events
        assert not any(event.event_type in {"job.completed", "job.failed"} for event in events)

        service.queue.heartbeat = original_heartbeat
        service.queue.requeue(job_id, leased["lease"]["token"], reason="retry")
        completed = service.run_once()
        assert completed is not None and completed["status"] == "succeeded"


def test_worker_rechecks_capability_intersection_after_enqueue() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        run_id, _, instance = _queued_fixture(workspace)
        instance_yaml = instance / "instance.yaml"
        instance_yaml.write_text(
            instance_yaml.read_text(encoding="utf-8").replace(
                "    - \"execute_container\"\n",
                "",
            ),
            encoding="utf-8",
        )
        executor = FakeExecutor()
        result = WorkerService(
            workspace,
            executor=executor,
            worker_id="worker-1",
            operator_allowed_capabilities=["read_state", "execute_container"],
        ).run_once()
        assert result is not None and result["status"] == "failed"
        assert executor.calls == 0
        run = RunLedger(workspace / ".stateport" / "runs.json").get(run_id)
        assert run is not None and run["status"] == "failed"
        assert "capability intersection" in run["outcome"]["errors"][0]


if __name__ == "__main__":
    for name, test in sorted(globals().items()):
        if name.startswith("test_") and callable(test):
            test()
    print("PASS")
