#!/usr/bin/env python3
"""Acceptance tests for approval-bound queue admission in the governed API."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for relative in (
    "packages/governed-api/src",
    "packages/governed-runner/src",
    "packages/container-runner/src",
    "packages/statedd-core/src",
    "packages/template-validator/src",
    "packages/approval-gate/src",
    "packages/quota-engine/src",
    "packages/audit-log/src",
    "apps/runner/src",
    "apps/worker/src",
):
    sys.path.insert(0, str(ROOT / relative))

from governed_api import GovernedAPI
from container_runner import ExecutorResult
from audit_log import AuditLog
from governed_runner import CONTAINER_ECHO_COMMAND, JobQueue
from statedd_core import create_instance
from stateport_worker.service import WorkerService


CLASSDD = ROOT / "templates" / "classdd"
RUNNER_IMAGE = "stateport/runner@sha256:" + ("1" * 64)


def _fixture(
    workspace: Path,
    *,
    runs_per_day: int = 100,
    runner_image: str = RUNNER_IMAGE,
) -> GovernedAPI:
    template = workspace / "template"
    shutil.copytree(CLASSDD, template)
    template_yaml = template / "template.yaml"
    text = template_yaml.read_text(encoding="utf-8")
    text = text.replace(
        "    - name: read_state\n",
        "    - name: execute_container\n"
        "      level: L3\n"
        "      description: Execute the isolated local runner\n"
        "    - name: read_state\n",
        1,
    ).replace("runsPerDay: 100", f"runsPerDay: {runs_per_day}")
    template_yaml.write_text(text, encoding="utf-8")
    instance = workspace / "instance"
    create_instance(
        template,
        instance,
        instance_id="queue-demo",
        name="Queue demo",
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
    return GovernedAPI(
        workspace,
        identities={
            "user": {"roles": ["user"], "instances": ["queue-demo"]},
            "reviewer": {"roles": ["approver"], "instances": ["queue-demo"]},
            "operator": {"roles": ["operator"], "instances": ["queue-demo"]},
            "outsider": {"roles": ["user"], "instances": ["other"]},
        },
        operator_allowed_capabilities=["read_state", "execute_container"],
        runner_image=runner_image,
    )


def _plan_and_approve(api: GovernedAPI, *, estimated_cost: float = 0.25) -> tuple[str, str]:
    planned = api.dispatch(
        "POST",
        "/v1/runs/plan",
        {
            "actor": "user",
            "instancePath": "instance",
            "templatePath": "template",
            "mode": "container_echo",
            "estimatedCost": estimated_cost,
        },
    )
    assert planned.status == 200
    assert planned.body["result"]["approvalRequired"] is True
    run = planned.body["result"]["run"]
    assert tuple(run["command"]) == CONTAINER_ECHO_COMMAND
    direct = api.dispatch(
        "POST", "/v1/runs/execute", {"actor": "user", "runId": run["runId"]}
    )
    assert direct.status == 409 and direct.body["error"]["code"] == "queue_required"
    requested = api.dispatch(
        "POST",
        "/v1/runs/request-execution",
        {"actor": "user", "runId": run["runId"], "reason": "run locally"},
    )
    assert requested.status == 200
    approval = requested.body["result"]["approval"]
    repeated = api.dispatch(
        "POST",
        "/v1/runs/request-execution",
        {"actor": "user", "runId": run["runId"]},
    )
    assert repeated.body["result"]["idempotent"] is True
    self_approval = api.dispatch(
        "POST",
        "/v1/approvals/decide",
        {"actor": "user", "approvalId": approval["id"], "status": "approved"},
    )
    assert self_approval.status == 403
    approved = api.dispatch(
        "POST",
        "/v1/approvals/decide",
        {"actor": "reviewer", "approvalId": approval["id"], "status": "approved"},
    )
    assert approved.status == 200
    approved_retry = api.dispatch(
        "POST",
        "/v1/runs/request-execution",
        {"actor": "user", "runId": run["runId"]},
    )
    assert approved_retry.status == 200
    assert approved_retry.body["result"]["idempotent"] is True
    assert approved_retry.body["result"]["approval"]["status"] == "approved"
    assert approved_retry.body["result"]["approval"]["metadata"]["decision"] == {
        "actor": "reviewer",
        "status": "approved",
        "at": approved.body["result"]["approval"]["metadata"]["decision"]["at"],
    }
    return run["runId"], approval["id"]


def test_approved_run_is_durably_enqueued_scoped_and_idempotent() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        api = _fixture(workspace)
        run_id, approval_id = _plan_and_approve(api)
        forbidden = api.dispatch(
            "POST",
            "/v1/runs/enqueue",
            {"actor": "user", "approvalId": approval_id},
        )
        assert forbidden.status == 403
        enqueued = api.dispatch(
            "POST",
            "/v1/runs/enqueue",
            {"actor": "operator", "approvalId": approval_id},
        )
        assert enqueued.status == 200
        result = enqueued.body["result"]
        assert result["idempotent"] is False
        assert result["run"]["status"] == "queued"
        assert result["job"]["status"] == "queued"
        job_id = result["job"]["jobId"]
        repeated = api.dispatch(
            "POST",
            "/v1/runs/enqueue",
            {"actor": "operator", "approvalId": approval_id},
        )
        assert repeated.body["result"]["idempotent"] is True

        inspected = api.dispatch(
            "POST", "/v1/jobs/inspect", {"actor": "user", "jobId": job_id}
        )
        listed = api.dispatch("POST", "/v1/jobs/list", {"actor": "user"})
        outside = api.dispatch(
            "POST", "/v1/jobs/inspect", {"actor": "outsider", "jobId": job_id}
        )
        assert inspected.status == listed.status == 200
        assert listed.body["result"]["jobs"][0]["jobId"] == job_id
        assert outside.status == 403
        usage = api.dispatch(
            "POST",
            "/v1/usage/inspect",
            {"actor": "user", "instanceId": "queue-demo"},
        )
        assert usage.body["result"]["usage"]["runs_today"] == 1
        assert usage.body["result"]["usage"]["monthly_euro_estimate"] == 0.25

        claimed = JobQueue(workspace / ".stateport" / "jobs.sqlite3").claim(
            worker_id="test-worker",
            lease_seconds=60,
        )
        assert claimed is not None and claimed["lease"]["token"]
        public = api.dispatch(
            "POST", "/v1/jobs/inspect", {"actor": "user", "jobId": job_id}
        ).body["result"]["job"]
        assert "token" not in public["lease"]

        reloaded = _fixture_for_reload(workspace)
        persisted = reloaded.dispatch(
            "POST", "/v1/jobs/inspect", {"actor": "user", "jobId": job_id}
        )
        assert persisted.status == 200 and persisted.body["result"]["job"]["status"] == "leased"
        assert reloaded.dispatch(
            "POST", "/v1/runs/inspect", {"actor": "user", "runId": run_id}
        ).body["result"]["run"]["status"] == "queued"


def _fixture_for_reload(workspace: Path) -> GovernedAPI:
    return GovernedAPI(
        workspace,
        identities={
            "user": {"roles": ["user"], "instances": ["queue-demo"]},
            "operator": {"roles": ["operator"], "instances": ["queue-demo"]},
        },
        operator_allowed_capabilities=["read_state", "execute_container"],
        runner_image=RUNNER_IMAGE,
    )


def test_execution_request_requires_fresh_capability_intersection() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        api = _fixture(workspace)
        planned = api.dispatch(
            "POST",
            "/v1/runs/plan",
            {
                "actor": "user",
                "instancePath": "instance",
                "templatePath": "template",
                "mode": "container_echo",
            },
        )
        run_id = planned.body["result"]["run"]["runId"]
        instance_yaml = workspace / "instance" / "instance.yaml"
        instance_yaml.write_text(
            instance_yaml.read_text(encoding="utf-8").replace(
                "    - \"execute_container\"\n", ""
            ),
            encoding="utf-8",
        )
        denied = api.dispatch(
            "POST",
            "/v1/runs/request-execution",
            {"actor": "user", "runId": run_id},
        )
        assert denied.status == 403 and denied.body["error"]["code"] == "capability_denied"


def test_execution_request_rejects_mutable_runner_image_tag() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        api = _fixture(workspace, runner_image="stateport/runner:local")
        planned = api.dispatch(
            "POST",
            "/v1/runs/plan",
            {
                "actor": "user",
                "instancePath": "instance",
                "templatePath": "template",
                "mode": "container_echo",
            },
        )
        run_id = planned.body["result"]["run"]["runId"]
        denied = api.dispatch(
            "POST",
            "/v1/runs/request-execution",
            {"actor": "user", "runId": run_id},
        )
        assert denied.status == 409
        assert denied.body["error"]["code"] == "runner_image_untrusted"


def test_atomic_usage_reservation_blocks_second_approved_enqueue() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        api = _fixture(workspace, runs_per_day=1)
        _, first_approval = _plan_and_approve(api, estimated_cost=0.0)
        _, second_approval = _plan_and_approve(api, estimated_cost=0.0)
        first = api.dispatch(
            "POST",
            "/v1/runs/enqueue",
            {"actor": "operator", "approvalId": first_approval},
        )
        second = api.dispatch(
            "POST",
            "/v1/runs/enqueue",
            {"actor": "operator", "approvalId": second_approval},
        )
        assert first.status == 200
        assert second.status == 429 and second.body["error"]["code"] == "quota_exceeded"
        assert len(JobQueue(workspace / ".stateport" / "jobs.sqlite3").list()) == 1


def test_concurrent_request_and_enqueue_share_one_approval_job_and_reservation() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        api = _fixture(workspace)
        planned = api.dispatch(
            "POST",
            "/v1/runs/plan",
            {
                "actor": "user",
                "instancePath": "instance",
                "templatePath": "template",
                "mode": "container_echo",
                "estimatedCost": 0.1,
            },
        )
        run_id = planned.body["result"]["run"]["runId"]

        with ThreadPoolExecutor(max_workers=4) as pool:
            requests = list(
                pool.map(
                    lambda _: api.dispatch(
                        "POST",
                        "/v1/runs/request-execution",
                        {"actor": "user", "runId": run_id},
                    ),
                    range(4),
                )
            )
        assert all(response.status == 200 for response in requests)
        approval_ids = {
            response.body["result"]["approval"]["id"] for response in requests
        }
        assert len(approval_ids) == 1
        approval_id = approval_ids.pop()
        assert api.dispatch(
            "POST",
            "/v1/approvals/decide",
            {"actor": "reviewer", "approvalId": approval_id, "status": "approved"},
        ).status == 200

        with ThreadPoolExecutor(max_workers=4) as pool:
            enqueues = list(
                pool.map(
                    lambda _: api.dispatch(
                        "POST",
                        "/v1/runs/enqueue",
                        {"actor": "operator", "approvalId": approval_id},
                    ),
                    range(4),
                )
            )
        assert all(response.status == 200 for response in enqueues)
        assert sum(
            not response.body["result"]["idempotent"] for response in enqueues
        ) == 1
        assert len(JobQueue(workspace / ".stateport" / "jobs.sqlite3").list()) == 1
        events = AuditLog(workspace / ".stateport" / "audit.jsonl").events
        assert sum(event.event_type == "job.enqueued" for event in events) == 1
        usage = api.dispatch(
            "POST",
            "/v1/usage/inspect",
            {"actor": "user", "instanceId": "queue-demo"},
        )
        assert usage.body["result"]["usage"]["runs_today"] == 1
        assert usage.body["result"]["usage"]["monthly_euro_estimate"] == 0.1


def test_enqueue_publish_failure_is_safely_retryable() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        api = _fixture(workspace)
        run_id, approval_id = _plan_and_approve(api, estimated_cost=0.1)
        queue = api._job_queue()
        original_enqueue = queue.enqueue

        def unavailable_enqueue(**kwargs):
            del kwargs
            raise OSError("synthetic queue outage")

        queue.enqueue = unavailable_enqueue
        failed = api.dispatch(
            "POST",
            "/v1/runs/enqueue",
            {"actor": "operator", "approvalId": approval_id},
        )
        assert failed.status == 400
        run = api.dispatch(
            "POST", "/v1/runs/inspect", {"actor": "user", "runId": run_id}
        ).body["result"]["run"]
        assert run["status"] == "queued"
        assert queue.list() == ()

        queue.enqueue = original_enqueue
        retried = api.dispatch(
            "POST",
            "/v1/runs/enqueue",
            {"actor": "operator", "approvalId": approval_id},
        )
        assert retried.status == 200
        assert retried.body["result"]["job"]["status"] == "queued"


def test_enqueue_rejects_template_content_changed_after_approval() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        api = _fixture(workspace)
        _, approval_id = _plan_and_approve(api)
        readme = workspace / "template" / "README.md"
        readme.write_text(readme.read_text(encoding="utf-8") + "\nchanged\n", encoding="utf-8")
        denied = api.dispatch(
            "POST",
            "/v1/runs/enqueue",
            {"actor": "operator", "approvalId": approval_id},
        )
        assert denied.status == 409
        assert denied.body["error"]["code"] == "plan_changed"
        assert JobQueue(workspace / ".stateport" / "jobs.sqlite3").list() == ()


def test_enqueue_retry_backfills_audit_after_transient_audit_failure() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        api = _fixture(workspace)
        _, approval_id = _plan_and_approve(api)
        original_audit_once = api._audit_once
        calls = 0

        def fail_once(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("synthetic audit outage")
            return original_audit_once(*args, **kwargs)

        api._audit_once = fail_once
        failed = api.dispatch(
            "POST",
            "/v1/runs/enqueue",
            {"actor": "operator", "approvalId": approval_id},
        )
        assert failed.status == 400
        assert len(JobQueue(workspace / ".stateport" / "jobs.sqlite3").list()) == 1
        retried = api.dispatch(
            "POST",
            "/v1/runs/enqueue",
            {"actor": "operator", "approvalId": approval_id},
        )
        assert retried.status == 200
        assert retried.body["result"]["idempotent"] is True
        events = AuditLog(workspace / ".stateport" / "audit.jsonl").events
        assert sum(event.event_type == "job.enqueued" for event in events) == 1


def test_api_approval_queue_and_worker_form_one_persistent_flow() -> None:
    class Executor:
        engine = "podman"
        image = RUNNER_IMAGE
        timeout_seconds = 10

        def execute(self, plan, command, *, approval_id=None):
            del plan
            assert approval_id
            return ExecutorResult(
                tuple(command),
                0,
                json.dumps(
                    {
                        "ok": True,
                        "status": "draft",
                        "logs": ["runner started"],
                        "errors": [],
                    }
                ),
                "",
            )

    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        api = _fixture(workspace)
        run_id, approval_id = _plan_and_approve(api, estimated_cost=0.1)
        enqueued = api.dispatch(
            "POST",
            "/v1/runs/enqueue",
            {"actor": "operator", "approvalId": approval_id},
        )
        job_id = enqueued.body["result"]["job"]["jobId"]
        completed = WorkerService(
            workspace,
            executor=Executor(),
            worker_id="worker-integration",
            operator_allowed_capabilities=["read_state", "execute_container"],
        ).run_once()
        assert completed is not None and completed["status"] == "succeeded"
        inspected_job = api.dispatch(
            "POST", "/v1/jobs/inspect", {"actor": "user", "jobId": job_id}
        ).body["result"]["job"]
        inspected_run = api.dispatch(
            "POST", "/v1/runs/inspect", {"actor": "user", "runId": run_id}
        ).body["result"]["run"]
        usage = api.dispatch(
            "POST",
            "/v1/usage/inspect",
            {"actor": "user", "instanceId": "queue-demo"},
        ).body["result"]["usage"]
        assert inspected_job["status"] == "succeeded"
        assert inspected_run["status"] == "completed"
        assert inspected_run["outcome"]["stateIntegrity"] == "preserved"
        assert usage["runs_today"] == 1
        assert usage["monthly_euro_estimate"] == 0.0


if __name__ == "__main__":
    for name, test in sorted(globals().items()):
        if name.startswith("test_") and callable(test):
            test()
    print("PASS")
