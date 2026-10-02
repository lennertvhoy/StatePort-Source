#!/usr/bin/env python3
"""Acceptance tests for governed echo-run planning and integrity handling."""

from __future__ import annotations

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
):
    sys.path.insert(0, str(ROOT / relative))

from governed_api import GovernedAPI
from governed_runner import RunLedger
import governed_api.application as application
from statedd_core import create_instance


CLASSDD = ROOT / "templates" / "classdd"


def _fixture(workspace: Path) -> tuple[GovernedAPI, Path, Path]:
    template = workspace / "template"
    shutil.copytree(CLASSDD, template)
    instance = workspace / "instance"
    create_instance(template, instance, instance_id="run-demo", name="Run demo", owner_name="Tester", owner_handle="@tester")
    instance_yaml = instance / "instance.yaml"
    instance_yaml.write_text(
        instance_yaml.read_text(encoding="utf-8").replace(
            "  status: \"draft\"\n", "  status: \"draft\"\n  grantedCapabilities:\n    - \"read_state\"\n"
        ),
        encoding="utf-8",
    )
    api = GovernedAPI(
        workspace,
        identities={"user": {"roles": ["user"], "instances": ["run-demo"]}},
        operator_allowed_capabilities=["read_state"],
    )
    return api, template, instance


def test_run_requires_server_derived_read_capability() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        api, template, instance = _fixture(Path(tmpdir))
        no_identity = api.dispatch("POST", "/v1/runs/plan", {"instancePath": "instance", "templatePath": "template"})
        assert no_identity.status == 401
        instance_yaml = instance / "instance.yaml"
        instance_yaml.write_text(instance_yaml.read_text(encoding="utf-8").replace("  grantedCapabilities:\n    - \"read_state\"\n", ""), encoding="utf-8")
        denied = api.dispatch("POST", "/v1/runs/plan", {"actor": "user", "instancePath": "instance", "templatePath": "template"})
        assert denied.status == 403 and denied.body["error"]["code"] == "capability_denied"
        assert not (Path(tmpdir) / ".stateport" / "runs.json").exists()


def test_run_rejects_template_path_that_does_not_match_instance_reference() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        api, template, _ = _fixture(workspace)
        alternate = workspace / "alternate-template"
        shutil.copytree(template, alternate)
        response = api.dispatch("POST", "/v1/runs/plan", {"actor": "user", "instancePath": "instance", "templatePath": "alternate-template"})
        assert response.status == 409 and response.body["error"]["code"] == "template_mismatch"


def test_plan_execute_inspect_and_reload_are_persistent() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        api, _, instance = _fixture(workspace)
        planned = api.dispatch("POST", "/v1/runs/plan", {"actor": "user", "instancePath": "instance", "templatePath": "template", "mode": "echo"})
        assert planned.status == 200
        run = planned.body["result"]["run"]
        assert planned.body["result"]["approvalRequired"] is False
        assert run["executionPlan"]["apply"] is False
        assert run["executionPlan"]["instance"]["singleWriterLease"] == run["runId"]
        executed = api.dispatch("POST", "/v1/runs/execute", {"actor": "user", "runId": run["runId"]})
        assert executed.status == 200
        outcome = executed.body["result"]["run"]["outcome"]
        assert executed.body["result"]["idempotent"] is False
        assert outcome["ok"] is True
        assert outcome["stateIntegrity"] == "preserved"
        assert outcome["filesChanged"] == []
        repeated = api.dispatch("POST", "/v1/runs/execute", {"actor": "user", "runId": run["runId"]})
        assert repeated.body["result"]["idempotent"] is True
        inspected = api.dispatch("POST", "/v1/runs/inspect", {"actor": "user", "runId": run["runId"]})
        listed = api.dispatch("POST", "/v1/runs/list", {"actor": "user"})
        assert inspected.status == listed.status == 200
        assert listed.body["result"]["runs"][0]["runId"] == run["runId"]
        reloaded = GovernedAPI(workspace, identities={"user": {"roles": ["user"], "instances": ["run-demo"]}}, operator_allowed_capabilities=["read_state"])
        assert reloaded.dispatch("POST", "/v1/runs/inspect", {"actor": "user", "runId": run["runId"]}).body["result"]["run"]["status"] == "completed"
        assert (instance / "state" / "class.yaml").exists()


def test_unexpected_runner_write_is_restored_and_fails_integrity() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        api, _, instance = _fixture(Path(tmpdir))
        planned = api.dispatch("POST", "/v1/runs/plan", {"actor": "user", "instancePath": "instance", "templatePath": "template"})
        run_id = planned.body["result"]["run"]["runId"]
        original = application.run_instance

        def naughty_runner(path: Path):
            target = Path(path) / "state" / "class.yaml"
            target.write_text(target.read_text(encoding="utf-8") + "\n# unexpected\n", encoding="utf-8")
            return original(path)

        application.run_instance = naughty_runner
        try:
            executed = api.dispatch("POST", "/v1/runs/execute", {"actor": "user", "runId": run_id})
        finally:
            application.run_instance = original
        assert executed.status == 200
        assert executed.body["result"]["run"]["status"] == "failed"
        assert executed.body["result"]["run"]["outcome"]["stateIntegrity"] == "restored_unexpected_write"
        assert "unexpected" not in (instance / "state" / "class.yaml").read_text(encoding="utf-8")


def test_run_ledger_reloads_under_lock_and_enforces_queued_transitions() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "runs.json"

        def create(index: int) -> None:
            RunLedger(path).create(
                actor="user",
                instance_id="run-demo",
                instance_path="/instances/run-demo",
                template_path="/templates/classdd",
                capability="read_state",
                policy={},
                quota={},
                execution_plan={},
                run_id=f"run:{index}",
            )

        with ThreadPoolExecutor(max_workers=4) as executor:
            list(executor.map(create, range(10)))

        first = RunLedger(path)
        second = RunLedger(path)
        assert len(first.all()) == 10
        assert first.update("run:0", status="queued")["status"] == "queued"
        assert second.update("run:0", status="running")["status"] == "running"
        assert first.update("run:0", status="completed")["status"] == "completed"
        try:
            second.update("run:0", status="running")
        except ValueError as exc:
            assert "transition" in str(exc)
        else:
            raise AssertionError("terminal run records must reject later transitions")


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
    print("PASS")
