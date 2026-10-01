from __future__ import annotations

import os
from pathlib import Path
import sys

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
):
    sys.path.insert(0, str(ROOT / relative))

from stateport_persistent_app import LocalLayout, PersistentApp  # noqa: E402
from stateport_portable_execution.runtime import PortableExecutionService  # noqa: E402
from run_bundle import verify_bundle  # noqa: E402
from statebench import ingest_run_bundle  # noqa: E402


def test_checklistdd_uses_generic_service_lifecycle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    execution = PortableExecutionService(app, ROOT)
    installed = execution.install_fixture_instance("checklistdd", "checklist-demo")
    assert installed["entry"]["applicationId"] == "checklistdd"
    actions = execution.action_list("checklist-demo")
    assert {item["actionId"] for item in actions} == {"checklistdd.plan-next-item/v1", "checklistdd.complete-item/v1"}

    prepared = execution.prepare("checklist-demo", "checklistdd.complete-item/v1", "synthetic", {"itemId": "first-item"})
    run_id = prepared["run"]["runId"]
    execution.approve_run(run_id)
    proposed = execution.execute(run_id)
    assert proposed["run"]["applicationId"] == "checklistdd"
    assert proposed["run"]["result"]["canonicalStateUnchanged"] is True
    sandbox = proposed["run"]["result"]["sandbox"]
    assert sandbox["executionBoundary"] == "staging_copy_only"
    assert sandbox["containerEnforced"] is False
    assert sandbox["networkIsolation"] == "unproven"
    assert sandbox["canonicalAccessIsolation"] == "unproven"
    assert "canonicalStateMount" not in sandbox and sandbox.get("network") != "disabled"
    run_result_sandbox = proposed["run"]["runResult"]["sandbox"]
    assert run_result_sandbox["containerEnforced"] is False
    assert run_result_sandbox["networkIsolation"] == "unproven"
    assert proposed["run"]["lifecycleState"] == "PROPOSAL_CREATED"
    assert proposed["run"]["status"] == "state_change_proposed"

    execution.reject_proposal(run_id)
    assert execution.inspect(run_id)["run"]["status"] == "state_change_rejected"

    prepared = execution.prepare("checklist-demo", "checklistdd.complete-item/v1", "synthetic", {"itemId": "first-item"})
    second_id = prepared["run"]["runId"]
    execution.approve_run(second_id)
    execution.execute(second_id)
    execution.approve_proposal(second_id)
    applied = execution.apply_proposal(second_id)
    assert applied["run"]["status"] == "applied"
    assert applied["run"]["lifecycleState"] == "CLOSED"
    assert applied["run"]["receipt"]["validation"] == "passed"
    assert applied["run"]["runBundle"]["path"]
    assert applied["run"]["appliedRunBundle"]["path"]
    assert verify_bundle(applied["run"]["appliedRunBundle"]["path"])["verified"] is True
    assert ingest_run_bundle(applied["run"]["appliedRunBundle"]["path"])["applicationId"] == "checklistdd"

    exported = execution.export_instance("checklist-demo")
    imported = execution.import_instance_archive(exported["archive"], app.layout.instances_root / "checklist-moved", new_instance_id="checklist-moved")
    assert imported["instanceId"] == "checklist-moved"
    assert (app.layout.instances_root / "checklist-moved/state/CHECKLIST.yaml").is_file()
    assert app.catalog.get("checklist-moved")["instanceId"] == "checklist-moved"
