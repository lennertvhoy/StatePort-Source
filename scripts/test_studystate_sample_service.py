from __future__ import annotations

import json
from pathlib import Path
import socket
import sys
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
for relative in (
    "packages/persistent-app/src",
    "packages/instance-backup/src",
    "packages/instance-catalog/src",
    "packages/diagnostics/src",
    "packages/statedd-core/src",
    "packages/template-validator/src",
    "apps/runner/src",
):
    sys.path.insert(0, str(ROOT / relative))

from stateport_persistent_app import LocalLayout, PersistentApp  # noqa: E402


def test_studystate_sample_completes_evidence_transaction_without_development_controls(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = int(probe.getsockname()[1])
    app.service_start(port=port)
    try:
        with urlopen(f"http://127.0.0.1:{port}/session") as response:
            session = json.loads(response.read())["result"]
            cookie = response.headers["Set-Cookie"].split(";", 1)[0]
        mutation_headers = {
            "Content-Type": "application/json",
            "Cookie": cookie,
            "Origin": f"http://127.0.0.1:{port}",
            "X-StatePort-CSRF": session["csrfToken"],
        }

        def get(path: str) -> dict[str, object]:
            with urlopen(Request(f"http://127.0.0.1:{port}{path}", headers={"Cookie": cookie})) as response:
                return json.loads(response.read())

        def post(path: str, payload: dict[str, object]) -> dict[str, object]:
            request = Request(
                f"http://127.0.0.1:{port}{path}",
                data=json.dumps(payload).encode(),
                headers=mutation_headers,
                method="POST",
            )
            with urlopen(request) as response:
                return json.loads(response.read())

        catalog = get("/v1/applications")["result"]["applications"]
        study = next(item for item in catalog if item["applicationId"] == "studystate.sample")
        assert study["install"]["status"] == "available"
        assert study["install"]["networkPolicy"] == "disabled"
        assert set(study["install"]["requestedCapabilities"]) == {
            "conversation", "goal_execution", "proactive_notifications", "progress_dashboard",
        }
        installed = post("/v1/application-fixtures/install", {
            "applicationId": "studystate.sample",
            "instanceId": "study-browser",
            "name": "StudyState Sample",
            "applicationDescriptorDigest": study["applicationIdentity"]["descriptorDigest"],
            "applicationPackageDigest": study["applicationIdentity"]["packageDigest"],
            "experienceDescriptorDigest": study["experienceIdentity"]["descriptorDigest"],
        })
        assert installed["result"]["receipt"]["formatVersion"] == "stateport.application-install-receipt/v1"
        experience = get("/v1/instances/study-browser/experience")["result"]
        capabilities = {item["id"] for item in experience["capabilities"]}
        assert {"workbench", "terminal", "editor", "cto_orchestration", "benchmark_evidence"}.isdisjoint(capabilities)

        actions = get("/v1/instances/study-browser/actions")["result"]["actions"]
        assert {item["actionId"] for item in actions} == {
            "studystate.sample.plan-next-activity/v1", "studystate.sample.record-evidence/v1",
            "studystate.sample.start-activity/v1", "studystate.sample.pause-activity/v1",
            "studystate.sample.redirect-activity/v1",
            "studystate.sample.undo-last-evidence/v1",
        }
        before_state = get("/v1/instances/study-browser")["result"]["packageState"]
        before_plan_digest = before_state["planDigest"]
        assert before_state["activities"][0]["reason"].startswith("This is the next unfinished")
        assert before_state["canUndo"] is False
        evidence_action = next(item for item in actions if item["actionId"] == "studystate.sample.record-evidence/v1")
        assert evidence_action["inputSchema"]["properties"]["activityId"] == {
            "type": "string",
            "title": "Planned activity",
            "default": "evidence-practice",
            "minLength": 1,
            "maxLength": 80,
        }

        prepared = post("/v1/instances/study-browser/execution/prepare", {
            "expectedInstanceId": "study-browser",
            "actionId": "studystate.sample.record-evidence/v1",
            "engineId": "synthetic",
            "inputs": {"activityId": "evidence-practice", "evidenceSummary": "Completed the governed evidence exercise."},
        })
        run = prepared["result"]["run"]
        run_id = run["runId"]
        approved = post(f"/v1/runs/{run_id}/approve", {
            "expectedInstanceId": "study-browser", "expectedRevision": run["revision"],
        })["result"]
        executed = post(f"/v1/runs/{run_id}/execute", {
            "expectedInstanceId": "study-browser", "expectedRevision": approved["revision"],
        })["result"]["run"]
        assert executed["status"] == "state_change_proposed"
        proposal_operation = executed["proposal"]["operation"]
        assert proposal_operation["activityId"] == "evidence-practice"
        assert proposal_operation["activityTitle"] == "Complete one evidence-backed practice activity"
        assert proposal_operation["reflection"] == "Completed the governed evidence exercise."
        assert proposal_operation["summary"] == proposal_operation["reflection"]
        # The approval inbox presents the declared action display name, not the
        # raw action identifier, while the exact identifier stays in scope.
        pending = get("/v1/approvals")["result"]["approvals"]
        proposal_decision = next(
            item for item in pending
            if item["decision"]["kind"] == "run_proposal" and item["runId"] == run_id
        )
        assert proposal_decision["title"] == "Approve changes proposed by Complete activity and record evidence"
        assert "Action: studystate.sample.record-evidence/v1" in proposal_decision["scope"]
        proposal_approved = post(f"/v1/runs/{run_id}/proposal-approve", {
            "expectedInstanceId": "study-browser", "expectedRevision": executed["revision"],
        })["result"]
        applied = post(f"/v1/runs/{run_id}/apply", {
            "expectedInstanceId": "study-browser", "expectedRevision": proposal_approved["revision"],
        })["result"]["run"]
        assert applied["status"] == "applied"
        state = (app.layout.instances_root / "study-browser" / "state" / "LEARNING.yaml").read_text(encoding="utf-8")
        assert "status: completed" in state
        assert "Completed the governed evidence exercise." in state
        bundle = get(f"/v1/runs/{run_id}/bundle")["result"]
        assert bundle["applied"] is True
        assert (
            bundle["bundle"]["contentDigest"]
            == applied["closureReceipt"]["appliedRunBundleDigest"]
        )
        assert bundle["verification"]["verified"] is True

        durable_state = get("/v1/instances/study-browser")["result"]["packageState"]
        assert durable_state["planDigest"] != before_plan_digest
        assert durable_state["goalProgressPercent"] == 50
        assert durable_state["canUndo"] is True
        assert durable_state["lastTransition"]["beforePlanDigest"] == before_plan_digest
        assert durable_state["evidence"] == [{
            "id": proposal_operation["evidenceId"],
            "title": "Completed the governed evidence exercise.",
            "state": "self_reported",
            "updatedAt": durable_state["evidence"][0]["updatedAt"],
        }]

        app.service_stop()
        app.service_start(port=port)
        with urlopen(f"http://127.0.0.1:{port}/session") as response:
            session = json.loads(response.read())["result"]
            cookie = response.headers["Set-Cookie"].split(";", 1)[0]
        mutation_headers = {
            "Content-Type": "application/json",
            "Cookie": cookie,
            "Origin": f"http://127.0.0.1:{port}",
            "X-StatePort-CSRF": session["csrfToken"],
        }
        after_restart = get("/v1/instances/study-browser")["result"]["packageState"]
        assert after_restart["planDigest"] == durable_state["planDigest"]
        assert after_restart["canUndo"] is True

        undo_prepared = post("/v1/instances/study-browser/execution/prepare", {
            "expectedInstanceId": "study-browser",
            "actionId": "studystate.sample.undo-last-evidence/v1",
            "engineId": "synthetic",
            "inputs": {"expectedPlanDigest": durable_state["planDigest"]},
        })["result"]["run"]
        undo_id = undo_prepared["runId"]
        undo_approved = post(f"/v1/runs/{undo_id}/approve", {
            "expectedInstanceId": "study-browser", "expectedRevision": undo_prepared["revision"],
        })["result"]
        undo_executed = post(f"/v1/runs/{undo_id}/execute", {
            "expectedInstanceId": "study-browser", "expectedRevision": undo_approved["revision"],
        })["result"]["run"]
        undo_operation = undo_executed["proposal"]["operation"]
        assert undo_operation["activityId"] == "evidence-practice"
        assert undo_operation["activityTitle"] == "Complete one evidence-backed practice activity"
        assert undo_operation["reflection"] == "Completed the governed evidence exercise."
        assert undo_operation["restoredPlanDigest"] == before_plan_digest
        undo_proposal_approved = post(f"/v1/runs/{undo_id}/proposal-approve", {
            "expectedInstanceId": "study-browser", "expectedRevision": undo_executed["revision"],
        })["result"]
        undo_applied = post(f"/v1/runs/{undo_id}/apply", {
            "expectedInstanceId": "study-browser", "expectedRevision": undo_proposal_approved["revision"],
        })["result"]["run"]
        assert undo_applied["status"] == "applied"
        restored = get("/v1/instances/study-browser")["result"]["packageState"]
        assert restored["planDigest"] == before_plan_digest
        assert restored["goalProgressPercent"] == 0
        assert restored["canUndo"] is False
        assert restored["lastTransition"]["restoredPlanDigest"] == before_plan_digest

        def governed_control(action_id: str, inputs: dict[str, object]) -> dict[str, object]:
            control_prepared = post("/v1/instances/study-browser/execution/prepare", {
                "expectedInstanceId": "study-browser",
                "actionId": action_id,
                "engineId": "synthetic",
                "inputs": inputs,
            })["result"]["run"]
            control_id = control_prepared["runId"]
            control_approved = post(f"/v1/runs/{control_id}/approve", {
                "expectedInstanceId": "study-browser", "expectedRevision": control_prepared["revision"],
            })["result"]
            control_proposed = post(f"/v1/runs/{control_id}/execute", {
                "expectedInstanceId": "study-browser", "expectedRevision": control_approved["revision"],
            })["result"]["run"]
            assert control_proposed["status"] == "state_change_proposed"
            control_proposal_approved = post(f"/v1/runs/{control_id}/proposal-approve", {
                "expectedInstanceId": "study-browser", "expectedRevision": control_proposed["revision"],
            })["result"]
            control_applied = post(f"/v1/runs/{control_id}/apply", {
                "expectedInstanceId": "study-browser", "expectedRevision": control_proposal_approved["revision"],
            })["result"]["run"]
            assert control_applied["status"] == "applied"
            assert control_applied["receipt"]["validation"] == "passed"
            assert control_applied["closureReceipt"]["proposalDigest"] == control_proposed["proposalDigest"]
            return control_proposed["proposal"]["operation"]

        start_operation = governed_control("studystate.sample.start-activity/v1", {
            "activityId": "evidence-practice",
            "expectedPlanDigest": restored["planDigest"],
        })
        assert start_operation["type"] == "start_activity"
        started = get("/v1/instances/study-browser")["result"]["packageState"]
        assert [item["state"] for item in started["activities"]] == ["in_progress", "not_started"]

        redirect_operation = governed_control("studystate.sample.redirect-activity/v1", {
            "fromActivityId": "evidence-practice",
            "toActivityId": "explain-back",
            "expectedPlanDigest": started["planDigest"],
        })
        assert redirect_operation["type"] == "redirect_activity"
        redirected = get("/v1/instances/study-browser")["result"]["packageState"]
        assert [item["state"] for item in redirected["activities"]] == ["paused", "in_progress"]
        assert redirected["lastTransition"]["fromActivityId"] == "evidence-practice"
        assert redirected["lastTransition"]["toActivityId"] == "explain-back"

        pause_operation = governed_control("studystate.sample.pause-activity/v1", {
            "activityId": "explain-back",
            "expectedPlanDigest": redirected["planDigest"],
        })
        assert pause_operation["type"] == "pause_activity"
        paused = get("/v1/instances/study-browser")["result"]["packageState"]
        assert [item["state"] for item in paused["activities"]] == ["paused", "paused"]
        assert paused["lastTransition"]["kind"] == "pause_applied"
    finally:
        app.service_stop()
