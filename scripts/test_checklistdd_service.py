from __future__ import annotations

import json
from pathlib import Path
import socket
import sys
from urllib.error import HTTPError
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


def test_checklistdd_fixture_is_installable_through_real_service(tmp_path, monkeypatch) -> None:
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

        def post(path: str, payload: dict[str, object]) -> dict[str, object]:
            request = Request(
                f"http://127.0.0.1:{port}{path}",
                data=json.dumps(payload).encode(),
                headers=mutation_headers,
                method="POST",
            )
            with urlopen(request) as response:
                return json.loads(response.read())

        def get(path: str) -> dict[str, object]:
            request = Request(f"http://127.0.0.1:{port}{path}", headers={"Cookie": cookie})
            with urlopen(request) as response:
                return json.loads(response.read())

        def rejected_post(path: str, payload: dict[str, object]) -> tuple[int, dict[str, object]]:
            request = Request(
                f"http://127.0.0.1:{port}{path}",
                data=json.dumps(payload).encode(),
                headers=mutation_headers,
                method="POST",
            )
            try:
                urlopen(request)
            except HTTPError as error:
                return error.code, json.loads(error.read())
            raise AssertionError("stale or mismatched mutation unexpectedly succeeded")

        unsafe_request = Request(
            f"http://127.0.0.1:{port}/v1/application-fixtures/install",
            data=json.dumps({"applicationId": "checklistdd", "instanceId": "service-checklist"}).encode(),
            headers={"Content-Type": "application/json", "Cookie": cookie},
            method="POST",
        )
        try:
            urlopen(unsafe_request)
        except HTTPError as error:
            assert error.code == 403
            assert json.loads(error.read())["error"]["code"] == "application_install_denied"
        else:
            raise AssertionError("legacy install without origin, CSRF, or exact package identity succeeded")

        catalog = get("/v1/applications")["result"]["applications"]
        checklist = next(item for item in catalog if item["applicationId"] == "checklistdd")
        installed = post(
            "/v1/application-fixtures/install",
            {
                "applicationId": "checklistdd",
                "instanceId": "service-checklist",
                "name": "ChecklistState",
                "applicationDescriptorDigest": checklist["applicationIdentity"]["descriptorDigest"],
                "applicationPackageDigest": checklist["applicationIdentity"]["packageDigest"],
                "experienceDescriptorDigest": checklist["experienceIdentity"]["descriptorDigest"],
            },
        )
        assert installed["ok"] is True
        assert installed["result"]["receipt"]["formatVersion"] == "stateport.application-install-receipt/v1"
        request = Request(f"http://127.0.0.1:{port}/v1/instances/service-checklist/actions", headers={"Cookie": cookie})
        with urlopen(request) as response:
            actions = json.loads(response.read())
        assert {item["actionId"] for item in actions["result"]["actions"]} == {"checklistdd.plan-next-item/v1", "checklistdd.complete-item/v1"}
        prepared = post("/v1/instances/service-checklist/execution/prepare", {"expectedInstanceId": "service-checklist", "actionId": "checklistdd.complete-item/v1", "engineId": "synthetic", "inputs": {"itemId": "first-item"}})
        run_id = prepared["result"]["run"]["runId"]
        revision = prepared["result"]["run"]["revision"]
        run_spec_digest = prepared["result"]["run"]["runSpecDigest"]
        fresh_index = get("/v1/approvals")["result"]
        assert fresh_index["formatVersion"] == "stateport.approval-index/v1"
        run_request = next(item for item in fresh_index["approvals"] if item.get("runId") == run_id)
        assert run_request["kind"] == "orchestration_run"
        assert run_request["planDigest"] == run_spec_digest
        assert run_request["decision"] == {
            "kind": "run_approval",
            "expectedInstanceId": "service-checklist",
            "expectedRevision": revision,
            "expectedDigest": run_spec_digest,
        }
        approved = post(f"/v1/runs/{run_id}/approve", {"expectedInstanceId": "service-checklist", "expectedRevision": revision})
        approved_revision = approved["result"]["revision"]
        assert approved_revision > revision
        assert all(
            item.get("runId") != run_id
            for item in get("/v1/approvals")["result"]["approvals"]
        )
        stale_status, stale = rejected_post(
            f"/v1/runs/{run_id}/approve",
            {"expectedInstanceId": "service-checklist", "expectedRevision": revision},
        )
        assert stale_status == 400 and stale["error"]["code"] == "operation_failed"
        wrong_status, wrong = rejected_post(
            f"/v1/runs/{run_id}/execute",
            {"expectedInstanceId": "different-instance", "expectedRevision": approved_revision},
        )
        assert wrong_status == 400 and wrong["error"]["code"] == "operation_failed"
        observed = get(f"/v1/runs/{run_id}")["result"]["run"]
        assert observed["status"] == "approved"
        assert observed["revision"] == approved_revision
        revision = approved_revision
        executed = post(f"/v1/runs/{run_id}/execute", {"expectedInstanceId": "service-checklist", "expectedRevision": revision})
        assert executed["result"]["run"]["status"] == "state_change_proposed"
        next_revision = executed["result"]["run"]["revision"]
        assert next_revision > revision
        revision = next_revision
        proposal_digest = executed["result"]["run"]["proposalDigest"]
        proposal_request = next(
            item
            for item in get("/v1/approvals")["result"]["approvals"]
            if item.get("runId") == run_id
        )
        assert proposal_request["planDigest"] == proposal_digest
        assert proposal_request["decision"] == {
            "kind": "run_proposal",
            "expectedInstanceId": "service-checklist",
            "expectedRevision": revision,
            "expectedDigest": proposal_digest,
        }
        proposal_approved = post(f"/v1/runs/{run_id}/proposal-approve", {"expectedInstanceId": "service-checklist", "expectedRevision": revision})
        revision = proposal_approved["result"]["revision"]
        assert all(
            item.get("runId") != run_id
            for item in get("/v1/approvals")["result"]["approvals"]
        )
        applied = post(f"/v1/runs/{run_id}/apply", {"expectedInstanceId": "service-checklist", "expectedRevision": revision})
        assert applied["result"]["run"]["status"] == "applied"
        closure_receipt = applied["result"]["run"]["closureReceipt"]
        receipt_id = closure_receipt["receiptId"]
        assert applied["result"]["run"]["receiptId"] == receipt_id
        assert closure_receipt["runId"] == run_id
        assert closure_receipt["instanceId"] == "service-checklist"
        assert closure_receipt["applicationId"] == "checklistdd"
        assert closure_receipt["proposalDigest"] == proposal_digest
        assert closure_receipt["canonicalStateAfter"] == applied["result"]["run"]["canonicalStateAfter"]
        assert closure_receipt["validation"]["state"] == "validated"
        assert closure_receipt["claimState"] == {
            "applied": True,
            "locallyValidated": True,
            "humanAccepted": False,
            "remotelyAccepted": False,
        }
        receipts = get("/v1/instances/service-checklist/receipts")["result"]
        indexed = next(item for item in receipts["receipts"] if item["receiptId"] == receipt_id)
        assert indexed["status"] == "applied"
        assert indexed["sourceKind"] == "governed_run"
        detail = get(
            f"/v1/instances/service-checklist/receipts/{receipt_id}"
        )["result"]["receipt"]
        assert detail["payload"] == closure_receipt
        assert detail["payloadDigest"].startswith("sha256:")
        bundle = get(f"/v1/runs/{run_id}/bundle")
        assert bundle["result"]["applied"] is True
        assert (
            bundle["result"]["bundle"]["contentDigest"]
            == closure_receipt["appliedRunBundleDigest"]
        )
        assert bundle["result"]["verification"]["verified"] is True
        statebench = get(f"/v1/runs/{run_id}/statebench")
        assert statebench["result"]["applied"] is True
        assert statebench["result"]["row"]["applicationId"] == "checklistdd"
    finally:
        app.service_stop()
