#!/usr/bin/env python3
"""Route-level tests for the web platform service surface (Stream B2 MS2).

Covers /v1/deployments, /v1/authority, and /v1/updater over the real web
AppServer with a fake Podman adapter and fixture authority/updater state —
no containers, no network.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import threading
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = Path(__file__).resolve().parent
for candidate in (SCRIPTS,):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))
for source_root in sorted((ROOT / "packages").glob("*/src")):
    sys.path.insert(0, str(source_root))
for source_root in sorted((ROOT / "apps").glob("*/src")):
    sys.path.insert(0, str(source_root))

from governed_runner.authority import AuthorityManager, grant_template  # noqa: E402
from stateport_deployment import DeploymentService  # noqa: E402
from stateport_persistent_app import LocalLayout  # noqa: E402
from stateport_persistent_app.service_process import AppServer  # noqa: E402

from service_test_product import service_product_fixture  # noqa: E402
from test_container_deployment import FakeAdapter, _git, committed_fixture  # noqa: E402
from test_deployment_lifecycle import FakeUpdateAdapter  # noqa: E402
from test_stateport_updater import initialized_engine, planned  # noqa: E402
from test_stateport_updater_installed import (  # noqa: E402
    adapter_engine,
    binding,
    inject,
)


ACTOR = "local-user"
SLICE_ID = "SLICE-WEB-TEST-001"
GRANT_ID = "grant_web_test_001"
DEPLOYMENT_ACTIONS = (
    "inspect_repository",
    "plan_deployment",
    "apply_deployment",
    "observe_deployment",
    "collect_deployment_logs",
    "restart_deployment",
    "remove_deployment_runtime",
    "backup_deployment_data",
    "restore_deployment_data",
    "purge_deployment_data",
)


def _request(
    port: int,
    path: str,
    *,
    method: str = "GET",
    cookie: str | None = None,
    csrf: str | None = None,
    origin: str | None = None,
    body: dict[str, object] | None = None,
) -> tuple[int, dict[str, object]]:
    headers: dict[str, str] = {}
    if cookie is not None:
        headers["Cookie"] = cookie
    if origin is not None:
        headers["Origin"] = origin
    if csrf is not None:
        headers["X-StatePort-CSRF"] = csrf
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode("utf-8")
    request = Request(
        f"http://127.0.0.1:{port}{path}", data=data, headers=headers, method=method
    )
    try:
        with urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except HTTPError as error:
        return error.code, json.loads(error.read())


class WebHarness:
    def __init__(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        *,
        adapter: FakeAdapter | None = None,
        preview_gateway: bool = False,
        actor_role: str = "platform_operator",
    ) -> None:
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
        monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
        monkeypatch.setenv("STATEPORT_DEPLOYMENT_PROJECT_ROOT", str(tmp_path))
        layout = LocalLayout.from_environment()
        layout.initialize()
        if actor_role == "platform_operator":
            boundary = layout.config_root / "platform-operator-authority"
            boundary.write_text("test operator boundary\n", encoding="utf-8")
            boundary.chmod(0o600)
        product_root = service_product_fixture(tmp_path, ROOT)
        self.server = AppServer(
            ("127.0.0.1", 0),
            layout,
            product_root / "apps" / "web",
            actor_role=actor_role,
        )
        # Same-origin previews stay disabled unless a test fixture opts in
        # explicitly; production services never set this attribute.
        self.server._preview_gateway_enabled = preview_gateway
        self.manager = AuthorityManager(
            product_root, state_root=tmp_path / "authority"
        )
        self.server._authority_manager = self.manager
        self.deployment_service = DeploymentService(
            state_root=None,
            adapter=adapter if adapter is not None else FakeAdapter(),
            authority_manager=self.manager,
            actor=self.server.actor_id,
        )
        self.server._deployment_service = self.deployment_service
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            kwargs={"poll_interval": 0.02},
            daemon=True,
        )
        self.thread.start()
        self.port = int(self.server.server_address[1])
        self.origin = f"http://127.0.0.1:{self.port}"
        with urlopen(f"{self.origin}/session", timeout=10) as response:
            session = json.loads(response.read())["result"]
            self.cookie = response.headers["Set-Cookie"].split(";", 1)[0]
        self.csrf = str(session["csrfToken"])

    def close(self) -> None:
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()

    def get(self, path: str) -> tuple[int, dict[str, object]]:
        return _request(self.port, path, cookie=self.cookie)

    def post(
        self, path: str, body: dict[str, object]
    ) -> tuple[int, dict[str, object]]:
        return _request(
            self.port,
            path,
            method="POST",
            cookie=self.cookie,
            csrf=self.csrf,
            origin=self.origin,
            body=body,
        )

    def grant(self, deployment_id: str, project: Path | None = None) -> str:
        from stateport_deployment.inspection import (  # noqa: PLC0415
            authority_source_identity,
            inspect_project,
        )

        deployment_sources = None
        if project is not None:
            identity = authority_source_identity(inspect_project(project))
            deployment_sources = [
                {
                    key: identity[key]
                    for key in ("repositoryIdentity", "projectPath")
                }
            ]
        grant = grant_template(
            self.manager,
            grant_id=GRANT_ID,
            profile="balanced",
            actor_id=self.server.actor_id,
            role="primary",
            branch_pattern="main",
            slice_id=None,
            application_id=deployment_id,
            run_id=None,
            paths=(".",),
            allow=DEPLOYMENT_ACTIONS,
            require_approval=(),
            forbid=(),
            owner_directive_id="OD-WEB-TEST-001",
            expires_when="timestamp",
            expires_at="2099-01-01T00:00:00Z",
            max_actions=100,
            max_duration_seconds=7200,
            max_cost_usd=0,
            deployment_sources=deployment_sources,
        )
        self.manager.activate_grant(grant, owner_actor_id="test-owner")
        return GRANT_ID

    def approval(self, digest: str) -> dict[str, object]:
        return {"decision": "approve", "actorId": self.server.actor_id, "proposalDigest": digest}


@pytest.fixture
def platform_harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> WebHarness:
    selected = WebHarness(tmp_path, monkeypatch, actor_role="platform_operator")
    try:
        yield selected
    finally:
        selected.close()


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> WebHarness:
    selected = WebHarness(tmp_path, monkeypatch)
    try:
        yield selected
    finally:
        selected.close()


@pytest.fixture
def local_user_harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> WebHarness:
    selected = WebHarness(tmp_path, monkeypatch, actor_role="local_user")
    try:
        yield selected
    finally:
        selected.close()


def test_deployment_index_requires_session_and_starts_empty(
    harness: WebHarness,
) -> None:
    status, payload = _request(harness.port, "/v1/deployments")
    assert status == 401
    assert payload["error"]["code"] == "session_required"

    status, payload = harness.get("/v1/deployments")
    assert status == 200
    assert payload["result"] == {
        "formatVersion": "stateport.deployment-index/v1",
        "deployments": [],
    }

    status, payload = harness.get("/v1/deployments/deployment-missing")
    assert status == 404
    assert payload["error"]["code"] == "deployment_not_found"


def test_deployment_plan_refuses_a_project_outside_the_owned_inbox(
    harness: WebHarness,
) -> None:
    status, payload = harness.post(
        "/v1/deployments/plan",
        {
            "project": "/etc",
            "deploymentId": "deployment-unsafe-path",
            "grantId": "grant_unsafe_path_test",
        },
    )

    assert status == 409
    assert payload["error"]["code"] == "unsafe_path"
    assert harness.get("/v1/deployments")[1]["result"]["deployments"] == []


def test_deployment_plan_apply_observe_logs_restart_remove_over_http(
    harness: WebHarness, tmp_path: Path
) -> None:
    project = committed_fixture(tmp_path, "python-http")
    deployment_id = "deployment-python-http"
    grant_id = harness.grant(deployment_id, project)

    status, payload = harness.post(
        "/v1/deployments/plan",
        {"project": str(project), "deploymentId": deployment_id, "grantId": grant_id},
    )
    assert status == 200, payload
    plan = payload["result"]
    digest = plan["planDigest"]
    assert plan["operation"] == "apply"
    assert payload["result"]["authorityReceipt"]["result"]["status"] == "succeeded"

    status, payload = harness.post(
        f"/v1/deployments/{deployment_id}/apply",
        {
            "acceptPlanDigest": digest,
            "grantId": grant_id,
            "approval": harness.approval("sha256:" + "0" * 64),
        },
    )
    assert status == 409
    assert payload["error"]["code"] == "approval_digest_mismatch"

    status, payload = harness.post(
        f"/v1/deployments/{deployment_id}/apply",
        {
            "acceptPlanDigest": digest,
            "grantId": grant_id,
            "approval": harness.approval(digest),
        },
    )
    assert status == 200, payload
    assert payload["result"]["state"]["lifecycleState"] == "healthy"

    status, payload = harness.get("/v1/deployments")
    assert status == 200
    summaries = payload["result"]["deployments"]
    assert [item["deploymentId"] for item in summaries] == [deployment_id]
    assert summaries[0]["lifecycleState"] == "healthy"

    status, payload = harness.get(f"/v1/deployments/{deployment_id}")
    assert status == 200
    assert payload["result"]["state"]["acceptedRevision"] == digest

    status, payload = harness.post(
        f"/v1/deployments/{deployment_id}/status", {"grantId": grant_id}
    )
    assert status == 200, payload
    assert payload["result"]["state"]["driftStatus"] == "in_sync"
    assert payload["result"]["observation"]["drift"] == []

    status, payload = harness.post(
        f"/v1/deployments/{deployment_id}/logs",
        {"grantId": grant_id, "serviceId": "web", "tail": 50},
    )
    assert status == 200, payload
    assert payload["result"]["deploymentId"] == deployment_id
    assert "web" in payload["result"]["logs"]
    assert payload["result"]["authorityReceipt"]["action"] == "collect_deployment_logs"
    assert payload["result"]["authorityReceipt"]["result"]["status"] == "succeeded"

    restart_digest = harness.deployment_service.peek_authority_run_id(
        deployment_id, "restart_deployment"
    )
    status, payload = harness.post(
        f"/v1/deployments/{deployment_id}/restart",
        {"grantId": grant_id, "approval": harness.approval(restart_digest)},
    )
    assert status == 200, payload
    assert payload["result"]["state"]["lifecycleState"] == "healthy"

    remove_digest = harness.deployment_service.peek_authority_run_id(
        deployment_id, "remove_deployment_runtime"
    )
    status, payload = harness.post(
        f"/v1/deployments/{deployment_id}/remove",
        {"grantId": grant_id, "approval": harness.approval(remove_digest)},
    )
    assert status == 200, payload
    assert payload["result"]["state"]["lifecycleState"] == "removed_runtime_data_retained"



def test_deployment_purge_plan_and_apply_over_http(
    harness: WebHarness, tmp_path: Path
) -> None:
    project = committed_fixture(tmp_path, "persistent-multi")
    deployment_id = "deployment-persistent-multi"
    grant_id = harness.grant(deployment_id, project)

    status, payload = harness.post(
        "/v1/deployments/plan",
        {"project": str(project), "deploymentId": deployment_id, "grantId": grant_id},
    )
    assert status == 200, payload
    digest = payload["result"]["planDigest"]
    status, payload = harness.post(
        f"/v1/deployments/{deployment_id}/apply",
        {
            "acceptPlanDigest": digest,
            "grantId": grant_id,
            "approval": harness.approval(digest),
        },
    )
    assert status == 200, payload
    assert payload["result"]["state"]["lifecycleState"] == "healthy"

    remove_digest = harness.deployment_service.peek_authority_run_id(
        deployment_id, "remove_deployment_runtime"
    )
    status, payload = harness.post(
        f"/v1/deployments/{deployment_id}/remove",
        {"grantId": grant_id, "approval": harness.approval(remove_digest)},
    )
    assert status == 200, payload
    assert payload["result"]["state"]["lifecycleState"] == "removed_runtime_data_retained"

    status, payload = harness.post(
        f"/v1/deployments/{deployment_id}/purge/plan", {"grantId": grant_id}
    )
    assert status == 200, payload
    purge_plan = payload["result"]
    assert purge_plan["operation"] == "purge_data"

    status, payload = harness.post(
        f"/v1/deployments/{deployment_id}/apply",
        {
            "acceptPlanDigest": purge_plan["planDigest"],
            "grantId": grant_id,
            "approval": harness.approval(purge_plan["planDigest"]),
        },
    )
    assert status == 200, payload
    assert payload["result"]["state"]["lifecycleState"] == "purged"


def test_deployment_backup_and_restore_over_http(
    harness: WebHarness, tmp_path: Path
) -> None:
    project = committed_fixture(tmp_path, "persistent-multi")
    deployment_id = "deployment-persistent-multi"
    grant_id = harness.grant(deployment_id, project)
    adapter = harness.deployment_service.adapter

    status, payload = harness.post(
        "/v1/deployments/plan",
        {
            "project": str(project),
            "deploymentId": deployment_id,
            "grantId": grant_id,
        },
    )
    assert status == 200, payload
    initial_digest = payload["result"]["planDigest"]
    status, payload = harness.post(
        f"/v1/deployments/{deployment_id}/apply",
        {
            "acceptPlanDigest": initial_digest,
            "grantId": grant_id,
            "approval": harness.approval(initial_digest),
        },
    )
    assert status == 200, payload
    adapter.volume_data["app-data"] = "durable-http-value"

    status, payload = harness.post(
        f"/v1/deployments/{deployment_id}/backup/plan",
        {"grantId": grant_id},
    )
    assert status == 200, payload
    backup_plan = payload["result"]
    assert backup_plan["operation"] == "backup_data"
    status, payload = harness.post(
        f"/v1/deployments/{deployment_id}/apply",
        {
            "acceptPlanDigest": backup_plan["planDigest"],
            "grantId": grant_id,
            "approval": harness.approval(backup_plan["planDigest"]),
        },
    )
    assert status == 200, payload
    backup = payload["result"]["backup"]
    assert backup["status"] == "available"

    status, payload = harness.post(
        f"/v1/deployments/{deployment_id}/status", {"grantId": grant_id}
    )
    assert status == 200, payload
    assert payload["result"]["state"]["driftStatus"] == "in_sync"

    adapter.volume_data["app-data"] = "mutated-http-value"
    status, payload = harness.post(
        f"/v1/deployments/{deployment_id}/restore/plan",
        {"backupId": backup["backupId"], "grantId": grant_id},
    )
    assert status == 200, payload
    restore_plan = payload["result"]
    assert restore_plan["operation"] == "restore_data"
    assert restore_plan["backupDigest"] == backup["backupDigest"]
    status, payload = harness.post(
        f"/v1/deployments/{deployment_id}/apply",
        {
            "acceptPlanDigest": restore_plan["planDigest"],
            "grantId": grant_id,
            "approval": harness.approval(restore_plan["planDigest"]),
        },
    )
    assert status == 200, payload
    assert adapter.volume_data["app-data"] == "durable-http-value"
    assert payload["result"]["backup"]["status"] == "restored_consumed"
    assert payload["result"]["state"]["lifecycleState"] == "healthy"


def test_deployment_update_and_rollback_over_http(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = FakeUpdateAdapter()
    harness = WebHarness(tmp_path, monkeypatch, adapter=adapter)
    try:
        project = committed_fixture(tmp_path, "python-http")
        deployment_id = "deployment-python-http"
        grant_id = harness.grant(deployment_id, project)

        status, payload = harness.post(
            "/v1/deployments/plan",
            {
                "project": str(project),
                "deploymentId": deployment_id,
                "grantId": grant_id,
            },
        )
        assert status == 200, payload
        first_digest = payload["result"]["planDigest"]
        first_commit = payload["result"]["spec"]["source"]["commit"]
        status, payload = harness.post(
            f"/v1/deployments/{deployment_id}/apply",
            {
                "acceptPlanDigest": first_digest,
                "grantId": grant_id,
                "approval": harness.approval(first_digest),
            },
        )
        assert status == 200, payload

        (project / "app.py").write_text(
            (project / "app.py").read_text(encoding="utf-8") + "\n# revision two\n",
            encoding="utf-8",
        )
        _git("add", ".", cwd=project)
        _git("commit", "-m", "revision two", cwd=project)

        status, payload = harness.post(
            "/v1/deployments/plan",
            {
                "project": str(project),
                "deploymentId": deployment_id,
                "grantId": grant_id,
            },
        )
        assert status == 200, payload
        update_plan = payload["result"]
        assert update_plan["operation"] == "update"
        assert update_plan["supersedes"] == first_digest

        calls_before_rejection = list(adapter.calls)
        status, payload = harness.post(
            f"/v1/deployments/{deployment_id}/reject",
            {"planDigest": update_plan["planDigest"], "grantId": grant_id},
        )
        assert status == 200, payload
        rejected = payload["result"]
        assert rejected["state"]["lifecycleState"] == "healthy"
        assert rejected["state"]["acceptedRevision"] == first_digest
        assert rejected["state"]["desiredRevision"] == first_digest
        assert rejected["receipt"]["event"] == "proposal_rejected"
        assert rejected["receipt"]["data"]["runtimeMutation"] is False
        assert adapter.calls == calls_before_rejection

        status, payload = harness.post(
            "/v1/deployments/plan",
            {
                "project": str(project),
                "deploymentId": deployment_id,
                "grantId": grant_id,
            },
        )
        assert status == 200, payload
        update_plan = payload["result"]
        assert update_plan["operation"] == "update"

        status, payload = harness.post(
            f"/v1/deployments/{deployment_id}/apply",
            {
                "acceptPlanDigest": update_plan["planDigest"],
                "grantId": grant_id,
                "approval": harness.approval(update_plan["planDigest"]),
            },
        )
        assert status == 200, payload
        state = payload["result"]["state"]
        assert state["lifecycleState"] == "healthy"
        assert state["acceptedRevision"] == update_plan["planDigest"]

        # A rollback plan restores the exact named revision, so the source is
        # checked out at that revision before planning.
        _git("checkout", first_commit, cwd=project)
        status, payload = harness.post(
            "/v1/deployments/plan",
            {
                "project": str(project),
                "deploymentId": deployment_id,
                "grantId": grant_id,
                "rollbackOf": first_digest,
            },
        )
        assert status == 200, payload
        rollback_plan = payload["result"]
        assert rollback_plan["operation"] == "rollback"
        assert rollback_plan["rollbackOf"] == first_digest

        status, payload = harness.post(
            f"/v1/deployments/{deployment_id}/apply",
            {
                "acceptPlanDigest": rollback_plan["planDigest"],
                "grantId": grant_id,
                "approval": harness.approval(rollback_plan["planDigest"]),
            },
        )
        assert status == 200, payload
        state = payload["result"]["state"]
        assert state["lifecycleState"] == "healthy"
        assert state["acceptedRevision"] == rollback_plan["planDigest"]
    finally:
        harness.close()


def test_authority_profiles_grants_pause_and_revoke_over_http(
    platform_harness: WebHarness, tmp_path: Path
) -> None:
    harness = platform_harness
    project = committed_fixture(tmp_path, "python-http")
    grant_id = harness.grant("deployment-python-http", project)

    status, payload = harness.get("/v1/authority/profiles")
    assert status == 200
    profiles = payload["result"]
    assert profiles["schema"] == "stateport.authority-policy/v1"
    assert profiles["defaultProfile"] == "balanced"
    assert profiles["policyDigest"].startswith("sha256:")
    assert set(profiles["profiles"]) == {"guarded", "balanced", "delegated", "custom"}
    assert "apply_deployment" in profiles["actionPolicies"]

    status, payload = harness.get("/v1/authority/grants")
    assert status == 200
    inspection = payload["result"]
    assert inspection["control"]["paused"] is False
    assert inspection["paused"] is False
    assert inspection["grants"][0]["grantDigest"].startswith("sha256:")
    assert [item["grantId"] for item in inspection["activeGrants"]] == [grant_id]
    assert inspection["activeGrants"][0]["grantDigest"].startswith("sha256:")

    status, payload = harness.get("/v1/authority/index")
    assert status == 200
    authority_index = payload["result"]
    assert authority_index["schema"] == "stateport.authority-index/v1"
    assert [item["grantId"] for item in authority_index["activeGrants"]] == [grant_id]
    assert authority_index["inactiveGrants"] == []
    assert authority_index["revisions"]["controlRevision"] == 0
    assert authority_index["reviewableDigests"]["grantDigests"][grant_id].startswith("sha256:")

    status, payload = harness.get(f"/v1/authority/grants/{grant_id}")
    assert status == 200
    grant = payload["result"]["grant"]
    assert grant["status"] == "active"
    grant_digest = grant["grantDigest"]
    assert grant_digest.startswith("sha256:")

    status, payload = harness.post(
        "/v1/authority/pause",
        {"paused": True, "ownerDirectiveId": "OD-WEB-TEST-MISSING-CONTROL", "reason": "missing digest"},
    )
    assert status == 400
    assert payload["error"]["code"] == "operation_failed"

    status, payload = harness.post(
        "/v1/authority/pause",
        {
            "paused": True,
            "ownerDirectiveId": "OD-WEB-TEST-MALFORMED-CONTROL",
            "reason": "malformed digest",
            "controlDigest": "not-a-sha256-digest",
            "approval": harness.approval("not-a-sha256-digest"),
        },
    )
    assert status == 409
    assert payload["error"]["code"] == "invalid_contract"

    status, payload = harness.get("/v1/authority/grants/grant_missing")
    assert status == 404
    assert payload["error"]["code"] == "grant_not_found"

    status, payload = harness.post(
        "/v1/authority/pause",
        {
            "paused": True,
            "ownerDirectiveId": "OD-WEB-TEST-PAUSE",
            "reason": "operator safety pause",
            "controlDigest": inspection["control"]["controlDigest"],
            "approval": harness.approval(inspection["control"]["controlDigest"]),
        },
    )
    assert status == 200, payload
    assert payload["result"]["receipt"]["receiptId"].startswith("authority_receipt_")
    status, payload = harness.get("/v1/authority/grants")
    assert payload["result"]["control"]["paused"] is True
    control_digest = payload["result"]["control"]["controlDigest"]

    status, payload = harness.post(
        "/v1/authority/pause",
        {
            "paused": False,
            "ownerDirectiveId": "OD-WEB-TEST-STALE",
            "reason": "stale resume",
            "controlDigest": control_digest,
            "approval": {"decision": "approve", "actorId": harness.server.actor_id},
        },
    )
    assert status == 409
    assert payload["error"]["code"] == "approval_required"

    status, payload = harness.post(
        "/v1/authority/pause",
        {
            "paused": False,
            "ownerDirectiveId": "OD-WEB-TEST-STALE",
            "reason": "stale resume",
            "controlDigest": inspection["control"]["controlDigest"],
            "approval": harness.approval(inspection["control"]["controlDigest"]),
        },
    )
    assert status == 409
    assert payload["error"]["code"] == "authority_digest_mismatch"

    status, payload = harness.post(
        "/v1/deployments/plan",
        {
            "project": str(project),
            "deploymentId": "deployment-python-http",
            "grantId": grant_id,
        },
    )
    assert status == 409
    assert payload["error"]["code"] == "authority_refused"

    status, payload = harness.post(
        "/v1/authority/pause",
        {
            "paused": False,
            "ownerDirectiveId": "OD-WEB-TEST-PAUSE",
            "reason": "operator resumed",
            "controlDigest": control_digest,
            "approval": harness.approval(control_digest),
        },
    )
    assert status == 200, payload
    status, payload = harness.get("/v1/authority/grants")
    assert payload["result"]["control"]["paused"] is False

    status, payload = harness.post(
        "/v1/authority/pause",
        {
            "paused": False,
            "ownerDirectiveId": "OD-WEB-TEST-REDUNDANT",
            "reason": "redundant resume",
            "controlDigest": payload["result"]["control"]["controlDigest"],
            "approval": harness.approval(payload["result"]["control"]["controlDigest"]),
        },
    )
    assert status == 409
    assert payload["error"]["code"] == "authority_state_unchanged"

    stale_grant_digest = "sha256:" + "f" * 64
    status, payload = harness.post(
        f"/v1/authority/grants/{grant_id}/revoke",
        {
            "ownerDirectiveId": "OD-WEB-TEST-STALE-GRANT",
            "reason": "stale grant review",
            "grantDigest": stale_grant_digest,
            "approval": harness.approval(stale_grant_digest),
        },
    )
    assert status == 409
    assert payload["error"]["code"] == "authority_digest_mismatch"

    status, payload = harness.post(
        f"/v1/authority/grants/{grant_id}/revoke",
        {
            "ownerDirectiveId": "OD-WEB-TEST-MISSING-GRANT",
            "reason": "missing digest",
            "approval": harness.approval(grant_digest),
        },
    )
    assert status == 400
    assert payload["error"]["code"] == "operation_failed"

    status, payload = harness.post(
        f"/v1/authority/grants/{grant_id}/revoke",
        {
            "ownerDirectiveId": "OD-WEB-TEST-REVOKE",
            "reason": "test complete",
            "grantDigest": grant_digest,
            "approval": harness.approval(grant_digest),
        },
    )
    assert status == 200, payload
    assert payload["result"]["receiptId"].startswith("authority_receipt_")
    assert payload["result"]["receiptDigest"].startswith("sha256:")
    status, payload = harness.get(f"/v1/authority/grants/{grant_id}")
    assert payload["result"]["grant"]["status"] == "revoked"
    status, payload = harness.get("/v1/authority/index")
    assert status == 200
    assert payload["result"]["activeGrants"] == []
    assert payload["result"]["inactiveGrants"][0]["grantDigest"] == grant_digest


def test_updater_status_policy_and_rollback_over_http(
    harness: WebHarness, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _updater, host, _authority, successor, _document = initialized_engine(tmp_path)
    inject(tmp_path)
    engine, adapter = adapter_engine(tmp_path, host)
    update_plan = engine.plan(successor)
    engine.apply(update_plan["planId"], adapter.reserve(update_plan))
    updater_root = tmp_path / "updater"
    monkeypatch.setenv("STATEPORT_UPDATER_STATE_ROOT", str(updater_root))

    status, payload = harness.get("/v1/updater/status")
    assert status == 200, payload
    assert payload["result"]["schema"] == "stateport.update-status/v1"
    assert payload["result"]["phase"] == "accepted"

    status, payload = harness.get("/v1/updater/policy")
    assert status == 200
    policy = payload["result"]
    assert policy["policy"]["mode"] == "download-and-notify"
    status_digest = policy["statusDigest"]
    assert status_digest.startswith("sha256:")

    # Policy mutation first, while the accepted status digest is current.
    status, payload = harness.post(
        "/v1/updater/policy",
        {
            "policy": {
                "mode": "manual",
                "channel": "alpha",
                "schedule": None,
                "retention": policy["policy"]["retention"],
                "downloadAhead": False,
            },
            "expectedStatusDigest": status_digest,
            "approval": harness.approval(status_digest),
        },
    )
    assert status == 200, payload
    assert payload["result"]["receipt"]["action"] == "modify_update_policy"
    assert payload["result"]["receipt"]["result"]["status"] == "succeeded"
    status, payload = harness.get("/v1/updater/policy")
    assert payload["result"]["policy"]["mode"] == "manual"
    status_digest = payload["result"]["statusDigest"]

    # A stale digest is refused before any mutation is attempted.
    status, payload = harness.post(
        "/v1/updater/policy",
        {
            "policy": payload["result"]["policy"],
            "expectedStatusDigest": "sha256:" + "0" * 64,
            "approval": harness.approval("sha256:" + "0" * 64),
        },
    )
    assert status == 409
    assert payload["error"]["code"] == "approval_digest_mismatch"

    status, payload = harness.get("/v1/updater/rollback")
    assert status == 200
    rollback = payload["result"]
    assert rollback["retainedPredecessor"]["releaseId"].endswith("0.1.0-rc.1")
    assert rollback["rollbackAvailable"] is True

    status, payload = harness.post(
        "/v1/updater/rollback",
        {
            "expectedStatusDigest": status_digest,
            "approval": harness.approval(status_digest),
        },
    )
    assert status == 409
    assert payload["error"]["code"] == "control_plane_trust_invalid"

    harness.server._updater_control_plane = binding(host)
    status, payload = harness.post(
        "/v1/updater/rollback",
        {
            "expectedStatusDigest": status_digest,
            "approval": harness.approval(status_digest),
        },
    )
    assert status == 200, payload
    assert payload["result"]["plan"]["operation"] == "rollback"
    assert payload["result"]["applyBoundary"] == "installed-authority-cli"


def test_updater_routes_are_typed_when_state_is_absent(harness: WebHarness) -> None:
    status, payload = harness.get("/v1/updater/status")
    assert status == 409
    assert payload["error"]["code"] == "updater_state_unavailable"
    status, payload = harness.get("/v1/updater/policy")
    assert status == 409
    status, payload = harness.get("/v1/updater/rollback")
    assert status == 409


def test_platform_mutations_require_csrf_origin_and_session(
    harness: WebHarness, tmp_path: Path
) -> None:
    project = committed_fixture(tmp_path, "python-http")
    deployment_id = "deployment-python-http"
    grant_id = harness.grant(deployment_id, project)
    body = {"project": str(project), "deploymentId": deployment_id, "grantId": grant_id}

    status, _payload = _request(harness.port, "/v1/deployments/plan", method="POST", body=body)
    assert status == 401

    status, payload = _request(
        harness.port,
        "/v1/deployments/plan",
        method="POST",
        cookie=harness.cookie,
        origin=harness.origin,
        body=body,
    )
    assert status == 403
    assert payload["error"]["code"] == "deployment_access_denied"

    status, payload = _request(
        harness.port,
        "/v1/deployments/plan",
        method="POST",
        cookie=harness.cookie,
        csrf=harness.csrf,
        origin="https://attacker.example",
        body=body,
    )
    assert status == 403
    assert payload["error"]["code"] == "deployment_access_denied"


def test_local_user_cannot_read_authority_index_or_mutate_authority_with_csrf(
    local_user_harness: WebHarness, tmp_path: Path
) -> None:
    harness = local_user_harness
    project = committed_fixture(tmp_path, "python-http")
    grant_id = harness.grant("deployment-python-http", project)
    grant = harness.manager.get_grant(grant_id)
    control_digest = harness.manager.inspect()["control"]["controlDigest"]

    for path in (
        "/v1/authority/profiles",
        "/v1/authority/index",
        "/v1/authority/grants",
        f"/v1/authority/grants/{grant_id}",
    ):
        status, payload = harness.get(path)
        assert status == 403
        assert payload["error"]["code"] == "authority_access_denied"

    for path, code in (
        ("/v1/deployments", "deployment_access_denied"),
        ("/v1/deployments/missing", "deployment_access_denied"),
        ("/v1/updater/status", "updater_access_denied"),
        ("/v1/updater/policy", "updater_access_denied"),
        ("/v1/updater/rollback", "updater_access_denied"),
        ("/v1/preview-routes", "preview_route_access_denied"),
        ("/v1/platform/statebench", "platform_operation_denied"),
    ):
        status, payload = harness.get(path)
        assert status == 403
        assert payload["error"]["code"] == code

    for path, code in (
        ("/v1/deployments/plan", "deployment_access_denied"),
        (f"/v1/deployments/{grant_id}/status", "deployment_access_denied"),
        ("/v1/updater/policy", "updater_access_denied"),
        ("/v1/updater/rollback", "updater_access_denied"),
        ("/v1/preview-routes", "preview_route_access_denied"),
        ("/v1/preview-routes/route_any/revoke", "preview_route_access_denied"),
    ):
        status, payload = harness.post(path, {})
        assert status == 403
        assert payload["error"]["code"] == code

    status, payload = harness.post(
        "/v1/authority/pause",
        {
            "paused": True,
            "ownerDirectiveId": "OD-WEB-TEST-LOCAL-PAUSE",
            "reason": "must be denied",
            "controlDigest": control_digest,
        },
    )
    assert status == 403
    assert payload["error"]["code"] == "authority_access_denied"

    status, payload = harness.post(
        f"/v1/authority/grants/{grant_id}/revoke",
        {
            "ownerDirectiveId": "OD-WEB-TEST-LOCAL-REVOKE",
            "reason": "must be denied",
            "grantDigest": grant["grantDigest"],
            "approval": harness.approval(grant["grantDigest"]),
        },
    )
    assert status == 403
    assert payload["error"]["code"] == "authority_access_denied"
    assert harness.manager.get_grant(grant_id)["status"] == "active"


def test_authority_http_controls_stop_real_file_consumer_and_survive_restart(platform_harness: WebHarness):
    """Real manager.execute file effects; no deployment adapter/container calls."""
    from governed_runner.authority import AuthorityRefusal
    harness = platform_harness
    manager = harness.manager
    grants = {}
    for suffix in ('a', 'b'):
        grant = grant_template(manager, grant_id=f'grant_browser_{suffix}', profile='balanced',
            actor_id=ACTOR, role='primary', branch_pattern='main', slice_id=None,
            application_id=None, run_id=None, paths=(f'proof-{suffix}.txt',),
            allow=('edit_scoped_files',), require_approval=(), forbid=(),
            owner_directive_id='OD-BROWSER-AUTHORITY-PROOF', expires_when='timestamp',
            expires_at='2099-01-01T00:00:00Z', max_actions=100,
            max_duration_seconds=7200, max_cost_usd=0)
        grants[suffix] = manager.activate_grant(grant, owner_actor_id='fixture-owner')['grant']

    def consume(suffix, text):
        path = manager.checkout / f'proof-{suffix}.txt'
        return manager.execute('edit_scoped_files', lambda: path.write_text(text),
            actor_id=ACTOR, grant_id=grants[suffix]['grantId'], branch='main', paths=[path.name])

    def pause(paused, reviewed=None):
        control = harness.get('/v1/authority/index')[1]['result']['control']
        digest = reviewed or control['controlDigest']
        return harness.post('/v1/authority/pause', {'paused': paused,
            'ownerDirectiveId': 'OD-BROWSER-AUTHORITY-PROOF', 'reason': 'source service proof',
            'controlDigest': digest, 'approval': harness.approval(digest)})

    for suffix in grants:
        _, receipt = consume(suffix, 'before')
        assert receipt['result']['status'] == 'succeeded'
    initial_control = harness.get('/v1/authority/index')[1]['result']['control']['controlDigest']
    status, paused = pause(True)
    assert status == 200
    assert paused['result']['receipt']['result']['status'] == 'succeeded'
    assert pause(False, initial_control)[0] == 409
    for suffix in grants:
        with pytest.raises(AuthorityRefusal) as refused:
            consume(suffix, 'must not be written')
        assert refused.value.code == 'autonomous_execution_paused'
        assert refused.value.receipt['result']['status'] == 'not_executed'
        assert (manager.checkout / f'proof-{suffix}.txt').read_text() == 'before'
    assert pause(False)[0] == 200
    for suffix in grants:
        consume(suffix, 'unpaused')
    grant_a = grants['a']
    status, revoked = harness.post(f"/v1/authority/grants/{grant_a['grantId']}/revoke", {
        'ownerDirectiveId': 'OD-BROWSER-AUTHORITY-PROOF', 'reason': 'revoke only a',
        'grantDigest': grant_a['grantDigest'], 'approval': harness.approval(grant_a['grantDigest'])})
    assert status == 200
    assert revoked['result']['revokedGrantDigest'] == grant_a['grantDigest']
    with pytest.raises(AuthorityRefusal) as refused:
        consume('a', 'must not be written')
    assert refused.value.code == 'grant_revoked'
    assert (manager.checkout / 'proof-a.txt').read_text() == 'unpaused'
    consume('b', 'independent')
    receipt_files = {path.name: path.read_bytes() for path in manager.receipts_root.glob('*.json')}
    assert receipt_files
    old_server = harness.server
    harness.close()
    manager = AuthorityManager(manager.checkout, state_root=manager.state_root)
    harness.manager = manager
    harness.server = AppServer(('127.0.0.1', 0), old_server.layout,
                              old_server.product_root / 'apps/web', actor_role='platform_operator')
    harness.server._authority_manager = manager
    harness.thread = threading.Thread(target=harness.server.serve_forever, kwargs={'poll_interval': 0.02}, daemon=True)
    harness.thread.start()
    harness.port = int(harness.server.server_address[1])
    harness.origin = f'http://127.0.0.1:{harness.port}'
    with urlopen(harness.origin + '/session', timeout=10) as response:
        harness.cookie = response.headers['Set-Cookie'].split(';', 1)[0]
        harness.csrf = json.loads(response.read())['result']['csrfToken']
    index = harness.get('/v1/authority/index')[1]['result']
    assert [grant['grantId'] for grant in index['activeGrants']] == [grants['b']['grantId']]
    assert index['control']['paused'] is False
    for name, content in receipt_files.items():
        assert (manager.receipts_root / name).read_bytes() == content
    with pytest.raises(AuthorityRefusal) as refused:
        consume('a', 'must not be written after restart')
    assert refused.value.code == 'grant_revoked'
    consume('b', 'after restart')
    assert (manager.checkout / 'proof-a.txt').read_text() == 'unpaused'
    assert (manager.checkout / 'proof-b.txt').read_text() == 'after restart'
