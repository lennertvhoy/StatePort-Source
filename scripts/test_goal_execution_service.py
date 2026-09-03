#!/usr/bin/env python3
"""Real-service proof for one provider-free, independently reviewed CTO slice.

The slice runs against the test-only synthetic backend, which the test opts
into explicitly through dependency injection. Production services never
register that backend: they observe a typed ``goal_backend_unavailable``
refusal instead of a fabricated result.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import sys
import threading
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
for relative in (
    "packages/persistent-app/src",
    "packages/portable-execution/src",
    "packages/application-experience/src",
    "packages/conversation-service/src",
    "packages/context-lifecycle/src",
    "packages/goal-execution/src",
    "packages/file-workspace-broker/src",
    "packages/terminal-broker/src",
    "packages/governed-runner/src",
    "packages/execution-host/src",
    "packages/opencode-adapter/src",
    "packages/container-opencode/src",
    "packages/external-engine-runtime/src",
    "packages/codex-adapter/src",
    "packages/run-bundle/src",
    "packages/sandbox-runtime/src",
    "packages/statebench/src",
    "packages/instance-backup/src",
    "packages/instance-catalog/src",
    "packages/diagnostics/src",
    "packages/statedd-core/src",
    "packages/template-validator/src",
    "apps/runner/src",
):
    sys.path.insert(0, str(ROOT / relative))

import stateport_goal_execution.coordinator as coordinator_module  # noqa: E402
from stateport_goal_execution import GoalContractError, GoalExecutionCoordinator, GovernanceRefusal  # noqa: E402
from stateport_persistent_app import LocalLayout, PersistentApp  # noqa: E402
from stateport_persistent_app.service_process import AppServer  # noqa: E402
from service_test_product import service_product_fixture  # noqa: E402


DIGEST = "sha256:" + "d" * 64


def _git(root: Path, *arguments: str) -> str:
    environment = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_AUTHOR_NAME": "StatePort test",
        "GIT_AUTHOR_EMAIL": "stateport@example.invalid",
        "GIT_COMMITTER_NAME": "StatePort test",
        "GIT_COMMITTER_EMAIL": "stateport@example.invalid",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    result = subprocess.run(
        ("/usr/bin/git", "-C", root, *arguments),
        check=True,
        capture_output=True,
        text=True,
        env=environment,
        timeout=10,
    )
    return result.stdout.strip()


def _repository(path: Path, application_id: str = "stateport.development-reference") -> Path:
    shutil.copytree(ROOT / "fixtures" / "apps" / "synthetic-reference", path)
    for name in ("application.yaml", "actions.yaml"):
        document = yaml.safe_load((path / name).read_text(encoding="utf-8"))
        document["applicationId"] = application_id
        (path / name).write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    _git(path, "init", "--initial-branch=main", "--template=")
    _git(path, "add", "--all")
    _git(path, "-c", "commit.gpgSign=false", "commit", "-m", "provider-free CTO fixture")
    return path.resolve()


def _content_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if not path.is_file() or ".git" in path.relative_to(root).parts:
            continue
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _register(app: PersistentApp, root: Path, instance_id: str, application_id: str) -> None:
    app.catalog.register(
        root,
        instance_id=instance_id,
        name=instance_id,
        source={
            "templateId": application_id,
            "resolvedCommit": _git(root, "rev-parse", "HEAD"),
            "resolvedTree": _git(root, "rev-parse", "HEAD^{tree}"),
            "manifestDigest": DIGEST,
        },
    )


def test_real_service_governs_one_provider_free_slice_and_stops(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    project = _repository(app.layout.instances_root / "development-one")
    study = _repository(app.layout.instances_root / "study-one", "studystate.sample")
    _register(app, project, "development-one", "stateport.development-reference")
    _register(app, study, "study-one", "studystate.sample")
    before = _content_digest(project)
    product_root = service_product_fixture(tmp_path, ROOT)
    server = AppServer(("127.0.0.1", 0), app.layout, product_root / "apps" / "web")
    # Explicit test-only dependency injection: production services keep the
    # synthetic backend unregistered and refuse with goal_backend_unavailable.
    server.goal_execution = GoalExecutionCoordinator(
        record_root=(app.layout.state_root / "goal-execution").resolve(),
        allow_synthetic_backend=True,
    )
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
    )
    thread.start()
    port = int(server.server_address[1])
    try:
        with pytest.raises(HTTPError) as unauthenticated:
            urlopen(f"http://127.0.0.1:{port}/v1/instances/development-one/goal-execution")
        assert unauthenticated.value.code == 401

        with urlopen(f"http://127.0.0.1:{port}/session") as response:
            session = json.loads(response.read())["result"]
            cookie = response.headers["Set-Cookie"].split(";", 1)[0]

        def get(path: str) -> dict[str, object]:
            request = Request(f"http://127.0.0.1:{port}{path}", headers={"Cookie": cookie})
            with urlopen(request) as response:
                return json.loads(response.read())["result"]

        def post(path: str, body: dict[str, object]) -> dict[str, object]:
            request = Request(
                f"http://127.0.0.1:{port}{path}",
                data=json.dumps(body).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Cookie": cookie,
                    "Origin": f"http://127.0.0.1:{port}",
                    "X-StatePort-CSRF": session["csrfToken"],
                },
                method="POST",
            )
            with urlopen(request) as response:
                return json.loads(response.read())["result"]

        with pytest.raises(HTTPError) as capability_denied:
            get("/v1/instances/study-one/goal-execution")
        assert capability_denied.value.code == 403

        view = get("/v1/instances/development-one/goal-execution")
        assert view["state"] == "not_prepared" and view["revision"] == 0
        assert view["mode"] == "advisory"
        assert view["currentIdentity"]["repositoryClean"] is True
        assert view["providerExecution"] is False
        # The test DI backend is labelled as test-only in the typed view.
        assert view["backendAvailability"] == {
            "status": "available",
            "backendId": "fake",
            "testOnly": True,
        }

        missing_csrf = Request(
            f"http://127.0.0.1:{port}/v1/instances/development-one/goal-execution/prepare",
            data=b"{}",
            headers={"Content-Type": "application/json", "Cookie": cookie},
            method="POST",
        )
        with pytest.raises(HTTPError) as csrf_denied:
            urlopen(missing_csrf)
        assert csrf_denied.value.code == 403

        advisory = post(
            "/v1/instances/development-one/goal-execution/prepare",
            {
                "expectedInstanceId": "development-one",
                "expectedRevision": view["revision"],
                "expectedBaseCommit": view["currentIdentity"]["baseCommit"],
                "mode": "advisory",
                "intent": "Continue this project in CTO mode.",
            },
        )
        assert advisory["state"] == "proposal_ready"
        assert advisory["proposal"]["proposalOnly"] is True
        assert advisory["proposal"]["networkUsed"] is False
        assert advisory["slice"]["networkPolicy"] == "disabled"
        assert advisory["delegation"]["implementerActor"] != advisory["delegation"]["reviewerActor"]
        assert all(
            item.get("kind") != "goal_execution"
            for item in get("/v1/approvals")["approvals"]
        )

        with pytest.raises(HTTPError) as advisory_refusal:
            post(
                "/v1/instances/development-one/goal-execution/approve",
                {
                    "expectedInstanceId": "development-one",
                    "expectedRevision": advisory["revision"],
                    "expectedPlanDigest": advisory["slice"]["planDigest"],
                },
            )
        assert advisory_refusal.value.code == 409
        assert json.loads(advisory_refusal.value.read())["error"]["code"] == "mode_does_not_permit_execution"

        off = post(
            "/v1/instances/development-one/goal-execution/prepare",
            {
                "expectedInstanceId": "development-one",
                "expectedRevision": advisory["revision"],
                "expectedBaseCommit": advisory["currentIdentity"]["baseCommit"],
                "mode": "off",
                "intent": "Stop the proposal.",
            },
        )
        assisted = post(
            "/v1/instances/development-one/goal-execution/prepare",
            {
                "expectedInstanceId": "development-one",
                "expectedRevision": off["revision"],
                "expectedBaseCommit": off["currentIdentity"]["baseCommit"],
                "mode": "assisted",
                "intent": "Prepare one bounded provider-free inspection.",
            },
        )
        goal_request = next(
            item
            for item in get("/v1/approvals")["approvals"]
            if item.get("kind") == "goal_execution"
        )
        assert goal_request["instanceId"] == "development-one"
        assert goal_request["planDigest"] == assisted["slice"]["planDigest"]
        assert goal_request["decision"] == {
            "kind": "goal_execution",
            "expectedInstanceId": "development-one",
            "expectedRevision": assisted["revision"],
            "expectedDigest": assisted["slice"]["planDigest"],
        }

        actor_spoof = Request(
            f"http://127.0.0.1:{port}/v1/instances/development-one/goal-execution/approve",
            data=json.dumps({
                "expectedInstanceId": "development-one",
                "expectedRevision": assisted["revision"],
                "expectedPlanDigest": assisted["slice"]["planDigest"],
                "actor": "cto-orchestrator",
            }).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Cookie": cookie,
                "Origin": f"http://127.0.0.1:{port}",
                "X-StatePort-CSRF": session["csrfToken"],
            },
            method="POST",
        )
        with pytest.raises(HTTPError) as spoof_refused:
            urlopen(actor_spoof)
        assert spoof_refused.value.code == 400

        approved = post(
            "/v1/instances/development-one/goal-execution/approve",
            {
                "expectedInstanceId": "development-one",
                "expectedRevision": assisted["revision"],
                "expectedPlanDigest": assisted["slice"]["planDigest"],
            },
        )
        assert approved["state"] == "approved"
        assert approved["approval"]["approverActor"] == "authenticated-local_user-approver"
        assert all(
            item.get("kind") != "goal_execution"
            for item in get("/v1/approvals")["approvals"]
        )

        with pytest.raises(HTTPError) as stale:
            post(
                "/v1/instances/development-one/goal-execution/execute",
                {
                    "expectedInstanceId": "development-one",
                    "expectedRevision": assisted["revision"],
                    "expectedPlanDigest": approved["slice"]["planDigest"],
                },
            )
        assert json.loads(stale.value.read())["error"]["code"] == "revision_stale"

        executed = post(
            "/v1/instances/development-one/goal-execution/execute",
            {
                "expectedInstanceId": "development-one",
                "expectedRevision": approved["revision"],
                "expectedPlanDigest": approved["slice"]["planDigest"],
            },
        )
        assert executed["state"] == "awaiting_independent_review"
        assert executed["executionResult"]["implementerActor"] == "stateport-bounded-inspector"
        assert executed["executionResult"]["usedBudget"] == {"token": 0, "costMinor": 0, "timeSeconds": 1, "steps": 1}

        reviewed = post(
            "/v1/instances/development-one/goal-execution/review",
            {
                "expectedInstanceId": "development-one",
                "expectedRevision": executed["revision"],
                "expectedExecutionResultDigest": executed["executionResult"]["executionResultDigest"],
            },
        )
        assert reviewed["state"] == "independently_reviewed"
        assert reviewed["review"]["reviewerActor"] == "stateport-independent-reviewer"
        assert reviewed["review"]["disposition"] == "accepted"
        before_close_receipts = get("/v1/instances/development-one/receipts")
        assert all(
            item.get("receiptType") != "stateport.goal-execution-receipt/v1"
            for item in before_close_receipts["receipts"]
        )

        closed = post(
            "/v1/instances/development-one/goal-execution/close",
            {
                "expectedInstanceId": "development-one",
                "expectedRevision": reviewed["revision"],
                "expectedReviewDigest": reviewed["review"]["reviewDigest"],
            },
        )
        assert closed["state"] == "closed"
        assert closed["closure"]["decidedBy"] == "stateport-governor"
        assert closed["receipt"]["formatVersion"] == "stateport.goal-execution-receipt/v1"
        assert closed["nextItemAutoStart"] is False
        assert closed["canonicalStateEffect"] == "none"
        receipt_id = closed["receipt"]["receiptId"]
        receipt_index = get("/v1/instances/development-one/receipts")
        indexed = next(
            item for item in receipt_index["receipts"]
            if item["receiptId"] == receipt_id
        )
        assert indexed["receiptType"] == "stateport.goal-execution-receipt/v1"
        assert indexed["action"] == "goal_execution.close"
        assert indexed["status"] == "completed_without_change"
        receipt_detail = get(
            f"/v1/instances/development-one/receipts/{receipt_id}"
        )["receipt"]
        assert receipt_detail["payload"]["goalExecutionReceipt"] == closed["receipt"]
        assert receipt_detail["payload"]["instanceId"] == "development-one"
        assert receipt_detail["payload"]["applicationId"] == "stateport.development-reference"
        # The durable receipt retains the exact backend identity behind the
        # closure: the test-only synthetic backend is labelled, never
        # recorded as provider execution.
        assert receipt_detail["payload"]["backendId"] == "fake"
        assert receipt_detail["payload"]["providerExecution"] is False
        assert receipt_detail["payload"]["goalExecutionReceipt"]["canonicalStateEffect"] == "none"
        assert _content_digest(project) == before
        assert not tuple((app.layout.state_root / "goal-execution" / "development-one" / "review-workspaces").glob("review-*"))
        record = app.layout.state_root / "goal-execution" / "development-one" / "current.json"
        assert stat.S_IMODE(record.stat().st_mode) == 0o600
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_restart_stops_in_flight_goal_instead_of_resuming(tmp_path: Path) -> None:
    project = _repository(tmp_path / "project")
    record_root = tmp_path / "records"
    first = GoalExecutionCoordinator(record_root=record_root, allow_synthetic_backend=True)
    identity = first.current_identity(project)
    proposal = first.prepare(
        application_id="stateport.development-reference",
        instance_id="project-one",
        instance_root=project,
        requested_by="local-user",
        text="Prepare one bounded inspection.",
        mode="assisted",
        expected_revision=0,
        expected_base_commit=identity["baseCommit"],
    )
    first.approve(
        "project-one",
        project,
        expected_revision=proposal["revision"],
        expected_plan_digest=proposal["slice"]["planDigest"],
        actor="authenticated-local-user-approver",
    )

    restarted = GoalExecutionCoordinator(record_root=record_root)
    view = restarted.inspect("project-one")
    assert view["state"] == "stopped"
    assert view["restartStatus"] == "in_flight_session_not_resumed"
    assert view["stop"]["code"] == "service_restart"
    assert view["revision"] == 3
    persisted = json.loads((record_root / "project-one" / "current.json").read_text(encoding="utf-8"))
    assert persisted["state"] == "stopped" and persisted["revision"] == 3
    assert stat.S_IMODE((record_root / "project-one" / "current.json").stat().st_mode) == 0o600


def test_service_view_preserves_terminal_stop_when_repository_is_dirty(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    project = _repository(app.layout.instances_root / "development-one")
    _register(app, project, "development-one", "stateport.development-reference")
    web_root = service_product_fixture(tmp_path, ROOT) / "apps" / "web"
    server = AppServer(("127.0.0.1", 0), app.layout, web_root)
    server.goal_execution = GoalExecutionCoordinator(
        record_root=(app.layout.state_root / "goal-execution").resolve(),
        allow_synthetic_backend=True,
    )
    try:
        identity = server.goal_execution.current_identity(project)
        proposal = server.goal_execution.prepare(
            application_id="stateport.development-reference",
            instance_id="development-one",
            instance_root=project,
            requested_by="local-user",
            text="Inspect one bounded application contract.",
            mode="assisted",
            expected_revision=0,
            expected_base_commit=identity["baseCommit"],
        )
        approved = server.goal_execution.approve(
            "development-one",
            project,
            expected_revision=proposal["revision"],
            expected_plan_digest=proposal["slice"]["planDigest"],
            actor="authenticated-local-user-approver",
        )
        (project / "dirty-after-approval.txt").write_text("drift\n", encoding="utf-8")
        with pytest.raises(GovernanceRefusal):
            server.goal_execution.execute(
                "development-one",
                project,
                expected_revision=approved["revision"],
                expected_plan_digest=approved["slice"]["planDigest"],
            )
        view = server.goal_execution_view("development-one")
        assert view["state"] == "stopped"
        assert view["stop"]["code"] == "base_drift"
        assert view["currentIdentity"]["baseCommit"] == proposal["slice"]["baseCommit"]
        assert view["currentIdentity"]["baseTree"] == proposal["slice"]["baseTree"]
        assert view["currentIdentity"]["repositoryClean"] is False
        assert view["currentIdentity"]["reasonCode"] == "base_drift"
        assert re.fullmatch(
            r"sha256:[0-9a-f]{64}",
            str(view["currentIdentity"]["workingTreeStatusDigest"]),
        )
    finally:
        server.server_close()


def test_service_view_projects_dirty_repository_without_an_active_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A legitimate governed file change must not make read projection fail."""

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    project = _repository(app.layout.instances_root / "development-one")
    _register(app, project, "development-one", "stateport.development-reference")
    clean_identity = _git(project, "rev-parse", "HEAD"), _git(project, "rev-parse", "HEAD^{tree}")
    (project / "governed-file-change.py").write_text("VALUE = 1\n", encoding="utf-8")

    web_root = service_product_fixture(tmp_path, ROOT) / "apps" / "web"
    server = AppServer(("127.0.0.1", 0), app.layout, web_root)
    server.goal_execution = GoalExecutionCoordinator(
        record_root=(app.layout.state_root / "goal-execution").resolve(),
        allow_synthetic_backend=True,
    )
    try:
        view = server.goal_execution_view("development-one")
        assert view["state"] == "not_prepared"
        assert view["revision"] == 0
        assert view["currentIdentity"]["baseCommit"] == clean_identity[0]
        assert view["currentIdentity"]["baseTree"] == clean_identity[1]
        assert view["currentIdentity"]["repositoryClean"] is False
        assert view["currentIdentity"]["reasonCode"] == "working_tree_dirty"
        assert re.fullmatch(
            r"sha256:[0-9a-f]{64}",
            str(view["currentIdentity"]["workingTreeStatusDigest"]),
        )

        # Read visibility does not weaken the mutation boundary: the exact
        # clean-basis guard still refuses preparation and leaves lifecycle
        # state untouched.
        with pytest.raises(GovernanceRefusal) as refusal:
            server.goal_execution.prepare(
                application_id="stateport.development-reference",
                instance_id="development-one",
                instance_root=project,
                requested_by="local-user",
                text="Prepare one bounded inspection.",
                mode="assisted",
                expected_revision=0,
                expected_base_commit=clean_identity[0],
            )
        assert refusal.value.code == "base_drift"
        assert server.goal_execution.inspect("development-one")["revision"] == 0
    finally:
        server.server_close()


def test_repository_drift_persists_terminal_stop_and_releases_approval(tmp_path: Path) -> None:
    project = _repository(tmp_path / "project")
    coordinator = GoalExecutionCoordinator(record_root=tmp_path / "records", allow_synthetic_backend=True)
    identity = coordinator.current_identity(project)
    proposal = coordinator.prepare(
        application_id="stateport.development-reference",
        instance_id="project-one",
        instance_root=project,
        requested_by="local-user",
        text="Prepare one bounded inspection.",
        mode="assisted",
        expected_revision=0,
        expected_base_commit=identity["baseCommit"],
    )
    approved = coordinator.approve(
        "project-one",
        project,
        expected_revision=proposal["revision"],
        expected_plan_digest=proposal["slice"]["planDigest"],
        actor="authenticated-local-user-approver",
    )
    (project / "application.yaml").write_text(
        (project / "application.yaml").read_text(encoding="utf-8") + "# drift\n",
        encoding="utf-8",
    )
    with pytest.raises(GovernanceRefusal) as failure:
        coordinator.execute(
            "project-one",
            project,
            expected_revision=approved["revision"],
            expected_plan_digest=approved["slice"]["planDigest"],
        )
    assert failure.value.code == "base_drift" and failure.value.terminal is True
    stopped = coordinator.inspect("project-one")
    assert stopped["state"] == "stopped"
    assert stopped["stop"]["code"] == "base_drift"
    assert stopped["revision"] == approved["revision"] + 1


def test_clean_commit_drift_persists_terminal_stop_to_disk(tmp_path: Path) -> None:
    project = _repository(tmp_path / "project")
    record_root = tmp_path / "records"
    coordinator = GoalExecutionCoordinator(record_root=record_root, allow_synthetic_backend=True)
    identity = coordinator.current_identity(project)
    proposal = coordinator.prepare(
        application_id="stateport.development-reference",
        instance_id="project-one",
        instance_root=project,
        requested_by="local-user",
        text="Prepare one bounded inspection.",
        mode="assisted",
        expected_revision=0,
        expected_base_commit=identity["baseCommit"],
    )
    approved = coordinator.approve(
        "project-one",
        project,
        expected_revision=proposal["revision"],
        expected_plan_digest=proposal["slice"]["planDigest"],
        actor="authenticated-local-user-approver",
    )
    (project / "clean-drift.txt").write_text("new clean base\n", encoding="utf-8")
    _git(project, "add", "clean-drift.txt")
    _git(project, "-c", "commit.gpgSign=false", "commit", "-m", "move clean base")

    with pytest.raises(GovernanceRefusal) as failure:
        coordinator.execute(
            "project-one",
            project,
            expected_revision=approved["revision"],
            expected_plan_digest=approved["slice"]["planDigest"],
        )
    assert failure.value.code == "base_drift" and failure.value.terminal is True
    stopped = coordinator.inspect("project-one")
    persisted = json.loads((record_root / "project-one" / "current.json").read_text(encoding="utf-8"))
    assert stopped["state"] == persisted["state"] == "stopped"
    assert stopped["revision"] == persisted["revision"] == approved["revision"] + 1
    assert stopped["stop"]["code"] == persisted["stop"]["code"] == "base_drift"


def test_mode_off_stops_approved_session_and_releases_instance_lease(tmp_path: Path) -> None:
    project = _repository(tmp_path / "project")
    coordinator = GoalExecutionCoordinator(record_root=tmp_path / "records", allow_synthetic_backend=True)
    identity = coordinator.current_identity(project)
    first = coordinator.prepare(
        application_id="stateport.development-reference",
        instance_id="project-one",
        instance_root=project,
        requested_by="local-user",
        text="Prepare the first bounded inspection.",
        mode="assisted",
        expected_revision=0,
        expected_base_commit=identity["baseCommit"],
    )
    approved = coordinator.approve(
        "project-one",
        project,
        expected_revision=first["revision"],
        expected_plan_digest=first["slice"]["planDigest"],
        actor="authenticated-local-user-approver",
    )
    off = coordinator.prepare(
        application_id="stateport.development-reference",
        instance_id="project-one",
        instance_root=project,
        requested_by="local-user",
        text="Disable CTO mode.",
        mode="off",
        expected_revision=approved["revision"],
        expected_base_commit=identity["baseCommit"],
    )
    assert off["state"] == "off"
    assert off["previousState"] == "approved"
    assert off["stop"]["code"] == "operator_disabled"

    second = coordinator.prepare(
        application_id="stateport.development-reference",
        instance_id="project-one",
        instance_root=project,
        requested_by="local-user",
        text="Prepare a fresh bounded inspection.",
        mode="assisted",
        expected_revision=off["revision"],
        expected_base_commit=identity["baseCommit"],
    )
    second_approval = coordinator.approve(
        "project-one",
        project,
        expected_revision=second["revision"],
        expected_plan_digest=second["slice"]["planDigest"],
        actor="authenticated-local-user-approver",
    )
    assert second_approval["state"] == "approved"


def test_review_rejects_symlink_without_chmoding_target_and_persists_stop(tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("unrelated user bytes\n", encoding="utf-8")
    outside.chmod(0o660)
    project = _repository(tmp_path / "project")
    os.symlink(outside, project / "outside-link")
    _git(project, "add", "outside-link")
    _git(project, "-c", "commit.gpgSign=false", "commit", "-m", "tracked symlink fixture")
    record_root = tmp_path / "records"
    coordinator = GoalExecutionCoordinator(record_root=record_root, allow_synthetic_backend=True)
    identity = coordinator.current_identity(project)
    proposal = coordinator.prepare(
        application_id="stateport.development-reference",
        instance_id="project-one",
        instance_root=project,
        requested_by="local-user",
        text="Prepare one bounded inspection.",
        mode="assisted",
        expected_revision=0,
        expected_base_commit=identity["baseCommit"],
    )
    approved = coordinator.approve(
        "project-one",
        project,
        expected_revision=proposal["revision"],
        expected_plan_digest=proposal["slice"]["planDigest"],
        actor="authenticated-local-user-approver",
    )
    executed = coordinator.execute(
        "project-one",
        project,
        expected_revision=approved["revision"],
        expected_plan_digest=approved["slice"]["planDigest"],
    )
    with pytest.raises(GovernanceRefusal) as failure:
        coordinator.review(
            "project-one",
            project,
            expected_revision=executed["revision"],
            expected_result_digest=executed["executionResult"]["executionResultDigest"],
        )
    assert failure.value.code == "review_isolation_invalid" and failure.value.terminal is True
    assert stat.S_IMODE(outside.stat().st_mode) == 0o660
    stopped = coordinator.inspect("project-one")
    persisted = json.loads((record_root / "project-one" / "current.json").read_text(encoding="utf-8"))
    assert stopped["state"] == persisted["state"] == "stopped"
    assert stopped["stop"]["code"] == persisted["stop"]["code"] == "review_isolation_invalid"
    assert not tuple((record_root / "project-one" / "review-workspaces").glob("review-*"))


def test_execution_inspection_exception_stops_and_persists_after_entering_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _repository(tmp_path / "project")
    record_root = tmp_path / "records"
    coordinator = GoalExecutionCoordinator(record_root=record_root, allow_synthetic_backend=True)
    identity = coordinator.current_identity(project)
    proposal = coordinator.prepare(
        application_id="stateport.development-reference",
        instance_id="project-one",
        instance_root=project,
        requested_by="local-user",
        text="Prepare one bounded inspection.",
        mode="assisted",
        expected_revision=0,
        expected_base_commit=identity["baseCommit"],
    )
    approved = coordinator.approve(
        "project-one",
        project,
        expected_revision=proposal["revision"],
        expected_plan_digest=proposal["slice"]["planDigest"],
        actor="authenticated-local-user-approver",
    )

    def concurrent_failure(**_kwargs: object) -> object:
        (project / "concurrent.txt").write_text("drift during inspection\n", encoding="utf-8")
        raise GoalContractError("concurrent inspection failure")

    monkeypatch.setattr(coordinator_module, "prepare_project_bootstrap", concurrent_failure)
    with pytest.raises(GovernanceRefusal) as failure:
        coordinator.execute(
            "project-one",
            project,
            expected_revision=approved["revision"],
            expected_plan_digest=approved["slice"]["planDigest"],
        )
    assert failure.value.code == "base_drift" and failure.value.terminal is True
    stopped = coordinator.inspect("project-one")
    persisted = json.loads((record_root / "project-one" / "current.json").read_text(encoding="utf-8"))
    assert stopped["state"] == persisted["state"] == "stopped"
    assert stopped["stop"]["stateBeforeStop"] == persisted["stop"]["stateBeforeStop"] == "executing"
    assert stopped["revision"] == persisted["revision"] == approved["revision"] + 1


def test_successful_execution_inspection_rechecks_unrelated_repository_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _repository(tmp_path / "project")
    record_root = tmp_path / "records"
    coordinator = GoalExecutionCoordinator(record_root=record_root, allow_synthetic_backend=True)
    identity = coordinator.current_identity(project)
    proposal = coordinator.prepare(
        application_id="stateport.development-reference",
        instance_id="project-one",
        instance_root=project,
        requested_by="local-user",
        text="Inspect one bounded application contract.",
        mode="assisted",
        expected_revision=0,
        expected_base_commit=identity["baseCommit"],
    )
    approved = coordinator.approve(
        "project-one",
        project,
        expected_revision=proposal["revision"],
        expected_plan_digest=proposal["slice"]["planDigest"],
        actor="local-user",
    )
    original = coordinator_module.prepare_project_bootstrap

    def drift_after_success(**kwargs: object) -> object:
        result = original(**kwargs)
        (project / "unrelated-drift.txt").write_text("drift after validated reads\n", encoding="utf-8")
        return result

    monkeypatch.setattr(coordinator_module, "prepare_project_bootstrap", drift_after_success)
    with pytest.raises(GovernanceRefusal) as failure:
        coordinator.execute(
            "project-one",
            project,
            expected_revision=approved["revision"],
            expected_plan_digest=approved["slice"]["planDigest"],
        )
    assert failure.value.code == "base_drift" and failure.value.terminal is True
    stopped = coordinator.inspect("project-one")
    persisted = json.loads((record_root / "project-one" / "current.json").read_text(encoding="utf-8"))
    assert stopped["state"] == persisted["state"] == "stopped"
    assert stopped["executionResult"] is None
    assert stopped["stop"]["stateBeforeStop"] == "executing"


def test_closure_guard_rechecks_identity_and_refuses_concurrent_dirty_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _repository(tmp_path / "project")
    record_root = tmp_path / "records"
    coordinator = GoalExecutionCoordinator(record_root=record_root, allow_synthetic_backend=True)
    identity = coordinator.current_identity(project)
    proposal = coordinator.prepare(
        application_id="stateport.development-reference",
        instance_id="project-one",
        instance_root=project,
        requested_by="local-user",
        text="Prepare one bounded inspection.",
        mode="assisted",
        expected_revision=0,
        expected_base_commit=identity["baseCommit"],
    )
    approved = coordinator.approve(
        "project-one", project,
        expected_revision=proposal["revision"],
        expected_plan_digest=proposal["slice"]["planDigest"],
        actor="authenticated-local-user-approver",
    )
    executed = coordinator.execute(
        "project-one", project,
        expected_revision=approved["revision"],
        expected_plan_digest=approved["slice"]["planDigest"],
    )
    reviewed = coordinator.review(
        "project-one", project,
        expected_revision=executed["revision"],
        expected_result_digest=executed["executionResult"]["executionResultDigest"],
    )
    original_identity = coordinator_module._git_identity
    calls = 0

    def edit_after_first_identity(root: Path) -> tuple[str, str]:
        nonlocal calls
        calls += 1
        result = original_identity(root)
        if calls == 1:
            (project / "closure-race.txt").write_text("dirty before closure guard\n", encoding="utf-8")
        return result

    monkeypatch.setattr(coordinator_module, "_git_identity", edit_after_first_identity)
    with pytest.raises(GovernanceRefusal) as failure:
        coordinator.close(
            "project-one", project,
            expected_revision=reviewed["revision"],
            expected_review_digest=reviewed["review"]["reviewDigest"],
            actor="stateport-governor",
        )
    assert calls >= 2
    assert failure.value.code == "base_drift" and failure.value.terminal is True
    stopped = coordinator.inspect("project-one")
    persisted = json.loads((record_root / "project-one" / "current.json").read_text(encoding="utf-8"))
    assert stopped["state"] == persisted["state"] == "stopped"
    assert stopped["closure"] is None and stopped["receipt"] is None
    assert stopped["stop"]["stateBeforeStop"] == "independently_reviewed"


def test_coordinator_fails_closed_without_test_backend_injection(tmp_path: Path) -> None:
    """No production default to the synthetic backend — typed unavailable.

    A coordinator built the way production builds it (no
    ``allow_synthetic_backend``) must refuse governed execution with
    ``goal_backend_unavailable`` rather than fabricate a result, whether the
    backend is implicit or the caller explicitly names the test-only backend.
    Mode ``off`` stays available: it is a stop operation, not an execution.
    """

    project = _repository(tmp_path / "project")
    coordinator = GoalExecutionCoordinator(record_root=tmp_path / "records")
    identity = coordinator.current_identity(project)
    base = {
        "application_id": "stateport.development-reference",
        "instance_id": "project-one",
        "instance_root": project,
        "requested_by": "local-user",
        "text": "Prepare one bounded inspection.",
        "expected_revision": 0,
        "expected_base_commit": identity["baseCommit"],
    }
    with pytest.raises(GovernanceRefusal) as implicit:
        coordinator.prepare(mode="assisted", **base)
    assert implicit.value.code == "goal_backend_unavailable"
    with pytest.raises(GovernanceRefusal) as explicit_fake:
        coordinator.prepare(mode="assisted", backend_id="fake", **base)
    assert explicit_fake.value.code == "goal_backend_unavailable"
    with pytest.raises(GovernanceRefusal) as unsupported:
        coordinator.prepare(mode="assisted", backend_id="provider_managed", **base)
    assert unsupported.value.code == "backend_unsupported"

    off = coordinator.prepare(mode="off", **base)
    assert off["state"] == "off"
    # Nothing was fabricated: no session, no proposal, no provider execution.
    view = coordinator.inspect("project-one")
    assert view["state"] == "off"
    assert view["providerExecution"] is False


def test_production_service_refuses_goal_prepare_without_a_configured_backend(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A default AppServer — exactly the production wiring — fails closed.

    No test-only dependency injection is applied, so governed execution must
    surface a typed ``goal_backend_unavailable`` refusal over the real HTTP
    boundary instead of a fabricated execution, review, or closure.
    """

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    project = _repository(app.layout.instances_root / "development-one")
    _register(app, project, "development-one", "stateport.development-reference")
    product_root = service_product_fixture(tmp_path, ROOT)
    server = AppServer(("127.0.0.1", 0), app.layout, product_root / "apps" / "web")
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
    )
    thread.start()
    port = int(server.server_address[1])
    try:
        with urlopen(f"http://127.0.0.1:{port}/session") as response:
            session = json.loads(response.read())["result"]
            cookie = response.headers["Set-Cookie"].split(";", 1)[0]

        def post(path: str, body: dict[str, object]) -> tuple[int, dict[str, object]]:
            request = Request(
                f"http://127.0.0.1:{port}{path}",
                data=json.dumps(body).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Cookie": cookie,
                    "Origin": f"http://127.0.0.1:{port}",
                    "X-StatePort-CSRF": session["csrfToken"],
                },
                method="POST",
            )
            try:
                with urlopen(request) as response:
                    return response.status, json.loads(response.read())
            except HTTPError as error:
                return error.code, json.loads(error.read())

        def get(path: str) -> dict[str, object]:
            request = Request(f"http://127.0.0.1:{port}{path}", headers={"Cookie": cookie})
            with urlopen(request) as response:
                return json.loads(response.read())["result"]

        view = get("/v1/instances/development-one/goal-execution")
        assert view["state"] == "not_prepared"
        # The typed view tells the frontend upfront that governed execution
        # is unavailable, so it must not offer active orchestration.
        availability = view["backendAvailability"]
        assert availability["status"] == "unavailable"
        assert availability["code"] == "goal_backend_unavailable"
        assert "no execution backend is configured" in availability["message"]
        assert availability["nextAction"]
        prepare_body = {
            "expectedInstanceId": "development-one",
            "expectedRevision": view["revision"],
            "expectedBaseCommit": view["currentIdentity"]["baseCommit"],
            "intent": "Prepare one bounded provider-free inspection.",
        }

        status, payload = post(
            "/v1/instances/development-one/goal-execution/prepare",
            {**prepare_body, "mode": "assisted"},
        )
        assert status == 409, payload
        assert payload["error"]["code"] == "goal_backend_unavailable"

        status, payload = post(
            "/v1/instances/development-one/goal-execution/prepare",
            {**prepare_body, "mode": "assisted", "backendId": "fake"},
        )
        assert status == 409, payload
        assert payload["error"]["code"] == "goal_backend_unavailable"

        status, payload = post(
            "/v1/instances/development-one/goal-execution/prepare",
            {**prepare_body, "mode": "assisted", "backendId": "provider_managed"},
        )
        assert status == 409, payload
        assert payload["error"]["code"] == "backend_unsupported"

        # Turning orchestration off is a stop operation and stays available.
        status, payload = post(
            "/v1/instances/development-one/goal-execution/prepare",
            {**prepare_body, "mode": "off"},
        )
        assert status == 200, payload
        assert payload["result"]["state"] == "off"

        # Nothing was fabricated: no session, no approval request, no
        # provider execution, no canonical state effect.
        assert not any(
            item.get("kind") == "goal_execution"
            for item in get("/v1/approvals")["approvals"]
        )
        after = get("/v1/instances/development-one/goal-execution")
        assert after["providerExecution"] is False
        assert after["canonicalStateEffect"] == "none"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
