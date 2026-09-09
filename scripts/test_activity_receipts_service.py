"""Focused Local Beta coverage for application activity and receipt projections."""

from __future__ import annotations

import hashlib
import json
import socket
import struct
import sys
import threading
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest


ROOT = Path(__file__).resolve().parents[1]
for relative in (
    "packages/persistent-app/src",
    "packages/statedd-core/src",
    "packages/template-validator/src",
    "packages/instance-backup/src",
    "packages/instance-catalog/src",
    "packages/diagnostics/src",
    "packages/application-experience/src",
    "packages/conversation-service/src",
    "packages/context-lifecycle/src",
    "packages/portable-execution/src",
    "packages/execution-host/src",
    "packages/codex-adapter/src",
    "packages/external-engine-runtime/src",
    "packages/opencode-adapter/src",
    "packages/container-opencode/src",
    "packages/run-bundle/src",
    "packages/sandbox-runtime/src",
    "packages/statebench/src",
    "packages/runtime-contracts/src",
    "packages/goal-execution/src",
):
    source = ROOT / relative
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from stateport_persistent_app import LocalLayout, PersistentApp  # noqa: E402
from stateport_persistent_app.activity_receipts import ActivityReceiptError, ActivityReceiptStore  # noqa: E402
from stateport_persistent_app.service_process import AppServer, Handler  # noqa: E402


def _settings_receipt(instance_id: str) -> dict[str, object]:
    return {
        "formatVersion": "stateport.settings-mutation-receipt/v1",
        "receiptId": "settings-receipt-1",
        "scope": "application",
        "instanceId": instance_id,
        "action": "settings.patch",
        "status": "applied",
        "revision": 1,
        "changes": {"context.mode": "faster"},
        "previousValues": {"context.mode": "balanced"},
        "createdAt": "2026-07-16T12:00:00Z",
    }


def _application_install_receipt(instance_id: str) -> dict[str, object]:
    base_git = "a" * 40
    return {
        "formatVersion": "stateport.application-install-receipt/v1",
        "receiptId": f"application-install.{instance_id}.{base_git[:12]}",
        "operation": "install_public_fixture",
        "applicationId": "checklistdd",
        "instanceId": instance_id,
        "actor": {
            "actorId": "local-user",
            "route": "explicit_browser_confirmation",
        },
        "descriptorIdentities": {
            "application": {
                "formatVersion": "stateport.application/v1",
                "applicationId": "checklistdd",
                "descriptorDigest": "sha256:" + "1" * 64,
                "packageDigest": "sha256:" + "2" * 64,
            },
            "experience": {"descriptorDigest": "sha256:" + "3" * 64},
        },
        "source": {
            "digest": "sha256:" + "2" * 64,
            "profile": "fixture:checklistdd",
            "networkPolicy": "disabled",
            "productionEligible": False,
        },
        "baseGit": base_git,
        "catalogIdentity": {
            "instanceId": instance_id,
            "applicationId": "checklistdd",
        },
        "consent": "explicit_browser_confirmation",
        "createdAt": "2026-07-19T00:00:00Z",
    }


def test_response_serialization_and_non_disconnect_io_errors_propagate() -> None:
    class Writer:
        def write(self, body: bytes) -> int:
            return len(body)

    class FailingWriter:
        def write(self, body: bytes) -> int:
            raise OSError("sentinel write failure")

    handler = object.__new__(Handler)
    handler.close_connection = False
    handler.wfile = Writer()
    handler.send_response = lambda _status: None
    handler.send_header = lambda _key, _value: None
    handler.end_headers = lambda: (_ for _ in ()).throw(ValueError("sentinel I/O failure"))

    with pytest.raises(ValueError, match="sentinel I/O failure"):
        Handler._send(handler, 200, {"ok": True})
    handler.end_headers = lambda: None
    handler.wfile = FailingWriter()
    with pytest.raises(OSError, match="sentinel write failure"):
        Handler._send(handler, 200, {"ok": True})
    with pytest.raises(TypeError, match="not JSON serializable"):
        Handler._send(handler, 200, object())


def test_client_rst_does_not_trigger_second_error_response(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    server = AppServer(("127.0.0.1", 0), app.layout, ROOT / "apps" / "web")
    log_path = Path(server.log.name)
    response_started = threading.Event()
    response_release = threading.Event()
    request_finished = threading.Event()
    handler_errors: list[tuple[object, object]] = []
    original_send = Handler._send

    def gated_send(
        handler: Handler,
        status: int,
        payload: object,
        *,
        content_type: str = "application/json; charset=utf-8",
        extra: dict[str, str] | None = None,
    ) -> None:
        if not response_started.is_set():
            response_started.set()
            assert response_release.wait(timeout=3)
        original_send(
            handler,
            status,
            payload,
            content_type=content_type,
            extra=extra,
        )

    monkeypatch.setattr(Handler, "_send", gated_send)

    def handle_error(request: object, client_address: object) -> None:
        handler_errors.append((request, client_address))

    server.handle_error = handle_error  # type: ignore[method-assign]
    original_process_request_thread = server.process_request_thread

    def tracked_process_request_thread(request: object, client_address: object) -> None:
        try:
            original_process_request_thread(request, client_address)
        finally:
            request_finished.set()

    server.process_request_thread = tracked_process_request_thread  # type: ignore[method-assign]
    thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.01},
        daemon=True,
    )
    thread.start()
    port = int(server.server_address[1])
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3) as probe:
            probe.sendall(
                (
                    f"GET /health HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{port}\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("ascii")
            )
            assert response_started.wait(timeout=3)
            probe.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_LINGER,
                struct.pack("ii", 1, 0),
            )
        response_release.set()
        assert request_finished.wait(timeout=3)

        server.log.flush()
        log_text = log_path.read_text(encoding="utf-8")
        assert handler_errors == []
        assert "status=400" not in log_text

        with urlopen(f"http://127.0.0.1:{port}/health", timeout=3) as response:
            assert response.status == 200
            assert json.loads(response.read())["result"]["status"] == "ok"
    finally:
        response_release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        server.log.close()


def test_activity_projection_persists_attention_state_and_receipt_details(tmp_path: Path) -> None:
    store = ActivityReceiptStore(tmp_path / "activity-receipts.sqlite3")
    inspection = {"health": "valid", "recovery": {"status": "no_backup"}}
    store.refresh(instance_id="activity-fixture", inspection=inspection, settings_receipts=[_settings_receipt("activity-fixture")])

    activity = store.activity("activity-fixture")
    assert activity["formatVersion"] == "stateport.activity-receipts-projection/v1"
    attention = activity["attention"]
    assert len(attention) == 1
    assert attention[0]["attentionId"] == "recovery-backup"
    assert attention[0]["acknowledgedAt"] is None

    read = store.transition_attention(
        instance_id="activity-fixture",
        attention_id="recovery-backup",
        action="read",
        expected_version=attention[0]["version"],
    )
    assert read["attention"]["readAt"]
    assert read["attention"]["acknowledgedAt"] is None
    assert read["receipt"]["action"] == "attention.read"

    with pytest.raises(ActivityReceiptError, match="changed; reload"):
        store.transition_attention(
            instance_id="activity-fixture",
            attention_id="recovery-backup",
            action="acknowledge",
            expected_version=attention[0]["version"],
        )

    changed = store.transition_attention(
        instance_id="activity-fixture",
        attention_id="recovery-backup",
        action="acknowledge",
        expected_version=read["attention"]["version"],
    )
    assert changed["attention"]["acknowledgedAt"]
    assert changed["receipt"]["effect"] == "local_operational_attention_state_only"

    restarted = ActivityReceiptStore(tmp_path / "activity-receipts.sqlite3")
    persisted = restarted.activity("activity-fixture")
    assert persisted["attention"][0]["acknowledgedAt"] == changed["attention"]["acknowledgedAt"]
    receipts = restarted.receipt_index("activity-fixture")["receipts"]
    assert {item["action"] for item in receipts} == {
        "settings.patch",
        "attention.read",
        "attention.acknowledge",
    }
    detail = restarted.receipt_detail("activity-fixture", changed["receipt"]["receiptId"])
    assert detail["receipt"]["payload"] == changed["receipt"]


def test_restore_staging_failure_enters_operator_attention(tmp_path: Path) -> None:
    store = ActivityReceiptStore(tmp_path / "activity-receipts.sqlite3")
    store.refresh(
        instance_id="restore-fixture",
        inspection={
            "health": "valid",
            "recovery": {
                "status": "verified",
                "restore": {
                    "status": "failed",
                    "operatorInspectionRequired": True,
                    "stagingRetained": True,
                },
            },
        },
        settings_receipts=[],
    )

    attention = store.activity("restore-fixture")["attention"]
    assert [item["attentionId"] for item in attention] == [
        "recovery-operator-inspection"
    ]
    assert attention[0]["detail"] == (
        "A failed restore retained staging data for operator review."
    )


def test_activity_projection_indexes_durable_backup_receipt(tmp_path: Path) -> None:
    store = ActivityReceiptStore(tmp_path / "activity-receipts.sqlite3")
    backup_receipt = {
        "formatVersion": "stateport.backup-receipt/v1",
        "receiptId": "backup-123456789012345678901234",
        "action": "backup.create",
        "status": "verified",
        "instanceId": "backup-fixture",
        "archiveDigest": "sha256:" + "1" * 64,
        "archiveFileDigest": "sha256:" + "2" * 64,
        "canonicalStateEffect": "none",
        "createdAt": "2026-07-16T00:00:00Z",
    }
    store.refresh(
        instance_id="backup-fixture",
        inspection={"recovery": {"status": "verified", "latest": {"backupReceipt": backup_receipt}}},
        settings_receipts=[],
    )
    index = store.receipt_index("backup-fixture")
    assert index["receipts"][0]["sourceKind"] == "application_backup"
    detail = store.receipt_detail("backup-fixture", backup_receipt["receiptId"])
    assert detail["receipt"]["payload"]["canonicalStateEffect"] == "none"


def test_activity_projection_rebuilds_exact_application_install_receipt(tmp_path: Path) -> None:
    store = ActivityReceiptStore(tmp_path / "activity-receipts.sqlite3")
    receipt = _application_install_receipt("install-fixture")
    store.refresh(
        instance_id="install-fixture",
        inspection={"health": "valid", "recovery": {"status": "verified"}},
        settings_receipts=[],
        application_install_receipt=receipt,
    )
    projected = store.receipt_index("install-fixture")["receipts"]
    authority_digest = "sha256:" + hashlib.sha256(
        (
            json.dumps(
                receipt,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            + "\n"
        ).encode("utf-8")
    ).hexdigest()
    assert projected == [
        {
            "receiptId": receipt["receiptId"],
            "receiptType": "stateport.application-install-receipt/v1",
            "action": "application.install.fixture",
            "status": "applied",
            "createdAt": receipt["createdAt"],
            "sourceKind": "application_install",
            "payloadDigest": authority_digest,
        }
    ]
    assert store.receipt_detail(
        "install-fixture",
        str(receipt["receiptId"]),
    )["receipt"]["payload"] == receipt

    mismatched = {**receipt, "instanceId": "other-fixture"}
    with pytest.raises(ActivityReceiptError, match="source identity"):
        store.refresh(
            instance_id="install-fixture",
            inspection={"health": "valid", "recovery": {"status": "verified"}},
            settings_receipts=[],
            application_install_receipt=mismatched,
        )


def test_same_origin_activity_and_receipt_endpoints_require_session_and_csrf(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    fixture = app.layout.instances_root / "activity-fixture"
    fixture.mkdir(parents=True)
    (fixture / "application.yaml").write_text(
        "formatVersion: stateport.application/v1\n"
        "applicationId: stateport.development-reference\n"
        "displayName: ProjectState\n"
        "description: Public-safe fixture\n",
        encoding="utf-8",
    )
    app.catalog.register(fixture, instance_id="activity-fixture", name="Activity fixture", source={"templateId": "stateport.development-reference"})
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = int(probe.getsockname()[1])
    app.service_start(port=port)
    base = f"http://127.0.0.1:{port}"

    def request(path: str, *, cookie: str | None = None, csrf: str | None = None, body: dict[str, object] | None = None) -> dict[str, object]:
        headers: dict[str, str] = {}
        data = None
        if cookie:
            headers["Cookie"] = cookie
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers.update({"Content-Type": "application/json", "Origin": base, "X-StatePort-CSRF": csrf or ""})
        with urlopen(Request(f"{base}{path}", data=data, method="POST" if body is not None else "GET", headers=headers)) as response:
            return json.loads(response.read())["result"]

    try:
        with pytest.raises(HTTPError) as unauthorized:
            request("/v1/instances/activity-fixture/activity")
        assert unauthorized.value.code == 401

        with urlopen(f"{base}/session") as response:
            session = json.loads(response.read())["result"]
            cookie = response.headers["Set-Cookie"].split(";", 1)[0]
        activity = request("/v1/instances/activity-fixture/activity", cookie=cookie)
        attention = activity["attention"][0]
        assert attention["attentionId"] == "recovery-backup"
        with pytest.raises(HTTPError) as csrf_refused:
            request(
                "/v1/instances/activity-fixture/activity/recovery-backup/acknowledge",
                cookie=cookie,
                body={"expectedVersion": attention["version"]},
            )
        assert csrf_refused.value.code == 403

        read = request(
            "/v1/instances/activity-fixture/activity/recovery-backup/read",
            cookie=cookie,
            csrf=session["csrfToken"],
            body={"expectedVersion": attention["version"]},
        )
        assert read["receipt"]["action"] == "attention.read"
        assert read["attention"]["readAt"]

        with pytest.raises(HTTPError) as stale:
            request(
                "/v1/instances/activity-fixture/activity/recovery-backup/acknowledge",
                cookie=cookie,
                csrf=session["csrfToken"],
                body={"expectedVersion": attention["version"]},
            )
        assert stale.value.code == 409

        changed = request(
            "/v1/instances/activity-fixture/activity/recovery-backup/acknowledge",
            cookie=cookie,
            csrf=session["csrfToken"],
            body={"expectedVersion": read["attention"]["version"]},
        )
        assert changed["receipt"]["action"] == "attention.acknowledge"
        index = request("/v1/instances/activity-fixture/receipts", cookie=cookie)
        receipt = next(item for item in index["receipts"] if item["receiptId"] == changed["receipt"]["receiptId"])
        detail = request(f"/v1/instances/activity-fixture/receipts/{receipt['receiptId']}", cookie=cookie)
        assert detail["receipt"]["payload"]["effect"] == "local_operational_attention_state_only"
    finally:
        app.service_stop()
