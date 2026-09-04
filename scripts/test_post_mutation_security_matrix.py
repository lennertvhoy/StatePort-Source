#!/usr/bin/env python3
"""Fail-closed origin/CSRF coverage for the persistent-app POST surface.

`POST /session` is the sole deliberate exception: it establishes the local
browser session and returns the CSRF token. Every other POST is authenticated
and origin/CSRF guarded before body parsing or route dispatch. Some POST
operations (repository inspection and catalog refresh) are currently read-only,
but they remain guarded so a later implementation cannot acquire side effects
without crossing the same boundary.
"""

from __future__ import annotations

from http.client import HTTPResponse
import hashlib
import json
from pathlib import Path
import socket
import sys
import threading
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest


ROOT = Path(__file__).resolve().parents[1]
TEST_WEB_ROOT = ROOT / "apps" / "_mutation-security-test-web"
for source_root in sorted((ROOT / "packages").glob("*/src")):
    sys.path.insert(0, str(source_root))
for source_root in sorted((ROOT / "apps").glob("*/src")):
    sys.path.insert(0, str(source_root))

from stateport_persistent_app import LocalLayout  # noqa: E402
from stateport_persistent_app.activity_receipts import ActivityReceiptStore  # noqa: E402
from stateport_persistent_app.service_process import AppServer  # noqa: E402


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


# Concrete representatives for every POST route or operation dispatched by
# Handler.do_POST. The expected code preserves each route's established denial
# contract; older routes that historically used the generic file-workspace
# denial retain it here rather than acquiring unrelated response churn.
SECURED_POST_ROUTES = (
    ("/v1/repository-import/inspect", "file_workspace_access_denied"),
    ("/v1/repository-import/register", "file_workspace_access_denied"),
    ("/v1/template-import/plan", "file_workspace_access_denied"),
    ("/v1/template-import/install", "file_workspace_access_denied"),
    ("/v1/instances/security-fixture/infrastructure/plan", "file_workspace_access_denied"),
    ("/v1/instances/security-fixture/infrastructure/approve", "file_workspace_access_denied"),
    ("/v1/instances/security-fixture/infrastructure/run", "file_workspace_access_denied"),
    ("/v1/instances/security-fixture/infrastructure/grant/prepare", "file_workspace_access_denied"),
    ("/v1/instances/security-fixture/infrastructure/grant/approve", "file_workspace_access_denied"),
    ("/v1/settings", "settings_access_denied"),
    ("/v1/settings/preview", "settings_access_denied"),
    ("/v1/settings/rollback", "settings_access_denied"),
    ("/v1/instances/security-fixture/settings", "settings_access_denied"),
    ("/v1/instances/security-fixture/settings-preview", "settings_access_denied"),
    ("/v1/instances/security-fixture/settings-rollback", "settings_access_denied"),
    ("/v1/instances/security-fixture/activity/attention-one/read", "file_workspace_access_denied"),
    ("/v1/instances/security-fixture/activity/attention-one/acknowledge", "file_workspace_access_denied"),
    ("/v1/sources/source-one/development-resolve", "source_verification_denied"),
    ("/v1/instances/security-fixture/terminal/prepare", "terminal_access_denied"),
    ("/v1/instances/security-fixture/file-workspace/prepareWrite", "file_workspace_access_denied"),
    ("/v1/instances/security-fixture/file-workspace/createFile", "file_workspace_access_denied"),
    ("/v1/instances/security-fixture/file-workspace/previewDiff", "file_workspace_access_denied"),
    ("/v1/instances/security-fixture/file-workspace/commitWrite", "file_workspace_access_denied"),
    ("/v1/instances/security-fixture/file-workspace/discardWrite", "file_workspace_access_denied"),
    ("/v1/instances/security-fixture/file-workspace/renamePath", "file_workspace_access_denied"),
    ("/v1/instances/security-fixture/file-workspace/deletePath", "file_workspace_access_denied"),
    ("/v1/catalog/refresh", "catalog_refresh_denied"),
    ("/v1/instances/security-fixture/portable-export", "portable_export_denied"),
    ("/v1/instances/security-fixture/backup", "backup_access_denied"),
    ("/v1/instances/security-fixture/recovery/restore/plan", "restore_access_denied"),
    ("/v1/instances/security-fixture/recovery/restore/approve", "restore_access_denied"),
    ("/v1/instances/security-fixture/recovery/restore/apply", "restore_access_denied"),
    ("/v1/instances/security-fixture/synthetic-run", "synthetic_validation_denied"),
    ("/v1/instances/security-fixture/conversation/messages", "conversation_access_denied"),
    ("/v1/instances/security-fixture/conversation/export", "conversation_access_denied"),
    ("/v1/instances/security-fixture/conversation/clear", "conversation_access_denied"),
    ("/v1/instances/security-fixture/conversation/attachments", "conversation_access_denied"),
    ("/v1/instances/security-fixture/conversation/attachments/attachment-one/delete", "conversation_access_denied"),
    ("/v1/instances/security-fixture/conversation/attachments/attachment-one/export", "conversation_access_denied"),
    ("/v1/instances/security-fixture/context-lifecycle/preference", "context_lifecycle_access_denied"),
    ("/v1/instances/security-fixture/context-lifecycle/compact", "context_lifecycle_access_denied"),
    ("/v1/instances/security-fixture/context-lifecycle/handoff", "context_lifecycle_access_denied"),
    ("/v1/instances/security-fixture/goal-execution/prepare", "goal_execution_access_denied"),
    ("/v1/instances/security-fixture/goal-execution/approve", "goal_execution_access_denied"),
    ("/v1/instances/security-fixture/goal-execution/execute", "goal_execution_access_denied"),
    ("/v1/instances/security-fixture/goal-execution/review", "goal_execution_access_denied"),
    ("/v1/instances/security-fixture/goal-execution/close", "goal_execution_access_denied"),
    ("/v1/portable-import/preview", "portable_import_denied"),
    ("/v1/portable-import/apply", "portable_import_denied"),
    ("/v1/application-fixtures/install", "application_install_denied"),
    ("/v1/instances/security-fixture/template-upgrade/request", "template_upgrade_denied"),
    ("/v1/instances/security-fixture/template-upgrade/approve", "template_upgrade_denied"),
    ("/v1/instances/security-fixture/template-upgrade/reject", "template_upgrade_denied"),
    ("/v1/instances/security-fixture/template-upgrade/apply", "template_upgrade_denied"),
    ("/v1/instances/security-fixture/execution/prepare", "execution_access_denied"),
    ("/v1/runs/run-one/approve", "execution_access_denied"),
    ("/v1/runs/run-one/execute", "execution_access_denied"),
    ("/v1/runs/run-one/cancel", "execution_access_denied"),
    ("/v1/runs/run-one/proposal-approve", "execution_access_denied"),
    ("/v1/runs/run-one/proposal-reject", "execution_access_denied"),
    ("/v1/runs/run-one/apply", "execution_access_denied"),
    ("/v1/execution-host/workloads", "execution_host_access_denied"),
    ("/v1/execution-host/workloads/start", "execution_host_access_denied"),
    ("/v1/execution-host/workloads/stop", "execution_host_access_denied"),
    ("/v1/execution-host/workloads/cancel", "execution_host_access_denied"),
    ("/v1/execution-host/workloads/remove", "execution_host_access_denied"),
    ("/v1/execution-host/workloads/exec", "execution_host_access_denied"),
)


def _post(
    port: int,
    path: str,
    *,
    cookie: str | None = None,
    csrf: str | None = None,
    origin: str | None = None,
    body: dict[str, object] | None = None,
) -> tuple[int, dict[str, object]]:
    headers = {"Content-Type": "application/json"}
    if cookie is not None:
        headers["Cookie"] = cookie
    if csrf is not None:
        headers["X-StatePort-CSRF"] = csrf
    if origin is not None:
        headers["Origin"] = origin
    request = Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(body or {}).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urlopen(request) as response:
            return response.status, json.loads(response.read())
    except HTTPError as error:
        return error.code, json.loads(error.read())


def _get(port: int, path: str, *, cookie: str) -> tuple[int, dict[str, object]]:
    request = Request(
        f"http://127.0.0.1:{port}{path}",
        headers={"Cookie": cookie},
        method="GET",
    )
    with urlopen(request) as response:
        return response.status, json.loads(response.read())


class _ExecutionHostStub:
    def __init__(self) -> None:
        self.create_calls = 0
        self.start_calls: list[object] = []
        self.exec_calls: list[tuple[object, object]] = []

    @staticmethod
    def _result(
        operation: str,
        *,
        state: str,
        second: int,
        output: str | None = None,
    ) -> dict[str, object]:
        result: dict[str, object] = {"workloadId": "default-dev", "state": state}
        if output is not None:
            result["output"] = output
        receipt: dict[str, object] = {
            "formatVersion": "stateport.execution-host-operation-receipt/v1",
            "receiptId": f"execution-host-op-{operation}",
            "receiptType": "stateport.execution-host-operation-receipt/v1",
            "action": f"execution_host.{operation}",
            "status": "accepted",
            "createdAt": f"2026-08-20T00:00:{second:02d}Z",
            "sourceKind": "execution_host",
            "operationId": f"op-{operation}",
            "requestDigest": "sha256:" + str(second + 1) * 64,
            "resultDigest": _canonical_digest(result),
            "workloadId": "default-dev",
        }
        if output is not None:
            receipt["outputDigest"] = _canonical_digest(output)
            receipt["outputBytes"] = len(output.encode("utf-8"))
        return {
            "operationId": f"op-{operation}",
            "accepted": True,
            "result": result,
            "receipt": receipt,
        }

    def create_default(self) -> dict[str, object]:
        self.create_calls += 1
        return self._result("createWorkload", state="created", second=0)

    def start(self, workload_id: object) -> dict[str, object]:
        self.start_calls.append(workload_id)
        return self._result("start", state="running", second=1)

    def exec(self, workload_id: object, argv: object) -> dict[str, object]:
        self.exec_calls.append((workload_id, argv))
        return self._result(
            "execWorkload",
            state="running",
            second=2,
            output="stateport-j1-ok\n",
        )


def _start_server(tmp_path: Path) -> tuple[AppServer, threading.Thread, str, str, str]:
    layout = LocalLayout.from_environment()
    layout.initialize()
    # This boundary test does not serve frontend assets. A sibling path keeps
    # product-root discovery real without coupling the test to an in-progress
    # or absent production bundle under apps/web/dist.
    server = AppServer(("127.0.0.1", 0), layout, TEST_WEB_ROOT)
    thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.02},
        daemon=True,
    )
    thread.start()
    port = int(server.server_address[1])
    origin = f"http://127.0.0.1:{port}"
    with urlopen(f"{origin}/session") as response:
        session = json.loads(response.read())["result"]
        cookie = response.headers["Set-Cookie"].split(";", 1)[0]
    return server, thread, origin, cookie, str(session["csrfToken"])


def _raw_post(
    port: int,
    headers: tuple[str, ...],
    *,
    path: str = "/v1/future-mutation",
    host: str | None = None,
) -> tuple[int, dict[str, object]]:
    selected_host = host or f"127.0.0.1:{port}"
    request = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {selected_host}\r\n"
        + "".join(f"{header}\r\n" for header in headers)
        + "Connection: close\r\n\r\n"
    ).encode("ascii")
    with socket.create_connection(("127.0.0.1", port), timeout=2.0) as connection:
        connection.settimeout(2.0)
        connection.sendall(request)
        response = HTTPResponse(connection)
        response.begin()
        return response.status, json.loads(response.read())


def _raw_request_with_host(
    port: int,
    method: str,
    path: str,
    host: str,
) -> tuple[int, dict[str, object], str | None]:
    request = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    with socket.create_connection(("127.0.0.1", port), timeout=2.0) as connection:
        connection.settimeout(2.0)
        connection.sendall(request)
        response = HTTPResponse(connection)
        response.begin()
        return response.status, json.loads(response.read()), response.getheader("Set-Cookie")


def test_every_post_route_requires_the_authenticated_mutation_boundary(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    server, thread, origin, cookie, _csrf = _start_server(tmp_path)
    port = int(server.server_address[1])
    try:
        for path, denial_code in SECURED_POST_ROUTES:
            status, payload = _post(
                port,
                path,
                cookie=cookie,
                origin=origin,
            )
            assert status == 403, path
            assert payload["error"]["code"] == denial_code, path
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()
    assert not thread.is_alive()


def test_execution_host_create_accepts_only_empty_body_and_persists_receipt(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    server, thread, origin, cookie, csrf = _start_server(tmp_path)
    stub = _ExecutionHostStub()
    server.execution_host = stub
    receipt_store_path = server.activity_receipts.path
    port = int(server.server_address[1])
    try:
        status, created = _post(
            port,
            "/v1/execution-host/workloads",
            cookie=cookie,
            csrf=csrf,
            origin=origin,
            body={},
        )
        assert status == 200
        assert created["result"]["result"] == {
            "workloadId": "default-dev",
            "state": "created",
        }
        assert created["result"]["receipt"]["actorId"] == "local-user"
        assert stub.create_calls == 1

        status, refused = _post(
            port,
            "/v1/execution-host/workloads",
            cookie=cookie,
            csrf=csrf,
            origin=origin,
            body={"workloadId": "attacker-selected"},
        )
        assert status == 400
        assert refused["error"]["code"] == "operation_failed"
        assert stub.create_calls == 1

        status, receipts = _get(
            port,
            "/v1/execution-host/receipts",
            cookie=cookie,
        )
        assert status == 200
        assert receipts["result"]["receipts"][0]["receiptId"] == (
            "execution-host-op-createWorkload"
        )
        assert receipts["result"]["receipts"][0]["action"] == (
            "execution_host.createWorkload"
        )

        status, started = _post(
            port,
            "/v1/execution-host/workloads/start",
            cookie=cookie,
            csrf=csrf,
            origin=origin,
            body={"workloadId": "default-dev"},
        )
        assert status == 200
        assert started["result"]["result"]["state"] == "running"
        assert stub.start_calls == ["default-dev"]

        argv = ["/bin/sh", "-lc", "printf 'stateport-j1-ok\\n'"]
        status, executed = _post(
            port,
            "/v1/execution-host/workloads/exec",
            cookie=cookie,
            csrf=csrf,
            origin=origin,
            body={"workloadId": "default-dev", "argv": argv},
        )
        assert status == 200
        assert executed["result"]["result"]["output"] == "stateport-j1-ok\n"
        assert stub.exec_calls == [("default-dev", argv)]
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()
    assert not thread.is_alive()
    reopened = ActivityReceiptStore(receipt_store_path)
    index = reopened.receipt_index("execution-host")
    assert [receipt["action"] for receipt in index["receipts"]] == [
        "execution_host.execWorkload",
        "execution_host.start",
        "execution_host.createWorkload",
    ]
    detail = reopened.receipt_detail(
        "execution-host", "execution-host-op-execWorkload"
    )["receipt"]
    assert detail["payload"]["actorId"] == "local-user"
    assert detail["payload"]["requestDigest"] == "sha256:" + "3" * 64
    assert detail["payload"]["resultDigest"] == _canonical_digest(
        {"workloadId": "default-dev", "state": "running", "output": "stateport-j1-ok\n"}
    )
    assert detail["payload"]["outputDigest"] == _canonical_digest(
        "stateport-j1-ok\n"
    )
    assert detail["payloadDigest"] == _canonical_digest(detail["payload"])


def test_post_boundary_is_fail_closed_for_future_routes_and_session_is_the_only_exception(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    server, thread, origin, cookie, csrf = _start_server(tmp_path)
    port = int(server.server_address[1])
    try:
        status, session = _post(port, "/session")
        assert status == 200
        assert session["result"]["csrfToken"]

        status, denied = _post(
            port,
            "/v1/future-mutation",
            cookie=cookie,
            origin=origin,
        )
        assert status == 403
        assert denied["error"]["code"] == "file_workspace_access_denied"

        status, denied = _post(
            port,
            "/v1/future-mutation",
            cookie=cookie,
            csrf=csrf,
            origin="https://attacker.invalid",
        )
        assert status == 403
        assert denied["error"]["code"] == "file_workspace_access_denied"

        status, missing = _post(
            port,
            "/v1/future-mutation",
            cookie=cookie,
            csrf=csrf,
            origin=origin,
        )
        assert status == 404
        assert missing["error"]["code"] == "not_found"
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()
    assert not thread.is_alive()


def test_every_post_route_rejects_duplicate_origin_and_csrf_headers(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    server, thread, origin, cookie, csrf = _start_server(tmp_path)
    port = int(server.server_address[1])
    common = (
        f"Cookie: {cookie}",
        "Content-Type: application/json",
        "Content-Length: 0",
    )
    duplicate_authorization_headers = (
        (
            *common,
            f"Origin: {origin}",
            f"Origin: {origin}",
            f"X-StatePort-CSRF: {csrf}",
        ),
        (
            *common,
            f"Origin: {origin}",
            f"X-StatePort-CSRF: {csrf}",
            f"X-StatePort-CSRF: {csrf}",
        ),
    )
    try:
        for path, denial_code in SECURED_POST_ROUTES:
            for headers in duplicate_authorization_headers:
                status, payload = _raw_post(port, headers, path=path)
                assert status == 403, path
                assert payload["error"]["code"] == denial_code, path
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()
    assert not thread.is_alive()


def test_post_body_framing_rejects_ambiguous_negative_and_transfer_encoded_requests(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    server, thread, origin, cookie, csrf = _start_server(tmp_path)
    port = int(server.server_address[1])
    authorization = (
        f"Cookie: {cookie}",
        f"Origin: {origin}",
        f"X-StatePort-CSRF: {csrf}",
        "Content-Type: application/json",
    )
    malformed_headers = (
        (*authorization, "Content-Length: -1"),
        (*authorization, "Content-Length: 0", "Content-Length: 2"),
        (*authorization, "Transfer-Encoding: chunked"),
    )
    try:
        for headers in malformed_headers:
            status, payload = _raw_post(port, headers)
            assert status == 400
            assert payload["error"]["code"] == "operation_failed"
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()
    assert not thread.is_alive()


def test_loopback_service_rejects_dns_rebinding_host_before_session_or_api_dispatch(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    server, thread, _origin, _cookie, _csrf = _start_server(tmp_path)
    port = int(server.server_address[1])
    try:
        for method, path in (("GET", "/session"), ("POST", "/session"), ("GET", "/v1/status")):
            for hostile_host in (
                f"attacker.invalid:{port}",
                f"127.0.0.1.attacker.invalid:{port}",
                f"192.168.1.10:{port}",
            ):
                status, payload, set_cookie = _raw_request_with_host(
                    port,
                    method,
                    path,
                    hostile_host,
                )
                assert status == 421, hostile_host
                assert payload["error"]["code"] == "invalid_host", hostile_host
                assert set_cookie is None, hostile_host

        # Every loopback alias names the same local service; rejecting them
        # would break `localhost` bookmarks without adding rebinding safety.
        for loopback_host in (
            f"127.0.0.1:{port}",
            f"localhost:{port}",
            f"[::1]:{port}",
        ):
            status, payload, set_cookie = _raw_request_with_host(
                port,
                "GET",
                "/session",
                loopback_host,
            )
            assert status == 200, loopback_host
            assert payload["result"]["csrfToken"], loopback_host
            assert set_cookie is not None, loopback_host
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()
    assert not thread.is_alive()


def test_container_host_mapping_uses_one_explicit_loopback_authority(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """A non-default Compose host port stays usable without accepting aliases."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    external_port = 45123
    layout = LocalLayout.from_environment()
    layout.initialize()
    server = AppServer(
        ("0.0.0.0", 0),
        layout,
        TEST_WEB_ROOT,
        allow_public_bind=True,
        external_loopback_port=external_port,
    )
    thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.02},
        daemon=True,
    )
    thread.start()
    bound_port = int(server.server_address[1])
    external_host = f"127.0.0.1:{external_port}"
    external_origin = f"http://127.0.0.1:{external_port}"
    try:
        status, payload, set_cookie = _raw_request_with_host(
            bound_port,
            "GET",
            "/session",
            external_host,
        )
        assert status == 200
        assert set_cookie is not None
        csrf = str(payload["result"]["csrfToken"])
        cookie = set_cookie.split(";", 1)[0]

        status, payload = _raw_post(
            bound_port,
            (
                f"Cookie: {cookie}",
                f"Origin: {external_origin}",
                f"X-StatePort-CSRF: {csrf}",
                "Content-Type: application/json",
                "Content-Length: 0",
            ),
            host=external_host,
        )
        assert status == 404
        assert payload["error"]["code"] == "not_found"

        status, payload = _raw_post(
            bound_port,
            (
                f"Cookie: {cookie}",
                f"Origin: http://127.0.0.1:{bound_port}",
                f"X-StatePort-CSRF: {csrf}",
                "Content-Type: application/json",
                "Content-Length: 0",
            ),
            host=external_host,
        )
        assert status == 403
        assert payload["error"]["code"] == "file_workspace_access_denied"

        status, payload, set_cookie = _raw_request_with_host(
            bound_port,
            "GET",
            "/session",
            "127.0.0.1:45124",
        )
        assert status == 421
        assert payload["error"]["code"] == "invalid_host"
        assert set_cookie is None
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()
    assert not thread.is_alive()


def test_external_loopback_port_requires_an_explicit_public_container_bind(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    layout = LocalLayout.from_environment()
    layout.initialize()
    with pytest.raises(ValueError, match="external loopback port"):
        AppServer(
            ("127.0.0.1", 0),
            layout,
            TEST_WEB_ROOT,
            external_loopback_port=45123,
        )


def test_newly_secured_routes_reject_non_exact_bodies_before_operations(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    server, thread, origin, cookie, csrf = _start_server(tmp_path)
    port = int(server.server_address[1])
    strict_routes = (
        "/v1/catalog/refresh",
        "/v1/instances/security-fixture/portable-export",
        "/v1/instances/security-fixture/execution/prepare",
        "/v1/runs/run-one/approve",
        "/v1/runs/run-one/execute",
        "/v1/runs/run-one/cancel",
        "/v1/runs/run-one/proposal-approve",
        "/v1/runs/run-one/proposal-reject",
        "/v1/runs/run-one/apply",
    )
    try:
        for path in strict_routes:
            status, payload = _post(
                port,
                path,
                cookie=cookie,
                csrf=csrf,
                origin=origin,
                body={"unexpected": True},
            )
            assert status == 400, path
            assert payload["error"]["code"] == "operation_failed", path

        status, refreshed = _post(
            port,
            "/v1/catalog/refresh",
            cookie=cookie,
            csrf=csrf,
            origin=origin,
        )
        assert status == 200
        assert refreshed["result"]["refreshed"] is True
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()
    assert not thread.is_alive()
