#!/usr/bin/env python3
"""Real loopback HTTP/WebSocket proof for the governed project terminal."""

from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from typing import Iterator
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest


ROOT = Path(__file__).resolve().parents[1]
for relative in (
    "packages/persistent-app/src",
    "packages/portable-execution/src",
    "packages/application-experience/src",
    "packages/conversation-service/src",
    "packages/context-lifecycle/src",
    "packages/file-workspace-broker/src",
    "packages/terminal-broker/src",
    "packages/governed-runner/src",
    "packages/execution-host/src",
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

from stateport_persistent_app import LocalLayout, PersistentApp  # noqa: E402
from stateport_persistent_app.service_process import AppServer  # noqa: E402
from stateport_terminal_broker import broker as terminal_broker_module  # noqa: E402
from service_test_product import service_product_fixture  # noqa: E402


APPLICATION_ID = "stateport.development-reference"
SOCKET_FORMAT = "stateport.terminal-socket/v1"
SOCKET_PATH = "/v1/terminal/socket"
SUBPROTOCOL = "stateport.terminal.v1"


def _git(project: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(project), *args],
        check=True,
        text=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout.strip()


def _project_fixture(project: Path, marker: str) -> str:
    (project / "src").mkdir(parents=True)
    (project / "src" / "main.py").write_text(f"MARKER = {marker!r}\n", encoding="utf-8")
    (project / "README.md").write_text(f"# {marker}\n", encoding="utf-8")
    _git(project, "init", "-q", "-b", "main")
    _git(project, "config", "user.email", "terminal-fixture@example.invalid")
    _git(project, "config", "user.name", "StatePort terminal fixture")
    _git(project, "add", ".")
    _git(project, "commit", "-q", "-m", "fixture")
    return _git(project, "rev-parse", "HEAD")


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@contextmanager
def _service(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, object]]:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    layout = LocalLayout.from_environment()
    app = PersistentApp(layout)
    app.setup_init()
    projects: dict[str, Path] = {}
    for instance_id, application_id in (
        ("dev-one", APPLICATION_ID),
        ("dev-two", APPLICATION_ID),
        ("study-one", "studydd"),
    ):
        project = layout.instances_root / instance_id
        head = _project_fixture(project, instance_id)
        app.catalog.register(
            project,
            instance_id=instance_id,
            name=instance_id,
            source={
                "templateId": application_id,
                "resolvedCommit": head,
                "resolvedTree": f"tree-{instance_id}",
                "manifestDigest": "sha256:" + hashlib.sha256(instance_id.encode()).hexdigest(),
            },
        )
        projects[instance_id] = project
    port = _free_port()
    origin = f"http://127.0.0.1:{port}"
    app.service_start(
        port=port,
        repo_root=service_product_fixture(tmp_path, ROOT),
    )
    try:
        with urlopen(f"{origin}/session") as response:
            session = json.loads(response.read())["result"]
            set_cookie = response.headers["Set-Cookie"]
        yield {
            "app": app,
            "layout": layout,
            "origin": origin,
            "port": port,
            "projects": projects,
            "cookie": set_cookie.split(";", 1)[0],
            "setCookie": set_cookie,
            "csrf": session["csrfToken"],
        }
    finally:
        app.service_stop()


def _prepare(
    service: dict[str, object],
    instance_id: str = "dev-one",
    *,
    csrf: str | None = None,
    origin: str | None = None,
    extra: dict[str, object] | None = None,
) -> tuple[int, dict[str, object]]:
    body: dict[str, object] = {"expectedInstanceId": instance_id, "columns": 80, "rows": 24}
    body.update(extra or {})
    headers = {
        "Cookie": str(service["cookie"]),
        "Content-Type": "application/json",
        "Origin": str(service["origin"] if origin is None else origin),
    }
    if csrf is not None or csrf is None and "csrf" in service:
        token = service["csrf"] if csrf is None else csrf
        if token:
            headers["X-StatePort-CSRF"] = str(token)
    request = Request(
        f"{service['origin']}/v1/instances/{instance_id}/terminal/prepare",
        data=json.dumps(body).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urlopen(request) as response:
            return response.status, json.loads(response.read())
    except HTTPError as error:
        return error.code, json.loads(error.read())


class RawWebSocket:
    def __init__(self, connection: socket.socket, stream: object, response_version: str, status: int, headers: dict[str, str]) -> None:
        self.connection = connection
        self.stream = stream
        self.response_version = response_version
        self.status = status
        self.headers = headers

    @classmethod
    def open(
        cls,
        service: dict[str, object],
        *,
        path: str = SOCKET_PATH,
        cookie: str | None = None,
        host: str | None = None,
        origin: str | None = None,
        key: str | None = None,
        version: str = "13",
        protocol: str = SUBPROTOCOL,
        connection_header: str = "Upgrade",
        extension: str | None = "permessage-deflate; client_max_window_bits",
    ) -> "RawWebSocket":
        connection = socket.create_connection(("127.0.0.1", int(service["port"])), timeout=3)
        # Full isolated/container closure runs exercise many process and PTY
        # boundaries before this journey. Keep a bounded but load-tolerant
        # read deadline so scheduler latency is not misclassified as a broken
        # resize/reconnect contract.
        connection.settimeout(10)
        stream = connection.makefile("rwb", buffering=0)
        supplied_key = key if key is not None else base64.b64encode(b"0123456789abcdef").decode("ascii")
        host_header = host if host is not None else f"127.0.0.1:{service['port']}"
        headers = [
            f"GET {path} HTTP/1.1",
            f"Host: {host_header}",
            "Upgrade: websocket",
            f"Connection: {connection_header}",
            f"Origin: {service['origin'] if origin is None else origin}",
            f"Cookie: {service['cookie'] if cookie is None else cookie}",
            f"Sec-WebSocket-Key: {supplied_key}",
            f"Sec-WebSocket-Version: {version}",
            f"Sec-WebSocket-Protocol: {protocol}",
        ]
        if extension is not None:
            headers.append(f"Sec-WebSocket-Extensions: {extension}")
        stream.write(("\r\n".join(headers) + "\r\n\r\n").encode("ascii"))
        status_line = stream.readline().decode("ascii").rstrip("\r\n")
        status_parts = status_line.split(" ", 2)
        response_version = status_parts[0]
        status = int(status_parts[1])
        response_headers: dict[str, str] = {}
        while True:
            line = stream.readline()
            if line in {b"\r\n", b"\n", b""}:
                break
            name, value = line.decode("ascii").split(":", 1)
            response_headers[name.lower()] = value.strip()
        return cls(connection, stream, response_version, status, response_headers)

    def send(self, opcode: int, payload: bytes = b"", *, masked: bool = True, fin: bool = True, rsv: int = 0) -> None:
        first = (0x80 if fin else 0) | (rsv & 0x70) | opcode
        mask = b"\x11\x22\x33\x44"
        length_flag = 0x80 if masked else 0
        if len(payload) < 126:
            header = bytes((first, length_flag | len(payload)))
        elif len(payload) <= 65_535:
            header = bytes((first, length_flag | 126)) + struct.pack("!H", len(payload))
        else:
            header = bytes((first, length_flag | 127)) + struct.pack("!Q", len(payload))
        if masked:
            encoded = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
            self.stream.write(header + mask + encoded)
        else:
            self.stream.write(header + payload)

    def send_json(self, value: dict[str, object]) -> None:
        self.send(0x1, json.dumps(value, separators=(",", ":")).encode("utf-8"))

    def receive(self) -> tuple[int, bytes]:
        first = self.stream.read(1)
        if not first:
            raise EOFError("WebSocket closed")
        second = self.stream.read(1)
        if not second:
            raise EOFError("WebSocket closed")
        first_value, second_value = first[0], second[0]
        assert first_value & 0x80 and not first_value & 0x70
        assert not second_value & 0x80
        length = second_value & 0x7F
        if length == 126:
            length = struct.unpack("!H", self.stream.read(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self.stream.read(8))[0]
        payload = self.stream.read(length)
        if len(payload) != length:
            raise EOFError("WebSocket payload truncated")
        return first_value & 0x0F, payload

    def close(self) -> None:
        try:
            self.stream.close()
        finally:
            self.connection.close()


def _authentication(ticket: dict[str, object], instance_id: str, **overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "formatVersion": SOCKET_FORMAT,
        "type": "authenticate",
        "instanceId": instance_id,
        "sessionId": ticket["sessionId"],
        "purpose": ticket["purpose"],
        "oneUseToken": ticket["oneUseToken"],
        "columns": 80,
        "rows": 24,
    }
    value.update(overrides)
    return value


def _receive_until(websocket: RawWebSocket, expected: bytes, *, maximum_frames: int = 30) -> bytes:
    value = bytearray()
    for _ in range(maximum_frames):
        opcode, payload = websocket.receive()
        assert opcode == 0x2
        assert len(payload) <= 65_536
        value.extend(payload)
        if expected in value:
            return bytes(value)
    raise AssertionError(f"terminal output did not contain {expected!r}: {bytes(value)!r}")


def _receive_close(websocket: RawWebSocket, *, maximum_frames: int = 30) -> bytes:
    for _ in range(maximum_frames):
        opcode, payload = websocket.receive()
        if opcode == 0x8:
            return payload
        assert opcode == 0x2 and len(payload) <= 65_536
    raise AssertionError("terminal WebSocket did not close")


def _wait_for(predicate: object, timeout: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return bool(predicate())


def test_real_project_root_terminal_io_resize_disconnect_reconnect_and_end(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with _service(tmp_path, monkeypatch) as service:
        assert "HttpOnly" in service["setCookie"] and "SameSite=Strict" in service["setCookie"]
        status, prepared_payload = _prepare(service)
        assert status == 200
        ticket = prepared_payload["result"]
        assert ticket["socketPath"] == SOCKET_PATH and "?" not in ticket["socketPath"]
        assert ticket["purpose"] == "create" and len(ticket["oneUseToken"]) >= 32
        websocket = RawWebSocket.open(service, connection_header="keep-alive, Upgrade")
        try:
            assert websocket.response_version == "HTTP/1.1"
            assert websocket.status == 101
            assert websocket.headers["sec-websocket-protocol"] == SUBPROTOCOL
            expected_accept = base64.b64encode(
                hashlib.sha1(b"MDEyMzQ1Njc4OWFiY2RlZg==258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest()
            ).decode("ascii")
            assert websocket.headers["sec-websocket-accept"] == expected_accept
            assert "sec-websocket-extensions" not in websocket.headers
            websocket.send_json(_authentication(ticket, "dev-one"))
            opcode, ready_payload = websocket.receive()
            ready = json.loads(ready_payload)
            assert opcode == 0x1
            assert ready == {
                "formatVersion": SOCKET_FORMAT,
                "purpose": "create",
                "reconnect": True,
                "sessionId": ticket["sessionId"],
                "targetClass": "local_pty",
                "type": "ready",
            }
            assert ticket["oneUseToken"] not in ready_payload.decode("utf-8")

            websocket.send(0x2, b"pwd\n")
            output = _receive_until(websocket, str(service["projects"]["dev-one"]).encode())
            assert b"pwd" in output
            websocket.send_json({"formatVersion": SOCKET_FORMAT, "type": "resize", "columns": 101, "rows": 31})
            websocket.send(0x2, b"stty size\n")
            assert b"31 101" in _receive_until(websocket, b"31 101")

            websocket.send(0x2, b"export STATEPORT_RECONNECT_MARKER=kept\n")
            websocket.send(0x8, struct.pack("!H", 1000) + b"refresh")
            _receive_close(websocket)
        finally:
            websocket.close()

        status, reconnect_payload = _prepare(service)
        reconnect_ticket = reconnect_payload["result"]
        assert status == 200 and reconnect_ticket["purpose"] == "reconnect"
        assert reconnect_ticket["sessionId"] == ticket["sessionId"]
        reconnect = RawWebSocket.open(service)
        try:
            assert reconnect.status == 101
            reconnect.send_json(_authentication(reconnect_ticket, "dev-one"))
            assert json.loads(reconnect.receive()[1])["purpose"] == "reconnect"
            reconnect.send(0x2, b"printf '%s\\n' \"$STATEPORT_RECONNECT_MARKER\"\n")
            assert b"kept" in _receive_until(reconnect, b"kept")
            reconnect.send_json({"formatVersion": SOCKET_FORMAT, "type": "end"})
            close = _receive_close(reconnect)
            assert struct.unpack("!H", close[:2])[0] == 1000
        finally:
            reconnect.close()

        state_files = tuple(Path(service["layout"].runtime_root).glob("terminal-broker-*/terminal-broker-state.json"))
        assert len(state_files) == 1
        assert _wait_for(lambda: json.loads(state_files[0].read_text(encoding="utf-8"))["activeSessions"] == [])
        persisted = state_files[0].read_text(encoding="utf-8")
        assert "stty size" not in persisted and "STATEPORT_RECONNECT_MARKER" not in persisted


def test_terminal_http_auth_csrf_capability_root_identity_and_ticket_replay(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with _service(tmp_path, monkeypatch) as service:
        status, value = _prepare(service, csrf="wrong")
        assert status == 403 and value["error"]["code"] == "terminal_access_denied"
        status, value = _prepare(service, origin="http://example.invalid")
        assert status == 403 and value["error"]["code"] == "terminal_access_denied"
        status, value = _prepare(service, "study-one")
        assert status == 403 and value["error"]["code"] == "terminal_access_denied"
        status, value = _prepare(service, extra={"command": "/bin/sh"})
        assert status == 400 and value["error"]["code"] == "operation_failed"

        wrong_cookie = RawWebSocket.open(service, cookie="stateport_session=wrong")
        try:
            assert wrong_cookie.status == 401
        finally:
            wrong_cookie.close()
        wrong_origin = RawWebSocket.open(service, origin="http://example.invalid")
        try:
            assert wrong_origin.status == 400
        finally:
            wrong_origin.close()

        status, prepared_payload = _prepare(service)
        assert status == 200
        ticket = prepared_payload["result"]
        duplicate_status, duplicate = _prepare(service)
        assert duplicate_status == 409 and duplicate["error"]["code"] == "terminal_refused"
        cross_instance = RawWebSocket.open(service)
        try:
            assert cross_instance.status == 101
            cross_instance.send_json(_authentication(ticket, "dev-two"))
            opcode, payload = cross_instance.receive()
            assert opcode == 0x8 and struct.unpack("!H", payload[:2])[0] == 1008
        finally:
            cross_instance.close()
        replay = RawWebSocket.open(service)
        try:
            assert replay.status == 101
            replay.send_json(_authentication(ticket, "dev-one"))
            opcode, payload = replay.receive()
            assert opcode == 0x8 and struct.unpack("!H", payload[:2])[0] == 1008
        finally:
            replay.close()

        secret_query = "SHOULD_NOT_ENTER_THE_SERVICE_LOG"
        dirty_url = RawWebSocket.open(service, path=f"{SOCKET_PATH}?token={secret_query}")
        try:
            assert dirty_url.status == 400
        finally:
            dirty_url.close()
        service_log = Path(service["layout"].logs_root) / "service.log"
        assert secret_query not in service_log.read_text(encoding="utf-8")

        displaced = tmp_path / "displaced-dev-one"
        service["projects"]["dev-one"].rename(displaced)
        _project_fixture(service["projects"]["dev-one"], "replacement")
        status, value = _prepare(service)
        assert status == 403 and value["error"]["code"] == "terminal_access_denied"


def test_terminal_upgrade_accepts_loopback_host_and_origin_aliases(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with _service(tmp_path, monkeypatch) as service:
        status, prepared_payload = _prepare(service)
        assert status == 200
        ticket = prepared_payload["result"]
        alias = f"localhost:{service['port']}"
        websocket = RawWebSocket.open(service, host=alias, origin=f"http://{alias}")
        try:
            assert websocket.response_version == "HTTP/1.1"
            assert websocket.status == 101
            websocket.send_json(_authentication(ticket, "dev-one"))
            opcode, ready_payload = websocket.receive()
            ready = json.loads(ready_payload)
            assert opcode == 0x1
            assert ready["type"] == "ready" and ready["sessionId"] == ticket["sessionId"]
            websocket.send_json({"formatVersion": SOCKET_FORMAT, "type": "end"})
            close = _receive_close(websocket)
            assert struct.unpack("!H", close[:2])[0] == 1000
        finally:
            websocket.close()


def test_rejected_http11_request_body_is_not_reparsed_on_the_connection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _service(tmp_path, monkeypatch) as service:
        port = int(service["port"])
        injected_request = f"GET /health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode("ascii")
        request = (
            f"POST /v1/instances/dev-one/terminal/prepare HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(injected_request)}\r\n"
            "Connection: keep-alive\r\n\r\n"
        ).encode("ascii") + injected_request
        connection = socket.create_connection(("127.0.0.1", port), timeout=3)
        try:
            connection.settimeout(3)
            connection.sendall(request)
            response = bytearray()
            while True:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                response.extend(chunk)
        finally:
            connection.close()

        assert bytes(response).count(b"HTTP/1.1 ") == 1
        assert b"HTTP/1.1 401" in response
        assert b"Connection: close" in response
        assert b"HTTP/1.1 200" not in response


@pytest.mark.parametrize(
    ("overrides", "status"),
    [
        ({"version": "12"}, 400),
        ({"key": "not-base64"}, 400),
        ({"protocol": "other.protocol"}, 400),
        ({"connection_header": "keep-alive, , Upgrade"}, 400),
        ({"connection_header": "Upgrade, bad token"}, 400),
        ({"connection_header": "close, Upgrade"}, 400),
        ({"extension": "unknown-extension"}, 400),
    ],
)
def test_terminal_upgrade_strictly_rejects_invalid_version_key_extension_and_subprotocol(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    overrides: dict[str, str],
    status: int,
) -> None:
    with _service(tmp_path, monkeypatch) as service:
        websocket = RawWebSocket.open(service, **overrides)
        try:
            assert websocket.status == status
        finally:
            websocket.close()


@pytest.mark.parametrize(
    "malformed",
    ["unmasked", "fragmented", "reserved", "oversized", "binary_auth"],
)
def test_terminal_socket_rejects_unmasked_fragmented_reserved_oversized_and_wrong_type_frames(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    malformed: str,
) -> None:
    with _service(tmp_path, monkeypatch) as service:
        status, prepared_payload = _prepare(service)
        assert status == 200
        auth = json.dumps(_authentication(prepared_payload["result"], "dev-one")).encode("utf-8")
        websocket = RawWebSocket.open(service)
        try:
            assert websocket.status == 101
            if malformed == "unmasked":
                websocket.send(0x1, auth, masked=False)
            elif malformed == "fragmented":
                websocket.send(0x1, auth, fin=False)
            elif malformed == "reserved":
                websocket.send(0x1, auth, rsv=0x40)
            elif malformed == "binary_auth":
                websocket.send(0x2, auth)
            else:
                websocket.stream.write(bytes((0x82, 0xFF)) + struct.pack("!Q", 65_537))
            opcode, payload = websocket.receive()
            assert opcode == 0x8
            expected = 1009 if malformed == "oversized" else 1008 if malformed == "binary_auth" else 1002
            assert struct.unpack("!H", payload[:2])[0] == expected
        finally:
            websocket.close()


def test_server_shutdown_closes_websocket_broker_and_descendant_process(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with _service(tmp_path, monkeypatch) as service:
        status, prepared_payload = _prepare(service)
        assert status == 200
        websocket = RawWebSocket.open(service)
        websocket.send_json(_authentication(prepared_payload["result"], "dev-one"))
        assert websocket.receive()[0] == 0x1
        websocket.send(0x2, b"sleep 30 & printf 'CHILD_STARTED\\n'\n")
        assert b"CHILD_STARTED" in _receive_until(websocket, b"CHILD_STARTED")
        state_files = tuple(Path(service["layout"].runtime_root).glob("terminal-broker-*/terminal-broker-state.json"))
        assert len(state_files) == 1
        active = json.loads(state_files[0].read_text(encoding="utf-8"))["activeSessions"]
        assert len(active) == 1
        generation = active[0]["generation"]
        assert _wait_for(
            lambda: len(terminal_broker_module._exact_generation_members(generation) or ()) >= 3
        )
        members = terminal_broker_module._exact_generation_members(generation)
        assert members is not None
        host_pids = [item[0] for item in members]
        assert service["app"].service_stop()["status"] == "stopped"
        assert all(_wait_for(lambda pid=pid: not Path(f"/proc/{pid}").exists()) for pid in host_pids)
        assert state_files and json.loads(state_files[0].read_text(encoding="utf-8"))["activeSessions"] == []
        websocket.close()


def test_persistent_service_periodically_enforces_terminal_expiry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    layout = LocalLayout.from_environment()
    layout.initialize()
    web_root = service_product_fixture(tmp_path, ROOT) / "apps" / "web"
    server = AppServer(("127.0.0.1", 0), layout, web_root)

    class ExpiryProbe:
        def __init__(self) -> None:
            self.swept = threading.Event()
            self.closed = False

        def sweep_expired(self) -> tuple[object, ...]:
            self.swept.set()
            return ()

        def close(self) -> None:
            self.closed = True

    probe = ExpiryProbe()
    server.terminal_brokers["expiry-fixture"] = (
        "identity", probe, object(), tmp_path, "profile", object(),
    )
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02})
    thread.start()
    try:
        assert probe.swept.wait(timeout=1.0), "serve_forever did not invoke the terminal lifetime sweep"
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()
    assert not thread.is_alive()
    assert probe.closed is True


def test_persistent_service_rejects_non_loopback_listener(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    layout = LocalLayout.from_environment()
    layout.initialize()
    web_root = service_product_fixture(tmp_path, ROOT) / "apps" / "web"
    with pytest.raises(ValueError, match="loopback-only"):
        AppServer(("0.0.0.0", 0), layout, web_root)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
