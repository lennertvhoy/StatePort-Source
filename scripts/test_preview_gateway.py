#!/usr/bin/env python3
"""Route-level tests for the preview gateway (Stream B2 MS3).

Covers the authenticated route registry, the loopback-only HTTP reverse
proxy, WebSocket/HMR passthrough, cookie isolation, reserved and unregistered
destination refusals, cross-capsule isolation, expiry, revocation, and the
atomic rollback rewrite — all over the real web AppServer with plain-Python
echo fixtures. No containers, no network beyond loopback.
"""

from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import sys
import threading
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = Path(__file__).resolve().parent
for candidate in (SCRIPTS, ROOT / "fixtures" / "previews"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))
for source_root in sorted((ROOT / "packages").glob("*/src")):
    sys.path.insert(0, str(source_root))
for source_root in sorted((ROOT / "apps").glob("*/src")):
    sys.path.insert(0, str(source_root))

from stateport_preview_gateway import PreviewGatewayError, PreviewRouteRegistry  # noqa: E402

from echo_server import make_server  # noqa: E402
from test_platform_services_api import WebHarness, _request  # noqa: E402


REVISION_A = "sha256:" + "a" * 64
REVISION_B = "sha256:" + "b" * 64
CAPSULE = "capsule:demo-classdd:001"


@pytest.fixture()
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> WebHarness:
    # Explicit test-only opt-in: same-origin previews are disabled by default
    # and enabled here only to exercise the gateway plumbing itself.
    instance = WebHarness(tmp_path, monkeypatch, preview_gateway=True)
    try:
        yield instance
    finally:
        instance.close()


class EchoFixture:
    def __init__(self) -> None:
        self.server = make_server(0)
        self.port = int(self.server.server_address[1])
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        )
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()


@pytest.fixture()
def echo() -> EchoFixture:
    fixture = EchoFixture()
    try:
        yield fixture
    finally:
        fixture.close()


def _register(harness: WebHarness, port: int, *, capsule: str = CAPSULE, ttl: int = 3600) -> dict[str, object]:
    status, payload = harness.post(
        "/v1/preview-routes",
        {
            "capsuleId": capsule,
            "serviceId": "web",
            "revisionDigest": REVISION_A,
            "upstreamPort": port,
            "ttlSeconds": ttl,
        },
    )
    assert status == 200, payload
    return payload["result"]


def test_registry_mutation_returns_route_and_receipt_from_one_locked_write(tmp_path: Path) -> None:
    registry = PreviewRouteRegistry(tmp_path / "preview-state")
    mutation = registry.register(
        capsule_id=CAPSULE,
        service_id="web",
        revision_digest=REVISION_A,
        upstream_port=9,
        ttl_seconds=3600,
        actor="concurrent-test",
    )
    assert set(mutation) == {"route", "receipt"}
    assert mutation["route"]["routeId"] == mutation["receipt"]["routeId"]
    assert mutation["route"]["routeDigest"] == mutation["receipt"]["data"]["routeDigest"]


def test_concurrent_registration_has_one_winner_and_one_receipted_route(tmp_path: Path) -> None:
    root = tmp_path / "preview-state"
    registries = [PreviewRouteRegistry(root), PreviewRouteRegistry(root)]

    def attempt(registry: PreviewRouteRegistry) -> tuple[str, object]:
        try:
            return "ok", registry.register(
                capsule_id=CAPSULE,
                service_id="web",
                revision_digest=REVISION_A,
                upstream_port=9,
                ttl_seconds=3600,
                actor="concurrent-test",
            )
        except PreviewGatewayError as exc:
            return "error", exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(attempt, registries))

    assert [kind for kind, _value in outcomes].count("ok") == 1
    failures = [value for kind, value in outcomes if kind == "error"]
    assert len(failures) == 1
    assert isinstance(failures[0], PreviewGatewayError)
    assert failures[0].code in {"preview_gateway_busy", "preview_route_conflict"}
    assert len(PreviewRouteRegistry(root).list_routes()) == 1


def test_route_without_receipt_is_recovered_and_never_resolved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "preview-state"
    registry = PreviewRouteRegistry(root)

    def crash_after_route(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise RuntimeError("simulated crash before receipt persistence")

    monkeypatch.setattr(registry, "_append_receipt_unlocked", crash_after_route)
    with pytest.raises(RuntimeError, match="simulated crash"):
        registry.register(
            capsule_id=CAPSULE,
            service_id="web",
            revision_digest=REVISION_A,
            upstream_port=9,
            ttl_seconds=3600,
            actor="crash-test",
        )

    route_path = next((root / "routes").glob("route_*.json"))
    route_id = route_path.stem
    recovered = PreviewRouteRegistry(root)
    markers = recovered.recover()
    assert markers[0]["routeId"] == route_id
    assert recovered.recovery_status(route_id)["status"] == "recovery_required"
    assert recovered.list_routes() == []
    with pytest.raises(PreviewGatewayError) as refused:
        recovered.resolve(CAPSULE, "web")
    assert refused.value.code == "preview_route_not_found"


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ARG002
        return None


_NO_REDIRECT_OPENER = build_opener(_NoRedirect)


def _raw_get(port: int, path: str, *, cookie: str | None = None) -> tuple[int, dict[str, list[str]], bytes]:
    headers: dict[str, str] = {}
    if cookie is not None:
        headers["Cookie"] = cookie
    request = Request(f"http://127.0.0.1:{port}{path}", headers=headers, method="GET")
    try:
        with _NO_REDIRECT_OPENER.open(request, timeout=10) as response:
            collected: dict[str, list[str]] = {}
            for name, value in response.headers.items():
                collected.setdefault(name.lower(), []).append(value)
            return response.status, collected, response.read()
    except HTTPError as error:
        collected = {}
        for name, value in (error.headers or {}).items():
            collected.setdefault(name.lower(), []).append(value)
        return error.code, collected, error.read()


# ---------------------------------------------------------------------------
# Minimal browser-side WebSocket client (masked frames, strict handshake)
# ---------------------------------------------------------------------------


def _read_exact(connection: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        if not chunk:
            raise EOFError("server closed")
        data += chunk
    return data


def _client_frame(opcode: int, payload: bytes) -> bytes:
    head = bytearray([0x80 | opcode])
    if len(payload) < 126:
        head.append(0x80 | len(payload))
    else:
        head.append(0x80 | 126)
        head += struct.pack(">H", len(payload))
    mask = os.urandom(4)
    head += mask
    return bytes(head) + bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))


def _server_frame(connection: socket.socket) -> tuple[int, bytes]:
    head = _read_exact(connection, 2)
    opcode = head[0] & 0x0F
    length = head[1] & 0x7F
    if length == 126:
        length = struct.unpack(">H", _read_exact(connection, 2))[0]
    elif length == 127:
        length = struct.unpack(">Q", _read_exact(connection, 8))[0]
    return opcode, _read_exact(connection, length) if length else b""


def _ws_connect(
    port: int,
    path: str,
    *,
    cookie: str | None,
    origin: str | None,
    subprotocol: str | None = None,
) -> tuple[socket.socket, dict[str, str]]:
    connection = socket.create_connection(("127.0.0.1", port), timeout=10)
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: 127.0.0.1:{port}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
    ]
    if cookie is not None:
        lines.append(f"Cookie: {cookie}")
    if origin is not None:
        lines.append(f"Origin: {origin}")
    if subprotocol is not None:
        lines.append(f"Sec-WebSocket-Protocol: {subprotocol}")
    connection.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = connection.recv(4096)
        if not chunk:
            raise EOFError("server closed during handshake")
        head += chunk
    head_lines = head.split(b"\r\n\r\n", 1)[0].decode("latin-1").split("\r\n")
    status = head_lines[0]
    headers: dict[str, str] = {}
    for line in head_lines[1:]:
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    if " 101 " not in status:
        raise ConnectionError(f"WebSocket upgrade refused: {status} {headers}")
    expected = base64.b64encode(
        hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode(), usedforsecurity=False).digest()
    ).decode("ascii")
    assert headers.get("sec-websocket-accept") == expected
    return connection, headers


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_preview_route_management_requires_session_and_guard(
    harness: WebHarness, echo: EchoFixture
) -> None:
    body = {
        "capsuleId": CAPSULE,
        "serviceId": "web",
        "revisionDigest": REVISION_A,
        "upstreamPort": echo.port,
        "ttlSeconds": 3600,
    }
    status, _payload = _request(harness.port, "/v1/preview-routes", method="POST", body=body)
    assert status == 401

    route = _register(harness, echo.port)
    status, _payload = _request(
        harness.port,
        f"/preview/{CAPSULE}/web/echo",
        method="POST",
        cookie=harness.cookie,
        body={"mutation": True},
    )
    assert status == 403
    assert route["routeId"]

    status, payload = _request(
        harness.port, "/v1/preview-routes", method="POST", cookie=harness.cookie, body=body
    )
    assert status == 403
    assert payload["error"]["code"] == "preview_route_access_denied"

    status, payload = _request(
        harness.port,
        "/v1/preview-routes",
        method="POST",
        cookie=harness.cookie,
        csrf=harness.csrf,
        origin="https://attacker.example",
        body=body,
    )
    assert status == 403

    status, _headers, _body = _raw_get(harness.port, f"/preview/{CAPSULE}/web/echo")
    assert status == 401


def test_preview_http_proxy_and_index(harness: WebHarness, echo: EchoFixture) -> None:
    route = _register(harness, echo.port)
    assert route["receipt"]["routeId"] == route["routeId"]
    assert route["receipt"]["event"] == "registered"
    assert route["upstream"] == {"host": "127.0.0.1", "port": echo.port}
    assert route["revisionDigest"] == REVISION_A

    status, headers, body = _raw_get(
        harness.port, f"/preview/{CAPSULE}/web/echo/deep/path?x=1", cookie=harness.cookie
    )
    assert status == 200
    echoed = json.loads(body)
    assert echoed["fixture"] == "preview-echo"
    assert echoed["path"] == "/echo/deep/path?x=1"
    assert echoed["method"] == "GET"
    assert "content-length" in headers

    status, payload = harness.get("/v1/preview-routes")
    assert status == 200
    routes = payload["result"]["routes"]
    assert [entry["routeId"] for entry in routes] == [route["routeId"]]
    assert routes[0]["status"] == "active"


def test_preview_websocket_passthrough(harness: WebHarness, echo: EchoFixture) -> None:
    _register(harness, echo.port)
    connection, headers = _ws_connect(
        harness.port,
        f"/preview/{CAPSULE}/web/ws",
        cookie=harness.cookie,
        origin=harness.origin,
        subprotocol="vite-hmr",
    )
    try:
        assert headers.get("sec-websocket-protocol") == "vite-hmr"
        connection.sendall(_client_frame(0x1, b'{"type":"hmr:update"}'))
        opcode, payload = _server_frame(connection)
        assert opcode == 0x1
        assert payload == b'{"type":"hmr:update"}'
        connection.sendall(_client_frame(0x2, b"\x00\x01\x02"))
        opcode, payload = _server_frame(connection)
        assert opcode == 0x2
        assert payload == b"\x00\x01\x02"
        connection.sendall(_client_frame(0x8, struct.pack(">H", 1000)))
        opcode, _payload = _server_frame(connection)
        assert opcode == 0x8
    finally:
        connection.close()


def test_preview_websocket_requires_session(harness: WebHarness, echo: EchoFixture) -> None:
    _register(harness, echo.port)
    with pytest.raises(ConnectionError):
        _ws_connect(
            harness.port,
            f"/preview/{CAPSULE}/web/ws",
            cookie=None,
            origin=harness.origin,
        )


def test_preview_cookie_isolation(harness: WebHarness, echo: EchoFixture) -> None:
    _register(harness, echo.port)

    status, _headers, body = _raw_get(
        harness.port, f"/preview/{CAPSULE}/web/__headers", cookie=harness.cookie
    )
    assert status == 200
    observed = json.loads(body)
    assert observed["sawCookie"] is False
    upstream_headers = {name.lower() for name in observed["headers"]}
    assert "cookie" not in upstream_headers
    assert "x-stateport-csrf" not in upstream_headers
    assert observed["headers"].get("Host") == f"127.0.0.1:{echo.port}"

    status, headers, _body = _raw_get(
        harness.port, f"/preview/{CAPSULE}/web/__set-cookie", cookie=harness.cookie
    )
    assert status == 200
    cookies = headers.get("set-cookie", [])
    assert len(cookies) == 2
    base = f"/preview/{CAPSULE}/web"
    for value in cookies:
        assert f"Path={base}" in value
        assert "Domain" not in value
        assert "Secure" not in value
        assert "SameSite" not in value
    assert any(value.startswith("hmr_token=fixture") for value in cookies)
    assert any(value.startswith("preview_second=2") and "HttpOnly" in value for value in cookies)
    assert all("stateport_session" not in value for value in cookies)

    status, headers, _body = _raw_get(
        harness.port, f"/preview/{CAPSULE}/web/__redirect", cookie=harness.cookie
    )
    assert status == 302
    assert headers.get("location") == [f"{base}/echo/target"]


def test_preview_unregistered_and_cross_capsule_refusal(
    harness: WebHarness, echo: EchoFixture
) -> None:
    _register(harness, echo.port)

    status, payload = harness.get(f"/preview/{CAPSULE}/unknown-service/echo")
    assert status == 404
    assert payload["error"]["code"] == "preview_route_not_found"

    status, payload = harness.get("/preview/capsule:other:999/web/echo")
    assert status == 404
    assert payload["error"]["code"] == "preview_route_not_found"


def test_preview_reserved_destinations_and_traversal_refused(
    harness: WebHarness, echo: EchoFixture
) -> None:
    for reserved in ("engine", "engine-socket", "metadata", "control-plane"):
        status, payload = harness.post(
            "/v1/preview-routes",
            {
                "capsuleId": reserved,
                "serviceId": "web",
                "revisionDigest": REVISION_A,
                "upstreamPort": echo.port,
                "ttlSeconds": 60,
            },
        )
        assert status == 409
        assert payload["error"]["code"] == "preview_destination_refused"

        status, payload = harness.get(f"/preview/{reserved}/web/echo")
        assert status == 409
        assert payload["error"]["code"] == "preview_destination_refused"

    _register(harness, echo.port)
    status, payload = harness.get(f"/preview/{CAPSULE}/web/..%2F..%2Fv1%2Fstatus")
    assert status == 409
    assert payload["error"]["code"] == "preview_path_refused"


def test_preview_route_conflict_and_non_loopback_safety(
    harness: WebHarness, echo: EchoFixture
) -> None:
    _register(harness, echo.port)
    status, payload = harness.post(
        "/v1/preview-routes",
        {
            "capsuleId": CAPSULE,
            "serviceId": "web",
            "revisionDigest": REVISION_B,
            "upstreamPort": echo.port,
            "ttlSeconds": 60,
        },
    )
    assert status == 409
    assert payload["error"]["code"] == "preview_route_conflict"


def test_preview_route_expiry(
    harness: WebHarness, echo: EchoFixture, tmp_path: Path
) -> None:
    from datetime import datetime, timedelta, timezone  # noqa: PLC0415

    now = datetime(2026, 8, 3, tzinfo=timezone.utc)
    clock = {"value": now}
    registry = PreviewRouteRegistry(
        tmp_path / "preview-gateway-clock", clock=lambda: clock["value"]
    )
    harness.server._preview_route_registry = registry
    _register(harness, echo.port, ttl=3600)

    status, _headers, _body = _raw_get(
        harness.port, f"/preview/{CAPSULE}/web/echo", cookie=harness.cookie
    )
    assert status == 200

    clock["value"] = now + timedelta(hours=2)
    status, payload = harness.get(f"/preview/{CAPSULE}/web/echo")
    assert status == 409
    assert payload["error"]["code"] == "preview_route_expired"


def test_preview_route_rewrite_and_revoke(harness: WebHarness, echo: EchoFixture) -> None:
    second = EchoFixture()
    try:
        route = _register(harness, echo.port)
        route_id = route["routeId"]

        status, _headers, body = _raw_get(
            harness.port, f"/preview/{CAPSULE}/web/echo", cookie=harness.cookie
        )
        assert status == 200
        first_port = json.loads(body)["path"]
        assert first_port == "/echo"

        # Atomic rollback rewrite: the route rebinds to the exact predecessor
        # revision and its new upstream in one locked, receipted write.
        status, payload = harness.post(
            f"/v1/preview-routes/{route_id}/rewrite",
            {"revisionDigest": REVISION_B, "upstreamPort": second.port, "expectedRouteDigest": route["routeDigest"]},
        )
        assert status == 200, payload
        rewritten = payload["result"]
        assert rewritten["receipt"]["routeId"] == route_id
        assert rewritten["receipt"]["event"] == "rewritten"
        assert rewritten["revisionDigest"] == REVISION_B
        assert rewritten["upstream"]["port"] == second.port
        assert rewritten["routeDigest"] != route["routeDigest"]

        registry = PreviewRouteRegistry(harness.server.layout.state_root / "preview-gateway")
        receipts = registry.receipts(route_id)
        assert [entry["event"] for entry in receipts] == ["registered", "rewritten"]
        assert receipts[1]["data"]["previousRouteDigest"] == route["routeDigest"]
        assert receipts[1]["previousReceiptDigest"] == receipts[0]["receiptDigest"]

        # Revocation refuses typed and is receipted.
        status, payload = harness.post(
            f"/v1/preview-routes/{route_id}/revoke", {"reason": "rollback complete", "expectedRouteDigest": rewritten["routeDigest"]}
        )
        assert status == 200
        assert payload["result"]["revokedAt"] is not None
        assert payload["result"]["receipt"]["routeId"] == route_id
        assert payload["result"]["receipt"]["event"] == "revoked"

        status, payload = harness.get(f"/preview/{CAPSULE}/web/echo")
        assert status == 409
        assert payload["error"]["code"] == "preview_route_revoked"

        receipts = registry.receipts(route_id)
        assert [entry["event"] for entry in receipts] == ["registered", "rewritten", "revoked"]
    finally:
        second.close()


def test_preview_upstream_unavailable_is_typed(harness: WebHarness) -> None:
    # Register against a port with no listener: the proxy refuses typed.
    reservation = socket.socket()
    reservation.bind(("127.0.0.1", 0))
    dead_port = reservation.getsockname()[1]
    reservation.close()
    _register(harness, dead_port)

    status, payload = harness.get(f"/preview/{CAPSULE}/web/echo")
    assert status == 502
    assert payload["error"]["code"] == "preview_upstream_unavailable"


def test_stale_preview_operator_rewrite_and_revoke_preserve_new_binding(harness: WebHarness, echo: EchoFixture) -> None:
    route = _register(harness, echo.port)
    route_id = route["routeId"]
    rewrite_url = f"/v1/preview-routes/{route_id}/rewrite"
    revoke_url = f"/v1/preview-routes/{route_id}/revoke"
    status, payload = harness.post(rewrite_url, {"revisionDigest": REVISION_B, "upstreamPort": echo.port, "expectedRouteDigest": route["routeDigest"]})
    assert status == 200
    current = payload["result"]
    root = harness.server.layout.state_root / "preview-gateway"
    before = {str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*.json")}
    for url, body in [(rewrite_url, {"revisionDigest": REVISION_A, "upstreamPort": echo.port, "expectedRouteDigest": route["routeDigest"]}), (revoke_url, {"reason": "stale screen", "expectedRouteDigest": route["routeDigest"]})]:
        status, payload = harness.post(url, body)
        assert status == 409
        assert payload["error"]["code"] == "preview_route_conflict"
        assert {str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*.json")} == before
    # Reopen the durable registry; the stale requests produced no mutation receipts.
    reopened = PreviewRouteRegistry(root)
    assert reopened.get(route_id)["routeDigest"] == current["routeDigest"]
    assert len(reopened.receipts(route_id)) == 2
    assert current["previewPath"] == "/preview/capsule%3Ademo-classdd%3A001/web/"
    status, _ = harness.get(current["previewPath"] + "echo")
    assert status == 200
    status, payload = harness.post(revoke_url, {"reason": "reviewed current binding", "expectedRouteDigest": current["routeDigest"]})
    assert status == 200
    assert payload["result"]["previewPath"] is None
    assert PreviewRouteRegistry(root).get(route_id)["status"] == "revoked"
    status, _ = harness.get(current["previewPath"] + "echo")
    assert status == 409
