#!/usr/bin/env python3
"""Focused transport tests for the local StatePort control plane."""

from __future__ import annotations

import http.client
import json
import socket
import sys
import tempfile
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
for relative in (
    "packages/api-auth/src",
    "packages/governed-api/src",
    "packages/statedd-core/src",
    "packages/template-validator/src",
    "packages/approval-gate/src",
    "packages/quota-engine/src",
    "packages/audit-log/src",
    "packages/governed-runner/src",
    "packages/container-runner/src",
    "packages/observability/src",
    "apps/runner/src",
    "apps/api/src",
):
    sys.path.insert(0, str(ROOT / relative))

from stateport_api.http import (  # noqa: E402
    MAX_REQUEST_BYTES,
    create_server,
    shutdown_server,
    start_server,
)
from stateport_observability import JsonStreamSink, OperationalObserver  # noqa: E402


def _url(server: object) -> str:
    address = server.server_address  # type: ignore[attr-defined]
    return f"http://127.0.0.1:{address[1]}"


def _request(
    url: str,
    *,
    method: str = "GET",
    body: object | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, object], dict[str, str]]:
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = Request(url, data=data, method=method, headers=headers or {})
    if data is not None and "content-type" not in {key.lower() for key in request.headers}:
        request.add_header("content-type", "application/json")
    try:
        with urlopen(request, timeout=3) as response:
            return response.status, json.loads(response.read()), dict(response.headers.items())
    except HTTPError as exc:
        return exc.code, json.loads(exc.read()), dict(exc.headers.items())


def _header(headers: dict[str, str], name: str) -> str:
    return next(value for key, value in headers.items() if key.lower() == name.lower())


def test_safe_bind_defaults_and_explicit_public_opt_in() -> None:
    with tempfile.TemporaryDirectory() as workspace:
        server = create_server(workspace, port=0)
        server.server_close()
        try:
            create_server(workspace, host="0.0.0.0", port=0)
        except ValueError as exc:
            assert "refusing non-loopback bind" in str(exc)
        else:
            raise AssertionError("public bind must require explicit opt-in")
        public = create_server(workspace, host="0.0.0.0", port=0, allow_public_bind=True)
        public.server_close()


def test_health_headers_query_independent_routing_and_method_errors() -> None:
    with tempfile.TemporaryDirectory() as workspace:
        server = start_server(workspace, port=0)
        try:
            status, payload, headers = _request(_url(server) + "/health?diagnostic-secret=never-echo")
            assert status == 200
            assert payload["result"]["apiVersion"] == "stateport.api/v1"  # type: ignore[index]
            assert _header(headers, "X-StatePort-API-Version") == "stateport.api/v1"
            assert _header(headers, "X-StatePort-Transport-Version") == "1"
            assert _header(headers, "X-Content-Type-Options") == "nosniff"
            assert _header(headers, "Cache-Control") == "no-store"

            status, payload, _ = _request(_url(server) + "/livez")
            assert status == 200 and payload["result"]["status"] == "live"  # type: ignore[index]
            status, payload, _ = _request(_url(server) + "/readyz")
            assert status == 200 and payload["result"]["ready"] is True  # type: ignore[index]

            status, payload, _ = _request(
                _url(server) + "/health?diagnostic-secret=never-echo",
                method="PUT",
                body={},
            )
            assert status == 405
            assert payload["error"]["code"] == "method_not_allowed"  # type: ignore[index]
            assert "never-echo" not in json.dumps(payload)
            assert payload["error"]["diagnostic"]["requestId"].startswith("sp-")  # type: ignore[index]
        finally:
            shutdown_server(server)


def test_http_parser_errors_remain_in_the_json_transport_contract() -> None:
    with tempfile.TemporaryDirectory() as workspace:
        server = start_server(workspace, port=0)
        try:
            # BaseHTTPRequestHandler rejects an overlong header before route
            # dispatch and invokes its send_error hook with a non-501 status.
            # That hook must never fall back to the stdlib HTML error page.
            request = (
                b"GET /health HTTP/1.1\r\n"
                + f"Host: 127.0.0.1:{server.server_address[1]}\r\n".encode("ascii")
                + b"X-Oversized: "
                + b"A" * 70_000
                + b"\r\nConnection: close\r\n\r\n"
            )
            with socket.create_connection(
                ("127.0.0.1", server.server_address[1]),
                timeout=3,
            ) as connection:
                connection.sendall(request)
                response = http.client.HTTPResponse(connection)
                response.begin()
                payload = json.loads(response.read())
                assert response.status == 431
                assert response.getheader("Content-Type") == "application/json; charset=utf-8"
                assert payload["error"]["code"] == "invalid_request"
                assert payload["error"]["message"] == "the HTTP request could not be parsed"
                assert "A" * 100 not in json.dumps(payload)
        finally:
            shutdown_server(server)


def test_post_requires_strict_json_media_type_and_bounded_body() -> None:
    with tempfile.TemporaryDirectory() as workspace:
        server = start_server(workspace, port=0)
        base = _url(server)
        try:
            status, payload, _ = _request(
                base + "/v1/identity/check",
                method="POST",
                body={},
                headers={"Content-Type": "text/plain"},
            )
            assert status == 415 and payload["error"]["code"] == "unsupported_media_type"  # type: ignore[index]

            status, payload, _ = _request(
                base + "/v1/identity/check",
                method="POST",
                body={"value": float("nan")},
            )
            assert status == 400 and payload["error"]["code"] == "invalid_json"  # type: ignore[index]

            connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=3)
            connection.putrequest("POST", "/v1/identity/check")
            connection.putheader("Content-Type", "application/json")
            connection.putheader("Content-Length", str(MAX_REQUEST_BYTES + 1))
            connection.endheaders()
            response = connection.getresponse()
            assert response.status == 413
            payload = json.loads(response.read())
            assert payload["error"]["code"] == "request_too_large"
            connection.close()

            connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=3)
            connection.putrequest("POST", "/v1/identity/check")
            connection.putheader("Content-Type", "application/json")
            connection.endheaders(b"{}")
            response = connection.getresponse()
            assert response.status == 411
            assert json.loads(response.read())["error"]["code"] == "length_required"
            connection.close()
        finally:
            shutdown_server(server)


def test_browser_mutations_are_same_origin_only_and_errors_do_not_echo_secrets() -> None:
    with tempfile.TemporaryDirectory() as workspace:
        server = start_server(workspace, port=0)
        base = _url(server)
        try:
            status, payload, _ = _request(
                base + "/v1/identity/check",
                method="POST",
                body={"actor": "browser-secret"},
                headers={"Origin": "https://evil.example"},
            )
            assert status == 403
            assert payload["error"]["code"] == "csrf_failed"  # type: ignore[index]
            assert "browser-secret" not in json.dumps(payload)

            status, payload, _ = _request(
                base + "/v1/identity/check",
                method="POST",
                body={},
                headers={"Origin": base},
            )
            assert status != 403
            assert payload["error"]["code"] != "csrf_failed"  # type: ignore[index]
        finally:
            shutdown_server(server)


def test_loopback_dashboard_can_call_read_only_post_contracts_with_cors() -> None:
    with tempfile.TemporaryDirectory() as workspace:
        server = start_server(workspace, port=0)
        base = _url(server)
        try:
            status, payload, headers = _request(
                base + "/v1/approvals/list",
                method="OPTIONS",
                headers={
                    "Origin": "http://127.0.0.1:18080",
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "content-type",
                },
            )
            assert status == 200
            assert payload["result"]["cors"] == "loopback-only"  # type: ignore[index]
            assert _header(headers, "Access-Control-Allow-Origin") == "http://127.0.0.1:18080"
            assert "POST" in _header(headers, "Access-Control-Allow-Methods")

            status, payload, headers = _request(
                base + "/v1/approvals/list",
                method="POST",
                body={},
                headers={"Origin": "http://127.0.0.1:18080"},
            )
            assert status == 401
            assert payload["error"]["code"] == "identity_required"  # type: ignore[index]
            assert _header(headers, "Access-Control-Allow-Origin") == "http://127.0.0.1:18080"

            status, payload, _ = _request(
                base + "/v1/approvals/list",
                method="POST",
                body={},
                headers={"Origin": "https://evil.example"},
            )
            assert status == 403
            assert payload["error"]["code"] == "csrf_failed"  # type: ignore[index]
        finally:
            shutdown_server(server)


def test_shutdown_is_bounded_and_does_not_create_a_second_queue() -> None:
    with tempfile.TemporaryDirectory() as workspace:
        server = start_server(workspace, port=0, poll_interval=0.05)
        thread = server._stateport_thread  # type: ignore[attr-defined]
        shutdown_server(server, timeout=3)
        assert not thread.is_alive()
        assert not (Path(workspace) / ".stateport" / "jobs.sqlite3").exists()


def test_request_id_matches_one_safe_operational_event() -> None:
    import io

    with tempfile.TemporaryDirectory() as workspace:
        stream = io.StringIO()
        observer = OperationalObserver("stateport-api", JsonStreamSink(stream), minimum_level="debug")
        server = start_server(workspace, port=0, observer=observer)
        try:
            status, _, headers = _request(
                _url(server) + "/readyz?token=never-log",
                headers={
                    "X-Request-ID": "caller-controlled",
                    "Authorization": "Bearer never-log",
                    "Cookie": "session=never-log",
                },
            )
            assert status == 200
            request_id = _header(headers, "X-Request-ID")
            events = [json.loads(line) for line in stream.getvalue().splitlines()]
            assert len(events) == 1
            assert events[0]["requestId"] == request_id
            assert events[0]["route"] == "/readyz"
            encoded = json.dumps(events)
            assert "caller-controlled" not in encoded
            assert "never-log" not in encoded
        finally:
            shutdown_server(server)


if __name__ == "__main__":
    test_safe_bind_defaults_and_explicit_public_opt_in()
    test_health_headers_query_independent_routing_and_method_errors()
    test_post_requires_strict_json_media_type_and_bounded_body()
    test_browser_mutations_are_same_origin_only_and_errors_do_not_echo_secrets()
    test_loopback_dashboard_can_call_read_only_post_contracts_with_cors()
    test_shutdown_is_bounded_and_does_not_create_a_second_queue()
    print("PASS")
