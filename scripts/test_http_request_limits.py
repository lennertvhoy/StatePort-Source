"""Oversized requests get a real, bounded JSON refusal instead of a dropped connection.

Found by the hostile-input e2e row: a 20 MB body and a 100 KB query string made the
stdlib server close the socket, so the client saw a reset and no HTTP status.
"""
from __future__ import annotations

import http.client
import json
import socket
import sys
import threading
import time
from pathlib import Path
from urllib.request import urlopen

import pytest

ROOT = Path(__file__).resolve().parents[1]
TEST_WEB_ROOT = ROOT / "apps" / "_request-limits-test-web"
for source_root in sorted((ROOT / "packages").glob("*/src")):
    sys.path.insert(0, str(source_root))
for source_root in sorted((ROOT / "apps").glob("*/src")):
    sys.path.insert(0, str(source_root))

from stateport_persistent_app import LocalLayout  # noqa: E402
from stateport_persistent_app.service_process import AppServer  # noqa: E402


@pytest.fixture
def service(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    layout = LocalLayout.from_environment()
    layout.initialize()
    server = AppServer(("127.0.0.1", 0), layout, TEST_WEB_ROOT)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    port = int(server.server_address[1])
    origin = f"http://127.0.0.1:{port}"
    with urlopen(f"{origin}/session") as response:
        csrf = str(json.loads(response.read())["result"]["csrfToken"])
        cookie = response.headers["Set-Cookie"].split(";", 1)[0]
    try:
        yield port, origin, cookie, csrf
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def _request(port: int, method: str, path: str, body: bytes | None, headers: dict[str, str]) -> tuple[int, dict, str | None]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read()
        try:
            document = json.loads(raw)
        except ValueError:
            document = {"_nonjson": raw[:80].decode("utf-8", "replace")}
        return response.status, document, response.getheader("Content-Type")
    finally:
        connection.close()


def _auth(origin: str, cookie: str, csrf: str) -> dict[str, str]:
    return {"Cookie": cookie, "Origin": origin, "X-StatePort-CSRF": csrf, "Content-Type": "application/json"}


def test_a_20_mb_body_is_answered_413_not_a_dropped_connection(service) -> None:
    port, origin, cookie, csrf = service
    body = b'{"name": "' + b"z" * 20_000_000 + b'"}'
    status, document, content_type = _request(port, "POST", "/v1/application-fixtures/install", body, _auth(origin, cookie, csrf))
    assert status == 413
    assert document["ok"] is False
    assert document["error"]["code"] == "request_body_too_large"
    assert "KiB" in document["error"]["message"] and "Nothing was changed" in document["error"]["message"]
    assert content_type.startswith("application/json")


def test_a_declared_huge_body_is_refused_without_waiting_for_or_buffering_it(service) -> None:
    port, origin, cookie, csrf = service
    headers = "".join(f"{k}: {v}\r\n" for k, v in _auth(origin, cookie, csrf).items())
    request = (
        "POST /v1/application-fixtures/install HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{port}\r\n{headers}Content-Length: 5000000000\r\nConnection: close\r\n\r\n"
    ).encode()
    with socket.create_connection(("127.0.0.1", port), timeout=10) as connection:
        started = time.monotonic()
        connection.sendall(request + b"x" * 1000)
        response = http.client.HTTPResponse(connection)
        response.begin()
        document = json.loads(response.read())
    assert response.status == 413
    assert document["error"]["code"] == "request_body_too_large"
    assert time.monotonic() - started < 5


def test_an_unauthenticated_large_body_still_gets_its_401(service) -> None:
    port, _origin, _cookie, _csrf = service
    status, document, _ = _request(
        port, "POST", "/v1/application-fixtures/install", b"{" + b"z" * 5_000_000, {"Content-Type": "application/json"},
    )
    assert status == 401
    assert document["error"]["code"] == "session_required"


def test_a_100_kb_query_string_is_answered_414_json(service) -> None:
    port, origin, cookie, csrf = service
    status, document, content_type = _request(port, "GET", "/v1/instances?a=" + "b" * 100_000, None, {"Cookie": cookie})
    assert status == 414
    assert document["error"]["code"] == "request_target_too_long"
    assert "too long" in document["error"]["message"]
    assert content_type.startswith("application/json")


def test_a_70_kb_header_is_answered_431_in_the_json_envelope(service) -> None:
    port, origin, cookie, csrf = service
    status, document, content_type = _request(port, "GET", "/v1/instances", None, {"Cookie": cookie, "X-Big": "h" * 70_000})
    assert status == 431
    assert document["error"]["code"] == "request_headers_too_large"
    assert content_type.startswith("application/json")


def test_unsupported_method_is_a_json_501_and_service_keeps_serving(service) -> None:
    port, origin, cookie, csrf = service
    status, document, _ = _request(port, "BREW", "/v1/instances", None, {"Cookie": cookie})
    assert status == 501
    assert document["error"]["code"] == "request_method_unsupported"
    status, _, _ = _request(port, "GET", "/health", None, {"Cookie": cookie})
    assert status == 200
