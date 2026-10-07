"""Runtime entrypoint and loopback health/readiness contract tests."""

from __future__ import annotations

import json
import io
import logging
from pathlib import Path
import sys
from http import HTTPStatus
from http.client import HTTPConnection
import socket
from threading import Event, Thread
from typing import Mapping
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest


ROOT = Path(__file__).resolve().parents[1]
for source in (
    ROOT,
    ROOT / "packages/release-contracts/src",
    ROOT / "packages/governed-runner/src",
    ROOT / "packages/updater/src",
):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from stateport_updater import UpdatePolicy, UpdateStore  # noqa: E402
from stateport_updater.cli import main  # noqa: E402
from stateport_updater.service import (  # noqa: E402
    ServiceStatus,
    UpdaterDiagnostics,
    UpdaterServiceError,
    build_server,
)
from stateport_updater.store import StoreError  # noqa: E402
from scripts.test_stateport_updater import (  # noqa: E402
    FixtureAuthority,
    FixtureHost,
    POLICY,
    NOW,
    _EphemeralTestVerifier,
    envelope,
)
from stateport_updater.engine import UpdateEngine  # noqa: E402


def initialized_state(root: Path) -> None:
    release, _document, _identity = envelope(
        "stateport-alpha-0.1.0-rc.1", "0.1.0-rc.1", predecessor=None
    )
    engine = UpdateEngine(
        UpdateStore.create(root),
        FixtureHost(),
        FixtureAuthority(),
        verification_policy=POLICY,
        signature_verifier=_EphemeralTestVerifier(),
        clock=lambda: NOW,
    )
    engine.initialize(release, UpdatePolicy(mode="download-and-notify", channel="alpha"))


def get(base: str, path: str) -> tuple[int, dict[str, object], Mapping[str, str]]:
    request = Request(base + path, headers={"X-Request-Id": "fixture-request"})
    try:
        response = urlopen(request, timeout=5)
    except HTTPError as exc:
        response = exc
    with response:
        return response.status, json.loads(response.read()), response.headers


def test_loopback_service_exposes_health_readiness_and_canonical_status(
    tmp_path: Path,
) -> None:
    state_root = tmp_path / "state"
    initialized_state(state_root)
    server = build_server(
        listen="127.0.0.1",
        port=0,
        state_root=state_root,
        service_version="0.1.0",
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        health, health_body, headers = get(base, "/healthz")
        ready, ready_body, _ = get(base, "/readyz")
        status, status_body, _ = get(base, "/v1/status")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert health == ready == status == 200
    assert health_body["service"] == "stateport-updater"
    assert ready_body["statusDigest"].startswith("sha256:")
    assert status_body["schema"] == "stateport.update-status/v1"
    assert headers["X-Request-Id"] == "fixture-request"
    assert headers["Cache-Control"] == "no-store"
    assert headers.get("Server") is None


def test_uninitialized_readiness_is_503_but_liveness_remains_200(tmp_path: Path) -> None:
    state_root = tmp_path / "missing-state"
    server = build_server(
        listen="127.0.0.1",
        port=0,
        state_root=state_root,
        service_version="0.1.0",
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        health, _, _ = get(base, "/healthz")
        ready, body, _ = get(base, "/readyz")
        status, status_body, _ = get(base, "/v1/status")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert health == 200
    assert ready == 503
    assert status == 503
    assert body["status"] == "not_ready"
    assert status_body["status"] == "unavailable"
    assert not state_root.exists()


def test_service_refuses_public_bind_and_http_mutation(tmp_path: Path) -> None:
    with pytest.raises(UpdaterServiceError) as refused:
        build_server(
            listen="0.0.0.0",
            port=8091,
            state_root=tmp_path / "state",
            service_version="0.1.0",
        )
    assert refused.value.code == "public_bind_refused"

    state_root = tmp_path / "initialized"
    initialized_state(state_root)
    server = build_server(
        listen="127.0.0.1",
        port=0,
        state_root=state_root,
        service_version="0.1.0",
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            request = Request(
                f"http://127.0.0.1:{server.server_port}/v1/status",
                method=method,
                data=b"{}",
            )
            with pytest.raises(HTTPError) as response:
                urlopen(request, timeout=5)
            assert response.value.code == 405
            assert response.value.headers["Allow"] == "GET, HEAD"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_cli_health_and_relative_state_root_refusal(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["--state-root", str(tmp_path / "state"), "health"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "alive"
    assert main(["--state-root", "relative", "status"]) == 2
    output = json.loads(capsys.readouterr().out)
    assert output["code"] == "state_root_invalid"


def test_cli_health_is_pure_and_does_not_create_state_root(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    absent = tmp_path / "must-not-exist"
    assert main(["--state-root", str(absent), "health"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "alive"
    assert not absent.exists()


def test_standalone_mutation_refuses_without_installed_authority_subject(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    absent = tmp_path / "must-not-exist"
    assert (
        main(
            [
                "--state-root",
                str(absent),
                "apply",
                "--plan-id",
                "update_plan_" + "a" * 32,
            ]
        )
        == 3
    )
    assert json.loads(capsys.readouterr().out) == {
        "schema": "stateport.updater-error/v1",
        "code": "installed_authority_adapter_required",
        "status": "not_executed",
    }
    assert not absent.exists()


def test_diagnostics_use_one_snapshot_and_busy_is_actionable() -> None:
    class OneSnapshotStore:
        calls = 0

        def snapshot(self) -> tuple[dict[str, object], None]:
            self.calls += 1
            raise StoreError("update_state_busy", "fixture lock is busy")

    store = OneSnapshotStore()
    diagnostics = UpdaterDiagnostics(store, service_version="0.1.0")  # type: ignore[arg-type]
    result = diagnostics.status()
    assert store.calls == 1
    assert result.http_status == 503
    assert result.payload["code"] == "update_state_busy"
    assert result.headers == {"Retry-After": "1"}

    class ExplodingStore:
        def snapshot(self) -> tuple[dict[str, object], None]:
            raise RuntimeError("secret-token /home/operator/private")

    failed = UpdaterDiagnostics(  # type: ignore[arg-type]
        ExplodingStore(), service_version="0.1.0"
    ).status()
    assert failed.http_status == 503
    assert failed.payload["code"] == "diagnostics_failed"
    assert "secret-token" not in json.dumps(failed.payload)


def test_status_projects_pending_wal_from_the_same_snapshot(tmp_path: Path) -> None:
    state_root = tmp_path / "state"
    initialized_state(state_root)
    persisted = UpdateStore.open_existing(state_root).status()

    class PendingSnapshotStore:
        calls = 0

        def snapshot(self) -> tuple[dict[str, object], dict[str, object]]:
            self.calls += 1
            return persisted, {
                "phase": "intent_pull",
                "intent": {"step": "pull"},
                "updatedAt": "2026-08-01T12:00:01Z",
            }

    store = PendingSnapshotStore()
    diagnostics = UpdaterDiagnostics(store, service_version="0.1.0")  # type: ignore[arg-type]
    result = diagnostics.status()
    assert store.calls == 1
    assert result.http_status == 200
    assert result.payload["phase"] == "downloading"
    assert result.payload["updatedAt"] == "2026-08-01T12:00:01Z"


def test_query_tokens_are_never_logged_and_header_bounds_fail_closed(
    tmp_path: Path,
) -> None:
    state_root = tmp_path / "state"
    initialized_state(state_root)
    stream = io.StringIO()
    logger = logging.Logger("updater-test")
    logger.addHandler(logging.StreamHandler(stream))
    server = build_server(
        listen="127.0.0.1",
        port=0,
        state_root=state_root,
        service_version="0.1.0",
        logger=logger,
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, _body, _headers = get(
            f"http://127.0.0.1:{server.server_port}",
            "/healthz?access_token=never-log-this",
        )
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        connection.putrequest("GET", "/healthz")
        for position in range(33):
            connection.putheader(f"X-Fixture-{position}", "bounded")
        connection.endheaders()
        response = connection.getresponse()
        response.read()
        connection.close()

        oversized = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        oversized.request("GET", "/healthz", headers={"X-Oversized": "x" * 9000})
        oversized_response = oversized.getresponse()
        oversized_response.read()
        oversized.close()

        raw = socket.create_connection(("127.0.0.1", server.server_port), timeout=5)
        raw.sendall(b"GET http://[ HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        malformed = raw.recv(4096)
        raw.close()

        hidden, _hidden_body, _hidden_headers = get(
            f"http://127.0.0.1:{server.server_port}",
            "/private-component-never-log",
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert status == 200
    assert response.status == 431
    assert oversized_response.status == 431
    assert b" 400 " in malformed
    assert "never-log-this" not in stream.getvalue()
    assert hidden == 404
    assert "private-component-never-log" not in stream.getvalue()
    assert '"path":"unmatched-route"' in stream.getvalue()
    assert '"path":"/healthz"' in stream.getvalue()


def test_head_and_host_public_status_metadata_are_explicit(tmp_path: Path) -> None:
    state_root = tmp_path / "state"
    initialized_state(state_root)
    server = build_server(
        listen="127.0.0.1",
        port=0,
        state_root=state_root,
        service_version="0.1.0",
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    try:
        connection.request("HEAD", "/v1/status")
        response = connection.getresponse()
        body = response.read()
    finally:
        connection.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert response.status == 200
    assert body == b""
    assert int(response.headers["Content-Length"]) > 0
    assert response.headers["X-StatePort-Data-Classification"] == "host-public"


def test_malformed_mutation_and_unexpected_diagnostics_return_bounded_json(
    tmp_path: Path,
) -> None:
    state_root = tmp_path / "state"
    initialized_state(state_root)
    stream = io.StringIO()
    logger = logging.Logger("updater-redaction-test")
    logger.addHandler(logging.StreamHandler(stream))
    server = build_server(
        listen="127.0.0.1",
        port=0,
        state_root=state_root,
        service_version="0.1.0",
        logger=logger,
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        raw = socket.create_connection(("127.0.0.1", server.server_port), timeout=5)
        raw.sendall(
            b"POST http://[ HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n"
            b"Connection: close\r\n\r\n"
        )
        chunks = bytearray()
        while chunk := raw.recv(4096):
            chunks.extend(chunk)
        raw.close()

        def explode() -> ServiceStatus:
            raise RuntimeError("secret-token /home/operator/private")

        server.diagnostics.health = explode  # type: ignore[method-assign]
        with pytest.raises(HTTPError) as response:
            urlopen(f"http://127.0.0.1:{server.server_port}/healthz", timeout=5)
        body = json.loads(response.value.read())
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    header, raw_body = bytes(chunks).split(b"\r\n\r\n", 1)
    assert b" 400 " in header
    assert b"application/json" in header
    assert json.loads(raw_body)["code"] in {"request_invalid", "request_target_invalid"}
    assert response.value.code == 500
    assert body["code"] == "diagnostics_failed"
    assert len(json.dumps(body)) < 1024
    assert "secret-token" not in stream.getvalue()
    assert "/home/operator" not in stream.getvalue()


def test_bounded_concurrency_returns_deterministic_503(tmp_path: Path) -> None:
    state_root = tmp_path / "state"
    initialized_state(state_root)
    server = build_server(
        listen="127.0.0.1",
        port=0,
        state_root=state_root,
        service_version="0.1.0",
        maximum_concurrency=1,
    )
    entered = Event()
    release = Event()

    def blocked_health() -> ServiceStatus:
        entered.set()
        assert release.wait(timeout=5)
        return ServiceStatus(
            HTTPStatus.OK,
            {"schema": "stateport.updater-health/v1", "status": "alive"},
        )

    server.diagnostics.health = blocked_health  # type: ignore[method-assign]
    serving = Thread(target=server.serve_forever, daemon=True)
    serving.start()
    first: list[tuple[int, dict[str, object], Mapping[str, str]]] = []
    request = Thread(
        target=lambda: first.append(get(f"http://127.0.0.1:{server.server_port}", "/healthz"))
    )
    request.start()
    assert entered.wait(timeout=5)
    try:
        second, body, headers = get(
            f"http://127.0.0.1:{server.server_port}",
            "/healthz",
        )
    finally:
        release.set()
        request.join(timeout=5)
        server.shutdown()
        server.server_close()
        serving.join(timeout=5)
    assert second == 503
    assert body["code"] == "service_busy"
    assert headers["Retry-After"] == "1"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Content-Security-Policy"] == "default-src 'none'"
    assert headers["X-Request-Id"].startswith("req-")
    assert first and first[0][0] == 200


def test_ipv6_server_is_v6_only_when_loopback_is_available(tmp_path: Path) -> None:
    if not socket.has_ipv6:
        pytest.skip("IPv6 is unavailable")
    state_root = tmp_path / "state"
    initialized_state(state_root)
    try:
        server = build_server(
            listen="::1",
            port=0,
            state_root=state_root,
            service_version="0.1.0",
        )
    except UpdaterServiceError as exc:
        if exc.code == "bind_failed":
            pytest.skip("IPv6 loopback is unavailable")
        raise
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = HTTPConnection("::1", server.server_port, timeout=5)
    try:
        connection.request("GET", "/healthz")
        response = connection.getresponse()
        response.read()
    finally:
        connection.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert response.status == 200
    assert server.socket.family == socket.AF_INET6
