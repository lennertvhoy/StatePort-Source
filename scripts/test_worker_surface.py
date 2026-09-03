#!/usr/bin/env python3
"""Acceptance checks for the plan-only Compose worker surface."""

import json
import sys
import threading
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from http.server import ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]
for relative in (
    "apps/worker/src",
    "packages/container-runner/src",
    "packages/governed-runner/src",
    "packages/approval-gate/src",
    "packages/audit-log/src",
    "packages/quota-engine/src",
    "packages/statedd-core/src",
    "packages/template-validator/src",
    "packages/observability/src",
):
    sys.path.insert(0, str(ROOT / relative))

from stateport_worker.http import _Handler, _execution_enabled, _payload, _validate_bind_host


def test_worker_advertises_plan_only_non_networked_mode() -> None:
    result = _payload()["result"]
    assert result["service"] == "stateport-worker"
    assert result["executionEnabled"] is False
    assert result["containerExecutor"] == "disabled"
    assert result["mode"] == "queue"
    assert result["queueClaiming"] is False
    assert result["networkEnabled"] is False
    assert result["ready"] is True
    assert "lastError" not in result


def test_worker_execution_enablement_is_explicit_and_strict() -> None:
    assert _execution_enabled(None) is False
    assert _execution_enabled("false") is False
    assert _execution_enabled("true") is True
    try:
        _execution_enabled("sometimes")
    except ValueError:
        pass
    else:
        raise AssertionError("ambiguous worker execution setting must fail")


def test_worker_bind_is_loopback_by_default_and_public_binding_is_explicit() -> None:
    _validate_bind_host("127.0.0.1", False)
    _validate_bind_host("localhost", False)
    try:
        _validate_bind_host("0.0.0.0", False)
    except ValueError:
        pass
    else:
        raise AssertionError("worker must reject an accidental public bind")
    _validate_bind_host("0.0.0.0", True)


def test_worker_rejects_control_posts_over_http() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    request = Request(
        f"http://127.0.0.1:{server.server_address[1]}/v1/jobs",
        data=json.dumps({"job": "forbidden"}).encode("utf-8"),
        headers={"content-type": "application/json"},
        method="POST",
    )
    try:
        try:
            urlopen(request, timeout=3)
        except HTTPError as exc:
            payload = json.loads(exc.read())
            assert exc.code == 405
            assert payload["error"]["code"] == "method_not_allowed"
        else:
            raise AssertionError("worker control POST must be rejected")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_worker_live_and_ready_surfaces_are_distinct_and_safe() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.execution_enabled = False  # type: ignore[attr-defined]
    server.worker_loop = None  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for route, expected in (("/livez", "live"), ("/readyz", "standby")):
            with urlopen(f"http://127.0.0.1:{server.server_address[1]}{route}", timeout=3) as response:
                payload = json.loads(response.read())
                assert response.status == 200
                assert payload["result"]["status"] == expected
                assert response.headers["X-Request-ID"].startswith("sp-")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


if __name__ == "__main__":
    test_worker_advertises_plan_only_non_networked_mode()
    test_worker_rejects_control_posts_over_http()
    print("PASS")
