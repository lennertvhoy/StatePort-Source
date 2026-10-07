#!/usr/bin/env python3
"""Typed execution-host refusals must survive the local GET error mapping.

An ``ExecutionHostProxyError`` already carries its own status and code. The
``do_POST`` mapping honours them; the ``do_GET`` mapping must do the same, or
an unavailable execution host is indistinguishable from any other local
failure and the browser trace records a bare ``operation_failed``.
"""

from __future__ import annotations

import contextlib
import json
from pathlib import Path
import sys
import threading
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest


ROOT = Path(__file__).resolve().parents[1]
for source_root in sorted((ROOT / "packages").glob("*/src")):
    sys.path.insert(0, str(source_root))
for source_root in sorted((ROOT / "apps").glob("*/src")):
    sys.path.insert(0, str(source_root))

from stateport_persistent_app import LocalLayout  # noqa: E402
from stateport_persistent_app.execution_host_proxy import (  # noqa: E402
    ExecutionHostProxyError,
)
from stateport_persistent_app.infrastructure import InfrastructureError  # noqa: E402
from stateport_persistent_app.service_process import AppServer  # noqa: E402
from service_test_product import service_product_fixture  # noqa: E402


WORKLOADS_PATH = "/v1/execution-host/workloads"


@contextlib.contextmanager
def _served_service(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Run the real local service and yield its origin and session cookie."""

    for key in ("XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_DATA_HOME"):
        monkeypatch.setenv(key, str(tmp_path / key))
    monkeypatch.delenv("STATEPORT_RELEASE_PROFILE", raising=False)
    layout = LocalLayout.from_environment()
    layout.initialize()
    web_root = service_product_fixture(tmp_path, ROOT) / "apps" / "web"
    server = AppServer(("127.0.0.1", 0), layout, web_root)
    thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.02},
        daemon=True,
    )
    thread.start()
    origin = f"http://127.0.0.1:{int(server.server_address[1])}"
    try:
        with urlopen(f"{origin}/session") as response:
            cookie = response.headers["Set-Cookie"].split(";", 1)[0]
        yield server, origin, cookie
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
        assert not thread.is_alive()


def _get_error(origin: str, cookie: str, path: str) -> tuple[int, dict]:
    """Return the status and parsed error body of a refused GET."""

    request = Request(
        f"{origin}{path}",
        headers={"Cookie": cookie},
        method="GET",
    )
    with pytest.raises(HTTPError) as refusal:
        urlopen(request)  # noqa: S310 - loopback test service
    body = json.loads(refusal.value.read())
    return int(refusal.value.code), body["error"]


def test_execution_host_refusal_keeps_its_own_status_and_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unavailable execution host is reported as itself, not as operation_failed."""

    with _served_service(tmp_path, monkeypatch) as (server, origin, cookie):
        refusal = ExecutionHostProxyError(
            "execution_unavailable",
            "the execution host socket is not available",
            status=503,
        )
        with patch.object(server.execution_host, "list", side_effect=refusal):
            status, error = _get_error(origin, cookie, WORKLOADS_PATH)

    assert status == 503
    assert error["code"] == "execution_unavailable"
    assert error["message"] == "the execution host socket is not available"


def test_unrelated_get_failure_still_uses_the_generic_refusal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The typed mapping stays narrow: other local failures are unchanged."""

    with _served_service(tmp_path, monkeypatch) as (server, origin, cookie):
        with patch.object(
            server.execution_host,
            "list",
            side_effect=RuntimeError("an unrelated local failure at /private/host/path"),
        ):
            status, error = _get_error(origin, cookie, WORKLOADS_PATH)

    assert status == 400
    assert error["code"] == "operation_failed"
    assert error["causeCode"] == "local_runtime_error"
    assert error["message"] == "The local service could not complete this request. Check service health and try again."
    assert "/private/host/path" not in json.dumps(error)


def test_unrelated_post_io_failure_names_safe_cause(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _served_service(tmp_path, monkeypatch) as (server, origin, cookie):
        with patch.object(server.execution_host, "exec", side_effect=OSError("/private/host/path")):
            request = Request(
                f"{origin}/v1/execution-host/workloads/exec",
                data=json.dumps({"workloadId": "agent-workspace", "argv": ["true"]}).encode(),
                headers={
                    "Cookie": cookie,
                    "Content-Type": "application/json",
                    "Origin": origin,
                    "X-StatePort-CSRF": server.csrf_token,
                },
                method="POST",
            )
            with pytest.raises(HTTPError) as refusal:
                urlopen(request)
            error = json.loads(refusal.value.read())["error"]

    assert refusal.value.code == 400
    assert error["code"] == "operation_failed"
    assert error["causeCode"] == "local_io_error"
    assert error["message"] == "A local resource could not be accessed. Check service setup and try again."
    assert "/private/host/path" not in json.dumps(error)


def test_infrastructure_operation_failed_names_command_cause(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _served_service(tmp_path, monkeypatch) as (server, origin, cookie):
        with patch.object(
            server,
            "infrastructure_adapter",
            side_effect=InfrastructureError("operation_failed", "private output /private/host/path"),
        ):
            request = Request(
                f"{origin}/v1/instances/demo/infrastructure/plan",
                data=json.dumps({"operation": "observe"}).encode(),
                headers={
                    "Cookie": cookie,
                    "Content-Type": "application/json",
                    "Origin": origin,
                    "X-StatePort-CSRF": server.csrf_token,
                },
                method="POST",
            )
            with pytest.raises(HTTPError) as refusal:
                urlopen(request)
            error = json.loads(refusal.value.read())["error"]

    assert refusal.value.code == 409
    assert error["code"] == "operation_failed"
    assert error["causeCode"] == "infrastructure_command_failed"
    assert error["message"] == "The infrastructure command failed. Review its run receipt and try again."
    assert "/private/host/path" not in json.dumps(error)
