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
            side_effect=RuntimeError("an unrelated local failure"),
        ):
            status, error = _get_error(origin, cookie, WORKLOADS_PATH)

    assert status == 400
    assert error["code"] == "operation_failed"
    assert error["message"] == "the local operation failed"
