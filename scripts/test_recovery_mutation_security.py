#!/usr/bin/env python3
"""CSRF/origin regressions for application backup and synthetic validation."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import threading
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest


ROOT = Path(__file__).resolve().parents[1]
TEST_WEB_ROOT = ROOT / "apps" / "_recovery-security-test-web"
for source_root in sorted((ROOT / "packages").glob("*/src")):
    sys.path.insert(0, str(source_root))
for source_root in sorted((ROOT / "apps").glob("*/src")):
    sys.path.insert(0, str(source_root))

from stateport_persistent_app import LocalLayout, PersistentApp  # noqa: E402
from stateport_persistent_app.service_process import AppServer  # noqa: E402


def _post(
    port: int,
    path: str,
    *,
    cookie: str,
    csrf: str | None,
    origin: str,
    body: dict[str, object],
) -> tuple[int, dict[str, object]]:
    headers = {
        "Content-Type": "application/json",
        "Cookie": cookie,
        "Origin": origin,
    }
    if csrf is not None:
        headers["X-StatePort-CSRF"] = csrf
    request = Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(body).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urlopen(request) as response:
            return response.status, json.loads(response.read())
    except HTTPError as error:
        return error.code, json.loads(error.read())


@pytest.mark.parametrize(
    ("operation", "method_name", "denial_code"),
    [
        ("backup", "backup", "backup_access_denied"),
        ("synthetic-run", "synthetic_run", "synthetic_validation_denied"),
    ],
)
def test_recovery_mutations_require_exact_same_origin_csrf_and_empty_body(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    method_name: str,
    denial_code: str,
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    layout = LocalLayout.from_environment()
    layout.initialize()

    calls: list[str] = []
    expected = {"operation": operation, "semantics": "preserved"}

    def operation_probe(self: PersistentApp, instance_id: str) -> dict[str, str]:
        calls.append(instance_id)
        return expected

    monkeypatch.setattr(PersistentApp, method_name, operation_probe)
    # Recovery security tests do not serve frontend assets. Keep them
    # independent of the current production bundle while retaining the real
    # StatePort product root for policies and application descriptors.
    server = AppServer(("127.0.0.1", 0), layout, TEST_WEB_ROOT)
    thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.02},
        daemon=True,
    )
    thread.start()
    port = int(server.server_address[1])
    origin = f"http://127.0.0.1:{port}"
    try:
        with urlopen(f"{origin}/session") as response:
            session = json.loads(response.read())["result"]
            cookie = response.headers["Set-Cookie"].split(";", 1)[0]
        csrf = str(session["csrfToken"])
        path = f"/v1/instances/security-fixture/{operation}"

        for supplied_csrf, supplied_origin in (
            (None, origin),
            ("wrong-csrf", origin),
            (csrf, "https://attacker.example"),
        ):
            status, payload = _post(
                port,
                path,
                cookie=cookie,
                csrf=supplied_csrf,
                origin=supplied_origin,
                body={},
            )
            assert status == 403
            assert payload["error"]["code"] == denial_code
            assert calls == []

        status, payload = _post(
            port,
            path,
            cookie=cookie,
            csrf=csrf,
            origin=origin,
            body={"unexpected": True},
        )
        assert status == 400
        assert payload["error"]["code"] == "operation_failed"
        assert calls == []

        status, payload = _post(
            port,
            path,
            cookie=cookie,
            csrf=csrf,
            origin=origin,
            body={},
        )
        assert status == 200
        assert payload == {"ok": True, "result": expected}
        assert calls == ["security-fixture"]
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()
    assert not thread.is_alive()
