#!/usr/bin/env python3
"""Operator-only StateBench platform inspection over verified RunBundles."""

from __future__ import annotations

import json
from pathlib import Path
import socket
import sys
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
for relative in (
    "packages/persistent-app/src",
    "packages/portable-execution/src",
    "packages/application-experience/src",
    "packages/conversation-service/src",
    "packages/context-lifecycle/src",
    "packages/goal-execution/src",
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

from run_bundle import RunBundleWriter  # noqa: E402
from stateport_persistent_app import LocalLayout, PersistentApp  # noqa: E402
from stateport_portable_execution import PortableExecutionService  # noqa: E402
from service_test_product import service_product_fixture  # noqa: E402


def _port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _session(port: int) -> str:
    with urlopen(f"http://127.0.0.1:{port}/session") as response:
        return response.headers["Set-Cookie"].split(";", 1)[0]


def _get(port: int, cookie: str, path: str, *, headers: dict[str, str] | None = None) -> dict[str, object]:
    request = Request(
        f"http://127.0.0.1:{port}{path}",
        headers={"Cookie": cookie, **(headers or {})},
    )
    with urlopen(request) as response:
        return json.loads(response.read())["result"]


def _verified_bundle(
    execution: PortableExecutionService,
    *,
    run_id: str = "operator-matrix-proof",
    degraded: list[object] | None = None,
    latency_ms: object = 12,
) -> dict[str, object]:
    state_digest = "sha256:" + "7" * 64
    reference = RunBundleWriter(execution.bundle_root / run_id).write(
        manifest={
            "runId": run_id,
            "instanceId": "public-fixture",
            "applicationId": "stateport.synthetic-reference",
            "status": "completed",
        },
        artifacts={
            "execution/agent-run-spec.json": {"formatVersion": "stateport.agent-run-spec/v1", "runId": run_id},
            "execution/result.json": {"canonicalStateUnchanged": True, "latencyMs": latency_ms, "unauthorizedMutations": 0},
            "execution/engine.json": {"engineId": "synthetic", "adapterId": "synthetic-action"},
            "execution/capability-negotiation.json": {"acceptedRun": True, "degraded": degraded or []},
            "identities/state-before.json": {"digest": state_digest},
            "identities/state-after.json": {"digest": state_digest},
        },
    )
    execution.store.create(
        {
            "runId": run_id,
            "instanceId": "public-fixture",
            "applicationId": "stateport.synthetic-reference",
            "status": "completed",
            "runBundle": reference,
        }
    )
    return reference


def test_trusted_startup_role_gates_path_free_statebench_matrix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    boundary = app.layout.config_root / "platform-operator-authority"
    boundary.write_text("test operator boundary\n", encoding="utf-8")
    boundary.chmod(0o600)
    execution = PortableExecutionService(app, ROOT)
    reference = _verified_bundle(
        execution,
        degraded=[{
            "id": "terminal.sandbox",
            "status": "unsupported",
            "reason": "fallback",
            "diagnostics": {"path": "/tmp/private/operator"},
        }],
    )
    _verified_bundle(
        execution,
        run_id="operator-matrix-malformed",
        degraded=[{"reason": "fallback", "path": "/tmp/private/operator"}],
    )
    _verified_bundle(
        execution,
        run_id="operator-matrix-non-finite",
        latency_ms=float("nan"),
    )

    local_port = _port()
    service_root = service_product_fixture(tmp_path, ROOT)
    app.service_start(port=local_port, repo_root=service_root)
    try:
        local_cookie = _session(local_port)
        local_status = _get(local_port, local_cookie, "/v1/status")
        assert local_status["actor"] == {
            "role": "local_user",
            "actorId": "local-user",
            "platformOperationsAllowed": False,
            "statebenchInspectionAllowed": False,
        }
        for path, headers in (
            ("/v1/platform/statebench", {}),
            ("/v1/platform/statebench?actor_role=platform_operator", {}),
            ("/v1/platform/statebench", {"X-StatePort-Actor-Role": "platform_operator"}),
        ):
            with pytest.raises(HTTPError) as denied:
                _get(local_port, local_cookie, path, headers=headers)
            assert denied.value.code == 403
            assert json.loads(denied.value.read())["error"]["code"] == "platform_operation_denied"
    finally:
        app.service_stop()

    operator_port = _port()
    runtime = app.service_start(
        port=operator_port,
        repo_root=service_root,
        actor_role="platform_operator",
    )
    try:
        assert runtime["actorRole"] == "platform_operator"
        operator_cookie = _session(operator_port)
        status = _get(operator_port, operator_cookie, "/v1/status")
        assert status["actor"] == {
            "role": "platform_operator",
            "actorId": "platform-operator",
            "platformOperationsAllowed": True,
            "statebenchInspectionAllowed": True,
        }
        matrix = _get(operator_port, operator_cookie, "/v1/platform/statebench")
        assert matrix["formatVersion"] == "stateport.platform-statebench-view/v1"
        assert matrix["verifiedRowCount"] == 1
        assert matrix["rejectedOrUnverifiedCount"] == 2
        assert matrix["authoritativePerformanceClaim"] is False
        assert matrix["rows"] == [
            {
                "formatVersion": "statebench.run-bundle-row/v1",
                "integrityStatus": "verified",
                "authoritative": False,
                "producerClaimsTrusted": False,
                "bundleDigest": reference["contentDigest"],
                "runId": "operator-matrix-proof",
                "applicationId": "stateport.synthetic-reference",
                "engineId": "synthetic",
                "adapterId": "synthetic-action",
                "status": "completed",
                "statePreserved": True,
                "capabilityDegradations": [{"id": "terminal.sandbox", "status": "unsupported"}],
                "acceptedRun": True,
                "usageAvailable": None,
                "latencyMs": 12,
                "unauthorizedMutations": 0,
                "bundleFileCount": 6,
            }
        ]
        encoded = json.dumps(matrix, sort_keys=True).lower()
        assert all(term not in encoded for term in ("/tmp/", "path", "qualityscore", "winner", "superiority", "hidden evaluator"))
    finally:
        app.service_stop()

    # The startup role and service permission checks above remain the
    # authority boundary. The typed client and routed consumer add
    # request-suppression for normal users without replacing that boundary.
    web_src = ROOT / "apps" / "web" / "src"
    endpoints = (web_src / "client" / "http" / "endpoints.ts").read_text(encoding="utf-8")
    assert "platformStateBench: '/v1/platform/statebench'" in endpoints
    manifest = yaml.safe_load(
        (ROOT / "config" / "functionality-preservation.v1.yaml").read_text(encoding="utf-8")
    )
    capability = next(
        item for item in manifest["capabilities"] if item["id"] == "statebench-evidence"
    )
    assert capability["status"] == "foundation"
    page = (web_src / "features" / "statebench" / "PlatformStateBenchPage.tsx").read_text(encoding="utf-8")
    assert "canInspectPlatformStateBench(status)" in page
    assert "client.platformStateBench.getMatrix(status)" in page
    assert "authoritativePerformanceClaim: false" in page


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
