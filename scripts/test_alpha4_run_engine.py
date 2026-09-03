#!/usr/bin/env python3
"""Focused tests for the authority-bound, daemon-observed RunEngine path."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import threading
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "execution-host" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "runtime-contracts" / "src"))

from execution_host import daemon_contract  # noqa: E402
from execution_host.client import ExecutionHostClient  # noqa: E402
from execution_host.provider_bindings import (  # noqa: E402
    ProviderBindingManager,
    ProviderSecretUnavailable,
    RunEvidenceService,
)
from execution_host.run_authority import RunAuthority, RunGrant  # noqa: E402
from execution_host.run_engine import RunEngine, RunEngineError  # noqa: E402
from execution_host.run_lease import RunCompletionGate  # noqa: E402
from runtime_contracts import canonical_digest  # noqa: E402

DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64
DAEMON_GRANT_DIGEST = "sha256:" + "e" * 64
IMAGE = "example.invalid/stateagent@sha256:" + "a" * 64
HOST = "exec-1"
KIND = "execution-host-agent-container"
PROVIDER_VALUE = "synthetic-provider-token"


def _owner_grant() -> RunGrant:
    return RunGrant(
        grant_id="grant.1",
        executor_kind=KIND,
        claimed_image=IMAGE,
        host=HOST,
        scope="test grant",
        issued_at="2026-08-08T00:00:00Z",
        digest_pin=DIGEST,
    )


OWNER_GRANT_DIGEST = _owner_grant().authority_digest


class ScriptedDaemonTransport:
    """Contract-valid transport seam used by a concrete ExecutionHostClient."""

    def __init__(
        self,
        *,
        exit_status: int | None = 0,
        output: str = "run-output",
        image_digest: str | None = DIGEST,
        terminal_state: str = "exited",
        on_create=None,
        on_start=None,
        fail_status: bool = False,
        fail_create_after_effect: bool = False,
        cancel_failures: int = 0,
        remove_failures: int = 0,
    ) -> None:
        self.workloads: list[dict[str, Any]] = []
        self.started: list[str] = []
        self.cancelled: list[str] = []
        self.removed: list[str] = []
        self.operations: list[str] = []
        self.cancel_attempts = 0
        self.remove_attempts = 0
        self._exit_status = exit_status
        self._output = output
        self._image = image_digest
        self._terminal_state = terminal_state
        self._state = "absent"
        self._on_create = on_create
        self._on_start = on_start
        self._fail_status = fail_status
        self._fail_create_after_effect = fail_create_after_effect
        self._cancel_failures = cancel_failures
        self._remove_failures = remove_failures
        self._lock = threading.Lock()

    @staticmethod
    def _observed(image_digest: str | None, exit_status: int | None) -> dict[str, Any]:
        return {
            "engine": "controlled-test-transport",
            "engineVersion": "1",
            "imageDigest": image_digest,
            "exitStatus": exit_status,
            "startedAt": "2026-08-09T00:00:00Z",
            "finishedAt": "2026-08-09T00:00:01Z",
        }

    @staticmethod
    def _receipt(request: dict[str, Any], result: Any, observed: dict[str, Any]) -> bytes:
        receipt = {
            "formatVersion": daemon_contract.RECEIPT_FORMAT,
            "operationId": request["operationId"],
            "requestDigest": daemon_contract.canonical_digest(request),
            "accepted": True,
            "refusal": None,
            "requester": {
                "uid": 1000,
                "gid": 1000,
                "pid": 1234,
                "grantId": request["requester"]["grantId"],
            },
            "result": result,
            "observed": observed,
            "cleanup": {"outcome": "not-required", "detail": "controlled test transport"},
            "timestamps": {
                "receivedAt": "2026-08-09T00:00:00Z",
                "completedAt": "2026-08-09T00:00:01Z",
            },
        }
        return (daemon_contract.canonical_json(receipt) + "\n").encode()

    def exchange(
        self,
        line: bytes,
        effective_timeout: int,
        *,
        source_fd: int | None = None,
    ) -> bytes:
        del effective_timeout
        if source_fd is not None:
            raise AssertionError("agent-run transport does not accept source descriptors")
        request = json.loads(line)
        operation = request["operation"]
        callback = None
        with self._lock:
            self.operations.append(operation)
            workload_id = (request.get("payload") or {}).get("workloadId")
            if operation == "createWorkload":
                workload = dict(request["payload"]["workload"])
                workload_id = workload["workloadId"]
                self.workloads.append(workload)
                self._state = "created"
                callback = self._on_create
                if self._fail_create_after_effect:
                    raise RuntimeError("response lost after daemon create")
                result = {"workloadId": workload_id, "state": "created"}
            elif operation == "start":
                self.started.append(workload_id)
                self._state = "running"
                callback = self._on_start
                result = {"workloadId": workload_id, "state": "running"}
            elif operation == "status":
                if self._fail_status:
                    raise RuntimeError("daemon unreachable")
                if self._state == "running" and self._terminal_state != "running":
                    self._state = self._terminal_state
                result = {
                    "workloadId": workload_id,
                    "state": self._state,
                    "exitStatus": self._exit_status,
                }
            elif operation == "logs":
                result = {
                    "workloadId": workload_id,
                    "output": self._output,
                    "byteCount": len(self._output.encode()),
                    "truncated": False,
                }
            elif operation == "cancel":
                self.cancel_attempts += 1
                if self.cancel_attempts <= self._cancel_failures:
                    raise RuntimeError("transient cancel failure")
                self.cancelled.append(workload_id)
                self._state = "cancelled"
                result = {"workloadId": workload_id, "state": "cancelled"}
            elif operation == "removeWorkload":
                self.remove_attempts += 1
                if self.remove_attempts <= self._remove_failures:
                    raise RuntimeError("transient remove failure")
                self.removed.append(workload_id)
                self._state = "removed"
                result = {"workloadId": workload_id, "state": "removed"}
            else:
                raise AssertionError(f"unexpected operation {operation}")
            observed = self._observed(self._image, self._exit_status)
        if callback is not None:
            callback()
        return self._receipt(request, result, observed)


class DuckHostClient:
    """Old caller-fabricable evidence adapter; RunEngine must reject it."""

    authority_grant_digest = DAEMON_GRANT_DIGEST

    def create_workload(self, workload):
        raise AssertionError("duck client must never be called")


def _spec(run_id: str = "run.1", time_seconds: int = 30) -> dict[str, Any]:
    return {
        "formatVersion": "stateport.managed-agent-run/v1",
        "runId": run_id,
        "workspaceId": "ws.1",
        "baseRevision": "d" * 40,
        "stagingPath": "/staging/candidate",
        "imageDigest": DIGEST,
        "provider": "synthetic",
        "model": "synthetic-model",
        "networkProfile": {"mode": "disabled", "allowlist": []},
        "authorityGrantDigest": OWNER_GRANT_DIGEST,
        "budgets": {"timeSeconds": time_seconds, "token": 100, "costMinor": 0, "steps": 10},
        "resources": {
            "memoryMaxBytes": 268435456,
            "cpuQuotaPercent": 100,
            "pidsMax": 128,
            "diskMaxBytes": 67108864,
        },
        "validationCommands": [],
    }


def _engine(
    tmp_path: Path,
    authority: RunAuthority | None = None,
) -> tuple[RunEngine, ProviderBindingManager, RunAuthority]:
    authority = authority or RunAuthority(host=HOST)
    if not authority.grant("grant.1"):
        authority.register(_owner_grant())
    manager = ProviderBindingManager(env={"SP_TEST_TOKEN": PROVIDER_VALUE})
    manager.define_config(
        "cfg.1",
        provider="synthetic",
        model="synthetic-model",
        token_env="SP_TEST_TOKEN",
    )
    engine = RunEngine(
        authority=authority,
        evidence_service=RunEvidenceService(),
        completion_gate=RunCompletionGate(),
        provider_manager=manager,
        state_dir=str(tmp_path / "runs"),
        monitor_poll_delay=0.001,
    )
    return engine, manager, authority


def _client(
    transport: ScriptedDaemonTransport, *, digest: str = DAEMON_GRANT_DIGEST
) -> ExecutionHostClient:
    client = ExecutionHostClient(
        "/controlled/test/execution-host.sock",
        grant_id="daemon-grant.1",
        authority_grant_digest=digest,
    )
    client._exchange = transport.exchange  # type: ignore[method-assign]
    return client


def _run(engine: RunEngine, client: ExecutionHostClient, spec: dict[str, Any] | None = None):
    return engine.run(
        specification=_spec() if spec is None else spec,
        client=client,
        claimed_image=IMAGE,
        host=HOST,
        config_id="cfg.1",
    )


def test_duck_typed_client_is_refused_before_a_lease_or_effect(tmp_path: Path) -> None:
    engine, _, _ = _engine(tmp_path)
    with pytest.raises(RunEngineError, match="concrete typed ExecutionHostClient"):
        engine.run(
            specification=_spec(),
            client=DuckHostClient(),  # type: ignore[arg-type]
            claimed_image=IMAGE,
            host=HOST,
            config_id="cfg.1",
        )
    assert list((engine.lifecycle.state_dir / "leases").glob("lease.*.json")) == []


def test_wrong_owner_grant_digest_refuses_before_lease_or_effect(tmp_path: Path) -> None:
    engine, _, _ = _engine(tmp_path)
    transport = ScriptedDaemonTransport()
    spec = _spec()
    spec["authorityGrantDigest"] = OTHER_DIGEST
    with pytest.raises(RunEngineError, match="grant_identity_mismatch"):
        _run(engine, _client(transport), spec)
    assert transport.operations == []
    assert list((engine.lifecycle.state_dir / "leases").glob("lease.*.json")) == []


@pytest.mark.parametrize("mismatch", ["provider", "model", "config"])
def test_client_and_owner_config_mismatches_refuse_before_effect(
    tmp_path: Path,
    mismatch: str,
) -> None:
    engine, _, _ = _engine(tmp_path)
    transport = ScriptedDaemonTransport()
    spec = _spec()
    client = _client(transport)
    config_id = "cfg.1"
    if mismatch == "provider":
        spec["provider"] = "other-provider"
    elif mismatch == "model":
        spec["model"] = "other-model"
    else:
        config_id = "cfg.missing"
    with pytest.raises(RunEngineError):
        engine.run(
            specification=spec,
            client=client,
            claimed_image=IMAGE,
            host=HOST,
            config_id=config_id,
        )
    assert transport.operations == []
    assert list((engine.lifecycle.state_dir / "leases").glob("lease.*.json")) == []


def test_model_gateway_route_refuses_when_not_executable(tmp_path: Path) -> None:
    engine, _, _ = _engine(tmp_path)
    transport = ScriptedDaemonTransport()
    spec = _spec("run.gateway")
    spec["networkProfile"] = {"mode": "model-gateway-only", "allowlist": []}
    with pytest.raises(RunEngineError, match="no configured model gateway is exposed"):
        _run(engine, _client(transport), spec)
    assert transport.operations == []


@pytest.mark.parametrize("mutation", ["missing", "extra"])
def test_malformed_agent_resources_refuse_before_lease_or_effect(
    tmp_path: Path, mutation: str
) -> None:
    engine, _, _ = _engine(tmp_path)
    transport = ScriptedDaemonTransport()
    run_spec = _spec()
    if mutation == "missing":
        run_spec["resources"].pop("diskMaxBytes")
    else:
        run_spec["resources"]["burstCpuPercent"] = 100
    with pytest.raises(RunEngineError, match="agent run specification is invalid"):
        _run(engine, _client(transport), run_spec)
    assert transport.operations == []
    assert list((engine.lifecycle.state_dir / "leases").glob("lease.*.json")) == []


def test_lowering_refuses_a_contract_that_drops_a_resource(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, _, _ = _engine(tmp_path)
    transport = ScriptedDaemonTransport()
    original = daemon_contract.validate_workload_spec

    def drop_disk(value):
        normalized = original(value)
        if normalized["kind"] == "agent-run":
            normalized["resources"].pop("diskMaxBytes")
        return normalized

    monkeypatch.setattr(daemon_contract, "validate_workload_spec", drop_disk)
    with pytest.raises(RunEngineError, match="did not retain every requested resource"):
        _run(engine, _client(transport))
    assert transport.operations == []
    assert list((engine.lifecycle.state_dir / "leases").glob("lease.*.json")) == []


def test_container_fixture_cannot_claim_provider_use_or_completed_evidence(
    tmp_path: Path,
) -> None:
    engine, manager, _ = _engine(tmp_path)
    transport = ScriptedDaemonTransport(output="real container output")
    client = _client(transport)
    outcome = _run(engine, client)
    assert outcome.outcome == "refused"
    evidence = outcome.evidence.to_dict()
    assert evidence["exitReason"] == "provider-effect-unobserved"
    assert engine._gate.finished_outcome(evidence["leaseId"]) == "refused"
    assert client.grant_id == "daemon-grant.1"
    assert client.authority_grant_digest == DAEMON_GRANT_DIGEST
    assert client.authority_grant_digest != _spec()["authorityGrantDigest"]
    assert str(client.socket_path) == "/controlled/test/execution-host.sock"
    assert len(transport.workloads) == 1
    workload = transport.workloads[0]
    assert workload["parameters"]["runSpecDigest"] == canonical_digest(_spec())
    assert workload["resources"] == _spec()["resources"]
    process = evidence["executedProcess"]
    assert process["containerWorkloadId"] == "run-run.1"
    assert process["observedImageDigest"] == DIGEST
    assert process["exitCode"] == 0
    assert process["digestOfOutput"] == (
        "sha256:" + hashlib.sha256(b"real container output").hexdigest()
    )
    assert manager.configured("cfg.1")
    assert PROVIDER_VALUE not in str(outcome.evidence.to_dict())
    assert transport.removed == ["run-run.1"]


def test_revocation_observed_during_create_prevents_start_and_cleans_up(
    tmp_path: Path,
) -> None:
    engine, _, authority = _engine(tmp_path)
    transport = ScriptedDaemonTransport(on_create=lambda: authority.revoke("grant.1"))
    outcome = _run(engine, _client(transport), _spec("run.prelaunch-revoke"))
    assert outcome.outcome == "refused"
    assert outcome.evidence.to_dict()["exitReason"] != "ok"
    assert transport.started == []
    assert transport.cancelled == ["run-run.prelaunch-revoke"]
    assert transport.removed == ["run-run.prelaunch-revoke"]
    assert engine.lifecycle.active_for("ws.1") is None


def test_mid_run_revocation_retries_cleanup_until_workload_cannot_run(
    tmp_path: Path,
) -> None:
    engine, _, authority = _engine(tmp_path)
    transport = ScriptedDaemonTransport(
        terminal_state="running",
        on_start=lambda: authority.revoke("grant.1"),
        cancel_failures=1,
        remove_failures=1,
    )
    outcome = _run(engine, _client(transport), _spec("run.revoked"))
    assert outcome.outcome in {"cancelled", "refused"}
    assert outcome.outcome != "completed"
    assert transport.started == ["run-run.revoked"]
    assert transport.cancel_attempts >= 2
    assert transport.removed == ["run-run.revoked"]
    assert engine.lifecycle.active_for("ws.1") is None


def test_post_begin_create_failure_releases_workspace_lease_and_config(
    tmp_path: Path,
) -> None:
    engine, manager, _ = _engine(tmp_path)
    transport = ScriptedDaemonTransport(fail_create_after_effect=True)
    outcome = _run(engine, _client(transport), _spec("run.create-lost"))
    assert outcome.outcome == "failed"
    assert outcome.evidence.to_dict()["exitReason"].startswith("observation-incomplete")
    assert transport.cancelled == ["run-run.create-lost"]
    assert transport.removed == ["run-run.create-lost"]
    assert engine.lifecycle.active_for("ws.1") is None
    assert manager.configured("cfg.1")


def test_definitive_transport_failure_releases_lease_without_cleanup_loop(
    tmp_path: Path,
) -> None:
    engine, _, _ = _engine(tmp_path)
    client = ExecutionHostClient(
        tmp_path / "absent.sock",
        grant_id="daemon-grant.1",
        authority_grant_digest=DAEMON_GRANT_DIGEST,
    )
    outcome = _run(engine, client, _spec("run.socket-absent"))
    assert outcome.outcome == "failed"
    assert outcome.evidence.to_dict()["exitReason"].startswith("observation-incomplete")
    assert engine.lifecycle.active_for("ws.1") is None


@pytest.mark.parametrize(
    ("observed_image", "reason"),
    [
        (None, "observed-image-missing"),
        (OTHER_DIGEST, "observed-image-identity-mismatch"),
    ],
)
def test_missing_or_mismatched_observed_image_cannot_complete(
    tmp_path: Path,
    observed_image: str | None,
    reason: str,
) -> None:
    engine, _, _ = _engine(tmp_path)
    outcome = _run(engine, _client(ScriptedDaemonTransport(image_digest=observed_image)))
    data = outcome.evidence.to_dict()
    assert outcome.outcome == "failed"
    assert data["exitReason"] == reason
    assert data["exitReason"] != "ok"


def test_failing_exit_and_missing_observation_are_honest_failures(
    tmp_path: Path,
) -> None:
    engine, _, _ = _engine(tmp_path)
    failed = _run(engine, _client(ScriptedDaemonTransport(exit_status=3)), _spec("run.fail"))
    assert failed.outcome == "failed"
    assert failed.evidence.to_dict()["executedProcess"]["exitCode"] == 3

    engine, _, _ = _engine(tmp_path / "unobserved")
    unobserved = _run(
        engine,
        _client(ScriptedDaemonTransport(fail_status=True)),
        _spec("run.unobserved"),
    )
    data = unobserved.evidence.to_dict()
    assert unobserved.outcome == "failed"
    assert data["exitReason"].startswith("observation-incomplete")
    assert data["digestOfOutput"] == "sha256:" + hashlib.sha256(b"").hexdigest()


def test_revoke_only_invalidates_run_handle_not_reusable_owner_config(tmp_path: Path) -> None:
    _, manager, _ = _engine(tmp_path)
    handle = manager.bind(config_id="cfg.1", granted=True)
    assert handle.token() == PROVIDER_VALUE
    manager.revoke(handle)
    assert manager.configured("cfg.1")
    with pytest.raises(ProviderSecretUnavailable, match="revoked"):
        handle.token()
    replacement = manager.bind(config_id="cfg.1", granted=True)
    assert replacement.token() == PROVIDER_VALUE
