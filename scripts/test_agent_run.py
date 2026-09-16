"""Bounded control-plane agent-run tests.

These tests prove the durable receipt contract of
:class:`stateport_persistent_app.agent_run.AgentRunService` against a
deterministic proxy double, and the strict binding reader of the real
``ExecutionHostProxy`` against an operator authority file.  No container,
podman, network, credential or real daemon is involved.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "packages" / "persistent-app" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "execution-host" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "deployment" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "release-contracts" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "runtime-contracts" / "src"))

from stateport_persistent_app.agent_run import (  # noqa: E402
    AGENT_WORKSPACE_ID,
    MAX_OBJECTIVE_CHARS,
    OUTPUT_BYTE_BOUND,
    RECEIPT_FORMAT,
    AgentRunError,
    AgentRunService,
)
from stateport_persistent_app.execution_host_proxy import (  # noqa: E402
    AGENT_WORKSPACE_BINDING_FORMAT,
    ExecutionHostProxy,
    ExecutionHostProxyError,
)
from execution_host import daemon_contract  # noqa: E402

FAKE_KEY = "stateport-agent-run-test-not-a-real-credential-0042"
IMAGE_REFERENCE = "ghcr.io/stateport/agent-workspace@sha256:" + "a" * 64
IMAGE_DIGEST = "sha256:" + "a" * 64
GRANT_DIGEST = "sha256:" + "b" * 64
SPEC_DIGEST = "sha256:" + "c" * 64
RECORD_KEYS = {
    "formatVersion",
    "runId",
    "status",
    "objective",
    "objectiveDigest",
    "workspaceId",
    "imageReference",
    "workspaceSpecDigest",
    "grantId",
    "authorityGrantDigest",
    "createOperationId",
    "startOperationId",
    "execOperationId",
    "exitStatus",
    "outputDigest",
    "outputBytes",
    "truncated",
    "refusal",
    "startedAt",
    "finishedAt",
    "createdAt",
    "updatedAt",
}


def _agent_workload() -> dict[str, Any]:
    workload = {
        "kind": "workspace",
        "workloadId": AGENT_WORKSPACE_ID,
        "image": {"reference": IMAGE_REFERENCE},
        "parameters": {
            "workspaceId": AGENT_WORKSPACE_ID,
            "workspaceSpecDigest": SPEC_DIGEST,
            "volumeName": "stateport-workspace-" + AGENT_WORKSPACE_ID,
            "stopAfterIdle": True,
            "shell": ["/bin/sh"],
            "networkMode": "developer",
            "cacheVolumes": [],
            "cpuQuotaPercent": 100,
            "diskMaxBytes": 256 * 1024 * 1024,
            "workSeconds": 0,
            "emitBytes": 0,
            "agentProviderProfile": daemon_contract.AGENT_PROVIDER_PROFILE,
        },
        "timeoutSeconds": 3600,
        "outputByteBound": 65536,
        "resources": {"memoryMaxBytes": 256 * 1024 * 1024, "pidsMax": 128},
    }
    return daemon_contract.validate_workload_spec(workload)


class FakeProxy:
    """Deterministic in-process double for the sanctioned execution proxy."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.binding = {
            "formatVersion": AGENT_WORKSPACE_BINDING_FORMAT,
            "grantId": "grant-agent",
            "authorityGrantDigest": GRANT_DIGEST,
            "workload": _agent_workload(),
        }
        self.status_result: dict[str, Any] = {
            "workloadId": AGENT_WORKSPACE_ID,
            "grantId": "grant-agent",
            "authorityGrantDigest": GRANT_DIGEST,
            "operations": ["createWorkload", "start", "execWorkload", "listWorkloads"],
            "state": "absent",
            "running": False,
            "imageDigest": None,
            "allowedOperations": [],
            "declaredLimits": {},
        }
        self.create_receipt: dict[str, Any] = {"operationId": "op-create", "accepted": True, "result": {"workloadId": AGENT_WORKSPACE_ID}}
        self.start_receipt: dict[str, Any] = {"operationId": "op-start", "accepted": True, "result": {"workloadId": AGENT_WORKSPACE_ID, "state": "running"}}
        self.exec_receipt: dict[str, Any] | None = {
            "operationId": "op-exec",
            "accepted": True,
            "result": {
                "workloadId": AGENT_WORKSPACE_ID,
                "exitStatus": 0,
                "output": "README summarized\n",
                "byteCount": 18,
                "truncated": False,
                "outputByteBound": 65536,
            },
            "observed": {"imageDigest": IMAGE_DIGEST, "exitStatus": 0},
        }
        self.raise_on: dict[str, Exception] = {}
        self.exec_gate: threading.Event | None = None

    def _maybe_raise(self, name: str) -> None:
        if name in self.raise_on:
            raise self.raise_on[name]

    def agent_workspace_binding(self) -> dict[str, Any]:
        self.calls.append("binding")
        self._maybe_raise("binding")
        return json.loads(json.dumps(self.binding))

    def agent_workspace_status(self) -> dict[str, Any]:
        self.calls.append("status")
        self._maybe_raise("status")
        return json.loads(json.dumps(self.status_result))

    def create_agent_workspace(self) -> dict[str, Any]:
        self.calls.append("create")
        self._maybe_raise("create")
        self.status_result.update(state="created", running=False)
        return json.loads(json.dumps(self.create_receipt))

    def start_agent_workspace(self) -> dict[str, Any]:
        self.calls.append("start")
        self._maybe_raise("start")
        self.status_result.update(state="running", running=True, imageDigest=IMAGE_DIGEST)
        return json.loads(json.dumps(self.start_receipt))

    def agent_exec(self, objective: Any, *, timeout_seconds: int) -> dict[str, Any]:
        self.calls.append(f"exec:{objective}:{timeout_seconds}")
        self._maybe_raise("exec")
        if self.exec_gate is not None:
            assert self.exec_gate.wait(timeout=10)
        if self.exec_receipt is None:
            raise AssertionError("no exec receipt configured")
        return json.loads(json.dumps(self.exec_receipt))


def _provider_directory(tmp_path: Path, *, env_mode: int = 0o644) -> Path:
    directory = tmp_path / "provider"
    directory.mkdir(mode=0o755, exist_ok=True)
    directory.chmod(0o755)
    env_path = directory / "provider.env"
    env_path.write_text(f"OPENROUTER_API_KEY={FAKE_KEY}\n", encoding="utf-8")
    env_path.chmod(env_mode)
    (directory / "opencode.json").write_text('{"theme":"dark"}\n', encoding="utf-8")
    (directory / "opencode.json").chmod(0o644)
    (directory / "model").write_text("openrouter/anthropic/claude-sonnet-test\n", encoding="utf-8")
    (directory / "model").chmod(0o644)
    return directory


def _service(tmp_path: Path, proxy: FakeProxy, *, provider_directory: Path | None, workspace_image: str | None = IMAGE_REFERENCE) -> AgentRunService:
    return AgentRunService(
        execution_host=proxy,
        state_dir=tmp_path / "agent-runs",
        provider_directory=str(provider_directory) if provider_directory is not None else None,
        workspace_image_reference=workspace_image,
        timeout_seconds=None,
    )


def _wait(service: AgentRunService, run_id: str, timeout: float = 10.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        row = service.status(run_id)
        if row["status"] != "running":
            return row
        time.sleep(0.01)
    raise AssertionError("agent run did not finish")


# --------------------------------------------------------------- validation


def test_objective_is_bounded_before_any_proxy_call(tmp_path: Path) -> None:
    proxy = FakeProxy()
    service = _service(tmp_path, proxy, provider_directory=_provider_directory(tmp_path))
    for bad in (123, b"x", None):
        with pytest.raises(AgentRunError) as exc:
            service.start(bad)
        assert exc.value.code == "objective_invalid"
    for bad in ("", "   ", "a\x00b"):
        with pytest.raises(AgentRunError) as exc:
            service.start(bad)
        assert exc.value.code == "objective_invalid"
    with pytest.raises(AgentRunError) as exc:
        service.start("x" * (MAX_OBJECTIVE_CHARS + 1))
    assert exc.value.code == "objective_too_long"
    assert proxy.calls == []


# --------------------------------------------------------------- readiness


def test_readiness_provider_directory_unconfigured(tmp_path: Path) -> None:
    proxy = FakeProxy()
    service = _service(tmp_path, proxy, provider_directory=None)
    review = service.readiness()
    assert review["available"] is False
    reasons = [row["reason"] for row in review["refusals"]]
    assert reasons[0] == "provider_directory_unconfigured"
    assert review["providerDirectory"]["configured"] is False

    relative = _service(tmp_path, proxy, provider_directory=Path("relative/provider"))
    assert relative.readiness()["refusals"][0]["reason"] == "provider_directory_unconfigured"


def test_readiness_provider_directory_missing_or_symlinked(tmp_path: Path) -> None:
    proxy = FakeProxy()
    absent = _service(tmp_path, proxy, provider_directory=tmp_path / "does-not-exist")
    assert absent.readiness()["refusals"][0]["reason"] == "provider_directory_missing"

    real = _provider_directory(tmp_path)
    link = tmp_path / "provider-link"
    link.symlink_to(real, target_is_directory=True)
    linked = _service(tmp_path, proxy, provider_directory=link)
    assert linked.readiness()["refusals"][0]["reason"] == "provider_directory_missing"


def test_readiness_provider_directory_incomplete(tmp_path: Path) -> None:
    proxy = FakeProxy()
    for name in ("env-symlink", "env-world-writable", "missing-json"):
        case = tmp_path / name
        case.mkdir()
        directory = _provider_directory(case)
        if name == "env-symlink":
            target = directory / "target.env"
            target.write_text(f"OPENROUTER_API_KEY={FAKE_KEY}\n", encoding="utf-8")
            target.chmod(0o600)
            (directory / "provider.env").unlink()
            (directory / "provider.env").symlink_to(target)
        elif name == "env-world-writable":
            (directory / "provider.env").chmod(0o666)
        else:
            (directory / "opencode.json").unlink()
        review = _service(case, proxy, provider_directory=directory).readiness()
        reasons = [row["reason"] for row in review["refusals"]]
        assert "provider_directory_incomplete" in reasons, (name, reasons)
        assert review["providerDirectory"]["files"]["providerEnv"] is (name == "missing-json")


def test_readiness_accepts_container_readable_material(tmp_path: Path) -> None:
    """The sealed container reads the material as a mapped uid: 0755/0644 is
    the working shape, while group/other WRITE bits stay refused."""

    proxy = FakeProxy()
    directory = _provider_directory(tmp_path)
    assert stat.S_IMODE(directory.stat().st_mode) == 0o755
    review = _service(tmp_path, proxy, provider_directory=directory).readiness()
    assert review["available"] is True, review["refusals"]
    assert review["providerDirectory"]["files"] == {
        "providerEnv": True,
        "opencodeJson": True,
        "model": True,
    }

    writable = tmp_path / "writable-dir"
    writable.mkdir()
    directory = _provider_directory(writable)
    directory.chmod(0o775)
    review = _service(writable, proxy, provider_directory=directory).readiness()
    assert review["refusals"][0]["reason"] == "provider_directory_missing"


def test_readiness_reports_execution_unavailable_and_image_gap(tmp_path: Path) -> None:
    proxy = FakeProxy()
    proxy.raise_on["status"] = ExecutionHostProxyError(
        "agent_workspace_authority_missing", "not installed", status=503
    )
    review = _service(tmp_path, proxy, provider_directory=_provider_directory(tmp_path)).readiness()
    assert review["available"] is False
    assert review["refusals"][0] == {
        "reason": "execution_unavailable",
        "detail": "agent_workspace_authority_missing",
    }

    proxy2 = FakeProxy()
    review2 = _service(tmp_path, proxy2, provider_directory=_provider_directory(tmp_path), workspace_image=None).readiness()
    assert any(row["reason"] == "agent_workspace_image_mismatch" for row in review2["refusals"])


# --------------------------------------------------------------- lifecycle


def test_happy_path_create_start_exec_completed(tmp_path: Path) -> None:
    proxy = FakeProxy()
    service = _service(tmp_path, proxy, provider_directory=_provider_directory(tmp_path))
    started = service.start("summarize README.md")
    assert started["status"] == "running"
    assert started["workspaceId"] == AGENT_WORKSPACE_ID
    record = _wait(service, started["runId"])
    assert record["status"] == "completed"
    assert set(record) == RECORD_KEYS
    assert record["formatVersion"] == RECEIPT_FORMAT
    assert record["objective"] == "summarize README.md"
    assert record["objectiveDigest"] == "sha256:" + hashlib.sha256(b"summarize README.md").hexdigest()
    assert record["workspaceId"] == AGENT_WORKSPACE_ID
    assert record["imageReference"] == IMAGE_REFERENCE
    assert record["workspaceSpecDigest"] == SPEC_DIGEST
    assert record["grantId"] == "grant-agent"
    assert record["authorityGrantDigest"] == GRANT_DIGEST
    assert record["createOperationId"] == "op-create"
    assert record["startOperationId"] == "op-start"
    assert record["execOperationId"] == "op-exec"
    assert record["exitStatus"] == 0
    assert record["outputBytes"] == len(b"README summarized\n")
    assert record["truncated"] is False
    assert record["refusal"] is None
    assert record["outputDigest"] == "sha256:" + hashlib.sha256(b"README summarized\n").hexdigest()
    assert proxy.calls == ["status", "binding", "status", "create", "status", "start", f"exec:summarize README.md:900"]
    logs = service.logs(started["runId"])
    assert logs["output"] == "README summarized\n"
    assert logs["outputBytes"] == len(b"README summarized\n")
    assert record["finishedAt"] is not None
    assert record["updatedAt"] is not None


def test_nonzero_exit_is_failed_with_exit_status(tmp_path: Path) -> None:
    proxy = FakeProxy()
    proxy.exec_receipt = {
        "operationId": "op-exec-fail",
        "accepted": True,
        "result": {"workloadId": AGENT_WORKSPACE_ID, "exitStatus": 3, "output": "boom\n", "truncated": False},
    }
    service = _service(tmp_path, proxy, provider_directory=_provider_directory(tmp_path))
    record = _wait(service, service.start("fail")["runId"])
    assert record["status"] == "failed"
    assert record["exitStatus"] == 3
    assert record["refusal"] is None
    assert record["outputDigest"] == "sha256:" + hashlib.sha256(b"boom\n").hexdigest()


def test_datastore_create_refusal_becomes_typed_refused_record(tmp_path: Path) -> None:
    proxy = FakeProxy()
    proxy.create_receipt = {
        "operationId": "op-create",
        "accepted": False,
        "refusal": {"reason": "authority-refused", "detail": "no"},
    }
    service = _service(tmp_path, proxy, provider_directory=_provider_directory(tmp_path))
    record = _wait(service, service.start("create me")["runId"])
    assert record["status"] == "refused"
    assert record["refusal"]["reason"] == "workspace_prepare_failed"
    assert "authority-refused" in record["refusal"]["detail"]


def test_exec_transport_refusal_becomes_typed_refused_record(tmp_path: Path) -> None:
    proxy = FakeProxy()
    proxy.raise_on["exec"] = ExecutionHostProxyError("execution_unavailable", "transport down", status=503)
    service = _service(tmp_path, proxy, provider_directory=_provider_directory(tmp_path))
    record = _wait(service, service.start("exec me")["runId"])
    assert record["status"] == "refused"
    assert record["refusal"]["reason"] == "execution_unavailable"


def test_exec_refusal_receipt_becomes_agent_run_failed(tmp_path: Path) -> None:
    proxy = FakeProxy()
    proxy.exec_receipt = {
        "operationId": "op-exec",
        "accepted": False,
        "refusal": {"reason": "workspace-not-running", "detail": "no"},
    }
    service = _service(tmp_path, proxy, provider_directory=_provider_directory(tmp_path))
    record = _wait(service, service.start("refused")["runId"])
    assert record["status"] == "refused"
    assert record["refusal"]["reason"] == "agent_run_failed"
    assert "workspace-not-running" in record["refusal"]["detail"]


def test_in_progress_refusal_and_marker_cleared(tmp_path: Path) -> None:
    proxy = FakeProxy()
    proxy.exec_gate = threading.Event()
    service = _service(tmp_path, proxy, provider_directory=_provider_directory(tmp_path))
    first = service.start("long objective")
    with pytest.raises(AgentRunError) as exc:
        service.start("second objective")
    assert exc.value.code == "agent_run_in_progress"
    marker = tmp_path / "agent-runs" / "runs" / ".active"
    assert marker.is_file()
    proxy.exec_gate.set()
    record = _wait(service, first["runId"])
    assert record["status"] == "completed"
    assert not marker.exists()


def test_stale_marker_with_dead_pid_is_reclaimed(tmp_path: Path) -> None:
    proxy = FakeProxy()
    service = _service(tmp_path, proxy, provider_directory=_provider_directory(tmp_path))
    runs = tmp_path / "agent-runs" / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    runs.chmod(0o700)
    dead = subprocess.Popen(["true"])
    dead.wait()
    stale = {
        "runId": "agent-run-deadbeef",
        "createdAt": "2000-01-01T00:00:00Z",
        "pid": dead.pid,
    }
    marker = runs / ".active"
    marker.write_text(json.dumps(stale), encoding="utf-8")
    marker.chmod(0o600)
    record = _wait(service, service.start("reclaim")["runId"])
    assert record["status"] == "completed"
    assert not marker.exists()


def test_output_is_capped_and_secret_never_persisted(tmp_path: Path) -> None:
    proxy = FakeProxy()
    payload = "y" * (OUTPUT_BYTE_BOUND + 5000)
    proxy.exec_receipt = {
        "operationId": "op-exec",
        "accepted": True,
        "result": {"workloadId": AGENT_WORKSPACE_ID, "exitStatus": 0, "output": payload, "truncated": False},
    }
    provider = _provider_directory(tmp_path)
    service = _service(tmp_path, proxy, provider_directory=provider)
    record = _wait(service, service.start("big output")["runId"])
    assert record["status"] == "completed"
    assert record["outputBytes"] == len(payload.encode("utf-8"))
    assert record["truncated"] is True
    logs = service.logs(record["runId"])
    assert len(logs["output"].encode("utf-8")) == OUTPUT_BYTE_BOUND
    runs_dir = tmp_path / "agent-runs" / "runs"
    combined = b"".join(path.read_bytes() for path in runs_dir.iterdir())
    assert FAKE_KEY.encode("utf-8") not in combined
    assert record["objective"] == "big output"
    assert FAKE_KEY not in json.dumps(record)


class _TickingClock:
    def __init__(self) -> None:
        self._ticks = 0

    def __call__(self) -> datetime:
        self._ticks += 1
        return datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=self._ticks)


def test_unknown_run_is_typed_and_list_is_newest_first(tmp_path: Path) -> None:
    proxy = FakeProxy()
    service = AgentRunService(
        execution_host=proxy,
        state_dir=tmp_path / "agent-runs",
        provider_directory=str(_provider_directory(tmp_path)),
        workspace_image_reference=IMAGE_REFERENCE,
        clock=_TickingClock(),
    )
    with pytest.raises(AgentRunError) as exc:
        service.status("agent-run-missing")
    assert exc.value.code == "unknown_run"
    first = service.start("first")["runId"]
    _wait(service, first)
    second = service.start("second")["runId"]
    _wait(service, second)
    runs = service.list_runs()
    assert [row["runId"] for row in runs][:2] == [second, first]
    assert service.list_runs(limit=1)[0]["runId"] == second


# --------------------------------------------------- real binding reader


def _write_binding(directory: Path, payload: dict[str, Any]) -> Path:
    directory.mkdir(mode=0o700, exist_ok=True)
    directory.chmod(0o700)
    path = directory / "agent-workspace.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    path.chmod(0o600)
    return path


def _binding_document() -> dict[str, Any]:
    return {
        "formatVersion": AGENT_WORKSPACE_BINDING_FORMAT,
        "grantId": "grant-agent",
        "authorityGrantDigest": GRANT_DIGEST,
        "workload": _agent_workload(),
    }


def test_proxy_binding_reader_missing_and_invalid(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    unset = ExecutionHostProxy(authority_directory="", bindings_owner_uid=os.getuid())
    with pytest.raises(ExecutionHostProxyError) as exc:
        unset.agent_workspace_binding()
    assert exc.value.code == "agent_workspace_authority_missing"

    empty = tmp_path / "empty"
    empty.mkdir()
    absent = ExecutionHostProxy(authority_directory=empty, bindings_owner_uid=os.getuid())
    with pytest.raises(ExecutionHostProxyError) as exc:
        absent.agent_workspace_binding()
    assert exc.value.code == "agent_workspace_authority_missing"

    bad_document = _binding_document()
    bad_document["extra"] = True
    directory = tmp_path / "bad"
    _write_binding(directory, bad_document)
    malformed = ExecutionHostProxy(authority_directory=directory, bindings_owner_uid=os.getuid())
    with pytest.raises(ExecutionHostProxyError) as exc:
        malformed.agent_workspace_binding()
    assert exc.value.code == "agent_workspace_authority_invalid"

    not_developer = _binding_document()
    not_developer["workload"]["parameters"]["networkMode"] = "none"
    directory2 = tmp_path / "not-developer"
    _write_binding(directory2, not_developer)
    invalid_profile = ExecutionHostProxy(authority_directory=directory2, bindings_owner_uid=os.getuid())
    with pytest.raises(ExecutionHostProxyError) as exc:
        invalid_profile.agent_workspace_binding()
    assert exc.value.code == "agent_workspace_authority_invalid"


def test_proxy_binding_reader_accepts_exact_profile_and_enforces_image(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STATEPORT_EXECUTION_HOST_WORKSPACE_IMAGE_REFERENCE", raising=False)
    directory = tmp_path / "good"
    _write_binding(directory, _binding_document())
    proxy = ExecutionHostProxy(authority_directory=directory, bindings_owner_uid=os.getuid())
    binding = proxy.agent_workspace_binding()
    assert binding["grantId"] == "grant-agent"
    assert binding["workload"]["parameters"]["agentProviderProfile"] == daemon_contract.AGENT_PROVIDER_PROFILE

    monkeypatch.setenv(
        "STATEPORT_EXECUTION_HOST_WORKSPACE_IMAGE_REFERENCE",
        "ghcr.io/stateport/agent-workspace@sha256:" + "d" * 64,
    )
    with pytest.raises(ExecutionHostProxyError) as exc:
        proxy.agent_workspace_binding()
    assert exc.value.code == "agent_workspace_image_mismatch"

    monkeypatch.setenv("STATEPORT_EXECUTION_HOST_WORKSPACE_IMAGE_REFERENCE", IMAGE_REFERENCE)
    assert proxy.agent_workspace_binding()["workload"]["image"]["reference"] == IMAGE_REFERENCE


def test_proxy_binding_reader_refuses_writable_authority(tmp_path: Path) -> None:
    directory = tmp_path / "good"
    path = _write_binding(directory, _binding_document())
    path.chmod(0o620)
    proxy = ExecutionHostProxy(authority_directory=directory, bindings_owner_uid=os.getuid())
    with pytest.raises(ExecutionHostProxyError) as exc:
        proxy.agent_workspace_binding()
    assert exc.value.code == "agent_workspace_authority_invalid"
    assert stat.S_IMODE(path.stat().st_mode) == 0o620
