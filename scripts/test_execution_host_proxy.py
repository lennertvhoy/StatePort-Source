"""Fail-old/pass-new tests for the sanctioned execution-host proxy boundary.

The proxy is the ONLY web-side path to the confined daemon.  These tests
prove:

- fail-old: with no socket or grant configured the proxy reports
  ``unavailable`` and never fabricates container state;
- the proxy validates caller-visible identities and operation shapes before
  any daemon round trip;
- unauthorized/malformed operations are refused with bounded errors;
- a live fake daemon (real AF_UNIX receipt contract) answers through the
  proxy and the bounded result never leaks socket paths or host identities;
- the AppServer routes the surface under session + CSRF authority.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
import threading
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "packages" / "persistent-app" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "execution-host" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "deployment" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "release-contracts" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "runtime-contracts" / "src"))

from stateport_persistent_app.execution_host_proxy import (  # noqa: E402
    DEFAULT_GRANT_ID,
    ExecutionHostProxy,
    ExecutionHostProxyError,
)
from execution_host import daemon_contract  # noqa: E402
from stateport_deployment.execution_host import (  # noqa: E402
    ExecutionHostDeploymentAdapter,
)
from stateport_release.execution_host_provisioning import (  # noqa: E402
    DEFAULT_WORKSPACE_ID,
    DEFAULT_WORKSPACE_SPEC_DIGEST,
    default_sealed_workspace_workload,
)


class FakeDaemon:
    """In-process AF_UNIX peer speaking the exact daemon receipt contract."""

    def __init__(self, socket_path: Path, *, refuse: str | None = None) -> None:
        self._path = socket_path
        self._refuse = refuse
        self._listener: socket.socket | None = None
        self.requests: list[dict[str, Any]] = []

    def start(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if self._path.exists() or self._path.is_symlink():
            self._path.unlink()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(self._path))
        os.chmod(self._path, 0o660)
        listener.listen(4)
        self._listener = listener
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        listener = self._listener
        assert listener is not None
        while True:
            try:
                connection, _ = listener.accept()
            except OSError:
                return
            try:
                buffer = b""
                while b"\n" not in buffer:
                    chunk = connection.recv(65536)
                    if not chunk:
                        break
                    buffer += chunk
                request = json.loads(buffer.split(b"\n", 1)[0])
                self.requests.append(request)
                digest = daemon_contract.canonical_digest(request)
                now = "2026-08-18T00:00:00Z"
                peer = {
                    "uid": os.getuid(),
                    "gid": os.getgid(),
                    "pid": os.getpid(),
                    "grantId": request["requester"]["grantId"],
                }
                if self._refuse is not None:
                    receipt: dict[str, Any] = {
                        "formatVersion": "stateport.execution-host-receipt/v1",
                        "operationId": request["operationId"],
                        "requestDigest": digest,
                        "accepted": False,
                        "refusal": {"reason": self._refuse, "detail": "simulated refusal"},
                        "requester": peer,
                        "result": None,
                        "observed": {
                            "engine": None,
                            "engineVersion": None,
                            "imageDigest": None,
                            "exitStatus": None,
                            "startedAt": None,
                            "finishedAt": None,
                        },
                        "cleanup": {"outcome": "not-required", "detail": "refused before execution"},
                        "timestamps": {"receivedAt": now, "completedAt": now},
                    }
                else:
                    result: dict[str, Any]
                    if request["operation"] == "describeCapabilities":
                        result = {
                            "formatVersion": "stateport.execution-host-contract/v1",
                            "contractVersion": 2,
                            "clientCompatibility": {"minimum": 1, "maximum": 2},
                            "transport": "confined-host-unix-socket",
                            "workloadKinds": ["workspace"],
                            "operations": ["describeCapabilities"],
                            "sealedWorkloadsOnly": True,
                            "providerAccess": False,
                            "publicNetwork": False,
                            "peerIdentity": {
                                "mechanism": "SO_PEERCRED",
                                "runtimeUid": 65532,
                                "runtimeGid": 65532,
                                "socketGroupGid": 65530,
                                "allowedClientUid": 65531,
                                "allowedClientGid": 65531,
                            },
                            "limits": {
                                "maxTimeoutSeconds": 86400,
                                "maxRequestTimeoutSeconds": 600,
                                "maxDeploymentRequestTimeoutSeconds": 1200,
                                "maxOutputBytes": 4194304,
                                "maxWorkloads": 64,
                            },
                        }
                    elif request["operation"] == "listWorkloads":
                        # Match the production daemon's object projection. A
                        # historical bare array masked the UI inventory bug.
                        result = {"workloads": [
                            {"workloadId": "project-work", "kind": "workspace", "state": "running"},
                            {"workloadId": "study-work", "kind": "job", "state": "created"},
                        ]}
                    elif request["operation"] == "probeDeploymentTarget":
                        result = {
                            "outcome": "succeeded",
                            "operation": "probeDeploymentTarget",
                            "value": {
                                "adapter": "rootless-podman-local",
                                "targetId": "local",
                                "architecture": "linux-amd64",
                                "identityDigest": "sha256:" + "2" * 64,
                            },
                            "failure": None,
                        }
                    elif request["operation"] == "createWorkload":
                        result = {
                            "workloadId": request["payload"]["workload"]["workloadId"],
                            "state": "created",
                        }
                    elif request["operation"] == "status":
                        result = {
                            "workloadId": request["payload"]["workloadId"],
                            "state": "running",
                            "exitStatus": None,
                            "engineStatus": "running",
                        }
                    elif request["operation"] == "logs":
                        result = {
                            "workloadId": request["payload"]["workloadId"],
                            "state": "running",
                            "output": "hello from the container\n",
                            "byteCount": 24,
                            "truncated": False,
                            "outputByteBound": 262144,
                        }
                    elif request["operation"] == "execWorkload":
                        result = {
                            "workloadId": request["payload"]["workloadId"],
                            "state": "running",
                            "output": "stateport-j1-ok\n",
                            "byteCount": 16,
                            "truncated": False,
                            "outputByteBound": 262144,
                        }
                    else:
                        result = {
                            "workloadId": request.get("payload", {}).get("workloadId", "w-1"),
                            "state": "performed",
                        }
                    receipt = {
                        "formatVersion": "stateport.execution-host-receipt/v1",
                        "operationId": request["operationId"],
                        "requestDigest": digest,
                        "accepted": True,
                        "refusal": None,
                        "requester": peer,
                        "result": result,
                        "observed": {
                            "engine": "fake-podman",
                            "engineVersion": "4.9.3",
                            "imageDigest": "sha256:" + "0" * 64,
                            "exitStatus": None,
                            "startedAt": now,
                            "finishedAt": None,
                        },
                        "cleanup": {"outcome": "not-required", "detail": "read-only"},
                        "timestamps": {"receivedAt": now, "completedAt": now},
                    }
                connection.sendall((json.dumps(receipt) + "\n").encode("utf-8"))
            except (OSError, ValueError, KeyError):
                pass
            finally:
                try:
                    connection.close()
                except OSError:
                    pass


@pytest.fixture
def short_tmp() -> Path:
    root = Path(tempfile.mkdtemp(prefix="ehp-"))
    yield root
    import shutil

    shutil.rmtree(root, ignore_errors=True)


def test_fail_old_unconfigured_proxy_reports_unavailable(short_tmp: Path, monkeypatch) -> None:
    """Fail-old: no socket/grant configured -> unavailable, never invented state."""
    monkeypatch.delenv("STATEPORT_EXECUTION_SOCKET", raising=False)
    monkeypatch.delenv("STATEPORT_EXECUTION_GRANT_DIGEST", raising=False)
    proxy = ExecutionHostProxy(socket_path="")
    status = proxy.status()
    assert status["status"] == "unavailable"
    assert status["reason"] == "execution_socket_not_configured"
    assert status["grantBound"] is False
    with pytest.raises(ExecutionHostProxyError) as exc:
        proxy.list()
    assert exc.value.code == "execution_unavailable"
    assert exc.value.status == 503


def test_fail_old_unreachable_daemon_reports_unavailable(short_tmp: Path) -> None:
    """Fail-old: a declared but absent socket stays unavailable, fail closed."""
    proxy = ExecutionHostProxy(
        socket_path=str(short_tmp / "absent" / "control.sock"),
        grant_id=DEFAULT_GRANT_ID,
        authority_grant_digest="sha256:" + "1" * 64,
    )
    status = proxy.status()
    assert status["status"] == "unavailable"
    assert status["reason"] == "execution_host_unreachable"
    assert status["grantBound"] is True
    assert str(short_tmp) not in json.dumps(status)


def test_pass_new_live_daemon_answers_through_proxy(short_tmp: Path) -> None:
    """Pass-new: a real contract round trip through the sanctioned proxy."""
    socket_path = short_tmp / "run" / "control.sock"
    daemon = FakeDaemon(socket_path)
    daemon.start()
    proxy = ExecutionHostProxy(
        socket_path=str(socket_path),
        grant_id=DEFAULT_GRANT_ID,
        authority_grant_digest="sha256:" + "1" * 64,
    )
    status = proxy.status()
    assert status["status"] == "available"
    assert status["contractVersion"] == 2
    assert status["engine"] == "fake-podman"
    assert status["grantBound"] is True
    assert status["peerIdentity"] == {"mechanism": "SO_PEERCRED"}
    assert str(socket_path) not in json.dumps(status)
    assert '"runtimeUid"' not in json.dumps(status)

    listed = proxy.list()
    assert listed["accepted"] is True
    assert listed["result"] == {"workloads": [
        {"workloadId": "project-work", "kind": "workspace", "state": "running"},
        {"workloadId": "study-work", "kind": "job", "state": "created"},
    ]}
    assert listed["receipt"]["resultDigest"] == daemon_contract.canonical_digest(listed["result"])

    # Existing proxy methods must retain the selected workload identity rather
    # than silently substituting the historical default development workspace.
    for action, workload_id in (("stop", "project-work"), ("cancel", "study-work")):
        result = getattr(proxy, action)(workload_id)
        assert result["accepted"] is True
        assert result["receipt"]["workloadId"] == workload_id
        assert daemon.requests[-1]["operation"] == action
        assert daemon.requests[-1]["payload"] == {"workloadId": workload_id}

    ran = proxy.status_of("w-1")
    assert ran["accepted"] is True
    assert ran["result"]["state"] == "running"

    logs = proxy.logs("w-1")
    assert logs["accepted"] is True
    assert logs["result"]["output"] == "hello from the container\n"
    assert "socket" not in json.dumps(logs).lower() or "socketPath" not in logs
    # The bounded result must not leak the control socket path or host uid.
    serialized = json.dumps(logs)
    assert str(socket_path) not in serialized


def test_proxy_constructs_deployment_adapter_on_the_confined_binding(
    short_tmp: Path,
) -> None:
    socket_path = short_tmp / "run" / "control.sock"
    daemon = FakeDaemon(socket_path)
    daemon.start()
    proxy = ExecutionHostProxy(
        socket_path=str(socket_path),
        grant_id=DEFAULT_GRANT_ID,
        authority_grant_digest="sha256:" + "1" * 64,
    )

    adapter = proxy.deployment_adapter()
    assert isinstance(adapter, ExecutionHostDeploymentAdapter)
    assert adapter.probe() == {
        "adapter": "rootless-podman-local",
        "targetId": "local",
        "architecture": "linux-amd64",
        "identityDigest": "sha256:" + "2" * 64,
    }
    assert daemon.requests[-1]["operation"] == "probeDeploymentTarget"
    assert daemon.requests[-1]["timeoutSeconds"] == 1200
    assert daemon.requests[-1]["outputByteBound"] == 262144


def test_proxy_creates_only_the_canonical_default_workspace(short_tmp: Path) -> None:
    socket_path = short_tmp / "run" / "control.sock"
    daemon = FakeDaemon(socket_path)
    daemon.start()
    proxy = ExecutionHostProxy(
        socket_path=str(socket_path),
        grant_id=DEFAULT_GRANT_ID,
        authority_grant_digest="sha256:" + "1" * 64,
    )

    created = proxy.create_default()

    assert created["accepted"] is True
    assert created["result"] == {"workloadId": DEFAULT_WORKSPACE_ID, "state": "created"}
    assert created["receipt"]["action"] == "execution_host.createWorkload"
    assert created["receipt"]["workloadId"] == DEFAULT_WORKSPACE_ID
    assert created["receipt"]["resultDigest"] == daemon_contract.canonical_digest(
        created["result"]
    )
    request = daemon.requests[-1]
    assert request["operation"] == "createWorkload"
    assert request["payload"]["workload"] == default_sealed_workspace_workload()
    assert (
        daemon_contract.canonical_digest(request["payload"]["workload"])
        == DEFAULT_WORKSPACE_SPEC_DIGEST
    )
    assert created["receipt"]["requestDigest"] == daemon_contract.canonical_digest(
        request
    )
    serialized = json.dumps(created)
    assert str(socket_path) not in serialized
    assert '"uid"' not in serialized and '"gid"' not in serialized

    started = proxy.start(DEFAULT_WORKSPACE_ID)
    assert started["accepted"] is True
    assert started["receipt"]["action"] == "execution_host.start"

    executed = proxy.exec(
        DEFAULT_WORKSPACE_ID,
        ["/bin/sh", "-lc", "printf 'stateport-j1-ok\\n'"],
    )
    assert executed["accepted"] is True
    assert executed["result"]["output"] == "stateport-j1-ok\n"
    assert executed["receipt"]["action"] == "execution_host.execWorkload"
    assert executed["receipt"]["outputBytes"] == 16
    assert executed["receipt"]["resultDigest"] == daemon_contract.canonical_digest(
        executed["result"]
    )
    assert executed["receipt"]["outputDigest"] == daemon_contract.canonical_digest(
        "stateport-j1-ok\n"
    )
    assert "output" not in executed["receipt"]


def test_proxy_refuses_default_creation_under_another_grant(short_tmp: Path) -> None:
    socket_path = short_tmp / "run" / "control.sock"
    daemon = FakeDaemon(socket_path)
    daemon.start()
    proxy = ExecutionHostProxy(
        socket_path=str(socket_path),
        grant_id="another-grant",
        authority_grant_digest="sha256:" + "1" * 64,
    )

    with pytest.raises(ExecutionHostProxyError) as exc:
        proxy.create_default()

    assert exc.value.code == "default_grant_required"
    assert daemon.requests == []


def test_proxy_refuses_malformed_workload_ids(short_tmp: Path) -> None:
    socket_path = short_tmp / "run" / "control.sock"
    FakeDaemon(socket_path).start()
    proxy = ExecutionHostProxy(
        socket_path=str(socket_path),
        grant_id=DEFAULT_GRANT_ID,
        authority_grant_digest="sha256:" + "1" * 64,
    )
    for bad in ("", "a b", "a/b", "../etc", "a" * 200):
        with pytest.raises(ExecutionHostProxyError) as exc:
            proxy.status_of(bad)
        assert exc.value.code == "invalid_workload_id"
        assert exc.value.status == 400


def test_proxy_refuses_malformed_exec_argv(short_tmp: Path) -> None:
    socket_path = short_tmp / "run" / "control.sock"
    FakeDaemon(socket_path).start()
    proxy = ExecutionHostProxy(
        socket_path=str(socket_path),
        grant_id=DEFAULT_GRANT_ID,
        authority_grant_digest="sha256:" + "1" * 64,
    )
    for bad in ([], [""], ["x" * 300], "not-a-list", [1, 2]):
        with pytest.raises(ExecutionHostProxyError) as exc:
            proxy.exec("w-1", bad)
        assert exc.value.code == "invalid_argv"
        assert exc.value.status == 400


def test_proxy_surfaces_daemon_refusal_bounded(short_tmp: Path) -> None:
    """A daemon refusal (e.g. grant revoked) is surfaced as bounded truth."""
    socket_path = short_tmp / "run" / "control.sock"
    FakeDaemon(socket_path, refuse="grant-revoked").start()
    proxy = ExecutionHostProxy(
        socket_path=str(socket_path),
        grant_id=DEFAULT_GRANT_ID,
        authority_grant_digest="sha256:" + "1" * 64,
    )
    status = proxy.status()
    assert status["status"] == "unavailable"
    assert status["reason"] == "execution_host_refused"
    assert status["detail"] == (
        "the execution host refused or invalidated the capability probe"
    )

    refused = proxy.start(DEFAULT_WORKSPACE_ID)
    assert refused["accepted"] is False
    assert refused["refusal"] == {
        "reason": "grant-revoked",
        "detail": "simulated refusal",
    }
    assert refused["receipt"]["status"] == "refused"
