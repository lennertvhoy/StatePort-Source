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
- the production daemon and private GrantStore also round-trip the dynamic
  workspace profile over AF_UNIX with the real test-process UID and inert engine;
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
_DEFAULT_LIST_RESULT = object()
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

    def __init__(self, socket_path: Path, *, refuse: str | None = None, private_grants=None, list_result: object = _DEFAULT_LIST_RESULT) -> None:
        self._path = socket_path
        self._refuse = refuse
        self._private_grants = private_grants
        self.list_result = list_result
        self.workspace_profile = None
        self.listed_operations = None
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
                refusal = self._refuse
                if self._private_grants is not None:
                    from execution_host.grants import GrantRefusal
                    validated = daemon_contract.validate_operation_request(request)
                    payload = daemon_contract.validate_request_payload(validated, request.get("payload"))
                    try:
                        # The fixture models installed canonical control UID;
                        # actual namespace/socket identity is not proved here.
                        self._private_grants.verify(request=validated, peer_uid=65531, payload=payload, active_count=lambda _: 0)
                    except GrantRefusal as exc:
                        refusal = exc.reason
                if refusal is not None:
                    receipt: dict[str, Any] = {
                        "formatVersion": "stateport.execution-host-receipt/v1",
                        "operationId": request["operationId"],
                        "requestDigest": digest,
                        "accepted": False,
                        "refusal": {"reason": refusal, "detail": "simulated refusal"},
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
                        result = self.list_result if self.list_result is not _DEFAULT_LIST_RESULT else {"workloads": [
                            {"workloadId": "project-work", "kind": "workspace", "state": "running"},
                            {"workloadId": "study-work", "kind": "job", "state": "created"},
                        ]}
                        if isinstance(result, dict):
                            if request["requester"]["grantId"] == DEFAULT_GRANT_ID and self.workspace_profile is not None:
                                result["workspaceProfile"] = self.workspace_profile
                            if self.listed_operations is not None:
                                result["allowedOperations"] = self.listed_operations
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
    assert listed["result"]["workloads"] == [
        {"workloadId": "project-work", "kind": "workspace", "state": "running"},
        {"workloadId": "study-work", "kind": "job", "state": "created"},
    ]
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


@pytest.mark.parametrize(
    "list_result",
    [
        None,
        [],
        {},
        {"workloads": None},
        {"workloads": [{}]},
        {"workloads": [{"workloadId": "bad id"}]},
        {
            "workloads": [
                {"workloadId": "duplicate", "state": "running"},
                {"workloadId": "duplicate", "state": "stopped"},
            ]
        },
    ],
)
def test_proxy_refuses_malformed_accepted_default_list_projection(
    short_tmp: Path,
    list_result: object,
) -> None:
    daemon = FakeDaemon(
        short_tmp / "control.sock",
        list_result=list_result,
    )
    daemon.start()
    proxy = ExecutionHostProxy(
        socket_path=str(short_tmp / "control.sock"),
        grant_id=DEFAULT_GRANT_ID,
        authority_grant_digest="sha256:" + "1" * 64,
    )
    with pytest.raises(ExecutionHostProxyError) as exc:
        proxy.list()
    assert exc.value.code == "execution_protocol_violation"
    assert exc.value.status == 502


def test_proxy_marks_application_unavailable_for_malformed_list_projection(
    short_tmp: Path,
    monkeypatch,
) -> None:
    monkeypatch.delenv("STATEPORT_EXECUTION_GRANT_DIGEST", raising=False)
    entry, document = _application_binding()
    path = short_tmp / "bindings.json"
    path.write_text(json.dumps(document))
    peer = FakeDaemon(
        short_tmp / "control.sock",
        list_result={"workloads": [{}]},
    )
    peer.start()
    try:
        proxy = ExecutionHostProxy(
            socket_path=str(short_tmp / "control.sock"),
            catalog_entry=lambda iid: entry,
            bindings_path=path,
            bindings_owner_uid=os.getuid(),
        )
        profile = proxy.list()["result"]["applicationWorkspaces"][0]
        assert profile["status"] == "unavailable"
        assert profile["reason"] == "execution_protocol_violation"
    finally:
        peer._listener.close()


def test_legacy_application_list_accepts_omitted_operation_metadata(
    short_tmp: Path,
    monkeypatch,
) -> None:
    monkeypatch.delenv("STATEPORT_EXECUTION_GRANT_DIGEST", raising=False)
    entry, document = _application_binding()
    path = short_tmp / "bindings.json"
    path.write_text(json.dumps(document))
    peer = FakeDaemon(short_tmp / "control.sock")
    peer.start()
    try:
        proxy = ExecutionHostProxy(
            socket_path=str(short_tmp / "control.sock"),
            catalog_entry=lambda iid: entry,
            bindings_path=path,
            bindings_owner_uid=os.getuid(),
        )
        profile = proxy.list()["result"]["applicationWorkspaces"][0]
        assert profile["status"] == "available"
        assert "allowedOperations" not in profile
    finally:
        peer._listener.close()


@pytest.mark.parametrize(
    "row",
    [
        {"workloadId": "workspace-project-one"},
        {"workloadId": "workspace-project-one", "state": 1},
        {
            "workloadId": "workspace-project-one",
            "state": "running",
            "sourceSeed": [],
        },
    ],
)
def test_proxy_refuses_malformed_recovery_row_shape(
    row: dict[str, object],
) -> None:
    proxy = ExecutionHostProxy(socket_path="")
    with pytest.raises(ExecutionHostProxyError) as exc:
        proxy._list_projection(
            {"accepted": True, "result": {"workloads": [row]}},
            recovery_fields=True,
        )
    assert exc.value.code == "execution_protocol_violation"
    assert exc.value.status == 502


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


def _application_binding(instance: str = "project-one", *, run_id=None):
    from execution_host.application_workspaces import FORMAT, catalog_identity
    entry = {"instanceId": instance, "applicationId": "projectstate", "name": "Project One", "filesystem": {"device": 1, "inode": 2, "kind": "directory"}, "metadata": {"source": {"commit": "a" * 40}}}
    spec = default_sealed_workspace_workload()
    wid = "workspace-" + instance
    spec["workloadId"] = wid
    spec["parameters"].update(workspaceId=wid, volumeName="stateport-workspace-" + wid, ownership={"applicationId": entry["applicationId"], "instanceId": instance, "catalogIdentityDigest": catalog_identity(entry), "runId": run_id})
    spec = daemon_contract.validate_workload_spec(spec)
    row = {"grantId": "grant-" + instance, "authorityGrantDigest": "sha256:" + "b" * 64, "workload": spec}
    return entry, {"formatVersion": FORMAT, "bindings": [row]}


def test_application_binding_selects_exact_grant_and_refuses_catalog_and_run_drift(short_tmp):
    entry, document = _application_binding()
    path = short_tmp / "bindings.json"
    path.write_text(json.dumps(document))
    daemon = FakeDaemon(short_tmp / "control.sock")
    daemon.start()
    proxy = ExecutionHostProxy(socket_path=short_tmp / "control.sock", authority_grant_digest="sha256:" + "1" * 64,
        catalog_entry=lambda iid: entry, bindings_path=path, bindings_owner_uid=os.getuid())
    assert proxy.create_application("project-one")["accepted"]
    assert daemon.requests[-1]["requester"]["grantId"] == "grant-project-one"
    assert daemon.requests[-1]["payload"]["workload"] == document["bindings"][0]["workload"]
    proxy.stop("workspace-project-one")
    assert daemon.requests[-1]["requester"]["grantId"] == "grant-project-one"
    before = len(daemon.requests)
    entry["filesystem"]["inode"] = 3
    with pytest.raises(ExecutionHostProxyError, match="no longer matches"):
        proxy.create_application("project-one")
    assert len(daemon.requests) == before
    entry, document = _application_binding(run_id="foreign-run")
    path.write_text(json.dumps(document))
    with pytest.raises(ExecutionHostProxyError, match="no longer matches"):
        proxy.start("workspace-project-one")
    assert len(daemon.requests) == before
    proxy._instance_runs = lambda iid: [{"runId": "foreign-run", "instanceId": "other-instance"}]
    with pytest.raises(ExecutionHostProxyError, match="no longer matches"):
        proxy.start("workspace-project-one")
    proxy._instance_runs = lambda iid: [{"runId": "foreign-run", "instanceId": iid}]
    assert proxy.start("workspace-project-one")["accepted"]
    daemon._listener.close()


def test_application_manifest_rejects_overlap_symlink_and_writable_authority(short_tmp):
    from execution_host.application_workspaces import read_bindings, validate_bindings
    _, document = _application_binding()
    document["bindings"].append(document["bindings"][0])
    with pytest.raises(ValueError, match="overlap"):
        validate_bindings(document)
    document["bindings"].pop()
    path = short_tmp / "bindings.json"
    path.write_text(json.dumps(document))
    assert len(read_bindings(path, operator_uid=os.getuid())) == 1
    path.chmod(0o666)
    with pytest.raises(ValueError, match="writable"):
        read_bindings(path, operator_uid=os.getuid())
    path.chmod(0o644)
    link = short_tmp / "link.json"
    link.symlink_to(path)
    with pytest.raises(OSError):
        read_bindings(link, operator_uid=os.getuid())
    with pytest.raises(ValueError, match="untrusted ownership"):
        read_bindings(path, operator_uid=os.getuid() + 1)


def test_catalog_identity_ignores_activity_but_binds_reimport():
    from execution_host.application_workspaces import catalog_identity
    entry, _ = _application_binding()
    identity = catalog_identity(entry)
    entry.update(lastVerifiedAt="later", updatedAt="later", lastBackup="receipt")
    assert catalog_identity(entry) == identity
    entry["metadata"]["source"]["commit"] = "c" * 40
    assert catalog_identity(entry) != identity


def test_application_authority_does_not_depend_on_default_grant(short_tmp, monkeypatch):
    monkeypatch.delenv("STATEPORT_EXECUTION_GRANT_DIGEST", raising=False)
    entry, document = _application_binding()
    path = short_tmp / "bindings.json"
    path.write_text(json.dumps(document))
    daemon = FakeDaemon(short_tmp / "control.sock")
    daemon.start()
    proxy = ExecutionHostProxy(socket_path=short_tmp / "control.sock", catalog_entry=lambda iid: entry,
        bindings_path=path, bindings_owner_uid=os.getuid())
    assert proxy.status()["status"] == "available"
    assert proxy.create_application("project-one")["accepted"]
    assert proxy.list()["result"]["applicationWorkspaces"][0]["status"] == "available"
    assert {request["requester"]["grantId"] for request in daemon.requests} == {"grant-project-one"}
    with pytest.raises(ExecutionHostProxyError, match="default workspace grant"):
        proxy.create_default()
    with pytest.raises(ExecutionHostProxyError, match="No exact authority"):
        proxy.stop("unknown-workload")
    daemon._listener.close()


@pytest.mark.parametrize("operations,valid", [
    (["listWorkloads", "status", "start"], True),
    (["listWorkloads", "status", "openTerminal", "resizeTerminal", "signalTerminal", "closeTerminal"], True),
    (["listWorkloads", "start", "start"], False),
    (["listWorkloads", "inventedAuthority"], False),
    ("start", False),
    (["listWorkloads", {}], False),
])
def test_legacy_application_operations_come_from_its_own_daemon_observation(short_tmp, monkeypatch, operations, valid):
    monkeypatch.delenv("STATEPORT_EXECUTION_GRANT_DIGEST", raising=False)
    entry, document = _application_binding()
    path = short_tmp / "bindings.json"
    path.write_text(json.dumps(document))
    peer = FakeDaemon(short_tmp / "control.sock")
    peer.listed_operations = operations
    peer.start()
    try:
        proxy = ExecutionHostProxy(socket_path=short_tmp / "control.sock", catalog_entry=lambda iid: entry,
            bindings_path=path, bindings_owner_uid=os.getuid())
        profile = proxy.list()["result"]["applicationWorkspaces"][0]
        assert profile["status"] == ("available" if valid else "unavailable")
        if valid:
            assert profile["allowedOperations"] == operations
            assert profile["terminalAvailable"] == ("openTerminal" in operations)
        else:
            assert profile["reason"] == "workspace_operations_invalid"
            assert "allowedOperations" not in profile
        assert {request["requester"]["grantId"] for request in peer.requests} == {"grant-project-one"}
    finally:
        peer._listener.close()


def test_binding_reader_refuses_fifo_without_blocking(short_tmp):
    from execution_host.application_workspaces import read_bindings
    fifo = short_tmp / "bindings.fifo"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(ValueError, match="bounded regular file"):
        read_bindings(fifo, operator_uid=os.getuid())


def test_application_terminal_uses_bound_capsule_client_and_preserves_catalog_gate(short_tmp):
    from types import SimpleNamespace
    for source in (ROOT / "packages").glob("*/src"):
        sys.path.insert(0, str(source))
    from stateport_persistent_app.service_process import AppServer
    from stateport_terminal_broker.execution_host_gateway import ExecutionHostTerminalGateway
    root = short_tmp / "project"
    root.mkdir()
    info = root.stat()
    entry, document = _application_binding()
    entry.update(path=str(root), pathState="present", status="active", filesystem={"device": info.st_dev, "inode": info.st_ino, "kind": "directory"})
    from execution_host.application_workspaces import catalog_identity
    document["bindings"][0]["workload"]["parameters"]["ownership"]["catalogIdentityDigest"] = catalog_identity(entry)
    path = short_tmp / "bindings.json"
    path.write_text(json.dumps(document))
    server = object.__new__(AppServer)
    server.source_app = lambda: SimpleNamespace(catalog=SimpleNamespace(get=lambda iid: entry, update=lambda iid, **values: entry["metadata"].update(values)))
    server.application_experience = lambda app, iid: {"capabilities": [{"id": item, "status": "available"} for item in ("workbench", "terminal")]}
    server.experience_policy = SimpleNamespace(permissions_for=lambda role: {"application.terminal.use"})
    server.actor_role = "platform_operator"
    server.actor_id = "operator"
    server.server_address = ("127.0.0.1", 12345)
    server.terminal_brokers = {}
    server.terminal_tickets = {}
    server._terminal_mutex = threading.RLock()
    server.execution_host = ExecutionHostProxy(socket_path=short_tmp / "control.sock", catalog_entry=server.workspace_catalog_entry, bindings_path=path, bindings_owner_uid=os.getuid())
    try:
        binding = server._terminal_binding_locked("project-one")
        assert isinstance(binding[1], ExecutionHostTerminalGateway)
        assert binding[1]._client.grant_id == "grant-project-one"
        assert binding[3] == Path("/workspace")
        prepared = server.prepare_terminal("project-one", columns=80, rows=24)
        assert prepared["target"]["targetClass"] == "capsule"
        # Removing authority closes a prior bound session and must never opt
        # the same application into the less isolated local-PTY path.
        document["bindings"] = []
        path.write_text(json.dumps(document))
        with pytest.raises(PermissionError, match="host terminal fallback"):
            server._terminal_binding_locked("project-one")
        assert server.terminal_brokers == {}
        # A fresh server cache still sees the durable catalog association.
        with pytest.raises(PermissionError, match="host terminal fallback"):
            server._terminal_binding_locked("project-one")
        entry["filesystem"]["inode"] += 1
        with pytest.raises(PermissionError, match="filesystem identity"):
            server._terminal_binding_locked("project-one")
        assert server.terminal_brokers == {}
    finally:
        for row in server.terminal_brokers.values():
            row[1].close()


def test_workspace_source_review_is_exact_and_stale_source_never_reaches_daemon(short_tmp):
    import shutil
    import subprocess
    from execution_host.application_workspaces import catalog_identity
    for package_source in (ROOT / "packages").glob("*/src"):
        sys.path.insert(0, str(package_source))
    from stateport_persistent_app.execution_host_proxy import prepare_workspace_source_seed
    entry, document = _application_binding()
    root = short_tmp / 'application'
    shutil.copytree(ROOT / 'fixtures' / 'apps' / 'development-reference', root)
    for args in [('init',), ('add', '--all'), ('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgSign=false', 'commit', '-m', 'source review')]:
        subprocess.run(['git', '-C', str(root), *args], check=True, capture_output=True)
    entry['path'] = str(root)
    entry['filesystem'] = {'device': root.stat().st_dev, 'inode': root.stat().st_ino, 'kind': 'directory'}
    spec = document['bindings'][0]['workload']
    spec['parameters']['ownership']['catalogIdentityDigest'] = catalog_identity(entry)
    seeded = prepare_workspace_source_seed(entry, spec)
    review = seeded['parameters']['sourceSeed']
    assert review['sourceArchive']['fileCount'] == len(review['sourceInventory'])
    assert any(row['path'] == 'application.yaml' for row in review['sourceInventory'])
    assert not any(row['path'].startswith('.git/') for row in review['sourceInventory'])
    assert prepare_workspace_source_seed(entry, spec) == seeded
    changed = json.loads(json.dumps(seeded))
    changed['parameters']['sourceSeed']['sourceInventory'][0]['contentDigest'] = 'sha256:' + '0' * 64
    with pytest.raises(ValueError, match='review digest'):
        daemon_contract.validate_workload_spec(changed)
    document['bindings'][0]['workload'] = seeded
    path = short_tmp / 'source-bindings.json'
    path.write_text(json.dumps(document))
    daemon = FakeDaemon(short_tmp / 'source-control.sock')
    daemon.start()
    proxy = ExecutionHostProxy(socket_path=short_tmp / 'source-control.sock', catalog_entry=lambda iid: entry, bindings_path=path, bindings_owner_uid=os.getuid())
    with pytest.raises(ExecutionHostProxyError, match='Confirm the exact'):
        proxy.create_application(entry['instanceId'])
    assert not daemon.requests
    (root / 'application.yaml').write_text((root / 'application.yaml').read_text() + '\n# changed after review\n')
    with pytest.raises(ExecutionHostProxyError, match='could not be verified'):
        proxy.create_application(entry['instanceId'], source_review_digest=review['reviewDigest'])
    assert all(request['operation'] != 'createWorkload' for request in daemon.requests)


def _issuer_fixture(root, *, terminal=False):
    from datetime import datetime, timedelta, timezone
    root.mkdir()
    profile = default_sealed_workspace_workload()
    value = {"formatVersion": "stateport.workspace-issuer-public/v1", "issuerContextDigest": "sha256:" + "a" * 64,
             "profileId": "stateport.empty-workspace/v1", "profileDigest": daemon_contract.canonical_digest(profile),
             "sourceMode": "empty", "profile": profile,
             "grantExpiresAtLimit": (datetime.now(timezone.utc) + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
             "operator": {"user": "fixture-operator", "uid": os.getuid(), "gid": os.getgid()}}
    if terminal:
        from execution_host.application_workspaces import terminal_authority_profile, TERMINAL_PROFILE_ID
        value.update(formatVersion="stateport.workspace-issuer-public/v2", profileId=TERMINAL_PROFILE_ID, profile=terminal_authority_profile(profile))
        value["profileDigest"] = daemon_contract.canonical_digest(value["profile"])
    (root / "issuer.json").write_text(json.dumps(value))
    (root / "bindings.json").write_text(json.dumps({"formatVersion": "stateport.application-workspace-bindings/v1", "bindings": []}))
    return value


def _source_issuer_fixture(root):
    from execution_host.application_workspaces import SOURCE_PROFILE_ID, source_authority_profile
    value = _issuer_fixture(root)
    template = value["profile"]
    value.update(
        formatVersion="stateport.workspace-issuer-public/v3",
        profileId=SOURCE_PROFILE_ID,
        sourceMode="reviewed-commit",
        profile=source_authority_profile(template),
    )
    value["profileDigest"] = daemon_contract.canonical_digest(value["profile"])
    (root / "issuer.json").write_text(json.dumps(value))
    return value


def _committed_source_fixture(root, entry):
    import shutil
    import subprocess
    source = root / "reviewed-source"
    shutil.copytree(ROOT / "fixtures" / "apps" / "development-reference", source)
    for args in [
        ("init",),
        ("add", "--all"),
        ("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgSign=false", "commit", "-m", "source review"),
    ]:
        subprocess.run(["git", "-C", str(source), *args], check=True, capture_output=True)
    info = source.stat()
    entry["path"] = str(source)
    entry["filesystem"] = {"device": info.st_dev, "inode": info.st_ino, "kind": "directory"}
    return source


def _authority_proxy(root, entry):
    return ExecutionHostProxy(authority_directory=root, bindings_path=root / "bindings.json", bindings_owner_uid=os.getuid(),
                              catalog_entry=lambda iid: entry, catalog_entries=lambda: [entry], socket_path="", authority_grant_digest="")


def test_workspace_authority_prepare_is_exact_read_only_and_catalog_available_without_daemon(short_tmp):
    root = short_tmp / "authority"
    issuer = _issuer_fixture(root)
    entry, _ = _application_binding()
    proxy = _authority_proxy(root, entry)
    before = {path.name: path.read_bytes() for path in root.iterdir()}
    review = proxy.workspace_authority(entry["instanceId"])
    assert review["status"] == "available"
    assert "operator" not in review["issuer"]
    result = proxy.prepare_workspace_authority(entry["instanceId"], profile_digest=issuer["profileDigest"], source_mode="empty", grant_expires_at=issuer["grantExpiresAtLimit"])
    request = result["request"]
    assert request["catalogIdentityDigest"] == review["catalogIdentityDigest"]
    assert request["issuerContextDigest"] == issuer["issuerContextDigest"]
    assert request["requestDigest"] == daemon_contract.canonical_digest({key: value for key, value in request.items() if key != "requestDigest"})
    assert {path.name: path.read_bytes() for path in root.iterdir()} == before
    assert proxy.list()["result"]["applicationWorkspaces"][0]["status"] == "unavailable"
    assert proxy.list()["result"]["workloads"] == []
    assert str(root) not in json.dumps(result)


def test_workspace_authority_prepare_source_binds_commit_witness_and_exact_inventory(short_tmp):
    import base64
    import hashlib
    import subprocess
    from execution_host.application_workspaces import SOURCE_REQUEST_FORMAT

    authority = short_tmp / "authority"
    issuer = _source_issuer_fixture(authority)
    entry, _ = _application_binding()
    source = _committed_source_fixture(short_tmp, entry)
    entry["metadata"]["source"]["commit"] = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()
    before = {path.name: path.read_bytes() for path in authority.iterdir()}
    result = _authority_proxy(authority, entry).prepare_workspace_authority(
        entry["instanceId"], profile_digest=issuer["profileDigest"],
        source_mode="reviewed-commit", grant_expires_at=issuer["grantExpiresAtLimit"],
    )
    request = result["request"]
    source_review = request["source"]
    raw = base64.b64decode(source_review["commitObject"], validate=True)
    assert request["formatVersion"] == SOURCE_REQUEST_FORMAT
    assert request["sourceMode"] == "reviewed-commit"
    assert result["review"]["issuer"]["profileId"] == "stateport.reviewed-source-workspace-terminal/v1"
    assert source_review["baseRevision"] == entry["metadata"]["source"]["commit"]
    assert hashlib.sha1(b"commit " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest() == source_review["baseRevision"]
    assert source_review["sourceArchive"]["fileCount"] == len(source_review["sourceInventory"])
    assert any(row["path"] == "application.yaml" for row in source_review["sourceInventory"])
    assert not any(row["path"].startswith(".git/") for row in source_review["sourceInventory"])
    assert request["sourceDigest"] == daemon_contract.canonical_digest(source_review)
    assert request["requestDigest"] == daemon_contract.canonical_digest({key: value for key, value in request.items() if key != "requestDigest"})
    assert {path.name: path.read_bytes() for path in authority.iterdir()} == before


def test_workspace_authority_prepare_source_refuses_dirty_repository_truthfully(short_tmp):
    authority = short_tmp / "authority"
    issuer = _source_issuer_fixture(authority)
    entry, _ = _application_binding()
    source = _committed_source_fixture(short_tmp, entry)
    (source / "application.yaml").write_text((source / "application.yaml").read_text() + "\n# unreviewed\n")
    with pytest.raises(ExecutionHostProxyError) as failure:
        _authority_proxy(authority, entry).prepare_workspace_authority(
            entry["instanceId"], profile_digest=issuer["profileDigest"],
            source_mode="reviewed-commit", grant_expires_at=issuer["grantExpiresAtLimit"],
        )
    assert failure.value.code == "workspace_source_review_failed"
    assert "no authority request" in str(failure.value)


def test_workspace_authority_prepare_source_maps_missing_repository_to_bounded_refusal(short_tmp):
    import shutil
    authority = short_tmp / "authority"
    issuer = _source_issuer_fixture(authority)
    entry, _ = _application_binding()
    source = _committed_source_fixture(short_tmp, entry)
    shutil.rmtree(source / ".git")
    with pytest.raises(ExecutionHostProxyError) as failure:
        _authority_proxy(authority, entry).prepare_workspace_authority(
            entry["instanceId"], profile_digest=issuer["profileDigest"],
            source_mode="reviewed-commit", grant_expires_at=issuer["grantExpiresAtLimit"],
        )
    assert failure.value.code == "workspace_source_review_failed"
    assert failure.value.status == 409


def test_workspace_authority_prepare_source_rejects_oversized_commit_witness(short_tmp, monkeypatch):
    import base64
    authority = short_tmp / "authority"
    issuer = _source_issuer_fixture(authority)
    entry, _ = _application_binding()
    _committed_source_fixture(short_tmp, entry)
    monkeypatch.setattr(
        "stateport_persistent_app.execution_host_proxy._read_reviewed_commit_object",
        lambda root, commit: base64.b64encode(b"x" * (64 * 1024 + 1)).decode("ascii"),
    )
    with pytest.raises(ExecutionHostProxyError) as failure:
        _authority_proxy(authority, entry).prepare_workspace_authority(
            entry["instanceId"], profile_digest=issuer["profileDigest"],
            source_mode="reviewed-commit", grant_expires_at=issuer["grantExpiresAtLimit"],
        )
    assert failure.value.code == "workspace_source_review_failed"


def test_workspace_authority_prepare_source_keeps_expiry_validation_as_bad_request(short_tmp):
    authority = short_tmp / "authority"
    issuer = _source_issuer_fixture(authority)
    entry, _ = _application_binding()
    with pytest.raises(ExecutionHostProxyError) as failure:
        _authority_proxy(authority, entry).prepare_workspace_authority(
            entry["instanceId"], profile_digest=issuer["profileDigest"],
            source_mode="reviewed-commit", grant_expires_at="2000-01-01T00:00:00Z",
        )
    assert failure.value.code == "workspace_authority_request_invalid"
    assert failure.value.status == 400


@pytest.mark.parametrize("profile,mode", [(None, "empty"), ("sha256:" + "c" * 64, "reviewed-commit")])
def test_workspace_authority_prepare_source_requires_exact_selected_profile_and_mode(short_tmp, profile, mode):
    authority = short_tmp / "authority"
    issuer = _source_issuer_fixture(authority)
    entry, _ = _application_binding()
    with pytest.raises(ExecutionHostProxyError) as failure:
        _authority_proxy(authority, entry).prepare_workspace_authority(
            entry["instanceId"], profile_digest=issuer["profileDigest"] if profile is None else profile,
            source_mode=mode, grant_expires_at=issuer["grantExpiresAtLimit"],
        )
    assert failure.value.code == "workspace_authority_review_stale"


@pytest.mark.parametrize("change", ["missing", "symlink", "writable", "changed-profile", "expired", "fifo"])
def test_workspace_authority_public_context_refuses_unsafe_or_stale_sources(short_tmp, change):
    root = short_tmp / "authority"
    value = _issuer_fixture(root)
    entry, _ = _application_binding()
    path = root / "issuer.json"
    if change == "missing": path.unlink()
    elif change == "symlink":
        path.rename(root / "original.json")
        path.symlink_to(root / "original.json")
    elif change == "fifo":
        path.unlink()
        os.mkfifo(path)
    elif change == "writable": path.chmod(0o666)
    else:
        if change == "changed-profile": value["profile"]["image"]["reference"] = "foreign"
        else: value["grantExpiresAtLimit"] = "2000-01-01T00:00:00Z"
        path.write_text(json.dumps(value))
    result = _authority_proxy(root, entry).workspace_authority(entry["instanceId"])
    assert result["status"] == "unavailable"
    assert "issuer" not in result


@pytest.mark.parametrize("profile,mode,expiry", [("sha256:" + "b" * 64, "empty", "2100-01-01T00:00:00Z"), (None, "seeded", "2100-01-01T00:00:00Z"), (None, "empty", "2000-01-01T00:00:00Z"), (None, "empty", "2100-01-01T00:00:00Z"), (None, "empty", "2030-1-1T1:1:1Z")])
def test_workspace_authority_prepare_refuses_profile_source_and_expiry_changes(short_tmp, profile, mode, expiry):
    root = short_tmp / "authority"
    issuer = _issuer_fixture(root)
    entry, _ = _application_binding()
    with pytest.raises(ExecutionHostProxyError):
        _authority_proxy(root, entry).prepare_workspace_authority(entry["instanceId"], profile_digest=profile or issuer["profileDigest"], source_mode=mode, grant_expires_at=expiry)


def test_workspace_authority_prepare_rechecks_catalog_during_request(short_tmp):
    root = short_tmp / "authority"
    issuer = _issuer_fixture(root)
    entry, _ = _application_binding()
    proxy = _authority_proxy(root, entry)
    calls = []
    def changing(iid):
        calls.append(iid)
        return {**entry, "filesystem": {"device": 1, "inode": len(calls)}}
    proxy._catalog_entry = changing
    with pytest.raises(ExecutionHostProxyError, match="changed during preparation"):
        proxy.prepare_workspace_authority(entry["instanceId"], profile_digest=issuer["profileDigest"], source_mode="empty", grant_expires_at=issuer["grantExpiresAtLimit"])


@pytest.mark.parametrize("terminal", [False, True])
def test_workspace_authority_real_http_session_csrf_operator_permission_and_zero_issuance(tmp_path, monkeypatch, terminal):
    # Existing real HTTP harness; no daemon/container launches or authority writes.
    from test_platform_services_api import WebHarness, _request
    harness = WebHarness(tmp_path, monkeypatch)
    try:
        directory = harness.server.layout.instances_root / "authority-app"
        directory.mkdir()
        harness.server.source_app().catalog.register(directory, instance_id="authority-app", name="Actual catalog application", source={})
        public = tmp_path / "workspace-authority"
        issuer = _issuer_fixture(public, terminal=terminal)
        harness.server.execution_host._authority_directory = str(public)
        harness.server.execution_host._bindings_path = str(public / "bindings.json")
        harness.server.execution_host._bindings_owner_uid = os.getuid()
        path = "/v1/execution-host/workspaces/authority-app/authority"
        body = {"profileDigest": issuer["profileDigest"], "sourceMode": "empty", "grantExpiresAt": issuer["grantExpiresAtLimit"]}
        assert _request(harness.port, path)[0] in {401, 403}
        assert harness.get(path)[0] == 200
        before = {p.name: p.read_bytes() for p in public.iterdir()}
        assert _request(harness.port, path + "/prepare", method="POST", cookie=harness.cookie, csrf="wrong", origin=harness.origin, body=body)[0] == 403
        status, response = harness.post(path + "/prepare", body)
        assert status == 200, response
        assert response["result"]["request"]["instanceId"] == "authority-app"
        assert harness.post(path + "/prepare", {**body, "image": "caller-image"})[0] == 400
        harness.server.actor_role = "local_user"
        assert harness.get(path)[0] == 403
        assert harness.post(path + "/prepare", body)[0] == 403
        harness.server.actor_role = "platform_operator"
        monkeypatch.setattr(harness.server, "require_actor_permission", lambda _: (_ for _ in ()).throw(PermissionError("fixture permission refused")))
        assert harness.get(path)[0] == 403
        assert harness.post(path + "/prepare", body)[0] == 403
        assert {p.name: p.read_bytes() for p in public.iterdir()} == before
    finally:
        harness.close()


def test_prepared_request_real_publication_is_discovered_and_replaced_binding_not_misreported(short_tmp, monkeypatch):
    from copy import deepcopy
    from execution_host import application_workspaces as authority
    from execution_host.grants import GrantStore
    root = short_tmp / "authority"
    issuer = _issuer_fixture(root)
    entry, _ = _application_binding()
    proxy = _authority_proxy(root, entry)
    request = proxy.prepare_workspace_authority(entry["instanceId"], profile_digest=issuer["profileDigest"], source_mode="empty", grant_expires_at=issuer["grantExpiresAtLimit"])["request"]
    # Real issuer filesystem transaction with test-only UID substitution; no sudo,
    # installed unit validation or daemon/container execution is claimed.
    monkeypatch.setattr(authority, "_ROOT_UID", os.getuid())
    monkeypatch.setattr(authority, "_EXEC_UID", os.getuid())
    grants = short_tmp / "private-grants"
    grants.mkdir(mode=0o700)
    revocation = grants / "revocation.json"
    revocation.write_text(json.dumps({"revocationEpoch": 1, "revokedGrantIds": [], "pausedGrantIds": []}))
    revocation.chmod(0o600)
    (root / "receipts").mkdir()
    wid = authority.workspace_authority_workload_id(request)
    spec = deepcopy(issuer["profile"])
    spec["workloadId"] = spec["parameters"]["workspaceId"] = wid
    spec["parameters"]["volumeName"] = "stateport-workspace-" + wid
    spec["parameters"]["ownership"] = {"instanceId": entry["instanceId"], "applicationId": entry["applicationId"], "catalogIdentityDigest": request["catalogIdentityDigest"], "runId": None}
    spec = daemon_contract.validate_workload_spec(spec)
    grant = {"formatVersion": "stateport.execution-host-grant/v2", "grantId": "workspace-grant-" + request["requestDigest"][7:39], "peerUid": 65531,
             "operations": ["createWorkload", "listWorkloads", "status", "start", "stop", "logs", "execWorkload", "removeWorkload"],
             "workloadIds": [wid], "workloadKinds": ["workspace"], "workloadSpecDigests": {wid: daemon_contract.canonical_digest(spec)},
             "imageReference": spec["image"]["reference"], "baseRevision": None, "issuedAt": request["createdAt"], "expiresAt": request["grantExpiresAt"], "revocationEpoch": 1,
             "budgets": {"maxTimeoutSeconds": 3600, "maxOutputBytes": 65536, "maxMemoryMaxBytes": 268435456, "maxPidsMax": 128, "maxActiveWorkloads": 1, "maxCpuQuotaPercent": 100, "maxDiskMaxBytes": 268435456}}
    binding = {"grantId": grant["grantId"], "authorityGrantDigest": daemon_contract.canonical_digest(grant), "workload": spec}
    receipt = authority.issue_workspace_authority(request, grant=grant, binding=binding, context_digest=issuer["issuerContextDigest"], operator={"user": "fixture", "uid": 1000, "gid": 1000}, grants_dir=grants, bindings_path=root / "bindings.json", receipt_dir=root / "receipts", verify_current=lambda: None, clock=lambda: request["createdAt"])
    assert GrantStore(grants, clock=lambda: request["createdAt"]).assert_live(grant["grantId"])["workloadIds"] == [wid]
    reopened = _authority_proxy(root, entry)
    assert reopened.workspace_authority(entry["instanceId"])["issued"] == receipt
    assert reopened.workspace_authority(entry["instanceId"])["status"] == "issued"
    with pytest.raises(ExecutionHostProxyError):
        reopened.prepare_workspace_authority(entry["instanceId"], profile_digest=issuer["profileDigest"], source_mode="empty", grant_expires_at=issuer["grantExpiresAtLimit"])
    # Revocation remains private: public receipt is explicitly historical, not live.
    revocation.write_text(json.dumps({"revocationEpoch": 1, "revokedGrantIds": [grant["grantId"]], "pausedGrantIds": []}))
    assert reopened.workspace_authority(entry["instanceId"])["issued"] == receipt
    # A newer binding must not borrow an older receipt, even for the same instance.
    binding["authorityGrantDigest"] = "sha256:" + "c" * 64
    (root / "bindings.json").write_text(json.dumps({"formatVersion": authority.FORMAT, "bindings": [binding]}))
    assert "issued" not in reopened.workspace_authority(entry["instanceId"])
    entry["filesystem"]["inode"] += 1
    assert reopened.workspace_authority(entry["instanceId"])["status"] == "unavailable"


def _v2_fixture(root, *, terminal=False):
    from execution_host.application_workspaces import TRANSPORT_FORMAT
    from execution_host.grants import GrantStore
    root.mkdir()
    entry, v1 = _application_binding()
    row = v1["bindings"][0]
    spec = row["workload"]
    grant = {"formatVersion": "stateport.execution-host-grant/v2", "grantId": row["grantId"], "peerUid": 65531,
             "operations": ["createWorkload", "listWorkloads", "status", "start", "stop", "logs", "execWorkload", "removeWorkload"],
             "workloadIds": [spec["workloadId"]], "workloadKinds": ["workspace"], "workloadSpecDigests": {spec["workloadId"]: daemon_contract.canonical_digest(spec)},
             "imageReference": spec["image"]["reference"], "baseRevision": None, "issuedAt": "2026-01-01T00:00:00Z", "expiresAt": "2100-01-01T00:00:00Z", "revocationEpoch": 1,
             "budgets": {"maxTimeoutSeconds": 3600, "maxOutputBytes": 65536, "maxMemoryMaxBytes": 268435456, "maxPidsMax": 128, "maxActiveWorkloads": 1, "maxCpuQuotaPercent": 100, "maxDiskMaxBytes": 268435456}}
    if terminal:
        from execution_host.application_workspaces import terminal_authority_profile
        grant["operations"] = terminal_authority_profile(default_sealed_workspace_workload())["operations"]
    row.update(grant=grant, authorityGrantDigest=daemon_contract.canonical_digest(grant))
    public = root / "bindings.json"
    public.write_text(json.dumps({"formatVersion": TRANSPORT_FORMAT, "bindings": [row]}))
    private = root / "grants"
    private.mkdir()
    (private / (grant["grantId"] + ".json")).write_text(json.dumps(grant))
    (private / "revocation.json").write_text(json.dumps({"revocationEpoch": 1, "revokedGrantIds": [], "pausedGrantIds": []}))
    peer = FakeDaemon(root / "control.sock", private_grants=GrantStore(private, clock=lambda: "2026-09-06T00:00:00Z"))
    peer.start()
    calls = []
    def catalog(iid):
        calls.append(iid)
        return entry
    proxy = ExecutionHostProxy(socket_path=root / "control.sock", bindings_format=TRANSPORT_FORMAT, bindings_path=public, catalog_entry=catalog, catalog_entries=lambda: [entry], authority_grant_digest="")
    return proxy, peer, entry, row, public, calls


@pytest.mark.parametrize("forgery", ["grant", "spec", "image", "operation", "removed", "empty", "downgrade"])
def test_v2_transport_cannot_reach_catalog_source_or_marker_before_private_grant_auth(short_tmp, monkeypatch, forgery):
    from copy import deepcopy
    from execution_host.application_workspaces import TRANSPORT_FORMAT
    from stateport_persistent_app.service_process import AppServer
    proxy, peer, entry, original, public, calls = _v2_fixture(short_tmp / "v2")
    row = deepcopy(original)
    if forgery == "grant": row["grant"]["expiresAt"] = "2099-01-01T00:00:00Z"
    if forgery in {"spec", "image"}:
        if forgery == "spec": row["workload"]["parameters"]["cpuQuotaPercent"] = 90
        else: row["workload"]["image"]["reference"] = "registry.invalid/workspace@sha256:" + "f" * 64
        row["workload"] = daemon_contract.validate_workload_spec(row["workload"])
        row["grant"]["workloadSpecDigests"] = {row["workload"]["workloadId"]: daemon_contract.canonical_digest(row["workload"])}
        row["grant"]["imageReference"] = row["workload"]["image"]["reference"]
    if forgery == "operation": row["grant"]["operations"].remove("execWorkload")
    row["authorityGrantDigest"] = daemon_contract.canonical_digest(row["grant"])
    document = {"formatVersion": TRANSPORT_FORMAT, "bindings": [row]}
    if forgery == "empty": document["bindings"] = []
    if forgery == "downgrade":
        document["formatVersion"] = "stateport.application-workspace-bindings/v1"
        row.pop("grant")
    public.write_text(json.dumps(document))
    if forgery == "removed": public.unlink()
    server = object.__new__(AppServer)
    server.execution_host = proxy
    writes = []
    server._remember_application_workspace = lambda *args: writes.append(args)
    monkeypatch.setattr("stateport_persistent_app.execution_host_proxy._workspace_source_archive", lambda *args: pytest.fail("source read before auth"))
    try:
        with pytest.raises(ExecutionHostProxyError): server.create_application_workspace(entry["instanceId"])
        with pytest.raises(ExecutionHostProxyError): proxy.create_application(entry["instanceId"])
        assert calls == []
        assert writes == []
        if forgery == "operation":
            before = len(peer.requests)
            with pytest.raises(ExecutionHostProxyError, match="does not authorize"): proxy.exec(row["workload"]["workloadId"], ["/bin/sh", "-c", "true"])
            assert len(peer.requests) == before
        assert all(request["operation"] == "listWorkloads" for request in peer.requests)
    finally:
        peer._listener.close()


def test_v2_private_grant_auth_precedes_catalog_and_marker_and_routes_exact_create(short_tmp):
    from stateport_persistent_app.service_process import AppServer
    proxy, peer, entry, row, public, calls = _v2_fixture(short_tmp / "v2")
    server = object.__new__(AppServer)
    server.execution_host = proxy
    def remember(iid, binding):
        assert peer.requests[-1]["operation"] == "listWorkloads"
        assert calls
        assert binding["authorityGrantDigest"] == row["authorityGrantDigest"]
    server._remember_application_workspace = remember
    try:
        assert server.create_application_workspace(entry["instanceId"])["accepted"]
        assert peer.requests[-1]["operation"] == "createWorkload"
        assert peer.requests[-1]["requester"]["authorityGrantDigest"] == row["authorityGrantDigest"]
        assert peer.requests[-1]["payload"]["workload"] == row["workload"]
        assert proxy.list()["result"]["applicationWorkspaces"][0]["terminalAvailable"] is False
        assert public.exists()
    finally:
        peer._listener.close()


@pytest.mark.parametrize("transport", ["valid-without-terminal", "empty", "removed"])
def test_v2_terminal_refuses_before_catalog_or_marker_and_never_host_fallback(short_tmp, transport):
    from execution_host.application_workspaces import TRANSPORT_FORMAT
    from stateport_persistent_app.service_process import AppServer
    proxy, peer, entry, row, public, calls = _v2_fixture(short_tmp / "v2")
    if transport == "empty": public.write_text(json.dumps({"formatVersion": TRANSPORT_FORMAT, "bindings": []}))
    if transport == "removed": public.unlink()
    server = object.__new__(AppServer)
    server.execution_host = proxy
    from types import SimpleNamespace
    server.actor_role = "platform_operator"
    server.experience_policy = SimpleNamespace(permissions_for=lambda role: {"application.terminal.use"})
    server.require_actor_permission = lambda permission: None
    server._drop_terminal_broker = lambda iid: None
    server.source_app = lambda: pytest.fail("catalog opened before terminal authority")
    server._remember_application_workspace = lambda *args: pytest.fail("marker written before terminal authority")
    try:
        for platform in [False, True]:
            with pytest.raises(PermissionError): server._terminal_binding_locked(entry["instanceId"], workspace_only=platform)
        assert calls == []
    finally:
        peer._listener.close()


def test_v2_environment_cannot_redirect_fixed_socket_and_unknown_workloads_never_use_default(short_tmp, monkeypatch):
    from execution_host.application_workspaces import TRANSPORT_FORMAT
    monkeypatch.setenv("STATEPORT_EXECUTION_SOCKET", str(short_tmp / "caller.sock"))
    monkeypatch.setenv("STATEPORT_APPLICATION_WORKSPACE_BINDINGS_FORMAT", TRANSPORT_FORMAT)
    proxy = ExecutionHostProxy(authority_grant_digest="sha256:" + "a" * 64)
    assert proxy.status()["status"] == "unavailable"
    assert proxy._client_ready()[0] is None
    proxy, peer, _, row, public, _ = _v2_fixture(short_tmp / "v2")
    proxy._grant_digest = "sha256:" + "a" * 64
    try:
        with pytest.raises(ExecutionHostProxyError): proxy.status_of("foreign-workspace")
        public.unlink()
        assert proxy._workload_client("default-dev").grant_id == DEFAULT_GRANT_ID
        assert peer.requests == []
    finally:
        peer._listener.close()


def test_v2_seeded_forgery_is_refused_before_reading_source_archive(short_tmp, monkeypatch):
    import shutil
    import subprocess
    from execution_host.application_workspaces import TRANSPORT_FORMAT, catalog_identity
    from stateport_persistent_app.execution_host_proxy import prepare_workspace_source_seed
    proxy, peer, entry, row, public, calls = _v2_fixture(short_tmp / "v2")
    source = short_tmp / "source"
    shutil.copytree(ROOT / "fixtures/apps/development-reference", source)
    for args in [("init",), ("add", "--all"), ("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgSign=false", "commit", "-m", "source review")]:
        subprocess.run(["git", "-C", str(source), *args], check=True, capture_output=True)
    entry["path"] = str(source)
    entry["filesystem"] = {"device": source.stat().st_dev, "inode": source.stat().st_ino, "kind": "directory"}
    row["workload"]["parameters"]["ownership"]["catalogIdentityDigest"] = catalog_identity(entry)
    row["workload"] = prepare_workspace_source_seed(entry, row["workload"])
    row["grant"]["baseRevision"] = row["workload"]["parameters"]["baseRevision"]
    row["grant"]["workloadSpecDigests"] = {row["workload"]["workloadId"]: daemon_contract.canonical_digest(row["workload"])}
    row["authorityGrantDigest"] = daemon_contract.canonical_digest(row["grant"])
    public.write_text(json.dumps({"formatVersion": TRANSPORT_FORMAT, "bindings": [row]}))
    monkeypatch.setattr("stateport_persistent_app.execution_host_proxy._workspace_source_archive", lambda *args: pytest.fail("untrusted source snapshot was opened"))
    try:
        with pytest.raises(ExecutionHostProxyError): proxy.create_application(entry["instanceId"], source_review_digest=row["workload"]["parameters"]["sourceSeed"]["reviewDigest"])
        assert calls == []
        profile = proxy.list()["result"]["applicationWorkspaces"][0]
        assert profile["status"] == "unavailable"
        assert "sourceReview" not in profile
    finally:
        peer._listener.close()


def test_v2_projection_uses_private_grant_auth_not_public_receipt_actor_claims(short_tmp):
    proxy, peer, entry, row, public, calls = _v2_fixture(short_tmp / "v2")
    hint = short_tmp / "issuer-hints"
    _issuer_fixture(hint)
    proxy._authority_directory = str(hint)
    (hint / "issuer.json").chmod(0o666)  # untrusted preparation hint only in v2
    (hint / "receipts").mkdir()
    (hint / "receipts" / ("f" * 64 + ".json")).write_text(json.dumps({"status": "issued", "operator": "invented", "activatedAt": "invented"}))
    try:
        projection = proxy.workspace_authority(entry["instanceId"])
        assert projection["status"] == "issued"
        assert projection["issued"]["status"] == "daemon-verified-grant"
        assert "operator" not in projection["issued"] and "activatedAt" not in projection["issued"]
        assert projection["issued"]["authorityGrantDigest"] == row["authorityGrantDigest"]
        assert projection["issued"]["bindingDigest"] == daemon_contract.canonical_digest({key: row[key] for key in ("grantId", "authorityGrantDigest", "workload")})
        assert peer.requests[-1]["operation"] == "listWorkloads"
    finally:
        peer._listener.close()


def test_terminal_profile_prepare_binds_whole_envelope_and_exact_displayed_shell_controls(short_tmp):
    root = short_tmp / "authority"
    issuer = _issuer_fixture(root, terminal=True)
    entry, _ = _application_binding()
    proxy = _authority_proxy(root, entry)
    review = proxy.workspace_authority(entry["instanceId"])
    assert review["issuer"]["profileId"] == "stateport.empty-workspace-terminal/v1"
    assert review["issuer"]["profile"]["parameters"]["shell"] == ["/bin/sh"]
    assert {"openTerminal", "resizeTerminal", "signalTerminal", "closeTerminal"} <= set(review["issuer"]["operations"])
    assert review["issuer"]["profileDigest"] != daemon_contract.canonical_digest(review["issuer"]["profile"])
    result = proxy.prepare_workspace_authority(entry["instanceId"], profile_digest=issuer["profileDigest"], source_mode="empty", grant_expires_at=issuer["grantExpiresAtLimit"])
    assert result["request"]["profileDigest"] == daemon_contract.canonical_digest(issuer["profile"])
    with pytest.raises(ExecutionHostProxyError):
        proxy.prepare_workspace_authority(entry["instanceId"], profile_digest=daemon_contract.canonical_digest(issuer["profile"]["workload"]), source_mode="empty", grant_expires_at=issuer["grantExpiresAtLimit"])


@pytest.mark.parametrize("change", ["missing-operation", "extra-operation", "different-shell", "legacy-version", "legacy-digest"])
def test_terminal_profile_preparation_rejects_forged_or_implicitly_widened_envelope(short_tmp, change):
    root = short_tmp / "authority"
    issuer = _issuer_fixture(root, terminal=True)
    entry, _ = _application_binding()
    if change == "missing-operation": issuer["profile"]["operations"].remove("closeTerminal")
    if change == "extra-operation": issuer["profile"]["operations"].append("purgeDeploymentData")
    if change == "different-shell": issuer["profile"]["workload"]["parameters"]["shell"] = ["/bin/bash"]
    if change == "legacy-version": issuer["formatVersion"] = "stateport.workspace-issuer-public/v1"
    issuer["profileDigest"] = daemon_contract.canonical_digest(issuer["profile"]["workload"] if change == "legacy-digest" else issuer["profile"])
    (root / "issuer.json").write_text(json.dumps(issuer))
    assert _authority_proxy(root, entry).workspace_authority(entry["instanceId"])["status"] == "unavailable"


def test_explicit_terminal_grant_authenticates_private_preimage_before_returning_gateway_client(short_tmp):
    proxy, peer, entry, row, public, calls = _v2_fixture(short_tmp / "v2", terminal=True)
    try:
        binding, client = proxy.application_client(entry["instanceId"])
        assert binding["grant"]["operations"] == row["grant"]["operations"]
        assert client.authority_grant_digest == row["authorityGrantDigest"]
        assert peer.requests[-1]["operation"] == "listWorkloads"
        assert calls == [entry["instanceId"]]
        assert proxy.list()["result"]["applicationWorkspaces"][0]["terminalAvailable"] is True
    finally:
        peer._listener.close()


def _dynamic_default_fixture(root, monkeypatch):
    from execution_host.grants import GrantStore
    root.mkdir()
    image = "ghcr.io/stateport/verified-workspace@sha256:" + "d" * 64
    workload = daemon_contract.workspace_template_for_image(image)
    monkeypatch.setenv("STATEPORT_EXECUTION_HOST_WORKSPACE_IMAGE_REFERENCE", image)
    monkeypatch.setenv("STATEPORT_EXECUTION_HOST_WORKSPACE_SPEC_DIGEST", daemon_contract.canonical_digest(workload))
    grant = {"formatVersion": "stateport.execution-host-grant/v2", "grantId": DEFAULT_GRANT_ID, "peerUid": 65531,
             "operations": ["createWorkload", "listWorkloads", "status", "start", "stop", "logs", "execWorkload", "removeWorkload"],
             "workloadIds": [workload["workloadId"]], "workloadKinds": ["workspace"], "workloadSpecDigests": {workload["workloadId"]: daemon_contract.canonical_digest(workload)},
             "imageReference": image, "baseRevision": None, "issuedAt": "2026-01-01T00:00:00Z", "expiresAt": "2100-01-01T00:00:00Z", "revocationEpoch": 1,
             "budgets": {"maxTimeoutSeconds": 3600, "maxOutputBytes": 1048576, "maxMemoryMaxBytes": 268435456, "maxPidsMax": 128, "maxActiveWorkloads": 1, "maxCpuQuotaPercent": 100, "maxDiskMaxBytes": 268435456}}
    private = root / "grants"
    private.mkdir()
    (private / (DEFAULT_GRANT_ID + ".json")).write_text(json.dumps(grant))
    revocation = private / "revocation.json"
    revocation.write_text(json.dumps({"revocationEpoch": 1, "revokedGrantIds": [], "pausedGrantIds": []}))
    peer = FakeDaemon(root / "control.sock", private_grants=GrantStore(private, clock=lambda: "2026-09-06T00:00:00Z"))
    peer.start()
    peer.workspace_profile = {"imageReference": image, "workloadSpecDigest": daemon_contract.canonical_digest(workload)}
    proxy = ExecutionHostProxy(socket_path=root / "control.sock", authority_grant_digest=daemon_contract.canonical_digest(grant))
    return proxy, peer, workload, revocation


def test_dynamic_default_uses_exact_installed_template_after_live_auth(short_tmp, monkeypatch):
    proxy, peer, workload, revocation = _dynamic_default_fixture(short_tmp / "dynamic", monkeypatch)
    try:
        assert proxy.create_default()["accepted"]
        assert [row["operation"] for row in peer.requests] == ["listWorkloads", "createWorkload"]
        assert peer.requests[-1]["payload"]["workload"] == workload
        revocation.write_text(json.dumps({"revocationEpoch": 1, "revokedGrantIds": [DEFAULT_GRANT_ID], "pausedGrantIds": []}))
        with pytest.raises(ExecutionHostProxyError, match="private default authority"):
            proxy.create_default()
        assert peer.requests[-1]["operation"] == "listWorkloads"
    finally:
        peer._listener.close()


@pytest.mark.parametrize("fault", ["missing_image", "missing_digest", "empty_image", "mismatch", "unpinned"])
def test_dynamic_pair_refuses_before_daemon_effect(short_tmp, monkeypatch, fault):
    proxy, peer, _, _ = _dynamic_default_fixture(short_tmp / "dynamic", monkeypatch)
    if fault == "missing_image": proxy._workspace_image = None
    if fault == "missing_digest": proxy._workspace_spec_digest = None
    if fault == "empty_image": proxy._workspace_image = ""
    if fault == "mismatch": proxy._workspace_spec_digest = "sha256:" + "a" * 64
    if fault == "unpinned": proxy._workspace_image = "ghcr.io/stateport/workspace:latest"
    try:
        with pytest.raises(ExecutionHostProxyError) as error:
            proxy.create_default()
        assert error.value.code == "default_workload_contract_invalid"
        assert peer.requests == []
    finally:
        peer._listener.close()


def test_dynamic_issuer_requires_matching_public_profile_and_current_base(short_tmp, monkeypatch):
    from execution_host.application_workspaces import terminal_authority_profile
    proxy, peer, workload, revocation = _dynamic_default_fixture(short_tmp / "dynamic", monkeypatch)
    root = short_tmp / "authority"
    issuer = _issuer_fixture(root, terminal=True)
    issuer["profile"] = terminal_authority_profile(workload)
    issuer["profileDigest"] = daemon_contract.canonical_digest(issuer["profile"])
    (root / "issuer.json").write_text(json.dumps(issuer))
    proxy._authority_directory = str(root)
    proxy._bindings_owner_uid = os.getuid()
    try:
        assert proxy._workspace_issuer()["profile"] == workload
        # A public self-consistent image edit cannot override trusted unit pair.
        forged = daemon_contract.workspace_template_for_image("ghcr.io/stateport/foreign@sha256:" + "f" * 64)
        issuer["profile"] = terminal_authority_profile(forged)
        issuer["profileDigest"] = daemon_contract.canonical_digest(issuer["profile"])
        (root / "issuer.json").write_text(json.dumps(issuer))
        with pytest.raises(ValueError, match="profile changed"): proxy._workspace_issuer()
        issuer["profile"] = terminal_authority_profile(workload)
        issuer["profileDigest"] = daemon_contract.canonical_digest(issuer["profile"])
        (root / "issuer.json").write_text(json.dumps(issuer))
        revocation.write_text(json.dumps({"revocationEpoch": 1, "revokedGrantIds": [DEFAULT_GRANT_ID], "pausedGrantIds": []}))
        with pytest.raises(ExecutionHostProxyError): proxy._workspace_issuer()
    finally:
        peer._listener.close()


def test_v2_operation_observation_must_match_authenticated_grant(short_tmp):
    proxy, peer, entry, row, _, _ = _v2_fixture(short_tmp / "operation-mismatch")
    peer.listed_operations = ["listWorkloads", "status"]
    try:
        profile = proxy.list()["result"]["applicationWorkspaces"][0]
        assert profile["instanceId"] == entry["instanceId"]
        assert profile["status"] == "unavailable"
        assert profile["reason"] == "workspace_operations_invalid"
    finally:
        peer._listener.close()


def test_dynamic_default_revocation_does_not_disable_existing_app_grant(short_tmp, monkeypatch):
    image = "ghcr.io/stateport/verified-workspace@sha256:" + "d" * 64
    template = daemon_contract.workspace_template_for_image(image)
    monkeypatch.setenv("STATEPORT_EXECUTION_HOST_WORKSPACE_IMAGE_REFERENCE", image)
    monkeypatch.setenv("STATEPORT_EXECUTION_HOST_WORKSPACE_SPEC_DIGEST", daemon_contract.canonical_digest(template))
    proxy, peer, entry, row, _, _ = _v2_fixture(short_tmp / "application")
    # No private default grant exists here: app authority must remain independent.
    proxy._grant_digest = "sha256:" + "a" * 64
    try:
        with pytest.raises(ExecutionHostProxyError): proxy._default_workspace_workload()
        assert proxy.application_client(entry["instanceId"], operation="start")[1].grant_id == row["grantId"]
        assert proxy.start(row["workload"]["workloadId"])["accepted"]
        assert peer.requests[-1]["requester"]["grantId"] == row["grantId"]
    finally:
        peer._listener.close()


@pytest.mark.parametrize("projection", [
    None,
    "invalid",
    {},
    {"imageReference": "ghcr.io/stateport/foreign@sha256:" + "f" * 64, "workloadSpecDigest": "sha256:" + "f" * 64},
    {"imageReference": "ghcr.io/stateport/verified-workspace@sha256:" + "d" * 64, "workloadSpecDigest": "sha256:" + "a" * 64},
])
def test_dynamic_default_and_preparation_refuse_unconfirmed_daemon_profile(short_tmp, monkeypatch, projection):
    from execution_host.application_workspaces import terminal_authority_profile
    proxy, peer, workload, _ = _dynamic_default_fixture(short_tmp / "dynamic", monkeypatch)
    peer.workspace_profile = projection
    root = short_tmp / "authority"
    issuer = _issuer_fixture(root, terminal=True)
    issuer["profile"] = terminal_authority_profile(workload)
    issuer["profileDigest"] = daemon_contract.canonical_digest(issuer["profile"])
    (root / "issuer.json").write_text(json.dumps(issuer))
    proxy._authority_directory = str(root)
    proxy._bindings_owner_uid = os.getuid()
    try:
        for action in (proxy.create_default, proxy._workspace_issuer):
            with pytest.raises(ExecutionHostProxyError) as error:
                action()
            assert error.value.code == "default_workload_profile_mismatch"
        assert [row["operation"] for row in peer.requests] == ["listWorkloads", "listWorkloads"]
    finally:
        peer._listener.close()


def test_dynamic_profile_confirmation_rejects_additional_unapproved_fields(short_tmp, monkeypatch):
    proxy, peer, _, _ = _dynamic_default_fixture(short_tmp / "dynamic", monkeypatch)
    peer.workspace_profile["callerAuthority"] = True
    try:
        with pytest.raises(ExecutionHostProxyError) as error:
            proxy.create_default()
        assert error.value.code == "default_workload_profile_mismatch"
        assert len(peer.requests) == 1
    finally:
        peer._listener.close()


@pytest.mark.parametrize("daemon_binding", ["matching", "legacy", "different"])
def test_dynamic_proxy_roundtrip_with_production_daemon_and_private_grants(short_tmp, monkeypatch, daemon_binding):
    """Actual AF_UNIX/SO_PEERCRED and GrantStore; inert engine, current OS uid.

    This is the source wire seam, not installed account/socket or image proof.
    Missing/wrong projections come from actual legacy/different daemon config,
    never a fabricated protocol response. No engine effect is implemented.
    """
    from execution_host.daemon import DaemonConfig, ExecutionHostDaemon
    from execution_host.grants import GrantStore
    from stateport_release.execution_host_provisioning import _default_grant_document, _DEFAULT_GRANT_BUDGETS

    class InertEngine:
        identity = {"engine": "inert-source-wire", "socket": "none"}

        def bind_workspace_image_authority(self, reference, verify):
            self.reference = reference
            self.verify = verify

        def list_managed(self):
            return []

        def version(self):
            return {"engine": "inert-source-wire", "engineVersion": "0"}

    image = "ghcr.io/stateport/wire-workspace@sha256:" + "d" * 64
    workload = daemon_contract.workspace_template_for_image(image)
    actual_image = image if daemon_binding != "different" else "ghcr.io/stateport/other-workspace@sha256:" + "e" * 64
    actual_workload = daemon_contract.workspace_template_for_image(actual_image)
    monkeypatch.setenv("STATEPORT_EXECUTION_HOST_WORKSPACE_IMAGE_REFERENCE", image)
    monkeypatch.setenv("STATEPORT_EXECUTION_HOST_WORKSPACE_SPEC_DIGEST", daemon_contract.canonical_digest(workload))
    for key in ("STATEPORT_APPLICATION_WORKSPACE_BINDINGS", "STATEPORT_APPLICATION_WORKSPACE_BINDINGS_FORMAT"):
        monkeypatch.delenv(key, raising=False)
    root = short_tmp / "real-wire"
    root.mkdir(mode=0o700)
    socket_dir = root / "control"
    socket_dir.mkdir(mode=0o750)
    private = root / "grants"
    private.mkdir(mode=0o700)
    grant = _default_grant_document(peer_uid=os.geteuid(), grant_id=DEFAULT_GRANT_ID,
        image_reference=actual_image, workspace_template=actual_workload, base_revision=None,
        budgets=_DEFAULT_GRANT_BUDGETS, operations=["listWorkloads"],
        issued_at="2026-01-01T00:00:00Z", expires_at="2100-01-01T00:00:00Z", revocation_epoch=1)
    entry, bindings = _application_binding()
    binding = bindings["bindings"][0]
    app_grant = {**grant, "grantId": binding["grantId"],
        "imageReference": binding["workload"]["image"]["reference"],
        "workloadIds": [binding["workload"]["workloadId"]],
        "workloadSpecDigests": {binding["workload"]["workloadId"]: daemon_contract.canonical_digest(binding["workload"])}}
    binding["authorityGrantDigest"] = daemon_contract.canonical_digest(app_grant)
    for document in (grant, app_grant):
        path = private / (document["grantId"] + ".json")
        path.write_text(json.dumps(document))
        path.chmod(0o600)
    revocation = private / "revocation.json"
    revocation.write_text(json.dumps({"revocationEpoch": 1, "revokedGrantIds": [], "pausedGrantIds": []}))
    revocation.chmod(0o600)
    public = root / "bindings.json"
    public.write_text(json.dumps(bindings))
    public.chmod(0o644)
    config = DaemonConfig(socket_path=socket_dir / "control.sock", state_dir=root / "state", grants_dir=private,
        socket_group_gid=os.getegid(), allowed_client_uid=os.geteuid(), allowed_client_gid=os.getegid(),
        runtime_uid=os.geteuid(), runtime_gid=os.getegid(), supervise_interval_seconds=0.05,
        **({"workspace_image_reference": actual_image, "workspace_spec_digest": daemon_contract.canonical_digest(actual_workload)}
           if daemon_binding != "legacy" else {}))
    daemon = ExecutionHostDaemon(config, InertEngine())
    daemon.boot()
    thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    thread.start()
    proxy = ExecutionHostProxy(socket_path=config.socket_path, authority_grant_digest=daemon_contract.canonical_digest(grant))
    original = {path.name: path.read_bytes() for path in private.iterdir() if path.is_file()}
    try:
        # Both projection and refusal are produced by the production daemon.
        listed = proxy.list()
        assert listed["accepted"] is True
        assert listed["result"]["workloads"] == []
        if daemon_binding == "matching":
            assert listed["result"]["workspaceProfile"] == {"imageReference": image, "workloadSpecDigest": daemon_contract.canonical_digest(workload)}
            assert proxy._default_workspace_workload() == workload
        else:
            if daemon_binding == "legacy":
                assert "workspaceProfile" not in listed["result"]
            with pytest.raises(ExecutionHostProxyError) as error:
                proxy._default_workspace_workload()
            assert error.value.code == "default_workload_profile_mismatch"
        proxy._workspace_spec_digest = None
        with pytest.raises(ExecutionHostProxyError) as error:
            proxy._default_workspace_workload()
        assert error.value.code == "default_workload_contract_invalid"
        proxy._workspace_spec_digest = daemon_contract.canonical_digest(workload)
        assert {path.name: path.read_bytes() for path in private.iterdir() if path.is_file()} == original
        revocation.write_text(json.dumps({"revocationEpoch": 1, "revokedGrantIds": [DEFAULT_GRANT_ID], "pausedGrantIds": []}))
        with pytest.raises(ExecutionHostProxyError) as error:
            proxy._default_workspace_workload()
        assert error.value.code == "default_workload_authority_unavailable"
        app_proxy = ExecutionHostProxy(socket_path=config.socket_path, authority_grant_digest=daemon_contract.canonical_digest(grant),
            catalog_entry=lambda iid: entry, catalog_entries=lambda: [entry], bindings_path=public, bindings_owner_uid=os.geteuid())
        observed = app_proxy.list()
        assert observed["accepted"] is True
        assert observed["result"]["defaultWorkspaceRefusal"]["reason"] == "grant-revoked"
        assert observed["result"]["applicationWorkspaces"][0]["status"] == "available"
        assert GrantStore(private, clock=config.clock).assert_live(app_grant["grantId"]) == app_grant
        assert daemon._ledger.all() == []
    finally:
        daemon.shutdown()
        thread.join(timeout=2)
        assert not thread.is_alive()


def test_source_review_refuses_root_before_repository_inspection(short_tmp, monkeypatch):
    from stateport_persistent_app.execution_host_proxy import _workspace_source_archive
    import stateport_deployment.inspection as inspection
    def unexpected(*args, **kwargs):
        raise AssertionError('root must not inspect a repository through Git')
    monkeypatch.setattr(inspection, 'git_source_identity', unexpected)
    monkeypatch.setattr(os, 'geteuid', lambda: 0)
    with tempfile.TemporaryFile('w+b') as archive:
        with pytest.raises(ValueError, match='ordinary service identity'):
            _workspace_source_archive({'path': str(short_tmp)}, archive, commit_witness=True)
