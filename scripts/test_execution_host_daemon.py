"""Integration tests for the execution-host daemon on real rootless Podman.

Boots the daemon as a real subprocess on a group-confined Unix socket,
drives sealed workloads through the typed client, and proves timeout
supervision, cancellation, output bounds, kill -9 restart reconciliation,
cleanup receipts, and boot/client refusals.  No control-plane Podman socket
is ever used; the test asserts the refusal instead.

Heavy-task policy: set STATEPORT_HEAVY_TASK_LOCK to a lock file path and the
whole session runs under flock so concurrent heavy runs cannot invalidate
evidence.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from urllib.request import Request, urlopen

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "execution-host" / "src"))

from execution_host.client import (
    ExecutionHostClient,
    ExecutionHostRefusal,
    ExecutionHostTransportError,
)

GRANT_DIGEST = "sha256:" + "c" * 64
WORKLOAD_IMAGE = (
    "docker.io/library/python:3.13-alpine3.23"
    "@sha256:9fdbf2e3e82628351513560b121e2ee6ce31cac212be9e070c5a5e2769fb5e76"
)
TEST_RUNTIME_UID = os.geteuid()
TEST_RUNTIME_GID = os.getegid()
TEST_SOCKET_GROUP_GID = next(
    (gid for gid in os.getgroups() if gid not in {TEST_RUNTIME_UID, TEST_RUNTIME_GID}),
    TEST_RUNTIME_GID,
)
TEST_ALLOWED_CLIENT_UID = max({TEST_RUNTIME_UID, TEST_RUNTIME_GID, *os.getgroups()}) + 1
TEST_ALLOWED_CLIENT_GID = TEST_ALLOWED_CLIENT_UID
PYTHONPATH = os.pathsep.join(
    [
        str(ROOT / "packages" / "execution-host" / "src"),
        str(ROOT / "apps" / "execution-host" / "src"),
        str(ROOT / "packages" / "deployment" / "src"),
        str(ROOT / "packages" / "runtime-contracts" / "src"),
        str(ROOT / "packages" / "tool-gateway" / "src"),
    ]
)
for _path in PYTHONPATH.split(os.pathsep):
    if _path not in sys.path:
        sys.path.insert(0, _path)
for _source_root in sorted((ROOT / "packages").glob("*/src")):
    if str(_source_root) not in sys.path:
        sys.path.insert(0, str(_source_root))
for _source_root in sorted((ROOT / "apps").glob("*/src")):
    if str(_source_root) not in sys.path:
        sys.path.insert(0, str(_source_root))

from execution_host import daemon_contract as contract  # noqa: E402


def _booked_scope() -> str:
    rows = Path("/proc/self/cgroup").read_text().splitlines()
    scopes = [row.split("::", 1)[1] for row in rows if row.startswith("0::")]
    if len(scopes) != 1:
        raise RuntimeError("governed container fixture requires unified cgroup membership")
    parts = Path(scopes[0]).parts
    for index, component in enumerate(parts):
        if component.startswith("stateport-heavy-") and component.endswith(".service") and "stateport-heavy.slice" in parts[:index]:
            return Path(*parts[:index + 1]).as_posix()
    raise RuntimeError("real container fixture is outside a booked governor service")


def _governed_engine_environment(root: Path, environment: dict[str, str]) -> tuple[dict[str, str], str]:
    """Test-only last config overlay; no production cgroup option is admitted."""
    scope = _booked_scope()
    if environment.get("CONTAINERS_CONF_OVERRIDE"):
        raise RuntimeError("fixture cannot replace an existing operator containers.conf override")
    overlay = root / "governed-containers.conf"
    with overlay.open("x", encoding="utf-8") as stream:
        stream.write('[containers]\ncgroups="split"\n')
    overlay.chmod(0o600)
    return {**environment, "CONTAINERS_CONF_OVERRIDE": str(overlay)}, scope


def _governed_container_membership(container_id: str, scope: str, *, environment: dict[str, str] | None = None) -> dict:
    if scope != _booked_scope():
        raise RuntimeError("container evidence does not name this booked governor scope")
    observed = subprocess.run(["podman", "inspect", "--format", "{{json .}}", container_id], env=environment, capture_output=True, text=True, timeout=15)
    if observed.returncode != 0:
        raise RuntimeError("container inspection unavailable for cgroup proof")
    info = json.loads(observed.stdout)
    if info.get("Id") != container_id:
        raise RuntimeError("container identity changed during cgroup proof")
    processes = {}
    for label, pid in (("init", info["State"]["Pid"]), ("conmon", info["State"]["ConmonPid"])):
        if not isinstance(pid, int) or pid <= 0:
            raise RuntimeError(label + " process identity is unavailable")
        rows = Path(f"/proc/{pid}/cgroup").read_text().splitlines()
        membership = next((row.split("::", 1)[1] for row in rows if row.startswith("0::")), None)
        if not membership or not (membership == scope or membership.startswith(scope + "/")):
            raise RuntimeError(f"{label} pid={pid} cgroup={membership!r} is outside booked scope {scope!r}")
        directory = Path("/sys/fs/cgroup") / membership.lstrip("/")
        processes[label] = {"pid": pid, "cgroup": membership, "limits": {name: (directory / name).read_text().strip() for name in ("memory.max", "cpu.max", "pids.max")}}
    return {"containerId": container_id, "bookedScope": scope, "processes": processes, "containerDeclaredParent": info["HostConfig"]["CgroupParent"]}


def _grant_document(grant_id: str, spec: dict) -> dict:
    validated = contract.validate_workload_spec(spec)
    workload_id = validated["workloadId"]
    return {
        "formatVersion": contract.GRANT_FORMAT,
        "grantId": grant_id,
        "peerUid": TEST_RUNTIME_UID,
        "operations": [
            operation
            for operation in contract.OPERATIONS
            if operation not in contract.DEPLOYMENT_OPERATIONS
        ],
        "workloadIds": [workload_id],
        "workloadKinds": [validated["kind"]],
        "workloadSpecDigests": {workload_id: contract.canonical_digest(validated)},
        "imageReference": WORKLOAD_IMAGE,
        "baseRevision": None,
        "issuedAt": "2026-08-08T00:00:00Z",
        "expiresAt": "2099-01-01T00:00:00Z",
        "revocationEpoch": 0,
        "budgets": {
            "maxTimeoutSeconds": 600,
            "maxOutputBytes": 4 * 1024 * 1024,
            "maxMemoryMaxBytes": 268435456,
            "maxPidsMax": 128,
            "maxActiveWorkloads": 4,
            "maxCpuQuotaPercent": 800,
            "maxDiskMaxBytes": 4 * 1024**3,
        },
    }


def _provision_grant(handle: "DaemonHandle", spec: dict) -> dict:
    """Provision one exact grant binding one exact spec; returns the document."""
    doc = _grant_document(f"grant-{spec['workloadId']}", spec)
    grants_dir = handle.state_dir / "grants"
    grants_dir.mkdir(parents=True, exist_ok=True)
    (grants_dir / f"{doc['grantId']}.json").write_text(
        json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return doc


def _podman(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["podman", *args], capture_output=True, text=True, timeout=300)


@pytest.fixture(scope="session", autouse=True)
def _heavy_task_lock():
    lock_path = os.environ.get("STATEPORT_HEAVY_TASK_LOCK")
    if not lock_path:
        yield
        return
    handle = open(lock_path, "a", encoding="utf-8")
    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
    try:
        yield
    finally:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


@pytest.fixture(scope="session", autouse=True)
def _workload_image(_heavy_task_lock):
    if shutil_which_podman() is None:
        pytest.skip("podman is not available on this host")
    if _podman("image", "inspect", WORKLOAD_IMAGE).returncode != 0:
        pulled = _podman("pull", WORKLOAD_IMAGE)
        if pulled.returncode != 0 or _podman("image", "inspect", WORKLOAD_IMAGE).returncode != 0:
            pytest.skip(f"pinned workload image unavailable: {pulled.stderr.strip()[:200]}")
    yield
    leftover = _podman(
        "ps", "-a", "--filter", "label=io.stateport.execution.managed=true",
        "--filter", "label=io.stateport.execution.test=wt1", "--format", "{{.ID}}",
    )
    for container_id in leftover.stdout.split():
        _podman("rm", "--force", container_id)


def shutil_which_podman() -> str | None:
    for candidate in ("/usr/bin/podman", "/usr/local/bin/podman", "/bin/podman"):
        if Path(candidate).exists():
            return candidate
    return None


class DaemonHandle:
    def __init__(
        self,
        root: Path,
        validator_staging_root: Path | None = None,
        *,
        socket_root: Path | None = None,
    ) -> None:
        self.root = root
        self.validator_staging_root = validator_staging_root
        # Evidence roots can exceed AF_UNIX's pathname limit. Keep sockets in
        # the existing short-root seam, independent of durable test artifacts.
        self.socket_dir = (socket_root or Path(tempfile.mkdtemp(prefix="s-", dir="/tmp"))) / "execution-control"
        self.socket_dir.mkdir(parents=True, exist_ok=True)
        os.chown(self.socket_dir, TEST_RUNTIME_UID, TEST_SOCKET_GROUP_GID)
        os.chmod(self.socket_dir, 0o750)
        self.state_dir = root / "state"
        self.socket_path = self.socket_dir / "control.sock"
        self.process: subprocess.Popen[str] | None = None

    def env(self) -> dict[str, str]:
        env = dict(os.environ)
        env.pop("CONTAINER_HOST", None)
        env.pop("DOCKER_HOST", None)
        env.update(
            {
                "PYTHONPATH": PYTHONPATH,
                "PYTHONDONTWRITEBYTECODE": "1",
                "STATEPORT_EXECUTION_HOST_SOCKET": str(self.socket_path),
                "STATEPORT_EXECUTION_HOST_STATE_DIR": str(self.state_dir),
                "STATEPORT_EXECUTION_HOST_SOCKET_GROUP_GID": str(TEST_SOCKET_GROUP_GID),
                "STATEPORT_EXECUTION_HOST_ALLOWED_CLIENT_UID": str(TEST_ALLOWED_CLIENT_UID),
                "STATEPORT_EXECUTION_HOST_ALLOWED_CLIENT_GID": str(TEST_ALLOWED_CLIENT_GID),
                "STATEPORT_EXECUTION_HOST_RUNTIME_UID": str(TEST_RUNTIME_UID),
                "STATEPORT_EXECUTION_HOST_RUNTIME_GID": str(TEST_RUNTIME_GID),
            }
        )
        if self.validator_staging_root is not None:
            self.validator_staging_root.mkdir(parents=True, exist_ok=True)
            env["STATEPORT_EXECUTION_HOST_VALIDATOR_STAGING_DIR"] = str(self.validator_staging_root)
        return env

    def boot(self) -> None:
        self.process = subprocess.Popen(
            [sys.executable, "-m", "stateport_execution_host"],
            env=self.env(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        deadline = time.time() + 60
        while time.time() < deadline:
            if self.process.poll() is not None:
                output = self.process.stdout.read() if self.process.stdout else ""
                raise AssertionError(f"daemon exited during boot: {output[-500:]}")
            if self.socket_path.exists():
                try:
                    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    probe.settimeout(2)
                    probe.connect(str(self.socket_path))
                    probe.close()
                    return
                except OSError:
                    # Stale socket from a previous epoch; the daemon reclaims it.
                    pass
            time.sleep(0.1)
        self.stop()
        raise AssertionError("daemon did not create its control socket within 60s")

    def stop(self) -> None:
        if self.process is None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=30)
        self.process = None

    def operator_remove_stale_socket(self) -> None:
        if self.socket_path.is_socket():
            self.socket_path.unlink()


def _client(handle: DaemonHandle, doc: dict, **changes) -> ExecutionHostClient:
    return ExecutionHostClient(
        handle.socket_path,
        grant_id=doc["grantId"],
        authority_grant_digest=contract.canonical_digest(doc),
        **changes,
    )


def _spec(workload_id: str, **changes) -> dict:
    value = {
        "kind": "terminal",
        "workloadId": workload_id,
        "image": {"reference": WORKLOAD_IMAGE},
        "parameters": {"sessionId": "sess-wt1", "workSeconds": 300, "emitBytes": 0},
        "timeoutSeconds": 600,
        "outputByteBound": 1048576,
        "resources": {"memoryMaxBytes": 268435456, "pidsMax": 128},
    }
    parameters = changes.pop("parameters", {})
    value.update(changes)
    value["parameters"].update(parameters)
    return value


def _workload_id(prefix: str) -> str:
    return f"wt1-{prefix}-{uuid.uuid4().hex[:12]}"


def _wait_state(client: ExecutionHostClient, workload_id: str, state: str, timeout: float) -> dict:
    deadline = time.time() + timeout
    last: dict | None = None
    while time.time() < deadline:
        last = client.status(workload_id)["result"]
        if last["state"] == state:
            return last
        time.sleep(0.5)
    raise AssertionError(f"workload {workload_id} never reached {state}; last={last}")


def _start_app_server(layout_root: Path) -> tuple[object, threading.Thread, str, str, str]:
    from stateport_persistent_app import LocalLayout  # noqa: PLC0415
    from stateport_persistent_app.service_process import AppServer  # noqa: PLC0415

    layout = LocalLayout(
        layout_root / "config",
        layout_root / "data",
        layout_root / "state",
    )
    layout.initialize()
    server = AppServer(("127.0.0.1", 0), layout, ROOT / "apps" / "web")
    thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.02},
        daemon=True,
    )
    thread.start()
    origin = f"http://127.0.0.1:{int(server.server_address[1])}"
    with urlopen(f"{origin}/session") as response:
        session = json.loads(response.read())["result"]
        cookie = response.headers["Set-Cookie"].split(";", 1)[0]
    return server, thread, origin, cookie, str(session["csrfToken"])


def _stop_app_server(server: object, thread: threading.Thread) -> None:
    server.shutdown()
    thread.join(timeout=5)
    server.server_close()
    assert not thread.is_alive()


def _app_post(
    origin: str,
    cookie: str,
    csrf: str,
    path: str,
    body: dict,
) -> dict:
    request = Request(
        f"{origin}{path}",
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Cookie": cookie,
            "Origin": origin,
            "X-StatePort-CSRF": csrf,
        },
        method="POST",
    )
    with urlopen(request) as response:
        assert response.status == 200
        return json.loads(response.read())["result"]


def _app_get(origin: str, cookie: str, path: str) -> dict:
    request = Request(
        f"{origin}{path}",
        headers={"Cookie": cookie},
        method="GET",
    )
    with urlopen(request) as response:
        assert response.status == 200
        return json.loads(response.read())["result"]


def test_sealed_workload_run_and_output_bound(tmp_path: Path) -> None:
    handle = DaemonHandle(tmp_path)
    handle.boot()
    try:
        workload_id = _workload_id("run")
        doc = _provision_grant(handle, _spec(workload_id, parameters={"workSeconds": 5, "emitBytes": 100000}))
        client = _client(handle, doc)
        capabilities = client.describe_capabilities()
        assert capabilities["result"]["formatVersion"] == "stateport.execution-host-contract/v1"
        assert capabilities["result"]["sealedWorkloadsOnly"] is True
        assert capabilities["observed"]["engineVersion"]

        created = client.create_workload(
            _spec(workload_id, parameters={"workSeconds": 5, "emitBytes": 100000})
        )
        assert created["result"]["state"] == "created"
        client.start(workload_id)
        final = _wait_state(client, workload_id, "exited", 60)
        assert final["exitStatus"] == 0
        logs = _client(handle, doc, output_byte_bound=1024).logs(workload_id)
        assert logs["result"]["truncated"] is True
        assert logs["result"]["byteCount"] == 1024
        full = _client(handle, doc, output_byte_bound=1048576).logs(workload_id)
        assert full["result"]["truncated"] is False
        assert "stateport-workload-start kind=terminal" in full["result"]["output"]
        assert "stateport-workload-complete" in full["result"]["output"]
        status = client.status(workload_id)
        assert status["observed"]["imageDigest"] and status["observed"]["imageDigest"].startswith(
            "sha256:"
        )
        client.remove_workload(workload_id)
        assert client.status(workload_id)["result"]["state"] == "removed"
    finally:
        handle.stop()


def test_timeout_supervision_and_cancel(tmp_path: Path) -> None:
    handle = DaemonHandle(tmp_path)
    handle.boot()
    try:
        slow = _workload_id("slow")
        slow_client = _client(handle, _provision_grant(handle, _spec(slow, timeoutSeconds=2, parameters={"workSeconds": 300})))
        slow_client.create_workload(_spec(slow, timeoutSeconds=2, parameters={"workSeconds": 300}))
        slow_client.start(slow)
        timed = _wait_state(slow_client, slow, "timed_out", 60)
        assert timed["engineStatus"] in {"exited", "absent"}
        ledger_entry = json.loads(
            (handle.state_dir / "workloads" / f"{slow}.json").read_text(encoding="utf-8")
        )
        assert ledger_entry["receipts"][-1]["kind"] == "supervision-timeout"
        assert ledger_entry["receipts"][-1]["cleanup"] == "performed"
        slow_client.remove_workload(slow)

        doomed = _workload_id("cancel")
        client = _client(handle, _provision_grant(handle, _spec(doomed, parameters={"workSeconds": 300})))
        client.create_workload(_spec(doomed, parameters={"workSeconds": 300}))
        client.start(doomed)
        cancelled = client.cancel(doomed)
        assert cancelled["result"]["state"] == "cancelled"
        assert cancelled["cleanup"]["outcome"] == "performed"
        assert _wait_state(client, doomed, "cancelled", 10)["state"] == "cancelled"
        assert _podman("container", "exists", f"stateport-exec-{doomed}").returncode != 0
        with pytest.raises(ExecutionHostRefusal, match="invalid-state"):
            client.cancel(doomed)
        client.remove_workload(doomed)
        garbage = client.collect_garbage()
        assert garbage["result"]["removedWorkloads"] == []
    finally:
        handle.stop()


def test_kill9_restart_reconciles_ledger_and_container(tmp_path: Path) -> None:
    handle = DaemonHandle(tmp_path)
    handle.boot()
    victim = _workload_id("victim")
    victim_doc = _provision_grant(handle, _spec(victim, parameters={"workSeconds": 300}))
    client = _client(handle, victim_doc)
    client.create_workload(_spec(victim, parameters={"workSeconds": 300}))
    client.start(victim)
    assert client.status(victim)["result"]["state"] == "running"
    assert handle.process is not None
    handle.process.send_signal(signal.SIGKILL)
    handle.process.wait(timeout=30)
    handle.process = None
    # The container survives the daemon; the restart must reconcile it.
    running = _podman("inspect", "--format", "{{.State.Running}}", f"stateport-exec-{victim}")
    assert running.stdout.strip() == "true"

    restarted = DaemonHandle(tmp_path)
    restarted.operator_remove_stale_socket()
    restarted.boot()
    try:
        entry = json.loads(
            (handle.state_dir / "workloads" / f"{victim}.json").read_text(encoding="utf-8")
        )
        assert entry["state"] == "interrupted"
        assert entry["receipts"][-1]["kind"] == "restart-recovery"
        assert entry["receipts"][-1]["cleanup"] == "performed"
        recovery = sorted((handle.state_dir / "recovery").glob("recovery-*.json"))
        assert recovery, "restart recovery journal is missing"
        assert victim in json.loads(recovery[-1].read_text(encoding="utf-8"))["report"]["interrupted"]
        gone = _podman("inspect", "--format", "{{.State.Running}}", f"stateport-exec-{victim}")
        assert gone.returncode != 0, "reconciled container must be removed"
        # The victim grant document persists in the state directory and is
        # re-read by the restarted daemon (digest binding still holds).
        client2 = _client(restarted, victim_doc)
        assert client2.status(victim)["result"]["state"] == "interrupted"
        # The restarted daemon accepts fresh work.
        fresh = _workload_id("fresh")
        fresh_client = _client(restarted, _provision_grant(restarted, _spec(fresh, parameters={"workSeconds": 1})))
        fresh_client.create_workload(_spec(fresh, parameters={"workSeconds": 1}))
        fresh_client.start(fresh)
        assert _wait_state(fresh_client, fresh, "exited", 60)["exitStatus"] == 0
        fresh_client.remove_workload(fresh)
        client2.remove_workload(victim)
    finally:
        restarted.stop()


def test_boot_and_client_refusals(tmp_path: Path) -> None:
    # Wrong group on the operator-provisioned directory: boot must refuse.
    wrong_group = DaemonHandle(tmp_path / "wrong-group")
    env = wrong_group.env()
    env["STATEPORT_EXECUTION_HOST_SOCKET_GROUP_GID"] = str(TEST_SOCKET_GROUP_GID + 1)
    refused = subprocess.run(
        [sys.executable, "-m", "stateport_execution_host"],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert refused.returncode == 2
    assert "group confinement failed" in refused.stderr

    # Control-plane engine socket: the daemon must refuse to touch it.
    control_plane = DaemonHandle(tmp_path / "control-plane")
    env = control_plane.env()
    env["STATEPORT_ENGINE_SOCKET"] = "/run/podman/podman.sock"
    refused = subprocess.run(
        [sys.executable, "-m", "stateport_execution_host"],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert refused.returncode == 2
    assert "control-plane" in refused.stderr

    # Client against an absent socket: typed transport error, never a guess.
    absent = ExecutionHostClient(
        tmp_path / "nowhere" / "control.sock",
        grant_id="grant-wt1",
        authority_grant_digest=GRANT_DIGEST,
    )
    with pytest.raises(ExecutionHostTransportError, match="socket-absent"):
        absent.describe_capabilities()


def test_no_control_plane_socket_in_workload_construction(tmp_path: Path) -> None:
    handle = DaemonHandle(tmp_path)
    handle.boot()
    try:
        workload_id = _workload_id("audit")
        client = _client(handle, _provision_grant(handle, _spec(workload_id, parameters={"workSeconds": 1})))
        client.create_workload(_spec(workload_id, parameters={"workSeconds": 1}))
        client.start(workload_id)
        _wait_state(client, workload_id, "exited", 60)
        inspect = _podman("inspect", f"stateport-exec-{workload_id}")
        assert inspect.returncode == 0
        import json as _json

        document = _json.loads(inspect.stdout)[0]
        mounts = _json.dumps(document.get("Mounts", [])) + _json.dumps(document.get("HostConfig", {}))
        assert "podman.sock" not in mounts
        assert "docker.sock" not in mounts
        assert document["HostConfig"]["NetworkMode"].startswith("none")
        assert document["HostConfig"]["ReadonlyRootfs"] is True
        assert document["HostConfig"]["Privileged"] is False
        labels = document["Config"]["Labels"]
        assert labels["io.stateport.execution.managed"] == "true"
        assert labels["io.stateport.execution.workload"] == workload_id
        client.remove_workload(workload_id)
        # The daemon's own process environment never points at a control-plane socket.
        assert handle.env().get("CONTAINER_HOST") is None
        assert handle.env().get("DOCKER_HOST") is None
    finally:
        handle.stop()


# ---------------------------------------------------------------------------
# alpha.4 persistent workspaces + human-operated terminals (real rootless Podman)
# ---------------------------------------------------------------------------

WORKSPACE_SPEC_DIGEST = "sha256:" + "e" * 64


def _workspace_spec(workload_id: str, **changes) -> dict:
    value = {
        "kind": "workspace",
        "workloadId": workload_id,
        "image": {"reference": WORKLOAD_IMAGE},
        "parameters": {
            "workspaceId": workload_id,
            "workspaceSpecDigest": WORKSPACE_SPEC_DIGEST,
            "volumeName": f"stateport-workspace-{workload_id}",
            "workSeconds": 0,
            "emitBytes": 0,
        },
        "timeoutSeconds": 600,
        "outputByteBound": 1048576,
        "resources": {"memoryMaxBytes": 268435456, "pidsMax": 128},
    }
    parameters = changes.pop("parameters", {})
    value.update(changes)
    value["parameters"].update(parameters)
    return value


def _remove_workspace_volume(workload_id: str) -> None:
    _podman("volume", "rm", "--force", f"stateport-workspace-{workload_id}")


def test_workspace_recovery_and_real_history_survive_restarts(tmp_path: Path) -> None:
    from stateport_persistent_app.execution_host_proxy import (  # noqa: PLC0415
        ExecutionHostProxy,
    )

    handle = DaemonHandle(tmp_path)
    handle.boot()
    workspace_id = _workload_id("ws")
    doc = _provision_grant(handle, _workspace_spec(workspace_id))
    client = _client(handle, doc)
    volume = f"stateport-workspace-{workspace_id}"
    try:
        created = client.create_workspace(_workspace_spec(workspace_id))
        assert created["result"]["state"] == "created"
        inventory = client.list_workloads()["result"]["workloads"]
        assert len(inventory) == 1
        assert inventory[0]["ownership"] == {
            "grantId": doc["grantId"],
            "applicationId": None,
            "runId": None,
        }
        assert inventory[0]["declaredLimits"] == {
            "memoryMaxBytes": 268435456,
            "pidsMax": 128,
            "timeoutSeconds": 600,
            "outputByteBound": 1048576,
            "cpuQuotaPercent": 100,
            "diskMaxBytes": 268435456,
        }
        disk_enforcement = inventory[0]["resourceEnforcement"][
            "persistentVolumeDiskMaxBytes"
        ]
        assert disk_enforcement["status"] == "unsupported"
        assert disk_enforcement["requestedBytes"] == 268435456
        assert "do not expose an enforceable per-volume byte quota" in disk_enforcement[
            "detail"
        ]
        client.start(workspace_id)
        # Typed exec writes through the daemon-owned named volume.
        written = client.exec_workload(
            workspace_id, ["sh", "-c", "echo stateport-marker > /workspace/marker.txt"]
        )
        assert written["result"]["exitStatus"] == 0
        assert client.stop(workspace_id)["result"]["state"] == "stopped"
        inspect = _podman("inspect", "--format", "{{.State.Running}}", f"stateport-exec-{workspace_id}")
        assert inspect.stdout.strip() == "false"

        # Daemon death + restart: the created-but-stopped workspace container
        # and its volume survive and are adopted, never terminated.
        assert handle.process is not None
        handle.process.send_signal(signal.SIGKILL)
        handle.process.wait(timeout=30)
        handle.process = None
        restarted = DaemonHandle(tmp_path)
        restarted.operator_remove_stale_socket()
        restarted.boot()
        try:
            client2 = _client(restarted, doc)
            status = client2.status(workspace_id)["result"]
            assert status["state"] == "stopped"
            entry = json.loads(
                (handle.state_dir / "workloads" / f"{workspace_id}.json").read_text(encoding="utf-8")
            )
            assert entry["receipts"][-1]["kind"] == "restart-adopt"
            recovery = sorted((handle.state_dir / "recovery").glob("recovery-*.json"))
            assert workspace_id in json.loads(recovery[-1].read_text(encoding="utf-8"))["report"]["adopted"]
            # Reattach and read the durable data back.
            client2.start(workspace_id)
            readback = client2.exec_workload(workspace_id, ["cat", "/workspace/marker.txt"])
            assert readback["result"]["exitStatus"] == 0
            assert readback["result"]["output"].strip() == "stateport-marker"

            # remove deletes only the container; the volume keeps the data.
            removed = client2.remove_workload(workspace_id)
            assert removed["result"]["state"] == "removed"
            assert "volume is preserved" in removed["cleanup"]["detail"]
            assert _podman("volume", "exists", volume).returncode == 0
            recovered = client2.create_workspace(_workspace_spec(workspace_id))
            assert recovered["result"]["state"] == "created"
            assert recovered["result"]["recovered"] is True
            assert recovered["result"]["recoveredFromState"] == "removed"
            # App state is isolated without changing either the daemon's or
            # this test process's rootless Podman storage environment.
            app_layout_root = tmp_path / "app-layout"
            app_server, app_thread, origin, cookie, csrf = _start_app_server(
                app_layout_root
            )
            try:
                app_server.execution_host = ExecutionHostProxy(
                    socket_path=restarted.socket_path,
                    grant_id=doc["grantId"],
                    authority_grant_digest=contract.canonical_digest(doc),
                )
                started = _app_post(
                    origin,
                    cookie,
                    csrf,
                    "/v1/execution-host/workloads/start",
                    {"workloadId": workspace_id},
                )
                assert started["result"]["state"] == "running"
                recovered_readback = _app_post(
                    origin,
                    cookie,
                    csrf,
                    "/v1/execution-host/workloads/exec",
                    {"workloadId": workspace_id, "argv": ["cat", "/workspace/marker.txt"]},
                )
                assert recovered_readback["result"]["exitStatus"] == 0
                assert recovered_readback["result"]["output"].strip() == "stateport-marker"
                stopped = _app_post(
                    origin,
                    cookie,
                    csrf,
                    "/v1/execution-host/workloads/stop",
                    {"workloadId": workspace_id},
                )
                assert stopped["result"]["state"] == "stopped"
                removed_through_app = _app_post(
                    origin,
                    cookie,
                    csrf,
                    "/v1/execution-host/workloads/remove",
                    {"workloadId": workspace_id},
                )
                assert removed_through_app["result"]["state"] == "removed"
                assert all(
                    result["receipt"]["actorId"] == "local-user"
                    for result in (
                        started,
                        recovered_readback,
                        stopped,
                        removed_through_app,
                    )
                )
                before_restart = _app_get(
                    origin, cookie, "/v1/execution-host/receipts"
                )["receipts"]
                assert [item["action"] for item in before_restart] == [
                    "execution_host.removeWorkload",
                    "execution_host.stop",
                    "execution_host.execWorkload",
                    "execution_host.start",
                ]
                assert [item["receiptId"] for item in before_restart] == [
                    result["receipt"]["receiptId"]
                    for result in (
                        removed_through_app,
                        stopped,
                        recovered_readback,
                        started,
                    )
                ]
            finally:
                _stop_app_server(app_server, app_thread)
            probe = _podman(
                "run", "--rm", "--network", "none", "-v", f"{volume}:/workspace:ro",
                WORKLOAD_IMAGE, "cat", "/workspace/marker.txt",
            )
            assert probe.returncode == 0
            assert probe.stdout.strip() == "stateport-marker"
            restarted.stop()
            offline_server, offline_thread, offline_origin, offline_cookie, _ = (
                _start_app_server(app_layout_root)
            )
            try:
                after_restart = _app_get(
                    offline_origin,
                    offline_cookie,
                    "/v1/execution-host/receipts",
                )["receipts"]
                assert after_restart == before_restart
            finally:
                _stop_app_server(offline_server, offline_thread)
        finally:
            restarted.stop()
    finally:
        handle.stop()
        _remove_workspace_volume(workspace_id)


def test_two_grant_owned_workspaces_remain_independent(tmp_path: Path) -> None:
    handle = DaemonHandle(tmp_path)
    handle.boot()
    workspace_a = _workload_id("owner-a")
    workspace_b = _workload_id("owner-b")
    spec_a = _workspace_spec(workspace_a, parameters={"ownership": {"applicationId": "application-a", "instanceId": "instance-a", "catalogIdentityDigest": "sha256:" + "a" * 64, "runId": "run-a"}})
    spec_b = _workspace_spec(workspace_b, parameters={"ownership": {"applicationId": "application-b", "instanceId": "instance-b", "catalogIdentityDigest": "sha256:" + "b" * 64, "runId": "run-b"}})
    doc_a = _provision_grant(handle, spec_a)
    doc_b = _provision_grant(handle, spec_b)
    client_a = _client(handle, doc_a)
    client_b = _client(handle, doc_b)
    try:
        client_a.create_workspace(spec_a)
        client_b.create_workspace(spec_b)
        client_a.start(workspace_a)
        client_b.start(workspace_b)
        assert client_a.exec_workload(
            workspace_a, ["sh", "-c", "echo owner-a > /workspace/owner.txt"]
        )["result"]["exitStatus"] == 0
        assert client_b.exec_workload(
            workspace_b, ["sh", "-c", "echo owner-b > /workspace/owner.txt"]
        )["result"]["exitStatus"] == 0

        # A separately provisioned grant may deliberately overlap the same
        # workload id, but durable grant ownership still hides and refuses it.
        intruder_doc = _grant_document(f"grant-intruder-{workspace_a}", spec_a)
        (handle.state_dir / "grants" / f"{intruder_doc['grantId']}.json").write_text(
            json.dumps(intruder_doc), encoding="utf-8"
        )
        intruder = _client(handle, intruder_doc)
        assert intruder.list_workloads()["result"]["workloads"] == []
        with pytest.raises(ExecutionHostRefusal, match="grant-identity-mismatch"):
            intruder.status(workspace_a)
        with pytest.raises(ExecutionHostRefusal, match="grant-identity-mismatch"):
            intruder.stop(workspace_a)

        assert client_a.stop(workspace_a)["result"]["state"] == "stopped"
        assert client_a.remove_workload(workspace_a)["result"]["state"] == "removed"
        assert client_b.status(workspace_b)["result"]["state"] == "running"
        read_b = client_b.exec_workload(workspace_b, ["cat", "/workspace/owner.txt"])
        assert read_b["result"]["output"].strip() == "owner-b"
        assert [
            item["workloadId"]
            for item in client_a.list_workloads()["result"]["workloads"]
        ] == [workspace_a]
        assert [
            item["workloadId"]
            for item in client_b.list_workloads()["result"]["workloads"]
        ] == [workspace_b]
        assert client_b.remove_workload(workspace_b)["result"]["state"] == "removed"

        probe_a = _podman(
            "run",
            "--rm",
            "--network",
            "none",
            "-v",
            f"stateport-workspace-{workspace_a}:/workspace:ro",
            WORKLOAD_IMAGE,
            "cat",
            "/workspace/owner.txt",
        )
        assert probe_a.returncode == 0
        assert probe_a.stdout.strip() == "owner-a"
    finally:
        handle.stop()
        _remove_workspace_volume(workspace_a)
        _remove_workspace_volume(workspace_b)


def test_workspace_idle_timeout_stops_container_and_preserves_volume(tmp_path: Path) -> None:
    handle = DaemonHandle(tmp_path)
    handle.boot()
    workspace_id = _workload_id("idle")
    client = _client(handle, _provision_grant(handle, _workspace_spec(workspace_id, timeoutSeconds=3)))
    try:
        client.create_workspace(_workspace_spec(workspace_id, timeoutSeconds=3))
        client.start(workspace_id)
        # Real inactivity (no terminal/exec/attach) triggers the idle stop;
        # this is not a lifetime cap: activity would restart the clock.
        final = _wait_state(client, workspace_id, "stopped", 30)
        assert final["engineStatus"] in {"exited", "stopped"}
        entry = json.loads(
            (handle.state_dir / "workloads" / f"{workspace_id}.json").read_text(encoding="utf-8")
        )
        assert entry["receipts"][-1]["kind"] == "idle-timeout"
        assert "volume preserved" in entry["receipts"][-1]["detail"]
        assert _podman("volume", "exists", f"stateport-workspace-{workspace_id}").returncode == 0
        # The stopped workspace reattaches and runs again.
        assert client.start(workspace_id)["result"]["state"] == "running"
        client.remove_workload(workspace_id)
    finally:
        handle.stop()
        _remove_workspace_volume(workspace_id)


def test_workspace_exec_exit_status_is_trustworthy_and_unbounded_output_honest(tmp_path: Path) -> None:
    handle = DaemonHandle(tmp_path)
    handle.boot()
    workspace_id = _workload_id("exec")
    client = _client(handle, _provision_grant(handle, _workspace_spec(workspace_id)))
    try:
        client.create_workspace(_workspace_spec(workspace_id))
        client.start(workspace_id)
        assert client.exec_workload(workspace_id, ["true"])["result"]["exitStatus"] == 0
        assert client.exec_workload(workspace_id, ["false"])["result"]["exitStatus"] == 1
        assert client.exec_workload(workspace_id, ["sh", "-c", "exit 3"])["result"]["exitStatus"] == 3
        # argv boundaries are preserved without shell joining: metacharacters
        # are literal tokens to the executed program.
        literal = client.exec_workload(workspace_id, ["echo", "a;b", "$(id -u)"])
        assert literal["result"]["exitStatus"] == 0
        assert literal["result"]["output"].strip() == "a;b $(id -u)"
        # No artificial post-command timeout: a 5s command completes whole.
        started = time.time()
        slow = client.exec_workload(workspace_id, ["sh", "-c", "sleep 5; echo done"], timeout_seconds=60)
        assert slow["result"]["exitStatus"] == 0
        assert slow["result"]["output"].strip() == "done"
        assert time.time() - started >= 5
        client.remove_workload(workspace_id)
    finally:
        handle.stop()
        _remove_workspace_volume(workspace_id)


def test_terminal_session_flows_through_the_broker_gateway(tmp_path: Path) -> None:
    import shutil
    import tempfile

    sys.path.insert(0, str(ROOT / "packages" / "terminal-broker" / "src"))
    from stateport_terminal_broker import (
        ExecutionHostTerminalGateway,
        GatewayActor,
        GatewayFrame,
        GatewayHandshake,
        TerminalCapabilities,
        TerminalTarget,
    )
    from stateport_terminal_broker.broker import TerminalAccessDenied, TerminalTokenError

    origin = "http://127.0.0.1:4100"
    # AF_UNIX paths are bounded to 107 bytes; pytest's tmp_path is too deep
    # for the confined per-session sockets. Keep only the socket tree on the
    # short tmpfs path; daemon state stays on pytest's durable /var/tmp root.
    short_socket_root = Path(tempfile.mkdtemp(prefix="s-", dir="/tmp"))
    handle = DaemonHandle(tmp_path, socket_root=short_socket_root)
    handle.boot()
    workspace_id = _workload_id("term")
    doc = _provision_grant(handle, _workspace_spec(workspace_id))
    client = _client(handle, doc)
    try:
        client.create_workspace(_workspace_spec(workspace_id))
        client.start(workspace_id)
        target = TerminalTarget(
            "terminal_target_" + "a" * 32,
            "capsule",
            "Workspace container",
            "available",
            TerminalCapabilities("capsule", True, True, True, False, False, True),
        )
        gateway = ExecutionHostTerminalGateway(
            client,
            workspace_id=workspace_id,
            instance_id="demo",
            profile_id="terminal.profile.demo",
            target=target,
            allowed_origins=(origin,),
        )
        actor = GatewayActor("operator.demo", frozenset({"demo"}), "operator_session")
        token = gateway.prepare(
            actor,
            profile_id="terminal.profile.demo",
            instance_id="demo",
            selected_root=Path("/workspace"),
            origin=origin,
        )
        handshake = GatewayHandshake(actor, "demo", origin, token_transport="first_frame")
        # Origin binding: a ticket minted for one origin cannot be spent by another.
        with pytest.raises(TerminalAccessDenied):
            gateway.accept_handshake(
                GatewayHandshake(actor, "demo", "http://evil.example", token_transport="first_frame"),
                one_use_value=token.value,
                selected_root=Path("/workspace"),
            )
        token = gateway.prepare(
            actor,
            profile_id="terminal.profile.demo",
            instance_id="demo",
            selected_root=Path("/workspace"),
            origin=origin,
        )
        session, created_receipt = gateway.accept_handshake(
            handshake, one_use_value=token.value, selected_root=Path("/workspace")
        )
        # Ticket single-use on the real path.
        with pytest.raises(TerminalTokenError):
            gateway.accept_handshake(
                handshake, one_use_value=token.value, selected_root=Path("/workspace")
            )
        # The browser-visible contract never carries a socket or engine path.
        assert "socket" not in json.dumps(session.to_dict()).lower()
        assert "socket" not in json.dumps(created_receipt.to_dict()).lower()
        # Real bytes round-trip into the workspace shell.
        gateway.handle_frame(handshake, session_id=session.session_id, frame=GatewayFrame("input", b"echo gateway-$((40+2))\n"))
        deadline = time.time() + 20
        output = b""
        while time.time() < deadline and b"gateway-42" not in output:
            frame = gateway.read_frame(handshake, session_id=session.session_id, timeout_seconds=0.5)
            output += frame.data
        assert b"gateway-42" in output
        # Typed signal support: interrupt a blocking read in the shell.
        gateway.handle_frame(handshake, session_id=session.session_id, frame=GatewayFrame("input", b"sleep 60\n"))
        time.sleep(1.0)
        gateway.handle_signal(handshake, session_id=session.session_id, signal="SIGINT")
        gateway.handle_frame(handshake, session_id=session.session_id, frame=GatewayFrame("input", b"echo after-signal\n"))
        deadline = time.time() + 20
        output = b""
        while time.time() < deadline and b"after-signal" not in output:
            frame = gateway.read_frame(handshake, session_id=session.session_id, timeout_seconds=0.5)
            output += frame.data
        assert b"after-signal" in output
        # Resize is accepted through the real daemon path.
        gateway.handle_frame(
            handshake, session_id=session.session_id, frame=GatewayFrame("resize", columns=132, rows=43)
        )
        # Disconnect cleanup: the daemon session is verifiably gone.
        exit_value, closed_receipt = gateway.handle_frame(
            handshake, session_id=session.session_id, frame=GatewayFrame("close")
        )
        assert exit_value.reason == "operator_closed"
        assert closed_receipt.cleanup == "terminated"
        time.sleep(0.5)
        session_socket = handle.socket_dir / "sessions" / f"{session.session_id}.sock"
        assert not session_socket.exists()
        with pytest.raises(ExecutionHostRefusal, match="unknown-terminal"):
            client.close_terminal(session.session_id)
        audits = gateway.audit_receipts(actor, instance_id="demo", origin=origin)
        assert [item.action for item in audits] == ["created", "closed"]
        gateway.close()
        client.remove_workload(workspace_id)
    finally:
        handle.stop()
        _remove_workspace_volume(workspace_id)
        shutil.rmtree(short_socket_root, ignore_errors=True)


def _validator_workload(workload_id: str, staging: Path, command: list[str]) -> dict:
    from execution_host.staging_identity import staging_manifest_digest  # noqa: PLC0415

    return {
        "kind": "validator-run",
        "workloadId": workload_id,
        "image": {"reference": WORKLOAD_IMAGE},
        "parameters": {
            "validatorId": f"validator.{workload_id}",
            "validatorSpecDigest": GRANT_DIGEST,
            "stagingIdentityDigest": staging_manifest_digest(staging),
            "stagingPath": str(staging),
            "commandDigest": contract.canonical_digest(command),
            "command": command,
            "network": "disabled",
            "stagingReadOnly": True,
            "providerAccess": False,
            "runtimeSocketAccess": False,
            "hostMounts": [],
        },
        "timeoutSeconds": 60,
        "outputByteBound": 4096,
        "resources": {
            "memoryMaxBytes": 268435456,
            "cpuQuotaPercent": 100,
            "pidsMax": 128,
            "diskMaxBytes": 67108864,
        },
    }


def test_validator_run_executes_sealed_staging_and_records_digest_evidence(tmp_path: Path) -> None:
    handle = DaemonHandle(tmp_path, validator_staging_root=tmp_path / "validator-staging")
    handle.boot()
    staging = tmp_path / "validator-staging" / "candidate"
    staging.mkdir(parents=True)
    (staging / "marker.txt").write_text("candidate-bytes\n", encoding="utf-8")
    workload_id = _workload_id("validator")
    command = ["sh", "-c", "grep -q candidate-bytes /validator/marker.txt"]
    workload = _validator_workload(workload_id, staging, command)
    client = _client(handle, _provision_grant(handle, workload))
    try:
        receipt = client.run_validator(workload)
        result = receipt["result"]
        assert result["classification"] == "passed"
        assert result["observedExitStatus"] == 0
        evidence_path = handle.state_dir / result["evidenceLocation"]
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        assert evidence["classification"] == "passed"
        assert evidence["rawOutputRecorded"] is False
        assert result["evidenceDigest"] == (
            "sha256:" + hashlib.sha256(evidence_path.read_bytes()).hexdigest()
        )
        assert receipt["cleanup"]["outcome"] == "performed"
        # The validator container is removed after the run.
        assert _podman("container", "exists", f"stateport-exec-{workload_id}").returncode != 0
        # A failing validator command classifies failed, never passed.
        failing = _validator_workload(_workload_id("validator-fail"), staging, ["sh", "-c", "exit 3"])
        failed = _client(handle, _provision_grant(handle, failing)).run_validator(failing)["result"]
        assert failed["classification"] == "failed"
        assert failed["observedExitStatus"] == 3
        # Staging outside the daemon staging root is refused before engine access.
        escape_staging = tmp_path / "outside-validator-staging"
        escape_staging.mkdir()
        (escape_staging / "marker.txt").write_text("outside\n", encoding="utf-8")
        escape = _validator_workload(
            _workload_id("validator-escape"), escape_staging, command
        )
        escape_client = _client(handle, _provision_grant(handle, escape))
        with pytest.raises(ExecutionHostRefusal, match="staging"):
            escape_client.run_validator(escape)
    finally:
        handle.stop()


def test_managed_run_engine_executes_a_real_container_through_the_daemon(tmp_path: Path) -> None:
    """One validated AgentRunSpecification lowered through the real client
    into a real digest-pinned container; everything observed at the daemon
    boundary (steer: no caller-supplied adapter, no self-attestation)."""
    from execution_host.provider_bindings import ProviderBindingManager, RunEvidenceService  # noqa: PLC0415
    from execution_host.run_authority import RunAuthority, RunGrant  # noqa: PLC0415
    from execution_host.run_engine import RunEngine  # noqa: PLC0415
    from execution_host.run_lease import RunCompletionGate  # noqa: PLC0415
    from runtime_contracts import canonical_digest  # noqa: PLC0415
    from runtime_contracts.alpha4 import AgentRunSpecification  # noqa: PLC0415

    image_digest = "sha256:" + WORKLOAD_IMAGE.rsplit("@sha256:", 1)[1]
    run_id = _workload_id("managed")
    authority = RunAuthority(host="exec-1")
    owner_grant = RunGrant(
        grant_id="grant.managed",
        executor_kind="execution-host-agent-container",
        claimed_image=WORKLOAD_IMAGE,
        host="exec-1",
        scope="managed run integration",
        issued_at="2026-08-08T00:00:00Z",
        digest_pin=image_digest,
    )
    authority.register(owner_grant)
    raw_spec = {
        "formatVersion": "stateport.managed-agent-run/v1",
        "runId": run_id,
        "workspaceId": "ws-managed",
        "baseRevision": "d" * 40,
        "stagingPath": "/staging/candidate",
        "imageDigest": image_digest,
        "provider": "synthetic",
        "model": "synthetic-model",
        "networkProfile": {"mode": "disabled", "allowlist": []},
        "authorityGrantDigest": owner_grant.authority_digest,
        "budgets": {"timeSeconds": 120, "token": 100, "costMinor": 0, "steps": 10},
        "resources": {
            "memoryMaxBytes": 268435456,
            "cpuQuotaPercent": 100,
            "pidsMax": 128,
            "diskMaxBytes": 67108864,
        },
        "validationCommands": [],
    }
    spec_data = AgentRunSpecification.from_dict(raw_spec).to_dict()
    lowered = {
        "kind": "agent-run",
        "workloadId": f"run-{run_id}",
        "image": {"reference": WORKLOAD_IMAGE},
        "parameters": {
            "runSpecDigest": canonical_digest(spec_data),
            "statePackReference": spec_data["stagingPath"],
            "baseRevision": spec_data["baseRevision"],
        },
        "timeoutSeconds": 120,
        "outputByteBound": 4 * 1024 * 1024,
        "resources": dict(spec_data["resources"]),
    }
    assert lowered["parameters"]["runSpecDigest"] == canonical_digest(spec_data)
    handle = DaemonHandle(tmp_path)
    handle.boot()
    daemon_grant = _provision_grant(handle, lowered)
    client = _client(handle, daemon_grant)
    assert client.authority_grant_digest == contract.canonical_digest(daemon_grant)
    assert client.authority_grant_digest != owner_grant.authority_digest
    manager = ProviderBindingManager(env={"SP_TEST_TOKEN": "synthetic-token"})
    manager.define_config(
        "cfg.managed", provider="synthetic", model="synthetic-model", token_env="SP_TEST_TOKEN"
    )
    engine = RunEngine(
        authority=authority,
        evidence_service=RunEvidenceService(),
        completion_gate=RunCompletionGate(),
        provider_manager=manager,
        state_dir=str(tmp_path / "runs"),
    )
    try:
        outcome = engine.run(
            specification=raw_spec,
            client=client,
            claimed_image=WORKLOAD_IMAGE,
            host="exec-1",
            config_id="cfg.managed",
        )
        assert outcome.outcome == "refused"
        assert outcome.evidence.to_dict()["exitReason"] == "provider-effect-unobserved"
        process = outcome.evidence.to_dict()["executedProcess"]
        assert process["containerWorkloadId"] == f"run-{run_id}"
        assert process["exitCode"] == 0
        expected_output = (
            f"stateport-workload-start kind=agent-run id=run-{run_id}\n"
            f"stateport-workload-complete id=run-{run_id}\n"
        )
        assert process["digestOfOutput"] == (
            "sha256:" + hashlib.sha256(expected_output.encode()).hexdigest()
        )
        # The daemon removed the ephemeral container after the run.
        assert _podman("container", "exists", f"stateport-exec-run-{run_id}").returncode != 0
        # The reusable owner configuration is not a run-bound handle.
        assert manager.configured("cfg.managed")
    finally:
        handle.stop()


def test_agent_source_command_isolated_candidate_and_durable_exit(tmp_path: Path) -> None:
    """Real daemon+SCM_RIGHTS+Podman proof; only run in booked heavy slot."""
    from execution_host.deployment_staging import build_deployment_archive
    from execution_host.ledger import OperationLedger

    source = tmp_path / 'source'
    source.mkdir()
    script = b'''import pathlib, socket, subprocess, sys
assert {name for _, name in socket.if_nameindex()} == {'lo'}
print('source-command-stderr-canary', file=sys.stderr, flush=True)
probe = pathlib.Path('noexec-probe')
probe.write_text('#!/bin/sh\\nexit 0\\n')
probe.chmod(0o755)
try:
 subprocess.run([str(probe.resolve())], check=True)
except PermissionError:
 pass
else:
 raise AssertionError('candidate permits direct executable launch')
p = pathlib.Path('marker.txt')
assert p.read_text() == 'original'
p.write_text('candidate changed')
assert pathlib.Path('/agent-input/marker.txt').read_text() == 'original'
try:
 pathlib.Path('/agent-input/marker.txt').write_text('escape')
except OSError:
 pass
else:
 raise AssertionError('source writable')
try:
 pathlib.Path('/outside-candidate').write_text('escape')
except OSError:
 pass
else:
 raise AssertionError('root writable')
pathlib.Path('escape-link').symlink_to('/agent-input/marker.txt')
try:
 pathlib.Path('escape-link').write_text('escape')
except OSError:
 pass
else:
 raise AssertionError('symlink escape')
s = socket.socket()
s.settimeout(1)
try:
 s.connect(('192.0.2.1', 443))
except OSError:
 pass
else:
 raise AssertionError('network reachable')
finally:
 s.close()
print('candidate-isolated-original-preserved', flush=True)
raise SystemExit(7)
'''
    files = {'main.py': script, 'marker.txt': b'original'}
    inventory, context = [], []
    for name, content in sorted(files.items()):
        path = source / name
        path.write_bytes(content)
        path.chmod(0o644)
        digest = 'sha256:' + hashlib.sha256(content).hexdigest()
        inventory.append({'path': name, 'mode': '100644', 'contentDigest': digest})
        context.append({'path': name, 'mode': '100644', 'size': len(content), 'sha256': digest})
    archive_path = tmp_path / 'source.tar'
    with archive_path.open('w+b') as archive:
        metadata = build_deployment_archive(archive, plan={'sourceInventory': inventory, 'overlay': {}}, context_root=source, overlay_root=source, context_digest=contract.canonical_digest(context))
    workload_id = _workload_id('source-command')
    command = ['/usr/local/bin/python3', 'main.py']
    workload = contract.validate_workload_spec({
        'kind': 'agent-run', 'workloadId': workload_id,
        'image': {'reference': WORKLOAD_IMAGE},
        'parameters': {'runSpecDigest': GRANT_DIGEST, 'statePackReference': 'statepack:real-source-proof', 'command': command, 'commandDigest': contract.canonical_digest(command), 'sourceInventory': inventory, 'sourceArchive': metadata},
        'timeoutSeconds': 60, 'outputByteBound': 4096,
        'resources': {'memoryMaxBytes': 268435456, 'cpuQuotaPercent': 100, 'pidsMax': 128, 'diskMaxBytes': 67108864},
    })
    handle = DaemonHandle(tmp_path)
    handle.boot()
    client = _client(handle, _provision_grant(handle, workload))
    try:
        with archive_path.open('rb') as archive:
            client.create_workload(workload, source_fd=archive.fileno())
        client.start(workload_id)
        ledger = OperationLedger(handle.state_dir)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            entry = ledger.get(workload_id)
            if entry.get('sourceCommandOutput'):
                break
            time.sleep(.1)
        evidence = entry['sourceCommandOutput']
        assert evidence['exitStatus'] == 7
        assert evidence['terminationReason'] == 'exited'
        assert 'candidate-isolated-original-preserved' in evidence['output']
        assert 'source-command-stderr-canary' in evidence['output']
        assert evidence['durableChangedFiles'] is False
        assert evidence['commandDigest'] == contract.canonical_digest(command)
        assert evidence['sourceArchiveDigest'] == metadata['archiveDigest']
        for name, content in files.items():
            assert (source / name).read_bytes() == content
        client.remove_workload(workload_id)
        assert _podman('container', 'exists', f'stateport-exec-{workload_id}').returncode != 0
        assert not list((handle.state_dir / 'validator-snapshots').glob('*'))
        handle.stop()
        handle.boot()
        observed = client.logs(workload_id)['result']
        assert observed['sourceCommand']['evidenceDigest'] == evidence['evidenceDigest']
        assert observed['output'] == evidence['output']
    finally:
        handle.stop()


def test_governed_container_cgroup_containment(tmp_path: Path) -> None:
    """Book this single sleeping-container premise before the browser journey."""
    from execution_host.engine import PodmanCliEngine
    handle = DaemonHandle(tmp_path)
    environment, scope = _governed_engine_environment(tmp_path, handle.env())
    handle.env = lambda: environment
    workload = contract.validate_workload_spec(_workspace_spec(_workload_id("governed")))
    handle.boot()
    client = _client(handle, _provision_grant(handle, workload))
    created = False
    try:
        client.create_workspace(workload)
        created = True
        client.start(workload["workloadId"])
        entry = json.loads((handle.state_dir / "workloads" / (workload["workloadId"] + ".json")).read_text())
        proof = _governed_container_membership(entry["containerId"], scope, environment=environment)
        (tmp_path / "cgroup-proof.json").write_text(json.dumps(proof, indent=2), encoding="utf-8")
    finally:
        try:
            if created:
                # Existing daemon removal validates the exact durable grant/container identity.
                client.remove_workload(workload["workloadId"])
                engine = PodmanCliEngine(runner=lambda args, **kwargs: subprocess.run(args, **{**kwargs, "env": environment}))
                engine.verify_workspace_volumes(workload)
                removed = subprocess.run(["podman", "volume", "rm", workload["parameters"]["volumeName"]], env=environment, capture_output=True, text=True, timeout=30)
                if removed.returncode != 0:
                    raise RuntimeError("governed premise volume cleanup failed; retained")
        finally:
            handle.stop()


def _materialize_seeded_workspace_source(layout_root: Path) -> Path:
    """Materialize the generic source fixture inside the actual managed root."""
    import shutil
    from stateport_persistent_app import LocalLayout
    layout = LocalLayout(layout_root / 'config', layout_root / 'data', layout_root / 'state')
    layout.initialize()
    source = layout.instances_root / 'seeded-template'
    shutil.copytree(ROOT / 'fixtures' / 'apps' / 'development-reference', source)
    executable = source / 'workspace-proof.sh'
    executable.write_text("#!/bin/sh\nprintf 'SEEDED_SOURCE_%s\\n' VERIFIED\n", encoding='utf-8')
    executable.chmod(0o755)
    for args in [('init',), ('add', '--all'), ('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgSign=false', 'commit', '-m', 'reviewed fixture source')]:
        subprocess.run(['git', '-C', str(source), *args], check=True, capture_output=True)
    return source


def test_seeded_application_workspace_source_modes_and_restart(tmp_path: Path) -> None:
    """Real source AppServer+daemon+Podman; requires booked measured split mode."""
    from urllib.error import HTTPError
    from execution_host.application_workspaces import FORMAT, catalog_identity
    from execution_host.engine import PodmanCliEngine
    from stateport_persistent_app.execution_host_proxy import ExecutionHostProxy, prepare_workspace_source_seed

    source = _materialize_seeded_workspace_source(tmp_path / 'app-layout')
    handle = DaemonHandle(tmp_path)
    environment, scope = _governed_engine_environment(tmp_path, handle.env())
    handle.env = lambda: environment
    server = None
    thread = None
    created = False
    workload = None
    client = None
    try:
        handle.boot()
        server, thread, origin, cookie, csrf = _start_app_server(tmp_path / 'app-layout')
        entry = server.source_app().catalog.register(source, instance_id='seeded-template', name='Seeded generic template', application_id='stateport.development-reference', source={'templateId': 'stateport.development-reference'})
        workload = _workspace_spec(_workload_id('seeded-template'), parameters={'ownership': {'applicationId': entry['applicationId'], 'instanceId': entry['instanceId'], 'catalogIdentityDigest': catalog_identity(entry), 'runId': None}})
        workload = prepare_workspace_source_seed(entry, workload)
        seed = workload['parameters']['sourceSeed']
        originals = {row['path']: ((source / row['path']).read_bytes(), (source / row['path']).stat().st_mode & 0o777) for row in seed['sourceInventory']}
        grant = _provision_grant(handle, workload)
        client = _client(handle, grant)
        manifest = tmp_path / 'reviewed-bindings.json'
        manifest.write_text(json.dumps({'formatVersion': FORMAT, 'bindings': [{'grantId': grant['grantId'], 'authorityGrantDigest': contract.canonical_digest(grant), 'workload': workload}]}), encoding='utf-8')
        manifest.chmod(0o600)
        server.execution_host = ExecutionHostProxy(socket_path=handle.socket_path, grant_id=grant['grantId'], authority_grant_digest=contract.canonical_digest(grant), catalog_entry=server.workspace_catalog_entry, bindings_path=manifest, bindings_owner_uid=os.getuid())
        reviewed_body = {'instanceId': entry['instanceId'], 'sourceReviewDigest': seed['reviewDigest']}
        original_descriptor = (source / 'application.yaml').read_bytes()
        (source / 'application.yaml').write_bytes(original_descriptor + b'\n# operator changed after review\n')
        with pytest.raises(HTTPError) as refused:
            _app_post(origin, cookie, csrf, '/v1/execution-host/workloads', reviewed_body)
        assert json.loads(refused.value.read())['error']['code'] == 'workspace_source_stale'
        assert not (handle.state_dir / 'workloads' / (workload['workloadId'] + '.json')).exists()
        assert _podman('volume', 'exists', workload['parameters']['volumeName']).returncode == 1
        (source / 'application.yaml').write_bytes(original_descriptor)
        result = _app_post(origin, cookie, csrf, '/v1/execution-host/workloads', reviewed_body)
        assert result['accepted'] is True
        assert result['result']['sourceSeed']['status'] == 'complete'
        created = True
        _app_post(origin, cookie, csrf, '/v1/execution-host/workloads/start', {'workloadId': workload['workloadId']})
        durable = json.loads((handle.state_dir / 'workloads' / (workload['workloadId'] + '.json')).read_text())
        proof = _governed_container_membership(durable['containerId'], scope, environment=environment)
        (tmp_path / 'seeded-cgroup-proof.json').write_text(json.dumps(proof, indent=2), encoding='utf-8')
        observed = client.exec_workload(workload['workloadId'], ['/bin/sh', '-c', './workspace-proof.sh && stat -c %a workspace-proof.sh && printf retained-workspace-edit > /workspace/retained-marker'])['result']
        assert observed['exitStatus'] == 0
        assert 'SEEDED_SOURCE_VERIFIED' in observed['output']
        assert '755' in observed['output']
        for relative, (content, mode) in originals.items():
            assert (source / relative).read_bytes() == content
            assert (source / relative).stat().st_mode & 0o777 == mode
        client.remove_workload(workload['workloadId'])
        handle.stop()
        handle.boot()
        recovered = _app_post(origin, cookie, csrf, '/v1/execution-host/workloads', reviewed_body)
        assert recovered['result']['sourceSeed']['reused'] is True
        client.start(workload['workloadId'])
        preserved = client.exec_workload(workload['workloadId'], ['/bin/sh', '-c', 'cat /workspace/retained-marker; ./workspace-proof.sh'])['result']
        assert preserved['exitStatus'] == 0
        assert 'retained-workspace-edit' in preserved['output']
        assert 'SEEDED_SOURCE_VERIFIED' in preserved['output']
        assert not (source / 'retained-marker').exists()
        durable = json.loads((handle.state_dir / 'workloads' / (workload['workloadId'] + '.json')).read_text())
        assert len([row for row in durable['receipts'] if row['kind'] == 'workspace-source-seeded']) == 1
    finally:
        try:
            if server is not None:
                _stop_app_server(server, thread)
        finally:
            try:
                if created and client is not None:
                    client.remove_workload(workload['workloadId'])
            finally:
                handle.stop()
        if created:
            engine = PodmanCliEngine(runner=lambda args, **kwargs: subprocess.run(args, **{**kwargs, 'env': environment}))
            engine.verify_workspace_volumes(workload)
            removed = subprocess.run(['podman', 'volume', 'rm', workload['parameters']['volumeName']], env=environment, capture_output=True, text=True, timeout=30)
            if removed.returncode != 0:
                raise RuntimeError('seeded test volume cleanup failed; retained')


def test_governed_daemon_foreign_ledger_and_replaced_name_retained(tmp_path: Path) -> None:
    """Real Podman identity race; only the coordinator launches under a governor."""
    import tempfile
    from execution_host.engine import KIND_LABEL, MANAGED_LABEL_KEY, WORKLOAD_LABEL, PodmanCliEngine, container_name
    from execution_host.ledger import OperationLedger

    socket_root = Path(tempfile.mkdtemp(prefix='sp-id-'))
    owner = DaemonHandle(tmp_path / 'owner', socket_root=socket_root / 'owner')
    stranger = DaemonHandle(tmp_path / 'stranger', socket_root=socket_root / 'stranger')
    owner_env, scope = _governed_engine_environment(tmp_path, owner.env())
    owner.env = lambda: owner_env
    stranger_env = {**stranger.env(), 'CONTAINERS_CONF_OVERRIDE': owner_env['CONTAINERS_CONF_OVERRIDE']}
    stranger.env = lambda: stranger_env
    engine = PodmanCliEngine(runner=lambda args, **kwargs: subprocess.run(args, **{**kwargs, 'env': owner_env}))
    workload = contract.validate_workload_spec(_workspace_spec(_workload_id('identity-retention')))
    wid = workload['workloadId']
    tracked: list[str] = []
    proof: dict = {'workloadId': wid, 'containers': [], 'socketRoot': str(socket_root)}
    complete = False

    def podman(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(['podman', *args], env=owner_env, capture_output=True, text=True, timeout=30)

    def exact_info(cid: str) -> dict:
        result = podman('inspect', '--format', '{{json .}}', cid)
        assert result.returncode == 0, 'tracked container inspection unavailable; retain evidence'
        info = json.loads(result.stdout)
        labels = info.get('Config', {}).get('Labels') or {}
        assert info.get('Id') == cid
        assert info.get('ImageDigest') == WORKLOAD_IMAGE.rsplit('@', 1)[1]
        assert all(labels.get(key) == value for key, value in {MANAGED_LABEL_KEY: 'true', WORKLOAD_LABEL: wid, KIND_LABEL: 'workspace'}.items())
        return info

    try:
        owner.boot()
        grant = _provision_grant(owner, workload)
        client = _client(owner, grant)
        client.create_workspace(workload)
        original = OperationLedger(owner.state_dir).get(wid)['containerId']
        tracked.append(original)
        client.start(wid)
        marker = client.exec_workload(wid, ['/bin/sh', '-c', 'printf identity-volume-preserved > /workspace/identity-marker'])['result']
        assert marker['exitStatus'] == 0
        proof['containers'].append(_governed_container_membership(original, scope, environment=owner_env))
        owner.stop()
        original_ledger = (owner.state_dir / 'workloads' / (wid + '.json')).read_bytes()
        with pytest.raises(AssertionError, match='no reservation in this ledger'):
            stranger.boot()
        stranger.stop()
        assert exact_info(original)['State']['Running'] is True
        assert (owner.state_dir / 'workloads' / (wid + '.json')).read_bytes() == original_ledger
        proof['foreignLedgerRetainedOriginal'] = True
        owner.boot()
        assert OperationLedger(owner.state_dir).get(wid)['state'] == 'running'
        owner.stop()

        # Test-owned adversarial mutation after checking the original exact ID.
        assert exact_info(original)['State']['Running'] is True
        assert podman('rename', original, container_name(wid) + '-retained').returncode == 0
        replacement = engine.create(workload).strip()
        assert len(replacement) == 64 and set(replacement) <= set('0123456789abcdef')
        tracked.append(replacement)
        exact_info(replacement)
        engine.start(wid, expected_container_id=replacement)
        proof['containers'].append(_governed_container_membership(replacement, scope, environment=owner_env))
        # The earlier checked identity remains the target despite name replacement.
        engine.stop(wid, expected_container_id=original)
        assert exact_info(original)['State']['Running'] is False
        assert exact_info(replacement)['State']['Running'] is True
        engine.remove(wid, expected_container_id=original)
        assert podman('container', 'exists', original).returncode == 1
        assert exact_info(replacement)['State']['Running'] is True
        proof['replacementSurvivedOriginalIdControls'] = True
        with pytest.raises(AssertionError, match='container ID does not match'):
            owner.boot()
        owner.stop()
        assert exact_info(replacement)['State']['Running'] is True
        observed = engine.exec_workload(wid, ['cat', '/workspace/identity-marker'], timeout=10, max_bytes=1024, expected_container_id=replacement)
        assert observed['exitStatus'] == 0
        assert observed['output'] == 'identity-volume-preserved'
        proof['ownerLedgerRefusedReplacement'] = True
        proof['volumeMarkerPreserved'] = True
        complete = True
    finally:
        owner.stop()
        stranger.stop()
        failures = []
        for cid in tracked:
            try:
                exists = podman('container', 'exists', cid)
                if exists.returncode == 1:
                    continue
                assert exists.returncode == 0
                exact_info(cid)
                engine.stop(wid, expected_container_id=cid)
                engine.remove(wid, expected_container_id=cid)
                assert podman('container', 'exists', cid).returncode == 1
            except Exception as exc:
                failures.append(f'{cid}: {type(exc).__name__}')
        if complete and not failures:
            engine.verify_workspace_volumes(workload)
            removed = podman('volume', 'rm', workload['parameters']['volumeName'])
            if removed.returncode != 0:
                failures.append('verified test volume cleanup failed')
        proof['cleanupFailures'] = failures
        proof['volumeRetained'] = not complete or bool(failures)
        (tmp_path / 'identity-retention-proof.json').write_text(json.dumps(proof, indent=2), encoding='utf-8')
        if failures:
            raise AssertionError('tracked identity cleanup failed; retained evidence: ' + ', '.join(failures))
