#!/usr/bin/env python3
"""Focused proof for the alpha.4 execution-host terminal boundary.

The gateway is exercised against a fake execution-host client that honours
the confined-session-socket contract; no container runtime is involved.
Covers ticket single-use and TTL, actor/instance/origin binding, byte round
trips, typed signals, resize, socket-path confinement, and disconnect
cleanup — the browser never sees a socket path or Podman endpoint.
"""
from __future__ import annotations

import fcntl
import os
from pathlib import Path
import pty
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import termios
import threading
import time
from types import SimpleNamespace
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
for source in (
    ROOT / "packages" / "terminal-broker" / "src",
    ROOT / "packages" / "execution-host" / "src",
    ROOT / "packages" / "runtime-contracts" / "src",
    ROOT / "apps" / "admin-cli" / "src",
):
    sys.path.insert(0, str(source))

from admin_cli import alpha4_runtime  # noqa: E402
from execution_host.client import ExecutionHostTransportError  # noqa: E402

from stateport_terminal_broker import (  # noqa: E402
    ExecutionHostTerminalGateway,
    GatewayActor,
    GatewayFrame,
    GatewayHandshake,
    TerminalCapabilities,
    TerminalTarget,
)
from stateport_terminal_broker.broker import (  # noqa: E402
    TerminalAccessDenied,
    TerminalBrokerError,
    TerminalTokenError,
)

ORIGIN = "http://127.0.0.1:4100"
OTHER_ORIGIN = "http://localhost:4100"


@pytest.fixture()
def short_root():
    # AF_UNIX paths are bounded to 107 bytes; pytest's tmp_path is too deep
    # for the confined session socket, so use a short scratch directory.
    root = Path(tempfile.mkdtemp(prefix="spt-", dir="/var/tmp"))
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


class FakeExecutionHost:
    """Honours the daemon's confined per-session socket contract."""

    def __init__(self, root: Path):
        self.__socket_path = root / "c" / "control.sock"
        self._sessions_dir = root / "c" / "sessions"
        self._sessions_dir.mkdir(parents=True, exist_ok=True)
        self._sessions_dir.parent.chmod(0o750)
        self._sessions_dir.chmod(0o750)
        self._control_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._control_listener.bind(str(self.__socket_path))
        self.__socket_path.chmod(0o660)
        self._control_listener.listen(1)
        self._control_stop = threading.Event()
        self._control_started = False
        self._listeners: dict[str, socket.socket] = {}
        self._peer_processes: dict[str, subprocess.Popen[str]] = {}
        self._executor_processes: dict[str, subprocess.Popen[str]] = {}
        self.received: dict[str, bytes] = {}
        self.received_event = threading.Event()
        self.resized: list[tuple[str, int, int]] = []
        self.signaled: list[tuple[str, str]] = []
        self.signal_started = threading.Event()
        self.signal_release: threading.Event | None = None
        self.closed: list[str] = []
        self.open_calls = 0
        self.bad_socket_path: str | None = None
        self.executor_pid: Any = "auto"
        self.connect_failure = False
        self.regular_socket_path = False
        self.foreign_peer = False
        self.close_after_echo = False

    @property
    def socket_path(self) -> Path:
        return self.__socket_path

    def _start_control_server(self) -> None:
        if self._control_started:
            return
        self._control_started = True

        def serve() -> None:
            self._control_listener.settimeout(0.1)
            while not self._control_stop.is_set():
                try:
                    connection, _ = self._control_listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                with connection:
                    try:
                        connection.recv(1)
                    except OSError:
                        pass
                return

        threading.Thread(target=serve, daemon=True).start()

    def _open_foreign_peer(self, path: Path, session_id: str) -> None:
        script = (
            "import os,socket,sys; "
            "p=sys.argv[1]; s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); "
            "s.bind(p); os.chmod(p,0o660); s.listen(1); print('ready',flush=True); "
            "c,_=s.accept(); c.recv(1); c.close(); s.close()"
        )
        process = subprocess.Popen(
            [sys.executable, "-c", script, str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert process.stdout is not None
        assert process.stdout.readline().strip() == "ready"
        self._peer_processes[session_id] = process

    def open_terminal(self, workload_id: str, session_id: str, *, columns: int, rows: int):
        self.open_calls += 1
        self._start_control_server()
        if self.bad_socket_path is not None:
            return self._result(workload_id, session_id, self.bad_socket_path)
        path = self._sessions_dir / f"{session_id}.sock"
        if self.regular_socket_path:
            path.write_text("not a socket", encoding="utf-8")
            path.chmod(0o660)
            return self._result(workload_id, session_id, str(path))
        if self.foreign_peer:
            self._open_foreign_peer(path, session_id)
            return self._result(workload_id, session_id, str(path))
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(path))
        path.chmod(0o660)
        if not self.connect_failure:
            listener.listen(1)
        self._listeners[session_id] = listener

        if self.connect_failure:
            return self._result(workload_id, session_id, str(path))

        def accept_and_echo() -> None:
            try:
                connection, _ = listener.accept()
            except OSError:
                return
            with connection:
                while True:
                    try:
                        data = connection.recv(4096)
                    except OSError:
                        return
                    if not data:
                        return
                    self.received[session_id] = data
                    self.received_event.set()
                    try:
                        connection.sendall(b"echo:" + data)
                    except OSError:
                        return
                    if self.close_after_echo:
                        return

        threading.Thread(target=accept_and_echo, daemon=True).start()
        return self._result(workload_id, session_id, str(path))

    def _result(self, workload_id: str, session_id: str, socket_path: str):
        executor_pid = self.executor_pid
        if executor_pid == "auto":
            process = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            self._executor_processes[session_id] = process
            executor_pid = process.pid
        return {
            "result": {
                "sessionId": session_id,
                "workloadId": workload_id,
                "socketPath": socket_path,
                "targetClass": "capsule",
                "reconnect": False,
                "executorPid": executor_pid,
            }
        }

    def resize_terminal(self, session_id: str, *, columns: int, rows: int):
        self.resized.append((session_id, columns, rows))
        return {"result": {"sessionId": session_id}}

    def signal_terminal(self, session_id: str, *, signal: str):
        self.signal_started.set()
        if self.signal_release is not None:
            self.signal_release.wait(timeout=5)
        self.signaled.append((session_id, signal))
        return {"result": {"sessionId": session_id}}

    def close_terminal(self, session_id: str):
        self.closed.append(session_id)
        self._control_stop.set()
        self._control_listener.close()
        listener = self._listeners.pop(session_id, None)
        if listener is not None:
            listener.close()
        process = self._peer_processes.pop(session_id, None)
        if process is not None:
            try:
                process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                process.terminate()
                process.wait(timeout=2)
        executor = self._executor_processes.pop(session_id, None)
        if executor is not None:
            executor.terminate()
            executor.wait(timeout=2)
        try:
            (self._sessions_dir / f"{session_id}.sock").unlink()
        except FileNotFoundError:
            pass
        return {"result": {"sessionId": session_id, "state": "closing"}}


def _target() -> TerminalTarget:
    return TerminalTarget(
        "terminal_target_" + "a" * 32,
        "capsule",
        "Workspace container",
        "available",
        TerminalCapabilities("capsule", True, True, True, False, False, True),
    )


def _gateway(fake: FakeExecutionHost, **changes) -> ExecutionHostTerminalGateway:
    options = {
        "workspace_id": "workspace.demo",
        "instance_id": "demo",
        "profile_id": "terminal.profile.demo",
        "target": _target(),
        "allowed_origins": (ORIGIN, OTHER_ORIGIN),
    }
    options.update(changes)
    return ExecutionHostTerminalGateway(fake, **options)


def _actor(instances=("demo",), actor_id="operator.demo") -> GatewayActor:
    return GatewayActor(actor_id, frozenset(instances), "operator_session")


def _handshake(actor: GatewayActor, origin: str = ORIGIN, instance_id: str = "demo") -> GatewayHandshake:
    return GatewayHandshake(actor, instance_id, origin, token_transport="first_frame")


def _prepare_and_accept(gateway: ExecutionHostTerminalGateway, actor: GatewayActor, origin: str = ORIGIN):
    token = gateway.prepare(
        actor,
        profile_id="terminal.profile.demo",
        instance_id="demo",
        selected_root=Path("/workspace"),
        origin=origin,
    )
    handshake = _handshake(actor, origin)
    session, receipt = gateway.accept_handshake(
        handshake, one_use_value=token.value, selected_root=Path("/workspace")
    )
    return session, receipt, handshake


def test_ticket_is_single_use(short_root: Path):
    fake = FakeExecutionHost(short_root)
    gateway = _gateway(fake)
    actor = _actor()
    token = gateway.prepare(
        actor, profile_id="terminal.profile.demo", instance_id="demo",
        selected_root=Path("/workspace"), origin=ORIGIN,
    )
    handshake = _handshake(actor)
    session, receipt = gateway.accept_handshake(
        handshake, one_use_value=token.value, selected_root=Path("/workspace")
    )
    assert receipt.action == "created"
    with pytest.raises(TerminalTokenError):
        gateway.accept_handshake(
            handshake, one_use_value=token.value, selected_root=Path("/workspace")
        )
    assert fake.open_calls == 1
    gateway.close()


def test_ticket_is_bound_to_actor_instance_and_origin(short_root: Path):
    fake = FakeExecutionHost(short_root)
    gateway = _gateway(fake)
    actor = _actor()

    def fresh_token():
        return gateway.prepare(
            actor, profile_id="terminal.profile.demo", instance_id="demo",
            selected_root=Path("/workspace"), origin=ORIGIN,
        )

    # A different actor holding the same instance grant cannot spend the
    # ticket: the actor binding fails and the ticket is consumed.
    token = fresh_token()
    with pytest.raises(TerminalTokenError):
        gateway.accept_handshake(
            _handshake(_actor(actor_id="intruder.demo")),
            one_use_value=token.value,
            selected_root=Path("/workspace"),
        )
    with pytest.raises(TerminalTokenError):
        gateway.accept_handshake(
            _handshake(actor), one_use_value=token.value, selected_root=Path("/workspace")
        )
    # A different (allowlisted) origin cannot spend it either.
    token = fresh_token()
    with pytest.raises(TerminalTokenError):
        gateway.accept_handshake(
            _handshake(actor, OTHER_ORIGIN),
            one_use_value=token.value,
            selected_root=Path("/workspace"),
        )
    # An origin outside the allowlist is refused before the ticket is read.
    token = fresh_token()
    with pytest.raises(TerminalAccessDenied):
        gateway.accept_handshake(
            _handshake(actor, "http://evil.example"),
            one_use_value=token.value,
            selected_root=Path("/workspace"),
        )
    # An actor without the instance grant never gets a ticket.
    with pytest.raises(TerminalAccessDenied):
        gateway.prepare(
            _actor(instances=("other",)),
            profile_id="terminal.profile.demo",
            instance_id="other",
            selected_root=Path("/workspace"),
            origin=ORIGIN,
        )
    gateway.close()


def test_ticket_expires_within_its_bounded_lifetime(short_root: Path, monkeypatch: pytest.MonkeyPatch):
    fake = FakeExecutionHost(short_root)
    gateway = _gateway(fake, token_ttl_seconds=5)
    actor = _actor()
    token = gateway.prepare(
        actor, profile_id="terminal.profile.demo", instance_id="demo",
        selected_root=Path("/workspace"), origin=ORIGIN,
    )
    real_time = time.time
    monkeypatch.setattr(
        "stateport_terminal_broker.execution_host_gateway.time.time",
        lambda: real_time() + 6,
    )
    with pytest.raises(TerminalTokenError):
        gateway.accept_handshake(
            _handshake(actor), one_use_value=token.value, selected_root=Path("/workspace")
        )
    gateway.close()


def test_byte_round_trip_resize_and_signal(short_root: Path):
    fake = FakeExecutionHost(short_root)
    gateway = _gateway(fake)
    actor = _actor()
    session, _receipt, handshake = _prepare_and_accept(gateway, actor)
    gateway.handle_frame(handshake, session_id=session.session_id, frame=GatewayFrame("input", b"pwd\n"))
    assert fake.received_event.wait(2.0)
    assert fake.received[session.session_id] == b"pwd\n"
    output = gateway.read_frame(handshake, session_id=session.session_id, timeout_seconds=1.0)
    assert output.data == b"echo:pwd\n"
    resize = gateway.handle_frame(
        handshake, session_id=session.session_id, frame=GatewayFrame("resize", columns=120, rows=40)
    )
    assert fake.resized == [(session.session_id, 120, 40)]
    ack = gateway.handle_signal(handshake, session_id=session.session_id, signal="SIGINT")
    assert fake.signaled == [(session.session_id, "SIGINT")]
    assert ack.byte_count == 1
    with pytest.raises(TerminalBrokerError):
        gateway.handle_signal(handshake, session_id=session.session_id, signal="SIGKILL")
    gateway.close()


def test_blocked_daemon_call_does_not_hold_the_gateway_lock(short_root: Path):
    fake = FakeExecutionHost(short_root)
    fake.signal_release = threading.Event()
    gateway = _gateway(fake)
    actor = _actor()
    session, _receipt, handshake = _prepare_and_accept(gateway, actor)
    errors: list[Exception] = []

    def signal_session() -> None:
        try:
            gateway.handle_signal(handshake, session_id=session.session_id)
        except Exception as exc:
            errors.append(exc)

    worker = threading.Thread(target=signal_session, daemon=True)
    worker.start()
    assert fake.signal_started.wait(timeout=2)
    started = time.monotonic()
    assert gateway.list_sessions(actor, instance_id="demo", origin=ORIGIN)
    exits = gateway.close()
    assert time.monotonic() - started < 1
    assert [item.session_id for item in exits] == [session.session_id]
    fake.signal_release.set()
    worker.join(timeout=2)
    assert not worker.is_alive()
    assert errors


def test_active_session_rejects_an_allowlisted_origin_switch(short_root: Path):
    fake = FakeExecutionHost(short_root)
    gateway = _gateway(fake)
    actor = _actor()
    session, _receipt, handshake = _prepare_and_accept(gateway, actor)
    switched = _handshake(actor, OTHER_ORIGIN)

    with pytest.raises(TerminalAccessDenied):
        gateway.handle_frame(
            switched,
            session_id=session.session_id,
            frame=GatewayFrame("input", b"not-authorized"),
        )
    with pytest.raises(TerminalAccessDenied):
        gateway.handle_signal(switched, session_id=session.session_id)
    with pytest.raises(TerminalAccessDenied):
        gateway.read_frame(switched, session_id=session.session_id)
    assert gateway.list_sessions(actor, instance_id="demo", origin=OTHER_ORIGIN) == ()
    assert gateway.audit_receipts(actor, instance_id="demo", origin=OTHER_ORIGIN) == ()
    intruder = _actor(actor_id="intruder.demo")
    assert gateway.list_sessions(intruder, instance_id="demo", origin=ORIGIN) == ()
    assert gateway.audit_receipts(intruder, instance_id="demo", origin=ORIGIN) == ()
    with pytest.raises(TerminalAccessDenied):
        gateway.list_sessions("operator.demo", instance_id="demo", origin=ORIGIN)  # type: ignore[arg-type]
    assert [item.session_id for item in gateway.list_sessions(
        actor, instance_id="demo", origin=ORIGIN
    )] == [session.session_id]
    assert [item.action for item in gateway.audit_receipts(
        actor, instance_id="demo", origin=ORIGIN
    )] == ["created"]

    gateway.handle_frame(
        handshake, session_id=session.session_id, frame=GatewayFrame("close")
    )
    assert gateway.audit_receipts(actor, instance_id="demo", origin=OTHER_ORIGIN) == ()
    assert [item.action for item in gateway.audit_receipts(
        actor, instance_id="demo", origin=ORIGIN
    )] == ["created", "closed"]
    gateway.close()


def test_disconnect_cleans_up_at_the_execution_host(short_root: Path):
    fake = FakeExecutionHost(short_root)
    gateway = _gateway(fake)
    actor = _actor()
    session, _receipt, handshake = _prepare_and_accept(gateway, actor)
    exit_value, receipt = gateway.handle_frame(
        handshake, session_id=session.session_id, frame=GatewayFrame("close")
    )
    assert exit_value.reason == "operator_closed"
    assert receipt.cleanup == "terminated"
    assert fake.closed == [session.session_id]
    assert gateway.list_sessions(actor, instance_id="demo", origin=ORIGIN) == ()
    # Audit evidence binds process/container identity as a digest only.
    audits = gateway.audit_receipts(actor, instance_id="demo", origin=ORIGIN)
    assert [item.action for item in audits] == ["created", "closed"]
    assert audits[-1].generation_digest.startswith("sha256:")
    assert audits[-1].target_id == _target().target_id
    # The terminal is gone: further frames meet the uniform refusal.
    with pytest.raises(TerminalAccessDenied):
        gateway.handle_frame(handshake, session_id=session.session_id, frame=GatewayFrame("input", b"x"))
    gateway.close()


def test_one_connected_terminal_per_workspace(short_root: Path):
    fake = FakeExecutionHost(short_root)
    gateway = _gateway(fake)
    actor = _actor()
    _session, _receipt, _handshake = _prepare_and_accept(gateway, actor)
    with pytest.raises(TerminalBrokerError, match="already has a connected terminal"):
        gateway.prepare(
            actor, profile_id="terminal.profile.demo", instance_id="demo",
            selected_root=Path("/workspace"), origin=ORIGIN,
        )
    gateway.close()


def test_background_sweeper_closes_an_expired_session(
    short_root: Path, monkeypatch: pytest.MonkeyPatch
):
    fake = FakeExecutionHost(short_root)
    gateway = _gateway(fake)
    actor = _actor()
    session, _receipt, _handshake_value = _prepare_and_accept(gateway, actor)
    real_time = time.time
    monkeypatch.setattr(
        "stateport_terminal_broker.execution_host_gateway.time.time",
        lambda: real_time() + 3_601,
    )
    deadline = real_time() + 3
    while session.session_id not in fake.closed and real_time() < deadline:
        time.sleep(0.05)
    assert fake.closed == [session.session_id]
    gateway.close()


def test_session_socket_must_stay_inside_the_confined_directory(short_root: Path):
    fake = FakeExecutionHost(short_root)
    fake.bad_socket_path = "/tmp/anywhere.sock"
    gateway = _gateway(fake)
    actor = _actor()
    token = gateway.prepare(
        actor, profile_id="terminal.profile.demo", instance_id="demo",
        selected_root=Path("/workspace"), origin=ORIGIN,
    )
    with pytest.raises(TerminalBrokerError, match="invalid terminal socket"):
        gateway.accept_handshake(
            _handshake(actor), one_use_value=token.value, selected_root=Path("/workspace")
        )
    assert fake.closed == [token.session_id]
    gateway.close()


@pytest.mark.parametrize("executor_pid", [None, 0, 1, -1, True])
def test_invalid_executor_identity_fails_closed_after_open(
    short_root: Path, executor_pid: Any
):
    fake = FakeExecutionHost(short_root)
    fake.executor_pid = executor_pid
    gateway = _gateway(fake)
    actor = _actor()
    token = gateway.prepare(
        actor, profile_id="terminal.profile.demo", instance_id="demo",
        selected_root=Path("/workspace"), origin=ORIGIN,
    )
    with pytest.raises(TerminalBrokerError, match="executor identity"):
        gateway.accept_handshake(
            _handshake(actor), one_use_value=token.value, selected_root=Path("/workspace")
        )
    assert fake.closed == [token.session_id]
    gateway.close()


def test_executor_pid_self_attestation_is_not_trusted(short_root: Path):
    fake = FakeExecutionHost(short_root)
    fake.executor_pid = os.getpid()
    gateway = _gateway(fake)
    actor = _actor()
    token = gateway.prepare(
        actor, profile_id="terminal.profile.demo", instance_id="demo",
        selected_root=Path("/workspace"), origin=ORIGIN,
    )
    with pytest.raises(TerminalBrokerError, match="executor identity is invalid"):
        gateway.accept_handshake(
            _handshake(actor), one_use_value=token.value, selected_root=Path("/workspace")
        )
    assert fake.closed == [token.session_id]
    gateway.close()


def test_post_open_connect_failure_closes_the_daemon_terminal(short_root: Path):
    fake = FakeExecutionHost(short_root)
    fake.connect_failure = True
    gateway = _gateway(fake)
    actor = _actor()
    token = gateway.prepare(
        actor, profile_id="terminal.profile.demo", instance_id="demo",
        selected_root=Path("/workspace"), origin=ORIGIN,
    )
    with pytest.raises(TerminalBrokerError, match="unreachable"):
        gateway.accept_handshake(
            _handshake(actor), one_use_value=token.value, selected_root=Path("/workspace")
        )
    assert fake.closed == [token.session_id]
    gateway.close()


def test_session_path_must_be_a_real_unix_socket(short_root: Path):
    fake = FakeExecutionHost(short_root)
    fake.regular_socket_path = True
    gateway = _gateway(fake)
    actor = _actor()
    token = gateway.prepare(
        actor, profile_id="terminal.profile.demo", instance_id="demo",
        selected_root=Path("/workspace"), origin=ORIGIN,
    )
    with pytest.raises(TerminalBrokerError, match="invalid terminal socket"):
        gateway.accept_handshake(
            _handshake(actor), one_use_value=token.value, selected_root=Path("/workspace")
        )
    assert fake.closed == [token.session_id]
    gateway.close()


@pytest.mark.skipif(not hasattr(socket, "SO_PEERCRED"), reason="Linux peer credentials unavailable")
def test_session_peer_must_be_the_control_daemon_process(short_root: Path):
    fake = FakeExecutionHost(short_root)
    fake.foreign_peer = True
    gateway = _gateway(fake)
    actor = _actor()
    token = gateway.prepare(
        actor, profile_id="terminal.profile.demo", instance_id="demo",
        selected_root=Path("/workspace"), origin=ORIGIN,
    )
    with pytest.raises(TerminalBrokerError, match="peer identity"):
        gateway.accept_handshake(
            _handshake(actor), one_use_value=token.value, selected_root=Path("/workspace")
        )
    assert fake.closed == [token.session_id]
    gateway.close()


def test_gateway_rejects_host_roots_and_replay(short_root: Path):
    fake = FakeExecutionHost(short_root)
    gateway = _gateway(fake)
    actor = _actor()
    with pytest.raises(TerminalAccessDenied):
        gateway.prepare(
            actor, profile_id="terminal.profile.demo", instance_id="demo",
            selected_root=short_root, origin=ORIGIN,
        )
    session, _receipt, handshake = _prepare_and_accept(gateway, actor)
    with pytest.raises(TerminalBrokerError, match="replay"):
        gateway.handle_frame(
            handshake, session_id=session.session_id, frame=GatewayFrame("replay", after_offset=0)
        )
    gateway.close()


class _DescriptorStream:
    def __init__(self, descriptor: int):
        self._descriptor = descriptor

    def fileno(self) -> int:
        return self._descriptor


def test_cli_shell_restores_descriptors_termios_and_sigwinch(
    short_root: Path, monkeypatch: pytest.MonkeyPatch
):
    fake = FakeExecutionHost(short_root)
    fake.close_after_echo = True
    master_fd, stdin_fd = pty.openpty()
    stdout_read, stdout_fd = os.pipe()
    original_handler = signal.getsignal(signal.SIGWINCH)

    def sentinel(_signum: int, _frame: Any) -> None:
        pass

    signal.signal(signal.SIGWINCH, sentinel)
    original_stdin_flags = fcntl.fcntl(stdin_fd, fcntl.F_GETFL)
    original_stdout_flags = fcntl.fcntl(stdout_fd, fcntl.F_GETFL) | os.O_NONBLOCK
    fcntl.fcntl(stdout_fd, fcntl.F_SETFL, original_stdout_flags)
    original_attributes = termios.tcgetattr(stdin_fd)
    real_write = os.write

    def partial_stdout_write(descriptor: int, data: bytes) -> int:
        if descriptor == stdout_fd and len(data) > 2:
            return real_write(descriptor, data[:2])
        return real_write(descriptor, data)

    monkeypatch.setattr(alpha4_runtime.sys, "stdin", _DescriptorStream(stdin_fd))
    monkeypatch.setattr(alpha4_runtime.sys, "stdout", _DescriptorStream(stdout_fd))
    monkeypatch.setattr(alpha4_runtime.os, "write", partial_stdout_write)

    def write_stdin() -> None:
        time.sleep(0.1)
        real_write(master_fd, b"hello")

    writer = threading.Thread(target=write_stdin, daemon=True)
    writer.start()
    try:
        result = alpha4_runtime._run_interactive_shell(
            fake,
            "workspace.demo",
            columns=80,
            rows=24,
            timeout_seconds=2,
        )
        writer.join(timeout=2)
        assert result["sessionId"].startswith("cli-session-")
        assert fcntl.fcntl(stdin_fd, fcntl.F_GETFL) == original_stdin_flags
        assert fcntl.fcntl(stdout_fd, fcntl.F_GETFL) == original_stdout_flags
        assert termios.tcgetattr(stdin_fd) == original_attributes
        assert signal.getsignal(signal.SIGWINCH) is sentinel
        assert os.read(stdout_read, 4096) == b"echo:hello"
        assert fake.closed == [result["sessionId"]]
    finally:
        signal.signal(signal.SIGWINCH, original_handler)
        for descriptor in (master_fd, stdin_fd, stdout_read, stdout_fd):
            try:
                os.close(descriptor)
            except OSError:
                pass


def test_cli_shell_closes_a_terminal_when_post_open_setup_fails():
    class MissingSocketClient:
        def __init__(self):
            self.closed: list[str] = []

        def open_terminal(
            self, workspace_id: str, session_id: str, *, columns: int, rows: int
        ):
            return {"result": {"sessionId": session_id}}

        def close_terminal(self, session_id: str):
            self.closed.append(session_id)
            return {"result": {"sessionId": session_id}}

    client = MissingSocketClient()
    with pytest.raises(ExecutionHostTransportError, match="socket was not provided"):
        alpha4_runtime._run_interactive_shell(
            client,
            "workspace.demo",
            columns=80,
            rows=24,
            timeout_seconds=2,
        )
    assert len(client.closed) == 1
    assert client.closed[0].startswith("cli-session-")


def test_exec_cmd_removes_only_the_optional_leading_separator(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    class ExecClient:
        def __init__(self):
            self.argv: list[str] | None = None

        def exec_workload(
            self, workspace_id: str, argv: list[str], *, timeout_seconds: int
        ):
            self.argv = list(argv)
            return {
                "result": {
                    "output": "ok\n",
                    "exitStatus": 0,
                    "byteCount": 3,
                    "truncated": False,
                }
            }

    client = ExecClient()
    monkeypatch.setattr(alpha4_runtime, "_client_from_args", lambda _args: client)
    args = SimpleNamespace(
        execution_host_socket="/run/stateport/control.sock",
        authority_grant_digest="sha256:" + "a" * 64,
        workspace_id="workspace.demo",
        command=["--", "printf", "--", "literal"],
        timeout_seconds=30,
    )
    assert alpha4_runtime.exec_cmd(args) == 0
    assert client.argv == ["printf", "--", "literal"]
    assert capsys.readouterr().out == "ok\n"
