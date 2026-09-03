"""Capsule terminal adapter backed by the dedicated execution host.

This adapter keeps the authenticated browser contract of
``stateport_terminal_broker.gateway`` while the PTY and shell live inside a
running rootless workspace container owned by the execution-host daemon.

Boundaries, aligned with ``broker.py`` conventions:

- one-use tickets are sha256-keyed, TTL-bound (5..300s), and bound to the
  exact actor, instance, and origin with constant-time comparisons;
- the per-session Unix socket returned by the execution host is an internal
  service-to-daemon value, validated against the confined session directory
  and never serialized into a browser response;
- no execution-host or Podman socket is ever exposed to a browser, and there
  is no fallback into a web or control container;
- audit receipts bind process/container identity as digests (workload,
  session, executor pid) and never carry terminal bytes or raw socket paths.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import os
import re
import select
import secrets
import socket
import stat
import struct
import threading
import time
from pathlib import Path
from typing import Any, Iterator, Mapping, TYPE_CHECKING

from .broker import TerminalAccessDenied, TerminalBrokerError, TerminalTokenError
from .contracts import (
    TerminalAuditReceipt,
    TerminalExit,
    TerminalInput,
    TerminalOutput,
    TerminalReconnectToken,
    TerminalResize,
    TerminalSession,
    TerminalTarget,
)
from .gateway import GatewayActor, GatewayFrame, GatewayHandshake

if TYPE_CHECKING:  # pragma: no cover - typing only; no runtime import cycle
    from execution_host.client import ExecutionHostClient


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SIGNALS = frozenset({"SIGINT", "SIGQUIT", "SIGTSTP"})
_MAX_PENDING = 128
_MAX_SESSIONS = 64
_MAX_AUDIT = 256
_CONNECT_TIMEOUT_SECONDS = 5.0
_IO_TIMEOUT_SECONDS = 1.0
_SWEEP_INTERVAL_SECONDS = 1.0


def _utc(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _path_components_are_real(path: Path) -> bool:
    cursor = Path(path.anchor)
    try:
        for part in path.parts[1:]:
            cursor /= part
            if stat.S_ISLNK(cursor.lstat().st_mode):
                return False
    except OSError:
        return False
    return True


def _socket_signature(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return value.st_dev, value.st_ino, value.st_uid, value.st_gid, value.st_mode


@dataclass
class _Pending:
    session_id: str
    actor_id: str
    instance_id: str
    origin: str
    expires_at: float


@dataclass
class _Session:
    session: TerminalSession
    origin: str
    connection: socket.socket
    executor_pid: int
    created_at: float
    expires_at: float
    last_activity: float
    input_bytes: int = 0
    output_bytes: int = 0
    input_sequence: int = 0
    resize_sequence: int = 0
    output_offset: int = 0
    lock: threading.RLock = field(default_factory=threading.RLock, repr=False)
    exit_result: tuple[TerminalExit, TerminalAuditReceipt] | None = field(
        default=None, repr=False
    )


@dataclass(frozen=True)
class _AuditEntry:
    receipt: TerminalAuditReceipt
    origin: str


class ExecutionHostTerminalGateway:
    """Terminal broker surface over an execution-host workspace PTY.

    One workspace serves one connected terminal at a time.  Reconnect is
    unavailable: a disconnect cleans the session up at the execution host.
    """

    def __init__(
        self,
        client: "ExecutionHostClient",
        *,
        workspace_id: str,
        instance_id: str,
        profile_id: str,
        target: TerminalTarget,
        allowed_origins: tuple[str, ...],
        token_ttl_seconds: int = 30,
        idle_timeout_seconds: int = 900,
        maximum_lifetime_seconds: int = 3600,
    ) -> None:
        if _ID.fullmatch(workspace_id) is None or _ID.fullmatch(instance_id) is None:
            raise ValueError("execution-host terminal identity is invalid")
        if _ID.fullmatch(profile_id) is None:
            raise ValueError("execution-host terminal profile id is invalid")
        if target.target_class != "capsule" or target.availability != "available":
            raise ValueError("execution-host terminal requires an available capsule target")
        if target.capabilities.reconnect or target.capabilities.replay:
            raise ValueError("capsule terminal reconnect and replay are unavailable")
        if (
            isinstance(token_ttl_seconds, bool)
            or not isinstance(token_ttl_seconds, int)
            or not 5 <= token_ttl_seconds <= 300
        ):
            raise ValueError("token_ttl_seconds must be between 5 and 300")
        if (
            isinstance(idle_timeout_seconds, bool)
            or not isinstance(idle_timeout_seconds, int)
            or not 60 <= idle_timeout_seconds <= 86_400
        ):
            raise ValueError("idle_timeout_seconds is outside policy")
        if (
            isinstance(maximum_lifetime_seconds, bool)
            or not isinstance(maximum_lifetime_seconds, int)
            or not idle_timeout_seconds <= maximum_lifetime_seconds <= 86_400
        ):
            raise ValueError("maximum_lifetime_seconds is outside policy")
        if not allowed_origins or len(allowed_origins) > 32 or len(set(allowed_origins)) != len(allowed_origins):
            raise ValueError("an explicit bounded origin allowlist is required")
        self._client = client
        self._workspace_id = workspace_id
        self._instance_id = instance_id
        self._profile_id = profile_id
        self._target = target
        self._origins = frozenset(allowed_origins)
        self._token_ttl_seconds = token_ttl_seconds
        self._idle_timeout_seconds = idle_timeout_seconds
        self._maximum_lifetime_seconds = maximum_lifetime_seconds
        self._mutex = threading.RLock()
        self._pending: dict[str, _Pending] = {}
        self._opening: set[str] = set()
        self._closing: set[str] = set()
        self._sessions: dict[str, _Session] = {}
        self._audit: list[_AuditEntry] = []
        self._closed = False
        self._stop_sweeper = threading.Event()
        self._sweeper = threading.Thread(
            target=self._sweep_loop,
            name=f"terminal-expiry-{workspace_id}",
            daemon=True,
        )
        self._sweeper.start()

    # ------------------------------------------------------------ internals

    def _assert_open(self) -> None:
        if self._closed:
            raise TerminalBrokerError("terminal gateway is closed")

    def _assert_actor(self, actor: GatewayActor, instance_id: str, origin: str) -> None:
        if (
            not isinstance(actor, GatewayActor)
            or not isinstance(instance_id, str)
            or not isinstance(origin, str)
            or not actor.can_access(instance_id)
            or not hmac.compare_digest(instance_id, self._instance_id)
            or origin not in self._origins
        ):
            raise TerminalAccessDenied()

    def _cleanup_pending(self, now: float) -> None:
        for digest, item in tuple(self._pending.items()):
            if item.expires_at <= now:
                self._pending.pop(digest, None)

    def _receipt(self, session: _Session, action: str, outcome: str, cleanup: str) -> TerminalAuditReceipt:
        return TerminalAuditReceipt(
            "receipt." + secrets.token_hex(24),
            session.session.session_id,
            self._target.target_id,
            session.session.actor_id,
            session.session.instance_id,
            action,
            outcome,
            _utc(time.time()),
            _digest("/workspace"),
            session.session.generation_digest,
            session.input_bytes,
            session.output_bytes,
            0,
            cleanup,
        )

    def _append_audit(self, receipt: TerminalAuditReceipt, origin: str) -> TerminalAuditReceipt:
        with self._mutex:
            self._audit.append(_AuditEntry(receipt, origin))
            del self._audit[:-_MAX_AUDIT]
        return receipt

    def _sweep_loop(self) -> None:
        while not self._stop_sweeper.wait(_SWEEP_INTERVAL_SECONDS):
            try:
                self.sweep_expired()
            except Exception:
                # An individual cleanup failure is already captured in its
                # receipt. The expiry path must remain live for other sessions.
                continue

    def _expiry_reason(self, live: _Session, now: float) -> str | None:
        if now >= live.expires_at:
            return "maximum_lifetime"
        if now - live.last_activity >= self._idle_timeout_seconds:
            return "idle_timeout"
        return None

    def _authorized(self, handshake: GatewayHandshake, session_id: str) -> _Session:
        if not isinstance(handshake, GatewayHandshake) or not isinstance(session_id, str):
            raise TerminalAccessDenied()
        self._assert_actor(handshake.actor, handshake.instance_id, handshake.origin)
        with self._mutex:
            self._assert_open()
            live = self._sessions.get(session_id)
            if (
                live is None
                or not hmac.compare_digest(live.session.actor_id, handshake.actor.actor_id)
                or not hmac.compare_digest(live.session.instance_id, handshake.instance_id)
                or not hmac.compare_digest(live.origin, handshake.origin)
            ):
                raise TerminalAccessDenied()
            return live

    @contextmanager
    def _locked_session(
        self, handshake: GatewayHandshake, session_id: str
    ) -> Iterator[_Session]:
        live = self._authorized(handshake, session_id)
        with live.lock:
            with self._mutex:
                self._assert_open()
                if (
                    self._sessions.get(session_id) is not live
                    or not hmac.compare_digest(
                        live.session.actor_id, handshake.actor.actor_id
                    )
                    or not hmac.compare_digest(
                        live.session.instance_id, handshake.instance_id
                    )
                    or not hmac.compare_digest(live.origin, handshake.origin)
                ):
                    raise TerminalAccessDenied()
            expiry_reason = self._expiry_reason(live, time.time())
            if expiry_reason is not None:
                self._finish(live, expiry_reason)
                raise TerminalAccessDenied()
            yield live

    def audit_receipts(
        self,
        actor: GatewayActor,
        *,
        instance_id: str,
        origin: str,
    ) -> tuple[TerminalAuditReceipt, ...]:
        self._assert_actor(actor, instance_id, origin)
        with self._mutex:
            self._assert_open()
            return tuple(
                item.receipt
                for item in self._audit
                if hmac.compare_digest(item.receipt.actor_id, actor.actor_id)
                and hmac.compare_digest(item.receipt.instance_id, instance_id)
                and hmac.compare_digest(item.origin, origin)
            )

    def list_sessions(
        self,
        actor: GatewayActor,
        *,
        instance_id: str,
        origin: str,
    ) -> tuple[TerminalSession, ...]:
        self._assert_actor(actor, instance_id, origin)
        with self._mutex:
            self._assert_open()
            return tuple(
                item.session
                for item in self._sessions.values()
                if hmac.compare_digest(item.session.actor_id, actor.actor_id)
                and hmac.compare_digest(item.session.instance_id, instance_id)
                and hmac.compare_digest(item.origin, origin)
            )

    # --------------------------------------------------------- ticket issue

    def prepare(
        self,
        actor: GatewayActor,
        *,
        profile_id: str,
        instance_id: str,
        selected_root: Path | str,
        origin: str,
    ) -> TerminalReconnectToken:
        self._assert_actor(actor, instance_id, origin)
        if not hmac.compare_digest(profile_id, self._profile_id):
            raise TerminalAccessDenied()
        if Path(selected_root) != Path("/workspace"):
            # The only root a capsule terminal can enter is the workspace
            # mount inside the container; host roots are not representable.
            raise TerminalAccessDenied()
        with self._mutex:
            self._assert_open()
            self._cleanup_pending(time.time())
            if (
                len(self._pending) >= _MAX_PENDING
                or len(self._sessions) + len(self._opening) + len(self._closing)
                >= _MAX_SESSIONS
            ):
                raise TerminalBrokerError("terminal session capacity is exhausted")
            if self._sessions or self._opening or self._closing:
                raise TerminalBrokerError("the selected workspace already has a connected terminal")
            session_id = "terminal." + secrets.token_hex(24)
            token = secrets.token_urlsafe(32)
            expires_at = time.time() + self._token_ttl_seconds
            digest = hashlib.sha256(token.encode("ascii")).hexdigest()
            self._pending[digest] = _Pending(
                session_id, actor.actor_id, instance_id, origin, expires_at
            )
            return TerminalReconnectToken(token, session_id, "create", _utc(expires_at))

    # ------------------------------------------------------- session accept

    def _client_socket_path(self) -> Path:
        value = getattr(self._client, "socket_path", None)
        if not isinstance(value, (str, os.PathLike)):
            raise TerminalBrokerError(
                "execution-host client does not expose its public socket identity"
            )
        raw = os.fspath(value)
        if not isinstance(raw, str) or not raw or "\x00" in raw:
            raise TerminalBrokerError("execution-host client socket identity is invalid")
        path = Path(raw)
        if (
            not path.is_absolute()
            or any(part in {".", ".."} for part in path.parts)
            or Path(os.path.abspath(raw)) != path
        ):
            raise TerminalBrokerError("execution-host client socket identity is invalid")
        return path

    @staticmethod
    def _socket_metadata(path: Path) -> os.stat_result:
        try:
            value = path.lstat()
        except OSError as exc:
            raise TerminalBrokerError("execution-host terminal socket is unavailable") from exc
        if not stat.S_ISSOCK(value.st_mode) or stat.S_IMODE(value.st_mode) != 0o660:
            raise TerminalBrokerError("execution host returned an invalid terminal socket")
        return value

    def _session_socket_path(
        self, session_id: str, result: Mapping[str, Any]
    ) -> tuple[Path, tuple[int, int, int, int, int], Path, tuple[int, int, int, int, int]]:
        """Bind a real daemon session socket to the trusted confined directory."""

        socket_value = result.get("socketPath")
        if not isinstance(socket_value, str) or not socket_value or "\x00" in socket_value:
            raise TerminalBrokerError("execution host returned an invalid terminal session")
        control_path = self._client_socket_path()
        expected_dir = control_path.parent / "sessions"
        expected_path = expected_dir / f"{session_id}.sock"
        socket_path = Path(socket_value)
        if (
            socket_value != expected_path.as_posix()
            or not socket_path.is_absolute()
            or any(part in {".", ".."} for part in socket_path.parts)
            or not _path_components_are_real(control_path.parent)
            or not _path_components_are_real(expected_dir)
        ):
            raise TerminalBrokerError("execution host returned an invalid terminal socket")
        try:
            control_directory = control_path.parent.lstat()
            directory = expected_dir.lstat()
        except OSError as exc:
            raise TerminalBrokerError("execution host returned an invalid terminal socket") from exc
        if (
            not stat.S_ISDIR(control_directory.st_mode)
            or stat.S_IMODE(control_directory.st_mode) != 0o750
            or not stat.S_ISDIR(directory.st_mode)
            or stat.S_IMODE(directory.st_mode) != 0o750
        ):
            raise TerminalBrokerError("execution host returned an invalid terminal socket")
        control = self._socket_metadata(control_path)
        session = self._socket_metadata(socket_path)
        if (
            (control_directory.st_uid, control_directory.st_gid)
            != (control.st_uid, control.st_gid)
            or (directory.st_uid, directory.st_gid) != (control.st_uid, control.st_gid)
            or (session.st_uid, session.st_gid) != (control.st_uid, control.st_gid)
        ):
            raise TerminalBrokerError("execution host returned an invalid terminal socket")
        return socket_path, _socket_signature(session), control_path, _socket_signature(control)

    @staticmethod
    def _peer_credentials(connection: socket.socket) -> tuple[int, int, int] | None:
        if not hasattr(socket, "SO_PEERCRED"):
            return None
        try:
            raw = connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
            )
            peer = struct.unpack("3i", raw)
        except (OSError, struct.error) as exc:
            raise TerminalBrokerError(
                "execution-host terminal peer identity could not be verified"
            ) from exc
        if peer[0] <= 1 or peer[1] < 0 or peer[2] < 0:
            raise TerminalBrokerError("execution-host terminal peer identity is invalid")
        return peer

    def _connect_session(
        self,
        socket_path: Path,
        socket_identity: tuple[int, int, int, int, int],
        control_path: Path,
        control_identity: tuple[int, int, int, int, int],
    ) -> tuple[socket.socket, tuple[int, int, int] | None]:
        control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            control.settimeout(_CONNECT_TIMEOUT_SECONDS)
            control.connect(str(control_path))
            if _socket_signature(self._socket_metadata(control_path)) != control_identity:
                raise TerminalBrokerError("execution-host control socket changed during connection")
            expected_peer = self._peer_credentials(control)
        except TerminalBrokerError:
            raise
        except OSError as exc:
            raise TerminalBrokerError(
                "execution-host control peer identity could not be verified"
            ) from exc
        finally:
            control.close()

        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.settimeout(_CONNECT_TIMEOUT_SECONDS)
            connection.connect(str(socket_path))
            if _socket_signature(self._socket_metadata(socket_path)) != socket_identity:
                raise TerminalBrokerError("execution-host terminal socket changed during connection")
            peer = self._peer_credentials(connection)
            if peer != expected_peer:
                raise TerminalBrokerError("execution-host terminal peer identity is invalid")
            connection.setblocking(False)
            return connection, peer
        except TerminalBrokerError:
            connection.close()
            raise
        except OSError as exc:
            connection.close()
            raise TerminalBrokerError("execution-host terminal session is unreachable") from exc

    @staticmethod
    def _verify_executor_identity(
        executor_pid: int, daemon_peer: tuple[int, int, int] | None
    ) -> None:
        if daemon_peer is None:
            return
        process_root = Path(f"/proc/{executor_pid}")
        try:
            process = process_root.lstat()
            value = (process_root / "stat").read_text(encoding="utf-8")
            identity, fields_value = value.rsplit(")", 1)
            fields = fields_value.strip().split()
            parent_pid = int(fields[1])
        except (OSError, UnicodeError, ValueError, IndexError) as exc:
            raise TerminalBrokerError(
                "execution-host terminal executor identity could not be verified"
            ) from exc
        if (
            not stat.S_ISDIR(process.st_mode)
            or not identity.startswith(f"{executor_pid} (")
            or not fields
            or fields[0] == "Z"
            or parent_pid != daemon_peer[0]
            or process.st_uid != daemon_peer[1]
        ):
            raise TerminalBrokerError("execution-host terminal executor identity is invalid")

    def _terminal_result(
        self, receipt: Mapping[str, Any], session_id: str
    ) -> tuple[Mapping[str, Any], int]:
        result = receipt.get("result")
        if not isinstance(result, Mapping):
            raise TerminalBrokerError("execution host returned an invalid terminal session")
        returned_session = result.get("sessionId")
        returned_workspace = result.get("workloadId")
        if (
            not isinstance(returned_session, str)
            or not isinstance(returned_workspace, str)
            or not hmac.compare_digest(returned_session, session_id)
            or not hmac.compare_digest(returned_workspace, self._workspace_id)
            or result.get("targetClass") != "capsule"
            or result.get("reconnect") is not False
        ):
            raise TerminalBrokerError("execution host returned an invalid terminal session")
        executor_pid = result.get("executorPid")
        if (
            isinstance(executor_pid, bool)
            or not isinstance(executor_pid, int)
            or not 1 < executor_pid < 2**31
        ):
            raise TerminalBrokerError("execution host returned an invalid terminal executor identity")
        return result, executor_pid

    def _close_open_attempt(self, session_id: str) -> None:
        try:
            self._client.close_terminal(session_id)
        except Exception:
            pass

    def accept_handshake(
        self,
        handshake: GatewayHandshake,
        *,
        one_use_value: str,
        selected_root: Path | str,
        columns: int = 80,
        rows: int = 24,
    ) -> tuple[TerminalSession, TerminalAuditReceipt]:
        if not isinstance(handshake, GatewayHandshake):
            raise TerminalAccessDenied()
        self._assert_actor(handshake.actor, handshake.instance_id, handshake.origin)
        if Path(selected_root) != Path("/workspace"):
            raise TerminalAccessDenied()
        if not isinstance(one_use_value, str) or len(one_use_value) > 256:
            raise TerminalTokenError()
        if any(
            isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 1000
            for value in (columns, rows)
        ):
            raise ValueError("terminal dimensions must be between 1 and 1000")
        try:
            digest = hashlib.sha256(one_use_value.encode("ascii")).hexdigest()
        except UnicodeEncodeError as exc:
            raise TerminalTokenError() from exc
        with self._mutex:
            self._assert_open()
            pending = self._pending.pop(digest, None)
            if pending is None:
                raise TerminalTokenError()
            checks = (
                pending.expires_at > time.time(),
                hmac.compare_digest(pending.actor_id, handshake.actor.actor_id),
                hmac.compare_digest(pending.instance_id, handshake.instance_id),
                hmac.compare_digest(pending.origin, handshake.origin),
                pending.session_id not in self._sessions,
                pending.session_id not in self._opening,
            )
            if not all(checks):
                raise TerminalTokenError()
            if self._sessions or self._opening or self._closing:
                raise TerminalBrokerError("the selected workspace already has a connected terminal")
            self._opening.add(pending.session_id)

        connection: socket.socket | None = None
        adopted = False
        open_attempted = False
        try:
            open_attempted = True
            open_receipt = self._client.open_terminal(
                self._workspace_id,
                pending.session_id,
                columns=columns,
                rows=rows,
            )
            if not isinstance(open_receipt, Mapping):
                raise TerminalBrokerError("execution host returned an invalid terminal session")
            result, executor_pid = self._terminal_result(open_receipt, pending.session_id)
            socket_path, socket_identity, control_path, control_identity = (
                self._session_socket_path(pending.session_id, result)
            )
            connection, daemon_peer = self._connect_session(
                socket_path, socket_identity, control_path, control_identity
            )
            self._verify_executor_identity(executor_pid, daemon_peer)
            now = time.time()
            session = TerminalSession(
                pending.session_id,
                self._target.target_id,
                "capsule",
                pending.actor_id,
                pending.instance_id,
                "connected",
                _utc(now),
                _utc(now + self._maximum_lifetime_seconds),
                _utc(now),
                # Process/container identity is visible in evidence only as a
                # digest bound to the exact workload, session, and exec pid.
                _digest(f"{self._workspace_id}:{pending.session_id}:{executor_pid}"),
                _digest("/workspace"),
                True,
            )
            live = _Session(
                session=session,
                origin=pending.origin,
                connection=connection,
                executor_pid=executor_pid,
                created_at=now,
                expires_at=now + self._maximum_lifetime_seconds,
                last_activity=now,
            )
            receipt = self._receipt(live, "created", "accepted", "not_required")
            with self._mutex:
                self._assert_open()
                if self._sessions:
                    raise TerminalBrokerError(
                        "the selected workspace already has a connected terminal"
                    )
                self._sessions[session.session_id] = live
                try:
                    self._append_audit(receipt, live.origin)
                except Exception:
                    self._sessions.pop(session.session_id, None)
                    raise
                adopted = True
            return session, receipt
        finally:
            with self._mutex:
                self._opening.discard(pending.session_id)
            if not adopted:
                if connection is not None:
                    connection.close()
                if open_attempted:
                    self._close_open_attempt(pending.session_id)

    def prepare_reconnect(self, *args: Any, **kwargs: Any) -> TerminalReconnectToken:
        raise TerminalAccessDenied()

    def accept_reconnect(self, *args: Any, **kwargs: Any) -> tuple[TerminalSession, TerminalAuditReceipt]:
        raise TerminalAccessDenied()

    # ------------------------------------------------------------ frame I/O

    def handle_frame(
        self,
        handshake: GatewayHandshake,
        *,
        session_id: str,
        frame: GatewayFrame,
    ) -> TerminalInput | TerminalResize | TerminalOutput | TerminalAuditReceipt | tuple[TerminalExit, TerminalAuditReceipt]:
        if not isinstance(frame, GatewayFrame):
            raise TerminalAccessDenied()
        if frame.frame_type == "resize":
            assert frame.columns is not None and frame.rows is not None
            with self._locked_session(handshake, session_id) as live:
                live.last_activity = time.time()
            self._client.resize_terminal(
                session_id, columns=frame.columns, rows=frame.rows
            )
            with self._locked_session(handshake, session_id) as current:
                if current is not live:
                    raise TerminalAccessDenied()
                current.resize_sequence += 1
                current.last_activity = time.time()
                return TerminalResize(
                    session_id, frame.columns, frame.rows, current.resize_sequence
                )
        with self._locked_session(handshake, session_id) as live:
            if frame.frame_type == "input":
                delivered = 0
                deadline = time.monotonic() + _IO_TIMEOUT_SECONDS
                try:
                    while delivered < len(frame.data):
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise TimeoutError
                        _, writable, _ = select.select(
                            [], [live.connection], [], remaining
                        )
                        if not writable:
                            raise TimeoutError
                        try:
                            written = live.connection.send(frame.data[delivered:])
                        except BlockingIOError:
                            continue
                        if written <= 0:
                            raise OSError("terminal socket stopped accepting input")
                        delivered += written
                        live.input_bytes += written
                except (OSError, TimeoutError, ValueError) as exc:
                    self._finish(live, "transport_error")
                    raise TerminalBrokerError(
                        "terminal input could not be delivered"
                    ) from exc
                live.input_sequence += 1
                live.last_activity = time.time()
                return TerminalInput(session_id, len(frame.data), live.input_sequence)
            if frame.frame_type == "replay":
                raise TerminalBrokerError("capsule terminal replay is unavailable")
            return self._finish(
                live, "operator_closed" if frame.frame_type == "close" else "transport_detached"
            )

    def handle_signal(
        self,
        handshake: GatewayHandshake,
        *,
        session_id: str,
        signal: str = "SIGINT",
    ) -> TerminalInput:
        """Deliver a typed signal (SIGINT etc.) through the daemon PTY."""

        if signal not in _SIGNALS:
            raise TerminalBrokerError("unsupported terminal signal")
        with self._locked_session(handshake, session_id) as live:
            live.last_activity = time.time()
        self._client.signal_terminal(session_id, signal=signal)
        with self._locked_session(handshake, session_id) as current:
            if current is not live:
                raise TerminalAccessDenied()
            current.last_activity = time.time()
            current.input_sequence += 1
            return TerminalInput(session_id, 1, current.input_sequence)

    def read_frame(
        self,
        handshake: GatewayHandshake,
        *,
        session_id: str,
        maximum_bytes: int = 65_536,
        timeout_seconds: float = 0.0,
    ) -> TerminalOutput:
        if isinstance(maximum_bytes, bool) or not isinstance(maximum_bytes, int) or not 1 <= maximum_bytes <= 65_536:
            raise ValueError("maximum_bytes must be between 1 and 65536")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not 0 <= timeout_seconds <= _IO_TIMEOUT_SECONDS
        ):
            raise ValueError("timeout_seconds must be between 0 and 1")
        with self._locked_session(handshake, session_id) as live:
            try:
                readable, _, _ = select.select(
                    [live.connection], [], [], float(timeout_seconds)
                )
            except (OSError, ValueError) as exc:
                self._finish(live, "transport_error")
                raise TerminalBrokerError("terminal output could not be read") from exc
            if not readable:
                return TerminalOutput(session_id, b"", live.output_offset, live.output_offset, False, 0, False)
            try:
                data = live.connection.recv(maximum_bytes)
            except BlockingIOError:
                return TerminalOutput(
                    session_id,
                    b"",
                    live.output_offset,
                    live.output_offset,
                    False,
                    0,
                    False,
                )
            except OSError:
                data = b""
            if not data:
                # The daemon relay hung up: the workspace shell exited or the
                # session was cleaned up.  Finish with cleanup evidence.
                self._finish(live, "process_exit")
                return TerminalOutput(session_id, b"", live.output_offset, live.output_offset, False, 0, True)
            start = live.output_offset
            live.output_offset += len(data)
            live.output_bytes += len(data)
            live.last_activity = time.time()
            return TerminalOutput(session_id, data, start, live.output_offset, False, 0, False)

    # --------------------------------------------------------------- finish

    def _finish(self, live: _Session, reason: str) -> tuple[TerminalExit, TerminalAuditReceipt]:
        with live.lock:
            if live.exit_result is not None:
                return live.exit_result
            with self._mutex:
                self._closing.add(live.session.session_id)
                if self._sessions.get(live.session.session_id) is live:
                    self._sessions.pop(live.session.session_id, None)
            try:
                self._client.close_terminal(live.session.session_id)
                cleanup = "terminated"
            except Exception:
                cleanup = "unverified"
            try:
                live.connection.close()
            except OSError:
                pass
            exit_value = TerminalExit(
                live.session.session_id, reason, None, cleanup, _utc(time.time())
            )
            outcome = "completed" if cleanup == "terminated" else "cleanup_failed"
            receipt = self._receipt(live, "closed", outcome, cleanup)
            self._append_audit(receipt, live.origin)
            live.exit_result = exit_value, receipt
            with self._mutex:
                self._closing.discard(live.session.session_id)
            return live.exit_result

    def sweep_expired(self) -> tuple[TerminalExit, ...]:
        with self._mutex:
            if self._closed:
                return ()
            self._cleanup_pending(time.time())
            sessions = tuple(self._sessions.values())
        result: list[TerminalExit] = []
        for live in sessions:
            with live.lock:
                with self._mutex:
                    if self._sessions.get(live.session.session_id) is not live:
                        continue
                reason = self._expiry_reason(live, time.time())
                if reason is not None:
                    result.append(self._finish(live, reason)[0])
        return tuple(result)

    def close(self) -> tuple[TerminalExit, ...]:
        self._stop_sweeper.set()
        with self._mutex:
            if self._closed:
                return ()
            self._closed = True
            self._pending.clear()
            sessions = tuple(self._sessions.values())
        result = [self._finish(live, "broker_shutdown")[0] for live in sessions]
        if threading.current_thread() is not self._sweeper:
            self._sweeper.join(timeout=2.0)
        return tuple(result)

    def __enter__(self) -> "ExecutionHostTerminalGateway":
        return self

    def __exit__(self, _exc_type: Any, _exc: Any, _traceback: Any) -> None:
        self.close()


__all__ = ["ExecutionHostTerminalGateway"]
