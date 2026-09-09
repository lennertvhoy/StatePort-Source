"""Execution-host daemon: versioned JSON over a group-confined Unix socket.

Boot sequence is fail-closed: private state directory, operator-provisioned
socket directory with exact owner/group/mode, engine socket confinement, then
ledger/engine crash reconciliation — and only then does the socket accept
work.  There is no HTTP listener and no mTLS in the alpha; the confinement
boundary is host filesystem ownership plus SO_PEERCRED observation.
"""

from __future__ import annotations

import array
import errno
import fcntl
import grp
import hashlib
import json
import os
import pwd
import select
import socket
import stat
import struct
import subprocess
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping

from . import daemon_contract as contract
from .engine import (
    EngineError,
    KIND_LABEL,
    MANAGED_LABEL_KEY,
    PodmanCliEngine,
    WORKLOAD_LABEL,
    development_seed_identity_error,
)
from .deployment_staging import (
    DeploymentStagingError,
    cleanup_deployment_snapshot_root,
    materialize_deployment_snapshot,
    remove_deployment_snapshot,
)
from .grants import GrantRefusal, GrantStore
from .ledger import LedgerError, OperationLedger, _atomic_write, reconcile_on_boot
from .staging_identity import (
    STAGING_SNAPSHOT_POLICY,
    StagingIdentityError,
    cleanup_staging_snapshot_root,
    create_staging_snapshot,
    remove_staging_snapshot,
)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class DaemonBootError(RuntimeError):
    """Boot refusal: the daemon never starts on a failed safety boundary."""


MAX_CLEANUP_RETRY_ATTEMPTS = 5
MAX_TERMINAL_SESSIONS = 32
TERMINAL_CLEANUP_TIMEOUT_SECONDS = 3.0
_TERMINAL_SIGNAL_BYTES = {"SIGINT": b"\x03", "SIGQUIT": b"\x1c", "SIGTSTP": b"\x1a"}
CLIENT_IDENTITY_FILE = ".stateport-control-client"


@dataclass
class _TerminalSession:
    """One daemon-owned terminal attach: a PTY relay behind a confined socket.

    The session socket lives in the group-confined ``sessions`` directory and
    accepts exactly one connection from an allowed peer uid (the terminal
    broker gateway or the operator CLI).  It is never exposed to a browser.
    """

    session_id: str
    workload_id: str
    process: Any
    master_fd: int
    listener: socket.socket
    socket_path: Path
    socket_identity: tuple[int, int]
    grant_id: str = "unbound"
    closing: threading.Event = field(default_factory=threading.Event)
    cleanup_complete: threading.Event = field(default_factory=threading.Event)
    cleanup_status: str = "unverified"
    mutex: Any = field(default_factory=threading.RLock)


@dataclass
class _WorkloadLock:
    mutex: Any = field(default_factory=threading.RLock)
    users: int = 0


@dataclass(frozen=True)
class DaemonConfig:
    socket_path: Path
    state_dir: Path
    grants_dir: Path | None = None
    workspace_image_reference: str | None = None
    workspace_spec_digest: str | None = None
    socket_group_name: str = "stateport-execution-control"
    socket_group_gid: int | None = None
    allowed_client_user: str = "stateport-control"
    allowed_client_uid: int | None = None
    allowed_client_gid: int | None = None
    runtime_uid: int | None = None
    runtime_gid: int | None = None
    user_namespace: str = "host"
    socket_directory_mode: int = 0o750
    uid_map_path: Path = Path("/proc/self/uid_map")
    gid_map_path: Path = Path("/proc/self/gid_map")
    overflow_uid_path: Path = Path("/proc/sys/kernel/overflowuid")
    overflow_gid_path: Path = Path("/proc/sys/kernel/overflowgid")
    supervise_interval_seconds: float = 0.5
    max_connections: int = 32
    connection_read_timeout_seconds: float = 30.0
    validator_staging_root: Path | None = None
    clock: Callable[[], str] = field(default=_utcnow, compare=False)

    def __post_init__(self) -> None:
        if (self.workspace_image_reference is None) != (self.workspace_spec_digest is None):
            raise DaemonBootError("installed workspace image/spec configuration requires both fields")
        if self.workspace_image_reference is not None:
            try:
                expected = contract.canonical_digest(contract.workspace_template_for_image(self.workspace_image_reference))
            except ValueError as exc:
                raise DaemonBootError("installed workspace image configuration is malformed") from exc
            if expected != self.workspace_spec_digest:
                raise DaemonBootError("installed workspace template digest differs")
        if not self.socket_path.is_absolute() or ".." in self.socket_path.parts:
            raise DaemonBootError("execution-host socket path must be absolute and non-traversing")
        for name, value in (
            ("socket_group_gid", self.socket_group_gid),
            ("allowed_client_uid", self.allowed_client_uid),
            ("allowed_client_gid", self.allowed_client_gid),
            ("runtime_uid", self.runtime_uid),
            ("runtime_gid", self.runtime_gid),
        ):
            if value is not None and (type(value) is not int or not 0 <= value <= 2**31 - 1):
                raise DaemonBootError(f"{name} must be an explicit numeric identity")
        if self.user_namespace not in {"host", "keep-id"}:
            raise DaemonBootError("execution-host user namespace must be host or keep-id")
        if self.socket_directory_mode not in {0o750, 0o2750}:
            raise DaemonBootError("socket directory mode must be 0750 or 2750")
        if self.user_namespace == "keep-id" and self.socket_directory_mode != 0o2750:
            raise DaemonBootError("keep-id requires a setgid 2750 socket directory")

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "DaemonConfig":
        env = dict(os.environ if env is None else env)
        socket_path = Path(
            env.get(
                "STATEPORT_EXECUTION_HOST_SOCKET",
                env.get("STATEPORT_HOST_SOCKET", "/run/stateport/execution-control/control.sock"),
            )
        )
        gid_raw = env.get("STATEPORT_EXECUTION_HOST_SOCKET_GROUP_GID")
        client_uid_raw = env.get("STATEPORT_EXECUTION_HOST_ALLOWED_CLIENT_UID")
        client_gid_raw = env.get("STATEPORT_EXECUTION_HOST_ALLOWED_CLIENT_GID")
        runtime_uid_raw = env.get("STATEPORT_EXECUTION_HOST_RUNTIME_UID")
        runtime_gid_raw = env.get("STATEPORT_EXECUTION_HOST_RUNTIME_GID")
        grants_raw = env.get("STATEPORT_EXECUTION_HOST_GRANTS_DIR")
        user_namespace = env.get("STATEPORT_EXECUTION_HOST_USER_NAMESPACE", "host")
        directory_mode_raw = env.get("STATEPORT_EXECUTION_HOST_SOCKET_DIRECTORY_MODE", "0750")

        def numeric(name: str, raw: str | None) -> int | None:
            if raw is None:
                return None
            try:
                value = int(raw, 10)
            except ValueError as exc:
                raise DaemonBootError(f"{name} must be a decimal numeric identity") from exc
            if value < 0 or value > 2**31 - 1:
                raise DaemonBootError(f"{name} is outside the supported numeric identity range")
            return value

        if env.get("STATEPORT_EXECUTION_HOST_REQUIRE_NUMERIC_HANDOFF") == "1":
            required = {
                "STATEPORT_EXECUTION_HOST_SOCKET_GROUP_GID": gid_raw,
                "STATEPORT_EXECUTION_HOST_ALLOWED_CLIENT_UID": client_uid_raw,
                "STATEPORT_EXECUTION_HOST_ALLOWED_CLIENT_GID": client_gid_raw,
                "STATEPORT_EXECUTION_HOST_RUNTIME_UID": runtime_uid_raw,
                "STATEPORT_EXECUTION_HOST_RUNTIME_GID": runtime_gid_raw,
            }
            missing = [name for name, value in required.items() if value is None]
            if missing:
                raise DaemonBootError(
                    "explicit host numeric identity handoff is required; missing "
                    + ", ".join(missing)
                )
        try:
            directory_mode = int(directory_mode_raw, 8)
        except ValueError as exc:
            raise DaemonBootError(
                "STATEPORT_EXECUTION_HOST_SOCKET_DIRECTORY_MODE must be octal"
            ) from exc
        return cls(
            socket_path=socket_path,
            state_dir=Path(
                env.get("STATEPORT_EXECUTION_HOST_STATE_DIR", "/var/lib/stateport/execution-host")
            ),
            grants_dir=Path(grants_raw) if grants_raw else None,
            workspace_image_reference=env.get("STATEPORT_EXECUTION_HOST_WORKSPACE_IMAGE_REFERENCE"),
            workspace_spec_digest=env.get("STATEPORT_EXECUTION_HOST_WORKSPACE_SPEC_DIGEST"),
            socket_group_name=env.get(
                "STATEPORT_EXECUTION_HOST_SOCKET_GROUP", "stateport-execution-control"
            ),
            socket_group_gid=numeric("STATEPORT_EXECUTION_HOST_SOCKET_GROUP_GID", gid_raw),
            allowed_client_user=env.get(
                "STATEPORT_EXECUTION_HOST_ALLOWED_CLIENT_USER", "stateport-control"
            ),
            allowed_client_uid=numeric("STATEPORT_EXECUTION_HOST_ALLOWED_CLIENT_UID", client_uid_raw),
            allowed_client_gid=numeric("STATEPORT_EXECUTION_HOST_ALLOWED_CLIENT_GID", client_gid_raw),
            runtime_uid=numeric("STATEPORT_EXECUTION_HOST_RUNTIME_UID", runtime_uid_raw),
            runtime_gid=numeric("STATEPORT_EXECUTION_HOST_RUNTIME_GID", runtime_gid_raw),
            user_namespace=user_namespace,
            socket_directory_mode=directory_mode,
            validator_staging_root=(
                Path(env["STATEPORT_EXECUTION_HOST_VALIDATOR_STAGING_DIR"])
                if env.get("STATEPORT_EXECUTION_HOST_VALIDATOR_STAGING_DIR")
                else None
            ),
        )


class ExecutionHostDaemon:
    def __init__(
        self,
        config: DaemonConfig,
        engine: Any,
        *,
        deployment_adapter: Any | None = None,
    ) -> None:
        self._config = config
        self._engine = engine
        self._deployment_adapter = deployment_adapter
        self._ledger: OperationLedger | None = None
        self._grants: GrantStore | None = None
        self._server: socket.socket | None = None
        self._shutdown = threading.Event()
        self._threads: list[threading.Thread] = []
        self._connection_slots = threading.BoundedSemaphore(config.max_connections)
        self._terminal_sessions: dict[str, _TerminalSession] = {}
        self._terminal_mutex = threading.RLock()
        self._workload_locks: dict[str, _WorkloadLock] = {}
        self._workload_locks_guard = threading.Lock()
        # Workspace activity: monotonic last-activity per workload id.  The
        # durable mirror is the ledger ``lastActivityAt`` field; the idle
        # supervisor reads the freshest of the two.
        self._activity: dict[str, float] = {}
        self.recovery_report: dict[str, Any] | None = None
        self._server_socket_identity: tuple[int, int] | None = None
        self._bound_client: tuple[int, int] | None = None
        self._socket_lock_fd: int | None = None
        self._socket_directory_fd: int | None = None
        self._terminal_directory_fd: int | None = None

    # ------------------------------------------------------------------ boot

    def _runtime_uid(self) -> int:
        return os.geteuid() if self._config.runtime_uid is None else self._config.runtime_uid

    def _runtime_gid(self) -> int:
        return os.getegid() if self._config.runtime_gid is None else self._config.runtime_gid

    def _host_runtime_identity(self) -> tuple[int, int]:
        return (
            os.geteuid() if self._config.runtime_uid is None else self._config.runtime_uid,
            os.getegid() if self._config.runtime_gid is None else self._config.runtime_gid,
        )

    @staticmethod
    def _id_map_has_keep_id(path: Path, identity: int) -> bool:
        try:
            mappings = [
                tuple(int(item, 10) for item in line.split())
                for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        except (OSError, UnicodeError, ValueError) as exc:
            raise DaemonBootError(f"cannot read user-namespace identity map: {path}") from exc
        # Rootless Podman maps the invoking host user to ID 0 in its
        # intermediate namespace, then keep-id exposes that ID in the container.
        return (identity, 0, 1) in mappings

    @staticmethod
    def _overflow_identity(path: Path) -> int:
        try:
            value = int(path.read_text(encoding="utf-8").strip(), 10)
        except (OSError, UnicodeError, ValueError) as exc:
            raise DaemonBootError(f"cannot read namespace overflow identity: {path}") from exc
        if value < 0 or value > 2**31 - 1:
            raise DaemonBootError(f"namespace overflow identity is unsafe: {value}")
        return value

    def _uses_keep_id(self) -> bool:
        return self._config.user_namespace == "keep-id"

    def _namespace_allowed_client_identity(self) -> tuple[int, int] | None:
        client = self._allowed_client_identity()
        if client is None or not self._uses_keep_id():
            return client
        return (
            self._overflow_identity(self._config.overflow_uid_path),
            self._overflow_identity(self._config.overflow_gid_path),
        )

    def _canonical_peer_identity(self, peer: Mapping[str, int]) -> dict[str, int]:
        canonical = dict(peer)
        if not self._uses_keep_id():
            return canonical
        observed = (peer.get("uid"), peer.get("gid"))
        client = self._allowed_client_identity()
        bound = self._bound_client_identity()
        if bound is not None and observed == bound:
            canonical["uid"], canonical["gid"] = bound
        elif client is not None and observed == self._namespace_allowed_client_identity():
            canonical["uid"], canonical["gid"] = client
        elif observed == (self._runtime_uid(), self._runtime_gid()):
            canonical["uid"], canonical["gid"] = self._host_runtime_identity()
        return canonical

    def _allowed_client_identity(self) -> tuple[int, int] | None:
        if self._config.allowed_client_uid is not None:
            return self._config.allowed_client_uid, (
                self._config.allowed_client_gid
                if self._config.allowed_client_gid is not None
                else self._runtime_gid()
            )
        try:
            client = pwd.getpwnam(self._config.allowed_client_user)
        except KeyError:
            return None
        return client.pw_uid, self._config.allowed_client_gid or client.pw_gid

    def _bound_client_identity(self) -> tuple[int, int] | None:
        """The provisioning-bound real client, carried by the root-owned
        identity file inside the confined socket directory.

        The daemon container cannot resolve the host group database, so the
        provisioning transaction records the exact host identity it admitted.
        keep-id maps the invoking host user to the same UID, so the peer's
        in-namespace identity is directly comparable.  A present but malformed
        file is a host-integrity failure and refuses boot.
        """
        if self._bound_client is not None:
            return self._bound_client
        path = self._config.socket_path.parent / CLIENT_IDENTITY_FILE
        try:
            content = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise DaemonBootError(f"cannot read the confined client identity file: {path}") from exc
        try:
            uid_raw, gid_raw = content.strip().split(":", 1)
            uid, gid = int(uid_raw), int(gid_raw)
        except (ValueError, TypeError) as exc:
            raise DaemonBootError(f"the confined client identity file is malformed: {path}") from exc
        if uid < 1 or gid < 1 or uid > 2**31 - 1 or gid > 2**31 - 1:
            raise DaemonBootError(f"the confined client identity is unsafe: {path}")
        self._bound_client = (uid, gid)
        return self._bound_client

    def _expected_socket_gid(self) -> int | None:
        if self._config.socket_group_gid is not None:
            if self._uses_keep_id() and self._config.socket_group_gid != self._config.runtime_gid:
                return self._overflow_identity(self._config.overflow_gid_path)
            return self._config.socket_group_gid
        try:
            return grp.getgrnam(self._config.socket_group_name).gr_gid
        except KeyError:
            return None

    def _peer_is_authorized(self, peer: Mapping[str, int]) -> bool:
        expected = {self._host_runtime_identity()}
        client = self._allowed_client_identity()
        if client is not None:
            expected.add(client)
        bound = self._bound_client_identity()
        if bound is not None:
            expected.add(bound)
        return (peer.get("uid"), peer.get("gid")) in expected

    def _assert_runtime_identity(self) -> None:
        observed = (os.geteuid(), os.getegid())
        expected = (self._runtime_uid(), self._runtime_gid())
        if observed != expected:
            raise DaemonBootError(
                f"runtime identity mismatch: observed {observed[0]}:{observed[1]}, "
                f"expected {expected[0]}:{expected[1]}"
            )
        if self._uses_keep_id() and (
            not self._id_map_has_keep_id(self._config.uid_map_path, observed[0])
            or not self._id_map_has_keep_id(self._config.gid_map_path, observed[1])
        ):
            raise DaemonBootError("runtime identity is not bound by the declared keep-id mapping")
        expected_gid = self._expected_socket_gid()
        if expected_gid is None:
            raise DaemonBootError("socket group is not resolvable")
        if expected_gid != self._runtime_gid() and expected_gid not in os.getgroups():
            raise DaemonBootError(f"runtime identity lacks socket group gid {expected_gid}")

    @staticmethod
    def _assert_real_path(path: Path, *, label: str) -> None:
        if not path.is_absolute() or ".." in path.parts:
            raise DaemonBootError(f"{label} is an unsafe absolute path: {path}")
        current = Path("/")
        for component in path.parts[1:]:
            current /= component
            try:
                observed = os.lstat(current)
            except FileNotFoundError as exc:
                raise DaemonBootError(f"{label} path component is absent: {current}") from exc
            if stat.S_ISLNK(observed.st_mode):
                raise DaemonBootError(f"{label} path component is a symlink: {current}")

    def _assert_socket_directory(self) -> None:
        directory = self._config.socket_path.parent
        self._assert_real_path(directory, label="socket directory")
        observed = os.lstat(directory)
        if not stat.S_ISDIR(observed.st_mode):
            raise DaemonBootError(
                f"socket directory {directory} is absent; it is operator-provisioned (tmpfiles) "
                "and the daemon must not create it"
            )
        if observed.st_uid != self._runtime_uid():
            raise DaemonBootError(
                f"socket directory {directory} is owned by uid {observed.st_uid}, not the daemon uid {self._runtime_uid()}"
            )
        expected_gid = self._expected_socket_gid()
        if expected_gid is None:
            raise DaemonBootError(
                f"socket group {self._config.socket_group_name!r} is not resolvable; refusing to guess confinement"
            )
        if observed.st_gid != expected_gid:
            raise DaemonBootError(
                f"socket directory {directory} has group {observed.st_gid}, expected {expected_gid} "
                f"({self._config.socket_group_name}); group confinement failed"
            )
        if stat.S_IMODE(observed.st_mode) != self._config.socket_directory_mode:
            raise DaemonBootError(
                f"socket directory {directory} has mode {oct(stat.S_IMODE(observed.st_mode))}, "
                f"expected {oct(self._config.socket_directory_mode)}"
            )

    def _open_socket_directory_fd(self) -> None:
        try:
            fd = os.open(
                str(self._config.socket_path.parent),
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
        except OSError as exc:
            raise DaemonBootError(f"cannot open stable socket directory: {exc}") from exc
        try:
            descriptor_stat = os.fstat(fd)
            path_stat = os.lstat(self._config.socket_path.parent)
            if (
                descriptor_stat.st_dev,
                descriptor_stat.st_ino,
                descriptor_stat.st_uid,
                descriptor_stat.st_gid,
                stat.S_IMODE(descriptor_stat.st_mode),
            ) != (
                path_stat.st_dev,
                path_stat.st_ino,
                self._runtime_uid(),
                self._expected_socket_gid(),
                self._config.socket_directory_mode,
            ):
                raise DaemonBootError("socket directory changed while opening its stable descriptor")
        except Exception:
            os.close(fd)
            raise
        self._socket_directory_fd = fd
        try:
            self._assert_socket_directory_binding()
        except Exception:
            self._release_socket_directory_fd()
            raise

    def _release_socket_directory_fd(self) -> None:
        fd, self._socket_directory_fd = self._socket_directory_fd, None
        if fd is not None:
            os.close(fd)

    def _assert_socket_directory_binding(self) -> None:
        directory_fd = self._socket_directory_fd
        if directory_fd is None:
            raise DaemonBootError("socket directory descriptor is not held")
        try:
            descriptor_stat = os.fstat(directory_fd)
            path_stat = os.lstat(self._config.socket_path.parent)
        except OSError as exc:
            raise DaemonBootError(f"socket directory binding is unavailable: {exc}") from exc
        if (
            descriptor_stat.st_dev,
            descriptor_stat.st_ino,
            descriptor_stat.st_uid,
            descriptor_stat.st_gid,
            stat.S_IMODE(descriptor_stat.st_mode),
        ) != (
            path_stat.st_dev,
            path_stat.st_ino,
            self._runtime_uid(),
            self._expected_socket_gid(),
            self._config.socket_directory_mode,
        ):
            raise DaemonBootError(
                "socket directory was renamed or changed while the daemon was starting"
            )

    def _socket_descriptor_path(self) -> str:
        directory_fd = self._socket_directory_fd
        if directory_fd is None:
            raise DaemonBootError("socket directory descriptor is not held")
        return f"/proc/self/fd/{directory_fd}/{self._config.socket_path.name}"

    def _socket_stat(self, *, allow_absent: bool) -> os.stat_result | None:
        directory_fd = self._socket_directory_fd
        try:
            if directory_fd is None:
                observed = os.lstat(self._config.socket_path)
            else:
                observed = os.stat(
                    self._config.socket_path.name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
        except FileNotFoundError:
            if allow_absent:
                return None
            raise DaemonBootError(f"socket path is absent: {self._config.socket_path}")
        return observed

    def _assert_socket_inode(self, *, allow_absent: bool) -> os.stat_result | None:
        observed = self._socket_stat(allow_absent=allow_absent)
        if observed is None:
            return None
        if stat.S_ISLNK(observed.st_mode):
            raise DaemonBootError(f"socket path is a symlink: {self._config.socket_path}")
        if not stat.S_ISSOCK(observed.st_mode):
            raise DaemonBootError(f"socket path is not a unix socket: {self._config.socket_path}")
        expected = (self._runtime_uid(), self._expected_socket_gid(), 0o660)
        actual = (observed.st_uid, observed.st_gid, stat.S_IMODE(observed.st_mode))
        if actual != expected:
            raise DaemonBootError(
                f"socket ownership/mode mismatch: observed {actual[0]}:{actual[1]} "
                f"{oct(actual[2])}, expected {expected[0]}:{expected[1]} {oct(expected[2])}"
            )
        return observed

    def _acquire_socket_lock(self) -> None:
        directory_fd = self._socket_directory_fd
        if directory_fd is None:
            raise DaemonBootError("socket directory descriptor is not held")
        self._assert_socket_directory_binding()
        lock_name = f".{self._config.socket_path.name}.lock"
        try:
            fd = os.open(
                lock_name,
                os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
                dir_fd=directory_fd,
            )
        except OSError as exc:
            raise DaemonBootError(f"cannot open socket writer lock: {exc}") from exc
        try:
            observed = os.fstat(fd)
            if observed.st_uid != self._runtime_uid() or stat.S_IMODE(observed.st_mode) != 0o600:
                raise DaemonBootError("socket writer lock ownership/mode mismatch")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except (BlockingIOError, OSError) as exc:
                if isinstance(exc, BlockingIOError) or exc.errno in {errno.EACCES, errno.EAGAIN}:
                    raise DaemonBootError("another daemon owns the execution-host socket writer lock") from exc
                raise DaemonBootError(f"cannot lock execution-host socket writer lock: {exc}") from exc
        except Exception:
            os.close(fd)
            raise
        self._socket_lock_fd = fd

    def _release_socket_lock(self) -> None:
        fd, self._socket_lock_fd = self._socket_lock_fd, None
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def _reclaim_stale_socket(self) -> None:
        raise DaemonBootError(
            "stale execution-host socket requires operator removal; daemon will not remove it"
        )

    def _assert_state_directory(self) -> None:
        state_dir = self._config.state_dir
        state_dir.mkdir(parents=True, exist_ok=True)
        stat = state_dir.stat()
        if stat.st_uid != os.geteuid():
            raise DaemonBootError(f"state directory {state_dir} is not owned by the daemon uid")
        os.chmod(state_dir, 0o700)

    def _verify_workspace_image_authority(self) -> None:
        """Validate fixed installed base authority, never a caller-selected grant."""
        reference = self._config.workspace_image_reference
        if reference is None:
            raise GrantRefusal("workspace-image-unavailable", "installed workspace image binding is absent")
        grant = self._grant_store().assert_live("control-plane-default")
        expected = contract.canonical_digest(contract.workspace_template_for_image(reference))
        if (grant["imageReference"] != reference or expected != self._config.workspace_spec_digest
                or grant["workloadSpecDigests"].get("default-dev") != expected
                or grant["workloadIds"] != ["default-dev"] or grant["workloadKinds"] != ["workspace"]
                or (self._config.allowed_client_uid is not None and grant["peerUid"] != self._config.allowed_client_uid)) :
            raise GrantRefusal("workspace-image-mismatch", "private default grant contradicts the installed workspace template")

    def _grants_directory(self) -> Path:
        return self._config.grants_dir or (self._config.state_dir / "grants")

    def _assert_grants_directory(self) -> Path:
        grants_dir = self._grants_directory()
        grants_dir.mkdir(parents=True, exist_ok=True)
        stat = grants_dir.stat()
        if stat.st_uid != os.geteuid():
            raise DaemonBootError(f"grants directory {grants_dir} is not owned by the daemon uid")
        os.chmod(grants_dir, 0o700)
        # Daemon-owned initialization: an absent revocation document is
        # created exactly once with the empty revocation state.  After boot,
        # a missing or corrupt document is tampering and fails closed.
        revocation = grants_dir / "revocation.json"
        empty = b'{"revokedGrantIds": [], "pausedGrantIds": [], "revocationEpoch": 0}\n'
        try:
            fd = os.open(str(revocation), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, "wb") as handle:
                handle.write(empty)
        return grants_dir

    def _terminal_directory(self) -> Path:
        return self._config.socket_path.parent / "sessions"

    def _assert_terminal_directory_binding(self) -> None:
        directory_fd = self._terminal_directory_fd
        if directory_fd is None:
            raise DaemonBootError("terminal session directory descriptor is not held")
        try:
            descriptor_stat = os.fstat(directory_fd)
            path_stat = os.lstat(self._terminal_directory())
        except OSError as exc:
            raise DaemonBootError(f"terminal session directory binding is unavailable: {exc}") from exc
        if (
            descriptor_stat.st_dev,
            descriptor_stat.st_ino,
            descriptor_stat.st_uid,
            descriptor_stat.st_gid,
            stat.S_IMODE(descriptor_stat.st_mode),
        ) != (
            path_stat.st_dev,
            path_stat.st_ino,
            self._runtime_uid(),
            self._expected_socket_gid(),
            self._config.socket_directory_mode,
        ):
            raise DaemonBootError(
                "terminal session directory was renamed or changed while the session was opening"
            )

    def _release_terminal_directory_fd(self) -> None:
        fd, self._terminal_directory_fd = self._terminal_directory_fd, None
        if fd is not None:
            os.close(fd)

    def _validator_snapshots_root(self) -> Path:
        return self._config.state_dir / "validator-snapshots"

    def _deployment_snapshots_root(self) -> Path:
        return self._config.state_dir / "deployment-snapshots"

    def _assert_terminal_directory(self) -> Path:
        parent_fd = self._socket_directory_fd
        if parent_fd is None:
            raise DaemonBootError("socket directory descriptor is not held")
        directory_name = self._terminal_directory().name
        try:
            fd = os.open(
                directory_name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
        except FileNotFoundError:
            try:
                os.mkdir(directory_name, self._config.socket_directory_mode, dir_fd=parent_fd)
                fd = os.open(
                    directory_name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=parent_fd,
                )
            except OSError as exc:
                raise DaemonBootError(f"cannot open terminal session directory: {exc}") from exc
        except OSError as exc:
            raise DaemonBootError(f"cannot open terminal session directory: {exc}") from exc
        try:
            observed = os.fstat(fd)
            if not stat.S_ISDIR(observed.st_mode):
                raise DaemonBootError("terminal session directory is not a real directory")
            if observed.st_uid != self._runtime_uid():
                raise DaemonBootError("terminal session directory is not owned by the daemon uid")
            if self._uses_keep_id():
                if observed.st_gid != self._expected_socket_gid():
                    raise DaemonBootError(
                        "terminal session directory did not inherit the confined socket group"
                    )
            else:
                os.fchown(fd, self._runtime_uid(), self._expected_socket_gid())
            os.fchmod(fd, self._config.socket_directory_mode)
            self._terminal_directory_fd = fd
        except Exception:
            os.close(fd)
            raise
        for name in os.listdir(fd):
            if not name.endswith(".sock"):
                continue
            try:
                path_stat = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(path_stat.st_mode) or not stat.S_ISSOCK(path_stat.st_mode):
                raise DaemonBootError(f"unexpected terminal session path: {name}")
            raise DaemonBootError(
                f"stale terminal session socket requires operator removal: {name}"
            )
        return self._terminal_directory()

    def _terminal_socket_descriptor_path(self, name: str) -> str:
        directory_fd = self._terminal_directory_fd
        if directory_fd is None:
            raise DaemonBootError("terminal session directory descriptor is not held")
        return f"/proc/self/fd/{directory_fd}/{name}"

    def _unlink_owned_socket(
        self,
        *,
        directory_fd: int | None,
        socket_name: str,
        socket_identity: tuple[int, int],
    ) -> None:
        if directory_fd is None:
            return
        try:
            observed = os.stat(socket_name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        if (
            not stat.S_ISSOCK(observed.st_mode)
            or (observed.st_dev, observed.st_ino) != socket_identity
            or observed.st_uid != self._runtime_uid()
            or observed.st_gid != self._expected_socket_gid()
            or stat.S_IMODE(observed.st_mode) != 0o660
        ):
            return
        try:
            os.unlink(socket_name, dir_fd=directory_fd)
        except OSError:
            pass

    def _unlink_owned_terminal_socket(self, session: _TerminalSession) -> None:
        self._unlink_owned_socket(
            directory_fd=self._terminal_directory_fd,
            socket_name=session.socket_path.name,
            socket_identity=session.socket_identity,
        )

    def boot(self) -> None:
        self._assert_state_directory()
        self._assert_socket_directory()
        self._assert_runtime_identity()
        self._open_socket_directory_fd()
        try:
            self._acquire_socket_lock()
            self._assert_socket_directory_binding()
            self._assert_terminal_directory()
            grants_dir = self._assert_grants_directory()
            self._grants = GrantStore(grants_dir, clock=self._config.clock)
            if self._config.workspace_image_reference is not None:
                binder = getattr(self._engine, "bind_workspace_image_authority", None)
                if not callable(binder):
                    raise DaemonBootError("engine cannot bind installed workspace image authority")
                binder(self._config.workspace_image_reference, self._verify_workspace_image_authority)
            self._ledger = OperationLedger(self._config.state_dir)
            self.recovery_report = reconcile_on_boot(
                self._ledger, self._engine, at=self._config.clock()
            )
            if self.recovery_report["failures"]:
                raise DaemonBootError(
                    f"restart reconciliation failed: {self.recovery_report['failures']}"
                )
            try:
                # Validators are never adopted across an epoch. Reconciliation has
                # now removed every validator container, so stale private snapshots
                # can be deterministically reclaimed before accepting new work.
                cleanup_staging_snapshot_root(self._validator_snapshots_root())
            except StagingIdentityError as exc:
                raise DaemonBootError(f"validator snapshot recovery failed: {exc}") from exc
            try:
                # Deployment snapshots are transfer-only and never canonical
                # state. Any interrupted effect is reconciled by the governed
                # deployment store against directly observed Podman state.
                cleanup_deployment_snapshot_root(self._deployment_snapshots_root())
            except DeploymentStagingError as exc:
                raise DaemonBootError(f"deployment snapshot recovery failed: {exc}") from exc
            self.recovery_report["deploymentOperationsInterrupted"] = (
                self._ledger.interrupt_deployment_operations(at=self._config.clock())
            )
        except Exception:
            self._release_socket_lock()
            self._release_terminal_directory_fd()
            self._release_socket_directory_fd()
            raise
        server: socket.socket | None = None
        try:
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            existing = self._assert_socket_inode(allow_absent=True)
            if existing is not None:
                probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    probe.connect(self._socket_descriptor_path())
                except OSError as exc:
                    if exc.errno not in {errno.ECONNREFUSED, errno.ENOENT, errno.ECONNRESET}:
                        raise DaemonBootError(
                            f"cannot determine whether stale socket is safe to reclaim: {exc}"
                        ) from exc
                    self._reclaim_stale_socket()
                else:
                    raise DaemonBootError(
                        f"a live daemon already owns {self._config.socket_path}; refusing a second writer"
                    )
                finally:
                    probe.close()
            try:
                self._assert_socket_directory_binding()
                server.bind(self._socket_descriptor_path())
            except OSError as exc:
                raise DaemonBootError(f"cannot bind {self._config.socket_path}: {exc}") from exc
            expected_gid = self._expected_socket_gid()
            socket_path = self._socket_descriptor_path()
            if not self._uses_keep_id():
                os.chown(socket_path, self._runtime_uid(), expected_gid)
            os.chmod(socket_path, 0o660)
            bound = self._assert_socket_inode(allow_absent=False)
            assert bound is not None
            self._assert_socket_directory_binding()
            self._server_socket_identity = (bound.st_dev, bound.st_ino)
            server.listen(16)
            server.settimeout(0.5)
            self._server = server
        except Exception:
            if server is not None:
                server.close()
            self._release_socket_lock()
            self._release_terminal_directory_fd()
            self._release_socket_directory_fd()
            raise
        supervisor = threading.Thread(target=self._supervise, name="exec-host-supervisor", daemon=True)
        supervisor.start()
        self._threads.append(supervisor)

    def shutdown(self) -> None:
        self._shutdown.set()
        with self._terminal_mutex:
            sessions = tuple(self._terminal_sessions.values())
        for session in sessions:
            self._close_terminal_session(session)
        if self._server is not None:
            try:
                self._server.close()
            except OSError:
                pass
        for thread in self._threads:
            thread.join(timeout=5)
        self._unlink_owned_socket(
            directory_fd=self._socket_directory_fd,
            socket_name=self._config.socket_path.name,
            socket_identity=self._server_socket_identity or (-1, -1),
        )
        self._release_socket_lock()
        self._release_terminal_directory_fd()
        self._release_socket_directory_fd()

    # ---------------------------------------------------- terminal sessions

    def _close_terminal_session(self, session: _TerminalSession) -> None:
        with session.mutex:
            if session.closing.is_set():
                return
            session.closing.set()
            try:
                # Wake an unattached relay blocked in accept() so bounded
                # close requests can observe its completion promptly.
                session.listener.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                session.listener.close()
            except OSError:
                pass
            try:
                session.process.kill()
            except OSError:
                pass

    def _close_sessions_for(self, workload_id: str) -> None:
        with self._terminal_mutex:
            sessions = [
                session
                for session in self._terminal_sessions.values()
                if session.workload_id == workload_id
            ]
        for session in sessions:
            self._close_terminal_session(session)

    @contextmanager
    def _workload_lock(self, workload_id: str) -> Iterator[None]:
        """Serialize one workload without blocking operations on other ids."""

        with self._workload_locks_guard:
            lock = self._workload_locks.get(workload_id)
            if lock is None:
                lock = _WorkloadLock()
                self._workload_locks[workload_id] = lock
            lock.users += 1
        acquired = False
        try:
            lock.mutex.acquire()
            acquired = True
            yield
        finally:
            if acquired:
                lock.mutex.release()
            with self._workload_locks_guard:
                lock.users -= 1
                if lock.users == 0 and self._workload_locks.get(workload_id) is lock:
                    del self._workload_locks[workload_id]

    def _touch_activity(self, workload_id: str, *, persist: bool = True) -> None:
        """Record real workspace activity (terminal/exec/attach), not lifetime."""

        with self._workload_lock(workload_id):
            self._activity[workload_id] = time.monotonic()
            ledger = self._ledger
            if not persist or ledger is None:
                return
            entry = ledger.get(workload_id)
            if entry is None or entry["state"] in contract.TERMINAL_STATES:
                return
            touched_at = self._config.clock()
            ledger.transition(
                workload_id,
                entry["state"],
                at=touched_at,
                extra={"lastActivityAt": touched_at},
                expect_states={entry["state"]},
                expect_version=int(entry["version"]),
            )

    def _serve_terminal(self, session: _TerminalSession) -> None:
        connection: socket.socket | None = None
        try:
            session.listener.settimeout(30.0)
            try:
                connection, _ = session.listener.accept()
            except (OSError, socket.timeout):
                return
            peer = self._peer_credentials(connection)
            if not self._peer_is_authorized(peer):
                return
            connection.setblocking(False)
            while not session.closing.is_set() and not self._shutdown.is_set():
                readable, _, _ = select.select([connection, session.master_fd], [], [], 0.25)
                if connection in readable:
                    try:
                        data = connection.recv(65_536)
                    except OSError:
                        return
                    if not data:
                        return
                    self._touch_activity(session.workload_id, persist=False)
                    pending = data
                    while pending:
                        try:
                            written = os.write(session.master_fd, pending)
                        except BlockingIOError:
                            select.select([], [session.master_fd], [], 0.25)
                            continue
                        except OSError:
                            return
                        if written <= 0:
                            return
                        pending = pending[written:]
                if session.master_fd in readable:
                    try:
                        data = os.read(session.master_fd, 65_536)
                    except OSError as exc:
                        if exc.errno in {errno.EIO, errno.EBADF}:
                            return
                        raise
                    if not data:
                        return
                    self._touch_activity(session.workload_id, persist=False)
                    try:
                        connection.sendall(data)
                    except OSError:
                        return
        except (OSError, ValueError):
            return
        finally:
            cleanup_status = "completed"
            if connection is not None:
                try:
                    connection.close()
                except OSError:
                    pass
            try:
                session.process.kill()
            except OSError:
                pass
            try:
                session.process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired, TimeoutError):
                cleanup_status = "unverified"
            with session.mutex:
                master_fd, session.master_fd = session.master_fd, -1
                if master_fd >= 0:
                    try:
                        os.close(master_fd)
                    except OSError:
                        pass
            try:
                session.listener.close()
            except OSError:
                pass
            self._unlink_owned_terminal_socket(session)
            with self._terminal_mutex:
                self._terminal_sessions.pop(session.session_id, None)
            # Publish completion before touching the workload ledger.  The
            # close dispatcher holds that workload lock while requesting
            # cleanup and must be able to wait without a lock inversion.
            with session.mutex:
                session.cleanup_status = cleanup_status
                session.cleanup_complete.set()
            # The session end is the last durable activity of this attach.
            try:
                self._touch_activity(session.workload_id)
            except (LedgerError, KeyError):
                pass

    # ------------------------------------------------------------ supervision

    def _supervise(self) -> None:
        while not self._shutdown.wait(self._config.supervise_interval_seconds):
            ledger = self._ledger
            if ledger is None:
                continue
            try:
                entries = ledger.all()
            except LedgerError:
                # A corrupt entry must not kill supervision; the next sweep
                # retries, and boot reconciliation owns store repair.
                continue
            for entry in entries:
                try:
                    workload_id = str(entry["workloadId"])
                    with self._workload_lock(workload_id):
                        current = ledger.get(workload_id)
                        if current is not None:
                            self._supervise_entry(ledger, current)
                except LedgerError:
                    # A racing transition (cancel/finalize) invalidated this
                    # stale snapshot entry; supervision must never die.
                    continue

    def _supervise_entry(self, ledger: OperationLedger, entry: Mapping[str, Any]) -> None:
        if entry["state"] == "cleanup_failed":
            self._retry_cleanup(ledger, entry)
            return
        if entry["state"] in contract.TERMINAL_STATES:
            if entry["state"] != "removed":
                ledger.capture_source_command_output(entry, self._engine, at=self._config.clock(), termination_reason=str(entry["state"]))
            return
        # Withdrawn authority terminates or quarantines active work
        # immediately — before any idle/timeout bookkeeping.
        if self._enforce_grant_liveness(ledger, entry):
            return
        if entry["state"] != "running" or not entry.get("startedAt"):
            return
        if entry["spec"].get("kind") == "agent-run" and "sourceArchive" in entry["spec"]["parameters"]:
            info = self._safe_inspect(entry["workloadId"])
            if info.get("present") is True and info.get("running") is False:
                entry = ledger.capture_source_command_output(entry, self._engine, at=self._config.clock(), termination_reason="exited")
                self._transition_snapshot(ledger, entry, "exited", at=self._config.clock(), finished_at=self._config.clock(), exit_status=info.get("exitStatus"))
                return
        if entry["spec"].get("kind") == "workspace":
            # Workspaces are bounded by real inactivity (terminal,
            # exec, attach), never by total lifetime.
            self._supervise_workspace_idle(ledger, entry)
            return
        try:
            started = datetime.fromisoformat(entry["startedAt"].replace("Z", "+00:00"))
            elapsed = (datetime.now(timezone.utc) - started).total_seconds()
        except (ValueError, TypeError):
            return
        if elapsed <= entry["spec"]["timeoutSeconds"]:
            return
        workload_id = entry["workloadId"]
        cleanup = "performed"
        entry = ledger.mark_source_termination(entry, at=self._config.clock(), reason="timed_out")
        try:
            self._engine.stop(workload_id, timeout=2, expected_container_id=self._engine_target(entry))
        except EngineError as exc:
            cleanup = f"failed: {exc}"[:200]
        observed = self._safe_inspect(workload_id)
        inspection_unknown = observed.get("present") is None or (
            observed.get("present") is True and observed.get("running") is None
        )
        if cleanup != "performed" or inspection_unknown or observed.get("running") is True:
            # Never record a terminal timeout while the process may
            # still exist; supervise the cleanup instead.
            self._transition_snapshot(
                ledger,
                entry,
                "cleanup_failed",
                at=self._config.clock(),
                receipt={
                    "kind": "supervision-timeout-cleanup-failure",
                    "detail": f"workload exceeded its timeout and cleanup is incomplete: {cleanup}",
                    "residual": self._residual_evidence(workload_id),
                },
                extra={
                    "cleanupTargetState": "timed_out",
                    "cleanupFinishedAt": self._config.clock(),
                    "cleanupExitStatus": observed.get("exitStatus"),
                },
            )
            return
        entry = ledger.capture_source_command_output(entry, self._engine, at=self._config.clock(), termination_reason="timed_out")
        self._transition_snapshot(
            ledger,
            entry,
            "timed_out",
            at=self._config.clock(),
            exit_status=observed.get("exitStatus"),
            finished_at=self._config.clock(),
            receipt={
                "kind": "supervision-timeout",
                "detail": f"workload exceeded its {entry['spec']['timeoutSeconds']}s timeout and was stopped",
                "cleanup": cleanup,
            },
        )

    def _supervise_workspace_idle(self, ledger: OperationLedger, entry: Mapping[str, Any]) -> None:
        """Stop a workspace after measured inactivity; preserve its volume."""

        workload_id = str(entry["workloadId"])
        parameters = entry["spec"].get("parameters", {})
        if not parameters.get("stopAfterIdle", True):
            return
        idle_seconds = int(entry["spec"]["timeoutSeconds"])
        last_monotonic = self._activity.get(workload_id)
        if last_monotonic is not None:
            idle_for = time.monotonic() - last_monotonic
        else:
            stamp = entry.get("lastActivityAt") or entry.get("startedAt") or entry.get("createdAt")
            try:
                last = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
                idle_for = (datetime.now(timezone.utc) - last).total_seconds()
            except (ValueError, TypeError):
                return
        if idle_for <= idle_seconds:
            return
        self._close_sessions_for(workload_id)
        cleanup = "performed"
        try:
            self._engine.stop(workload_id, timeout=2, expected_container_id=self._engine_target(entry))
        except EngineError as exc:
            cleanup = f"failed: {exc}"[:200]
        observed = self._safe_inspect(workload_id)
        inspection_unknown = observed.get("present") is None or (
            observed.get("present") is True and observed.get("running") is None
        )
        if cleanup != "performed" or inspection_unknown or observed.get("running") is True:
            self._transition_snapshot(
                ledger,
                entry,
                "cleanup_failed",
                at=self._config.clock(),
                receipt={
                    "kind": "idle-timeout-cleanup-failure",
                    "detail": f"workspace exceeded its inactivity bound and cleanup is incomplete: {cleanup}",
                    "residual": self._residual_evidence(workload_id),
                },
                extra={
                    "cleanupTargetState": "stopped",
                    "cleanupFinishedAt": self._config.clock(),
                    "cleanupExitStatus": observed.get("exitStatus"),
                },
            )
            return
        self._transition_snapshot(
            ledger,
            entry,
            "stopped",
            at=self._config.clock(),
            exit_status=observed.get("exitStatus"),
            finished_at=self._config.clock(),
            receipt={
                "kind": "idle-timeout",
                "detail": (
                    f"workspace was inactive for {int(idle_for)}s, exceeding its "
                    f"{idle_seconds}s inactivity bound; container stopped, data volume preserved"
                ),
                "cleanup": cleanup,
            },
        )

    def _enforce_grant_liveness(
        self, ledger: OperationLedger, entry: Mapping[str, Any]
    ) -> bool:
        """Terminate or quarantine active work whose authority was withdrawn.

        Returns True when the entry was acted on.  Any liveness failure —
        revoked, paused, expired, epoch-superseded, unknown grant, or a
        missing/corrupt revocation store — is fail-closed: the workload is
        stopped and receipted immediately, never left running on stale
        authority.
        """
        grant_id = str(entry.get("grantId", "unbound"))
        try:
            self._grant_store().assert_live(
                grant_id,
                expected_digest=(
                    str(entry["grantDigest"]) if entry.get("grantDigest") else None
                ),
            )
            return False
        except GrantRefusal as refusal:
            reason = refusal.reason
        if any(receipt.get("kind") == "authority-withdrawn" for receipt in entry.get("receipts", [])):
            # Already acted on this dead grant (e.g. a stopped workspace):
            # never hammer the engine or grow receipts every sweep.
            return True
        workload_id = str(entry["workloadId"])
        self._close_sessions_for(workload_id)
        if entry["state"] == "reserved":
            self._transition_snapshot(
                ledger,
                entry,
                "cancelled",
                at=self._config.clock(),
                finished_at=self._config.clock(),
                receipt={
                    "kind": "authority-withdrawn",
                    "detail": f"grant {grant_id} is no longer live ({reason}); reservation cancelled before engine creation",
                    "refusal": reason,
                    "cleanup": "not-required",
                },
            )
            return True
        is_workspace = entry["spec"].get("kind") == "workspace"
        if is_workspace:
            cleanup_error: str | None = None
            try:
                self._engine.stop(workload_id, timeout=2, expected_container_id=self._engine_target(entry))
            except EngineError as exc:
                cleanup_error = str(exc)[:200]
            residual_evidence = self._residual_evidence(workload_id)
            cleanup_complete = (
                residual_evidence["containerPresent"] is False
                or (
                    residual_evidence["containerPresent"] is True
                    and residual_evidence["containerRunning"] is False
                )
            )
            cleanup = "workspace stopped; daemon-owned volumes preserved"
            if cleanup_error is not None:
                cleanup += f"; stop reported: {cleanup_error}"
        else:
            cleanup_complete, cleanup, residual_evidence = self._cleanup_engine_effect(
                workload_id,
                snapshot_path=(
                    str(entry.get("sourceSnapshotPath") or entry["validatorSnapshotPath"])
                    if entry.get("sourceSnapshotPath") or entry.get("validatorSnapshotPath")
                    else None
                ),
                termination_reason="authority-withdrawn",
            )
        entry = ledger.get(workload_id) or entry
        if not cleanup_complete:
            self._transition_snapshot(
                ledger,
                entry,
                "cleanup_failed",
                at=self._config.clock(),
                receipt={
                    "kind": "authority-withdrawn-cleanup-failure",
                    "detail": f"grant {grant_id} is no longer live ({reason}) but cleanup is incomplete: {cleanup}",
                    "refusal": reason,
                    "residual": residual_evidence,
                },
                extra={
                    "cleanupTargetState": "stopped" if is_workspace else "cancelled",
                    "cleanupFinishedAt": self._config.clock(),
                },
            )
            return True
        # A workspace keeps its daemon-owned volume (stopped, restartable by
        # a live grant); ephemeral work is cancelled outright.
        next_state = "stopped" if is_workspace else "cancelled"
        self._transition_snapshot(
            ledger,
            entry,
            next_state,
            at=self._config.clock(),
            finished_at=self._config.clock(),
            receipt={
                "kind": "authority-withdrawn",
                "detail": f"grant {grant_id} is no longer live ({reason}); workload terminated immediately",
                "refusal": reason,
                "cleanup": cleanup,
            },
        )
        return True

    def _residual_evidence(self, workload_id: str) -> dict[str, Any]:
        """Exact observed state of a possibly-residual workload container."""
        info = self._safe_inspect(workload_id)
        present = info.get("present")
        running = info.get("running")
        return {
            "engine": self._engine.identity["engine"],
            "containerPresent": present if isinstance(present, bool) else None,
            "containerRunning": running if isinstance(running, bool) else None,
            "engineStatus": (
                info.get("status")
                if present is True
                else ("absent" if present is False else "unknown")
            ),
            "exitStatus": info.get("exitStatus"),
            "inspectionError": info.get("inspectionError"),
        }

    def _retry_cleanup(self, ledger: OperationLedger, entry: Mapping[str, Any]) -> None:
        """Retry a failed cleanup; escalate with durable residual evidence."""
        workload_id = entry["workloadId"]
        attempts = sum(
            1 for receipt in entry.get("receipts", []) if receipt.get("kind") == "cleanup-retry"
        )
        if attempts >= MAX_CLEANUP_RETRY_ATTEMPTS:
            if not entry.get("cleanupEscalated"):
                self._transition_snapshot(
                    ledger,
                    entry,
                    "cleanup_failed",
                    at=self._config.clock(),
                    receipt={
                        "kind": "cleanup-escalated",
                        "detail": (
                            f"cleanup failed {attempts} times; workload remains "
                            "non-terminal and supervised; operator intervention required"
                        ),
                        "residual": self._residual_evidence(workload_id),
                    },
                    extra={"cleanupEscalated": True},
                )
            return
        target_state = str(entry.get("cleanupTargetState") or "cancelled")
        if target_state == "stopped" and entry["spec"].get("kind") == "workspace":
            error: str | None = None
            try:
                self._engine.stop(workload_id, timeout=2, expected_container_id=self._engine_target(entry))
            except EngineError as exc:
                error = str(exc)[:200]
            residual = self._residual_evidence(workload_id)
            complete = (
                residual["containerPresent"] is False
                or (
                    residual["containerPresent"] is True
                    and residual["containerRunning"] is False
                )
            )
            cleanup_detail = error or "workspace stop verified"
        else:
            complete, cleanup_detail, residual = self._cleanup_engine_effect(
                workload_id,
                snapshot_path=(
                    str(entry.get("sourceSnapshotPath") or entry["validatorSnapshotPath"])
                    if entry.get("sourceSnapshotPath") or entry.get("validatorSnapshotPath")
                    else None
                ),
            )
        entry = ledger.get(workload_id) or entry
        if not complete:
            self._transition_snapshot(
                ledger,
                entry,
                "cleanup_failed",
                at=self._config.clock(),
                receipt={
                    "kind": "cleanup-retry",
                    "detail": f"cleanup retry {attempts + 1} failed: {cleanup_detail}",
                    "residual": residual,
                },
            )
            return
        self._transition_snapshot(
            ledger,
            entry,
            target_state,
            at=self._config.clock(),
            exit_status=entry.get("cleanupExitStatus"),
            finished_at=str(entry.get("cleanupFinishedAt") or self._config.clock()),
            receipt={
                "kind": "cleanup-recovered",
                "detail": f"cleanup succeeded after {attempts + 1} supervised retries",
            },
            extra={
                "cleanupTargetState": None,
                "cleanupFinishedAt": None,
                "cleanupExitStatus": None,
                "validatorSnapshotPath": None,
                "sourceSnapshotPath": None,
            },
        )

    # --------------------------------------------------------------- serving

    def serve_forever(self) -> None:
        server = self._server
        if server is None:
            raise DaemonBootError("boot() must complete before serve_forever()")
        while not self._shutdown.is_set():
            try:
                connection, _ = server.accept()
            except socket.timeout:
                self._threads = [thread for thread in self._threads if thread.is_alive()]
                continue
            except OSError:
                break
            if not self._connection_slots.acquire(blocking=False):
                # Connection bound reached: refuse the excess connection by
                # closing it rather than queueing unbounded threads.
                try:
                    connection.close()
                except OSError:
                    pass
                continue
            thread = threading.Thread(
                target=self._serve_connection, args=(connection,), daemon=True
            )
            thread.start()
            self._threads.append(thread)

    def _peer_credentials(self, connection: socket.socket) -> dict[str, int]:
        if not hasattr(socket, "SO_PEERCRED"):
            raise OSError("SO_PEERCRED is unavailable; peer identity cannot be verified")
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        if len(raw) != struct.calcsize("3i"):
            raise OSError("SO_PEERCRED returned an invalid credential shape")
        pid, uid, gid = struct.unpack("3i", raw)
        return self._canonical_peer_identity({"pid": pid, "uid": uid, "gid": gid})

    def _serve_connection(self, connection: socket.socket) -> None:
        try:
            connection.settimeout(self._config.connection_read_timeout_seconds)
            peer = self._peer_credentials(connection)
            buffer = b""
            source_fd: int | None = None
            source_fd_invalid = False
            while not self._shutdown.is_set():
                try:
                    chunk, ancillary, flags, _address = connection.recvmsg(
                        65536,
                        socket.CMSG_SPACE(array.array("i").itemsize),
                        getattr(socket, "MSG_CMSG_CLOEXEC", 0),
                    )
                except (OSError, socket.timeout):
                    break
                if not chunk:
                    break
                received: list[int] = []
                for level, kind, content in ancillary:
                    if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                        continue
                    descriptors = array.array("i")
                    usable = len(content) - (len(content) % descriptors.itemsize)
                    descriptors.frombytes(content[:usable])
                    received.extend(descriptors)
                if flags & getattr(socket, "MSG_CTRUNC", 0):
                    source_fd_invalid = True
                if received:
                    if source_fd is not None or len(received) != 1:
                        source_fd_invalid = True
                        for descriptor in received:
                            os.close(descriptor)
                    else:
                        source_fd = received[0]
                buffer += chunk
                if len(buffer) > contract.MAX_REQUEST_BYTES:
                    break
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    if not line.strip():
                        continue
                    effective_fd = -1 if source_fd_invalid else source_fd
                    receipt = self._handle_line(line, peer, source_fd=effective_fd)
                    if source_fd is not None:
                        os.close(source_fd)
                    source_fd = None
                    source_fd_invalid = False
                    payload = (contract.canonical_json(receipt) + "\n").encode("utf-8")
                    if len(payload) > contract.MAX_RESPONSE_BYTES:
                        # Response bound is distinct from the request bound:
                        # refuse rather than stream an unbounded answer.
                        receipt = contract.refusal_receipt(
                            receipt["requestDigest"],
                            receipt["operationId"],
                            receipt["requester"],
                            "response-bound-exceeded",
                            "the operation result exceeded the daemon response byte bound",
                            received_at=receipt["timestamps"]["receivedAt"],
                            completed_at=self._config.clock(),
                        )
                        payload = (contract.canonical_json(receipt) + "\n").encode("utf-8")
                    connection.sendall(payload)
        except OSError:
            pass
        finally:
            if "source_fd" in locals() and source_fd is not None:
                try:
                    os.close(source_fd)
                except OSError:
                    pass
            self._connection_slots.release()
            try:
                connection.close()
            except OSError:
                pass

    def _handle_line(
        self,
        line: bytes,
        peer: Mapping[str, int],
        *,
        source_fd: int | None = None,
    ) -> dict[str, Any]:
        received_at = self._config.clock()
        try:
            raw = json.loads(line)
            request = contract.validate_operation_request(raw)
        except (ValueError, TypeError):
            digest = "sha256:" + __import__("hashlib").sha256(line).hexdigest()
            return contract.refusal_receipt(
                digest,
                "malformed-request",
                {**peer, "grantId": "unknown"},
                "contract-violation",
                "request is not a valid stateport.execution-host-operation/v1 document",
                received_at=received_at,
                completed_at=self._config.clock(),
            )
        request_digest = contract.canonical_digest(raw)
        peer_record = {**peer, "grantId": request["requester"]["grantId"]}
        deployment_admitted = False

        def finalize(receipt: Mapping[str, Any]) -> dict[str, Any]:
            validated = contract.validate_receipt(receipt)
            if not deployment_admitted:
                return validated
            try:
                self._ledger_required().complete_deployment_operation(
                    request["operationId"],
                    request_digest=request_digest,
                    receipt=validated,
                    at=self._config.clock(),
                )
            except LedgerError as exc:
                return contract.refusal_receipt(
                    request_digest,
                    request["operationId"],
                    peer_record,
                    "operation-ledger-failed",
                    f"the deployment effect has no durable terminal receipt: {exc}",
                    received_at=received_at,
                    completed_at=self._config.clock(),
                )
            return validated
        if not self._peer_is_authorized(peer):
            return contract.refusal_receipt(
                request_digest,
                request["operationId"],
                peer_record,
                "peer-not-authorized",
                "peer uid is not the daemon user or the declared allowed client user",
                received_at=received_at,
                completed_at=self._config.clock(),
            )
        try:
            payload = contract.validate_request_payload(request, raw.get("payload"))
        except ValueError as exc:
            return contract.refusal_receipt(
                request_digest,
                request["operationId"],
                peer_record,
                "contract-violation",
                str(exc),
                received_at=received_at,
                completed_at=self._config.clock(),
            )
        if (
            request["operation"] in contract.DEPLOYMENT_OPERATIONS
            and request["operation"] != "probeDeploymentTarget"
            and request["operationId"]
            != contract.deployment_host_operation_id(request["operation"], payload)
        ):
            return contract.refusal_receipt(
                request_digest,
                request["operationId"],
                peer_record,
                "operation-identity-mismatch",
                "deployment operationId does not bind the exact control context and payload",
                received_at=received_at,
                completed_at=self._config.clock(),
            )
        requires_source_fd = request["operation"] in contract.DEPLOYMENT_ARCHIVE_OPERATIONS or (
            request["operation"] == "createWorkload"
            and payload["workload"]["kind"] == "agent-run"
            and "sourceArchive" in payload["workload"]["parameters"]
        )
        accepts_seed_fd = request["operation"] == "createWorkload" and "sourceSeed" in payload["workload"]["parameters"]
        if source_fd is not None and (source_fd < 0 or not (requires_source_fd or accepts_seed_fd)):
            return contract.refusal_receipt(
                request_digest,
                request["operationId"],
                peer_record,
                "source-descriptor-invalid",
                "the operation carried an unexpected or malformed source descriptor",
                received_at=received_at,
                completed_at=self._config.clock(),
            )
        if requires_source_fd and source_fd is None:
            return contract.refusal_receipt(
                request_digest,
                request["operationId"],
                peer_record,
                "source-descriptor-required",
                "the deployment operation requires one read-only source archive descriptor",
                received_at=received_at,
                completed_at=self._config.clock(),
            )
        grant: Mapping[str, Any] | None = None
        if request["operation"] != "describeCapabilities":
            # describeCapabilities is the read-only protocol health surface
            # and stays peer-uid gated; every engine-reaching operation
            # requires a verified provisioned grant.
            try:
                grant = self._grant_store().verify(
                    request=request,
                    peer_uid=peer["uid"],
                    payload=payload,
                    active_count=self._active_count_for_grant,
                )
                if self._config.workspace_image_reference is not None and grant["grantId"] == "control-plane-default":
                    self._verify_workspace_image_authority()
            except GrantRefusal as refusal:
                return contract.refusal_receipt(
                    request_digest,
                    request["operationId"],
                    peer_record,
                    refusal.reason,
                    refusal.detail,
                    received_at=received_at,
                    completed_at=self._config.clock(),
                )
            except LedgerError as exc:
                return contract.refusal_receipt(
                    request_digest,
                    request["operationId"],
                    peer_record,
                    "daemon-not-ready",
                    str(exc),
                    received_at=received_at,
                    completed_at=self._config.clock(),
                )
        if request["operation"] in contract.DEPLOYMENT_OPERATIONS:
            try:
                admission = self._ledger_required().admit_deployment_operation(
                    request,
                    request_digest=request_digest,
                    requester=peer_record,
                    payload=payload,
                    at=received_at,
                )
            except LedgerError as exc:
                return contract.refusal_receipt(
                    request_digest,
                    request["operationId"],
                    peer_record,
                    "operation-id-conflict",
                    str(exc),
                    received_at=received_at,
                    completed_at=self._config.clock(),
                )
            if admission["status"] == "replay":
                return contract.validate_receipt(admission["receipt"])
            if admission["status"] == "in-progress":
                return contract.refusal_receipt(
                    request_digest,
                    request["operationId"],
                    peer_record,
                    "operation-in-progress",
                    "the exact deployment operation is already admitted",
                    received_at=received_at,
                    completed_at=self._config.clock(),
                )
            deployment_admitted = True
        try:
            result, observed, cleanup = self._dispatch(
                request, payload, grant, source_fd=source_fd
            )
            workload_id = result.get("workloadId") if isinstance(result, dict) else None
            if isinstance(workload_id, str):
                entry = self._ledger_required().get(workload_id)
                if entry is not None and self._grant_owns_entry(entry, grant):
                    owner = entry["spec"]["parameters"].get("ownership")
                    if owner is not None:
                        result["ownership"] = {"grantId": entry["grantId"], **owner}
        except _Refusal as refusal:
            return finalize(
                contract.refusal_receipt(
                    request_digest,
                    request["operationId"],
                    peer_record,
                    refusal.reason,
                    refusal.detail,
                    received_at=received_at,
                    completed_at=self._config.clock(),
                )
            )
        except LedgerError as exc:
            # A CAS/legal-state violation from a racing transition: the
            # workload changed under the request; refuse, never crash.
            return finalize(
                contract.refusal_receipt(
                    request_digest,
                    request["operationId"],
                    peer_record,
                    "state-conflict",
                    str(exc),
                    received_at=received_at,
                    completed_at=self._config.clock(),
                )
            )
        receipt = {
            "formatVersion": contract.RECEIPT_FORMAT,
            "operationId": request["operationId"],
            "requestDigest": request_digest,
            "accepted": True,
            "refusal": None,
            "requester": peer_record,
            "result": result,
            "observed": observed,
            "cleanup": cleanup,
            "timestamps": {"receivedAt": received_at, "completedAt": self._config.clock()},
        }
        return finalize(receipt)

    def _empty_observed(self) -> dict[str, Any]:
        identity = self._engine.identity
        return {
            "engine": identity["engine"],
            "engineVersion": None,
            "imageDigest": None,
            "exitStatus": None,
            "startedAt": None,
            "finishedAt": None,
        }

    def _safe_inspect(self, workload_id: str) -> dict[str, Any]:
        try:
            return self._engine.inspect(workload_id)
        except EngineError as exc:
            return {
                "present": None,
                "running": None,
                "inspectionError": str(exc)[:200],
            }

    def _transition_snapshot(
        self,
        ledger: OperationLedger,
        entry: Mapping[str, Any],
        state: str,
        **changes: Any,
    ) -> dict[str, Any]:
        """CAS one runtime snapshot by both state and durable version."""
        return ledger.transition(
            str(entry["workloadId"]),
            state,
            expect_states={str(entry["state"])},
            expect_version=int(entry["version"]),
            **changes,
        )

    def _remove_snapshot_path(self, snapshot_path: str | None) -> str | None:
        if snapshot_path is None:
            return None
        try:
            remove_staging_snapshot(
                Path(snapshot_path), snapshots_root=self._validator_snapshots_root()
            )
        except StagingIdentityError as exc:
            return str(exc)[:200]
        return None

    @staticmethod
    def _container_identity_error(
        workload_id: str, entry: Mapping[str, Any] | None, info: Mapping[str, Any]
    ) -> str | None:
        """One established identity contract for cleanup and explicit controls."""
        labels = info.get("labels")
        if entry is not None:
            policy_error = development_seed_identity_error(entry["spec"], info)
            if policy_error is not None:
                return policy_error
        if entry is None:
            return "no durable workload owns the container name"
        if not isinstance(info.get("containerId"), str) or not info["containerId"]:
            return "observed container ID is unavailable"
        expected_container_id = entry.get("containerId")
        if expected_container_id is not None and info.get("containerId") != expected_container_id:
            return "container ID does not match the durable ledger identity"
        if not isinstance(labels, Mapping):
            return "container has no label mapping"
        if labels.get(MANAGED_LABEL_KEY) != "true":
            return "container lacks the managed label"
        if labels.get(WORKLOAD_LABEL) != workload_id:
            return "container workload label does not match"
        if labels.get(KIND_LABEL) != entry["spec"].get("kind"):
            return "container kind label does not match"
        if info.get("imageDigest") != entry["spec"]["image"]["reference"].rsplit("@", 1)[1]:
            return "container image digest does not match the sealed spec"
        return None

    def _assert_owned_container(
        self, entry: Mapping[str, Any], *, allow_absent: bool = False
    ) -> str | None:
        workload_id = str(entry["workloadId"])
        info = self._safe_inspect(workload_id)
        if info.get("present") is None:
            raise _Refusal("container-identity-unavailable", "container identity could not be inspected")
        if info.get("present") is not True:
            if allow_absent:
                return
            raise _Refusal("container-absent", "the managed container is absent; no engine action was attempted")
        error = self._container_identity_error(workload_id, entry, info)
        if error is not None:
            raise _Refusal("foreign-container", error)
        return str(info["containerId"])

    def _engine_target(self, entry: Mapping[str, Any] | None) -> str:
        if entry is None:
            raise EngineError("no durable workload owns this engine effect")
        try:
            return str(self._assert_owned_container(entry))
        except _Refusal as exc:
            raise EngineError(exc.detail) from exc

    def _cleanup_engine_effect(
        self, workload_id: str, *, snapshot_path: str | None = None,
        termination_reason: str = "interrupted",
    ) -> tuple[bool, str, dict[str, Any]]:
        """Stop and remove an engine effect, verifying absence rather than calls."""
        seeded = self._ledger_required().get(workload_id)
        if seeded is not None and seeded.get("sourceSeedStatus") in {"started", "failed"}:
            return False, "partial source seed and volume retained for operator review", self._residual_evidence(workload_id)
        initial = self._safe_inspect(workload_id)
        if initial.get("present") is None:
            residual = self._residual_evidence(workload_id)
            return False, "container identity could not be inspected", residual
        if initial.get("present") is True:
            entry = self._ledger_required().get(workload_id)
            identity_error = self._container_identity_error(workload_id, entry, initial)
            if identity_error is not None:
                residual = self._residual_evidence(workload_id)
                residual["identityMismatch"] = identity_error
                return False, f"foreign container refused: {identity_error}", residual
        self._close_sessions_for(workload_id)
        call_errors: list[str] = []
        if initial.get("present") is True:
            if initial.get("running") is True:
                current = self._ledger_required().get(workload_id)
                if current is not None:
                    self._ledger_required().mark_source_termination(current, at=self._config.clock(), reason=termination_reason)
            try:
                self._engine.stop(workload_id, timeout=2, expected_container_id=initial["containerId"])
            except EngineError as exc:
                call_errors.append(f"stop: {str(exc)[:160]}")
            try:
                current = self._ledger_required().get(workload_id)
                if current is not None:
                    reason = termination_reason if initial.get("running") else (str(current["state"]) if current["state"] in contract.TERMINAL_STATES else "exited")
                    self._ledger_required().capture_source_command_output(current, self._engine, at=self._config.clock(), termination_reason=reason)
            except LedgerError:
                return False, "source command output capture failed; stopped container retained", self._residual_evidence(workload_id)
            try:
                self._engine.remove(workload_id, force=True, expected_container_id=initial["containerId"])
            except EngineError as exc:
                call_errors.append(f"remove: {str(exc)[:160]}")
        residual = self._residual_evidence(workload_id)
        complete = residual["containerPresent"] is False
        if complete:
            snapshot_error = self._remove_snapshot_path(snapshot_path)
            if snapshot_error is not None:
                call_errors.append(f"snapshot: {snapshot_error}")
                complete = False
        detail = "engine workload absence verified"
        if call_errors:
            detail += "; " + "; ".join(call_errors)
        if not complete and not call_errors:
            detail += "; container presence could not be disproved"
        return complete, detail[:500], residual

    def _record_post_effect_reconciliation(
        self,
        workload_id: str,
        *,
        kind: str,
        detail: str,
        target_state: str,
        snapshot_path: str | None = None,
    ) -> dict[str, Any]:
        """Clean an effect whose CAS lost and durably expose any residual."""
        ledger = self._ledger_required()
        complete, cleanup_detail, residual = self._cleanup_engine_effect(
            workload_id, snapshot_path=snapshot_path
        )
        for _ in range(16):
            current = ledger.get(workload_id)
            if current is None:
                raise LedgerError(f"workload {workload_id} vanished during effect cleanup")
            if complete:
                state = (
                    current["state"]
                    if current["state"] in contract.TERMINAL_STATES
                    else target_state
                )
                extra: dict[str, Any] = {}
            else:
                state = "cleanup_failed"
                extra = {
                    "cleanupTargetState": (
                        current["state"]
                        if current["state"] in contract.TERMINAL_STATES
                        else target_state
                    ),
                    "cleanupFinishedAt": self._config.clock(),
                }
                if snapshot_path is not None:
                    extra["validatorSnapshotPath"] = snapshot_path
            try:
                return self._transition_snapshot(
                    ledger,
                    current,
                    state,
                    at=self._config.clock(),
                    finished_at=self._config.clock(),
                    receipt={
                        "kind": kind,
                        "detail": detail[:300],
                        "cleanup": cleanup_detail,
                        "residual": residual,
                    },
                    extra=extra,
                )
            except LedgerError:
                continue
        raise LedgerError(
            f"workload {workload_id} effect cleanup could not be durably reconciled"
        )

    def _assert_activation_authority(
        self, entry: Mapping[str, Any], grant: Mapping[str, Any] | None
    ) -> None:
        grant_id = str(entry.get("grantId", "unbound"))
        if grant is None or grant.get("grantId") != grant_id:
            raise _Refusal(
                "grant-identity-mismatch",
                "the activating grant does not own the durable workload reservation",
            )
        expected_digest = entry.get("grantDigest") or contract.canonical_digest(grant)
        try:
            self._grant_store().assert_live(
                grant_id, expected_digest=str(expected_digest)
            )
        except GrantRefusal as refusal:
            raise _Refusal(refusal.reason, refusal.detail) from refusal

    def _resource_enforcement(self, spec: Mapping[str, Any]) -> dict[str, Any]:
        observer = getattr(self._engine, "resource_enforcement", None)
        if callable(observer):
            value = observer(spec)
            if isinstance(value, Mapping):
                return dict(value)
        if spec["kind"] == "workspace":
            return {
                "persistentVolumeDiskMaxBytes": {
                    "status": "unknown",
                    "requestedBytes": spec["parameters"]["diskMaxBytes"],
                    "detail": "the engine did not report persistent-volume quota enforcement",
                }
            }
        return {}

    @staticmethod
    def _workload_inventory_metadata(entry: Mapping[str, Any]) -> dict[str, Any]:
        """Project sealed ownership and declared limits without host internals.

        Application/run ownership comes from the exact grant-bound sealed spec.
        Legacy workspaces retain explicit null ownership.  The grant identity is durable daemon truth; the
        resource values come only from the validated sealed spec admitted for
        that grant.
        """

        spec = entry["spec"]
        resources = spec["resources"]
        parameters = spec["parameters"]
        declared_limits: dict[str, Any] = {
            "memoryMaxBytes": resources["memoryMaxBytes"],
            "pidsMax": resources["pidsMax"],
            "timeoutSeconds": spec["timeoutSeconds"],
            "outputByteBound": spec["outputByteBound"],
        }
        if spec["kind"] in {"agent-run", "validator-run"}:
            declared_limits.update(
                cpuQuotaPercent=resources["cpuQuotaPercent"],
                diskMaxBytes=resources["diskMaxBytes"],
            )
        elif spec["kind"] == "workspace":
            declared_limits.update(
                cpuQuotaPercent=parameters["cpuQuotaPercent"],
                diskMaxBytes=parameters["diskMaxBytes"],
            )
        enforcement = entry.get("resourceEnforcement")
        return {
            "ownership": {
                "grantId": entry.get("grantId"),
                "applicationId": None,
                "runId": None,
                **parameters.get("ownership", {}),
            },
            **({"sourceSeed": {"status": entry.get("sourceSeedStatus", "not-started"), "reviewDigest": parameters["sourceSeed"]["reviewDigest"]}} if "sourceSeed" in parameters else {}),
            "declaredLimits": declared_limits,
            "resourceEnforcement": (
                dict(enforcement) if isinstance(enforcement, Mapping) else {}
            ),
        }

    @staticmethod
    def _grant_owns_entry(
        entry: Mapping[str, Any], grant: Mapping[str, Any] | None
    ) -> bool:
        if grant is None or entry.get("grantId") != grant.get("grantId"):
            return False
        recorded_digest = entry.get("grantDigest")
        return recorded_digest in {None, contract.canonical_digest(grant)}

    def _observed_for(self, workload_id: str) -> dict[str, Any]:
        observed = self._empty_observed()
        info = self._safe_inspect(workload_id)
        observed["imageDigest"] = info.get("imageDigest")
        observed["exitStatus"] = info.get("exitStatus")
        observed["startedAt"] = info.get("startedAt")
        observed["finishedAt"] = info.get("finishedAt")
        return observed

    # -------------------------------------------------------------- dispatch

    def _operation_workload_id(self, payload: Mapping[str, Any]) -> str | None:
        workload = payload.get("workload")
        if isinstance(workload, Mapping) and workload.get("workloadId") is not None:
            return str(workload["workloadId"])
        if payload.get("workloadId") is not None:
            return str(payload["workloadId"])
        if payload.get("deploymentId") is not None:
            return str(payload["deploymentId"])
        return None

    def _dispatch(
        self,
        request: Mapping[str, Any],
        payload: Mapping[str, Any],
        grant: Mapping[str, Any] | None,
        *,
        source_fd: int | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
        operation = request["operation"]
        if operation in contract.DEPLOYMENT_OPERATIONS:
            deployment_id = self._operation_workload_id(payload)
            if deployment_id is None:
                return self._op_deployment(
                    request, payload, grant, source_fd=source_fd
                )
            with self._workload_lock(deployment_id):
                return self._op_deployment(
                    request, payload, grant, source_fd=source_fd
                )
        if operation == "createWorkload":
            with self._workload_lock(payload["workload"]["workloadId"]):
                return self._op_create(request, payload, grant, source_fd=source_fd)
        handler = {
            "describeCapabilities": self._op_describe,
            "createWorkload": self._op_create,
            "start": self._op_start,
            "stop": self._op_stop,
            "status": self._op_status,
            "logs": self._op_logs,
            "cancel": self._op_cancel,
            "removeWorkload": self._op_remove,
            "openTerminal": self._op_open_terminal,
            "resizeTerminal": self._op_resize_terminal,
            "signalTerminal": self._op_signal_terminal,
            "closeTerminal": self._op_close_terminal,
            "execWorkload": self._op_exec_workload,
            "listWorkloads": self._op_list_workloads,
            "collectGarbage": self._op_collect_garbage,
            "runValidator": self._op_run_validator,
        }[operation]
        if operation in {"resizeTerminal", "signalTerminal", "closeTerminal"}:
            session_id = str(payload["sessionId"])
            while True:
                with self._terminal_mutex:
                    session = self._terminal_sessions.get(session_id)
                    if session is None:
                        raise _Refusal(
                            "unknown-terminal", "terminal session is no longer active"
                        )
                with self._workload_lock(session.workload_id):
                    with self._terminal_mutex:
                        if self._terminal_sessions.get(session_id) is not session:
                            continue
                        result = handler(request, payload, grant)
                if operation != "closeTerminal":
                    return result
                if not session.cleanup_complete.wait(TERMINAL_CLEANUP_TIMEOUT_SECONDS):
                    raise _Refusal(
                        "terminal-cleanup-unverified",
                        "terminal relay cleanup did not complete within the bounded timeout",
                    )
                with session.mutex:
                    cleanup_status = session.cleanup_status
                if cleanup_status != "completed":
                    raise _Refusal(
                        "terminal-cleanup-unverified",
                        "terminal relay or process cleanup could not be verified",
                    )
                result, observed, _cleanup = result
                return (
                    {**result, "state": "closed"},
                    observed,
                    {"outcome": "performed", "detail": "terminal relay and process cleanup verified"},
                )
        workload_id = self._operation_workload_id(payload)
        if workload_id is None:
            return handler(request, payload, grant)
        with self._workload_lock(workload_id):
            return handler(request, payload, grant)

    def _op_deployment(
        self,
        request: Mapping[str, Any],
        payload: Mapping[str, Any],
        grant: Mapping[str, Any] | None,
        *,
        source_fd: int | None,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
        adapter = self._deployment_adapter
        if adapter is None:
            raise _Refusal(
                "deployment-adapter-unavailable",
                "the execution host has no configured deployment effect adapter",
            )
        operation = request["operation"]
        snapshot: Mapping[str, Any] | None = None
        cleanup = {"outcome": "not-required", "detail": "operation carried no source snapshot"}
        try:
            if operation in contract.DEPLOYMENT_ARCHIVE_OPERATIONS:
                if source_fd is None:
                    raise DeploymentStagingError(
                        "source-descriptor-required",
                        "deployment source archive descriptor is absent",
                    )
                snapshot = materialize_deployment_snapshot(
                    source_fd,
                    metadata=payload["sourceArchive"],
                    plan=payload["plan"],
                    snapshots_root=self._deployment_snapshots_root(),
                    operation_id=request["operationId"],
                )
            if operation == "probeDeploymentTarget":
                value = adapter.probe()
            elif operation == "applyDeployment":
                assert snapshot is not None
                value = adapter.apply(
                    payload["plan"],
                    context_root=snapshot["contextRoot"],
                    overlay_root=snapshot["overlayRoot"],
                    failpoint=payload["failpoint"],
                )
            elif operation == "updateDeployment":
                assert snapshot is not None
                value = adapter.apply_update(
                    payload["plan"],
                    predecessor_plan=payload["predecessorPlan"],
                    predecessor_images=payload["predecessorImages"],
                    infrastructure=payload["infrastructure"],
                    context_root=snapshot["contextRoot"],
                    overlay_root=snapshot["overlayRoot"],
                    failpoint=payload["failpoint"],
                )
            elif operation == "observeDeployment":
                value = adapter.observe(
                    payload["spec"],
                    expected_revision=payload["expectedRevision"],
                    expected_images=payload["expectedImages"],
                    verify_health=payload["verifyHealth"],
                    infrastructure=payload["infrastructure"],
                )
            elif operation == "collectDeploymentLogs":
                value = adapter.logs(
                    payload["spec"],
                    service_id=payload["serviceId"],
                    tail=payload["tail"],
                    expected_revision=payload["expectedRevision"],
                )
            elif operation == "restartDeployment":
                value = adapter.restart(
                    payload["spec"],
                    expected_revision=payload["expectedRevision"],
                    expected_images=payload["expectedImages"],
                    infrastructure=payload["infrastructure"],
                )
            elif operation == "removeDeploymentRuntime":
                value = adapter.remove_runtime(
                    payload["spec"],
                    expected_revision=payload["expectedRevision"],
                    recovery_operation=payload["recoveryOperation"],
                )
            elif operation == "backupDeploymentData":
                value = adapter.backup_data(
                    payload["spec"],
                    backup_id=payload["backupId"],
                    plan_digest=payload["planDigest"],
                    expected_volumes=payload["expectedVolumes"],
                    expected_revision=payload["expectedRevision"],
                    expected_images=payload["expectedImages"],
                    infrastructure=payload["infrastructure"],
                )
            elif operation == "restoreDeploymentData":
                value = adapter.restore_data(
                    payload["spec"],
                    backup=payload["backup"],
                    plan_digest=payload["planDigest"],
                    expected_volumes=payload["expectedVolumes"],
                    expected_revision=payload["expectedRevision"],
                    expected_images=payload["expectedImages"],
                    infrastructure=payload["infrastructure"],
                )
            else:
                value = adapter.purge_data(
                    payload["spec"],
                    expected_volumes=payload["expectedVolumes"],
                    expected_revision=payload["expectedRevision"],
                    recover_interrupted=payload["recoverInterrupted"],
                )
            if not isinstance(value, Mapping):
                raise _Refusal(
                    "deployment-adapter-invalid",
                    "the deployment adapter returned a non-object result",
                )
            result: dict[str, Any] = {
                "outcome": "succeeded",
                "operation": operation,
                "value": dict(value),
                "failure": None,
            }
        except DeploymentStagingError as exc:
            result = {
                "outcome": "failed",
                "operation": operation,
                "value": None,
                "failure": {"code": exc.code, "message": exc.detail, "details": {}},
            }
        except Exception as exc:
            try:
                from stateport_deployment.errors import DeploymentError
            except ImportError as import_exc:
                raise _Refusal(
                    "deployment-adapter-unavailable",
                    "deployment error contracts are unavailable on the execution host",
                ) from import_exc
            if not isinstance(exc, DeploymentError):
                raise _Refusal(
                    "deployment-adapter-failed",
                    "the deployment adapter failed outside its typed error contract",
                ) from exc
            result = {
                "outcome": "failed",
                "operation": operation,
                "value": None,
                "failure": {
                    "code": exc.code,
                    "message": str(exc)[:500],
                    "details": dict(exc.details),
                },
            }
        finally:
            if snapshot is not None:
                try:
                    remove_deployment_snapshot(
                        Path(snapshot["root"]),
                        snapshots_root=self._deployment_snapshots_root(),
                    )
                except DeploymentStagingError as exc:
                    cleanup = {"outcome": "failed", "detail": exc.detail[:500]}
                else:
                    cleanup = {
                        "outcome": "performed",
                        "detail": "private deployment context snapshot removed",
                    }
        try:
            result_bytes = len(contract.canonical_json(result).encode("utf-8"))
        except (TypeError, ValueError):
            result = {
                "outcome": "failed",
                "operation": operation,
                "value": None,
                "failure": {
                    "code": "deployment-adapter-invalid",
                    "message": "the deployment adapter returned non-canonical JSON",
                    "details": {"runtimeEffectUncertain": True},
                },
            }
        else:
            if result_bytes > request["outputByteBound"]:
                result = {
                    "outcome": "failed",
                    "operation": operation,
                    "value": None,
                    "failure": {
                        "code": "output-bound-exceeded",
                        "message": "the deployment result exceeded the request output bound",
                        "details": {
                            "outputBytes": result_bytes,
                            "outputByteBound": request["outputByteBound"],
                            "runtimeEffectUncertain": operation
                            in {
                                "applyDeployment",
                                "updateDeployment",
                                "restartDeployment",
                                "removeDeploymentRuntime",
                                "backupDeploymentData",
                                "restoreDeploymentData",
                                "purgeDeploymentData",
                            },
                        },
                    },
                }
        return result, self._empty_observed(), cleanup

    def _ledger_required(self) -> OperationLedger:
        if self._ledger is None:
            raise _Refusal("daemon-not-ready", "daemon boot has not completed")
        return self._ledger

    def _grant_store(self) -> GrantStore:
        if self._grants is None:
            raise GrantRefusal("daemon-not-ready", "daemon grant store is not initialized")
        return self._grants

    def _active_count_for_grant(self, grant_id: str) -> int:
        ledger = self._ledger
        if ledger is None:
            raise LedgerError("daemon ledger is not initialized")
        return len(ledger.active_workload_ids(grant_id))

    def _entry_required(self, workload_id: str) -> dict[str, Any]:
        entry = self._ledger_required().get(workload_id)
        if entry is None:
            raise _Refusal("unknown-workload", f"workload {workload_id} has no ledger entry")
        return entry

    def _op_describe(
        self,
        request: Mapping[str, Any],
        payload: Mapping[str, Any],
        grant: Mapping[str, Any] | None,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
        observed = self._empty_observed()
        try:
            observed.update(self._engine.version())
        except EngineError:
            observed["engineVersion"] = "unavailable"
        result = {
            "formatVersion": "stateport.execution-host-contract/v1",
            "contractVersion": contract.CONTRACT_VERSION,
            "clientCompatibility": dict(contract.CLIENT_COMPATIBILITY),
            "transport": "confined-host-unix-socket",
            "workloadKinds": list(contract.WORKLOAD_KINDS),
            "operations": list(contract.OPERATIONS),
            "sealedWorkloadsOnly": True,
            "providerAccess": False,
            "publicNetwork": False,
            "peerIdentity": {
                "mechanism": "SO_PEERCRED",
                "runtimeUid": self._runtime_uid(),
                "runtimeGid": self._runtime_gid(),
                "socketGroupGid": self._expected_socket_gid(),
                "allowedClientUid": (
                    self._allowed_client_identity()[0]
                    if self._allowed_client_identity() is not None
                    else None
                ),
                "allowedClientGid": (
                    self._allowed_client_identity()[1]
                    if self._allowed_client_identity() is not None
                    else None
                ),
            },
            "limits": {
                "maxTimeoutSeconds": contract.MAX_TIMEOUT_SECONDS,
                "maxRequestTimeoutSeconds": contract.MAX_REQUEST_TIMEOUT_SECONDS,
                "maxDeploymentRequestTimeoutSeconds": (
                    contract.MAX_DEPLOYMENT_REQUEST_TIMEOUT_SECONDS
                ),
                "maxOutputBytes": contract.MAX_OUTPUT_BYTES,
                "maxWorkloads": contract.MAX_WORKLOADS,
            },
        }
        return result, observed, {"outcome": "not-required", "detail": "read-only operation"}

    def _op_create(
        self,
        request: Mapping[str, Any],
        payload: Mapping[str, Any],
        grant: Mapping[str, Any] | None,
        *, source_fd: int | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
        ledger = self._ledger_required()
        spec = payload["workload"]
        if "sourceSeed" in spec["parameters"] and getattr(self._engine, "workspace_source_seed_supported", False) is not True:
            raise _Refusal("workspace-seed-unavailable", "the engine does not implement verified fresh-volume source seeding")
        if "sourceArchive" in spec["parameters"] and getattr(self._engine, "agent_source_commands_supported", False) is not True:
            raise _Refusal("agent-command-unavailable", "the engine does not implement sealed source commands")
        grant = grant or {}
        grant_id = str(grant.get("grantId", request["requester"]["grantId"]))
        budgets = grant.get("budgets", {})
        grant_digest = contract.canonical_digest(grant) if grant else None
        existing = ledger.get(str(spec["workloadId"]))
        seed = spec["parameters"].get("sourceSeed")
        seed_reusing = seed is not None and existing is not None and existing.get("sourceSeedStatus") == "complete"
        if seed is not None:
            try:
                self._engine.validate_workspace_seed_capability(spec)
            except EngineError as exc:
                raise _Refusal("workspace-seed-unavailable", str(exc)) from exc
            if existing is not None and (existing.get("sourceSeedStatus") in {"started", "failed"} or (seed_reusing and source_fd is not None)):
                raise _Refusal("workspace-seed-recovery-refused", "only a completed source seed can be recovered, without a new archive")
            if not seed_reusing and source_fd is None:
                raise _Refusal("source-descriptor-required", "fresh workspace source initialization requires its exact archive descriptor")
        recovering_from: str | None = None
        try:
            if (
                existing is not None
                and existing.get("spec", {}).get("kind") == "workspace"
                and existing.get("state") in {"removed", "interrupted"}
            ):
                info = self._safe_inspect(str(spec["workloadId"]))
                if info.get("present") is None:
                    raise _Refusal(
                        "container-identity-unavailable",
                        "workspace recovery could not verify that the container name is free",
                    )
                if info.get("present") is True:
                    identity_error = self._container_identity_error(
                        str(spec["workloadId"]), existing, info
                    )
                    if identity_error is not None:
                        raise _Refusal("foreign-container", identity_error)
                    raise _Refusal(
                        "container-present",
                        "workspace recovery requires the retained container to be absent",
                    )
                if grant_digest is None:
                    raise _Refusal(
                        "grant-identity-mismatch",
                        "workspace recovery requires an exact durable grant identity",
                    )
                recovering_from = str(existing["state"])
                reservation = ledger.reserve_workspace_recovery(
                    spec,
                    at=self._config.clock(),
                    grant_id=grant_id,
                    grant_epoch=int(grant.get("revocationEpoch", 0)),
                    max_active=contract.MAX_WORKLOADS,
                    max_per_grant=int(budgets.get("maxActiveWorkloads", 256)),
                    grant_digest=grant_digest,
                )
            else:
                # Atomic capacity reservation: the placeholder counts against
                # every capacity check before the engine call exists, so a
                # concurrent create can never slip through the same budget.
                reservation = ledger.reserve(
                    spec,
                    at=self._config.clock(),
                    grant_id=grant_id,
                    grant_epoch=int(grant.get("revocationEpoch", 0)),
                    max_active=contract.MAX_WORKLOADS,
                    max_per_grant=int(budgets.get("maxActiveWorkloads", 256)),
                    grant_digest=grant_digest,
                )
        except _Refusal:
            raise
        except LedgerError as exc:
            detail = str(exc)
            if "capacity" in detail or "budget" in detail:
                reason = "workload-limit"
            elif existing is not None and existing.get("state") in {"removed", "interrupted"}:
                reason = "workspace-recovery-refused"
            else:
                reason = "duplicate-workload"
            raise _Refusal(reason, detail) from exc
        try:
            self._assert_activation_authority(reservation, grant)
        except _Refusal as refusal:
            self._transition_snapshot(
                ledger,
                reservation,
                recovering_from or "cancelled",
                at=self._config.clock(),
                finished_at=self._config.clock(),
                receipt={
                    "kind": "create-authority-withdrawn",
                    "detail": refusal.detail,
                    "refusal": refusal.reason,
                    "cleanup": "not-required",
                },
            )
            raise
        if seed is not None:
            if seed_reusing:
                try:
                    self._engine.reconcile_workspace_seed(spec, existing["sourceSeedId"])
                except EngineError as exc:
                    self._transition_snapshot(ledger, reservation, recovering_from or "failed", at=self._config.clock(), receipt={"kind": "workspace-seed-recovery-refused", "detail": "retained source identity was not verified; existing volume retained"})
                    raise _Refusal("workspace-seed-recovery-refused", "retained source volume identity could not be verified") from exc
            else:
                seed_snapshot = None
                seed_effect_attempted = False
                seed_id = contract.canonical_digest({"operationId": request["operationId"], "specDigest": reservation["specDigest"]}).split(":", 1)[1]
                reservation = self._transition_snapshot(ledger, reservation, "reserved", at=self._config.clock(), extra={"sourceSeedStatus": "admitting", "sourceSeedId": seed_id})
                try:
                    seed_snapshot = materialize_deployment_snapshot(source_fd,
                        metadata=seed["sourceArchive"], plan={"sourceInventory": seed["sourceInventory"], "overlay": {}},
                        snapshots_root=self._validator_snapshots_root(), operation_id=request["operationId"],
                        max_context_bytes=min(spec["parameters"]["diskMaxBytes"], contract.MAX_DEPLOYMENT_CONTEXT_BYTES))
                    manifest_path = Path(seed_snapshot["root"]) / "seed-manifest.json"
                    with manifest_path.open("x", encoding="utf-8") as manifest:
                        manifest.write(json.dumps({"sourceInventory": seed["sourceInventory"]}))
                        manifest.flush()
                        os.fchmod(manifest.fileno(), 0o644)
                        os.fsync(manifest.fileno())
                    for directory, _dirs, _files in os.walk(seed_snapshot["root"]):
                        os.chmod(directory, 0o755)
                    reservation = self._transition_snapshot(ledger, reservation, "reserved", at=self._config.clock(), extra={"sourceSnapshotPath": str(seed_snapshot["root"])})
                    self._assert_activation_authority(reservation, grant)
                    reservation = self._transition_snapshot(ledger, reservation, "reserved", at=self._config.clock(), extra={"sourceSeedStatus": "started"})
                    seed_effect_attempted = True
                    self._engine.seed_workspace(spec, snapshot_root=str(seed_snapshot["root"]), seed_id=seed_id, timeout=request["timeoutSeconds"])
                    self._assert_activation_authority(reservation, grant)
                    reservation = self._transition_snapshot(ledger, reservation, "reserved", at=self._config.clock(), extra={"sourceSeedStatus": "complete"}, receipt={"kind": "workspace-source-seeded", "reviewDigest": seed["reviewDigest"], "archiveDigest": seed["sourceArchive"]["archiveDigest"], "fileCount": len(seed["sourceInventory"]), "persistentVolumeQuota": "unsupported"})
                    self._engine.finish_workspace_seed(spec, seed_id)
                    cleanup_error = self._remove_snapshot_path(str(seed_snapshot["root"]))
                    if cleanup_error:
                        raise EngineError(cleanup_error)
                    reservation = self._transition_snapshot(ledger, reservation, "reserved", at=self._config.clock(), extra={"sourceSnapshotPath": None})
                except (EngineError, DeploymentStagingError, _Refusal, OSError) as exc:
                    current = ledger.get(spec["workloadId"]) or reservation
                    retained_snapshot = str(seed_snapshot["root"]) if seed_snapshot else None
                    if not seed_effect_attempted and retained_snapshot is not None:
                        cleanup_error = self._remove_snapshot_path(retained_snapshot)
                        if cleanup_error is None:
                            retained_snapshot = None
                    quarantined = seed_effect_attempted or retained_snapshot is not None
                    detail = "source initialization did not complete; partial volume and source evidence retained" if quarantined else "source admission refused before any volume effect; an exact fresh retry remains possible"
                    self._transition_snapshot(ledger, current, "failed", at=self._config.clock(), receipt={"kind": "workspace-source-seed-refused", "detail": detail}, extra={"sourceSeedStatus": "failed" if quarantined else "not-started", "sourceSnapshotPath": retained_snapshot})
                    raise _Refusal("workspace-seed-failed" if quarantined else "workspace-source-admission-refused", detail) from exc
        snapshot = None
        execution_spec = spec
        if "sourceArchive" in spec["parameters"]:
            parameters = spec["parameters"]
            try:
                if source_fd is None:
                    raise DeploymentStagingError("source-descriptor-required", "agent source descriptor is absent")
                snapshot = materialize_deployment_snapshot(
                    source_fd, metadata=parameters["sourceArchive"],
                    plan={"sourceInventory": parameters["sourceInventory"], "overlay": {}},
                    snapshots_root=self._validator_snapshots_root(),
                    operation_id=request["operationId"],
                    max_context_bytes=min(spec["resources"]["diskMaxBytes"], contract.MAX_DEPLOYMENT_CONTEXT_BYTES),
                )
                # Images may run a non-root UID. Only the admitted source tree
                # is traversable inside its read-only mount; the daemon's
                # parent staging directory remains private to its own UID.
                for directory, _subdirectories, _files in os.walk(snapshot["contextRoot"]):
                    os.chmod(directory, 0o755)
                execution_spec = {**spec, "parameters": {**parameters, "sourceSnapshotPath": str(snapshot["contextRoot"])}}
                self._assert_activation_authority(reservation, grant)
            except (DeploymentStagingError, _Refusal, OSError) as exc:
                if snapshot is not None:
                    self._record_post_effect_reconciliation(spec["workloadId"], kind="source-admission-refused", detail=str(exc)[:280], target_state="failed", snapshot_path=str(snapshot["root"]))
                else:
                    self._transition_snapshot(ledger, reservation, "failed", at=self._config.clock(), finished_at=self._config.clock(), receipt={"kind": "source-admission-refused", "detail": str(exc)[:280]})
                raise _Refusal("source-admission-refused", "agent source archive or authority failed exact admission") from exc
        resource_enforcement = self._resource_enforcement(spec)
        source_snapshot_path = str(snapshot["root"]) if snapshot is not None else None
        try:
            container_id = self._engine.create(execution_spec, timeout=request["timeoutSeconds"])
        except EngineError as exc:
            self._record_post_effect_reconciliation(
                spec["workloadId"],
                kind="create-engine-failure",
                detail=str(exc),
                snapshot_path=source_snapshot_path,
                target_state=recovering_from or "failed",
            )
            raise _Refusal("engine-failure", str(exc)) from exc
        try:
            finalized = ledger.finalize_reserved(
                spec["workloadId"],
                at=self._config.clock(),
                container_id=container_id,
                expect_version=int(reservation["version"]),
                extra={"resourceEnforcement": resource_enforcement, **({"sourceSnapshotPath": source_snapshot_path, "sourceArchiveDigest": spec["parameters"]["sourceArchive"]["archiveDigest"]} if snapshot is not None else {})},
            )
        except LedgerError as exc:
            self._record_post_effect_reconciliation(
                spec["workloadId"],
                kind="create-cas-conflict",
                detail=str(exc),
                snapshot_path=source_snapshot_path,
                target_state=recovering_from or "failed",
            )
            raise _Refusal("state-conflict", str(exc)) from exc
        if spec["kind"] == "workspace":
            self._touch_activity(spec["workloadId"])
        observed = self._observed_for(spec["workloadId"])
        result = {
            "workloadId": spec["workloadId"],
            "state": "created",
            "specDigest": finalized["specDigest"],
            "resourceEnforcement": resource_enforcement,
        }
        if snapshot is not None:
            result["source"] = {"archiveDigest": snapshot["archiveDigest"], "contextDigest": snapshot["contextDigest"], "files": snapshot["files"], "bytes": snapshot["bytes"], "candidateStorage": "bounded-ephemeral-tmpfs", "durableChangedFiles": False}
        if seed is not None:
            result["sourceSeed"] = {"status": "complete", "reviewDigest": seed["reviewDigest"], "baseRevision": spec["parameters"]["baseRevision"], "fileCount": len(seed["sourceInventory"]), "reused": seed_reusing, "persistentVolumeQuota": "unsupported"}
        if recovering_from is not None:
            result.update(
                recovered=True,
                recoveredFromState=recovering_from,
            )
        return (
            result,
            observed,
            {
                "outcome": "not-required",
                "detail": (
                    "workspace container recreated; preserved data volume reattached"
                    if recovering_from is not None
                    else "workload created; removal is an explicit operation"
                ),
            },
        )

    def _op_start(
        self,
        request: Mapping[str, Any],
        payload: Mapping[str, Any],
        grant: Mapping[str, Any] | None,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
        ledger = self._ledger_required()
        entry = self._entry_required(payload["workloadId"])
        if "sourceSeed" in entry["spec"]["parameters"] and entry.get("sourceSeedStatus") != "complete":
            raise _Refusal("workspace-seed-incomplete", "partial source initialization cannot be started or adopted")
        self._assert_activation_authority(entry, grant)
        startable = {"created"}
        if entry["spec"].get("kind") == "workspace":
            # A stopped workspace restarts against its preserved container
            # and daemon-owned volume.
            startable.add("stopped")
        if entry["state"] not in startable:
            raise _Refusal(
                "invalid-state", f"workload is {entry['state']}; only a created workload can start"
            )
        target_id = self._assert_owned_container(entry)
        try:
            self._engine.start(entry["workloadId"], timeout=request["timeoutSeconds"], expected_container_id=target_id)
        except EngineError as exc:
            self._record_post_effect_reconciliation(
                entry["workloadId"],
                kind="start-engine-failure",
                detail=str(exc),
                target_state="failed",
            )
            raise _Refusal("engine-failure", str(exc)) from exc
        try:
            # Re-read live authority after the process effect and before the
            # durable activation CAS. A revocation at either boundary cannot
            # leave an activated process represented by stale created state.
            self._assert_activation_authority(entry, grant)
        except _Refusal as refusal:
            self._record_post_effect_reconciliation(
                entry["workloadId"],
                kind="start-authority-conflict",
                detail=f"{refusal.reason}: {refusal.detail}",
                target_state="cancelled",
            )
            raise
        started_at = self._config.clock()
        try:
            self._transition_snapshot(
                ledger,
                entry,
                "running",
                at=started_at,
                started_at=started_at,
            )
        except LedgerError as exc:
            self._record_post_effect_reconciliation(
                entry["workloadId"],
                kind="start-cas-conflict",
                detail=str(exc),
                target_state="failed",
            )
            raise _Refusal("state-conflict", str(exc)) from exc
        if entry["spec"].get("kind") == "workspace":
            self._touch_activity(entry["workloadId"])
        return (
            {"workloadId": entry["workloadId"], "state": "running"},
            self._observed_for(entry["workloadId"]),
            {"outcome": "not-required", "detail": "workload running under daemon supervision"},
        )

    def _op_stop(
        self,
        request: Mapping[str, Any],
        payload: Mapping[str, Any],
        grant: Mapping[str, Any] | None,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
        ledger = self._ledger_required()
        entry = self._entry_required(payload["workloadId"])
        self._assert_activation_authority(entry, grant)
        if entry["state"] in contract.TERMINAL_STATES:
            raise _Refusal("invalid-state", f"workload is already {entry['state']}")
        target_id = self._assert_owned_container(entry)
        is_workspace = entry["spec"].get("kind") == "workspace"
        if is_workspace:
            self._close_sessions_for(entry["workloadId"])
        entry = ledger.mark_source_termination(entry, at=self._config.clock(), reason="stopped")
        try:
            self._engine.stop(entry["workloadId"], timeout=2, expected_container_id=target_id)
        except EngineError as exc:
            raise _Refusal("engine-failure", str(exc)) from exc
        info = self._safe_inspect(entry["workloadId"])
        if info.get("present") is None or (
            info.get("present") is True and info.get("running") is not False
        ):
            self._record_post_effect_reconciliation(
                entry["workloadId"],
                kind="stop-verification-failure",
                detail="the stop effect did not verify a non-running container",
                target_state="failed",
            )
            raise _Refusal(
                "engine-failure", "workload stop could not verify a non-running container"
            )
        finished_at = self._config.clock()
        exit_status = info.get("exitStatus")
        next_state = "stopped" if is_workspace else "exited"
        entry = ledger.capture_source_command_output(entry, self._engine, at=self._config.clock(), termination_reason="stopped")
        try:
            self._transition_snapshot(
                ledger,
                entry,
                next_state,
                at=finished_at,
                exit_status=exit_status,
                finished_at=finished_at,
            )
        except LedgerError as exc:
            self._record_post_effect_reconciliation(
                entry["workloadId"],
                kind="stop-cas-conflict",
                detail=str(exc),
                target_state="failed",
            )
            raise _Refusal("state-conflict", str(exc)) from exc
        if is_workspace:
            self._touch_activity(entry["workloadId"])
        return (
            {"workloadId": entry["workloadId"], "state": next_state, "exitStatus": exit_status},
            self._observed_for(entry["workloadId"]),
            {"outcome": "performed", "detail": "workload stopped on explicit request"},
        )

    def _op_status(
        self,
        request: Mapping[str, Any],
        payload: Mapping[str, Any],
        grant: Mapping[str, Any] | None,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
        entry = self._entry_required(payload["workloadId"])
        self._assert_activation_authority(entry, grant)
        info = self._safe_inspect(entry["workloadId"])
        container_identity = self._assert_owned_container(entry) if info.get("present") else None
        state = entry["state"]
        if state == "running" and info.get("present") and not info.get("running"):
            finished_at = self._config.clock()
            entry = self._ledger_required().capture_source_command_output(entry, self._engine, at=finished_at, termination_reason="exited")
            state = "stopped" if entry["spec"].get("kind") == "workspace" else "exited"
            self._transition_snapshot(
                self._ledger_required(),
                entry,
                state,
                at=finished_at,
                exit_status=info.get("exitStatus"),
                finished_at=finished_at,
            )
            entry = self._entry_required(payload["workloadId"])
        return (
            {
                "containerIdentityDigest": "sha256:" + hashlib.sha256(container_identity.encode()).hexdigest() if container_identity else None,
                "workloadId": entry["workloadId"],
                "kind": entry["spec"].get("kind"),
                "state": state,
                "exitStatus": entry.get("exitStatus"),
                "engineStatus": info.get("status") if info.get("present") else "absent",
                **self._workload_inventory_metadata(entry),
            },
            self._observed_for(entry["workloadId"]),
            {"outcome": "not-required", "detail": "read-only operation"},
        )

    def _op_logs(
        self,
        request: Mapping[str, Any],
        payload: Mapping[str, Any],
        grant: Mapping[str, Any] | None,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
        entry = self._entry_required(payload["workloadId"])
        self._assert_activation_authority(entry, grant)
        bound = min(request["outputByteBound"], entry["spec"]["outputByteBound"])
        if "sourceArchive" in entry["spec"]["parameters"]:
            if entry.get("sourceCommandOutput") is not None:
                entry = self._ledger_required().capture_source_command_output(entry, self._engine, at=self._config.clock(), termination_reason="exited")
            else:
                info = self._safe_inspect(entry["workloadId"])
                if info.get("present") is True and info.get("running") is False:
                    entry = self._ledger_required().capture_source_command_output(entry, self._engine, at=self._config.clock(), termination_reason=str(entry["state"]) if entry["state"] in contract.TERMINAL_STATES else "exited")
            evidence = entry.get("sourceCommandOutput")
            if isinstance(evidence, Mapping):
                output = evidence["output"].encode("utf-8")[:bound].decode("utf-8", "ignore")
                return ({"workloadId": entry["workloadId"], "state": entry["state"], "output": output, "byteCount": len(output.encode("utf-8")), "truncated": evidence["truncated"] or evidence["byteCount"] > bound, "outputByteBound": bound, "sourceCommand": {key: value for key, value in evidence.items() if key != "output"}}, self._observed_for(entry["workloadId"]), {"outcome": "not-required", "detail": "durable bounded source command output"})
        target_id = self._assert_owned_container(entry)
        try:
            logs = self._engine.logs(entry["workloadId"], max_bytes=bound, expected_container_id=target_id)
        except EngineError as exc:
            raise _Refusal("engine-failure", str(exc)) from exc
        return (
            {
                "workloadId": entry["workloadId"],
                "state": entry["state"],
                "output": logs["bytes"],
                "byteCount": logs["byteCount"],
                "truncated": logs["truncated"],
                "outputByteBound": bound,
            },
            self._observed_for(entry["workloadId"]),
            {"outcome": "not-required", "detail": "read-only operation"},
        )

    # ------------------------------------------------- workspace terminals

    def _session_required(
        self, session_id: str, grant: Mapping[str, Any] | None
    ) -> _TerminalSession:
        with self._terminal_mutex:
            session = self._terminal_sessions.get(session_id)
            if session is None or session.session_id != session_id:
                session = None
        if session is None or session.closing.is_set():
            raise _Refusal("unknown-terminal", "terminal session is no longer active")
        # Terminal sessions stay inside the presenting grant's workload scope
        # and grant identity.
        if grant is not None:
            if session.workload_id not in grant["workloadIds"]:
                raise _Refusal(
                    "grant-workspace-mismatch", "the grant does not cover this terminal session"
                )
            if session.grant_id != grant["grantId"]:
                raise _Refusal(
                    "grant-identity-mismatch", "the grant does not own this terminal session"
                )
        return session

    def _op_open_terminal(
        self,
        request: Mapping[str, Any],
        payload: Mapping[str, Any],
        grant: Mapping[str, Any] | None,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
        entry = self._entry_required(payload["workloadId"])
        self._assert_activation_authority(entry, grant)
        if entry["spec"].get("kind") != "workspace":
            raise _Refusal("invalid-state", "terminal attach requires a workspace workload")
        if entry["state"] != "running":
            raise _Refusal("workspace-not-running", "terminal attach requires a running workspace")
        info = self._safe_inspect(entry["workloadId"])
        if not info.get("present") or not info.get("running"):
            raise _Refusal("workspace-not-running", "workspace container is not running")
        session_id = payload["sessionId"]
        process: Any = None
        master_fd = -1
        listener: socket.socket | None = None
        socket_identity: tuple[int, int] | None = None
        socket_path = self._terminal_directory() / f"{session_id}.sock"
        with self._terminal_mutex:
            if len(self._terminal_sessions) >= MAX_TERMINAL_SESSIONS:
                raise _Refusal("terminal-limit", "daemon terminal session capacity is exhausted")
            if session_id in self._terminal_sessions:
                raise _Refusal("duplicate-terminal", "terminal session already exists")
            try:
                exact_id = self._engine_target(entry)
                expected_digest = payload.get("expectedContainerIdentityDigest")
                if expected_digest is not None and expected_digest != "sha256:" + hashlib.sha256(exact_id.encode()).hexdigest():
                    raise _Refusal("workspace-identity-changed", "workspace container changed after terminal preparation")
                process, master_fd = self._engine.open_terminal(
                    entry["workloadId"],
                    expected_container_id=exact_id,
                    columns=payload["columns"],
                    rows=payload["rows"],
                    shell=tuple(entry["spec"]["parameters"].get("shell") or ("/bin/sh",)),
                )
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self._assert_socket_directory_binding()
                self._assert_terminal_directory_binding()
                listener.bind(self._terminal_socket_descriptor_path(socket_path.name))
                expected_gid = self._expected_socket_gid()
                if expected_gid is None:
                    raise OSError("terminal session socket group is unresolved")
                descriptor_path = self._terminal_socket_descriptor_path(socket_path.name)
                os.chown(descriptor_path, self._runtime_uid(), expected_gid)
                os.chmod(descriptor_path, 0o660)
                observed = os.stat(
                    socket_path.name,
                    dir_fd=self._terminal_directory_fd,
                    follow_symlinks=False,
                )
                if (
                    not stat.S_ISSOCK(observed.st_mode)
                    or observed.st_uid != self._runtime_uid()
                    or observed.st_gid != expected_gid
                    or stat.S_IMODE(observed.st_mode) != 0o660
                ):
                    raise OSError("terminal session socket ownership/mode validation failed")
                socket_identity = (observed.st_dev, observed.st_ino)
                listener.listen(1)
                self._assert_socket_directory_binding()
                self._assert_terminal_directory_binding()
            except (DaemonBootError, EngineError, OSError) as exc:
                if master_fd >= 0:
                    try:
                        os.close(master_fd)
                    except OSError:
                        pass
                if process is not None:
                    try:
                        process.kill()
                    except OSError:
                        pass
                if listener is not None:
                    try:
                        listener.close()
                    except OSError:
                        pass
                raise _Refusal("terminal-attach-failed", str(exc)[:300]) from exc
            assert socket_identity is not None
            session = _TerminalSession(
                session_id,
                entry["workloadId"],
                process,
                master_fd,
                listener,
                socket_path,
                socket_identity,
                grant_id=request["requester"]["grantId"],
            )
            self._terminal_sessions[session_id] = session
            thread = threading.Thread(
                target=self._serve_terminal,
                args=(session,),
                name=f"terminal-{session_id}",
                daemon=True,
            )
            thread.start()
            self._threads.append(thread)
        self._touch_activity(entry["workloadId"])
        return (
            {
                "sessionId": session_id,
                "workloadId": entry["workloadId"],
                # Host-confined session socket: only reachable by an allowed
                # peer uid inside the confined directory; never a browser.
                "socketPath": socket_path.as_posix(),
                "targetClass": "capsule",
                "reconnect": False,
                "executorPid": process.pid,
            },
            self._observed_for(entry["workloadId"]),
            {"outcome": "not-required", "detail": "terminal socket is owned by the execution host"},
        )

    def _op_resize_terminal(
        self,
        request: Mapping[str, Any],
        payload: Mapping[str, Any],
        grant: Mapping[str, Any] | None,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
        session = self._session_required(payload["sessionId"], grant)
        with session.mutex:
            if session.closing.is_set() or session.master_fd < 0:
                raise _Refusal("terminal-resize-failed", "terminal session is closing")
            try:
                self._engine.resize_terminal(
                    session.master_fd, columns=payload["columns"], rows=payload["rows"]
                )
            except EngineError as exc:
                raise _Refusal("terminal-resize-failed", str(exc)[:300]) from exc
        self._touch_activity(session.workload_id)
        return (
            {"sessionId": session.session_id, "columns": payload["columns"], "rows": payload["rows"]},
            self._empty_observed(),
            {"outcome": "performed", "detail": "terminal dimensions applied by the execution host"},
        )

    def _op_signal_terminal(
        self,
        request: Mapping[str, Any],
        payload: Mapping[str, Any],
        grant: Mapping[str, Any] | None,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
        session = self._session_required(payload["sessionId"], grant)
        # The container PTY line discipline turns the typed signal into the
        # real signal for the foreground process group.
        control = _TERMINAL_SIGNAL_BYTES[payload["signal"]]
        with session.mutex:
            if session.closing.is_set() or session.master_fd < 0:
                raise _Refusal("terminal-signal-failed", "terminal session is closing")
            try:
                os.write(session.master_fd, control)
            except OSError as exc:
                raise _Refusal("terminal-signal-failed", str(exc)[:300]) from exc
        self._touch_activity(session.workload_id)
        return (
            {"sessionId": session.session_id, "signal": payload["signal"]},
            self._empty_observed(),
            {"outcome": "performed", "detail": "signal delivered through the terminal PTY"},
        )

    def _op_close_terminal(
        self,
        request: Mapping[str, Any],
        payload: Mapping[str, Any],
        grant: Mapping[str, Any] | None,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
        session = self._session_required(payload["sessionId"], grant)
        self._close_terminal_session(session)
        self._touch_activity(session.workload_id)
        return (
            {"sessionId": payload["sessionId"], "state": "closing"},
            self._empty_observed(),
            {"outcome": "performed", "detail": "terminal process cleanup requested"},
        )

    def _op_exec_workload(
        self,
        request: Mapping[str, Any],
        payload: Mapping[str, Any],
        grant: Mapping[str, Any] | None,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
        entry = self._entry_required(payload["workloadId"])
        self._assert_activation_authority(entry, grant)
        if entry["spec"].get("kind") != "workspace":
            raise _Refusal("invalid-state", "typed exec requires a workspace workload")
        if entry["state"] != "running":
            raise _Refusal("workspace-not-running", "typed exec requires a running workspace")
        info = self._safe_inspect(entry["workloadId"])
        if not info.get("present") or not info.get("running"):
            raise _Refusal("workspace-not-running", "workspace container is not running")
        budgets = grant["budgets"] if grant is not None else None
        bound = request["outputByteBound"]
        if budgets is not None:
            bound = min(bound, budgets["maxOutputBytes"])
        timeout = request["timeoutSeconds"]
        if budgets is not None:
            timeout = min(timeout, budgets["maxTimeoutSeconds"])
        try:
            outcome = self._engine.exec_workload(
                entry["workloadId"],
                payload["argv"],
                timeout=timeout,
                max_bytes=bound,
                expected_container_id=self._engine_target(entry),
            )
        except EngineError as exc:
            raise _Refusal("engine-failure", str(exc)) from exc
        self._touch_activity(entry["workloadId"])
        observed = self._observed_for(entry["workloadId"])
        observed["exitStatus"] = outcome["exitStatus"]
        return (
            {
                "workloadId": entry["workloadId"],
                "exitStatus": outcome["exitStatus"],
                "output": outcome["output"],
                "byteCount": outcome["byteCount"],
                "truncated": outcome["truncated"],
                "outputByteBound": bound,
            },
            observed,
            {"outcome": "not-required", "detail": "typed exec completed; argv was never shell-joined"},
        )

    def _op_list_workloads(
        self,
        request: Mapping[str, Any],
        payload: Mapping[str, Any],
        grant: Mapping[str, Any] | None,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
        ledger = self._ledger_required()
        scope = set(grant["workloadIds"]) if grant is not None else set()
        workloads: list[dict[str, Any]] = []
        for snapshot in ledger.all():
            workload_id = str(snapshot["workloadId"])
            if workload_id not in scope or not self._grant_owns_entry(snapshot, grant):
                continue
            with self._workload_lock(workload_id):
                entry = ledger.get(workload_id)
                if entry is None:
                    continue
                info = self._safe_inspect(workload_id)
                state = entry["state"]
                if state == "running" and info.get("present") and not info.get("running"):
                    finished_at = self._config.clock()
                    state = (
                        "stopped"
                        if entry["spec"].get("kind") == "workspace"
                        else "exited"
                    )
                    entry = self._transition_snapshot(
                        ledger,
                        entry,
                        state,
                        at=finished_at,
                        exit_status=info.get("exitStatus"),
                        finished_at=finished_at,
                    )
                workloads.append(
                    {
                        "workloadId": workload_id,
                        "kind": entry["spec"].get("kind"),
                        "state": state,
                        "engineStatus": (
                            info.get("status") if info.get("present") else "absent"
                        ),
                        "running": bool(info.get("running")),
                        "imageDigest": info.get("imageDigest"),
                        "createdAt": entry.get("createdAt"),
                        "lastActivityAt": entry.get("lastActivityAt"),
                        "allowedOperations": sorted(grant["operations"]) if grant is not None else [],
                        **self._workload_inventory_metadata(entry),
                    }
                )
        return (
            {"workloads": sorted(workloads, key=lambda item: item["workloadId"]),
             "allowedOperations": sorted(grant["operations"]) if grant is not None else [],
             **({"workspaceProfile": {"imageReference": self._config.workspace_image_reference,
                                      "workloadSpecDigest": self._config.workspace_spec_digest}}
                if self._config.workspace_image_reference is not None and grant is not None and grant["grantId"] == "control-plane-default" else {})},
            self._empty_observed(),
            {"outcome": "not-required", "detail": "grant-scoped enumeration from daemon state"},
        )

    def _op_cancel(
        self,
        request: Mapping[str, Any],
        payload: Mapping[str, Any],
        grant: Mapping[str, Any] | None,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
        ledger = self._ledger_required()
        entry = self._entry_required(payload["workloadId"])
        self._assert_activation_authority(entry, grant)
        if entry["state"] in contract.TERMINAL_STATES:
            raise _Refusal("invalid-state", f"workload is already {entry['state']}")
        if entry["state"] == "reserved":
            cancelled_at = self._config.clock()
            self._transition_snapshot(
                ledger,
                entry,
                "cancelled",
                at=cancelled_at,
                finished_at=cancelled_at,
                receipt={
                    "kind": "cancel-reservation",
                    "detail": "reservation cancelled before an engine workload existed",
                    "cleanup": "not-required",
                },
            )
            return (
                {"workloadId": entry["workloadId"], "state": "cancelled"},
                self._empty_observed(),
                {"outcome": "not-required", "detail": "reservation cancelled"},
            )
        self._assert_owned_container(entry, allow_absent=True)
        self._close_sessions_for(entry["workloadId"])
        snapshot_path = (
            str(entry.get("sourceSnapshotPath") or entry["validatorSnapshotPath"])
            if entry.get("sourceSnapshotPath") or entry.get("validatorSnapshotPath")
            else None
        )
        complete, cleanup_detail, residual = self._cleanup_engine_effect(
            entry["workloadId"], snapshot_path=snapshot_path, termination_reason="cancelled"
        )
        entry = ledger.get(entry["workloadId"]) or entry
        if not complete:
            # A terminal cancellation state requires verified process/
            # container absence; otherwise the workload stays supervised.
            try:
                reconciled = self._transition_snapshot(
                    ledger,
                    entry,
                    "cleanup_failed",
                    at=self._config.clock(),
                    receipt={
                        "kind": "cancel-cleanup-failure",
                        "detail": f"cancel cleanup is incomplete: {cleanup_detail}",
                        "residual": residual,
                    },
                    extra={
                        "cleanupTargetState": "cancelled",
                        "cleanupFinishedAt": self._config.clock(),
                        **(
                            {"validatorSnapshotPath": snapshot_path}
                            if snapshot_path is not None
                            else {}
                        ),
                    },
                )
            except LedgerError as exc:
                reconciled = self._record_post_effect_reconciliation(
                    entry["workloadId"],
                    kind="cancel-cas-conflict",
                    detail=str(exc),
                    target_state="cancelled",
                    snapshot_path=snapshot_path,
                )
            return (
                {"workloadId": entry["workloadId"], "state": reconciled["state"]},
                self._observed_for(entry["workloadId"]),
                {
                    "outcome": "failed" if reconciled["state"] == "cleanup_failed" else "performed",
                    "detail": "cancel residual was durably reconciled",
                },
            )
        finished_at = self._config.clock()
        try:
            self._transition_snapshot(
                ledger,
                entry,
                "cancelled",
                at=finished_at,
                finished_at=finished_at,
                receipt={
                    "kind": "cancel",
                    "detail": "container absence verified after cancellation",
                    "cleanup": cleanup_detail,
                },
                extra={"validatorSnapshotPath": None, "sourceSnapshotPath": None},
            )
        except LedgerError as exc:
            self._record_post_effect_reconciliation(
                entry["workloadId"],
                kind="cancel-cas-conflict",
                detail=str(exc),
                target_state="cancelled",
                snapshot_path=snapshot_path,
            )
            raise _Refusal("state-conflict", str(exc)) from exc
        return (
            {"workloadId": entry["workloadId"], "state": "cancelled"},
            self._observed_for(entry["workloadId"]),
            {"outcome": "performed", "detail": "workload cancelled; container absence verified"},
        )

    def _op_remove(
        self,
        request: Mapping[str, Any],
        payload: Mapping[str, Any],
        grant: Mapping[str, Any] | None,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
        ledger = self._ledger_required()
        entry = self._entry_required(payload["workloadId"])
        self._assert_activation_authority(entry, grant)
        is_workspace = entry["spec"].get("kind") == "workspace"
        self._assert_owned_container(entry, allow_absent=True)
        snapshot_path = str(entry.get("sourceSnapshotPath") or entry["validatorSnapshotPath"]) if entry.get("sourceSnapshotPath") or entry.get("validatorSnapshotPath") else None
        complete, cleanup_detail, _residual = self._cleanup_engine_effect(
            entry["workloadId"], snapshot_path=snapshot_path, termination_reason="removed_while_running"
        )
        entry = ledger.get(entry["workloadId"]) or entry
        if not complete:
            self._record_post_effect_reconciliation(
                entry["workloadId"],
                kind="remove-engine-failure",
                detail=cleanup_detail,
                target_state="removed",
                snapshot_path=snapshot_path,
            )
            raise _Refusal("engine-failure", "workload removal could not verify container absence")
        try:
            self._transition_snapshot(
                ledger,
                entry,
                "removed",
                at=self._config.clock(),
                extra={"validatorSnapshotPath": None, "sourceSnapshotPath": None},
            )
        except LedgerError as exc:
            self._record_post_effect_reconciliation(
                entry["workloadId"],
                kind="remove-cas-conflict",
                detail=str(exc),
                target_state="removed",
                snapshot_path=(
                    str(entry.get("sourceSnapshotPath") or entry["validatorSnapshotPath"])
                    if entry.get("sourceSnapshotPath") or entry.get("validatorSnapshotPath")
                    else None
                ),
            )
            raise _Refusal("state-conflict", str(exc)) from exc
        detail = (
            # WorkspaceSpec preserveDataOnRemove: container removal never
            # deletes the daemon-owned named volume.
            "container removed; daemon-owned workspace volume is preserved"
            if is_workspace
            else "workload container removed; ledger entry retained for audit"
        )
        return (
            {"workloadId": entry["workloadId"], "state": "removed"},
            self._empty_observed(),
            {"outcome": "performed", "detail": detail},
        )

    # ------------------------------------------------- sealed validator runs

    def _admit_validator_staging(self, staging_path: str) -> Path:
        """Immutable staging admission: the exact validated path must resolve
        inside the daemon's validator staging root, lexically equal its
        resolution (no symlink components), and be a real directory."""
        root = self._config.validator_staging_root
        if root is None:
            raise _Refusal(
                "validator-unavailable", "the daemon has no validator staging root configured"
            )
        try:
            resolved_root = root.resolve(strict=True)
        except OSError as exc:
            raise _Refusal("validator-unavailable", f"validator staging root is absent: {exc}") from exc
        lexical = Path(os.path.normpath(staging_path))
        try:
            resolved = lexical.resolve(strict=True)
        except OSError as exc:
            raise _Refusal("staging-unavailable", f"validator staging path is not resolvable: {exc}") from exc
        if resolved != lexical.absolute():
            raise _Refusal(
                "staging-symlink", "validator staging path contains symlink components"
            )
        if not resolved.is_dir():
            raise _Refusal("staging-unavailable", "validator staging path is not a directory")
        if resolved != resolved_root and resolved_root not in resolved.parents:
            raise _Refusal(
                "staging-scope-violation", "validator staging path escapes the daemon staging root"
            )
        return resolved

    def _op_run_validator(
        self,
        request: Mapping[str, Any],
        payload: Mapping[str, Any],
        grant: Mapping[str, Any] | None,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
        ledger = self._ledger_required()
        spec = payload["workload"]
        if spec["kind"] != "validator-run":
            raise _Refusal("contract-violation", "runValidator requires a validator-run workload")
        parameters = spec["parameters"]
        staging = self._admit_validator_staging(parameters["stagingPath"])
        observed_command_digest = contract.canonical_digest(parameters["command"])
        if observed_command_digest != parameters["commandDigest"]:
            # Defense in depth: contract admission already performs this exact
            # recomputation before grant verification.
            raise _Refusal(
                "command-identity-mismatch",
                "validator command does not match its sealed command digest",
            )
        root = self._config.validator_staging_root
        if root is None:  # guarded by _admit_validator_staging
            raise _Refusal("validator-unavailable", "validator staging root is absent")
        try:
            snapshot = create_staging_snapshot(
                staging,
                trusted_root=root.resolve(strict=True),
                snapshots_root=self._validator_snapshots_root(),
                workload_id=spec["workloadId"],
                max_bytes=spec["resources"]["diskMaxBytes"],
            )
        except StagingIdentityError as exc:
            raise _Refusal("staging-identity-unreadable", str(exc)) from exc
        if snapshot.digest != parameters["stagingIdentityDigest"]:
            self._remove_snapshot_path(snapshot.path.as_posix())
            raise _Refusal(
                "staging-identity-mismatch",
                "staged content does not match the sealed staging identity digest",
            )
        execution_spec = {
            **spec,
            "parameters": {
                **parameters,
                # This is the only daemon transformation: replace the client
                # path with the exact private snapshot carrying the same
                # content identity. The client spec remains the grant/ledger
                # authority and both identities are recorded below.
                "stagingPath": snapshot.path.as_posix(),
            },
        }
        client_spec_digest = contract.canonical_digest(spec)
        execution_spec_digest = contract.canonical_digest(execution_spec)
        grant = grant or {}
        grant_id = str(grant.get("grantId", request["requester"]["grantId"]))
        budgets = grant.get("budgets", {})
        workload_id = spec["workloadId"]
        try:
            reservation = ledger.reserve(
                spec,
                at=self._config.clock(),
                grant_id=grant_id,
                grant_epoch=int(grant.get("revocationEpoch", 0)),
                max_active=contract.MAX_WORKLOADS,
                max_per_grant=int(budgets.get("maxActiveWorkloads", 256)),
                grant_digest=(contract.canonical_digest(grant) if grant else None),
            )
        except LedgerError as exc:
            self._remove_snapshot_path(snapshot.path.as_posix())
            detail = str(exc)
            reason = "duplicate-workload" if "already has a ledger entry" in detail else "workload-limit"
            raise _Refusal(reason, detail) from exc
        snapshot_binding = {
            "validatorSnapshotPath": snapshot.path.as_posix(),
            "validatorSnapshotPolicy": STAGING_SNAPSHOT_POLICY,
            "clientWorkloadSpecDigest": client_spec_digest,
            "executionWorkloadSpecDigest": execution_spec_digest,
            "executionStagingIdentityDigest": snapshot.digest,
            "snapshotEntryCount": snapshot.entry_count,
            "snapshotByteCount": snapshot.byte_count,
        }
        try:
            self._assert_activation_authority(reservation, grant)
        except _Refusal as refusal:
            self._remove_snapshot_path(snapshot.path.as_posix())
            self._transition_snapshot(
                ledger,
                reservation,
                "cancelled",
                at=self._config.clock(),
                finished_at=self._config.clock(),
                receipt={
                    "kind": "validator-authority-withdrawn",
                    "detail": refusal.detail,
                    "refusal": refusal.reason,
                    "cleanup": "not-required",
                },
            )
            raise
        started_at: str | None = None
        timed_out = False
        info: dict[str, Any] = {"present": False}
        logs: dict[str, Any] = {"bytes": "", "byteCount": 0, "truncated": False}
        try:
            container_id = self._engine.create(
                execution_spec, timeout=request["timeoutSeconds"]
            )
        except EngineError as exc:
            self._record_post_effect_reconciliation(
                workload_id,
                kind="validator-create-engine-failure",
                detail=str(exc),
                target_state="failed",
                snapshot_path=snapshot.path.as_posix(),
            )
            raise _Refusal("engine-failure", str(exc)) from exc
        try:
            created = ledger.finalize_reserved(
                workload_id,
                at=self._config.clock(),
                container_id=container_id,
                expect_version=int(reservation["version"]),
                extra=snapshot_binding,
            )
        except LedgerError as exc:
            self._record_post_effect_reconciliation(
                workload_id,
                kind="validator-create-cas-conflict",
                detail=str(exc),
                target_state="failed",
                snapshot_path=snapshot.path.as_posix(),
            )
            raise _Refusal("state-conflict", str(exc)) from exc
        try:
            self._assert_activation_authority(created, grant)
        except _Refusal as refusal:
            self._record_post_effect_reconciliation(
                workload_id,
                kind="validator-start-authority-conflict",
                detail=f"{refusal.reason}: {refusal.detail}",
                target_state="cancelled",
                snapshot_path=snapshot.path.as_posix(),
            )
            raise
        try:
            self._engine.start(workload_id, timeout=request["timeoutSeconds"], expected_container_id=self._engine_target(created))
        except EngineError as exc:
            self._record_post_effect_reconciliation(
                workload_id,
                kind="validator-start-engine-failure",
                detail=str(exc),
                target_state="failed",
                snapshot_path=snapshot.path.as_posix(),
            )
            raise _Refusal("engine-failure", str(exc)) from exc
        try:
            self._assert_activation_authority(created, grant)
        except _Refusal as refusal:
            self._record_post_effect_reconciliation(
                workload_id,
                kind="validator-post-start-authority-conflict",
                detail=f"{refusal.reason}: {refusal.detail}",
                target_state="cancelled",
                snapshot_path=snapshot.path.as_posix(),
            )
            raise
        started_at = self._config.clock()
        try:
            running_entry = self._transition_snapshot(
                ledger,
                created,
                "running",
                at=started_at,
                started_at=started_at,
            )
        except LedgerError as exc:
            self._record_post_effect_reconciliation(
                workload_id,
                kind="validator-start-cas-conflict",
                detail=str(exc),
                target_state="failed",
                snapshot_path=snapshot.path.as_posix(),
            )
            raise _Refusal("state-conflict", str(exc)) from exc
        try:
            # Observe completion at the engine/OS boundary, while requiring
            # the exact running ledger version to remain authoritative.
            deadline = time.monotonic() + spec["timeoutSeconds"]
            while True:
                current = ledger.get(workload_id)
                if (
                    current is None
                    or current["state"] != "running"
                    or int(current["version"]) != int(running_entry["version"])
                ):
                    raise _Refusal(
                        "state-conflict",
                        "validator durable state changed while execution was active",
                    )
                info = self._safe_inspect(workload_id)
                if info.get("present") is None:
                    raise EngineError(
                        str(info.get("inspectionError") or "validator inspection failed")
                    )
                if info.get("present") is False:
                    raise _Refusal(
                        "state-conflict",
                        "validator container disappeared while durable state remained running",
                    )
                if info.get("running") is False:
                    break
                if time.monotonic() > deadline:
                    timed_out = True
                    break
                time.sleep(0.05)
            if timed_out:
                try:
                    self._engine.kill(workload_id, expected_container_id=self._engine_target(self._entry_required(workload_id)))
                except EngineError:
                    pass
                info = self._safe_inspect(workload_id)
                if info.get("present") is None:
                    raise EngineError(
                        str(info.get("inspectionError") or "validator inspection failed")
                    )
            current = ledger.get(workload_id)
            if (
                current is None
                or current["state"] != "running"
                or int(current["version"]) != int(running_entry["version"])
            ):
                raise _Refusal(
                    "state-conflict",
                    "validator durable state changed before evidence collection",
                )
            logs = self._engine.logs(
                workload_id, max_bytes=spec["outputByteBound"], expected_container_id=self._engine_target(self._entry_required(workload_id))
            )
        except _Refusal as refusal:
            self._record_post_effect_reconciliation(
                workload_id,
                kind="validator-execution-state-conflict",
                detail=refusal.detail,
                target_state="failed",
                snapshot_path=snapshot.path.as_posix(),
            )
            raise
        except EngineError as exc:
            self._record_post_effect_reconciliation(
                workload_id,
                kind="validator-engine-failure",
                detail=str(exc),
                target_state="failed",
                snapshot_path=snapshot.path.as_posix(),
            )
            raise _Refusal("engine-failure", str(exc)) from exc
        finished_at = self._config.clock()
        exit_status = info.get("exitStatus")
        classification = "timed_out" if timed_out else ("passed" if exit_status == 0 else "failed")
        status = "passed" if classification == "passed" else "failed"
        output_text = str(logs.get("bytes", ""))
        output_digest = "sha256:" + hashlib.sha256(output_text.encode("utf-8")).hexdigest()
        evidence = {
            "formatVersion": "stateport.execution-host-validator-evidence/v1",
            "validatorId": parameters["validatorId"],
            "workloadId": workload_id,
            "classification": classification,
            "status": status,
            "validatorSpecDigest": parameters["validatorSpecDigest"],
            "stagingIdentityDigest": parameters["stagingIdentityDigest"],
            "executionStagingIdentityDigest": snapshot.digest,
            "stagingSnapshotPolicy": STAGING_SNAPSHOT_POLICY,
            "snapshotEntryCount": snapshot.entry_count,
            "snapshotByteCount": snapshot.byte_count,
            "clientWorkloadSpecDigest": client_spec_digest,
            "executionWorkloadSpecDigest": execution_spec_digest,
            "sealedCommandIdentityDigest": parameters["commandDigest"],
            "observedCommandIdentityDigest": observed_command_digest,
            "commandIdentityDigest": observed_command_digest,
            "imageDigest": info.get("imageDigest"),
            "observedExitStatus": exit_status,
            "timedOut": timed_out,
            "engine": self._engine.identity["engine"],
            "startedAt": started_at,
            "finishedAt": finished_at,
            "outputDigest": output_digest,
            "outputTruncated": bool(logs.get("truncated")),
            # Raw validator output is never persisted: evidence carries its
            # digest and truncation posture only.
            "rawOutputRecorded": False,
        }
        evidence_relative = Path("validator-evidence") / f"{workload_id}.json"
        evidence_path = ledger.state_dir / evidence_relative
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(evidence_path.parent, 0o700)
        _atomic_write(evidence_path, evidence)
        evidence_digest = "sha256:" + hashlib.sha256(evidence_path.read_bytes()).hexdigest()
        cleanup_complete, cleanup, residual = self._cleanup_engine_effect(
            workload_id, snapshot_path=snapshot.path.as_posix()
        )
        receipt = {
            "kind": "validator-run",
            "detail": f"validator completed with classification {classification}; evidence digest recorded, raw output discarded",
            "evidenceLocation": evidence_relative.as_posix(),
            "evidenceDigest": evidence_digest,
            "cleanup": cleanup,
        }
        final_state = "timed_out" if timed_out else "exited"
        try:
            if not cleanup_complete:
                self._transition_snapshot(
                    ledger,
                    running_entry,
                    "cleanup_failed",
                    at=self._config.clock(),
                    receipt={**receipt, "residual": residual},
                    extra={
                        "cleanupTargetState": final_state,
                        "cleanupFinishedAt": finished_at,
                        "cleanupExitStatus": exit_status,
                        "validatorSnapshotPath": snapshot.path.as_posix(),
                    },
                )
            else:
                self._transition_snapshot(
                    ledger,
                    running_entry,
                    final_state,
                    at=finished_at,
                    exit_status=exit_status,
                    finished_at=finished_at,
                    receipt=receipt,
                    extra={"validatorSnapshotPath": None, "sourceSnapshotPath": None},
                )
        except LedgerError as exc:
            try:
                evidence_path.unlink()
            except OSError:
                pass
            self._record_post_effect_reconciliation(
                workload_id,
                kind="validator-finalize-cas-conflict",
                detail=str(exc),
                target_state="failed",
                snapshot_path=snapshot.path.as_posix(),
            )
            raise _Refusal("state-conflict", str(exc)) from exc
        result = {
            "validatorId": parameters["validatorId"],
            "workloadId": workload_id,
            "status": status,
            "classification": classification,
            "imageDigest": info.get("imageDigest"),
            "commandIdentityDigest": observed_command_digest,
            "sealedCommandIdentityDigest": parameters["commandDigest"],
            "stagingIdentityDigest": parameters["stagingIdentityDigest"],
            "executionStagingIdentityDigest": snapshot.digest,
            "stagingSnapshotPolicy": STAGING_SNAPSHOT_POLICY,
            "clientWorkloadSpecDigest": client_spec_digest,
            "executionWorkloadSpecDigest": execution_spec_digest,
            "observedExitStatus": exit_status,
            "timedOut": timed_out,
            "evidenceLocation": evidence_relative.as_posix(),
            "evidenceDigest": evidence_digest,
        }
        observed = self._empty_observed()
        observed.update(
            {
                "imageDigest": info.get("imageDigest"),
                "exitStatus": exit_status,
                "startedAt": info.get("startedAt") or started_at,
                "finishedAt": info.get("finishedAt") or finished_at,
            }
        )
        outcome = "performed" if cleanup_complete else "failed"
        return result, observed, {"outcome": outcome, "detail": f"validator container cleanup: {cleanup}"}

    def _op_collect_garbage(
        self,
        request: Mapping[str, Any],
        payload: Mapping[str, Any],
        grant: Mapping[str, Any] | None,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
        ledger = self._ledger_required()
        active = ledger.active_workload_ids()
        removed: list[str] = []
        failures: list[str] = []
        for item in self._engine.list_managed():
            workload_id = item.get("workloadId")
            if not workload_id:
                continue
            workload_id = str(workload_id)
            with self._workload_lock(workload_id):
                current = ledger.get(workload_id)
                if current is not None and current["state"] not in contract.TERMINAL_STATES:
                    active.add(workload_id)
                    continue
                active.discard(workload_id)
                try:
                    target_id = self._engine_target(current)
                    ledger.capture_source_command_output(current, self._engine, at=self._config.clock(), termination_reason=str(current["state"]))
                    self._engine.remove(workload_id, force=True, expected_container_id=target_id)
                    if current is not None and current.get("sourceSnapshotPath"):
                        error = self._remove_snapshot_path(str(current["sourceSnapshotPath"]))
                        if error:
                            raise EngineError("source snapshot cleanup failed")
                    removed.append(workload_id)
                except (EngineError, LedgerError) as exc:
                    failures.append(f"{workload_id}: {exc}"[:200])
        if failures:
            raise _Refusal("engine-failure", "; ".join(failures))
        return (
            {"removedWorkloads": sorted(removed), "activeWorkloads": sorted(active)},
            self._empty_observed(),
            {"outcome": "performed", "detail": f"removed {len(removed)} terminated managed containers"},
        )


class _Refusal(Exception):
    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail
