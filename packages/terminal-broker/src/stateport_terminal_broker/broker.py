"""StatePort-owned local PTY broker with fail-closed ownership recovery.

The broker is transport neutral.  It accepts identities only from a trusted
caller, validates exact browser origins, keeps terminal bytes in memory, and
persists only process ownership, quarantine state, and bounded audit metadata.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import errno
import fcntl
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import pty
import re
import secrets
import select
import shutil
import signal
import stat
import struct
import subprocess
import sys
import termios
import threading
import time
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from .contracts import (
    TerminalAuditReceipt,
    TerminalConnectionProfile,
    TerminalExit,
    TerminalInput,
    TerminalOutput,
    TerminalReconnectToken,
    TerminalResize,
    TerminalSession,
    TerminalTarget,
)


BROKER_STATE_VERSION = "stateport.terminal-broker-state/v1"
_GENERATION = re.compile(r"^generation\.[0-9a-f]{64}$")
_MAX_SESSIONS = 64
_MAX_PENDING = 128
_MAX_TOKENS = 256
_MAX_AUDIT = 256
_MAX_QUARANTINE = 128
_MAX_INPUT_FRAME = 65_536
_MAX_OUTPUT_FRAME = 65_536
_CONTRACT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SANDBOX_SYSTEM_ROOTS = (Path("/usr"), Path("/bin"), Path("/lib"), Path("/lib64"))
_SANDBOX_RESERVED_ROOTS = frozenset(
    Path(value) for value in ("/", "/home", "/tmp", "/var", "/usr", "/etc", "/opt")
)


def _project_sandbox_command(
    sandbox_executable: Path,
    root: Path,
    command: tuple[str, ...],
) -> tuple[str, ...]:
    """Build a browser-inaccessible, project-scoped Bubblewrap launch.

    The writable project bind is the only host data tree exposed.  Runtime
    binaries and the few identity/loader files required by normal command-line
    tools are read-only; the network, process, home, run, and temporary
    namespaces are private.  An explicit ``elevated`` profile bypasses this
    helper and is therefore a visibly different server-owned policy.
    """

    if root in _SANDBOX_RESERVED_ROOTS or root == Path.home().resolve():
        raise ValueError("a project-scoped terminal requires a bounded project root")
    arguments: list[str] = [
        sandbox_executable.as_posix(),
        "--unshare-all",
        "--cap-drop",
        "ALL",
        "--hostname",
        "stateport-workspace",
    ]
    # The broker already gives each session a dedicated pseudoterminal and
    # process session.  Asking Bubblewrap to create another session would
    # detach the shell from that PTY and disable interactive job control.
    for system_root in _SANDBOX_SYSTEM_ROOTS:
        if system_root.exists():
            arguments.extend(("--ro-bind", system_root.as_posix(), system_root.as_posix()))
    arguments.extend((
        "--proc", "/proc",
        "--dev", "/dev",
        "--tmpfs", "/tmp",
        "--dir", "/home",
        "--dir", "/run",
        "--dir", "/etc",
    ))
    for config_file in (
        Path("/etc/ld.so.cache"),
        Path("/etc/passwd"),
        Path("/etc/group"),
        Path("/etc/nsswitch.conf"),
        Path("/etc/localtime"),
    ):
        if config_file.is_file() and not config_file.is_symlink():
            arguments.extend(("--ro-bind", config_file.as_posix(), config_file.as_posix()))

    # Bubblewrap creates bind destinations, not their missing ancestors.  Add
    # only the project path's parents that are not already supplied by a
    # read-only system bind or a private namespace above.
    supplied = (*_SANDBOX_SYSTEM_ROOTS, Path("/proc"), Path("/dev"), Path("/tmp"), Path("/home"), Path("/run"), Path("/etc"))
    for parent in reversed(root.parents):
        if parent == Path("/") or parent in supplied:
            continue
        if any(parent == base or base in parent.parents for base in _SANDBOX_SYSTEM_ROOTS):
            continue
        arguments.extend(("--dir", parent.as_posix()))
    arguments.extend((
        "--bind", root.as_posix(), root.as_posix(),
        "--chdir", root.as_posix(),
        "--setenv", "HOME", root.as_posix(),
        "--",
        *command,
    ))
    return tuple(arguments)


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON numeric constant: {value}")


class TerminalBrokerError(RuntimeError):
    """Base class for safe terminal broker failures."""


class TerminalAccessDenied(TerminalBrokerError):
    """The caller cannot access a terminal resource.

    The intentionally uniform message avoids distinguishing unknown session
    ids from sessions owned by another actor.
    """

    def __init__(self) -> None:
        super().__init__("terminal access denied")


class TerminalTokenError(TerminalBrokerError):
    def __init__(self) -> None:
        super().__init__("terminal session token is invalid or expired")


class TerminalTargetUnavailable(TerminalBrokerError):
    """A requested target is unavailable under its declared capability."""


class TerminalQuarantined(TerminalBrokerError):
    """The exact configured root is fail-closed after unresolved cleanup."""


class TerminalCleanupError(TerminalBrokerError):
    """Process-tree cleanup could not be proved."""


@dataclass(frozen=True)
class _PreparedSession:
    session_id: str
    profile_id: str
    actor_id: str
    instance_id: str
    root: Path
    origin: str
    generation: str
    created_at: float
    expires_at: float


@dataclass(frozen=True)
class _TokenBinding:
    session_id: str
    purpose: str
    actor_id: str
    instance_id: str
    root: str
    origin: str
    generation: str
    expires_at: float


@dataclass
class _LiveSession:
    prepared: _PreparedSession
    profile: TerminalConnectionProfile
    process: subprocess.Popen[bytes]
    master_fd: int
    pid: int
    process_group_id: int
    process_session_id: int
    start_time_ticks: str
    connected: bool
    last_activity: float
    input_bytes: int = 0
    output_bytes: int = 0
    replay: bytearray | None = None
    replay_start_offset: int = 0
    input_sequence: int = 0
    resize_sequence: int = 0

    def __post_init__(self) -> None:
        if self.replay is None:
            self.replay = bytearray()


def _utc(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _process_identity(pid: int) -> tuple[str, int, int, str] | None:
    """Return Linux state, process group, session, and start-time identity."""

    try:
        value = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        fields = value.rsplit(")", 1)[1].strip().split()
        state, group, session, started = fields[0], int(fields[2]), int(fields[3]), fields[19]
        if state not in frozenset("RSDZTWtXxIKP") or not started.isdigit():
            return None
        return state, group, session, started
    except (OSError, IndexError, ValueError):
        return None


def _process_generation(pid: int) -> str | None:
    try:
        values = Path(f"/proc/{pid}/environ").read_bytes().split(b"\0")
    except OSError:
        return None
    prefix = b"STATEPORT_PROCESS_GENERATION="
    for item in values:
        if item.startswith(prefix):
            try:
                result = item[len(prefix):].decode("ascii")
            except UnicodeDecodeError:
                return None
            return result if _GENERATION.fullmatch(result) else None
    return None


def _observe_started_identity(
    pid: int,
    generation: str,
    root_identity: tuple[int, int],
    timeout_seconds: float = 0.5,
) -> tuple[str, int, int, str] | None:
    """Wait briefly for procfs to expose the already exec'd gate environment."""

    deadline = time.monotonic() + timeout_seconds
    while True:
        identity = _process_identity(pid)
        try:
            cwd_stat = os.stat(f"/proc/{pid}/cwd")
            cwd_identity = (cwd_stat.st_dev, cwd_stat.st_ino)
        except OSError:
            cwd_identity = None
        if (
            identity is not None
            and identity[0] != "Z"
            and identity[1] == pid
            and identity[2] == pid
            and _process_generation(pid) == generation
            and cwd_identity == root_identity
        ):
            return identity
        if time.monotonic() >= deadline:
            return None
        time.sleep(0.005)


def _exact_generation_members(generation: str) -> tuple[tuple[int, str, str, int, int], ...] | None:
    if _GENERATION.fullmatch(generation) is None:
        return None
    try:
        entries = tuple(Path("/proc").iterdir())
    except OSError:
        return None
    result: list[tuple[int, str, str, int, int]] = []
    for entry in entries:
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        identity = _process_identity(pid)
        if identity is None or _process_generation(pid) != generation:
            continue
        state, group, session, started = identity
        result.append((pid, started, state, group, session))
    return tuple(sorted(result))


def _exact_session_members(session_id: int) -> tuple[tuple[int, str, str, int, int], ...] | None:
    try:
        entries = tuple(Path("/proc").iterdir())
    except OSError:
        return None
    result: list[tuple[int, str, str, int, int]] = []
    for entry in entries:
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        identity = _process_identity(pid)
        if identity is None:
            continue
        state, group, current_session, started = identity
        if current_session == session_id:
            result.append((pid, started, state, group, current_session))
    return tuple(sorted(result))


def _process_group_exists(group_id: int) -> bool:
    try:
        os.killpg(group_id, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _path_components_are_real(path: Path) -> bool:
    cursor = Path(path.anchor)
    try:
        for part in path.parts[1:]:
            cursor = cursor / part
            mode = cursor.lstat().st_mode
            if stat.S_ISLNK(mode):
                return False
        return True
    except OSError:
        return False


def _open_directory_fd(path: Path) -> int:
    """Open every absolute path component without following a symlink."""

    descriptor = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            next_descriptor = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _directory_identity(path: Path) -> tuple[int, int]:
    descriptor = _open_directory_fd(path)
    try:
        value = os.fstat(descriptor)
        return value.st_dev, value.st_ino
    finally:
        os.close(descriptor)


def _safe_existing_root(value: Path | str) -> Path:
    if not isinstance(value, (Path, str)) or not os.fspath(value):
        raise ValueError("selected terminal root is required")
    supplied = Path(os.fspath(value))
    if not supplied.is_absolute() or any(part in {".", ".."} for part in supplied.parts):
        raise ValueError("selected terminal root must be an absolute non-traversing path")
    raw = Path(os.path.abspath(os.fspath(supplied)))
    if not raw.is_absolute() or not raw.is_dir() or not _path_components_are_real(raw):
        raise ValueError("selected terminal root must be an existing non-symlink directory")
    resolved = raw.resolve(strict=True)
    if resolved != raw:
        raise ValueError("selected terminal root may not traverse a symlink")
    home = Path.home().resolve(strict=False)
    if resolved == Path(resolved.anchor) or resolved == home:
        raise ValueError("unrestricted root and home-directory terminal targets are forbidden")
    return resolved


def _safe_state_directory(value: Path | str) -> Path:
    if not isinstance(value, (Path, str)) or not os.fspath(value):
        raise ValueError("terminal broker state_directory is required")
    supplied = Path(os.fspath(value))
    if not supplied.is_absolute() or any(part in {".", ".."} for part in supplied.parts):
        raise ValueError("terminal broker state_directory must be an absolute non-traversing path")
    raw = Path(os.path.abspath(os.fspath(supplied)))
    if raw.exists():
        if not raw.is_dir() or not _path_components_are_real(raw):
            raise ValueError("terminal broker state directory is unsafe")
    else:
        parent = raw.parent
        if not parent.is_dir() or not _path_components_are_real(parent):
            raise ValueError("terminal broker state parent is unsafe")
        raw.mkdir(mode=0o700)
    os.chmod(raw, 0o700)
    if raw.is_symlink() or raw.resolve(strict=True) != raw:
        raise ValueError("terminal broker state directory may not be a symlink")
    return raw


class TerminalSessionBroker:
    """Own authenticated local PTY sessions behind a transport adapter.

    A profile is trusted server configuration.  Browser requests may select a
    profile and exact configured root, but may not supply a shell command,
    environment, SSH credential, host socket, or broader filesystem root.
    """

    def __init__(
        self,
        profiles: tuple[TerminalConnectionProfile, ...],
        *,
        state_directory: Path | str,
        allowed_origins: tuple[str, ...],
        token_ttl_seconds: int = 30,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if not profiles or len(profiles) > 128:
            raise ValueError("at least one bounded terminal profile is required")
        if (
            isinstance(token_ttl_seconds, bool)
            or not isinstance(token_ttl_seconds, int)
            or not 5 <= token_ttl_seconds <= 300
        ):
            raise ValueError("token_ttl_seconds must be between 5 and 300")
        if not allowed_origins or len(allowed_origins) > 32:
            raise ValueError("an explicit bounded origin allowlist is required")
        origins: set[str] = set()
        for origin in allowed_origins:
            try:
                parsed = urlsplit(origin)
            except (TypeError, ValueError) as exc:
                raise ValueError("allowed origins must be exact http(s) origins without paths") from exc
            local_http = parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
            if (
                not isinstance(origin, str) or not origin or origin != origin.strip()
                or origin == "*" or parsed.scheme not in {"http", "https"}
                or (parsed.scheme == "http" and not local_http)
                or not parsed.hostname or parsed.username is not None or parsed.password is not None
                or parsed.path or parsed.query or parsed.fragment
                or parsed.geturl() != origin
            ):
                raise ValueError("allowed origins must be exact http(s) origins without paths")
            origins.add(origin)
        if len(origins) != len(allowed_origins):
            raise ValueError("allowed origins must be unique")

        self._clock = clock or time.time
        self._token_ttl_seconds = token_ttl_seconds
        self._origins = frozenset(origins)
        self._state_directory = _safe_state_directory(state_directory)
        self._state_path = self._state_directory / "terminal-broker-state.json"
        self._lock_path = self._state_directory / "terminal-broker.lock"
        for candidate in (self._state_path, self._lock_path):
            if candidate.is_symlink():
                raise ValueError("terminal broker state files may not be symlinks")
        self._lock_fd = os.open(self._lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(self._lock_fd)
            raise TerminalBrokerError("another terminal broker owns this state directory") from exc

        self._mutex = threading.RLock()
        self._closed = False
        self._profiles: dict[str, TerminalConnectionProfile] = {}
        self._resolved_commands: dict[str, tuple[str, ...]] = {}
        self._sandbox_executables: dict[str, Path] = {}
        self._roots: dict[str, Path] = {}
        self._root_identities: dict[str, tuple[int, int]] = {}
        self._pending: dict[str, _PreparedSession] = {}
        self._tokens: dict[str, _TokenBinding] = {}
        self._live: dict[str, _LiveSession] = {}
        self._exits: dict[str, tuple[str, str, TerminalExit]] = {}
        self._audit: list[TerminalAuditReceipt] = []
        self._quarantine: dict[str, dict[str, Any]] = {}

        try:
            self._configure_profiles(profiles)
            recovered = self._load_state()
            self._recover_processes(recovered)
            self._persist_state()
        except Exception:
            fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            os.close(self._lock_fd)
            self._closed = True
            raise

    def _configure_profiles(self, profiles: tuple[TerminalConnectionProfile, ...]) -> None:
        target_ids: set[str] = set()
        for profile in profiles:
            if profile.profile_id in self._profiles:
                raise ValueError("terminal profile ids must be unique")
            if profile.target.target_id in target_ids:
                raise ValueError("each terminal target must have exactly one profile")
            target_ids.add(profile.target.target_id)
            self._profiles[profile.profile_id] = profile
            if profile.target.target_class != "local_pty":
                continue
            assert profile.working_root is not None
            root = _safe_existing_root(profile.working_root)
            state = self._state_directory
            if state == root or root in state.parents or state in root.parents:
                raise ValueError("terminal broker state must be outside every terminal working root")
            executable = Path(profile.command[0])
            if not executable.is_absolute():
                resolved = shutil.which(profile.command[0])
                if resolved is None:
                    raise ValueError("terminal command executable is unavailable")
                executable = Path(resolved)
            try:
                executable = executable.resolve(strict=True)
            except OSError as exc:
                raise ValueError("terminal command executable is unavailable") from exc
            if not executable.is_file() or not os.access(executable, os.X_OK):
                raise ValueError("terminal command executable must be an executable file")
            self._roots[profile.profile_id] = root
            self._root_identities[profile.profile_id] = _directory_identity(root)
            self._resolved_commands[profile.profile_id] = (executable.as_posix(), *profile.command[1:])
            if not profile.elevated:
                sandbox = shutil.which("bwrap")
                if sandbox is None:
                    raise ValueError("project-scoped terminal sandbox is unavailable")
                sandbox_path = Path(sandbox).resolve(strict=True)
                if not sandbox_path.is_file() or not os.access(sandbox_path, os.X_OK):
                    raise ValueError("project-scoped terminal sandbox is unavailable")
                self._sandbox_executables[profile.profile_id] = sandbox_path

    def _load_state(self) -> tuple[dict[str, Any], ...]:
        if not self._state_path.exists():
            return ()
        if self._state_path.is_symlink() or not self._state_path.is_file():
            raise TerminalBrokerError("terminal broker state file is unsafe")
        try:
            if self._state_path.stat().st_size > 1_048_576:
                raise TerminalBrokerError("terminal broker state exceeds its 1MiB bound")
            value = json.loads(
                self._state_path.read_text(encoding="utf-8"),
                object_pairs_hook=_unique_json_object,
                parse_constant=_reject_json_constant,
            )
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            raise TerminalBrokerError("terminal broker state is unreadable") from exc
        if not isinstance(value, Mapping) or set(value) != {"formatVersion", "activeSessions", "quarantine", "auditReceipts"}:
            raise TerminalBrokerError("terminal broker state has an invalid shape")
        if value["formatVersion"] != BROKER_STATE_VERSION:
            raise TerminalBrokerError("terminal broker state has an unsupported version")
        active = value["activeSessions"]
        quarantine = value["quarantine"]
        audit = value["auditReceipts"]
        if not isinstance(active, list) or len(active) > _MAX_SESSIONS:
            raise TerminalBrokerError("terminal broker active state is invalid")
        if not isinstance(quarantine, list) or len(quarantine) > _MAX_QUARANTINE:
            raise TerminalBrokerError("terminal broker quarantine state is invalid")
        if not isinstance(audit, list) or len(audit) > _MAX_AUDIT:
            raise TerminalBrokerError("terminal broker audit state is invalid")
        for item in quarantine:
            if not isinstance(item, Mapping) or set(item) != {"root", "rootDigest", "instanceId", "reason", "generationDigest", "occurredAt"}:
                raise TerminalBrokerError("terminal broker quarantine entry is invalid")
            root = item["root"]
            if not isinstance(root, str) or not Path(root).is_absolute() or ".." in Path(root).parts:
                raise TerminalBrokerError("terminal broker quarantine root is invalid")
            if item["rootDigest"] != _digest(root):
                raise TerminalBrokerError("terminal broker quarantine root digest is invalid")
            self._quarantine[root] = dict(item)
        for item in audit:
            audit_fields = {
                "receiptId", "sessionId", "targetId", "actorId", "instanceId",
                "action", "outcome", "occurredAt", "workingRootDigest",
                "generationDigest", "inputBytes", "outputBytes",
                "replayDroppedBytes", "cleanup",
            }
            if not isinstance(item, Mapping) or set(item) != audit_fields:
                raise TerminalBrokerError("terminal broker audit entry is invalid")
            try:
                receipt = TerminalAuditReceipt(
                    receipt_id=item["receiptId"], session_id=item["sessionId"],
                    target_id=item["targetId"], actor_id=item["actorId"],
                    instance_id=item["instanceId"], action=item["action"],
                    outcome=item["outcome"], occurred_at=item["occurredAt"],
                    working_root_digest=item["workingRootDigest"],
                    generation_digest=item["generationDigest"],
                    input_bytes=item["inputBytes"], output_bytes=item["outputBytes"],
                    replay_dropped_bytes=item["replayDroppedBytes"], cleanup=item["cleanup"],
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise TerminalBrokerError("terminal broker audit entry is invalid") from exc
            self._audit.append(receipt)
        if any(not isinstance(item, Mapping) for item in active):
            raise TerminalBrokerError("terminal broker active state is invalid")
        return tuple(dict(item) for item in active)

    def _active_record(self, live: _LiveSession) -> dict[str, Any]:
        return {
            "sessionId": live.prepared.session_id,
            "profileId": live.prepared.profile_id,
            "targetId": live.profile.target.target_id,
            "actorId": live.prepared.actor_id,
            "instanceId": live.prepared.instance_id,
            "root": live.prepared.root.as_posix(),
            "rootDevice": self._root_identities[live.prepared.profile_id][0],
            "rootInode": self._root_identities[live.prepared.profile_id][1],
            "generation": live.prepared.generation,
            "createdAt": live.prepared.created_at,
            "expiresAt": live.prepared.expires_at,
            "lastActivity": live.last_activity,
            "pid": live.pid,
            "processGroupId": live.process_group_id,
            "processSessionId": live.process_session_id,
            "startTimeTicks": live.start_time_ticks,
        }

    def _persist_state(self) -> None:
        value = {
            "formatVersion": BROKER_STATE_VERSION,
            "activeSessions": [self._active_record(self._live[key]) for key in sorted(self._live)],
            "quarantine": [self._quarantine[key] for key in sorted(self._quarantine)],
            "auditReceipts": [receipt.to_dict() | {} for receipt in self._audit[-_MAX_AUDIT:]],
        }
        # The nested receipt formatVersion is contract metadata; the state
        # loader deliberately ignores it while validating the explicit fields.
        for receipt in value["auditReceipts"]:
            receipt.pop("formatVersion", None)
            receipt.pop("localAdapterCleanup", None)
            receipt.pop("remoteProcessCleanup", None)
            receipt.pop("reconnectScope", None)
        encoded = (
            json.dumps(
                value, ensure_ascii=False, sort_keys=True,
                separators=(",", ":"), allow_nan=False,
            ) + "\n"
        ).encode("utf-8")
        temporary = self._state_directory / f".terminal-broker-state.{secrets.token_hex(12)}.tmp"
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.close(descriptor)
            descriptor = -1
            os.replace(temporary, self._state_path)
            os.chmod(self._state_path, 0o600)
            directory_fd = os.open(self._state_directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    @staticmethod
    def _validate_process_record(record: Mapping[str, Any]) -> tuple[int, int, int, str, str, str, str, str, str]:
        required = {
            "sessionId", "profileId", "targetId", "actorId", "instanceId", "root",
            "rootDevice", "rootInode",
            "generation", "createdAt", "expiresAt", "lastActivity", "pid",
            "processGroupId", "processSessionId", "startTimeTicks",
        }
        if set(record) != required:
            raise TerminalBrokerError("persisted terminal ownership record is invalid")
        pid, group, session = record["pid"], record["processGroupId"], record["processSessionId"]
        if (
            isinstance(pid, bool) or not isinstance(pid, int) or pid <= 1
            or group != pid or session != pid
            or not isinstance(record["startTimeTicks"], str) or not record["startTimeTicks"].isdigit()
            or not isinstance(record["generation"], str) or _GENERATION.fullmatch(record["generation"]) is None
        ):
            raise TerminalBrokerError("persisted terminal process identity is invalid")
        root_device, root_inode = record["rootDevice"], record["rootInode"]
        if (
            isinstance(root_device, bool) or not isinstance(root_device, int) or root_device < 0
            or isinstance(root_inode, bool) or not isinstance(root_inode, int) or root_inode <= 0
        ):
            raise TerminalBrokerError("persisted terminal root identity is invalid")
        strings = ("sessionId", "profileId", "targetId", "actorId", "instanceId", "root")
        if any(not isinstance(record[key], str) or not record[key] for key in strings):
            raise TerminalBrokerError("persisted terminal ownership identity is invalid")
        if any(_CONTRACT_ID.fullmatch(record[key]) is None for key in strings[:-1]):
            raise TerminalBrokerError("persisted terminal ownership identifier is invalid")
        if len(record["root"]) > 4096 or not Path(record["root"]).is_absolute() or ".." in Path(record["root"]).parts:
            raise TerminalBrokerError("persisted terminal ownership root is invalid")
        for key in ("createdAt", "expiresAt", "lastActivity"):
            amount = record[key]
            if isinstance(amount, bool) or not isinstance(amount, (int, float)) or not math.isfinite(float(amount)):
                raise TerminalBrokerError("persisted terminal ownership time is invalid")
        return (
            pid, group, session, record["startTimeTicks"], record["generation"],
            record["root"], record["instanceId"], record["sessionId"], record["targetId"],
        )

    @classmethod
    def _cleanup_record(cls, record: Mapping[str, Any]) -> str:
        pid, group, session, started, generation, _root, _instance, _session_id, _target = cls._validate_process_record(record)
        leader = _process_identity(pid)
        generation_members = _exact_generation_members(generation)
        session_members = _exact_session_members(session)
        if generation_members is None or session_members is None:
            return "cleanup_failed"
        leader_owned = (
            leader is not None
            and leader[1:] == (group, session, started)
            and _process_generation(pid) == generation
        )
        if not generation_members and not session_members:
            return "already_exited" if not _process_group_exists(group) else "cleanup_failed"
        if not leader_owned and not generation_members:
            # A numeric session/group may have been reused. Never signal it.
            return "cleanup_failed"

        def members() -> tuple[
            tuple[tuple[int, str, str, int, int], ...],
            frozenset[tuple[int, str]],
            bool,
        ] | None:
            by_generation = _exact_generation_members(generation)
            by_session = _exact_session_members(session)
            if by_generation is None or by_session is None:
                return None
            combined = {(item[0], item[1]): item for item in (*by_session, *by_generation)}
            current_leader = _process_identity(pid)
            current_leader_owned = (
                current_leader is not None
                and current_leader[1:] == (group, session, started)
            )
            generation_keys = frozenset((item[0], item[1]) for item in by_generation)
            return (
                tuple(combined[key] for key in sorted(combined)),
                generation_keys,
                current_leader_owned or bool(by_generation),
            )

        for selected_signal, delay in ((signal.SIGTERM, 0.20), (signal.SIGKILL, 0.25)):
            observation = members()
            if observation is None:
                return "cleanup_failed"
            current_members, generation_keys, session_anchor = observation
            active = [item for item in current_members if item[2] != "Z"]
            if not active:
                break
            for member_pid, member_started, _state, _member_group, member_session in active:
                current = _process_identity(member_pid)
                if current is None or current[3] != member_started:
                    continue
                owned_by_generation = (
                    (member_pid, member_started) in generation_keys
                    and _process_generation(member_pid) == generation
                )
                owned_by_session = session_anchor and member_session == session
                if not (owned_by_generation or owned_by_session):
                    continue
                try:
                    os.kill(member_pid, selected_signal)
                except ProcessLookupError:
                    pass
                except PermissionError:
                    return "cleanup_failed"
            deadline = time.monotonic() + delay
            while time.monotonic() < deadline:
                observation = members()
                if observation is None:
                    return "cleanup_failed"
                observed, _generation_keys, _session_anchor = observation
                if not any(item[2] != "Z" for item in observed):
                    break
                time.sleep(0.01)

        final_generation = _exact_generation_members(generation)
        final_session = _exact_session_members(session)
        if final_generation is None or final_session is None:
            return "cleanup_failed"
        remaining = {(item[0], item[1]): item for item in (*final_generation, *final_session)}
        if any(item[2] != "Z" for item in remaining.values()):
            return "cleanup_failed"
        # A zombie leader is safe to reap by the owning broker. A recovered
        # orphan is reaped by init; it is no longer executing.
        return "terminated"

    def _quarantine_root(self, record: Mapping[str, Any], reason: str) -> None:
        root = str(record["root"])
        if len(self._quarantine) >= _MAX_QUARANTINE and root not in self._quarantine:
            raise TerminalBrokerError("terminal quarantine capacity is exhausted")
        self._quarantine[root] = {
            "root": root,
            "rootDigest": _digest(root),
            "instanceId": str(record["instanceId"]),
            "reason": reason,
            "generationDigest": _digest(str(record["generation"])),
            "occurredAt": _utc(self._clock()),
        }

    def _recover_processes(self, records: tuple[dict[str, Any], ...]) -> None:
        for record in records:
            self._validate_process_record(record)
            profile = self._profiles.get(str(record["profileId"]))
            configured_root = self._roots.get(str(record["profileId"]))
            if (
                profile is None or configured_root is None
                or record["targetId"] != profile.target.target_id
                or record["root"] != configured_root.as_posix()
                or record["instanceId"] not in profile.instance_ids
            ):
                raise TerminalBrokerError("persisted terminal ownership does not match configured policy")
            root_identity_drifted = (
                (record["rootDevice"], record["rootInode"])
                != self._root_identities[str(record["profileId"])]
            )
            cleanup = self._cleanup_record(record)
            if root_identity_drifted:
                self._quarantine_root(record, "restart_root_identity_drifted")
            elif cleanup == "cleanup_failed":
                self._quarantine_root(record, "restart_cleanup_unresolved")
            receipt = TerminalAuditReceipt(
                receipt_id="receipt." + secrets.token_hex(24),
                session_id=str(record.get("sessionId", "invalid")),
                target_id=str(record.get("targetId", "invalid")),
                actor_id=str(record.get("actorId", "invalid")),
                instance_id=str(record.get("instanceId", "invalid")),
                action="recovered",
                outcome="cleanup_failed" if cleanup == "cleanup_failed" else "completed",
                occurred_at=_utc(self._clock()),
                working_root_digest=_digest(str(record.get("root", "invalid"))),
                generation_digest=_digest(str(record.get("generation", "invalid"))),
                input_bytes=0,
                output_bytes=0,
                replay_dropped_bytes=0,
                cleanup=cleanup,
            )
            self._append_audit(receipt)

    def _append_audit(self, receipt: TerminalAuditReceipt) -> None:
        self._audit.append(receipt)
        if len(self._audit) > _MAX_AUDIT:
            del self._audit[:-_MAX_AUDIT]

    def _assert_open(self) -> None:
        if self._closed:
            raise TerminalBrokerError("terminal broker is closed")

    def _origin(self, origin: str) -> None:
        if not isinstance(origin, str) or origin not in self._origins:
            raise TerminalAccessDenied()

    def targets(self) -> tuple[TerminalTarget, ...]:
        with self._mutex:
            self._assert_open()
            return tuple(self._profiles[key].target for key in sorted(self._profiles))

    def profile_summaries(self) -> tuple[dict[str, Any], ...]:
        with self._mutex:
            self._assert_open()
            values = []
            for key in sorted(self._profiles):
                profile = self._profiles[key]
                root = self._roots.get(key)
                values.append(profile.to_dict(working_root_digest=None if root is None else _digest(root.as_posix())))
            return tuple(values)

    def quarantine(self) -> tuple[dict[str, Any], ...]:
        """Return non-secret quarantine metadata without absolute roots."""

        with self._mutex:
            self._assert_open()
            return tuple({key: value for key, value in item.items() if key != "root"} for item in self._quarantine.values())

    def audit_receipts(self, *, actor_id: str, instance_id: str, origin: str) -> tuple[TerminalAuditReceipt, ...]:
        self._origin(origin)
        with self._mutex:
            self._assert_open()
            return tuple(item for item in self._audit if item.actor_id == actor_id and item.instance_id == instance_id)

    def _cleanup_tokens(self, now: float) -> None:
        expired = [digest for digest, item in self._tokens.items() if item.expires_at <= now]
        for digest in expired:
            binding = self._tokens.pop(digest)
            if binding.purpose == "create":
                self._pending.pop(binding.session_id, None)

    def _new_token(self, prepared: _PreparedSession, purpose: str) -> TerminalReconnectToken:
        now = self._clock()
        self._cleanup_tokens(now)
        if len(self._tokens) >= _MAX_TOKENS:
            raise TerminalBrokerError("terminal token capacity is exhausted")
        value = secrets.token_urlsafe(32)
        digest = hashlib.sha256(value.encode("ascii")).hexdigest()
        expires = now + self._token_ttl_seconds
        self._tokens[digest] = _TokenBinding(
            session_id=prepared.session_id,
            purpose=purpose,
            actor_id=prepared.actor_id,
            instance_id=prepared.instance_id,
            root=prepared.root.as_posix(),
            origin=prepared.origin,
            generation=prepared.generation,
            expires_at=expires,
        )
        return TerminalReconnectToken(value, prepared.session_id, purpose, _utc(expires))

    def prepare_session(
        self,
        profile_id: str,
        *,
        actor_id: str,
        instance_id: str,
        selected_root: Path | str,
        origin: str,
    ) -> TerminalReconnectToken:
        self._origin(origin)
        with self._mutex:
            self._assert_open()
            now = self._clock()
            self._cleanup_tokens(now)
            if len(self._pending) >= _MAX_PENDING or len(self._live) >= _MAX_SESSIONS:
                raise TerminalBrokerError("terminal session capacity is exhausted")
            profile = self._profiles.get(profile_id)
            if profile is None:
                raise TerminalTargetUnavailable("unknown terminal target profile")
            if profile.target.target_class != "local_pty" or profile.target.availability != "available":
                reason = profile.target.unavailable_reason or "terminal target is environment-gated"
                raise TerminalTargetUnavailable(reason)
            if instance_id not in profile.instance_ids:
                raise TerminalAccessDenied()
            if not isinstance(actor_id, str) or _CONTRACT_ID.fullmatch(actor_id) is None:
                raise TerminalAccessDenied()
            root = _safe_existing_root(selected_root)
            expected = self._roots[profile_id]
            if root != expected:
                raise TerminalAccessDenied()
            if _directory_identity(root) != self._root_identities[profile_id]:
                raise TerminalAccessDenied()
            if root.as_posix() in self._quarantine:
                raise TerminalQuarantined("selected terminal root is quarantined after unresolved cleanup")
            session_id = "terminal." + secrets.token_hex(24)
            generation = "generation." + secrets.token_hex(32)
            prepared = _PreparedSession(
                session_id, profile_id, actor_id, instance_id, root, origin,
                generation, now, now + profile.maximum_lifetime_seconds,
            )
            self._pending[session_id] = prepared
            return self._new_token(prepared, "create")

    def _consume_token(
        self,
        value: str,
        *,
        purpose: str,
        actor_id: str,
        instance_id: str,
        origin: str,
    ) -> _TokenBinding:
        if not isinstance(value, str) or len(value) > 256:
            raise TerminalTokenError()
        try:
            digest = hashlib.sha256(value.encode("ascii")).hexdigest()
        except UnicodeEncodeError as exc:
            raise TerminalTokenError() from exc
        binding = self._tokens.pop(digest, None)
        if binding is None:
            raise TerminalTokenError()
        now = self._clock()
        checks = (
            binding.expires_at > now,
            hmac.compare_digest(binding.purpose, purpose),
            hmac.compare_digest(binding.actor_id, actor_id),
            hmac.compare_digest(binding.instance_id, instance_id),
            hmac.compare_digest(binding.origin, origin),
        )
        if not all(checks):
            if binding.purpose == "create":
                self._pending.pop(binding.session_id, None)
            raise TerminalTokenError()
        return binding

    def _environment(self, profile: TerminalConnectionProfile, root: Path, generation: str) -> dict[str, str]:
        environment = {
            name: value for name, value in os.environ.items()
            if name in frozenset(profile.environment_allowlist)
        }
        environment.update({
            "HOME": root.as_posix(),
            "TERM": "xterm-256color",
            "COLORTERM": "truecolor",
            # The selected project is the shell HOME for confinement and
            # prompt consistency.  Disable shell history so routine terminal
            # use cannot create user-owned files inside that repository.
            "HISTFILE": "/dev/null",
            "HISTSIZE": "0",
            "HISTFILESIZE": "0",
            "BASH_ENV": "/dev/null",
            "ENV": "/dev/null",
            "STATEPORT_PROCESS_GENERATION": generation,
        })
        return environment

    def _session_contract(self, live: _LiveSession, state: str | None = None) -> TerminalSession:
        session_state = state or ("connected" if live.connected else "disconnected")
        return TerminalSession(
            live.prepared.session_id,
            live.profile.target.target_id,
            live.profile.target.target_class,
            live.prepared.actor_id,
            live.prepared.instance_id,
            session_state,
            _utc(live.prepared.created_at),
            _utc(live.prepared.expires_at),
            _utc(live.last_activity),
            _digest(live.prepared.generation),
            _digest(live.prepared.root.as_posix()),
            session_state == "connected",
        )

    def _receipt(self, live: _LiveSession, action: str, outcome: str, cleanup: str) -> TerminalAuditReceipt:
        replay_dropped = max(0, live.output_bytes - len(live.replay or b""))
        return TerminalAuditReceipt(
            "receipt." + secrets.token_hex(24),
            live.prepared.session_id,
            live.profile.target.target_id,
            live.prepared.actor_id,
            live.prepared.instance_id,
            action,
            outcome,
            _utc(self._clock()),
            _digest(live.prepared.root.as_posix()),
            _digest(live.prepared.generation),
            live.input_bytes,
            live.output_bytes,
            replay_dropped,
            cleanup,
        )

    def open_session(
        self,
        token: str,
        *,
        actor_id: str,
        instance_id: str,
        selected_root: Path | str,
        origin: str,
        columns: int = 80,
        rows: int = 24,
    ) -> tuple[TerminalSession, TerminalAuditReceipt]:
        self._origin(origin)
        if isinstance(columns, bool) or not isinstance(columns, int) or not 1 <= columns <= 1000:
            raise ValueError("columns must be between 1 and 1000")
        if isinstance(rows, bool) or not isinstance(rows, int) or not 1 <= rows <= 1000:
            raise ValueError("rows must be between 1 and 1000")
        with self._mutex:
            self._assert_open()
            binding = self._consume_token(
                token, purpose="create", actor_id=actor_id, instance_id=instance_id,
                origin=origin,
            )
            try:
                root = _safe_existing_root(selected_root)
            except ValueError as exc:
                self._pending.pop(binding.session_id, None)
                raise TerminalTokenError() from exc
            if not hmac.compare_digest(binding.root, root.as_posix()):
                self._pending.pop(binding.session_id, None)
                raise TerminalTokenError()
            prepared = self._pending.pop(binding.session_id, None)
            if prepared is None or prepared.generation != binding.generation:
                raise TerminalTokenError()
            profile = self._profiles[prepared.profile_id]
            if prepared.expires_at <= self._clock():
                raise TerminalTokenError()
            if root.as_posix() in self._quarantine:
                raise TerminalQuarantined("selected terminal root is quarantined after unresolved cleanup")

            try:
                root_fd = _open_directory_fd(root)
                root_stat = os.fstat(root_fd)
                root_identity = (root_stat.st_dev, root_stat.st_ino)
                if root_identity != self._root_identities[prepared.profile_id]:
                    raise OSError("terminal root identity changed")
            except OSError as exc:
                try:
                    os.close(root_fd)
                except (UnboundLocalError, OSError):
                    pass
                raise TerminalTokenError() from exc

            master_fd = slave_fd = gate_read = gate_write = -1
            process: subprocess.Popen[bytes] | None = None
            try:
                master_fd, slave_fd = pty.openpty()
                gate_read, gate_write = os.pipe()
                termios.tcsetattr(slave_fd, termios.TCSANOW, termios.tcgetattr(slave_fd))
                fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))
                gate_program = (
                    "import fcntl,os,sys,termios; gate=int(sys.argv[1]); root=int(sys.argv[2]); "
                    "fcntl.ioctl(0,termios.TIOCSCTTY,0); os.tcsetpgrp(0,os.getpgrp()); "
                    "os.fchdir(root); os.close(root); "
                    "allowed=os.read(gate,1)==b'1'; os.close(gate); "
                    "os.execvpe(sys.argv[3],sys.argv[3:],os.environ) if allowed else sys.exit(125)"
                )
                command = self._resolved_commands[prepared.profile_id]
                if not profile.elevated:
                    command = _project_sandbox_command(
                        self._sandbox_executables[prepared.profile_id], root, command,
                    )
                process = subprocess.Popen(
                    [
                        sys.executable,
                        "-I",
                        "-S",
                        "-c",
                        gate_program,
                        str(gate_read),
                        str(root_fd),
                        *command,
                    ],
                    env=self._environment(profile, root, prepared.generation),
                    stdin=slave_fd,
                    stdout=slave_fd,
                    stderr=slave_fd,
                    start_new_session=True,
                    close_fds=True,
                    pass_fds=(gate_read, root_fd),
                )
                os.close(root_fd)
                root_fd = -1
                os.close(slave_fd)
                slave_fd = -1
                os.close(gate_read)
                gate_read = -1
                identity = _observe_started_identity(process.pid, prepared.generation, root_identity)
                if identity is None:
                    raise TerminalBrokerError("terminal process ownership could not be proven before exec")
                os.set_blocking(master_fd, False)
                live = _LiveSession(
                    prepared=prepared, profile=profile, process=process, master_fd=master_fd,
                    pid=process.pid, process_group_id=process.pid,
                    process_session_id=process.pid, start_time_ticks=identity[3],
                    connected=True, last_activity=self._clock(),
                )
                self._live[prepared.session_id] = live
                # Persist exact ownership while the child is still behind the
                # exec gate. EOF before this point makes the child exit 125.
                self._persist_state()
                os.write(gate_write, b"1")
                os.close(gate_write)
                gate_write = -1
                receipt = self._receipt(live, "created", "accepted", "not_required")
                self._append_audit(receipt)
                self._persist_state()
                return self._session_contract(live), receipt
            except Exception:
                for descriptor in (gate_write, gate_read, slave_fd, root_fd):
                    if descriptor >= 0:
                        try:
                            os.close(descriptor)
                        except OSError:
                            pass
                if process is not None:
                    record = {
                        "sessionId": prepared.session_id,
                        "profileId": prepared.profile_id,
                        "targetId": profile.target.target_id,
                        "actorId": prepared.actor_id,
                        "instanceId": prepared.instance_id,
                        "root": prepared.root.as_posix(),
                        "rootDevice": root_identity[0],
                        "rootInode": root_identity[1],
                        "generation": prepared.generation,
                        "createdAt": prepared.created_at,
                        "expiresAt": prepared.expires_at,
                        "lastActivity": self._clock(),
                        "pid": process.pid,
                        "processGroupId": process.pid,
                        "processSessionId": process.pid,
                        "startTimeTicks": (_process_identity(process.pid) or ("", 0, 0, "0"))[3],
                    }
                    try:
                        cleanup = self._cleanup_record(record)
                    except TerminalBrokerError:
                        cleanup = "cleanup_failed"
                    try:
                        process.wait(timeout=0.5)
                    except (subprocess.TimeoutExpired, OSError):
                        pass
                    if cleanup == "cleanup_failed":
                        self._quarantine_root(record, "session_start_cleanup_unresolved")
                self._live.pop(prepared.session_id, None)
                try:
                    os.close(master_fd)
                except OSError:
                    pass
                self._persist_state()
                raise

    def _authorized(self, session_id: str, actor_id: str, instance_id: str, origin: str, *, connected: bool | None = None) -> _LiveSession:
        self._origin(origin)
        live = self._live.get(session_id)
        if (
            live is None
            or not hmac.compare_digest(live.prepared.actor_id, actor_id)
            or not hmac.compare_digest(live.prepared.instance_id, instance_id)
            or not hmac.compare_digest(live.prepared.origin, origin)
            or (connected is not None and live.connected != connected)
        ):
            raise TerminalAccessDenied()
        return live

    def list_sessions(self, *, actor_id: str, instance_id: str, origin: str) -> tuple[TerminalSession, ...]:
        self._origin(origin)
        with self._mutex:
            self._assert_open()
            return tuple(
                self._session_contract(live)
                for live in self._live.values()
                if live.prepared.actor_id == actor_id and live.prepared.instance_id == instance_id
            )

    def write_input(
        self, session_id: str, data: bytes, *, actor_id: str, instance_id: str, origin: str,
    ) -> TerminalInput:
        if not isinstance(data, bytes) or not data or len(data) > _MAX_INPUT_FRAME:
            raise ValueError("terminal input must be non-empty bytes bounded to 64KiB")
        with self._mutex:
            self._assert_open()
            live = self._authorized(session_id, actor_id, instance_id, origin, connected=True)
            try:
                written = os.write(live.master_fd, data)
            except (BrokenPipeError, OSError) as exc:
                raise TerminalBrokerError("terminal input could not be delivered") from exc
            if written != len(data):
                raise TerminalBrokerError("terminal input was only partially delivered")
            live.input_bytes += written
            live.input_sequence += 1
            live.last_activity = self._clock()
            self._persist_state()
            return TerminalInput(session_id, written, live.input_sequence)

    def resize(
        self, session_id: str, columns: int, rows: int, *, actor_id: str, instance_id: str, origin: str,
    ) -> TerminalResize:
        with self._mutex:
            self._assert_open()
            live = self._authorized(session_id, actor_id, instance_id, origin, connected=True)
            if isinstance(columns, bool) or not isinstance(columns, int) or not 1 <= columns <= 1000:
                raise ValueError("columns must be between 1 and 1000")
            if isinstance(rows, bool) or not isinstance(rows, int) or not 1 <= rows <= 1000:
                raise ValueError("rows must be between 1 and 1000")
            fcntl.ioctl(live.master_fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))
            live.resize_sequence += 1
            live.last_activity = self._clock()
            self._persist_state()
            return TerminalResize(session_id, columns, rows, live.resize_sequence)

    def _record_output(self, live: _LiveSession, data: bytes) -> bytes:
        remaining = live.profile.output_limit_bytes - live.output_bytes
        kept = data[:max(0, remaining)]
        start = live.output_bytes
        live.output_bytes += len(kept)
        assert live.replay is not None
        live.replay.extend(kept)
        if len(live.replay) > live.profile.replay_limit_bytes:
            dropped = len(live.replay) - live.profile.replay_limit_bytes
            del live.replay[:dropped]
            live.replay_start_offset = start + len(kept) - len(live.replay)
        if len(data) > remaining:
            self._finalize_live(live, "output_limit", "closed")
            raise TerminalBrokerError("terminal output limit was reached")
        return kept

    def read_output(
        self,
        session_id: str,
        *,
        actor_id: str,
        instance_id: str,
        origin: str,
        maximum_bytes: int = _MAX_OUTPUT_FRAME,
        timeout_seconds: float = 0.0,
    ) -> TerminalOutput:
        if isinstance(maximum_bytes, bool) or not isinstance(maximum_bytes, int) or not 1 <= maximum_bytes <= _MAX_OUTPUT_FRAME:
            raise ValueError("maximum_bytes must be between 1 and 65536")
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or not 0 <= timeout_seconds <= 1.0:
            raise ValueError("timeout_seconds must be between 0 and 1")
        with self._mutex:
            self._assert_open()
            live = self._authorized(session_id, actor_id, instance_id, origin, connected=True)
            before = live.output_bytes
            data = b""
            eof = False
            try:
                readable, _, _ = select.select([live.master_fd], [], [], float(timeout_seconds))
                if readable:
                    try:
                        data = os.read(live.master_fd, maximum_bytes)
                    except OSError as exc:
                        if exc.errno == errno.EIO:
                            data = b""
                            eof = True
                        else:
                            raise
            except OSError as exc:
                raise TerminalBrokerError("terminal output could not be read") from exc
            if data:
                data = self._record_output(live, data)
                live.last_activity = self._clock()
            if live.process.poll() is not None and not data:
                eof = True
            dropped_before = live.replay_start_offset
            if eof:
                self._finalize_live(live, "process_exit", "closed")
            else:
                self._persist_state()
            return TerminalOutput(session_id, data, before, before + len(data), False, dropped_before, eof)

    def replay_output(
        self,
        session_id: str,
        after_offset: int,
        *,
        actor_id: str,
        instance_id: str,
        origin: str,
        maximum_bytes: int = _MAX_OUTPUT_FRAME,
    ) -> TerminalOutput:
        if isinstance(after_offset, bool) or not isinstance(after_offset, int) or after_offset < 0:
            raise ValueError("after_offset must be non-negative")
        if isinstance(maximum_bytes, bool) or not isinstance(maximum_bytes, int) or not 1 <= maximum_bytes <= _MAX_OUTPUT_FRAME:
            raise ValueError("maximum_bytes must be between 1 and 65536")
        with self._mutex:
            self._assert_open()
            live = self._authorized(session_id, actor_id, instance_id, origin, connected=True)
            assert live.replay is not None
            start = max(after_offset, live.replay_start_offset)
            relative = max(0, start - live.replay_start_offset)
            data = bytes(live.replay[relative:relative + maximum_bytes])
            live.last_activity = self._clock()
            self._persist_state()
            return TerminalOutput(session_id, data, start, start + len(data), True, live.replay_start_offset, False)

    def disconnect_session(
        self, session_id: str, *, actor_id: str, instance_id: str, origin: str,
    ) -> TerminalAuditReceipt:
        with self._mutex:
            self._assert_open()
            live = self._authorized(session_id, actor_id, instance_id, origin, connected=True)
            live.connected = False
            live.last_activity = self._clock()
            receipt = self._receipt(live, "disconnected", "completed", "not_required")
            self._append_audit(receipt)
            self._persist_state()
            return receipt

    def prepare_reconnect(
        self, session_id: str, *, actor_id: str, instance_id: str, origin: str,
    ) -> TerminalReconnectToken:
        with self._mutex:
            self._assert_open()
            live = self._authorized(session_id, actor_id, instance_id, origin, connected=False)
            if live.process.poll() is not None:
                self._finalize_live(live, "process_exit", "closed")
                raise TerminalAccessDenied()
            return self._new_token(live.prepared, "reconnect")

    def reconnect_session(
        self,
        token: str,
        *,
        actor_id: str,
        instance_id: str,
        selected_root: Path | str,
        origin: str,
    ) -> tuple[TerminalSession, TerminalAuditReceipt]:
        self._origin(origin)
        with self._mutex:
            self._assert_open()
            binding = self._consume_token(
                token, purpose="reconnect", actor_id=actor_id, instance_id=instance_id,
                origin=origin,
            )
            try:
                root = _safe_existing_root(selected_root)
            except ValueError as exc:
                raise TerminalTokenError() from exc
            if not hmac.compare_digest(binding.root, root.as_posix()):
                raise TerminalTokenError()
            live = self._authorized(binding.session_id, actor_id, instance_id, origin, connected=False)
            if live.prepared.generation != binding.generation or root != live.prepared.root:
                raise TerminalTokenError()
            if root.as_posix() in self._quarantine or live.process.poll() is not None:
                if live.process.poll() is not None:
                    self._finalize_live(live, "process_exit", "closed")
                raise TerminalAccessDenied()
            live.connected = True
            live.last_activity = self._clock()
            receipt = self._receipt(live, "reconnected", "accepted", "not_required")
            self._append_audit(receipt)
            self._persist_state()
            return self._session_contract(live), receipt

    def _finalize_live(self, live: _LiveSession, reason: str, action: str) -> tuple[TerminalExit, TerminalAuditReceipt]:
        live.process.poll()  # Reap a naturally exited leader before descendant proof.
        record = self._active_record(live)
        cleanup = self._cleanup_record(record)
        try:
            live.process.wait(timeout=0.5)
        except (subprocess.TimeoutExpired, OSError):
            pass
        try:
            os.close(live.master_fd)
        except OSError:
            pass
        self._live.pop(live.prepared.session_id, None)
        if cleanup == "cleanup_failed":
            self._quarantine_root(record, "terminal_cleanup_unresolved")
        now = self._clock()
        exit_contract = TerminalExit(
            live.prepared.session_id,
            reason,
            live.process.returncode,
            cleanup,
            _utc(now),
        )
        outcome = "cleanup_failed" if cleanup == "cleanup_failed" else "completed"
        receipt = self._receipt(live, action, outcome, cleanup)
        self._append_audit(receipt)
        self._exits[live.prepared.session_id] = (live.prepared.actor_id, live.prepared.instance_id, exit_contract)
        if len(self._exits) > _MAX_AUDIT:
            self._exits.pop(next(iter(self._exits)))
        self._persist_state()
        return exit_contract, receipt

    def close_session(
        self,
        session_id: str,
        *,
        actor_id: str,
        instance_id: str,
        origin: str,
        reason: str = "operator_closed",
    ) -> tuple[TerminalExit, TerminalAuditReceipt]:
        if (
            not isinstance(reason, str) or not reason or reason != reason.strip()
            or len(reason) > 128 or any(ord(character) < 32 for character in reason)
        ):
            raise ValueError("terminal close reason must be bounded")
        with self._mutex:
            self._assert_open()
            live = self._authorized(session_id, actor_id, instance_id, origin)
            return self._finalize_live(live, reason, "closed")

    def poll_exit(
        self, session_id: str, *, actor_id: str, instance_id: str, origin: str,
    ) -> TerminalExit | None:
        self._origin(origin)
        with self._mutex:
            self._assert_open()
            value = self._exits.get(session_id)
            if value is None:
                if session_id in self._live:
                    self._authorized(session_id, actor_id, instance_id, origin)
                    return None
                raise TerminalAccessDenied()
            owner, instance, result = value
            if not hmac.compare_digest(owner, actor_id) or not hmac.compare_digest(instance, instance_id):
                raise TerminalAccessDenied()
            return result

    def sweep_expired(self) -> tuple[TerminalExit, ...]:
        with self._mutex:
            self._assert_open()
            now = self._clock()
            self._cleanup_tokens(now)
            results: list[TerminalExit] = []
            for live in tuple(self._live.values()):
                if live.process.poll() is not None:
                    exit_contract, _ = self._finalize_live(live, "process_exit", "closed")
                    results.append(exit_contract)
                elif now >= live.prepared.expires_at:
                    exit_contract, _ = self._finalize_live(live, "maximum_lifetime", "timed_out")
                    results.append(exit_contract)
                elif now - live.last_activity >= live.profile.idle_timeout_seconds:
                    exit_contract, _ = self._finalize_live(live, "idle_timeout", "timed_out")
                    results.append(exit_contract)
            return tuple(results)

    def close(self) -> tuple[TerminalExit, ...]:
        with self._mutex:
            if self._closed:
                return ()
            results: list[TerminalExit] = []
            for live in tuple(self._live.values()):
                exit_contract, _ = self._finalize_live(live, "broker_shutdown", "closed")
                results.append(exit_contract)
            self._pending.clear()
            self._tokens.clear()
            self._persist_state()
            self._closed = True
            fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            os.close(self._lock_fd)
            return tuple(results)

    def __enter__(self) -> "TerminalSessionBroker":
        return self

    def __exit__(self, _exc_type: Any, _exc: Any, _traceback: Any) -> None:
        self.close()
