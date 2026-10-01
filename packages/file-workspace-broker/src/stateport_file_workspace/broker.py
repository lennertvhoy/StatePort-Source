"""Symlink-safe, lease-bound broker for a development application's files."""

from __future__ import annotations

import ctypes
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import difflib
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import select
import stat
import subprocess
import threading
import time
from typing import Callable, Iterable

from governed_runner.lease import InstanceLease, InstanceLeaseBusy, InstanceLeaseError

from .contracts import (
    FILE_WORKSPACE_FORMAT,
    DiffPreview,
    DirectoryEntry,
    DirectoryListing,
    FileMetadata,
    FileMutationReceipt,
    FileRead,
    FileWorkspaceProfile,
    PathPolicyRule,
    PreparedWrite,
    relative_path,
)


_GIT_SHA = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_SAFE_SUFFIXES = frozenset({
    ".c", ".cc", ".conf", ".cpp", ".css", ".csv", ".go", ".h", ".hpp",
    ".html", ".ini", ".java", ".js", ".json", ".jsx", ".md", ".mjs",
    ".py", ".rb", ".rs", ".scss", ".sh", ".sql", ".toml", ".ts", ".tsx",
    ".txt", ".xml", ".yaml", ".yml", ".nix", ".tf", ".tfvars", ".hcl", ".lock",
})
_SAFE_EXTENSIONLESS = frozenset({
    "AGENTS.md", "BACKLOG.md", "CHANGELOG", "Dockerfile", "LICENSE", "Makefile",
    "NEXT_ACTIONS.md", "PROJECT_ADAPTER.yaml", "PROJECT_DNA.yaml", "PROJECT_STATE.yaml", "README", "README.md",
    "STATUS.md", "WORKLOG.md",
})
_RESERVED_COMPONENTS = frozenset({
    ".aws", ".azure", ".git", ".gnupg", ".kube", ".ssh", ".stateport",
    ".venv", "__pycache__", "node_modules",
})
_SENSITIVE_NAMES = frozenset({
    ".dockercfg", ".env", ".git-credentials", ".htpasswd", ".netrc", ".npmrc", ".pypirc",
    "access-key", "access_key", "api-key", "api_key", "authorized_keys", "credentials",
    "credentials.json", "id_dsa", "id_ecdsa", "id_ed25519", "id_rsa", "known_hosts",
    "passwd", "password", "private-key", "private_key", "secrets.json", "secrets.yaml",
    "secrets.yml", "service-account.json", "service_account.json", "token", "token.json",
})
_SENSITIVE_SUFFIXES = frozenset({".key", ".p12", ".pfx", ".pem"})
_SENSITIVE_PATH_TOKENS = frozenset({"credential", "credentials", "secret", "secrets", "token", "tokens"})
_SENSITIVE_KEY_PREFIXES = frozenset({"access", "api", "private", "signing"})
_SENSITIVE_CONTAINER_SUFFIXES = frozenset({".jks", ".keystore", ".kubeconfig", ".ovpn"})
_TOKEN_BOUNDARY = re.compile(r"[._-]+")
_MAX_DIFF_CHARACTERS = 262_144
_RENAME_NOREPLACE = 1
_RENAME_EXCHANGE = 2
_QUARANTINE_FORMAT = "stateport.file-workspace-quarantine/v1"
_QUARANTINE_STATUS_FORMAT = "stateport.file-workspace-quarantine-status/v1"
_QUARANTINE_CLEAR_FORMAT = "stateport.file-workspace-quarantine-clear/v1"
_QUARANTINE_RECORD_LIMIT = 16_384
_QUARANTINE_REASON = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_RECOVERY_ARTIFACT = re.compile(
    r"^\.stateport-(?:write|delete|rollback|recovery)-[0-9a-f]{32}\.tmp$"
)
_GIT_COMMAND_PREFIX = ("git", "-c", "core.hooksPath=/dev/null")
_GIT_ENV = {
    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    "LC_ALL": "C",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
}
_LIBC = ctypes.CDLL(None, use_errno=True)
_RENAMEAT2 = getattr(_LIBC, "renameat2", None)
if _RENAMEAT2 is not None:
    _RENAMEAT2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    _RENAMEAT2.restype = ctypes.c_int


class FileWorkspaceError(RuntimeError):
    """Base class for safe file-workspace failures."""


class FileWorkspaceAccessDenied(FileWorkspaceError):
    def __init__(self) -> None:
        super().__init__("file workspace access denied")


class FileWorkspacePathError(FileWorkspaceError):
    """A path is malformed, unknown, reserved, or outside its declared rule."""


class FileWorkspaceTypeRefused(FileWorkspaceError):
    """A binary, oversized, active-secret, or unsupported file was refused."""


class FileWorkspaceLeaseDenied(FileWorkspaceError):
    """The exact project already has a writer or a lease could not be proved."""


class FileWorkspaceStale(FileWorkspaceError):
    """The Git base, source content, or staged identity changed."""

    def __init__(self, message: str, *, prepared_write_id: str | None = None, current_hash: str | None = None) -> None:
        super().__init__(message)
        self.prepared_write_id = prepared_write_id
        self.current_hash = current_hash


class FileWorkspaceValidationError(FileWorkspaceError):
    """A candidate failed syntax or canonical StateSpec validation."""

    def __init__(self, issues: Iterable[str]) -> None:
        values = tuple(str(item)[:240] for item in issues if str(item).strip())
        super().__init__("file workspace validation failed" + (f": {values[0]}" if values else ""))
        self.issues = values


class FileWorkspaceAtomicWriteError(FileWorkspaceError):
    """The atomic replacement failed and the original path was retained."""


@dataclass
class _PendingWrite:
    prepared: PreparedWrite
    original: bytes | None
    candidate: bytes
    lease: InstanceLease | None
    expires_at: float
    preview_digest: str | None = None
    preview_truncated: bool = False
    state: str = "prepared"


def _utc(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _hash(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _receipt_id() -> str:
    return "file-receipt." + secrets.token_hex(16)


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _credential_like_path(components: tuple[str, ...]) -> bool:
    """Classify bounded credential path patterns without inspecting values."""

    if not components:
        return False
    lowered = tuple(component.casefold() for component in components)
    name = lowered[-1]
    component_tokens = tuple(
        tuple(token for token in _TOKEN_BOUNDARY.split(component) if token)
        for component in lowered
    )
    path_tokens = frozenset(
        token
        for tokens in component_tokens
        for token in tokens
    )
    contains_sensitive_key_pair = any(
        any(left in _SENSITIVE_KEY_PREFIXES and right == "key" for left, right in zip(tokens, tokens[1:]))
        for tokens in component_tokens
    )
    return (
        name in _SENSITIVE_NAMES
        or name.startswith(".env.")
        or name.endswith(tuple(_SENSITIVE_SUFFIXES | _SENSITIVE_CONTAINER_SUFFIXES))
        or bool(path_tokens & _SENSITIVE_PATH_TOKENS)
        or contains_sensitive_key_pair
        or re.fullmatch(r"id_(?:dsa|ecdsa|ed25519|rsa)(?:\.pub)?", name) is not None
    )


def _rename_no_replace(source_parent: int, source_name: str, destination_parent: int, destination_name: str) -> None:
    """Perform a descriptor-relative Linux rename that cannot replace a destination."""

    if _RENAMEAT2 is None:
        raise FileWorkspaceAtomicWriteError("kernel no-replace rename is unavailable; source retained")
    result = _RENAMEAT2(
        source_parent,
        ctypes.c_char_p(os.fsencode(source_name)),
        destination_parent,
        ctypes.c_char_p(os.fsencode(destination_name)),
        _RENAME_NOREPLACE,
    )
    if result == 0:
        return
    error = ctypes.get_errno()
    if error in {errno.EEXIST, errno.ENOTEMPTY}:
        raise FileWorkspaceStale("rename destination appeared before the atomic mutation")
    if error in {errno.EINVAL, errno.ENOSYS, errno.EOPNOTSUPP}:
        raise FileWorkspaceAtomicWriteError("filesystem no-replace rename is unavailable; source retained")
    raise FileWorkspaceAtomicWriteError("atomic no-replace rename failed; source retained")


def _rename_exchange(source_parent: int, source_name: str, destination_parent: int, destination_name: str) -> None:
    """Atomically exchange two descriptor-relative paths for reversible commit."""

    if _RENAMEAT2 is None:
        raise FileWorkspaceAtomicWriteError("kernel exchange rename is unavailable; original retained")
    result = _RENAMEAT2(
        source_parent,
        ctypes.c_char_p(os.fsencode(source_name)),
        destination_parent,
        ctypes.c_char_p(os.fsencode(destination_name)),
        _RENAME_EXCHANGE,
    )
    if result == 0:
        return
    error = ctypes.get_errno()
    if error in {errno.EINVAL, errno.ENOSYS, errno.EOPNOTSUPP}:
        raise FileWorkspaceAtomicWriteError("filesystem exchange rename is unavailable; original retained")
    raise FileWorkspaceAtomicWriteError("atomic exchange rename failed; original retained")


class _GitHeadLock:
    """Prepared Git ref transaction which verifies and locks dereferenced HEAD."""

    def __init__(self, root_fd: int, expected_head: str) -> None:
        self._root_fd = root_fd
        self._expected_head = expected_head
        self._process: subprocess.Popen[bytes] | None = None

    @staticmethod
    def _read_until(process: subprocess.Popen[bytes], marker: bytes, timeout: float = 5.0) -> bytes:
        if process.stdout is None:
            raise FileWorkspaceStale("Git boundary lock output is unavailable")
        descriptor = process.stdout.fileno()
        deadline = time.monotonic() + timeout
        output = bytearray()
        while marker not in output:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise FileWorkspaceStale("Git boundary lock timed out")
            readable, _, _ = select.select((descriptor,), (), (), remaining)
            if not readable:
                raise FileWorkspaceStale("Git boundary lock timed out")
            chunk = os.read(descriptor, 4096)
            if not chunk:
                raise FileWorkspaceStale("Git boundary lock was refused")
            output.extend(chunk)
            if len(output) > 4096:
                raise FileWorkspaceStale("Git boundary lock response exceeded its bound")
        return bytes(output)

    @staticmethod
    def _stop(process: subprocess.Popen[bytes]) -> None:
        if process.stdin is not None and not process.stdin.closed:
            try:
                process.stdin.close()
            except OSError:
                pass
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            try:
                process.terminate()
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                process.wait(timeout=1)

    def acquire(self) -> None:
        root = f"/proc/self/fd/{self._root_fd}"
        try:
            process = subprocess.Popen(
                [*_GIT_COMMAND_PREFIX, "-C", root, "update-ref", "--stdin"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                bufsize=0,
                pass_fds=(self._root_fd,),
                env=_GIT_ENV,
            )
        except OSError as exc:
            raise FileWorkspaceStale("Git boundary lock is unavailable") from exc
        self._process = process
        try:
            if process.stdin is None:
                raise FileWorkspaceStale("Git boundary lock input is unavailable")
            process.stdin.write(f"start\nverify HEAD {self._expected_head}\nprepare\n".encode("ascii"))
            process.stdin.flush()
            response = self._read_until(process, b"prepare: ok\n")
            if response.splitlines() != [b"start: ok", b"prepare: ok"]:
                raise FileWorkspaceStale("Git boundary lock response is invalid")
        except Exception:
            self._stop(process)
            self._process = None
            raise

    def release(self) -> bool:
        process = self._process
        self._process = None
        if process is None:
            return True
        released = False
        try:
            if process.stdin is None:
                return False
            process.stdin.write(b"abort\n")
            process.stdin.flush()
            response = self._read_until(process, b"abort: ok\n")
            released = response.splitlines()[-1:] == [b"abort: ok"]
            return released
        except (BrokenPipeError, OSError, FileWorkspaceError):
            return False
        finally:
            self._stop(process)


def _default_base_sha(root_fd: int) -> str:
    root = f"/proc/self/fd/{root_fd}"
    try:
        process = subprocess.run(
            [*_GIT_COMMAND_PREFIX, "-C", root, "rev-parse", "--verify", "HEAD"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=5,
            pass_fds=(root_fd,),
            env=_GIT_ENV,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise FileWorkspaceStale("project Git identity is unavailable") from exc
    value = process.stdout.decode("ascii", errors="ignore").strip()
    if process.returncode != 0 or _GIT_SHA.fullmatch(value) is None:
        raise FileWorkspaceStale("project Git identity is unavailable")
    return value


def _open_root_without_symlinks(path: Path) -> int:
    if not path.is_absolute():
        raise FileWorkspacePathError("project root must be absolute")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    current = os.open("/", flags)
    try:
        for component in path.parts[1:]:
            if component in {"", ".", ".."}:
                raise FileWorkspacePathError("project root contains an unsafe component")
            next_fd = os.open(component, flags | nofollow, dir_fd=current)
            os.close(current)
            current = next_fd
        info = os.fstat(current)
        if not stat.S_ISDIR(info.st_mode):
            raise FileWorkspacePathError("project root is not a directory")
        return current
    except Exception:
        os.close(current)
        raise


class FileWorkspaceBroker:
    """Own a single development application's bounded file capability.

    The broker holds an open descriptor for the configured project root, so a
    later rename cannot retarget operations.  Every component is opened with
    ``O_NOFOLLOW`` and mutations use directory descriptors plus atomic rename.
    """

    def __init__(
        self,
        profile: FileWorkspaceProfile,
        *,
        lease_directory: Path,
        base_sha_provider: Callable[[int], str] | None = None,
        clock: Callable[[], float] = time.time,
        reaper_maximum_sleep_seconds: float = 1.0,
    ) -> None:
        if profile.application_id.casefold() in {"studydd", "studystate", "study-state"}:
            raise ValueError("StudyState cannot receive a file Workbench profile")
        self.profile = profile
        self._root_fd = _open_root_without_symlinks(profile.project_root)
        root_info = os.fstat(self._root_fd)
        self._root_identity = (root_info.st_dev, root_info.st_ino)
        if self._root_identity != profile.expected_root_identity:
            os.close(self._root_fd)
            raise FileWorkspacePathError("project root does not match the cataloged filesystem identity")
        self._root_identity_digest = _hash(f"{root_info.st_dev}:{root_info.st_ino}".encode("ascii"))
        self._lease_directory = Path(lease_directory)
        self._lease_directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        self._base_sha_provider = base_sha_provider or _default_base_sha
        self._clock = clock
        if not isinstance(reaper_maximum_sleep_seconds, (int, float)) or not 0.01 <= reaper_maximum_sleep_seconds <= 60:
            os.close(self._root_fd)
            raise ValueError("reaper_maximum_sleep_seconds is outside the supported bound")
        self._reaper_maximum_sleep_seconds = float(reaper_maximum_sleep_seconds)
        self._quarantine_directory = self._lease_directory / "file-workspace-quarantine"
        self._quarantine_directory.mkdir(mode=0o700, exist_ok=True)
        quarantine_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        try:
            self._quarantine_fd = os.open(self._quarantine_directory, quarantine_flags)
            quarantine_info = os.fstat(self._quarantine_fd)
            if (
                not stat.S_ISDIR(quarantine_info.st_mode)
                or quarantine_info.st_uid != os.geteuid()
                or stat.S_IMODE(quarantine_info.st_mode) & 0o077
            ):
                raise FileWorkspaceLeaseDenied("file workspace quarantine directory is not private")
        except Exception:
            if hasattr(self, "_quarantine_fd"):
                os.close(self._quarantine_fd)
            os.close(self._root_fd)
            raise
        binding = _hash(
            json.dumps(
                {
                    "applicationId": profile.application_id,
                    "instanceId": profile.instance_id,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        binding_token = binding.split(":", 1)[1]
        self._quarantine_binding_digest = binding
        self._quarantine_record_name = f"{binding_token}.json"
        self._quarantine_lock_name = f"{binding_token}.lock"
        self._pending: dict[str, _PendingWrite] = {}
        self._mutex = threading.RLock()
        self._condition = threading.Condition(self._mutex)
        self._closed = False
        self._cleanup_failed = self._quarantine_record_exists()
        self._quarantine_persistence_failed = False
        # Test-only race injection points. Production leaves them as None;
        # the boundary hook runs after prechecks and immediately before the
        # reversible syscall, whose actual result is then revalidated.
        self._before_replace: Callable[[str], None] | None = None
        self._before_destructive: Callable[[str], None] | None = None
        self._at_mutation_boundary: Callable[[str], None] | None = None
        self._reaper = threading.Thread(
            target=self._reap_expired_writes,
            name=f"file-workspace-reaper-{profile.profile_id}",
            daemon=True,
        )
        self._reaper.start()

    @property
    def root_identity_digest(self) -> str:
        return self._root_identity_digest

    @property
    def root_identity(self) -> tuple[int, int]:
        return self._root_identity

    def _quarantine_record_exists(self) -> bool:
        try:
            os.stat(
                self._quarantine_record_name,
                dir_fd=self._quarantine_fd,
                follow_symlinks=False,
            )
            return True
        except FileNotFoundError:
            return False

    @contextmanager
    def _quarantine_lock(self):
        flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(
            self._quarantine_lock_name,
            flags,
            0o600,
            dir_fd=self._quarantine_fd,
        )
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o077
            ):
                raise FileWorkspaceLeaseDenied("file workspace quarantine lock is unsafe")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    @staticmethod
    def _quarantine_record_digest(record: dict[str, object]) -> str:
        return _hash(
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )

    def _read_quarantine_record_locked(self) -> dict[str, object] | None:
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        descriptor = -1
        try:
            descriptor = os.open(
                self._quarantine_record_name,
                flags,
                dir_fd=self._quarantine_fd,
            )
        except FileNotFoundError:
            return None
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_size <= 0
                or info.st_size > _QUARANTINE_RECORD_LIMIT
                or stat.S_IMODE(info.st_mode) & 0o077
            ):
                raise FileWorkspaceLeaseDenied(
                    "file workspace quarantine record is invalid"
                )
            raw = bytearray()
            while len(raw) <= _QUARANTINE_RECORD_LIMIT:
                chunk = os.read(descriptor, min(4096, _QUARANTINE_RECORD_LIMIT + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
            after = os.fstat(descriptor)
            if (
                (after.st_dev, after.st_ino, after.st_size)
                != (info.st_dev, info.st_ino, info.st_size)
                or after.st_mtime_ns != info.st_mtime_ns
                or after.st_ctime_ns != info.st_ctime_ns
            ):
                raise FileWorkspaceLeaseDenied(
                    "file workspace quarantine record changed while reading"
                )
            if len(raw) > _QUARANTINE_RECORD_LIMIT:
                raise FileWorkspaceLeaseDenied(
                    "file workspace quarantine record is invalid"
                )
            try:
                value = json.loads(
                    bytes(raw).decode("utf-8"),
                    object_pairs_hook=_unique_json_object,
                )
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                raise FileWorkspaceLeaseDenied(
                    "file workspace quarantine record is invalid"
                ) from exc
            required = {
                "formatVersion",
                "quarantineId",
                "bindingDigest",
                "applicationId",
                "instanceId",
                "rootIdentityDigest",
                "reasonCode",
                "recoveryArtifactCount",
                "createdAt",
            }
            if not isinstance(value, dict) or set(value) != required:
                raise FileWorkspaceLeaseDenied(
                    "file workspace quarantine record is invalid"
                )
            artifact_count = value.get("recoveryArtifactCount")
            if (
                value.get("formatVersion") != _QUARANTINE_FORMAT
                or not isinstance(value.get("quarantineId"), str)
                or re.fullmatch(r"file-quarantine\.[0-9a-f]{32}", value["quarantineId"])
                is None
                or value.get("bindingDigest") != self._quarantine_binding_digest
                or value.get("applicationId") != self.profile.application_id
                or value.get("instanceId") != self.profile.instance_id
                or not isinstance(value.get("rootIdentityDigest"), str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", value["rootIdentityDigest"])
                is None
                or not isinstance(value.get("reasonCode"), str)
                or _QUARANTINE_REASON.fullmatch(value["reasonCode"]) is None
                or isinstance(artifact_count, bool)
                or not isinstance(artifact_count, int)
                or not 0 <= artifact_count <= 128
                or not isinstance(value.get("createdAt"), str)
                or not value["createdAt"]
                or len(value["createdAt"]) > 64
            ):
                raise FileWorkspaceLeaseDenied(
                    "file workspace quarantine record is invalid"
                )
            return value
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _public_quarantine_record(
        self, record: dict[str, object]
    ) -> dict[str, object]:
        return {
            "quarantineId": record["quarantineId"],
            "quarantineDigest": self._quarantine_record_digest(record),
            "applicationId": record["applicationId"],
            "instanceId": record["instanceId"],
            "rootIdentityDigest": record["rootIdentityDigest"],
            "reasonCode": record["reasonCode"],
            "recoveryArtifactCount": record["recoveryArtifactCount"],
            "createdAt": record["createdAt"],
        }

    def _persist_quarantine(
        self, reason_code: str, *, recovery_artifact_count: int
    ) -> dict[str, object]:
        self._cleanup_failed = True
        try:
            record = self._persist_quarantine_record(
                reason_code,
                recovery_artifact_count=recovery_artifact_count,
            )
        except BaseException:
            # If the durable record itself cannot be proved, this broker must
            # remain fail-closed even if another broker later sees no file.
            self._quarantine_persistence_failed = True
            raise
        self._quarantine_persistence_failed = False
        return record

    def _persist_quarantine_record(
        self, reason_code: str, *, recovery_artifact_count: int
    ) -> dict[str, object]:
        if (
            not isinstance(reason_code, str)
            or _QUARANTINE_REASON.fullmatch(reason_code) is None
            or isinstance(recovery_artifact_count, bool)
            or not isinstance(recovery_artifact_count, int)
            or not 0 <= recovery_artifact_count <= 128
        ):
            raise FileWorkspaceAtomicWriteError(
                "file workspace quarantine metadata is invalid"
            )
        self._cleanup_failed = True
        with self._quarantine_lock():
            return self._persist_quarantine_record_locked(
                reason_code,
                recovery_artifact_count=recovery_artifact_count,
            )

    def _persist_quarantine_record_locked(
        self, reason_code: str, *, recovery_artifact_count: int
    ) -> dict[str, object]:
        """Persist a quarantine while the cross-broker quarantine lock is held."""

        if (
            not isinstance(reason_code, str)
            or _QUARANTINE_REASON.fullmatch(reason_code) is None
            or isinstance(recovery_artifact_count, bool)
            or not isinstance(recovery_artifact_count, int)
            or not 0 <= recovery_artifact_count <= 128
        ):
            raise FileWorkspaceAtomicWriteError(
                "file workspace quarantine metadata is invalid"
            )
        existing = self._read_quarantine_record_locked()
        if existing is not None:
            return existing
        record: dict[str, object] = {
            "formatVersion": _QUARANTINE_FORMAT,
            "quarantineId": "file-quarantine." + secrets.token_hex(16),
            "bindingDigest": self._quarantine_binding_digest,
            "applicationId": self.profile.application_id,
            "instanceId": self.profile.instance_id,
            "rootIdentityDigest": self._root_identity_digest,
            "reasonCode": reason_code,
            "recoveryArtifactCount": recovery_artifact_count,
            "createdAt": _utc(self._clock()),
        }
        temporary = f".{self._quarantine_record_name}.{secrets.token_hex(16)}.tmp"
        descriptor = -1
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_CLOEXEC
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=self._quarantine_fd,
            )
            payload = (
                json.dumps(record, sort_keys=True, separators=(",", ":"))
                + "\n"
            ).encode("utf-8")
            view = memoryview(payload)
            written = 0
            while written < len(view):
                count = os.write(descriptor, view[written:])
                if count <= 0:
                    raise OSError("short quarantine write")
                written += count
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.replace(
                temporary,
                self._quarantine_record_name,
                src_dir_fd=self._quarantine_fd,
                dst_dir_fd=self._quarantine_fd,
            )
            os.fsync(self._quarantine_fd)
        except OSError as exc:
            raise FileWorkspaceAtomicWriteError(
                "durable file workspace quarantine could not be recorded"
            ) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary, dir_fd=self._quarantine_fd)
            except FileNotFoundError:
                pass
        return record

    def _assert_mutation_not_quarantined(self) -> None:
        with self._quarantine_lock():
            self._assert_mutation_not_quarantined_locked()

    def _assert_mutation_not_quarantined_locked(self) -> None:
        if self._quarantine_persistence_failed:
            raise FileWorkspaceLeaseDenied(
                "file workspace cleanup could not be proved"
            )
        record = self._read_quarantine_record_locked()
        if record is None:
            # Another identity-bound broker may have completed the explicit
            # clear while this broker remained alive.
            self._cleanup_failed = False
            return
        self._cleanup_failed = True
        if record["rootIdentityDigest"] != self._root_identity_digest:
            raise FileWorkspaceLeaseDenied(
                "file workspace quarantine belongs to a different root identity"
            )
        raise FileWorkspaceLeaseDenied(
            "file workspace cleanup requires explicit operator recovery"
        )

    def _quarantine_unresolved(self, reason_code: str) -> None:
        with self._quarantine_lock():
            self._quarantine_unresolved_locked(reason_code)

    def _quarantine_unresolved_locked(self, reason_code: str) -> None:
        try:
            artifact_count = self._count_recovery_artifacts()
        except (FileWorkspaceError, OSError):
            artifact_count = 128
        self._cleanup_failed = True
        try:
            self._persist_quarantine_record_locked(
                reason_code,
                recovery_artifact_count=artifact_count,
            )
        except BaseException:
            self._quarantine_persistence_failed = True
            raise
        self._quarantine_persistence_failed = False

    def _assert_configured_root_binding(self) -> None:
        """Re-open the configured path with no-follow dir-fd traversal and compare inodes."""

        rebound_fd = -1
        try:
            rebound_fd = _open_root_without_symlinks(self.profile.project_root)
            info = os.fstat(rebound_fd)
            if (info.st_dev, info.st_ino) != self._root_identity:
                raise FileWorkspacePathError("configured project path no longer names the bound project root")
        except FileWorkspacePathError:
            raise
        except OSError as exc:
            raise FileWorkspacePathError("configured project path cannot be revalidated safely") from exc
        finally:
            if rebound_fd >= 0:
                os.close(rebound_fd)

    def _live_root(self) -> None:
        if self._closed:
            raise FileWorkspaceError("file workspace broker is closed")
        info = os.fstat(self._root_fd)
        if (info.st_dev, info.st_ino) != self._root_identity or not stat.S_ISDIR(info.st_mode):
            raise FileWorkspacePathError("project root identity changed")
        self._assert_configured_root_binding()

    def _base_sha(self) -> str:
        self._live_root()
        value = self._base_sha_provider(self._root_fd)
        if not isinstance(value, str) or _GIT_SHA.fullmatch(value) is None:
            raise FileWorkspaceStale("project Git identity is unavailable")
        return value

    def _assert_base_at_boundary(self, expected_base_sha: str, operation: str) -> None:
        if self._base_sha() != expected_base_sha:
            raise FileWorkspaceStale(f"project base changed at the {operation} boundary")

    @contextmanager
    def _locked_git_head(self, expected_base_sha: str):
        guard = _GitHeadLock(self._root_fd, expected_base_sha)
        guard.acquire()
        active_error: BaseException | None = None
        try:
            yield
        except BaseException as exc:
            active_error = exc
            raise
        finally:
            if not guard.release():
                self._quarantine_unresolved("git_lock_cleanup_required")
                if active_error is None:
                    raise FileWorkspaceAtomicWriteError("Git boundary lock cleanup failed; broker quarantined")

    def _invoke_mutation_boundary(self, operation: str) -> None:
        if self._at_mutation_boundary is not None:
            self._at_mutation_boundary(operation)

    def profile_description(self, *, actor_id: str, application_id: str, instance_id: str) -> dict[str, object]:
        self._authorize(actor_id, application_id, instance_id, write=False)
        return self.profile.to_dict(root_identity_digest=self._root_identity_digest, base_sha=self._base_sha())

    def _authorize(self, actor_id: str, application_id: str, instance_id: str, *, write: bool) -> None:
        permissions = self.profile.actor_permissions.get(actor_id)
        if (
            permissions is None
            or application_id != self.profile.application_id
            or instance_id != self.profile.instance_id
            or "file.read" not in permissions
        ):
            raise FileWorkspaceAccessDenied()
        required = {"workbench", "file_viewer"}
        if write:
            required.add("editor")
            if "file.write" not in permissions:
                raise FileWorkspaceAccessDenied()
        if not required.issubset(self.profile.effective_capabilities):
            raise FileWorkspaceAccessDenied()
        self._live_root()

    def _path(self, value: str, *, allow_root: bool = False) -> str:
        try:
            path = relative_path(value, allow_root=allow_root)
        except ValueError as exc:
            raise FileWorkspacePathError(str(exc)) from exc
        components = PurePosixPath(path).parts if path else ()
        lowered = tuple(component.casefold() for component in components)
        if any(component in _RESERVED_COMPONENTS for component in lowered):
            raise FileWorkspacePathError("path enters a reserved operational directory")
        if _credential_like_path(components):
            raise FileWorkspaceTypeRefused("credential-like files are unavailable in the browser Workbench")
        return path

    def _rule_for(self, path: str) -> PathPolicyRule:
        matching = [rule for rule in self.profile.path_rules if rule.matches(path)]
        if not matching:
            raise FileWorkspacePathError("path is not classified by the application policy")
        matching.sort(key=lambda rule: (len(PurePosixPath(rule.path).parts), rule.match == "exact"), reverse=True)
        return matching[0]

    def _directory_is_visible(self, path: str) -> bool:
        return any(rule.read and rule.contains(path) for rule in self.profile.path_rules)

    def _count_recovery_artifacts(self) -> int:
        """Count strict broker recovery names without following links or exposing paths."""

        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        stack: list[tuple[int, str]] = [(os.dup(self._root_fd), "")]
        visited: set[tuple[int, int]] = set()
        count = 0
        entries = 0
        try:
            while stack:
                directory_fd, directory_path = stack.pop()
                try:
                    directory_info = os.fstat(directory_fd)
                    identity = (directory_info.st_dev, directory_info.st_ino)
                    if identity in visited:
                        continue
                    visited.add(identity)
                    for name in os.listdir(directory_fd):
                        entries += 1
                        if entries > 100_000:
                            raise FileWorkspaceLeaseDenied(
                                "recovery artifact verification exceeded its bound"
                            )
                        info = self._stat_name(directory_fd, name)
                        if info is None:
                            continue
                        if _RECOVERY_ARTIFACT.fullmatch(name):
                            if not stat.S_ISREG(info.st_mode):
                                raise FileWorkspaceLeaseDenied(
                                    "recovery artifact identity changed"
                                )
                            count += 1
                            if count > 128:
                                raise FileWorkspaceLeaseDenied(
                                    "too many recovery artifacts require operator inspection"
                                )
                            continue
                        if (
                            not stat.S_ISDIR(info.st_mode)
                            or name.casefold() in _RESERVED_COMPONENTS
                        ):
                            continue
                        child = f"{directory_path}/{name}" if directory_path else name
                        try:
                            child_fd = os.open(name, flags, dir_fd=directory_fd)
                        except OSError as exc:
                            raise FileWorkspaceLeaseDenied(
                                "recovery artifact verification could not prove the project tree"
                            ) from exc
                        stack.append((child_fd, child))
                finally:
                    os.close(directory_fd)
            return count
        finally:
            for descriptor, _ in stack:
                os.close(descriptor)

    def quarantine_status(
        self,
        *,
        actor_id: str,
        application_id: str,
        instance_id: str,
    ) -> dict[str, object]:
        with self._mutex:
            self._authorize(actor_id, application_id, instance_id, write=False)
            with self._quarantine_lock():
                record = self._read_quarantine_record_locked()
            if record is None:
                if self._quarantine_persistence_failed:
                    raise FileWorkspaceLeaseDenied(
                        "file workspace cleanup could not be proved"
                    )
                return {
                    "formatVersion": _QUARANTINE_STATUS_FORMAT,
                    "operation": "fileWorkspaceQuarantineStatus",
                    "quarantined": False,
                    "quarantine": None,
                }
            return {
                "formatVersion": _QUARANTINE_STATUS_FORMAT,
                "operation": "fileWorkspaceQuarantineStatus",
                "quarantined": True,
                "identityMatches": record["rootIdentityDigest"]
                == self._root_identity_digest,
                "quarantine": self._public_quarantine_record(record),
            }

    def clear_quarantine(
        self,
        *,
        actor_id: str,
        application_id: str,
        instance_id: str,
        expected_quarantine_digest: str,
        recovery_disposition: str,
    ) -> dict[str, object]:
        """Clear only an exact, current-root quarantine after artifacts are resolved."""

        with self._mutex:
            self._authorize(actor_id, application_id, instance_id, write=True)
            if (
                not isinstance(expected_quarantine_digest, str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", expected_quarantine_digest)
                is None
            ):
                raise FileWorkspaceLeaseDenied(
                    "quarantine clear requires an exact record digest"
                )
            if recovery_disposition != "recovery_artifacts_resolved":
                raise FileWorkspaceLeaseDenied(
                    "quarantine clear requires a verified recovery disposition"
                )
            lease = self._acquire_lease(actor_id, allow_quarantined=True)
            try:
                with self._quarantine_lock():
                    record = self._read_quarantine_record_locked()
                    if record is None:
                        raise FileWorkspaceLeaseDenied(
                            "file workspace is not quarantined"
                        )
                    if record["rootIdentityDigest"] != self._root_identity_digest:
                        raise FileWorkspaceLeaseDenied(
                            "quarantine clear root identity does not match"
                        )
                    record_digest = self._quarantine_record_digest(record)
                    if not secrets.compare_digest(
                        record_digest, expected_quarantine_digest
                    ):
                        raise FileWorkspaceLeaseDenied(
                            "quarantine clear digest does not match"
                        )
                    if self._count_recovery_artifacts() != 0:
                        raise FileWorkspaceLeaseDenied(
                            "recovery artifacts remain unresolved"
                        )
                    os.unlink(
                        self._quarantine_record_name,
                        dir_fd=self._quarantine_fd,
                    )
                    os.fsync(self._quarantine_fd)
                self._cleanup_failed = False
                self._quarantine_persistence_failed = False
                return {
                    "formatVersion": _QUARANTINE_CLEAR_FORMAT,
                    "operation": "clearFileWorkspaceQuarantine",
                    "quarantineId": record["quarantineId"],
                    "quarantineDigest": record_digest,
                    "applicationId": application_id,
                    "instanceId": instance_id,
                    "rootIdentityDigest": self._root_identity_digest,
                    "recoveryDisposition": recovery_disposition,
                    "clearedBy": actor_id,
                    "clearedAt": _utc(self._clock()),
                }
            finally:
                self._release(lease)

    def _open_directory(self, path: str) -> int:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        current = os.dup(self._root_fd)
        try:
            for component in PurePosixPath(path).parts if path else ():
                next_fd = os.open(component, flags, dir_fd=current)
                os.close(current)
                current = next_fd
            return current
        except (OSError, ValueError) as exc:
            os.close(current)
            raise FileWorkspacePathError("directory is unavailable without following links") from exc

    def _open_parent(self, path: str) -> tuple[int, str]:
        parts = PurePosixPath(path).parts
        parent = "/".join(parts[:-1])
        return self._open_directory(parent), parts[-1]

    def _assert_parent_binding(self, path: str, parent_fd: int) -> None:
        """Prove a captured parent still names the path below the bound root."""

        parts = PurePosixPath(path).parts
        try:
            rebound = self._open_directory("/".join(parts[:-1]))
        except FileWorkspacePathError as exc:
            raise FileWorkspaceStale("path ancestor changed at the mutation boundary") from exc
        try:
            captured_info = os.fstat(parent_fd)
            rebound_info = os.fstat(rebound)
            if (captured_info.st_dev, captured_info.st_ino) != (rebound_info.st_dev, rebound_info.st_ino):
                raise FileWorkspaceStale("path ancestor changed at the mutation boundary")
        finally:
            os.close(rebound)

    @staticmethod
    def _stat_name(parent_fd: int, name: str) -> os.stat_result | None:
        try:
            return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None

    def _language(self, path: str) -> str:
        name = PurePosixPath(path).name
        suffix = PurePosixPath(path).suffix.casefold()
        if suffix not in _SAFE_SUFFIXES and name not in _SAFE_EXTENSIONLESS:
            raise FileWorkspaceTypeRefused("file type is not permitted by the Workbench text policy")
        return {
            ".css": "css", ".go": "go", ".html": "html", ".java": "java",
            ".js": "javascript", ".json": "json", ".jsx": "javascript", ".md": "markdown",
            ".py": "python", ".rs": "rust", ".sh": "shell", ".sql": "sql",
            ".ts": "typescript", ".tsx": "typescript", ".xml": "xml", ".yaml": "yaml", ".yml": "yaml",
        }.get(suffix, "plaintext")

    def _read_bytes_at(self, parent_fd: int, name: str, path: str) -> tuple[bytes, os.stat_result]:
        self._language(path)
        file_fd = -1
        try:
            file_fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
            before = os.fstat(file_fd)
            if not stat.S_ISREG(before.st_mode):
                raise FileWorkspacePathError("only regular files are available")
            if before.st_nlink != 1:
                raise FileWorkspacePathError("hard-linked files are unavailable in the Workbench")
            if before.st_size > self.profile.maximum_file_bytes:
                raise FileWorkspaceTypeRefused("file exceeds the configured Workbench size limit")
            data = bytearray()
            while True:
                chunk = os.read(file_fd, min(65_536, self.profile.maximum_file_bytes + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > self.profile.maximum_file_bytes:
                    raise FileWorkspaceTypeRefused("file exceeds the configured Workbench size limit")
            after = os.fstat(file_fd)
            before_identity = (
                before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_nlink,
            )
            after_identity = (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_nlink,
            )
            if after.st_nlink != 1 or before_identity != after_identity:
                raise FileWorkspaceStale("file changed while it was being read")
            raw = bytes(data)
            if b"\0" in raw:
                raise FileWorkspaceTypeRefused("binary files are unavailable in the Workbench")
            try:
                raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise FileWorkspaceTypeRefused("non-UTF-8 files are unavailable in the Workbench") from exc
            return raw, after
        except FileNotFoundError as exc:
            raise FileWorkspacePathError("file is unavailable") from exc
        except OSError as exc:
            raise FileWorkspacePathError("file is unavailable without following links") from exc
        finally:
            if file_fd >= 0:
                os.close(file_fd)

    def _read_bytes(self, path: str) -> tuple[bytes, os.stat_result]:
        parent_fd, name = self._open_parent(path)
        try:
            return self._read_bytes_at(parent_fd, name, path)
        finally:
            os.close(parent_fd)

    def _metadata(self, path: str, rule: PathPolicyRule, data: bytes) -> FileMetadata:
        return FileMetadata(
            path=path,
            size=len(data),
            content_hash=_hash(data),
            base_sha=self._base_sha(),
            ownership_class=rule.ownership_class,
            language=self._language(path),
            read_only=not rule.write or rule.ownership_class == "generated",
        )

    def list_directory(self, path: str, *, actor_id: str, application_id: str, instance_id: str) -> DirectoryListing:
        with self._mutex:
            self._authorize(actor_id, application_id, instance_id, write=False)
            selected = self._path(path, allow_root=True)
            if not self._directory_is_visible(selected):
                raise FileWorkspacePathError("directory is not covered by the application path policy")
            directory_fd = self._open_directory(selected)
            try:
                names = sorted(os.listdir(directory_fd), key=lambda item: (item.casefold(), item))
                visible: list[DirectoryEntry] = []
                for name in names:
                    try:
                        child = self._path(f"{selected}/{name}" if selected else name)
                    except (FileWorkspacePathError, FileWorkspaceTypeRefused):
                        continue
                    rule: PathPolicyRule | None
                    try:
                        rule = self._rule_for(child)
                    except FileWorkspacePathError:
                        rule = None
                    if rule is None and not self._directory_is_visible(child):
                        continue
                    info = self._stat_name(directory_fd, name)
                    if info is None:
                        continue
                    if stat.S_ISLNK(info.st_mode):
                        kind = "symlink"
                    elif stat.S_ISDIR(info.st_mode):
                        kind = "directory"
                    elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                        kind = "file"
                    else:
                        kind = "unavailable"
                    if kind == "file":
                        try:
                            self._language(child)
                        except FileWorkspaceTypeRefused:
                            kind = "unavailable"
                    visible.append(DirectoryEntry(
                        path=child,
                        name=name,
                        kind=kind,
                        ownership_class=rule.ownership_class if rule else None,
                        size=info.st_size if kind == "file" else None,
                        read_only=kind != "file" or rule is None or not rule.write or rule.ownership_class == "generated",
                    ))
                truncated = len(visible) > self.profile.maximum_directory_entries
                entries = tuple(visible[: self.profile.maximum_directory_entries])
                return DirectoryListing(selected, entries, self._base_sha(), truncated)
            finally:
                os.close(directory_fd)

    def read_file(self, path: str, *, actor_id: str, application_id: str, instance_id: str) -> FileRead:
        with self._mutex:
            self._authorize(actor_id, application_id, instance_id, write=False)
            selected = self._path(path)
            rule = self._rule_for(selected)
            if not rule.read:
                raise FileWorkspaceAccessDenied()
            data, _ = self._read_bytes(selected)
            return FileRead(self._metadata(selected, rule, data), data.decode("utf-8"))

    def read_file_metadata(self, path: str, *, actor_id: str, application_id: str, instance_id: str) -> FileMetadata:
        return self.read_file(path, actor_id=actor_id, application_id=application_id, instance_id=instance_id).metadata

    def _validate_candidate(self, path: str, data: bytes, rule: PathPolicyRule) -> None:
        if len(data) > self.profile.maximum_file_bytes:
            raise FileWorkspaceTypeRefused("candidate exceeds the configured Workbench size limit")
        if b"\0" in data:
            raise FileWorkspaceTypeRefused("binary candidates are unavailable in the Workbench")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise FileWorkspaceTypeRefused("candidate must be UTF-8 text") from exc
        language = self._language(path)
        if language == "json":
            try:
                json.loads(text, object_pairs_hook=_unique_json_object)
            except (json.JSONDecodeError, ValueError) as exc:
                raise FileWorkspaceValidationError((f"invalid JSON: {exc}",)) from exc
        if rule.ownership_class == "canonical":
            # File-workspace v1 has no authoritative StateSpec transaction
            # adapter. Canonical mutation therefore remains fail-closed even
            # if a caller somehow supplies an inconsistent policy object.
            raise FileWorkspaceAccessDenied()

    def _acquire_lease(
        self,
        actor_id: str,
        *,
        allow_quarantined: bool = False,
    ) -> InstanceLease:
        if allow_quarantined:
            # Explicit quarantine clearing already requires an exact durable
            # record digest. Acquire the writer lease non-blocking first so a
            # concurrent clear reports the active writer instead of waiting
            # behind the quarantine-record inspection lock.
            try:
                return InstanceLease(
                    self._lease_directory,
                    Path(f"/proc/self/fd/{self._root_fd}"),
                    owner=f"file-workspace:{actor_id}",
                ).acquire()
            except (InstanceLeaseBusy, InstanceLeaseError) as exc:
                raise FileWorkspaceLeaseDenied("project writer lease is unavailable") from exc
        # Quarantine and writer-lease transitions share one cross-process lock.
        # A failing release therefore records quarantine before a waiting
        # broker can acquire the newly unlocked writer lease.
        with self._quarantine_lock():
            if not allow_quarantined:
                self._assert_mutation_not_quarantined_locked()
            try:
                lease = InstanceLease(
                    self._lease_directory,
                    Path(f"/proc/self/fd/{self._root_fd}"),
                    owner=f"file-workspace:{actor_id}",
                )
                acquired = lease.acquire()
            except (InstanceLeaseBusy, InstanceLeaseError) as exc:
                raise FileWorkspaceLeaseDenied("project writer lease is unavailable") from exc
            try:
                if not allow_quarantined:
                    self._assert_mutation_not_quarantined_locked()
            except BaseException:
                self._release_locked(acquired)
                raise
            return acquired

    def _release_locked(self, lease: InstanceLease | None) -> None:
        if lease is None:
            return
        try:
            lease.release()
        except OSError as exc:
            self._quarantine_unresolved_locked("lease_cleanup_required")
            raise FileWorkspaceAtomicWriteError(
                "writer lease cleanup failed; broker quarantined"
            ) from exc

    def _release(self, lease: InstanceLease | None) -> None:
        if lease is None:
            return
        with self._quarantine_lock():
            self._release_locked(lease)

    def _prune_pending(self) -> None:
        now = self._clock()
        expired = [identifier for identifier, pending in self._pending.items() if pending.expires_at <= now]
        for identifier in expired:
            pending = self._pending.pop(identifier)
            try:
                self._release(pending.lease)
            except FileWorkspaceAtomicWriteError:
                pass

    def _reap_expired_writes(self) -> None:
        """Release expired writer leases without requiring another broker request."""

        with self._condition:
            while not self._closed:
                self._prune_pending()
                if self._closed:
                    return
                if not self._pending:
                    self._condition.wait()
                    continue
                delay = max(0.0, min(item.expires_at for item in self._pending.values()) - self._clock())
                self._condition.wait(timeout=min(max(delay, 0.01), self._reaper_maximum_sleep_seconds))

    def _prepare(
        self,
        path: str,
        content: str,
        *,
        create: bool,
        expected_content_hash: str | None,
        expected_base_sha: str,
        actor_id: str,
        application_id: str,
        instance_id: str,
    ) -> PreparedWrite:
        self._authorize(actor_id, application_id, instance_id, write=True)
        self._assert_mutation_not_quarantined()
        self._prune_pending()
        if len(self._pending) >= self.profile.maximum_pending_writes:
            raise FileWorkspaceError("too many staged file writes")
        selected = self._path(path)
        rule = self._rule_for(selected)
        allowed = rule.create if create else rule.write
        if not allowed or rule.ownership_class == "generated":
            raise FileWorkspaceAccessDenied()
        if not isinstance(content, str):
            raise FileWorkspaceTypeRefused("candidate content must be text")
        candidate = content.encode("utf-8")
        self._validate_candidate(selected, candidate, rule)
        lease = self._acquire_lease(actor_id)
        try:
            # A different broker may have persisted quarantine while this
            # broker waited for the cross-process writer lease.
            self._assert_mutation_not_quarantined()
            current_base = self._base_sha()
            if current_base != expected_base_sha:
                raise FileWorkspaceStale("project base changed before write preparation")
            original: bytes | None
            if create:
                parent_fd, name = self._open_parent(selected)
                try:
                    if self._stat_name(parent_fd, name) is not None:
                        raise FileWorkspaceStale("create target already exists")
                finally:
                    os.close(parent_fd)
                if expected_content_hash is not None:
                    raise FileWorkspaceStale("create operation must expect an absent path")
                original = None
            else:
                original, _ = self._read_bytes(selected)
                current_hash = _hash(original)
                if expected_content_hash != current_hash:
                    raise FileWorkspaceStale("file changed before write preparation", current_hash=current_hash)
            now = self._clock()
            identifier = "prepared-write." + secrets.token_hex(16)
            prepared = PreparedWrite(
                prepared_write_id=identifier,
                operation="create" if create else "write",
                path=selected,
                actor_id=actor_id,
                application_id=application_id,
                instance_id=instance_id,
                base_sha=current_base,
                original_hash=_hash(original) if original is not None else None,
                candidate_hash=_hash(candidate),
                ownership_class=rule.ownership_class,
                expires_at=_utc(now + self.profile.pending_write_lifetime_seconds),
                validation_required=rule.ownership_class == "canonical",
            )
            self._pending[identifier] = _PendingWrite(prepared, original, candidate, lease, now + self.profile.pending_write_lifetime_seconds)
            self._condition.notify_all()
            return prepared
        except Exception:
            self._release(lease)
            raise

    def prepare_write(
        self,
        path: str,
        content: str,
        *,
        expected_content_hash: str,
        expected_base_sha: str,
        actor_id: str,
        application_id: str,
        instance_id: str,
    ) -> PreparedWrite:
        with self._mutex:
            return self._prepare(
                path, content, create=False, expected_content_hash=expected_content_hash,
                expected_base_sha=expected_base_sha, actor_id=actor_id,
                application_id=application_id, instance_id=instance_id,
            )

    def create_file(
        self,
        path: str,
        content: str,
        *,
        expected_base_sha: str,
        actor_id: str,
        application_id: str,
        instance_id: str,
    ) -> PreparedWrite:
        with self._mutex:
            return self._prepare(
                path, content, create=True, expected_content_hash=None,
                expected_base_sha=expected_base_sha, actor_id=actor_id,
                application_id=application_id, instance_id=instance_id,
            )

    def _owned_pending(self, identifier: str, actor_id: str, application_id: str, instance_id: str) -> _PendingWrite:
        self._prune_pending()
        pending = self._pending.get(identifier)
        if (
            pending is None
            or pending.prepared.actor_id != actor_id
            or pending.prepared.application_id != application_id
            or pending.prepared.instance_id != instance_id
        ):
            raise FileWorkspaceAccessDenied()
        return pending

    @staticmethod
    def _diff(pending: _PendingWrite) -> str:
        original = pending.original.decode("utf-8").splitlines(keepends=True) if pending.original is not None else []
        candidate = pending.candidate.decode("utf-8").splitlines(keepends=True)
        return "".join(difflib.unified_diff(
            original,
            candidate,
            fromfile=f"a/{pending.prepared.path}" if pending.original is not None else "/dev/null",
            tofile=f"b/{pending.prepared.path}",
            lineterm="\n",
        ))

    def preview_diff(self, prepared_write_id: str, *, actor_id: str, application_id: str, instance_id: str) -> DiffPreview:
        with self._mutex:
            self._authorize(actor_id, application_id, instance_id, write=True)
            pending = self._owned_pending(prepared_write_id, actor_id, application_id, instance_id)
            full = self._diff(pending)
            value = _hash(full.encode("utf-8"))
            truncated = len(full) > _MAX_DIFF_CHARACTERS
            pending.preview_digest = value
            pending.preview_truncated = truncated
            pending.state = "previewed"
            shown = full[:_MAX_DIFF_CHARACTERS] if truncated else full
            return DiffPreview(
                prepared_write_id,
                pending.prepared.path,
                shown,
                value,
                pending.prepared.original_hash,
                pending.prepared.candidate_hash,
                truncated,
            )

    def _mark_conflicted(self, pending: _PendingWrite) -> None:
        self._release(pending.lease)
        pending.lease = None
        pending.state = "conflicted"

    def _verify_current(self, pending: _PendingWrite) -> tuple[int, str, os.stat_result | None]:
        parent_fd, name = self._open_parent(pending.prepared.path)
        try:
            info = self._stat_name(parent_fd, name)
            if pending.original is None:
                if info is not None:
                    raise FileWorkspaceStale("create target appeared before commit", prepared_write_id=pending.prepared.prepared_write_id)
            else:
                if info is None or not stat.S_ISREG(info.st_mode):
                    raise FileWorkspaceStale("file identity changed before commit", prepared_write_id=pending.prepared.prepared_write_id)
                current, current_info = self._read_bytes_at(parent_fd, name, pending.prepared.path)
                if (current_info.st_dev, current_info.st_ino) != (info.st_dev, info.st_ino):
                    raise FileWorkspaceStale(
                        "file identity changed before commit",
                        prepared_write_id=pending.prepared.prepared_write_id,
                    )
                current_hash = _hash(current)
                if current_hash != pending.prepared.original_hash:
                    raise FileWorkspaceStale(
                        "file changed before commit",
                        prepared_write_id=pending.prepared.prepared_write_id,
                        current_hash=current_hash,
                    )
            return parent_fd, name, info
        except Exception:
            os.close(parent_fd)
            raise

    def _verify_named_file(
        self,
        parent_fd: int,
        name: str,
        path: str,
        *,
        expected_info: os.stat_result,
        expected_hash: str,
        message: str,
    ) -> bytes:
        info = self._stat_name(parent_fd, name)
        if (
            info is None
            or not stat.S_ISREG(info.st_mode)
            or (info.st_dev, info.st_ino) != (expected_info.st_dev, expected_info.st_ino)
        ):
            raise FileWorkspaceStale(message)
        data, read_info = self._read_bytes_at(parent_fd, name, path)
        if (
            (read_info.st_dev, read_info.st_ino) != (info.st_dev, info.st_ino)
            or _hash(data) != expected_hash
        ):
            raise FileWorkspaceStale(message, current_hash=_hash(data))
        return data

    def _named_file_matches(
        self,
        parent_fd: int,
        name: str,
        path: str,
        *,
        expected_info: os.stat_result,
        expected_hash: str,
    ) -> bool:
        try:
            self._verify_named_file(
                parent_fd,
                name,
                path,
                expected_info=expected_info,
                expected_hash=expected_hash,
                message="file identity or content changed",
            )
            return True
        except (FileWorkspaceError, OSError):
            return False

    def _retain_recovery_bytes(
        self,
        parent_fd: int,
        path: str,
        data: bytes,
        mode: int,
    ) -> tuple[str, os.stat_result]:
        """Persist byte-exact recovery evidence and deliberately leave it in place."""

        recovery = f".stateport-recovery-{secrets.token_hex(16)}.tmp"
        recovery_fd = -1
        retained = False
        try:
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_CLOEXEC
                | getattr(os, "O_NOFOLLOW", 0)
            )
            recovery_fd = os.open(recovery, flags, 0o600, dir_fd=parent_fd)
            view = memoryview(data)
            written = 0
            while written < len(view):
                count = os.write(recovery_fd, view[written:])
                if count <= 0:
                    raise OSError("short recovery write")
                written += count
            os.fchmod(recovery_fd, mode & 0o777)
            os.fsync(recovery_fd)
            info = os.fstat(recovery_fd)
            os.close(recovery_fd)
            recovery_fd = -1
            os.fsync(parent_fd)
            self._verify_named_file(
                parent_fd,
                recovery,
                path,
                expected_info=info,
                expected_hash=_hash(data),
                message="recovery evidence could not be proved",
            )
            retained = True
            return recovery, info
        finally:
            if recovery_fd >= 0:
                os.close(recovery_fd)
            if not retained:
                try:
                    os.unlink(recovery, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass

    def _retain_write_conflict_evidence(
        self,
        parent_fd: int,
        pending: _PendingWrite,
        *,
        original_info: os.stat_result | None,
        candidate_info: os.stat_result,
    ) -> None:
        """Retain the browser candidate and, when present, the opened original."""

        candidate_mode = stat.S_IMODE(
            original_info.st_mode if original_info is not None else candidate_info.st_mode
        )
        if pending.original is not None:
            self._retain_recovery_bytes(
                parent_fd,
                pending.prepared.path,
                pending.original,
                candidate_mode,
            )
        self._retain_recovery_bytes(
            parent_fd,
            pending.prepared.path,
            pending.candidate,
            candidate_mode,
        )

    def _restore_bytes(
        self,
        parent_fd: int,
        name: str,
        path: str,
        data: bytes,
        mode: int,
        *,
        expected_current: os.stat_result | None,
        expected_current_hash: str | None = None,
    ) -> None:
        recovery, recovery_info = self._retain_recovery_bytes(
            parent_fd, path, data, mode
        )
        original_hash = _hash(data)
        current = self._stat_name(parent_fd, name)
        if expected_current is None:
            if current is not None:
                raise FileWorkspaceAtomicWriteError(
                    "rollback target appeared; recovery retained and broker quarantined"
                )
            _rename_no_replace(parent_fd, recovery, parent_fd, name)
            recovery = ""
        else:
            if expected_current_hash is None or not self._named_file_matches(
                parent_fd,
                name,
                path,
                expected_info=expected_current,
                expected_hash=expected_current_hash,
            ):
                raise FileWorkspaceAtomicWriteError(
                    "rollback target changed; recovery retained and broker quarantined"
                )
            _rename_exchange(parent_fd, recovery, parent_fd, name)
            if not self._named_file_matches(
                parent_fd,
                recovery,
                path,
                expected_info=expected_current,
                expected_hash=expected_current_hash,
            ):
                raise FileWorkspaceAtomicWriteError(
                    "concurrent target was preserved during rollback; broker quarantined"
                )
            if not self._named_file_matches(
                parent_fd,
                name,
                path,
                expected_info=recovery_info,
                expected_hash=original_hash,
            ):
                self._retain_recovery_bytes(parent_fd, path, data, mode)
                raise FileWorkspaceAtomicWriteError(
                    "restored target changed; recovery retained and broker quarantined"
                )
            os.unlink(recovery, dir_fd=parent_fd)
            recovery = ""
        os.fsync(parent_fd)
        if not self._named_file_matches(
            parent_fd,
            name,
            path,
            expected_info=recovery_info,
            expected_hash=original_hash,
        ):
            self._retain_recovery_bytes(parent_fd, path, data, mode)
            raise FileWorkspaceAtomicWriteError(
                "restored target changed during finalization; recovery retained and broker quarantined"
            )

    def _atomic_replace(self, pending: _PendingWrite) -> None:
        parent_fd, name, original_info = self._verify_current(pending)
        temporary = f".stateport-write-{secrets.token_hex(16)}.tmp"
        temporary_fd = -1
        candidate_info: os.stat_result | None = None
        applied = False
        finalized = False
        backup_data: bytes | None = None
        backup_info: os.stat_result | None = None
        temporary_disposable = True
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
            temporary_fd = os.open(temporary, flags, 0o600, dir_fd=parent_fd)
            view = memoryview(pending.candidate)
            written = 0
            while written < len(view):
                count = os.write(temporary_fd, view[written:])
                if count <= 0:
                    raise OSError("short atomic write")
                written += count
            if original_info is not None:
                os.fchmod(temporary_fd, stat.S_IMODE(original_info.st_mode) & 0o666)
            os.fsync(temporary_fd)
            candidate_info = os.fstat(temporary_fd)
            os.close(temporary_fd)
            temporary_fd = -1
            if self._before_replace is not None:
                self._before_replace(pending.prepared.path)
            # Recheck after every potentially long or externally observable
            # step.  A swapped symlink is compared as a symlink and rejected;
            # it is never followed or opened as the replacement destination.
            current_info = self._stat_name(parent_fd, name)
            if pending.original is None:
                if current_info is not None:
                    raise FileWorkspaceStale("create target appeared during commit", prepared_write_id=pending.prepared.prepared_write_id)
            else:
                if current_info is None or not stat.S_ISREG(current_info.st_mode):
                    raise FileWorkspaceStale("file identity changed during commit", prepared_write_id=pending.prepared.prepared_write_id)
                if original_info is None or (current_info.st_dev, current_info.st_ino) != (original_info.st_dev, original_info.st_ino):
                    raise FileWorkspaceStale(
                        "file identity changed during commit",
                        prepared_write_id=pending.prepared.prepared_write_id,
                    )
                current, current_read_info = self._read_bytes_at(parent_fd, name, pending.prepared.path)
                if (current_read_info.st_dev, current_read_info.st_ino) != (current_info.st_dev, current_info.st_ino):
                    raise FileWorkspaceStale(
                        "file identity changed during commit",
                        prepared_write_id=pending.prepared.prepared_write_id,
                    )
                if _hash(current) != pending.prepared.original_hash:
                    raise FileWorkspaceStale("file changed during commit", prepared_write_id=pending.prepared.prepared_write_id, current_hash=_hash(current))
            self._assert_parent_binding(pending.prepared.path, parent_fd)
            self._assert_base_at_boundary(pending.prepared.base_sha, "commit")
            with self._locked_git_head(pending.prepared.base_sha):
                self._invoke_mutation_boundary("commitWrite" if original_info is not None else "createFile")
                if original_info is None:
                    _rename_no_replace(parent_fd, temporary, parent_fd, name)
                else:
                    _rename_exchange(parent_fd, temporary, parent_fd, name)
                    temporary_disposable = False
                applied = True
                os.fsync(parent_fd)

                self._assert_parent_binding(pending.prepared.path, parent_fd)
                self._assert_base_at_boundary(pending.prepared.base_sha, "commit")
                if candidate_info is None:
                    raise FileWorkspaceAtomicWriteError("candidate identity is unavailable")
                self._verify_named_file(
                    parent_fd,
                    name,
                    pending.prepared.path,
                    expected_info=candidate_info,
                    expected_hash=pending.prepared.candidate_hash,
                    message="candidate changed at the commit boundary",
                )
                if original_info is not None:
                    backup_info = self._stat_name(parent_fd, temporary)
                    if backup_info is None or not stat.S_ISREG(backup_info.st_mode):
                        raise FileWorkspaceStale("original file was not retained at the commit boundary")
                    backup_data, backup_read_info = self._read_bytes_at(parent_fd, temporary, pending.prepared.path)
                    if (
                        (backup_read_info.st_dev, backup_read_info.st_ino) != (backup_info.st_dev, backup_info.st_ino)
                        or (backup_info.st_dev, backup_info.st_ino) != (original_info.st_dev, original_info.st_ino)
                        or _hash(backup_data) != pending.prepared.original_hash
                    ):
                        raise FileWorkspaceStale("original file changed at the commit boundary", current_hash=_hash(backup_data))
                    os.unlink(temporary, dir_fd=parent_fd)
                    temporary_disposable = True
                    finalized = True
                    os.fsync(parent_fd)
                    self._assert_parent_binding(pending.prepared.path, parent_fd)
                    self._assert_base_at_boundary(pending.prepared.base_sha, "commit finalization")
                    self._verify_named_file(
                        parent_fd,
                        name,
                        pending.prepared.path,
                        expected_info=candidate_info,
                        expected_hash=pending.prepared.candidate_hash,
                        message="candidate changed during commit finalization",
                    )
            applied = False
        except BaseException as exc:
            if applied:
                try:
                    if candidate_info is None:
                        raise FileWorkspaceAtomicWriteError(
                            "commit rollback candidate identity is unavailable"
                        )
                    target_is_candidate = self._named_file_matches(
                        parent_fd,
                        name,
                        pending.prepared.path,
                        expected_info=candidate_info,
                        expected_hash=pending.prepared.candidate_hash,
                    )
                    if not target_is_candidate:
                        self._retain_write_conflict_evidence(
                            parent_fd,
                            pending,
                            original_info=original_info,
                            candidate_info=candidate_info,
                        )
                        raise FileWorkspaceAtomicWriteError(
                            "concurrent writer preserved at commit boundary"
                        )
                    if original_info is None:
                        _rename_no_replace(parent_fd, name, parent_fd, temporary)
                        temporary_disposable = False
                        if not self._named_file_matches(
                            parent_fd,
                            temporary,
                            pending.prepared.path,
                            expected_info=candidate_info,
                            expected_hash=pending.prepared.candidate_hash,
                        ) or self._stat_name(parent_fd, name) is not None:
                            self._retain_write_conflict_evidence(
                                parent_fd,
                                pending,
                                original_info=original_info,
                                candidate_info=candidate_info,
                            )
                            raise FileWorkspaceAtomicWriteError(
                                "concurrent create value preserved during rollback"
                            )
                        os.unlink(temporary, dir_fd=parent_fd)
                        temporary_disposable = True
                        if self._stat_name(parent_fd, name) is not None:
                            self._retain_write_conflict_evidence(
                                parent_fd,
                                pending,
                                original_info=original_info,
                                candidate_info=candidate_info,
                            )
                            raise FileWorkspaceAtomicWriteError(
                                "concurrent create value preserved during rollback finalization"
                            )
                    elif not finalized:
                        rollback_info = self._stat_name(parent_fd, temporary)
                        if rollback_info is None or not stat.S_ISREG(
                            rollback_info.st_mode
                        ):
                            raise FileWorkspaceAtomicWriteError(
                                "commit rollback source is unavailable"
                            )
                        rollback_data, rollback_read_info = self._read_bytes_at(
                            parent_fd,
                            temporary,
                            pending.prepared.path,
                        )
                        if (
                            rollback_read_info.st_dev,
                            rollback_read_info.st_ino,
                        ) != (rollback_info.st_dev, rollback_info.st_ino):
                            raise FileWorkspaceAtomicWriteError(
                                "commit rollback source identity changed"
                            )
                        rollback_hash = _hash(rollback_data)
                        _rename_exchange(parent_fd, temporary, parent_fd, name)
                        temporary_disposable = False
                        if not self._named_file_matches(
                            parent_fd,
                            temporary,
                            pending.prepared.path,
                            expected_info=candidate_info,
                            expected_hash=pending.prepared.candidate_hash,
                        ):
                            self._retain_write_conflict_evidence(
                                parent_fd,
                                pending,
                                original_info=original_info,
                                candidate_info=candidate_info,
                            )
                            raise FileWorkspaceAtomicWriteError(
                                "concurrent writer preserved during commit rollback"
                            )
                        if not self._named_file_matches(
                            parent_fd,
                            name,
                            pending.prepared.path,
                            expected_info=rollback_info,
                            expected_hash=rollback_hash,
                        ):
                            self._retain_write_conflict_evidence(
                                parent_fd,
                                pending,
                                original_info=original_info,
                                candidate_info=candidate_info,
                            )
                            raise FileWorkspaceAtomicWriteError(
                                "restored value changed during commit rollback"
                            )
                        os.unlink(temporary, dir_fd=parent_fd)
                        temporary_disposable = True
                        if not self._named_file_matches(
                            parent_fd,
                            name,
                            pending.prepared.path,
                            expected_info=rollback_info,
                            expected_hash=rollback_hash,
                        ):
                            self._retain_write_conflict_evidence(
                                parent_fd,
                                pending,
                                original_info=original_info,
                                candidate_info=candidate_info,
                            )
                            raise FileWorkspaceAtomicWriteError(
                                "restored value changed during commit finalization"
                            )
                    else:
                        if backup_data is None or backup_info is None:
                            raise FileWorkspaceAtomicWriteError(
                                "commit rollback evidence is unavailable"
                            )
                        self._restore_bytes(
                            parent_fd,
                            name,
                            pending.prepared.path,
                            backup_data,
                            stat.S_IMODE(backup_info.st_mode),
                            expected_current=candidate_info,
                            expected_current_hash=pending.prepared.candidate_hash,
                        )
                    os.fsync(parent_fd)
                except Exception as rollback_exc:
                    self._quarantine_unresolved("commit_recovery_required")
                    raise FileWorkspaceAtomicWriteError(
                        "commit rollback requires operator recovery; broker quarantined"
                    ) from rollback_exc
            if isinstance(exc, OSError):
                raise FileWorkspaceAtomicWriteError("atomic file replacement failed; original retained") from exc
            raise
        finally:
            if temporary_fd >= 0:
                os.close(temporary_fd)
            if temporary_disposable:
                try:
                    os.unlink(temporary, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
            os.close(parent_fd)

    def commit_write(
        self,
        prepared_write_id: str,
        *,
        confirmed_diff_digest: str,
        actor_id: str,
        application_id: str,
        instance_id: str,
    ) -> FileMutationReceipt:
        with self._mutex:
            self._authorize(actor_id, application_id, instance_id, write=True)
            self._assert_mutation_not_quarantined()
            pending = self._owned_pending(prepared_write_id, actor_id, application_id, instance_id)
            if pending.lease is None or pending.state != "previewed":
                raise FileWorkspaceStale("staged write must be previewed and remain commit-capable", prepared_write_id=prepared_write_id)
            if pending.preview_truncated:
                raise FileWorkspaceValidationError(("diff exceeds the reviewable bound",))
            if not secrets.compare_digest(pending.preview_digest or "", confirmed_diff_digest):
                raise FileWorkspaceStale("diff confirmation does not match the staged write", prepared_write_id=prepared_write_id)
            if self._base_sha() != pending.prepared.base_sha:
                self._mark_conflicted(pending)
                raise FileWorkspaceStale("project base changed before commit", prepared_write_id=prepared_write_id)
            rule = self._rule_for(pending.prepared.path)
            self._validate_candidate(pending.prepared.path, pending.candidate, rule)
            self._assert_mutation_not_quarantined()
            try:
                self._atomic_replace(pending)
            except FileWorkspaceError:
                self._mark_conflicted(pending)
                raise
            completed = self._clock()
            receipt = FileMutationReceipt(
                receipt_id=_receipt_id(),
                operation="commitWrite" if pending.prepared.operation == "write" else "createFile",
                actor_id=actor_id,
                application_id=application_id,
                instance_id=instance_id,
                source_path=pending.prepared.path,
                destination_path=None,
                base_sha=pending.prepared.base_sha,
                pre_hash=pending.prepared.original_hash,
                post_hash=pending.prepared.candidate_hash,
                ownership_class=pending.prepared.ownership_class,
                diff_digest=pending.preview_digest,
                validation="passed" if pending.prepared.validation_required else "not_required",
                completed_at=_utc(completed),
            )
            self._release(pending.lease)
            self._pending.pop(prepared_write_id, None)
            self._condition.notify_all()
            return receipt

    def discard_write(self, prepared_write_id: str, *, actor_id: str, application_id: str, instance_id: str) -> dict[str, object]:
        with self._mutex:
            self._authorize(actor_id, application_id, instance_id, write=True)
            pending = self._owned_pending(prepared_write_id, actor_id, application_id, instance_id)
            self._release(pending.lease)
            self._pending.pop(prepared_write_id, None)
            self._condition.notify_all()
            return {"formatVersion": FILE_WORKSPACE_FORMAT, "operation": "discardWrite", "preparedWriteId": prepared_write_id, "discarded": True}

    def _short_mutation_lease(self, actor_id: str, expected_base_sha: str) -> tuple[InstanceLease, str]:
        self._assert_mutation_not_quarantined()
        lease = self._acquire_lease(actor_id)
        try:
            self._assert_mutation_not_quarantined()
            base = self._base_sha()
            if base != expected_base_sha:
                raise FileWorkspaceStale("project base changed before path mutation")
            return lease, base
        except Exception:
            self._release(lease)
            raise

    def rename_path(
        self,
        source_path: str,
        destination_path: str,
        *,
        expected_content_hash: str,
        expected_base_sha: str,
        actor_id: str,
        application_id: str,
        instance_id: str,
    ) -> FileMutationReceipt:
        with self._mutex:
            self._authorize(actor_id, application_id, instance_id, write=True)
            source = self._path(source_path)
            destination = self._path(destination_path)
            source_rule = self._rule_for(source)
            destination_rule = self._rule_for(destination)
            if (
                not source_rule.rename
                or not destination_rule.create
                or source_rule.ownership_class != destination_rule.ownership_class
                or source_rule.ownership_class in {"canonical", "generated"}
            ):
                raise FileWorkspaceAccessDenied()
            self._language(destination)
            lease, base = self._short_mutation_lease(actor_id, expected_base_sha)
            source_parent = -1
            destination_parent = -1
            applied = False
            try:
                source_parent, source_name = self._open_parent(source)
                destination_parent, destination_name = self._open_parent(destination)
                initial_source_info = self._stat_name(source_parent, source_name)
                if initial_source_info is None or not stat.S_ISREG(initial_source_info.st_mode):
                    raise FileWorkspaceStale("rename source identity changed")
                data, read_info = self._read_bytes_at(source_parent, source_name, source)
                if (read_info.st_dev, read_info.st_ino) != (initial_source_info.st_dev, initial_source_info.st_ino):
                    raise FileWorkspaceStale("rename source identity changed")
                if _hash(data) != expected_content_hash:
                    raise FileWorkspaceStale("rename source changed", current_hash=_hash(data))
                if self._stat_name(destination_parent, destination_name) is not None:
                    raise FileWorkspaceStale("rename destination already exists")
                if self._before_destructive is not None:
                    self._before_destructive(source)
                source_info = self._stat_name(source_parent, source_name)
                if source_info is None or not stat.S_ISREG(source_info.st_mode):
                    raise FileWorkspaceStale("rename source identity changed")
                if (source_info.st_dev, source_info.st_ino) != (initial_source_info.st_dev, initial_source_info.st_ino):
                    raise FileWorkspaceStale("rename source identity changed")
                fresh, fresh_info = self._read_bytes_at(source_parent, source_name, source)
                if (fresh_info.st_dev, fresh_info.st_ino) != (source_info.st_dev, source_info.st_ino):
                    raise FileWorkspaceStale("rename source identity changed")
                if _hash(fresh) != expected_content_hash:
                    raise FileWorkspaceStale("rename source changed", current_hash=_hash(fresh))
                self._assert_parent_binding(source, source_parent)
                self._assert_parent_binding(destination, destination_parent)
                self._assert_base_at_boundary(base, "rename")
                with self._locked_git_head(base):
                    self._invoke_mutation_boundary("renamePath")
                    _rename_no_replace(source_parent, source_name, destination_parent, destination_name)
                    applied = True
                    os.fsync(source_parent)
                    if source_parent != destination_parent:
                        os.fsync(destination_parent)
                    self._assert_parent_binding(source, source_parent)
                    self._assert_parent_binding(destination, destination_parent)
                    self._assert_base_at_boundary(base, "rename")
                    if self._stat_name(source_parent, source_name) is not None:
                        raise FileWorkspaceStale("rename source reappeared at the mutation boundary")
                    self._verify_named_file(
                        destination_parent,
                        destination_name,
                        destination,
                        expected_info=initial_source_info,
                        expected_hash=expected_content_hash,
                        message="rename source changed at the mutation boundary",
                    )
                applied = False
            except BaseException as exc:
                if applied:
                    try:
                        moved_info = self._stat_name(destination_parent, destination_name)
                        destination_is_original = (
                            moved_info is not None
                            and stat.S_ISREG(moved_info.st_mode)
                            and self._named_file_matches(
                                destination_parent,
                                destination_name,
                                destination,
                                expected_info=initial_source_info,
                                expected_hash=expected_content_hash,
                            )
                        )
                        if (
                            not destination_is_original
                            or self._stat_name(source_parent, source_name) is not None
                        ):
                            self._retain_recovery_bytes(
                                source_parent,
                                source,
                                data,
                                stat.S_IMODE(initial_source_info.st_mode),
                            )
                            raise FileWorkspaceAtomicWriteError(
                                "concurrent rename value preserved; recovery retained"
                            )
                        _rename_no_replace(destination_parent, destination_name, source_parent, source_name)
                        os.fsync(source_parent)
                        if source_parent != destination_parent:
                            os.fsync(destination_parent)
                        if (
                            moved_info is None
                            or not self._named_file_matches(
                                source_parent,
                                source_name,
                                source,
                                expected_info=moved_info,
                                expected_hash=expected_content_hash,
                            )
                            or self._stat_name(destination_parent, destination_name)
                            is not None
                        ):
                            self._retain_recovery_bytes(
                                source_parent,
                                source,
                                data,
                                stat.S_IMODE(initial_source_info.st_mode),
                            )
                            raise FileWorkspaceAtomicWriteError(
                                "rename rollback changed concurrently; recovery retained"
                            )
                    except Exception as rollback_exc:
                        self._quarantine_unresolved("rename_recovery_required")
                        raise FileWorkspaceAtomicWriteError(
                            "rename rollback requires operator recovery; broker quarantined"
                        ) from rollback_exc
                if isinstance(exc, OSError):
                    raise FileWorkspaceAtomicWriteError("atomic rename failed; source retained") from exc
                raise
            finally:
                if source_parent >= 0:
                    os.close(source_parent)
                if destination_parent >= 0:
                    os.close(destination_parent)
                self._release(lease)
            return FileMutationReceipt(
                _receipt_id(), "renamePath", actor_id, application_id, instance_id,
                source, destination, base, expected_content_hash, expected_content_hash,
                source_rule.ownership_class, None, "not_required", _utc(self._clock()),
            )

    def delete_path(
        self,
        path: str,
        *,
        expected_content_hash: str,
        expected_base_sha: str,
        actor_id: str,
        application_id: str,
        instance_id: str,
    ) -> FileMutationReceipt:
        with self._mutex:
            self._authorize(actor_id, application_id, instance_id, write=True)
            selected = self._path(path)
            rule = self._rule_for(selected)
            if not rule.delete or rule.ownership_class in {"canonical", "generated"}:
                raise FileWorkspaceAccessDenied()
            lease, base = self._short_mutation_lease(actor_id, expected_base_sha)
            parent_fd = -1
            temporary = f".stateport-delete-{secrets.token_hex(16)}.tmp"
            applied = False
            finalized = False
            staged_data: bytes | None = None
            staged_info: os.stat_result | None = None
            temporary_disposable = True
            try:
                parent_fd, name = self._open_parent(selected)
                initial_info = self._stat_name(parent_fd, name)
                if initial_info is None or not stat.S_ISREG(initial_info.st_mode):
                    raise FileWorkspaceStale("delete target identity changed")
                data, read_info = self._read_bytes_at(parent_fd, name, selected)
                if (read_info.st_dev, read_info.st_ino) != (initial_info.st_dev, initial_info.st_ino):
                    raise FileWorkspaceStale("delete target identity changed")
                if _hash(data) != expected_content_hash:
                    raise FileWorkspaceStale("delete target changed", current_hash=_hash(data))
                if self._before_destructive is not None:
                    self._before_destructive(selected)
                info = self._stat_name(parent_fd, name)
                if info is None or not stat.S_ISREG(info.st_mode):
                    raise FileWorkspaceStale("delete target identity changed")
                if (info.st_dev, info.st_ino) != (initial_info.st_dev, initial_info.st_ino):
                    raise FileWorkspaceStale("delete target identity changed")
                fresh, fresh_info = self._read_bytes_at(parent_fd, name, selected)
                if (fresh_info.st_dev, fresh_info.st_ino) != (info.st_dev, info.st_ino):
                    raise FileWorkspaceStale("delete target identity changed")
                if _hash(fresh) != expected_content_hash:
                    raise FileWorkspaceStale("delete target changed", current_hash=_hash(fresh))
                self._assert_parent_binding(selected, parent_fd)
                self._assert_base_at_boundary(base, "delete")
                with self._locked_git_head(base):
                    self._invoke_mutation_boundary("deletePath")
                    _rename_no_replace(parent_fd, name, parent_fd, temporary)
                    applied = True
                    temporary_disposable = False
                    os.fsync(parent_fd)
                    self._assert_parent_binding(selected, parent_fd)
                    self._assert_base_at_boundary(base, "delete")
                    if self._stat_name(parent_fd, name) is not None:
                        raise FileWorkspaceStale("delete target reappeared at the mutation boundary")
                    staged_info = self._stat_name(parent_fd, temporary)
                    if staged_info is None or not stat.S_ISREG(staged_info.st_mode):
                        raise FileWorkspaceStale("delete target was not retained at the mutation boundary")
                    staged_data, staged_read_info = self._read_bytes_at(parent_fd, temporary, selected)
                    if (
                        (staged_read_info.st_dev, staged_read_info.st_ino) != (staged_info.st_dev, staged_info.st_ino)
                        or (staged_info.st_dev, staged_info.st_ino) != (initial_info.st_dev, initial_info.st_ino)
                        or _hash(staged_data) != expected_content_hash
                    ):
                        raise FileWorkspaceStale("delete target changed at the mutation boundary", current_hash=_hash(staged_data))
                    os.unlink(temporary, dir_fd=parent_fd)
                    temporary_disposable = True
                    finalized = True
                    os.fsync(parent_fd)
                    self._assert_parent_binding(selected, parent_fd)
                    self._assert_base_at_boundary(base, "delete finalization")
                    if self._stat_name(parent_fd, name) is not None:
                        raise FileWorkspaceStale("delete target reappeared during finalization")
                applied = False
            except BaseException as exc:
                if applied:
                    try:
                        if not finalized:
                            rollback_info = self._stat_name(parent_fd, temporary)
                            rollback_data: bytes | None = None
                            rollback_hash: str | None = None
                            rollback_is_safe = False
                            if rollback_info is not None and stat.S_ISREG(
                                rollback_info.st_mode
                            ):
                                rollback_data, rollback_read_info = self._read_bytes_at(
                                    parent_fd,
                                    temporary,
                                    selected,
                                )
                                rollback_hash = _hash(rollback_data)
                                rollback_is_safe = (
                                    (rollback_read_info.st_dev, rollback_read_info.st_ino)
                                    == (rollback_info.st_dev, rollback_info.st_ino)
                                    and (rollback_info.st_dev, rollback_info.st_ino)
                                    == (initial_info.st_dev, initial_info.st_ino)
                                )
                            if (
                                self._stat_name(parent_fd, name) is not None
                                or not rollback_is_safe
                            ):
                                self._retain_recovery_bytes(
                                    parent_fd,
                                    selected,
                                    data,
                                    stat.S_IMODE(initial_info.st_mode),
                                )
                                raise FileWorkspaceAtomicWriteError(
                                    "concurrent delete value preserved; recovery retained"
                                )
                            _rename_no_replace(parent_fd, temporary, parent_fd, name)
                            temporary_disposable = True
                            os.fsync(parent_fd)
                            if (
                                rollback_info is None
                                or rollback_hash is None
                                or not self._named_file_matches(
                                    parent_fd,
                                    name,
                                    selected,
                                    expected_info=rollback_info,
                                    expected_hash=rollback_hash,
                                )
                                or self._stat_name(parent_fd, temporary) is not None
                            ):
                                self._retain_recovery_bytes(
                                    parent_fd,
                                    selected,
                                    data,
                                    stat.S_IMODE(initial_info.st_mode),
                                )
                                raise FileWorkspaceAtomicWriteError(
                                    "delete rollback changed concurrently; recovery retained"
                                )
                        else:
                            if staged_data is None or staged_info is None:
                                raise FileWorkspaceAtomicWriteError("delete rollback evidence is unavailable")
                            self._restore_bytes(
                                parent_fd,
                                name,
                                selected,
                                staged_data,
                                stat.S_IMODE(staged_info.st_mode),
                                expected_current=None,
                            )
                    except Exception as rollback_exc:
                        self._quarantine_unresolved("delete_recovery_required")
                        raise FileWorkspaceAtomicWriteError(
                            "delete rollback requires operator recovery; broker quarantined"
                        ) from rollback_exc
                if isinstance(exc, OSError):
                    raise FileWorkspaceAtomicWriteError("atomic delete failed; target retained") from exc
                raise
            finally:
                if parent_fd >= 0:
                    if temporary_disposable:
                        try:
                            os.unlink(temporary, dir_fd=parent_fd)
                        except FileNotFoundError:
                            pass
                    os.close(parent_fd)
                self._release(lease)
            return FileMutationReceipt(
                _receipt_id(), "deletePath", actor_id, application_id, instance_id,
                selected, None, base, expected_content_hash, None,
                rule.ownership_class, None, "not_required", _utc(self._clock()),
            )

    # Wire-contract spellings are provided explicitly while Python callers can
    # use the idiomatic methods above.
    listDirectory = list_directory
    readFile = read_file
    readFileMetadata = read_file_metadata
    prepareWrite = prepare_write
    previewDiff = preview_diff
    commitWrite = commit_write
    discardWrite = discard_write
    renamePath = rename_path
    createFile = create_file
    deletePath = delete_path

    def close(self) -> None:
        quarantine_error: Exception | None = None
        with self._condition:
            if self._closed:
                return
            self._closed = True
            for pending in self._pending.values():
                try:
                    self._release(pending.lease)
                except FileWorkspaceAtomicWriteError as exc:
                    if quarantine_error is None:
                        quarantine_error = exc
            self._pending.clear()
            self._condition.notify_all()
            os.close(self._root_fd)
            os.close(self._quarantine_fd)
        self._reaper.join(timeout=max(2.0, self._reaper_maximum_sleep_seconds + 1.0))
        if quarantine_error is not None:
            raise quarantine_error

    def __enter__(self) -> "FileWorkspaceBroker":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()
