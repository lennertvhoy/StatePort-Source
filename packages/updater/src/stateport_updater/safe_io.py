"""Fail-closed local persistence primitives for the installed updater.

The updater state is authority and recovery evidence.  It therefore lives in
an owner-private directory, rejects symlinks and multiply-linked files, and
uses create-only records for plans, outcomes, and authority links. Mutable state is
published with an fsync + atomic replace while a process lock is held.
"""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import secrets
import stat
import time
from typing import Any, Iterator, Mapping


MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
MAX_RELEASE_INDEX_BYTES = 4 * 1024 * 1024
MAX_DOCUMENT_DEPTH = 64
MAX_DOCUMENT_NODES = 100_000


class SafeIOError(ValueError):
    """A persistence path or document failed a fail-closed check."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _bounded(value: object, *, label: str) -> None:
    nodes = 0

    def visit(item: object, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if depth > MAX_DOCUMENT_DEPTH or nodes > MAX_DOCUMENT_NODES:
            raise SafeIOError("document_too_complex", f"{label} exceeds bounded complexity")
        if isinstance(item, Mapping):
            for key, child in item.items():
                visit(key, depth + 1)
                visit(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                visit(child, depth + 1)

    visit(value, 0)


def _directory_metadata(path: Path) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise SafeIOError("unsafe_state_root", "could not inspect updater state directory") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise SafeIOError("unsafe_state_root", "updater state path is not a real directory")
    return metadata


def _validate_private_directory(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise SafeIOError(
            "unsafe_state_root",
            "updater state directory must remain owner-private",
        )


def ensure_private_directory(path: Path) -> Path:
    """Create ``path`` without changing caller-owned ancestor permissions."""

    path = path.absolute()
    missing: list[Path] = []
    cursor = path
    while True:
        try:
            metadata = cursor.lstat()
        except FileNotFoundError:
            missing.append(cursor)
        except OSError as exc:
            raise SafeIOError("unsafe_state_root", "could not inspect updater state path") from exc
        else:
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise SafeIOError(
                    "unsafe_state_root", "state path traverses a symlink or non-directory"
                )
        parent = cursor.parent
        if parent == cursor:
            break
        cursor = parent

    for candidate in reversed(missing):
        try:
            candidate.mkdir(mode=0o700)
        except FileExistsError:
            pass
        metadata = _directory_metadata(candidate)
        _validate_private_directory(metadata)

    metadata = _directory_metadata(path)
    _validate_private_directory(metadata)
    return path


def _open_directory(path: Path) -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise SafeIOError("unsupported_filesystem", "no-follow descriptor support is required")
    before = _directory_metadata(path)
    _validate_private_directory(before)
    flags = (
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
    )
    try:
        descriptor = os.open(path, flags)
        observed = os.fstat(descriptor)
    except OSError as exc:
        raise SafeIOError("unsafe_state_root", "could not open updater state directory") from exc
    if (before.st_dev, before.st_ino) != (observed.st_dev, observed.st_ino):
        os.close(descriptor)
        raise SafeIOError("unsafe_state_root", "updater state directory changed identity")
    try:
        _validate_private_directory(observed)
    except SafeIOError:
        os.close(descriptor)
        raise
    return descriptor


def _validate_regular(metadata: os.stat_result, label: str) -> None:
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise SafeIOError("unsafe_state_file", f"{label} is not a single regular file")
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise SafeIOError("unsafe_state_file", f"{label} is not owner-private")
    if metadata.st_size > MAX_DOCUMENT_BYTES:
        raise SafeIOError("document_too_large", f"{label} exceeds the document size limit")


def read_json(path: Path, label: str) -> dict[str, Any]:
    parent_fd = _open_directory(path.parent)
    descriptor = -1
    try:
        try:
            descriptor = os.open(
                path.name,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
            _validate_regular(os.fstat(descriptor), label)
            payload = bytearray()
            while chunk := os.read(descriptor, 128 * 1024):
                payload.extend(chunk)
                if len(payload) > MAX_DOCUMENT_BYTES:
                    raise SafeIOError(
                        "document_too_large", f"{label} exceeds the document size limit"
                    )
        except OSError as exc:
            raise SafeIOError("state_read_failed", f"could not read {label}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_fd)
    try:
        value = json.loads(bytes(payload))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SafeIOError("state_invalid", f"{label} is not valid JSON") from exc
    _bounded(value, label=label)
    if not isinstance(value, dict):
        raise SafeIOError("state_invalid", f"{label} must contain an object")
    return value


def read_bytes(path: Path, label: str, *, maximum: int = MAX_RELEASE_INDEX_BYTES) -> bytes:
    """Read one owner-private immutable byte record without following links."""

    parent_fd = _open_directory(path.parent)
    descriptor = -1
    try:
        try:
            descriptor = os.open(
                path.name,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) & 0o077
            ):
                raise SafeIOError("unsafe_state_file", f"{label} is not owner-private")
            if metadata.st_size > maximum:
                raise SafeIOError("document_too_large", f"{label} exceeds the byte limit")
            payload = bytearray()
            while chunk := os.read(descriptor, 128 * 1024):
                payload.extend(chunk)
                if len(payload) > maximum:
                    raise SafeIOError("document_too_large", f"{label} exceeds the byte limit")
        except OSError as exc:
            raise SafeIOError("state_read_failed", f"could not read {label}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_fd)
    return bytes(payload)


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise SafeIOError("state_write_failed", "short write while persisting updater state")
        view = view[written:]


def create_json(path: Path, value: Mapping[str, Any], label: str) -> None:
    payload = canonical_json_bytes(value)
    if len(payload) > MAX_DOCUMENT_BYTES:
        raise SafeIOError("document_too_large", f"{label} exceeds the document size limit")
    _bounded(dict(value), label=label)
    parent_fd = _open_directory(path.parent)
    descriptor = -1
    try:
        try:
            descriptor = os.open(
                path.name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent_fd,
            )
            _write_all(descriptor, payload)
            os.fsync(descriptor)
        except FileExistsError as exc:
            raise SafeIOError("immutable_record_exists", f"{label} already exists") from exc
        except OSError as exc:
            raise SafeIOError("state_write_failed", f"could not create {label}") from exc
        os.fsync(parent_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_fd)


def create_bytes(
    path: Path,
    payload: bytes,
    label: str,
    *,
    maximum: int = MAX_RELEASE_INDEX_BYTES,
) -> None:
    """Create one immutable owner-private byte record with directory fsync."""

    if not isinstance(payload, bytes) or not payload or len(payload) > maximum:
        raise SafeIOError("document_too_large", f"{label} is empty or exceeds the byte limit")
    parent_fd = _open_directory(path.parent)
    descriptor = -1
    try:
        try:
            descriptor = os.open(
                path.name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent_fd,
            )
            _write_all(descriptor, payload)
            os.fsync(descriptor)
        except FileExistsError as exc:
            raise SafeIOError("immutable_record_exists", f"{label} already exists") from exc
        except OSError as exc:
            raise SafeIOError("state_write_failed", f"could not create {label}") from exc
        os.fsync(parent_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_fd)


def replace_json(path: Path, value: Mapping[str, Any], label: str) -> None:
    payload = canonical_json_bytes(value)
    if len(payload) > MAX_DOCUMENT_BYTES:
        raise SafeIOError("document_too_large", f"{label} exceeds the document size limit")
    _bounded(dict(value), label=label)
    parent_fd = _open_directory(path.parent)
    temporary = f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
    descriptor = -1
    try:
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent_fd,
            )
            _write_all(descriptor, payload)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.replace(temporary, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            os.fsync(parent_fd)
        except OSError as exc:
            raise SafeIOError("state_write_failed", f"could not replace {label}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        except OSError:
            # The private root prevents another user from introducing this
            # name.  A residue is retained for operator inspection if local IO
            # itself failed.
            pass
        os.close(parent_fd)


def unlink_regular(path: Path, label: str) -> None:
    """Remove one known mutable record without following a replacement link."""

    parent_fd = _open_directory(path.parent)
    try:
        try:
            metadata = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise SafeIOError("state_write_failed", f"could not inspect {label}") from exc
        _validate_regular(metadata, label)
        try:
            os.unlink(path.name, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except OSError as exc:
            raise SafeIOError("state_write_failed", f"could not remove {label}") from exc
    finally:
        os.close(parent_fd)


@contextmanager
def exclusive_lock(
    path: Path,
    *,
    timeout_seconds: float = 1.0,
    create: bool = True,
) -> Iterator[None]:
    """Acquire one owner-private lock within a bounded interval.

    Updater diagnostics must never wait behind a long-running host operation.
    Callers therefore use this primitive only for short state transactions or
    for the separate single-mutator operation lease.
    """

    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not 0 < timeout_seconds <= 30
    ):
        raise SafeIOError("update_state_busy", "updater lock timeout is invalid")

    parent_fd = _open_directory(path.parent)
    descriptor = -1
    try:
        try:
            flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
            if create:
                flags |= os.O_CREAT
            descriptor = os.open(path.name, flags, 0o600, dir_fd=parent_fd)
            metadata = os.fstat(descriptor)
            _validate_regular(metadata, "updater lock")
            deadline = time.monotonic() + float(timeout_seconds)
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError as exc:
                    if time.monotonic() >= deadline:
                        raise SafeIOError(
                            "update_state_busy",
                            "updater state is busy; retry after the active transaction",
                        ) from exc
                    time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))
            # Metadata is re-read after the synchronization boundary.  Refuse
            # chmod, replacement, or hard-link drift even when it happened
            # between the initial open and successful flock.
            locked = os.fstat(descriptor)
            _validate_regular(locked, "updater lock")
            linked = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            if (locked.st_dev, locked.st_ino) != (linked.st_dev, linked.st_ino):
                raise SafeIOError("unsafe_state_file", "updater lock changed identity")
        except FileNotFoundError as exc:
            raise SafeIOError("state_uninitialized", "updater state is not initialized") from exc
        except SafeIOError:
            raise
        except OSError as exc:
            raise SafeIOError("state_lock_failed", "could not acquire updater lock") from exc
        # Only lock acquisition is translated above.  Errors raised by the
        # session body while the lock is held keep their real identity.
        yield
    finally:
        if descriptor >= 0:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)
        os.close(parent_fd)
