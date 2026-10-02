"""Kernel-backed single-writer leases for local StateSpec instances."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


INSTANCE_LEASE_FORMAT = "stateport.instance-lease/v1"


class InstanceLeaseError(RuntimeError):
    """An instance lease could not be configured or acquired safely."""


class InstanceLeaseBusy(InstanceLeaseError):
    """Another open file description currently holds the kernel lease."""


def _utc_timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise InstanceLeaseError("lease clock must return a timezone-aware datetime")
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _safe_lease_directory(path: Path | str) -> Path:
    if not isinstance(path, (Path, str)) or not os.fspath(path):
        raise InstanceLeaseError("operational lease directory is required")
    target = Path(os.path.abspath(os.fspath(path)))
    cursor = Path(target.anchor)
    parts = target.parts[1:] if target.is_absolute() else target.parts
    for part in parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise InstanceLeaseError("operational lease directory may not traverse a symlink")
        if cursor.exists() and not cursor.is_dir():
            raise InstanceLeaseError("operational lease path must be a directory")
    target.mkdir(parents=True, exist_ok=True)
    cursor = Path(target.anchor)
    for part in parts:
        cursor = cursor / part
        if cursor.is_symlink() or not cursor.is_dir():
            raise InstanceLeaseError("operational lease directory is not symlink-safe")
    return target


class InstanceLease:
    """Non-blocking local single-writer lease backed by ``fcntl.flock``.

    JSON stored in the lock file is diagnostic metadata only. Ownership is
    determined exclusively by the kernel lock held on the open file
    description and must never be inferred from that metadata.
    """

    def __init__(
        self,
        lease_directory: Path | str,
        instance_path: Path | str,
        *,
        owner: str = "",
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(owner, str):
            raise InstanceLeaseError("lease owner must be a string")
        try:
            resolved_instance = Path(instance_path).resolve(strict=True)
        except (OSError, RuntimeError, TypeError) as exc:
            raise InstanceLeaseError(f"instance path could not be resolved: {exc}") from exc
        if not resolved_instance.is_dir():
            raise InstanceLeaseError("instance path must be an existing directory")
        self.lease_directory = _safe_lease_directory(lease_directory)
        self.instance_path = resolved_instance
        self.owner = owner
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self.key = hashlib.sha256(
            os.fsencode(self.instance_path.as_posix())
        ).hexdigest()
        self.lock_path = self.lease_directory / f"{self.key}.lock"
        self._fd: int | None = None

    @property
    def acquired(self) -> bool:
        return self._fd is not None

    def _metadata(self) -> bytes:
        payload: dict[str, Any] = {
            "formatVersion": INSTANCE_LEASE_FORMAT,
            "instancePath": self.instance_path.as_posix(),
            "key": self.key,
            "owner": self.owner,
            "pid": os.getpid(),
            "acquiredAt": _utc_timestamp(self._clock()),
            "authority": "fcntl.flock",
        }
        return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode(
            "utf-8"
        )

    def acquire(self) -> "InstanceLease":
        if self._fd is not None:
            raise InstanceLeaseError("instance lease is already acquired")
        _safe_lease_directory(self.lease_directory)
        directory_fd: int | None = None
        lock_fd: int | None = None
        try:
            directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
            directory_fd = os.open(self.lease_directory, directory_flags)
            lock_flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
            lock_fd = os.open(
                self.lock_path.name,
                lock_flags,
                0o600,
                dir_fd=directory_fd,
            )
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise InstanceLeaseBusy("instance already has an active writer lease") from exc
            metadata = self._metadata()
            os.ftruncate(lock_fd, 0)
            os.lseek(lock_fd, 0, os.SEEK_SET)
            written = 0
            while written < len(metadata):
                written += os.write(lock_fd, metadata[written:])
            os.fsync(lock_fd)
            self._fd = lock_fd
            lock_fd = None
            return self
        except InstanceLeaseError:
            raise
        except OSError as exc:
            raise InstanceLeaseError(f"instance lease could not be acquired safely: {exc}") from exc
        finally:
            if lock_fd is not None:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                except OSError:
                    pass
                os.close(lock_fd)
            if directory_fd is not None:
                os.close(directory_fd)

    def release(self) -> None:
        if self._fd is None:
            return
        descriptor = self._fd
        self._fd = None
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    def __enter__(self) -> "InstanceLease":
        return self.acquire()

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        del exc_type, exc, traceback
        self.release()
        return False


__all__ = [
    "INSTANCE_LEASE_FORMAT",
    "InstanceLease",
    "InstanceLeaseBusy",
    "InstanceLeaseError",
]
