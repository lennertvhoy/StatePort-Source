"""Safe, deterministic backups for a StatePort instance.

The archive format deliberately contains only ``manifest.json`` and regular
files below ``files/``.  The manifest's ``archiveDigest`` is the SHA-256 of a
canonical inventory of those files (path, ownership, mode, size, and content
digest), rather than a digest of the archive bytes.  This makes the manifest
deterministic without an impossible self-referential archive hash and lets a
tar backup and a zip backup describe the same payload.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import io
import json
import os
from dataclasses import dataclass
from pathlib import Path
import posixpath
import re
import secrets
import stat
import sys
import tarfile
import tempfile
from typing import Any, BinaryIO, Callable, Iterator, Mapping
import zipfile


BACKUP_FORMAT = "stateport.instance-backup/v1"
MANIFEST_NAME = "manifest.json"
FILES_PREFIX = "files/"
SUPPORTED_ARCHIVE_FORMATS = {"tar", "zip"}
OWNERS = {"template", "instance", "generated", "override"}
SENSITIVITIES = {"public", "internal", "private", "secret"}

# Portable archives use the same outer repository envelope as local source
# inspection (50,000 files / 512 MiB materialized content), with additional
# per-member limits because tar/zip metadata and compression are untrusted.
# These are product contract limits, not caller-controlled tuning knobs.
MAX_BACKUP_FILES = 50_000
MAX_ARCHIVE_MEMBERS = 100_000
MAX_ARCHIVE_FILE_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_MATERIALIZED_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_CONTAINER_BYTES = MAX_ARCHIVE_MATERIALIZED_BYTES + 64 * 1024 * 1024
MAX_ARCHIVE_PATH_LENGTH = 512

FaultInjector = Callable[[str], None]

# Git metadata belongs to the execution host.  It can retain remotes, hooks,
# local identities, or credential-bearing configuration and is never portable
# canonical instance state.
_EXCLUDED_INSTANCE_PREFIXES = (".git",)


class BackupError(ValueError):
    """Base error for invalid, unsafe, or unusable backup operations."""


class UnsafePathError(BackupError):
    """A source, archive, or archive member uses an unsafe path."""


class BackupConflictError(BackupError):
    """A restore would overwrite or be confused with existing state."""


class BackupIntegrityError(BackupError):
    """An archive or its manifest does not match its declared content."""


class CrashInjected(BackupError):
    """A test-only interruption at a named backup/restore durability boundary."""


_RENAME_NOREPLACE = 1

# musl (Alpine) does not export renameat2 as a libc symbol even though the
# kernel supports RENAME_NOREPLACE; the raw syscall works on every Linux libc.
_SYS_RENAMEAT2 = 316  # x86_64
_renameat2_syscall: Any | None = None


def _resolve_renameat2() -> Any:
    """Resolve renameat2 from libc, falling back to the raw syscall.

    glibc exports renameat2; musl (used by the Alpine web image) does not,
    so ctypes.CDLL(None) cannot see it.  Calling the syscall directly is
    portable across both and fails only when the kernel lacks support.
    """

    global _renameat2_syscall
    if _renameat2_syscall is not None:
        return _renameat2_syscall
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is not None:
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        _renameat2_syscall = renameat2
        return _renameat2_syscall
    syscall = getattr(libc, "syscall", None)
    if syscall is None:
        raise BackupError("atomic no-replace rename is unavailable in the runtime C library")
    syscall.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_char_p, ctypes.c_long, ctypes.c_char_p, ctypes.c_uint]
    syscall.restype = ctypes.c_long
    _renameat2_syscall = ("syscall", syscall)
    return _renameat2_syscall


def _rename_noreplace(parent_fd: int, source_name: str, target_name: str, label: str) -> None:
    if not sys.platform.startswith("linux"):
        raise BackupError(f"atomic no-replace {label} is unavailable on this platform")
    resolved = _resolve_renameat2()
    if isinstance(resolved, tuple):
        _, syscall = resolved
        result = syscall(_SYS_RENAMEAT2, parent_fd, os.fsencode(source_name), parent_fd, os.fsencode(target_name), _RENAME_NOREPLACE)
    else:
        result = resolved(
            parent_fd,
            os.fsencode(source_name),
            parent_fd,
            os.fsencode(target_name),
            _RENAME_NOREPLACE,
        )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise BackupConflictError(f"{label} destination appeared during operation")
    unsupported = {errno.ENOSYS, errno.EINVAL}
    unsupported.update(
        value
        for value in (getattr(errno, "EOPNOTSUPP", None), getattr(errno, "ENOTSUP", None))
        if isinstance(value, int)
    )
    if error_number in unsupported:
        raise BackupError(f"atomic no-replace {label} is unavailable on this filesystem")
    raise OSError(error_number, os.strerror(error_number), target_name)


def _fault(injector: FaultInjector | None, boundary: str) -> None:
    if injector is not None:
        injector(boundary)
    configured = os.environ.get("STATEPORT_BACKUP_CRASH_AT")
    if configured and configured == boundary:
        raise CrashInjected(f"crash injected at {boundary}")


def _directory_identity(path: Path) -> tuple[int, int]:
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise UnsafePathError("restore staging is not a real directory")
    return int(info.st_dev), int(info.st_ino)


def _directory_identity_at(parent_fd: int, name: str) -> tuple[int, int]:
    info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise UnsafePathError("restore staging is not a real directory")
    return int(info.st_dev), int(info.st_ino)


def _remove_tree_at(parent_fd: int, name: str) -> None:
    """Remove a directory through descriptors, never by recursively following a name."""

    directory_fd = os.open(
        name,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=parent_fd,
    )
    try:
        directory_info = os.fstat(directory_fd)
        if not stat.S_ISDIR(directory_info.st_mode):
            raise BackupConflictError("owned rollback target is no longer a directory")
        with os.scandir(directory_fd) as entries:
            for entry in sorted(entries, key=lambda item: item.name):
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    _remove_tree_at(directory_fd, entry.name)
                    continue
                if not stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode):
                    raise UnsafePathError("owned rollback tree contains an unsupported file")
                child_fd = -1
                if stat.S_ISREG(info.st_mode):
                    child_fd = os.open(
                        entry.name,
                        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=directory_fd,
                    )
                    child_info = os.fstat(child_fd)
                    if (child_info.st_dev, child_info.st_ino) != (info.st_dev, info.st_ino):
                        raise BackupConflictError("owned rollback file identity changed")
                try:
                    os.unlink(entry.name, dir_fd=directory_fd)
                finally:
                    if child_fd >= 0:
                        os.close(child_fd)
        os.rmdir(name, dir_fd=parent_fd)
    finally:
        os.close(directory_fd)


def remove_owned_directory(path: str | os.PathLike[str], expected_identity: tuple[int, int]) -> None:
    """Atomically quarantine and remove only a directory with the expected inode."""

    target = Path(path)
    parent_fd = _open_safe_directory(target.parent, "owned rollback parent")
    quarantine: str | None = None
    try:
        if _directory_identity_at(parent_fd, target.name) != expected_identity:
            raise BackupConflictError("owned rollback target identity changed")
        for _attempt in range(128):
            candidate = f".{target.name}.rollback-{secrets.token_hex(12)}"
            try:
                _rename_noreplace(parent_fd, target.name, candidate, "rollback")
            except BackupConflictError:
                continue
            quarantine = candidate
            break
        if quarantine is None:
            raise BackupError("could not allocate an owned rollback quarantine")
        if _directory_identity_at(parent_fd, quarantine) != expected_identity:
            try:
                _rename_noreplace(parent_fd, quarantine, target.name, "rollback recovery")
            except BackupError:
                pass
            raise BackupConflictError("owned rollback target identity changed")
        _remove_tree_at(parent_fd, quarantine)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _regular_file_identity(path: Path) -> tuple[int, int]:
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise UnsafePathError("backup staging is not a single regular file")
    return int(info.st_dev), int(info.st_ino)


def _regular_file_identity_fd(fd: int) -> tuple[int, int]:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise UnsafePathError("backup staging is not a single regular file")
    return int(info.st_dev), int(info.st_ino)


def _regular_file_identity_at(parent_fd: int, name: str) -> tuple[int, int]:
    info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise UnsafePathError("backup staging is not a single regular file")
    return int(info.st_dev), int(info.st_ino)


def _open_safe_directory(path: Path, label: str) -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise BackupError(f"{label} requires no-follow descriptor support")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | os.O_NOFOLLOW
    )
    absolute = Path(os.path.abspath(path))
    descriptor = -1
    try:
        descriptor = os.open(absolute.anchor or ".", flags)
        for component in absolute.parts[1:]:
            successor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = successor
        observed = os.fstat(descriptor)
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise UnsafePathError(f"{label} could not be opened safely") from exc
    if not stat.S_ISDIR(observed.st_mode):
        os.close(descriptor)
        raise UnsafePathError(f"{label} is not a real directory")
    return descriptor


def _open_archive_descriptor(path: Path) -> int:
    parent_fd = _open_safe_directory(path.parent, "archive parent")
    try:
        descriptor = os.open(
            path.name,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_fd,
        )
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink < 1:
            os.close(descriptor)
            raise BackupError("archive path must be a regular file")
        return descriptor
    finally:
        os.close(parent_fd)


def _open_relative_directory(
    root_fd: int,
    relative: str,
    *,
    create: bool,
    fault_injector: FaultInjector | None = None,
) -> int:
    """Open a confined directory chain without resolving pathnames."""

    relative = _safe_relative(relative, "relative directory")
    current_fd = os.dup(root_fd)
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        for component in relative.split("/"):
            try:
                successor = os.open(component, flags, dir_fd=current_fd)
            except FileNotFoundError:
                if not create:
                    raise
                _fault(fault_injector, "restore.write.directory")
                try:
                    os.mkdir(component, mode=0o700, dir_fd=current_fd)
                except FileExistsError:
                    pass
                successor = os.open(component, flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = successor
        return current_fd
    except Exception:
        os.close(current_fd)
        raise


def _open_relative_file(
    root_fd: int,
    relative: str,
    *,
    create_parents: bool = False,
    fault_injector: FaultInjector | None = None,
) -> tuple[int, str]:
    relative = _safe_relative(relative, "relative file")
    parts = relative.split("/")
    parent_fd = os.dup(root_fd)
    try:
        if len(parts) > 1:
            parent_fd = _replace_fd(
                parent_fd,
                _open_relative_directory(
                    root_fd,
                    "/".join(parts[:-1]),
                    create=create_parents,
                    fault_injector=fault_injector,
                ),
            )
        return parent_fd, parts[-1]
    except Exception:
        os.close(parent_fd)
        raise


def _replace_fd(old_fd: int, new_fd: int) -> int:
    os.close(old_fd)
    return new_fd


def _read_fd(fd: int) -> bytes:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_ARCHIVE_MANIFEST_BYTES:
        raise BackupError("restore identity file is unsafe or oversized")
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(fd, 64 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_ARCHIVE_MANIFEST_BYTES:
            raise BackupError("restore identity file is oversized")
        chunks.append(chunk)
    return b"".join(chunks)


def _write_fd(fd: int, data: bytes, mode: int) -> None:
    os.ftruncate(fd, 0)
    os.lseek(fd, 0, os.SEEK_SET)
    offset = 0
    while offset < len(data):
        offset += os.write(fd, data[offset:])
    os.fchmod(fd, mode)
    os.fsync(fd)


def write_recovery_marker(path: str | os.PathLike[str], payload: Mapping[str, Any]) -> None:
    """Best-effort durable marker for a publication whose parent sync is uncertain."""

    target = Path(path)
    marker_name = f".{target.name}.recovery.json"
    parent_fd = -1
    temporary_fd = -1
    temporary_name = f".{marker_name}.{secrets.token_hex(8)}.tmp"
    raw = (json.dumps(dict(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
    try:
        parent_fd = _open_safe_directory(target.parent, "recovery marker parent")
        temporary_fd = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=parent_fd,
        )
        offset = 0
        while offset < len(raw):
            offset += os.write(temporary_fd, raw[offset:])
        os.fsync(temporary_fd)
        try:
            _rename_noreplace(parent_fd, temporary_name, marker_name, "recovery marker")
        except BackupConflictError:
            return
        os.fsync(parent_fd)
    except (BackupError, OSError):
        return
    finally:
        if temporary_fd >= 0:
            os.close(temporary_fd)
        if parent_fd >= 0:
            try:
                os.unlink(temporary_name, dir_fd=parent_fd)
            except OSError:
                pass
            os.close(parent_fd)


def _create_restore_staging(
    parent: Path, target_name: str, *, parent_fd: int | None = None,
) -> tuple[Path, int, tuple[int, int]]:
    """Create and open a staging directory through its parent descriptor."""

    owned_parent_fd = parent_fd is None
    if parent_fd is None:
        parent_fd = _open_safe_directory(parent, "restore staging parent")
    try:
        for _attempt in range(128):
            name = f".{target_name}.restore-{secrets.token_hex(12)}"
            try:
                os.mkdir(name, mode=0o700, dir_fd=parent_fd)
            except FileExistsError:
                continue
            staging_fd = os.open(
                name,
                os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_fd,
            )
            try:
                os.fchmod(staging_fd, 0o700)
                os.fsync(staging_fd)
                info = os.fstat(staging_fd)
                return parent / name, staging_fd, (int(info.st_dev), int(info.st_ino))
            except Exception:
                os.close(staging_fd)
                raise
        raise BackupError("could not allocate a unique restore staging directory")
    finally:
        if owned_parent_fd:
            os.close(parent_fd)


def _open_directory_path(path: Path, label: str, *, create: bool) -> int:
    """Open/create an absolute directory path one no-follow component at a time."""

    absolute = Path(os.path.abspath(path))
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    current_fd = os.open(absolute.anchor or ".", flags)
    try:
        for component in absolute.parts[1:]:
            try:
                successor = os.open(component, flags, dir_fd=current_fd)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(component, mode=0o700, dir_fd=current_fd)
                successor = os.open(component, flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = successor
        return current_fd
    except Exception as exc:
        os.close(current_fd)
        raise UnsafePathError(f"{label} could not be opened safely") from exc


def _renameat2_noreplace(parent_fd: int, source_name: str, target_name: str) -> None:
    _rename_noreplace(parent_fd, source_name, target_name, "restore")


def _renameat2_noreplace_file(parent_fd: int, source_name: str, target_name: str) -> None:
    _rename_noreplace(parent_fd, source_name, target_name, "backup")


def _atomic_promote_new_directory(
    source: Path,
    target: Path,
    *,
    expected_source_identity: tuple[int, int],
    parent_fd: int | None = None,
    expected_parent_identity: tuple[int, int] | None = None,
) -> None:
    """Publish a completed restore only while target is still absent."""

    if source.parent != target.parent:
        raise BackupError("restore staging and target must share one parent directory")
    if source.name in {"", ".", ".."} or target.name in {"", ".", ".."}:
        raise BackupError("restore promotion names are invalid")
    if os.name == "nt":
        if _directory_identity(source) != expected_source_identity:
            raise BackupConflictError("restore staging was replaced before promotion")
        try:
            os.rename(source, target)
        except FileExistsError as exc:
            raise BackupConflictError("restore target appeared during restore") from exc
        if _directory_identity(target) != expected_source_identity:
            raise BackupConflictError("restore promotion identity changed")
        return

    owned_parent_fd = parent_fd is None
    if parent_fd is None:
        parent_fd = _open_safe_directory(source.parent, "restore target parent")
    try:
        parent_info = os.fstat(parent_fd)
        if (
            not stat.S_ISDIR(parent_info.st_mode)
            or expected_parent_identity is not None
            and (parent_info.st_dev, parent_info.st_ino) != expected_parent_identity
        ):
            raise BackupConflictError("restore target parent identity changed")
        if _directory_identity_at(parent_fd, source.name) != expected_source_identity:
            raise BackupConflictError("restore staging was replaced before promotion")
        _renameat2_noreplace(parent_fd, source.name, target.name)
        # The no-replace rename is not durable until the containing directory
        # itself is synced.  This is the commit point for the restored tree.
        os.fsync(parent_fd)
        try:
            target_identity = _directory_identity_at(parent_fd, target.name)
        except (OSError, UnsafePathError) as exc:
            raise BackupConflictError("restore promotion identity changed") from exc
        if target_identity != expected_source_identity:
            raise BackupConflictError("restore promotion identity changed")
        parent_info = os.fstat(parent_fd)
        if expected_parent_identity is not None and (parent_info.st_dev, parent_info.st_ino) != expected_parent_identity:
            raise BackupConflictError("restore target parent identity changed")
    finally:
        if owned_parent_fd:
            os.close(parent_fd)


def _file_inventory_fd(root_fd: int, prefix: str = "") -> dict[str, tuple[int, str, int]]:
    # Callers intentionally reuse confined directory descriptors across
    # extraction, inventory, reidentification, and durability checks.
    os.lseek(root_fd, 0, os.SEEK_SET)
    inventory: dict[str, tuple[int, str, int]] = {}
    with os.scandir(root_fd) as entries:
        for entry in sorted(entries, key=lambda item: item.name):
            relative = f"{prefix}/{entry.name}" if prefix else entry.name
            info = entry.stat(follow_symlinks=False)
            if entry.name == ".git" and stat.S_ISDIR(info.st_mode):
                continue
            if stat.S_ISLNK(info.st_mode):
                raise UnsafePathError(f"restore tree contains symlink {relative!r}")
            if stat.S_ISDIR(info.st_mode):
                child_fd = os.open(
                    entry.name,
                    os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=root_fd,
                )
                try:
                    inventory.update(_file_inventory_fd(child_fd, relative))
                finally:
                    os.close(child_fd)
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise UnsafePathError(f"restore tree contains an unsupported file {relative!r}")
            file_fd = os.open(
                entry.name,
                os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=root_fd,
            )
            try:
                data_digest = _sha256_fd(file_fd)
                current = os.fstat(file_fd)
                inventory[relative] = (int(current.st_size), data_digest, current.st_mode & 0o777)
            finally:
                os.close(file_fd)
    return inventory


def _fsync_tree_fd(root_fd: int) -> None:
    """Recursively sync restored files and directories through descriptors."""

    os.lseek(root_fd, 0, os.SEEK_SET)
    with os.scandir(root_fd) as entries:
        for entry in sorted(entries, key=lambda item: item.name):
            info = entry.stat(follow_symlinks=False)
            if entry.name == ".git" and stat.S_ISDIR(info.st_mode):
                continue
            if stat.S_ISLNK(info.st_mode):
                raise UnsafePathError(f"restore staging contains symlink {entry.name!r}")
            if stat.S_ISDIR(info.st_mode):
                child_fd = os.open(
                    entry.name,
                    os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=root_fd,
                )
                try:
                    _fsync_tree_fd(child_fd)
                finally:
                    os.close(child_fd)
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise UnsafePathError("restore staging contains an unsupported file")
            file_fd = os.open(
                entry.name,
                os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=root_fd,
            )
            try:
                current = os.fstat(file_fd)
                if (current.st_dev, current.st_ino, current.st_size) != (info.st_dev, info.st_ino, info.st_size):
                    raise BackupConflictError("restored file identity changed before fsync")
                os.fsync(file_fd)
            finally:
                os.close(file_fd)
    os.fsync(root_fd)


def _fsync_tree(root: Path) -> None:
    """Compatibility wrapper for descriptor-relative recursive syncing."""

    root_fd = _open_safe_directory(root, "restore staging directory")
    try:
        _fsync_tree_fd(root_fd)
    finally:
        os.close(root_fd)


def _sha256_fd(fd: int) -> str:
    position = os.lseek(fd, 0, os.SEEK_CUR)
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        hasher = hashlib.sha256()
        while chunk := os.read(fd, 1024 * 1024):
            hasher.update(chunk)
        return "sha256:" + hasher.hexdigest()
    finally:
        os.lseek(fd, position, os.SEEK_SET)


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _canonical_copy(value: Any) -> Any:
    """Return JSON-safe metadata while dropping machine-local path fields."""

    if isinstance(value, Mapping):
        copied = {
            str(key): _canonical_copy(item)
            for key, item in sorted(value.items(), key=lambda item: str(item[0]))
            if str(key).lower() not in {"checkoutlocation", "sourcepath", "localpath"}
        }
        if (
            copied.get("formatVersion") == "statedd.source/v1"
            and copied.get("kind") == "local"
        ):
            copied.pop("path", None)
        return copied
    if isinstance(value, (list, tuple)):
        return [_canonical_copy(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise BackupError(f"metadata contains unsupported value {type(value).__name__}")


def _yaml_scalar(value: str) -> Any:
    value = value.strip()
    if not value:
        return None
    if value.startswith("#"):
        return None
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    if value in {"[]", "[ ]"}:
        return []
    if value in {"{}", "{ }"}:
        return {}
    if value.lower() in {"null", "~"}:
        return None
    if value.lower() in {"true", "false"}:
        return value.lower() == "true"
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    # StateDD metadata intentionally uses conservative scalars.  Keeping
    # unfamiliar values as strings is safer than silently coercing YAML.
    return value


def _fallback_yaml(text: str) -> dict[str, Any]:
    """Small YAML subset fallback for package use outside the repo import path."""

    lines: list[tuple[int, str]] = []
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        lines.append((indent, raw[indent:]))

    def parse(index: int, indent: int) -> tuple[Any, int]:
        if index >= len(lines) or lines[index][0] < indent:
            return {}, index
        is_list = lines[index][0] == indent and lines[index][1].startswith("- ")
        output: Any = [] if is_list else {}
        while index < len(lines):
            current_indent, content = lines[index]
            if current_indent < indent:
                break
            if current_indent != indent:
                raise BackupError("unsupported YAML indentation in identity document")
            if is_list:
                if not content.startswith("- "):
                    break
                item = content[2:].strip()
                index += 1
                if not item:
                    value, index = parse(index, lines[index][0]) if index < len(lines) and lines[index][0] > indent else ({}, index)
                    output.append(value)
                    continue
                if ":" in item and not item.startswith(('"', "'")):
                    key, raw_value = item.split(":", 1)
                    item_map: dict[str, Any] = {key.strip(): _yaml_scalar(raw_value)} if raw_value.strip() else {key.strip(): {}}
                    if index < len(lines) and lines[index][0] > indent:
                        child, index = parse(index, lines[index][0])
                        if raw_value.strip():
                            if isinstance(child, dict):
                                item_map.update(child)
                            else:
                                raise BackupError("unsupported YAML sequence structure")
                        else:
                            item_map[key.strip()] = child
                    output.append(item_map)
                else:
                    output.append(_yaml_scalar(item))
                continue
            if content.startswith("-"):
                break
            if ":" not in content:
                raise BackupError("unsupported YAML mapping in identity document")
            key, raw_value = content.split(":", 1)
            key = key.strip()
            if not key:
                raise BackupError("empty YAML key in identity document")
            index += 1
            if raw_value.strip():
                output[key] = _yaml_scalar(raw_value)
            elif index < len(lines) and lines[index][0] > indent:
                output[key], index = parse(index, lines[index][0])
            else:
                output[key] = {}
        return output, index

    value, _ = parse(0, lines[0][0]) if lines else ({}, 0)
    if not isinstance(value, dict):
        raise BackupError("identity document must be a YAML mapping")
    return value


def _safe_relative(value: str, label: str = "path") -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_ARCHIVE_PATH_LENGTH
        or "\\" in value
        or "\x00" in value
    ):
        raise UnsafePathError(f"{label} must be a non-empty POSIX relative path")
    if value.startswith("/") or value.startswith("//"):
        raise UnsafePathError(f"{label} must not be absolute")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise UnsafePathError(f"{label} contains traversal or empty components")
    if posixpath.normpath(value) != value:
        raise UnsafePathError(f"{label} is not normalized")
    return value


def _safe_root(path: Path, label: str) -> Path:
    path = Path(path)
    if path.is_symlink():
        raise UnsafePathError(f"{label} must not be a symlink")
    if not path.is_dir():
        raise BackupError(f"{label} must be an existing directory")
    # Check every existing component so a later operation cannot escape via a
    # symlinked ancestor.
    current = path.anchor and Path(path.anchor) or Path(".")
    for part in path.parts[1:] if path.is_absolute() else path.parts:
        current = current / part
        if current.is_symlink():
            raise UnsafePathError(f"{label} has a symlinked component")
    return path


def _root_identity(path: Path) -> tuple[int, int]:
    try:
        observed = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise BackupConflictError("instance root identity could not be observed") from exc
    if stat.S_ISLNK(observed.st_mode) or not stat.S_ISDIR(observed.st_mode):
        raise BackupConflictError("instance root identity changed")
    return int(observed.st_dev), int(observed.st_ino)


def _safe_existing_parent(path: Path, label: str) -> None:
    """Reject symlinked ancestors before creating an archive or restore tree."""

    parent = path.parent
    current = parent.anchor and Path(parent.anchor) or Path(".")
    for part in parent.parts[1:] if parent.is_absolute() else parent.parts:
        current = current / part
        if current.is_symlink():
            raise UnsafePathError(f"{label} has a symlinked parent component")


def _safe_file(root: Path, relative: str) -> Path:
    relative = _safe_relative(relative)
    current = root
    for part in relative.split("/"):
        current = current / part
        if current.is_symlink():
            raise UnsafePathError(f"instance file {relative!r} is a symlink")
    resolved = current.resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise UnsafePathError(f"instance file {relative!r} escapes the instance")
    return current


def _read_source_file(path: Path, maximum_bytes: int, label: str) -> tuple[bytes, int]:
    parent_fd = -1
    descriptor = -1
    try:
        parent_fd = _open_safe_directory(path.parent, f"{label} parent")
        descriptor = os.open(
            path.name,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_fd,
        )
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink < 1:
            raise UnsafePathError(f"{label} is not a regular file")
        initial_identity = (
            int(info.st_dev), int(info.st_ino), int(info.st_size),
            info.st_mtime_ns, info.st_ctime_ns,
        )
        chunks: list[bytes] = []
        total = 0
        while total <= maximum_bytes:
            chunk = os.read(descriptor, min(64 * 1024, maximum_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        data = b"".join(chunks)
        if len(data) > maximum_bytes:
            raise BackupError(f"{label} exceeds the bounded backup limit")
        final = os.fstat(descriptor)
        observed = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        final_identity = (
            int(final.st_dev), int(final.st_ino), int(final.st_size),
            final.st_mtime_ns, final.st_ctime_ns,
        )
        observed_identity = (
            int(observed.st_dev), int(observed.st_ino), int(observed.st_size),
            observed.st_mtime_ns, observed.st_ctime_ns,
        )
        if (
            not stat.S_ISREG(observed.st_mode)
            or observed.st_nlink < 1
            or final_identity != initial_identity
            or observed_identity != initial_identity
            or len(data) != final.st_size
        ):
            raise BackupConflictError(f"{label} changed during read")
    except OSError as exc:
        raise BackupError(f"cannot read {label}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent_fd >= 0:
            os.close(parent_fd)
    return data, 0o700 if stat.S_IXUSR & final.st_mode else 0o600


def _read_bounded_file(path: Path, maximum_bytes: int, label: str) -> bytes:
    return _read_source_file(path, maximum_bytes, label)[0]


def _parse_document_bytes(data: bytes, path: Path) -> dict[str, Any]:
    try:
        raw = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BackupError(f"cannot read {path}: {exc}") from exc
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        try:
            from statedd_core.yaml import parse_yaml_text

            value = parse_yaml_text(raw)
        except Exception:
            value = _fallback_yaml(raw)
    if not isinstance(value, dict):
        raise BackupError(f"{path} must contain a mapping")
    return value


def _load_document_with_bytes(path: Path) -> tuple[dict[str, Any], bytes]:
    data = _read_bounded_file(path, MAX_ARCHIVE_MANIFEST_BYTES, path.name)
    return _parse_document_bytes(data, path), data


def _load_document(path: Path) -> dict[str, Any]:
    return _load_document_with_bytes(path)[0]


def _nested(document: Mapping[str, Any], *keys: str) -> Any:
    value: Any = document
    for key in keys:
        if not isinstance(value, Mapping):
            return None
        value = value.get(key)
    return value


def _identity(instance_root: Path, lock_path: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    instance_path = _safe_file(instance_root, "instance.yaml")
    try:
        lock_rel = lock_path.resolve().relative_to(instance_root.resolve()).as_posix()
    except ValueError:
        raise UnsafePathError("lock path must be inside the instance")
    lock_path = _safe_file(instance_root, lock_rel)
    if not instance_path.is_file() or not lock_path.is_file():
        raise BackupError("instance.yaml and .statedd/lock.yaml are required for a backup")
    instance_doc, _instance_bytes = _load_document_with_bytes(instance_path)
    lock_doc, lock_bytes = _load_document_with_bytes(lock_path)
    if _contains_secret_classification(instance_doc) or _contains_secret_classification(lock_doc):
        raise BackupError("instance identity contains secret-classified fields")
    instance_id = _nested(instance_doc, "metadata", "id") or instance_doc.get("instanceId") or instance_doc.get("id")
    lock_id = lock_doc.get("instanceId") or _nested(lock_doc, "instance", "id")
    if not isinstance(instance_id, str) or not instance_id.strip():
        raise BackupError("instance.yaml does not declare metadata.id")
    if not isinstance(lock_id, str) or not lock_id.strip():
        raise BackupError("lock.yaml does not declare instanceId")
    if instance_id != lock_id:
        raise BackupConflictError("instance.yaml and lock.yaml identify different instances")
    source = _nested(lock_doc, "template", "source") or lock_doc.get("source")
    if not isinstance(source, Mapping) or not source:
        raise BackupError("lock.yaml does not contain a source identity")
    source_identity = _canonical_copy(source)
    lock_identity = {
        "formatVersion": lock_doc.get("formatVersion", "unknown"),
        "instanceId": lock_id,
        "digest": _sha256(lock_bytes),
    }
    instance_identity = {"id": instance_id}
    name = _nested(instance_doc, "metadata", "name")
    if isinstance(name, str) and name:
        instance_identity["name"] = name
    return instance_identity, lock_identity, source_identity, lock_doc


def _ownership_from_documents(
    instance_root: Path,
    lock_path: Path,
    overrides: Mapping[str, Any] | None,
    *,
    lock_document: Mapping[str, Any] | None = None,
) -> dict[str, dict[str, str]]:
    lock_doc = dict(lock_document) if lock_document is not None else _load_document(lock_path)
    entries = lock_doc.get("files")
    if not isinstance(entries, list):
        entries = []
    result: dict[str, dict[str, str]] = {}
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise BackupError("lock file ownership entries must be mappings")
        path = _safe_relative(entry.get("path"), "ownership path")
        owner = entry.get("owner")
        sensitivity = entry.get("sensitivity", "private")
        if owner not in OWNERS:
            raise BackupError(f"unsupported owner {owner!r} for {path}")
        if sensitivity not in SENSITIVITIES:
            raise BackupError(f"unsupported sensitivity {sensitivity!r} for {path}")
        result[path] = {"owner": owner, "sensitivity": sensitivity}
    if overrides:
        for raw_path, raw_value in overrides.items():
            path = _safe_relative(raw_path, "ownership override path")
            if isinstance(raw_value, str):
                raw_value = {"owner": raw_value}
            if not isinstance(raw_value, Mapping):
                raise BackupError(f"ownership override for {path} must be a mapping or owner string")
            owner = raw_value.get("owner", "instance")
            sensitivity = raw_value.get("sensitivity", "private")
            if owner not in OWNERS or sensitivity not in SENSITIVITIES:
                raise BackupError(f"invalid ownership override for {path}")
            result[path] = {"owner": owner, "sensitivity": sensitivity}
    return result


def _classify(path: str, classifications: Mapping[str, dict[str, str]]) -> dict[str, str]:
    if path in classifications:
        return dict(classifications[path])
    matches = [key for key in classifications if key != path and path.startswith(key.rstrip("/") + "/")]
    if matches:
        return dict(classifications[max(matches, key=len)])
    if path == ".statedd/lock.yaml":
        return {"owner": "generated", "sensitivity": "internal"}
    if path == "instance.yaml":
        return {"owner": "instance", "sensitivity": "private"}
    # Unlisted content is conservatively treated as private instance state;
    # every file still receives an explicit classification in the manifest.
    return {"owner": "instance", "sensitivity": "private"}


def _looks_like_secret(path: str) -> bool:
    name = Path(path).name.lower()
    return (
        name == ".env"
        or name.startswith(".env.")
        or name in {
            "credentials.json",
            "credentials.yaml",
            "credentials.yml",
            "secrets.json",
            "secrets.yaml",
            "secrets.yml",
            "secret.json",
            "secret.yaml",
            "secret.yml",
        }
        or name.startswith(("credentials.", "secrets.", "secret."))
        or name.endswith((".pem", ".key"))
    )


def _contains_secret_classification(value: Any) -> bool:
    classification_keys = {"classification", "privacyclassification", "sensitivity", "sourceclassification"}
    sensitive_keys = {
        "access_token", "access_token_value", "api_key", "apikey", "client_secret",
        "credential", "credentials", "password", "private_key", "privatekey",
        "secret", "secrets", "token_value",
    }
    secret_values = {"secret", "secret-bearing", "sensitive"}
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if isinstance(key, str):
                normalized_key = key.casefold().replace("-", "_")
                if normalized_key in sensitive_keys and nested not in (None, False, ""):
                    return True
                if normalized_key in classification_keys:
                    if isinstance(nested, str) and nested.casefold() in secret_values:
                        return True
            if _contains_secret_classification(nested):
                return True
    elif isinstance(value, (list, tuple)):
        return any(_contains_secret_classification(item) for item in value)
    return False


@dataclass(frozen=True)
class FileRecord:
    path: str
    owner: str
    sensitivity: str
    sha256: str
    size: int
    mode: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "owner": self.owner,
            "sensitivity": self.sensitivity,
            "sha256": self.sha256,
            "size": self.size,
            "mode": self.mode,
        }


@dataclass(frozen=True)
class BackupResult:
    archive_path: Path
    archive_format: str
    manifest: dict[str, Any]
    archive_digest: str
    archive_file_digest: str


@dataclass(frozen=True)
class RestoreResult:
    archive_path: Path
    target_path: Path
    dry_run: bool
    identity_policy: str
    instance_id: str
    file_count: int
    archive_digest: str


def _inventory_digest(records: list[FileRecord]) -> str:
    payload = [record.to_dict() for record in records]
    return _sha256(_canonical_json(payload))


def _iter_files(
    root: Path,
    excluded: Path | None = None,
    excluded_prefixes: tuple[str, ...] = _EXCLUDED_INSTANCE_PREFIXES,
) -> Iterator[tuple[str, Path]]:
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if excluded is not None and path == excluded:
            continue
        if any(
            relative == prefix or relative.startswith(prefix + "/")
            for prefix in excluded_prefixes
        ):
            continue
        if path.is_symlink():
            raise UnsafePathError(f"instance contains symlink {relative!r}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise BackupError(f"instance contains unsupported special file {relative!r}")
        if _looks_like_secret(relative):
            raise BackupError(f"refusing secret-looking file {relative!r}; backups do not include secrets")
        _safe_file(root, relative)
        yield relative, path


def _inventory_exclusions(root: Path, prefixes: tuple[str, ...]) -> list[dict[str, Any]]:
    return [
        {
            "path": prefix,
            "reason": "execution_host_metadata" if prefix == ".git" else "transient_runtime_state",
            "present": (root / prefix).exists() or (root / prefix).is_symlink(),
        }
        for prefix in prefixes
    ]


def _normalized_mode(path: Path) -> int:
    parent_fd = _open_safe_directory(path.parent, "instance file parent")
    descriptor = -1
    try:
        descriptor = os.open(
            path.name,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_fd,
        )
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink < 1:
            raise UnsafePathError("instance file is not a regular file")
        return 0o700 if stat.S_IXUSR & info.st_mode else 0o600
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_fd)


def _archive_path(path: Path, label: str) -> None:
    if path.exists() and path.is_symlink():
        raise UnsafePathError(f"{label} must not be a symlink")
    _safe_existing_parent(path, label)


def _tar_info(name: str, *, mode: int, size: int, is_dir: bool = False) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE if is_dir else tarfile.REGTYPE
    info.mode = mode
    info.size = 0 if is_dir else size
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    return info


def _parent_dirs(paths: list[str]) -> list[str]:
    dirs: set[str] = {"files"}
    for path in paths:
        parts = path.split("/")
        for index in range(1, len(parts)):
            dirs.add("files/" + "/".join(parts[:index]))
    return sorted(dirs, key=lambda item: (item.count("/"), item))


def _write_tar(handle: BinaryIO, manifest_bytes: bytes, records: list[tuple[FileRecord, bytes]]) -> None:
    handle.seek(0)
    handle.truncate(0)
    with tarfile.open(fileobj=handle, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        archive.addfile(_tar_info(MANIFEST_NAME, mode=0o600, size=len(manifest_bytes)), io.BytesIO(manifest_bytes))
        for directory in _parent_dirs([record.path for record, _ in records]):
            archive.addfile(_tar_info(directory, mode=0o700, size=0, is_dir=True))
        for record, data in records:
            name = FILES_PREFIX + record.path
            archive.addfile(_tar_info(name, mode=record.mode, size=len(data)), io.BytesIO(data))


def _write_zip(handle: BinaryIO, manifest_bytes: bytes, records: list[tuple[FileRecord, bytes]]) -> None:
    handle.seek(0)
    handle.truncate(0)
    with zipfile.ZipFile(handle, mode="w", compression=zipfile.ZIP_STORED, strict_timestamps=True) as archive:
        def write(name: str, data: bytes, mode: int) -> None:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = mode << 16
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, data)

        write(MANIFEST_NAME, manifest_bytes, 0o600)
        for directory in _parent_dirs([record.path for record, _ in records]):
            write(directory + "/", b"", 0o700)
        for record, data in records:
            write(FILES_PREFIX + record.path, data, record.mode)


def _format_for(path: Path, archive_format: str | None) -> str:
    value = archive_format.lower() if archive_format else ("zip" if path.suffix.lower() == ".zip" else "tar")
    if value not in SUPPORTED_ARCHIVE_FORMATS:
        raise BackupError(f"archive format must be one of {sorted(SUPPORTED_ARCHIVE_FORMATS)}")
    return value


def create_backup(
    instance_root: str | os.PathLike[str],
    archive_path: str | os.PathLike[str],
    *,
    archive_format: str | None = None,
    ownership: Mapping[str, Any] | None = None,
    lock_path: str | os.PathLike[str] | None = None,
    excluded_prefixes: tuple[str, ...] = _EXCLUDED_INSTANCE_PREFIXES,
    file_projections: Mapping[str, bytes] | None = None,
    expected_root_identity: tuple[int, int] | None = None,
    fault_injector: FaultInjector | None = None,
) -> BackupResult:
    """Create a deterministic, restrictive, secret-free local backup."""

    root = _safe_root(Path(instance_root), "instance root")
    root_identity = _root_identity(root)
    if expected_root_identity is not None:
        if (
            not isinstance(expected_root_identity, tuple)
            or len(expected_root_identity) != 2
            or any(isinstance(value, bool) or not isinstance(value, int) for value in expected_root_identity)
        ):
            raise BackupError("expected instance root identity is invalid")
        if root_identity != expected_root_identity:
            raise BackupConflictError("instance root identity changed before backup")
    for prefix in excluded_prefixes:
        _safe_relative(prefix, "excluded inventory path")
    destination = Path(archive_path)
    _archive_path(destination, "archive path")
    if destination.resolve().is_relative_to(root.resolve()):
        raise UnsafePathError("archive path must be outside the instance root")
    if lock_path is None:
        lock = root / ".statedd" / "lock.yaml"
    else:
        lock = Path(lock_path)
    lock = _safe_file(root, lock.relative_to(root).as_posix())
    projections: dict[str, bytes] = {}
    for relative, data in (file_projections or {}).items():
        safe_relative = _safe_relative(relative, "projected file path")
        if not isinstance(data, bytes):
            raise BackupError("projected file content must be bytes")
        _safe_file(root, safe_relative)
        projections[safe_relative] = data
    instance_identity, lock_identity, source_identity, lock_document = _identity(root, lock)
    lock_relative = lock.relative_to(root).as_posix()
    projected_lock = projections.get(lock_relative)
    if projected_lock is not None:
        lock_document = _parse_document_bytes(projected_lock, lock)
        projected_instance_id = lock_document.get("instanceId") or _nested(
            lock_document, "instance", "id"
        )
        projected_source = _nested(lock_document, "template", "source") or lock_document.get("source")
        if projected_instance_id != instance_identity["id"] or not isinstance(projected_source, Mapping):
            raise BackupError("projected lock changed the instance or source identity shape")
        if _contains_secret_classification(lock_document):
            raise BackupError("projected lock contains secret-classified fields")
        lock_identity = {
            "formatVersion": lock_document.get("formatVersion", "unknown"),
            "instanceId": projected_instance_id,
            "digest": _sha256(projected_lock),
        }
        source_identity = _canonical_copy(projected_source)
    classifications = _ownership_from_documents(root, lock, ownership, lock_document=lock_document)
    excluded = destination if destination.parent == root else None
    records: list[FileRecord] = []
    payload: list[tuple[FileRecord, bytes]] = []
    total_bytes = 0
    for relative, path in _iter_files(root, excluded, excluded_prefixes):
        if len(records) >= MAX_BACKUP_FILES:
            raise BackupError("instance file count exceeds the bounded backup limit")
        data, source_mode = _read_source_file(path, MAX_ARCHIVE_FILE_BYTES, f"instance file {relative!r}")
        data = projections.get(relative, data)
        if len(data) > MAX_ARCHIVE_FILE_BYTES:
            raise BackupError(f"projected instance file exceeds the bounded limit: {relative!r}")
        if Path(relative).suffix.lower() in {".json", ".yaml", ".yml"}:
            try:
                source_document = _parse_document_bytes(data, path)
            except BackupError:
                source_document = None
            if source_document is not None and _contains_secret_classification(source_document):
                raise BackupError(f"instance metadata contains sensitive fields in {relative!r}")
        total_bytes += len(data)
        if total_bytes > MAX_ARCHIVE_MATERIALIZED_BYTES:
            raise BackupError("instance content exceeds the bounded backup limit")
        classification = _classify(relative, classifications)
        if classification["sensitivity"] == "secret":
            raise BackupError("backup manifest contains secret-class files")
        record = FileRecord(relative, classification["owner"], classification["sensitivity"], _sha256(data), len(data), source_mode)
        records.append(record)
        payload.append((record, data))
    records.sort(key=lambda item: item.path)
    payload.sort(key=lambda item: item[0].path)
    archive_member_count = 1 + len(_parent_dirs([record.path for record in records])) + len(records)
    if archive_member_count > MAX_ARCHIVE_MEMBERS:
        raise BackupError("instance archive member count exceeds the bounded backup limit")
    digest = _inventory_digest(records)
    manifest = {
        "formatVersion": BACKUP_FORMAT,
        "instance": instance_identity,
        "instanceId": instance_identity["id"],
        "lock": lock_identity,
        "sourceIdentity": source_identity,
        "ownership": [{"path": record.path, "owner": record.owner, "sensitivity": record.sensitivity} for record in records],
        "files": [record.to_dict() for record in records],
        "inventory": {
            "included": [record.to_dict() for record in records],
            "excluded": _inventory_exclusions(root, excluded_prefixes),
        },
        "archiveDigest": digest,
        "archive": {"format": _format_for(destination, archive_format), "digest": digest},
        "identityPolicy": "preserve",
    }
    manifest_bytes = _canonical_json(manifest)
    if len(manifest_bytes) > MAX_ARCHIVE_MANIFEST_BYTES:
        raise BackupError("backup manifest exceeds the bounded backup limit")
    if total_bytes + len(manifest_bytes) > MAX_ARCHIVE_MATERIALIZED_BYTES:
        raise BackupError("instance content exceeds the bounded backup limit")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        raise BackupConflictError("backup destination already exists; refusing to overwrite it")
    if not sys.platform.startswith("linux"):
        raise BackupError(
            "descriptor-anchored backup publication is available only in the qualified Linux path"
        )

    parent_fd = _open_safe_directory(destination.parent, "backup destination parent")
    archive_fd: int | None = None
    temp_name: str | None = None
    promoted = False
    archive_file_digest: str | None = None
    try:
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        for _attempt in range(128):
            candidate = f".{destination.name}.{secrets.token_hex(12)}.tmp"
            try:
                archive_fd = os.open(candidate, flags, 0o600, dir_fd=parent_fd)
            except FileExistsError:
                continue
            temp_name = candidate
            break
        if archive_fd is None or temp_name is None:
            raise BackupError("could not allocate a unique backup staging file")

        expected_identity = _regular_file_identity_fd(archive_fd)
        with os.fdopen(os.dup(archive_fd), "w+b") as handle:
            _fault(fault_injector, "backup.write.archive")
            if manifest["archive"]["format"] == "tar":
                _write_tar(handle, manifest_bytes, payload)
            else:
                _write_zip(handle, manifest_bytes, payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.fchmod(archive_fd, 0o600)
        os.fsync(archive_fd)

        if _regular_file_identity_fd(archive_fd) != expected_identity:
            raise BackupConflictError("backup staging identity changed during creation")
        try:
            staged_identity = _regular_file_identity_at(parent_fd, temp_name)
        except (OSError, UnsafePathError) as exc:
            raise BackupConflictError("backup staging name changed during creation") from exc
        if staged_identity != expected_identity:
            raise BackupConflictError("backup staging name changed during creation")
        if _root_identity(root) != root_identity:
            raise BackupConflictError("instance root identity changed during backup")

        _fault(fault_injector, "backup.rename.publish")
        _renameat2_noreplace_file(parent_fd, temp_name, destination.name)
        promoted = True
        try:
            published_identity = _regular_file_identity_at(parent_fd, destination.name)
        except (OSError, UnsafePathError) as exc:
            raise BackupConflictError("backup publication identity changed") from exc
        if published_identity != expected_identity:
            raise BackupConflictError("backup publication identity changed")
        try:
            public_identity = _regular_file_identity(destination)
        except (OSError, UnsafePathError) as exc:
            raise BackupConflictError("backup destination path changed after publication") from exc
        if public_identity != expected_identity:
            raise BackupConflictError("backup destination path changed after publication")
        archive_file_digest = _sha256_fd(archive_fd)
        try:
            os.fsync(parent_fd)
        except OSError as exc:
            write_recovery_marker(
                destination,
                {
                    "formatVersion": "stateport.backup-recovery/v1",
                    "status": "operator_inspection_required",
                    "archiveDigest": digest,
                    "archiveFileDigest": archive_file_digest,
                    "reason": "backup publication parent fsync failed",
                },
            )
            raise BackupError("backup publication requires operator inspection") from exc
    finally:
        if archive_fd is not None:
            if not promoted:
                # The path may have been rebound. Clear only the exact owned
                # inode through its descriptor and retain names for inspection.
                try:
                    os.ftruncate(archive_fd, 0)
                    os.fsync(archive_fd)
                except OSError:
                    pass
            os.close(archive_fd)
        os.close(parent_fd)
    if archive_file_digest is None:
        raise BackupError("backup publication did not produce an exact archive digest")
    return BackupResult(
        destination,
        manifest["archive"]["format"],
        manifest,
        digest,
        archive_file_digest,
    )


def _archive_members_from_descriptor(
    descriptor: int,
) -> tuple[dict[str, bytes], dict[str, Any], str]:
    if os.fstat(descriptor).st_size > MAX_ARCHIVE_CONTAINER_BYTES:
        raise BackupIntegrityError("archive container exceeds the bounded resource limit")
    stream = os.fdopen(os.dup(descriptor), "rb")
    try:
        if zipfile.is_zipfile(stream):
            stream.seek(0)
            members, manifest = _read_zip(stream)
        else:
            stream.seek(0)
            members, manifest = _read_tar(stream)
        stream.seek(0)
        digest = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
        return members, manifest, "sha256:" + digest.hexdigest()
    except (tarfile.TarError, zipfile.BadZipFile, OSError) as exc:
        raise BackupIntegrityError(f"cannot read archive safely: {exc}") from exc
    finally:
        stream.close()


def _archive_members(archive_path: Path) -> tuple[dict[str, bytes], dict[str, Any], str]:
    _archive_path(archive_path, "archive path")
    descriptor = _open_archive_descriptor(archive_path)
    try:
        return _archive_members_from_descriptor(descriptor)
    finally:
        os.close(descriptor)


def _manifest_from_bytes(data: bytes) -> dict[str, Any]:
    if len(data) > MAX_ARCHIVE_MANIFEST_BYTES:
        raise BackupIntegrityError("archive manifest exceeds the bounded resource limit")
    try:
        manifest = json.loads(data)
    except (RecursionError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupIntegrityError("manifest.json is not valid UTF-8 JSON") from exc
    if not isinstance(manifest, dict) or manifest.get("formatVersion") != BACKUP_FORMAT:
        raise BackupIntegrityError("unsupported or missing backup manifest version")
    required = {"instance", "instanceId", "lock", "sourceIdentity", "ownership", "files", "archiveDigest", "archive"}
    if not required.issubset(manifest):
        raise BackupIntegrityError("backup manifest is missing required identity or file fields")
    if _contains_secret_classification(manifest):
        raise BackupIntegrityError("backup manifest contains secret-classified fields")
    if not isinstance(manifest["files"], list) or not isinstance(manifest["ownership"], list):
        raise BackupIntegrityError("manifest files and ownership must be lists")
    if len(manifest["files"]) > MAX_BACKUP_FILES:
        raise BackupIntegrityError("archive file count exceeds the bounded resource limit")
    if manifest.get("instance", {}).get("id") != manifest.get("instanceId"):
        raise BackupIntegrityError("manifest instance identity is inconsistent")
    records: list[FileRecord] = []
    total_bytes = 0
    for raw in manifest["files"]:
        if not isinstance(raw, Mapping):
            raise BackupIntegrityError("manifest file record must be a mapping")
        path = _safe_relative(raw.get("path"), "manifest file path")
        owner = raw.get("owner")
        sensitivity = raw.get("sensitivity")
        digest = raw.get("sha256")
        size = raw.get("size")
        mode = raw.get("mode")
        if (
            owner not in OWNERS
            or sensitivity not in SENSITIVITIES
            or not isinstance(digest, str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
            or size > MAX_ARCHIVE_FILE_BYTES
            or mode not in {0o600, 0o700}
        ):
            raise BackupIntegrityError(f"invalid manifest file record for {path!r}")
        if _looks_like_secret(path):
            raise BackupIntegrityError(f"backup manifest contains secret-looking file {path!r}")
        total_bytes += size
        if total_bytes > MAX_ARCHIVE_MATERIALIZED_BYTES:
            raise BackupIntegrityError("archive payload exceeds the bounded resource limit")
        records.append(FileRecord(path, owner, sensitivity, digest, size, mode))
    if [record.path for record in records] != sorted({record.path for record in records}):
        raise BackupIntegrityError("manifest file paths must be unique and sorted")
    expected = _inventory_digest(records)
    if manifest.get("archiveDigest") != expected or manifest.get("archive", {}).get("digest") != expected:
        raise BackupIntegrityError("manifest archive digest does not match its file inventory")
    ownership = manifest.get("ownership")
    expected_ownership = [
        {"path": record.path, "owner": record.owner, "sensitivity": record.sensitivity}
        for record in records
    ]
    if ownership != expected_ownership:
        raise BackupIntegrityError("manifest ownership classification does not match file records")
    inventory = manifest.get("inventory")
    if inventory is not None:
        if not isinstance(inventory, Mapping) or not isinstance(inventory.get("included"), list) or not isinstance(inventory.get("excluded"), list):
            raise BackupIntegrityError("manifest durable-state inventory is invalid")
        included_paths = [item.get("path") for item in inventory["included"] if isinstance(item, Mapping)]
        if included_paths != [record.path for record in records]:
            raise BackupIntegrityError("manifest included inventory does not match file records")
        for excluded in inventory["excluded"]:
            if not isinstance(excluded, Mapping):
                raise BackupIntegrityError("manifest excluded inventory entry is invalid")
            _safe_relative(excluded.get("path"), "excluded inventory path")
            if not isinstance(excluded.get("reason"), str) or not isinstance(excluded.get("present"), bool):
                raise BackupIntegrityError("manifest excluded inventory entry is incomplete")
    return manifest


def _member_name(name: str, *, allow_manifest: bool = True) -> str:
    if (
        not isinstance(name, str)
        or not name
        or len(name) > len(FILES_PREFIX) + MAX_ARCHIVE_PATH_LENGTH
    ):
        raise UnsafePathError("archive member path exceeds the bounded resource limit")
    if name == MANIFEST_NAME and allow_manifest:
        return name
    if name.endswith("/"):
        name = name[:-1]
    if not name.startswith(FILES_PREFIX):
        raise UnsafePathError("archive member is outside its files namespace")
    return _safe_relative(name[len(FILES_PREFIX):], "archive member")


def _bounded_member_bytes(
    stream: Any,
    *,
    expected_size: int,
    maximum_size: int,
    label: str,
) -> bytes:
    """Read one declared member without trusting archive size metadata."""

    if (
        isinstance(expected_size, bool)
        or not isinstance(expected_size, int)
        or expected_size < 0
        or expected_size > maximum_size
    ):
        raise BackupIntegrityError(f"{label} exceeds the bounded resource limit")
    data = stream.read(expected_size + 1)
    if len(data) > expected_size:
        raise BackupIntegrityError(f"{label} exceeds its declared size")
    if len(data) < expected_size:
        raise BackupIntegrityError(f"{label} is truncated")
    return data


def _archive_member_budget(
    *,
    member_count: int,
    file_count: int,
    total_size: int,
    member_size: int,
    maximum_size: int,
    count_file: bool,
) -> tuple[int, int, int]:
    member_count += 1
    if member_count > MAX_ARCHIVE_MEMBERS:
        raise BackupIntegrityError("archive member count exceeds the bounded resource limit")
    if (
        isinstance(member_size, bool)
        or not isinstance(member_size, int)
        or member_size < 0
        or member_size > maximum_size
    ):
        raise BackupIntegrityError("archive member exceeds the bounded resource limit")
    if count_file:
        file_count += 1
        if file_count > MAX_BACKUP_FILES:
            raise BackupIntegrityError("archive file count exceeds the bounded resource limit")
    total_size += member_size
    if total_size > MAX_ARCHIVE_MATERIALIZED_BYTES:
        raise BackupIntegrityError("archive payload exceeds the bounded resource limit")
    return member_count, file_count, total_size


def _read_tar(stream: BinaryIO) -> tuple[dict[str, bytes], dict[str, Any]]:
    members: dict[str, bytes] = {}
    manifest_data: bytes | None = None
    member_count = file_count = total_size = 0
    with tarfile.open(fileobj=stream, mode="r:") as archive:
        for member in archive:
            if member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
                raise UnsafePathError("tar archive contains a symlink, link, or special file")
            if member.isdir():
                if member.name != "files" and not member.name.startswith(FILES_PREFIX):
                    raise UnsafePathError("tar directory is outside its namespace")
                _member_name(member.name + "/") if member.name != "files" else None
                member_count, file_count, total_size = _archive_member_budget(
                    member_count=member_count,
                    file_count=file_count,
                    total_size=total_size,
                    member_size=member.size,
                    maximum_size=0,
                    count_file=False,
                )
                continue
            name = _member_name(member.name)
            maximum_size = (
                MAX_ARCHIVE_MANIFEST_BYTES
                if name == MANIFEST_NAME
                else MAX_ARCHIVE_FILE_BYTES
            )
            member_count, file_count, total_size = _archive_member_budget(
                member_count=member_count,
                file_count=file_count,
                total_size=total_size,
                member_size=member.size,
                maximum_size=maximum_size,
                count_file=name != MANIFEST_NAME,
            )
            if name == MANIFEST_NAME:
                if manifest_data is not None:
                    raise BackupIntegrityError("archive contains duplicate manifest")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise BackupIntegrityError("manifest cannot be read")
                manifest_data = _bounded_member_bytes(
                    extracted,
                    expected_size=member.size,
                    maximum_size=maximum_size,
                    label="archive manifest",
                )
            else:
                if name in members:
                    raise BackupIntegrityError(f"archive contains duplicate file {name!r}")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise BackupIntegrityError(f"archive member {name!r} cannot be read")
                members[name] = _bounded_member_bytes(
                    extracted,
                    expected_size=member.size,
                    maximum_size=maximum_size,
                    label=f"archive member {name!r}",
                )
    if manifest_data is None:
        raise BackupIntegrityError("archive has no manifest.json")
    return members, _manifest_from_bytes(manifest_data)


def _read_zip(stream: BinaryIO) -> tuple[dict[str, bytes], dict[str, Any]]:
    members: dict[str, bytes] = {}
    manifest_data: bytes | None = None
    member_count = file_count = total_size = 0
    with zipfile.ZipFile(stream, mode="r") as archive:
        for info in archive.infolist():
            mode = (info.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                raise UnsafePathError("zip archive contains a symlink")
            if info.flag_bits & 0x1:
                raise BackupIntegrityError("encrypted zip archive members are unsupported")
            if info.is_dir():
                if info.filename != "files/" and not info.filename.startswith(FILES_PREFIX):
                    raise UnsafePathError("zip directory is outside its namespace")
                if info.filename != "files/":
                    _member_name(info.filename)
                member_count, file_count, total_size = _archive_member_budget(
                    member_count=member_count,
                    file_count=file_count,
                    total_size=total_size,
                    member_size=info.file_size,
                    maximum_size=0,
                    count_file=False,
                )
                continue
            name = _member_name(info.filename)
            maximum_size = (
                MAX_ARCHIVE_MANIFEST_BYTES
                if name == MANIFEST_NAME
                else MAX_ARCHIVE_FILE_BYTES
            )
            member_count, file_count, total_size = _archive_member_budget(
                member_count=member_count,
                file_count=file_count,
                total_size=total_size,
                member_size=info.file_size,
                maximum_size=maximum_size,
                count_file=name != MANIFEST_NAME,
            )
            with archive.open(info, mode="r") as stream:
                data = _bounded_member_bytes(
                    stream,
                    expected_size=info.file_size,
                    maximum_size=maximum_size,
                    label=(
                        "archive manifest"
                        if name == MANIFEST_NAME
                        else f"archive member {name!r}"
                    ),
                )
            if name == MANIFEST_NAME:
                if manifest_data is not None:
                    raise BackupIntegrityError("archive contains duplicate manifest")
                manifest_data = data
            else:
                if name in members:
                    raise BackupIntegrityError(f"archive contains duplicate file {name!r}")
                members[name] = data
    if manifest_data is None:
        raise BackupIntegrityError("archive has no manifest.json")
    return members, _manifest_from_bytes(manifest_data)


def _validate_payload(members: Mapping[str, bytes], manifest: Mapping[str, Any]) -> list[FileRecord]:
    records = [FileRecord(item["path"], item["owner"], item["sensitivity"], item["sha256"], item["size"], item["mode"]) for item in manifest["files"]]
    if any(record.sensitivity == "secret" for record in records):
        raise BackupIntegrityError("backup manifest contains secret-class files")
    expected = {record.path: record for record in records}
    if set(members) != set(expected):
        raise BackupIntegrityError("archive payload does not exactly match the manifest")
    for path, record in expected.items():
        if _looks_like_secret(path):
            raise BackupIntegrityError(f"archive payload contains secret-looking file {path!r}")
        data = members[path]
        if len(data) != record.size or _sha256(data) != record.sha256:
            raise BackupIntegrityError(f"archive content hash mismatch for {path!r}")
    return records


def read_manifest(archive_path: str | os.PathLike[str]) -> dict[str, Any]:
    """Validate an archive without creating or modifying any filesystem path."""

    members, manifest, _archive_file_digest = _archive_members(Path(archive_path))
    _validate_payload(members, manifest)
    return manifest


def read_manifest_with_file_digest(
    archive_path: str | os.PathLike[str],
) -> tuple[dict[str, Any], str]:
    """Read and validate one archive through a no-follow file descriptor."""

    path = Path(archive_path)
    _archive_path(path, "archive path")
    descriptor = _open_archive_descriptor(path)
    try:
        members, manifest, archive_file_digest = _archive_members_from_descriptor(descriptor)
        _validate_payload(members, manifest)
        return manifest, archive_file_digest
    finally:
        os.close(descriptor)


def restore_staging_retained(target_path: str | os.PathLike[str]) -> bool:
    """Report path-free restore staging residue, failing safe on uncertainty.

    Restore failures deliberately retain staging rather than recursively
    deleting a pathname that a same-user process may have replaced.  Product
    callers need the resulting operator-inspection signal, but must not expose
    the host path.  Any matching entry, unsafe parent, or failed inventory is
    therefore reported as retained.
    """

    target = Path(target_path)
    parent = target.parent
    prefix = f".{target.name}.restore-"
    if not target.name or target.name in {".", ".."}:
        return True
    try:
        _safe_existing_parent(target, "restore staging target")
    except BackupError:
        return True
    try:
        parent_info = os.lstat(parent)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
        return True
    parent_fd = -1
    try:
        parent_fd = _open_safe_directory(parent, "restore staging parent")
        with os.scandir(parent_fd) as entries:
            return any(entry.name.startswith(prefix) for entry in entries)
    except (BackupError, OSError):
        return True
    finally:
        if parent_fd >= 0:
            os.close(parent_fd)


def _rewrite_identity_text(path_name: str, text: str, old_id: str, new_id: str) -> bytes:
    """Produce the exact staged bytes used for identity re-identification."""

    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        document = None
    if isinstance(document, dict):
        if path_name == "instance.yaml":
            metadata = document.get("metadata")
            if isinstance(metadata, dict) and metadata.get("id") == old_id:
                metadata["id"] = new_id
        if path_name == ".statedd/lock.yaml" and document.get("instanceId") == old_id:
            document["instanceId"] = new_id
        return _canonical_json(document)

    lines = text.splitlines(keepends=True)
    changed = False
    if path_name == "instance.yaml":
        in_metadata = False
        metadata_indent = -1
        for index, line in enumerate(lines):
            stripped = line.lstrip(" ")
            indent = len(line) - len(stripped)
            if stripped.startswith("metadata:"):
                in_metadata, metadata_indent = True, indent
            elif in_metadata and indent <= metadata_indent and stripped and not stripped.startswith("#"):
                in_metadata = False
            identity_match = re.match(
                rf"^(\s+id:\s*)(['\"]?){re.escape(old_id)}\2\s*(?:#.*)?(?:\n)?$",
                line,
            )
            if in_metadata and identity_match:
                newline = "\n" if line.endswith("\n") else ""
                lines[index] = line[: len(line) - len(stripped)] + f"id: {json.dumps(new_id)}" + newline
                changed = True
    elif path_name == ".statedd/lock.yaml":
        for index, line in enumerate(lines):
            identity_match = re.match(
                rf"^(\s*instanceId:\s*)(['\"]?){re.escape(old_id)}\2\s*(?:#.*)?(?:\n)?$",
                line,
            )
            if identity_match:
                newline = "\n" if line.endswith("\n") else ""
                indent = line[: len(line) - len(line.lstrip(" "))]
                lines[index] = indent + f"instanceId: {json.dumps(new_id)}" + newline
                changed = True
    if not changed:
        raise BackupError(f"cannot safely reidentify {path_name}")
    return "".join(lines).encode("utf-8")


def verify_restored_target(
    archive_path: str | os.PathLike[str],
    target_path: str | os.PathLike[str],
    *,
    identity_policy: str = "preserve",
    new_instance_id: str | None = None,
    expected_archive_file_digest: str | None = None,
) -> str:
    """Verify every published non-host file against the archive inventory."""

    members, manifest, actual_archive_file_digest = _archive_members(Path(archive_path))
    if expected_archive_file_digest is not None and actual_archive_file_digest != expected_archive_file_digest:
        raise BackupIntegrityError("opened verification archive does not match its bound file digest")
    records = _validate_payload(members, manifest)
    if identity_policy not in {"preserve", "reidentify"}:
        raise BackupError("identity_policy must be 'preserve' or 'reidentify'")
    if identity_policy == "reidentify" and (not isinstance(new_instance_id, str) or not new_instance_id.strip()):
        raise BackupError("reidentify verification requires a non-empty new_instance_id")
    root_fd = _open_safe_directory(Path(target_path), "restored target")
    try:
        actual = _file_inventory_fd(root_fd)
        expected: dict[str, tuple[int, str, int]] = {}
        for record in records:
            data = members[record.path]
            if identity_policy == "reidentify" and record.path in {"instance.yaml", ".statedd/lock.yaml"}:
                data = _rewrite_identity_text(
                    record.path,
                    data.decode("utf-8"),
                    str(manifest["instanceId"]),
                    str(new_instance_id),
                )
            expected[record.path] = (len(data), _sha256(data), record.mode)
        if actual != expected:
            raise BackupIntegrityError("restored target content does not match the archive")
    finally:
        os.close(root_fd)
    return str(manifest["archiveDigest"])


def restore_backup(
    archive_path: str | os.PathLike[str],
    target_path: str | os.PathLike[str],
    *,
    dry_run: bool = False,
    identity_policy: str = "preserve",
    new_instance_id: str | None = None,
    fault_injector: FaultInjector | None = None,
    expected_archive_file_digest: str | None = None,
) -> RestoreResult:
    """Validate and atomically restore an archive into a new path.

    ``preserve`` retains the backed-up identity.  ``reidentify`` is explicit,
    requires ``new_instance_id``, and rewrites only identity fields in the
    instance and lock documents after extraction.  It is intentionally not a
    silent default because it changes the lifecycle identity.
    """

    archive = Path(archive_path)
    members, manifest, actual_archive_file_digest = _archive_members(archive)
    if expected_archive_file_digest is not None and actual_archive_file_digest != expected_archive_file_digest:
        raise BackupIntegrityError("opened restore archive does not match its bound file digest")
    records = _validate_payload(members, manifest)
    target = Path(target_path)
    if identity_policy not in {"preserve", "reidentify"}:
        raise BackupError("identity_policy must be 'preserve' or 'reidentify'")
    if identity_policy == "reidentify" and (not isinstance(new_instance_id, str) or not new_instance_id.strip()):
        raise BackupError("reidentify policy requires a non-empty new_instance_id")
    if target.exists() or target.is_symlink():
        if target.is_symlink():
            raise BackupConflictError("restore target is a symlink")
        raise BackupConflictError("restore target already exists; refusing to overwrite an unrelated path")
    if target.parent.exists() and target.parent.is_symlink():
        raise UnsafePathError("restore target parent is a symlink")
    _safe_existing_parent(target, "restore target")
    if dry_run:
        return RestoreResult(archive, target, True, identity_policy, new_instance_id or manifest["instanceId"], len(records), manifest["archiveDigest"])
    temp_path: Path | None = None
    temp_identity: tuple[int, int] | None = None
    staging_fd = -1
    target_parent_fd = -1
    try:
        target_parent_fd = _open_directory_path(target.parent, "restore target parent", create=True)
        parent_info = os.fstat(target_parent_fd)
        parent_identity = (int(parent_info.st_dev), int(parent_info.st_ino))
        temp_path, staging_fd, temp_identity = _create_restore_staging(
            target.parent, target.name, parent_fd=target_parent_fd,
        )
        for record in records:
            parent_fd, filename = _open_relative_file(
                staging_fd,
                record.path,
                create_parents=True,
                fault_injector=fault_injector,
            )
            file_fd = -1
            try:
                file_fd = os.open(
                    filename,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | os.O_CLOEXEC
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=parent_fd,
                )
                info = os.fstat(file_fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise UnsafePathError(f"restore file {record.path!r} is unsafe")
                _fault(fault_injector, "restore.write.file")
                offset = 0
                data = members[record.path]
                while offset < len(data):
                    offset += os.write(file_fd, data[offset:])
                os.fchmod(file_fd, record.mode)
                os.fsync(file_fd)
            finally:
                if file_fd >= 0:
                    os.close(file_fd)
                os.close(parent_fd)
        actual = _file_inventory_fd(staging_fd)
        expected = {record.path: (record.size, record.sha256, record.mode) for record in records}
        if actual != expected:
            raise BackupIntegrityError("restore staging content changed during extraction")
        if identity_policy == "reidentify":
            _reidentify(
                temp_path,
                manifest["instanceId"],
                new_instance_id or "",
                root_fd=staging_fd,
                expected_files=members,
                fault_injector=fault_injector,
            )
        _fault(fault_injector, "restore.verify.staging")
        _fsync_tree_fd(staging_fd)
        os.close(staging_fd)
        staging_fd = -1
        _fault(fault_injector, "restore.rename.publish")
        _atomic_promote_new_directory(
            temp_path,
            target,
            expected_source_identity=temp_identity,
            parent_fd=target_parent_fd,
            expected_parent_identity=parent_identity,
        )
        if _directory_identity_at(target_parent_fd, target.name) != temp_identity:
            raise BackupConflictError("restore target changed after promotion")
        temp_path = None
    finally:
        # A failed staging pathname can be replaced by another same-user
        # process. Retain it for recovery rather than recursively deleting a
        # path whose identity is no longer owned by this operation.
        if staging_fd >= 0:
            os.close(staging_fd)
        if target_parent_fd >= 0:
            os.close(target_parent_fd)
    return RestoreResult(archive, target, False, identity_policy, new_instance_id or manifest["instanceId"], len(records), manifest["archiveDigest"])


def _reidentify(
    root: Path,
    old_id: str,
    new_id: str,
    *,
    root_fd: int,
    expected_files: Mapping[str, bytes],
    fault_injector: FaultInjector | None = None,
) -> None:
    """Change identity fields through descriptor-relative no-follow handles."""

    _ = root
    for relative in ("instance.yaml", ".statedd/lock.yaml"):
        parent_fd, filename = _open_relative_file(root_fd, relative)
        file_fd = -1
        try:
            file_fd = os.open(
                filename,
                os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_fd,
            )
            original = _read_fd(file_fd)
            expected = expected_files.get(relative)
            if expected is not None and original != expected:
                raise BackupConflictError(f"restore identity file {relative!r} changed during extraction")
            rewritten = _rewrite_identity_text(
                relative,
                original.decode("utf-8"),
                old_id,
                new_id,
            )
            _fault(fault_injector, "restore.write.identity")
            _write_fd(file_fd, rewritten, 0o600)
        finally:
            if file_fd >= 0:
                os.close(file_fd)
            os.close(parent_fd)


__all__ = [
    "BACKUP_FORMAT",
    "MAX_ARCHIVE_CONTAINER_BYTES",
    "MAX_ARCHIVE_FILE_BYTES",
    "MAX_ARCHIVE_MANIFEST_BYTES",
    "MAX_ARCHIVE_MATERIALIZED_BYTES",
    "MAX_ARCHIVE_MEMBERS",
    "MAX_ARCHIVE_PATH_LENGTH",
    "MAX_BACKUP_FILES",
    "BackupConflictError",
    "BackupError",
    "BackupIntegrityError",
    "CrashInjected",
    "BackupResult",
    "RestoreResult",
    "UnsafePathError",
    "create_backup",
    "read_manifest",
    "read_manifest_with_file_digest",
    "remove_owned_directory",
    "restore_backup",
    "restore_staging_retained",
    "verify_restored_target",
    "write_recovery_marker",
]
