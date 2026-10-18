"""Fail-closed filesystem primitives for local release evidence.

Release evidence is written outside the repository through create-only files
under one operator-selected 0700 root.  Directory traversal is performed with
``openat``-style ``dir_fd`` operations, and every final file is opened with
``O_NOFOLLOW`` and checked with ``fstat`` before it is trusted.  This keeps a
path lookup race from turning release evidence into an overwrite primitive.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
from typing import Any, Mapping, Sequence


class ReleaseIOError(ValueError):
    pass


_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
_FILE_READ_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW


def _validate_path_text(value: str, *, kind: str) -> None:
    if not value or "\x00" in value or "\\" in value:
        raise ReleaseIOError(f"{kind} contains an unsafe path character")


def _relative_parts(relative: str) -> tuple[str, ...]:
    _validate_path_text(relative, kind="release evidence path")
    if relative.startswith("/"):
        raise ReleaseIOError(f"unsafe release evidence path: {relative!r}")
    parts = tuple(relative.split("/"))
    if any(part in {"", ".", ".."} for part in parts):
        raise ReleaseIOError(f"unsafe release evidence path: {relative!r}")
    return parts


def _absolute_parts(path: Path) -> tuple[str, ...]:
    value = os.fspath(path)
    _validate_path_text(value, kind="absolute release path")
    if not path.is_absolute():
        raise ReleaseIOError("release output paths must be absolute")
    return tuple(part for part in path.parts if part != path.anchor)


def _verify_directory_descriptor(
    descriptor: int, *, private: bool, description: str
) -> os.stat_result:
    observed = os.fstat(descriptor)
    if not stat.S_ISDIR(observed.st_mode):
        raise ReleaseIOError(f"{description} is not a directory")
    if private and stat.S_IMODE(observed.st_mode) & 0o077:
        raise ReleaseIOError(f"{description} must not be group- or world-accessible")
    return observed


def _open_absolute_directory(
    path: Path, *, create_missing: bool = False, private_final: bool = False
) -> int:
    parts = _absolute_parts(path)
    descriptor = os.open(path.anchor, _DIRECTORY_FLAGS)
    try:
        for position, part in enumerate(parts):
            try:
                child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            except FileNotFoundError:
                if not create_missing:
                    raise ReleaseIOError(f"release directory is unavailable: {path}") from None
                os.mkdir(part, mode=0o700, dir_fd=descriptor)
                os.fsync(descriptor)
                child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            _verify_directory_descriptor(
                descriptor,
                private=private_final and position == len(parts) - 1,
                description="release directory",
            )
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _walk_private_directories(root_descriptor: int, parts: Sequence[str], *, create: bool) -> int:
    descriptor = os.dup(root_descriptor)
    try:
        for part in parts:
            try:
                child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise ReleaseIOError(
                        f"release directory component is unavailable: {part}"
                    ) from None
                os.mkdir(part, mode=0o700, dir_fd=descriptor)
                os.fsync(descriptor)
                child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            _verify_directory_descriptor(
                child, private=True, description="release evidence directory"
            )
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _root_descriptor(root: Path) -> tuple[Path, int]:
    root_input = root.expanduser()
    descriptor = _open_absolute_directory(root_input, private_final=True)
    try:
        observed = _verify_directory_descriptor(
            descriptor, private=True, description="release output root"
        )
        resolved = root_input.resolve(strict=True)
        if resolved.is_symlink() or not stat.S_ISDIR(observed.st_mode):
            raise ReleaseIOError("release output root is unsafe")
        return resolved, descriptor
    except BaseException:
        os.close(descriptor)
        raise


def prepare_output_root(path: Path, *, repository: Path) -> Path:
    repository_root = repository.resolve(strict=True)
    candidate = path.expanduser()
    _absolute_parts(candidate)
    if candidate in {Path("/"), Path.home(), repository_root}:
        raise ReleaseIOError("release output root is too broad")

    parent_descriptor = _open_absolute_directory(candidate.parent, create_missing=True)
    try:
        parent = candidate.parent.resolve(strict=True)
        exact_candidate = parent / candidate.name
        if exact_candidate == repository_root or repository_root in exact_candidate.parents:
            raise ReleaseIOError("release evidence must remain outside the repository")
        try:
            os.stat(candidate.name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ReleaseIOError("release output root must be a new directory")
        os.mkdir(candidate.name, mode=0o700, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
        created = os.open(candidate.name, _DIRECTORY_FLAGS, dir_fd=parent_descriptor)
        try:
            _verify_directory_descriptor(created, private=True, description="release output root")
            os.fsync(created)
        finally:
            os.close(created)
    finally:
        os.close(parent_descriptor)
    return exact_candidate


def open_existing_output_root(path: Path, *, repository: Path) -> Path:
    """Validate an existing private evidence root for an explicit resume."""
    repository_root = repository.resolve(strict=True)
    candidate = path.expanduser()
    _absolute_parts(candidate)
    resolved, descriptor = _root_descriptor(candidate)
    try:
        if resolved in {Path("/"), Path.home(), repository_root}:
            raise ReleaseIOError("release output root is too broad")
        if resolved == repository_root or repository_root in resolved.parents:
            raise ReleaseIOError("release evidence must remain outside the repository")
        return resolved
    finally:
        os.close(descriptor)


def safe_path(root: Path, relative: str) -> Path:
    """Return a lexical child after proving the private root and existing parents.

    This helper is appropriate when an external process needs a pathname.  The
    0700 root prevents another user from swapping descendants.  StatePort's own
    writers use the stronger descriptor-relative primitives below.
    """

    parts = _relative_parts(relative)
    resolved_root, descriptor = _root_descriptor(root)
    try:
        current = descriptor
        for part in parts[:-1]:
            try:
                child = os.open(part, _DIRECTORY_FLAGS, dir_fd=current)
            except FileNotFoundError:
                break
            _verify_directory_descriptor(
                child, private=True, description="release evidence directory"
            )
            if current != descriptor:
                os.close(current)
            current = child
        if current != descriptor:
            os.close(current)
    finally:
        os.close(descriptor)
    return resolved_root.joinpath(*parts)


def write_bytes_create_only(root: Path, relative: str, content: bytes) -> Path:
    parts = _relative_parts(relative)
    resolved_root, root_descriptor = _root_descriptor(root)
    parent_descriptor: int | None = None
    file_descriptor: int | None = None
    try:
        parent_descriptor = _walk_private_directories(root_descriptor, parts[:-1], create=True)
        file_descriptor = os.open(
            parts[-1],
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent_descriptor,
        )
        observed = os.fstat(file_descriptor)
        if not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1:
            raise ReleaseIOError("create-only release output is not a singly linked regular file")
        view = memoryview(content)
        while view:
            written = os.write(file_descriptor, view)
            if written <= 0:
                raise ReleaseIOError("create-only release write made no progress")
            view = view[written:]
        os.fsync(file_descriptor)
        final = os.fstat(file_descriptor)
        if (final.st_dev, final.st_ino, final.st_nlink, final.st_size) != (
            observed.st_dev,
            observed.st_ino,
            1,
            len(content),
        ):
            raise ReleaseIOError("create-only release output identity changed during write")
        os.close(file_descriptor)
        file_descriptor = None
        os.fsync(parent_descriptor)
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)
        os.close(root_descriptor)
    return resolved_root.joinpath(*parts)


def write_json_create_only(root: Path, relative: str, value: Any) -> Path:
    content = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return write_bytes_create_only(root, relative, (content + "\n").encode("utf-8"))


def remove_file_exact(root: Path, relative: str) -> None:
    """Remove one singly linked file from a private evidence root."""
    parts = _relative_parts(relative)
    resolved_root, root_descriptor = _root_descriptor(root)
    del resolved_root
    if len(parts) != 1:
        os.close(root_descriptor)
        raise ReleaseIOError("file cleanup is limited to one exact output-root child")
    descriptor: int | None = None
    try:
        observed = os.stat(parts[0], dir_fd=root_descriptor, follow_symlinks=False)
        if not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1:
            raise ReleaseIOError(f"cleanup target is not a singly linked regular file: {parts[0]}")
        descriptor = os.open(parts[0], _FILE_READ_FLAGS, dir_fd=root_descriptor)
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_nlink) != (
            observed.st_dev,
            observed.st_ino,
            1,
        ):
            raise ReleaseIOError(f"cleanup target is not a singly linked regular file: {parts[0]}")
        os.unlink(parts[0], dir_fd=root_descriptor)
        os.fsync(root_descriptor)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(root_descriptor)


def _open_regular_file(path: Path) -> tuple[int, os.stat_result]:
    if path.is_symlink():
        raise ReleaseIOError(f"release input is not a regular file: {path}")
    parent_descriptor = _open_absolute_directory(path.absolute().parent)
    try:
        descriptor = os.open(path.name, _FILE_READ_FLAGS, dir_fd=parent_descriptor)
    except BaseException:
        os.close(parent_descriptor)
        raise
    os.close(parent_descriptor)
    observed = os.fstat(descriptor)
    if not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1:
        os.close(descriptor)
        raise ReleaseIOError(f"release input is not a singly linked regular file: {path}")
    return descriptor, observed


def sha256_file(path: Path) -> str:
    descriptor, before = _open_regular_file(path)
    digest = hashlib.sha256()
    try:
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_nlink")
        if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
            raise ReleaseIOError(f"release input changed while hashing: {path}")
    finally:
        os.close(descriptor)
    return "sha256:" + digest.hexdigest()


def directory_identity(path: Path) -> dict[str, int | str]:
    resolved, descriptor = _root_descriptor(path)
    try:
        observed = os.fstat(descriptor)
        return {
            "path": str(resolved),
            "device": observed.st_dev,
            "inode": observed.st_ino,
            "mode": format(stat.S_IMODE(observed.st_mode), "04o"),
        }
    finally:
        os.close(descriptor)


def remove_tree_exact(root: Path, relative: str, *, expected_identity: Mapping[str, Any]) -> None:
    """Remove one exact task-owned directory after identity revalidation."""

    if not shutil.rmtree.avoids_symlink_attacks:
        raise ReleaseIOError("platform does not provide symlink-safe recursive removal")
    parts = _relative_parts(relative)
    if len(parts) != 1:
        raise ReleaseIOError("recursive cleanup is limited to one exact output-root child")
    resolved_root, root_descriptor = _root_descriptor(root)
    del resolved_root
    child_descriptor: int | None = None
    try:
        child_descriptor = os.open(parts[0], _DIRECTORY_FLAGS, dir_fd=root_descriptor)
        observed = _verify_directory_descriptor(
            child_descriptor, private=True, description="cleanup target"
        )
        expected = (
            int(expected_identity.get("device", -1)),
            int(expected_identity.get("inode", -1)),
            str(expected_identity.get("mode", "")),
        )
        actual = (
            observed.st_dev,
            observed.st_ino,
            format(stat.S_IMODE(observed.st_mode), "04o"),
        )
        if actual != expected:
            raise ReleaseIOError("cleanup target identity changed")
        os.close(child_descriptor)
        child_descriptor = None
        shutil.rmtree(parts[0], dir_fd=root_descriptor)
        os.fsync(root_descriptor)
        try:
            os.stat(parts[0], dir_fd=root_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise ReleaseIOError("cleanup target remained after recursive removal")
    finally:
        if child_descriptor is not None:
            os.close(child_descriptor)
        os.close(root_descriptor)
