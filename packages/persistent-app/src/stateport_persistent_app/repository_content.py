from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
from time import monotonic


CONTENT_IDENTITY_FORMAT = "stateport.repository-content-identity/v1"
DEFAULT_MAXIMUM_FILE_COUNT = 50_000
DEFAULT_MAXIMUM_TOTAL_BYTES = 512 * 1024 * 1024
DEFAULT_MAXIMUM_PATH_LENGTH = 512
DEFAULT_TIMEOUT_SECONDS = 8.0


class RepositoryContentError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True)
class RepositoryContentSnapshot:
    identity: dict[str, object]
    lfs_pointers_detected: bool


def repository_content_snapshot(
    root: Path,
    *,
    maximum_file_count: int = DEFAULT_MAXIMUM_FILE_COUNT,
    maximum_total_bytes: int = DEFAULT_MAXIMUM_TOTAL_BYTES,
    maximum_path_length: int = DEFAULT_MAXIMUM_PATH_LENGTH,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> RepositoryContentSnapshot:
    """Bind every non-Git repository file to one bounded deterministic identity."""

    path = Path(root)
    try:
        if not path.is_absolute() or path.resolve(strict=True) != path:
            raise RepositoryContentError(
                "repository_content_unsafe",
                "repository content identity requires one absolute path without symbolic-link components",
            )
    except OSError as exc:
        raise RepositoryContentError(
            "repository_content_unavailable",
            "repository content is unavailable",
        ) from exc
    if (
        isinstance(maximum_file_count, bool)
        or not isinstance(maximum_file_count, int)
        or maximum_file_count < 1
        or isinstance(maximum_total_bytes, bool)
        or not isinstance(maximum_total_bytes, int)
        or maximum_total_bytes < 1
        or isinstance(maximum_path_length, bool)
        or not isinstance(maximum_path_length, int)
        or maximum_path_length < 1
        or not isinstance(timeout_seconds, (int, float))
        or isinstance(timeout_seconds, bool)
        or timeout_seconds <= 0
    ):
        raise RepositoryContentError(
            "repository_content_policy_invalid",
            "repository content identity limits are invalid",
        )
    deadline = monotonic() + float(timeout_seconds)
    first = _snapshot(
        path,
        maximum_file_count=maximum_file_count,
        maximum_total_bytes=maximum_total_bytes,
        maximum_path_length=maximum_path_length,
        deadline=deadline,
    )
    second = _snapshot(
        path,
        maximum_file_count=maximum_file_count,
        maximum_total_bytes=maximum_total_bytes,
        maximum_path_length=maximum_path_length,
        deadline=deadline,
    )
    if first.identity != second.identity or first.lfs_pointers_detected != second.lfs_pointers_detected:
        raise RepositoryContentError(
            "repository_content_changed",
            "repository content changed while its identity was inspected",
        )
    return second


def _snapshot(
    root: Path,
    *,
    maximum_file_count: int,
    maximum_total_bytes: int,
    maximum_path_length: int,
    deadline: float,
) -> RepositoryContentSnapshot:
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        root_descriptor = os.open(root, directory_flags)
    except OSError as exc:
        raise RepositoryContentError(
            "repository_content_unsafe",
            "repository content root is not a safe directory",
        ) from exc
    files: list[dict[str, object]] = []
    totals: dict[str, int | bool] = {"bytes": 0, "lfs": False}
    try:
        _scan_directory(
            root_descriptor,
            (),
            files,
            totals,
            maximum_file_count=maximum_file_count,
            maximum_total_bytes=maximum_total_bytes,
            maximum_path_length=maximum_path_length,
            deadline=deadline,
        )
    finally:
        os.close(root_descriptor)
    manifest = {"formatVersion": CONTENT_IDENTITY_FORMAT, "files": files}
    encoded = json.dumps(
        manifest,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    identity: dict[str, object] = {
        "formatVersion": CONTENT_IDENTITY_FORMAT,
        "manifestDigest": "sha256:" + hashlib.sha256(encoded).hexdigest(),
        "fileCount": len(files),
        "totalBytes": totals["bytes"],
    }
    return RepositoryContentSnapshot(identity, bool(totals["lfs"]))


def _scan_directory(
    directory_descriptor: int,
    relative_parts: tuple[str, ...],
    files: list[dict[str, object]],
    totals: dict[str, int | bool],
    *,
    maximum_file_count: int,
    maximum_total_bytes: int,
    maximum_path_length: int,
    deadline: float,
) -> None:
    _check_deadline(deadline)
    before = os.fstat(directory_descriptor)
    if not stat.S_ISDIR(before.st_mode):
        raise RepositoryContentError(
            "repository_content_unsafe",
            "repository content may contain only regular files and directories",
    )
    try:
        with os.scandir(directory_descriptor) as scanned:
            entries = sorted(
                ((item.name, item.stat(follow_symlinks=False)) for item in scanned),
                key=lambda item: os.fsencode(item[0]),
            )
        for name, info in entries:
            _check_deadline(deadline)
            parts = (*relative_parts, name)
            relative = "/".join(parts)
            try:
                relative.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise RepositoryContentError(
                    "repository_content_unsafe",
                    "repository content paths must be valid UTF-8",
                ) from exc
            if len(relative) > maximum_path_length:
                raise RepositoryContentError(
                    "repository_content_limit_exceeded",
                    "repository content exceeds the configured path-length limit",
                )
            if stat.S_ISLNK(info.st_mode):
                raise RepositoryContentError(
                    "repository_content_unsafe",
                    "repository contents may not contain symbolic links",
                )
            if name == ".git":
                if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                    raise RepositoryContentError(
                        "repository_content_unsafe",
                        "repository Git metadata has an unsafe filesystem type",
                    )
                continue
            if stat.S_ISDIR(info.st_mode):
                flags = (
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                child = os.open(name, flags, dir_fd=directory_descriptor)
                try:
                    opened = os.fstat(child)
                    if _entry_identity(opened) != _entry_identity(info):
                        raise RepositoryContentError(
                            "repository_content_changed",
                            "repository content changed while its identity was inspected",
                        )
                    _scan_directory(
                        child,
                        parts,
                        files,
                        totals,
                        maximum_file_count=maximum_file_count,
                        maximum_total_bytes=maximum_total_bytes,
                        maximum_path_length=maximum_path_length,
                        deadline=deadline,
                    )
                finally:
                    os.close(child)
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise RepositoryContentError(
                    "repository_content_unsafe",
                    "repository contents may contain only single-link regular files and directories",
                )
            if len(files) >= maximum_file_count:
                raise RepositoryContentError(
                    "repository_content_limit_exceeded",
                    "repository content exceeds the configured file-count limit",
                )
            file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(name, file_flags, dir_fd=directory_descriptor)
            try:
                opened = os.fstat(descriptor)
                if (
                    _entry_identity(opened) != _entry_identity(info)
                    or not stat.S_ISREG(opened.st_mode)
                    or opened.st_nlink != 1
                ):
                    raise RepositoryContentError(
                        "repository_content_changed",
                        "repository content changed while its identity was inspected",
                    )
                digest = hashlib.sha256()
                size = 0
                sample = bytearray()
                while True:
                    _check_deadline(deadline)
                    chunk = os.read(descriptor, 1024 * 1024)
                    if not chunk:
                        break
                    if len(sample) < 256:
                        sample.extend(chunk[: 256 - len(sample)])
                    size += len(chunk)
                    if int(totals["bytes"]) + size > maximum_total_bytes:
                        raise RepositoryContentError(
                            "repository_content_limit_exceeded",
                            "repository content exceeds the configured byte limit",
                        )
                    digest.update(chunk)
                after = os.fstat(descriptor)
                if _stable_file_identity(opened) != _stable_file_identity(after) or size != opened.st_size:
                    raise RepositoryContentError(
                        "repository_content_changed",
                        "repository content changed while its identity was inspected",
                    )
            finally:
                os.close(descriptor)
            mode = "100755" if info.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH) else "100644"
            files.append({
                "path": relative,
                "mode": mode,
                "size": size,
                "digest": "sha256:" + digest.hexdigest(),
            })
            totals["bytes"] = int(totals["bytes"]) + size
            if b"git-lfs.github.com/spec/v1" in sample and b"oid sha256:" in sample:
                totals["lfs"] = True
    except RepositoryContentError:
        raise
    except OSError as exc:
        raise RepositoryContentError(
            "repository_content_changed",
            "repository content changed while its identity was inspected",
        ) from exc
    after = os.fstat(directory_descriptor)
    if _stable_directory_identity(before) != _stable_directory_identity(after):
        raise RepositoryContentError(
            "repository_content_changed",
            "repository content changed while its identity was inspected",
        )


def _check_deadline(deadline: float) -> None:
    if monotonic() > deadline:
        raise RepositoryContentError(
            "repository_content_timeout",
            "repository content identity inspection exceeded the configured timeout",
        )


def _entry_identity(value: os.stat_result) -> tuple[int, int, int]:
    return value.st_dev, value.st_ino, value.st_mode


def _stable_file_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _stable_directory_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
