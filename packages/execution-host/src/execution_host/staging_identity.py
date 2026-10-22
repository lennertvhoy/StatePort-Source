"""Content identity and daemon-owned snapshots for validator staging."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
import tempfile
from typing import Any

from .daemon_contract import canonical_digest


STAGING_MANIFEST_FORMAT = "stateport.validator-staging-manifest/v1"
STAGING_SNAPSHOT_POLICY = "stateport.validator-staging-snapshot/v1"
MAX_STAGING_ENTRIES = 10_000
MAX_STAGING_BYTES = 4 * 1024**3
MAX_STAGING_DEPTH = 64
MAX_STAGING_PATH_BYTES = 4096
_COPY_CHUNK_BYTES = 1024 * 1024
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


class StagingIdentityError(RuntimeError):
    """Staging content is unreadable, mutable, or of an unsupported shape."""


@dataclass(frozen=True)
class StagingSnapshot:
    path: Path
    digest: str
    entry_count: int
    byte_count: int
    policy: str = STAGING_SNAPSHOT_POLICY


def _same_node(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        first.st_dev == second.st_dev
        and first.st_ino == second.st_ino
        and stat.S_IFMT(first.st_mode) == stat.S_IFMT(second.st_mode)
    )


def _relative_path(parent: str, name: str) -> str:
    if not name or name in {".", ".."} or "/" in name or "\x00" in name:
        raise StagingIdentityError("validator staging contains an invalid path")
    relative = f"{parent}/{name}" if parent else name
    try:
        encoded = relative.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise StagingIdentityError("validator staging paths must be valid UTF-8") from exc
    if len(encoded) > MAX_STAGING_PATH_BYTES:
        raise StagingIdentityError("validator staging path length exceeds the bound")
    return relative


def _directory_names(directory_fd: int) -> list[str]:
    try:
        return sorted(os.listdir(directory_fd))
    except OSError as exc:
        raise StagingIdentityError("validator staging could not be read") from exc


def _write_all(file_fd: int, data: bytes) -> None:
    pending = memoryview(data)
    while pending:
        written = os.write(file_fd, pending)
        if written <= 0:
            raise StagingIdentityError("validator snapshot could not be written")
        pending = pending[written:]


def _scan_directory(
    directory_fd: int,
    *,
    relative_directory: str,
    destination: Path | None,
    entries: list[dict[str, Any]],
    counters: dict[str, int],
    max_bytes: int,
    depth: int,
) -> None:
    if depth > MAX_STAGING_DEPTH:
        raise StagingIdentityError("validator staging directory depth exceeds the bound")
    before_directory = os.fstat(directory_fd)
    names = _directory_names(directory_fd)
    for name in names:
        relative = _relative_path(relative_directory, name)
        counters["entries"] += 1
        if counters["entries"] > MAX_STAGING_ENTRIES:
            raise StagingIdentityError("validator staging entry count exceeds the bound")
        try:
            before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            raise StagingIdentityError("validator staging identity could not be read") from exc
        destination_path = destination / name if destination is not None else None
        if stat.S_ISLNK(before.st_mode):
            raise StagingIdentityError("validator staging must not contain symlinks")
        if stat.S_ISDIR(before.st_mode):
            try:
                child_fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=directory_fd)
            except OSError as exc:
                raise StagingIdentityError(
                    "validator staging directory changed while being opened"
                ) from exc
            try:
                opened = os.fstat(child_fd)
                if not _same_node(before, opened):
                    raise StagingIdentityError(
                        "validator staging directory changed while being opened"
                    )
                if destination_path is not None:
                    os.mkdir(destination_path, 0o700)
                entries.append(
                    {
                        "path": relative,
                        "type": "directory",
                        "mode": stat.S_IMODE(opened.st_mode),
                    }
                )
                _scan_directory(
                    child_fd,
                    relative_directory=relative,
                    destination=destination_path,
                    entries=entries,
                    counters=counters,
                    max_bytes=max_bytes,
                    depth=depth + 1,
                )
                after = os.fstat(child_fd)
                if (
                    not _same_node(opened, after)
                    or opened.st_mtime_ns != after.st_mtime_ns
                    or opened.st_ctime_ns != after.st_ctime_ns
                ):
                    raise StagingIdentityError(
                        "validator staging directory mutated while being copied"
                    )
                if destination_path is not None:
                    os.chmod(destination_path, stat.S_IMODE(opened.st_mode))
            finally:
                os.close(child_fd)
            continue
        if not stat.S_ISREG(before.st_mode):
            raise StagingIdentityError("validator staging contains an unsupported file type")
        if before.st_size < 0 or counters["bytes"] + before.st_size > max_bytes:
            raise StagingIdentityError("validator staging content exceeds the byte bound")
        try:
            source_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
        except OSError as exc:
            raise StagingIdentityError(
                "validator staging file changed while being opened"
            ) from exc
        destination_fd: int | None = None
        digest = hashlib.sha256()
        copied = 0
        try:
            opened = os.fstat(source_fd)
            if not stat.S_ISREG(opened.st_mode) or not _same_node(before, opened):
                raise StagingIdentityError(
                    "validator staging file changed while being opened"
                )
            if destination_path is not None:
                destination_fd = os.open(
                    destination_path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                )
            while chunk := os.read(source_fd, _COPY_CHUNK_BYTES):
                copied += len(chunk)
                if counters["bytes"] + copied > max_bytes:
                    raise StagingIdentityError(
                        "validator staging content exceeds the byte bound"
                    )
                digest.update(chunk)
                if destination_fd is not None:
                    _write_all(destination_fd, chunk)
            after = os.fstat(source_fd)
            if (
                not _same_node(opened, after)
                or opened.st_size != after.st_size
                or opened.st_mtime_ns != after.st_mtime_ns
                or opened.st_ctime_ns != after.st_ctime_ns
                or copied != opened.st_size
            ):
                raise StagingIdentityError("validator staging mutated while being copied")
            if destination_fd is not None:
                os.fsync(destination_fd)
                os.fchmod(destination_fd, stat.S_IMODE(opened.st_mode))
        except OSError as exc:
            raise StagingIdentityError("validator staging content could not be read") from exc
        finally:
            if destination_fd is not None:
                os.close(destination_fd)
            os.close(source_fd)
        counters["bytes"] += copied
        entries.append(
            {
                "path": relative,
                "type": "file",
                "mode": stat.S_IMODE(opened.st_mode),
                "size": copied,
                "contentDigest": "sha256:" + digest.hexdigest(),
            }
        )
    after_names = _directory_names(directory_fd)
    after_directory = os.fstat(directory_fd)
    if (
        names != after_names
        or not _same_node(before_directory, after_directory)
        or before_directory.st_mtime_ns != after_directory.st_mtime_ns
        or before_directory.st_ctime_ns != after_directory.st_ctime_ns
    ):
        raise StagingIdentityError("validator staging directory mutated while being scanned")


def _open_beneath(trusted_root: Path, source: Path) -> int:
    root = Path(os.path.abspath(trusted_root))
    candidate = Path(os.path.abspath(source))
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise StagingIdentityError("validator staging escapes the configured root") from exc
    try:
        root_stat = os.stat(root, follow_symlinks=False)
        if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
            raise StagingIdentityError("validator staging root must be a real directory")
        current_fd = os.open(root, _DIRECTORY_FLAGS)
    except OSError as exc:
        raise StagingIdentityError("validator staging root could not be opened") from exc
    try:
        if not _same_node(root_stat, os.fstat(current_fd)):
            raise StagingIdentityError("validator staging root changed while being opened")
        for part in relative.parts:
            if part in {"", ".", ".."}:
                raise StagingIdentityError("validator staging path is invalid")
            try:
                next_fd = os.open(part, _DIRECTORY_FLAGS, dir_fd=current_fd)
            except OSError as exc:
                raise StagingIdentityError(
                    "validator staging path contains a symlink or non-directory component"
                ) from exc
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def _manifest_entries_from_fd(
    directory_fd: int, *, destination: Path | None, max_bytes: int
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    if isinstance(max_bytes, bool) or not 0 <= max_bytes <= MAX_STAGING_BYTES:
        raise StagingIdentityError("validator staging byte bound is invalid")
    entries: list[dict[str, Any]] = []
    counters = {"entries": 0, "bytes": 0}
    _scan_directory(
        directory_fd,
        relative_directory="",
        destination=destination,
        entries=entries,
        counters=counters,
        max_bytes=max_bytes,
        depth=0,
    )
    entries.sort(key=lambda item: (item["path"], item["type"]))
    return entries, counters


def staging_manifest_entries(
    path: Path, *, max_bytes: int = MAX_STAGING_BYTES
) -> list[dict[str, Any]]:
    try:
        directory_fd = os.open(path, _DIRECTORY_FLAGS)
    except OSError as exc:
        raise StagingIdentityError("validator staging must be a real directory") from exc
    try:
        entries, _ = _manifest_entries_from_fd(
            directory_fd, destination=None, max_bytes=max_bytes
        )
        return entries
    finally:
        os.close(directory_fd)


def staging_manifest_digest(path: Path, *, max_bytes: int = MAX_STAGING_BYTES) -> str:
    """The canonical content identity of one staging tree."""
    return canonical_digest(
        {
            "formatVersion": STAGING_MANIFEST_FORMAT,
            "entries": staging_manifest_entries(path, max_bytes=max_bytes),
        }
    )


def create_staging_snapshot(
    source: Path,
    *,
    trusted_root: Path,
    snapshots_root: Path,
    workload_id: str,
    max_bytes: int,
) -> StagingSnapshot:
    """Securely copy staging into a private, daemon-owned immutable input tree."""
    snapshots_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root_stat = os.stat(snapshots_root, follow_symlinks=False)
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        raise StagingIdentityError("validator snapshot root must be a real directory")
    os.chmod(snapshots_root, 0o700)
    snapshot_path = Path(
        tempfile.mkdtemp(prefix=f"{workload_id}.", dir=str(snapshots_root))
    )
    os.chmod(snapshot_path, 0o700)
    source_fd: int | None = None
    try:
        source_fd = _open_beneath(trusted_root, source)
        entries, counters = _manifest_entries_from_fd(
            source_fd, destination=snapshot_path, max_bytes=max_bytes
        )
        digest = canonical_digest(
            {"formatVersion": STAGING_MANIFEST_FORMAT, "entries": entries}
        )
        # Re-open and re-hash the exact daemon-owned tree that will be mounted.
        if staging_manifest_digest(snapshot_path, max_bytes=max_bytes) != digest:
            raise StagingIdentityError("validator snapshot identity changed after copy")
        return StagingSnapshot(
            path=snapshot_path,
            digest=digest,
            entry_count=counters["entries"],
            byte_count=counters["bytes"],
        )
    except BaseException:
        remove_staging_snapshot(snapshot_path, snapshots_root=snapshots_root)
        raise
    finally:
        if source_fd is not None:
            os.close(source_fd)


def _remove_tree(path: Path) -> None:
    node = os.stat(path, follow_symlinks=False)
    if stat.S_ISLNK(node.st_mode) or not stat.S_ISDIR(node.st_mode):
        path.unlink()
        return
    for entry in os.scandir(path):
        child = Path(entry.path)
        child_stat = entry.stat(follow_symlinks=False)
        if stat.S_ISDIR(child_stat.st_mode) and not stat.S_ISLNK(child_stat.st_mode):
            _remove_tree(child)
        else:
            child.unlink()
    path.rmdir()


def remove_staging_snapshot(path: Path, *, snapshots_root: Path) -> None:
    root = Path(os.path.abspath(snapshots_root))
    candidate = Path(os.path.abspath(path))
    if candidate.parent != root:
        raise StagingIdentityError("validator snapshot cleanup escaped its daemon-owned root")
    try:
        _remove_tree(candidate)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise StagingIdentityError("validator snapshot cleanup failed") from exc


def cleanup_staging_snapshot_root(snapshots_root: Path) -> None:
    """Remove snapshots left after boot reconciliation terminated all validators."""
    if not snapshots_root.exists():
        return
    root_stat = os.stat(snapshots_root, follow_symlinks=False)
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        raise StagingIdentityError("validator snapshot root is not a real directory")
    for entry in os.scandir(snapshots_root):
        _remove_tree(Path(entry.path))


__all__ = [
    "MAX_STAGING_BYTES",
    "STAGING_MANIFEST_FORMAT",
    "STAGING_SNAPSHOT_POLICY",
    "StagingIdentityError",
    "StagingSnapshot",
    "cleanup_staging_snapshot_root",
    "create_staging_snapshot",
    "remove_staging_snapshot",
    "staging_manifest_digest",
    "staging_manifest_entries",
]
