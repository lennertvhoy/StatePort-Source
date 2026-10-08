"""Canonical instance snapshot and state-integrity helpers for governed runs."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class StateSnapshot(Mapping[str, bytes]):
    """Canonical regular-file contents plus every directory entry."""

    files: dict[str, bytes]
    directories: frozenset[str]

    def __getitem__(self, key: str) -> bytes:
        return self.files[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.files)

    def __len__(self) -> int:
        return len(self.files)


def snapshot_files(root: Path | str) -> StateSnapshot:
    """Capture every safe filesystem entry below ``root`` without links."""

    target = Path(root)
    if not target.is_dir():
        raise ValueError(f"instance is not a directory: {target}")
    files: dict[str, bytes] = {}
    directories: set[str] = set()
    for item in target.rglob("*"):
        relative = item.relative_to(target).as_posix()
        if item.is_symlink():
            raise ValueError(f"instance contains a symlink: {relative}")
        if item.is_file():
            files[relative] = item.read_bytes()
        elif item.is_dir():
            directories.add(relative)
        else:
            raise ValueError(f"instance contains a non-regular entry: {relative}")
    return StateSnapshot(files, frozenset(directories))


def _hash(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _hashes(snapshot: Mapping[str, bytes]) -> dict[str, str]:
    return {path: _hash(snapshot[path]) for path in sorted(snapshot)}


def digest_snapshot(snapshot: StateSnapshot) -> str:
    """Return a deterministic content digest for a confined file snapshot."""

    encoded = json.dumps(
        {
            "directories": sorted(snapshot.directories),
            "files": _hashes(snapshot),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def diff_snapshots(before: StateSnapshot, after: StateSnapshot) -> dict[str, object]:
    """Return metadata-only changes between two canonical file snapshots."""

    before_hashes = _hashes(before)
    after_hashes = _hashes(after)
    added = sorted(set(after_hashes) - set(before_hashes))
    removed = sorted(set(before_hashes) - set(after_hashes))
    modified = sorted(
        path for path in set(before_hashes) & set(after_hashes)
        if before_hashes[path] != after_hashes[path]
    )
    added_directories = sorted(after.directories - before.directories)
    removed_directories = sorted(before.directories - after.directories)
    return {
        "before": before_hashes,
        "after": after_hashes,
        "added": added,
        "removed": removed,
        "modified": modified,
        "addedDirectories": added_directories,
        "removedDirectories": removed_directories,
        "filesChanged": sorted(
            set(added)
            | set(removed)
            | set(modified)
            | {f"{path}/" for path in added_directories}
            | {f"{path}/" for path in removed_directories}
        ),
    }


def restore_snapshot(root: Path | str, snapshot: StateSnapshot) -> None:
    """Restore regular files while removing added links, files, and directories.

    Expected files are unlinked before recreation so an unexpected hard link
    cannot redirect restoration writes to another inode.
    """

    target = Path(root)
    if not target.exists():
        return
    items = sorted(
        target.rglob("*"),
        key=lambda item: (len(item.relative_to(target).parts), item.as_posix()),
        reverse=True,
    )
    required_directories = set(snapshot.directories)
    for item in items:
        relative = item.relative_to(target).as_posix()
        if item.is_symlink() or (not item.is_dir() and not item.is_file()):
            item.unlink()
        elif item.is_file():
            item.unlink()
        elif relative not in required_directories:
            try:
                item.rmdir()
            except OSError:
                # A retained required descendant can keep a parent non-empty.
                pass
    for relative in sorted(required_directories, key=lambda value: len(Path(value).parts)):
        (target / relative).mkdir(parents=True, exist_ok=True)
    for relative, content in snapshot.files.items():
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(
            destination,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
            0o666,
        )
        try:
            view = memoryview(content)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("snapshot restoration write made no progress")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    # The caller may publish a successful transaction immediately after this
    # returns. Persist both file contents and every recreated directory entry.
    directories = [target / relative for relative in required_directories]
    directories.append(target)
    for directory in sorted(
        directories,
        key=lambda value: len(value.relative_to(target).parts),
        reverse=True,
    ):
        descriptor = os.open(
            directory,
            os.O_RDONLY
            | os.O_CLOEXEC
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
