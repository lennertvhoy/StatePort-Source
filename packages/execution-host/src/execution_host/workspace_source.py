"""Pure descriptor based verification for reviewed workspace source.

This module deliberately has no repository or subprocess dependency.  The
issuer receives an anchored directory descriptor and an operator reviewed
Git commit object; it verifies the exact files named by the review before a
source archive is handed to the daemon.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import os
from pathlib import PurePosixPath
import re
import stat
import tarfile
import tempfile
from typing import Any, BinaryIO, Callable, Mapping, NoReturn

from . import daemon_contract as contract
from .deployment_staging import _tar_info as reuse_tar_info


MAX_COMMIT_OBJECT_BYTES = 64 * 1024
MAX_SOURCE_REVIEW_BYTES = 1024 * 1024
MAX_SOURCE_PATH_BYTES = 4096
_GIT_OID = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_MODES = {"100644": {0o600, 0o644}, "100755": {0o700, 0o755}}


class WorkspaceSourceRefusal(ValueError):
    """The reviewed source is malformed, changed, or unsafe."""


def _refuse(detail: str) -> NoReturn:
    raise WorkspaceSourceRefusal(detail)


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        _refuse(f"{label} must be a sha256 digest")
    return value


def _relative(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        _refuse(f"{label} is unsafe")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        _refuse(f"{label} is not valid UTF-8")
    if len(encoded) > MAX_SOURCE_PATH_BYTES:
        _refuse(f"{label} is too long")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or value in {"", "."} or ".." in path.parts:
        _refuse(f"{label} is unsafe")
    if any(component in {"", ".", "..", ".git"} for component in path.parts):
        _refuse(f"{label} is unsafe")
    if any(len(component.encode("utf-8")) > 255 for component in path.parts):
        _refuse(f"{label} component is too long")
    return value


def _archive(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "formatVersion", "archiveDigest", "archiveBytes", "contextDigest", "fileCount"
    }:
        _refuse("source archive has an invalid shape")
    if value["formatVersion"] != "stateport.deployment-context-archive/v1":
        _refuse("source archive format is unsupported")
    for key in ("archiveDigest", "contextDigest"):
        _digest(value[key], f"sourceArchive.{key}")
    for key, maximum in (("archiveBytes", contract.MAX_DEPLOYMENT_ARCHIVE_BYTES), ("fileCount", contract.MAX_DEPLOYMENT_FILES)):
        if isinstance(value[key], bool) or not isinstance(value[key], int) or not 1 <= value[key] <= maximum:
            _refuse(f"sourceArchive.{key} is outside its bound")
    return {
        "formatVersion": value["formatVersion"],
        "archiveDigest": value["archiveDigest"],
        "archiveBytes": value["archiveBytes"],
        "contextDigest": value["contextDigest"],
        "fileCount": value["fileCount"],
    }


def _commit_bytes(value: Any) -> tuple[str, bytes, str]:
    if not isinstance(value, str) or not value or len(value) > MAX_COMMIT_OBJECT_BYTES * 2:
        _refuse("commit object witness is oversized")
    try:
        encoded = value.encode("ascii")
        raw = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise WorkspaceSourceRefusal("commit object witness is not strict base64") from exc
    if not 1 <= len(raw) <= MAX_COMMIT_OBJECT_BYTES or base64.b64encode(raw).decode("ascii") != value:
        _refuse("commit object witness is outside its bound or not canonical base64")
    if b"\x00" in raw:
        _refuse("commit object witness contains NUL")
    first, separator, _rest = raw.partition(b"\n")
    if not separator or len(first) != 45 or not first.startswith(b"tree "):
        _refuse("commit object witness has no canonical tree header")
    tree = first[5:].decode("ascii", "strict")
    if _GIT_OID.fullmatch(tree) is None:
        _refuse("commit object witness tree header is invalid")
    return value, raw, tree


def _inventory(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list) or not 1 <= len(value) <= contract.MAX_DEPLOYMENT_FILES:
        _refuse("source inventory is outside its bound")
    result: list[dict[str, str]] = []
    paths: set[str] = set()
    for item in value:
        if not isinstance(item, Mapping) or set(item) != {"path", "mode", "contentDigest"}:
            _refuse("source inventory entry has an invalid shape")
        path = _relative(item["path"], "sourceInventory.path")
        if path in paths:
            _refuse("source inventory path is duplicated")
        if not isinstance(item["mode"], str) or item["mode"] not in _SAFE_MODES:
            _refuse("source inventory admits only regular Git files")
        digest = _digest(item["contentDigest"], "sourceInventory.contentDigest")
        paths.add(path)
        result.append({"path": path, "mode": item["mode"], "contentDigest": digest})
    # A file cannot also be an ancestor directory.  Detect this before opening
    # anything so the result does not depend on inventory order.
    for path in paths:
        parent = PurePosixPath(path).parent
        while str(parent) != ".":
            if parent.as_posix() in paths:
                _refuse("source inventory contains a file-directory collision")
            parent = parent.parent
    return result


def validate_source_commit(value: Any) -> dict[str, Any]:
    """Normalize the complete reviewed-commit source request fragment."""

    if not isinstance(value, Mapping) or set(value) != {
        "baseRevision", "commitObject", "sourceInventory", "sourceArchive", "descriptorDigest"
    }:
        _refuse("reviewed source has an invalid shape")
    if not isinstance(value["baseRevision"], str) or _GIT_OID.fullmatch(value["baseRevision"]) is None:
        _refuse("baseRevision must be a full lowercase Git object id")
    witness, raw, tree = _commit_bytes(value["commitObject"])
    observed_commit = hashlib.sha1(b"commit " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
    if observed_commit != value["baseRevision"]:
        _refuse("commit object witness does not match baseRevision")
    inventory = _inventory(value["sourceInventory"])
    archive = _archive(value["sourceArchive"])
    if archive["fileCount"] != len(inventory):
        _refuse("source archive file count differs from inventory")
    descriptor = _digest(value["descriptorDigest"], "source descriptor digest")
    result = {
        "baseRevision": value["baseRevision"],
        "commitObject": witness,
        "sourceInventory": inventory,
        "sourceArchive": archive,
        "descriptorDigest": descriptor,
    }
    try:
        encoded = contract.canonical_json(result).encode("utf-8")
    except (TypeError, UnicodeError, ValueError) as exc:
        raise WorkspaceSourceRefusal("reviewed source is not canonical JSON") from exc
    if len(encoded) > MAX_SOURCE_REVIEW_BYTES:
        _refuse("reviewed source exceeds its byte bound")
    return result


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _check_directory(fd: int, owner_uid: int, label: str) -> os.stat_result:
    try:
        info = os.fstat(fd)
    except OSError as exc:
        raise WorkspaceSourceRefusal(f"{label} cannot be inspected") from exc
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner_uid or info.st_mode & 0o022:
        _refuse(f"{label} is not a confined owner directory")
    return info


def _open_parent(root_fd: int, path: str, owner_uid: int) -> tuple[int, list[tuple[int, str, os.stat_result]]]:
    current = os.dup(root_fd)
    chain: list[tuple[int, str, os.stat_result]] = []
    opened_fds = [current]
    try:
        for component in PurePosixPath(path).parts[:-1]:
            parent = current
            try:
                namespace = os.stat(component, dir_fd=parent, follow_symlinks=False)
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                opened_fds.append(child)
            except OSError as exc:
                _refuse("source inventory parent is unavailable or unsafe")
            opened = _check_directory(child, owner_uid, "source inventory parent")
            if _identity(namespace) != _identity(opened):
                _refuse("source inventory parent changed while opening")
            chain.append((parent, component, opened))
            current = child
        return current, chain
    except Exception:
        for fd in reversed(opened_fds):
            try:
                os.close(fd)
            except OSError:
                pass
        raise


def _read_verified(root_fd: int, row: Mapping[str, str], owner_uid: int, *, remaining_bytes: int,
                   consume: Callable[[BinaryIO, int], None] | None = None) -> tuple[int, str, str]:
    path = row["path"]
    parent, chain = _open_parent(root_fd, path, owner_uid)
    descriptor = -1
    try:
        leaf = PurePosixPath(path).parts[-1]
        namespace = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISREG(namespace.st_mode) or namespace.st_uid != owner_uid
                or namespace.st_nlink != 1 or stat.S_IMODE(namespace.st_mode) not in _SAFE_MODES[row["mode"]]):
            _refuse("source file is not a confined regular file")
        descriptor = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
        opened = os.fstat(descriptor)
        if (_identity(namespace) != _identity(opened) or not stat.S_ISREG(opened.st_mode)
                or opened.st_uid != owner_uid or opened.st_nlink != 1
                or stat.S_IMODE(opened.st_mode) not in _SAFE_MODES[row["mode"]]):
            _refuse("source file identity, owner, link count, or mode changed")
        expected_mode = 0o755 if row["mode"] == "100755" else 0o644
        if opened.st_size < 0 or opened.st_size > remaining_bytes:
            _refuse("source file exceeds the bounded source context")
        sha256 = hashlib.sha256()
        blob = hashlib.sha1(b"blob " + str(opened.st_size).encode("ascii") + b"\0")
        size = 0
        spool: BinaryIO | None = None
        if consume is not None:
            spool = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024, mode="w+b")
        try:
            while True:
                chunk = os.read(descriptor, min(1024 * 1024, opened.st_size - size + 1))
                if not chunk:
                    break
                size += len(chunk)
                if size > opened.st_size or size > remaining_bytes:
                    _refuse("source file grew beyond its reviewed size")
                sha256.update(chunk)
                blob.update(chunk)
                if spool is not None:
                    spool.write(chunk)
            if size != opened.st_size or _identity(os.fstat(descriptor)) != _identity(opened):
                _refuse("source file changed while being read")
            after = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            if _identity(after) != _identity(opened):
                _refuse("source file changed in its namespace")
            for chain_parent, component, observed in chain:
                current = os.stat(component, dir_fd=chain_parent, follow_symlinks=False)
                if _identity(current) != _identity(observed):
                    _refuse("source directory changed while being read")
            digest = "sha256:" + sha256.hexdigest()
            if digest != row["contentDigest"]:
                _refuse("source file content differs from the reviewed inventory")
            if spool is not None:
                spool.flush()
                spool.seek(0)
                consume(spool, expected_mode)
            return size, digest, blob.hexdigest()
        finally:
            if spool is not None:
                spool.close()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        for chain_parent, _component, _observed in reversed(chain):
            os.close(chain_parent)
        os.close(parent)


def _tree_oid(rows: list[tuple[str, str, str]]) -> str:
    root: dict[str, Any] = {}
    for path, mode, blob_oid in rows:
        node = root
        parts = PurePosixPath(path).parts
        for component in parts[:-1]:
            current = node.get(component)
            if current is None:
                current = {}
                node[component] = current
            if not isinstance(current, dict):
                _refuse("source inventory contains a file-directory collision")
            node = current
        leaf = parts[-1]
        if leaf in node:
            _refuse("source inventory path is duplicated")
        node[leaf] = (mode, blob_oid)

    # Git trees can be deeper than the interpreter recursion limit.  Keep the
    # traversal iterative so a valid bounded inventory cannot turn into an
    # uncontrolled RecursionError in the root issuer.
    pending = [root]
    ordered: list[dict[str, Any]] = []
    while pending:
        tree = pending.pop()
        ordered.append(tree)
        pending.extend(value for value in tree.values() if isinstance(value, dict))

    digests: dict[int, str] = {}
    for tree in reversed(ordered):
        entries: list[tuple[bytes, bytes]] = []
        for name, value in tree.items():
            name_bytes = name.encode("utf-8")
            if isinstance(value, dict):
                oid = digests[id(value)]
                entries.append((name_bytes + b"/", b"40000 " + name_bytes + b"\0" + bytes.fromhex(oid)))
            else:
                mode, oid = value
                entries.append((name_bytes, mode.encode("ascii") + b" " + name_bytes + b"\0" + bytes.fromhex(oid)))
        raw = b"".join(entry for _sort, entry in sorted(entries, key=lambda item: item[0]))
        digests[id(tree)] = hashlib.sha1(b"tree " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()

    return digests[id(root)]


def _scan(root_fd: int, source: Mapping[str, Any], owner_uid: int, *, consume: Callable[[BinaryIO, int, str], None] | None = None) -> dict[str, Any]:
    source = validate_source_commit(source)
    root_observed = _check_directory(root_fd, owner_uid, "source root")
    rows: list[tuple[str, str, str]] = []
    context: list[dict[str, Any]] = []
    total = 0
    for row in source["sourceInventory"]:
        def emit(handle: BinaryIO, mode: int, path: str = row["path"]) -> None:
            if consume is not None:
                consume(handle, mode, path)
        remaining = contract.MAX_DEPLOYMENT_CONTEXT_BYTES - total
        size, digest, blob_oid = _read_verified(root_fd, row, owner_uid, remaining_bytes=remaining,
                                                consume=emit if consume is not None else None)
        total += size
        if total > contract.MAX_DEPLOYMENT_CONTEXT_BYTES:
            _refuse("source inventory exceeds the bounded context")
        rows.append((row["path"], row["mode"], blob_oid))
        context.append({"path": row["path"], "mode": row["mode"], "size": size, "sha256": digest})
    if _identity(_check_directory(root_fd, owner_uid, "source root")) != _identity(root_observed):
        _refuse("source root changed while being read")
    _witness, raw, expected_tree = _commit_bytes(source["commitObject"])
    if hashlib.sha1(b"commit " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest() != source["baseRevision"]:
        _refuse("commit object changed from the reviewed revision")
    if _tree_oid(rows) != expected_tree:
        _refuse("source inventory does not reconstruct the reviewed Git tree")
    if source["sourceArchive"]["contextDigest"] != contract.canonical_digest(context):
        _refuse("source archive context digest differs from the verified files")
    return {"context": context, "tree": expected_tree, "bytes": total, "fileCount": len(rows)}


class _ArchiveSink:
    """Sequential PAX sink that hashes bytes without retaining the archive."""

    def __init__(self, target: BinaryIO | None = None) -> None:
        self.target = target
        self.digest = hashlib.sha256()
        self.size = 0

    def write(self, data: bytes) -> int:
        if not isinstance(data, bytes):
            data = bytes(data)
        if self.size + len(data) > contract.MAX_DEPLOYMENT_ARCHIVE_BYTES:
            _refuse("source archive exceeds its byte bound")
        if self.target is not None:
            written = self.target.write(data)
            if written != len(data):
                raise WorkspaceSourceRefusal("source archive sink wrote a short record")
        self.digest.update(data)
        self.size += len(data)
        return len(data)

    def tell(self) -> int:
        return self.size

    def flush(self) -> None:
        if self.target is not None:
            self.target.flush()


def _verified_archive(handle: BinaryIO | None, root_fd: int, source: Mapping[str, Any], owner_uid: int) -> dict[str, Any]:
    source = validate_source_commit(source)
    sink = _ArchiveSink(handle)
    archive = tarfile.open(fileobj=sink, mode="w", format=tarfile.PAX_FORMAT)
    try:
        def consume(file_handle: BinaryIO, mode: int, path: str) -> None:
            size = file_handle.seek(0, io.SEEK_END)
            file_handle.seek(0)
            archive.addfile(reuse_tar_info(f"context/{path}", size=size, mode=mode), file_handle)
        observed = _scan(root_fd, source, owner_uid, consume=consume)
        archive.close()
        sink.flush()
    except Exception:
        archive.close()
        raise
    metadata = {
        "formatVersion": "stateport.deployment-context-archive/v1",
        "archiveDigest": "sha256:" + sink.digest.hexdigest(),
        "archiveBytes": sink.size,
        "contextDigest": contract.canonical_digest(observed["context"]),
        "fileCount": observed["fileCount"],
    }
    if metadata != source["sourceArchive"]:
        _refuse("verified source archive differs from the reviewed archive")
    if handle is not None:
        try:
            handle.seek(0)
        except (OSError, AttributeError) as exc:
            raise WorkspaceSourceRefusal("source archive cannot be rewound") from exc
    return metadata


def verify_source_commit(root_fd: int, source: Mapping[str, Any], owner_uid: int) -> None:
    """Verify source bytes, modes, Git blobs/tree and review metadata by FD."""

    if isinstance(owner_uid, bool) or not isinstance(owner_uid, int) or owner_uid < 0:
        _refuse("source owner UID is invalid")
    observed = os.fstat(root_fd)
    if observed.st_uid != owner_uid:
        _refuse("source root owner differs from the reviewed owner")
    _verified_archive(None, root_fd, source, owner_uid)


def stream_verified_source_archive(handle: BinaryIO, root_fd: int, source: Mapping[str, Any], owner_uid: int) -> dict[str, Any]:
    """Verify and stream the exact PAX source archive from pinned descriptors."""

    if isinstance(owner_uid, bool) or not isinstance(owner_uid, int) or owner_uid < 0:
        _refuse("source owner UID is invalid")
    if os.fstat(root_fd).st_uid != owner_uid:
        _refuse("source root owner differs from the reviewed owner")
    return _verified_archive(handle, root_fd, source, owner_uid)


__all__ = ["WorkspaceSourceRefusal", "validate_source_commit", "verify_source_commit", "stream_verified_source_archive"]
