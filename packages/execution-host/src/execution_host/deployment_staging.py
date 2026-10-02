"""Immutable deployment-context transfer over a confined Unix socket.

The control plane materializes the exact Git inventory, writes a deterministic
tar archive to its private state, and passes only an open read-only descriptor
to the execution host with ``SCM_RIGHTS``.  The daemon never needs a shared
writable mount: it verifies every archive byte and member against the approved
plan before publishing a private, operation-scoped snapshot.
"""

from __future__ import annotations

import hashlib
import fcntl
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tarfile
from typing import Any, BinaryIO, Mapping

from . import daemon_contract as contract


ARCHIVE_FORMAT = "stateport.deployment-context-archive/v1"
_OPERATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class DeploymentStagingError(RuntimeError):
    """The transferred archive or daemon-owned snapshot failed closed."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def _relative(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise DeploymentStagingError("deployment-context-invalid", f"{label} is unsafe")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() == "." or any(part in {"", ".."} for part in path.parts):
        raise DeploymentStagingError("deployment-context-invalid", f"{label} is unsafe")
    return path.as_posix()


def _regular_confined(root: Path, relative: str, label: str) -> Path:
    if root.is_symlink() or not root.is_dir():
        raise DeploymentStagingError("deployment-context-invalid", f"{label} root is unsafe")
    current = root
    for component in PurePosixPath(relative).parts:
        current /= component
        try:
            observed = os.lstat(current)
        except OSError as exc:
            raise DeploymentStagingError(
                "deployment-context-invalid", f"{label} is unavailable"
            ) from exc
        if stat.S_ISLNK(observed.st_mode):
            raise DeploymentStagingError("deployment-context-invalid", f"{label} traverses a symlink")
    if not stat.S_ISREG(observed.st_mode):
        raise DeploymentStagingError("deployment-context-invalid", f"{label} is not a regular file")
    return current


def _stream_digest(handle: BinaryIO) -> tuple[str, int]:
    handle.seek(0)
    hasher = hashlib.sha256()
    size = 0
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        hasher.update(chunk)
        size += len(chunk)
    return "sha256:" + hasher.hexdigest(), size


def _tar_info(name: str, *, size: int, mode: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    return info


def build_deployment_archive(
    handle: BinaryIO,
    *,
    plan: Mapping[str, Any],
    context_root: Path,
    overlay_root: Path,
    context_digest: str,
) -> dict[str, Any]:
    """Write and identify one exact context+overlay archive."""

    inventory = plan.get("sourceInventory")
    overlay = plan.get("overlay")
    if (
        not isinstance(inventory, list)
        or not inventory
        or len(inventory) > contract.MAX_DEPLOYMENT_FILES
        or not isinstance(overlay, Mapping)
        or len(inventory) + len(overlay) > contract.MAX_DEPLOYMENT_FILES
    ):
        raise DeploymentStagingError(
            "deployment-context-invalid", "deployment context inventory is not bounded"
        )
    if overlay_root.is_symlink() or not overlay_root.is_dir():
        raise DeploymentStagingError("deployment-context-invalid", "deployment overlay root is unsafe")

    written: list[dict[str, Any]] = []
    source_bytes = 0
    with tarfile.open(fileobj=handle, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for raw in inventory:
            if not isinstance(raw, Mapping):
                raise DeploymentStagingError(
                    "deployment-context-invalid", "source inventory item is invalid"
                )
            relative = _relative(raw.get("path"), "source inventory path")
            source = _regular_confined(context_root, relative, "source inventory file")
            observed = source.stat()
            expected_mode = 0o755 if raw.get("mode") == "100755" else 0o644
            # Managed template imports deliberately keep source files owner-only.
            # The archive preserves Git's executable bit, never widens the source.
            allowed_modes = (0o755, 0o700) if raw.get("mode") == "100755" else (0o644, 0o600)
            if raw.get("mode") not in {"100644", "100755"} or stat.S_IMODE(observed.st_mode) not in allowed_modes:
                raise DeploymentStagingError(
                    "deployment-context-invalid", "source inventory mode changed before transfer"
                )
            source_bytes += observed.st_size
            if source_bytes > contract.MAX_DEPLOYMENT_CONTEXT_BYTES:
                raise DeploymentStagingError(
                    "deployment-context-too-large", "deployment context exceeds the byte bound"
                )
            def source_identity(info: os.stat_result) -> tuple[int, ...]:
                return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
                        info.st_size, info.st_mtime_ns, info.st_ctime_ns)

            descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, "rb") as source_handle:
                opened = os.fstat(source_handle.fileno())
                if not stat.S_ISREG(opened.st_mode) or source_identity(opened) != source_identity(observed):
                    raise DeploymentStagingError(
                        "deployment-context-invalid", "source inventory identity changed before transfer"
                    )
                digest, size = _stream_digest(source_handle)
                if digest != raw.get("contentDigest") or size != observed.st_size:
                    raise DeploymentStagingError(
                        "deployment-context-invalid", "source inventory content changed before transfer"
                    )
                source_handle.seek(0)
                archive.addfile(
                    _tar_info(f"context/{relative}", size=size, mode=expected_mode),
                    source_handle,
                )
                if source_identity(os.fstat(source_handle.fileno())) != source_identity(opened):
                    raise DeploymentStagingError(
                        "deployment-context-invalid", "source inventory changed during transfer"
                    )
            written.append(
                {
                    "path": relative,
                    "mode": raw["mode"],
                    "size": size,
                    "sha256": digest,
                }
            )

        overlay_bytes = 0
        for relative_raw, expected_text in sorted(overlay.items()):
            relative = _relative(relative_raw, "overlay path")
            if not isinstance(expected_text, str):
                raise DeploymentStagingError(
                    "deployment-context-invalid", "deployment overlay content is invalid"
                )
            source = _regular_confined(overlay_root, relative, "overlay file")
            observed = source.stat()
            content = expected_text.encode("utf-8")
            overlay_bytes += len(content)
            if (
                overlay_bytes > contract.MAX_DEPLOYMENT_OVERLAY_BYTES
                or stat.S_IMODE(observed.st_mode) != 0o600
                or source.read_bytes() != content
            ):
                raise DeploymentStagingError(
                    "deployment-context-invalid", "deployment overlay changed before transfer"
                )
            with source.open("rb") as source_handle:
                archive.addfile(
                    _tar_info(f"overlay/{relative}", size=len(content), mode=0o600),
                    source_handle,
                )

    handle.flush()
    try:
        os.fsync(handle.fileno())
    except OSError as exc:
        raise DeploymentStagingError(
            "deployment-context-invalid", "deployment archive could not be synchronized"
        ) from exc
    archive_digest, archive_bytes = _stream_digest(handle)
    observed_context_digest = contract.canonical_digest(written)
    if observed_context_digest != context_digest:
        raise DeploymentStagingError(
            "deployment-context-invalid", "deployment context receipt does not match transferred files"
        )
    if archive_bytes > contract.MAX_DEPLOYMENT_ARCHIVE_BYTES:
        raise DeploymentStagingError(
            "deployment-context-too-large", "deployment archive exceeds the byte bound"
        )
    handle.seek(0)
    return {
        "formatVersion": ARCHIVE_FORMAT,
        "archiveDigest": archive_digest,
        "archiveBytes": archive_bytes,
        "contextDigest": observed_context_digest,
        "fileCount": len(inventory) + len(overlay),
    }


def reopen_archive_read_only(handle: BinaryIO) -> int:
    """Reopen the built anonymous archive without retaining write access."""

    writer_fd = handle.fileno()
    try:
        writer_identity = os.fstat(writer_fd)
        os.fchmod(writer_fd, 0o400)
        read_fd = os.open(
            f"/proc/self/fd/{writer_fd}",
            os.O_RDONLY | os.O_CLOEXEC,
        )
    except OSError as exc:
        raise DeploymentStagingError(
            "deployment-context-invalid",
            "deployment archive could not be reopened read-only",
        ) from exc
    try:
        reader_identity = os.fstat(read_fd)
        access_mode = fcntl.fcntl(read_fd, fcntl.F_GETFL) & os.O_ACCMODE
        if (
            not stat.S_ISREG(reader_identity.st_mode)
            or (reader_identity.st_dev, reader_identity.st_ino)
            != (writer_identity.st_dev, writer_identity.st_ino)
            or access_mode != os.O_RDONLY
        ):
            raise DeploymentStagingError(
                "deployment-context-invalid",
                "deployment archive read-only descriptor identity is invalid",
            )
        os.lseek(read_fd, 0, os.SEEK_SET)
        return read_fd
    except Exception:
        os.close(read_fd)
        raise


def _snapshot_root(path: Path) -> None:
    if path.is_symlink():
        raise DeploymentStagingError(
            "deployment-snapshot-unsafe", "deployment snapshot root is a symlink"
        )
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    observed = os.lstat(path)
    if not stat.S_ISDIR(observed.st_mode) or observed.st_uid != os.geteuid():
        raise DeploymentStagingError(
            "deployment-snapshot-unsafe", "deployment snapshot root is not daemon-owned"
        )
    os.chmod(path, 0o700)


def _write_member(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    *,
    target: Path,
    expected_digest: str,
    expected_size: int | None,
    mode: int,
) -> tuple[str, int]:
    stream = archive.extractfile(member)
    if stream is None:
        raise DeploymentStagingError(
            "deployment-context-invalid", "deployment archive member has no content"
        )
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    hasher = hashlib.sha256()
    size = 0
    try:
        with target.open("xb") as destination:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > contract.MAX_DEPLOYMENT_CONTEXT_BYTES:
                    raise DeploymentStagingError(
                        "deployment-context-too-large", "deployment archive member exceeds the byte bound"
                    )
                hasher.update(chunk)
                destination.write(chunk)
            destination.flush()
            os.fsync(destination.fileno())
    finally:
        stream.close()
    digest = "sha256:" + hasher.hexdigest()
    if digest != expected_digest or size != member.size or (
        expected_size is not None and size != expected_size
    ):
        raise DeploymentStagingError(
            "deployment-context-invalid", "deployment archive member identity differs from the plan"
        )
    target.chmod(mode)
    return digest, size


def materialize_deployment_snapshot(
    archive_fd: int,
    *,
    metadata: Mapping[str, Any],
    plan: Mapping[str, Any],
    snapshots_root: Path,
    operation_id: str,
    max_context_bytes: int = contract.MAX_DEPLOYMENT_CONTEXT_BYTES,
) -> dict[str, Any]:
    """Verify an archive descriptor and publish one private daemon snapshot."""

    if isinstance(max_context_bytes, bool) or not 0 < max_context_bytes <= contract.MAX_DEPLOYMENT_CONTEXT_BYTES:
        raise DeploymentStagingError("deployment-context-too-large", "context byte limit is invalid")
    if _OPERATION_ID.fullmatch(operation_id) is None:
        raise DeploymentStagingError("deployment-snapshot-unsafe", "operation id is invalid")
    try:
        observed = os.fstat(archive_fd)
        access_mode = fcntl.fcntl(archive_fd, fcntl.F_GETFL) & os.O_ACCMODE
    except OSError as exc:
        raise DeploymentStagingError(
            "deployment-context-invalid", "deployment archive descriptor is unavailable"
        ) from exc
    if (
        not stat.S_ISREG(observed.st_mode)
        or access_mode != os.O_RDONLY
        or observed.st_size != metadata.get("archiveBytes")
        or observed.st_size > contract.MAX_DEPLOYMENT_ARCHIVE_BYTES
    ):
        raise DeploymentStagingError(
            "deployment-context-invalid", "deployment archive descriptor identity is invalid"
        )
    try:
        os.lseek(archive_fd, 0, os.SEEK_SET)
        hasher = hashlib.sha256()
        remaining = observed.st_size
        while remaining:
            chunk = os.read(archive_fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            hasher.update(chunk)
            remaining -= len(chunk)
    except OSError as exc:
        raise DeploymentStagingError(
            "deployment-context-invalid", "deployment archive could not be read"
        ) from exc
    if remaining or "sha256:" + hasher.hexdigest() != metadata.get("archiveDigest"):
        raise DeploymentStagingError(
            "deployment-context-invalid", "deployment archive digest does not match the request"
        )

    _snapshot_root(snapshots_root)
    pending = snapshots_root / f".pending-{operation_id}"
    final = snapshots_root / operation_id
    if pending.exists() or pending.is_symlink() or final.exists() or final.is_symlink():
        raise DeploymentStagingError(
            "deployment-snapshot-conflict", "deployment snapshot operation already exists"
        )
    pending.mkdir(mode=0o700)
    context_root = pending / "context"
    overlay_root = pending / "overlay"
    context_root.mkdir(mode=0o700)
    overlay_root.mkdir(mode=0o700)

    inventory = plan["sourceInventory"]
    overlay = plan["overlay"]
    expected: dict[str, tuple[str, Mapping[str, Any] | str]] = {}
    for item in inventory:
        relative = _relative(item["path"], "source inventory path")
        expected[f"context/{relative}"] = ("context", item)
    for relative_raw, content in overlay.items():
        relative = _relative(relative_raw, "overlay path")
        expected[f"overlay/{relative}"] = ("overlay", content)
    if len(expected) != metadata.get("fileCount"):
        shutil.rmtree(pending)
        raise DeploymentStagingError(
            "deployment-context-invalid", "deployment archive file count differs from the plan"
        )

    seen: set[str] = set()
    written: list[dict[str, Any]] = []
    source_bytes = 0
    try:
        os.lseek(archive_fd, 0, os.SEEK_SET)
        with os.fdopen(os.dup(archive_fd), "rb") as raw_handle:
            with tarfile.open(fileobj=raw_handle, mode="r:") as archive:
                for member in archive:
                    expected_member = expected.get(member.name)
                    if (
                        expected_member is None
                        or member.name in seen
                        or not member.isfile()
                        or member.issparse()
                    ):
                        raise DeploymentStagingError(
                            "deployment-context-invalid", "deployment archive contains an unexpected member"
                        )
                    seen.add(member.name)
                    kind, identity = expected_member
                    relative = member.name.split("/", 1)[1]
                    if kind == "context":
                        assert isinstance(identity, Mapping)
                        expected_mode = 0o755 if identity["mode"] == "100755" else 0o644
                        if member.mode != expected_mode:
                            raise DeploymentStagingError(
                                "deployment-context-invalid", "deployment archive source mode differs"
                            )
                        if member.size < 0 or source_bytes + member.size > max_context_bytes:
                            raise DeploymentStagingError("deployment-context-too-large", "source content exceeds its admitted byte bound")
                        digest, size = _write_member(
                            archive,
                            member,
                            target=context_root / relative,
                            expected_digest=str(identity["contentDigest"]),
                            expected_size=None,
                            mode=expected_mode,
                        )
                        source_bytes += size
                        if source_bytes > max_context_bytes:
                            raise DeploymentStagingError(
                                "deployment-context-too-large", "deployment context exceeds the byte bound"
                            )
                        written.append(
                            {
                                "path": relative,
                                "mode": identity["mode"],
                                "size": size,
                                "sha256": digest,
                            }
                        )
                    else:
                        assert isinstance(identity, str)
                        content = identity.encode("utf-8")
                        if member.mode != 0o600:
                            raise DeploymentStagingError(
                                "deployment-context-invalid", "deployment archive overlay mode differs"
                            )
                        _write_member(
                            archive,
                            member,
                            target=overlay_root / relative,
                            expected_digest="sha256:" + hashlib.sha256(content).hexdigest(),
                            expected_size=len(content),
                            mode=0o600,
                        )
        if seen != set(expected) or contract.canonical_digest(written) != metadata.get("contextDigest"):
            raise DeploymentStagingError(
                "deployment-context-invalid", "deployment snapshot does not match the exact plan"
            )
        pending.replace(final)
    except Exception:
        if pending.exists() and not pending.is_symlink():
            shutil.rmtree(pending)
        raise
    return {
        "root": final,
        "contextRoot": final / "context",
        "overlayRoot": final / "overlay",
        "contextDigest": metadata["contextDigest"],
        "archiveDigest": metadata["archiveDigest"],
        "files": len(seen),
        "bytes": source_bytes,
    }


def remove_deployment_snapshot(path: Path, *, snapshots_root: Path) -> None:
    """Remove one exact daemon-owned snapshot without following links."""

    if path.parent != snapshots_root or path.is_symlink():
        raise DeploymentStagingError(
            "deployment-snapshot-unsafe", "deployment snapshot path is outside its private root"
        )
    if not path.exists():
        return
    observed = os.lstat(path)
    if not stat.S_ISDIR(observed.st_mode) or observed.st_uid != os.geteuid():
        raise DeploymentStagingError(
            "deployment-snapshot-unsafe", "deployment snapshot is not daemon-owned"
        )
    shutil.rmtree(path)


def cleanup_deployment_snapshot_root(snapshots_root: Path) -> None:
    """Reclaim transfer-only snapshots after daemon restart reconciliation."""

    if not snapshots_root.exists() and not snapshots_root.is_symlink():
        return
    _snapshot_root(snapshots_root)
    for child in snapshots_root.iterdir():
        if child.is_symlink() or not child.is_dir():
            raise DeploymentStagingError(
                "deployment-snapshot-unsafe", "deployment snapshot root contains an unsafe entry"
            )
        remove_deployment_snapshot(child, snapshots_root=snapshots_root)


__all__ = [
    "ARCHIVE_FORMAT",
    "DeploymentStagingError",
    "build_deployment_archive",
    "cleanup_deployment_snapshot_root",
    "materialize_deployment_snapshot",
    "reopen_archive_read_only",
    "remove_deployment_snapshot",
]
