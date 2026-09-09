from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
from typing import Any

import yaml

from instance_backup import (
    BackupError,
    create_backup,
    remove_owned_directory,
    read_manifest_with_file_digest,
    restore_backup,
    write_recovery_marker,
)


class PortabilityError(ValueError):
    """A portable instance package is invalid or unsafe."""


def _directory_identity(path: Path) -> tuple[int, int]:
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise PortabilityError("portable import target is unsafe")
    return int(info.st_dev), int(info.st_ino)


def _remove_materialized_target(path: Path, expected: tuple[int, int]) -> None:
    if not (path.exists() or path.is_symlink()):
        return
    try:
        remove_owned_directory(path, expected)
    except BackupError as exc:
        raise PortabilityError("portable import rollback target identity changed") from exc


_TRANSIENT_PREFIXES = (".stateport/", ".statedd/runtime/", "engine_sessions/")
_PORTABLE_EXCLUSIONS = (".git",)


def _portable_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    files = manifest.get("files", [])
    if not isinstance(files, list):
        raise PortabilityError("portable package manifest files must be a list")
    for item in files:
        path = item.get("path") if isinstance(item, dict) else None
        if not isinstance(path, str) or path.startswith("/") or "\\" in path or ".." in path.split("/"):
            raise PortabilityError("portable package contains an unsafe path")
        if any(path == prefix[:-1] or path.startswith(prefix) for prefix in _TRANSIENT_PREFIXES):
            raise PortabilityError(f"portable package contains transient engine/runtime state: {path}")
    return {
        "formatVersion": "stateport.instance-portable/v1",
        "backupFormat": manifest.get("formatVersion"),
        "instanceId": manifest.get("instanceId"),
        "sourceIdentity": manifest.get("sourceIdentity"),
        "archiveDigest": manifest.get("archiveDigest"),
        "fileCount": len(files),
        "inventory": manifest.get(
            "inventory",
            {
                "included": files,
                "excluded": [
                    {"path": path, "reason": "portable_runtime_state", "present": False}
                    for path in _PORTABLE_EXCLUSIONS
                ],
            },
        ),
        "engineSessions": {"included": False, "reason": "portable packages contain canonical instance files only"},
        "machinePaths": {"included": False, "reason": "manifest paths are repository-relative"},
    }


def _portable_document_projection(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise PortabilityError(f"portable metadata is unsafe: {path.name}")
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise PortabilityError(f"portable metadata is invalid: {path.name}") from exc
    if not isinstance(value, dict):
        raise PortabilityError(f"portable metadata is invalid: {path.name}")
    projected = copy.deepcopy(value)
    template = value.get("template")
    canonical_lock = (
        path.name == "lock.yaml"
        and value.get("formatVersion") == "statedd.lock/v1"
        and isinstance(template, dict)
        and template.get("instanceSchemaVersion") == "statedd.stateport.io/instance/v1alpha1"
    )
    embedded_relative: str | None = None
    if canonical_lock:
        relative = template.get("sourcePath")
        if isinstance(relative, str) and not Path(relative).is_absolute() and relative != ".":
            if "\\" in relative or "\x00" in relative or any(part in {"", ".", ".."} for part in relative.split("/")):
                raise PortabilityError("portable embedded source path is not confined")
            from template_validator.validator import validate_instance

            if not validate_instance(path.parent.parent).ok:
                raise PortabilityError("portable embedded source failed exact StateSpec validation")
            embedded_relative = relative

    def scrub(item: Any) -> None:
        if isinstance(item, dict):
            if (
                item.get("formatVersion") == "statedd.source/v1"
                and item.get("kind") == "local"
                and isinstance(item.get("path"), str)
            ):
                item["path"] = "."
            for key, child in item.items():
                if key in {"checkoutLocation", "sourcePath"} and isinstance(child, str):
                    item[key] = "."
                elif key == "rootIdentity" and isinstance(child, dict) and isinstance(child.get("path"), str):
                    child["path"] = "."
                    scrub(child)
                else:
                    scrub(child)
        elif isinstance(item, list):
            for child in item:
                scrub(child)

    scrub(projected)
    if embedded_relative is not None:
        projected["template"]["sourcePath"] = embedded_relative
        projected["template"]["source"]["checkoutLocation"] = embedded_relative
    if canonical_lock:
        class IndentedDumper(yaml.SafeDumper):
            def increase_indent(self, flow: bool = False, indentless: bool = False) -> None:
                return super().increase_indent(flow, False)

        return yaml.dump(projected, Dumper=IndentedDumper, sort_keys=True).encode("utf-8")
    return (json.dumps(projected, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def export_portable(instance_root: str | Path, archive_path: str | Path) -> dict[str, Any]:
    archive = Path(archive_path)
    temporary = archive.with_name(
        f".{archive.name}.stateport-exporting-{secrets.token_hex(12)}"
    )
    staging_identity: tuple[int, int] | None = None

    def cleanup_staging() -> None:
        if staging_identity is None:
            return
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        parent_fd = -1
        try:
            parent_fd = os.open(archive.parent, flags)
            current = os.stat(temporary.name, dir_fd=parent_fd, follow_symlinks=False)
            if (current.st_dev, current.st_ino) == staging_identity:
                os.unlink(temporary.name, dir_fd=parent_fd)
        except (FileNotFoundError, OSError):
            pass
        finally:
            if parent_fd >= 0:
                os.close(parent_fd)

    try:
        source = Path(instance_root)
        source_identity = _directory_identity(source)
        projections = {
            ".statedd/lock.yaml": _portable_document_projection(source / ".statedd" / "lock.yaml")
        }
        upgrade_receipt = source / ".statedd" / "upgrade-receipt.yaml"
        if upgrade_receipt.exists():
            projections[".statedd/upgrade-receipt.yaml"] = _portable_document_projection(
                upgrade_receipt
            )
        result = create_backup(
            source,
            temporary,
            archive_format="zip",
            excluded_prefixes=_PORTABLE_EXCLUSIONS,
            file_projections=projections,
            expected_root_identity=source_identity,
        )
        temporary_info = os.stat(temporary, follow_symlinks=False)
        if not stat.S_ISREG(temporary_info.st_mode):
            raise PortabilityError("portable export staging is not a regular file")
        staging_identity = (int(temporary_info.st_dev), int(temporary_info.st_ino))
        if _directory_identity(source) != source_identity:
            raise PortabilityError("instance root identity changed during portable export")
        portable = _portable_manifest(result.manifest)
    except PortabilityError:
        cleanup_staging()
        raise
    except (BackupError, OSError, TypeError) as exc:
        cleanup_staging()
        raise PortabilityError(str(exc)) from exc
    try:
        if archive.exists() or archive.is_symlink():
            raise PortabilityError("portable archive destination already exists")
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        parent_fd = os.open(archive.parent, flags)
        try:
            temporary_fd = os.open(
                temporary.name,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_fd,
            )
            temporary_info = os.fstat(temporary_fd)
            if not stat.S_ISREG(temporary_info.st_mode):
                raise PortabilityError("portable export staging is not a regular file")
            staging_identity = (int(temporary_info.st_dev), int(temporary_info.st_ino))

            def verify_published() -> None:
                published_fd = os.open(
                    archive.name,
                    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=parent_fd,
                )
                try:
                    published_info = os.fstat(published_fd)
                    if (published_info.st_dev, published_info.st_ino) != (
                        temporary_info.st_dev,
                        temporary_info.st_ino,
                    ):
                        raise PortabilityError("portable export destination inode changed")
                    digest = hashlib.sha256()
                    os.lseek(published_fd, 0, os.SEEK_SET)
                    for block in iter(lambda: os.read(published_fd, 1024 * 1024), b""):
                        digest.update(block)
                    if "sha256:" + digest.hexdigest() != result.archive_file_digest:
                        raise PortabilityError("portable export destination bytes changed")
                finally:
                    os.close(published_fd)

            # A hard-link publication gives this external export no-overwrite
            # semantics without relying on a platform-specific renameat2 call.
            os.link(
                temporary.name,
                archive.name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
                follow_symlinks=False,
            )
            try:
                os.fsync(parent_fd)
            except OSError as exc:
                write_recovery_marker(
                    archive,
                    {
                        "formatVersion": "stateport.portable-export-recovery/v1",
                        "status": "operator_inspection_required",
                        "archiveDigest": result.archive_digest,
                        "archiveFileDigest": result.archive_file_digest,
                        "reason": "portable export publication parent fsync failed",
                    },
                )
                raise PortabilityError("portable export publication requires operator inspection") from exc
            verify_published()
            os.unlink(temporary.name, dir_fd=parent_fd)
            staging_identity = None
            try:
                os.fsync(parent_fd)
            except OSError as exc:
                write_recovery_marker(
                    archive,
                    {
                        "formatVersion": "stateport.portable-export-recovery/v1",
                        "status": "operator_inspection_required",
                        "archiveDigest": result.archive_digest,
                        "archiveFileDigest": result.archive_file_digest,
                        "reason": "portable export cleanup parent fsync failed",
                    },
                )
                raise PortabilityError("portable export cleanup requires operator inspection") from exc
            verify_published()
        finally:
            if "temporary_fd" in locals():
                os.close(temporary_fd)
            os.close(parent_fd)
    except (OSError, PortabilityError) as exc:
        cleanup_staging()
        if isinstance(exc, PortabilityError):
            raise
        raise PortabilityError("portable archive could not be published") from exc
    try:
        source_device = source.stat().st_dev
        archive_device = archive.parent.stat().st_dev
    except OSError as exc:
        raise PortabilityError("portable export storage identity could not be observed") from exc
    return {
        "formatVersion": "stateport.instance-portable/v1",
        "archive": archive.as_posix(),
        "archiveDigest": result.archive_digest,
        "archiveFileDigest": result.archive_file_digest,
        "storage": {
            "class": "external_archive_path",
            "survivesOriginalInstanceDeletion": True,
            "survivesSourceVolumeDeletion": source_device != archive_device,
        },
        "manifest": portable,
    }


def inspect_portable(archive_path: str | Path) -> dict[str, Any]:
    archive = Path(archive_path)
    try:
        manifest, archive_file_digest = read_manifest_with_file_digest(archive)
        portable = _portable_manifest(manifest)
        portable["archiveFileDigest"] = archive_file_digest
        return portable
    except (BackupError, OSError, TypeError) as exc:
        raise PortabilityError(str(exc)) from exc


def import_portable(
    archive_path: str | Path,
    destination: str | Path,
    *,
    dry_run: bool = False,
    new_instance_id: str | None = None,
    expected_archive_digest: str | None = None,
    expected_archive_file_digest: str | None = None,
) -> dict[str, Any]:
    portable = inspect_portable(archive_path)
    if (
        expected_archive_digest is not None
        and portable.get("archiveDigest") != expected_archive_digest
    ) or (
        expected_archive_file_digest is not None
        and portable.get("archiveFileDigest") != expected_archive_file_digest
    ):
        raise PortabilityError("portable archive changed after inspection")
    materialized_identity: tuple[int, int] | None = None
    try:
        result = restore_backup(
            archive_path,
            destination,
            dry_run=dry_run,
            identity_policy="reidentify" if new_instance_id else "preserve",
            new_instance_id=new_instance_id,
            expected_archive_file_digest=str(portable["archiveFileDigest"]),
        )
        if not dry_run:
            materialized_identity = _directory_identity(Path(destination))
        if result.archive_digest != portable.get("archiveDigest"):
            raise PortabilityError("portable archive payload changed after inspection")
    except (BackupError, OSError, TypeError) as exc:
        if materialized_identity is not None:
            _remove_materialized_target(Path(destination), materialized_identity)
        raise PortabilityError(str(exc)) from exc
    except PortabilityError:
        if materialized_identity is not None:
            _remove_materialized_target(Path(destination), materialized_identity)
        raise
    return {"formatVersion": "stateport.instance-portable-import/v1", "archiveDigest": result.archive_digest, "destination": result.target_path.as_posix(), "instanceId": result.instance_id, "fileCount": result.file_count, "dryRun": result.dry_run, "manifest": portable}
