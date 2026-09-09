from __future__ import annotations

import copy
import ctypes
import errno
import fcntl
import hashlib
from functools import wraps
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from statedd_core import (
    CanonicalSourceIdentity,
    ResolvedSource,
    build_state_ir,
    build_state_pack,
    create_instance,
    describe_template_source,
    load_builtin_source_contract,
    load_source_contract,
    load_template_manifest,
    normalize_canonical_source_descriptor,
    parse_yaml_text,
    resolve_source_contract,
)
from template_validator.validator import validate_instance
from instance_backup import (
    BackupError,
    create_backup,
    read_manifest,
    restore_backup,
    restore_staging_retained,
)
from instance_catalog import CatalogError, CatalogSchemaError, InstanceCatalog
from instance_catalog.catalog import CatalogConflictError, catalog_lock, reviewed_name_change
from stateport_persistent_app.repository_content import (
    RepositoryContentError,
    repository_content_snapshot,
)
from stateport_persistent_app.template_adapters import (
    TemplateAdapterError,
    TemplateAdapterRegistry,
)


FORMAT = "stateport.persistent-local/v1"
CATALOG_FORMAT = "stateport.instance-catalog/v1"
APPROVAL_FORMAT = "stateport.exact-approval/v1"
RESTORE_PLAN_FORMAT = "stateport.restore-plan/v1"
RESTORE_APPROVAL_FORMAT = "stateport.restore-approval/v1"
RESTORE_RECEIPT_FORMAT = "stateport.restore-receipt/v1"
RECOVERY_STATUS_FORMAT = "stateport.recovery-status/v1"
SOURCE_ACCESS_FORMAT = "stateport.source-access/v1"
TEMPLATE_IMPORT_PLAN_FORMAT = "stateport.template-import-plan/v1"
TEMPLATE_INSTALL_RECEIPT_FORMAT = "stateport.template-install-receipt/v1"
MANAGED_INCARNATION_FORMAT = "stateport.managed-incarnation/v1"
_MANAGED_INCARNATION_PATH = ".stateport/managed-incarnation.json"
_RESTORE_STATUS_ARTIFACT_LIMIT = 4096
_RESTORE_ARTIFACT_BYTES_LIMIT = 256 * 1024
_RESTORE_INVENTORY_BYTES_LIMIT = 16 * 1024 * 1024
_ID = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_HEX = re.compile(r"^[0-9a-f]{64}$")
_GIT_OID = re.compile(r"^[0-9a-f]{40}$")
_SOURCE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_BOOTSTRAP_PATH_FIELD = re.compile(r"\{([a-z][a-z0-9_]*)\}")
_RENAME_NOREPLACE = 1
_SYS_RENAMEAT2 = 316
_renameat2: Any | None = None
_REPO_ROOT = Path(__file__).resolve().parents[4]
_STUDYSTATE_CATALOG = _REPO_ROOT / "sources" / "canonical" / "studydd.yaml"
_ALLOWED_IMPORT_FILES = {
    "NEXT_ACTIONS.md": "current_state",
    "state/STUDY_STATE.yaml": "current_state",
    "state/SKILL_MAP.yaml": "current_state",
    "state/LEARNER_PROFILE.yaml": "current_state",
    "state/ACTIVITY_STATE.yaml": "current_state",
    "sources/SOURCE_STATE.yaml": "source_state",
    "sources/SOURCE_INDEX.md": "source_state",
    "reviews/REVIEW_STATE.yaml": "review_state",
    "reviews/REVIEW_QUEUE.md": "review_state",
    "reviews/REVIEW_OVERRIDES.md": "review_state",
    "activities/ACTIVITY_LOG.md": "audit_history",
    "sessions/SESSION_LOG.md": "session_history",
}
_GENERATED_IMPORT_PREFIXES = (
    "state/CURRENT_CONTEXT.md",
    "state/EVIDENCE_INDEX.yaml",
    "sessions/SESSION_SUMMARIES.md",
    ".studydd/",
)


class AppError(ValueError):
    """A safe, user-facing local application error."""


class ApplicationRenameError(AppError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


class BootstrapError(AppError):
    pass


class ApprovalError(AppError):
    pass


class ServiceError(AppError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _managed_incarnation_binding(
    root: Path,
    *,
    expected_instance_id: str | None = None,
) -> dict[str, Any]:
    """Bind a managed root to a random marker and the marker's own inode."""

    marker = root / _MANAGED_INCARNATION_PATH
    try:
        before = os.lstat(marker)
    except OSError as exc:
        raise AppError("managed instance incarnation marker is unavailable") from exc
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 4096:
        raise AppError("managed instance incarnation marker is unsafe")
    try:
        descriptor = os.open(
            marker,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise AppError("managed instance incarnation marker is unavailable") from exc
    try:
        payload = os.read(descriptor, 4097)
        after = os.fstat(descriptor)
        fsid = os.fstatvfs(descriptor).f_fsid
        if type(fsid) is not int or not 0 < fsid < 2**64:
            raise AppError("managed instance filesystem identity is unavailable")
    finally:
        os.close(descriptor)
    before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_nlink,
    )
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_nlink,
    )
    if before_identity != after_identity or len(payload) > 4096:
        raise AppError("managed instance incarnation marker changed during validation")
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AppError("managed instance incarnation marker is invalid") from exc
    if (
        not isinstance(value, Mapping)
        or set(value) != {"formatVersion", "instanceId", "incarnationId", "createdAt"}
        or value.get("formatVersion") != MANAGED_INCARNATION_FORMAT
        or not isinstance(value.get("instanceId"), str)
        or (expected_instance_id is not None and value.get("instanceId") != expected_instance_id)
        or not isinstance(value.get("incarnationId"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", str(value.get("incarnationId")))
        or not isinstance(value.get("createdAt"), str)
    ):
        raise AppError("managed instance incarnation marker is invalid")
    return {
        "formatVersion": MANAGED_INCARNATION_FORMAT,
        "markerPath": _MANAGED_INCARNATION_PATH,
        "markerDigest": _digest(payload),
        "markerFilesystem": {
            "device": after.st_dev,
            "inode": after.st_ino,
            "filesystemId": f"statvfs:{fsid:016x}",
            "kind": "regular_file",
        },
    }


def _managed_incarnation_equivalent(expected: Any, observed: Mapping[str, Any]) -> bool:
    if not isinstance(expected, Mapping) or not isinstance(expected.get("markerFilesystem"), Mapping):
        return False
    old = dict(expected["markerFilesystem"])
    new = dict(observed["markerFilesystem"])
    if any(type(old.get(key)) is not int or old[key] < 0 for key in ("device", "inode")):
        return False
    if "filesystemId" in old:
        # Keep inode and persistent filesystem ID; only mount-local device IDs vary.
        old.pop("device", None)
        new.pop("device", None)
    else:
        # Legacy comparison retains its original exact device/inode requirement.
        new.pop("filesystemId", None)
    return secrets.compare_digest(_digest({**expected, "markerFilesystem": old}),
                                  _digest({**observed, "markerFilesystem": new}))


def _managed_incarnation_matches(
    root: Path,
    instance_id: str,
    expected: Any,
) -> bool:
    if not isinstance(expected, Mapping):
        return False
    try:
        observed = _managed_incarnation_binding(
            root,
            expected_instance_id=instance_id,
        )
    except AppError:
        return False
    return _managed_incarnation_equivalent(expected, observed)


def initialize_instance_repository(root: Path | str) -> str:
    """Create the exact local Git base required before any governed write.

    Instance creation owns this initialization.  Imported legacy instances
    remain untouched and are ineligible for write-capable runs until an
    operator establishes their repository identity explicitly.
    """

    target = Path(root).resolve(strict=True)
    if target.is_symlink() or not target.is_dir() or (target / ".git").exists():
        raise AppError("instance repository initialization requires a new safe directory")
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "LC_ALL": "C.UTF-8",
        "GIT_AUTHOR_NAME": "StatePort",
        "GIT_AUTHOR_EMAIL": "stateport@example.invalid",
        "GIT_COMMITTER_NAME": "StatePort",
        "GIT_COMMITTER_EMAIL": "stateport@example.invalid",
        "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+0000",
        "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+0000",
    }

    def run(arguments: list[str]) -> str:
        completed = subprocess.run(
            ["git", "-C", str(target), *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            shell=False,
            env=environment,
        )
        if completed.returncode:
            raise AppError("instance Git base could not be initialized")
        return completed.stdout.strip()

    run(["init", "--initial-branch=main", "--template="])
    run(["add", "--all"])
    run([
        "-c", "core.hooksPath=/dev/null",
        "-c", "commit.gpgSign=false",
        "commit", "--no-verify", "-m", "Initialize StatePort instance",
    ])
    identity = run(["rev-parse", "HEAD"])
    if not re.fullmatch(r"[0-9a-f]{40,64}", identity):
        raise AppError("initialized instance Git base is invalid")
    if run(["status", "--porcelain=v1", "--untracked-files=all"]):
        raise AppError("initialized instance Git base is not clean")
    return identity


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def _digest(value: Any) -> str:
    raw = value if isinstance(value, bytes) else _canonical(value)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _file_digest(path: Path) -> str:
    return _digest(path.read_bytes())


def _resolve_renameat2() -> Any:
    global _renameat2
    if _renameat2 is not None:
        return _renameat2
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
        _renameat2 = renameat2
        return _renameat2
    syscall = getattr(libc, "syscall", None)
    if syscall is None:
        raise AppError("atomic no-replace promotion is unavailable")
    syscall.argtypes = [
        ctypes.c_long,
        ctypes.c_long,
        ctypes.c_char_p,
        ctypes.c_long,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    syscall.restype = ctypes.c_long
    _renameat2 = ("syscall", syscall)
    return _renameat2


def _rename_no_replace(
    source_parent: int,
    source_name: str,
    destination_parent: int,
    destination_name: str,
) -> None:
    """Promote one descriptor-relative path without replacing concurrent state."""

    if not sys.platform.startswith("linux"):
        raise AppError("atomic no-replace promotion is unavailable")
    resolved = _resolve_renameat2()
    if isinstance(resolved, tuple):
        _, syscall = resolved
        result = syscall(
            _SYS_RENAMEAT2,
            source_parent,
            os.fsencode(source_name),
            destination_parent,
            os.fsencode(destination_name),
            _RENAME_NOREPLACE,
        )
    else:
        result = resolved(
            source_parent,
            os.fsencode(source_name),
            destination_parent,
            os.fsencode(destination_name),
            _RENAME_NOREPLACE,
        )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise AppError("destination appeared during promotion")
    if error_number in {
        errno.ENOSYS,
        errno.EINVAL,
        getattr(errno, "EOPNOTSUPP", errno.EINVAL),
        getattr(errno, "ENOTSUP", errno.EINVAL),
    }:
        raise AppError("atomic no-replace promotion is unavailable")
    raise OSError(error_number, os.strerror(error_number), destination_name)


def _atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists() and path.is_symlink():
        raise AppError(f"refusing to replace symlink: {path}")
    fd, raw = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(raw, mode)
        os.replace(raw, path)
    finally:
        try:
            os.unlink(raw)
        except FileNotFoundError:
            pass


def _write_json(path: Path, value: Any, mode: int = 0o600) -> None:
    _atomic_write(path, _canonical(value), mode)


def _write_json_new(path: Path, value: Any, mode: int = 0o600) -> None:
    """Create one immutable JSON artifact without replacing prior history."""

    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.is_symlink() or path.exists() or path.is_symlink():
        raise AppError("immutable operation artifact already exists or is unsafe")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, mode)
    except FileExistsError as exc:
        raise AppError("immutable operation artifact already exists") from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(_canonical(value))
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, mode)
        parent_descriptor = os.open(
            path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _parse_utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise AppError(f"{label} is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise AppError(f"{label} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise AppError(f"{label} is invalid")
    return parsed


def _yaml_dump(value: Any) -> bytes:
    try:
        import yaml

        class _IndentedSafeDumper(yaml.SafeDumper):
            def increase_indent(
                self, flow: bool = False, indentless: bool = False
            ) -> None:
                return super().increase_indent(flow, False)

        return yaml.dump(
            value,
            Dumper=_IndentedSafeDumper,
            sort_keys=False,
            allow_unicode=True,
        ).encode("utf-8")
    except ImportError as exc:  # pragma: no cover - requirements includes PyYAML
        raise AppError("PyYAML is required for typed StudyState bootstrap") from exc


def _safe_relative(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise AppError("path must be a non-empty POSIX relative path")
    candidate = _BOOTSTRAP_PATH_FIELD.sub("__field__", value)
    if "{" in candidate or "}" in candidate:
        raise AppError(f"unsafe contract path: {value}")
    path = Path(candidate)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise AppError(f"unsafe contract path: {value}")
    return value


def _render_bootstrap_path(value: str, fields: Mapping[str, Any]) -> str:
    _safe_relative(value)

    def substitute(match: re.Match[str]) -> str:
        field_id = match.group(1)
        field = fields.get(field_id)
        if not isinstance(field, str) or not _ID.fullmatch(field):
            raise BootstrapError(
                f"bootstrap destination field {field_id} must be a safe identifier"
            )
        return field

    rendered = _BOOTSTRAP_PATH_FIELD.sub(substitute, value)
    _safe_relative(rendered)
    return rendered


def _safe_instance_root(path: Path, *, must_exist: bool = False) -> Path:
    path = Path(path).expanduser()
    if path.is_symlink():
        raise AppError(f"instance path must not be a symlink: {path}")
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if current.is_symlink():
            raise AppError(f"instance path has a symlinked ancestor: {current}")
    if must_exist and not absolute.is_dir():
        raise AppError(f"instance path is not a directory: {absolute}")
    return absolute


@dataclass(frozen=True)
class LocalLayout:
    config_root: Path
    data_root: Path
    state_root: Path

    @classmethod
    def from_environment(cls) -> "LocalLayout":
        config = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "stateport"
        data = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "stateport"
        state = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")) / "stateport"
        return cls(config.expanduser().resolve(), data.expanduser().resolve(), state.expanduser().resolve())

    @property
    def config_file(self) -> Path:
        return self.config_root / "config.json"

    @property
    def identity_file(self) -> Path:
        return self.config_root / "operator.json"

    @property
    def catalog_file(self) -> Path:
        return self.data_root / "catalog" / "instances.json"

    @property
    def external_catalog_file(self) -> Path:
        return self.data_root / "catalog" / "external-instances.json"

    @property
    def instances_root(self) -> Path:
        return self.data_root / "instances"

    @property
    def source_cache_root(self) -> Path:
        return self.data_root / "sources"

    @property
    def backups_root(self) -> Path:
        return self.data_root / "backups"

    @property
    def settings_root(self) -> Path:
        return self.data_root / "settings"

    @property
    def operations_root(self) -> Path:
        return self.state_root / "operations"

    @property
    def source_access_root(self) -> Path:
        return self.state_root / "source-access"

    @property
    def runtime_root(self) -> Path:
        return self.state_root / "runtime"

    @property
    def logs_root(self) -> Path:
        return self.state_root / "logs"

    def initialize(self, *, source_mirror: str | None = None) -> dict[str, Any]:
        for path in (
            self.config_root,
            self.data_root,
            self.state_root,
            self.catalog_file.parent,
            self.instances_root,
            self.source_cache_root,
            self.backups_root,
            self.settings_root,
            self.operations_root,
            self.source_access_root,
            self.runtime_root,
            self.logs_root,
        ):
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(path, 0o700)
        current: dict[str, Any] = {}
        if self.config_file.is_file():
            try:
                current = json.loads(self.config_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise AppError(f"configuration is invalid: {exc}") from exc
        mirror = source_mirror or current.get("sourceMirrors", {}).get("studydd") or os.environ.get("STATEPORT_STUDYDD_MIRROR")
        config = {
            "formatVersion": FORMAT,
            "schemaVersion": 1,
            "configRoot": self.config_root.as_posix(),
            "dataRoot": self.data_root.as_posix(),
            "stateRoot": self.state_root.as_posix(),
            "instancesRoot": self.instances_root.as_posix(),
            "sourceCacheRoot": self.source_cache_root.as_posix(),
            "backupRoot": self.backups_root.as_posix(),
            "settingsRoot": self.settings_root.as_posix(),
            "sourceMirrors": {"studydd": str(Path(mirror).expanduser().resolve())} if mirror else {},
        }
        _write_json(self.config_file, config)
        if not self.identity_file.exists():
            _write_json(self.identity_file, {"formatVersion": "stateport.operator/v1", "operatorId": "local-operator", "createdAt": _now()}, 0o600)
        os.chmod(self.identity_file, 0o600)
        # InstanceCatalog owns creation and persistence of the canonical catalog.
        # Do not silently rewrite an older catalog shape here; callers receive a
        # migration diagnostic from PersistentCatalog instead.
        return config

    def status(self) -> dict[str, Any]:
        return {
            "formatVersion": FORMAT,
            "initialized": self.config_file.is_file(),
            "configRoot": self.config_root.as_posix(),
            "dataRoot": self.data_root.as_posix(),
            "stateRoot": self.state_root.as_posix(),
            "instancesRoot": self.instances_root.as_posix(),
            "sourceCacheRoot": self.source_cache_root.as_posix(),
            "backupRoot": self.backups_root.as_posix(),
            "operatorConfigured": self.identity_file.is_file() and self.identity_file.stat().st_mode & 0o077 == 0,
        }

    def uninstall_metadata(self) -> dict[str, Any]:
        if self.config_root.exists():
            shutil.rmtree(self.config_root)
        if self.state_root.exists():
            shutil.rmtree(self.state_root)
        if self.catalog_file.parent.exists():
            shutil.rmtree(self.catalog_file.parent)
        if self.source_cache_root.exists():
            shutil.rmtree(self.source_cache_root)
        if self.settings_root.exists():
            shutil.rmtree(self.settings_root)
        return {"ok": True, "action": "metadata-removed", "instancesPreserved": self.instances_root.exists(), "backupsPreserved": self.backups_root.exists(), "sourceCacheDisposable": True}


def _load_json(path: Path, default: Any) -> Any:
    if not path.is_file():
        return copy.deepcopy(default)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AppError(f"invalid JSON metadata {path}: {exc}") from exc


def _catalog_mutation(method):
    @wraps(method)
    def serialized(self, *args, **kwargs):
        # All external writers share one outer lock. Canonical operations take
        # their existing inner lock in this order; no inverse order is used.
        with catalog_lock(self.layout.external_catalog_file.with_suffix(".json.lock")):
            return method(self, *args, **kwargs)
    return serialized


class PersistentCatalog:
    def __init__(self, layout: LocalLayout):
        self.layout = layout
        self._catalog: InstanceCatalog | None = None

    def _external_load(self) -> list[dict[str, Any]]:
        value = _load_json(self.layout.external_catalog_file, {"formatVersion": "stateport.external-catalog/v1", "entries": []})
        if not isinstance(value, Mapping) or value.get("formatVersion") != "stateport.external-catalog/v1" or not isinstance(value.get("entries"), list):
            raise AppError("external repository catalog is invalid")
        if any(not isinstance(item, Mapping) for item in value["entries"]):
            raise AppError("external repository catalog contains an invalid entry")
        return [dict(item) for item in value["entries"]]

    def _external_write(self, entries: list[dict[str, Any]]) -> None:
        _write_json(self.layout.external_catalog_file, {"formatVersion": "stateport.external-catalog/v1", "entries": entries})

    @staticmethod
    def _external_entry(value: Mapping[str, Any]) -> dict[str, Any]:
        path = Path(str(value.get("path", ""))).expanduser()
        filesystem = value.get("filesystem") if isinstance(value.get("filesystem"), Mapping) else {}
        state = "missing"
        if path.is_absolute() and path.is_dir() and not path.is_symlink():
            info = os.lstat(path)
            state = "present" if filesystem.get("device") == info.st_dev and filesystem.get("inode") == info.st_ino else "stale"
            filesystem = {"device": info.st_dev, "inode": info.st_ino, "kind": "directory"}
        if state == "present":
            expected_content = value.get("contentIdentity")
            if not isinstance(expected_content, Mapping):
                state = "stale"
            else:
                try:
                    observed_content = repository_content_snapshot(path).identity
                except RepositoryContentError as exc:
                    state = "stale" if exc.code == "repository_content_changed" else "unsafe"
                else:
                    if dict(expected_content) != observed_content:
                        state = "stale"
        return {
            "instanceId": str(value["instanceId"]),
            "name": str(value["name"]),
            "path": path.as_posix(),
            "status": str(value.get("status", "active")),
            "adoption": {"mode": "registered", "readOnly": True},
            "filesystem": dict(filesystem),
            "contentIdentity": dict(value.get("contentIdentity", {})) if isinstance(value.get("contentIdentity"), Mapping) else None,
            "pathState": state,
            "previousPaths": list(value.get("previousPaths", [])),
            "createdAt": str(value.get("createdAt", _now())),
            "updatedAt": str(value.get("updatedAt", _now())),
            "lastValidatedAt": str(value.get("lastValidatedAt", _now())),
            "metadata": dict(value.get("metadata", {})) if isinstance(value.get("metadata"), Mapping) else {},
            "applicationId": str(value.get("applicationId", "nixos-infrastructure")),
            "observedSource": dict(value.get("source", {})) if isinstance(value.get("source"), Mapping) else {},
            "lastVerifiedAt": str(value.get("lastVerifiedAt", _now())),
            "lastBackup": value.get("lastBackup"),
        }

    @_catalog_mutation
    def register_external(self, path: Path, *, instance_id: str, name: str, application_id: str, source: Mapping[str, Any]) -> dict[str, Any]:
        root = _safe_instance_root(path, must_exist=True).resolve(strict=True)
        if not re.fullmatch(r"[a-z][a-z0-9-]{1,63}", instance_id):
            raise AppError("external application instance identity is invalid")
        if not isinstance(name, str) or not name.strip() or len(name) > 120:
            raise AppError("external application name is invalid")
        existing = self.list()
        for item in existing:
            if item.get("instanceId") == instance_id:
                if Path(str(item.get("path", ""))).resolve() == root and item.get("pathState") == "present":
                    return item
                raise AppError("application instance identity is already registered")
        if any(Path(str(item.get("path", ""))).resolve() == root for item in existing if item.get("path")):
            raise AppError("repository is already registered")
        try:
            content_identity = repository_content_snapshot(root).identity
        except RepositoryContentError as exc:
            raise AppError(str(exc)) from exc
        observed_source = dict(source)
        inspected_content_identity = observed_source.get("contentIdentity")
        if inspected_content_identity is not None and inspected_content_identity != content_identity:
            raise AppError("repository content identity changed since inspection")
        observed_source["contentIdentity"] = content_identity
        info = os.lstat(root)
        now = _now()
        entry = {
            "formatVersion": "stateport.external-catalog-entry/v1",
            "instanceId": instance_id,
            "name": name,
            "path": root.as_posix(),
            "status": "active",
            "applicationId": application_id,
            "source": observed_source,
            "filesystem": {"device": info.st_dev, "inode": info.st_ino, "kind": "directory"},
            "contentIdentity": content_identity,
            "metadata": {"applicationId": application_id, "source": observed_source, "externalRepository": True, "lastVerifiedAt": now, "lastBackup": None},
            "createdAt": now,
            "updatedAt": now,
            "lastValidatedAt": now,
            "lastVerifiedAt": now,
            "previousPaths": [],
        }
        entries = self._external_load()
        entries.append(entry)
        self._external_write(entries)
        return self._external_entry(entry)

    @_catalog_mutation
    def rebind_external_content(
        self,
        instance_id: str,
        *,
        expected_content_identity: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Advance one external identity after a receipt-bound StatePort mutation."""

        entries = self._external_load()
        for item in entries:
            if item.get("instanceId") != instance_id:
                continue
            if item.get("contentIdentity") != dict(expected_content_identity):
                raise AppError("external repository content identity changed before rebind")
            root = _safe_instance_root(Path(str(item.get("path", ""))), must_exist=True).resolve(strict=True)
            info = os.lstat(root)
            filesystem = item.get("filesystem")
            if (
                not isinstance(filesystem, Mapping)
                or filesystem.get("device") != info.st_dev
                or filesystem.get("inode") != info.st_ino
            ):
                raise AppError("external repository filesystem identity changed before rebind")
            try:
                content_identity = repository_content_snapshot(root).identity
            except RepositoryContentError as exc:
                raise AppError(str(exc)) from exc
            source = dict(item.get("source", {})) if isinstance(item.get("source"), Mapping) else {}
            source["contentIdentity"] = content_identity
            metadata = dict(item.get("metadata", {})) if isinstance(item.get("metadata"), Mapping) else {}
            metadata_source = dict(metadata.get("source", {})) if isinstance(metadata.get("source"), Mapping) else {}
            metadata_source["contentIdentity"] = content_identity
            now = _now()
            item.update({
                "contentIdentity": content_identity,
                "source": source,
                "metadata": {**metadata, "source": metadata_source},
                "updatedAt": now,
                "lastValidatedAt": now,
            })
            self._external_write(entries)
            rebound = self._external_entry(item)
            if rebound.get("pathState") != "present":
                raise AppError("external repository content identity rebind did not converge")
            return rebound
        raise AppError("external repository instance is not registered")

    def _canonical(self) -> InstanceCatalog:
        if self._catalog is None:
            if not self.layout.instances_root.is_dir():
                self.layout.initialize()
            self._catalog = InstanceCatalog(self.layout.catalog_file, self.layout.instances_root)
        return self._catalog

    def _entry(self, record: Any) -> dict[str, Any]:
        value = record.to_dict()
        metadata = dict(record.metadata)
        root = self.layout.instances_root / record.path
        value["path"] = root.as_posix()
        managed_incarnation = metadata.get("managedIncarnation")
        if managed_incarnation is not None and value.get("pathState") == "present":
            try:
                observed = _managed_incarnation_binding(root, expected_instance_id=record.instance_id)
            except (AppError, OSError):
                observed = None
            if observed is None or not _managed_incarnation_equivalent(managed_incarnation, observed):
                value["pathState"] = "stale"
            elif "filesystemId" not in managed_incarnation["markerFilesystem"]:
                upgraded = self._canonical().merge_metadata_if_matches(record, {"managedIncarnation": observed})
                if upgraded is not None:
                    metadata = dict(upgraded.metadata)
                    value["metadata"] = metadata
        value["applicationId"] = metadata.get("applicationId", "studydd")
        value["observedSource"] = dict(metadata.get("source", {}))
        value["lastVerifiedAt"] = metadata.get("lastVerifiedAt", record.last_validated_at)
        value["lastBackup"] = metadata.get("lastBackup")
        return value

    def register(
        self,
        path: Path,
        *,
        instance_id: str,
        name: str,
        source: Mapping[str, Any],
        application_id: str | None = None,
        managed_incarnation: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        root = _safe_instance_root(path, must_exist=True)
        selected_application_id = application_id or source.get("templateId", "studydd")
        metadata = {
            "applicationId": selected_application_id,
            "source": {
                key: value
                for key, value in source.items()
                if key not in {"checkoutLocation", "profile"}
            },
            "lastVerifiedAt": _now(),
            "lastBackup": None,
        }
        if managed_incarnation is not None:
            observed_incarnation = _managed_incarnation_binding(
                root,
                expected_instance_id=instance_id,
            )
            if not _managed_incarnation_equivalent(managed_incarnation, observed_incarnation):
                raise AppError("managed instance incarnation changed before catalog registration")
            metadata["managedIncarnation"] = observed_incarnation
        try:
            record = self._canonical().register(root, instance_id=instance_id, name=name, metadata=metadata)
        except CatalogSchemaError as exc:
            raise AppError("legacy catalog detected; run the explicit read-only catalog import before using StatePort") from exc
        except CatalogError as exc:
            raise AppError(str(exc)) from exc
        return self._entry(record)

    def import_instance(
        self,
        path: Path | str,
        *,
        instance_id: str | None = None,
        name: str | None = None,
        application_id: str | None = None,
        source: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Adopt an existing safe instance without reading its canonical files."""

        root = _safe_instance_root(Path(path), must_exist=True)
        metadata = (
            {
                "applicationId": application_id,
                "source": {
                    key: value
                    for key, value in source.items()
                    if key not in {"checkoutLocation", "profile"}
                },
            }
            if isinstance(application_id, str) and application_id and isinstance(source, Mapping)
            else {"applicationId": "unknown", "source": {"status": "not_observed"}}
        )
        try:
            record = self._canonical().import_instance(
                root,
                instance_id=instance_id,
                name=name,
                metadata=metadata,
            )
        except CatalogSchemaError as exc:
            raise AppError("legacy catalog detected; run the explicit read-only catalog import before using StatePort") from exc
        except CatalogError as exc:
            raise AppError(str(exc)) from exc
        return self._entry(record)

    def operation_owners(self) -> list[dict[str, Any]]:
        """Read current catalog membership without inspecting repository contents."""
        try:
            entries = [{"instanceId": record.instance_id,
                        "applicationId": record.metadata.get("applicationId", "studydd"),
                        "infrastructure": False}
                       for record in self._canonical().list(refresh=False)]
        except CatalogSchemaError as exc:
            raise AppError("legacy catalog detected; StatePort will not use it as a dashboard source") from exc
        entries.extend({"instanceId": entry["instanceId"],
                        "applicationId": entry.get("applicationId", "nixos-infrastructure"),
                        "repositoryPath": entry.get("path"),
                        "repositoryFilesystem": entry.get("filesystem"),
                        "infrastructure": entry.get("applicationId", "nixos-infrastructure") == "nixos-infrastructure"
                        and entry.get("metadata", {}).get("externalRepository") is True}
                       for entry in self._external_load())
        return entries

    def list(self) -> list[dict[str, Any]]:
        try:
            return [self._entry(record) for record in self._canonical().list()] + [self._external_entry(item) for item in self._external_load()]
        except CatalogSchemaError as exc:
            raise AppError("legacy catalog detected; StatePort will not use it as a dashboard source") from exc

    def get(self, instance_id: str) -> dict[str, Any]:
        for item in self._external_load():
            if item.get("instanceId") == instance_id:
                return self._external_entry(item)
        try:
            return self._entry(self._canonical().get(instance_id))
        except CatalogError as exc:
            raise AppError(str(exc)) from exc

    @_catalog_mutation
    def rename(self, instance_id: str, *, name: str, expected_name: str,
               actor_id: str, actor_role: str) -> dict[str, Any]:
        try:
            entries = self._external_load()
            for item in entries:
                if item.get("instanceId") != instance_id:
                    continue
                metadata, receipt, replayed = reviewed_name_change(
                    instance_id, item["name"], item.get("metadata", {}), name=name,
                    expected_name=expected_name, actor_id=actor_id, actor_role=actor_role,
                )
                if not replayed:
                    item.update(name=name, metadata=metadata, updatedAt=_now())
                    self._external_write(entries)
                break
            else:
                _record, receipt, replayed = self._canonical().rename_reviewed(
                    instance_id, name, expected_name=expected_name,
                    actor_id=actor_id, actor_role=actor_role,
                )
        except CatalogConflictError as exc:
            raise ApplicationRenameError("rename_conflict", str(exc)) from exc
        except CatalogError as exc:
            raise ApplicationRenameError("rename_invalid", str(exc)) from exc
        return {"formatVersion": "stateport.application-rename-result/v1",
                "instanceId": instance_id, "name": name, "receipt": receipt, "replayed": replayed}

    @_catalog_mutation
    def forget(self, instance_id: str) -> dict[str, Any]:
        external = self._external_load()
        retained = [item for item in external if item.get("instanceId") != instance_id]
        if len(retained) != len(external):
            self._external_write(retained)
            return {"ok": True, "instanceId": instance_id, "canonicalStatePreserved": True}
        try:
            self._canonical().forget(instance_id)
        except CatalogError as exc:
            raise AppError(str(exc)) from exc
        return {"ok": True, "instanceId": instance_id, "canonicalStatePreserved": True}

    def forget_if_matches(self, entry: Mapping[str, Any]) -> bool:
        """Forget only the exact canonical record returned by ``register``.

        This is a transaction rollback primitive.  It never removes instance
        files and refuses to touch external-repository registrations.
        """

        filesystem = entry.get("filesystem")
        relative_path: str | None = None
        absolute_path = entry.get("path")
        if isinstance(absolute_path, str):
            try:
                relative_path = Path(absolute_path).relative_to(
                    self.layout.instances_root
                ).as_posix()
            except ValueError:
                relative_path = None
        if (
            not isinstance(entry.get("instanceId"), str)
            or not isinstance(relative_path, str)
            or not isinstance(filesystem, Mapping)
            or not isinstance(entry.get("createdAt"), str)
        ):
            return False
        try:
            removed = self._canonical().forget_if_matches(
                str(entry["instanceId"]),
                path=relative_path,
                filesystem=filesystem,
                created_at=str(entry["createdAt"]),
            )
        except CatalogError:
            return False
        return removed is not None

    @_catalog_mutation
    def update(self, instance_id: str, **fields: Any) -> dict[str, Any]:
        external = self._external_load()
        for item in external:
            if item.get("instanceId") == instance_id:
                metadata = dict(item.get("metadata", {})) if isinstance(item.get("metadata"), Mapping) else {}
                metadata.update(fields)
                item["metadata"] = metadata
                item["updatedAt"] = _now()
                self._external_write(external)
                return self._external_entry(item)
        try:
            return self._entry(self._canonical().merge_metadata(instance_id, fields))
        except CatalogError as exc:
            raise AppError(str(exc)) from exc

    def rebind_replaced_directory(
        self, entry: Mapping[str, Any], expected_filesystem: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Rebind the exact canonical entry after lifecycle swaps its root inode."""

        absolute_path = entry.get("path")
        previous = entry.get("filesystem")
        if (
            not isinstance(entry.get("instanceId"), str)
            or not isinstance(absolute_path, str)
            or not isinstance(previous, Mapping)
            or not isinstance(entry.get("createdAt"), str)
        ):
            raise AppError("catalog replacement binding is invalid")
        try:
            relative = Path(absolute_path).relative_to(self.layout.instances_root).as_posix()
            record = self._canonical().rebind_replaced_directory(
                str(entry["instanceId"]),
                path=relative,
                previous_filesystem=previous,
                expected_filesystem=expected_filesystem,
                created_at=str(entry["createdAt"]),
            )
        except (CatalogError, ValueError) as exc:
            raise AppError(str(exc)) from exc
        return self._entry(record)

    def _read(self) -> dict[str, Any]:
        """Compatibility hook for creation rollback; never used as a source."""
        return {"entries": self.list()}


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        import yaml
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        try:
            value = parse_yaml_text(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            raise AppError(f"could not parse {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise AppError(f"{path} must contain a mapping")
    return value


def _read_yaml_optional(path: Path) -> dict[str, Any]:
    """Read a YAML mapping, returning an empty mapping when the file is absent.

    Registered application fixtures can expose an application descriptor and
    actions without the StateSpec-style instance/lock materialization; inspection
    must describe what is actually present instead of failing on a missing file.
    """
    if not path.is_file():
        return {}
    return _read_yaml(path)


def _scan_instance_files(root: Path) -> dict[str, list[str]]:
    """Classify files present in an instance that has no lock manifest.

    Files are reported as instance-owned application state; the ``.git`` working
    tree is excluded so internal version-control data is never exposed.
    """
    ownership = {owner: [] for owner in ("template", "instance", "generated", "override")}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(root).as_posix()
        if relative.startswith(".git/"):
            continue
        ownership["instance"].append(relative)
    return ownership


def _validate_id(value: str, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise AppError(f"{label} must match {_ID.pattern}")
    return value


def _render_node(node: Any, values: Mapping[str, Any]) -> Any:
    if isinstance(node, dict):
        if set(node) == {"field"}:
            field = node["field"]
            if field not in values:
                raise BootstrapError(f"bootstrap contract references unknown field: {field}")
            return values[field]
        return {key: _render_node(value, values) for key, value in node.items()}
    if isinstance(node, list):
        return [_render_node(value, values) for value in node]
    return node


def _bootstrap_contract(source_root: Path) -> dict[str, Any]:
    path = source_root / ".statedd" / "bootstrap.yaml"
    if path.is_symlink() or not path.is_file():
        raise BootstrapError("selected StudyState source does not declare .statedd/bootstrap.yaml")
    try:
        import yaml

        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (ImportError, OSError, UnicodeDecodeError) as exc:
        raise BootstrapError(f"could not read StudyState bootstrap contract: {exc}") from exc
    if not isinstance(value, dict) or value.get("formatVersion") != "studydd.bootstrap/v1":
        raise BootstrapError("unsupported StudyState bootstrap contract")
    fields = value.get("fields")
    writes = value.get("writes")
    if not isinstance(fields, list) or not isinstance(writes, list):
        raise BootstrapError("bootstrap contract requires fields and writes")
    return value


def validate_bootstrap(contract: Mapping[str, Any], supplied: Mapping[str, Any]) -> dict[str, Any]:
    fields = contract.get("fields", [])
    known = {item.get("id") for item in fields if isinstance(item, Mapping)}
    unknown = sorted(set(supplied) - known)
    if unknown:
        raise BootstrapError(f"unknown bootstrap fields: {', '.join(unknown)}")
    values: dict[str, Any] = {}
    for item in fields:
        if not isinstance(item, Mapping) or not isinstance(item.get("id"), str):
            raise BootstrapError("invalid bootstrap field declaration")
        field = item["id"]
        value = supplied.get(field, item.get("default"))
        if value is None and item.get("required"):
            raise BootstrapError(f"missing required bootstrap field: {field}")
        field_type = item.get("type")
        if field_type in {"string", "identifier", "enum"} and value is not None and not isinstance(value, str):
            raise BootstrapError(f"bootstrap field {field} must be a string")
        if field_type == "identifier" and value and not _ID.fullmatch(value):
            raise BootstrapError(f"bootstrap field {field} must be a safe identifier")
        if field_type == "enum" and value not in item.get("values", []):
            raise BootstrapError(f"bootstrap field {field} is not an accepted enum value")
        values[field] = value
    if values.get("seed_mode") == "synthetic-demo":
        values["learning_goal"] = values.get("learning_goal") or "Synthetic StudyState local contract demonstration"
    return values


def apply_bootstrap(contract: Mapping[str, Any], root: Path, supplied: Mapping[str, Any], *, template_root: Path | None = None) -> dict[str, Any]:
    values = validate_bootstrap(contract, supplied)
    written: list[str] = []
    rendered_seeds: list[tuple[Mapping[str, Any], str]] = []
    rendered_writes: list[tuple[Mapping[str, Any], str]] = []
    destinations: dict[str, str] = {}

    def admit_destination(raw_path: object) -> str:
        if not isinstance(raw_path, str):
            raise BootstrapError("bootstrap destination path is invalid")
        rendered = _render_bootstrap_path(raw_path, values)
        folded = rendered.casefold()
        for existing_folded, existing in destinations.items():
            if (
                folded == existing_folded
                or folded.startswith(existing_folded + "/")
                or existing_folded.startswith(folded + "/")
            ):
                raise BootstrapError(
                    f"bootstrap destination {rendered} conflicts with {existing}"
                )
        destinations[folded] = rendered
        return rendered

    for seed in contract.get("seeds", []):
        if not isinstance(seed, Mapping) or not isinstance(seed.get("path"), str) or not isinstance(seed.get("source"), str):
            raise BootstrapError("invalid bootstrap seed declaration")
        rendered_seeds.append((seed, admit_destination(seed["path"])))
    for write in contract["writes"]:
        if not isinstance(write, Mapping):
            raise BootstrapError("invalid bootstrap write declaration")
        rendered_writes.append((write, admit_destination(write.get("path"))))

    for seed, destination_path in rendered_seeds:
        if template_root is None:
            raise BootstrapError("bootstrap seeds require the resolved template root")
        source_path = _safe_relative(seed["source"])
        source = template_root / source_path
        destination = root / destination_path
        if source.is_symlink() or not source.is_file():
            raise BootstrapError(f"bootstrap seed source is not a safe file: {source_path}")
        if not destination.resolve().is_relative_to(root.resolve()):
            raise BootstrapError("bootstrap seed escapes instance root")
        _atomic_write(destination, source.read_bytes(), 0o600)
        written.append(destination_path)
    for write, rendered_path in rendered_writes:
        destination = root / rendered_path
        if not destination.resolve().is_relative_to(root.resolve()):
            raise BootstrapError("bootstrap write escapes instance root")
        if write.get("format") == "yaml":
            document = _render_node(write.get("document"), values)
            if not isinstance(document, dict):
                raise BootstrapError(f"bootstrap YAML document must be a mapping: {rendered_path}")
            _atomic_write(destination, _yaml_dump(document), 0o600)
        elif write.get("format") == "text":
            template = write.get("template")
            if not isinstance(template, str):
                raise BootstrapError(f"bootstrap text writer requires a template: {rendered_path}")
            text = template
            for key, value in values.items():
                text = text.replace("{" + key + "}", str(value or ""))
            _atomic_write(destination, text.encode("utf-8"), 0o600)
        else:
            raise BootstrapError(f"unsupported bootstrap writer format: {rendered_path}")
        written.append(rendered_path)
    return {"contract": contract["formatVersion"], "values": {"seedMode": values.get("seed_mode"), "targetId": values.get("target_id")}, "written": written}


class SourceCache:
    _FORMAT = "stateport.immutable-source-cache/v1"
    _POINTER_FORMAT = "stateport.immutable-source-cache-pointer/v1"
    _MAX_FILES = 32_768
    _MAX_FILE_BYTES = 64 * 1024 * 1024
    _MAX_TOTAL_BYTES = 512 * 1024 * 1024
    _MAX_BUNDLE_BYTES = 1024 * 1024 * 1024

    def __init__(self, layout: LocalLayout):
        self.layout = layout

    def resolve(self, contract: Any, mirror: str | None = None) -> Any:
        key = hashlib.sha256(f"{contract.repository}\0{contract.commit}".encode()).hexdigest()[:32]
        cache_root = _safe_instance_root(self.layout.source_cache_root)
        cache_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        for directory in (cache_root / "locks", cache_root / "contracts", cache_root / "immutable"):
            if directory.is_symlink():
                raise AppError("source cache path must not be a symlink")
            directory.mkdir(mode=0o700, exist_ok=True)
        lock_path = cache_root / "locks" / f"{key}.lock"
        if lock_path.is_symlink():
            raise AppError("source cache lock must not be a symlink")
        lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with lock_path.open("a+", encoding="utf-8") as lock:
            os.chmod(lock_path, 0o600)
            deadline = time.monotonic() + 30
            while True:
                try:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise AppError("source cache lock timed out")
                    time.sleep(0.05)
            try:
                return self._resolve_unlocked(contract, key, cache_root, mirror)
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def _resolve_unlocked(
        self,
        contract: Any,
        key: str,
        cache_root: Path,
        mirror: str | None = None,
    ) -> Any:
        pointer_path = cache_root / "contracts" / f"{key}.json"
        cached = self._cached_resolution(contract, pointer_path, cache_root)
        if cached is not None:
            return cached

        configured_mirror = mirror or os.environ.get("STATEPORT_STUDYDD_MIRROR")
        repository = self._validated_clone_source(contract.repository, configured_mirror)
        checkout_root = cache_root / f".{key}.checkout-{os.getpid()}-{secrets.token_hex(4)}"
        materializing = cache_root / "immutable" / f".{key}.materializing-{os.getpid()}-{secrets.token_hex(4)}"
        for temporary in (checkout_root, materializing):
            if temporary.exists() or temporary.is_symlink():
                raise AppError("source cache staging identity already exists")
        try:
            result = self._run_cache_git(
                ["clone", "--no-checkout", "--origin", "origin", repository, str(checkout_root)],
                failure="source cache clone failed; verify the configured credential-free repository or local mirror",
            )
            if result.returncode != 0:
                raise AppError("source cache clone failed; verify the configured credential-free repository or local mirror")
            checkout_result = self._run_cache_git(
                ["checkout", "--detach", contract.commit],
                cwd=checkout_root,
                failure="source cache checkout failed for the required immutable commit",
            )
            if checkout_result.returncode != 0:
                raise AppError("source cache checkout failed for the required immutable commit")
            origin_result = self._run_cache_git(
                ["remote", "set-url", "origin", contract.repository],
                cwd=checkout_root,
                failure="source cache origin binding failed",
            )
            if origin_result.returncode != 0:
                raise AppError("source cache origin binding failed")
            resolved = resolve_source_contract(contract, repository_override=checkout_root)
            marker = self._materialize(resolved, checkout_root, materializing)
            cache_digest = str(marker["cacheDigest"])
            destination = cache_root / "immutable" / cache_digest[7:]
            if destination.exists() or destination.is_symlink():
                try:
                    existing = self._resolved_from_cache(contract, cache_digest, cache_root)
                except AppError:
                    self._discard_cache_entry(destination)
                else:
                    shutil.rmtree(materializing)
                    self._write_pointer(pointer_path, contract, marker)
                    return existing
            os.replace(materializing, destination)
            self._fsync_directory(destination.parent)
            self._write_pointer(pointer_path, contract, marker)
            return self._resolved_from_cache(contract, cache_digest, cache_root)
        finally:
            if checkout_root.exists() or checkout_root.is_symlink():
                shutil.rmtree(checkout_root, ignore_errors=True)
            if materializing.exists() or materializing.is_symlink():
                shutil.rmtree(materializing, ignore_errors=True)

    def _cached_resolution(
        self,
        contract: Any,
        pointer_path: Path,
        cache_root: Path,
    ) -> ResolvedSource | None:
        if not pointer_path.exists() and not pointer_path.is_symlink():
            return None
        if pointer_path.is_symlink() or not pointer_path.is_file():
            raise AppError("source cache pointer is unsafe")
        try:
            pointer = _load_json(pointer_path, None)
        except AppError:
            pointer_path.unlink()
            return None
        if not isinstance(pointer, Mapping):
            pointer_path.unlink()
            return None
        expected = {
            "formatVersion": self._POINTER_FORMAT,
            "repository": contract.repository,
            "resolvedCommit": contract.commit,
        }
        if any(pointer.get(field) != value for field, value in expected.items()):
            pointer_path.unlink()
            return None
        if contract.expected_tree is None or pointer.get("resolvedTree") != contract.expected_tree:
            pointer_path.unlink()
            return None
        if (
            contract.expected_manifest_digest is not None
            and pointer.get("manifestDigest") != contract.expected_manifest_digest
        ):
            pointer_path.unlink()
            return None
        cache_digest = pointer.get("cacheDigest")
        if not isinstance(cache_digest, str) or not _SOURCE_DIGEST.fullmatch(cache_digest):
            pointer_path.unlink()
            return None
        try:
            return self._resolved_from_cache(contract, cache_digest, cache_root)
        except AppError:
            self._discard_cache_entry(cache_root / "immutable" / cache_digest[7:])
            pointer_path.unlink(missing_ok=True)
            return None

    def _write_pointer(
        self,
        path: Path,
        contract: Any,
        marker: Mapping[str, Any],
    ) -> None:
        _write_json(
            path,
            {
                "formatVersion": self._POINTER_FORMAT,
                "repository": contract.repository,
                "resolvedCommit": contract.commit,
                "resolvedTree": marker["resolvedTree"],
                "manifestDigest": marker["manifestDigest"],
                "sourceDigest": marker["sourceDigest"],
                "cacheDigest": marker["cacheDigest"],
            },
        )
        self._fsync_directory(path.parent)

    def _materialize(
        self,
        resolved: ResolvedSource,
        checkout_root: Path,
        destination: Path,
    ) -> dict[str, Any]:
        destination.mkdir(mode=0o700)
        source_root = destination / "source"
        source_root.mkdir(mode=0o700)
        files = self._copy_verified_git_tree(
            checkout_root,
            str(resolved.descriptor["resolvedCommit"]),
            source_root,
        )
        tree = self._git_tree_id(files)
        if tree != resolved.descriptor.get("resolvedTree"):
            raise AppError("immutable source cache tree does not match the selected Git tree")
        manifest_path = source_root / resolved.contract.manifest_path
        manifest_digest = _file_digest(manifest_path)
        if manifest_digest != resolved.descriptor.get("manifestDigest"):
            raise AppError("immutable source cache manifest differs from the selected source")
        manifest = load_template_manifest(source_root)
        local_descriptor = describe_template_source(source_root)
        source_digest = local_descriptor.get("sourceDigest")
        if source_digest != resolved.descriptor.get("sourceDigest"):
            raise AppError("immutable source cache representation changed the source digest")
        total_bytes = sum(int(item["size"]) for item in files)
        marker: dict[str, Any] = {
            "formatVersion": self._FORMAT,
            "repository": resolved.contract.repository,
            "resolvedCommit": resolved.descriptor["resolvedCommit"],
            "resolvedTree": tree,
            "manifestDigest": manifest_digest,
            "sourceDigest": source_digest,
            "fileCount": len(files),
            "totalBytes": total_bytes,
            "files": files,
        }
        marker["cacheDigest"] = _digest(self._cache_digest_payload(marker))
        _write_json(destination / "cache-manifest.json", marker)
        for directory in sorted(
            (path for path in source_root.rglob("*") if path.is_dir()),
            key=lambda path: len(path.parts),
            reverse=True,
        ):
            self._fsync_directory(directory)
        self._fsync_directory(source_root)
        self._fsync_directory(destination)
        if manifest.get("templateId") != resolved.contract.template_id:
            raise AppError("immutable source cache template identity changed")
        return marker

    def _resolved_from_cache(
        self,
        contract: Any,
        cache_digest: str,
        cache_root: Path,
    ) -> ResolvedSource:
        if not _SOURCE_DIGEST.fullmatch(cache_digest):
            raise AppError("source cache digest is invalid")
        destination = cache_root / "immutable" / cache_digest[7:]
        source_root = destination / "source"
        marker_path = destination / "cache-manifest.json"
        if (
            destination.is_symlink()
            or source_root.is_symlink()
            or marker_path.is_symlink()
            or not destination.is_dir()
            or not source_root.is_dir()
            or not marker_path.is_file()
        ):
            raise AppError("immutable source cache entry is unsafe")
        marker = _load_json(marker_path, None)
        required = {
            "formatVersion", "repository", "resolvedCommit", "resolvedTree",
            "manifestDigest", "sourceDigest", "fileCount", "totalBytes",
            "files", "cacheDigest",
        }
        if not isinstance(marker, Mapping) or set(marker) != required or marker.get("formatVersion") != self._FORMAT:
            raise AppError("immutable source cache manifest is invalid")
        if (
            marker.get("repository") != contract.repository
            or marker.get("resolvedCommit") != contract.commit
            or (
                contract.expected_tree is not None
                and marker.get("resolvedTree") != contract.expected_tree
            )
            or (
                contract.expected_manifest_digest is not None
                and marker.get("manifestDigest") != contract.expected_manifest_digest
            )
        ):
            raise AppError("immutable source cache identity differs from the source contract")
        files = self._snapshot_inventory(source_root)
        if marker.get("files") != files:
            raise AppError("immutable source cache file inventory changed")
        if marker.get("fileCount") != len(files) or marker.get("totalBytes") != sum(int(item["size"]) for item in files):
            raise AppError("immutable source cache inventory totals changed")
        if self._git_tree_id(files) != marker.get("resolvedTree"):
            raise AppError("immutable source cache no longer matches the selected Git tree")
        manifest_path = source_root / contract.manifest_path
        if _file_digest(manifest_path) != marker.get("manifestDigest"):
            raise AppError("immutable source cache manifest content changed")
        manifest = load_template_manifest(source_root)
        local_descriptor = describe_template_source(source_root)
        if local_descriptor.get("sourceDigest") != marker.get("sourceDigest"):
            raise AppError("immutable source cache source digest changed")
        if (
            manifest.get("templateId") != contract.template_id
            or manifest.get("sourceClass") != contract.source_class
            or manifest.get("productionEligible") is not contract.production_eligible
        ):
            raise AppError("immutable source cache policy identity changed")
        observed_cache_digest = _digest(self._cache_digest_payload(marker))
        if observed_cache_digest != cache_digest or marker.get("cacheDigest") != cache_digest:
            raise AppError("immutable source cache digest changed")
        descriptor = {
            "formatVersion": "statedd.source/v2",
            "kind": "git",
            "sourceClass": contract.source_class,
            "productionEligible": contract.production_eligible,
            "repository": contract.repository,
            "requestedRef": contract.commit,
            "resolvedCommit": contract.commit,
            "resolvedTree": marker["resolvedTree"],
            "checkoutLocation": source_root.as_posix(),
            "manifestDigest": marker["manifestDigest"],
            "sourceDigest": marker["sourceDigest"],
            "cacheDigest": cache_digest,
        }
        return ResolvedSource(contract, source_root, descriptor, manifest)

    @classmethod
    def describe_cached_root(cls, root: Path) -> dict[str, Any] | None:
        """Return a fully reverified descriptor for one managed Git-free cache root."""

        source_root = _safe_instance_root(root)
        marker_path = source_root.parent / "cache-manifest.json"
        if not source_root.is_dir():
            if marker_path.exists() or marker_path.is_symlink():
                raise AppError("immutable source cache entry is unsafe")
            return None
        if not marker_path.exists() and not marker_path.is_symlink():
            return None
        if source_root.name != "source" or marker_path.is_symlink() or not marker_path.is_file():
            raise AppError("immutable source cache entry is unsafe")
        marker_bytes, _marker_info = cls._read_regular_file(
            source_root.parent,
            marker_path.name,
        )
        try:
            marker = json.loads(marker_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AppError("immutable source cache manifest is invalid") from exc
        required = {
            "formatVersion", "repository", "resolvedCommit", "resolvedTree",
            "manifestDigest", "sourceDigest", "fileCount", "totalBytes",
            "files", "cacheDigest",
        }
        if not isinstance(marker, Mapping) or set(marker) != required or marker.get("formatVersion") != cls._FORMAT:
            raise AppError("immutable source cache manifest is invalid")
        cache_digest = marker.get("cacheDigest")
        if (
            not isinstance(cache_digest, str)
            or not _SOURCE_DIGEST.fullmatch(cache_digest)
            or source_root.parent.name != cache_digest[7:]
        ):
            raise AppError("immutable source cache digest changed")
        files = cls._snapshot_inventory(source_root)
        if marker.get("files") != files:
            raise AppError("immutable source cache file inventory changed")
        if marker.get("fileCount") != len(files) or marker.get("totalBytes") != sum(int(item["size"]) for item in files):
            raise AppError("immutable source cache inventory totals changed")
        if cls._git_tree_id(files) != marker.get("resolvedTree"):
            raise AppError("immutable source cache no longer matches the selected Git tree")
        manifest_path = source_root / ".statedd/manifest.yaml"
        if _file_digest(manifest_path) != marker.get("manifestDigest"):
            raise AppError("immutable source cache manifest content changed")
        manifest = load_template_manifest(source_root)
        local_descriptor = describe_template_source(source_root)
        if local_descriptor.get("sourceDigest") != marker.get("sourceDigest"):
            raise AppError("immutable source cache source digest changed")
        observed_cache_digest = _digest(cls._cache_digest_payload(marker))
        if observed_cache_digest != cache_digest:
            raise AppError("immutable source cache digest changed")
        repository = marker.get("repository")
        commit = marker.get("resolvedCommit")
        tree = marker.get("resolvedTree")
        if (
            not isinstance(repository, str)
            or not repository
            or not isinstance(commit, str)
            or not _GIT_OID.fullmatch(commit)
            or not isinstance(tree, str)
            or not _GIT_OID.fullmatch(tree)
        ):
            raise AppError("immutable source cache identity is invalid")
        return {
            "formatVersion": "statedd.source/v2",
            "kind": "git",
            "sourceClass": manifest["sourceClass"],
            "productionEligible": manifest["productionEligible"],
            "repository": repository,
            "requestedRef": commit,
            "resolvedCommit": commit,
            "resolvedTree": tree,
            "checkoutLocation": source_root.as_posix(),
            "manifestDigest": marker["manifestDigest"],
            "sourceDigest": marker["sourceDigest"],
            "cacheDigest": cache_digest,
        }

    @staticmethod
    def _cache_digest_payload(marker: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "formatVersion": SourceCache._FORMAT,
            "repository": marker.get("repository"),
            "resolvedCommit": marker.get("resolvedCommit"),
            "resolvedTree": marker.get("resolvedTree"),
            "manifestDigest": marker.get("manifestDigest"),
            "sourceDigest": marker.get("sourceDigest"),
            "files": marker.get("files"),
        }

    @classmethod
    def _copy_verified_git_tree(
        cls,
        checkout_root: Path,
        commit: str,
        destination: Path,
        *,
        from_objects: bool = False,
    ) -> list[dict[str, Any]]:
        listed = cls._run_cache_git(
            ["ls-tree", "-r", "-z", "--full-tree", commit],
            cwd=checkout_root,
            failure="source cache could not inventory the selected Git tree",
            text=False,
        )
        if listed.returncode != 0 or not isinstance(listed.stdout, bytes):
            raise AppError("source cache could not inventory the selected Git tree")
        raw_entries = [entry for entry in listed.stdout.split(b"\0") if entry]
        if not raw_entries or len(raw_entries) > cls._MAX_FILES:
            raise AppError("source cache Git tree file count is outside the supported bound")
        files: list[dict[str, Any]] = []
        total_bytes = 0
        seen: set[str] = set()
        for raw in raw_entries:
            try:
                header, raw_path = raw.split(b"\t", 1)
                mode, kind, object_id = header.decode("ascii").split(" ")
                relative = raw_path.decode("utf-8")
            except (UnicodeDecodeError, ValueError) as exc:
                raise AppError("source cache Git tree inventory is malformed") from exc
            relative = _safe_relative(relative)
            if relative in seen:
                raise AppError("source cache Git tree contains duplicate paths")
            seen.add(relative)
            if mode == "120000":
                raise AppError("source cache Git tree may not contain symbolic links")
            if kind != "blob" or mode not in {"100644", "100755"} or not re.fullmatch(r"[0-9a-f]{40}", object_id):
                raise AppError("source cache Git tree may contain only regular files")
            if from_objects:
                blob_result = cls._run_cache_git(
                    ["cat-file", "blob", object_id],
                    cwd=checkout_root,
                    failure="source cache could not read the selected Git object",
                    text=False,
                )
                if blob_result.returncode != 0 or not isinstance(blob_result.stdout, bytes):
                    raise AppError("source cache could not read the selected Git object")
                data = blob_result.stdout
                if len(data) > cls._MAX_FILE_BYTES:
                    raise AppError("source cache Git tree contains an oversized file")
            else:
                data, _info = cls._read_regular_file(checkout_root, relative)
            blob = hashlib.sha1(
                b"blob " + str(len(data)).encode("ascii") + b"\0" + data,
                usedforsecurity=False,
            ).hexdigest()
            if not secrets.compare_digest(blob, object_id):
                raise AppError("source cache checkout changed during acquisition")
            total_bytes += len(data)
            if total_bytes > cls._MAX_TOTAL_BYTES:
                raise AppError("source cache Git tree exceeds the supported size bound")
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(target, flags, 0o500 if mode == "100755" else 0o400)
            try:
                offset = 0
                while offset < len(data):
                    offset += os.write(descriptor, data[offset:])
                os.fchmod(descriptor, 0o500 if mode == "100755" else 0o400)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            files.append({
                "path": relative,
                "kind": "regular_file",
                "gitMode": mode,
                "gitBlob": object_id,
                "size": len(data),
                "digest": _digest(data),
            })
        return sorted(files, key=lambda item: str(item["path"]))

    @classmethod
    def _snapshot_inventory(cls, root: Path) -> list[dict[str, Any]]:
        files: list[dict[str, Any]] = []
        total_bytes = 0
        for current, directories, filenames in os.walk(root, topdown=True, followlinks=False):
            directories.sort()
            filenames.sort()
            current_path = Path(current)
            for name in directories:
                info = os.lstat(current_path / name)
                if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                    raise AppError("immutable source cache contains an unsafe directory entry")
            for name in filenames:
                relative = (current_path / name).relative_to(root).as_posix()
                data, info = cls._read_regular_file(root, relative)
                total_bytes += len(data)
                if total_bytes > cls._MAX_TOTAL_BYTES or len(files) >= cls._MAX_FILES:
                    raise AppError("immutable source cache exceeds the supported resource bound")
                mode = "100755" if info.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH) else "100644"
                blob = hashlib.sha1(
                    b"blob " + str(len(data)).encode("ascii") + b"\0" + data,
                    usedforsecurity=False,
                ).hexdigest()
                files.append({
                    "path": relative,
                    "kind": "regular_file",
                    "gitMode": mode,
                    "gitBlob": blob,
                    "size": len(data),
                    "digest": _digest(data),
                })
        if not files:
            raise AppError("immutable source cache contains no regular files")
        return sorted(files, key=lambda item: str(item["path"]))

    @classmethod
    def _read_regular_file(cls, root: Path, relative: str) -> tuple[bytes, os.stat_result]:
        relative = _safe_relative(relative)
        directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        directories: list[int] = []
        file_descriptor = -1
        try:
            directories.append(os.open(root, directory_flags))
            parts = Path(relative).parts
            for part in parts[:-1]:
                directories.append(os.open(part, directory_flags, dir_fd=directories[-1]))
            file_descriptor = os.open(parts[-1], file_flags, dir_fd=directories[-1])
            before = os.fstat(file_descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > cls._MAX_FILE_BYTES:
                raise AppError("source cache may contain only bounded single-link regular files")
            payload = bytearray()
            while len(payload) <= cls._MAX_FILE_BYTES:
                chunk = os.read(file_descriptor, min(1024 * 1024, cls._MAX_FILE_BYTES + 1 - len(payload)))
                if not chunk:
                    break
                payload.extend(chunk)
            if len(payload) > cls._MAX_FILE_BYTES:
                raise AppError("source cache file exceeds the supported size bound")
            after = os.fstat(file_descriptor)
            identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_nlink, value.st_size, value.st_mtime_ns)
            if identity(before) != identity(after) or len(payload) != before.st_size:
                raise AppError("source cache file changed while it was read")
            return bytes(payload), after
        except OSError as exc:
            raise AppError("source cache file could not be read safely") from exc
        finally:
            if file_descriptor >= 0:
                os.close(file_descriptor)
            for directory in reversed(directories):
                os.close(directory)

    @staticmethod
    def _git_tree_id(files: list[dict[str, Any]]) -> str:
        root: dict[str, tuple[str, Any]] = {}
        for item in files:
            parts = Path(str(item["path"])).parts
            node = root
            for part in parts[:-1]:
                existing = node.get(part)
                if existing is None:
                    child: dict[str, tuple[str, Any]] = {}
                    node[part] = ("tree", child)
                    node = child
                elif existing[0] == "tree":
                    node = existing[1]
                else:
                    raise AppError("source cache paths overlap ambiguously")
            if parts[-1] in node:
                raise AppError("source cache paths overlap ambiguously")
            node[parts[-1]] = ("file", item)

        def encode(node: dict[str, tuple[str, Any]]) -> str:
            entries: list[tuple[bytes, bytes]] = []
            for name, (kind, value) in node.items():
                name_bytes = name.encode("utf-8")
                if kind == "tree":
                    mode = b"40000"
                    object_id = encode(value)
                    sort_key = name_bytes + b"/"
                else:
                    mode = str(value["gitMode"]).encode("ascii")
                    object_id = str(value["gitBlob"])
                    sort_key = name_bytes
                entry = mode + b" " + name_bytes + b"\0" + bytes.fromhex(object_id)
                entries.append((sort_key, entry))
            payload = b"".join(entry for _key, entry in sorted(entries, key=lambda item: item[0]))
            return hashlib.sha1(
                b"tree " + str(len(payload)).encode("ascii") + b"\0" + payload,
                usedforsecurity=False,
            ).hexdigest()

        return encode(root)

    @staticmethod
    def _discard_cache_entry(path: Path) -> None:
        if path.is_symlink():
            path.unlink()
        elif path.is_dir():
            shutil.rmtree(path)
        elif path.exists():
            path.unlink()

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _validated_clone_source(contract_repository: str, mirror: str | None) -> str:
        parsed = urlsplit(str(contract_repository))
        if (
            parsed.scheme not in {"https", "ssh"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise AppError("source repository must be a credential-free https or ssh URL")
        if mirror is not None:
            candidate = Path(mirror).expanduser()
            if not candidate.is_absolute() or candidate.is_symlink():
                raise AppError("source mirror must be an absolute, non-symlink local Git directory or bundle")
            try:
                resolved = candidate.resolve(strict=True)
            except OSError as exc:
                raise AppError("source mirror must be an existing local Git directory or bundle") from exc
            if resolved != candidate:
                raise AppError("source mirror must be an absolute, non-symlink local Git directory or bundle")
            if resolved.is_file():
                info = resolved.stat()
                if (
                    info.st_nlink != 1
                    or info.st_uid != os.getuid()
                    or info.st_mode & 0o077
                    or info.st_size <= 0
                    or info.st_size > SourceCache._MAX_BUNDLE_BYTES
                ):
                    raise AppError("source bundle must be owner-private, single-link, and within the supported size bound")
            elif not resolved.is_dir():
                raise AppError("source mirror must be an absolute, non-symlink local Git directory or bundle")
            return resolved.as_posix()

        return str(contract_repository)

    @staticmethod
    def _run_cache_git(
        arguments: list[str],
        *,
        failure: str,
        cwd: Path | None = None,
        text: bool = True,
    ) -> subprocess.CompletedProcess[Any]:
        environment = dict(os.environ)
        environment.update(
            {
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_ASKPASS": "/bin/false",
                "SSH_ASKPASS": "/bin/false",
            }
        )
        try:
            return subprocess.run(
                ["git", "-c", "credential.helper=", *arguments],
                cwd=cwd,
                capture_output=True,
                text=text,
                timeout=30,
                env=environment,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AppError(failure) from exc


@dataclass(frozen=True)
class ImportPlan:
    payload: dict[str, Any]

    @property
    def digest(self) -> str:
        return _digest(self.payload)


class PersistentApp:
    def __init__(
        self,
        layout: LocalLayout | None = None,
        *,
        canonical_source_catalog: Path | str | None = None,
    ):
        self.layout = layout or LocalLayout.from_environment()
        self.catalog = PersistentCatalog(self.layout)
        self.cache = SourceCache(self.layout)
        (
            self.canonical_source_catalog,
            self.canonical_source_catalog_digest,
            self._canonical_source_descriptor,
        ) = self._load_canonical_source_authority(
            Path(canonical_source_catalog or _STUDYSTATE_CATALOG),
        )

    @staticmethod
    def _load_canonical_source_authority(path: Path) -> tuple[Path, str, Any]:
        configured = path.expanduser()
        try:
            parent = _safe_instance_root(configured.parent, must_exist=True)
            resolved = parent / configured.name
            if resolved.is_symlink():
                raise AppError("configured source catalog must not be a symlink")
            payload, _info = SourceCache._read_regular_file(parent, configured.name)
            descriptor = normalize_canonical_source_descriptor(
                parse_yaml_text(payload.decode("utf-8")),
            )
        except AppError:
            raise
        except Exception as exc:  # noqa: BLE001 - expose one bounded startup refusal
            raise AppError("the tracked application source catalog is invalid") from exc
        return resolved, _digest(payload), descriptor

    def setup_init(self, source_mirror: str | None = None) -> dict[str, Any]:
        return self.layout.initialize(source_mirror=source_mirror)

    def setup_status(self) -> dict[str, Any]:
        return self.layout.status()

    def setup_uninstall(self) -> dict[str, Any]:
        return self.layout.uninstall_metadata()

    def execution_runtime_status(self) -> dict[str, Any]:
        """Truthful bounded view of the installed execution runtime.

        The web process cannot reach the execution-host control socket unless
        the mounted directory is actually readable by the container user. The
        unit files express the intended contract as environment; report the
        observed reality, never a synthetic "available". When the sanctioned
        proxy is configured (socket + grant), the bounded proxy health round
        trip is the authority.
        """

        socket_value = os.environ.get("STATEPORT_EXECUTION_SOCKET", "")
        peer_policy = os.environ.get("STATEPORT_EXECUTION_PEER_POLICY", "")
        grant_digest = os.environ.get("STATEPORT_EXECUTION_GRANT_DIGEST", "")
        if not socket_value:
            return {
                "status": "unavailable",
                "reason": "execution_socket_not_configured",
                "detail": "Execution host socket is not configured for this service.",
                "workerExecutionEnabled": False,
                "proxyBound": False,
            }
        try:
            socket_path = Path(socket_value)
        except (TypeError, ValueError) as exc:
            return {
                "status": "unavailable",
                "reason": "execution_socket_invalid",
                "detail": f"Execution host socket path is invalid: {exc}",
                "workerExecutionEnabled": False,
                "proxyBound": False,
            }
        if not socket_path.is_absolute():
            return {
                "status": "unavailable",
                "reason": "execution_socket_invalid",
                "detail": "Execution host socket path must be absolute.",
                "workerExecutionEnabled": False,
                "proxyBound": False,
            }
        socket_absent = not socket_path.exists()
        socket_readable = False
        if not socket_absent:
            try:
                socket_stat = socket_path.stat()
                socket_readable = stat.S_ISSOCK(socket_stat.st_mode)
            except OSError:
                socket_readable = False
        worker_enabled = (os.environ.get("STATEPORT_WORKER_EXECUTION_ENABLED", "") or "").strip().lower() in {"1", "true", "yes"}
        base = {
            "socketPath": socket_value,
            "socketPresent": not socket_absent,
            "peerPolicy": peer_policy or None,
            "workerExecutionEnabled": worker_enabled,
            "proxyBound": bool(grant_digest),
        }
        if socket_absent or not socket_readable:
            return {
                "status": "unavailable",
                "reason": "execution_socket_unreachable",
                "detail": (
                    "Execution host control socket is not reachable from this service; "
                    "container execution cannot start."
                ),
                **base,
            }
        if grant_digest:
            try:
                from stateport_persistent_app.execution_host_proxy import ExecutionHostProxy
            except ModuleNotFoundError:
                pass
            else:
                proxy = ExecutionHostProxy()
                probe = proxy.status()
                if probe.get("status") == "available":
                    return {
                        "status": "available",
                        "detail": "Execution host daemon answered the sanctioned proxy contract.",
                        "contractVersion": probe.get("contractVersion"),
                        "engine": probe.get("engine"),
                        **base,
                    }
                return {
                    "status": "unavailable",
                    "reason": str(probe.get("reason") or "execution_host_unreachable"),
                    "detail": str(probe.get("detail") or "Execution host daemon did not answer the proxy probe.")[:280],
                    **base,
                }
        return {
            "status": "available",
            "detail": "Execution host control socket is reachable from this service.",
            **base,
        }

    def product_status(self) -> dict[str, Any]:
        """Return bounded operator-facing status for the browser surface."""

        setup = self.setup_status()
        source = self._source_status_projection()
        runtime = self.execution_runtime_status()
        if not setup["initialized"]:
            return {
                "setup": setup,
                "catalog": {"status": "not_initialized", "count": 0},
                "sources": [source],
                "runtime": runtime,
                "diagnostics": [],
            }
        try:
            entries = self.instance_list()
        except AppError as exc:
            return {
                "setup": setup,
                "catalog": {"status": "migration_required", "count": 0},
                "sources": [source],
                "runtime": runtime,
                "diagnostics": [{"code": "catalog_migration_required", "severity": "warning", "message": str(exc)}],
            }
        return {
            "setup": setup,
            "catalog": {"status": "ready", "count": len(entries)},
            "sources": [source],
            "runtime": runtime,
            "diagnostics": [],
        }

    def _canonical_source(self) -> Any:
        return self._canonical_source_descriptor

    def _current_canonical_source(self) -> Any:
        current_path, current_digest, _descriptor = self._load_canonical_source_authority(
            self.canonical_source_catalog,
        )
        if (
            current_path != self.canonical_source_catalog
            or current_digest != self.canonical_source_catalog_digest
        ):
            raise AppError("the tracked application source catalog changed; restart the service")
        return _descriptor

    def _source_status_projection(self) -> dict[str, Any]:
        try:
            descriptor = self._canonical_source()
        except AppError:
            return {
                "id": "studydd",
                "sourceId": "stateport.source.studystate",
                "applicationId": "study-state",
                "profile": "builtin:studydd-local-alpha",
                "status": "rejected",
                "installable": False,
                "developmentTestingAllowed": False,
                "reason": "source_catalog_invalid",
                "message": "Application source verification is unavailable.",
            }
        messages = {
            "awaiting_verified_release": "Application source is awaiting a verified release.",
            "source_available": "Application source is available.",
            "rejected": "Application source verification is unavailable.",
        }
        return {
            "id": "studydd",
            "sourceId": descriptor.source_id,
            "applicationId": descriptor.application_id,
            "profile": "builtin:studydd-local-alpha",
            "status": descriptor.status.code,
            "installable": descriptor.status.installable,
            "developmentTestingAllowed": descriptor.trust.development_testing_allowed,
            "reason": descriptor.status.unresolved_reason,
            "message": messages[descriptor.status.code],
        }

    def canonical_source_registry(self) -> list[dict[str, Any]]:
        """Return the browser-safe source registry without infrastructure identity."""

        source = self._source_status_projection()
        return [{
            "formatVersion": "stateport.canonical-source-public-view/v1",
            "sourceId": source["sourceId"],
            "applicationId": source["applicationId"],
            "publicName": "StudyState",
            "status": source["status"],
            "installable": source["installable"],
            "productionAction": {
                "action": "install_or_update",
                "enabled": source["installable"],
            },
            "message": source["message"],
        }]

    def canonical_source_operator_projection(self, source_id: str) -> dict[str, Any]:
        """Return exact source evidence for an authorized operator surface.

        Repository and immutable object identities are useful for an operator,
        but checkout locations, configured mirrors, credentials, and parser
        diagnostics are deliberately outside this projection.
        """

        if source_id != "stateport.source.studystate":
            raise AppError("unknown canonical application source")
        descriptor = self._canonical_source()
        if source_id != descriptor.source_id:
            raise AppError("unknown canonical application source")
        candidate = descriptor.development_candidate
        candidate_projection: dict[str, Any] | None = None
        if candidate is not None and candidate.identity is not None:
            acknowledgement = _digest({
                "formatVersion": "stateport.development-source-acknowledgement/v1",
                "sourceId": descriptor.source_id,
                "sourceClass": candidate.source_class,
                "identity": candidate.identity.to_dict(),
                "purpose": "isolated_development_verification_only",
                "productionInstallAllowed": False,
            })
            candidate_projection = {
                "sourceClass": candidate.source_class,
                "releaseStatus": candidate.release_status,
                "testingAllowed": descriptor.trust.development_testing_allowed,
                "productionInstallAllowed": False,
                "identity": candidate.identity.to_dict(),
                "verifiedModules": list(candidate.verified_modules),
                "verifiedSelfTests": list(candidate.verified_self_tests),
                "verificationAction": {
                    "enabled": descriptor.trust.development_testing_allowed,
                    "acknowledgement": acknowledgement,
                    "purpose": "isolated_development_verification_only",
                },
            }
        return {
            "formatVersion": "stateport.canonical-source-operator-view/v1",
            "sourceId": descriptor.source_id,
            "application": {
                "id": descriptor.application_id,
                "publicName": descriptor.public_name,
                "legacyIdentifiers": list(descriptor.legacy_identifiers),
            },
            "authority": {
                "repository": descriptor.repository,
                "canonicalRefPolicy": descriptor.canonical_ref_policy,
                "manifestPath": descriptor.manifest_path,
                "manifestContract": descriptor.manifest_contract,
            },
            "canonicalRelease": {
                "sourceClass": descriptor.canonical_resolution.source_class,
                "identity": (
                    None if descriptor.identity is None else descriptor.identity.to_dict()
                ),
                "status": descriptor.status.code,
                "trust": descriptor.trust.state,
                "installable": descriptor.status.installable,
                "missingRequirement": descriptor.status.unresolved_reason,
                "requiredModules": list(descriptor.required_modules),
                "expectedSelfTests": list(descriptor.expected_self_tests),
            },
            "developmentCandidate": candidate_projection,
            "message": self._source_status_projection()["message"],
        }

    def _configured_source_mirror(self) -> str | None:
        try:
            config = _load_json(self.layout.config_file, {})
        except AppError:
            return None
        mirrors = config.get("sourceMirrors") if isinstance(config, Mapping) else None
        value = mirrors.get("studydd") if isinstance(mirrors, Mapping) else None
        return value if isinstance(value, str) and value else None

    def _contract(self, profile: str, source_repository: str | None = None) -> tuple[Any, Any]:
        contract = load_builtin_source_contract(profile) if profile.startswith("builtin:") else load_source_contract(profile)
        if contract.template_id == "studydd":
            descriptor = self._canonical_source()
            if not descriptor.status.installable or descriptor.identity is None:
                raise AppError("Application source is awaiting a verified release.")
        resolved = self.cache.resolve(
            contract,
            source_repository or self._configured_source_mirror(),
        )
        expected = descriptor.identity if contract.template_id == "studydd" else None
        if expected is not None and CanonicalSourceIdentity.from_resolved_descriptor(resolved.descriptor) != expected:
            raise AppError("the resolved application source does not match the verified release")
        return contract, resolved

    @staticmethod
    def _candidate_manifest_claims(resolved: Any) -> tuple[str, set[str], set[str]]:
        manifest_path = resolved.root / resolved.contract.manifest_path
        try:
            raw = parse_yaml_text(manifest_path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001 - never expose parser/path details
            raise AppError("the development candidate manifest could not be verified") from exc
        template = raw.get("template") if isinstance(raw, Mapping) else None
        modules = raw.get("modules") if isinstance(raw, Mapping) else None
        selected = raw.get("selectedModules") if isinstance(raw, Mapping) else None
        if (
            not isinstance(template, Mapping)
            or not isinstance(modules, list)
            or not isinstance(selected, list)
            or any(not isinstance(item, str) for item in selected)
        ):
            raise AppError("the development candidate manifest is incomplete")
        release_status = template.get("releaseStatus")
        module_ids: set[str] = set()
        self_tests: set[str] = set()
        for module in modules:
            if not isinstance(module, Mapping) or not isinstance(module.get("id"), str):
                raise AppError("the development candidate module contract is invalid")
            module_ids.add(module["id"])
            tests = module.get("selfTests", [])
            if not isinstance(tests, list):
                raise AppError("the development candidate self-test contract is invalid")
            for test in tests:
                if not isinstance(test, Mapping) or not isinstance(test.get("id"), str):
                    raise AppError("the development candidate self-test contract is invalid")
                self_tests.add(test["id"])
        selected_modules = set(selected)
        if not selected_modules.issubset(module_ids):
            raise AppError("the development candidate selects an unknown module")
        return str(release_status or ""), selected_modules, self_tests

    def _resolve_development_candidate(
        self,
        *,
        source_profile: str,
        source_repository: str | None,
    ) -> tuple[Any, Any, Any]:
        descriptor = self._canonical_source()
        candidate = descriptor.development_candidate
        if (
            candidate is None
            or candidate.identity is None
            or descriptor.trust.state != "development_only"
            or not descriptor.trust.development_testing_allowed
        ):
            raise AppError("no verified development candidate is available")
        contract = (
            load_builtin_source_contract(source_profile)
            if source_profile.startswith("builtin:")
            else load_source_contract(source_profile)
        )
        identity = candidate.identity
        if (
            contract.template_id != "studydd"
            or contract.repository != identity.repository
            or contract.commit != identity.commit
            or contract.expected_tree != identity.tree
            or contract.expected_manifest_digest != identity.manifest_digest
            or contract.manifest_path != descriptor.manifest_path
        ):
            raise AppError("the development source profile does not match the tracked candidate")
        resolved = self.cache.resolve(
            contract,
            source_repository or self._configured_source_mirror(),
        )
        actual = CanonicalSourceIdentity.from_resolved_descriptor(resolved.descriptor)
        if actual != identity:
            raise AppError("the resolved development candidate identity does not match the catalog")
        release_status, modules, self_tests = self._candidate_manifest_claims(resolved)
        if release_status != "candidate":
            raise AppError("the development source is not marked as a candidate")
        if not set(descriptor.required_modules).issubset(modules):
            raise AppError("the development candidate is missing a required module")
        if not set(descriptor.expected_self_tests).issubset(self_tests):
            raise AppError("the development candidate is missing an expected self-test declaration")
        return descriptor, candidate, resolved

    def resolve_development_candidate(
        self,
        *,
        source_id: str = "stateport.source.studystate",
        source_profile: str = "builtin:studydd-local-alpha",
        source_repository: str | None = None,
        operator_acknowledged: bool = False,
    ) -> dict[str, Any]:
        """Verify the tracked candidate for isolated testing, never installation."""

        if operator_acknowledged is not True:
            raise AppError("explicit operator acknowledgement is required for development-candidate testing")
        descriptor, candidate, resolved = self._resolve_development_candidate(
            source_profile=source_profile,
            source_repository=source_repository,
        )
        if source_id != descriptor.source_id or candidate.identity is None:
            raise AppError("unknown canonical application source")
        receipt = {
            "formatVersion": "stateport.development-source-resolution/v1",
            "sourceId": descriptor.source_id,
            "applicationId": descriptor.application_id,
            "sourceClass": "development_candidate",
            "identity": candidate.identity.to_dict(),
            "releaseStatus": candidate.release_status,
            "trust": "development_only",
            "productionInstallAllowed": False,
            "verifiedModules": list(candidate.verified_modules),
            "requiredSelfTests": list(candidate.verified_self_tests),
            "selfTestDeclarationsMatched": True,
            "selfTestsExecutedByThisOperation": False,
            "verifiedAt": _now(),
        }
        receipt["receiptDigest"] = _digest(receipt)
        safe_id = re.sub(r"[^A-Za-z0-9._-]", "-", descriptor.source_id)
        _write_json(self.layout.operations_root / "source-resolutions" / f"{safe_id}.json", receipt)
        return receipt

    def bind_installed_source(
        self,
        instance_id: str,
        source_profile: str,
        *,
        allow_development_candidate: bool = False,
    ) -> Any:
        """Bind cached bytes to the installed lock before an action reads them."""

        locked = self.locked_source(instance_id)
        source = locked["source"]
        if (
            source.get("formatVersion") != "statedd.source/v2"
            or source.get("kind") != "git"
            or source.get("sourceClass") != "canonical_source"
            or source.get("productionEligible") is not True
        ):
            raise AppError("the installed application lock is not an immutable Git source")
        contract = (
            load_builtin_source_contract(source_profile)
            if source_profile.startswith("builtin:")
            else load_source_contract(source_profile)
        )
        if (
            contract.repository != source.get("repository")
            or contract.commit != source.get("resolvedCommit")
            or contract.expected_tree != source.get("resolvedTree")
            or contract.expected_manifest_digest != source.get("manifestDigest")
        ):
            raise AppError("the current application source profile differs from the installed lock; plan an update")
        descriptor = self._canonical_source()
        try:
            lock_identity = CanonicalSourceIdentity.from_mapping(
                {
                    "repository": source.get("repository"),
                    "commit": source.get("resolvedCommit"),
                    "tree": source.get("resolvedTree"),
                    "manifestDigest": source.get("manifestDigest"),
                    "sourceDigest": source.get("sourceDigest"),
                },
                "installedSource.identity",
            )
        except Exception as exc:  # noqa: BLE001 - keep lock failures path-free and bounded
            raise AppError("the installed application lock has malformed source identity") from exc
        if descriptor.identity == lock_identity and descriptor.status.installable:
            resolved = self.cache.resolve(contract, self._configured_source_mirror())
        elif (
            descriptor.development_candidate is not None
            and descriptor.development_candidate.identity == lock_identity
        ):
            if allow_development_candidate is not True:
                raise AppError("the installed source is a development candidate; use the explicit operator testing path")
            _, _, resolved = self._resolve_development_candidate(
                source_profile=source_profile,
                source_repository=None,
            )
        else:
            raise AppError("the installed application source is no longer trusted by the tracked catalog")
        if CanonicalSourceIdentity.from_resolved_descriptor(resolved.descriptor) != lock_identity:
            raise AppError("the cached application source differs from the installed lock")
        return resolved

    @staticmethod
    def _locked_source_at(root: Path) -> tuple[str, dict[str, Any]]:
        try:
            lock = _read_yaml(root / ".statedd" / "lock.yaml")
        except AppError as exc:
            raise AppError("the installed application lock could not be read safely") from exc
        template = lock.get("template") if isinstance(lock.get("template"), Mapping) else None
        source = template.get("source") if isinstance(template, Mapping) else None
        if not isinstance(source, Mapping):
            raise AppError("the installed application lock has no source identity")
        projected = {
            key: value
            for key, value in source.items()
            if key not in {"checkoutLocation", "path", "profile"}
        }
        if projected.get("formatVersion") == "statedd.source/v2":
            if (
                not _SOURCE_DIGEST.fullmatch(str(projected.get("sourceDigest")))
                or projected.get("kind") not in {"git", "local_development"}
                or not isinstance(projected.get("sourceClass"), str)
                or not isinstance(projected.get("productionEligible"), bool)
            ):
                raise AppError("the installed application lock has malformed source identity")
            resolved_commit = projected.get("resolvedCommit")
            if resolved_commit is not None and (
                not isinstance(resolved_commit, str)
                or not _GIT_OID.fullmatch(resolved_commit)
                or not _GIT_OID.fullmatch(str(projected.get("resolvedTree")))
                or not _SOURCE_DIGEST.fullmatch(str(projected.get("manifestDigest")))
            ):
                raise AppError("the installed application lock has malformed Git source identity")
        elif projected.get("formatVersion") == "statedd.source/v1":
            if (
                projected.get("kind") != "local"
                or not _SOURCE_DIGEST.fullmatch(str(projected.get("identity")))
            ):
                raise AppError("the installed application lock has malformed legacy source identity")
        else:
            for field in ("resolvedCommit", "resolvedTree", "manifestDigest"):
                if not isinstance(projected.get(field), str) or not projected[field]:
                    raise AppError("the installed application lock has incomplete source identity")
        return str(template.get("id") or "unknown"), projected

    def _validate_managed_instance(
        self,
        root: Path,
        *,
        template_root: Path | None = None,
        source_descriptor: Mapping[str, Any] | None = None,
    ) -> Any:
        selected_root = template_root
        selected_descriptor = dict(source_descriptor) if source_descriptor is not None else None
        if selected_root is None:
            lock = _read_yaml(root / ".statedd" / "lock.yaml")
            template = lock.get("template") if isinstance(lock.get("template"), Mapping) else None
            source_path = template.get("sourcePath") if isinstance(template, Mapping) else None
            if isinstance(source_path, str) and source_path:
                candidate = Path(source_path)
                cached_descriptor = SourceCache.describe_cached_root(candidate)
                if cached_descriptor is not None:
                    selected_root = candidate
                    selected_descriptor = cached_descriptor
                elif not candidate.is_dir():
                    template_id, locked_source = self._locked_source_at(root)
                    if (
                        template_id == "studydd"
                        and locked_source.get("kind") == "git"
                        and locked_source.get("formatVersion") == "statedd.source/v2"
                    ):
                        locked_identity = self._locked_canonical_source_identity(locked_source)
                        authority = self._current_canonical_source()
                        if (
                            authority.development_candidate is not None
                            and authority.development_candidate.identity == locked_identity
                        ):
                            _descriptor, _candidate, resolved = self._resolve_development_candidate(
                                source_profile="builtin:studydd-local-alpha",
                                source_repository=None,
                            )
                            selected_root = resolved.root
                            selected_descriptor = resolved.descriptor
        if selected_root is None or selected_descriptor is None:
            return validate_instance(root)
        return validate_instance(
            root,
            template_path_override=selected_root,
            template_source_descriptor_override=selected_descriptor,
        )

    def locked_source(self, instance_id: str) -> dict[str, Any]:
        """Return a path-free, exact source projection from the installed lock."""

        entry, root = self._entry(instance_id)
        template_id, projected = self._locked_source_at(root)
        return {
            "applicationId": str(entry.get("applicationId") or template_id),
            "source": projected,
        }

    def register_portable_import(
        self,
        root: Path | str,
        *,
        instance_id: str,
        name: str,
        expected_source: Mapping[str, Any],
        application_id: str,
    ) -> dict[str, Any]:
        """Register a restored lock without resolving its upstream checkout."""

        destination = _safe_instance_root(Path(root), must_exist=True)
        _template_id, source = self._locked_source_at(destination)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", application_id):
            raise AppError("the restored application identity was not validated")
        expected = {
            key: value
            for key, value in expected_source.items()
            if key not in {"checkoutLocation", "profile"}
        }
        if _digest(source) != _digest(expected):
            raise AppError("the restored source lock does not match the portable archive identity")
        return self.catalog.import_instance(
            destination,
            instance_id=instance_id,
            name=name,
            application_id=application_id,
            source=source,
        )

    @staticmethod
    def _template_match_from_inspection(inspection: Mapping[str, Any]) -> dict[str, Any]:
        template = inspection.get("template")
        validation = template.get("validation") if isinstance(template, Mapping) else None
        if (
            not isinstance(template, Mapping)
            or template.get("formatVersion") != "stateport.template-adapter-match/v1"
            or not isinstance(validation, Mapping)
            or validation.get("status") != "passed"
            or not isinstance(template.get("adapterId"), str)
            or not isinstance(template.get("applicationId"), str)
            or template.get("executionTrust") != "stateport_owned_adapter_only"
            or template.get("repositoryCommandsExecuted") is not False
        ):
            raise AppError("repository does not expose a valid supported template contract")
        return copy.deepcopy(dict(template))

    @staticmethod
    def _template_git_identity_from_inspection(
        inspection: Mapping[str, Any],
    ) -> dict[str, Any]:
        identity = inspection.get("sourceIdentity")
        if (
            inspection.get("formatVersion") != "stateport.repository-inspection/v1"
            or inspection.get("sourceKind") not in {"local", "public_https"}
            or not isinstance(identity, Mapping)
            or not isinstance(identity.get("headCommit"), str)
            or not _GIT_OID.fullmatch(str(identity.get("headCommit")))
            or not isinstance(identity.get("headTree"), str)
            or not _GIT_OID.fullmatch(str(identity.get("headTree")))
            or not isinstance(identity.get("dirty"), bool)
            or not isinstance(identity.get("contentIdentity"), Mapping)
        ):
            raise AppError("repository inspection lacks an exact Git identity")
        return {
            "sourceKind": "public_git_snapshot" if inspection.get("sourceKind") == "public_https" else "local_git_snapshot",
            "resolvedCommit": str(identity["headCommit"]),
            "resolvedTree": str(identity["headTree"]),
            "workingTreeDirty": bool(identity["dirty"]),
            "workingTreeChangesExcluded": True,
            "contentIdentity": copy.deepcopy(dict(identity["contentIdentity"])),
            "remote": identity.get("remote")
            if isinstance(identity.get("remote"), str)
            else None,
        }

    def plan_template_import(
        self,
        inspection: Mapping[str, Any],
        *,
        candidate_id: str,
        instance_id: str,
        name: str,
    ) -> dict[str, Any]:
        """Plan an isolated copy of one exact inspected Git template."""

        _validate_id(instance_id, "instance_id")
        if not isinstance(name, str) or not name.strip() or len(name) > 120:
            raise AppError("template instance name is invalid")
        if not re.fullmatch(r"repo-[0-9a-f]{32}", candidate_id):
            raise AppError("template repository candidate identity is invalid")
        inspection_digest = inspection.get("inspectionDigest")
        if not isinstance(inspection_digest, str) or not _SOURCE_DIGEST.fullmatch(
            inspection_digest
        ):
            raise AppError("repository inspection digest is invalid")
        template = self._template_match_from_inspection(inspection)
        source = self._template_git_identity_from_inspection(inspection)
        destination = self.layout.instances_root / instance_id
        if destination.is_symlink():
            conflict = "symlink"
        elif destination.exists() and (
            not destination.is_dir() or any(destination.iterdir())
        ):
            conflict = "nonempty"
        elif destination.exists():
            conflict = "empty_directory"
        else:
            conflict = "none"
        plan = {
            "formatVersion": TEMPLATE_IMPORT_PLAN_FORMAT,
            "operation": "template-import",
            "candidateId": candidate_id,
            "inspectionDigest": inspection_digest,
            "instanceId": instance_id,
            "name": name.strip(),
            "destination": {
                "kind": "stateport_managed_storage",
                "instanceId": instance_id,
                "conflict": conflict,
            },
            "source": source,
            "template": template,
            "effects": {
                "sourceRepositoryMutation": False,
                "managedCopyCreated": True,
                "managedGitHistoryCreated": True,
                "repositoryCommandsExecuted": False,
                "networkAccess": False,
            },
            "approvalRequired": True,
            "createdAt": _now(),
        }
        plan["planDigest"] = _digest(plan)
        return plan

    @staticmethod
    def _validate_template_import_approval(
        plan: Mapping[str, Any],
        approval: Mapping[str, Any] | None,
        *,
        expected_actor_id: str,
    ) -> None:
        if (
            not isinstance(approval, Mapping)
            or set(approval) != {"decision", "actorId", "planDigest"}
            or approval.get("decision") != "approve"
            or approval.get("actorId") != expected_actor_id
            or approval.get("planDigest") != plan.get("planDigest")
        ):
            raise ApprovalError("exact template import approval is required")

    @staticmethod
    def _make_managed_incarnation(stage: Path, instance_id: str) -> dict[str, Any]:
        reserved = stage / ".stateport"
        if reserved.exists() or reserved.is_symlink():
            raise AppError("template source uses the reserved .stateport path")
        reserved.mkdir(mode=0o700)
        _write_json(
            stage / _MANAGED_INCARNATION_PATH,
            {
                "formatVersion": MANAGED_INCARNATION_FORMAT,
                "instanceId": instance_id,
                "incarnationId": secrets.token_hex(32),
                "createdAt": _now(),
            },
        )
        return _managed_incarnation_binding(
            stage,
            expected_instance_id=instance_id,
        )

    @staticmethod
    def _make_template_tree_writable(
        stage: Path,
        files: list[dict[str, Any]],
    ) -> None:
        for directory in sorted(
            (item for item in stage.rglob("*") if item.is_dir()),
            key=lambda item: len(item.parts),
            reverse=True,
        ):
            if directory.is_symlink():
                raise AppError("materialized template contains an unsafe directory")
            os.chmod(directory, 0o700)
        for item in files:
            path = stage / str(item["path"])
            os.chmod(path, 0o700 if item.get("gitMode") == "100755" else 0o600)

    def install_template(
        self,
        plan: Mapping[str, Any],
        approval: Mapping[str, Any] | None,
        *,
        source_root: Path,
        current_inspection: Mapping[str, Any],
        actor_id: str,
    ) -> dict[str, Any]:
        """Materialize and register one exact committed template snapshot."""

        if (
            plan.get("formatVersion") != TEMPLATE_IMPORT_PLAN_FORMAT
            or plan.get("operation") != "template-import"
            or plan.get("planDigest")
            != _digest({key: value for key, value in plan.items() if key != "planDigest"})
        ):
            raise ApprovalError("template import plan digest is invalid")
        self._validate_template_import_approval(
            plan,
            approval,
            expected_actor_id=actor_id,
        )
        if current_inspection.get("inspectionDigest") != plan.get("inspectionDigest"):
            raise AppError("repository identity changed after planning; inspect it again")
        current_template = self._template_match_from_inspection(current_inspection)
        current_source = self._template_git_identity_from_inspection(current_inspection)
        if (
            _digest(current_template) != _digest(plan.get("template"))
            or _digest(current_source) != _digest(plan.get("source"))
        ):
            raise AppError("template or source identity changed after planning")
        instance_id = plan.get("instanceId")
        name = plan.get("name")
        if not isinstance(instance_id, str):
            raise AppError("template instance identity is invalid")
        _validate_id(instance_id, "instance_id")
        if not isinstance(name, str) or not name.strip() or len(name) > 120:
            raise AppError("template instance name is invalid")
        destination_info = plan.get("destination")
        if (
            not isinstance(destination_info, Mapping)
            or destination_info.get("kind") != "stateport_managed_storage"
            or destination_info.get("instanceId") != instance_id
            or destination_info.get("conflict") != "none"
        ):
            raise AppError("template import destination is unavailable")
        source = plan.get("source")
        template = plan.get("template")
        if not isinstance(source, Mapping) or not isinstance(template, Mapping):
            raise AppError("template import source contract is invalid")
        commit = str(source.get("resolvedCommit", ""))
        expected_tree = str(source.get("resolvedTree", ""))
        if not _GIT_OID.fullmatch(commit) or not _GIT_OID.fullmatch(expected_tree):
            raise AppError("template import Git identity is invalid")
        destination = self.layout.instances_root / instance_id
        if destination.exists() or destination.is_symlink():
            raise AppError("template import destination already exists")
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        stage = destination.parent / (
            f".{instance_id}.template-import-{os.getpid()}-{secrets.token_hex(4)}"
        )
        if stage.exists() or stage.is_symlink():
            raise AppError("template import staging identity already exists")
        catalog_entry: dict[str, Any] | None = None
        promoted_identity: tuple[int, int] | None = None
        receipt_path = (
            self.layout.operations_root
            / "template-imports"
            / f"{instance_id}.json"
        )
        try:
            stage.mkdir(mode=0o700)
            files = SourceCache._copy_verified_git_tree(
                source_root,
                commit,
                stage,
                from_objects=True,
            )
            if SourceCache._git_tree_id(files) != expected_tree:
                raise AppError("materialized template differs from the planned Git tree")
            self._make_template_tree_writable(stage, files)
            matched = TemplateAdapterRegistry().require(
                stage,
                str(template.get("adapterId", "")),
            )
            if _digest(matched) != _digest(template):
                raise AppError("materialized template contract differs from the inspected contract")
            incarnation = self._make_managed_incarnation(stage, instance_id)
            base_git = initialize_instance_repository(stage)
            parent_fd = os.open(
                destination.parent,
                os.O_RDONLY
                | os.O_CLOEXEC
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                _rename_no_replace(parent_fd, stage.name, parent_fd, destination.name)
            finally:
                os.close(parent_fd)
            promoted = os.lstat(destination)
            promoted_identity = (promoted.st_dev, promoted.st_ino)
            incarnation = _managed_incarnation_binding(
                destination,
                expected_instance_id=instance_id,
            )
            origin = {
                "formatVersion": "stateport.managed-template-source/v1",
                "management": "isolated_template",
                "templateId": str(template["applicationId"]),
                "adapterId": str(template["adapterId"]),
                "declaredTemplateId": template.get("declaredTemplateId"),
                "declaredVersion": template.get("declaredVersion"),
                "sourceKind": source.get("sourceKind"),
                "resolvedCommit": commit,
                "resolvedTree": expected_tree,
                "workingTreeChangesExcluded": True,
            }
            if source.get("sourceKind") == "public_git_snapshot":
                origin["remote"] = source["remote"]
            catalog_entry = self.catalog.register(
                destination,
                instance_id=instance_id,
                name=name.strip(),
                source=origin,
                application_id=str(template["applicationId"]),
                managed_incarnation=incarnation,
            )
            receipt = {
                "formatVersion": TEMPLATE_INSTALL_RECEIPT_FORMAT,
                "operation": "template-import",
                "instanceId": instance_id,
                "applicationId": str(template["applicationId"]),
                "planDigest": plan["planDigest"],
                "inspectionDigest": plan["inspectionDigest"],
                "source": origin,
                "template": copy.deepcopy(dict(template)),
                "baseGit": base_git,
                "managedIncarnation": incarnation,
                "catalogIdentity": {
                    "instanceId": catalog_entry["instanceId"],
                    "applicationId": catalog_entry["applicationId"],
                    "createdAt": catalog_entry["createdAt"],
                    "filesystemIdentityDigest": _digest(catalog_entry["filesystem"]),
                },
                "approval": {
                    "actorId": actor_id,
                    "decision": "approved",
                    "planDigest": plan["planDigest"],
                },
                "effects": copy.deepcopy(dict(plan["effects"])),
                "createdAt": _now(),
            }
            if receipt_path.exists() or receipt_path.is_symlink():
                raise AppError("template import receipt already exists")
            _write_json(receipt_path, receipt)
            return {
                "formatVersion": "stateport.template-install-result/v1",
                "instanceId": instance_id,
                "applicationId": str(template["applicationId"]),
                "name": name.strip(),
                "source": origin,
                "template": copy.deepcopy(dict(template)),
                "baseGit": base_git,
                "managedIncarnationDigest": incarnation["markerDigest"],
                "receiptDigest": _digest(receipt),
                "sourceRepositoryMutated": False,
                "managedCopyCreated": True,
            }
        except Exception:
            catalog_removed = catalog_entry is None
            if catalog_entry is not None:
                catalog_removed = self.catalog.forget_if_matches(catalog_entry)
            if receipt_path.is_file() and not receipt_path.is_symlink():
                receipt_path.unlink()
            if stage.exists() and not stage.is_symlink():
                shutil.rmtree(stage, ignore_errors=True)
            if destination.exists() and catalog_removed and promoted_identity is not None:
                try:
                    current = os.lstat(destination)
                except OSError:
                    current = None
                if current is not None and (
                    current.st_dev,
                    current.st_ino,
                ) == promoted_identity:
                    shutil.rmtree(destination, ignore_errors=True)
            raise

    def managed_template_binding(
        self,
        instance_id: str,
        *,
        adapter_id: str,
        application_id: str,
    ) -> tuple[Path, dict[str, Any]]:
        """Validate a managed template's catalog, marker, and adapter identity."""

        entry, root = self._entry(instance_id)
        metadata = entry.get("metadata")
        source = entry.get("observedSource")
        if (
            entry.get("applicationId") != application_id
            or not isinstance(metadata, Mapping)
            or not isinstance(metadata.get("managedIncarnation"), Mapping)
            or not isinstance(source, Mapping)
            or source.get("formatVersion") != "stateport.managed-template-source/v1"
            or source.get("management") != "isolated_template"
            or source.get("adapterId") != adapter_id
            or source.get("templateId") != application_id
        ):
            raise AppError("managed template catalog binding is invalid")
        match = TemplateAdapterRegistry().require(root, adapter_id)
        if match.get("applicationId") != application_id:
            raise AppError("managed template adapter application identity changed")
        return root, match

    def plan_create(self, *, source_profile: str, instance_id: str, name: str, owner_name: str, owner_handle: str, target_id: str, target_title: str = "", timezone: str = "UTC", learning_goal: str = "", seed_mode: str = "empty", destination: str | None = None, source_repository: str | None = None, allow_development_candidate: bool = False) -> dict[str, Any]:
        _validate_id(instance_id, "instance_id")
        _validate_id(target_id, "target_id")
        if allow_development_candidate:
            _, _, resolved = self._resolve_development_candidate(
                source_profile=source_profile,
                source_repository=source_repository,
            )
            contract = resolved.contract
        else:
            contract, resolved = self._contract(source_profile, source_repository)
        bootstrap = _bootstrap_contract(resolved.root)
        values = validate_bootstrap(bootstrap, {"instance_id": instance_id, "display_name": name, "owner_name": owner_name, "owner_handle": owner_handle, "target_id": target_id, "target_title": target_title, "timezone": timezone, "learning_goal": learning_goal, "seed_mode": seed_mode})
        destination_path = _safe_instance_root(Path(destination).expanduser() if destination else self.layout.instances_root / instance_id)
        try:
            destination_path.relative_to(self.layout.instances_root)
            root_conflict = "none"
        except ValueError:
            root_conflict = "outside_catalog_root"
        if root_conflict != "none":
            conflict = root_conflict
        elif destination_path.exists() and any(destination_path.iterdir()):
            conflict = "nonempty"
        elif destination_path.exists() and destination_path.is_symlink():
            conflict = "symlink"
        else:
            conflict = "none"
        source_identity = resolved.to_dict()
        source_identity.pop("checkoutLocation", None)
        payload = {
            "formatVersion": "stateport.instance-create-plan/v1",
            "operation": "instance-create",
            "instanceId": instance_id,
            "name": name,
            "destination": destination_path.as_posix(),
            "sourceProfile": source_profile,
            "sourceAccessClass": (
                "development_candidate" if allow_development_candidate else "canonical_release"
            ),
            "productionInstallAllowed": not allow_development_candidate,
            "source": source_identity,
            "bootstrap": {"contract": bootstrap["formatVersion"], "fields": values, "seedMode": values.get("seed_mode")},
            "plannedFiles": sorted({item.get("path") for item in resolved.manifest.get("files", []) if isinstance(item, Mapping)} | {item.get("path") for item in resolved.manifest.get("trees", []) if isinstance(item, Mapping)} | {item.get("path") for item in bootstrap.get("writes", []) if isinstance(item, Mapping)}),
            "ownership": {owner: sum(1 for item in resolved.manifest.get("files", []) if isinstance(item, Mapping) and item.get("owner") == owner) for owner in ("template", "instance", "generated", "override")},
            "conflict": conflict,
            "approvalRequired": True,
            "createdAt": _now(),
        }
        payload["planDigest"] = _digest(payload)
        return payload

    def approve(self, plan: Mapping[str, Any], operator_id: str = "local-operator") -> dict[str, Any]:
        expected = plan.get("planDigest")
        unsigned = dict(plan)
        unsigned.pop("planDigest", None)
        if expected != _digest(unsigned):
            raise ApprovalError("plan digest is not self-consistent")
        approval = {"formatVersion": APPROVAL_FORMAT, "operation": plan.get("operation"), "planDigest": expected, "operatorId": operator_id, "approvedAt": _now(), "expiresAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")}
        approval["approvalDigest"] = _digest(approval)
        return approval

    def create(self, plan: Mapping[str, Any], approval: Mapping[str, Any] | None = None) -> dict[str, Any]:
        if plan.get("planDigest") != _digest({key: value for key, value in plan.items() if key != "planDigest"}):
            raise ApprovalError("plan digest does not match exact plan")
        if (
            approval is None
            or approval.get("planDigest") != plan.get("planDigest")
            or approval.get("approvalDigest")
            != _digest({key: value for key, value in approval.items() if key != "approvalDigest"})
        ):
            raise ApprovalError("exact plan approval is required")
        destination = _safe_instance_root(Path(str(plan["destination"])))
        if plan.get("conflict") == "outside_catalog_root":
            raise AppError("destination must be inside the canonical StatePort instance root")
        destination_preexisted = destination.exists()
        destination_before = os.lstat(destination) if destination_preexisted else None
        if destination.exists() and (destination.is_symlink() or not destination.is_dir() or any(destination.iterdir())):
            raise AppError("destination is not an empty safe directory")
        source = plan["source"]
        source_repo = os.environ.get("STATEPORT_STUDYDD_MIRROR")
        if plan.get("sourceAccessClass") == "development_candidate":
            if plan.get("productionInstallAllowed") is not False:
                raise AppError("development-candidate plans cannot allow production installation")
            _, _, resolved = self._resolve_development_candidate(
                source_profile=str(plan.get("sourceProfile", "builtin:studydd-local-alpha")),
                source_repository=source_repo,
            )
            contract = resolved.contract
        elif plan.get("sourceAccessClass") == "canonical_release" and plan.get("productionInstallAllowed") is True:
            contract, resolved = self._contract(str(plan.get("sourceProfile", "builtin:studydd-local-alpha")), source_repo)
        else:
            raise AppError("instance creation plan has an unsupported source trust class")
        resolved_identity = {
            key: resolved.descriptor.get(key)
            for key in (
                "repository", "resolvedCommit", "resolvedTree", "manifestDigest",
                "sourceDigest", "sourceClass", "productionEligible",
            )
        }
        planned_identity = {key: source.get(key) for key in resolved_identity}
        if resolved_identity != planned_identity:
            raise AppError("source changed after plan; create a new plan")
        parent = destination.parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        stage = parent / f".{destination.name}.stateport-staging-{os.getpid()}"
        if stage.exists():
            shutil.rmtree(stage)
        catalog_entry: dict[str, Any] | None = None
        source_access_recorded = False
        destination_promoted = False
        promoted_identity: tuple[int, int] | None = None
        promoted_children: list[tuple[str, int, int]] = []
        try:
            create_instance(resolved.root, stage, instance_id=plan["instanceId"], name=plan["name"], owner_name=plan["bootstrap"]["fields"].get("owner_name", ""), owner_handle=plan["bootstrap"]["fields"].get("owner_handle", ""), status="active", source_descriptor=resolved.descriptor)
            bootstrap = _bootstrap_contract(resolved.root)
            inputs = dict(plan["bootstrap"]["fields"])
            inputs.update({"instance_id": plan["instanceId"], "display_name": plan["name"], "owner_name": plan["bootstrap"]["fields"].get("owner_name", ""), "owner_handle": plan["bootstrap"]["fields"].get("owner_handle", "")})
            apply_bootstrap(bootstrap, stage, inputs, template_root=resolved.root)
            validation = self._validate_managed_instance(
                stage,
                template_root=resolved.root,
                source_descriptor=resolved.descriptor,
            )
            result = {"valid": validation.ok, "issues": [{"path": issue.path, "message": issue.message} for issue in validation.issues]}
            if not validation.ok:
                first = result["issues"][0] if result["issues"] else {"path": "instance", "message": "unknown validation error"}
                raise AppError(
                    f"created StudyState instance failed StateSpec validation at {first['path']}: {first['message']}"
                )
            base_git = initialize_instance_repository(stage)
            if destination_preexisted:
                current = os.lstat(destination)
                if (
                    destination_before is None
                    or (current.st_dev, current.st_ino)
                    != (destination_before.st_dev, destination_before.st_ino)
                    or not stat.S_ISDIR(current.st_mode)
                    or any(destination.iterdir())
                ):
                    raise AppError("destination changed after planning")
                destination_promoted = True
                promoted_identity = (current.st_dev, current.st_ino)
                stage_fd = os.open(
                    stage,
                    os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                )
                destination_fd = os.open(
                    destination,
                    os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                )
                try:
                    for child in sorted(stage.iterdir(), key=lambda item: item.name):
                        child_identity = os.lstat(child)
                        _rename_no_replace(
                            stage_fd,
                            child.name,
                            destination_fd,
                            child.name,
                        )
                        promoted_children.append(
                            (child.name, child_identity.st_dev, child_identity.st_ino)
                        )
                finally:
                    os.close(destination_fd)
                    os.close(stage_fd)
                stage.rmdir()
            else:
                parent_fd = os.open(
                    parent,
                    os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                )
                try:
                    _rename_no_replace(
                        parent_fd,
                        stage.name,
                        parent_fd,
                        destination.name,
                    )
                finally:
                    os.close(parent_fd)
                destination_promoted = True
            promoted = os.lstat(destination)
            promoted_identity = (promoted.st_dev, promoted.st_ino)
            _template_id, installed_source = self._locked_source_at(destination)
            source_metadata = {
                "templateId": contract.template_id,
                **plan["source"],
                "sourceAccessClass": plan["sourceAccessClass"],
                "productionInstallAllowed": plan["productionInstallAllowed"],
            }
            entry = self.catalog.register(
                destination,
                instance_id=plan["instanceId"],
                name=plan["name"],
                source=source_metadata,
            )
            catalog_entry = entry
            entry_filesystem = entry.get("filesystem")
            if (
                not isinstance(entry_filesystem, Mapping)
                or (entry_filesystem.get("device"), entry_filesystem.get("inode"))
                != promoted_identity
            ):
                raise AppError("catalog registration observed a different instance directory")
            self._record_source_access_receipt(
                str(plan["instanceId"]),
                installed_source,
                filesystem_identity=entry["filesystem"],
                source_access_class=str(plan["sourceAccessClass"]),
                production_install_allowed=bool(plan["productionInstallAllowed"]),
                authority={
                    "kind": "instance_create",
                    "plan": copy.deepcopy(dict(plan)),
                    "approval": copy.deepcopy(dict(approval)),
                },
            )
            source_access_recorded = True
            receipt = {"formatVersion": "stateport.creation-receipt/v1", "planDigest": plan["planDigest"], "instanceId": plan["instanceId"], "destination": destination.as_posix(), "sourceAccessClass": plan["sourceAccessClass"], "productionInstallAllowed": plan["productionInstallAllowed"], "source": plan["source"], "baseGit": base_git, "validation": result, "catalogIdentity": entry, "createdAt": _now()}
            _write_json(self.layout.operations_root / "creations" / f"{plan['instanceId']}.json", receipt)
            return {"ok": True, "instanceId": plan["instanceId"], "path": destination.as_posix(), "dashboardCommand": "stateport service start --open", "receiptDigest": _digest(receipt), "sourceAccessClass": plan["sourceAccessClass"], "productionInstallAllowed": plan["productionInstallAllowed"], "source": plan["source"], "baseGit": base_git, "validation": result}
        except Exception:
            catalog_rolled_back = catalog_entry is None
            if catalog_entry is not None:
                catalog_rolled_back = self.catalog.forget_if_matches(catalog_entry)
            if source_access_recorded:
                self._discard_source_access_receipt(str(plan["instanceId"]))
            if stage.exists():
                shutil.rmtree(stage, ignore_errors=True)
            if destination_promoted and catalog_rolled_back:
                try:
                    current = os.lstat(destination)
                except OSError:
                    current = None
                if current is not None and promoted_identity == (current.st_dev, current.st_ino):
                    if destination_preexisted:
                        clean = True
                        for name, device, inode in reversed(promoted_children):
                            child = destination / name
                            try:
                                child_identity = os.lstat(child)
                            except OSError:
                                continue
                            if (child_identity.st_dev, child_identity.st_ino) != (
                                device,
                                inode,
                            ):
                                clean = False
                                continue
                            if stat.S_ISDIR(child_identity.st_mode):
                                shutil.rmtree(child, ignore_errors=True)
                            else:
                                try:
                                    child.unlink()
                                except OSError:
                                    clean = False
                        if clean and destination_before is not None and not any(
                            destination.iterdir()
                        ):
                            os.utime(
                                destination,
                                ns=(
                                    destination_before.st_atime_ns,
                                    destination_before.st_mtime_ns,
                                ),
                                follow_symlinks=False,
                            )
                    else:
                        shutil.rmtree(destination, ignore_errors=True)
            raise

    def instance_list(self) -> list[dict[str, Any]]:
        return self.catalog.list()

    @staticmethod
    def _locked_canonical_source_identity(source: Mapping[str, Any]) -> CanonicalSourceIdentity:
        return CanonicalSourceIdentity.from_mapping(
            {
                "repository": source.get("repository"),
                "commit": source.get("resolvedCommit"),
                "tree": source.get("resolvedTree"),
                "manifestDigest": source.get("manifestDigest"),
                "sourceDigest": source.get("sourceDigest"),
            },
            "installedSource.identity",
        )

    def _source_access_matches_current_authority(
        self,
        source: Mapping[str, Any],
        source_access_class: str,
        production_install_allowed: bool,
    ) -> bool:
        try:
            identity = self._locked_canonical_source_identity(source)
            descriptor = self._current_canonical_source()
        except Exception:  # noqa: BLE001 - unavailable authority fails closed
            return False
        if source_access_class == "development_candidate":
            return bool(
                production_install_allowed is False
                and descriptor.development_candidate is not None
                and descriptor.development_candidate.identity == identity
                and descriptor.trust.state == "development_only"
                and descriptor.trust.development_testing_allowed
            )
        return bool(
            source_access_class == "canonical_release"
            and production_install_allowed is True
            and descriptor.status.installable
            and descriptor.identity == identity
        )

    def _source_access_path(self, instance_id: str) -> Path:
        if not isinstance(instance_id, str) or not instance_id:
            raise AppError("source access instance identity must be a non-empty string")
        receipt_name = hashlib.sha256(instance_id.encode("utf-8")).hexdigest()
        return self.layout.source_access_root / f"{receipt_name}.json"

    @staticmethod
    def _source_access_identity(source: Mapping[str, Any]) -> dict[str, Any]:
        return {
            key: copy.deepcopy(source.get(key))
            for key in (
                "repository",
                "resolvedCommit",
                "resolvedTree",
                "manifestDigest",
                "sourceDigest",
                "sourceClass",
                "productionEligible",
            )
        }

    @staticmethod
    def _validated_filesystem_identity(value: Any) -> dict[str, Any]:
        if (
            not isinstance(value, Mapping)
            or set(value) != {"device", "inode", "kind"}
            or value.get("kind") != "directory"
            or any(
                isinstance(value.get(field), bool)
                or not isinstance(value.get(field), int)
                or int(value[field]) < 0
                for field in ("device", "inode")
            )
        ):
            raise AppError("source access filesystem identity is invalid")
        return copy.deepcopy(dict(value))

    @staticmethod
    def _validated_source_access_receipt(
        value: Any,
        *,
        expected_instance_id: str,
    ) -> dict[str, Any]:
        expected_keys = {
            "formatVersion",
            "instanceId",
            "sourceAccessClass",
            "productionInstallAllowed",
            "sourceIdentityDigest",
            "filesystemIdentity",
            "authority",
            "createdAt",
            "receiptDigest",
        }
        if not isinstance(value, Mapping) or set(value) != expected_keys:
            raise AppError("source access receipt is invalid")
        access_class = value.get("sourceAccessClass")
        production_allowed = value.get("productionInstallAllowed")
        source_identity_digest = value.get("sourceIdentityDigest")
        authority = value.get("authority")
        if (
            value.get("formatVersion") != SOURCE_ACCESS_FORMAT
            or value.get("instanceId") != expected_instance_id
            or (access_class, production_allowed)
            not in {
                ("canonical_release", True),
                ("development_candidate", False),
            }
            or not isinstance(source_identity_digest, str)
            or not _SOURCE_DIGEST.fullmatch(source_identity_digest)
            or not isinstance(authority, Mapping)
        ):
            raise AppError("source access receipt is invalid")
        PersistentApp._validated_filesystem_identity(value.get("filesystemIdentity"))
        authority_kind = authority.get("kind")
        authority_keys = {"kind", "plan", "approval"}
        if authority_kind == "restore_new_instance":
            authority_keys |= {"sourceInstanceId", "sourceReceiptDigest"}
        if set(authority) != authority_keys:
            raise AppError("source access receipt authority is invalid")
        plan = authority.get("plan")
        approval = authority.get("approval")
        if not isinstance(plan, Mapping) or not isinstance(approval, Mapping):
            raise AppError("source access receipt authority is invalid")
        plan_digest = plan.get("planDigest")
        approval_digest = approval.get("approvalDigest")
        if (
            not isinstance(plan_digest, str)
            or not _SOURCE_DIGEST.fullmatch(plan_digest)
            or plan_digest != _digest({key: item for key, item in plan.items() if key != "planDigest"})
            or not isinstance(approval_digest, str)
            or not _SOURCE_DIGEST.fullmatch(approval_digest)
            or approval_digest != _digest({key: item for key, item in approval.items() if key != "approvalDigest"})
            or approval.get("planDigest") != plan_digest
        ):
            raise AppError("source access receipt authority is invalid")
        if authority_kind == "instance_create":
            plan_source = plan.get("source")
            if (
                plan.get("formatVersion") != "stateport.instance-create-plan/v1"
                or plan.get("operation") != "instance-create"
                or plan.get("instanceId") != expected_instance_id
                or plan.get("sourceAccessClass") != access_class
                or plan.get("productionInstallAllowed") is not production_allowed
                or not isinstance(plan_source, Mapping)
                or _digest(PersistentApp._source_access_identity(plan_source)) != source_identity_digest
                or approval.get("formatVersion") != APPROVAL_FORMAT
                or approval.get("operation") != "instance-create"
            ):
                raise AppError("source access receipt authority is invalid")
        elif authority_kind == "restore_new_instance":
            source_instance_id = authority.get("sourceInstanceId")
            source_receipt_digest = authority.get("sourceReceiptDigest")
            effects = plan.get("effects")
            planned_access = effects.get("sourceAccess") if isinstance(effects, Mapping) else None
            if (
                plan.get("formatVersion") != RESTORE_PLAN_FORMAT
                or plan.get("operation") != "restore_new_instance"
                or plan.get("destinationInstanceId") != expected_instance_id
                or not isinstance(source_instance_id, str)
                or not _ID.fullmatch(source_instance_id)
                or plan.get("sourceInstanceId") != source_instance_id
                or approval.get("sourceInstanceId") != source_instance_id
                or approval.get("destinationInstanceId") != expected_instance_id
                or approval.get("formatVersion") != RESTORE_APPROVAL_FORMAT
                or approval.get("operation") != "restore_new_instance"
                or approval.get("decision") != "approved"
                or not isinstance(source_receipt_digest, str)
                or not _SOURCE_DIGEST.fullmatch(source_receipt_digest)
                or not isinstance(planned_access, Mapping)
                or planned_access.get("disposition") != "propagate_exact_receipt"
                or planned_access.get("sourceAccessClass") != access_class
                or planned_access.get("productionInstallAllowed") is not production_allowed
                or planned_access.get("sourceReceiptDigest") != source_receipt_digest
            ):
                raise AppError("source access receipt authority is invalid")
        else:
            raise AppError("source access receipt authority is invalid")
        _parse_utc(value.get("createdAt"), "source access receipt timestamp")
        unsigned = {key: item for key, item in value.items() if key != "receiptDigest"}
        if value.get("receiptDigest") != _digest(unsigned):
            raise AppError("source access receipt digest is invalid")
        return copy.deepcopy(dict(value))

    def _load_source_access_receipt(
        self,
        instance_id: str,
        source_identity: Mapping[str, Any],
        filesystem_identity: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        path = self._source_access_path(instance_id)
        if not path.exists():
            return None
        if path.is_symlink() or not path.is_file() or path.parent.is_symlink():
            raise AppError("source access receipt path is unsafe")
        receipt = self._validated_source_access_receipt(
            _load_json(path, None), expected_instance_id=instance_id,
        )
        if receipt["sourceIdentityDigest"] != _digest(self._source_access_identity(source_identity)):
            return None
        if receipt["filesystemIdentity"] != self._validated_filesystem_identity(filesystem_identity):
            return None
        if not self._source_access_matches_current_authority(
            source_identity,
            str(receipt["sourceAccessClass"]),
            bool(receipt["productionInstallAllowed"]),
        ):
            return None
        return receipt

    def _record_source_access_receipt(
        self,
        instance_id: str,
        source_identity: Mapping[str, Any],
        *,
        filesystem_identity: Mapping[str, Any],
        source_access_class: str,
        production_install_allowed: bool,
        authority: Mapping[str, Any],
        authority_guard: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        if not self._source_access_matches_current_authority(
            source_identity, source_access_class, production_install_allowed,
        ):
            raise AppError("source access authority no longer matches the tracked source")
        receipt = {
            "formatVersion": SOURCE_ACCESS_FORMAT,
            "instanceId": instance_id,
            "sourceAccessClass": source_access_class,
            "productionInstallAllowed": production_install_allowed,
            "sourceIdentityDigest": _digest(self._source_access_identity(source_identity)),
            "filesystemIdentity": self._validated_filesystem_identity(filesystem_identity),
            "authority": copy.deepcopy(dict(authority)),
            "createdAt": _now(),
        }
        receipt["receiptDigest"] = _digest(receipt)
        receipt = self._validated_source_access_receipt(receipt, expected_instance_id=instance_id)
        if authority_guard is not None:
            authority_guard()
        _write_json_new(self._source_access_path(instance_id), receipt)
        return receipt

    def _discard_source_access_receipt(self, instance_id: str) -> None:
        path = self._source_access_path(instance_id)
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise AppError("source access receipt path is unsafe")
        try:
            path.unlink()
        except FileNotFoundError:
            pass

    def _effective_source_access(
        self,
        instance_id: str,
        entry: Mapping[str, Any],
        source_identity: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        metadata = entry.get("metadata")
        if isinstance(metadata, Mapping) and metadata.get("externalRepository") is True:
            return None
        source = entry.get("observedSource")
        filesystem = entry.get("filesystem")
        if not isinstance(source, Mapping) or not isinstance(filesystem, Mapping):
            return None
        receipt = self._load_source_access_receipt(instance_id, source_identity, filesystem)
        if receipt is None:
            return None
        if (
            source.get("sourceAccessClass") != receipt["sourceAccessClass"]
            or source.get("productionInstallAllowed") is not receipt["productionInstallAllowed"]
        ):
            return None
        return receipt

    def source_access_authorization(self, instance_id: str) -> dict[str, Any] | None:
        """Return the currently effective, receipt-bound source access grant."""

        try:
            entry = self.catalog.get(instance_id)
            locked = self.locked_source(instance_id)["source"]
            receipt = self._effective_source_access(instance_id, entry, locked)
        except (AppError, CatalogError):
            return None
        if receipt is None:
            return None
        return {
            "sourceAccessClass": receipt["sourceAccessClass"],
            "productionInstallAllowed": receipt["productionInstallAllowed"],
            "receiptDigest": receipt["receiptDigest"],
        }

    def development_candidate_testing_allowed(self, instance_id: str) -> bool:
        receipt = self.source_access_authorization(instance_id)
        return bool(
            receipt
            and receipt["sourceAccessClass"] == "development_candidate"
            and receipt["productionInstallAllowed"] is False
        )

    def register_external_repository(
        self,
        path: Path,
        *,
        instance_id: str,
        name: str,
        application_id: str,
        source: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Register an allowlisted user-owned repository without copying it."""

        return self.catalog.register_external(
            path,
            instance_id=instance_id,
            name=name,
            application_id=application_id,
            source=source,
        )

    def rename_instance(self, instance_id: str, *, name: Any, expected_name: Any,
                        actor_id: str, actor_role: str) -> dict[str, Any]:
        """Change the local display name without touching source or instance files."""
        if actor_role not in {"local_user", "platform_operator"}:
            raise ApplicationRenameError("rename_forbidden", "application rename requires local mutation authority")
        if not isinstance(name, str) or not isinstance(expected_name, str):
            raise ApplicationRenameError("rename_invalid", "application name and reviewed name must be strings")
        return self.catalog.rename(instance_id, name=name, expected_name=expected_name,
                                   actor_id=actor_id, actor_role=actor_role)

    def instance_list_public(self) -> list[dict[str, Any]]:
        """Return the browser-safe catalog representation without local paths."""

        public: list[dict[str, Any]] = []
        for entry in self.instance_list():
            item = dict(entry)
            observed_source = (
                dict(entry["observedSource"])
                if isinstance(entry.get("observedSource"), Mapping)
                else {}
            )
            for field in ("sourceAccessClass", "productionInstallAllowed"):
                observed_source.pop(field, None)
            try:
                locked = self.locked_source(str(entry["instanceId"]))["source"]
                source_access = self._effective_source_access(
                    str(entry["instanceId"]), entry, locked,
                )
            except AppError:
                source_access = None
            if source_access:
                observed_source.update(
                    {
                        "sourceAccessClass": source_access["sourceAccessClass"],
                        "productionInstallAllowed": source_access["productionInstallAllowed"],
                    }
                )
            item["observedSource"] = observed_source
            item.pop("path", None)
            item.pop("filesystem", None)
            item.pop("metadata", None)
            public.append(item)
        return public

    def application_rename_receipts(self, instance_id: str) -> list[dict[str, Any]]:
        """Read the atomic catalog history used to rebuild the receipt index."""
        metadata = self.catalog.get(instance_id).get("metadata", {})
        history = metadata.get("displayNameChanges", []) if isinstance(metadata, Mapping) else None
        if not isinstance(history, list) or any(not isinstance(item, dict) for item in history):
            raise AppError("catalog name-change history is invalid")
        return copy.deepcopy(history)

    @staticmethod
    def _validated_application_install_receipt(
        receipt: Mapping[str, Any],
        *,
        expected_instance_id: str | None = None,
    ) -> dict[str, Any]:
        """Validate the durable browser-install authority without reconstructing it."""

        required = {
            "formatVersion", "receiptId", "operation", "applicationId",
            "instanceId", "actor", "descriptorIdentities", "source",
            "baseGit", "catalogIdentity", "consent", "createdAt",
        }
        if (
            not isinstance(receipt, Mapping)
            or not required.issubset(set(receipt))
            or set(receipt) - required > {"lifecycle"}
            or receipt.get("formatVersion") != "stateport.application-install-receipt/v1"
            or receipt.get("operation") != "install_public_fixture"
        ):
            raise AppError("application install receipt shape is invalid")
        lifecycle_provenance = receipt.get("lifecycle")
        if lifecycle_provenance is not None:
            if (
                not isinstance(lifecycle_provenance, Mapping)
                or set(lifecycle_provenance)
                != {"formatVersion", "templateId", "releaseVersion", "sourceRevision", "revisionId"}
                or lifecycle_provenance.get("formatVersion") != "statedd.lock/v1"
                or not isinstance(lifecycle_provenance.get("templateId"), str)
                or not re.fullmatch(
                    r"stateport\.fixture\.[a-z0-9][a-z0-9.-]*",
                    str(lifecycle_provenance.get("templateId")),
                )
                or not isinstance(lifecycle_provenance.get("releaseVersion"), str)
                or not lifecycle_provenance.get("releaseVersion")
                or not re.fullmatch(
                    r"sha256:[0-9a-f]{64}",
                    str(lifecycle_provenance.get("sourceRevision", "")),
                )
                or not isinstance(lifecycle_provenance.get("revisionId"), str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", str(lifecycle_provenance.get("revisionId")))
            ):
                raise AppError("application install receipt lifecycle provenance is invalid")
        value = dict(receipt)
        instance_id = value.get("instanceId")
        application_id = value.get("applicationId")
        if (
            not isinstance(instance_id, str)
            or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", instance_id)
            or (
                expected_instance_id is not None
                and not secrets.compare_digest(instance_id, expected_instance_id)
            )
            or not isinstance(application_id, str)
            or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", application_id)
        ):
            raise AppError("application install receipt identity is invalid")
        base_git = value.get("baseGit")
        receipt_id = value.get("receiptId")
        if (
            not isinstance(base_git, str)
            or not re.fullmatch(r"[0-9a-f]{40,64}", base_git)
            or receipt_id != f"application-install.{instance_id}.{base_git[:12]}"
        ):
            raise AppError("application install receipt Git or receipt identity is invalid")

        consent = value.get("consent")
        actor = value.get("actor")
        if (
            consent not in {"explicit_browser_confirmation", "trusted_internal"}
            or not isinstance(actor, Mapping)
            or set(actor) != {"actorId", "route"}
            or actor.get("route") != consent
            or not isinstance(actor.get("actorId"), str)
            or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", str(actor.get("actorId")))
        ):
            raise AppError("application install receipt actor binding is invalid")

        identities = value.get("descriptorIdentities")
        application_identity = (
            identities.get("application") if isinstance(identities, Mapping) else None
        )
        experience_identity = (
            identities.get("experience") if isinstance(identities, Mapping) else None
        )
        if (
            not isinstance(identities, Mapping)
            or set(identities) != {"application", "experience"}
            or not isinstance(application_identity, Mapping)
            or set(application_identity)
            != {"formatVersion", "applicationId", "descriptorDigest", "packageDigest"}
            or application_identity.get("applicationId") != application_id
            or not isinstance(application_identity.get("formatVersion"), str)
            or not re.fullmatch(
                r"sha256:[0-9a-f]{64}",
                str(application_identity.get("descriptorDigest", "")),
            )
            or not re.fullmatch(
                r"sha256:[0-9a-f]{64}",
                str(application_identity.get("packageDigest", "")),
            )
            or not isinstance(experience_identity, Mapping)
            or set(experience_identity) != {"descriptorDigest"}
        ):
            raise AppError("application install receipt descriptor identity is invalid")
        experience_digest = experience_identity.get("descriptorDigest")
        if (
            experience_digest != "trusted_internal_not_supplied"
            and (
                not isinstance(experience_digest, str)
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", experience_digest)
            )
        ):
            raise AppError("application install receipt experience identity is invalid")

        source = value.get("source")
        if (
            not isinstance(source, Mapping)
            or set(source)
            != {"digest", "profile", "networkPolicy", "productionEligible"}
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(source.get("digest", "")))
            or not isinstance(source.get("profile"), str)
            or not str(source.get("profile")).startswith("fixture:")
            or source.get("networkPolicy") != "disabled"
            or source.get("productionEligible") is not False
        ):
            raise AppError("application install receipt source identity is invalid")
        catalog_identity = value.get("catalogIdentity")
        if (
            not isinstance(catalog_identity, Mapping)
            or catalog_identity.get("instanceId") != instance_id
            or catalog_identity.get("applicationId") != application_id
        ):
            raise AppError("application install receipt catalog identity is invalid")
        created_at = value.get("createdAt")
        if not isinstance(created_at, str) or not created_at.endswith("Z"):
            raise AppError("application install receipt timestamp is invalid")
        try:
            created = datetime.fromisoformat(created_at[:-1] + "+00:00")
        except ValueError as exc:
            raise AppError("application install receipt timestamp is invalid") from exc
        if created.tzinfo is None or created.utcoffset() != timezone.utc.utcoffset(created):
            raise AppError("application install receipt timestamp is invalid")
        return value

    def record_application_install_receipt(self, receipt: Mapping[str, Any]) -> str:
        """Persist one browser-install receipt without exposing local paths.

        The caller owns the surrounding instance/catalog transaction.  This
        helper only accepts the closed v1 receipt shape and refuses to replace
        an existing receipt so a repeated request cannot rewrite history.
        """

        value = self._validated_application_install_receipt(receipt)
        instance_id = str(value["instanceId"])
        path = self.layout.operations_root / "application-installs" / f"{instance_id}.json"
        if path.exists() or path.is_symlink():
            raise AppError("application install receipt already exists")
        _write_json(path, value)
        return _digest(value)

    def application_install_receipt(self, instance_id: str) -> dict[str, Any] | None:
        """Load the exact durable install receipt used to rebuild projections."""

        if not isinstance(instance_id, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", instance_id):
            raise AppError("application install receipt instance identity is unsafe")
        path = self.layout.operations_root / "application-installs" / f"{instance_id}.json"
        if not path.exists():
            return None
        if path.is_symlink() or not path.is_file():
            raise AppError("application install receipt path is unsafe")
        value = _load_json(path, None)
        if not isinstance(value, Mapping):
            raise AppError("application install receipt is invalid")
        return self._validated_application_install_receipt(
            value,
            expected_instance_id=instance_id,
        )

    def discard_application_install_receipt(self, instance_id: str) -> None:
        """Remove only a receipt created by a transaction being rolled back."""

        if not isinstance(instance_id, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", instance_id):
            raise AppError("application install receipt instance identity is unsafe")
        path = self.layout.operations_root / "application-installs" / f"{instance_id}.json"
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise AppError("application install receipt path is unsafe")
        try:
            path.unlink()
        except FileNotFoundError:
            pass

    def import_instance(self, path: str) -> dict[str, Any]:
        root = _safe_instance_root(Path(path), must_exist=True)
        descriptor = _read_yaml(root / "instance.yaml")
        lock = _read_yaml(root / ".statedd/lock.yaml")
        metadata = descriptor.get("metadata") if isinstance(descriptor.get("metadata"), Mapping) else {}
        instance_id = metadata.get("id") or lock.get("instanceId")
        name = metadata.get("name") or instance_id
        source = lock.get("template", {}).get("source") if isinstance(lock.get("template"), Mapping) else None
        if not isinstance(instance_id, str) or not _ID.fullmatch(instance_id):
            raise AppError("existing instance has no safe instance ID")
        if not isinstance(source, Mapping) or not source.get("resolvedCommit") or not source.get("resolvedTree") or not source.get("manifestDigest"):
            raise AppError("existing instance lock does not contain exact source identity")
        validation = self._validate_managed_instance(root)
        if not validation.ok:
            raise AppError("existing instance failed StateSpec validation and was not imported")
        entry = self.catalog.register(root, instance_id=instance_id, name=str(name), source={"templateId": lock.get("template", {}).get("id", "studydd"), **dict(source)})
        backups = _load_json(self.layout.data_root / "backups" / "index.json", {"entries": []}).get("entries", [])
        matching = [item for item in backups if item.get("instanceId") == instance_id]
        if matching:
            entry = self.catalog.update(instance_id, lastBackup=matching[-1])
        return {"ok": True, "mode": "read-only-import", "entry": entry, "validation": {"valid": True, "issues": []}}

    def _entry(
        self,
        instance_id: str,
        *,
        allow_stale_replacement: bool = False,
    ) -> tuple[dict[str, Any], Path]:
        entry = self.catalog.get(instance_id)
        if entry.get("pathState") != "present":
            if (
                allow_stale_replacement
                and entry.get("pathState") == "stale"
                and entry.get("contentIdentity") is None
            ):
                pass
            elif entry.get("pathState") == "stale" and entry.get("contentIdentity") is not None:
                raise AppError("instance repository content identity changed")
            else:
                raise AppError("instance path is unavailable or changed")
        root = _safe_instance_root(Path(entry["path"]), must_exist=True)
        return entry, root

    def inspect(self, instance_id: str) -> dict[str, Any]:
        entry, root = self._entry(instance_id)
        lock = _read_yaml_optional(root / ".statedd/lock.yaml")
        descriptor = _read_yaml_optional(root / "instance.yaml")
        application = _read_yaml_optional(root / "application.yaml")
        if not descriptor and application:
            descriptor = {"kind": "Application", "spec": {"mode": None}, "applicationId": application.get("applicationId"), "displayName": application.get("displayName"), "formatVersion": application.get("formatVersion")}
        template = lock.get("template", {}) if isinstance(lock.get("template"), Mapping) else {}
        source = dict(template.get("source", {})) if isinstance(template.get("source"), Mapping) else {}
        source.pop("checkoutLocation", None)
        source.pop("profile", None)
        files = lock.get("files", []) if isinstance(lock.get("files"), list) else []
        ownership = {owner: [] for owner in ("template", "instance", "generated", "override")}
        if files:
            for item in files:
                if isinstance(item, Mapping) and item.get("owner") in ownership:
                    ownership[item["owner"]].append(item.get("path"))
        else:
            ownership = _scan_instance_files(root)
        counts = {key: len(value) for key, value in ownership.items()}
        bounded_paths = {key: sorted(value)[:24] for key, value in ownership.items()}
        if not source:
            source = dict(entry.get("observedSource", {})) if isinstance(entry.get("observedSource"), Mapping) else {}
        if not source:
            source = {"templateId": application.get("applicationId") or "fixture"}
        external = bool(entry.get("metadata", {}).get("externalRepository")) if isinstance(entry.get("metadata"), Mapping) else False
        for field in ("sourceAccessClass", "productionInstallAllowed"):
            source.pop(field, None)
        if not external:
            source_access = self._effective_source_access(instance_id, entry, source)
            if source_access:
                source.update(
                    {
                        "sourceAccessClass": source_access["sourceAccessClass"],
                        "productionInstallAllowed": source_access["productionInstallAllowed"],
                    }
                )
        if external:
            source.setdefault("sourceKind", "local")
            source.setdefault("ownership", "user_owned_repository")
        package_state = self._package_state(entry, root)
        return {"instance": {"id": instance_id, "name": entry.get("name"), "pathState": entry.get("pathState", "present"), "descriptor": {"kind": "ProjectState" if external else descriptor.get("kind"), "mode": descriptor.get("spec", {}).get("mode") if isinstance(descriptor.get("spec"), Mapping) else None}}, "source": source, "version": template.get("version") or descriptor.get("formatVersion"), "health": "valid" if entry.get("pathState") == "present" else "unavailable", "ownership": {"counts": counts, "paths": bounded_paths, "truncated": {key: len(value) > 24 for key, value in ownership.items()}}, "recovery": self.recovery(instance_id), "runs": self.runs(instance_id), "approvals": [], "capabilities": ["inspect", "verify", "backup", "synthetic-run", "import-state"], **({"packageState": package_state} if package_state is not None else {})}

    @staticmethod
    def _package_state(entry: Mapping[str, Any], root: Path) -> dict[str, Any] | None:
        if entry.get("applicationId") != "studystate.sample":
            return None
        path = root / "state/LEARNING.yaml"
        value = _read_yaml_optional(path)
        if value.get("formatVersion") != "studystate.sample.state/v1":
            raise AppError("StudyState durable learning state is invalid")
        goal = value.get("goal")
        activities = value.get("activities")
        evidence = value.get("evidence")
        if not isinstance(goal, Mapping) or not isinstance(activities, list) or not isinstance(evidence, list):
            raise AppError("StudyState durable learning state is incomplete")
        plan_value = {
            "goal": {"id": goal.get("id"), "label": goal.get("label")},
            "activities": [
                {
                    "id": item.get("id"),
                    "label": item.get("label"),
                    "reason": item.get("reason"),
                    "status": item.get("status"),
                }
                for item in activities
                if isinstance(item, Mapping)
            ],
        }
        plan_digest = _digest(plan_value)
        fallback_updated = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()
        projected_activities = []
        active_activity_count = 0
        for item in activities:
            if not isinstance(item, Mapping) or not isinstance(item.get("id"), str) or not isinstance(item.get("label"), str):
                raise AppError("StudyState activity state is invalid")
            status = {
                "planned": "not_started",
                "in_progress": "in_progress",
                "paused": "paused",
                "completed": "done",
            }.get(item.get("status"))
            if status is None:
                raise AppError("StudyState activity status is invalid")
            active_activity_count += status == "in_progress"
            projected_activities.append({
                "id": item["id"],
                "title": item["label"],
                "reason": str(item.get("reason", "Selected from the durable learning plan.")),
                "state": status,
                "updatedAt": str(item.get("updatedAt", fallback_updated)),
            })
        if active_activity_count > 1:
            raise AppError("StudyState may have only one active activity")
        projected_evidence = []
        for item in evidence:
            if not isinstance(item, Mapping) or not isinstance(item.get("id"), str) or not isinstance(item.get("summary"), str):
                raise AppError("StudyState evidence state is invalid")
            assessment = item.get("assessment")
            assessment_verified = bool(
                isinstance(assessment, Mapping)
                and assessment.get("status") == "verified"
                and isinstance(assessment.get("assessedBy"), str)
                and bool(assessment.get("assessedBy"))
                and isinstance(assessment.get("assessedAt"), str)
                and bool(assessment.get("assessedAt"))
            )
            projected_evidence.append({
                "id": item["id"],
                "title": item["summary"],
                "state": "verified" if assessment_verified else "self_reported",
                "updatedAt": str(item.get("updatedAt", fallback_updated)),
            })
        transition = value.get("lastTransition")
        transition_keys = (
            "kind", "proposalId", "undidProposalId", "activityId", "evidenceId",
            "priorStatus", "fromActivityId", "toActivityId", "beforePlanDigest", "afterPlanDigest",
            "restoredPlanDigest", "updatedAt",
        )
        bounded_transition = (
            {key: transition[key] for key in transition_keys if key in transition}
            if isinstance(transition, Mapping)
            else None
        )
        can_undo = bool(
            bounded_transition
            and bounded_transition.get("kind") == "evidence_applied"
            and bounded_transition.get("afterPlanDigest") == plan_digest
        )
        completed = sum(1 for item in projected_activities if item["state"] == "done")
        return {
            "kind": "study-state",
            "goal": str(goal.get("label", "")),
            "goalProgressPercent": round((completed / len(projected_activities)) * 100) if projected_activities else 0,
            "activities": projected_activities,
            "evidence": projected_evidence,
            "planDigest": plan_digest,
            "canUndo": can_undo,
            **({"lastTransition": bounded_transition} if bounded_transition is not None else {}),
        }

    @staticmethod
    def _public_backup_entry(value: Mapping[str, Any]) -> dict[str, Any]:
        """Project backup state without its host-local archive pathname."""

        projected = {
            key: copy.deepcopy(item)
            for key, item in value.items()
            if key != "archive"
        }
        projected["storageLocation"] = "stateport_managed_backup_root"
        return projected

    def recovery(self, instance_id: str) -> dict[str, Any]:
        index = _load_json(
            self.layout.data_root / "backups" / "index.json",
            {"formatVersion": "stateport.backup-index/v1", "entries": []},
        )
        items = index.get("entries", []) if isinstance(index, Mapping) else []
        if not isinstance(items, list):
            return {
                "status": "degraded",
                "latest": None,
                "operatorInspectionRequired": True,
                "verificationIssues": ["backup index entries are malformed"],
            }
        matches = [item for item in items if isinstance(item, Mapping) and item.get("instanceId") == instance_id]
        if not matches:
            return {"status": "no_backup", "latest": None}

        latest = dict(matches[-1])
        issues: list[str] = []
        archive_value = latest.get("archive")
        archive = Path(archive_value).expanduser() if isinstance(archive_value, str) and archive_value else None
        backup_root = _safe_instance_root(self.layout.backups_root, must_exist=True)
        if archive is None:
            issues.append("backup index entry has no archive path")
        else:
            if archive.is_symlink() or not archive.is_file():
                issues.append("recorded backup archive is missing or not a regular file")
            else:
                try:
                    resolved_archive = archive.resolve(strict=True)
                    if not resolved_archive.is_relative_to(backup_root.resolve(strict=True)):
                        issues.append("recorded backup archive is outside the StatePort backup root")
                    else:
                        manifest = read_manifest(resolved_archive)
                        if manifest.get("instanceId") != instance_id:
                            issues.append("backup manifest instance identity does not match the catalog instance")
                        if latest.get("archiveDigest") != manifest.get("archiveDigest"):
                            issues.append("backup inventory digest does not match the index")
                        actual_file_digest = _file_digest(resolved_archive)
                        if latest.get("archiveFileDigest") != actual_file_digest:
                            issues.append("backup archive digest does not match the index")
                except (BackupError, OSError, ValueError) as exc:
                    # Keep the reason bounded and actionable; do not expose
                    # parser internals or archive contents in the projection.
                    _ = exc
                    issues.append("recorded backup archive failed integrity verification")

        if issues:
            return {
                "status": "degraded",
                "latest": self._public_backup_entry(latest),
                "operatorInspectionRequired": True,
                "verificationIssues": sorted(set(issues)),
            }
        return {
            "status": "verified",
            "latest": self._public_backup_entry(latest),
            "operatorInspectionRequired": False,
            "verification": {
                "archive": "confined_regular_file",
                "manifest": "validated",
                "payload": "content_hashes_validated",
                "index": "digests_match",
                "checkedAt": _now(),
            },
        }

    def runs(self, instance_id: str) -> list[dict[str, Any]]:
        return [item for item in _load_json(self.layout.operations_root / "runs.json", {"formatVersion": "stateport.run-history/v1", "entries": []}).get("entries", []) if item.get("instanceId") == instance_id]

    def synthetic_run(self, instance_id: str) -> dict[str, Any]:
        _, root = self._entry(instance_id)
        before = _digest(sorted((path.relative_to(root).as_posix(), _file_digest(path)) for path in root.rglob("*") if path.is_file() and not path.is_symlink()))
        ir = build_state_ir(root)
        pack = build_state_pack(ir, task="StudyState synthetic contract inspection", model="synthetic/local-alpha", budget_tokens=1000, profile="compact", selection="eager")
        after = _digest(sorted((path.relative_to(root).as_posix(), _file_digest(path)) for path in root.rglob("*") if path.is_file() and not path.is_symlink()))
        result = {"runId": f"synthetic-{hashlib.sha256((instance_id + _now()).encode()).hexdigest()[:16]}", "instanceId": instance_id, "status": "passed" if before == after else "failed", "label": "Synthetic contract inspection — not execution evidence", "productionEligible": False, "statePackDigest": _digest(pack.to_dict()), "canonicalStateUnchanged": before == after, "completedAt": _now()}
        value = _load_json(self.layout.operations_root / "runs.json", {"formatVersion": "stateport.run-history/v1", "entries": []})
        value["entries"].append(result)
        _write_json(self.layout.operations_root / "runs.json", value)
        return result

    def backup(self, instance_id: str) -> dict[str, Any]:
        _, root = self._entry(instance_id)
        path = self.layout.backups_root / instance_id / f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(12)}.tar"
        result = create_backup(root, path)
        created_at = _now()
        summary = {
            "instanceId": instance_id,
            "archive": result.archive_path.as_posix(),
            "archiveDigest": result.archive_digest,
            "archiveFileDigest": result.archive_file_digest,
            "createdAt": created_at,
            "validation": "verified",
        }
        summary["backupReceipt"] = {
            "formatVersion": "stateport.backup-receipt/v1",
            "receiptId": "backup-" + _digest(summary)[7:31],
            "action": "backup.create",
            "status": "verified",
            "instanceId": instance_id,
            "archiveDigest": result.archive_digest,
            "archiveFileDigest": result.archive_file_digest,
            "canonicalStateEffect": "none",
            "createdAt": created_at,
        }
        value = _load_json(self.layout.data_root / "backups" / "index.json", {"formatVersion": "stateport.backup-index/v1", "entries": []})
        value["entries"].append(summary)
        _write_json(self.layout.data_root / "backups" / "index.json", value)
        self.catalog.update(instance_id, lastBackup=summary)
        return summary

    @property
    def _restore_operations_root(self) -> Path:
        return self.layout.operations_root / "restores"

    @staticmethod
    def _restore_digest(value: str, label: str) -> str:
        if not isinstance(value, str) or not _SOURCE_DIGEST.fullmatch(value):
            raise ApprovalError(f"{label} is invalid")
        return value

    def _restore_artifact_path(self, kind: str, digest: str) -> Path:
        if kind not in {"plans", "approvals", "receipts", "failures"}:
            raise AppError("restore artifact class is invalid")
        safe_digest = self._restore_digest(digest, f"restore {kind} digest")[7:]
        return self._restore_operations_root / kind / f"{safe_digest}.json"

    def _load_restore_artifact(
        self,
        kind: str,
        digest: str,
        *,
        format_version: str,
        digest_field: str,
    ) -> dict[str, Any]:
        value = self._read_restore_artifact(kind, digest)
        if not isinstance(value, Mapping) or value.get("formatVersion") != format_version:
            raise ApprovalError(f"restore {kind[:-1]} is invalid")
        result = dict(value)
        embedded = result.pop(digest_field, None)
        if embedded != digest or not secrets.compare_digest(_digest(result), digest):
            raise ApprovalError(f"restore {kind[:-1]} digest is invalid")
        result[digest_field] = digest
        return result

    def _load_restore_receipt(self, plan_digest: str) -> dict[str, Any]:
        value = self._read_restore_artifact("receipts", plan_digest)
        if (
            not isinstance(value, Mapping)
            or value.get("formatVersion") != RESTORE_RECEIPT_FORMAT
            or value.get("planDigest") != plan_digest
        ):
            raise ApprovalError("restore receipt is invalid")
        result = dict(value)
        receipt_digest = result.pop("receiptDigest", None)
        if (
            not isinstance(receipt_digest, str)
            or not secrets.compare_digest(_digest(result), receipt_digest)
        ):
            raise ApprovalError("restore receipt digest is invalid")
        result["receiptDigest"] = receipt_digest
        return result

    def _open_restore_artifact_directory(
        self, kind: str, *, create: bool = False
    ) -> int | None:
        if kind not in {"plans", "approvals", "receipts", "failures", "locks"}:
            raise AppError("restore artifact inventory class is invalid")
        flags = (
            os.O_RDONLY
            | os.O_CLOEXEC
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = -1
        try:
            descriptor = os.open(self.layout.state_root, flags)
            for component in ("operations", "restores", kind):
                try:
                    successor = os.open(component, flags, dir_fd=descriptor)
                except FileNotFoundError:
                    if not create:
                        raise
                    try:
                        os.mkdir(component, mode=0o700, dir_fd=descriptor)
                    except FileExistsError:
                        pass
                    successor = os.open(component, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = successor
            return descriptor
        except FileNotFoundError:
            if descriptor >= 0:
                os.close(descriptor)
            return None
        except OSError as exc:
            if descriptor >= 0:
                os.close(descriptor)
            raise ApprovalError(f"restore {kind} inventory is unsafe") from exc

    def _restore_artifact_digests(self, kind: str) -> tuple[str, ...]:
        descriptor = self._open_restore_artifact_directory(kind)
        if descriptor is None:
            return ()
        names: list[str] = []
        total_bytes = 0
        try:
            with os.scandir(descriptor) as entries:
                for entry in entries:
                    if not re.fullmatch(r"[0-9a-f]{64}\.json", entry.name):
                        raise ApprovalError(
                            f"restore {kind} inventory contains an unexpected entry"
                        )
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except OSError as exc:
                        raise ApprovalError(
                            f"restore {kind} inventory contains an unsafe artifact"
                        ) from exc
                    if (
                        not stat.S_ISREG(info.st_mode)
                        or info.st_nlink != 1
                        or info.st_size > _RESTORE_ARTIFACT_BYTES_LIMIT
                    ):
                        raise ApprovalError(
                            f"restore {kind} inventory contains an unsafe artifact"
                        )
                    names.append(entry.name)
                    total_bytes += info.st_size
        finally:
            os.close(descriptor)
        if len(names) > _RESTORE_STATUS_ARTIFACT_LIMIT:
            raise ApprovalError(f"restore {kind} inventory exceeds the safe review limit")
        if total_bytes > _RESTORE_INVENTORY_BYTES_LIMIT:
            raise ApprovalError(f"restore {kind} inventory exceeds the safe byte limit")
        return tuple(f"sha256:{name[:-5]}" for name in sorted(names))

    def _write_restore_artifact_new(
        self,
        kind: str,
        digest: str,
        value: Any,
        *,
        mode: int = 0o600,
    ) -> None:
        safe_digest = self._restore_digest(digest, f"restore {kind} digest")
        payload = _canonical(value)
        if len(payload) > _RESTORE_ARTIFACT_BYTES_LIMIT:
            raise AppError(f"restore {kind[:-1]} artifact is oversized")
        directory = self._open_restore_artifact_directory(kind, create=True)
        if directory is None:  # pragma: no cover - create=True either opens or raises
            raise AppError(f"restore {kind} inventory is unavailable")
        filename = f"{safe_digest[7:]}.json"
        artifact_descriptor = -1
        created = False
        created_identity: tuple[int, int] | None = None
        try:
            artifact_descriptor = os.open(
                filename,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_CLOEXEC
                | getattr(os, "O_NOFOLLOW", 0),
                mode,
                dir_fd=directory,
            )
            created = True
            info = os.fstat(artifact_descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise AppError(f"restore {kind[:-1]} artifact is unsafe")
            created_identity = (info.st_dev, info.st_ino)
            with os.fdopen(artifact_descriptor, "wb", closefd=False) as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.fchmod(artifact_descriptor, mode)
            current = os.stat(filename, dir_fd=directory, follow_symlinks=False)
            final_info = os.fstat(artifact_descriptor)
            if (
                created_identity != (current.st_dev, current.st_ino)
                or created_identity != (final_info.st_dev, final_info.st_ino)
                or not stat.S_ISREG(current.st_mode)
                or final_info.st_nlink != 1
            ):
                raise AppError(f"restore {kind[:-1]} artifact ownership changed")
            os.fsync(directory)
        except FileExistsError as exc:
            raise AppError("immutable restore operation artifact already exists") from exc
        except Exception:
            if created and created_identity is not None:
                try:
                    current = os.stat(
                        filename, dir_fd=directory, follow_symlinks=False
                    )
                    if created_identity == (current.st_dev, current.st_ino):
                        os.unlink(filename, dir_fd=directory)
                except OSError:
                    pass
            raise
        finally:
            if artifact_descriptor >= 0:
                os.close(artifact_descriptor)
            os.close(directory)

    def _read_restore_artifact(self, kind: str, digest: str) -> Any:
        safe_digest = self._restore_digest(digest, f"restore {kind} digest")
        descriptor = self._open_restore_artifact_directory(kind)
        if descriptor is None:
            raise ApprovalError(f"restore {kind[:-1]} was not found")
        artifact_descriptor = -1
        try:
            artifact_descriptor = os.open(
                f"{safe_digest[7:]}.json",
                os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            info = os.fstat(artifact_descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_size > _RESTORE_ARTIFACT_BYTES_LIMIT
            ):
                raise ApprovalError(f"restore {kind[:-1]} artifact is unsafe")
            payload = bytearray()
            while len(payload) <= _RESTORE_ARTIFACT_BYTES_LIMIT:
                chunk = os.read(artifact_descriptor, 64 * 1024)
                if not chunk:
                    break
                payload.extend(chunk)
            if len(payload) > _RESTORE_ARTIFACT_BYTES_LIMIT:
                raise ApprovalError(f"restore {kind[:-1]} artifact is oversized")
            return json.loads(payload.decode("utf-8"))
        except FileNotFoundError as exc:
            raise ApprovalError(f"restore {kind[:-1]} was not found") from exc
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ApprovalError(f"restore {kind[:-1]} artifact is invalid") from exc
        finally:
            if artifact_descriptor >= 0:
                os.close(artifact_descriptor)
            os.close(descriptor)

    def _with_restore_lock(
        self,
        source_instance_id: str,
        destination_instance_id: str,
        operation: Callable[[], dict[str, Any]],
    ) -> dict[str, Any]:
        _validate_id(source_instance_id, "source_instance_id")
        _validate_id(destination_instance_id, "destination_instance_id")
        lock_key = hashlib.sha256(
            f"{source_instance_id}\0{destination_instance_id}".encode("utf-8")
        ).hexdigest()
        lock_directory = self._open_restore_artifact_directory("locks", create=True)
        if lock_directory is None:  # pragma: no cover - create=True either opens or raises
            raise AppError("restore transaction lock directory is unavailable")
        lock_descriptor = -1
        try:
            try:
                lock_descriptor = os.open(
                    f"{lock_key}.lock",
                    os.O_RDWR
                    | os.O_APPEND
                    | os.O_CREAT
                    | os.O_CLOEXEC
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=lock_directory,
                )
                lock_info = os.fstat(lock_descriptor)
                if not stat.S_ISREG(lock_info.st_mode) or lock_info.st_nlink != 1:
                    raise AppError("restore transaction lock is unsafe")
                os.fchmod(lock_descriptor, 0o600)
            except OSError as exc:
                raise AppError("restore transaction lock is unsafe") from exc
            finally:
                os.close(lock_directory)
            with os.fdopen(lock_descriptor, "a+", encoding="utf-8") as lock:
                lock_descriptor = -1
                deadline = time.monotonic() + 15.0
                while True:
                    try:
                        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if time.monotonic() >= deadline:
                            raise AppError("restore transaction lock timed out")
                        time.sleep(0.05)
                try:
                    return operation()
                finally:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        finally:
            if lock_descriptor >= 0:
                os.close(lock_descriptor)

    def _verified_backup_record(
        self,
        source_instance_id: str,
        backup_receipt_id: str | None,
    ) -> tuple[dict[str, Any], Path, dict[str, Any], dict[str, Any]]:
        """Resolve one indexed backup and prove its exact bytes and identity."""

        _validate_id(source_instance_id, "source_instance_id")
        index_path = self.layout.backups_root / "index.json"
        if index_path.is_symlink() or (index_path.exists() and not index_path.is_file()):
            raise AppError("backup index is unsafe")
        index = _load_json(
            index_path,
            {"formatVersion": "stateport.backup-index/v1", "entries": []},
        )
        entries = index.get("entries") if isinstance(index, Mapping) else None
        if (
            not isinstance(index, Mapping)
            or index.get("formatVersion") != "stateport.backup-index/v1"
            or not isinstance(entries, list)
        ):
            raise AppError("backup index is invalid")
        matches: list[dict[str, Any]] = []
        for item in entries:
            if not isinstance(item, Mapping) or item.get("instanceId") != source_instance_id:
                continue
            receipt = item.get("backupReceipt")
            receipt_id = receipt.get("receiptId") if isinstance(receipt, Mapping) else None
            if backup_receipt_id is None or receipt_id == backup_receipt_id:
                matches.append(dict(item))
        if not matches:
            raise AppError("the selected verified backup was not found")
        record = matches[-1]
        receipt = record.get("backupReceipt")
        if (
            not isinstance(receipt, Mapping)
            or receipt.get("formatVersion") != "stateport.backup-receipt/v1"
            or receipt.get("action") != "backup.create"
            or receipt.get("status") != "verified"
            or receipt.get("instanceId") != source_instance_id
            or not isinstance(receipt.get("receiptId"), str)
        ):
            raise AppError("the selected backup receipt is invalid")
        archive_value = record.get("archive")
        if not isinstance(archive_value, str) or not archive_value:
            raise AppError("the selected backup has no managed archive")
        archive = Path(archive_value).expanduser()
        backup_root = _safe_instance_root(self.layout.backups_root, must_exist=True)
        if archive.is_symlink() or not archive.is_file():
            raise AppError("the selected backup archive is unavailable")
        try:
            resolved_archive = archive.resolve(strict=True)
            if not resolved_archive.is_relative_to(backup_root.resolve(strict=True)):
                raise AppError("the selected backup is outside the managed backup root")
        except OSError as exc:
            raise AppError("the selected backup archive is unavailable") from exc
        before = os.lstat(resolved_archive)
        manifest = read_manifest(resolved_archive)
        actual_file_digest = _file_digest(resolved_archive)
        after = os.lstat(resolved_archive)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise AppError("the selected backup changed during verification")
        if (
            manifest.get("instanceId") != source_instance_id
            or manifest.get("archiveDigest") != record.get("archiveDigest")
            or manifest.get("archiveDigest") != receipt.get("archiveDigest")
            or actual_file_digest != record.get("archiveFileDigest")
            or actual_file_digest != receipt.get("archiveFileDigest")
        ):
            raise AppError("the selected backup identity does not match its index")
        public_record = self._public_backup_entry(record)
        binding = {
            "receiptId": receipt["receiptId"],
            "receiptDigest": _digest(dict(receipt)),
            "createdAt": record.get("createdAt"),
            "archiveDigest": record.get("archiveDigest"),
            "archiveFileDigest": record.get("archiveFileDigest"),
            "manifestDigest": _digest(manifest),
            "sourceLockDigest": manifest.get("lock", {}).get("digest")
            if isinstance(manifest.get("lock"), Mapping)
            else None,
            "fileCount": len(manifest.get("files", [])),
            "storageLocation": "stateport_managed_backup_root",
        }
        if (
            not isinstance(binding["createdAt"], str)
            or any(
                not isinstance(binding[field], str)
                or not _SOURCE_DIGEST.fullmatch(str(binding[field]))
                for field in (
                    "receiptDigest",
                    "archiveDigest",
                    "archiveFileDigest",
                    "manifestDigest",
                    "sourceLockDigest",
                )
            )
            or not isinstance(binding["fileCount"], int)
            or binding["fileCount"] < 1
        ):
            raise AppError("the selected backup contract is incomplete")
        return public_record, resolved_archive, manifest, binding

    def _restore_source_binding(
        self,
        source_instance_id: str,
        entry: Mapping[str, Any],
        manifest: Mapping[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        source_identity = manifest.get("sourceIdentity")
        current_source = self.locked_source(source_instance_id)["source"]
        source_access = None
        if (
            isinstance(source_identity, Mapping)
            and _digest(self._source_access_identity(current_source))
            == _digest(self._source_access_identity(source_identity))
        ):
            source_access = self._effective_source_access(
                source_instance_id, entry, current_source,
            )
        access_effect = (
            {
                "disposition": "propagate_exact_receipt",
                "sourceAccessClass": source_access["sourceAccessClass"],
                "productionInstallAllowed": source_access["productionInstallAllowed"],
                "sourceReceiptDigest": source_access["receiptDigest"],
            }
            if source_access
            else {"disposition": "not_propagated"}
        )
        return (
            {
                "sourceInstanceId": source_instance_id,
                "applicationId": entry.get("applicationId"),
                "sourceIdentity": copy.deepcopy(source_identity),
                "sourceLock": copy.deepcopy(manifest.get("lock")),
                "catalogSource": copy.deepcopy(entry.get("observedSource", {})),
                "sourceAccess": access_effect,
            },
            source_access,
        )

    def _assert_restore_destination_available(self, destination_instance_id: str) -> Path:
        _validate_id(destination_instance_id, "destination_instance_id")
        if any(
            item.get("instanceId") == destination_instance_id
            for item in self.catalog.list()
        ):
            raise AppError("restore destination identity is already cataloged")
        target = _safe_instance_root(
            self.layout.instances_root / destination_instance_id
        )
        if target.exists() or target.is_symlink():
            raise AppError("restore destination already exists")
        if target.parent.is_symlink():
            raise AppError("restore destination parent is unsafe")
        return target

    def restore_plan(
        self,
        source_instance_id: str,
        *,
        backup_receipt_id: str,
        destination_instance_id: str,
        destination_name: str | None = None,
    ) -> dict[str, Any]:
        """Persist a path-free exact plan for a new-identity restore."""

        _validate_id(source_instance_id, "source_instance_id")
        _validate_id(destination_instance_id, "destination_instance_id")
        if source_instance_id == destination_instance_id:
            raise AppError("restore must create a different instance identity")
        if not isinstance(backup_receipt_id, str) or not re.fullmatch(
            r"backup-[0-9a-f]{24}", backup_receipt_id
        ):
            raise AppError("backup receipt identity is invalid")
        source_entry, _source_root = self._entry(source_instance_id)
        _public_record, archive, manifest, backup_binding = self._verified_backup_record(
            source_instance_id, backup_receipt_id
        )
        target = self._assert_restore_destination_available(destination_instance_id)
        dry_run = restore_backup(
            archive,
            target,
            dry_run=True,
            identity_policy="reidentify",
            new_instance_id=destination_instance_id,
        )
        name = destination_name or f"{source_entry.get('name') or source_instance_id} restored"
        if not isinstance(name, str) or not name.strip() or len(name) > 120:
            raise AppError("restore destination name is invalid")
        now = datetime.now(timezone.utc).replace(microsecond=0)
        source_binding, _source_access = self._restore_source_binding(
            source_instance_id, source_entry, manifest
        )
        plan = {
            "formatVersion": RESTORE_PLAN_FORMAT,
            "operation": "restore_new_instance",
            "sourceInstanceId": source_instance_id,
            "destinationInstanceId": destination_instance_id,
            "destinationName": name.strip(),
            "identityPolicy": "reidentify",
            "backup": backup_binding,
            "preconditions": {
                "sourceBindingDigest": _digest(source_binding),
                "destinationRootClass": "stateport_managed_instances_root",
                "destinationAbsent": True,
                "destinationCatalogIdentityAbsent": True,
            },
            "dryRun": {
                "status": "verified",
                "instanceId": dry_run.instance_id,
                "fileCount": dry_run.file_count,
                "archiveDigest": dry_run.archive_digest,
            },
            "effects": {
                "sourceCanonicalState": "unchanged",
                "destinationCanonicalState": "new_instance_created",
                "externalEffectsRestored": False,
                "overwriteAllowed": False,
                "sourceAccess": copy.deepcopy(source_binding["sourceAccess"]),
            },
            "limitations": [
                "filesystem_state_only",
                "external_side_effects_not_restored",
                "source_instance_not_modified",
            ],
            "createdAt": now.isoformat().replace("+00:00", "Z"),
            "expiresAt": (now + timedelta(minutes=15)).isoformat().replace(
                "+00:00", "Z"
            ),
        }
        plan["planDigest"] = _digest(plan)
        try:
            self._write_restore_artifact_new(
                "plans", plan["planDigest"], plan
            )
        except AppError:
            existing = self._load_restore_artifact(
                "plans",
                plan["planDigest"],
                format_version=RESTORE_PLAN_FORMAT,
                digest_field="planDigest",
            )
            if existing != plan:
                raise
        return plan

    def approve_restore(
        self,
        source_instance_id: str,
        *,
        plan_digest: str,
        actor_id: str,
        actor_role: str,
    ) -> dict[str, Any]:
        """Approve only the exact stored restore plan digest."""

        plan = self._load_restore_artifact(
            "plans",
            plan_digest,
            format_version=RESTORE_PLAN_FORMAT,
            digest_field="planDigest",
        )
        if plan.get("sourceInstanceId") != source_instance_id:
            raise ApprovalError("restore plan source identity does not match")
        if not isinstance(actor_id, str) or not re.fullmatch(
            r"[A-Za-z0-9._:-]{1,128}", actor_id
        ):
            raise ApprovalError("restore approver identity is invalid")
        if actor_role not in {"platform_operator", "local_operator"}:
            raise ApprovalError("restore approval requires an operator role")
        now = datetime.now(timezone.utc).replace(microsecond=0)
        if _parse_utc(plan.get("expiresAt"), "restore plan expiry") <= now:
            raise ApprovalError("restore plan has expired")
        approval = {
            "formatVersion": RESTORE_APPROVAL_FORMAT,
            "operation": "restore_new_instance",
            "sourceInstanceId": source_instance_id,
            "destinationInstanceId": plan["destinationInstanceId"],
            "planDigest": plan_digest,
            "actor": {"actorId": actor_id, "actorRole": actor_role},
            "decision": "approved",
            "approvedAt": now.isoformat().replace("+00:00", "Z"),
            "expiresAt": min(
                _parse_utc(plan["expiresAt"], "restore plan expiry"),
                now + timedelta(minutes=10),
            ).isoformat().replace("+00:00", "Z"),
        }
        approval["approvalDigest"] = _digest(approval)
        self._write_restore_artifact_new(
            "approvals", approval["approvalDigest"], approval
        )
        return approval

    @staticmethod
    def _public_catalog_restore_identity(entry: Mapping[str, Any]) -> dict[str, Any]:
        filesystem = entry.get("filesystem")
        return {
            "instanceId": entry.get("instanceId"),
            "applicationId": entry.get("applicationId"),
            "pathState": entry.get("pathState"),
            "catalogCreatedAt": entry.get("createdAt"),
            "filesystemIdentityDigest": _digest(filesystem)
            if isinstance(filesystem, Mapping)
            else None,
        }

    def _record_restore_failure(
        self,
        plan: Mapping[str, Any],
        *,
        reason_code: str,
        destination_present: bool,
        catalog_registered: bool,
        staging_retained: bool,
    ) -> None:
        failure = {
            "formatVersion": "stateport.restore-failure/v1",
            "operation": "restore_new_instance",
            "sourceInstanceId": plan.get("sourceInstanceId"),
            "destinationInstanceId": plan.get("destinationInstanceId"),
            "planDigest": plan.get("planDigest"),
            "reasonCode": reason_code,
            "destinationPresent": destination_present,
            "catalogRegistered": catalog_registered,
            "stagingRetained": staging_retained,
            "operatorInspectionRequired": (
                destination_present or catalog_registered or staging_retained
            ),
            "externalEffectsRestored": False,
            "recordedAt": _now(),
        }
        failure["failureDigest"] = _digest(failure)
        try:
            self._write_restore_artifact_new(
                "failures", failure["failureDigest"], failure
            )
        except AppError as exc:
            raise AppError("restore failure receipt could not be published") from exc

    def apply_restore(
        self,
        source_instance_id: str,
        *,
        plan_digest: str,
        approval_digest: str,
    ) -> dict[str, Any]:
        """Apply an exact approved restore into a new managed instance."""

        plan = self._load_restore_artifact(
            "plans",
            plan_digest,
            format_version=RESTORE_PLAN_FORMAT,
            digest_field="planDigest",
        )
        approval = self._load_restore_artifact(
            "approvals",
            approval_digest,
            format_version=RESTORE_APPROVAL_FORMAT,
            digest_field="approvalDigest",
        )
        if (
            plan.get("sourceInstanceId") != source_instance_id
            or approval.get("sourceInstanceId") != source_instance_id
            or approval.get("destinationInstanceId")
            != plan.get("destinationInstanceId")
            or approval.get("planDigest") != plan_digest
            or approval.get("decision") != "approved"
        ):
            raise ApprovalError("restore approval does not bind the exact plan")
        now = datetime.now(timezone.utc).replace(microsecond=0)
        if _parse_utc(plan.get("expiresAt"), "restore plan expiry") <= now:
            raise ApprovalError("restore plan has expired")
        if _parse_utc(approval.get("expiresAt"), "restore approval expiry") <= now:
            raise ApprovalError("restore approval has expired")
        destination_instance_id = str(plan["destinationInstanceId"])

        def transaction() -> dict[str, Any]:
            if plan_digest in self._restore_artifact_digests("receipts"):
                return self._load_restore_receipt(plan_digest)
            source_entry, _ = self._entry(source_instance_id)
            _record, archive, manifest, backup_binding = self._verified_backup_record(
                source_instance_id, str(plan["backup"]["receiptId"])
            )
            if backup_binding != plan.get("backup"):
                raise AppError("restore backup changed after planning")
            source_binding, source_access = self._restore_source_binding(
                source_instance_id, source_entry, manifest
            )
            if _digest(source_binding) != plan.get("preconditions", {}).get(
                "sourceBindingDigest"
            ):
                raise AppError("restore source binding changed after planning")
            if not isinstance(source_entry.get("applicationId"), str) or not source_entry["applicationId"]:
                raise AppError("restore source application identity is invalid")
            planned_source_access = plan.get("effects", {}).get("sourceAccess")
            if planned_source_access != source_binding.get("sourceAccess"):
                raise AppError("restore source access changed after planning")

            def require_source_access_unchanged() -> None:
                if source_access is None:
                    return
                current_entry, _current_root = self._entry(source_instance_id)
                _current_binding, current_access = self._restore_source_binding(
                    source_instance_id, current_entry, manifest,
                )
                if current_access != source_access:
                    raise AppError("restore source access changed before effect")

            target = self._assert_restore_destination_available(
                destination_instance_id
            )
            dry_run = restore_backup(
                archive,
                target,
                dry_run=True,
                identity_policy="reidentify",
                new_instance_id=destination_instance_id,
            )
            if {
                "status": "verified",
                "instanceId": dry_run.instance_id,
                "fileCount": dry_run.file_count,
                "archiveDigest": dry_run.archive_digest,
            } != plan.get("dryRun"):
                raise AppError("restore dry-run result changed after planning")
            catalog_entry: dict[str, Any] | None = None
            source_access_recorded = False
            destination_source_access: dict[str, Any] | None = None
            try:
                require_source_access_unchanged()
                restored = restore_backup(
                    archive,
                    target,
                    identity_policy="reidentify",
                    new_instance_id=destination_instance_id,
                )
                validation = self._validate_managed_instance(target)
                validation_result = {
                    "valid": validation.ok,
                    "issues": [
                        {"path": issue.path, "message": issue.message}
                        for issue in validation.issues
                    ],
                }
                if not validation.ok:
                    raise AppError("restored instance failed StateSpec validation")
                base_git = initialize_instance_repository(target)
                lock = _read_yaml(target / ".statedd" / "lock.yaml")
                template = lock.get("template")
                source = template.get("source") if isinstance(template, Mapping) else None
                if not isinstance(template, Mapping) or not isinstance(source, Mapping):
                    raise AppError("restored instance lock source is invalid")
                catalog_source = {
                    "templateId": template.get("id", "unknown"),
                    **dict(source),
                }
                if source_access:
                    require_source_access_unchanged()
                    _template_id, installed_source = self._locked_source_at(target)
                    catalog_source.update(
                        {
                            "sourceAccessClass": source_access["sourceAccessClass"],
                            "productionInstallAllowed": source_access["productionInstallAllowed"],
                        }
                    )
                catalog_entry = self.catalog.register(
                    target,
                    instance_id=destination_instance_id,
                    name=str(plan["destinationName"]),
                    source=catalog_source,
                    application_id=source_entry["applicationId"],
                )
                if source_access:
                    require_source_access_unchanged()
                    destination_source_access = self._record_source_access_receipt(
                        destination_instance_id,
                        installed_source,
                        filesystem_identity=catalog_entry["filesystem"],
                        source_access_class=str(source_access["sourceAccessClass"]),
                        production_install_allowed=bool(source_access["productionInstallAllowed"]),
                        authority={
                            "kind": "restore_new_instance",
                            "plan": copy.deepcopy(dict(plan)),
                            "approval": copy.deepcopy(dict(approval)),
                            "sourceInstanceId": source_instance_id,
                            "sourceReceiptDigest": source_access["receiptDigest"],
                        },
                        authority_guard=require_source_access_unchanged,
                    )
                    source_access_recorded = True
                created_at = _now()
                receipt = {
                    "formatVersion": RESTORE_RECEIPT_FORMAT,
                    "receiptId": "restore-" + plan_digest[7:31],
                    "operation": "restore_new_instance",
                    "status": "validated",
                    "sourceInstanceId": source_instance_id,
                    "destinationInstanceId": destination_instance_id,
                    "planDigest": plan_digest,
                    "approvalDigest": approval_digest,
                    "backup": copy.deepcopy(plan["backup"]),
                    "result": {
                        "identityPolicy": restored.identity_policy,
                        "instanceId": restored.instance_id,
                        "fileCount": restored.file_count,
                        "archiveDigest": restored.archive_digest,
                        "baseGit": base_git,
                        "validation": validation_result,
                        "catalogIdentity": self._public_catalog_restore_identity(
                            catalog_entry
                        ),
                    },
                    "effects": {
                        "sourceCanonicalState": "unchanged",
                        "destinationCanonicalState": "new_instance_created",
                        "externalEffectsRestored": False,
                        "sourceAccess": (
                            {
                                "disposition": "propagated",
                                "sourceAccessClass": source_access["sourceAccessClass"],
                                "productionInstallAllowed": source_access["productionInstallAllowed"],
                                "sourceReceiptDigest": source_access["receiptDigest"],
                                "destinationReceiptDigest": destination_source_access["receiptDigest"],
                            }
                            if source_access and destination_source_access
                            else {"disposition": "not_propagated"}
                        ),
                    },
                    "createdAt": created_at,
                }
                receipt["receiptDigest"] = _digest(receipt)
                # The file name is the plan digest so an exact retry can return
                # the already-accepted result without repeating filesystem work.
                self._write_restore_artifact_new(
                    "receipts", plan_digest, receipt
                )
                return receipt
            except Exception as exc:
                if source_access_recorded:
                    self._discard_source_access_receipt(destination_instance_id)
                catalog_rolled_back = (
                    self.catalog.forget_if_matches(catalog_entry)
                    if catalog_entry is not None
                    else False
                )
                self._record_restore_failure(
                    plan,
                    reason_code=(
                        "receipt_publication_failed"
                        if catalog_entry is not None and catalog_rolled_back
                        else "restore_apply_failed"
                    ),
                    destination_present=target.exists() or target.is_symlink(),
                    catalog_registered=catalog_entry is not None and not catalog_rolled_back,
                    staging_retained=restore_staging_retained(target),
                )
                if isinstance(exc, AppError):
                    raise
                if isinstance(exc, BackupError):
                    raise AppError("restore archive operation failed") from exc
                raise AppError("restore transaction failed; inspection may be required") from exc

        return self._with_restore_lock(
            source_instance_id, destination_instance_id, transaction
        )

    def recovery_status(self, instance_id: str) -> dict[str, Any]:
        """Return path-free backup and restore truth for one source instance."""

        backup = self.recovery(instance_id)
        restore: dict[str, Any] = {
            "status": "not_planned",
            "latestPlanDigest": None,
            "latestApprovalDigest": None,
            "latestReceiptId": None,
            "operatorInspectionRequired": False,
            "stagingRetained": False,
        }
        plans: list[dict[str, Any]] = []
        for digest in self._restore_artifact_digests("plans"):
            value = self._load_restore_artifact(
                "plans",
                digest,
                format_version=RESTORE_PLAN_FORMAT,
                digest_field="planDigest",
            )
            if value.get("sourceInstanceId") == instance_id:
                plans.append(dict(value))
        approvals: list[dict[str, Any]] = []
        for digest in self._restore_artifact_digests("approvals"):
            value = self._load_restore_artifact(
                "approvals",
                digest,
                format_version=RESTORE_APPROVAL_FORMAT,
                digest_field="approvalDigest",
            )
            if value.get("sourceInstanceId") == instance_id:
                approvals.append(value)
        receipts = {
            digest: self._load_restore_receipt(digest)
            for digest in self._restore_artifact_digests("receipts")
        }
        failures: list[dict[str, Any]] = []
        for digest in self._restore_artifact_digests("failures"):
            value = self._load_restore_artifact(
                "failures",
                digest,
                format_version="stateport.restore-failure/v1",
                digest_field="failureDigest",
            )
            if value.get("sourceInstanceId") == instance_id:
                failures.append(value)
        plans.sort(key=lambda item: str(item.get("createdAt", "")))
        if plans:
            latest_plan = plans[-1]
            restore.update(
                {
                    "status": "planned",
                    "latestPlanDigest": latest_plan.get("planDigest"),
                    "destinationInstanceId": latest_plan.get("destinationInstanceId"),
                    "expiresAt": latest_plan.get("expiresAt"),
                }
            )
            matching_approvals = [
                value
                for value in approvals
                if value.get("planDigest") == latest_plan.get("planDigest")
            ]
            matching_approvals.sort(
                key=lambda item: str(item.get("approvedAt", ""))
            )
            if matching_approvals:
                restore["status"] = "approved"
                restore["latestApprovalDigest"] = matching_approvals[-1].get(
                    "approvalDigest"
                )
            receipt = receipts.get(str(latest_plan.get("planDigest")))
            if receipt is not None:
                restore["status"] = str(receipt.get("status", "completed"))
                restore["latestReceiptId"] = receipt.get("receiptId")
        if failures:
            failures.sort(key=lambda item: str(item.get("recordedAt", "")))
            if (
                not plans
                or failures[-1].get("planDigest") == plans[-1].get("planDigest")
                and restore.get("latestReceiptId") is None
            ):
                latest_failure = failures[-1]
                restore.update(
                    {
                        "status": "failed",
                        "failureReasonCode": latest_failure.get("reasonCode"),
                        "operatorInspectionRequired": bool(
                            latest_failure.get("operatorInspectionRequired")
                        ),
                        "stagingRetained": bool(
                            latest_failure.get("stagingRetained")
                        ),
                    }
                )
        return {
            "formatVersion": RECOVERY_STATUS_FORMAT,
            "sourceInstanceId": instance_id,
            **backup,
            "restore": restore,
            "limitations": {
                "filesystemStateOnly": True,
                "externalEffectsRestored": False,
                "overwriteRestoreSupported": False,
            },
        }

    def _source_inventory(self, source: Path) -> tuple[dict[str, str], list[str]]:
        files: dict[str, str] = {}
        unknown: list[str] = []
        for path in sorted(source.rglob("*"), key=lambda item: item.relative_to(source).as_posix()):
            if not path.is_file() or path.is_symlink():
                continue
            rel = path.relative_to(source).as_posix()
            if rel.startswith(".git/") or rel.startswith(".venv") or rel.startswith(".studydd/"):
                continue
            if rel in _ALLOWED_IMPORT_FILES or (rel.startswith("targets/") and rel.endswith("/TARGET.yaml")):
                files[rel] = _file_digest(path)
            elif rel.startswith("state/") and Path(rel).name in {"QUESTION_BANK_STATE.yaml", "QUESTION_BANK_MIGRATION_RECEIPT.yaml", "QUESTION_BANK_ROUTE_MIGRATION_REPORT.yaml", "AGENT_ERROR_LOG.md", "KNOWLEDGE_ATLAS.yaml", "INSTANCE_ROLE.yaml", "REPOSITORY_REMEDIATION_STATE.yaml", "TEMPLATE_SYNC.yaml"}:
                files[rel] = _file_digest(path)
            elif rel.startswith("targets/") and "/" in rel:
                files[rel] = _file_digest(path)
            elif rel.startswith("state/") or rel.startswith("sources/") or rel.startswith("reviews/") or rel.startswith("sessions/") or rel.startswith("activities/") or rel.startswith("targets/"):
                unknown.append(rel)
        return files, unknown

    def import_state_plan(self, source: str, destination_instance: str, *, include_history: bool = False) -> dict[str, Any]:
        source_root = _safe_instance_root(Path(source), must_exist=True)
        entry, destination = self._entry(destination_instance)
        files, unknown = self._source_inventory(source_root)
        selected = {path: category for path, category in _ALLOWED_IMPORT_FILES.items() if include_history or category not in {"audit_history", "session_history"}}
        selected.update({path: "current_state" for path in files if path.startswith("targets/") and path.endswith("/TARGET.yaml")})
        selected_files = {path: digest for path, digest in files.items() if path in selected}
        source_digest = _digest({"files": selected_files, "unknown": unknown})
        destination_files = {}
        for path in selected_files:
            candidate = destination / path
            if candidate.is_file():
                destination_files[path] = _file_digest(candidate)
        destination_digest = _digest(destination_files)
        categories = sorted(set(selected.values()))
        unsupported = sorted(path for path in files if path not in selected_files)
        plan = {"formatVersion": "stateport.state-import-plan/v1", "operation": "state-import", "sourceKind": "private-local-studydd", "sourceStateDigest": source_digest, "destinationInstance": destination_instance, "destinationDigest": destination_digest, "recognized": {category: sum(1 for path in selected_files if selected[path] == category) for category in categories}, "required": ["current_state"], "optional": ["review_state", "source_state", "audit_history", "session_history"], "selected": [category for category in categories if category not in {"audit_history", "session_history"} or include_history], "regenerated": ["context_pack", "compatibility_views"], "excluded": ["lifecycle_lock", "lifecycle_receipt", "provider_credentials", "caches", "raw_transcripts"], "unsupported": {"count": len(unsupported), "paths": unsupported}, "unknown": {"count": len(unknown), "status": "surfaced" if unknown else "none", "requires_explicit_approval": bool(unknown)}, "conflicts": [], "privacy": {"rawValuesDisplayed": False, "sourceReadOnly": True}, "createdAt": _now()}
        plan["planDigest"] = _digest(plan)
        return plan

    def import_state(self, plan: Mapping[str, Any], source: str, approval: Mapping[str, Any]) -> dict[str, Any]:
        if approval.get("planDigest") != plan.get("planDigest"):
            raise ApprovalError("state import approval does not match exact plan")
        if plan.get("unknown", {}).get("status") == "blocking":
            raise AppError("state import plan contains unknown state; review and resolve it before applying")
        source_root = _safe_instance_root(Path(source), must_exist=True)
        _, destination = self._entry(str(plan["destinationInstance"]))
        selected_paths = {path for path in _ALLOWED_IMPORT_FILES if _ALLOWED_IMPORT_FILES[path] not in {"audit_history", "session_history"}}
        selected_paths.update(path for path in self._source_inventory(source_root)[0] if path.startswith("targets/") and path.endswith("/TARGET.yaml"))
        current_destination_digest = _digest({path: _file_digest(destination / path) for path in selected_paths if (destination / path).is_file()})
        import_dir = self.layout.operations_root / "imports"
        for receipt_path in sorted(import_dir.glob(f"{plan['destinationInstance']}-*.json")) if import_dir.is_dir() else ():
            prior = _load_json(receipt_path, {})
            if prior.get("sourceStateDigest") == plan.get("sourceStateDigest") and prior.get("destinationPostDigest") == current_destination_digest:
                return {**prior, "idempotentRerun": True}
        fresh = self.import_state_plan(source, str(plan["destinationInstance"]))
        if fresh.get("sourceStateDigest") != plan.get("sourceStateDigest") or fresh.get("destinationDigest") != plan.get("destinationDigest"):
            raise AppError("state import plan is stale; source or destination changed")
        files, _ = self._source_inventory(source_root)
        selected = {path: category for path, category in _ALLOWED_IMPORT_FILES.items() if category not in {"audit_history", "session_history"}}
        selected.update({path: "current_state" for path in files if path.startswith("targets/") and path.endswith("/TARGET.yaml")})
        before = {path: (destination / path).read_bytes() for path in selected if (destination / path).is_file()}
        source_before = self._source_inventory(source_root)
        try:
            for path in selected:
                source_file = source_root / path
                if not source_file.is_file():
                    continue
                target = destination / path
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                if target.exists() and target.is_symlink():
                    raise AppError(f"destination state path is a symlink: {path}")
                if path.endswith((".yaml", ".yml")):
                    value = _read_yaml(source_file)
                    _atomic_write(target, _yaml_dump(value), 0o600)
                else:
                    _atomic_write(target, source_file.read_bytes(), 0o600)
            validation = self._validate_managed_instance(destination)
            if not validation.ok:
                raise AppError("destination failed StateSpec validation after state import")
            source_after = self._source_inventory(source_root)
            result = {"formatVersion": "stateport.state-import-result/v1", "sourceStateDigest": plan["sourceStateDigest"], "destinationInstance": plan["destinationInstance"], "destinationPreDigest": plan["destinationDigest"], "destinationPostDigest": _digest({path: _file_digest(destination / path) for path in selected if (destination / path).is_file()}), "imported": {"current_state": sum(1 for path in selected if selected[path] == "current_state" and (source_root / path).is_file()), "review_state": sum(1 for path in selected if selected[path] == "review_state" and (source_root / path).is_file()), "source_state": sum(1 for path in selected if selected[path] == "source_state" and (source_root / path).is_file())}, "skipped": ["raw_transcripts", "generated_context", "lifecycle_identity"], "regenerated": ["compatibility_views", "context_pack"], "sourceUnchanged": source_before == source_after, "validation": {"valid": validation.ok, "issues": [{"path": issue.path, "message": issue.message} for issue in validation.issues]}, "completedAt": _now()}
            _write_json(self.layout.operations_root / "imports" / f"{plan['destinationInstance']}-{plan['planDigest'][7:19]}.json", result)
            return result
        except Exception:
            for path, contents in before.items():
                target = destination / path
                # Restore original bytes from the plan target is intentionally
                # limited: destination files are re-read from the immutable
                # pre-import snapshot captured before any write.
                _atomic_write(target, contents, 0o600)
            for path in selected:
                if path not in before and (destination / path).exists():
                    (destination / path).unlink()
            raise

    def service_status(self) -> dict[str, Any]:
        runtime = self.layout.runtime_root / "service.json"
        if not runtime.is_file():
            return {"status": "stopped", "runtime": runtime.as_posix()}
        try:
            data = json.loads(runtime.read_text(encoding="utf-8"))
            pid = int(data["pid"])
            port = int(data["port"])
            expected_start_ticks = data.get("processStartTicks")
            if expected_start_ticks is not None:
                expected_start_ticks = int(expected_start_ticks)
            repo_root = data.get("repoRoot")
            if not isinstance(repo_root, str) or not self._owned_service_pid(
                pid,
                expected_start_ticks=expected_start_ticks,
                expected_repo_root=repo_root,
            ):
                return {"status": "stale-runtime", "runtime": runtime.as_posix()}
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            return {"status": "stale-runtime", "runtime": runtime.as_posix()}
        return {"status": "running", **data, "url": f"http://127.0.0.1:{port}/"}

    @staticmethod
    def _owned_service_pid(
        pid: int,
        *,
        expected_start_ticks: int | None = None,
        expected_repo_root: str | None = None,
    ) -> bool:
        """Return whether a PID is still the StatePort local service."""
        try:
            os.kill(pid, 0)
            command_line = Path(f"/proc/{pid}/cmdline")
            if not command_line.is_file() or b"stateport_persistent_app.service_process" not in command_line.read_bytes():
                return False
            if expected_repo_root is not None:
                if Path(f"/proc/{pid}/cwd").resolve() != Path(expected_repo_root).expanduser().resolve():
                    return False
            if expected_start_ticks is not None:
                return PersistentApp._process_start_ticks(pid) == expected_start_ticks
            return True
        except (OSError, ValueError):
            return False

    @staticmethod
    def _process_start_ticks(pid: int) -> int:
        stat_value = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        fields_after_command = stat_value[stat_value.rfind(")") + 2 :].split()
        if len(fields_after_command) <= 19:
            raise ValueError("process stat record is incomplete")
        return int(fields_after_command[19])

    @staticmethod
    def _service_git_identity(root: Path) -> dict[str, str]:
        """Resolve the exact checkout identity requested for a local service."""

        root = root.expanduser().resolve()

        def git(*arguments: str) -> str:
            try:
                completed = subprocess.run(
                    ("git", "-C", str(root), "rev-parse", *arguments),
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                raise ServiceError("configured service root has no readable Git identity") from exc
            return completed.stdout.strip()

        top = Path(git("--show-toplevel")).resolve()
        if top != root:
            raise ServiceError("configured service root does not match its Git identity")
        git_head = git("HEAD")
        return {
            "repoRoot": root.as_posix(),
            "gitBranch": git("--abbrev-ref", "HEAD"),
            "gitHead": git_head,
            "gitTree": git(f"{git_head}^{{tree}}"),
        }

    def _service_start_request(
        self,
        *,
        port: int,
        repo_root: Path | None,
        actor_role: str,
    ) -> tuple[Path, dict[str, Any]]:
        if actor_role not in {"local_user", "platform_operator"}:
            raise ServiceError("service actor role must be local_user or platform_operator")
        if not 1024 <= port <= 65535:
            raise ServiceError("port must be between 1024 and 65535")
        root = (repo_root or Path(__file__).resolve().parents[4]).expanduser().resolve()
        host_root = os.environ.get("STATEPORT_HOST_ROOT")
        if host_root and Path(host_root).expanduser().resolve() != root:
            raise ServiceError("STATEPORT_HOST_ROOT must match the configured service root")
        identity: dict[str, Any] = {
            **self._service_git_identity(root),
            **self._service_source_catalog_identity(),
            "port": port,
            "actorRole": actor_role,
            "runtimeFingerprint": self._service_runtime_fingerprint(root),
        }
        return root, identity

    def _service_source_catalog_identity(self) -> dict[str, str]:
        """Return the immutable source authority parsed by this app instance."""

        self._canonical_source()
        return {
            "canonicalSourceCatalog": self.canonical_source_catalog.as_posix(),
            "canonicalSourceCatalogDigest": self.canonical_source_catalog_digest,
        }

    @staticmethod
    def _require_matching_web_build(
        root: Path, git_head: str, git_tree: str
    ) -> None:
        """Refuse a frontend artifact from another exact commit/tree pair."""

        package = root / "apps" / "web" / "package.json"
        built_index = root / "apps" / "web" / "dist" / "index.html"
        marker = root / "apps" / "web" / "dist" / "stateport-build.json"
        if not package.is_file() or package.is_symlink():
            return
        try:
            package_identity = json.loads(package.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ServiceError("StatePort frontend package identity is unreadable") from exc
        if not isinstance(package_identity, dict) or package_identity.get("name") != "stateport-frontend":
            return
        if not built_index.is_file() or not marker.is_file() or marker.is_symlink():
            raise ServiceError("StatePort production web build is missing; rebuild apps/web")
        try:
            if marker.stat().st_size > 1024:
                raise ServiceError("StatePort web build identity is invalid; rebuild apps/web")
            build_identity = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ServiceError("StatePort web build identity is unreadable; rebuild apps/web") from exc
        source_commit = build_identity.get("sourceCommit") if isinstance(build_identity, dict) else None
        source_tree = build_identity.get("sourceTree") if isinstance(build_identity, dict) else None
        if source_commit != git_head or source_tree != git_tree:
            raise ServiceError(
                "StatePort web build does not match the requested Git commit/tree; "
                "run `npm --prefix apps/web run build` before starting the service"
            )

    @staticmethod
    def _service_runtime_fingerprint(root: Path) -> str:
        """Digest loaded Python sources and the complete served web artifact."""

        root = root.expanduser().resolve()
        source_roots = [
            *sorted(root.glob("packages/*/src")),
            *sorted(root.glob("apps/*/src")),
        ]
        web_dist = root / "apps" / "web" / "dist"
        digest = hashlib.sha256()
        seen_directories: set[Path] = set()

        def add_tree(base: Path, *, python_only: bool) -> None:
            if not base.is_dir():
                return
            for directory, child_directories, filenames in os.walk(base, followlinks=True):
                resolved_directory = Path(directory).resolve()
                if resolved_directory in seen_directories:
                    child_directories[:] = []
                    continue
                seen_directories.add(resolved_directory)
                child_directories[:] = sorted(
                    name for name in child_directories if name not in {".git", "__pycache__", "node_modules"}
                )
                for filename in sorted(filenames):
                    path = Path(directory) / filename
                    if python_only and path.suffix != ".py":
                        continue
                    relative = path.relative_to(root).as_posix().encode("utf-8")
                    digest.update(len(relative).to_bytes(8, "big"))
                    digest.update(relative)
                    if path.is_symlink():
                        payload = os.readlink(path).encode("utf-8")
                    else:
                        payload = path.read_bytes()
                    digest.update(len(payload).to_bytes(8, "big"))
                    digest.update(payload)

        for source_root in source_roots:
            add_tree(source_root, python_only=True)
        add_tree(root / "config", python_only=False)
        add_tree(web_dist, python_only=False)
        return "sha256:" + digest.hexdigest()

    @staticmethod
    def _service_identity_summary(identity: Mapping[str, Any]) -> str:
        root = identity.get("repoRoot", "unknown-root")
        branch = identity.get("gitBranch", "unknown-branch")
        head = str(identity.get("gitHead", "unknown-head"))
        tree = str(identity.get("gitTree", "unknown-tree"))
        port = identity.get("port", "unknown-port")
        return f"{root} ({branch}@{head[:12]}/{tree[:12]}) on port {port}"

    def _require_service_identity(
        self,
        current: Mapping[str, Any],
        expected: Mapping[str, Any],
    ) -> None:
        fields = (
            "repoRoot", "gitBranch", "gitHead", "gitTree", "port", "actorRole",
            "canonicalSourceCatalog", "canonicalSourceCatalogDigest",
        )
        if any(current.get(field) != expected.get(field) for field in fields):
            raise ServiceError(
                "running service belongs to "
                f"{self._service_identity_summary(current)}; stop it before starting "
                f"{self._service_identity_summary(expected)}"
            )
        if current.get("runtimeFingerprint") != expected.get("runtimeFingerprint"):
            raise ServiceError(
                "running service loaded a different source or web build; "
                "stop it before reusing the updated checkout"
            )

    @staticmethod
    def _service_listener_open(port: int) -> bool:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return True
        except OSError:
            return False

    @staticmethod
    def _terminate_spawned_service(process: Any) -> None:
        """Terminate and reap the exact daemon child before allowing a retry."""

        try:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=10)
            return
        except ProcessLookupError:
            process.wait(timeout=2)
            return
        except subprocess.TimeoutExpired:
            pass
        try:
            process.kill()
            process.wait(timeout=2)
        except (ProcessLookupError, subprocess.TimeoutExpired) as exc:
            raise ServiceError("spawned local service process could not be reaped") from exc

    def _with_service_lifecycle_lock(
        self,
        operation: Callable[[], dict[str, Any]],
    ) -> dict[str, Any]:
        """Serialize global service start/stop decisions across local clients."""

        self.layout.initialize()
        lock_path = self.layout.runtime_root / "service-lifecycle.lock"
        with lock_path.open("a+", encoding="utf-8") as lock:
            os.chmod(lock_path, 0o600)
            deadline = time.monotonic() + 15.0
            while True:
                try:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise ServiceError("local service lifecycle lock timed out")
                    time.sleep(0.05)
            try:
                return operation()
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def service_start(self, *, port: int = 8790, open_browser: bool = False, repo_root: Path | None = None, actor_role: str = "local_user") -> dict[str, Any]:
        return self._with_service_lifecycle_lock(
            lambda: self._service_start_locked(
                port=port,
                open_browser=open_browser,
                repo_root=repo_root,
                actor_role=actor_role,
            )
        )

    def _service_start_locked(self, *, port: int, open_browser: bool, repo_root: Path | None, actor_role: str) -> dict[str, Any]:
        root, expected = self._service_start_request(
            port=port,
            repo_root=repo_root,
            actor_role=actor_role,
        )
        current = self.service_status()
        if current.get("status") == "running":
            self._require_service_identity(current, expected)
            self._require_matching_web_build(
                root, expected["gitHead"], expected["gitTree"]
            )
            if open_browser:
                import webbrowser
                webbrowser.open(current["url"])
            return current
        if current.get("status") == "stale-runtime":
            try:
                (self.layout.runtime_root / "service.json").unlink()
            except FileNotFoundError:
                pass
        self._require_matching_web_build(
            root, expected["gitHead"], expected["gitTree"]
        )
        self.layout.initialize()
        log_path = self.layout.logs_root / "service.log"
        command = [
            sys.executable,
            "-m",
            "stateport_persistent_app.service_process",
            "--port",
            str(port),
            "--repo-root",
            str(root),
            "--actor-role",
            actor_role,
            "--canonical-source-catalog",
            str(expected["canonicalSourceCatalog"]),
            "--expected-source-catalog-digest",
            str(expected["canonicalSourceCatalogDigest"]),
        ]
        env = dict(os.environ)
        source_paths = [str(Path(__file__).resolve().parents[1]), str(root / "packages/portable-execution/src"), str(root / "packages/application-experience/src"), str(root / "packages/conversation-service/src"), str(root / "packages/context-lifecycle/src"), str(root / "packages/goal-execution/src"), str(root / "packages/file-workspace-broker/src"), str(root / "packages/terminal-broker/src"), str(root / "packages/governed-runner/src"), str(root / "packages/execution-host/src"), str(root / "packages/external-engine-runtime/src"), str(root / "packages/codex-adapter/src"), str(root / "packages/run-bundle/src"), str(root / "packages/sandbox-runtime/src"), str(root / "packages/statebench/src"), str(root / "packages/statedd-core/src"), str(root / "packages/template-validator/src"), str(root / "packages/instance-backup/src"), str(root / "packages/instance-catalog/src"), str(root / "packages/diagnostics/src"), str(root / "packages/opencode-adapter/src"), str(root / "packages/container-opencode/src"), str(root / "apps/runner/src"), str(root / "apps/telegram-adapter/src")]
        existing_pythonpath = env.get("PYTHONPATH")
        if existing_pythonpath:
            source_paths.append(existing_pythonpath)
        env["PYTHONPATH"] = os.pathsep.join(source_paths)
        with open(log_path, "ab") as log:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, start_new_session=True, close_fds=True, env=env, cwd=root)
        for _ in range(40):
            time.sleep(0.05)
            status = self.service_status()
            if status.get("status") == "running":
                try:
                    self._require_service_identity(status, expected)
                    if int(status.get("pid", -1)) != process.pid:
                        raise ServiceError("local service readiness came from an unexpected process")
                except (ServiceError, TypeError, ValueError):
                    self._terminate_spawned_service(process)
                    raise
                if open_browser:
                    import webbrowser
                    webbrowser.open(status["url"])
                return status
            if process.poll() is not None:
                break
        self._terminate_spawned_service(process)
        raise ServiceError("local service did not become ready; inspect service logs")

    def service_stop(self) -> dict[str, Any]:
        return self._with_service_lifecycle_lock(self._service_stop_locked)

    def _service_stop_locked(self) -> dict[str, Any]:
        current = self.service_status()
        if current.get("status") != "running":
            if current.get("status") == "stale-runtime":
                try:
                    (self.layout.runtime_root / "service.json").unlink()
                except FileNotFoundError:
                    pass
            return {"status": "stopped"}
        pid = int(current["pid"])
        expected_start_ticks = current.get("processStartTicks")
        if expected_start_ticks is not None:
            expected_start_ticks = int(expected_start_ticks)
        expected_repo_root = current.get("repoRoot")
        if self._owned_service_pid(
            pid,
            expected_start_ticks=expected_start_ticks,
            expected_repo_root=expected_repo_root if isinstance(expected_repo_root, str) else None,
        ):
            try:
                os.kill(pid, __import__("signal").SIGTERM)
            except ProcessLookupError:
                pass
        port = int(current["port"])
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            time.sleep(0.05)
            # The child removes runtime metadata in its finally block before
            # the listening socket and process are necessarily gone.  Wait on
            # the owned PID itself so an immediate restart cannot race the
            # previous server's shutdown.
            if not self._owned_service_pid(
                pid,
                expected_start_ticks=expected_start_ticks,
                expected_repo_root=expected_repo_root if isinstance(expected_repo_root, str) else None,
            ):
                runtime = self.service_status()
                if runtime.get("status") == "running" and int(runtime.get("pid", -1)) != pid:
                    raise ServiceError("another local service started while the previous service was stopping")
                if self._service_listener_open(port):
                    continue
                if runtime.get("status") == "stale-runtime":
                    try:
                        (self.layout.runtime_root / "service.json").unlink()
                    except FileNotFoundError:
                        pass
                return {"status": "stopped", "pid": pid}
        raise ServiceError(f"service pid {pid} did not stop cleanly within 10 seconds")
