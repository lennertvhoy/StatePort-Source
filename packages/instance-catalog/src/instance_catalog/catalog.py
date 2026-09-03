"""Authoritative, local-only discovery catalog for StatePort instances.

The implementation intentionally treats an instance directory as opaque. It
uses ``lstat``/``scandir`` only to establish directory identity and does not
read learner, workflow, or StateDD files.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
import errno
import fcntl
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tempfile
import uuid
from typing import Any, Iterator, Literal, Mapping


CATALOG_FORMAT = "stateport.instance-catalog/v1"
PathState = Literal["present", "moved", "stale", "missing", "unsafe"]
Status = Literal["active", "archived"]
AdoptionMode = Literal["registered", "imported"]


class CatalogError(ValueError):
    """Base error for malformed catalog data or unsafe catalog operations."""


class CatalogSchemaError(CatalogError):
    """Raised when the on-disk catalog is not the supported schema."""


class PathSafetyError(CatalogError):
    """Raised when a path is outside the root or contains a symlink."""


class InstanceNotFoundError(CatalogError):
    """Raised when an instance ID is not in the catalog."""


class DuplicateInstanceError(CatalogError):
    """Raised when an ID or path is already cataloged."""


class CatalogConflictError(CatalogError):
    """Raised when an exact catalog mutation binding no longer matches."""


@dataclass(frozen=True)
class FilesystemIdentity:
    device: int
    inode: int

    def to_dict(self) -> dict[str, Any]:
        return {"device": self.device, "inode": self.inode, "kind": "directory"}

    @classmethod
    def from_dict(cls, value: Any) -> "FilesystemIdentity":
        if not isinstance(value, Mapping) or set(value) != {"device", "inode", "kind"}:
            raise CatalogSchemaError("filesystem must contain device, inode, and kind")
        if value["kind"] != "directory":
            raise CatalogSchemaError("filesystem.kind must be directory")
        if any(isinstance(value[key], bool) or not isinstance(value[key], int) or value[key] < 0 for key in ("device", "inode")):
            raise CatalogSchemaError("filesystem device and inode must be non-negative integers")
        return cls(value["device"], value["inode"])


@dataclass(frozen=True)
class InstanceRecord:
    """A catalog entry containing no instance-file content."""

    instance_id: str
    name: str
    path: str
    status: Status
    adoption_mode: AdoptionMode
    read_only: bool
    filesystem: FilesystemIdentity
    path_state: PathState
    created_at: str
    updated_at: str
    last_validated_at: str
    previous_paths: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _non_empty(self.instance_id, "instance_id")
        _non_empty(self.name, "name")
        _validate_name(self.name)
        _validate_relative_path(self.path)
        if self.status not in {"active", "archived"}:
            raise CatalogSchemaError("status must be active or archived")
        if self.adoption_mode not in {"registered", "imported"}:
            raise CatalogSchemaError("adoption mode must be registered or imported")
        if self.read_only is not True:
            raise CatalogSchemaError("catalog adoption must be read-only")
        if self.path_state not in {"present", "moved", "stale", "missing", "unsafe"}:
            raise CatalogSchemaError("unsupported path state")
        if any(_validate_relative_path(path) != path for path in self.previous_paths):
            raise CatalogSchemaError("previous paths must be canonical relative paths")
        if not isinstance(self.metadata, dict):
            raise CatalogSchemaError("metadata must be an object")
        object.__setattr__(self, "previous_paths", tuple(dict.fromkeys(self.previous_paths)))
        object.__setattr__(self, "metadata", json.loads(json.dumps(self.metadata, ensure_ascii=False)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "instanceId": self.instance_id,
            "name": self.name,
            "path": self.path,
            "status": self.status,
            "adoption": {"mode": self.adoption_mode, "readOnly": True},
            "filesystem": self.filesystem.to_dict(),
            "pathState": self.path_state,
            "previousPaths": list(self.previous_paths),
            "createdAt": self.created_at,
            "updatedAt": self.updated_at,
            "lastValidatedAt": self.last_validated_at,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "InstanceRecord":
        if not isinstance(value, Mapping):
            raise CatalogSchemaError("catalog entry must be an object")
        expected = {
            "instanceId", "name", "path", "status", "adoption", "filesystem",
            "pathState", "previousPaths", "createdAt", "updatedAt", "lastValidatedAt",
        }
        unexpected = set(value) - expected - {"metadata"}
        if unexpected:
            raise CatalogSchemaError(f"catalog entry fields are unsupported: {sorted(unexpected)}")
        adoption = value["adoption"]
        if not isinstance(adoption, Mapping) or set(adoption) != {"mode", "readOnly"}:
            raise CatalogSchemaError("adoption must contain mode and readOnly")
        if adoption["readOnly"] is not True:
            raise CatalogSchemaError("catalog adoption must be read-only")
        previous = value["previousPaths"]
        if not isinstance(previous, list) or any(not isinstance(item, str) for item in previous):
            raise CatalogSchemaError("previousPaths must be a list of strings")
        for label in ("instanceId", "name", "path", "status", "pathState", "createdAt", "updatedAt", "lastValidatedAt"):
            if not isinstance(value[label], str):
                raise CatalogSchemaError(f"{label} must be a string")
        return cls(
            instance_id=value["instanceId"], name=value["name"], path=value["path"],
            status=value["status"], adoption_mode=adoption["mode"], read_only=True,
            filesystem=FilesystemIdentity.from_dict(value["filesystem"]),
            path_state=value["pathState"], previous_paths=tuple(previous),
            created_at=value["createdAt"], updated_at=value["updatedAt"],
            last_validated_at=value["lastValidatedAt"],
            metadata=dict(value.get("metadata", {})),
        )


def _non_empty(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise CatalogError(f"{label} must be a non-empty string")
    return value


def _validate_name(value: str) -> str:
    _non_empty(value, "name")
    if value.strip() != value or "\n" in value or "\r" in value:
        raise CatalogError("name must not have surrounding whitespace or newlines")
    return value


def _validate_relative_path(value: Any) -> str:
    path = _non_empty(value, "path")
    if "\\" in path or path.startswith("/") or (len(path) > 1 and path[1] == ":"):
        raise PathSafetyError("path must be a relative POSIX path")
    parsed = PurePosixPath(path)
    if path == "." or parsed.is_absolute() or parsed.as_posix() != path or any(part in {"", ".", ".."} for part in parsed.parts):
        raise PathSafetyError("path must be canonical and must not contain traversal")
    return path


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _same_identity(left: FilesystemIdentity, right: FilesystemIdentity) -> bool:
    return left.device == right.device and left.inode == right.inode


class InstanceCatalog:
    """A locked, atomically persisted catalog confined to one local root."""

    def __init__(self, catalog_path: str | os.PathLike[str], instances_root: str | os.PathLike[str]) -> None:
        self.catalog_path = _absolute_path(catalog_path, "catalog path")
        self.lock_path = self.catalog_path.with_name(self.catalog_path.name + ".lock")
        self.instances_root = _absolute_path(instances_root, "instances root")
        _validate_parent_chain(self.catalog_path.parent)
        _validate_parent_chain(self.instances_root)
        self._assert_root()

    def register(self, path: str | os.PathLike[str], *, name: str | None = None, instance_id: str | None = None, metadata: Mapping[str, Any] | None = None) -> InstanceRecord:
        """Record a known local directory as read-only ``registered`` state."""

        return self._adopt(path, mode="registered", name=name, instance_id=instance_id, metadata=metadata)

    def import_instance(self, path: str | os.PathLike[str], *, name: str | None = None, instance_id: str | None = None, metadata: Mapping[str, Any] | None = None) -> InstanceRecord:
        """Adopt an existing local directory without reading or changing it."""

        return self._adopt(path, mode="imported", name=name, instance_id=instance_id, metadata=metadata)

    # A descriptive alias for callers that prefer the operation's intent.
    adopt = import_instance

    def get(self, instance_id: str, *, refresh: bool = True) -> InstanceRecord:
        _non_empty(instance_id, "instance_id")
        with self._locked(exclusive=refresh):
            document = self._load()
            index = self._find_index(document, instance_id)
            record = InstanceRecord.from_dict(document["entries"][index])
            if not refresh:
                return record
            changed, record = self._revalidate(record)
            if changed:
                document["entries"][index] = record.to_dict()
                self._write(document)
            return record

    def list(self, *, include_archived: bool = True, refresh: bool = True) -> tuple[InstanceRecord, ...]:
        """List entries in stable ID order, optionally revalidating paths."""

        with self._locked(exclusive=refresh):
            document = self._load()
            records = [InstanceRecord.from_dict(item) for item in document["entries"]]
            if refresh:
                refreshed = [self._revalidate(record)[1] for record in records]
                if refreshed != records:
                    document["entries"] = [record.to_dict() for record in refreshed]
                    self._write(document)
                records = refreshed
            if not include_archived:
                records = [record for record in records if record.status == "active"]
            return tuple(records)

    def refresh(self, instance_id: str | None = None) -> tuple[InstanceRecord, ...]:
        """Revalidate one or all paths, finding moved directories by identity."""

        with self._locked(exclusive=True):
            document = self._load()
            selected = range(len(document["entries"])) if instance_id is None else (self._find_index(document, instance_id),)
            changed = False
            for index in selected:
                current = InstanceRecord.from_dict(document["entries"][index])
                did_change, refreshed = self._revalidate(current)
                if did_change:
                    document["entries"][index] = refreshed.to_dict()
                    changed = True
            if changed:
                self._write(document)
            return tuple(InstanceRecord.from_dict(item) for item in document["entries"])

    def rename(self, instance_id: str, name: str) -> InstanceRecord:
        """Rename only the catalog display name; never rename the directory."""

        _validate_name(name)
        return self._update_record(instance_id, lambda record: replace(record, name=name))

    def archive(self, instance_id: str) -> InstanceRecord:
        """Archive an entry without changing its instance directory."""

        return self._update_record(instance_id, lambda record: replace(record, status="archived"))

    def unarchive(self, instance_id: str) -> InstanceRecord:
        """Restore an entry to active catalog state."""

        return self._update_record(instance_id, lambda record: replace(record, status="active"))

    def forget(self, instance_id: str) -> InstanceRecord:
        """Remove one index entry, deliberately leaving the instance untouched."""

        _non_empty(instance_id, "instance_id")
        with self._locked(exclusive=True):
            document = self._load()
            index = self._find_index(document, instance_id)
            record = InstanceRecord.from_dict(document["entries"].pop(index))
            self._write(document)
            return record

    def forget_if_matches(
        self,
        instance_id: str,
        *,
        path: str,
        filesystem: Mapping[str, Any],
        created_at: str,
    ) -> InstanceRecord | None:
        """Forget only the exact durable record created by this operation."""

        _non_empty(instance_id, "instance_id")
        expected_path = _validate_relative_path(path)
        expected_filesystem = FilesystemIdentity.from_dict(filesystem)
        _non_empty(created_at, "created_at")
        with self._locked(exclusive=True):
            document = self._load()
            try:
                index = self._find_index(document, instance_id)
            except InstanceNotFoundError:
                return None
            record = InstanceRecord.from_dict(document["entries"][index])
            if (
                record.path != expected_path
                or record.filesystem != expected_filesystem
                or record.created_at != created_at
            ):
                return None
            document["entries"].pop(index)
            self._write(document)
            return record

    def update_metadata(self, instance_id: str, metadata: Mapping[str, Any]) -> InstanceRecord:
        """Update only operator metadata; the adopted directory is untouched."""

        if not isinstance(metadata, Mapping):
            raise CatalogSchemaError("metadata must be an object")
        safe = dict(metadata)
        return self._update_record(instance_id, lambda record: replace(record, metadata=safe))

    def rebind_replaced_directory(
        self,
        instance_id: str,
        *,
        path: str,
        previous_filesystem: Mapping[str, Any],
        expected_filesystem: Mapping[str, Any],
        created_at: str,
    ) -> InstanceRecord:
        """Rebind one exact catalog record after an approved atomic replacement."""

        _non_empty(instance_id, "instance_id")
        relative = _validate_relative_path(path)
        previous = FilesystemIdentity.from_dict(previous_filesystem)
        expected = FilesystemIdentity.from_dict(expected_filesystem)
        _non_empty(created_at, "created_at")
        with self._locked(exclusive=True):
            document = self._load()
            index = self._find_index(document, instance_id)
            record = InstanceRecord.from_dict(document["entries"][index])
            if (
                record.path != relative
                or record.filesystem != previous
                or record.created_at != created_at
            ):
                raise CatalogConflictError("catalog replacement binding changed")
            observed_path, observed = self._inspect_path(relative)
            if observed_path != relative or observed != expected:
                raise CatalogConflictError("replacement directory identity changed")
            if any(
                item_index != index
                and _same_identity(InstanceRecord.from_dict(item).filesystem, observed)
                for item_index, item in enumerate(document["entries"])
            ):
                raise DuplicateInstanceError("replacement directory identity is already cataloged")
            now = _now()
            updated = replace(
                record,
                filesystem=observed,
                path_state="present",
                updated_at=now,
                last_validated_at=now,
            )
            document["entries"][index] = updated.to_dict()
            self._write(document)
            return updated

    def _adopt(self, path: str | os.PathLike[str], *, mode: AdoptionMode, name: str | None, instance_id: str | None, metadata: Mapping[str, Any] | None = None) -> InstanceRecord:
        chosen_id = _non_empty(str(uuid.uuid4()) if instance_id is None else instance_id, "instance_id")
        with self._locked(exclusive=True):
            # Inspect while holding the same lock used for the catalog write so
            # the recorded identity and path are one observation.
            relative, identity = self._inspect_path(path)
            chosen_name = _validate_name(name if name is not None else PurePosixPath(relative).name)
            document = self._load()
            records = [InstanceRecord.from_dict(item) for item in document["entries"]]
            # Revalidate before duplicate checks so a directory moved since the
            # previous operation cannot be adopted a second time under its new
            # path or identity.
            refreshed = [self._revalidate(record)[1] for record in records]
            if refreshed != records:
                document["entries"] = [record.to_dict() for record in refreshed]
                self._write(document)
                records = refreshed
            if any(record.instance_id == chosen_id for record in records):
                raise DuplicateInstanceError(f"instance ID is already cataloged: {chosen_id}")
            if any(record.path == relative for record in records):
                raise DuplicateInstanceError(f"path is already cataloged: {relative}")
            if any(_same_identity(record.filesystem, identity) for record in records):
                raise DuplicateInstanceError("directory identity is already cataloged")
            now = _now()
            record = InstanceRecord(
                instance_id=chosen_id, name=chosen_name, path=relative, status="active",
                adoption_mode=mode, read_only=True, filesystem=identity, path_state="present",
                created_at=now, updated_at=now, last_validated_at=now,
                metadata=dict(metadata or {}),
            )
            document["entries"].append(record.to_dict())
            document["entries"].sort(key=lambda item: item["instanceId"])
            self._write(document)
            return record

    def _update_record(self, instance_id: str, update: Any) -> InstanceRecord:
        with self._locked(exclusive=True):
            document = self._load()
            index = self._find_index(document, instance_id)
            current = InstanceRecord.from_dict(document["entries"][index])
            _, current = self._revalidate(current)
            updated = update(current)
            updated = replace(updated, updated_at=_now())
            document["entries"][index] = updated.to_dict()
            self._write(document)
            return updated

    def _revalidate(self, record: InstanceRecord) -> tuple[bool, InstanceRecord]:
        now = _now()
        try:
            relative, identity = self._inspect_path(record.path)
        except PathSafetyError:
            updated = replace(record, path_state="unsafe", last_validated_at=now, updated_at=now)
            return updated != record, updated
        except (FileNotFoundError, NotADirectoryError, OSError):
            relative = record.path
            identity = None
        if identity is not None and _same_identity(identity, record.filesystem):
            state: PathState = "present" if relative == record.path else "moved"
            updated = replace(record, path=relative, path_state=state, last_validated_at=now, updated_at=now)
            return updated != record, updated
        moved = self._find_identity(record.filesystem)
        if moved is not None:
            previous = record.previous_paths + ((record.path,) if moved != record.path else ())
            updated = replace(record, path=moved, path_state="moved", previous_paths=previous, last_validated_at=now, updated_at=now)
            return updated != record, updated
        state = "unsafe" if self._path_is_unsafe(record.path) else ("missing" if not self._path_exists(record.path) else "stale")
        updated = replace(record, path_state=state, last_validated_at=now, updated_at=now)
        return updated != record, updated

    def _inspect_path(self, path: str | os.PathLike[str]) -> tuple[str, FilesystemIdentity]:
        candidate = Path(path)
        if candidate.is_absolute():
            # Keep symlink components visible.  ``Path.resolve`` here would
            # turn an unsafe link into a seemingly safe path before the
            # component checks below could reject it.
            candidate = Path(os.path.abspath(os.fspath(candidate)))
            try:
                relative = candidate.relative_to(self.instances_root)
            except ValueError as exc:
                raise PathSafetyError("instance path is outside instances root") from exc
        else:
            relative = candidate
        relative_text = _validate_relative_path(relative.as_posix())
        self._assert_root()
        target = self.instances_root.joinpath(*PurePosixPath(relative_text).parts)
        self._assert_no_symlink_components(target)
        info = os.lstat(target)
        if not stat.S_ISDIR(info.st_mode):
            raise NotADirectoryError(str(target))
        return relative_text, FilesystemIdentity(info.st_dev, info.st_ino)

    def _find_identity(self, wanted: FilesystemIdentity) -> str | None:
        self._assert_root()
        stack = [self.instances_root]
        while stack:
            directory = stack.pop()
            try:
                self._assert_no_symlink_components(directory)
                with os.scandir(directory) as entries:
                    for entry in entries:
                        try:
                            info = entry.stat(follow_symlinks=False)
                        except OSError:
                            continue
                        if stat.S_ISLNK(info.st_mode):
                            continue
                        if not stat.S_ISDIR(info.st_mode):
                            continue
                        relative = Path(entry.path).relative_to(self.instances_root).as_posix()
                        if _same_identity(wanted, FilesystemIdentity(info.st_dev, info.st_ino)):
                            return _validate_relative_path(relative)
                        stack.append(Path(entry.path))
            except OSError:
                continue
        return None

    def _path_exists(self, relative: str) -> bool:
        try:
            self._inspect_path(relative)
        except (CatalogError, OSError):
            return False
        return True

    def _path_is_unsafe(self, relative: str) -> bool:
        try:
            self._assert_no_symlink_components(self.instances_root.joinpath(*PurePosixPath(relative).parts))
        except PathSafetyError:
            return True
        except FileNotFoundError:
            return False
        except OSError:
            return True
        return False

    def _assert_root(self) -> None:
        info = os.lstat(self.instances_root)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise PathSafetyError("instances root must be a real directory")
        self._assert_no_symlink_components(self.instances_root)

    def _assert_no_symlink_components(self, target: Path) -> None:
        try:
            relative = target.relative_to(self.instances_root)
        except ValueError as exc:
            raise PathSafetyError("path is outside instances root") from exc
        current = self.instances_root
        for component in relative.parts:
            current /= component
            info = os.lstat(current)
            if stat.S_ISLNK(info.st_mode):
                raise PathSafetyError(f"symlink path component rejected: {current}")

    def _find_index(self, document: Mapping[str, Any], instance_id: str) -> int:
        for index, entry in enumerate(document["entries"]):
            if entry["instanceId"] == instance_id:
                return index
        raise InstanceNotFoundError(f"instance is not cataloged: {instance_id}")

    def _load(self) -> dict[str, Any]:
        try:
            catalog_info = os.lstat(self.catalog_path)
        except FileNotFoundError:
            return {"formatVersion": CATALOG_FORMAT, "root": {"path": str(self.instances_root)}, "entries": []}
        if stat.S_ISLNK(catalog_info.st_mode):
            raise PathSafetyError("catalog file must not be a symlink")
        try:
            with self.catalog_path.open("r", encoding="utf-8") as handle:
                document = json.load(handle)
        except json.JSONDecodeError as exc:
            raise CatalogSchemaError("catalog is not valid JSON") from exc
        self._validate_document(document)
        return document

    def _validate_document(self, document: Any) -> None:
        if not isinstance(document, Mapping) or set(document) != {"formatVersion", "root", "entries"}:
            raise CatalogSchemaError("catalog must contain exactly formatVersion, root, and entries")
        if document["formatVersion"] != CATALOG_FORMAT:
            raise CatalogSchemaError(f"unsupported catalog format: {document.get('formatVersion')!r}")
        root = document["root"]
        if not isinstance(root, Mapping) or set(root) != {"path"} or root["path"] != str(self.instances_root):
            raise CatalogSchemaError("catalog root does not match configured instances root")
        if not isinstance(document["entries"], list):
            raise CatalogSchemaError("catalog entries must be a list")
        records = [InstanceRecord.from_dict(item) for item in document["entries"]]
        ids = [record.instance_id for record in records]
        if len(set(ids)) != len(ids) or ids != sorted(ids):
            raise CatalogSchemaError("catalog instance IDs must be unique and sorted")

    def _write(self, document: Mapping[str, Any]) -> None:
        self._validate_document(document)
        self.catalog_path.parent.mkdir(parents=True, exist_ok=True)
        if self.catalog_path.is_symlink():
            raise PathSafetyError("catalog file must not be a symlink")
        encoded = json.dumps(document, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
        descriptor, temporary = tempfile.mkstemp(prefix=f".{self.catalog_path.name}.", suffix=".tmp", dir=self.catalog_path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.catalog_path)
            directory_fd = os.open(self.catalog_path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except Exception:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise

    @contextmanager
    def _locked(self, *, exclusive: bool) -> Iterator[None]:
        self.catalog_path.parent.mkdir(parents=True, exist_ok=True)
        _validate_parent_chain(self.catalog_path.parent)
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.lock_path, flags, 0o600)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise PathSafetyError("catalog lock must not be a symlink") from exc
            raise
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)


def _absolute_path(value: str | os.PathLike[str], label: str) -> Path:
    raw = Path(value).expanduser()
    if not raw.is_absolute():
        raw = Path.cwd() / raw
    # Normalize lexical ``.``/``..`` components but deliberately do not
    # resolve symlinks: symlink identity must remain observable and fail
    # closed at the boundary.
    return Path(os.path.abspath(os.fspath(raw)))


def _validate_parent_chain(parent: Path) -> None:
    current = parent
    while True:
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            current = current.parent
            if current == current.parent:
                break
            continue
        if stat.S_ISLNK(info.st_mode):
            raise PathSafetyError("catalog parent must not contain a symlink")
        if not stat.S_ISDIR(info.st_mode):
            raise PathSafetyError("catalog parent must be a directory")
        if current == current.parent:
            break
        current = current.parent


__all__ = [
    "CATALOG_FORMAT", "Catalog", "CatalogError", "CatalogSchemaError", "DuplicateInstanceError",
    "FilesystemIdentity", "InstanceCatalog", "InstanceNotFoundError", "InstanceRecord",
    "PathSafetyError",
]


# Short alias for applications that do not need the longer product-qualified
# class name; both names refer to the same API.
Catalog = InstanceCatalog
