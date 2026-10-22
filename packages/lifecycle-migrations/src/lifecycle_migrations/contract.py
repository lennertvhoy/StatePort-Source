"""The closed, JSON-compatible migration contract.

The contract is deliberately declarative.  It describes data operations; it
does not contain import paths, callbacks, commands, expressions, or source
code.  Validation is strict so an unrecognised operation cannot be silently
accepted as a future extension.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath
from typing import Any, Mapping


CONTRACT_FORMAT = "stateport.lifecycle-migration/v1"
RECEIPT_FORMAT = "stateport.migration-receipt/v1"
REGISTRY_FORMAT = "stateport.migration-registry/v1"
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID_RE = re.compile(r"^stateport\.[a-z0-9][a-z0-9._-]*$")


class MigrationError(ValueError):
    """Raised when a migration contract or execution input is unsafe."""


class PathOwner(str, Enum):
    INSTANCE = "instance"


class OperationKind(str, Enum):
    COPY = "copy"
    MOVE = "move"
    DELETE = "delete"
    WRITE_TEXT = "write_text"
    REPLACE_TEXT = "replace_text"


def _string(value: Any, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        raise MigrationError(f"{label} must be a non-empty string")
    if "\x00" in value:
        raise MigrationError(f"{label} contains a NUL byte")
    return value


def safe_relative_path(value: Any, label: str = "path") -> str:
    """Validate the portable relative path form used by the contract."""

    path = _string(value, label)
    if "\\" in path or path.startswith("/") or (len(path) > 1 and path[1] == ":"):
        raise MigrationError(f"{label} must be a relative POSIX path")
    parsed = PurePosixPath(path)
    if parsed.is_absolute() or path != parsed.as_posix():
        raise MigrationError(f"{label} is not in canonical relative path form")
    if any(part in {"", ".", ".."} for part in parsed.parts):
        raise MigrationError(f"{label} must not contain empty, '.', or '..' components")
    if path == "." or not parsed.parts:
        raise MigrationError(f"{label} must name a file")
    # These are StatePort control-plane paths, never migration data paths.
    if parsed.parts[0] in {".git", ".statedd", ".stateport"}:
        raise MigrationError(f"{label} targets a reserved StatePort path")
    return path


def _digest(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _hash_or_none(value: Any, label: str) -> str | None:
    if value is None:
        return None
    result = _string(value, label)
    if not _DIGEST_RE.fullmatch(result):
        raise MigrationError(f"{label} must be a sha256 digest")
    return result


@dataclass(frozen=True)
class OwnedPath:
    """An exact path the migration is allowed to inspect or mutate."""

    path: str
    owner: PathOwner = PathOwner.INSTANCE

    def __post_init__(self) -> None:
        safe_relative_path(self.path, "owned path")
        if not isinstance(self.owner, PathOwner):
            raise MigrationError("owned path owner must be instance")

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "owner": self.owner.value}

    @classmethod
    def from_dict(cls, value: Any, label: str = "ownedPath") -> "OwnedPath":
        if not isinstance(value, Mapping) or set(value) != {"path", "owner"}:
            raise MigrationError(f"{label} must contain only path and owner")
        try:
            owner = PathOwner(value["owner"])
        except (TypeError, ValueError) as exc:
            raise MigrationError(f"{label}.owner must be 'instance'") from exc
        return cls(safe_relative_path(value["path"], f"{label}.path"), owner)


@dataclass(frozen=True)
class MigrationOperation:
    """One closed-set deterministic file operation."""

    kind: OperationKind
    target: str
    source: str | None = None
    content: str | None = None
    old: str | None = None
    new: str | None = None
    expected_hash: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, OperationKind):
            raise MigrationError("operation kind is unsupported")
        safe_relative_path(self.target, "operation target")
        if self.source is not None:
            safe_relative_path(self.source, "operation source")
        if self.expected_hash is not None:
            _hash_or_none(self.expected_hash, "operation expectedHash")
        if self.kind in {OperationKind.COPY, OperationKind.MOVE}:
            if self.source is None or self.content is not None or self.old is not None or self.new is not None:
                raise MigrationError(f"{self.kind.value} requires only source and target")
        elif self.kind is OperationKind.DELETE:
            if self.source is not None or self.content is not None or self.old is not None or self.new is not None:
                raise MigrationError("delete requires only target")
        elif self.kind is OperationKind.WRITE_TEXT:
            if self.source is not None or self.content is None or self.old is not None or self.new is not None:
                raise MigrationError("write_text requires content and target")
        elif self.kind is OperationKind.REPLACE_TEXT:
            if self.source is not None or self.content is not None or self.old is None or self.new is None:
                raise MigrationError("replace_text requires old, new, and target")
            if self.old == "":
                raise MigrationError("replace_text.old must not be empty")

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {"kind": self.kind.value, "target": self.target}
        if self.source is not None:
            value["source"] = self.source
        if self.content is not None:
            value["content"] = self.content
        if self.old is not None:
            value["old"] = self.old
        if self.new is not None:
            value["new"] = self.new
        if self.expected_hash is not None:
            value["expectedHash"] = self.expected_hash
        return value

    @classmethod
    def from_dict(cls, value: Any, label: str = "operation") -> "MigrationOperation":
        if not isinstance(value, Mapping):
            raise MigrationError(f"{label} must be a mapping")
        allowed = {"kind", "target", "source", "content", "old", "new", "expectedHash"}
        unknown = set(value) - allowed
        if unknown:
            raise MigrationError(f"{label} contains unknown fields: {sorted(unknown)}")
        try:
            kind = OperationKind(value.get("kind"))
        except (TypeError, ValueError) as exc:
            raise MigrationError(f"{label}.kind is unsupported") from exc
        for key in ("source", "content", "old", "new"):
            if key in value and not isinstance(value[key], str):
                raise MigrationError(f"{label}.{key} must be a string")
        return cls(
            kind=kind,
            target=safe_relative_path(value.get("target"), f"{label}.target"),
            source=(safe_relative_path(value["source"], f"{label}.source") if "source" in value else None),
            content=value.get("content"),
            old=value.get("old"),
            new=value.get("new"),
            expected_hash=_hash_or_none(value.get("expectedHash"), f"{label}.expectedHash"),
        )


@dataclass(frozen=True)
class MigrationContract:
    """A fully declarative, StatePort-owned migration definition."""

    migration_id: str
    from_version: str
    to_version: str
    read_paths: tuple[str, ...]
    write_paths: tuple[str, ...]
    owned_paths: tuple[OwnedPath, ...]
    operations: tuple[MigrationOperation, ...]
    description: str = ""
    owner: str = "stateport"
    format_version: str = CONTRACT_FORMAT

    def __post_init__(self) -> None:
        _string(self.migration_id, "migration_id")
        if not _ID_RE.fullmatch(self.migration_id):
            raise MigrationError("migration_id must use the stateport.<name> form")
        _string(self.from_version, "from_version")
        _string(self.to_version, "to_version")
        if self.from_version == self.to_version:
            raise MigrationError("from_version and to_version must differ")
        if self.owner != "stateport":
            raise MigrationError("migration owner must be 'stateport'")
        if self.format_version != CONTRACT_FORMAT:
            raise MigrationError(f"format_version must be {CONTRACT_FORMAT!r}")
        if not self.operations:
            raise MigrationError("a migration must declare at least one operation")
        reads = tuple(safe_relative_path(path, "read path") for path in self.read_paths)
        writes = tuple(safe_relative_path(path, "write path") for path in self.write_paths)
        if len(set(reads)) != len(reads) or len(set(writes)) != len(writes):
            raise MigrationError("read and write paths must be unique")
        if tuple(sorted(reads)) != reads or tuple(sorted(writes)) != writes:
            raise MigrationError("read and write paths must be sorted deterministically")
        owned = tuple(item.path for item in self.owned_paths)
        if len(set(owned)) != len(owned) or tuple(sorted(owned)) != owned:
            raise MigrationError("owned paths must be unique and sorted deterministically")
        if set(owned) != set(reads) | set(writes):
            raise MigrationError("owned paths must exactly cover declared reads and writes")
        if any(item.owner is not PathOwner.INSTANCE for item in self.owned_paths):
            raise MigrationError("only instance-owned paths may be migrated")
        read_set, write_set = set(reads), set(writes)
        for index, operation in enumerate(self.operations):
            if not isinstance(operation, MigrationOperation):
                raise MigrationError(f"operations[{index}] is not typed")
            if operation.target not in write_set:
                raise MigrationError(f"operations[{index}].target is not a declared write path")
            if operation.kind is OperationKind.REPLACE_TEXT and operation.target not in read_set:
                raise MigrationError("replace_text target must also be a read path")
            if operation.kind in {OperationKind.COPY, OperationKind.MOVE} and operation.source not in read_set:
                raise MigrationError(f"operations[{index}].source is not a declared read path")
        if len({operation.target for operation in self.operations}) < 1:
            raise MigrationError("migration has no write target")

    @property
    def digest(self) -> str:
        return _digest(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        value: dict[str, Any] = {
            "formatVersion": self.format_version,
            "owner": self.owner,
            "migrationId": self.migration_id,
            "fromVersion": self.from_version,
            "toVersion": self.to_version,
            "description": self.description,
            "readPaths": list(self.read_paths),
            "writePaths": list(self.write_paths),
            "ownedPaths": [item.to_dict() for item in self.owned_paths],
            "operations": [item.to_dict() for item in self.operations],
        }
        if include_digest:
            value["contractDigest"] = self.digest
        return value

    @classmethod
    def from_dict(cls, value: Any) -> "MigrationContract":
        if not isinstance(value, Mapping):
            raise MigrationError("migration contract must be a mapping")
        allowed = {
            "formatVersion", "owner", "migrationId", "fromVersion", "toVersion",
            "description", "readPaths", "writePaths", "ownedPaths", "operations",
            "contractDigest",
        }
        unknown = set(value) - allowed
        if unknown:
            raise MigrationError(f"migration contract contains unknown fields: {sorted(unknown)}")
        for key in ("readPaths", "writePaths", "ownedPaths", "operations"):
            if not isinstance(value.get(key), list):
                raise MigrationError(f"{key} must be a list")
        description = value.get("description", "")
        if not isinstance(description, str):
            raise MigrationError("description must be a string")
        contract = cls(
            migration_id=_string(value.get("migrationId"), "migrationId"),
            from_version=_string(value.get("fromVersion"), "fromVersion"),
            to_version=_string(value.get("toVersion"), "toVersion"),
            description=description,
            owner=value.get("owner", "stateport"),
            format_version=value.get("formatVersion", CONTRACT_FORMAT),
            read_paths=tuple(value["readPaths"]),
            write_paths=tuple(value["writePaths"]),
            owned_paths=tuple(OwnedPath.from_dict(item, f"ownedPaths[{i}]") for i, item in enumerate(value["ownedPaths"])),
            operations=tuple(MigrationOperation.from_dict(item, f"operations[{i}]") for i, item in enumerate(value["operations"])),
        )
        supplied_digest = value.get("contractDigest")
        if supplied_digest is not None and supplied_digest != contract.digest:
            raise MigrationError("contractDigest does not match canonical contract")
        return contract
