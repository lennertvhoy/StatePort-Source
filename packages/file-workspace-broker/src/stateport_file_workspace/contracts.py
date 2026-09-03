"""Versioned transport-neutral contracts for the scoped file Workbench.

The project root and policy rules are server-owned configuration.  Browser
messages contain repository-relative paths and exact identities only; no
contract serializes an absolute host path, lease token, or file contents into
an audit receipt.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import re
from typing import Any, Mapping
import unicodedata


FILE_WORKSPACE_FORMAT = "stateport.file-workspace/v1"
OWNERSHIP_CLASSES = frozenset({"application_owned", "canonical", "generated", "disposable"})
RULE_MATCH_TYPES = frozenset({"exact", "subtree"})
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def _format(payload: dict[str, Any]) -> dict[str, Any]:
    return {"formatVersion": FILE_WORKSPACE_FORMAT, **payload}


def bounded_id(value: str, label: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ValueError(f"{label} must be a bounded identifier")
    return value


def git_sha(value: str, label: str = "base_sha") -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise ValueError(f"{label} must be an exact Git object identity")
    return value


def digest(value: str | None, label: str) -> str | None:
    if value is not None and (not isinstance(value, str) or _DIGEST.fullmatch(value) is None):
        raise ValueError(f"{label} must be a sha256 digest")
    return value


def relative_path(value: str, label: str = "path", *, allow_root: bool = False) -> str:
    """Validate a canonical browser path without decoding ambiguous input."""

    if not isinstance(value, str):
        raise ValueError(f"{label} must be a repository-relative path")
    if value == "" and allow_root:
        return value
    if (
        not value
        or len(value) > 512
        or value != unicodedata.normalize("NFC", value)
        or value.startswith("/")
        or value.endswith("/")
        or "//" in value
        or "\\" in value
        or "%" in value
        or "\x00" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError(f"{label} must be a canonical repository-relative POSIX path")
    parsed = PurePosixPath(value)
    parts = parsed.parts
    if (
        parsed.is_absolute()
        or not parts
        or any(part in {"", ".", ".."} or part != part.strip() or len(part) > 128 for part in parts)
        or parsed.as_posix() != value
    ):
        raise ValueError(f"{label} must not traverse or use ambiguous components")
    return value


@dataclass(frozen=True)
class PathPolicyRule:
    """Server-owned classification and operation allowlist for one path tree."""

    rule_id: str
    path: str
    match: str
    ownership_class: str
    read: bool = True
    write: bool = False
    create: bool = False
    rename: bool = False
    delete: bool = False

    def __post_init__(self) -> None:
        bounded_id(self.rule_id, "rule_id")
        relative_path(self.path, "rule path", allow_root=True)
        if self.match not in RULE_MATCH_TYPES:
            raise ValueError("path policy match must be exact or subtree")
        if self.match == "exact" and not self.path:
            raise ValueError("the root path cannot be an exact file rule")
        if self.ownership_class not in OWNERSHIP_CLASSES:
            raise ValueError("path policy ownership class is unsupported")
        for field_name in ("read", "write", "create", "rename", "delete"):
            if not isinstance(getattr(self, field_name), bool):
                raise ValueError(f"{field_name} must be boolean")
        if self.ownership_class == "generated" and any(
            (self.write, self.create, self.rename, self.delete)
        ):
            raise ValueError("generated paths are read-only in file-workspace v1")
        if self.ownership_class == "canonical" and any((self.write, self.create, self.rename, self.delete)):
            raise ValueError(
                "canonical paths are read-only until an authoritative StatePort transaction boundary is available"
            )

    def matches(self, path: str) -> bool:
        if self.match == "exact":
            return path == self.path
        return not self.path or path == self.path or path.startswith(self.path + "/")

    def contains(self, directory: str) -> bool:
        """Return whether a directory can lead to this rule without granting it."""

        if not directory:
            return True
        return self.path == directory or self.path.startswith(directory + "/") or self.matches(directory)

    def to_dict(self) -> dict[str, Any]:
        return _format({
            "ruleId": self.rule_id,
            "path": self.path,
            "match": self.match,
            "ownershipClass": self.ownership_class,
            "operations": {
                "read": self.read,
                "write": self.write,
                "create": self.create,
                "rename": self.rename,
                "delete": self.delete,
            },
        })


@dataclass(frozen=True)
class FileWorkspaceProfile:
    """Trusted application/instance/root binding; never accepted from a client."""

    profile_id: str
    application_id: str
    application_kind: str
    instance_id: str
    project_root: Path
    expected_root_identity: tuple[int, int]
    effective_capabilities: frozenset[str]
    actor_permissions: Mapping[str, frozenset[str]]
    path_rules: tuple[PathPolicyRule, ...]
    maximum_file_bytes: int = 1_048_576
    maximum_directory_entries: int = 2_000
    maximum_pending_writes: int = 32
    pending_write_lifetime_seconds: int = 1_800

    def __post_init__(self) -> None:
        bounded_id(self.profile_id, "profile_id")
        bounded_id(self.application_id, "application_id")
        bounded_id(self.instance_id, "instance_id")
        if self.application_kind != "development":
            raise ValueError("file Workbench profiles are limited to development applications")
        if not isinstance(self.project_root, Path) or not self.project_root.is_absolute():
            raise ValueError("project_root must be a server-owned absolute path")
        if (
            not isinstance(self.expected_root_identity, tuple)
            or len(self.expected_root_identity) != 2
            or any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in self.expected_root_identity)
        ):
            raise ValueError("expected_root_identity must be the cataloged directory device and inode")
        required = {"workbench", "file_viewer"}
        if not required.issubset(self.effective_capabilities):
            raise ValueError("file Workbench profile lacks required effective capabilities")
        if not self.actor_permissions:
            raise ValueError("file Workbench profile requires at least one bound actor")
        for actor_id, permissions in self.actor_permissions.items():
            bounded_id(actor_id, "actor_id")
            if not isinstance(permissions, frozenset) or not permissions <= {"file.read", "file.write"}:
                raise ValueError("actor permissions contain an unsupported permission")
        if not self.path_rules or len({rule.rule_id for rule in self.path_rules}) != len(self.path_rules):
            raise ValueError("path rules must be non-empty and uniquely identified")
        if not 1 <= self.maximum_file_bytes <= 16_777_216:
            raise ValueError("maximum_file_bytes is outside the supported bound")
        if not 1 <= self.maximum_directory_entries <= 10_000:
            raise ValueError("maximum_directory_entries is outside the supported bound")
        if not 1 <= self.maximum_pending_writes <= 128:
            raise ValueError("maximum_pending_writes is outside the supported bound")
        if not 30 <= self.pending_write_lifetime_seconds <= 86_400:
            raise ValueError("pending_write_lifetime_seconds is outside the supported bound")

    def to_dict(self, *, root_identity_digest: str, base_sha: str) -> dict[str, Any]:
        digest(root_identity_digest, "root_identity_digest")
        git_sha(base_sha)
        return _format({
            "profileId": self.profile_id,
            "applicationId": self.application_id,
            "applicationKind": self.application_kind,
            "instanceId": self.instance_id,
            "effectiveCapabilities": sorted(self.effective_capabilities),
            "rootIdentityDigest": root_identity_digest,
            "baseSha": base_sha,
            "maximumFileBytes": self.maximum_file_bytes,
            "autosave": False,
        })


@dataclass(frozen=True)
class DirectoryEntry:
    path: str
    name: str
    kind: str
    ownership_class: str | None
    size: int | None
    read_only: bool

    def to_dict(self) -> dict[str, Any]:
        return _format({
            "path": self.path,
            "name": self.name,
            "kind": self.kind,
            "ownershipClass": self.ownership_class or "unavailable",
            "size": self.size,
            "readOnly": self.read_only,
            "generated": self.ownership_class == "generated",
            "disposable": self.ownership_class == "disposable",
        })


@dataclass(frozen=True)
class DirectoryListing:
    path: str
    entries: tuple[DirectoryEntry, ...]
    base_sha: str
    truncated: bool

    def to_dict(self) -> dict[str, Any]:
        return _format({"operation": "listDirectory", "path": self.path, "entries": [item.to_dict() for item in self.entries], "baseSha": self.base_sha, "truncated": self.truncated})


@dataclass(frozen=True)
class FileMetadata:
    path: str
    size: int
    content_hash: str
    base_sha: str
    ownership_class: str
    language: str
    read_only: bool

    def __post_init__(self) -> None:
        relative_path(self.path)
        digest(self.content_hash, "content_hash")
        git_sha(self.base_sha)

    def to_dict(self) -> dict[str, Any]:
        return _format({
            "operation": "readFileMetadata",
            "path": self.path,
            "size": self.size,
            "contentHash": self.content_hash,
            "baseSha": self.base_sha,
            "ownershipClass": self.ownership_class,
            "language": self.language,
            "encoding": "utf-8",
            "readOnly": self.read_only,
            "generated": self.ownership_class == "generated",
            "disposable": self.ownership_class == "disposable",
        })


@dataclass(frozen=True)
class FileRead:
    metadata: FileMetadata
    content: str

    def to_dict(self) -> dict[str, Any]:
        return _format({"operation": "readFile", "metadata": self.metadata.to_dict(), "content": self.content})


@dataclass(frozen=True)
class PreparedWrite:
    prepared_write_id: str
    operation: str
    path: str
    actor_id: str
    application_id: str
    instance_id: str
    base_sha: str
    original_hash: str | None
    candidate_hash: str
    ownership_class: str
    expires_at: str
    validation_required: bool

    def to_dict(self) -> dict[str, Any]:
        return _format({
            "operation": "prepareWrite" if self.operation == "write" else "createFile",
            "preparedWriteId": self.prepared_write_id,
            "writeKind": self.operation,
            "path": self.path,
            "actorId": self.actor_id,
            "applicationId": self.application_id,
            "instanceId": self.instance_id,
            "baseSha": self.base_sha,
            "originalHash": self.original_hash,
            "candidateHash": self.candidate_hash,
            "ownershipClass": self.ownership_class,
            "expiresAt": self.expires_at,
            "requiresDiffConfirmation": True,
            "validationRequired": self.validation_required,
        })


@dataclass(frozen=True)
class DiffPreview:
    prepared_write_id: str
    path: str
    diff: str
    diff_digest: str
    original_hash: str | None
    candidate_hash: str
    truncated: bool

    def to_dict(self) -> dict[str, Any]:
        return _format({
            "operation": "previewDiff",
            "preparedWriteId": self.prepared_write_id,
            "path": self.path,
            "diff": self.diff,
            "diffDigest": self.diff_digest,
            "originalHash": self.original_hash,
            "candidateHash": self.candidate_hash,
            "truncated": self.truncated,
            "confirmable": not self.truncated,
        })


@dataclass(frozen=True)
class FileMutationReceipt:
    receipt_id: str
    operation: str
    actor_id: str
    application_id: str
    instance_id: str
    source_path: str
    destination_path: str | None
    base_sha: str
    pre_hash: str | None
    post_hash: str | None
    ownership_class: str
    diff_digest: str | None
    validation: str
    completed_at: str

    def to_dict(self) -> dict[str, Any]:
        return _format({
            "operation": self.operation,
            "receiptId": self.receipt_id,
            "actorId": self.actor_id,
            "applicationId": self.application_id,
            "instanceId": self.instance_id,
            "sourcePath": self.source_path,
            "destinationPath": self.destination_path,
            "baseSha": self.base_sha,
            "preHash": self.pre_hash,
            "postHash": self.post_hash,
            "ownershipClass": self.ownership_class,
            "diffDigest": self.diff_digest,
            "validation": self.validation,
            "completedAt": self.completed_at,
            "contentRetained": False,
        })
