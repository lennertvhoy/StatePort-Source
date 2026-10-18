"""Immutable, local-only Git snapshot identities for StateBench.

This module resolves objects already present in a local checkout. It never
fetches or serializes a checkout path. It verifies the configured public
origin without contacting it. A caller may use a moving revision at resolution
time, but final identities contain only immutable Git and content identities.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any
from urllib.parse import urlparse


SNAPSHOT_CONFIGURATION_FORMAT = "statebench.snapshot-configuration/v1"
LOCAL_READ_ONLY_PROVENANCE = "local_read_only_git"
_OBJECT_ID = re.compile(r"^[0-9a-f]{40,64}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class SnapshotResolutionError(ValueError):
    """The supplied local Git source cannot produce a safe snapshot."""


class CompatibilityMode(str, Enum):
    """The StateDD compatibility boundary selected for a snapshot."""

    NATIVE = "native"
    LEGACY = "legacy"


def _canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _require_object_id(value: str, name: str) -> str:
    if not isinstance(value, str) or not _OBJECT_ID.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase full Git object ID")
    return value


def _require_public_repository(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("repository must be a non-empty public HTTPS URL")
    parsed = urlparse(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.endswith(".git")
    ):
        raise ValueError("repository must be a credential-free public HTTPS Git URL")
    return value


def _require_provenance(value: str) -> str:
    if value != LOCAL_READ_ONLY_PROVENANCE:
        raise ValueError(f"unsupported source provenance: {value!r}")
    return value


def _require_safe_relative_path(path: str) -> None:
    candidate = Path(path)
    if not path or candidate.is_absolute() or ".." in candidate.parts or "\\" in path:
        raise SnapshotResolutionError("tracked Git path is unsafe")


def _require_safe_checkout(path: str | Path) -> Path:
    checkout = Path(path)
    if ".." in checkout.parts:
        raise SnapshotResolutionError("source checkout must not contain path traversal")
    current = checkout
    while True:
        if current.is_symlink():
            raise SnapshotResolutionError("source checkout must not traverse a symlink")
        if current.parent == current:
            break
        current = current.parent
    if not checkout.is_dir():
        raise SnapshotResolutionError("source checkout must be a directory")
    return checkout


@dataclass(frozen=True)
class SnapshotConfiguration:
    """A strict, portable StateDD content identity with no mutable ref field."""

    repository: str
    commit: str
    tree: str
    content_digest: str
    compatibility_mode: CompatibilityMode
    compatibility_wrapper: str | None
    source_provenance: str = LOCAL_READ_ONLY_PROVENANCE
    format_version: str = SNAPSHOT_CONFIGURATION_FORMAT

    def __post_init__(self) -> None:
        _require_public_repository(self.repository)
        _require_object_id(self.commit, "commit")
        _require_object_id(self.tree, "tree")
        if not isinstance(self.content_digest, str) or not _DIGEST.fullmatch(self.content_digest):
            raise ValueError("content_digest must be a sha256 digest")
        if not isinstance(self.compatibility_mode, CompatibilityMode):
            raise ValueError("compatibility_mode is unsupported")
        if self.compatibility_wrapper is not None and (
            not isinstance(self.compatibility_wrapper, str) or not self.compatibility_wrapper.strip()
        ):
            raise ValueError("compatibility_wrapper must be a non-empty identity or None")
        if self.compatibility_mode is CompatibilityMode.LEGACY and self.compatibility_wrapper is None:
            raise ValueError("legacy snapshots require a compatibility wrapper identity")
        _require_provenance(self.source_provenance)
        if self.format_version != SNAPSHOT_CONFIGURATION_FORMAT:
            raise ValueError("unsupported snapshot configuration format")

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.format_version,
            "repository": self.repository,
            "commit": self.commit,
            "tree": self.tree,
            "contentDigest": self.content_digest,
            "compatibilityMode": self.compatibility_mode.value,
            "compatibilityWrapper": self.compatibility_wrapper,
            "sourceProvenance": self.source_provenance,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "SnapshotConfiguration":
        """Parse only the closed wire shape; unknown properties fail closed."""

        if not isinstance(value, dict):
            raise ValueError("snapshot configuration must be an object")
        expected = {
            "formatVersion", "repository", "commit", "tree", "contentDigest",
            "compatibilityMode", "compatibilityWrapper", "sourceProvenance",
        }
        if set(value) != expected:
            raise ValueError("snapshot configuration has missing or additional properties")
        try:
            mode = CompatibilityMode(value["compatibilityMode"])
        except (TypeError, ValueError) as exc:
            raise ValueError("compatibilityMode is unsupported") from exc
        return cls(
            repository=value["repository"], commit=value["commit"], tree=value["tree"],
            content_digest=value["contentDigest"], compatibility_mode=mode,
            compatibility_wrapper=value["compatibilityWrapper"],
            source_provenance=value["sourceProvenance"], format_version=value["formatVersion"],
        )

    def canonical_json(self) -> str:
        return _canonical_json(self.to_dict())

    @property
    def identity_digest(self) -> str:
        return "sha256:" + hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()


class LocalReadOnlySnapshotResolver:
    """Resolve a revision from a pre-existing local Git checkout without mutation."""

    def __init__(self, *, timeout_seconds: float = 10.0) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._timeout_seconds = timeout_seconds

    def resolve(
        self,
        source_checkout: str | Path,
        *,
        repository: str,
        requested_revision: str,
        compatibility_mode: CompatibilityMode = CompatibilityMode.NATIVE,
        compatibility_wrapper: str | None = None,
    ) -> SnapshotConfiguration:
        """Resolve a revision, retaining none of the requested ref in the result."""

        _require_public_repository(repository)
        if not isinstance(requested_revision, str) or not requested_revision.strip():
            raise SnapshotResolutionError("requested_revision must be non-empty")
        checkout = _require_safe_checkout(source_checkout)
        if self._git(checkout, ["rev-parse", "--is-inside-work-tree"]) != "true":
            raise SnapshotResolutionError("source checkout is not a Git worktree")
        origin = self._git(checkout, ["config", "--get", "remote.origin.url"])
        if origin != repository:
            raise SnapshotResolutionError("source checkout origin does not match repository identity")
        if self._git(checkout, ["status", "--porcelain=v1", "--untracked-files=all"]):
            raise SnapshotResolutionError("source checkout must be clean")
        commit = self._git(checkout, ["rev-parse", "--verify", f"{requested_revision}^{{commit}}"])
        tree = self._git(checkout, ["rev-parse", "--verify", f"{commit}^{{tree}}"])
        return SnapshotConfiguration(
            repository=repository, commit=commit, tree=tree,
            content_digest=self._tracked_content_digest(checkout, commit),
            compatibility_mode=compatibility_mode, compatibility_wrapper=compatibility_wrapper,
        )

    def _git(self, checkout: Path, args: list[str], *, raw: bool = False) -> str | bytes:
        completed = subprocess.run(
            ["git", "-C", str(checkout), *args], check=False, capture_output=True,
            text=not raw, timeout=self._timeout_seconds, shell=False,
        )
        if completed.returncode != 0:
            stderr = completed.stderr.decode("utf-8", "replace") if raw else completed.stderr
            raise SnapshotResolutionError(f"Git command failed: {stderr.strip()}")
        return completed.stdout if raw else completed.stdout.strip()

    def _tracked_content_digest(self, checkout: Path, commit: str) -> str:
        listing = self._git(checkout, ["ls-tree", "-r", "-z", "--full-tree", commit], raw=True)
        assert isinstance(listing, bytes)
        digest = hashlib.sha256()
        for entry in listing.split(b"\0"):
            if not entry:
                continue
            try:
                metadata, raw_path = entry.split(b"\t", 1)
                mode, object_type, object_id = metadata.decode("ascii").split(" ", 2)
                relative = raw_path.decode("utf-8", "strict")
            except (UnicodeDecodeError, ValueError) as exc:
                raise SnapshotResolutionError("Git tree entry is malformed") from exc
            _require_safe_relative_path(relative)
            if object_type != "blob":
                raise SnapshotResolutionError("tracked Git tree contains a non-file entry")
            if mode == "120000":
                raise SnapshotResolutionError("tracked symlinks are not allowed in snapshots")
            if mode not in {"100644", "100755"}:
                raise SnapshotResolutionError("tracked Git tree contains an unsupported file mode")
            content = self._git(checkout, ["cat-file", "blob", object_id], raw=True)
            assert isinstance(content, bytes)
            digest.update(mode.encode("ascii")); digest.update(b"\0")
            digest.update(raw_path); digest.update(b"\0")
            digest.update(str(len(content)).encode("ascii")); digest.update(b"\0")
            digest.update(content)
        return "sha256:" + digest.hexdigest()
