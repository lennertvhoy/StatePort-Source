"""File-change proposals: StatePort's own view of what a staged run changed.

An agent (or a reviewed instance script) edits a disposable staged copy of an
instance. StatePort, never the agent, compares that copy with the exact base it
staged, applies the action's writable-path policy and size budget, stores the
new file contents content-addressed outside the run store, and emits exactly
one ``stateport.file-change-proposal/v1``. Nothing here writes canonical state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Iterable, Mapping

FILE_CHANGE_PROPOSAL_FORMAT = "stateport.file-change-proposal/v1"
FILE_CHANGE_WRITER_RECEIPT_FORMAT = "stateport.file-change-writer-receipt/v1"
# Never writable by any action, whatever a descriptor declares. `.git` at the
# top level is StatePort's history (changes there are ignored, never proposed);
# a nested `.git` anywhere is refused outright.
ALWAYS_PROTECTED_ROOTS = (".git", ".stateport", ".statedd")
OWNERSHIP_VALUES = ("instance", "template", "generated")
_BLOB_HEX = re.compile(r"^[0-9a-f]{64}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class FileChangeRefusal(ValueError):
    """A typed refusal of an observed change set; nothing is proposed."""

    def __init__(self, code: str, message: str, paths: Iterable[str] = ()):
        self.code = code
        self.paths = tuple(sorted(set(paths)))[:32]
        super().__init__(message)

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": str(self), "paths": list(self.paths)}


@dataclass(frozen=True)
class FileChangeLimits:
    max_files: int = 256
    max_total_bytes: int = 4 * 1024 * 1024
    max_file_bytes: int = 2 * 1024 * 1024
    max_patch_bytes: int = 256 * 1024

    def to_dict(self) -> dict[str, int]:
        return {
            "maxFiles": self.max_files, "maxTotalBytes": self.max_total_bytes,
            "maxFileBytes": self.max_file_bytes, "maxPatchBytes": self.max_patch_bytes,
        }


def _sha256(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _canonical_digest(value: Any) -> str:
    payload = (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
    return _sha256(payload)


def _entry_matches(entry: str, path: str) -> bool:
    if entry == "./":
        return True
    if entry.endswith("/"):
        return path.startswith(entry) or path + "/" == entry
    return path == entry


def _entry_specificity(entry: str) -> int:
    return 0 if entry == "./" else len(entry)


def _first_component(path: str) -> str:
    return path.split("/", 1)[0]


@dataclass(frozen=True)
class WritablePolicy:
    """Effective writable set = instance-owned − protected ∩ action narrowing."""

    ownership: tuple[tuple[str, str], ...]
    protected: tuple[str, ...] = ()
    narrowing: tuple[str, ...] = ()
    limits: FileChangeLimits = field(default_factory=FileChangeLimits)

    @classmethod
    def build(
        cls,
        ownership: Mapping[str, str],
        *,
        protected: Iterable[str] = (),
        narrowing: Iterable[str] = (),
        limits: FileChangeLimits | None = None,
    ) -> "WritablePolicy":
        # Only `instance` is ever writable; any other owner value (including a
        # lifecycle manifest's `override`) is kept and simply not writable.
        normalized: dict[str, str] = {}
        for key, owner in ownership.items():
            normalized[_normalize_entry(key)] = str(owner)
        return cls(
            tuple(sorted(normalized.items())),
            tuple(sorted({_normalize_entry(item) for item in protected})),
            tuple(sorted({_normalize_entry(item) for item in narrowing})),
            limits or FileChangeLimits(),
        )

    def owner(self, path: str) -> str | None:
        best: tuple[int, str] | None = None
        for entry, owner in self.ownership:
            if _entry_matches(entry, path):
                rank = _entry_specificity(entry)
                if best is None or rank > best[0]:
                    best = (rank, owner)
        return best[1] if best else None

    def refusal_reason(self, path: str) -> str | None:
        parts = path.split("/")
        if parts[0].casefold() in {item.casefold() for item in ALWAYS_PROTECTED_ROOTS}:
            return "protected_path"
        if any(part.casefold() == ".git" for part in parts):
            return "protected_path"
        if any(_entry_matches(entry, path) for entry in self.protected):
            return "protected_path"
        if self.owner(path) != "instance":
            return "not_instance_owned"
        if self.narrowing and not any(_entry_matches(entry, path) for entry in self.narrowing):
            return "outside_action_writable_paths"
        return None

    def allows(self, path: str) -> bool:
        return self.refusal_reason(path) is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ownership": {entry: owner for entry, owner in self.ownership},
            "protected": sorted({*self.protected, *(f"{root}/" for root in ALWAYS_PROTECTED_ROOTS)}),
            "narrowing": list(self.narrowing),
            "limits": self.limits.to_dict(),
        }

    def describe_for_prompt(self) -> str:
        writable = [entry for entry, owner in self.ownership if owner == "instance"]
        if self.narrowing:
            writable = list(self.narrowing)
        protected = sorted({*self.protected, *(f"{root}/" for root in ALWAYS_PROTECTED_ROOTS)})
        return (
            "You may change only: " + ", ".join(("the whole working directory" if item == "./" else item) for item in writable)
            + ". Never change: " + ", ".join(protected) + "."
        )


def owner_of(ownership: Mapping[str, str], path: str) -> str | None:
    """Longest-match owner of ``path``; unsafe keys are ignored, never matched."""

    best: tuple[int, str] | None = None
    for key, owner in ownership.items():
        try:
            entry = _normalize_entry(key)
        except ValueError:
            continue
        if _entry_matches(entry, path):
            rank = _entry_specificity(entry)
            if best is None or rank > best[0]:
                best = (rank, str(owner))
    return best[1] if best else None


def _normalize_entry(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or value.startswith("/") or "\x00" in value:
        raise ValueError(f"unsafe path entry: {value!r}")
    if value in {".", "./"}:
        return "./"
    prefix = value.endswith("/")
    body = value[:-1] if prefix else value
    if any(part in {"", ".", ".."} for part in body.split("/")):
        raise ValueError(f"unsafe path entry: {value!r}")
    return body + ("/" if prefix else "")


@dataclass(frozen=True)
class ObservedChanges:
    written: dict[str, bytes]
    deleted: dict[str, bytes]
    base: dict[str, bytes]
    added_directories: tuple[str, ...]
    removed_directories: tuple[str, ...]
    ignored_git_paths: int

    @property
    def empty(self) -> bool:
        return not self.written and not self.deleted


def observe_changes(before: Any, after: Any) -> ObservedChanges:
    """Compare two governed snapshots (``files`` mapping + ``directories`` set)."""

    def is_git(path: str) -> bool:
        return _first_component(path) == ".git"

    before_files = {path: content for path, content in before.files.items()}
    after_files = {path: content for path, content in after.files.items()}
    ignored = sum(
        1 for path in set(before_files) | set(after_files)
        if is_git(path) and before_files.get(path) != after_files.get(path)
    )
    written = {
        path: content for path, content in after_files.items()
        if not is_git(path) and before_files.get(path) != content
    }
    deleted = {
        path: content for path, content in before_files.items()
        if not is_git(path) and path not in after_files
    }
    before_dirs = {item for item in before.directories if not is_git(item) and item != ".git"}
    after_dirs = {item for item in after.directories if not is_git(item) and item != ".git"}
    needed: set[str] = set()
    for path in written:
        parts = path.split("/")[:-1]
        for index in range(1, len(parts) + 1):
            needed.add("/".join(parts[:index]))
    added = sorted(item for item in after_dirs - before_dirs if item in needed)
    removed = sorted(before_dirs - after_dirs)
    return ObservedChanges(written, deleted, before_files, tuple(added), tuple(removed), ignored)


def check_policy(changes: ObservedChanges, policy: WritablePolicy) -> None:
    violations: dict[str, list[str]] = {}
    for path in sorted({*changes.written, *changes.deleted}):
        reason = policy.refusal_reason(path)
        if reason is not None:
            violations.setdefault(reason, []).append(path)
    for directory in changes.removed_directories:
        prefix = directory + "/"
        had_files = any(path.startswith(prefix) for path in changes.deleted)
        if not had_files:
            reason = policy.refusal_reason(prefix)
            if reason is not None:
                violations.setdefault(reason, []).append(prefix)
    if violations:
        code = sorted(violations)[0]
        paths = [path for items in violations.values() for path in items]
        raise FileChangeRefusal(
            code,
            "The run changed files outside this action's writable set, so no proposal was made: "
            + ", ".join(paths[:8]) + (" ..." if len(paths) > 8 else ""),
            paths,
        )
    limits = policy.limits
    count = len(changes.written) + len(changes.deleted)
    if count > limits.max_files:
        raise FileChangeRefusal(
            "change_too_large",
            f"The run changed {count} files; one proposal may change at most {limits.max_files}.",
        )
    oversized = [path for path, content in changes.written.items() if len(content) > limits.max_file_bytes]
    if oversized:
        raise FileChangeRefusal(
            "change_too_large",
            f"A changed file exceeds the {limits.max_file_bytes}-byte limit for one proposal.",
            oversized,
        )
    total = sum(len(content) for content in changes.written.values())
    if total > limits.max_total_bytes:
        raise FileChangeRefusal(
            "change_too_large",
            f"The run wrote {total} bytes; one proposal may write at most {limits.max_total_bytes}.",
        )


def _lines(content: bytes | None) -> list[str] | None:
    if content is None:
        return []
    try:
        return content.decode("utf-8").splitlines(keepends=True)
    except UnicodeDecodeError:
        return None


def build_patch(changes: ObservedChanges, max_patch_bytes: int) -> tuple[str, bool, list[dict[str, Any]]]:
    chunks: list[str] = []
    size = 0
    truncated = False
    files: list[dict[str, Any]] = []
    for path in sorted({*changes.written, *changes.deleted}):
        old_bytes = changes.base.get(path)
        new_bytes = changes.written.get(path)
        change = "deleted" if path in changes.deleted else ("added" if old_bytes is None else "modified")
        old = _lines(old_bytes)
        new = _lines(new_bytes)
        if old is None or new is None:
            piece = f"Binary file {path} {change}\n"
            additions = deletions = 0
            binary = True
        else:
            diff = list(difflib.unified_diff(
                old, new,
                "/dev/null" if old_bytes is None else f"a/{path}",
                "/dev/null" if change == "deleted" else f"b/{path}",
            ))
            additions = sum(1 for line in diff if line.startswith("+") and not line.startswith("+++"))
            deletions = sum(1 for line in diff if line.startswith("-") and not line.startswith("---"))
            piece = "".join(line if line.endswith("\n") else line + "\n\\ No newline at end of file\n" for line in diff)
            binary = False
        files.append({"path": path, "change": change, "additions": additions, "deletions": deletions, "binary": binary})
        if truncated:
            continue
        encoded = len(piece.encode("utf-8"))
        if size + encoded > max_patch_bytes:
            truncated = True
            continue
        size += encoded
        chunks.append(piece)
    return "".join(chunks), truncated, files


def blob_path(blob_root: Path, content_digest: str) -> Path:
    if not _DIGEST.fullmatch(content_digest):
        raise ValueError("blob digest is invalid")
    return blob_root / "sha256" / content_digest[7:]


def store_blob(blob_root: Path, content: bytes) -> tuple[str, str]:
    """Store bytes content-addressed; returns (contentDigest, blobRef)."""

    content_digest = _sha256(content)
    target = blob_path(blob_root, content_digest)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if target.is_symlink():
        raise ValueError("blob store entry may not be a symlink")
    if target.exists():
        if _sha256(target.read_bytes()) != content_digest:
            raise ValueError("blob store entry is corrupt")
    else:
        temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            view = memoryview(content)
            while view:
                view = view[os.write(descriptor, view):]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, target)
    return content_digest, "sha256/" + content_digest[7:]


def build_file_change_proposal(
    *,
    run_id: str,
    action_id: str,
    pre_state_digest: str,
    base_git: str | None,
    changes: ObservedChanges,
    policy: WritablePolicy,
    blob_root: Path,
    summary: str | None = None,
    evaluator: dict[str, Any] | None = None,
    producer: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Store blobs and return one proposal; the caller has already checked policy."""

    check_policy(changes, policy)
    operations: list[dict[str, Any]] = []
    for path in sorted({*changes.written, *changes.deleted}):
        if path in changes.deleted:
            operations.append({
                "operation": "delete", "path": path,
                "previousDigest": _sha256(changes.deleted[path]),
            })
            continue
        content = changes.written[path]
        content_digest, blob_ref = store_blob(blob_root, content)
        previous = changes.base.get(path)
        operations.append({
            "operation": "write", "path": path, "contentDigest": content_digest,
            "blobRef": blob_ref, "bytes": len(content),
            "previousDigest": _sha256(previous) if previous is not None else None,
        })
    patch, truncated, files = build_patch(changes, policy.limits.max_patch_bytes)
    stats = {
        "filesChanged": len(files),
        "added": sum(1 for item in files if item["change"] == "added"),
        "modified": sum(1 for item in files if item["change"] == "modified"),
        "deleted": sum(1 for item in files if item["change"] == "deleted"),
        "additions": sum(item["additions"] for item in files),
        "deletions": sum(item["deletions"] for item in files),
        "bytesWritten": sum(len(content) for content in changes.written.values()),
        "gitMetadataChangesIgnored": changes.ignored_git_paths,
    }
    identity = {
        "runId": run_id, "actionId": action_id, "preStateDigest": pre_state_digest,
        "operations": operations,
    }
    proposal: dict[str, Any] = {
        "formatVersion": FILE_CHANGE_PROPOSAL_FORMAT,
        "kind": "files",
        "proposalId": "proposal-" + _canonical_digest(identity)[7:23],
        "applicationAction": action_id,
        "runId": run_id,
        "preStateDigest": pre_state_digest,
        "baseGit": base_git,
        "operations": operations,
        "directories": {
            "added": list(changes.added_directories),
            "removed": list(changes.removed_directories),
        },
        "files": files,
        "patch": patch,
        "patchTruncated": truncated,
        "patchDigest": _sha256(patch.encode("utf-8")),
        "stats": stats,
        "writablePolicy": policy.to_dict(),
        "summary": summary,
        "evaluator": evaluator,
        "producer": producer,
    }
    return proposal


def is_file_change_proposal(value: Any) -> bool:
    return isinstance(value, Mapping) and value.get("formatVersion") == FILE_CHANGE_PROPOSAL_FORMAT


def validate_file_change_proposal(
    proposal: Mapping[str, Any], policy: WritablePolicy, blob_root: Path,
) -> tuple[str, ...]:
    """Re-check a stored proposal before approval/apply; returns its sorted paths."""

    if not is_file_change_proposal(proposal) or proposal.get("kind") != "files":
        raise FileChangeRefusal("proposal_invalid", "file-change proposal format is invalid")
    operations = proposal.get("operations")
    if not isinstance(operations, list) or not operations:
        raise FileChangeRefusal("proposal_invalid", "file-change proposal has no operations")
    paths: list[str] = []
    for item in operations:
        if not isinstance(item, Mapping) or item.get("operation") not in {"write", "delete"}:
            raise FileChangeRefusal("proposal_invalid", "file-change operation is invalid")
        path = _normalize_entry(str(item.get("path", "")))
        if path.endswith("/") or path == "./":
            raise FileChangeRefusal("proposal_invalid", "file-change operation must name a file")
        reason = policy.refusal_reason(path)
        if reason is not None:
            raise FileChangeRefusal(reason, "file-change operation is outside the writable set", [path])
        if item["operation"] == "write":
            content_digest = item.get("contentDigest")
            if not isinstance(content_digest, str) or item.get("blobRef") != "sha256/" + content_digest[7:]:
                raise FileChangeRefusal("proposal_invalid", "file-change blob reference is invalid", [path])
            target = blob_path(blob_root, content_digest)
            if target.is_symlink() or not target.is_file() or _sha256(target.read_bytes()) != content_digest:
                raise FileChangeRefusal("proposal_blob_missing", "file-change content is missing or corrupt", [path])
        paths.append(path)
    if len(set(paths)) != len(paths):
        raise FileChangeRefusal("proposal_invalid", "file-change paths must be unique")
    directories = proposal.get("directories")
    if not isinstance(directories, Mapping):
        raise FileChangeRefusal("proposal_invalid", "file-change directory changes are missing")
    for key in ("added", "removed"):
        values = directories.get(key)
        if not isinstance(values, list):
            raise FileChangeRefusal("proposal_invalid", "file-change directory changes are invalid")
        for value in values:
            directory = _normalize_entry(str(value))
            if directory.endswith("/") or _first_component(directory).casefold() in {
                item.casefold() for item in ALWAYS_PROTECTED_ROOTS
            }:
                raise FileChangeRefusal("protected_path", "file-change directory change is protected", [str(value)])
    return tuple(sorted(paths))


def expected_changed_set(proposal: Mapping[str, Any]) -> set[str]:
    """The exact `filesChanged` set the writer must produce (files plus `dir/`)."""

    directories = proposal.get("directories") or {}
    return {
        *(str(item["path"]) for item in proposal.get("operations", [])),
        *(f"{item}/" for item in directories.get("added", [])),
        *(f"{item}/" for item in directories.get("removed", [])),
    }
