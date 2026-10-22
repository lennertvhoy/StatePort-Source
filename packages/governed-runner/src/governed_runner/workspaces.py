"""Fail-closed lifecycle authority for StatePort-managed Git worktrees.

The durable store is operational state outside the repository.  Registered
worktrees created by StatePort have one typed lease from creation through
evidence export and retirement.  Manual worktrees remain possible, but they
must be explicitly classified before this manager will create another one.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urlsplit


WORKSPACE_LEASE_SCHEMA = "stateport.workspace-lease/v1"
WORKSPACE_BUDGET_SCHEMA = "stateport.workspace-budget/v1"
WORKSPACE_CLASSIFICATION_SCHEMA = "stateport.workspace-classification/v1"
WORKSPACE_CREATION_RECEIPT_SCHEMA = "stateport.workspace-creation-receipt/v1"
WORKSPACE_FAILURE_RECEIPT_SCHEMA = "stateport.workspace-failure-receipt/v1"
WORKSPACE_EVIDENCE_SCHEMA = "stateport.workspace-evidence/v1"
WORKSPACE_CLEANUP_RECEIPT_SCHEMA = "stateport.workspace-cleanup-receipt/v1"
WORKSPACE_AUDIT_SCHEMA = "stateport.workspace-audit/v1"
WORKSPACE_SLICE_CLOSURE_SCHEMA = "stateport.workspace-slice-closure/v1"
WORKSPACE_OBSERVATION_SCHEMA = "statebench.workspace-lifecycle-observation/v1"

ACTIVE_STATUS = "active"
TERMINAL_STATUSES = frozenset(
    {
        "integrated_and_removed",
        "rejected_and_removed",
        "archived_and_removed",
        "retained_exception",
    }
)
REMOVED_STATUSES = TERMINAL_STATUSES - {"retained_exception"}
REFUSAL_CODES = frozenset(
    {
        "workspace_budget_exceeded",
        "inventory_unknown",
        "unleased_workspace_present",
        "expired_lease_present",
        "prior_slice_cleanup_incomplete",
        "repository_identity_mismatch",
        "workspace_lock_busy",
        "branch_already_checked_out",
        "slice_already_closed",
        "unsafe_or_dirty_creation_base",
    }
)
EVIDENCE_CATEGORIES = (
    "testReceipts",
    "browserJourneyEvidence",
    "generatedArtifacts",
    "stateBenchTrace",
    "subagentResult",
)
WORKSPACE_METRICS = (
    "worktrees_created",
    "worktrees_removed",
    "worktrees_leaked",
    "branches_created",
    "branches_retired",
    "peak_registered_worktrees",
    "peak_active_writable_worktrees",
    "unclassified_workspace_count",
    "expired_lease_count",
    "cleanup_duration",
    "cleanup_failures",
    "owner_interventions_for_workspace_hygiene",
    "wrong_worktree_incidents",
    "closure_gate_workspace_failures",
)

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_LEASE_ID = re.compile(r"^lease_[0-9a-f]{32}$")
_OBJECT_ID = re.compile(r"^[0-9a-f]{40,64}$")
_SAFE_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$")
_MAX_JSON_BYTES = 8 * 1024 * 1024
_MAX_ARTIFACTS = 256
_MAX_ARTIFACT_BYTES = 64 * 1024 * 1024


class WorkspaceLifecycleError(RuntimeError):
    """A workspace lifecycle operation could not complete safely."""

    def __init__(self, code: str, detail: str) -> None:
        if not isinstance(code, str) or not code:
            raise ValueError("workspace lifecycle error code is required")
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}")


class WorkspaceLifecycleRefusal(WorkspaceLifecycleError):
    """A typed fail-closed admission or closure decision."""


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _utc_timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise WorkspaceLifecycleError("invalid_clock", "workspace clock must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise WorkspaceLifecycleError("malformed_lease", f"{label} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise WorkspaceLifecycleError("malformed_lease", f"{label} is invalid") from exc
    if parsed.tzinfo is None:
        raise WorkspaceLifecycleError("malformed_lease", f"{label} must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _require_id(value: object, label: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise WorkspaceLifecycleError("invalid_contract", f"{label} must be a bounded identifier")
    return value


def _require_object_id(value: object, label: str) -> str:
    if not isinstance(value, str) or _OBJECT_ID.fullmatch(value) is None:
        raise WorkspaceLifecycleError("invalid_contract", f"{label} must be a full Git object id")
    return value


def _assert_no_symlink_ancestors(path: Path, *, allow_missing: bool = True) -> Path:
    """Return an absolute lexical path after rejecting every symlink ancestor."""

    if not isinstance(path, Path):
        path = Path(path)
    if "\x00" in os.fspath(path):
        raise WorkspaceLifecycleError("unsafe_path", "workspace path contains NUL")
    absolute = Path(os.path.abspath(os.fspath(path)))
    cursor = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        cursor = cursor / part
        try:
            metadata = cursor.lstat()
        except FileNotFoundError:
            if allow_missing:
                continue
            raise WorkspaceLifecycleError("unsafe_path", f"required path is missing: {cursor}")
        if metadata and cursor.is_symlink():
            raise WorkspaceLifecycleError("unsafe_path", "workspace path may not traverse a symlink")
    return absolute


def _safe_directory(path: Path, *, create: bool = False) -> Path:
    absolute = _assert_no_symlink_ancestors(path)
    if create:
        absolute.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not absolute.is_dir() or absolute.is_symlink():
        raise WorkspaceLifecycleError("unsafe_path", f"workspace directory is unsafe: {absolute}")
    os.chmod(absolute, 0o700)
    _assert_no_symlink_ancestors(absolute, allow_missing=False)
    return absolute


def _confined_child(root: Path, path: Path, *, direct: bool = False) -> Path:
    root = _safe_directory(root, create=True)
    candidate = _assert_no_symlink_ancestors(path)
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise WorkspaceLifecycleError("unsafe_path", "workspace path escapes its configured root") from exc
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise WorkspaceLifecycleError("unsafe_path", "workspace path must be below its configured root")
    if direct and len(relative.parts) != 1:
        raise WorkspaceLifecycleError("unsafe_path", "managed worktrees must be direct children of the workspace root")
    return candidate


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_bytes(path: Path, content: bytes, *, root: Path, create_only: bool = False) -> None:
    root = _safe_directory(root, create=True)
    path = _confined_child(root, path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _safe_directory(path.parent)
    if path.exists():
        if path.is_symlink() or not path.is_file():
            raise WorkspaceLifecycleError("unsafe_state_store", "operational record target is unsafe")
        if create_only:
            raise WorkspaceLifecycleError("duplicate_record", f"operational record already exists: {path.name}")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(6)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if create_only and path.exists():
            raise WorkspaceLifecycleError("duplicate_record", f"operational record already exists: {path.name}")
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _atomic_json(path: Path, value: Mapping[str, Any], *, root: Path, create_only: bool = False) -> None:
    _atomic_bytes(
        path,
        (_canonical_json(dict(value)) + "\n").encode("utf-8"),
        root=root,
        create_only=create_only,
    )


def _read_json(path: Path, *, root: Path) -> dict[str, Any]:
    path = _confined_child(root, path)
    if path.is_symlink() or not path.is_file():
        raise WorkspaceLifecycleError("malformed_lease", f"operational record is missing or unsafe: {path.name}")
    if path.stat().st_size > _MAX_JSON_BYTES:
        raise WorkspaceLifecycleError("malformed_lease", f"operational record is oversized: {path.name}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise WorkspaceLifecycleError("malformed_lease", f"operational record is not valid JSON: {path.name}") from exc
    if not isinstance(value, dict):
        raise WorkspaceLifecycleError("malformed_lease", f"operational record must be an object: {path.name}")
    return value


def _safe_origin(value: str | None) -> str | None:
    if value is None or value == "":
        return None
    parsed = urlsplit(value)
    if parsed.username is not None or parsed.password is not None:
        raise WorkspaceLifecycleRefusal(
            "repository_identity_mismatch",
            "repository origin may not contain credentials",
        )
    if "\n" in value or "\r" in value or "\x00" in value:
        raise WorkspaceLifecycleRefusal(
            "repository_identity_mismatch",
            "repository origin contains unsupported characters",
        )
    return value


def _git_environment() -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
    }


@dataclass(frozen=True)
class WorkspaceBudget:
    max_registered_worktrees: int = 8
    max_active_writable_worktrees: int = 3
    max_unclassified_worktrees: int = 0
    max_unreconciled_branches: int = 3
    max_expired_leases: int = 0
    block_inventory_unknown: bool = True
    block_prior_cleanup_incomplete: bool = True
    workspace_directory_name: str = "_worktrees"
    default_duration_seconds: int = 14_400
    max_duration_seconds: int = 86_400

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "WorkspaceBudget":
        expected = {
            "schema",
            "maxRegisteredWorktrees",
            "maxActiveWritableWorktrees",
            "maxUnclassifiedWorktrees",
            "maxUnreconciledBranches",
            "maxExpiredLeases",
            "blockNewWorkspaceWhenInventoryUnknown",
            "blockNewWorkspaceWhenAnyPriorSliceCleanupIncomplete",
            "workspaceRoot",
            "lease",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise WorkspaceLifecycleError("invalid_budget", "workspace budget has missing or unsupported fields")
        if value.get("schema") != WORKSPACE_BUDGET_SCHEMA:
            raise WorkspaceLifecycleError("invalid_budget", "workspace budget schema is unsupported")
        workspace_root = value.get("workspaceRoot")
        lease = value.get("lease")
        if (
            not isinstance(workspace_root, Mapping)
            or set(workspace_root) != {"mode", "directoryName"}
            or workspace_root.get("mode") != "sibling_directory"
        ):
            raise WorkspaceLifecycleError("invalid_budget", "workspace root policy is invalid")
        directory_name = workspace_root.get("directoryName")
        if not isinstance(directory_name, str) or _SAFE_NAME.fullmatch(directory_name) is None:
            raise WorkspaceLifecycleError("invalid_budget", "workspace directory name is invalid")
        if not isinstance(lease, Mapping) or set(lease) != {"defaultDurationSeconds", "maxDurationSeconds"}:
            raise WorkspaceLifecycleError("invalid_budget", "workspace lease duration policy is invalid")

        names = {
            "max_registered_worktrees": "maxRegisteredWorktrees",
            "max_active_writable_worktrees": "maxActiveWritableWorktrees",
            "max_unclassified_worktrees": "maxUnclassifiedWorktrees",
            "max_unreconciled_branches": "maxUnreconciledBranches",
            "max_expired_leases": "maxExpiredLeases",
        }
        parsed: dict[str, int] = {}
        for target, source in names.items():
            number = value.get(source)
            minimum = 1 if source in {"maxRegisteredWorktrees", "maxActiveWritableWorktrees"} else 0
            if isinstance(number, bool) or not isinstance(number, int) or number < minimum or number > 64:
                raise WorkspaceLifecycleError("invalid_budget", f"{source} is invalid")
            parsed[target] = number
        for source in (
            "blockNewWorkspaceWhenInventoryUnknown",
            "blockNewWorkspaceWhenAnyPriorSliceCleanupIncomplete",
        ):
            if value.get(source) is not True:
                raise WorkspaceLifecycleError("invalid_budget", f"{source} must fail closed")
        default_duration = lease.get("defaultDurationSeconds")
        max_duration = lease.get("maxDurationSeconds")
        if any(isinstance(item, bool) or not isinstance(item, int) for item in (default_duration, max_duration)):
            raise WorkspaceLifecycleError("invalid_budget", "workspace lease durations must be integers")
        if not 60 <= default_duration <= max_duration <= 604_800:
            raise WorkspaceLifecycleError("invalid_budget", "workspace lease durations are out of bounds")
        if parsed["max_active_writable_worktrees"] > parsed["max_registered_worktrees"]:
            raise WorkspaceLifecycleError("invalid_budget", "active workspace budget exceeds registered budget")
        if parsed["max_unclassified_worktrees"] > parsed["max_registered_worktrees"]:
            raise WorkspaceLifecycleError("invalid_budget", "unclassified workspace budget exceeds registered budget")
        if parsed["max_unreconciled_branches"] > parsed["max_registered_worktrees"]:
            raise WorkspaceLifecycleError("invalid_budget", "unreconciled branch budget exceeds registered budget")
        return cls(
            **parsed,
            workspace_directory_name=directory_name,
            default_duration_seconds=default_duration,
            max_duration_seconds=max_duration,
        )

    @classmethod
    def from_file(cls, path: Path) -> "WorkspaceBudget":
        if path.is_symlink() or not path.is_file():
            raise WorkspaceLifecycleError("invalid_budget", "workspace budget file is missing or unsafe")
        try:
            import yaml

            value = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (ImportError, OSError, UnicodeError, ValueError) as exc:
            raise WorkspaceLifecycleError("invalid_budget", "workspace budget could not be loaded") from exc
        if not isinstance(value, Mapping):
            raise WorkspaceLifecycleError("invalid_budget", "workspace budget must be a mapping")
        return cls.from_mapping(value)


@dataclass(frozen=True)
class RepositoryIdentity:
    repository_key: str
    repository_root: str
    common_git_dir: str
    object_format: str
    origin: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "repositoryKey": self.repository_key,
            "repositoryRoot": self.repository_root,
            "commonGitDir": self.common_git_dir,
            "objectFormat": self.object_format,
            "origin": self.origin,
        }

    @classmethod
    def from_dict(cls, value: object) -> "RepositoryIdentity":
        expected = {"repositoryKey", "repositoryRoot", "commonGitDir", "objectFormat", "origin"}
        if not isinstance(value, Mapping) or set(value) != expected:
            raise WorkspaceLifecycleError("malformed_lease", "repository identity shape is invalid")
        key = value.get("repositoryKey")
        root = value.get("repositoryRoot")
        common = value.get("commonGitDir")
        object_format = value.get("objectFormat")
        origin = value.get("origin")
        if not isinstance(key, str) or re.fullmatch(r"[0-9a-f]{32}", key) is None:
            raise WorkspaceLifecycleError("malformed_lease", "repository key is invalid")
        if not isinstance(root, str) or not root or not isinstance(common, str) or not common:
            raise WorkspaceLifecycleError("malformed_lease", "repository paths are invalid")
        if object_format not in {"sha1", "sha256"} or (origin is not None and not isinstance(origin, str)):
            raise WorkspaceLifecycleError("malformed_lease", "repository identity values are invalid")
        result = cls(key, root, common, object_format, origin)
        seed = {
            "repositoryRoot": root,
            "commonGitDir": common,
            "objectFormat": object_format,
            "origin": origin,
        }
        if hashlib.sha256(_canonical_json(seed).encode("utf-8")).hexdigest()[:32] != key:
            raise WorkspaceLifecycleError("malformed_lease", "repository key digest is invalid")
        return result


@dataclass(frozen=True)
class WorktreeInventoryEntry:
    path: Path
    head: str
    branch: str | None
    locked: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path.as_posix(),
            "head": self.head,
            "branch": self.branch,
            "locked": self.locked,
        }


class WorkspaceLifecycleLock:
    """Non-blocking repository-wide lifecycle lock backed by ``flock``."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._descriptor: int | None = None

    def acquire(self) -> "WorkspaceLifecycleLock":
        if self._descriptor is not None:
            raise WorkspaceLifecycleError("workspace_lock_busy", "workspace lifecycle lock is already held")
        _safe_directory(self.path.parent, create=True)
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.path, flags, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(descriptor)
            raise WorkspaceLifecycleRefusal("workspace_lock_busy", "another workspace lifecycle transaction is active") from exc
        metadata = (_canonical_json({"schema": "stateport.workspace-lock/v1", "pid": os.getpid()}) + "\n").encode("utf-8")
        os.ftruncate(descriptor, 0)
        os.write(descriptor, metadata)
        os.fsync(descriptor)
        self._descriptor = descriptor
        return self

    def release(self) -> None:
        if self._descriptor is None:
            return
        descriptor = self._descriptor
        self._descriptor = None
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    def __enter__(self) -> "WorkspaceLifecycleLock":
        return self.acquire()

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        del exc_type, exc, traceback
        self.release()
        return False


class WorkspaceLifecycleManager:
    """Own the full create/evidence/retire lifecycle for one Git repository."""

    def __init__(
        self,
        repository: Path | str,
        *,
        state_root: Path | str | None = None,
        budget: WorkspaceBudget | None = None,
        budget_path: Path | str | None = None,
        clock: Callable[[], datetime] | None = None,
        process_observer: Callable[[Path], Sequence[int]] | None = None,
        fault_injector: Callable[[str], None] | None = None,
    ) -> None:
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._process_observer = process_observer or self._observe_processes
        self._fault_injector = fault_injector
        supplied = _assert_no_symlink_ancestors(Path(repository), allow_missing=False)
        if not supplied.is_dir():
            raise WorkspaceLifecycleRefusal("repository_identity_mismatch", "repository must be an existing directory")
        self.repository = supplied
        self.identity = self._observe_repository_identity()
        self.repository = Path(self.identity.repository_root)
        selected_budget = Path(budget_path) if budget_path is not None else self.repository / "config/workspace-lifecycle.v1.yaml"
        self.budget = budget or WorkspaceBudget.from_file(selected_budget)
        if state_root is None:
            xdg = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state"))
            state_root = xdg / "stateport" / "operations" / "workspaces"
        candidate_state_root = _assert_no_symlink_ancestors(Path(state_root))
        if candidate_state_root == self.repository or self.repository in candidate_state_root.parents:
            raise WorkspaceLifecycleError(
                "unsafe_state_store",
                "workspace lifecycle state must remain outside the repository checkout",
            )
        self.state_root = _safe_directory(candidate_state_root, create=True)
        self.repository_store = _safe_directory(
            self.state_root / "repositories" / self.identity.repository_key,
            create=True,
        )
        self.leases_root = _safe_directory(self.repository_store / "leases", create=True)
        self.classifications_root = _safe_directory(self.repository_store / "classifications", create=True)
        self.transactions_root = _safe_directory(self.repository_store / "transactions", create=True)
        self.receipts_root = _safe_directory(self.repository_store / "receipts", create=True)
        self.evidence_root = _safe_directory(self.repository_store / "evidence", create=True)
        self.archives_root = _safe_directory(self.repository_store / "archives", create=True)
        self.observations_path = self.repository_store / "observations.jsonl"
        self.lock_path = self.repository_store / "lifecycle.lock"
        self.workspace_root = _safe_directory(
            self.repository.parent / self.budget.workspace_directory_name,
            create=True,
        )
        if self.state_root == self.workspace_root or self.workspace_root in self.state_root.parents:
            raise WorkspaceLifecycleError(
                "unsafe_state_store",
                "workspace lifecycle state must remain outside the disposable workspace root",
            )

    def lifecycle_lock(self) -> WorkspaceLifecycleLock:
        return WorkspaceLifecycleLock(self.lock_path)

    def _now(self) -> datetime:
        value = self._clock()
        _utc_timestamp(value)
        return value.astimezone(timezone.utc)

    def _fault(self, stage: str) -> None:
        if self._fault_injector is not None:
            self._fault_injector(stage)

    def _run_git(
        self,
        args: Sequence[str],
        *,
        cwd: Path | None = None,
        check: bool = True,
        code: str = "inventory_unknown",
        timeout: float = 30.0,
        text: bool = True,
    ) -> subprocess.CompletedProcess[Any]:
        root = self.repository if cwd is None else cwd
        try:
            completed = subprocess.run(
                [
                    "git",
                    "--no-replace-objects",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    "core.fsmonitor=false",
                    "-c",
                    "core.untrackedCache=false",
                    "-C",
                    str(root),
                    *args,
                ],
                check=False,
                capture_output=True,
                text=text,
                timeout=timeout,
                shell=False,
                env=_git_environment(),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise WorkspaceLifecycleError(code, "bounded Git operation could not complete") from exc
        if check and completed.returncode != 0:
            stderr = completed.stderr if text else completed.stderr.decode("utf-8", "replace")
            raise WorkspaceLifecycleError(code, f"Git operation failed: {str(stderr).strip()[-500:]}")
        return completed

    def _git(self, args: Sequence[str], *, cwd: Path | None = None, code: str = "inventory_unknown") -> str:
        return self._run_git(args, cwd=cwd, code=code).stdout.strip()

    def _observe_repository_identity(self) -> RepositoryIdentity:
        try:
            root = Path(self._git(("rev-parse", "--path-format=absolute", "--show-toplevel"))).resolve(strict=True)
            common = Path(self._git(("rev-parse", "--path-format=absolute", "--git-common-dir"))).resolve(strict=True)
            object_format = self._git(("rev-parse", "--show-object-format"))
        except (OSError, RuntimeError, WorkspaceLifecycleError) as exc:
            raise WorkspaceLifecycleRefusal("repository_identity_mismatch", "exact Git repository identity is unavailable") from exc
        if root.is_symlink() or not root.is_dir() or common.is_symlink() or not common.is_dir():
            raise WorkspaceLifecycleRefusal("repository_identity_mismatch", "Git repository paths are unsafe")
        if object_format not in {"sha1", "sha256"}:
            raise WorkspaceLifecycleRefusal("repository_identity_mismatch", "Git object format is unsupported")
        origin_result = self._run_git(("config", "--get", "remote.origin.url"), check=False)
        if origin_result.returncode not in {0, 1}:
            raise WorkspaceLifecycleRefusal("repository_identity_mismatch", "repository origin could not be observed")
        origin = _safe_origin(origin_result.stdout.strip() if origin_result.returncode == 0 else None)
        seed = {
            "repositoryRoot": root.as_posix(),
            "commonGitDir": common.as_posix(),
            "objectFormat": object_format,
            "origin": origin,
        }
        key = hashlib.sha256(_canonical_json(seed).encode("utf-8")).hexdigest()[:32]
        return RepositoryIdentity(key, root.as_posix(), common.as_posix(), object_format, origin)

    def _require_repository_identity(self, value: object) -> RepositoryIdentity:
        identity = RepositoryIdentity.from_dict(value)
        if identity != self.identity:
            raise WorkspaceLifecycleRefusal(
                "repository_identity_mismatch",
                "persisted workspace state belongs to a different repository",
            )
        return identity

    def _inventory(self) -> tuple[WorktreeInventoryEntry, ...]:
        raw = self._git(("worktree", "list", "--porcelain", "-z"))
        records = [record for record in raw.split("\x00\x00") if record]
        entries: list[WorktreeInventoryEntry] = []
        seen_paths: set[Path] = set()
        seen_branches: set[str] = set()
        for record in records:
            fields: dict[str, str | bool] = {}
            for raw_field in record.split("\x00"):
                if not raw_field:
                    continue
                name, separator, value = raw_field.partition(" ")
                if name in fields:
                    raise WorkspaceLifecycleRefusal("inventory_unknown", "Git worktree inventory contains duplicate fields")
                fields[name] = value if separator else True
            path_value = fields.get("worktree")
            head = fields.get("HEAD")
            if not isinstance(path_value, str) or not isinstance(head, str) or _OBJECT_ID.fullmatch(head) is None:
                raise WorkspaceLifecycleRefusal("inventory_unknown", "Git worktree inventory is malformed")
            if "prunable" in fields or "bare" in fields:
                raise WorkspaceLifecycleRefusal("inventory_unknown", "Git worktree inventory contains unavailable entries")
            path = _assert_no_symlink_ancestors(Path(path_value), allow_missing=False)
            if not path.is_dir() or path in seen_paths:
                raise WorkspaceLifecycleRefusal("inventory_unknown", "Git worktree inventory path is missing or duplicated")
            branch_value = fields.get("branch")
            branch: str | None = None
            if branch_value is not None:
                if not isinstance(branch_value, str) or not branch_value.startswith("refs/heads/"):
                    raise WorkspaceLifecycleRefusal("inventory_unknown", "Git worktree branch identity is malformed")
                branch = branch_value[len("refs/heads/") :]
                if branch in seen_branches:
                    raise WorkspaceLifecycleRefusal("inventory_unknown", "a local branch is checked out more than once")
                seen_branches.add(branch)
            entries.append(WorktreeInventoryEntry(path, head, branch, "locked" in fields))
            seen_paths.add(path)
        if not entries or self.repository not in seen_paths:
            raise WorkspaceLifecycleRefusal("inventory_unknown", "repository checkout is absent from its own worktree inventory")
        return tuple(entries)

    def _worktree_state(self, path: Path) -> dict[str, Any]:
        tracked = self._git(("status", "--porcelain=v2", "--untracked-files=no"), cwd=path)
        untracked_raw = self._run_git(
            ("ls-files", "--others", "--exclude-standard", "-z"), cwd=path, text=False
        ).stdout
        ignored_raw = self._run_git(
            ("ls-files", "--others", "--ignored", "--exclude-standard", "-z"), cwd=path, text=False
        ).stdout
        untracked = tuple(item for item in untracked_raw.split(b"\0") if item)
        ignored = tuple(item for item in ignored_raw.split(b"\0") if item)
        payload = {
            "trackedDirty": bool(tracked),
            "trackedStatusDigest": _sha256_bytes(tracked.encode("utf-8")),
            "untrackedCount": len(untracked),
            "untrackedDigest": _sha256_bytes(b"\0".join(sorted(untracked))),
            "ignoredCount": len(ignored),
            "ignoredDigest": _sha256_bytes(b"\0".join(sorted(ignored))),
        }
        payload["stateDigest"] = _digest(payload)
        return payload

    def _observe_processes(self, worktree: Path) -> Sequence[int]:
        root = worktree.resolve(strict=True)
        observed: list[int] = []
        proc = Path("/proc")
        if not proc.is_dir():
            raise WorkspaceLifecycleError("process_inventory_unknown", "process observation is unavailable")
        for entry in proc.iterdir():
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            if pid == os.getpid():
                continue
            try:
                cwd = (entry / "cwd").resolve(strict=True)
            except (FileNotFoundError, PermissionError, OSError, RuntimeError):
                continue
            if cwd == root or root in cwd.parents:
                observed.append(pid)
        return tuple(sorted(set(observed)))

    def _process_observation(self, worktree: Path) -> dict[str, Any]:
        pids = tuple(self._process_observer(worktree))
        if any(isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0 for pid in pids):
            raise WorkspaceLifecycleError("process_inventory_unknown", "process observer returned invalid identifiers")
        unique = sorted(set(pids))
        return {
            "observedAt": _utc_timestamp(self._now()),
            "ownerPid": os.getpid(),
            "active": bool(unique),
            "pids": unique,
        }

    def _lease_path(self, lease_id: str) -> Path:
        if _LEASE_ID.fullmatch(lease_id) is None:
            raise WorkspaceLifecycleError("invalid_contract", "lease id is invalid")
        return self.leases_root / f"{lease_id}.json"

    def _validate_process_observation(self, value: object) -> None:
        expected = {"observedAt", "ownerPid", "active", "pids"}
        if not isinstance(value, Mapping) or set(value) != expected:
            raise WorkspaceLifecycleError("malformed_lease", "process observation is invalid")
        _parse_timestamp(value.get("observedAt"), "process observedAt")
        owner_pid = value.get("ownerPid")
        pids = value.get("pids")
        if isinstance(owner_pid, bool) or not isinstance(owner_pid, int) or owner_pid <= 0:
            raise WorkspaceLifecycleError("malformed_lease", "process owner pid is invalid")
        if not isinstance(value.get("active"), bool) or not isinstance(pids, list):
            raise WorkspaceLifecycleError("malformed_lease", "process observation fields are invalid")
        if any(isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0 for pid in pids):
            raise WorkspaceLifecycleError("malformed_lease", "process observation pids are invalid")
        if len(pids) != len(set(pids)) or value.get("active") is not bool(pids):
            raise WorkspaceLifecycleError("malformed_lease", "process observation is contradictory")

    def _validate_worktree_state(self, value: object) -> None:
        expected = {
            "trackedDirty",
            "trackedStatusDigest",
            "untrackedCount",
            "untrackedDigest",
            "ignoredCount",
            "ignoredDigest",
            "stateDigest",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise WorkspaceLifecycleError("malformed_lease", "worktree state is invalid")
        if not isinstance(value.get("trackedDirty"), bool):
            raise WorkspaceLifecycleError("malformed_lease", "worktree tracked state is invalid")
        for name in ("untrackedCount", "ignoredCount"):
            count = value.get(name)
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise WorkspaceLifecycleError("malformed_lease", "worktree state count is invalid")
        for name in ("trackedStatusDigest", "untrackedDigest", "ignoredDigest", "stateDigest"):
            digest = value.get(name)
            if not isinstance(digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
                raise WorkspaceLifecycleError("malformed_lease", "worktree state digest is invalid")
        body = {name: value[name] for name in expected if name != "stateDigest"}
        if value.get("stateDigest") != _digest(body):
            raise WorkspaceLifecycleError("malformed_lease", "worktree state digest is inconsistent")

    def _validate_branch_disposition(self, value: object, status: str) -> None:
        expected = {"status", "integrationRef", "archiveBundle", "archiveDigest"}
        if not isinstance(value, Mapping) or set(value) != expected:
            raise WorkspaceLifecycleError("malformed_lease", "branch disposition is invalid")
        disposition = value.get("status")
        allowed = {"pending", "integrated", "rejected", "archived", "retained_exception"}
        if disposition not in allowed:
            raise WorkspaceLifecycleError("malformed_lease", "branch disposition status is invalid")
        for name in ("integrationRef", "archiveBundle", "archiveDigest"):
            if value.get(name) is not None and not isinstance(value.get(name), str):
                raise WorkspaceLifecycleError("malformed_lease", "branch disposition value is invalid")
        if status == ACTIVE_STATUS and disposition != "pending":
            raise WorkspaceLifecycleError("malformed_lease", "active lease branch disposition must be pending")
        if status in REMOVED_STATUSES and disposition == "pending":
            raise WorkspaceLifecycleError("malformed_lease", "removed lease branch disposition is incomplete")
        required_by_status = {
            "integrated_and_removed": "integrated",
            "rejected_and_removed": "rejected",
            "archived_and_removed": "archived",
            "retained_exception": "retained_exception",
        }
        if status in required_by_status and disposition != required_by_status[status]:
            raise WorkspaceLifecycleError("malformed_lease", "lease status contradicts its branch disposition")
        if disposition == "integrated" and not value.get("integrationRef"):
            raise WorkspaceLifecycleError("malformed_lease", "integrated branch lacks its integration ref")
        if disposition != "integrated" and value.get("integrationRef") is not None:
            raise WorkspaceLifecycleError("malformed_lease", "non-integrated branch carries an integration ref")
        if disposition == "archived":
            archive = value.get("archiveBundle")
            digest = value.get("archiveDigest")
            if not archive or not isinstance(digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
                raise WorkspaceLifecycleError("malformed_lease", "archived branch lacks verified archive evidence")
            _confined_child(self.archives_root, Path(archive), direct=True)
        elif value.get("archiveBundle") is not None or value.get("archiveDigest") is not None:
            raise WorkspaceLifecycleError("malformed_lease", "non-archived branch carries archive state")

    def _validate_closure_state(self, value: object, status: str) -> None:
        if status == ACTIVE_STATUS:
            if value is not None:
                raise WorkspaceLifecycleError("malformed_lease", "active workspace has closure state")
            return
        expected = {
            "requestedDisposition",
            "trackedState",
            "processObservation",
            "classifications",
            "closedAt",
            "worktreeRemoved",
            "branchRetired",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise WorkspaceLifecycleError("malformed_lease", "terminal workspace closure state is invalid")
        if value.get("requestedDisposition") not in {"integrated", "rejected", "archived", "retained_exception"}:
            raise WorkspaceLifecycleError("malformed_lease", "workspace closure disposition is invalid")
        tracked = value.get("trackedState")
        if tracked is not None:
            self._validate_worktree_state(tracked)
        self._validate_process_observation(value.get("processObservation"))
        classifications = value.get("classifications")
        if not isinstance(classifications, list) or any(not isinstance(item, str) or not item for item in classifications):
            raise WorkspaceLifecycleError("malformed_lease", "workspace closure classifications are invalid")
        _parse_timestamp(value.get("closedAt"), "closure closedAt")
        if not isinstance(value.get("worktreeRemoved"), bool) or not isinstance(value.get("branchRetired"), bool):
            raise WorkspaceLifecycleError("malformed_lease", "workspace closure flags are invalid")
        removed = status in REMOVED_STATUSES
        if value.get("worktreeRemoved") is not removed or value.get("branchRetired") is not removed:
            raise WorkspaceLifecycleError("malformed_lease", "workspace closure flags contradict terminal status")

    def _validate_lease(self, value: Mapping[str, Any], *, filename: str | None = None) -> dict[str, Any]:
        expected = {
            "schema",
            "leaseId",
            "sliceId",
            "ownerAgentId",
            "repositoryIdentity",
            "worktreePath",
            "branch",
            "baseHead",
            "createdHead",
            "currentHead",
            "createdAt",
            "expiresAt",
            "status",
            "purpose",
            "temporary",
            "cleanupRequired",
            "processObservation",
            "closureState",
            "branchDisposition",
            "evidenceExportLocation",
            "creationReceipt",
            "cleanupReceipt",
            "retainedException",
        }
        if set(value) != expected or value.get("schema") != WORKSPACE_LEASE_SCHEMA:
            raise WorkspaceLifecycleError("malformed_lease", "workspace lease has missing or unsupported fields")
        lease_id = value.get("leaseId")
        if not isinstance(lease_id, str) or _LEASE_ID.fullmatch(lease_id) is None:
            raise WorkspaceLifecycleError("malformed_lease", "workspace lease id is invalid")
        if filename is not None and filename != f"{lease_id}.json":
            raise WorkspaceLifecycleError("malformed_lease", "workspace lease filename does not match its id")
        _require_id(value.get("sliceId"), "slice id")
        _require_id(value.get("ownerAgentId"), "owner agent id")
        self._require_repository_identity(value.get("repositoryIdentity"))
        worktree_path = value.get("worktreePath")
        branch = value.get("branch")
        if not isinstance(worktree_path, str) or not worktree_path or not isinstance(branch, str) or not branch:
            raise WorkspaceLifecycleError("malformed_lease", "workspace lease path or branch is invalid")
        _confined_child(self.workspace_root, Path(worktree_path), direct=True)
        for name in ("baseHead", "createdHead", "currentHead"):
            _require_object_id(value.get(name), name)
        created = _parse_timestamp(value.get("createdAt"), "createdAt")
        expires = _parse_timestamp(value.get("expiresAt"), "expiresAt")
        if expires <= created:
            raise WorkspaceLifecycleError("malformed_lease", "workspace lease expiry must follow creation")
        status = value.get("status")
        if status not in {ACTIVE_STATUS, *TERMINAL_STATUSES}:
            raise WorkspaceLifecycleError("malformed_lease", "workspace lease status is invalid")
        if not isinstance(value.get("purpose"), str) or not 1 <= len(value["purpose"]) <= 1024:
            raise WorkspaceLifecycleError("malformed_lease", "workspace lease purpose is invalid")
        if value.get("temporary") is not True or not isinstance(value.get("cleanupRequired"), bool):
            raise WorkspaceLifecycleError("malformed_lease", "workspace lease lifecycle flags are invalid")
        if status in REMOVED_STATUSES and value.get("cleanupRequired") is not False:
            raise WorkspaceLifecycleError("malformed_lease", "removed workspace cannot require cleanup")
        if status in {ACTIVE_STATUS, "retained_exception"} and value.get("cleanupRequired") is not True:
            raise WorkspaceLifecycleError("malformed_lease", "active or retained workspace must require cleanup")
        self._validate_process_observation(value.get("processObservation"))
        self._validate_branch_disposition(value.get("branchDisposition"), status)
        for name in ("evidenceExportLocation", "creationReceipt", "cleanupReceipt"):
            item = value.get(name)
            if item is not None and not isinstance(item, str):
                raise WorkspaceLifecycleError("malformed_lease", f"{name} is invalid")
        if status == ACTIVE_STATUS and (value.get("closureState") is not None or value.get("cleanupReceipt") is not None or value.get("retainedException") is not None):
            raise WorkspaceLifecycleError("malformed_lease", "active workspace lease contains terminal state")
        if status in TERMINAL_STATUSES and (not isinstance(value.get("closureState"), Mapping) or value.get("cleanupReceipt") is None):
            raise WorkspaceLifecycleError("malformed_lease", "terminal workspace lease lacks closure state")
        self._validate_closure_state(value.get("closureState"), status)
        path_roots = {
            "evidenceExportLocation": self.evidence_root,
            "creationReceipt": self.receipts_root,
            "cleanupReceipt": self.receipts_root,
        }
        for name, root in path_roots.items():
            item = value.get(name)
            if item is not None:
                _confined_child(root, Path(item))
        retained = value.get("retainedException")
        if status == "retained_exception":
            expected_retained = {"reason", "classifications", "expiresAt"}
            if not isinstance(retained, Mapping) or set(retained) != expected_retained:
                raise WorkspaceLifecycleError("malformed_lease", "retained exception is invalid")
            if not isinstance(retained.get("reason"), str) or not retained.get("reason"):
                raise WorkspaceLifecycleError("malformed_lease", "retained exception reason is required")
            if not isinstance(retained.get("classifications"), list) or not retained.get("classifications"):
                raise WorkspaceLifecycleError("malformed_lease", "retained exception classifications are required")
            _parse_timestamp(retained.get("expiresAt"), "retained exception expiresAt")
        elif retained is not None:
            raise WorkspaceLifecycleError("malformed_lease", "non-retained lease carries an exception")
        return dict(value)

    def _load_leases(self) -> dict[str, dict[str, Any]]:
        leases: dict[str, dict[str, Any]] = {}
        for path in sorted(self.leases_root.iterdir()):
            if path.name == ".keep":
                continue
            if path.is_symlink() or not path.is_file() or path.suffix != ".json":
                raise WorkspaceLifecycleError("malformed_lease", "workspace lease directory contains an unsupported entry")
            value = self._validate_lease(_read_json(path, root=self.repository_store), filename=path.name)
            lease_id = value["leaseId"]
            if lease_id in leases:
                raise WorkspaceLifecycleError("malformed_lease", "duplicate workspace lease id")
            leases[lease_id] = value
        return leases

    def _classification_path(self, worktree: Path) -> Path:
        name = hashlib.sha256(worktree.as_posix().encode("utf-8")).hexdigest()
        return self.classifications_root / f"{name}.json"

    def _validate_classification(self, value: Mapping[str, Any]) -> dict[str, Any]:
        expected = {
            "schema",
            "repositoryIdentity",
            "worktreePath",
            "branch",
            "head",
            "headPolicy",
            "stateDigest",
            "classification",
            "reason",
            "recordedAt",
            "expiresAt",
        }
        if set(value) != expected or value.get("schema") != WORKSPACE_CLASSIFICATION_SCHEMA:
            raise WorkspaceLifecycleError("inventory_unknown", "workspace classification is malformed")
        self._require_repository_identity(value.get("repositoryIdentity"))
        path_value = value.get("worktreePath")
        if not isinstance(path_value, str) or not path_value:
            raise WorkspaceLifecycleError("inventory_unknown", "workspace classification path is invalid")
        path = _assert_no_symlink_ancestors(Path(path_value), allow_missing=True)
        if self._classification_path(path).name != hashlib.sha256(path.as_posix().encode("utf-8")).hexdigest() + ".json":
            raise WorkspaceLifecycleError("inventory_unknown", "workspace classification path digest is invalid")
        branch = value.get("branch")
        if branch is not None and not isinstance(branch, str):
            raise WorkspaceLifecycleError("inventory_unknown", "workspace classification branch is invalid")
        _require_object_id(value.get("head"), "classification head")
        if value.get("headPolicy") not in {"exact", "branch_tip"}:
            raise WorkspaceLifecycleError("inventory_unknown", "workspace classification head policy is invalid")
        state_digest = value.get("stateDigest")
        if not isinstance(state_digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", state_digest) is None:
            raise WorkspaceLifecycleError("inventory_unknown", "workspace classification state digest is invalid")
        if value.get("classification") not in {"primary_creation_base", "external_retained", "historical_retained"}:
            raise WorkspaceLifecycleError("inventory_unknown", "workspace classification kind is invalid")
        if not isinstance(value.get("reason"), str) or not value.get("reason"):
            raise WorkspaceLifecycleError("inventory_unknown", "workspace classification reason is required")
        _parse_timestamp(value.get("recordedAt"), "classification recordedAt")
        expires = value.get("expiresAt")
        if expires is not None:
            _parse_timestamp(expires, "classification expiresAt")
        return dict(value)

    def _load_classifications(self) -> dict[Path, dict[str, Any]]:
        result: dict[Path, dict[str, Any]] = {}
        for path in sorted(self.classifications_root.iterdir()):
            if path.name == ".keep":
                continue
            if path.is_symlink() or not path.is_file() or path.suffix != ".json":
                raise WorkspaceLifecycleError("inventory_unknown", "classification store contains an unsupported entry")
            value = self._validate_classification(_read_json(path, root=self.repository_store))
            worktree = _assert_no_symlink_ancestors(Path(value["worktreePath"]), allow_missing=True)
            if path != self._classification_path(worktree) or worktree in result:
                raise WorkspaceLifecycleError("inventory_unknown", "workspace classification identity is ambiguous")
            result[worktree] = value
        return result

    def _incomplete_transactions(self) -> list[str]:
        incomplete: list[str] = []
        for path in sorted(self.transactions_root.iterdir()):
            if path.name == ".keep":
                continue
            if path.is_symlink() or not path.is_file() or path.suffix != ".json":
                raise WorkspaceLifecycleError("inventory_unknown", "transaction store contains an unsupported entry")
            value = _read_json(path, root=self.repository_store)
            transaction_id = value.get("transactionId")
            status = value.get("status")
            identity = value.get("repositoryIdentity")
            if (
                not isinstance(transaction_id, str)
                or path.name != f"{transaction_id}.json"
                or status not in {
                    "pending",
                    "committed",
                    "failed_rolled_back",
                    "failed_residue_preserved",
                    "failed_active_lease_preserved",
                }
            ):
                raise WorkspaceLifecycleError("inventory_unknown", "workspace transaction is malformed")
            self._require_repository_identity(identity)
            if status in {"pending", "failed_residue_preserved"}:
                incomplete.append(transaction_id)
        return incomplete

    def classify_workspace(
        self,
        worktree: Path | str,
        *,
        classification: str,
        reason: str,
        head_policy: str = "exact",
        expires_at: datetime | None = None,
    ) -> dict[str, Any]:
        """Bind known external residue to an exact observed checkout state."""

        if classification not in {"primary_creation_base", "external_retained", "historical_retained"}:
            raise WorkspaceLifecycleError("invalid_contract", "unsupported workspace classification")
        if not isinstance(reason, str) or not reason.strip():
            raise WorkspaceLifecycleError("invalid_contract", "workspace classification reason is required")
        if head_policy not in {"exact", "branch_tip"}:
            raise WorkspaceLifecycleError("invalid_contract", "workspace classification head policy is invalid")
        requested = _assert_no_symlink_ancestors(Path(worktree), allow_missing=False)
        with self.lifecycle_lock():
            inventory = self._inventory()
            matches = [entry for entry in inventory if entry.path == requested]
            if len(matches) != 1:
                raise WorkspaceLifecycleRefusal("inventory_unknown", "classified workspace is not registered exactly once")
            entry = matches[0]
            if classification == "primary_creation_base" and entry.path != self.repository:
                raise WorkspaceLifecycleError("invalid_contract", "only the primary checkout can be a creation base")
            if head_policy == "branch_tip" and entry.branch is None:
                raise WorkspaceLifecycleError("invalid_contract", "branch-tip policy requires an attached branch")
            state = self._worktree_state(entry.path)
            record = {
                "schema": WORKSPACE_CLASSIFICATION_SCHEMA,
                "repositoryIdentity": self.identity.to_dict(),
                "worktreePath": entry.path.as_posix(),
                "branch": entry.branch,
                "head": entry.head,
                "headPolicy": head_policy,
                "stateDigest": state["stateDigest"],
                "classification": classification,
                "reason": reason.strip(),
                "recordedAt": _utc_timestamp(self._now()),
                "expiresAt": _utc_timestamp(expires_at) if expires_at is not None else None,
            }
            self._validate_classification(record)
            _atomic_json(self._classification_path(entry.path), record, root=self.repository_store)
            return record

    def _classification_matches(
        self,
        entry: WorktreeInventoryEntry,
        classification: Mapping[str, Any],
        *,
        now: datetime,
    ) -> bool:
        expires = classification.get("expiresAt")
        if expires is not None and _parse_timestamp(expires, "classification expiresAt") <= now:
            return False
        if classification.get("branch") != entry.branch:
            return False
        if classification.get("headPolicy") == "exact":
            if classification.get("head") != entry.head:
                return False
        else:
            if entry.branch is None:
                return False
            tip = self._git(("rev-parse", "--verify", f"refs/heads/{entry.branch}^{{commit}}"))
            if tip != entry.head:
                return False
        return classification.get("stateDigest") == self._worktree_state(entry.path)["stateDigest"]

    def _validate_observation_chain(self) -> tuple[str | None, int]:
        if not self.observations_path.exists():
            return None, 0
        if self.observations_path.is_symlink() or not self.observations_path.is_file():
            raise WorkspaceLifecycleError("inventory_unknown", "workspace observation store is unsafe")
        previous: str | None = None
        count = 0
        try:
            with self.observations_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    count += 1
                    value = json.loads(line)
                    if not isinstance(value, dict):
                        raise ValueError("observation is not an object")
                    digest = value.pop("digest", None)
                    if value.get("schema") != WORKSPACE_OBSERVATION_SCHEMA or value.get("previousDigest") != previous:
                        raise ValueError("observation chain mismatch")
                    if not isinstance(value.get("metrics"), dict) or set(value["metrics"]) != set(WORKSPACE_METRICS):
                        raise ValueError("observation metric vector mismatch")
                    if any(
                        isinstance(item, bool) or not isinstance(item, (int, float)) or item < 0
                        for item in value["metrics"].values()
                    ):
                        raise ValueError("observation metric value is invalid")
                    expected = _digest(value)
                    if digest != expected:
                        raise ValueError("observation digest mismatch")
                    previous = digest
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            raise WorkspaceLifecycleError("inventory_unknown", "workspace observation chain is malformed") from exc
        return previous, count

    def _record_observation(self, *, event: str, metrics: Mapping[str, int | float], detail: Mapping[str, Any]) -> dict[str, Any]:
        if set(metrics) - set(WORKSPACE_METRICS):
            raise WorkspaceLifecycleError("invalid_contract", "workspace observation contains unknown metrics")
        previous, sequence = self._validate_observation_chain()
        complete: dict[str, int | float] = {name: 0 for name in WORKSPACE_METRICS}
        complete.update(metrics)
        if any(isinstance(item, bool) or not isinstance(item, (int, float)) or item < 0 for item in complete.values()):
            raise WorkspaceLifecycleError("invalid_contract", "workspace observation metric values are invalid")
        body = {
            "schema": WORKSPACE_OBSERVATION_SCHEMA,
            "sequence": sequence + 1,
            "observedAt": _utc_timestamp(self._now()),
            "repositoryIdentity": self.identity.to_dict(),
            "event": event,
            "metrics": complete,
            "detail": dict(detail),
            "previousDigest": previous,
        }
        record = {**body, "digest": _digest(body)}
        line = (_canonical_json(record) + "\n").encode("utf-8")
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.observations_path, flags, 0o600)
        try:
            remaining = memoryview(line)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise WorkspaceLifecycleError("observation_write_failed", "workspace observation write made no progress")
                remaining = remaining[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _fsync_directory(self.repository_store)
        return record

    def _audit_unlocked(self, *, slice_id: str | None = None) -> dict[str, Any]:
        inventory = self._inventory()
        leases = self._load_leases()
        classifications = self._load_classifications()
        incomplete_transactions = self._incomplete_transactions()
        for lease in leases.values():
            self._load_creation_receipt(lease)
            if lease["evidenceExportLocation"] is not None:
                self._load_evidence_manifest(lease)
            if lease["status"] in TERMINAL_STATUSES:
                self._load_cleanup_receipt(lease)
        now = self._now()
        by_path: dict[Path, dict[str, Any]] = {}
        duplicate_paths: list[str] = []
        for lease in leases.values():
            if lease["status"] not in {ACTIVE_STATUS, "retained_exception"}:
                continue
            path = _assert_no_symlink_ancestors(Path(lease["worktreePath"]), allow_missing=True)
            if path in by_path:
                duplicate_paths.append(path.as_posix())
            by_path[path] = lease
        unknown: list[str] = []
        leaked: list[str] = []
        valid_classified: list[str] = []
        inventory_paths = {entry.path for entry in inventory}
        for entry in inventory:
            lease = by_path.get(entry.path)
            if lease is not None:
                if lease["branch"] != entry.branch:
                    unknown.append(entry.path.as_posix())
                continue
            terminal_for_path = [
                lease for lease in leases.values()
                if lease["status"] in REMOVED_STATUSES and lease["worktreePath"] == entry.path.as_posix()
            ]
            if terminal_for_path:
                leaked.append(entry.path.as_posix())
                continue
            classification = classifications.get(entry.path)
            if classification is not None and self._classification_matches(entry, classification, now=now):
                valid_classified.append(entry.path.as_posix())
                continue
            if entry.path == self.repository:
                state = self._worktree_state(entry.path)
                if not state["trackedDirty"] and not state["untrackedCount"] and not state["ignoredCount"]:
                    valid_classified.append(entry.path.as_posix())
                    continue
            unknown.append(entry.path.as_posix())
        missing_active = sorted(
            lease["worktreePath"] for lease in leases.values()
            if lease["status"] in {ACTIVE_STATUS, "retained_exception"}
            and Path(lease["worktreePath"]) not in inventory_paths
        )
        expired = sorted(
            lease["leaseId"] for lease in leases.values()
            if lease["status"] == ACTIVE_STATUS and _parse_timestamp(lease["expiresAt"], "expiresAt") <= now
        )
        retained_expired = sorted(
            lease["leaseId"] for lease in leases.values()
            if lease["status"] == "retained_exception"
            and _parse_timestamp(lease["retainedException"]["expiresAt"], "retained exception expiresAt") <= now
        )
        active = sorted(lease["leaseId"] for lease in leases.values() if lease["status"] == ACTIVE_STATUS)
        retained = sorted(lease["leaseId"] for lease in leases.values() if lease["status"] == "retained_exception")
        prior = sorted(
            lease["leaseId"] for lease in leases.values()
            if lease["status"] in {ACTIVE_STATUS, "retained_exception"}
            and (slice_id is None or lease["sliceId"] != slice_id)
        )
        violations: list[dict[str, Any]] = []
        def add(code: str, items: Sequence[str]) -> None:
            if items:
                violations.append({"code": code, "items": list(items)})
        add("inventory_unknown", duplicate_paths + missing_active + incomplete_transactions)
        add("unleased_workspace_present", unknown)
        add("workspace_leaked", leaked)
        add("expired_lease_present", expired + retained_expired)
        add("prior_slice_cleanup_incomplete", retained if slice_id is None else prior)
        result = {
            "schema": WORKSPACE_AUDIT_SCHEMA,
            "observedAt": _utc_timestamp(now),
            "repositoryIdentity": self.identity.to_dict(),
            "sliceId": slice_id,
            "ok": not violations,
            "counts": {
                "registeredWorktrees": len(inventory),
                "activeWritableWorktrees": len(active),
                "unclassifiedWorktrees": len(unknown),
                "unreconciledBranches": len(active) + len(retained),
                "expiredLeases": len(expired) + len(retained_expired),
                "leakedWorktrees": len(leaked),
            },
            "activeLeases": active,
            "retainedExceptions": retained,
            "classifiedWorktrees": sorted(valid_classified),
            "violations": violations,
            "inventory": [entry.to_dict() for entry in inventory],
        }
        return result

    def audit(self, *, slice_id: str | None = None, record: bool = False) -> dict[str, Any]:
        if slice_id is not None:
            _require_id(slice_id, "slice id")
        with self.lifecycle_lock():
            result = self._audit_unlocked(slice_id=slice_id)
            if record:
                counts = result["counts"]
                self._record_observation(
                    event="workspace_inventory_audited",
                    metrics={
                        "peak_registered_worktrees": counts["registeredWorktrees"],
                        "peak_active_writable_worktrees": counts["activeWritableWorktrees"],
                        "unclassified_workspace_count": counts["unclassifiedWorktrees"],
                        "expired_lease_count": counts["expiredLeases"],
                        "worktrees_leaked": counts["leakedWorktrees"],
                    },
                    detail={"ok": result["ok"], "sliceId": slice_id},
                )
            return result

    def _admit_creation(self, *, slice_id: str, branch: str, base_ref: str) -> tuple[dict[str, Any], str]:
        if self._load_slice_closure_receipt(slice_id) is not None:
            raise WorkspaceLifecycleRefusal(
                "slice_already_closed",
                "a closed slice identifier cannot authorize another managed workspace",
            )
        audit = self._audit_unlocked(slice_id=slice_id)
        root_entry = next(entry for entry in self._inventory() if entry.path == self.repository)
        root_state = self._worktree_state(self.repository)
        if root_state["trackedDirty"]:
            raise WorkspaceLifecycleRefusal("unsafe_or_dirty_creation_base", "creation base has tracked changes")
        if root_state["untrackedCount"] or root_state["ignoredCount"]:
            classification = self._load_classifications().get(self.repository)
            if (
                classification is None
                or classification.get("classification") != "primary_creation_base"
                or not self._classification_matches(root_entry, classification, now=self._now())
            ):
                raise WorkspaceLifecycleRefusal("unsafe_or_dirty_creation_base", "creation base residue is not exactly classified")
        expired = audit["counts"]["expiredLeases"]
        if expired > self.budget.max_expired_leases:
            raise WorkspaceLifecycleRefusal("expired_lease_present", "workspace lease inventory contains expired state")
        prior = next((item for item in audit["violations"] if item["code"] == "prior_slice_cleanup_incomplete"), None)
        if prior is not None and self.budget.block_prior_cleanup_incomplete:
            raise WorkspaceLifecycleRefusal("prior_slice_cleanup_incomplete", "a prior slice has incomplete cleanup")
        unknown = audit["counts"]["unclassifiedWorktrees"]
        if unknown > self.budget.max_unclassified_worktrees:
            raise WorkspaceLifecycleRefusal("unleased_workspace_present", "registered inventory contains an unleased workspace")
        if any(item["code"] in {"inventory_unknown", "workspace_leaked"} for item in audit["violations"]):
            raise WorkspaceLifecycleRefusal("inventory_unknown", "workspace inventory cannot be proven complete")
        if audit["counts"]["registeredWorktrees"] + 1 > self.budget.max_registered_worktrees:
            raise WorkspaceLifecycleRefusal("workspace_budget_exceeded", "registered-worktree budget would be exceeded")
        if audit["counts"]["activeWritableWorktrees"] + 1 > self.budget.max_active_writable_worktrees:
            raise WorkspaceLifecycleRefusal("workspace_budget_exceeded", "active-writable-worktree budget would be exceeded")
        if audit["counts"]["unreconciledBranches"] + 1 > self.budget.max_unreconciled_branches:
            raise WorkspaceLifecycleRefusal("workspace_budget_exceeded", "unreconciled-branch budget would be exceeded")
        inventory_branches = {entry.branch for entry in self._inventory() if entry.branch is not None}
        if branch in inventory_branches:
            raise WorkspaceLifecycleRefusal("branch_already_checked_out", "requested branch is already checked out")
        branch_check = self._run_git(("check-ref-format", "--branch", branch), check=False)
        if branch_check.returncode != 0:
            raise WorkspaceLifecycleError("invalid_contract", "requested branch name is invalid")
        existing = self._run_git(("show-ref", "--verify", "--quiet", f"refs/heads/{branch}"), check=False)
        if existing.returncode == 0:
            raise WorkspaceLifecycleRefusal("branch_already_checked_out", "requested branch already exists")
        if existing.returncode not in {0, 1}:
            raise WorkspaceLifecycleRefusal("inventory_unknown", "requested branch availability is unknown")
        try:
            base_head = self._git(("rev-parse", "--verify", f"{base_ref}^{{commit}}"))
        except WorkspaceLifecycleError as exc:
            raise WorkspaceLifecycleRefusal("unsafe_or_dirty_creation_base", "creation base is not an exact commit") from exc
        _require_object_id(base_head, "base head")
        return audit, base_head

    def _transaction_path(self, transaction_id: str) -> Path:
        _require_id(transaction_id, "transaction id")
        return self.transactions_root / f"{transaction_id}.json"

    def _receipt_path(self, name: str) -> Path:
        if _SAFE_NAME.fullmatch(name) is None:
            raise WorkspaceLifecycleError("invalid_contract", "receipt name is invalid")
        return self.receipts_root / f"{name}.json"

    def _load_slice_closure_receipt(self, slice_id: str) -> dict[str, Any] | None:
        """Load one successful immutable slice closure or fail on malformed state."""

        _require_id(slice_id, "slice id")
        path = self._receipt_path(f"slice-closure-{slice_id}")
        if not path.exists():
            return None
        value = _read_json(path, root=self.repository_store)
        expected = {
            "schema",
            "sliceId",
            "checkedAt",
            "repositoryIdentity",
            "ok",
            "blockers",
            "audit",
        }
        audit = value.get("audit")
        if (
            set(value) != expected
            or value.get("schema") != WORKSPACE_SLICE_CLOSURE_SCHEMA
            or value.get("sliceId") != slice_id
            or value.get("ok") is not True
            or value.get("blockers") != []
            or not isinstance(audit, Mapping)
            or audit.get("schema") != WORKSPACE_AUDIT_SCHEMA
            or audit.get("sliceId") != slice_id
            or audit.get("ok") is not True
        ):
            raise WorkspaceLifecycleError(
                "receipt_integrity_failed",
                "slice closure receipt is malformed or does not prove successful closure",
            )
        _parse_timestamp(value.get("checkedAt"), "slice closure checkedAt")
        self._require_repository_identity(value.get("repositoryIdentity"))
        return dict(value)

    def _write_transaction(self, value: Mapping[str, Any], *, create_only: bool = False) -> Path:
        path = self._transaction_path(str(value["transactionId"]))
        _atomic_json(path, value, root=self.repository_store, create_only=create_only)
        return path

    def _verified_created_checkout(self, path: Path, *, branch: str, head: str) -> None:
        top = Path(self._git(("rev-parse", "--path-format=absolute", "--show-toplevel"), cwd=path)).resolve(strict=True)
        common = Path(self._git(("rev-parse", "--path-format=absolute", "--git-common-dir"), cwd=path)).resolve(strict=True)
        observed_branch = self._git(("branch", "--show-current"), cwd=path)
        observed_head = self._git(("rev-parse", "HEAD"), cwd=path)
        if top != path or common.as_posix() != self.identity.common_git_dir or observed_branch != branch or observed_head != head:
            raise WorkspaceLifecycleRefusal("repository_identity_mismatch", "created checkout identity did not match its transaction")

    def _rollback_creation(self, *, path: Path, branch: str, head: str) -> tuple[bool, list[str]]:
        residue: list[str] = []
        inventory = self._inventory()
        entry = next((item for item in inventory if item.path == path), None)
        if entry is not None:
            try:
                state = self._worktree_state(path)
                processes = self._process_observation(path)
                if entry.branch != branch or entry.head != head:
                    residue.append("identity_disagreement")
                if state["trackedDirty"]:
                    residue.append("dirty_tracked_files")
                if state["untrackedCount"]:
                    residue.append("untracked_content")
                if state["ignoredCount"]:
                    residue.append("ignored_content")
                if processes["active"]:
                    residue.append("active_processes")
            except WorkspaceLifecycleError:
                residue.append("inventory_uncertain")
            if not residue:
                removed = self._run_git(("worktree", "remove", path.as_posix()), check=False)
                if removed.returncode != 0:
                    residue.append("worktree_removal_failed")
        elif path.exists():
            residue.append("unregistered_path_present")
        branch_result = self._run_git(("show-ref", "--verify", "--quiet", f"refs/heads/{branch}"), check=False)
        if not residue and branch_result.returncode == 0:
            tip = self._git(("rev-parse", f"refs/heads/{branch}"))
            if tip != head:
                residue.append("branch_ref_disagreement")
            else:
                deleted = self._run_git(("branch", "-D", "--", branch), check=False)
                if deleted.returncode != 0:
                    residue.append("branch_removal_failed")
        elif branch_result.returncode not in {0, 1}:
            residue.append("branch_inventory_unknown")
        return not residue, sorted(set(residue))

    def create_workspace(
        self,
        *,
        slice_id: str,
        owner_agent_id: str,
        branch: str,
        workspace_name: str,
        purpose: str,
        base_ref: str = "HEAD",
        duration_seconds: int | None = None,
    ) -> dict[str, Any]:
        """Create one branch/worktree and persist its active typed lease."""

        _require_id(slice_id, "slice id")
        _require_id(owner_agent_id, "owner agent id")
        if _SAFE_NAME.fullmatch(workspace_name) is None:
            raise WorkspaceLifecycleError("invalid_contract", "workspace name must be one safe path component")
        if not isinstance(purpose, str) or not purpose.strip() or len(purpose) > 1024:
            raise WorkspaceLifecycleError("invalid_contract", "workspace purpose is required and bounded")
        duration = self.budget.default_duration_seconds if duration_seconds is None else duration_seconds
        if isinstance(duration, bool) or not isinstance(duration, int) or not 60 <= duration <= self.budget.max_duration_seconds:
            raise WorkspaceLifecycleError("invalid_contract", "workspace lease duration is out of bounds")
        target = _confined_child(self.workspace_root, self.workspace_root / workspace_name, direct=True)
        if target.exists():
            raise WorkspaceLifecycleRefusal("unsafe_or_dirty_creation_base", "workspace target already exists")
        lease_id = f"lease_{secrets.token_hex(16)}"
        transaction_id = f"create_{lease_id}"
        transaction: dict[str, Any] | None = None
        branch_created = False
        lease_persisted = False
        base_head = ""
        try:
            with self.lifecycle_lock():
                audit, base_head = self._admit_creation(slice_id=slice_id, branch=branch, base_ref=base_ref)
                started = self._now()
                transaction = {
                    "schema": "stateport.workspace-creation-transaction/v1",
                    "transactionId": transaction_id,
                    "leaseId": lease_id,
                    "sliceId": slice_id,
                    "repositoryIdentity": self.identity.to_dict(),
                    "worktreePath": target.as_posix(),
                    "branch": branch,
                    "baseHead": base_head,
                    "startedAt": _utc_timestamp(started),
                    "status": "pending",
                    "residue": [],
                    "failureCode": None,
                }
                self._write_transaction(transaction, create_only=True)
                self._fault("before_worktree_add")
                created = self._run_git(
                    ("worktree", "add", "--no-track", "-b", branch, target.as_posix(), base_head),
                    check=False,
                )
                if created.returncode != 0:
                    detail = created.stderr.strip()[-500:]
                    raise WorkspaceLifecycleError("workspace_creation_failed", f"Git worktree creation failed: {detail}")
                branch_created = True
                self._fault("after_worktree_add")
                self._verified_created_checkout(target, branch=branch, head=base_head)
                process = self._process_observation(target)
                created_at = self._now()
                receipt_path = self._receipt_path(f"creation-{lease_id}")
                receipt = {
                    "schema": WORKSPACE_CREATION_RECEIPT_SCHEMA,
                    "leaseId": lease_id,
                    "sliceId": slice_id,
                    "repositoryIdentity": self.identity.to_dict(),
                    "worktreePath": target.as_posix(),
                    "branch": branch,
                    "baseHead": base_head,
                    "createdHead": base_head,
                    "createdAt": _utc_timestamp(created_at),
                    "inventoryBefore": audit["counts"],
                    "receiptDigest": None,
                }
                receipt["receiptDigest"] = _digest({key: value for key, value in receipt.items() if key != "receiptDigest"})
                _atomic_json(receipt_path, receipt, root=self.repository_store, create_only=True)
                lease = {
                    "schema": WORKSPACE_LEASE_SCHEMA,
                    "leaseId": lease_id,
                    "sliceId": slice_id,
                    "ownerAgentId": owner_agent_id,
                    "repositoryIdentity": self.identity.to_dict(),
                    "worktreePath": target.as_posix(),
                    "branch": branch,
                    "baseHead": base_head,
                    "createdHead": base_head,
                    "currentHead": base_head,
                    "createdAt": _utc_timestamp(created_at),
                    "expiresAt": _utc_timestamp(created_at + timedelta(seconds=duration)),
                    "status": ACTIVE_STATUS,
                    "purpose": purpose.strip(),
                    "temporary": True,
                    "cleanupRequired": True,
                    "processObservation": process,
                    "closureState": None,
                    "branchDisposition": {
                        "status": "pending",
                        "integrationRef": None,
                        "archiveBundle": None,
                        "archiveDigest": None,
                    },
                    "evidenceExportLocation": None,
                    "creationReceipt": receipt_path.as_posix(),
                    "cleanupReceipt": None,
                    "retainedException": None,
                }
                self._validate_lease(lease)
                _atomic_json(self._lease_path(lease_id), lease, root=self.repository_store, create_only=True)
                lease_persisted = True
                transaction.update({"status": "committed", "completedAt": _utc_timestamp(self._now())})
                self._write_transaction(transaction)
                final_count = audit["counts"]["registeredWorktrees"] + 1
                final_active = audit["counts"]["activeWritableWorktrees"] + 1
                self._record_observation(
                    event="workspace_created",
                    metrics={
                        "worktrees_created": 1,
                        "branches_created": 1,
                        "peak_registered_worktrees": final_count,
                        "peak_active_writable_worktrees": final_active,
                    },
                    detail={"leaseId": lease_id, "sliceId": slice_id},
                )
                return lease
        except Exception as exc:
            if transaction is None:
                raise
            code = exc.code if isinstance(exc, WorkspaceLifecycleError) else "workspace_creation_failed"
            rollback_ok = False
            residue: list[str] = []
            with self.lifecycle_lock():
                try:
                    if lease_persisted:
                        residue = ["active_lease_preserved"]
                    elif branch_created:
                        rollback_ok, residue = self._rollback_creation(path=target, branch=branch, head=base_head)
                except Exception:
                    residue = ["rollback_inventory_unknown"]
                transaction.update(
                    {
                        "status": (
                            "failed_active_lease_preserved"
                            if lease_persisted
                            else "failed_rolled_back"
                            if rollback_ok or not branch_created
                            else "failed_residue_preserved"
                        ),
                        "residue": residue,
                        "failureCode": code,
                        "completedAt": _utc_timestamp(self._now()),
                    }
                )
                self._write_transaction(transaction)
                failure = {
                    "schema": WORKSPACE_FAILURE_RECEIPT_SCHEMA,
                    "transactionId": transaction_id,
                    "leaseId": lease_id,
                    "repositoryIdentity": self.identity.to_dict(),
                    "failedAt": _utc_timestamp(self._now()),
                    "failureCode": code,
                    "rollbackCompleted": not lease_persisted and (rollback_ok or not branch_created),
                    "residue": residue,
                }
                _atomic_json(
                    self._receipt_path(f"failure-{lease_id}"),
                    failure,
                    root=self.repository_store,
                    create_only=True,
                )
                self._record_observation(
                    event="workspace_creation_failed",
                    metrics={
                        "worktrees_created": 1 if branch_created else 0,
                        "branches_created": 1 if branch_created else 0,
                        "worktrees_removed": 1 if rollback_ok else 0,
                        "branches_retired": 1 if rollback_ok else 0,
                        "cleanup_failures": 1 if residue else 0,
                        "worktrees_leaked": 1 if residue else 0,
                    },
                    detail={"leaseId": lease_id, "failureCode": code, "residue": residue},
                )
            if isinstance(exc, WorkspaceLifecycleError):
                raise
            raise WorkspaceLifecycleError("workspace_creation_failed", "workspace creation transaction failed") from exc

    def get_lease(self, lease_id: str) -> dict[str, Any]:
        _require_id(lease_id, "lease id")
        with self.lifecycle_lock():
            leases = self._load_leases()
            if lease_id not in leases:
                raise WorkspaceLifecycleError("lease_not_found", "workspace lease does not exist")
            return leases[lease_id]

    def _copy_evidence_artifact(
        self,
        *,
        lease_id: str,
        category: str,
        source: Path,
        index: int,
        evidence_directory: Path | None = None,
    ) -> dict[str, Any]:
        if category not in EVIDENCE_CATEGORIES:
            raise WorkspaceLifecycleError("invalid_contract", "workspace evidence category is unsupported")
        source = _assert_no_symlink_ancestors(source, allow_missing=False)
        if source.is_symlink() or not source.is_file():
            raise WorkspaceLifecycleError("evidence_export_failed", "workspace evidence source must be a regular file")
        size = source.stat().st_size
        if size > _MAX_ARTIFACT_BYTES:
            raise WorkspaceLifecycleError("evidence_export_failed", "workspace evidence artifact is oversized")
        safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", source.name)[:100] or "artifact"
        lease_evidence_root = _safe_directory(self.evidence_root / lease_id, create=True)
        target_root = lease_evidence_root
        if evidence_directory is not None:
            requested_root = _assert_no_symlink_ancestors(evidence_directory)
            if requested_root != lease_evidence_root:
                target_root = _safe_directory(
                    _confined_child(lease_evidence_root, requested_root),
                    create=True,
                )
        target_dir = _safe_directory(target_root / category, create=True)
        target = target_dir / f"{index:03d}-{safe_name}"
        content = source.read_bytes()
        _atomic_bytes(target, content, root=self.repository_store, create_only=True)
        return {
            "sourceName": source.name,
            "storedPath": target.as_posix(),
            "size": len(content),
            "digest": _sha256_bytes(content),
        }

    def _load_evidence_manifest_at(
        self,
        lease: Mapping[str, Any],
        path: Path,
        *,
        visited: set[Path],
    ) -> dict[str, Any]:
        lease_evidence_root = _safe_directory(self.evidence_root / str(lease["leaseId"]), create=True)
        path = _confined_child(lease_evidence_root, path)
        if path in visited:
            raise WorkspaceLifecycleError("evidence_integrity_failed", "workspace evidence revision chain is cyclic")
        visited.add(path)
        legacy_path = lease_evidence_root / "manifest.json"
        expected_revision_head: str | None = None
        if path != legacy_path:
            relative = path.relative_to(lease_evidence_root)
            if len(relative.parts) != 3 or relative.parts[0] != "revisions" or relative.parts[2] != "manifest.json":
                raise WorkspaceLifecycleError("evidence_integrity_failed", "workspace evidence manifest path is not canonical")
            expected_revision_head = _require_object_id(relative.parts[1], "evidence revision head")
        manifest = _read_json(path, root=self.repository_store)
        expected = {
            "schema",
            "leaseId",
            "sliceId",
            "repositoryIdentity",
            "branch",
            "baseHead",
            "head",
            "tree",
            "patch",
            "artifacts",
            "exportedAt",
            "manifestDigest",
        }
        manifest_keys = frozenset(manifest)
        if (
            manifest_keys not in {frozenset(expected), frozenset({*expected, "previousManifest"})}
            or manifest.get("schema") != WORKSPACE_EVIDENCE_SCHEMA
        ):
            raise WorkspaceLifecycleError("evidence_integrity_failed", "workspace evidence manifest is malformed")
        if (
            manifest.get("leaseId") != lease["leaseId"]
            or manifest.get("sliceId") != lease["sliceId"]
            or manifest.get("repositoryIdentity") != self.identity.to_dict()
            or manifest.get("branch") != lease["branch"]
            or manifest.get("baseHead") != lease["baseHead"]
        ):
            raise WorkspaceLifecycleError("evidence_integrity_failed", "workspace evidence identity is inconsistent")
        for name in ("head", "tree"):
            _require_object_id(manifest.get(name), f"evidence {name}")
        if expected_revision_head is not None and manifest.get("head") != expected_revision_head:
            raise WorkspaceLifecycleError("evidence_integrity_failed", "workspace evidence revision path disagrees with its head")
        _parse_timestamp(manifest.get("exportedAt"), "evidence exportedAt")
        body = {key: value for key, value in manifest.items() if key != "manifestDigest"}
        if manifest.get("manifestDigest") != _digest(body):
            raise WorkspaceLifecycleError("evidence_integrity_failed", "workspace evidence manifest digest is invalid")
        patch = manifest.get("patch")
        if not isinstance(patch, Mapping) or set(patch) != {"storedPath", "size", "digest"}:
            raise WorkspaceLifecycleError("evidence_integrity_failed", "workspace evidence patch record is invalid")
        artifacts = manifest.get("artifacts")
        if not isinstance(artifacts, Mapping) or set(artifacts) != set(EVIDENCE_CATEGORIES):
            raise WorkspaceLifecycleError("evidence_integrity_failed", "workspace evidence artifact vector is invalid")
        records: list[Mapping[str, Any]] = [patch]
        for category in EVIDENCE_CATEGORIES:
            values = artifacts.get(category)
            if not isinstance(values, list):
                raise WorkspaceLifecycleError("evidence_integrity_failed", "workspace evidence artifact category is invalid")
            for item in values:
                if not isinstance(item, Mapping) or set(item) != {"sourceName", "storedPath", "size", "digest"}:
                    raise WorkspaceLifecycleError("evidence_integrity_failed", "workspace evidence artifact record is invalid")
                records.append(item)
        if len(records) > _MAX_ARTIFACTS + 1:
            raise WorkspaceLifecycleError("evidence_integrity_failed", "workspace evidence manifest is oversized")
        for item in records:
            stored = item.get("storedPath")
            size = item.get("size")
            digest = item.get("digest")
            if (
                not isinstance(stored, str)
                or isinstance(size, bool)
                or not isinstance(size, int)
                or size < 0
                or size > _MAX_ARTIFACT_BYTES
                or not isinstance(digest, str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
            ):
                raise WorkspaceLifecycleError("evidence_integrity_failed", "workspace evidence artifact metadata is invalid")
            stored_path = _confined_child(self.evidence_root / str(lease["leaseId"]), Path(stored))
            if stored_path.is_symlink() or not stored_path.is_file():
                raise WorkspaceLifecycleError("evidence_integrity_failed", "workspace evidence artifact is missing")
            content = stored_path.read_bytes()
            if len(content) != size or _sha256_bytes(content) != digest:
                raise WorkspaceLifecycleError("evidence_integrity_failed", "workspace evidence artifact digest is invalid")
        previous = manifest.get("previousManifest")
        if previous is not None:
            if not isinstance(previous, Mapping) or set(previous) != {"storedPath", "head", "manifestDigest"}:
                raise WorkspaceLifecycleError("evidence_integrity_failed", "workspace evidence predecessor is malformed")
            previous_head = _require_object_id(previous.get("head"), "previous evidence head")
            previous_digest = previous.get("manifestDigest")
            previous_location = previous.get("storedPath")
            if (
                not isinstance(previous_digest, str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", previous_digest) is None
                or not isinstance(previous_location, str)
            ):
                raise WorkspaceLifecycleError("evidence_integrity_failed", "workspace evidence predecessor identity is invalid")
            predecessor = self._load_evidence_manifest_at(
                lease,
                Path(previous_location),
                visited=visited,
            )
            if predecessor.get("head") != previous_head or predecessor.get("manifestDigest") != previous_digest:
                raise WorkspaceLifecycleError("evidence_integrity_failed", "workspace evidence predecessor identity disagrees")
        return manifest

    def _load_evidence_manifest(self, lease: Mapping[str, Any]) -> dict[str, Any]:
        location = lease.get("evidenceExportLocation")
        if not isinstance(location, str):
            raise WorkspaceLifecycleError("evidence_export_missing", "workspace lease has no evidence location")
        return self._load_evidence_manifest_at(lease, Path(location), visited=set())

    def _load_creation_receipt(self, lease: Mapping[str, Any]) -> dict[str, Any]:
        location = lease.get("creationReceipt")
        if not isinstance(location, str):
            raise WorkspaceLifecycleError("receipt_integrity_failed", "workspace creation receipt is missing")
        path = _confined_child(self.receipts_root, Path(location), direct=True)
        if path != self._receipt_path(f"creation-{lease['leaseId']}"):
            raise WorkspaceLifecycleError("receipt_integrity_failed", "workspace creation receipt path is not canonical")
        receipt = _read_json(path, root=self.repository_store)
        expected = {
            "schema",
            "leaseId",
            "sliceId",
            "repositoryIdentity",
            "worktreePath",
            "branch",
            "baseHead",
            "createdHead",
            "createdAt",
            "inventoryBefore",
            "receiptDigest",
        }
        if set(receipt) != expected or receipt.get("schema") != WORKSPACE_CREATION_RECEIPT_SCHEMA:
            raise WorkspaceLifecycleError("receipt_integrity_failed", "workspace creation receipt is malformed")
        bindings = {
            "leaseId": "leaseId",
            "sliceId": "sliceId",
            "repositoryIdentity": "repositoryIdentity",
            "worktreePath": "worktreePath",
            "branch": "branch",
            "baseHead": "baseHead",
            "createdHead": "createdHead",
            "createdAt": "createdAt",
        }
        if any(receipt.get(receipt_name) != lease.get(lease_name) for receipt_name, lease_name in bindings.items()):
            raise WorkspaceLifecycleError("receipt_integrity_failed", "workspace creation receipt contradicts its lease")
        body = {key: value for key, value in receipt.items() if key != "receiptDigest"}
        if receipt.get("receiptDigest") != _digest(body):
            raise WorkspaceLifecycleError("receipt_integrity_failed", "workspace creation receipt digest is invalid")
        return receipt

    def _load_cleanup_receipt(self, lease: Mapping[str, Any]) -> dict[str, Any]:
        location = lease.get("cleanupReceipt")
        if not isinstance(location, str):
            raise WorkspaceLifecycleError("receipt_integrity_failed", "workspace cleanup receipt is missing")
        path = _confined_child(self.receipts_root, Path(location), direct=True)
        if path != self._receipt_path(f"cleanup-{lease['leaseId']}"):
            raise WorkspaceLifecycleError("receipt_integrity_failed", "workspace cleanup receipt path is not canonical")
        receipt = _read_json(path, root=self.repository_store)
        expected = {
            "schema",
            "leaseId",
            "sliceId",
            "repositoryIdentity",
            "status",
            "worktreePath",
            "branch",
            "head",
            "evidenceExportLocation",
            "branchDisposition",
            "archiveBundle",
            "archiveDigest",
            "worktreeRemoved",
            "branchRetired",
            "classifications",
            "closedAt",
            "cleanupDurationSeconds",
            "receiptDigest",
        }
        if set(receipt) != expected or receipt.get("schema") != WORKSPACE_CLEANUP_RECEIPT_SCHEMA:
            raise WorkspaceLifecycleError("receipt_integrity_failed", "workspace cleanup receipt is malformed")
        if (
            receipt.get("leaseId") != lease["leaseId"]
            or receipt.get("sliceId") != lease["sliceId"]
            or receipt.get("repositoryIdentity") != self.identity.to_dict()
            or receipt.get("status") != lease["status"]
            or receipt.get("worktreePath") != lease["worktreePath"]
            or receipt.get("branch") != lease["branch"]
            or receipt.get("head") != lease["currentHead"]
            or receipt.get("evidenceExportLocation") != lease["evidenceExportLocation"]
            or receipt.get("branchDisposition") != lease["branchDisposition"]["status"]
            or receipt.get("archiveBundle") != lease["branchDisposition"]["archiveBundle"]
            or receipt.get("archiveDigest") != lease["branchDisposition"]["archiveDigest"]
        ):
            raise WorkspaceLifecycleError("receipt_integrity_failed", "workspace cleanup receipt contradicts its lease")
        duration = receipt.get("cleanupDurationSeconds")
        if isinstance(duration, bool) or not isinstance(duration, (int, float)) or duration < 0:
            raise WorkspaceLifecycleError("receipt_integrity_failed", "workspace cleanup duration is invalid")
        if not isinstance(receipt.get("worktreeRemoved"), bool) or not isinstance(receipt.get("branchRetired"), bool):
            raise WorkspaceLifecycleError("receipt_integrity_failed", "workspace cleanup flags are invalid")
        expected_removed = lease["status"] in REMOVED_STATUSES
        if receipt["worktreeRemoved"] is not expected_removed or receipt["branchRetired"] is not expected_removed:
            raise WorkspaceLifecycleError("receipt_integrity_failed", "workspace cleanup flags contradict its lease")
        classifications = receipt.get("classifications")
        if not isinstance(classifications, list) or any(not isinstance(item, str) or not item for item in classifications):
            raise WorkspaceLifecycleError("receipt_integrity_failed", "workspace cleanup classifications are invalid")
        _parse_timestamp(receipt.get("closedAt"), "cleanup closedAt")
        body = {key: value for key, value in receipt.items() if key != "receiptDigest"}
        if receipt.get("receiptDigest") != _digest(body):
            raise WorkspaceLifecycleError("receipt_integrity_failed", "workspace cleanup receipt digest is invalid")
        if lease["status"] == "archived_and_removed":
            bundle = _confined_child(self.archives_root, Path(receipt["archiveBundle"]), direct=True)
            if bundle.is_symlink() or not bundle.is_file() or _sha256_bytes(bundle.read_bytes()) != receipt["archiveDigest"]:
                raise WorkspaceLifecycleError("receipt_integrity_failed", "workspace archive evidence is invalid")
        return receipt

    def export_evidence(
        self,
        lease_id: str,
        *,
        artifacts: Mapping[str, Sequence[Path | str]] | None = None,
    ) -> dict[str, Any]:
        """Export exact checkout evidence into the durable operational store."""

        _require_id(lease_id, "lease id")
        supplied = artifacts or {}
        if set(supplied) - set(EVIDENCE_CATEGORIES):
            raise WorkspaceLifecycleError("invalid_contract", "workspace evidence contains an unsupported category")
        if sum(len(items) for items in supplied.values()) > _MAX_ARTIFACTS:
            raise WorkspaceLifecycleError("invalid_contract", "too many workspace evidence artifacts")
        with self.lifecycle_lock():
            leases = self._load_leases()
            lease = leases.get(lease_id)
            if lease is None:
                raise WorkspaceLifecycleError("lease_not_found", "workspace lease does not exist")
            if lease["status"] != ACTIVE_STATUS:
                if lease["evidenceExportLocation"]:
                    return self._load_evidence_manifest(lease)
                raise WorkspaceLifecycleError("invalid_lease_state", "terminal workspace has no evidence export")
            previous_manifest = (
                self._load_evidence_manifest(lease)
                if lease["evidenceExportLocation"] is not None
                else None
            )
            path = _assert_no_symlink_ancestors(Path(lease["worktreePath"]), allow_missing=False)
            inventory = self._inventory()
            entry = next((item for item in inventory if item.path == path), None)
            if entry is None or entry.branch != lease["branch"]:
                raise WorkspaceLifecycleRefusal("repository_identity_mismatch", "leased checkout identity changed before evidence export")
            self._verified_created_checkout(path, branch=lease["branch"], head=entry.head)
            if previous_manifest is not None and previous_manifest.get("head") == entry.head:
                return previous_manifest
            tree = self._git(("rev-parse", "HEAD^{tree}"), cwd=path)
            patch = self._run_git(
                ("diff", "--binary", "--full-index", f"{lease['baseHead']}..{entry.head}", "--"),
                cwd=path,
                text=False,
            ).stdout
            if len(patch) > _MAX_ARTIFACT_BYTES:
                raise WorkspaceLifecycleError("evidence_export_failed", "workspace patch evidence is oversized")
            lease_evidence_root = _safe_directory(self.evidence_root / lease_id, create=True)
            evidence_dir = lease_evidence_root
            if previous_manifest is not None:
                evidence_dir = _safe_directory(
                    lease_evidence_root / "revisions" / entry.head,
                    create=True,
                )
            patch_path = evidence_dir / "base-to-head.patch"
            _atomic_bytes(patch_path, patch, root=self.repository_store, create_only=True)
            copied: dict[str, list[dict[str, Any]]] = {category: [] for category in EVIDENCE_CATEGORIES}
            for category in EVIDENCE_CATEGORIES:
                for index, source in enumerate(supplied.get(category, ())):
                    copied[category].append(
                        self._copy_evidence_artifact(
                            lease_id=lease_id,
                            category=category,
                            source=Path(source),
                            index=index,
                            evidence_directory=evidence_dir,
                        )
                    )
            manifest_path = evidence_dir / "manifest.json"
            body = {
                "schema": WORKSPACE_EVIDENCE_SCHEMA,
                "leaseId": lease_id,
                "sliceId": lease["sliceId"],
                "repositoryIdentity": self.identity.to_dict(),
                "branch": lease["branch"],
                "baseHead": lease["baseHead"],
                "head": entry.head,
                "tree": tree,
                "patch": {
                    "storedPath": patch_path.as_posix(),
                    "size": len(patch),
                    "digest": _sha256_bytes(patch),
                },
                "artifacts": copied,
                "exportedAt": _utc_timestamp(self._now()),
            }
            if previous_manifest is not None:
                body["previousManifest"] = {
                    "storedPath": lease["evidenceExportLocation"],
                    "head": previous_manifest["head"],
                    "manifestDigest": previous_manifest["manifestDigest"],
                }
            manifest = {**body, "manifestDigest": _digest(body)}
            _atomic_json(manifest_path, manifest, root=self.repository_store, create_only=True)
            lease["currentHead"] = entry.head
            lease["evidenceExportLocation"] = manifest_path.as_posix()
            self._validate_lease(lease)
            _atomic_json(self._lease_path(lease_id), lease, root=self.repository_store)
            return self._load_evidence_manifest(lease)

    def _archive_branch(self, *, lease_id: str, branch: str, head: str) -> tuple[str, str]:
        bundle = self.archives_root / f"{lease_id}.bundle"
        if bundle.exists():
            raise WorkspaceLifecycleError("archive_failed", "workspace archive target already exists")
        created = self._run_git(("bundle", "create", bundle.as_posix(), f"refs/heads/{branch}"), check=False)
        if created.returncode != 0 or not bundle.is_file() or bundle.is_symlink():
            raise WorkspaceLifecycleError("archive_failed", "workspace branch could not be archived")
        verified = self._run_git(("bundle", "verify", bundle.as_posix()), check=False)
        if verified.returncode != 0:
            raise WorkspaceLifecycleError("archive_failed", "workspace branch archive could not be verified")
        heads = self._git(("bundle", "list-heads", bundle.as_posix()))
        if not any(line.split(maxsplit=1)[0] == head for line in heads.splitlines() if line.strip()):
            raise WorkspaceLifecycleError("archive_failed", "workspace archive does not preserve the expected head")
        content = bundle.read_bytes()
        os.chmod(bundle, 0o600)
        _fsync_directory(self.archives_root)
        return bundle.as_posix(), _sha256_bytes(content)

    def _retention_classifications(
        self,
        *,
        entry: WorktreeInventoryEntry | None,
        lease: Mapping[str, Any],
        path: Path,
    ) -> tuple[list[str], dict[str, Any] | None, dict[str, Any]]:
        classifications: list[str] = []
        state: dict[str, Any] | None = None
        process: dict[str, Any] = {
            "observedAt": _utc_timestamp(self._now()),
            "ownerPid": os.getpid(),
            "active": False,
            "pids": [],
        }
        if entry is None:
            classifications.append("workspace_missing_or_unregistered")
            return classifications, state, process
        if entry.branch != lease["branch"]:
            classifications.append("branch_ref_disagreement")
        try:
            current = self._git(("rev-parse", "HEAD"), cwd=path)
            if current != entry.head:
                classifications.append("head_identity_disagreement")
            state = self._worktree_state(path)
            if state["trackedDirty"]:
                classifications.append("dirty_tracked_files")
            if state["untrackedCount"]:
                classifications.append("untracked_content")
            if state["ignoredCount"]:
                classifications.append("ignored_content")
            process = self._process_observation(path)
            if process["active"]:
                classifications.append("active_processes")
        except (OSError, WorkspaceLifecycleError):
            classifications.append("ownership_or_inventory_uncertain")
        return sorted(set(classifications)), state, process

    def _terminalize_exception(
        self,
        *,
        lease: dict[str, Any],
        classifications: Sequence[str],
        state: Mapping[str, Any] | None,
        process: Mapping[str, Any],
        reason: str,
        expires_at: datetime,
        started: datetime,
    ) -> dict[str, Any]:
        if expires_at <= self._now():
            raise WorkspaceLifecycleError("invalid_contract", "retained exception expiry must be in the future")
        closed_at = self._now()
        receipt_path = self._receipt_path(f"cleanup-{lease['leaseId']}")
        closure_state = {
            "requestedDisposition": "retained_exception",
            "trackedState": dict(state) if state is not None else None,
            "processObservation": dict(process),
            "classifications": list(classifications),
            "closedAt": _utc_timestamp(closed_at),
            "worktreeRemoved": False,
            "branchRetired": False,
        }
        receipt = {
            "schema": WORKSPACE_CLEANUP_RECEIPT_SCHEMA,
            "leaseId": lease["leaseId"],
            "sliceId": lease["sliceId"],
            "repositoryIdentity": self.identity.to_dict(),
            "status": "retained_exception",
            "worktreePath": lease["worktreePath"],
            "branch": lease["branch"],
            "head": lease["currentHead"],
            "evidenceExportLocation": lease["evidenceExportLocation"],
            "branchDisposition": "retained_exception",
            "archiveBundle": None,
            "archiveDigest": None,
            "worktreeRemoved": False,
            "branchRetired": False,
            "classifications": list(classifications),
            "closedAt": _utc_timestamp(closed_at),
            "cleanupDurationSeconds": max(0.0, (closed_at - started).total_seconds()),
            "receiptDigest": None,
        }
        receipt["receiptDigest"] = _digest({key: value for key, value in receipt.items() if key != "receiptDigest"})
        _atomic_json(receipt_path, receipt, root=self.repository_store, create_only=True)
        lease.update(
            {
                "status": "retained_exception",
                "cleanupRequired": True,
                "processObservation": dict(process),
                "closureState": closure_state,
                "branchDisposition": {
                    "status": "retained_exception",
                    "integrationRef": None,
                    "archiveBundle": None,
                    "archiveDigest": None,
                },
                "cleanupReceipt": receipt_path.as_posix(),
                "retainedException": {
                    "reason": reason.strip(),
                    "classifications": list(classifications),
                    "expiresAt": _utc_timestamp(expires_at),
                },
            }
        )
        self._validate_lease(lease)
        _atomic_json(self._lease_path(lease["leaseId"]), lease, root=self.repository_store)
        self._record_observation(
            event="workspace_retained_exception",
            metrics={
                "worktrees_leaked": 1,
                "cleanup_failures": 1,
                "cleanup_duration": receipt["cleanupDurationSeconds"],
            },
            detail={"leaseId": lease["leaseId"], "classifications": list(classifications)},
        )
        return receipt

    def close_workspace(
        self,
        lease_id: str,
        *,
        disposition: str,
        integration_ref: str | None = None,
        exception_reason: str | None = None,
        exception_expires_at: datetime | None = None,
    ) -> dict[str, Any]:
        """Exported, clean workspaces retire automatically; unsafe residue is retained."""

        _require_id(lease_id, "lease id")
        if disposition not in {"integrated", "rejected", "archived"}:
            raise WorkspaceLifecycleError("invalid_contract", "workspace disposition is unsupported")
        started = self._now()
        with self.lifecycle_lock():
            leases = self._load_leases()
            lease = leases.get(lease_id)
            if lease is None:
                raise WorkspaceLifecycleError("lease_not_found", "workspace lease does not exist")
            if lease["status"] in TERMINAL_STATUSES:
                return self._load_cleanup_receipt(lease)
            if lease["evidenceExportLocation"] is None:
                self._record_observation(
                    event="workspace_closure_refused",
                    metrics={"closure_gate_workspace_failures": 1},
                    detail={"leaseId": lease_id, "code": "evidence_export_missing"},
                )
                raise WorkspaceLifecycleRefusal("evidence_export_missing", "workspace evidence must be exported before closure")
            manifest = self._load_evidence_manifest(lease)
            path = _assert_no_symlink_ancestors(Path(lease["worktreePath"]), allow_missing=True)
            entry = next((item for item in self._inventory() if item.path == path), None)
            classifications, state, process = self._retention_classifications(
                entry=entry,
                lease=lease,
                path=path,
            )
            if entry is not None:
                lease["currentHead"] = entry.head
            if classifications:
                if exception_reason is None or exception_expires_at is None:
                    self._record_observation(
                        event="workspace_closure_refused",
                        metrics={"closure_gate_workspace_failures": 1, "cleanup_failures": 1},
                        detail={"leaseId": lease_id, "code": "retained_exception_required", "classifications": classifications},
                    )
                    raise WorkspaceLifecycleRefusal(
                        "retained_exception_required",
                        "unsafe workspace residue requires a reason and expiry; no force removal was attempted",
                    )
                return self._terminalize_exception(
                    lease=lease,
                    classifications=classifications,
                    state=state,
                    process=process,
                    reason=exception_reason,
                    expires_at=exception_expires_at,
                    started=started,
                )
            assert entry is not None
            if manifest.get("head") != entry.head:
                raise WorkspaceLifecycleRefusal("evidence_export_stale", "workspace head changed after evidence export")
            archive_bundle: str | None = None
            archive_digest: str | None = None
            if disposition == "integrated":
                if integration_ref is None:
                    raise WorkspaceLifecycleError("invalid_contract", "integrated disposition requires an integration ref")
                integration_head = self._git(("rev-parse", "--verify", f"{integration_ref}^{{commit}}"))
                ancestor = self._run_git(("merge-base", "--is-ancestor", entry.head, integration_head), check=False)
                if ancestor.returncode != 0:
                    raise WorkspaceLifecycleRefusal("branch_ref_disagreement", "workspace head is not integrated into the declared ref")
            elif disposition == "archived":
                archive_bundle, archive_digest = self._archive_branch(
                    lease_id=lease_id,
                    branch=lease["branch"],
                    head=entry.head,
                )
            transaction_id = f"close_{lease_id}"
            transaction = {
                "schema": "stateport.workspace-closure-transaction/v1",
                "transactionId": transaction_id,
                "leaseId": lease_id,
                "sliceId": lease["sliceId"],
                "repositoryIdentity": self.identity.to_dict(),
                "worktreePath": path.as_posix(),
                "branch": lease["branch"],
                "head": entry.head,
                "disposition": disposition,
                "startedAt": _utc_timestamp(started),
                "status": "pending",
            }
            self._write_transaction(transaction, create_only=True)
            removed = self._run_git(("worktree", "remove", path.as_posix()), check=False)
            if removed.returncode != 0:
                transaction.update({"status": "failed_residue_preserved", "failureCode": "worktree_removal_failed"})
                self._write_transaction(transaction)
                raise WorkspaceLifecycleError("cleanup_failed", "clean workspace could not be removed")
            # The disposition proof above (integration ancestry, exported patch,
            # or verified bundle) is the durable safety boundary; delete the
            # temporary ref independent of the primary checkout's current HEAD.
            deleted = self._run_git(("branch", "-D", "--", lease["branch"]), check=False)
            if deleted.returncode != 0:
                transaction.update({"status": "failed_residue_preserved", "failureCode": "branch_removal_failed"})
                self._write_transaction(transaction)
                raise WorkspaceLifecycleError("cleanup_failed", "workspace branch could not be retired")
            remaining_paths = {item.path for item in self._inventory()}
            branch_exists = self._run_git(
                ("show-ref", "--verify", "--quiet", f"refs/heads/{lease['branch']}"), check=False
            ).returncode == 0
            if path in remaining_paths or branch_exists:
                transaction.update({"status": "failed_residue_preserved", "failureCode": "cleanup_verification_failed"})
                self._write_transaction(transaction)
                raise WorkspaceLifecycleError("cleanup_failed", "workspace retirement could not be verified")
            closed_at = self._now()
            terminal = {
                "integrated": "integrated_and_removed",
                "rejected": "rejected_and_removed",
                "archived": "archived_and_removed",
            }[disposition]
            receipt_path = self._receipt_path(f"cleanup-{lease_id}")
            closure_state = {
                "requestedDisposition": disposition,
                "trackedState": state,
                "processObservation": process,
                "classifications": [],
                "closedAt": _utc_timestamp(closed_at),
                "worktreeRemoved": True,
                "branchRetired": True,
            }
            receipt = {
                "schema": WORKSPACE_CLEANUP_RECEIPT_SCHEMA,
                "leaseId": lease_id,
                "sliceId": lease["sliceId"],
                "repositoryIdentity": self.identity.to_dict(),
                "status": terminal,
                "worktreePath": path.as_posix(),
                "branch": lease["branch"],
                "head": entry.head,
                "evidenceExportLocation": lease["evidenceExportLocation"],
                "branchDisposition": disposition,
                "archiveBundle": archive_bundle,
                "archiveDigest": archive_digest,
                "worktreeRemoved": True,
                "branchRetired": True,
                "classifications": [],
                "closedAt": _utc_timestamp(closed_at),
                "cleanupDurationSeconds": max(0.0, (closed_at - started).total_seconds()),
                "receiptDigest": None,
            }
            receipt["receiptDigest"] = _digest({key: value for key, value in receipt.items() if key != "receiptDigest"})
            _atomic_json(receipt_path, receipt, root=self.repository_store, create_only=True)
            lease.update(
                {
                    "status": terminal,
                    "cleanupRequired": False,
                    "processObservation": process,
                    "closureState": closure_state,
                    "branchDisposition": {
                        "status": disposition,
                        "integrationRef": integration_ref,
                        "archiveBundle": archive_bundle,
                        "archiveDigest": archive_digest,
                    },
                    "cleanupReceipt": receipt_path.as_posix(),
                    "retainedException": None,
                }
            )
            self._validate_lease(lease)
            _atomic_json(self._lease_path(lease_id), lease, root=self.repository_store)
            transaction.update({"status": "committed", "completedAt": _utc_timestamp(closed_at)})
            self._write_transaction(transaction)
            self._record_observation(
                event="workspace_removed",
                metrics={
                    "worktrees_removed": 1,
                    "branches_retired": 1,
                    "cleanup_duration": receipt["cleanupDurationSeconds"],
                },
                detail={"leaseId": lease_id, "status": terminal},
            )
            return receipt

    def reconcile_missing_integrated_workspace(
        self,
        lease_id: str,
        *,
        recovered_ref: str,
        integration_ref: str,
    ) -> dict[str, Any]:
        """Terminalize an externally removed workspace from retained Git evidence.

        This recovery is deliberately narrower than normal closure. It is
        available only when both the leased worktree and local branch are
        already absent, the recovered head descends from the lease base, and
        that exact head is an ancestor of the declared integration ref. It
        reconstructs checkout-independent patch evidence and records that the
        normal managed lifecycle was bypassed.
        """

        _require_id(lease_id, "lease id")
        if not isinstance(recovered_ref, str) or not recovered_ref.strip():
            raise WorkspaceLifecycleError("invalid_contract", "recovered ref is required")
        if not isinstance(integration_ref, str) or not integration_ref.strip():
            raise WorkspaceLifecycleError("invalid_contract", "integration ref is required")
        started = self._now()
        with self.lifecycle_lock():
            leases = self._load_leases()
            lease = leases.get(lease_id)
            if lease is None:
                raise WorkspaceLifecycleError("lease_not_found", "workspace lease does not exist")
            if lease["status"] in TERMINAL_STATUSES:
                return self._load_cleanup_receipt(lease)
            if lease["status"] != ACTIVE_STATUS:
                raise WorkspaceLifecycleError("invalid_lease_state", "workspace lease is not active")
            if lease["evidenceExportLocation"] is not None:
                raise WorkspaceLifecycleRefusal(
                    "evidence_export_stale",
                    "missing-workspace recovery only accepts a lease without prior evidence export",
                )
            path = _assert_no_symlink_ancestors(Path(lease["worktreePath"]), allow_missing=True)
            inventory = self._inventory()
            if path.exists() or any(item.path == path for item in inventory):
                raise WorkspaceLifecycleRefusal(
                    "repository_identity_mismatch",
                    "leased workspace still exists; use the normal evidence and closure path",
                )
            if any(item.branch == lease["branch"] for item in inventory):
                raise WorkspaceLifecycleRefusal(
                    "branch_ref_disagreement",
                    "leased branch is still checked out in another workspace",
                )
            local_branch = self._run_git(
                ("show-ref", "--verify", "--quiet", f"refs/heads/{lease['branch']}"),
                check=False,
            )
            if local_branch.returncode == 0:
                raise WorkspaceLifecycleRefusal(
                    "branch_ref_disagreement",
                    "leased local branch still exists; use the normal closure path",
                )
            if local_branch.returncode != 1:
                raise WorkspaceLifecycleRefusal("inventory_unknown", "local branch state is unknown")
            recovered_head = self._git(("rev-parse", "--verify", f"{recovered_ref}^{{commit}}"))
            integration_head = self._git(("rev-parse", "--verify", f"{integration_ref}^{{commit}}"))
            base_relation = self._run_git(
                ("merge-base", "--is-ancestor", lease["baseHead"], recovered_head),
                check=False,
            )
            if base_relation.returncode != 0:
                raise WorkspaceLifecycleRefusal(
                    "branch_ref_disagreement",
                    "recovered head does not descend from the leased base",
                )
            integration_relation = self._run_git(
                ("merge-base", "--is-ancestor", recovered_head, integration_head),
                check=False,
            )
            if integration_relation.returncode != 0:
                raise WorkspaceLifecycleRefusal(
                    "branch_ref_disagreement",
                    "recovered head is not integrated into the declared ref",
                )
            tree = self._git(("rev-parse", f"{recovered_head}^{{tree}}"))
            patch = self._run_git(
                ("diff", "--binary", "--full-index", f"{lease['baseHead']}..{recovered_head}", "--"),
                text=False,
            ).stdout
            if len(patch) > _MAX_ARTIFACT_BYTES:
                raise WorkspaceLifecycleError("evidence_export_failed", "recovered workspace patch is oversized")
            evidence_dir = _safe_directory(self.evidence_root / lease_id, create=True)
            patch_path = evidence_dir / "base-to-head.patch"
            _atomic_bytes(patch_path, patch, root=self.repository_store, create_only=True)
            artifacts: dict[str, list[dict[str, Any]]] = {
                category: [] for category in EVIDENCE_CATEGORIES
            }
            manifest_path = evidence_dir / "manifest.json"
            body = {
                "schema": WORKSPACE_EVIDENCE_SCHEMA,
                "leaseId": lease_id,
                "sliceId": lease["sliceId"],
                "repositoryIdentity": self.identity.to_dict(),
                "branch": lease["branch"],
                "baseHead": lease["baseHead"],
                "head": recovered_head,
                "tree": tree,
                "patch": {
                    "storedPath": patch_path.as_posix(),
                    "size": len(patch),
                    "digest": _sha256_bytes(patch),
                },
                "artifacts": artifacts,
                "exportedAt": _utc_timestamp(self._now()),
            }
            manifest = {**body, "manifestDigest": _digest(body)}
            _atomic_json(manifest_path, manifest, root=self.repository_store, create_only=True)
            lease["currentHead"] = recovered_head
            lease["evidenceExportLocation"] = manifest_path.as_posix()
            transaction_id = f"reconcile_missing_{lease_id}"
            transaction = {
                "schema": "stateport.workspace-closure-transaction/v1",
                "transactionId": transaction_id,
                "leaseId": lease_id,
                "sliceId": lease["sliceId"],
                "repositoryIdentity": self.identity.to_dict(),
                "worktreePath": path.as_posix(),
                "branch": lease["branch"],
                "head": recovered_head,
                "disposition": "integrated",
                "startedAt": _utc_timestamp(started),
                "status": "pending",
            }
            self._write_transaction(transaction, create_only=True)
            closed_at = self._now()
            process = {
                "observedAt": _utc_timestamp(closed_at),
                "ownerPid": os.getpid(),
                "active": False,
                "pids": [],
            }
            classifications = ["reconciled_after_external_removal"]
            closure_state = {
                "requestedDisposition": "integrated",
                "trackedState": None,
                "processObservation": process,
                "classifications": classifications,
                "closedAt": _utc_timestamp(closed_at),
                "worktreeRemoved": True,
                "branchRetired": True,
            }
            receipt_path = self._receipt_path(f"cleanup-{lease_id}")
            receipt = {
                "schema": WORKSPACE_CLEANUP_RECEIPT_SCHEMA,
                "leaseId": lease_id,
                "sliceId": lease["sliceId"],
                "repositoryIdentity": self.identity.to_dict(),
                "status": "integrated_and_removed",
                "worktreePath": path.as_posix(),
                "branch": lease["branch"],
                "head": recovered_head,
                "evidenceExportLocation": manifest_path.as_posix(),
                "branchDisposition": "integrated",
                "archiveBundle": None,
                "archiveDigest": None,
                "worktreeRemoved": True,
                "branchRetired": True,
                "classifications": classifications,
                "closedAt": _utc_timestamp(closed_at),
                "cleanupDurationSeconds": max(0.0, (closed_at - started).total_seconds()),
                "receiptDigest": None,
            }
            receipt["receiptDigest"] = _digest(
                {key: value for key, value in receipt.items() if key != "receiptDigest"}
            )
            _atomic_json(receipt_path, receipt, root=self.repository_store, create_only=True)
            lease.update(
                {
                    "status": "integrated_and_removed",
                    "cleanupRequired": False,
                    "processObservation": process,
                    "closureState": closure_state,
                    "branchDisposition": {
                        "status": "integrated",
                        "integrationRef": integration_ref,
                        "archiveBundle": None,
                        "archiveDigest": None,
                    },
                    "cleanupReceipt": receipt_path.as_posix(),
                    "retainedException": None,
                }
            )
            self._validate_lease(lease)
            _atomic_json(self._lease_path(lease_id), lease, root=self.repository_store)
            transaction.update({"status": "committed", "completedAt": _utc_timestamp(closed_at)})
            self._write_transaction(transaction)
            self._record_observation(
                event="workspace_missing_reconciled",
                metrics={"worktrees_removed": 1, "branches_retired": 1},
                detail={
                    "leaseId": lease_id,
                    "head": recovered_head,
                    "recoveredRef": recovered_ref,
                    "integrationRef": integration_ref,
                    "classification": classifications[0],
                },
            )
            return self._load_cleanup_receipt(lease)

    def assert_slice_closed(self, slice_id: str) -> dict[str, Any]:
        """Reject closure until every workspace and branch for a slice is terminal and removed."""

        _require_id(slice_id, "slice id")
        with self.lifecycle_lock():
            audit = self._audit_unlocked(slice_id=slice_id)
            leases = self._load_leases()
            blockers: list[dict[str, Any]] = list(audit["violations"])
            prior_closure = self._load_slice_closure_receipt(slice_id)
            if prior_closure is not None:
                prior_checked_at = _parse_timestamp(
                    prior_closure["checkedAt"], "slice closure checkedAt"
                )
                reused = sorted(
                    lease["leaseId"]
                    for lease in leases.values()
                    if lease["sliceId"] == slice_id
                    and _parse_timestamp(lease["createdAt"], "createdAt") > prior_checked_at
                )
                if reused:
                    blockers.append({"code": "slice_identifier_reused", "items": reused})
            active = sorted(
                lease["leaseId"] for lease in leases.values()
                if lease["sliceId"] == slice_id and lease["status"] == ACTIVE_STATUS
            )
            retained = sorted(
                lease["leaseId"] for lease in leases.values()
                if lease["sliceId"] == slice_id and lease["status"] == "retained_exception"
            )
            missing_evidence = sorted(
                lease["leaseId"] for lease in leases.values()
                if lease["sliceId"] == slice_id and lease["evidenceExportLocation"] is None
            )
            if active:
                blockers.append({"code": "active_lease_present", "items": active})
            if retained:
                blockers.append({"code": "retained_exception_present", "items": retained})
            if missing_evidence:
                blockers.append({"code": "evidence_export_missing", "items": missing_evidence})
            result = {
                "schema": WORKSPACE_SLICE_CLOSURE_SCHEMA,
                "sliceId": slice_id,
                "checkedAt": _utc_timestamp(self._now()),
                "repositoryIdentity": self.identity.to_dict(),
                "ok": not blockers,
                "blockers": blockers,
                "audit": audit,
            }
            if blockers:
                self._record_observation(
                    event="workspace_slice_closure_failed",
                    metrics={
                        "closure_gate_workspace_failures": 1,
                        "worktrees_leaked": audit["counts"]["leakedWorktrees"],
                    },
                    detail={"sliceId": slice_id, "blockers": blockers},
                )
                raise WorkspaceLifecycleRefusal("slice_closure_blocked", _canonical_json(result))
            receipt_path = self._receipt_path(f"slice-closure-{slice_id}")
            if prior_closure is not None:
                return prior_closure
            _atomic_json(receipt_path, result, root=self.repository_store, create_only=True)
            return result

    def assert_repository_closed(self) -> dict[str, Any]:
        """Repository closure gate: no active/retained/unknown/expired/leaked workspace."""

        with self.lifecycle_lock():
            audit = self._audit_unlocked()
            leases = self._load_leases()
            pending_branches = sorted(
                lease["branch"] for lease in leases.values()
                if lease["status"] in {ACTIVE_STATUS, "retained_exception"}
                or lease["branchDisposition"]["status"] == "pending"
            )
            blockers = list(audit["violations"])
            if pending_branches:
                blockers.append({"code": "unclassified_branch_present", "items": pending_branches})
            result = {
                "schema": "stateport.workspace-repository-closure/v1",
                "checkedAt": _utc_timestamp(self._now()),
                "repositoryIdentity": self.identity.to_dict(),
                "ok": not blockers,
                "blockers": blockers,
                "audit": audit,
            }
            if blockers:
                self._record_observation(
                    event="workspace_repository_closure_failed",
                    metrics={
                        "closure_gate_workspace_failures": 1,
                        "worktrees_leaked": audit["counts"]["leakedWorktrees"],
                    },
                    detail={"blockers": blockers},
                )
                raise WorkspaceLifecycleRefusal("repository_closure_blocked", _canonical_json(result))
            return result
