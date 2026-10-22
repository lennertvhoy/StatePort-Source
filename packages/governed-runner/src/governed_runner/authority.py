"""Typed standing authority and action receipts for StatePort operations.

The repository policy defines action classes and profile defaults.  Active
grants, revocations, pauses, scope-closure markers, and action receipts live in
an operator-private store outside Git.  A grant is declared authority; callers
must still enforce the returned decision at the actual execution boundary and
record the observed result.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
from fnmatch import fnmatchcase
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import subprocess
from typing import Any, Callable, Mapping, Sequence, TypeVar
from urllib.parse import urlsplit


AUTHORITY_POLICY_SCHEMA = "stateport.authority-policy/v1"
AUTHORITY_GRANT_SCHEMA = "stateport.authority-grant/v1"
AUTHORITY_DECISION_SCHEMA = "stateport.authority-decision/v1"
AUTHORITY_ACTION_RESERVATION_SCHEMA = "stateport.authority-action-reservation/v1"
AUTHORITY_ACTION_CLAIM_SCHEMA = "stateport.authority-action-claim/v1"
AUTHORITY_ACTION_RECEIPT_SCHEMA = "stateport.authority-action-receipt/v1"
AUTHORITY_CONTROL_SCHEMA = "stateport.authority-control/v1"
AUTHORITY_REVOCATION_SCHEMA = "stateport.authority-revocation/v1"
AUTHORITY_SCOPE_CLOSURE_SCHEMA = "stateport.authority-scope-closure/v1"
AUTHORITY_RECOVERY_SCHEMA = "stateport.authority-recovery-attention/v1"

AUTHORITY_MODES = frozenset(
    {"deny", "ask_each_time", "approve_scope_once", "auto_and_notify", "auto_with_receipt"}
)
AUTHORITY_PROFILES = frozenset({"guarded", "balanced", "delegated", "custom"})
AUTHORITY_DECISIONS = frozenset({"authorized", "approval_required", "denied"})
ACTION_RESULTS = frozenset({"succeeded", "failed", "refused", "not_executed"})
GRANT_KINDS = frozenset({"standing", "one_time"})
EXPIRY_MODES = frozenset({"revoked", "slice_closed", "run_closed", "timestamp", "one_action"})
SUBJECT_ROLES = frozenset({"primary", "subagent", "operator"})
NETWORK_MODES = frozenset({"denied", "allowlisted", "unrestricted"})

GRANTLESS_ACTIONS = frozenset({"inspect_repository", "analyze", "run_tests"})
PATH_BOUND_ACTIONS = frozenset(
    {
        "edit_scoped_files",
        "update_project_state",
        "commit",
        "plan_deployment",
        "apply_deployment",
        "observe_deployment",
        "collect_deployment_logs",
        "restart_deployment",
        "remove_deployment_runtime",
        "backup_deployment_data",
        "restore_deployment_data",
        "purge_deployment_data",
    }
)
BRANCH_BOUND_ACTIONS = frozenset(
    {
        "edit_scoped_files", "update_project_state", "commit", "create_managed_worktree",
        "export_workspace_evidence", "retire_owned_worktree", "push_private_branch",
        "push_integration_branch", "open_draft_pr", "merge", "tag",
        "plan_deployment", "apply_deployment", "observe_deployment",
        "collect_deployment_logs",
        "restart_deployment", "remove_deployment_runtime", "backup_deployment_data",
        "restore_deployment_data", "purge_deployment_data",
    }
)
PAUSE_EXEMPT_ACTIONS = frozenset({"inspect_repository", "analyze"})
GRANT_STATUSES = frozenset(
    {
        "active",
        "revoked",
        "policy_unbound",
        "policy_changed",
        "parent_inactive",
        "expired",
        "consumed",
        "budget_exhausted",
    }
)

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_GRANT_ID = re.compile(r"^grant_[A-Za-z0-9][A-Za-z0-9._-]{2,95}$")
_REQUEST_ID = re.compile(r"^authority_request_[0-9a-f]{32}$")
_RESERVATION_ID = re.compile(r"^authority_reservation_[0-9a-f]{32}$")
_CLAIM_ID = re.compile(r"^authority_claim_[0-9a-f]{32}$")
_RECEIPT_ID = re.compile(r"^authority_receipt_[0-9a-f]{32}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REPOSITORY_KEY = re.compile(r"^[0-9a-f]{32}$")
_ACTION = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$"
)
_MAX_JSON_BYTES = 4 * 1024 * 1024

T = TypeVar("T")


class AuthorityError(RuntimeError):
    """Authority policy or durable state is invalid."""

    def __init__(self, code: str, detail: str) -> None:
        if not isinstance(code, str) or not code:
            raise ValueError("authority error code is required")
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}")


class AuthorityRefusal(AuthorityError):
    """A typed authority decision refused execution."""

    def __init__(self, code: str, detail: str, *, receipt: Mapping[str, Any] | None = None) -> None:
        self.receipt = dict(receipt) if receipt is not None else None
        super().__init__(code, detail)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise AuthorityError("invalid_clock", "authority clock must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise AuthorityError("invalid_grant", f"{label} must be a UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise AuthorityError("invalid_grant", f"{label} is invalid") from exc
    if parsed.tzinfo is None:
        raise AuthorityError("invalid_grant", f"{label} must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise AuthorityError("invalid_contract", f"{label} must be a bounded identifier")
    return value


def _safe_origin(value: str | None) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str) or any(character in value for character in ("\n", "\r", "\x00")):
        raise AuthorityError("repository_identity_uncertain", "repository origin is invalid")
    parsed = urlsplit(value)
    if parsed.username is not None or parsed.password is not None:
        raise AuthorityError("repository_identity_uncertain", "repository origin may not contain credentials")
    return value


def _absolute_no_symlinks(path: Path, *, allow_missing: bool = True) -> Path:
    absolute = Path(os.path.abspath(os.fspath(path)))
    if "\x00" in os.fspath(absolute):
        raise AuthorityError("unsafe_path", "authority path contains NUL")
    cursor = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        cursor = cursor / part
        try:
            cursor.lstat()
        except FileNotFoundError:
            if allow_missing:
                continue
            raise AuthorityError("unsafe_path", f"required authority path is missing: {cursor}")
        if cursor.is_symlink():
            raise AuthorityError("unsafe_path", "authority path may not traverse a symlink")
    return absolute


def _safe_directory(path: Path, *, create: bool = False) -> Path:
    path = _absolute_no_symlinks(path)
    if create:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not path.is_dir() or path.is_symlink():
        raise AuthorityError("unsafe_state_store", f"authority directory is unsafe: {path}")
    os.chmod(path, 0o700)
    return path


def _confined(root: Path, path: Path, *, direct: bool = False) -> Path:
    root = _safe_directory(root, create=True)
    candidate = _absolute_no_symlinks(path)
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise AuthorityError("unsafe_path", "authority path escapes its store") from exc
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise AuthorityError("unsafe_path", "authority path must be below its store")
    if direct and len(relative.parts) != 1:
        raise AuthorityError("unsafe_path", "authority record must be a direct child")
    return candidate


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_json(path: Path, value: Mapping[str, Any], *, root: Path, create_only: bool = False) -> None:
    path = _confined(root, path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _safe_directory(path.parent)
    if path.exists():
        if path.is_symlink() or not path.is_file():
            raise AuthorityError("unsafe_state_store", "authority record target is unsafe")
        if create_only:
            raise AuthorityError("duplicate_record", f"authority record already exists: {path.name}")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(6)}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write((_canonical_json(dict(value)) + "\n").encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        if create_only and path.exists():
            raise AuthorityError("duplicate_record", f"authority record already exists: {path.name}")
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _read_json(path: Path, *, root: Path) -> dict[str, Any]:
    path = _confined(root, path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_JSON_BYTES:
        raise AuthorityError("invalid_authority_state", f"authority record is missing, unsafe, or oversized: {path.name}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AuthorityError("invalid_authority_state", f"authority record is malformed: {path.name}") from exc
    if not isinstance(value, dict):
        raise AuthorityError("invalid_authority_state", "authority record must be an object")
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


def _git(repository: Path, *args: str) -> str:
    try:
        completed = subprocess.run(
            ["git", "--no-replace-objects", "-c", "core.hooksPath=/dev/null", "-C", str(repository), *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            shell=False,
            env=_git_environment(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise AuthorityError("repository_identity_uncertain", "repository identity observation failed") from exc
    if completed.returncode != 0:
        raise AuthorityError("repository_identity_uncertain", "repository identity is unavailable")
    return completed.stdout.strip()


def _normalized_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise AuthorityError("invalid_grant", "scope path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".."} for part in path.parts):
        raise AuthorityError("invalid_grant", "scope paths must be normalized repository-relative paths")
    normalized = path.as_posix()
    return "." if normalized == "." else normalized.removeprefix("./")


def _path_is_within(path: str, prefix: str) -> bool:
    if prefix == ".":
        return True
    return path == prefix or path.startswith(prefix + "/")


def _normalized_source_identity(value: object) -> dict[str, Any] | None:
    if value is None:
        return None
    expected = {
        "repositoryIdentity",
        "projectPath",
        "commit",
        "treeDigest",
        "dirty",
        "dirtyDigest",
        "descriptorDigest",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise AuthorityError(
            "invalid_contract", "requested source identity is malformed"
        )
    normalized = dict(value)
    for name in (
        "repositoryIdentity",
        "treeDigest",
        "dirtyDigest",
        "descriptorDigest",
    ):
        if not isinstance(normalized[name], str) or _DIGEST.fullmatch(
            normalized[name]
        ) is None:
            raise AuthorityError(
                "invalid_contract", f"requested source {name} is invalid"
            )
    if not isinstance(normalized["commit"], str) or re.fullmatch(
        r"[0-9a-f]{40,64}", normalized["commit"]
    ) is None:
        raise AuthorityError("invalid_contract", "requested source commit is invalid")
    normalized["projectPath"] = _normalized_path(normalized["projectPath"])
    if not isinstance(normalized["dirty"], bool):
        raise AuthorityError(
            "invalid_contract", "requested source dirty status is invalid"
        )
    return normalized


def _branch_pattern(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not 1 <= len(value) <= 255:
        raise AuthorityError("invalid_grant", "branch pattern is invalid")
    if any(item in value for item in ("..", "//", "@{", "\\", "[", "]", "?")):
        raise AuthorityError("invalid_grant", "branch pattern contains unsupported Git or glob syntax")
    if value.count("*") > 1 or ("*" in value and not value.endswith("*")):
        raise AuthorityError("invalid_grant", "branch pattern supports only one trailing wildcard")
    wildcard = value.endswith("*")
    base = value[:-1] if wildcard else value
    if (
        not base
        or base.startswith("/")
        or (base.endswith("/") and not wildcard)
        or not re.fullmatch(r"[A-Za-z0-9._/-]+", base)
    ):
        raise AuthorityError("invalid_grant", "branch pattern is not a safe ref pattern")
    return value


def _pattern_narrower(child: str | None, parent: str | None) -> bool:
    if parent is None:
        return True
    if child is None:
        return False
    if not parent.endswith("*"):
        return child == parent
    parent_prefix = parent[:-1]
    child_prefix = child[:-1] if child.endswith("*") else child
    return child_prefix.startswith(parent_prefix)


@dataclass(frozen=True)
class RepositoryAuthorityIdentity:
    repository_key: str
    repository_root: str
    origin: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "repositoryKey": self.repository_key,
            "repositoryRoot": self.repository_root,
            "origin": self.origin,
        }


@dataclass(frozen=True)
class AuthorityPolicy:
    default_profile: str
    actions: Mapping[str, Mapping[str, Any]]
    profiles: Mapping[str, Mapping[str, Any]]
    hard_deny: frozenset[str]
    merge_requirements: frozenset[str]
    subagent_default_deny: frozenset[str]
    escalation_conditions: tuple[str, ...]
    policy_digest: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "AuthorityPolicy":
        expected = {
            "schema", "defaultProfile", "actionPolicies", "profiles", "hardDeny",
            "mergeRequirements", "subagentDefaultDeny", "escalationConditions",
        }
        if not isinstance(value, Mapping) or set(value) != expected or value.get("schema") != AUTHORITY_POLICY_SCHEMA:
            raise AuthorityError("invalid_policy", "authority policy has missing or unsupported fields")
        default_profile = value.get("defaultProfile")
        actions = value.get("actionPolicies")
        profiles = value.get("profiles")
        if default_profile not in AUTHORITY_PROFILES or not isinstance(actions, Mapping) or not actions:
            raise AuthorityError("invalid_policy", "authority profile or action vocabulary is invalid")
        if not isinstance(profiles, Mapping) or set(profiles) != AUTHORITY_PROFILES:
            raise AuthorityError("invalid_policy", "authority policy must define exactly four profiles")
        parsed_actions: dict[str, dict[str, Any]] = {}
        action_shape = {"risk", "reversible", "localMutation", "processLaunch", "remoteSideEffect"}
        for action, metadata in actions.items():
            if not isinstance(action, str) or _ACTION.fullmatch(action) is None:
                raise AuthorityError("invalid_policy", "authority action name is invalid")
            if not isinstance(metadata, Mapping) or set(metadata) != action_shape:
                raise AuthorityError("invalid_policy", f"action metadata is invalid: {action}")
            if metadata.get("risk") not in {"low", "medium", "high", "critical"}:
                raise AuthorityError("invalid_policy", f"action risk is invalid: {action}")
            if any(not isinstance(metadata.get(name), bool) for name in action_shape - {"risk"}):
                raise AuthorityError("invalid_policy", f"action flags are invalid: {action}")
            parsed_actions[action] = dict(metadata)
        parsed_profiles: dict[str, dict[str, Any]] = {}
        profile_shape = {"default", "autoWithReceipt", "approveScopeOnce", "autoAndNotify", "deny"}
        for profile, definition in profiles.items():
            if not isinstance(definition, Mapping) or set(definition) != profile_shape:
                raise AuthorityError("invalid_policy", f"authority profile is malformed: {profile}")
            if definition.get("default") not in AUTHORITY_MODES:
                raise AuthorityError("invalid_policy", f"authority profile default is invalid: {profile}")
            groups: dict[str, list[str]] = {}
            seen: set[str] = set()
            for name in profile_shape - {"default"}:
                group = definition.get(name)
                if (
                    not isinstance(group, list)
                    or any(not isinstance(item, str) for item in group)
                    or len(group) != len(set(group))
                    or any(item not in parsed_actions for item in group)
                ):
                    raise AuthorityError("invalid_policy", f"authority profile action group is invalid: {profile}.{name}")
                if seen.intersection(group):
                    raise AuthorityError("invalid_policy", f"authority profile action groups overlap: {profile}")
                seen.update(group)
                groups[name] = list(group)
            parsed_profiles[profile] = {"default": definition["default"], **groups}
        hard_deny = cls._action_set(value.get("hardDeny"), parsed_actions, "hardDeny")
        subagent_deny = cls._action_set(value.get("subagentDefaultDeny"), parsed_actions, "subagentDefaultDeny")
        merge_requirements = value.get("mergeRequirements")
        if (
            not isinstance(merge_requirements, list)
            or any(not isinstance(item, str) for item in merge_requirements)
            or len(merge_requirements) != len(set(merge_requirements))
            or set(merge_requirements) - {"exact_head_verified", "required_gates_passed"}
        ):
            raise AuthorityError("invalid_policy", "merge requirements are invalid")
        escalation = value.get("escalationConditions")
        if (
            not isinstance(escalation, list)
            or not escalation
            or any(not isinstance(item, str) for item in escalation)
            or len(escalation) != len(set(escalation))
        ):
            raise AuthorityError("invalid_policy", "escalation conditions are invalid")
        if any(not isinstance(item, str) or _ACTION.fullmatch(item) is None for item in escalation):
            raise AuthorityError("invalid_policy", "escalation condition name is invalid")
        return cls(
            default_profile=default_profile,
            actions=parsed_actions,
            profiles=parsed_profiles,
            hard_deny=hard_deny,
            merge_requirements=frozenset(merge_requirements),
            subagent_default_deny=subagent_deny,
            escalation_conditions=tuple(escalation),
            policy_digest=_digest(value),
        )

    @staticmethod
    def _action_set(value: object, actions: Mapping[str, Any], label: str) -> frozenset[str]:
        if (
            not isinstance(value, list)
            or any(not isinstance(item, str) for item in value)
            or len(value) != len(set(value))
            or any(item not in actions for item in value)
        ):
            raise AuthorityError("invalid_policy", f"{label} is invalid")
        return frozenset(value)

    @classmethod
    def from_file(cls, path: Path) -> "AuthorityPolicy":
        if path.is_symlink() or not path.is_file():
            raise AuthorityError("invalid_policy", "authority policy is missing or unsafe")
        try:
            import yaml
        except ImportError as exc:
            raise AuthorityError("invalid_policy", "authority policy parser is unavailable") from exc
        try:
            value = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, yaml.YAMLError) as exc:
            raise AuthorityError("invalid_policy", "authority policy could not be loaded") from exc
        if not isinstance(value, Mapping):
            raise AuthorityError("invalid_policy", "authority policy must be a mapping")
        return cls.from_mapping(value)

    def mode_for(self, profile: str, action: str, custom: Mapping[str, str] | None = None) -> str:
        if profile not in AUTHORITY_PROFILES or action not in self.actions:
            raise AuthorityError("invalid_contract", "unknown authority profile or action")
        if profile == "custom":
            if custom is None or set(custom) != set(self.actions) or any(mode not in AUTHORITY_MODES for mode in custom.values()):
                raise AuthorityError("invalid_grant", "custom profile requires one policy for every action")
            return custom[action]
        definition = self.profiles[profile]
        groups = {
            "autoWithReceipt": "auto_with_receipt",
            "approveScopeOnce": "approve_scope_once",
            "autoAndNotify": "auto_and_notify",
            "deny": "deny",
        }
        for group, mode in groups.items():
            if action in definition[group]:
                return mode
        return str(definition["default"])


class AuthorityLock:
    """A non-blocking per-repository authority-store lock."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._descriptor: int | None = None

    def __enter__(self) -> "AuthorityLock":
        _safe_directory(self.path.parent, create=True)
        descriptor = os.open(self.path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(descriptor)
            raise AuthorityRefusal("authority_store_busy", "another authority transaction is active") from exc
        self._descriptor = descriptor
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        del exc_type, exc, traceback
        if self._descriptor is not None:
            descriptor = self._descriptor
            self._descriptor = None
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)
        return False


class AuthorityManager:
    """Evaluate scoped grants and persist inspectable authority receipts."""

    def __init__(
        self,
        repository: Path | str,
        *,
        state_root: Path | str | None = None,
        policy: AuthorityPolicy | None = None,
        policy_path: Path | str | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        supplied = _absolute_no_symlinks(Path(repository), allow_missing=False)
        if not supplied.is_dir():
            raise AuthorityError("repository_identity_uncertain", "repository must be an existing directory")
        checkout_root = Path(_git(supplied, "rev-parse", "--path-format=absolute", "--show-toplevel")).resolve(strict=True)
        common = Path(_git(supplied, "rev-parse", "--path-format=absolute", "--git-common-dir")).resolve(strict=True)
        root = common.parent.resolve(strict=True) if common.name == ".git" else checkout_root
        if not root.is_dir() or root.is_symlink():
            raise AuthorityError("repository_identity_uncertain", "canonical repository root is unsafe")
        origin_result = subprocess.run(
            ["git", "--no-replace-objects", "-c", "core.hooksPath=/dev/null", "-C", str(root), "config", "--get", "remote.origin.url"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            shell=False,
            env=_git_environment(),
        )
        if origin_result.returncode not in {0, 1}:
            raise AuthorityError("repository_identity_uncertain", "repository origin is unavailable")
        origin = _safe_origin(origin_result.stdout.strip() if origin_result.returncode == 0 else None)
        seed = {"repositoryRoot": root.as_posix(), "commonGitDir": common.as_posix(), "origin": origin}
        repository_key = hashlib.sha256(_canonical_json(seed).encode("utf-8")).hexdigest()[:32]
        self.repository = root
        self.checkout = checkout_root
        self.identity = RepositoryAuthorityIdentity(repository_key, root.as_posix(), origin)
        selected_policy = _absolute_no_symlinks(
            Path(policy_path) if policy_path is not None else checkout_root / "config/authority-policy.v1.yaml",
            allow_missing=False,
        )
        self.policy = policy or AuthorityPolicy.from_file(selected_policy)
        if state_root is None:
            xdg = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state"))
            state_root = xdg / "stateport" / "authority"
        candidate_root = _absolute_no_symlinks(Path(state_root))
        if candidate_root in {root, checkout_root} or root in candidate_root.parents or checkout_root in candidate_root.parents:
            raise AuthorityError("unsafe_state_store", "authority state must remain outside the repository")
        self.state_root = _safe_directory(candidate_root, create=True)
        self.repository_store = _safe_directory(
            self.state_root / "repositories" / self.identity.repository_key,
            create=True,
        )
        self.grants_root = _safe_directory(self.repository_store / "grants", create=True)
        self.revocations_root = _safe_directory(self.repository_store / "revocations", create=True)
        self.reservations_root = _safe_directory(
            self.repository_store / "reservations", create=True
        )
        self.claims_root = _safe_directory(
            self.repository_store / "claims", create=True
        )
        self.receipts_root = _safe_directory(self.repository_store / "receipts", create=True)
        self.recovery_root = _safe_directory(self.repository_store / "recovery", create=True)
        self.closures_root = _safe_directory(self.repository_store / "scope-closures", create=True)
        self.control_path = self.repository_store / "control.json"
        self.lock_path = self.repository_store / "authority.lock"

    def _now(self) -> datetime:
        return _parse_timestamp(_timestamp(self._clock()), "clock")

    def lock(self) -> AuthorityLock:
        return AuthorityLock(self.lock_path)

    def _grant_path(self, grant_id: str) -> Path:
        if _GRANT_ID.fullmatch(grant_id) is None:
            raise AuthorityError("invalid_contract", "grant id is invalid")
        return self.grants_root / f"{grant_id}.json"

    def _revocation_path(self, grant_id: str) -> Path:
        if _GRANT_ID.fullmatch(grant_id) is None:
            raise AuthorityError("invalid_contract", "grant id is invalid")
        return self.revocations_root / f"{grant_id}.json"

    def _receipt_path(self, receipt_id: str) -> Path:
        if _RECEIPT_ID.fullmatch(receipt_id) is None:
            raise AuthorityError("invalid_contract", "authority receipt id is invalid")
        return self.receipts_root / f"{receipt_id}.json"

    def _recovery_path(self, operation: str, target_id: str) -> Path:
        key = hashlib.sha256(f"{operation}:{target_id}".encode("utf-8")).hexdigest()[:32]
        return self.recovery_root / f"{operation}_{key}.json"

    def _begin_recovery_attention(self, operation: str, target_id: str) -> None:
        if self.recovery_attention():
            raise AuthorityRefusal(
                "authority_recovery_required",
                "authority state has an unresolved pause or revocation transaction",
            )
        record = {
            "schema": AUTHORITY_RECOVERY_SCHEMA,
            "operation": operation,
            "targetId": target_id,
            "status": "attention_required",
            "reason": "canonical authority state and receipt commit must be reconciled",
            "detectedAt": _timestamp(self._now()),
        }
        _atomic_json(self._recovery_path(operation, target_id), record, root=self.repository_store)

    def _clear_recovery_attention(self, operation: str, target_id: str) -> None:
        path = self._recovery_path(operation, target_id)
        if path.exists():
            path.unlink()
            _fsync_directory(self.recovery_root)

    def recovery_attention(self) -> list[dict[str, Any]]:
        attention: list[dict[str, Any]] = []
        for path in sorted(self.recovery_root.glob("*.json")):
            record = _read_json(path, root=self.repository_store)
            expected = {"schema", "operation", "targetId", "status", "reason", "detectedAt"}
            if set(record) != expected or record.get("schema") != AUTHORITY_RECOVERY_SCHEMA or record.get("status") != "attention_required":
                raise AuthorityError("invalid_authority_state", "authority recovery attention record is malformed")
            attention.append(record)
        return attention

    def _reservation_path(self, reservation_id: str) -> Path:
        if _RESERVATION_ID.fullmatch(reservation_id) is None:
            raise AuthorityError("invalid_contract", "authority reservation id is invalid")
        return self.reservations_root / f"{reservation_id}.json"

    def _claim_path(self, claim_id: str) -> Path:
        if _CLAIM_ID.fullmatch(claim_id) is None:
            raise AuthorityError("invalid_contract", "authority claim id is invalid")
        return self.claims_root / f"{claim_id}.json"

    def _scope_closure_path(self, kind: str, scope_id: str) -> Path:
        if kind not in {"slice", "run"}:
            raise AuthorityError("invalid_contract", "scope closure kind is invalid")
        _identifier(scope_id, f"{kind} id")
        name = hashlib.sha256(f"{kind}:{scope_id}".encode("utf-8")).hexdigest()
        return self.closures_root / f"{name}.json"

    def _validate_scope(self, value: object) -> dict[str, Any]:
        expected = {
            "repository",
            "branchPattern",
            "sliceId",
            "applicationId",
            "runId",
            "paths",
        }
        supported = {frozenset(expected), frozenset(expected | {"deploymentSources"})}
        if not isinstance(value, Mapping) or frozenset(value) not in supported:
            raise AuthorityError("invalid_grant", "grant scope is malformed")
        repository = value.get("repository")
        if not isinstance(repository, Mapping) or set(repository) != {"repositoryKey", "repositoryRoot", "origin"}:
            raise AuthorityError("invalid_grant", "grant repository scope is malformed")
        if repository.get("repositoryKey") != self.identity.repository_key:
            raise AuthorityError("invalid_grant", "grant repository key does not match the observed repository")
        if repository.get("repositoryRoot") != self.identity.repository_root:
            raise AuthorityError("invalid_grant", "grant repository root does not match the observed repository")
        if _safe_origin(repository.get("origin")) != self.identity.origin:
            raise AuthorityError("invalid_grant", "grant repository origin does not match the observed repository")
        branch_pattern = _branch_pattern(value.get("branchPattern"))
        identifiers: dict[str, str | None] = {}
        for name in ("sliceId", "applicationId", "runId"):
            item = value.get(name)
            identifiers[name] = None if item is None else _identifier(item, name)
        paths = value.get("paths")
        if not isinstance(paths, list) or not paths or any(not isinstance(item, str) for item in paths):
            raise AuthorityError("invalid_grant", "grant scope paths must be a non-empty unique list")
        normalized = [_normalized_path(item) for item in paths]
        if len(normalized) != len(set(normalized)):
            raise AuthorityError("invalid_grant", "grant scope paths normalize to duplicates")
        normalized_scope: dict[str, Any] = {
            "repository": self.identity.to_dict(),
            "branchPattern": branch_pattern,
            **identifiers,
            "paths": normalized,
        }
        if "deploymentSources" in value:
            sources = value.get("deploymentSources")
            if not isinstance(sources, list) or not sources:
                raise AuthorityError(
                    "invalid_grant",
                    "deployment source scope must be a non-empty exact list",
                )
            normalized_sources: list[dict[str, str]] = []
            for source in sources:
                if not isinstance(source, Mapping) or set(source) != {
                    "repositoryIdentity",
                    "projectPath",
                }:
                    raise AuthorityError(
                        "invalid_grant", "deployment source selector is malformed"
                    )
                repository_identity = source.get("repositoryIdentity")
                if (
                    not isinstance(repository_identity, str)
                    or _DIGEST.fullmatch(repository_identity) is None
                ):
                    raise AuthorityError(
                        "invalid_grant",
                        "deployment source repository identity is invalid",
                    )
                try:
                    project_path = _normalized_path(source.get("projectPath"))
                except AuthorityError as exc:
                    raise AuthorityError(
                        "invalid_grant",
                        "deployment source project path is invalid",
                    ) from exc
                normalized_sources.append(
                    {
                        "repositoryIdentity": repository_identity,
                        "projectPath": project_path,
                    }
                )
            canonical_sources = sorted(
                normalized_sources,
                key=lambda item: (
                    item["repositoryIdentity"],
                    item["projectPath"],
                ),
            )
            if len({(item["repositoryIdentity"], item["projectPath"]) for item in canonical_sources}) != len(canonical_sources):
                raise AuthorityError(
                    "invalid_grant", "deployment source selectors contain duplicates"
                )
            normalized_scope["deploymentSources"] = canonical_sources
        return normalized_scope

    def _validate_action_list(self, value: object, label: str) -> list[str]:
        if (
            not isinstance(value, list)
            or any(not isinstance(item, str) for item in value)
            or len(value) != len(set(value))
            or any(item not in self.policy.actions for item in value)
        ):
            raise AuthorityError("invalid_grant", f"{label} must contain unique known action classes")
        return list(value)

    def _validate_limits(self, value: object) -> dict[str, Any]:
        expected = {
            "maxActions", "maxDurationSeconds", "maxCostUsd", "network",
            "allowedDomains", "providers", "secretCapabilities",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise AuthorityError("invalid_grant", "grant limits are malformed")
        parsed: dict[str, Any] = {}
        for name in ("maxActions", "maxDurationSeconds"):
            number = value.get(name)
            if number is not None and (isinstance(number, bool) or not isinstance(number, int) or number < 1):
                raise AuthorityError("invalid_grant", f"{name} is invalid")
            parsed[name] = number
        cost = value.get("maxCostUsd")
        if cost is not None and (isinstance(cost, bool) or not isinstance(cost, (int, float)) or cost < 0):
            raise AuthorityError("invalid_grant", "maxCostUsd is invalid")
        parsed["maxCostUsd"] = None if cost is None else float(cost)
        network = value.get("network")
        if network not in NETWORK_MODES:
            raise AuthorityError("invalid_grant", "network limit is invalid")
        parsed["network"] = network
        for name in ("allowedDomains", "providers", "secretCapabilities"):
            items = value.get(name)
            if not isinstance(items, list) or any(not isinstance(item, str) for item in items):
                raise AuthorityError("invalid_grant", f"{name} must be a unique list")
            if len(items) != len(set(items)):
                raise AuthorityError("invalid_grant", f"{name} must be a unique list")
            if any(not 1 <= len(item) <= (253 if name == "allowedDomains" else 128) for item in items):
                raise AuthorityError("invalid_grant", f"{name} contains an invalid value")
            if name == "allowedDomains" and any(_DOMAIN.fullmatch(item) is None for item in items):
                raise AuthorityError("invalid_grant", "allowedDomains contains an invalid domain")
            parsed[name] = list(items)
        if network == "denied" and parsed["allowedDomains"]:
            raise AuthorityError("invalid_grant", "denied network grants cannot carry allowed domains")
        if network == "unrestricted" and parsed["allowedDomains"]:
            raise AuthorityError("invalid_grant", "unrestricted network grants do not use an allowlist")
        return parsed

    def prepare_grant(self, value: Mapping[str, Any]) -> dict[str, Any]:
        """Validate and canonicalize a grant, filling its digest when omitted."""

        expected = {
            "schema", "grantId", "kind", "profile", "subject", "scope", "allow",
            "requireApproval", "forbid", "customPolicies", "limits", "issuedAt",
            "expiresWhen", "expiresAt", "ownerDirectiveId", "parentGrantId",
            "canDelegate", "grantDigest",
        }
        supported_shapes = {frozenset(expected), frozenset(expected | {"policyDigest"})}
        if not isinstance(value, Mapping) or frozenset(value) not in supported_shapes or value.get("schema") != AUTHORITY_GRANT_SCHEMA:
            raise AuthorityError("invalid_grant", "grant has missing or unsupported fields")
        legacy_unbound = "policyDigest" not in value
        policy_digest = value.get("policyDigest")
        if not legacy_unbound and (not isinstance(policy_digest, str) or _DIGEST.fullmatch(policy_digest) is None):
            raise AuthorityError("invalid_grant", "grant policy digest is invalid")
        grant_id = value.get("grantId")
        if not isinstance(grant_id, str) or _GRANT_ID.fullmatch(grant_id) is None:
            raise AuthorityError("invalid_grant", "grant id is invalid")
        kind = value.get("kind")
        profile = value.get("profile")
        if kind not in GRANT_KINDS or profile not in AUTHORITY_PROFILES:
            raise AuthorityError("invalid_grant", "grant kind or profile is invalid")
        subject = value.get("subject")
        if not isinstance(subject, Mapping) or set(subject) != {"actorId", "role"}:
            raise AuthorityError("invalid_grant", "grant subject is malformed")
        actor_id = _identifier(subject.get("actorId"), "subject actor id")
        role = subject.get("role")
        if role not in SUBJECT_ROLES:
            raise AuthorityError("invalid_grant", "grant subject role is invalid")
        scope = self._validate_scope(value.get("scope"))
        allow = self._validate_action_list(value.get("allow"), "allow")
        require_approval = self._validate_action_list(value.get("requireApproval"), "requireApproval")
        forbid = self._validate_action_list(value.get("forbid"), "forbid")
        if set(allow) & set(require_approval) or set(allow) & set(forbid) or set(require_approval) & set(forbid):
            raise AuthorityError("conflicting_policy_rules", "grant action lists overlap")
        custom = value.get("customPolicies")
        if not isinstance(custom, Mapping) or any(key not in self.policy.actions or mode not in AUTHORITY_MODES for key, mode in custom.items()):
            raise AuthorityError("invalid_grant", "custom action policies are invalid")
        if profile == "custom" and set(custom) != set(self.policy.actions):
            raise AuthorityError("invalid_grant", "custom grants must classify every action")
        if profile != "custom" and custom:
            raise AuthorityError("invalid_grant", "non-custom grants cannot carry custom action policies")
        limits = self._validate_limits(value.get("limits"))
        issued_at = _parse_timestamp(value.get("issuedAt"), "issuedAt")
        expiry = value.get("expiresWhen")
        expires_at_value = value.get("expiresAt")
        if expiry not in EXPIRY_MODES:
            raise AuthorityError("invalid_grant", "grant expiry mode is invalid")
        if expiry == "slice_closed" and scope["sliceId"] is None:
            raise AuthorityError("invalid_grant", "slice-closed expiry requires a slice scope")
        if expiry == "run_closed" and scope["runId"] is None:
            raise AuthorityError("invalid_grant", "run-closed expiry requires a run scope")
        if expiry == "timestamp":
            expires_at = _parse_timestamp(expires_at_value, "expiresAt")
            if expires_at <= issued_at:
                raise AuthorityError("invalid_grant", "grant expiry must follow issuance")
            normalized_expiry = _timestamp(expires_at)
        elif expires_at_value is not None:
            raise AuthorityError("invalid_grant", "expiresAt is only valid for timestamp expiry")
        else:
            normalized_expiry = None
        owner_directive_id = _identifier(value.get("ownerDirectiveId"), "owner directive id")
        parent = value.get("parentGrantId")
        if parent is not None and (not isinstance(parent, str) or _GRANT_ID.fullmatch(parent) is None):
            raise AuthorityError("invalid_grant", "parent grant id is invalid")
        if role == "subagent" and parent is None:
            raise AuthorityError("invalid_grant", "subagent grants require a parent grant")
        if role != "subagent" and parent is not None:
            raise AuthorityError("invalid_grant", "only subagent grants may name a parent grant")
        can_delegate = value.get("canDelegate")
        if not isinstance(can_delegate, bool) or (role == "subagent" and can_delegate):
            raise AuthorityError("invalid_grant", "subagents cannot delegate authority")
        body = {
            "schema": AUTHORITY_GRANT_SCHEMA,
            "grantId": grant_id,
            "kind": kind,
            "profile": profile,
            "subject": {"actorId": actor_id, "role": role},
            "scope": scope,
            "allow": allow,
            "requireApproval": require_approval,
            "forbid": forbid,
            "customPolicies": dict(custom),
            "limits": limits,
            "issuedAt": _timestamp(issued_at),
            "expiresWhen": expiry,
            "expiresAt": normalized_expiry,
            "ownerDirectiveId": owner_directive_id,
            "parentGrantId": parent,
            "canDelegate": can_delegate,
        }
        digest_body = body if legacy_unbound else {**body, "policyDigest": policy_digest}
        expected_digest = _digest(digest_body)
        supplied_digest = value.get("grantDigest")
        if supplied_digest not in {None, expected_digest}:
            raise AuthorityError("invalid_grant", "grant digest is invalid")
        return {**body, "policyDigest": policy_digest, "grantDigest": expected_digest}

    def _load_grant_unlocked(self, grant_id: str) -> dict[str, Any]:
        path = self._grant_path(grant_id)
        if not path.exists():
            raise AuthorityError("grant_not_found", "authority grant does not exist")
        return self.prepare_grant(_read_json(path, root=self.repository_store))

    def get_grant(self, grant_id: str) -> dict[str, Any]:
        with self.lock():
            grant = self._load_grant_unlocked(grant_id)
            return {**grant, "status": self._grant_status_unlocked(grant)}

    def _base_mode(self, grant: Mapping[str, Any], action: str) -> str:
        mode = self.policy.mode_for(grant["profile"], action, grant["customPolicies"])
        if action in grant["forbid"]:
            return "deny"
        if action in grant["requireApproval"]:
            return "ask_each_time"
        if action in grant["allow"]:
            return "auto_with_receipt"
        return mode

    def _assert_child_is_narrower(self, child: Mapping[str, Any], parent: Mapping[str, Any]) -> None:
        if not parent["canDelegate"]:
            raise AuthorityRefusal("delegation_not_allowed", "parent grant cannot delegate")
        if self._grant_status_unlocked(parent) != "active":
            raise AuthorityRefusal("grant_inactive", "parent grant is not active")
        child_scope = child["scope"]
        parent_scope = parent["scope"]
        if not _pattern_narrower(child_scope["branchPattern"], parent_scope["branchPattern"]):
            raise AuthorityRefusal("delegation_scope_broadened", "subagent branch scope exceeds its parent")
        for name in ("sliceId", "applicationId", "runId"):
            parent_value = parent_scope[name]
            if parent_value is not None and child_scope[name] != parent_value:
                raise AuthorityRefusal("delegation_scope_broadened", f"subagent {name} scope exceeds its parent")
        if any(not any(_path_is_within(path, prefix) for prefix in parent_scope["paths"]) for path in child_scope["paths"]):
            raise AuthorityRefusal("delegation_scope_broadened", "subagent file scope exceeds its parent")
        child_sources = child_scope.get("deploymentSources")
        parent_sources = parent_scope.get("deploymentSources")
        if child_sources is not None and (
            parent_sources is None
            or not {
                (item["repositoryIdentity"], item["projectPath"])
                for item in child_sources
            }.issubset(
                {
                    (item["repositoryIdentity"], item["projectPath"])
                    for item in parent_sources
                }
            )
        ):
            raise AuthorityRefusal(
                "delegation_scope_broadened",
                "subagent deployment source scope exceeds its parent",
            )
        permissiveness = {
            "deny": 0,
            "ask_each_time": 1,
            "approve_scope_once": 2,
            "auto_and_notify": 3,
            "auto_with_receipt": 3,
        }
        for action in self.policy.actions:
            child_mode = self._base_mode(child, action)
            parent_mode = self._base_mode(parent, action)
            if permissiveness[child_mode] > permissiveness[parent_mode]:
                raise AuthorityRefusal("delegation_authority_broadened", f"subagent action exceeds parent: {action}")
        child_limits = child["limits"]
        parent_limits = parent["limits"]
        for name in ("maxActions", "maxDurationSeconds", "maxCostUsd"):
            parent_limit = parent_limits[name]
            child_limit = child_limits[name]
            if parent_limit is not None and (child_limit is None or child_limit > parent_limit):
                raise AuthorityRefusal("delegation_budget_broadened", f"subagent {name} exceeds its parent")
        network_rank = {"denied": 0, "allowlisted": 1, "unrestricted": 2}
        if network_rank[child_limits["network"]] > network_rank[parent_limits["network"]]:
            raise AuthorityRefusal("delegation_capability_broadened", "subagent network scope exceeds its parent")
        if parent_limits["network"] == "allowlisted" and not set(child_limits["allowedDomains"]).issubset(parent_limits["allowedDomains"]):
            raise AuthorityRefusal("delegation_capability_broadened", "subagent domains exceed its parent")
        for name in ("providers", "secretCapabilities"):
            if not set(child_limits[name]).issubset(parent_limits[name]):
                raise AuthorityRefusal("delegation_capability_broadened", f"subagent {name} exceed its parent")

    def _owner_receipt_unlocked(
        self,
        *,
        actor_id: str,
        owner_directive_id: str,
        summary: str,
        resource: Mapping[str, Any],
    ) -> dict[str, Any]:
        now = self._now()
        request_id = f"authority_request_{secrets.token_hex(16)}"
        authorized_by = {"type": "owner_directive", "id": owner_directive_id, "digest": None}
        scope = {
            "repository": self.identity.to_dict(),
            "branch": None,
            "sliceId": None,
            "applicationId": None,
            "runId": None,
            "paths": [],
        }
        decision_body = {
            "schema": AUTHORITY_DECISION_SCHEMA,
            "requestId": request_id,
            "action": "modify_authority_policy",
            "actorId": actor_id,
            "authorizedBy": authorized_by,
            "scope": scope,
            "profile": self.policy.default_profile,
            "configuredPolicy": "ask_each_time",
            "policy": "auto_with_receipt",
            "decision": "authorized",
            "reason": "explicit_owner_directive",
            "missingAssurances": [],
            "estimatedCostUsd": 0.0,
            "estimatedDurationSeconds": 0,
            "requestedCapabilities": {
                "domains": [],
                "provider": None,
                "secretCapabilities": [],
                "assurances": [],
                "sourceIdentity": None,
            },
            "decidedAt": _timestamp(now),
        }
        decision = {**decision_body, "decisionDigest": _digest(decision_body)}
        receipt_id = f"authority_receipt_{secrets.token_hex(16)}"
        body = {
            "schema": AUTHORITY_ACTION_RECEIPT_SCHEMA,
            "receiptId": receipt_id,
            "requestId": request_id,
            "action": "modify_authority_policy",
            "actorId": actor_id,
            "authorizedBy": authorized_by,
            "scope": scope,
            "profile": self.policy.default_profile,
            "configuredPolicy": "ask_each_time",
            "policy": "auto_with_receipt",
            "decision": "authorized",
            "result": {"status": "succeeded", "code": None, "summary": summary, "resource": dict(resource)},
            "startedAt": _timestamp(now),
            "completedAt": _timestamp(self._now()),
            "estimatedCostUsd": 0.0,
            "actualCostUsd": 0.0,
            "decisionDigest": decision["decisionDigest"],
            "reservation": None,
            "claim": None,
        }
        receipt = {**body, "receiptDigest": _digest(body)}
        _atomic_json(self._receipt_path(receipt_id), receipt, root=self.repository_store, create_only=True)
        return receipt

    def activate_grant(self, value: Mapping[str, Any], *, owner_actor_id: str) -> dict[str, Any]:
        grant = self.prepare_grant(value)
        _identifier(owner_actor_id, "owner actor id")
        if grant["policyDigest"] != self.policy.policy_digest:
            raise AuthorityError("invalid_grant", "new grants must bind the exact active authority policy")
        with self.lock():
            if grant["parentGrantId"] is not None:
                parent = self._load_grant_unlocked(grant["parentGrantId"])
                self._assert_child_is_narrower(grant, parent)
            _atomic_json(self._grant_path(grant["grantId"]), grant, root=self.repository_store, create_only=True)
            receipt = self._owner_receipt_unlocked(
                actor_id=owner_actor_id,
                owner_directive_id=grant["ownerDirectiveId"],
                summary="Owner-authorized standing authority grant was activated",
                resource={"grantId": grant["grantId"], "grantDigest": grant["grantDigest"]},
            )
        return {"grant": grant, "receipt": receipt}

    def _load_receipts_unlocked(self) -> list[dict[str, Any]]:
        receipts: list[dict[str, Any]] = []
        for path in sorted(self.receipts_root.iterdir()):
            if not path.is_file() or path.is_symlink() or path.suffix != ".json":
                raise AuthorityError("invalid_authority_state", "authority receipt directory contains an unsafe entry")
            receipt = _read_json(path, root=self.repository_store)
            if receipt.get("schema") != AUTHORITY_ACTION_RECEIPT_SCHEMA:
                raise AuthorityError("invalid_authority_state", "authority receipt schema is unsupported")
            body = {key: value for key, value in receipt.items() if key != "receiptDigest"}
            if receipt.get("receiptDigest") != _digest(body):
                raise AuthorityError("invalid_authority_state", "authority receipt digest is invalid")
            if "reservation" in receipt or "claim" in receipt:
                reservation_ref = receipt.get("reservation")
                claim_ref = receipt.get("claim")
                result = receipt.get("result", {})
                executed = (
                    receipt.get("decision") == "authorized"
                    and isinstance(result, Mapping)
                    and result.get("status") in {"succeeded", "failed"}
                    and receipt.get("authorizedBy", {}).get("type")
                    != "owner_directive"
                )
                if isinstance(reservation_ref, Mapping):
                    canonical_reservation = self._load_reservation_unlocked(
                        str(receipt.get("requestId", ""))
                    )
                    if reservation_ref != {
                        "reservationId": canonical_reservation["reservationId"],
                        "reservationDigest": canonical_reservation[
                            "reservationDigest"
                        ],
                    } or canonical_reservation["decision"].get(
                        "decisionDigest"
                    ) != receipt.get("decisionDigest"):
                        raise AuthorityError(
                            "invalid_authority_state",
                            "authority receipt reservation binding is invalid",
                        )
                elif executed:
                    raise AuthorityError(
                        "invalid_authority_state",
                        "executed authority receipt lacks a reservation",
                    )
                if isinstance(claim_ref, Mapping):
                    canonical_claim = self._load_claim_unlocked(
                        str(receipt.get("requestId", ""))
                    )
                    if claim_ref != {
                        "claimId": canonical_claim["claimId"],
                        "claimDigest": canonical_claim["claimDigest"],
                    }:
                        raise AuthorityError(
                            "invalid_authority_state",
                            "authority receipt claim binding is invalid",
                        )
                elif executed:
                    raise AuthorityError(
                        "invalid_authority_state",
                        "executed authority receipt lacks an effect claim",
                    )
            receipts.append(receipt)
        receipts.sort(key=lambda item: (str(item.get("completedAt", "")), str(item.get("receiptId", ""))))
        return receipts

    def get_receipt(self, receipt_id: str) -> dict[str, Any]:
        with self.lock():
            receipt = _read_json(self._receipt_path(receipt_id), root=self.repository_store)
            body = {key: value for key, value in receipt.items() if key != "receiptDigest"}
            if receipt.get("schema") != AUTHORITY_ACTION_RECEIPT_SCHEMA or receipt.get("receiptDigest") != _digest(body):
                raise AuthorityError("invalid_authority_state", "authority receipt is malformed or has an invalid digest")
            return receipt

    def get_receipt_for_request(
        self, request_id: str
    ) -> dict[str, Any] | None:
        """Resolve the unique terminal receipt for an exact authority request."""

        if _REQUEST_ID.fullmatch(request_id) is None:
            raise AuthorityError("invalid_contract", "authority request id is invalid")
        with self.lock():
            matches = [
                receipt
                for receipt in self._load_receipts_unlocked()
                if receipt.get("requestId") == request_id
            ]
            if len(matches) > 1:
                raise AuthorityError(
                    "invalid_authority_state",
                    "authority request has multiple terminal receipts",
                )
            return matches[0] if matches else None

    @staticmethod
    def _reservation_id(request_id: str) -> str:
        if _REQUEST_ID.fullmatch(request_id) is None:
            raise AuthorityError("invalid_contract", "authority request id is invalid")
        return "authority_reservation_" + request_id.removeprefix(
            "authority_request_"
        )

    @staticmethod
    def _claim_id(request_id: str) -> str:
        if _REQUEST_ID.fullmatch(request_id) is None:
            raise AuthorityError("invalid_contract", "authority request id is invalid")
        return "authority_claim_" + request_id.removeprefix("authority_request_")

    def _load_reservations_unlocked(self) -> list[dict[str, Any]]:
        reservations: list[dict[str, Any]] = []
        for path in sorted(self.reservations_root.iterdir()):
            if not path.is_file() or path.is_symlink() or path.suffix != ".json":
                raise AuthorityError(
                    "invalid_authority_state",
                    "authority reservation directory contains an unsafe entry",
                )
            reservation = _read_json(path, root=self.repository_store)
            expected = {
                "schema",
                "reservationId",
                "requestId",
                "decision",
                "reservedAt",
                "reservationDigest",
            }
            body = {
                key: value
                for key, value in reservation.items()
                if key != "reservationDigest"
            }
            decision = reservation.get("decision")
            if (
                set(reservation) != expected
                or reservation.get("schema")
                != AUTHORITY_ACTION_RESERVATION_SCHEMA
                or reservation.get("reservationDigest") != _digest(body)
                or not isinstance(decision, Mapping)
                or decision.get("schema") != AUTHORITY_DECISION_SCHEMA
                or reservation.get("requestId") != decision.get("requestId")
                or reservation.get("reservationId")
                != self._reservation_id(str(reservation.get("requestId", "")))
            ):
                raise AuthorityError(
                    "invalid_authority_state",
                    "authority reservation is malformed or has an invalid digest",
                )
            decision_body = {
                key: value
                for key, value in decision.items()
                if key != "decisionDigest"
            }
            if decision.get("decisionDigest") != _digest(decision_body):
                raise AuthorityError(
                    "invalid_authority_state",
                    "reserved authority decision has an invalid digest",
                )
            reservations.append(reservation)
        reservations.sort(
            key=lambda item: (str(item.get("reservedAt", "")), item["reservationId"])
        )
        return reservations

    def _load_reservation_unlocked(self, request_id: str) -> dict[str, Any]:
        reservation_id = self._reservation_id(request_id)
        reservation = _read_json(
            self._reservation_path(reservation_id), root=self.repository_store
        )
        matches = [
            item
            for item in self._load_reservations_unlocked()
            if item["reservationId"] == reservation_id
        ]
        if len(matches) != 1 or matches[0] != reservation:
            raise AuthorityError(
                "invalid_authority_state", "authority reservation identity is invalid"
            )
        return reservation

    def get_reservation(self, request_id: str) -> dict[str, Any]:
        with self.lock():
            return self._load_reservation_unlocked(request_id)

    def _load_claim_unlocked(self, request_id: str) -> dict[str, Any]:
        claim_id = self._claim_id(request_id)
        claim = _read_json(
            self._claim_path(claim_id), root=self.repository_store
        )
        expected = {
            "schema",
            "claimId",
            "requestId",
            "reservationId",
            "reservationDigest",
            "decisionDigest",
            "claimedAt",
            "claimDigest",
        }
        body = {key: value for key, value in claim.items() if key != "claimDigest"}
        if (
            set(claim) != expected
            or claim.get("schema") != AUTHORITY_ACTION_CLAIM_SCHEMA
            or claim.get("claimId") != claim_id
            or claim.get("requestId") != request_id
            or claim.get("claimDigest") != _digest(body)
        ):
            raise AuthorityError(
                "invalid_authority_state",
                "authority claim is malformed or has an invalid digest",
            )
        reservation = self._load_reservation_unlocked(request_id)
        if (
            claim.get("reservationId") != reservation["reservationId"]
            or claim.get("reservationDigest") != reservation["reservationDigest"]
            or claim.get("decisionDigest")
            != reservation["decision"].get("decisionDigest")
        ):
            raise AuthorityError(
                "invalid_authority_state",
                "authority claim does not bind its canonical reservation",
            )
        return claim

    def get_claim(self, request_id: str) -> dict[str, Any]:
        with self.lock():
            return self._load_claim_unlocked(request_id)

    def has_claim(self, request_id: str) -> bool:
        """Return whether an exact, valid effect claim exists for a request."""

        claim_id = self._claim_id(request_id)
        with self.lock():
            if not self._claim_path(claim_id).exists():
                return False
            self._load_claim_unlocked(request_id)
            return True

    def _grant_usage_unlocked(self, grant_id: str) -> tuple[int, float]:
        family_ids = {grant_id}
        for path in sorted(self.grants_root.iterdir()):
            if not path.is_file() or path.is_symlink() or path.suffix != ".json":
                raise AuthorityError("invalid_authority_state", "grant directory contains an unsafe entry")
            candidate = self.prepare_grant(_read_json(path, root=self.repository_store))
            if candidate["parentGrantId"] == grant_id:
                family_ids.add(candidate["grantId"])
        receipts = [
            receipt for receipt in self._load_receipts_unlocked()
            if receipt.get("authorizedBy", {}).get("type") == "grant"
            and receipt.get("authorizedBy", {}).get("id") in family_ids
            and receipt.get("decision") == "authorized"
        ]
        reservations = [
            reservation
            for reservation in self._load_reservations_unlocked()
            if reservation.get("decision", {})
            .get("authorizedBy", {})
            .get("type")
            == "grant"
            and reservation["decision"]["authorizedBy"].get("id") in family_ids
            and reservation["decision"].get("decision") == "authorized"
        ]
        request_ids = {
            str(item.get("requestId")) for item in (*receipts, *reservations)
        }
        receipt_costs = {
            str(receipt["requestId"]): float(receipt.get("actualCostUsd", 0.0))
            for receipt in receipts
        }
        reservation_costs = {
            str(reservation["requestId"]): float(
                reservation["decision"].get("estimatedCostUsd", 0.0)
            )
            for reservation in reservations
        }
        total_cost = sum(
            receipt_costs.get(request_id, reservation_costs.get(request_id, 0.0))
            for request_id in request_ids
        )
        return len(request_ids), total_cost

    def _grant_status_unlocked(self, grant: Mapping[str, Any]) -> str:
        grant_id = grant["grantId"]
        if self._revocation_path(grant_id).exists():
            status = "revoked"
        elif grant["policyDigest"] is None:
            status = "policy_unbound"
        elif grant["policyDigest"] != self.policy.policy_digest:
            status = "policy_changed"
        else:
            parent_id = grant["parentGrantId"]
            if parent_id is not None:
                parent = self._load_grant_unlocked(parent_id)
                if self._grant_status_unlocked(parent) != "active":
                    status = "parent_inactive"
                else:
                    status = self._grant_expiry_status_unlocked(grant)
            else:
                status = self._grant_expiry_status_unlocked(grant)
        if status not in GRANT_STATUSES:
            raise AuthorityError("invalid_authority_state", "authority grant status is unsupported")
        return status

    def _grant_expiry_status_unlocked(self, grant: Mapping[str, Any]) -> str:
        expiry = grant["expiresWhen"]
        if expiry == "timestamp" and self._now() >= _parse_timestamp(grant["expiresAt"], "expiresAt"):
            return "expired"
        if expiry == "slice_closed" and self._scope_closure_path("slice", grant["scope"]["sliceId"]).exists():
            return "expired"
        if expiry == "run_closed" and self._scope_closure_path("run", grant["scope"]["runId"]).exists():
            return "expired"
        uses, _ = self._grant_usage_unlocked(grant["grantId"])
        if (expiry == "one_action" or grant["kind"] == "one_time") and uses >= 1:
            return "consumed"
        max_actions = grant["limits"]["maxActions"]
        if max_actions is not None and uses >= max_actions:
            return "budget_exhausted"
        return "active"

    def list_grants(self) -> dict[str, Any]:
        with self.lock():
            grants = self._grant_index_unlocked()
            return {
                "schema": "stateport.authority-grant-index/v1",
                "repository": self.identity.to_dict(),
                "paused": self._control_unlocked()["paused"],
                "grants": grants,
            }

    def _grant_index_unlocked(self) -> list[dict[str, Any]]:
        grants = []
        for path in sorted(self.grants_root.iterdir()):
            if not path.is_file() or path.is_symlink() or path.suffix != ".json":
                raise AuthorityError("invalid_authority_state", "grant directory contains an unsafe entry")
            grant = self.prepare_grant(_read_json(path, root=self.repository_store))
            grants.append({**grant, "status": self._grant_status_unlocked(grant)})
        return grants

    def _control_unlocked(self) -> dict[str, Any]:
        if not self.control_path.exists():
            body = {
                "schema": AUTHORITY_CONTROL_SCHEMA,
                "revision": 0,
                "paused": False,
                "reason": None,
                "actorId": None,
                "ownerDirectiveId": None,
                "changedAt": None,
            }
            return {**body, "controlDigest": _digest(body)}
        control = _read_json(self.control_path, root=self.repository_store)
        expected = {
            "schema", "revision", "paused", "reason", "actorId",
            "ownerDirectiveId", "changedAt", "controlDigest",
        }
        if set(control) != expected or control.get("schema") != AUTHORITY_CONTROL_SCHEMA:
            raise AuthorityError("invalid_authority_state", "authority control record is malformed")
        if isinstance(control.get("revision"), bool) or not isinstance(control.get("revision"), int) or control["revision"] < 1:
            raise AuthorityError("invalid_authority_state", "authority control revision is invalid")
        if not isinstance(control.get("paused"), bool):
            raise AuthorityError("invalid_authority_state", "authority pause state is invalid")
        _identifier(control.get("actorId"), "control actor id")
        _identifier(control.get("ownerDirectiveId"), "control owner directive id")
        _parse_timestamp(control.get("changedAt"), "control changedAt")
        body = {key: value for key, value in control.items() if key != "controlDigest"}
        if control.get("controlDigest") != _digest(body):
            raise AuthorityError("invalid_authority_state", "authority control digest is invalid")
        return control

    def inspect(self) -> dict[str, Any]:
        with self.lock():
            grants = []
            for path in sorted(self.grants_root.iterdir()):
                grant = self.prepare_grant(_read_json(path, root=self.repository_store))
                grants.append({"grantId": grant["grantId"], "grantDigest": grant["grantDigest"], "profile": grant["profile"], "scope": grant["scope"], "status": self._grant_status_unlocked(grant)})
            receipts = self._load_receipts_unlocked()
            return {
                "schema": "stateport.authority-inspection/v1",
                "repository": self.identity.to_dict(),
                "defaultProfile": self.policy.default_profile,
                "control": self._control_unlocked(),
                "grants": grants,
                "activeGrants": [item for item in grants if item["status"] == "active"],
                "inactiveGrants": [item for item in grants if item["status"] != "active"],
                "recentActions": receipts[-20:][::-1],
                "recoveryAttention": self.recovery_attention(),
                "hardDeny": sorted(self.policy.hard_deny),
                "escalationConditions": list(self.policy.escalation_conditions),
            }

    def authority_index(self) -> dict[str, Any]:
        """Return one lock-consistent, digestable authority review snapshot."""

        with self.lock():
            control = self._control_unlocked()
            grants = self._grant_index_unlocked()
            policy = {
                "formatVersion": "stateport.authority-profile-index/v1",
                "schema": AUTHORITY_POLICY_SCHEMA,
                "defaultProfile": self.policy.default_profile,
                "policyDigest": self.policy.policy_digest,
                "actionPolicies": {key: dict(value) for key, value in self.policy.actions.items()},
                "profiles": {key: dict(value) for key, value in self.policy.profiles.items()},
                "hardDeny": sorted(self.policy.hard_deny),
                "mergeRequirements": sorted(self.policy.merge_requirements),
                "subagentDefaultDeny": sorted(self.policy.subagent_default_deny),
                "escalationConditions": list(self.policy.escalation_conditions),
            }
            active = [grant for grant in grants if grant["status"] == "active"]
            inactive = [grant for grant in grants if grant["status"] != "active"]
            grant_digests = {grant["grantId"]: grant["grantDigest"] for grant in grants}
            body = {
                "schema": "stateport.authority-index/v1",
                "repository": self.identity.to_dict(),
                "policy": policy,
                "defaultProfile": self.policy.default_profile,
                "policyDigest": self.policy.policy_digest,
                "control": control,
                "activeGrants": active,
                "inactiveGrants": inactive,
                "revisions": {
                    "controlRevision": control["revision"],
                    "grantRevisions": dict(grant_digests),
                },
                "reviewableDigests": {
                    "controlDigest": control["controlDigest"],
                    "grantDigests": dict(grant_digests),
                },
                "recentActions": self._load_receipts_unlocked()[-20:][::-1],
                "recoveryAttention": self.recovery_attention(),
            }
            index_digest = _digest(body)
            return {
                **body,
                "revisions": {**body["revisions"], "indexRevision": index_digest},
                "reviewableDigests": {**body["reviewableDigests"], "indexDigest": index_digest},
            }

    def set_paused(
        self,
        *,
        paused: bool,
        actor_id: str,
        owner_directive_id: str,
        reason: str,
        expected_control_digest: str | None = None,
    ) -> dict[str, Any]:
        _identifier(actor_id, "actor id")
        _identifier(owner_directive_id, "owner directive id")
        if not isinstance(paused, bool) or not isinstance(reason, str) or not reason.strip() or len(reason) > 1024:
            raise AuthorityError("invalid_contract", "pause change requires a bounded reason")
        with self.lock():
            prior = self._control_unlocked()
            if expected_control_digest is not None and expected_control_digest != prior["controlDigest"]:
                raise AuthorityRefusal(
                    "authority_digest_mismatch",
                    "authority control changed since it was reviewed",
                )
            if prior["paused"] == paused:
                raise AuthorityRefusal(
                    "authority_state_unchanged",
                    "authority control is already in the requested state",
                )
            self._begin_recovery_attention("pause", owner_directive_id)
            body = {
                "schema": AUTHORITY_CONTROL_SCHEMA,
                "revision": prior["revision"] + 1,
                "paused": paused,
                "reason": reason.strip(),
                "actorId": actor_id,
                "ownerDirectiveId": owner_directive_id,
                "changedAt": _timestamp(self._now()),
            }
            control = {**body, "controlDigest": _digest(body)}
            _atomic_json(self.control_path, control, root=self.repository_store)
            receipt = self._owner_receipt_unlocked(
                actor_id=actor_id,
                owner_directive_id=owner_directive_id,
                summary="Autonomous execution was paused" if paused else "Autonomous execution was resumed",
                resource={"paused": paused, "controlDigest": control["controlDigest"]},
            )
            self._clear_recovery_attention("pause", owner_directive_id)
            return {"control": control, "receipt": receipt}

    def revoke_grant(
        self,
        grant_id: str,
        *,
        actor_id: str,
        owner_directive_id: str,
        reason: str,
        expected_grant_digest: str | None = None,
    ) -> dict[str, Any]:
        _identifier(actor_id, "actor id")
        _identifier(owner_directive_id, "owner directive id")
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 1024:
            raise AuthorityError("invalid_contract", "revocation requires a bounded reason")
        with self.lock():
            grant = self._load_grant_unlocked(grant_id)
            if expected_grant_digest is not None and expected_grant_digest != grant["grantDigest"]:
                raise AuthorityRefusal(
                    "authority_digest_mismatch",
                    "authority grant changed since it was reviewed",
                )
            self._begin_recovery_attention("revoke", grant_id)
            body = {
                "schema": AUTHORITY_REVOCATION_SCHEMA,
                "grantId": grant_id,
                "grantDigest": grant["grantDigest"],
                "actorId": actor_id,
                "ownerDirectiveId": owner_directive_id,
                "reason": reason.strip(),
                "revokedAt": _timestamp(self._now()),
            }
            revocation = {**body, "revocationDigest": _digest(body)}
            path = self._revocation_path(grant_id)
            if path.exists():
                revocation = _read_json(path, root=self.repository_store)
                receipt = self._owner_receipt_unlocked(
                    actor_id=actor_id,
                    owner_directive_id=owner_directive_id,
                    summary="Owner confirmed an already-revoked authority grant",
                    resource={"grantId": grant_id, "revocationDigest": revocation.get("revocationDigest")},
                )
                self._clear_recovery_attention("revoke", grant_id)
                return {"revocation": revocation, "receipt": receipt}
            _atomic_json(path, revocation, root=self.repository_store, create_only=True)
            receipt = self._owner_receipt_unlocked(
                actor_id=actor_id,
                owner_directive_id=owner_directive_id,
                summary="Owner revoked a standing authority grant",
                resource={"grantId": grant_id, "revocationDigest": revocation["revocationDigest"]},
            )
            self._clear_recovery_attention("revoke", grant_id)
            return {"revocation": revocation, "receipt": receipt}

    def close_scope(self, *, kind: str, scope_id: str, actor_id: str) -> dict[str, Any]:
        _identifier(actor_id, "actor id")
        path = self._scope_closure_path(kind, scope_id)
        with self.lock():
            if path.exists():
                return _read_json(path, root=self.repository_store)
            body = {
                "schema": AUTHORITY_SCOPE_CLOSURE_SCHEMA,
                "kind": kind,
                "scopeId": scope_id,
                "actorId": actor_id,
                "closedAt": _timestamp(self._now()),
            }
            record = {**body, "closureDigest": _digest(body)}
            _atomic_json(path, record, root=self.repository_store, create_only=True)
            return record

    def _scope_matches(
        self,
        grant: Mapping[str, Any],
        *,
        branch: str | None,
        slice_id: str | None,
        application_id: str | None,
        run_id: str | None,
        paths: Sequence[str],
        source_identity: Mapping[str, Any] | None = None,
    ) -> tuple[bool, str]:
        scope = grant["scope"]
        pattern = scope["branchPattern"]
        if pattern is not None and branch is not None and not fnmatchcase(branch, pattern):
            return False, "branch_outside_grant"
        values = {"sliceId": slice_id, "applicationId": application_id, "runId": run_id}
        for name, actual in values.items():
            expected = scope[name]
            if expected is not None and actual != expected:
                return False, f"{name}_outside_grant"
        if paths and any(not any(_path_is_within(path, prefix) for prefix in scope["paths"]) for path in paths):
            return False, "path_outside_grant"
        if source_identity is not None:
            selectors = scope.get("deploymentSources")
            if not isinstance(selectors, list) or not any(
                item.get("repositoryIdentity")
                == source_identity.get("repositoryIdentity")
                and item.get("projectPath") == source_identity.get("projectPath")
                for item in selectors
                if isinstance(item, Mapping)
            ):
                return False, "deployment_source_outside_grant"
        return True, "scope_matched"

    def evaluate(
        self,
        action: str,
        *,
        actor_id: str,
        grant_id: str | None = None,
        branch: str | None = None,
        slice_id: str | None = None,
        application_id: str | None = None,
        run_id: str | None = None,
        paths: Sequence[str] = (),
        estimated_cost_usd: float = 0.0,
        estimated_duration_seconds: int = 0,
        domains: Sequence[str] = (),
        provider: str | None = None,
        secret_capabilities: Sequence[str] = (),
        assurances: Sequence[str] = (),
        source_identity: Mapping[str, Any] | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        if action not in self.policy.actions:
            raise AuthorityError("invalid_contract", "unknown authority action class")
        _identifier(actor_id, "actor id")
        if request_id is None:
            request_id = f"authority_request_{secrets.token_hex(16)}"
        if _REQUEST_ID.fullmatch(request_id) is None:
            raise AuthorityError("invalid_contract", "authority request id is invalid")
        if branch is not None:
            parsed_branch = _branch_pattern(branch)
            if parsed_branch is None or "*" in parsed_branch:
                raise AuthorityError("invalid_contract", "action branch must be an exact safe ref")
        normalized_paths = tuple(_normalized_path(path) for path in paths)
        if action in PATH_BOUND_ACTIONS and not normalized_paths:
            raise AuthorityError("invalid_contract", f"{action} requires exact repository-relative paths")
        if action in BRANCH_BOUND_ACTIONS and branch is None:
            raise AuthorityError("invalid_contract", f"{action} requires an exact branch")
        if isinstance(estimated_duration_seconds, bool) or not isinstance(estimated_duration_seconds, int) or estimated_duration_seconds < 0:
            raise AuthorityError("invalid_contract", "estimated duration is invalid")
        if isinstance(estimated_cost_usd, bool) or not isinstance(estimated_cost_usd, (int, float)) or estimated_cost_usd < 0:
            raise AuthorityError("invalid_contract", "estimated cost is invalid")
        if (
            any(not isinstance(domain, str) for domain in domains)
            or len(domains) != len(set(domains))
            or any(_DOMAIN.fullmatch(domain) is None for domain in domains)
        ):
            raise AuthorityError("invalid_contract", "requested domains are invalid")
        if (
            any(not isinstance(item, str) for item in secret_capabilities)
            or len(secret_capabilities) != len(set(secret_capabilities))
            or any(_ID.fullmatch(item) is None for item in secret_capabilities)
        ):
            raise AuthorityError("invalid_contract", "requested secret capabilities are invalid")
        if provider is not None and (not isinstance(provider, str) or _ID.fullmatch(provider) is None):
            raise AuthorityError("invalid_contract", "requested provider is invalid")
        if (
            any(not isinstance(item, str) for item in assurances)
            or len(assurances) != len(set(assurances))
            or any(_ACTION.fullmatch(item) is None for item in assurances)
        ):
            raise AuthorityError("invalid_contract", "action assurances are invalid")
        if action == "network_access" and not domains:
            raise AuthorityError("invalid_contract", "network access requires exact requested domains")
        if action == "provider_access" and provider is None:
            raise AuthorityError("invalid_contract", "provider access requires an exact provider")
        if action == "real_secret_use" and not secret_capabilities:
            raise AuthorityError("invalid_contract", "real-secret use requires exact capability identifiers")
        normalized_source_identity = _normalized_source_identity(source_identity)
        preflight_only = "preflight_only" in assurances
        if preflight_only and (
            tuple(assurances) != ("preflight_only",)
            or run_id is not None
            or normalized_source_identity is not None
        ):
            raise AuthorityError(
                "invalid_contract",
                "preflight-only authority may bind only an unresolved exact scope",
            )
        if (
            action == "plan_deployment"
            and run_id is None
            and normalized_source_identity is None
            and not preflight_only
        ):
            raise AuthorityError(
                "invalid_contract",
                "initial deployment planning requires an exact source identity",
            )
        if action != "plan_deployment" and normalized_source_identity is not None:
            raise AuthorityError(
                "invalid_contract",
                "source identity may only be bound to deployment planning",
            )
        for value, label in ((slice_id, "slice id"), (application_id, "application id"), (run_id, "run id")):
            if value is not None:
                _identifier(value, label)
        with self.lock():
            control = self._control_unlocked()
            implicit_conflict = False
            if grant_id is None:
                candidates: list[str] = []
                for path in sorted(self.grants_root.iterdir()):
                    if not path.is_file() or path.is_symlink() or path.suffix != ".json":
                        raise AuthorityError("invalid_authority_state", "grant directory contains an unsafe entry")
                    candidate = self.prepare_grant(_read_json(path, root=self.repository_store))
                    if candidate["subject"]["actorId"] != actor_id or self._grant_status_unlocked(candidate) != "active":
                        continue
                    matches, _ = self._scope_matches(
                        candidate,
                        branch=branch,
                        slice_id=slice_id,
                        application_id=application_id,
                        run_id=run_id,
                        paths=normalized_paths,
                        source_identity=normalized_source_identity,
                    )
                    if matches:
                        candidates.append(candidate["grantId"])
                if len(candidates) == 1:
                    grant_id = candidates[0]
                elif len(candidates) > 1:
                    implicit_conflict = True
            grant: dict[str, Any] | None = None
            profile = self.policy.default_profile
            configured = self.policy.mode_for(profile, action)
            effective = configured
            reason = "profile_default"
            authorized_by = {"type": "policy_default", "id": f"profile:{profile}", "digest": None}
            if grant_id is not None:
                grant = self._load_grant_unlocked(grant_id)
                profile = grant["profile"]
                configured = self.policy.mode_for(profile, action, grant["customPolicies"])
                effective = configured
                authorized_by = {"type": "grant", "id": grant_id, "digest": grant["grantDigest"]}
                status = self._grant_status_unlocked(grant)
                if status != "active":
                    effective, reason = "deny", f"grant_{status}"
                elif grant["subject"]["actorId"] != actor_id:
                    effective, reason = "deny", "actor_outside_grant"
                else:
                    matches, scope_reason = self._scope_matches(
                        grant,
                        branch=branch,
                        slice_id=slice_id,
                        application_id=application_id,
                        run_id=run_id,
                        paths=normalized_paths,
                        source_identity=normalized_source_identity,
                    )
                    if not matches:
                        effective, reason = "deny", scope_reason
                    elif action in grant["forbid"]:
                        effective, reason = "deny", "grant_forbids_action"
                    elif action in grant["requireApproval"]:
                        effective, reason = "ask_each_time", "grant_requires_approval"
                    elif action in grant["allow"]:
                        effective, reason = "auto_with_receipt", "standing_scope_approved"
                    else:
                        reason = "profile_policy"
                    if grant["subject"]["role"] == "subagent" and action in self.policy.subagent_default_deny:
                        effective, reason = "deny", "subagent_default_deny"
                    limits = grant["limits"]
                    uses, actual_cost = self._grant_usage_unlocked(grant_id)
                    if limits["maxActions"] is not None and uses >= limits["maxActions"]:
                        effective, reason = "deny", "action_budget_exceeded"
                    if limits["maxDurationSeconds"] is not None and estimated_duration_seconds > limits["maxDurationSeconds"]:
                        effective, reason = "ask_each_time", "time_budget_exceeded"
                    if limits["maxCostUsd"] is not None and actual_cost + float(estimated_cost_usd) > limits["maxCostUsd"]:
                        effective, reason = "ask_each_time", "cost_budget_exceeded"
                    if domains or action == "network_access":
                        if limits["network"] == "denied":
                            effective, reason = "ask_each_time", "network_outside_grant"
                        elif limits["network"] == "allowlisted" and not set(domains).issubset(limits["allowedDomains"]):
                            effective, reason = "ask_each_time", "network_domain_outside_grant"
                    if provider is not None and provider not in limits["providers"]:
                        effective, reason = "ask_each_time", "provider_outside_grant"
                    if not set(secret_capabilities).issubset(limits["secretCapabilities"]):
                        effective, reason = "ask_each_time", "secret_capability_outside_grant"
            elif action not in GRANTLESS_ACTIONS:
                effective, reason = "approve_scope_once", "standing_grant_required"
            if implicit_conflict:
                effective, reason = "deny", "conflicting_policy_rules"
            if action in self.policy.hard_deny:
                effective, reason = "deny", "non_negotiable_policy"
            if control["paused"] and action not in PAUSE_EXEMPT_ACTIONS:
                effective, reason = "deny", "autonomous_execution_paused"
            normalized_assurances = sorted(assurances)
            missing_assurances = (
                sorted(self.policy.merge_requirements - set(normalized_assurances))
                if action == "merge"
                else []
            )
            if missing_assurances:
                effective, reason = "ask_each_time", "merge_assurance_missing"
            # A dirty source is a valid observed identity, but it is never an
            # executable deployment source.  Keep the exact dirty digest in
            # the decision so the refusal can be durably receipted without
            # reserving or claiming an external effect.
            if (
                action == "plan_deployment"
                and run_id is None
                and normalized_source_identity is not None
                and normalized_source_identity["dirty"]
            ):
                effective, reason = "deny", "dirty_source"
            if effective in {"auto_with_receipt", "auto_and_notify"}:
                decision = "authorized"
            elif effective in {"ask_each_time", "approve_scope_once"}:
                decision = "approval_required"
            else:
                decision = "denied"
            scope = {
                "repository": self.identity.to_dict(),
                "branch": branch,
                "sliceId": slice_id,
                "applicationId": application_id,
                "runId": run_id,
                "paths": list(normalized_paths),
            }
            body = {
                "schema": AUTHORITY_DECISION_SCHEMA,
                "requestId": request_id,
                "action": action,
                "actorId": actor_id,
                "authorizedBy": authorized_by,
                "scope": scope,
                "profile": profile,
                "configuredPolicy": configured,
                "policy": effective,
                "decision": decision,
                "reason": reason,
                "missingAssurances": missing_assurances,
                "estimatedCostUsd": float(estimated_cost_usd),
                "estimatedDurationSeconds": estimated_duration_seconds,
                "requestedCapabilities": {
                    "domains": list(domains),
                    "provider": provider,
                    "secretCapabilities": list(secret_capabilities),
                    "assurances": normalized_assurances,
                    "sourceIdentity": normalized_source_identity,
                },
                "decidedAt": _timestamp(self._now()),
            }
            return {**body, "decisionDigest": _digest(body)}

    @staticmethod
    def _validate_decision_contract(decision: Mapping[str, Any]) -> None:
        if decision.get("schema") != AUTHORITY_DECISION_SCHEMA:
            raise AuthorityError("invalid_contract", "authority decision is invalid")
        body = {
            key: value for key, value in decision.items() if key != "decisionDigest"
        }
        if decision.get("decisionDigest") != _digest(body):
            raise AuthorityError(
                "invalid_contract", "authority decision digest is invalid"
            )
        if _REQUEST_ID.fullmatch(str(decision.get("requestId", ""))) is None:
            raise AuthorityError("invalid_contract", "authority request id is invalid")
        requested = decision.get("requestedCapabilities")
        if not isinstance(requested, Mapping) or set(requested) != {
            "domains",
            "provider",
            "secretCapabilities",
            "assurances",
            "sourceIdentity",
        }:
            raise AuthorityError(
                "invalid_contract", "authority requested capabilities are invalid"
            )
        assurances = requested.get("assurances")
        if (
            not isinstance(assurances, list)
            or any(not isinstance(item, str) or _ID.fullmatch(item) is None for item in assurances)
            or assurances != sorted(set(assurances))
        ):
            raise AuthorityError("invalid_contract", "authority assurances are invalid")
        _normalized_source_identity(requested.get("sourceIdentity"))

    def _revalidate_authorized_unlocked(
        self, decision: Mapping[str, Any]
    ) -> None:
        self._validate_decision_contract(decision)
        if decision.get("decision") != "authorized":
            raise AuthorityError(
                "authority_not_authorized", "only authorized decisions may be reserved"
            )
        action = decision.get("action")
        actor_id = decision.get("actorId")
        if action not in self.policy.actions or not isinstance(actor_id, str):
            raise AuthorityError("invalid_contract", "authority decision action is invalid")
        scope = decision.get("scope")
        if (
            not isinstance(scope, Mapping)
            or scope.get("repository") != self.identity.to_dict()
        ):
            raise AuthorityError(
                "repository_identity_uncertain",
                "authority decision repository identity changed before reservation",
            )
        decided_at = _parse_timestamp(decision.get("decidedAt"), "decidedAt")
        now = self._now()
        age = (now - decided_at).total_seconds()
        if age < 0 or age > 300:
            raise AuthorityError(
                "decision_expired", "authority decision was not reserved promptly"
            )
        control = self._control_unlocked()
        if control["paused"] and action not in PAUSE_EXEMPT_ACTIONS:
            raise AuthorityError(
                "autonomous_execution_paused", "authority execution is paused"
            )
        authorized_by = decision.get("authorizedBy")
        if not isinstance(authorized_by, Mapping):
            raise AuthorityError("invalid_contract", "authority source is invalid")
        if authorized_by.get("type") == "grant":
            grant_id = authorized_by.get("id")
            if not isinstance(grant_id, str):
                raise AuthorityError("invalid_contract", "authority grant id is invalid")
            grant = self._load_grant_unlocked(grant_id)
            if self._grant_status_unlocked(grant) != "active":
                raise AuthorityError(
                    "grant_inactive", "authority grant became inactive before reservation"
                )
            if (
                authorized_by.get("digest") != grant["grantDigest"]
                or grant["subject"]["actorId"] != actor_id
                or decision.get("profile") != grant["profile"]
            ):
                raise AuthorityError(
                    "grant_identity_changed", "authority grant identity changed"
                )
            matches, reason = self._scope_matches(
                grant,
                branch=scope.get("branch"),
                slice_id=scope.get("sliceId"),
                application_id=scope.get("applicationId"),
                run_id=scope.get("runId"),
                paths=tuple(scope.get("paths", ())),
                source_identity=decision.get("requestedCapabilities", {}).get(
                    "sourceIdentity"
                ),
            )
            if not matches:
                raise AuthorityError(reason, "authority scope changed before reservation")
            configured = self.policy.mode_for(
                grant["profile"], action, grant["customPolicies"]
            )
            effective = configured
            if action in grant["forbid"]:
                effective = "deny"
            elif action in grant["requireApproval"]:
                effective = "ask_each_time"
            elif action in grant["allow"]:
                effective = "auto_with_receipt"
            if (
                grant["subject"]["role"] == "subagent"
                and action in self.policy.subagent_default_deny
            ):
                effective = "deny"
            limits = grant["limits"]
            requested = decision.get("requestedCapabilities", {})
            domains = requested.get("domains", []) if isinstance(requested, Mapping) else []
            provider = requested.get("provider") if isinstance(requested, Mapping) else None
            secrets_requested = (
                requested.get("secretCapabilities", [])
                if isinstance(requested, Mapping)
                else []
            )
            assurances = (
                requested.get("assurances", [])
                if isinstance(requested, Mapping)
                else []
            )
            expected_missing = (
                sorted(self.policy.merge_requirements - set(assurances))
                if action == "merge"
                else []
            )
            if (
                decision.get("missingAssurances") != expected_missing
                or expected_missing
            ):
                raise AuthorityError(
                    "merge_assurance_missing",
                    "required merge assurances are not durably bound",
                )
            _uses, actual_cost = self._grant_usage_unlocked(grant_id)
            if (
                limits["maxDurationSeconds"] is not None
                and decision.get("estimatedDurationSeconds", 0)
                > limits["maxDurationSeconds"]
            ):
                effective = "ask_each_time"
            if (
                limits["maxCostUsd"] is not None
                and actual_cost + float(decision.get("estimatedCostUsd", 0.0))
                > limits["maxCostUsd"]
            ):
                effective = "ask_each_time"
            if domains:
                if limits["network"] == "denied" or (
                    limits["network"] == "allowlisted"
                    and not set(domains).issubset(limits["allowedDomains"])
                ):
                    effective = "ask_each_time"
            if provider is not None and provider not in limits["providers"]:
                effective = "ask_each_time"
            if not set(secrets_requested).issubset(limits["secretCapabilities"]):
                effective = "ask_each_time"
            if (
                decision.get("configuredPolicy") != configured
                or decision.get("policy") != effective
                or effective not in {"auto_with_receipt", "auto_and_notify"}
            ):
                raise AuthorityError(
                    "authority_policy_changed",
                    "effective authority changed before reservation",
                )
        elif authorized_by.get("type") == "policy_default":
            configured = self.policy.mode_for(self.policy.default_profile, action)
            if (
                action not in GRANTLESS_ACTIONS
                or decision.get("configuredPolicy") != configured
                or decision.get("policy") != configured
                or configured not in {"auto_with_receipt", "auto_and_notify"}
            ):
                raise AuthorityError(
                    "standing_grant_required", "action requires a canonical grant"
                )
        else:
            raise AuthorityError("invalid_contract", "authority source is invalid")
        if action in self.policy.hard_deny:
            raise AuthorityError("non_negotiable_policy", "action is hard denied")

    def _reserve_evaluated_decision(
        self, decision: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Atomically reserve a decision produced inside ``reserve_action``."""

        with self.lock():
            self._revalidate_authorized_unlocked(decision)
            reservation_id = self._reservation_id(str(decision["requestId"]))
            body = {
                "schema": AUTHORITY_ACTION_RESERVATION_SCHEMA,
                "reservationId": reservation_id,
                "requestId": decision["requestId"],
                "decision": json.loads(_canonical_json(decision)),
                "reservedAt": _timestamp(self._now()),
            }
            reservation = {**body, "reservationDigest": _digest(body)}
            _atomic_json(
                self._reservation_path(reservation_id),
                reservation,
                root=self.repository_store,
                create_only=True,
            )
            return reservation

    def reserve_action(self, action: str, **kwargs: Any) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Evaluate and durably reserve one action before it can execute."""

        decision = self.evaluate(action, **kwargs)
        if decision["decision"] != "authorized":
            return decision, None
        return decision, self._reserve_evaluated_decision(decision)

    def _grant_live_for_reserved_unlocked(self, grant: Mapping[str, Any]) -> bool:
        if (
            self._revocation_path(grant["grantId"]).exists()
            or grant.get("policyDigest") != self.policy.policy_digest
        ):
            return False
        parent_id = grant.get("parentGrantId")
        if parent_id is not None and not self._grant_live_for_reserved_unlocked(
            self._load_grant_unlocked(parent_id)
        ):
            return False
        expiry = grant["expiresWhen"]
        if expiry == "timestamp" and self._now() >= _parse_timestamp(
            grant["expiresAt"], "expiresAt"
        ):
            return False
        if expiry == "slice_closed" and self._scope_closure_path(
            "slice", grant["scope"]["sliceId"]
        ).exists():
            return False
        if expiry == "run_closed" and self._scope_closure_path(
            "run", grant["scope"]["runId"]
        ).exists():
            return False
        return True

    def claim_reserved_decision(
        self, decision: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Atomically claim a live reservation exactly once before its effect."""

        self._validate_decision_contract(decision)
        with self.lock():
            reservation = self._load_reservation_unlocked(str(decision["requestId"]))
            if reservation["decision"] != dict(decision):
                raise AuthorityError(
                    "authority_reservation_mismatch",
                    "reserved decision differs from the requested effect",
                )
            if any(
                receipt.get("requestId") == decision["requestId"]
                for receipt in self._load_receipts_unlocked()
            ):
                raise AuthorityError(
                    "authority_reservation_finalized",
                    "authority reservation is already finalized",
                )
            claim_id = self._claim_id(str(decision["requestId"]))
            claim_path = self._claim_path(claim_id)
            if claim_path.exists():
                raise AuthorityError(
                    "authority_reservation_already_claimed",
                    "authority reservation was already claimed for an effect",
                )
            if self._control_unlocked()["paused"] and decision["action"] not in PAUSE_EXEMPT_ACTIONS:
                raise AuthorityError(
                    "autonomous_execution_paused", "authority execution is paused"
                )
            authorized_by = decision["authorizedBy"]
            if authorized_by.get("type") == "grant":
                grant = self._load_grant_unlocked(authorized_by["id"])
                if (
                    authorized_by.get("digest") != grant["grantDigest"]
                    or not self._grant_live_for_reserved_unlocked(grant)
                ):
                    raise AuthorityError(
                        "grant_inactive", "reserved authority grant is no longer live"
                    )
            body = {
                "schema": AUTHORITY_ACTION_CLAIM_SCHEMA,
                "claimId": claim_id,
                "requestId": decision["requestId"],
                "reservationId": reservation["reservationId"],
                "reservationDigest": reservation["reservationDigest"],
                "decisionDigest": decision["decisionDigest"],
                "claimedAt": _timestamp(self._now()),
            }
            claim = {**body, "claimDigest": _digest(body)}
            _atomic_json(
                claim_path,
                claim,
                root=self.repository_store,
                create_only=True,
            )
            return {**reservation, "claim": claim}

    def record_action(
        self,
        decision: Mapping[str, Any],
        *,
        result_status: str,
        summary: str,
        code: str | None = None,
        resource: Mapping[str, Any] | None = None,
        actual_cost_usd: float = 0.0,
        started_at: datetime | None = None,
        reservation: Mapping[str, Any] | None = None,
        claim: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._validate_decision_contract(decision)
        canonical_reservation: dict[str, Any] | None = None
        canonical_claim: dict[str, Any] | None = None
        if result_status not in ACTION_RESULTS:
            raise AuthorityError("invalid_contract", "action result status is invalid")
        if not isinstance(summary, str) or not summary.strip() or len(summary) > 1024:
            raise AuthorityError("invalid_contract", "action receipt summary is invalid")
        if code is not None and (not isinstance(code, str) or _ID.fullmatch(code) is None):
            raise AuthorityError("invalid_contract", "action result code is invalid")
        if isinstance(actual_cost_usd, bool) or not isinstance(actual_cost_usd, (int, float)) or actual_cost_usd < 0:
            raise AuthorityError("invalid_contract", "actual action cost is invalid")
        with self.lock():
            if decision["decision"] != "authorized" and result_status not in {
                "refused",
                "not_executed",
            }:
                raise AuthorityError(
                    "invalid_contract", "refused decisions cannot claim execution"
                )
            if decision["decision"] == "authorized":
                if reservation is None:
                    raise AuthorityError(
                        "authority_reservation_required",
                        "authorized actions must be durably reserved before execution",
                    )
                canonical_reservation = self._load_reservation_unlocked(
                    decision["requestId"]
                )
                if (
                    dict(reservation) != canonical_reservation
                    or canonical_reservation.get("decision") != dict(decision)
                ):
                    raise AuthorityError(
                        "authority_reservation_mismatch",
                        "action finalization does not match its reservation",
                    )
                claim_path = self._claim_path(
                    self._claim_id(decision["requestId"])
                )
                if claim_path.exists():
                    canonical_claim = self._load_claim_unlocked(
                        decision["requestId"]
                    )
                    if claim is None or dict(claim) != canonical_claim:
                        raise AuthorityError(
                            "authority_claim_mismatch",
                            "action finalization does not match its effect claim",
                        )
                    if result_status not in {"succeeded", "failed"}:
                        raise AuthorityError(
                            "authority_claim_outcome_mismatch",
                            "a claimed action cannot be finalized as unexecuted",
                        )
                elif result_status in {"succeeded", "failed"}:
                    raise AuthorityError(
                        "authority_claim_required",
                        "executed actions require an exact pre-effect claim",
                    )
                elif claim is not None:
                    raise AuthorityError(
                        "authority_claim_mismatch",
                        "unexecuted action supplied a nonexistent effect claim",
                    )
            if any(
                item.get("requestId") == decision["requestId"]
                for item in self._load_receipts_unlocked()
            ):
                raise AuthorityError(
                    "duplicate_record", "authority request is already finalized"
                )
            started = started_at or _parse_timestamp(
                decision["decidedAt"], "decidedAt"
            )
            completed = self._now()
            if started > completed:
                raise AuthorityError(
                    "invalid_clock", "action completion precedes its start"
                )
            receipt_id = f"authority_receipt_{secrets.token_hex(16)}"
            body = {
                "schema": AUTHORITY_ACTION_RECEIPT_SCHEMA,
                "receiptId": receipt_id,
                "requestId": decision["requestId"],
                "action": decision["action"],
                "actorId": decision["actorId"],
                "authorizedBy": dict(decision["authorizedBy"]),
                "scope": dict(decision["scope"]),
                "profile": decision["profile"],
                "configuredPolicy": decision["configuredPolicy"],
                "policy": decision["policy"],
                "decision": decision["decision"],
                "result": {
                    "status": result_status,
                    "code": code,
                    "summary": summary.strip(),
                    "resource": dict(resource or {}),
                },
                "startedAt": _timestamp(started),
                "completedAt": _timestamp(completed),
                "estimatedCostUsd": float(decision["estimatedCostUsd"]),
                "actualCostUsd": float(actual_cost_usd),
                "decisionDigest": decision["decisionDigest"],
                "reservation": (
                    {
                        "reservationId": canonical_reservation["reservationId"],
                        "reservationDigest": canonical_reservation[
                            "reservationDigest"
                        ],
                    }
                    if canonical_reservation is not None
                    else None
                ),
                "claim": (
                    {
                        "claimId": canonical_claim["claimId"],
                        "claimDigest": canonical_claim["claimDigest"],
                    }
                    if canonical_claim is not None
                    else None
                ),
            }
            receipt = {**body, "receiptDigest": _digest(body)}
            _atomic_json(self._receipt_path(receipt_id), receipt, root=self.repository_store, create_only=True)
            return receipt

    def execute(
        self,
        action: str,
        operation: Callable[[], T],
        *,
        actor_id: str,
        grant_id: str | None = None,
        branch: str | None = None,
        slice_id: str | None = None,
        application_id: str | None = None,
        run_id: str | None = None,
        paths: Sequence[str] = (),
        estimated_cost_usd: float = 0.0,
        estimated_duration_seconds: int = 0,
        domains: Sequence[str] = (),
        provider: str | None = None,
        secret_capabilities: Sequence[str] = (),
        assurances: Sequence[str] = (),
        source_identity: Mapping[str, Any] | None = None,
        resource_from_result: Callable[[T], Mapping[str, Any]] | None = None,
    ) -> tuple[T, dict[str, Any]]:
        started = self._now()
        decision, reservation = self.reserve_action(
            action,
            actor_id=actor_id,
            grant_id=grant_id,
            branch=branch,
            slice_id=slice_id,
            application_id=application_id,
            run_id=run_id,
            paths=paths,
            estimated_cost_usd=estimated_cost_usd,
            estimated_duration_seconds=estimated_duration_seconds,
            domains=domains,
            provider=provider,
            secret_capabilities=secret_capabilities,
            assurances=assurances,
            source_identity=source_identity,
        )
        if decision["decision"] != "authorized":
            receipt = self.record_action(
                decision,
                result_status="not_executed",
                summary=f"Action was not executed: {decision['reason']}",
                code=decision["reason"],
                started_at=started,
            )
            raise AuthorityRefusal(decision["reason"], "action is outside effective standing authority", receipt=receipt)
        try:
            claimed_reservation = self.claim_reserved_decision(decision)
        except AuthorityError as exc:
            if exc.code == "authority_reservation_already_claimed":
                raise AuthorityRefusal(
                    "authority_reconciliation_required",
                    "reserved action was already claimed; its existing effect must be reconciled",
                ) from exc
            receipt = self.record_action(
                decision,
                result_status="not_executed",
                summary=f"Reserved action was not executed: {exc.code}",
                code=exc.code,
                started_at=started,
                reservation=reservation,
            )
            raise AuthorityRefusal(
                exc.code,
                "reserved action lost live authority before execution",
                receipt=receipt,
            ) from exc
        try:
            result = operation()
        except Exception as exc:
            code = getattr(exc, "code", None)
            safe_code = code if isinstance(code, str) and _ID.fullmatch(code) is not None else "operation_failed"
            receipt = self.record_action(
                decision,
                result_status="failed",
                summary=f"Authorized action failed with {type(exc).__name__}",
                code=safe_code,
                started_at=started,
                reservation=reservation,
                claim=claimed_reservation["claim"],
            )
            try:
                setattr(exc, "authority_receipt", receipt)
            except Exception:
                pass
            raise
        try:
            resource = (
                resource_from_result(result)
                if resource_from_result is not None
                else {}
            )
        except Exception as exc:
            code = getattr(exc, "code", None)
            safe_code = (
                code
                if isinstance(code, str) and _ID.fullmatch(code) is not None
                else "result_evidence_failed"
            )
            receipt = self.record_action(
                decision,
                result_status="failed",
                summary=f"Authorized action completed but result evidence failed with {type(exc).__name__}",
                code=safe_code,
                started_at=started,
                reservation=reservation,
                claim=claimed_reservation["claim"],
            )
            try:
                setattr(exc, "authority_receipt", receipt)
            except Exception:
                pass
            raise
        receipt = self.record_action(
            decision,
            result_status="succeeded",
            summary="Authorized action completed and its result was recorded",
            resource=resource,
            started_at=started,
            reservation=reservation,
            claim=claimed_reservation["claim"],
        )
        return result, receipt


def grant_template(
    manager: AuthorityManager,
    *,
    grant_id: str,
    profile: str,
    actor_id: str,
    role: str,
    branch_pattern: str | None,
    slice_id: str | None,
    application_id: str | None,
    run_id: str | None,
    paths: Sequence[str],
    allow: Sequence[str],
    require_approval: Sequence[str],
    forbid: Sequence[str],
    owner_directive_id: str,
    expires_when: str,
    expires_at: str | None = None,
    parent_grant_id: str | None = None,
    can_delegate: bool = False,
    kind: str = "standing",
    custom_policies: Mapping[str, str] | None = None,
    max_actions: int | None = None,
    max_duration_seconds: int | None = None,
    max_cost_usd: float | None = None,
    network: str = "denied",
    allowed_domains: Sequence[str] = (),
    providers: Sequence[str] = (),
    secret_capabilities: Sequence[str] = (),
    deployment_sources: Sequence[Mapping[str, str]] | None = None,
) -> dict[str, Any]:
    """Build a complete digest-ready grant without persisting it."""

    scope: dict[str, Any] = {
        "repository": manager.identity.to_dict(),
        "branchPattern": branch_pattern,
        "sliceId": slice_id,
        "applicationId": application_id,
        "runId": run_id,
        "paths": list(paths),
    }
    if deployment_sources is not None:
        scope["deploymentSources"] = [dict(item) for item in deployment_sources]
    value = {
        "schema": AUTHORITY_GRANT_SCHEMA,
        "grantId": grant_id,
        "kind": kind,
        "profile": profile,
        "subject": {"actorId": actor_id, "role": role},
        "scope": scope,
        "allow": list(allow),
        "requireApproval": list(require_approval),
        "forbid": list(forbid),
        "customPolicies": dict(custom_policies or {}),
        "limits": {
            "maxActions": max_actions,
            "maxDurationSeconds": max_duration_seconds,
            "maxCostUsd": max_cost_usd,
            "network": network,
            "allowedDomains": list(allowed_domains),
            "providers": list(providers),
            "secretCapabilities": list(secret_capabilities),
        },
        "issuedAt": _timestamp(manager._now()),
        "expiresWhen": expires_when,
        "expiresAt": expires_at,
        "ownerDirectiveId": owner_directive_id,
        "parentGrantId": parent_grant_id,
        "canDelegate": can_delegate,
        "policyDigest": manager.policy.policy_digest,
        "grantDigest": None,
    }
    return manager.prepare_grant(value)
