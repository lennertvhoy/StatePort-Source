"""Workspace revision tracking for StatePort-authoritative transitions.

Git is executed from a trusted absolute path with a minimal environment.  Each
observation binds the confined workspace directory, Git directory, and common
directory by path and inode so repository indirection or a path swap fails
closed.  Legitimate linked worktrees remain supported when their Git metadata
contains the reciprocal worktree registration.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
from typing import Any, Iterator, Mapping, Sequence

from runtime_contracts import canonical_digest


TRANSITION_FORMAT = "stateport.workspace-revision-transition/v1"
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_GIT_TIMEOUT_SECONDS = 30
_REASON_LIMIT = 512
_TIMESTAMP_LIMIT = 64
_MAX_GIT_POINTER_BYTES = 4096


class WorkspaceRevisionError(RuntimeError):
    """A workspace revision observation or transition record was invalid."""


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write_json(path: Path, payload: Mapping[str, Any]) -> None:
    """Persist one complete JSON document with fsync and atomic replacement."""

    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(6)}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        _fsync_directory(path.parent)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        if path.is_symlink() or not path.is_file():
            raise WorkspaceRevisionError(f"{label} is missing or unsafe")
        value = json.loads(path.read_text(encoding="utf-8"))
    except WorkspaceRevisionError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise WorkspaceRevisionError(f"{label} is malformed or unreadable") from exc
    if not isinstance(value, dict):
        raise WorkspaceRevisionError(f"{label} must contain a JSON object")
    return value


def _read_bounded_text(path: Path, label: str) -> str:
    try:
        if path.is_symlink() or not path.is_file():
            raise WorkspaceRevisionError(f"{label} is missing or unsafe")
        if path.stat().st_size > _MAX_GIT_POINTER_BYTES:
            raise WorkspaceRevisionError(f"{label} is oversized")
        return path.read_text(encoding="utf-8").strip()
    except WorkspaceRevisionError:
        raise
    except (OSError, UnicodeError) as exc:
        raise WorkspaceRevisionError(f"{label} is malformed or unreadable") from exc


def _trusted_git_executable() -> Path:
    """Resolve Git only from the operating system's trusted executable roots."""

    for candidate in (Path("/usr/bin/git"), Path("/bin/git")):
        try:
            resolved = candidate.resolve(strict=True)
            metadata = resolved.stat()
        except OSError:
            continue
        if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
            continue
        if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
            continue
        return resolved
    raise WorkspaceRevisionError("no trusted system Git executable is available")


def _git_environment(git_executable: Path) -> dict[str, str]:
    """Return an explicit environment with no process-injection inheritance."""

    trusted_path = os.pathsep.join(dict.fromkeys((str(git_executable.parent), "/usr/bin", "/bin")))
    return {
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_EDITOR": ":",
        "GIT_MERGE_AUTOEDIT": "no",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_PROTOCOL_FROM_USER": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": "/nonexistent-stateport-home",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": trusted_path,
        "TZ": "UTC",
        "XDG_CONFIG_HOME": "/nonexistent-stateport-config",
    }


def _git_config_overrides() -> tuple[str, ...]:
    return (
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "extensions.worktreeConfig=false",
        "-c",
        "submodule.recurse=false",
        "-c",
        "fetch.fsckObjects=true",
        "-c",
        "gc.auto=0",
        "-c",
        "maintenance.auto=false",
        "-c",
        "protocol.allow=never",
    )


@dataclass(frozen=True)
class WorkspaceIdentity:
    """Stable identity of one confined Git worktree, excluding mutable HEAD."""

    workspace_path: Path
    workspace_device: int
    workspace_inode: int
    git_dir: Path
    git_dir_device: int
    git_dir_inode: int
    common_dir: Path
    common_dir_device: int
    common_dir_inode: int
    linked_worktree: bool

    @property
    def workspace_path_digest(self) -> str:
        return canonical_digest(str(self.workspace_path))

    @property
    def repository_identity_digest(self) -> str:
        return canonical_digest(
            {
                "workspacePathDigest": self.workspace_path_digest,
                "workspaceDevice": self.workspace_device,
                "workspaceInode": self.workspace_inode,
                "gitDirPathDigest": canonical_digest(str(self.git_dir)),
                "gitDirDevice": self.git_dir_device,
                "gitDirInode": self.git_dir_inode,
                "commonDirPathDigest": canonical_digest(str(self.common_dir)),
                "commonDirDevice": self.common_dir_device,
                "commonDirInode": self.common_dir_inode,
                "linkedWorktree": self.linked_worktree,
            }
        )

    def durable_binding(self) -> dict[str, str]:
        return {
            "workspacePathDigest": self.workspace_path_digest,
            "repositoryIdentityDigest": self.repository_identity_digest,
        }


class WorkspaceRevisionTracker:
    """Observe and durably record workspace revisions across transitions."""

    def __init__(
        self,
        state_dir: Path | str,
        *,
        workspace_root: Path | str,
        staging_root: Path | str,
    ) -> None:
        self._state_dir = Path(state_dir)
        self._transitions_dir = self._state_dir / "workspace-revisions"
        self._transitions_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self._transitions_dir, 0o700)
        self._workspace_root = Path(workspace_root).resolve()
        self._staging_root = Path(staging_root).resolve()
        self._git = _trusted_git_executable()
        self._git_env = _git_environment(self._git)
        self._git_overrides = _git_config_overrides()

    @property
    def state_dir(self) -> Path:
        return self._state_dir

    @property
    def git_executable(self) -> Path:
        return self._git

    def git_environment(self) -> dict[str, str]:
        return dict(self._git_env)

    @staticmethod
    def git_config_overrides() -> tuple[str, ...]:
        return _git_config_overrides()

    @staticmethod
    def _validate_identifier(value: Any, name: str) -> str:
        if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
            raise WorkspaceRevisionError(f"{name} is not a valid identifier")
        return value

    @staticmethod
    def _require_revision(value: Any) -> str:
        if not isinstance(value, str) or not _REVISION.fullmatch(value):
            raise WorkspaceRevisionError("revision must be 40 lowercase hex characters")
        return value

    @classmethod
    def _optional_revision(cls, value: Any) -> str | None:
        if value is None:
            return None
        return cls._require_revision(value)

    def _within_roots(self, resolved: Path) -> bool:
        for root in (self._workspace_root, self._staging_root):
            try:
                resolved.relative_to(root)
                return True
            except ValueError:
                continue
        return False

    @contextmanager
    def _open_workspace(self, workspace_path: Path | str) -> Iterator[tuple[int, Path]]:
        supplied = Path(workspace_path)
        absolute = Path(os.path.abspath(supplied))
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(absolute, flags)
        except OSError as exc:
            raise WorkspaceRevisionError("workspace path is missing, symlinked, or not a directory") from exc
        try:
            actual = Path(f"/proc/self/fd/{descriptor}").resolve(strict=True)
            if actual != absolute:
                raise WorkspaceRevisionError("workspace path must be canonical and contain no symlinks")
            if not self._within_roots(actual):
                raise WorkspaceRevisionError("workspace path is outside the permitted roots")
            self._assert_open_path(descriptor, actual)
            yield descriptor, actual
            self._assert_open_path(descriptor, actual)
        finally:
            os.close(descriptor)

    @staticmethod
    def _assert_open_path(descriptor: int, path: Path) -> None:
        try:
            opened = os.fstat(descriptor)
            current = os.stat(path, follow_symlinks=False)
        except OSError as exc:
            raise WorkspaceRevisionError("workspace path changed during observation") from exc
        if not stat.S_ISDIR(current.st_mode) or (
            opened.st_dev,
            opened.st_ino,
        ) != (current.st_dev, current.st_ino):
            raise WorkspaceRevisionError("workspace path changed during observation")

    def _run_open_git(
        self,
        descriptor: int,
        argv: Sequence[str],
    ) -> subprocess.CompletedProcess[str]:
        command = [
            str(self._git),
            *self._git_overrides,
            "-C",
            f"/proc/self/fd/{descriptor}",
            *argv,
        ]
        try:
            return subprocess.run(
                command,
                capture_output=True,
                timeout=_GIT_TIMEOUT_SECONDS,
                text=True,
                env=self._git_env,
                pass_fds=(descriptor,),
            )
        except subprocess.TimeoutExpired as exc:
            raise WorkspaceRevisionError("git command timed out") from exc
        except (subprocess.SubprocessError, OSError) as exc:
            raise WorkspaceRevisionError(f"git command failed: {exc}") from exc

    @staticmethod
    def _one_line(result: subprocess.CompletedProcess[str], label: str) -> str:
        lines = result.stdout.splitlines()
        if result.returncode != 0 or result.stderr.strip() or len(lines) != 1 or not lines[0].strip():
            raise WorkspaceRevisionError(f"Git could not resolve {label} safely")
        return lines[0].strip()

    def _inspect_identity(self, descriptor: int, workspace_path: Path) -> WorkspaceIdentity:
        self._assert_open_path(descriptor, workspace_path)
        top = self._one_line(
            self._run_open_git(
                descriptor,
                ("rev-parse", "--path-format=absolute", "--show-toplevel"),
            ),
            "the worktree root",
        )
        git_dir_value = self._one_line(
            self._run_open_git(
                descriptor,
                ("rev-parse", "--path-format=absolute", "--absolute-git-dir"),
            ),
            "the Git directory",
        )
        common_dir_value = self._one_line(
            self._run_open_git(
                descriptor,
                ("rev-parse", "--path-format=absolute", "--git-common-dir"),
            ),
            "the common Git directory",
        )
        flags = self._run_open_git(
            descriptor,
            ("rev-parse", "--is-inside-work-tree", "--is-bare-repository"),
        )
        if flags.returncode != 0 or flags.stderr.strip() or flags.stdout.splitlines() != ["true", "false"]:
            raise WorkspaceRevisionError("workspace is not a non-bare Git worktree")

        try:
            top_supplied = Path(os.path.abspath(top))
            git_dir_supplied = Path(os.path.abspath(git_dir_value))
            common_dir_supplied = Path(os.path.abspath(common_dir_value))
            top_path = top_supplied.resolve(strict=True)
            git_dir = git_dir_supplied.resolve(strict=True)
            common_dir = common_dir_supplied.resolve(strict=True)
        except OSError as exc:
            raise WorkspaceRevisionError("Git resolved missing repository metadata") from exc
        if top_supplied != workspace_path or top_path != workspace_path:
            raise WorkspaceRevisionError("Git resolved a different worktree than the confined workspace")
        if git_dir_supplied != git_dir or common_dir_supplied != common_dir:
            raise WorkspaceRevisionError("Git metadata directories must not be symlinks")
        try:
            workspace_stat = os.fstat(descriptor)
            git_stat = git_dir.stat()
            common_stat = common_dir.stat()
        except OSError as exc:
            raise WorkspaceRevisionError("Git repository metadata is unobservable") from exc
        if not stat.S_ISDIR(git_stat.st_mode) or not stat.S_ISDIR(common_stat.st_mode):
            raise WorkspaceRevisionError("Git repository metadata is not directory-backed")

        git_entry = workspace_path / ".git"
        if git_entry.is_symlink():
            raise WorkspaceRevisionError("workspace .git entry must not be a symlink")
        if git_entry.is_dir():
            if git_entry.resolve(strict=True) != git_dir or common_dir != git_dir:
                raise WorkspaceRevisionError("Git resolved repository metadata outside the workspace")
            linked_worktree = False
        elif git_entry.is_file():
            pointer = _read_bounded_text(git_entry, "linked-worktree .git pointer")
            if not pointer.startswith("gitdir: "):
                raise WorkspaceRevisionError("linked-worktree .git pointer is malformed")
            declared = Path(pointer.removeprefix("gitdir: "))
            if not declared.is_absolute():
                declared = git_entry.parent / declared
            try:
                declared = declared.resolve(strict=True)
            except OSError as exc:
                raise WorkspaceRevisionError("linked-worktree Git directory is missing") from exc
            if declared != git_dir:
                raise WorkspaceRevisionError("linked-worktree Git directory does not match Git")
            back_pointer = Path(_read_bounded_text(git_dir / "gitdir", "linked-worktree back pointer"))
            if not back_pointer.is_absolute():
                back_pointer = git_dir / back_pointer
            try:
                back_pointer = back_pointer.resolve(strict=True)
            except OSError as exc:
                raise WorkspaceRevisionError("linked-worktree back pointer is invalid") from exc
            if back_pointer != git_entry.resolve(strict=True):
                raise WorkspaceRevisionError("linked-worktree registration does not point back to workspace")
            common_pointer = Path(
                _read_bounded_text(git_dir / "commondir", "linked-worktree common pointer")
            )
            if not common_pointer.is_absolute():
                common_pointer = git_dir / common_pointer
            try:
                common_pointer = common_pointer.resolve(strict=True)
            except OSError as exc:
                raise WorkspaceRevisionError("linked-worktree common directory is invalid") from exc
            if common_pointer != common_dir:
                raise WorkspaceRevisionError("linked-worktree common directory does not match Git")
            linked_worktree = True
        else:
            raise WorkspaceRevisionError("workspace has no safe .git directory or worktree pointer")

        core_worktree = self._run_open_git(
            descriptor,
            ("config", "--local", "--get", "core.worktree"),
        )
        if core_worktree.returncode == 0 and core_worktree.stdout.strip():
            raise WorkspaceRevisionError("repository core.worktree indirection is not permitted")
        if core_worktree.returncode != 1 or core_worktree.stdout.strip() or core_worktree.stderr.strip():
            raise WorkspaceRevisionError("repository core.worktree configuration is unobservable")
        self._assert_open_path(descriptor, workspace_path)
        return WorkspaceIdentity(
            workspace_path=workspace_path,
            workspace_device=workspace_stat.st_dev,
            workspace_inode=workspace_stat.st_ino,
            git_dir=git_dir,
            git_dir_device=git_stat.st_dev,
            git_dir_inode=git_stat.st_ino,
            common_dir=common_dir,
            common_dir_device=common_stat.st_dev,
            common_dir_inode=common_stat.st_ino,
            linked_worktree=linked_worktree,
        )

    def workspace_identity(self, workspace_path: Path | str) -> WorkspaceIdentity:
        with self._open_workspace(workspace_path) as (descriptor, resolved):
            return self._inspect_identity(descriptor, resolved)

    def run_git(
        self,
        workspace_path: Path | str,
        argv: Sequence[str],
        *,
        expected_identity: WorkspaceIdentity,
    ) -> subprocess.CompletedProcess[str]:
        """Run fixed Git argv against exactly one previously observed identity."""

        with self._open_workspace(workspace_path) as (descriptor, resolved):
            before = self._inspect_identity(descriptor, resolved)
            if before != expected_identity:
                raise WorkspaceRevisionError("workspace or repository identity changed before Git command")
            result = self._run_open_git(descriptor, argv)
            self._assert_open_path(descriptor, resolved)
            after = self._inspect_identity(descriptor, resolved)
            if after != expected_identity:
                raise WorkspaceRevisionError("workspace or repository identity changed during Git command")
            return result

    def observe_revision(
        self,
        workspace_path: Path | str,
        *,
        expected_identity: WorkspaceIdentity | None = None,
    ) -> str:
        """Return HEAD from a sanitized Git process bound to the exact workspace."""

        identity = expected_identity or self.workspace_identity(workspace_path)
        result = self.run_git(
            workspace_path,
            ("rev-parse", "--verify", "HEAD^{commit}"),
            expected_identity=identity,
        )
        if result.returncode != 0 or result.stderr.strip():
            raise WorkspaceRevisionError("git rev-parse returned a non-zero or noisy result")
        return self._require_revision(result.stdout.strip())

    def _transition_path(self, workspace_id: str, digest: str) -> Path:
        return self._transitions_dir / workspace_id / f"{digest.split(':', 1)[1]}.json"

    def record_transition(
        self,
        *,
        workspace_id: str,
        workspace_path: Path | str,
        promotion_id: str,
        pre_revision: str,
        post_revision: str | None,
        status: str,
        reason: str,
        observed_at: str,
        expected_identity: WorkspaceIdentity | None = None,
    ) -> dict[str, Any]:
        """Atomically record one append-only workspace revision transition."""

        self._validate_identifier(workspace_id, "workspace_id")
        self._validate_identifier(promotion_id, "promotion_id")
        identity = self.workspace_identity(workspace_path)
        if expected_identity is not None and identity != expected_identity:
            raise WorkspaceRevisionError("workspace or repository identity changed before transition record")
        pre = self._require_revision(pre_revision)
        post = self._optional_revision(post_revision)
        if status not in {"succeeded", "failed", "interrupted"}:
            raise WorkspaceRevisionError("status must be succeeded, failed, or interrupted")
        if not isinstance(reason, str) or not reason.strip() or len(reason) > _REASON_LIMIT:
            raise WorkspaceRevisionError("reason must be a bounded non-empty string")
        if not isinstance(observed_at, str) or not observed_at.strip() or len(observed_at) > _TIMESTAMP_LIMIT:
            raise WorkspaceRevisionError("observed_at must be a bounded non-empty timestamp")

        body: dict[str, Any] = {
            "formatVersion": TRANSITION_FORMAT,
            "workspaceId": workspace_id,
            "promotionId": promotion_id,
            **identity.durable_binding(),
            "prePromotionRevision": pre,
            "postPromotionRevision": post,
            "status": status,
            "reason": reason,
            "observedAt": observed_at,
        }
        digest = canonical_digest(body)
        record = {**body, "transitionDigest": digest}
        path = self._transition_path(workspace_id, digest)
        if path.is_file():
            if _read_json(path, "workspace transition record") != record:
                raise WorkspaceRevisionError("workspace transition record has conflicting content")
        else:
            _atomic_write_json(path, record)
        return dict(record)

    def load_transitions(self, workspace_id: str) -> list[dict[str, Any]]:
        """Return validated transition records ordered by time then digest."""

        self._validate_identifier(workspace_id, "workspace_id")
        workspace_dir = self._transitions_dir / workspace_id
        if not workspace_dir.is_dir():
            return []
        expected_keys = {
            "formatVersion",
            "workspaceId",
            "promotionId",
            "workspacePathDigest",
            "repositoryIdentityDigest",
            "prePromotionRevision",
            "postPromotionRevision",
            "status",
            "reason",
            "observedAt",
            "transitionDigest",
        }
        records: list[dict[str, Any]] = []
        for path in sorted(workspace_dir.glob("*.json")):
            record = _read_json(path, "workspace transition record")
            if set(record) != expected_keys or record.get("formatVersion") != TRANSITION_FORMAT:
                raise WorkspaceRevisionError("transition record has an invalid shape")
            self._validate_identifier(record.get("workspaceId"), "workspace_id")
            self._validate_identifier(record.get("promotionId"), "promotion_id")
            self._require_revision(record.get("prePromotionRevision"))
            self._optional_revision(record.get("postPromotionRevision"))
            for name in ("workspacePathDigest", "repositoryIdentityDigest"):
                if not isinstance(record.get(name), str) or not _DIGEST.fullmatch(record[name]):
                    raise WorkspaceRevisionError(f"transition record {name} is invalid")
            if record.get("status") not in {"succeeded", "failed", "interrupted"}:
                raise WorkspaceRevisionError("transition record status is invalid")
            if not isinstance(record.get("reason"), str) or not record["reason"].strip():
                raise WorkspaceRevisionError("transition record reason is invalid")
            if not isinstance(record.get("observedAt"), str) or not record["observedAt"].strip():
                raise WorkspaceRevisionError("transition record timestamp is invalid")
            stored = record.get("transitionDigest")
            body = {key: value for key, value in record.items() if key != "transitionDigest"}
            if not isinstance(stored, str) or canonical_digest(body) != stored:
                raise WorkspaceRevisionError("transition record digest mismatch")
            if path.stem != stored.split(":", 1)[1]:
                raise WorkspaceRevisionError("transition filename does not match its digest")
            records.append(dict(record))
        records.sort(
            key=lambda record: (
                str(record.get("observedAt")),
                str(record.get("transitionDigest")),
            )
        )
        return records


__all__ = ["WorkspaceIdentity", "WorkspaceRevisionTracker", "WorkspaceRevisionError"]
