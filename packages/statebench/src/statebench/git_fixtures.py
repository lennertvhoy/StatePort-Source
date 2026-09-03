"""Local Git-bundle fixtures and bare remotes for controlled StateBench cases."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import subprocess


class GitFixtureError(ValueError):
    """A Git fixture violates StateBench's isolated local-test boundary."""


def _safe_path(path: str | Path, *, name: str) -> Path:
    candidate = Path(path)
    if ".." in candidate.parts:
        raise GitFixtureError(f"{name} must not contain path traversal")
    return Path(os.path.abspath(os.fspath(candidate)))


def _assert_no_symlink_ancestors(path: Path, *, name: str) -> None:
    current = path
    while True:
        if current.is_symlink():
            raise GitFixtureError(f"{name} must not traverse a symlink")
        if current.parent == current:
            return
        current = current.parent


@dataclass(frozen=True)
class FixtureMaterialization:
    """Fresh local fixture facts; these paths are not snapshot identities."""

    worktree: Path
    origin: str
    commit: str
    tree: str
    clean: bool


class GitBundleFixtureMaterializer:
    """Materialize one supplied bundle into an empty isolated directory."""

    def __init__(self, *, timeout_seconds: float = 10.0) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._timeout_seconds = timeout_seconds

    def materialize(
        self, bundle: str | Path, destination: str | Path, *, expected_origin: str
    ) -> FixtureMaterialization:
        bundle_path = _safe_path(bundle, name="bundle")
        destination_path = _safe_path(destination, name="destination")
        _assert_no_symlink_ancestors(bundle_path, name="bundle")
        _assert_no_symlink_ancestors(destination_path, name="destination")
        if not bundle_path.is_file() or bundle_path.is_symlink():
            raise GitFixtureError("bundle must be an existing regular file")
        if destination_path.exists():
            raise GitFixtureError("destination must be a new directory")
        if not isinstance(expected_origin, str) or not expected_origin:
            raise GitFixtureError("expected_origin must be non-empty")
        self._run(["git", "bundle", "verify", str(bundle_path)])
        branch = self._bundle_branch(bundle_path)
        try:
            self._run(["git", "clone", "--no-local", "--no-checkout", str(bundle_path), str(destination_path)])
            origin = self._git(destination_path, ["remote", "get-url", "origin"])
            if origin != expected_origin:
                raise GitFixtureError("fixture origin does not match expected_origin")
            self._git(destination_path, ["switch", "--create", branch, "--track", f"origin/{branch}"])
            self._run(["git", "-C", str(destination_path), "fsck", "--no-dangling"])
            if self._git(destination_path, ["status", "--porcelain=v1", "--untracked-files=all"]):
                raise GitFixtureError("fresh fixture is dirty")
            return FixtureMaterialization(
                worktree=destination_path, origin=origin,
                commit=self._git(destination_path, ["rev-parse", "HEAD"]),
                tree=self._git(destination_path, ["rev-parse", "HEAD^{tree}"]), clean=True,
            )
        except Exception:
            if destination_path.exists():
                shutil.rmtree(destination_path)
            raise

    def _run(self, argv: list[str]) -> str:
        completed = subprocess.run(
            argv, check=False, capture_output=True, text=True,
            timeout=self._timeout_seconds, shell=False,
        )
        if completed.returncode != 0:
            raise GitFixtureError(f"Git command failed: {completed.stderr.strip()}")
        return completed.stdout.strip()

    def _git(self, directory: Path, args: list[str]) -> str:
        return self._run(["git", "-C", str(directory), *args])

    def _bundle_branch(self, bundle: Path) -> str:
        heads = []
        for line in self._run(["git", "bundle", "list-heads", str(bundle)]).splitlines():
            parts = line.split(maxsplit=1)
            if len(parts) == 2 and parts[1].startswith("refs/heads/"):
                heads.append(parts[1][len("refs/heads/"):])
        if len(heads) != 1:
            raise GitFixtureError("bundle must advertise exactly one fixture branch")
        branch = heads[0]
        self._run(["git", "check-ref-format", "--branch", branch])
        return branch


@dataclass(frozen=True)
class RemoteEqualityFacts:
    """Explicit local/remote branch equality facts for a local bare remote."""

    branch: str
    local_commit: str
    remote_commit: str | None
    equal: bool


class TemporaryBareRemote:
    """A local bare remote with deliberately non-force branch operations only."""

    def __init__(self, path: Path, *, timeout_seconds: float = 10.0) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.path = path
        self._timeout_seconds = timeout_seconds

    @classmethod
    def create(cls, path: str | Path, *, timeout_seconds: float = 10.0) -> "TemporaryBareRemote":
        remote_path = _safe_path(path, name="bare remote")
        _assert_no_symlink_ancestors(remote_path, name="bare remote")
        if remote_path.exists():
            raise GitFixtureError("bare remote destination must not already exist")
        manager = cls(remote_path, timeout_seconds=timeout_seconds)
        manager._run(["git", "init", "--bare", str(remote_path)])
        manager._run(["git", "--git-dir", str(remote_path), "config", "receive.denyNonFastForwards", "true"])
        manager._run(["git", "--git-dir", str(remote_path), "config", "receive.denyDeletes", "true"])
        return manager

    def create_branch(self, worktree: str | Path, branch: str, *, start_point: str = "HEAD") -> RemoteEqualityFacts:
        worktree_path = self._worktree(worktree)
        self._validate_branch(branch)
        self._git(worktree_path, ["switch", "--create", branch, start_point])
        return self.equality_facts(worktree_path, branch)

    def attach(self, worktree: str | Path) -> None:
        """Bind a fixture worktree to this local bare remote and no other origin."""

        worktree_path = self._worktree(worktree)
        remotes = set(self._git(worktree_path, ["remote"]).splitlines())
        if "origin" not in remotes:
            self._git(worktree_path, ["remote", "add", "origin", str(self.path)])
            return
        origin = self._git(worktree_path, ["remote", "get-url", "origin"])
        if origin != str(self.path):
            raise GitFixtureError("worktree origin does not match this local bare remote")

    def attach_fresh_fixture(self, worktree: str | Path) -> None:
        """Replace a clean bundle origin with this isolated bare remote.

        A materialized bundle necessarily starts with the bundle file as its
        ``origin``.  This narrow operation is the hand-off point to an
        isolated benchmark remote; it refuses a dirty worktree and does not
        provide any force-push operation.
        """

        worktree_path = self._worktree(worktree)
        if self._git(worktree_path, ["status", "--porcelain=v1", "--untracked-files=all"]):
            raise GitFixtureError("fresh fixture must be clean before remote attachment")
        remotes = set(self._git(worktree_path, ["remote"]).splitlines())
        if "origin" in remotes:
            self._git(worktree_path, ["remote", "remove", "origin"])
        self.attach(worktree_path)

    def push_branch(self, worktree: str | Path, branch: str) -> RemoteEqualityFacts:
        """Push normally after a local fast-forward check; force is not an API option."""

        worktree_path = self._worktree(worktree)
        self._validate_branch(branch)
        self.attach(worktree_path)
        # A normal Git push is the authority for the non-fast-forward check.
        # This API never accepts a force option or emits a force refspec.
        completed = subprocess.run(
            ["git", "-C", str(worktree_path), "push", "--no-verify", "origin", f"{branch}:refs/heads/{branch}"],
            check=False, capture_output=True, text=True,
            timeout=self._timeout_seconds, shell=False,
        )
        if completed.returncode != 0:
            raise GitFixtureError("non-fast-forward updates and force pushes are forbidden")
        facts = self.equality_facts(worktree_path, branch)
        if not facts.equal:
            raise GitFixtureError("local and bare-remote branch identities differ after push")
        return facts

    def equality_facts(self, worktree: str | Path, branch: str) -> RemoteEqualityFacts:
        worktree_path = self._worktree(worktree)
        self._validate_branch(branch)
        local = self._git(worktree_path, ["rev-parse", branch])
        remote = self._remote_commit(branch)
        return RemoteEqualityFacts(branch=branch, local_commit=local, remote_commit=remote, equal=local == remote)

    def _remote_commit(self, branch: str) -> str | None:
        exists = subprocess.run(
            ["git", "--git-dir", str(self.path), "show-ref", "--verify", "--quiet", f"refs/heads/{branch}"],
            check=False, capture_output=True, text=True,
            timeout=self._timeout_seconds, shell=False,
        )
        if exists.returncode == 1:
            return None
        if exists.returncode != 0:
            raise GitFixtureError(f"could not inspect bare remote branch: {exists.stderr.strip()}")
        return self._run(["git", "--git-dir", str(self.path), "rev-parse", f"refs/heads/{branch}"])

    def _worktree(self, value: str | Path) -> Path:
        path = _safe_path(value, name="worktree")
        _assert_no_symlink_ancestors(path, name="worktree")
        if not path.is_dir() or path.is_symlink():
            raise GitFixtureError("worktree must be a non-symlink directory")
        return path

    def _validate_branch(self, branch: str) -> None:
        if not isinstance(branch, str) or not branch or branch.startswith("-"):
            raise GitFixtureError("branch name is invalid")
        self._run(["git", "check-ref-format", "--branch", branch])

    def _run(self, argv: list[str]) -> str:
        completed = subprocess.run(
            argv, check=False, capture_output=True, text=True,
            timeout=self._timeout_seconds, shell=False,
        )
        if completed.returncode != 0:
            raise GitFixtureError(f"Git command failed: {completed.stderr.strip()}")
        return completed.stdout.strip()

    def _git(self, directory: Path, args: list[str]) -> str:
        return self._run(["git", "-C", str(directory), *args])
