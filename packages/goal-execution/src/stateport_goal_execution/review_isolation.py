"""StatePort-owned verification for exact review-workspace isolation.

The browser or execution adapter cannot satisfy this boundary with booleans.
StatePort inspects a concrete local Git worktree, binds its immutable identity,
and returns a typed evidence record consumed by the goal-execution service.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import subprocess

from .contracts import (
    GoalContractError,
    ReviewWorkspaceIsolation,
    canonical_digest,
)


_MAX_WORKSPACE_ENTRIES = 4096
_MAX_WORKSPACE_BYTES = 128 * 1024 * 1024
_WRITE_BITS = stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH


def _reject_symlink_ancestors(path: Path) -> None:
    current = path.absolute()
    while True:
        if current.is_symlink():
            raise GoalContractError("review workspace roots may not traverse symlinks")
        if current.parent == current:
            return
        current = current.parent


def _git(
    worktree: Path,
    *arguments: str,
    expected: tuple[int, ...] = (0,),
) -> subprocess.CompletedProcess[str]:
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
    }
    completed = subprocess.run(
        [
            "git",
            "--no-replace-objects",
            "-c", "core.hooksPath=/dev/null",
            "-c", "core.fsmonitor=false",
            "-c", "core.untrackedCache=false",
            "-c", "diff.external=",
            "-C", str(worktree),
            *arguments,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        shell=False,
        env=environment,
    )
    if completed.returncode not in expected:
        raise GoalContractError(
            "review workspace Git verification failed: "
            + completed.stderr.strip()[-500:]
        )
    return completed


def _bounded_read_only_tree(root: Path) -> None:
    entries = [root, *root.rglob("*")]
    if len(entries) > _MAX_WORKSPACE_ENTRIES:
        raise GoalContractError("review workspace exceeds the verification bound")
    for path in entries:
        if path.is_symlink():
            raise GoalContractError("review workspace may not contain symlinks")
        try:
            mode = path.stat().st_mode
        except OSError as exc:
            raise GoalContractError(
                "review workspace entry could not be inspected"
            ) from exc
        if mode & _WRITE_BITS:
            raise GoalContractError("review workspace must be filesystem read-only")


def _verify_exact_tree_bytes(root: Path, commit: str) -> None:
    """Compare filesystem bytes and executable bits directly with Git blobs.

    Git status is retained as a useful diagnostic, but it is not the trust
    boundary: worktree-local fsmonitor, excludes, attributes, and index flags
    must not be able to hide content from review isolation.
    """

    records = _git(root, "ls-tree", "-r", "-z", "--full-tree", commit).stdout
    expected: dict[str, tuple[str, str]] = {}
    for raw in records.split("\0"):
        if not raw:
            continue
        try:
            metadata, path = raw.split("\t", 1)
            mode, kind, object_id = metadata.split(" ", 2)
        except ValueError as exc:
            raise GoalContractError("review workspace tree listing is malformed") from exc
        candidate = Path(path)
        if (
            kind != "blob"
            or mode not in {"100644", "100755"}
            or candidate.is_absolute()
            or not candidate.parts
            or any(part in {"", ".", "..", ".git"} for part in candidate.parts)
        ):
            raise GoalContractError("review workspace contains an unsupported tree entry")
        expected[candidate.as_posix()] = (mode, object_id)
    if len(expected) > _MAX_WORKSPACE_ENTRIES:
        raise GoalContractError("review workspace exceeds the verification bound")

    actual_files: dict[str, Path] = {}
    actual_directories: set[str] = set()
    total_bytes = 0
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if relative.parts and relative.parts[0] == ".git":
            continue
        value = relative.as_posix()
        if path.is_symlink():
            raise GoalContractError("review workspace contains an unsupported filesystem entry")
        if path.is_dir():
            actual_directories.add(value)
            continue
        if not path.is_file():
            raise GoalContractError("review workspace contains an unsupported filesystem entry")
        info = path.stat()
        total_bytes += info.st_size
        if total_bytes > _MAX_WORKSPACE_BYTES:
            raise GoalContractError("review workspace content exceeds the verification bound")
        actual_files[value] = path

    expected_directories = {
        parent.as_posix()
        for name in expected
        for parent in Path(name).parents
        if parent.as_posix() != "."
    }
    if set(actual_files) != set(expected) or actual_directories != expected_directories:
        raise GoalContractError("review workspace files differ from the expected clean tree")

    object_format = _git(root, "rev-parse", "--show-object-format").stdout.strip()
    if object_format not in {"sha1", "sha256"}:
        raise GoalContractError("review workspace Git object format is unsupported")
    for name, (mode, object_id) in expected.items():
        path = actual_files[name]
        data = path.read_bytes()
        payload = f"blob {len(data)}\0".encode("ascii") + data
        observed = hashlib.new(object_format, payload).hexdigest()
        executable = bool(path.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
        if observed != object_id or executable != (mode == "100755"):
            raise GoalContractError("review workspace content differs from the expected commit tree")


def verify_review_workspace(
    *,
    review_worktree: Path,
    implementation_worktree: Path,
    reviewer_actor: str,
    expected_commit: str,
    expected_tree: str,
) -> ReviewWorkspaceIsolation:
    """Verify a distinct, clean, detached and filesystem-read-only worktree."""

    _reject_symlink_ancestors(review_worktree)
    _reject_symlink_ancestors(implementation_worktree)
    try:
        review = review_worktree.resolve(strict=True)
        implementation = implementation_worktree.resolve(strict=True)
    except OSError as exc:
        raise GoalContractError("review workspace roots must exist") from exc
    if not review.is_dir() or not implementation.is_dir():
        raise GoalContractError("review workspace roots must be directories")
    if (
        review == implementation
        or review in implementation.parents
        or implementation in review.parents
    ):
        raise GoalContractError("review workspace must be separate from implementation")

    _git(review, "rev-parse", "--is-inside-work-tree")
    detached = _git(review, "symbolic-ref", "-q", "HEAD", expected=(0, 1))
    if detached.returncode != 1:
        raise GoalContractError("review workspace HEAD must be detached")
    commit = _git(review, "rev-parse", "HEAD").stdout.strip()
    tree = _git(review, "rev-parse", "HEAD^{tree}").stdout.strip()
    status = _git(
        review,
        "status",
        "--porcelain=v2",
        "--untracked-files=all",
    ).stdout
    if commit != expected_commit or tree != expected_tree:
        raise GoalContractError(
            "review workspace does not bind the expected commit and tree"
        )
    _verify_exact_tree_bytes(review, commit)
    if status:
        raise GoalContractError("review workspace must be clean")
    _bounded_read_only_tree(review)

    implementation_digest = canonical_digest(
        {"kind": "implementation-worktree", "realpath": str(implementation)}
    )
    review_digest = canonical_digest(
        {"kind": "review-worktree", "realpath": str(review)}
    )
    seed = {
        "reviewerActor": reviewer_actor,
        "implementationWorkspaceDigest": implementation_digest,
        "reviewWorkspaceDigest": review_digest,
        "functionalCommit": commit,
        "functionalTree": tree,
    }
    return ReviewWorkspaceIsolation(
        evidence_id="review-isolation-" + canonical_digest(seed).split(":", 1)[1][:24],
        reviewer_actor=reviewer_actor,
        implementation_workspace_digest=implementation_digest,
        review_workspace_digest=review_digest,
        functional_commit=commit,
        functional_tree=tree,
    )
