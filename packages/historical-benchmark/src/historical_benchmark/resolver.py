"""Local Git history resolution with immutable commit/tree observations."""

from __future__ import annotations

from pathlib import Path
import subprocess

from .contracts import HistoricalCandidate


def _git(repository: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repository, text=True, capture_output=True, check=False
    )
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise ValueError(f"local Git command failed: {' '.join(args)}: {detail}")
    return result.stdout.strip()


def resolve_historical_candidates(
    repository: str | Path,
    *,
    ref: str = "HEAD",
    limit: int = 20,
    repository_id: str | None = None,
) -> tuple[HistoricalCandidate, ...]:
    """Resolve the newest first-parent history from a local Git repository.

    ``ref`` is only a traversal anchor. The returned identity is the full
    commit and tree, so later movement of a branch cannot silently change an
    already recorded candidate. No fetch, clone, or other network operation is
    performed.
    """

    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
        raise ValueError("limit must be a positive integer")
    root = Path(repository).expanduser().resolve()
    if not root.is_dir():
        raise ValueError("repository must be a local directory")
    top_level = Path(_git(root, "rev-parse", "--show-toplevel")).resolve()
    identity = repository_id or top_level.as_posix()
    if not identity.strip():
        raise ValueError("repository_id must not be empty")
    commits = _git(
        top_level,
        "rev-list",
        "--first-parent",
        f"--max-count={limit}",
        ref,
    ).splitlines()
    candidates: list[HistoricalCandidate] = []
    for commit in commits:
        full_commit = _git(top_level, "rev-parse", f"{commit}^{{commit}}")
        tree = _git(top_level, "rev-parse", f"{full_commit}^{{tree}}")
        subject = _git(top_level, "show", "-s", "--format=%s", full_commit)
        candidates.append(
            HistoricalCandidate(
                repository=identity,
                commit=full_commit,
                tree=tree,
                ref=ref,
                subject=subject,
                local_repository=top_level.as_posix(),
            )
        )
    if not candidates:
        raise ValueError(f"ref {ref!r} has no local commits")
    return tuple(candidates)
