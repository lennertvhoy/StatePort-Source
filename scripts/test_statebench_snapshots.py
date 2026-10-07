#!/usr/bin/env python3
"""Focused public-safe tests for StateBench Git snapshot infrastructure."""

from __future__ import annotations

import inspect
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "statebench" / "src"))

from statebench import (  # noqa: E402
    CompatibilityMode,
    GitBundleFixtureMaterializer,
    GitFixtureError,
    LocalReadOnlySnapshotResolver,
    SnapshotConfiguration,
    SnapshotResolutionError,
    TemporaryBareRemote,
)


# Public reference identities only. These tests do not contact their repository
# and do not classify either identity as a canonical or accepted release.
STATEDD_TEMPLATE_REPOSITORY = "https://github.com/lennertvhoy/StateDD_Template.git"
STABLE_V4_COMMIT = "2a9afd47b22d67704e097c93bbb2ca6d16fd08e1"
STABLE_V4_TREE = "99b7ae332eb72c1f70d20e041ac8b72d94e49ffe"
CANDIDATE_LOCAL_ORIGIN_MAIN_COMMIT = "917f3f35d191f120be4439ae4cd3d5ba5d50599c"
CANDIDATE_LOCAL_ORIGIN_MAIN_TREE = "18bc76c8f884561122de71760cf81a4bacb2d4b2"


def _run(argv: list[str], *, cwd: Path | None = None) -> str:
    completed = subprocess.run(
        argv, cwd=cwd, check=False, capture_output=True, text=True,
        timeout=10, shell=False,
    )
    if completed.returncode != 0:
        raise AssertionError(f"command failed: {argv!r}\n{completed.stderr}")
    return completed.stdout.strip()


def _commit(repository: Path, relative: str, contents: str, message: str) -> str:
    target = repository / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(contents, encoding="utf-8")
    _run(["git", "add", relative], cwd=repository)
    _run(["git", "commit", "-m", message], cwd=repository)
    return _run(["git", "rev-parse", "HEAD"], cwd=repository)


def _repository(root: Path) -> Path:
    repository = root / "source"
    _run(["git", "init", "--initial-branch=main", str(repository)])
    _run(["git", "config", "user.email", "statebench@example.invalid"], cwd=repository)
    _run(["git", "config", "user.name", "StateBench fixture"], cwd=repository)
    _run(["git", "remote", "add", "origin", "https://example.invalid/public-fixture.git"], cwd=repository)
    _commit(repository, "template.txt", "public-safe fixture\n", "initial fixture")
    return repository


def _assert_raises(error: type[Exception], text: str, callback: object) -> None:
    try:
        callback()  # type: ignore[operator]
    except error as exc:
        assert text in str(exc), str(exc)
    else:
        raise AssertionError(f"expected {error.__name__}")


def test_reference_identities_are_syntax_constants_only() -> None:
    resolver = LocalReadOnlySnapshotResolver()
    # This focused test intentionally makes no network call. Delivery evidence
    # records remote-ref verification separately from contract conformance.
    assert len(STABLE_V4_COMMIT) == len(STABLE_V4_TREE) == 40
    assert len(CANDIDATE_LOCAL_ORIGIN_MAIN_COMMIT) == len(CANDIDATE_LOCAL_ORIGIN_MAIN_TREE) == 40
    assert STATEDD_TEMPLATE_REPOSITORY.startswith("https://github.com/")
    assert resolver is not None


def test_snapshot_resolution_is_immutable_deterministic_and_path_free() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        repository = _repository(Path(tmpdir))
        before_head = _run(["git", "rev-parse", "HEAD"], cwd=repository)
        before_status = _run(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=repository)
        resolver = LocalReadOnlySnapshotResolver()
        first = resolver.resolve(
            repository, repository="https://example.invalid/public-fixture.git", requested_revision="main"
        )
        second = resolver.resolve(
            repository, repository="https://example.invalid/public-fixture.git", requested_revision="HEAD"
        )
        assert first == second
        assert first.commit == before_head
        assert first.tree == _run(["git", "rev-parse", "HEAD^{tree}"], cwd=repository)
        assert first.to_dict()["compatibilityWrapper"] is None
        assert "main" not in first.canonical_json()
        assert str(repository) not in first.canonical_json()
        assert _run(["git", "rev-parse", "HEAD"], cwd=repository) == before_head
        assert _run(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=repository) == before_status
        assert SnapshotConfiguration.from_dict(first.to_dict()) == first
        _run(["git", "remote", "set-url", "origin", "https://example.invalid/wrong.git"], cwd=repository)
        _assert_raises(
            SnapshotResolutionError, "origin", lambda: resolver.resolve(
                repository, repository="https://example.invalid/public-fixture.git", requested_revision="HEAD"
            )
        )
        _run(["git", "remote", "set-url", "origin", "https://example.invalid/public-fixture.git"], cwd=repository)
        changed = _commit(repository, "template.txt", "changed fixture\n", "change")
        later = resolver.resolve(
            repository, repository="https://example.invalid/public-fixture.git", requested_revision=changed
        )
        assert later.content_digest != first.content_digest
        _assert_raises(ValueError, "additional properties", lambda: SnapshotConfiguration.from_dict({**first.to_dict(), "ref": "main"}))
        _assert_raises(ValueError, "unsupported", lambda: SnapshotConfiguration.from_dict({**first.to_dict(), "compatibilityMode": "unknown"}))


def test_snapshot_rejects_dirty_symlink_and_invalid_compatibility() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        repository = _repository(root)
        resolver = LocalReadOnlySnapshotResolver()
        (repository / "untracked.txt").write_text("not clean\n", encoding="utf-8")
        _assert_raises(
            SnapshotResolutionError, "clean", lambda: resolver.resolve(
                repository, repository="https://example.invalid/public-fixture.git", requested_revision="HEAD"
            )
        )
        (repository / "untracked.txt").unlink()
        try:
            checkout_link = root / "checkout-link"
            checkout_link.symlink_to(repository, target_is_directory=True)
        except OSError:
            checkout_link = None
        if checkout_link is not None:
            _assert_raises(
                SnapshotResolutionError, "symlink", lambda: resolver.resolve(
                    checkout_link, repository="https://example.invalid/public-fixture.git", requested_revision="HEAD"
                )
            )
        _assert_raises(
            ValueError, "legacy snapshots", lambda: resolver.resolve(
                repository, repository="https://example.invalid/public-fixture.git", requested_revision="HEAD",
                compatibility_mode=CompatibilityMode.LEGACY,
            )
        )
        link = repository / "link"
        try:
            link.symlink_to("template.txt")
        except OSError:
            return
        _run(["git", "add", "link"], cwd=repository)
        _run(["git", "commit", "-m", "add symlink"], cwd=repository)
        _assert_raises(
            SnapshotResolutionError, "symlinks", lambda: resolver.resolve(
                repository, repository="https://example.invalid/public-fixture.git", requested_revision="HEAD"
            )
        )


def test_bundle_materializer_rejects_invalid_inputs_and_proves_clean_fixture() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        repository = _repository(root)
        bundle = root / "fixture.bundle"
        _run(["git", "bundle", "create", str(bundle), "main"], cwd=repository)
        materializer = GitBundleFixtureMaterializer()
        result = materializer.materialize(bundle, root / "fixture", expected_origin=str(bundle))
        assert result.clean is True
        assert result.commit == _run(["git", "rev-parse", "HEAD"], cwd=repository)
        assert _run(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=result.worktree) == ""
        nonempty = root / "nonempty"
        nonempty.mkdir(); (nonempty / "existing").write_text("x", encoding="utf-8")
        _assert_raises(GitFixtureError, "destination", lambda: materializer.materialize(bundle, nonempty, expected_origin=str(bundle)))
        _assert_raises(GitFixtureError, "expected_origin", lambda: materializer.materialize(bundle, root / "wrong-origin", expected_origin="https://example.invalid/other.git"))
        _assert_raises(GitFixtureError, "regular file", lambda: materializer.materialize(root / "missing.bundle", root / "missing", expected_origin="missing"))
        corrupt = root / "corrupt.bundle"
        corrupt.write_bytes(b"not a git bundle")
        _assert_raises(GitFixtureError, "Git command failed", lambda: materializer.materialize(corrupt, root / "corrupt", expected_origin=str(corrupt)))
        _assert_raises(GitFixtureError, "path traversal", lambda: materializer.materialize(bundle, root / "fixture" / ".." / "escape", expected_origin=str(bundle)))
        try:
            symlink = root / "bundle-link"
            symlink.symlink_to(bundle)
        except OSError:
            return
        _assert_raises(GitFixtureError, "symlink", lambda: materializer.materialize(symlink, root / "symlink-destination", expected_origin=str(symlink)))


def test_temporary_bare_remote_is_fast_forward_only_and_reports_equality() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        worktree = _repository(root)
        _run(["git", "remote", "remove", "origin"], cwd=worktree)
        remote = TemporaryBareRemote.create(root / "remote.git")
        created = remote.create_branch(worktree, "bench/main")
        assert created.remote_commit is None and not created.equal
        pushed = remote.push_branch(worktree, "bench/main")
        assert pushed.equal and pushed.local_commit == pushed.remote_commit
        assert _run(["git", "--git-dir", str(remote.path), "config", "--get", "receive.denyNonFastForwards"]) == "true"
        assert _run(["git", "--git-dir", str(remote.path), "config", "--get", "receive.denyDeletes"]) == "true"
        assert _run(["git", "remote", "get-url", "origin"], cwd=worktree) == str(remote.path)
        challenger = root / "challenger"
        _run(["git", "clone", "--branch", "bench/main", str(remote.path), str(challenger)])
        _run(["git", "config", "user.email", "statebench@example.invalid"], cwd=challenger)
        _run(["git", "config", "user.name", "StateBench fixture"], cwd=challenger)
        _commit(challenger, "challenger.txt", "advance remote\n", "advance")
        _run(["git", "push", "origin", "bench/main"], cwd=challenger)
        _commit(worktree, "local.txt", "stale local\n", "stale")
        facts = remote.equality_facts(worktree, "bench/main")
        assert not facts.equal and facts.remote_commit is not None
        _assert_raises(GitFixtureError, "non-fast-forward", lambda: remote.push_branch(worktree, "bench/main"))
        forced = subprocess.run(
            ["git", "-C", str(worktree), "push", "--force", "origin", "bench/main"],
            check=False, capture_output=True, text=True, timeout=10, shell=False,
        )
        assert forced.returncode != 0 and "denying non-fast-forward" in forced.stderr
        deleted = subprocess.run(
            ["git", "-C", str(worktree), "push", "origin", ":refs/heads/bench/main"],
            check=False, capture_output=True, text=True, timeout=10, shell=False,
        )
        assert deleted.returncode != 0 and "deletion prohibited" in deleted.stderr
        assert "force" not in inspect.signature(remote.push_branch).parameters


if __name__ == "__main__":
    test_reference_identities_are_syntax_constants_only()
    test_snapshot_resolution_is_immutable_deterministic_and_path_free()
    test_snapshot_rejects_dirty_symlink_and_invalid_compatibility()
    test_bundle_materializer_rejects_invalid_inputs_and_proves_clean_fixture()
    test_temporary_bare_remote_is_fast_forward_only_and_reports_equality()
    print("PASS")
