#!/usr/bin/env python3
"""Focused tests for workspace revision tracking and durable transitions.

The tracker observes real git revisions and records append-only, content-
addressed transition records.  These tests prove the required path with real
git repositories (no fakes for the git observation) and confirm fail-closed
validation of revisions, identifiers, and workspace paths.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "runtime-contracts" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "execution-host" / "src"))

from execution_host.workspace_revisions import (  # noqa: E402
    WorkspaceRevisionError,
    WorkspaceRevisionTracker,
)

_SECRET = re.compile(
    r"(?:api[_-]?key|authorization|cookie|credential|password|secret|"
    r"access[_-]?token|refresh[_-]?token|private[_-]?key)",
    re.I,
)


def _git(path: Path, *argv: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(path), *argv],
        capture_output=True,
        text=True,
        check=True,
    )


def _head(path: Path) -> str:
    return _git(path, "rev-parse", "HEAD").stdout.strip()


def _init_repo(path: Path) -> str:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", str(path)], capture_output=True, text=True, check=True)
    _git(path, "config", "user.email", "test@example.invalid")
    _git(path, "config", "user.name", "StatePort Test")
    (path / "README.md").write_text("base\n", encoding="utf-8")
    _git(path, "add", ".")
    _git(path, "commit", "-m", "base")
    return _head(path)


def _commit(path: Path, content: str, message: str) -> str:
    (path / "README.md").write_text(content, encoding="utf-8")
    _git(path, "add", ".")
    _git(path, "commit", "-m", message)
    return _head(path)


def _tracker(tmp_path: Path, *, workspace_root: Path | None = None) -> WorkspaceRevisionTracker:
    root = workspace_root if workspace_root is not None else tmp_path / "ws"
    root.mkdir(parents=True, exist_ok=True)
    return WorkspaceRevisionTracker(
        tmp_path / "state",
        workspace_root=root,
        staging_root=tmp_path / "staging",
    )


def _has_secret(node) -> bool:
    if isinstance(node, dict):
        for key, value in node.items():
            if _SECRET.search(str(key)) or _has_secret(value):
                return True
    elif isinstance(node, list):
        return any(_has_secret(item) for item in node)
    elif isinstance(node, str):
        return _SECRET.search(node) is not None
    return False


def test_revision_tracking_round_trip(tmp_path: Path):
    workspace_root = tmp_path / "ws"
    repo = workspace_root / "demo"
    base = _init_repo(repo)

    tracker = _tracker(tmp_path, workspace_root=workspace_root)
    observed = tracker.observe_revision(repo)
    assert observed == base

    record = tracker.record_transition(
        workspace_id="workspace.demo",
        workspace_path=repo,
        promotion_id="promotion.demo",
        pre_revision=base,
        post_revision=base,
        status="succeeded",
        reason="promoted",
        observed_at="2026-01-01T00:00:00Z",
    )
    assert record["formatVersion"] == "stateport.workspace-revision-transition/v1"
    assert record["workspaceId"] == "workspace.demo"
    assert record["prePromotionRevision"] == base
    assert record["postPromotionRevision"] == base
    assert record["status"] == "succeeded"
    assert record["transitionDigest"].startswith("sha256:")
    assert "workspacePathDigest" in record and record["workspacePathDigest"].startswith("sha256:")

    loaded = tracker.load_transitions("workspace.demo")
    assert len(loaded) == 1
    assert loaded[0] == record


def test_record_transition_rejects_invalid_revisions(tmp_path: Path):
    workspace_root = tmp_path / "ws"
    repo = workspace_root / "demo"
    base = _init_repo(repo)
    tracker = _tracker(tmp_path, workspace_root=workspace_root)

    with pytest.raises(WorkspaceRevisionError):
        tracker.record_transition(
            workspace_id="workspace.demo",
            workspace_path=repo,
            promotion_id="promotion.demo",
            pre_revision="not-a-sha",
            post_revision=base,
            status="succeeded",
            reason="promoted",
            observed_at="2026-01-01T00:00:00Z",
        )
    with pytest.raises(WorkspaceRevisionError):
        tracker.record_transition(
            workspace_id="workspace.demo",
            workspace_path=repo,
            promotion_id="promotion.demo",
            pre_revision=base,
            post_revision="ABCDEF" * 6 + "00",
            status="succeeded",
            reason="promoted",
            observed_at="2026-01-01T00:00:00Z",
        )
    with pytest.raises(WorkspaceRevisionError):
        tracker.record_transition(
            workspace_id="workspace.demo",
            workspace_path=repo,
            promotion_id="promotion.demo",
            pre_revision=base,
            post_revision="b" * 39,
            status="succeeded",
            reason="promoted",
            observed_at="2026-01-01T00:00:00Z",
        )


def test_post_revision_may_be_null_for_failed_transitions(tmp_path: Path):
    workspace_root = tmp_path / "ws"
    repo = workspace_root / "demo"
    base = _init_repo(repo)
    tracker = _tracker(tmp_path, workspace_root=workspace_root)

    record = tracker.record_transition(
        workspace_id="workspace.demo",
        workspace_path=repo,
        promotion_id="promotion.demo",
        pre_revision=base,
        post_revision=None,
        status="failed",
        reason="git_transition_failed",
        observed_at="2026-01-01T00:00:00Z",
    )
    assert record["postPromotionRevision"] is None
    assert tracker.load_transitions("workspace.demo")[0] == record


def test_observe_rejects_missing_workspace_path(tmp_path: Path):
    tracker = _tracker(tmp_path, workspace_root=tmp_path / "ws")
    with pytest.raises(WorkspaceRevisionError):
        tracker.observe_revision(tmp_path / "ws" / "missing")


def test_record_transition_rejects_missing_workspace_path(tmp_path: Path):
    tracker = _tracker(tmp_path, workspace_root=tmp_path / "ws")
    with pytest.raises(WorkspaceRevisionError):
        tracker.record_transition(
            workspace_id="workspace.demo",
            workspace_path=tmp_path / "ws" / "missing",
            promotion_id="promotion.demo",
            pre_revision="a" * 40,
            post_revision=None,
            status="failed",
            reason="missing",
            observed_at="2026-01-01T00:00:00Z",
        )


def test_observe_rejects_path_outside_both_roots(tmp_path: Path):
    outside = tmp_path / "outside"
    repo = outside / "repo"
    _init_repo(repo)
    tracker = _tracker(tmp_path, workspace_root=tmp_path / "ws")
    with pytest.raises(WorkspaceRevisionError):
        tracker.observe_revision(repo)


def test_record_transition_rejects_path_outside_both_roots(tmp_path: Path):
    outside = tmp_path / "outside"
    repo = outside / "repo"
    _init_repo(repo)
    tracker = _tracker(tmp_path, workspace_root=tmp_path / "ws")
    with pytest.raises(WorkspaceRevisionError):
        tracker.record_transition(
            workspace_id="workspace.demo",
            workspace_path=repo,
            promotion_id="promotion.demo",
            pre_revision="a" * 40,
            post_revision=None,
            status="failed",
            reason="outside",
            observed_at="2026-01-01T00:00:00Z",
        )


def test_path_within_staging_root_is_accepted(tmp_path: Path):
    staging = tmp_path / "staging"
    repo = staging / "stage-demo"
    base = _init_repo(repo)
    tracker = WorkspaceRevisionTracker(
        tmp_path / "state",
        workspace_root=tmp_path / "ws",
        staging_root=staging,
    )
    assert tracker.observe_revision(repo) == base


def test_observe_rejects_symlinked_workspace(tmp_path: Path):
    workspace_root = tmp_path / "ws"
    real = workspace_root / "real"
    _init_repo(real)
    link = workspace_root / "link"
    link.symlink_to(real)
    tracker = _tracker(tmp_path, workspace_root=workspace_root)
    with pytest.raises(WorkspaceRevisionError):
        tracker.observe_revision(link)


def test_record_transition_rejects_symlinked_workspace(tmp_path: Path):
    workspace_root = tmp_path / "ws"
    real = workspace_root / "real"
    _init_repo(real)
    link = workspace_root / "link"
    link.symlink_to(real)
    tracker = _tracker(tmp_path, workspace_root=workspace_root)
    with pytest.raises(WorkspaceRevisionError):
        tracker.record_transition(
            workspace_id="workspace.demo",
            workspace_path=link,
            promotion_id="promotion.demo",
            pre_revision="a" * 40,
            post_revision=None,
            status="failed",
            reason="symlink",
            observed_at="2026-01-01T00:00:00Z",
        )


def test_record_transition_rejects_invalid_identifiers(tmp_path: Path):
    workspace_root = tmp_path / "ws"
    repo = workspace_root / "demo"
    base = _init_repo(repo)
    tracker = _tracker(tmp_path, workspace_root=workspace_root)

    with pytest.raises(WorkspaceRevisionError):
        tracker.record_transition(
            workspace_id="bad id",
            workspace_path=repo,
            promotion_id="promotion.demo",
            pre_revision=base,
            post_revision=base,
            status="succeeded",
            reason="promoted",
            observed_at="2026-01-01T00:00:00Z",
        )
    with pytest.raises(WorkspaceRevisionError):
        tracker.record_transition(
            workspace_id="workspace.demo",
            workspace_path=repo,
            promotion_id="",
            pre_revision=base,
            post_revision=base,
            status="succeeded",
            reason="promoted",
            observed_at="2026-01-01T00:00:00Z",
        )


def test_record_transition_rejects_invalid_status_and_reason(tmp_path: Path):
    workspace_root = tmp_path / "ws"
    repo = workspace_root / "demo"
    base = _init_repo(repo)
    tracker = _tracker(tmp_path, workspace_root=workspace_root)

    with pytest.raises(WorkspaceRevisionError):
        tracker.record_transition(
            workspace_id="workspace.demo",
            workspace_path=repo,
            promotion_id="promotion.demo",
            pre_revision=base,
            post_revision=base,
            status="maybe",
            reason="promoted",
            observed_at="2026-01-01T00:00:00Z",
        )
    with pytest.raises(WorkspaceRevisionError):
        tracker.record_transition(
            workspace_id="workspace.demo",
            workspace_path=repo,
            promotion_id="promotion.demo",
            pre_revision=base,
            post_revision=base,
            status="succeeded",
            reason="",
            observed_at="2026-01-01T00:00:00Z",
        )


def test_transitions_are_append_only_ordered_and_reloadable(tmp_path: Path):
    workspace_root = tmp_path / "ws"
    repo = workspace_root / "demo"
    base = _init_repo(repo)
    candidate = _commit(repo, "candidate\n", "candidate")
    _git(repo, "reset", "--hard", base)

    tracker = _tracker(tmp_path, workspace_root=workspace_root)
    first = tracker.record_transition(
        workspace_id="workspace.demo",
        workspace_path=repo,
        promotion_id="promotion.one",
        pre_revision=base,
        post_revision=base,
        status="succeeded",
        reason="promoted",
        observed_at="2026-01-01T00:00:00Z",
    )
    second = tracker.record_transition(
        workspace_id="workspace.demo",
        workspace_path=repo,
        promotion_id="promotion.two",
        pre_revision=base,
        post_revision=candidate,
        status="succeeded",
        reason="promoted",
        observed_at="2026-01-01T00:00:01Z",
    )

    loaded = tracker.load_transitions("workspace.demo")
    assert [record["transitionDigest"] for record in loaded] == [
        first["transitionDigest"],
        second["transitionDigest"],
    ]
    assert loaded[0]["observedAt"] < loaded[1]["observedAt"]

    files = list((tmp_path / "state" / "workspace-revisions" / "workspace.demo").glob("*.json"))
    assert len(files) == 2
    assert tracker.load_transitions("workspace.missing") == []


def test_transition_digest_mismatch_on_tamper_raises(tmp_path: Path):
    workspace_root = tmp_path / "ws"
    repo = workspace_root / "demo"
    base = _init_repo(repo)
    tracker = _tracker(tmp_path, workspace_root=workspace_root)
    tracker.record_transition(
        workspace_id="workspace.demo",
        workspace_path=repo,
        promotion_id="promotion.demo",
        pre_revision=base,
        post_revision=base,
        status="succeeded",
        reason="promoted",
        observed_at="2026-01-01T00:00:00Z",
    )

    record_path = (tmp_path / "state" / "workspace-revisions" / "workspace.demo").glob("*.json")
    target = next(record_path)
    payload = json.loads(target.read_text(encoding="utf-8"))
    payload["reason"] = "tampered"
    target.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(WorkspaceRevisionError):
        tracker.load_transitions("workspace.demo")


def test_no_secrets_appear_in_transition_records(tmp_path: Path):
    workspace_root = tmp_path / "ws"
    repo = workspace_root / "demo"
    base = _init_repo(repo)
    tracker = _tracker(tmp_path, workspace_root=workspace_root)
    tracker.record_transition(
        workspace_id="workspace.demo",
        workspace_path=repo,
        promotion_id="promotion.demo",
        pre_revision=base,
        post_revision=base,
        status="succeeded",
        reason="promoted",
        observed_at="2026-01-01T00:00:00Z",
    )

    loaded = tracker.load_transitions("workspace.demo")
    assert _has_secret(loaded) is False
    for path in (tmp_path / "state" / "workspace-revisions").rglob("*.json"):
        assert _SECRET.search(path.read_text(encoding="utf-8")) is None


def test_git_observation_uses_trusted_binary_and_minimal_environment(
    tmp_path: Path, monkeypatch
):
    workspace_root = tmp_path / "ws"
    repo = workspace_root / "demo"
    base = _init_repo(repo)
    attacker_bin = tmp_path / "attacker-bin"
    attacker_bin.mkdir()
    marker = tmp_path / "attacker-git-ran"
    fake_git = attacker_bin / "git"
    fake_git.write_text(
        f"#!/bin/sh\ntouch {marker}\nexit 99\n",
        encoding="utf-8",
    )
    fake_git.chmod(0o755)
    monkeypatch.setenv("PATH", str(attacker_bin))
    monkeypatch.setenv("LD_PRELOAD", "/tmp/attacker-preload.so")
    monkeypatch.setenv("GIT_DIR", "/tmp/attacker-git-dir")
    monkeypatch.setenv("PYTHONPATH", "/tmp/attacker-python")

    tracker = _tracker(tmp_path, workspace_root=workspace_root)
    environment = tracker.git_environment()
    assert set(environment) == {
        "GIT_ATTR_NOSYSTEM",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_SYSTEM",
        "GIT_EDITOR",
        "GIT_MERGE_AUTOEDIT",
        "GIT_NO_LAZY_FETCH",
        "GIT_NO_REPLACE_OBJECTS",
        "GIT_PROTOCOL_FROM_USER",
        "GIT_TERMINAL_PROMPT",
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "TZ",
        "XDG_CONFIG_HOME",
    }
    assert "LD_PRELOAD" not in environment
    assert "GIT_DIR" not in environment
    assert "PYTHONPATH" not in environment
    assert tracker.git_executable.is_absolute()
    assert tracker.observe_revision(repo) == base
    assert not marker.exists()


def test_observe_rejects_local_core_worktree_indirection(tmp_path: Path):
    workspace_root = tmp_path / "ws"
    repo = workspace_root / "demo"
    _init_repo(repo)
    outside = tmp_path / "outside-worktree"
    outside.mkdir()
    _git(repo, "config", "core.worktree", str(outside))
    tracker = _tracker(tmp_path, workspace_root=workspace_root)

    with pytest.raises(WorkspaceRevisionError, match="worktree"):
        tracker.observe_revision(repo)


def test_observe_rejects_unregistered_git_directory_indirection(tmp_path: Path):
    workspace_root = tmp_path / "ws"
    victim = workspace_root / "victim"
    other = workspace_root / "other"
    _init_repo(victim)
    _init_repo(other)
    (victim / ".git").rename(victim / "saved-git")
    (victim / ".git").write_text(f"gitdir: {other / '.git'}\n", encoding="utf-8")
    tracker = _tracker(tmp_path, workspace_root=workspace_root)

    with pytest.raises(WorkspaceRevisionError, match="back pointer|registration"):
        tracker.observe_revision(victim)


def test_registered_linked_worktree_is_identity_checked_and_supported(tmp_path: Path):
    source = tmp_path / "source"
    base = _init_repo(source)
    workspace_root = tmp_path / "ws"
    workspace_root.mkdir()
    linked = workspace_root / "linked"
    _git(source, "worktree", "add", "-q", "-b", "linked-test", str(linked), base)
    tracker = _tracker(tmp_path, workspace_root=workspace_root)

    identity = tracker.workspace_identity(linked)
    assert identity.linked_worktree is True
    assert identity.workspace_path == linked
    assert identity.git_dir != linked / ".git"
    assert tracker.observe_revision(linked, expected_identity=identity) == base


def test_observe_rejects_a_symlinked_parent_component(tmp_path: Path):
    workspace_root = tmp_path / "ws"
    real_parent = workspace_root / "real-parent"
    repo = real_parent / "demo"
    _init_repo(repo)
    alias = workspace_root / "alias"
    alias.symlink_to(real_parent, target_is_directory=True)
    tracker = _tracker(tmp_path, workspace_root=workspace_root)

    with pytest.raises(WorkspaceRevisionError, match="canonical|symlink"):
        tracker.observe_revision(alias / "demo")


def test_malformed_transition_record_raises_typed_error(tmp_path: Path):
    workspace_root = tmp_path / "ws"
    repo = workspace_root / "demo"
    base = _init_repo(repo)
    tracker = _tracker(tmp_path, workspace_root=workspace_root)
    record = tracker.record_transition(
        workspace_id="workspace.demo",
        workspace_path=repo,
        promotion_id="promotion.demo",
        pre_revision=base,
        post_revision=base,
        status="failed",
        reason="test",
        observed_at="2026-01-01T00:00:00Z",
    )
    path = (
        tmp_path
        / "state"
        / "workspace-revisions"
        / "workspace.demo"
        / f"{record['transitionDigest'].split(':', 1)[1]}.json"
    )
    path.write_bytes(b'{"formatVersion":')

    with pytest.raises(WorkspaceRevisionError, match="malformed"):
        tracker.load_transitions("workspace.demo")
