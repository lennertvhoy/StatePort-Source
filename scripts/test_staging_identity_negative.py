"""Negative tests for the snapshot deletion guard and post-copy rehash.

Audit S2-02 (2026-10-17): every mutant of remove_staging_snapshot, _remove_tree,
cleanup_staging_snapshot_root and the post-copy rehash in create_staging_snapshot
survived the validator-runtime suite. These tests make a broken guard visible:
they assert that nothing outside the daemon-owned snapshot root is ever deleted
or followed, and that a snapshot whose bytes change after the copy is refused.
"""

from __future__ import annotations

from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "execution-host" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "runtime-contracts" / "src"))

from execution_host import staging_identity as si  # noqa: E402
from execution_host.staging_identity import (  # noqa: E402
    StagingIdentityError,
    cleanup_staging_snapshot_root,
    create_staging_snapshot,
    remove_staging_snapshot,
    staging_manifest_digest,
)


def _victim(tmp_path: Path) -> Path:
    """A directory outside the snapshot root that must never be touched."""
    victim = tmp_path / "victim"
    (victim / "nested").mkdir(parents=True)
    (victim / "precious.txt").write_text("precious\n", encoding="utf-8")
    (victim / "nested" / "deep.txt").write_text("deep\n", encoding="utf-8")
    return victim


def _assert_victim_intact(victim: Path) -> None:
    assert (victim / "precious.txt").read_text(encoding="utf-8") == "precious\n"
    assert (victim / "nested" / "deep.txt").read_text(encoding="utf-8") == "deep\n"


def _snapshots_root(tmp_path: Path) -> Path:
    root = tmp_path / "snapshots"
    root.mkdir(mode=0o700)
    return root


def test_remove_snapshot_outside_root_is_refused_and_untouched(tmp_path: Path):
    root = _snapshots_root(tmp_path)
    victim = _victim(tmp_path)
    with pytest.raises(StagingIdentityError, match="escaped"):
        remove_staging_snapshot(victim, snapshots_root=root)
    _assert_victim_intact(victim)


def test_remove_snapshot_nested_below_root_is_refused(tmp_path: Path):
    root = _snapshots_root(tmp_path)
    nested = root / "snap" / "inner"
    nested.mkdir(parents=True)
    (nested / "f.txt").write_text("keep\n", encoding="utf-8")
    with pytest.raises(StagingIdentityError, match="escaped"):
        remove_staging_snapshot(nested, snapshots_root=root)
    assert (nested / "f.txt").read_text(encoding="utf-8") == "keep\n"


def test_remove_snapshot_refuses_the_root_itself_and_dotdot_escape(tmp_path: Path):
    root = _snapshots_root(tmp_path)
    (root / "snap").mkdir()
    victim = _victim(tmp_path)
    with pytest.raises(StagingIdentityError, match="escaped"):
        remove_staging_snapshot(root, snapshots_root=root)
    with pytest.raises(StagingIdentityError, match="escaped"):
        remove_staging_snapshot(root / "snap" / ".." / ".." / "victim", snapshots_root=root)
    assert (root / "snap").is_dir()
    _assert_victim_intact(victim)


def test_remove_snapshot_does_not_follow_a_symlinked_top_entry(tmp_path: Path):
    root = _snapshots_root(tmp_path)
    victim = _victim(tmp_path)
    link = root / "linked-snapshot"
    link.symlink_to(victim, target_is_directory=True)
    remove_staging_snapshot(link, snapshots_root=root)
    assert not link.is_symlink() and not link.exists()
    _assert_victim_intact(victim)


def test_remove_snapshot_does_not_follow_symlinked_children(tmp_path: Path):
    root = _snapshots_root(tmp_path)
    victim = _victim(tmp_path)
    outside_file = tmp_path / "outside.txt"
    outside_file.write_text("outside\n", encoding="utf-8")
    snapshot = root / "snap"
    (snapshot / "real-dir").mkdir(parents=True)
    (snapshot / "real-dir" / "inner.txt").write_text("x\n", encoding="utf-8")
    (snapshot / "dir-link").symlink_to(victim, target_is_directory=True)
    (snapshot / "file-link").symlink_to(outside_file)
    (snapshot / "real-dir" / "nested-dir-link").symlink_to(victim, target_is_directory=True)
    (snapshot / "dangling").symlink_to(tmp_path / "does-not-exist")
    remove_staging_snapshot(snapshot, snapshots_root=root)
    assert not snapshot.exists() and not snapshot.is_symlink()
    _assert_victim_intact(victim)
    assert outside_file.read_text(encoding="utf-8") == "outside\n"


def test_remove_tree_alone_does_not_follow_symlinks(tmp_path: Path):
    """The recursive helper is also reached from cleanup_staging_snapshot_root."""
    victim = _victim(tmp_path)
    outside_file = tmp_path / "outside.txt"
    outside_file.write_text("outside\n", encoding="utf-8")
    top_link = tmp_path / "top-link"
    top_link.symlink_to(victim, target_is_directory=True)
    si._remove_tree(top_link)
    assert not top_link.is_symlink()
    tree = tmp_path / "tree"
    (tree / "a").mkdir(parents=True)
    (tree / "a" / "dir-link").symlink_to(victim, target_is_directory=True)
    (tree / "file-link").symlink_to(outside_file)
    si._remove_tree(tree)
    assert not tree.exists()
    _assert_victim_intact(victim)
    assert outside_file.read_text(encoding="utf-8") == "outside\n"


def test_remove_snapshot_removes_a_normal_tree_and_tolerates_absence(tmp_path: Path):
    root = _snapshots_root(tmp_path)
    snapshot = root / "snap"
    (snapshot / "d").mkdir(parents=True)
    (snapshot / "d" / "f.txt").write_text("x\n", encoding="utf-8")
    remove_staging_snapshot(snapshot, snapshots_root=root)
    assert list(root.iterdir()) == []
    remove_staging_snapshot(snapshot, snapshots_root=root)


def test_cleanup_root_refuses_a_symlinked_root_and_leaves_target_untouched(tmp_path: Path):
    victim = _victim(tmp_path)
    (victim / "snap").mkdir()
    link_root = tmp_path / "link-root"
    link_root.symlink_to(victim, target_is_directory=True)
    with pytest.raises(StagingIdentityError, match="not a real directory"):
        cleanup_staging_snapshot_root(link_root)
    _assert_victim_intact(victim)
    assert (victim / "snap").is_dir()


def test_cleanup_root_refuses_a_regular_file_root(tmp_path: Path):
    not_a_dir = tmp_path / "root-file"
    not_a_dir.write_text("data\n", encoding="utf-8")
    with pytest.raises(StagingIdentityError, match="not a real directory"):
        cleanup_staging_snapshot_root(not_a_dir)
    assert not_a_dir.read_text(encoding="utf-8") == "data\n"


def test_cleanup_root_removes_children_without_following_symlinks(tmp_path: Path):
    victim = _victim(tmp_path)
    root = _snapshots_root(tmp_path)
    (root / "orphan" / "sub").mkdir(parents=True)
    (root / "orphan" / "sub" / "f.txt").write_text("x\n", encoding="utf-8")
    (root / "orphan" / "link").symlink_to(victim, target_is_directory=True)
    (root / "top-link").symlink_to(victim, target_is_directory=True)
    cleanup_staging_snapshot_root(root)
    assert root.is_dir() and list(root.iterdir()) == []
    _assert_victim_intact(victim)
    cleanup_staging_snapshot_root(tmp_path / "never-created")


def _source(tmp_path: Path) -> tuple[Path, Path]:
    trusted = tmp_path / "trusted"
    source = trusted / "candidate"
    (source / "sub").mkdir(parents=True)
    (source / "input.txt").write_bytes(b"candidate-bytes\n")
    (source / "sub" / "more.txt").write_bytes(b"more\n")
    return trusted, source


def test_snapshot_detects_content_changed_after_copy(tmp_path: Path, monkeypatch):
    trusted, source = _source(tmp_path)
    snapshots = tmp_path / "snapshots"
    real_digest = si.staging_manifest_digest
    seen: list[Path] = []

    def tamper_then_hash(path: Path, **kwargs):
        seen.append(Path(path))
        (Path(path) / "input.txt").write_bytes(b"tampered-bytes!\n")
        return real_digest(path, **kwargs)

    monkeypatch.setattr(si, "staging_manifest_digest", tamper_then_hash)
    with pytest.raises(StagingIdentityError, match="changed after copy"):
        create_staging_snapshot(
            source,
            trusted_root=trusted,
            snapshots_root=snapshots,
            workload_id="validator-rehash",
            max_bytes=1024,
        )
    assert len(seen) == 1
    # the refused snapshot is cleaned up, never handed to a validator
    assert list(snapshots.iterdir()) == []
    assert (source / "input.txt").read_bytes() == b"candidate-bytes\n"


def test_snapshot_detects_file_added_after_copy(tmp_path: Path, monkeypatch):
    trusted, source = _source(tmp_path)
    snapshots = tmp_path / "snapshots"
    real_digest = si.staging_manifest_digest

    def add_then_hash(path: Path, **kwargs):
        (Path(path) / "smuggled.txt").write_bytes(b"x")
        return real_digest(path, **kwargs)

    monkeypatch.setattr(si, "staging_manifest_digest", add_then_hash)
    with pytest.raises(StagingIdentityError, match="changed after copy"):
        create_staging_snapshot(
            source,
            trusted_root=trusted,
            snapshots_root=snapshots,
            workload_id="validator-rehash",
            max_bytes=1024,
        )
    assert list(snapshots.iterdir()) == []


def test_snapshot_of_unchanged_source_matches_source_digest(tmp_path: Path):
    trusted, source = _source(tmp_path)
    snapshots = tmp_path / "snapshots"
    snapshot = create_staging_snapshot(
        source,
        trusted_root=trusted,
        snapshots_root=snapshots,
        workload_id="validator-ok",
        max_bytes=1024,
    )
    assert snapshot.digest == staging_manifest_digest(source)
    assert snapshot.digest == staging_manifest_digest(snapshot.path)
    assert snapshot.path.parent == snapshots
    remove_staging_snapshot(snapshot.path, snapshots_root=snapshots)
    assert list(snapshots.iterdir()) == []
