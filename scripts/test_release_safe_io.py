from __future__ import annotations

from pathlib import Path
import os
import stat

import pytest

from release_safe_io import (
    ReleaseIOError,
    directory_identity,
    open_existing_output_root,
    prepare_output_root,
    remove_file_exact,
    remove_tree_exact,
    safe_path,
    sha256_file,
    write_bytes_create_only,
    write_json_create_only,
)


def test_external_create_only_output_refuses_traversal_and_overwrite(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    output = prepare_output_root(tmp_path / "evidence", repository=repository)
    target = write_json_create_only(output, "images/web.json", {"safe": True})
    assert sha256_file(target).startswith("sha256:")
    with pytest.raises(FileExistsError):
        write_json_create_only(output, "images/web.json", {"safe": False})
    with pytest.raises(ReleaseIOError):
        safe_path(output, "../escape.json")
    for unsafe in ("a\\b", "a\x00b", "/absolute", "a//b", "a/./b"):
        with pytest.raises(ReleaseIOError):
            safe_path(output, unsafe)


def test_output_root_refuses_repository_and_symlink(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    with pytest.raises(ReleaseIOError):
        prepare_output_root(repository, repository=repository)
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(ReleaseIOError):
        prepare_output_root(link, repository=repository)


def test_existing_output_root_is_only_available_for_explicit_resume(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    output = prepare_output_root(tmp_path / "evidence", repository=repository)
    assert open_existing_output_root(output, repository=repository) == output
    with pytest.raises(ReleaseIOError):
        open_existing_output_root(repository, repository=repository)


def test_exact_file_cleanup_refuses_links_and_removes_only_owned_file(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    output = prepare_output_root(tmp_path / "evidence", repository=repository)
    (output / "partial.json").write_text("partial", encoding="utf-8")
    remove_file_exact(output, "partial.json")
    assert not (output / "partial.json").exists()
    target = output / "target.json"
    target.write_text("target", encoding="utf-8")
    link = output / "link.json"
    link.symlink_to(target)
    with pytest.raises(ReleaseIOError):
        remove_file_exact(output, "link.json")


def test_create_only_writer_fsyncs_file_and_parent_and_refuses_hardlinks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    output = prepare_output_root(tmp_path / "evidence", repository=repository)
    observed_fsync_modes: list[int] = []
    real_fsync = os.fsync

    def recording_fsync(descriptor: int) -> None:
        observed_fsync_modes.append(os.fstat(descriptor).st_mode)
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", recording_fsync)
    written = write_bytes_create_only(output, "nested/evidence.bin", b"proof")
    assert written.read_bytes() == b"proof"
    assert any(stat.S_ISREG(mode) for mode in observed_fsync_modes)
    assert any(stat.S_ISDIR(mode) for mode in observed_fsync_modes)

    original = output / "original"
    original.write_bytes(b"same inode")
    hardlink = output / "hardlink"
    hardlink.hardlink_to(original)
    with pytest.raises(ReleaseIOError, match="singly linked"):
        sha256_file(original)
    with pytest.raises(ReleaseIOError, match="singly linked"):
        sha256_file(hardlink)


def test_private_root_and_exact_identity_bound_recursive_cleanup(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    output = prepare_output_root(tmp_path / "evidence", repository=repository)
    target = output / "registry-data"
    target.mkdir(mode=0o700)
    (target / "blob").write_bytes(b"task-owned")
    identity = directory_identity(target)

    changed = dict(identity)
    changed["inode"] = int(changed["inode"]) + 1
    with pytest.raises(ReleaseIOError, match="identity changed"):
        remove_tree_exact(output, "registry-data", expected_identity=changed)
    assert target.is_dir()

    remove_tree_exact(output, "registry-data", expected_identity=identity)
    assert not target.exists()


def test_private_root_refuses_permission_drift(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    output = prepare_output_root(tmp_path / "evidence", repository=repository)
    output.chmod(0o755)
    with pytest.raises(ReleaseIOError, match="group- or world-accessible"):
        write_json_create_only(output, "unsafe.json", {"safe": False})
