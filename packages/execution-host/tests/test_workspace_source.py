"""Pure source authority tests; Git is used only to create review fixtures."""

from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tarfile

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "packages/execution-host/src"))

from execution_host import daemon_contract as contract
from execution_host.deployment_staging import _tar_info
from execution_host.workspace_source import (
    WorkspaceSourceRefusal,
    _tree_oid,
    _ArchiveSink,
    stream_verified_source_archive,
    validate_source_commit,
    verify_source_commit,
)


def _git(path: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=path, check=True, text=True, capture_output=True
    ).stdout.strip()


def _fixture(tmp_path: Path) -> tuple[Path, dict]:
    root = tmp_path / "project"
    root.mkdir(mode=0o700)
    _git(root, "init", "--quiet")
    _git(root, "config", "user.email", "test@example.invalid")
    _git(root, "config", "user.name", "Source Test")
    (root / "README.md").write_bytes(b"reviewed source\n")
    (root / "README.md").chmod(0o600)
    (root / "a").write_bytes(b"file before a directory\n")
    (root / "a").chmod(0o600)
    (root / "a.b").mkdir(mode=0o700)
    (root / "a.b" / "inside").write_bytes(b"directory beside a file\n")
    (root / "a.b" / "inside").chmod(0o600)
    (root / "bin").mkdir(mode=0o700)
    (root / "bin" / "run.sh").write_bytes(b"#!/bin/sh\nexit 0\n")
    (root / "bin" / "run.sh").chmod(0o700)
    _git(root, "add", "README.md", "a", "a.b/inside", "bin/run.sh")
    _git(root, "commit", "--quiet", "-m", "reviewed source")
    commit = _git(root, "rev-parse", "HEAD")
    raw_commit = subprocess.run(
        ["git", "cat-file", "commit", commit], cwd=root, check=True, capture_output=True
    ).stdout
    inventory = []
    for path, mode in (("a", "100644"), ("a.b/inside", "100644"), ("README.md", "100644"), ("bin/run.sh", "100755")):
        content = (root / path).read_bytes()
        inventory.append({
            "path": path,
            "mode": mode,
            "contentDigest": "sha256:" + hashlib.sha256(content).hexdigest(),
        })
    context = [
        {"path": row["path"], "mode": row["mode"], "size": (root / row["path"]).stat().st_size,
         "sha256": row["contentDigest"]}
        for row in inventory
    ]
    archive_bytes = io.BytesIO()
    with tarfile.open(fileobj=archive_bytes, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for row in inventory:
            content = (root / row["path"]).read_bytes()
            mode = 0o755 if row["mode"] == "100755" else 0o644
            archive.addfile(_tar_info(f"context/{row['path']}", size=len(content), mode=mode), io.BytesIO(content))
    encoded_archive = archive_bytes.getvalue()
    source = {
        "baseRevision": commit,
        "commitObject": base64.b64encode(raw_commit).decode("ascii"),
        "sourceInventory": inventory,
        "sourceArchive": {
            "formatVersion": "stateport.deployment-context-archive/v1",
            "archiveDigest": "sha256:" + hashlib.sha256(encoded_archive).hexdigest(),
            "archiveBytes": len(encoded_archive),
            "contextDigest": contract.canonical_digest(context),
            "fileCount": len(inventory),
        },
        "descriptorDigest": "sha256:" + "d" * 64,
    }
    return root, source


def _source_fd(root: Path) -> int:
    return os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)


def test_valid_commit_and_git_tree_ordering_are_verified(tmp_path: Path) -> None:
    root, source = _fixture(tmp_path)
    fd = _source_fd(root)
    try:
        verify_source_commit(fd, source, os.getuid())
    finally:
        os.close(fd)


def test_unlisted_file_is_not_part_of_reviewed_snapshot(tmp_path: Path) -> None:
    root, source = _fixture(tmp_path)
    (root / ".stateport").mkdir(mode=0o700)
    (root / ".stateport" / "managed-incarnation.json").write_text("marker")
    (root / "ignored.tmp").write_text("unlisted")
    fd = _source_fd(root)
    try:
        verify_source_commit(fd, source, os.getuid())
    finally:
        os.close(fd)


def test_changed_missing_or_extra_inventory_cannot_match_tree(tmp_path: Path) -> None:
    root, source = _fixture(tmp_path)
    changed = deepcopy(source)
    (root / "README.md").write_bytes(b"changed source\n")
    fd = _source_fd(root)
    try:
        with pytest.raises(WorkspaceSourceRefusal):
            verify_source_commit(fd, changed, os.getuid())
    finally:
        os.close(fd)

    missing = deepcopy(source)
    missing["sourceInventory"] = missing["sourceInventory"][:1]
    missing["sourceArchive"]["fileCount"] = 1
    missing["sourceArchive"]["contextDigest"] = contract.canonical_digest([
        {"path": "a", "mode": "100644", "size": 24, "sha256": source["sourceInventory"][0]["contentDigest"]}
    ])
    fd = _source_fd(root)
    try:
        with pytest.raises(WorkspaceSourceRefusal):
            verify_source_commit(fd, missing, os.getuid())
    finally:
        os.close(fd)


def test_symlink_parent_and_unsafe_witness_refuse(tmp_path: Path) -> None:
    root, source = _fixture(tmp_path)
    saved = root / "bin.real"
    (root / "bin").rename(saved)
    (root / "bin").symlink_to(saved, target_is_directory=True)
    fd = _source_fd(root)
    try:
        with pytest.raises(WorkspaceSourceRefusal):
            verify_source_commit(fd, source, os.getuid())
    finally:
        os.close(fd)

    invalid = deepcopy(source)
    invalid["commitObject"] = base64.b64encode(b"tree " + b"0" * 40 + b"\n\n").decode("ascii")
    with pytest.raises(WorkspaceSourceRefusal):
        validate_source_commit(invalid)


def test_archive_metadata_owner_hardlink_fifo_and_mode_are_fail_closed(tmp_path: Path) -> None:
    root, source = _fixture(tmp_path)

    forged = deepcopy(source)
    forged["sourceArchive"]["archiveDigest"] = "sha256:" + "e" * 64
    fd = _source_fd(root)
    try:
        with pytest.raises(WorkspaceSourceRefusal):
            verify_source_commit(fd, forged, os.getuid())
    finally:
        os.close(fd)

    forged = deepcopy(source)
    forged["sourceArchive"]["archiveBytes"] += 1
    fd = _source_fd(root)
    try:
        with pytest.raises(WorkspaceSourceRefusal):
            verify_source_commit(fd, forged, os.getuid())
    finally:
        os.close(fd)

    with pytest.raises(WorkspaceSourceRefusal):
        fd = _source_fd(root)
        try:
            verify_source_commit(fd, source, os.getuid() + 1)
        finally:
            os.close(fd)

    hardlink = root / "alias"
    hardlink.hardlink_to(root / "README.md")
    linked = deepcopy(source)
    linked["sourceInventory"].append({
        "path": "alias", "mode": "100644",
        "contentDigest": source["sourceInventory"][2]["contentDigest"],
    })
    linked["sourceArchive"]["fileCount"] += 1
    fd = _source_fd(root)
    try:
        with pytest.raises(WorkspaceSourceRefusal):
            verify_source_commit(fd, linked, os.getuid())
    finally:
        os.close(fd)

    fifo = root / "pipe"
    os.mkfifo(fifo, 0o600)
    piped = deepcopy(source)
    piped["sourceInventory"].append({
        "path": "pipe", "mode": "100644", "contentDigest": "sha256:" + "f" * 64,
    })
    piped["sourceArchive"]["fileCount"] += 1
    fd = _source_fd(root)
    try:
        with pytest.raises(WorkspaceSourceRefusal):
            verify_source_commit(fd, piped, os.getuid())
    finally:
        os.close(fd)

    (root / "bin" / "run.sh").chmod(0o644)
    fd = _source_fd(root)
    try:
        with pytest.raises(WorkspaceSourceRefusal):
            verify_source_commit(fd, source, os.getuid())
    finally:
        os.close(fd)


def test_context_budget_is_preflighted_and_archive_sink_is_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root, source = _fixture(tmp_path)
    monkeypatch.setattr(contract, "MAX_DEPLOYMENT_CONTEXT_BYTES", 1)
    fd = _source_fd(root)
    try:
        with pytest.raises(WorkspaceSourceRefusal):
            verify_source_commit(fd, source, os.getuid())
    finally:
        os.close(fd)

    monkeypatch.setattr(contract, "MAX_DEPLOYMENT_ARCHIVE_BYTES", 8)
    sink = _ArchiveSink()
    with pytest.raises(WorkspaceSourceRefusal):
        sink.write(b"x" * 9)


def test_verified_archive_is_streamed_from_the_same_fd_reads(tmp_path: Path) -> None:
    root, source = _fixture(tmp_path)
    archive = io.BytesIO()
    fd = _source_fd(root)
    try:
        observed = stream_verified_source_archive(archive, fd, source, os.getuid())
    finally:
        os.close(fd)
    assert observed == source["sourceArchive"]
    with tarfile.open(fileobj=io.BytesIO(archive.getvalue()), mode="r:") as tar:
        assert tar.getnames() == ["context/a", "context/a.b/inside", "context/README.md", "context/bin/run.sh"]


def test_deep_bounded_git_tree_hash_is_iterative(tmp_path: Path) -> None:
    root = tmp_path / "deep"
    root.mkdir(mode=0o700)
    _git(root, "init", "--quiet")
    _git(root, "config", "user.email", "test@example.invalid")
    _git(root, "config", "user.name", "Source Test")
    current = root
    for _ in range(1100):
        current = current / "a"
        current.mkdir(mode=0o700)
    leaf = current / "file"
    leaf.write_bytes(b"deep tree\n")
    leaf.chmod(0o600)
    _git(root, "add", "--all")
    _git(root, "commit", "--quiet", "-m", "deep tree")
    path = "/".join(["a"] * 1100 + ["file"])
    content = leaf.read_bytes()
    blob = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
    assert _tree_oid([(path, "100644", blob)]) == _git(root, "rev-parse", "HEAD^{tree}")
