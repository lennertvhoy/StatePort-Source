#!/usr/bin/env python3
"""Adversarial acceptance tests for the scoped file-workspace broker."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "file-workspace-broker" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "governed-runner" / "src"))

import stateport_file_workspace.broker as broker_module  # noqa: E402
from stateport_file_workspace import (  # noqa: E402
    FILE_WORKSPACE_FORMAT,
    FileWorkspaceAccessDenied,
    FileWorkspaceAtomicWriteError,
    FileWorkspaceBroker,
    FileWorkspaceLeaseDenied,
    FileWorkspacePathError,
    FileWorkspaceProfile,
    FileWorkspaceStale,
    FileWorkspaceTypeRefused,
    FileWorkspaceValidationError,
    PathPolicyRule,
)


APP = "stateport.development-reference"
INSTANCE = "project.demo"
ALICE = "actor.alice"


def _git(project: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(project), *args],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.stdout.strip()


def _sha(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _project(tmp_path: Path) -> Path:
    project = tmp_path / "project"
    (project / "src").mkdir(parents=True)
    (project / "generated").mkdir()
    (project / "scratch").mkdir()
    (project / "src" / "main.py").write_text("answer = 41\n", encoding="utf-8")
    (project / "src" / "data.json").write_text('{"answer": 41}\n', encoding="utf-8")
    (project / "src" / "binary.txt").write_bytes(b"safe\0binary")
    (project / "generated" / "build.txt").write_text("generated\n", encoding="utf-8")
    (project / "scratch" / "notes.md").write_text("# Notes\n", encoding="utf-8")
    (project / "README.md").write_text("# Project\n", encoding="utf-8")
    (project / "PROJECT_STATE.yaml").write_text("safe: true\n", encoding="utf-8")
    _git(project, "init", "-q", "-b", "main")
    _git(project, "config", "user.email", "stateport-fixture@example.invalid")
    _git(project, "config", "user.name", "StatePort Fixture")
    _git(project, "add", ".")
    _git(project, "commit", "-q", "-m", "fixture")
    return project


def _profile(project: Path, *, maximum_file_bytes: int = 1_048_576) -> FileWorkspaceProfile:
    return FileWorkspaceProfile(
        profile_id="profile.files.demo",
        application_id=APP,
        application_kind="development",
        instance_id=INSTANCE,
        project_root=project,
        expected_root_identity=(os.lstat(project).st_dev, os.lstat(project).st_ino),
        effective_capabilities=frozenset({"workbench", "file_viewer", "editor"}),
        actor_permissions={
            ALICE: frozenset({"file.read", "file.write"}),
            "actor.bob": frozenset({"file.read"}),
        },
        path_rules=(
            PathPolicyRule("rule.src", "src", "subtree", "application_owned", True, True, True, True, True),
            PathPolicyRule("rule.readme", "README.md", "exact", "application_owned", True, True, False, False, False),
            PathPolicyRule("rule.canonical", "PROJECT_STATE.yaml", "exact", "canonical", True, False, False, False, False),
            PathPolicyRule("rule.generated", "generated", "subtree", "generated", True, False, False, False, False),
            PathPolicyRule("rule.scratch", "scratch", "subtree", "disposable", True, True, True, True, True),
        ),
        maximum_file_bytes=maximum_file_bytes,
    )


def _broker(tmp_path: Path, *, maximum_file_bytes: int = 1_048_576) -> tuple[FileWorkspaceBroker, Path]:
    project = _project(tmp_path)
    broker = FileWorkspaceBroker(
        _profile(project, maximum_file_bytes=maximum_file_bytes),
        lease_directory=tmp_path / "leases",
    )
    return broker, project


def _broker_with_mutable_base(tmp_path: Path) -> tuple[FileWorkspaceBroker, Path, dict[str, str]]:
    project = _project(tmp_path)
    state = {"head": _git(project, "rev-parse", "HEAD")}
    broker = FileWorkspaceBroker(
        _profile(project),
        lease_directory=tmp_path / "leases",
        base_sha_provider=lambda _root_fd: state["head"],
    )
    return broker, project, state


def _identity() -> dict[str, str]:
    return {"actor_id": ALICE, "application_id": APP, "instance_id": INSTANCE}


def _recovery_artifacts(project: Path) -> list[Path]:
    return sorted(
        path
        for path in project.rglob(".stateport-*.tmp")
        if path.is_file()
    )


def _recovery_values(project: Path) -> list[bytes]:
    return [path.read_bytes() for path in _recovery_artifacts(project)]


def test_contracts_and_wire_method_names_are_versioned_and_root_is_not_serialized(tmp_path: Path) -> None:
    broker, project = _broker(tmp_path)
    try:
        profile = broker.profile_description(**_identity())
        assert profile["formatVersion"] == FILE_WORKSPACE_FORMAT
        assert profile["applicationId"] == APP
        assert str(project) not in repr(profile)
        listing = broker.listDirectory("", **_identity()).to_dict()
        assert listing["operation"] == "listDirectory"
        assert listing["formatVersion"] == FILE_WORKSPACE_FORMAT
        assert {entry["path"] for entry in listing["entries"]} >= {"src", "generated", "scratch", "README.md", "PROJECT_STATE.yaml"}
        assert callable(broker.readFile) and callable(broker.readFileMetadata)
        assert callable(broker.prepareWrite) and callable(broker.previewDiff)
        assert callable(broker.commitWrite) and callable(broker.discardWrite)
        assert callable(broker.renamePath) and callable(broker.createFile) and callable(broker.deletePath)
    finally:
        broker.close()


def test_read_and_metadata_bind_hash_base_language_and_classification(tmp_path: Path) -> None:
    broker, project = _broker(tmp_path)
    try:
        value = broker.read_file("src/main.py", **_identity())
        assert value.content == "answer = 41\n"
        assert value.metadata.content_hash == _sha(value.content)
        assert value.metadata.base_sha == _git(project, "rev-parse", "HEAD")
        assert value.metadata.language == "python"
        assert value.metadata.ownership_class == "application_owned"
        generated = broker.read_file_metadata("generated/build.txt", **_identity()).to_dict()
        assert generated["generated"] is True and generated["readOnly"] is True
        disposable = broker.read_file_metadata("scratch/notes.md", **_identity()).to_dict()
        assert disposable["disposable"] is True
    finally:
        broker.close()


def test_generated_read_only_file_cannot_be_deleted(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="read-only"):
        PathPolicyRule(
            "invalid.generated",
            "generated",
            "subtree",
            "generated",
            True,
            False,
            False,
            False,
            True,
        )
    broker, project = _broker(tmp_path)
    try:
        generated = broker.read_file_metadata("generated/build.txt", **_identity())
        assert generated.read_only is True
        with pytest.raises(FileWorkspaceAccessDenied):
            broker.delete_path(
                "generated/build.txt",
                expected_content_hash=generated.content_hash,
                expected_base_sha=generated.base_sha,
                **_identity(),
            )
        assert (project / "generated" / "build.txt").read_text(encoding="utf-8") == "generated\n"
    finally:
        broker.close()


@pytest.mark.parametrize(
    "path",
    [
        "../outside.txt", "src/../outside.txt", "/etc/passwd", "src\\..\\outside.txt",
        "src//main.py", "src/%2e%2e/outside.txt", "src/%252e%252e/outside.txt",
        "src/%2fetc/passwd", "src/%5coutside.txt", "file://etc/passwd", "src/./main.py",
        "src/main.py/", " src/main.py", "src/main.py ",
    ],
)
def test_traversal_encoded_and_mixed_separator_paths_fail_closed(tmp_path: Path, path: str) -> None:
    broker, _ = _broker(tmp_path)
    try:
        with pytest.raises((FileWorkspacePathError, FileWorkspaceTypeRefused)):
            broker.read_file(path, **_identity())
    finally:
        broker.close()


@pytest.mark.parametrize(
    "path",
    [
        ".git/config", "node_modules/pkg/index.js", ".stateport/runtime.json",
        ".ssh/config", ".aws/credentials", "src/.env", "src/.npmrc",
        "src/id_rsa", "src/client.pem", "src/secrets.yaml",
    ],
)
def test_operational_dependency_and_credential_like_paths_are_unavailable(tmp_path: Path, path: str) -> None:
    broker, project = _broker(tmp_path)
    target = project / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("not-a-secret fixture\n", encoding="utf-8")
    try:
        with pytest.raises((FileWorkspacePathError, FileWorkspaceTypeRefused)):
            broker.read_file(path, **_identity())
    finally:
        broker.close()


def test_unknown_paths_and_unsupported_types_fail_closed(tmp_path: Path) -> None:
    broker, project = _broker(tmp_path)
    (project / "unknown").mkdir()
    (project / "unknown" / "note.txt").write_text("hidden\n", encoding="utf-8")
    (project / "src" / "image.png").write_bytes(b"not really an image")
    try:
        with pytest.raises(FileWorkspacePathError, match="not classified"):
            broker.read_file("unknown/note.txt", **_identity())
        with pytest.raises(FileWorkspaceTypeRefused, match="file type"):
            broker.read_file("src/image.png", **_identity())
        root = broker.list_directory("", **_identity()).to_dict()
        assert "unknown" not in {entry["name"] for entry in root["entries"]}
    finally:
        broker.close()


def test_symlink_file_and_directory_escape_are_never_followed(tmp_path: Path) -> None:
    broker, project = _broker(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside\n", encoding="utf-8")
    (project / "src" / "link.txt").symlink_to(outside)
    (project / "src" / "linked-dir").symlink_to(tmp_path, target_is_directory=True)
    try:
        listing = broker.list_directory("src", **_identity()).to_dict()
        symlinks = {entry["name"]: entry for entry in listing["entries"] if entry["kind"] == "symlink"}
        assert {"link.txt", "linked-dir"} <= set(symlinks)
        assert all(item["readOnly"] for item in symlinks.values())
        with pytest.raises(FileWorkspacePathError):
            broker.read_file("src/link.txt", **_identity())
        with pytest.raises(FileWorkspacePathError):
            broker.list_directory("src/linked-dir", **_identity())
        assert outside.read_text(encoding="utf-8") == "outside\n"
    finally:
        broker.close()


def test_hardlinks_cannot_import_or_export_content_across_the_project_boundary(tmp_path: Path) -> None:
    broker, project = _broker(tmp_path)
    outside = tmp_path / "outside.py"
    outside.write_text("OUTSIDE_VALUE = 'not project content'\n", encoding="utf-8")
    os.link(outside, project / "src" / "outside.py")
    os.link(project / "src" / "main.py", tmp_path / "exported-main.py")
    try:
        listing = broker.list_directory("src", **_identity()).to_dict()
        entries = {entry["name"]: entry for entry in listing["entries"]}
        assert entries["outside.py"]["kind"] == "unavailable"
        assert entries["main.py"]["kind"] == "unavailable"
        with pytest.raises(FileWorkspacePathError, match="hard-linked"):
            broker.read_file("src/outside.py", **_identity())
        with pytest.raises(FileWorkspacePathError, match="hard-linked"):
            broker.read_file("src/main.py", **_identity())
        assert outside.read_text(encoding="utf-8") == "OUTSIDE_VALUE = 'not project content'\n"
    finally:
        broker.close()


def test_diff_first_write_requires_exact_preview_digest_and_returns_content_free_receipt(tmp_path: Path) -> None:
    broker, project = _broker(tmp_path)
    try:
        opened = broker.read_file("src/main.py", **_identity())
        prepared = broker.prepare_write(
            "src/main.py", "answer = 42\n",
            expected_content_hash=opened.metadata.content_hash,
            expected_base_sha=opened.metadata.base_sha,
            **_identity(),
        )
        with pytest.raises(FileWorkspaceStale, match="previewed"):
            broker.commit_write(prepared.prepared_write_id, confirmed_diff_digest=_sha(b"no"), **_identity())
        preview = broker.preview_diff(prepared.prepared_write_id, **_identity())
        assert "-answer = 41" in preview.diff and "+answer = 42" in preview.diff
        with pytest.raises(FileWorkspaceStale, match="confirmation"):
            broker.commit_write(prepared.prepared_write_id, confirmed_diff_digest=_sha(b"wrong"), **_identity())
        receipt = broker.commit_write(prepared.prepared_write_id, confirmed_diff_digest=preview.diff_digest, **_identity()).to_dict()
        assert (project / "src" / "main.py").read_text(encoding="utf-8") == "answer = 42\n"
        assert receipt["operation"] == "commitWrite"
        assert receipt["preHash"] == opened.metadata.content_hash
        assert receipt["postHash"] == _sha("answer = 42\n")
        assert receipt["diffDigest"] == preview.diff_digest
        assert receipt["contentRetained"] is False
        assert "answer = 42" not in repr(receipt)
        assert not list((project / "src").glob(".stateport-write-*.tmp"))
    finally:
        broker.close()


def test_stale_external_write_is_rejected_and_both_versions_are_preserved(tmp_path: Path) -> None:
    broker, project = _broker(tmp_path)
    try:
        opened = broker.read_file("src/main.py", **_identity())
        prepared = broker.prepare_write(
            "src/main.py", "answer = 42\n",
            expected_content_hash=opened.metadata.content_hash,
            expected_base_sha=opened.metadata.base_sha,
            **_identity(),
        )
        preview = broker.preview_diff(prepared.prepared_write_id, **_identity())
        (project / "src" / "main.py").write_text("answer = 99\n", encoding="utf-8")
        with pytest.raises(FileWorkspaceStale) as caught:
            broker.commit_write(prepared.prepared_write_id, confirmed_diff_digest=preview.diff_digest, **_identity())
        assert caught.value.current_hash == _sha("answer = 99\n")
        assert (project / "src" / "main.py").read_text(encoding="utf-8") == "answer = 99\n"
        # The candidate remains in bounded broker memory and can still be
        # reviewed/discarded, but the released lease makes it non-committable.
        preserved = broker.preview_diff(prepared.prepared_write_id, **_identity())
        assert "+answer = 42" in preserved.diff
        with pytest.raises(FileWorkspaceStale, match="commit-capable"):
            broker.commit_write(prepared.prepared_write_id, confirmed_diff_digest=preserved.diff_digest, **_identity())
        assert broker.discard_write(prepared.prepared_write_id, **_identity())["discarded"] is True
    finally:
        broker.close()


def test_writer_lease_refuses_a_second_broker_for_the_same_root(tmp_path: Path) -> None:
    project = _project(tmp_path)
    first = FileWorkspaceBroker(_profile(project), lease_directory=tmp_path / "leases")
    second = FileWorkspaceBroker(_profile(project), lease_directory=tmp_path / "leases")
    try:
        opened = first.read_file("src/main.py", **_identity())
        pending = first.prepare_write("src/main.py", "answer = 42\n", expected_content_hash=opened.metadata.content_hash, expected_base_sha=opened.metadata.base_sha, **_identity())
        opened_again = second.read_file("src/main.py", **_identity())
        with pytest.raises(FileWorkspaceLeaseDenied):
            second.prepare_write("src/main.py", "answer = 43\n", expected_content_hash=opened_again.metadata.content_hash, expected_base_sha=opened_again.metadata.base_sha, **_identity())
        first.discard_write(pending.prepared_write_id, **_identity())
        accepted = second.prepare_write("src/main.py", "answer = 43\n", expected_content_hash=opened_again.metadata.content_hash, expected_base_sha=opened_again.metadata.base_sha, **_identity())
        second.discard_write(accepted.prepared_write_id, **_identity())
    finally:
        first.close()
        second.close()


def test_git_base_drift_refuses_commit_even_when_file_hash_is_unchanged(tmp_path: Path) -> None:
    broker, project = _broker(tmp_path)
    try:
        opened = broker.read_file("src/main.py", **_identity())
        pending = broker.prepare_write("src/main.py", "answer = 42\n", expected_content_hash=opened.metadata.content_hash, expected_base_sha=opened.metadata.base_sha, **_identity())
        preview = broker.preview_diff(pending.prepared_write_id, **_identity())
        (project / "scratch" / "base-change.md").write_text("base drift\n", encoding="utf-8")
        _git(project, "add", "scratch/base-change.md")
        _git(project, "commit", "-q", "-m", "drift")
        with pytest.raises(FileWorkspaceStale, match="base changed"):
            broker.commit_write(pending.prepared_write_id, confirmed_diff_digest=preview.diff_digest, **_identity())
        assert (project / "src" / "main.py").read_text(encoding="utf-8") == "answer = 41\n"
        broker.discard_write(pending.prepared_write_id, **_identity())
    finally:
        broker.close()


def test_atomic_replace_failure_preserves_original_and_removes_temporary_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    broker, project = _broker(tmp_path)
    try:
        opened = broker.read_file("src/main.py", **_identity())
        pending = broker.prepare_write("src/main.py", "answer = 42\n", expected_content_hash=opened.metadata.content_hash, expected_base_sha=opened.metadata.base_sha, **_identity())
        preview = broker.preview_diff(pending.prepared_write_id, **_identity())

        def fail_replace(*args, **kwargs):
            raise OSError("fixture replacement failure")

        monkeypatch.setattr(broker_module, "_rename_exchange", fail_replace)
        with pytest.raises(FileWorkspaceAtomicWriteError):
            broker.commit_write(pending.prepared_write_id, confirmed_diff_digest=preview.diff_digest, **_identity())
        assert (project / "src" / "main.py").read_text(encoding="utf-8") == "answer = 41\n"
        assert not list((project / "src").glob(".stateport-write-*.tmp"))
        broker.discard_write(pending.prepared_write_id, **_identity())
    finally:
        broker.close()


def test_symlink_swap_during_commit_is_rejected_without_touching_target(tmp_path: Path) -> None:
    broker, project = _broker(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside\n", encoding="utf-8")
    try:
        opened = broker.read_file("src/main.py", **_identity())
        pending = broker.prepare_write("src/main.py", "answer = 42\n", expected_content_hash=opened.metadata.content_hash, expected_base_sha=opened.metadata.base_sha, **_identity())
        preview = broker.preview_diff(pending.prepared_write_id, **_identity())

        def swap(_: str) -> None:
            target = project / "src" / "main.py"
            target.unlink()
            target.symlink_to(outside)

        broker._before_replace = swap
        with pytest.raises(FileWorkspaceStale, match="identity changed"):
            broker.commit_write(pending.prepared_write_id, confirmed_diff_digest=preview.diff_digest, **_identity())
        assert outside.read_text(encoding="utf-8") == "outside\n"
        assert (project / "src" / "main.py").is_symlink()
        broker.discard_write(pending.prepared_write_id, **_identity())
    finally:
        broker.close()


def test_root_rename_aborts_without_retargeting_open_broker_to_replacement_directory(tmp_path: Path) -> None:
    broker, project = _broker(tmp_path)
    moved = tmp_path / "moved-project"
    project.rename(moved)
    project.mkdir()
    (project / "src").mkdir()
    (project / "src" / "main.py").write_text("replacement = True\n", encoding="utf-8")
    try:
        with pytest.raises(FileWorkspacePathError, match="bound project root"):
            broker.read_file("src/main.py", **_identity())
        assert (moved / "src" / "main.py").read_text(encoding="utf-8") == "answer = 41\n"
        assert (project / "src" / "main.py").read_text(encoding="utf-8") == "replacement = True\n"
    finally:
        broker.close()


def test_binary_oversized_and_invalid_json_content_are_refused(tmp_path: Path) -> None:
    broker, project = _broker(tmp_path, maximum_file_bytes=128)
    (project / "src" / "large.txt").write_text("x" * 129, encoding="utf-8")
    try:
        with pytest.raises(FileWorkspaceTypeRefused, match="binary"):
            broker.read_file("src/binary.txt", **_identity())
        with pytest.raises(FileWorkspaceTypeRefused, match="size limit"):
            broker.read_file("src/large.txt", **_identity())
        opened = broker.read_file("src/data.json", **_identity())
        with pytest.raises(FileWorkspaceValidationError, match="invalid JSON"):
            broker.prepare_write("src/data.json", '{"broken": }', expected_content_hash=opened.metadata.content_hash, expected_base_sha=opened.metadata.base_sha, **_identity())
    finally:
        broker.close()


def test_a12_canonical_paths_are_read_only_without_authoritative_transaction_boundary(tmp_path: Path) -> None:
    broker, project = _broker(tmp_path)
    try:
        opened = broker.read_file("PROJECT_STATE.yaml", **_identity())
        assert opened.metadata.ownership_class == "canonical"
        assert opened.metadata.read_only is True
        with pytest.raises(FileWorkspaceAccessDenied):
            broker.prepare_write("PROJECT_STATE.yaml", "safe: true\nupdated: yes\n", expected_content_hash=opened.metadata.content_hash, expected_base_sha=opened.metadata.base_sha, **_identity())
        assert (project / "PROJECT_STATE.yaml").read_text(encoding="utf-8") == "safe: true\n"
    finally:
        broker.close()


def test_create_rename_and_delete_are_exact_hash_base_bound(tmp_path: Path) -> None:
    broker, project = _broker(tmp_path)
    try:
        base = broker.profile_description(**_identity())["baseSha"]
        created = broker.create_file("src/new.py", "created = True\n", expected_base_sha=base, **_identity())
        preview = broker.preview_diff(created.prepared_write_id, **_identity())
        receipt = broker.commit_write(created.prepared_write_id, confirmed_diff_digest=preview.diff_digest, **_identity()).to_dict()
        assert receipt["operation"] == "createFile" and (project / "src" / "new.py").is_file()
        content_hash = _sha("created = True\n")
        renamed = broker.rename_path("src/new.py", "src/renamed.py", expected_content_hash=content_hash, expected_base_sha=base, **_identity()).to_dict()
        assert renamed["operation"] == "renamePath" and not (project / "src" / "new.py").exists()
        with pytest.raises(FileWorkspaceStale):
            broker.delete_path("src/renamed.py", expected_content_hash=_sha("wrong"), expected_base_sha=base, **_identity())
        deleted = broker.delete_path("src/renamed.py", expected_content_hash=content_hash, expected_base_sha=base, **_identity()).to_dict()
        assert deleted["operation"] == "deletePath" and not (project / "src" / "renamed.py").exists()
    finally:
        broker.close()


def test_unsafe_rename_delete_create_and_cross_ownership_moves_are_refused(tmp_path: Path) -> None:
    broker, _ = _broker(tmp_path)
    try:
        base = broker.profile_description(**_identity())["baseSha"]
        generated = broker.read_file("generated/build.txt", **_identity()).metadata.content_hash
        with pytest.raises(FileWorkspaceAccessDenied):
            broker.create_file("generated/new.txt", "no\n", expected_base_sha=base, **_identity())
        with pytest.raises(FileWorkspaceAccessDenied):
            broker.rename_path("generated/build.txt", "src/build.txt", expected_content_hash=generated, expected_base_sha=base, **_identity())
        canonical = broker.read_file("PROJECT_STATE.yaml", **_identity()).metadata.content_hash
        with pytest.raises(FileWorkspaceAccessDenied):
            broker.delete_path("PROJECT_STATE.yaml", expected_content_hash=canonical, expected_base_sha=base, **_identity())
        source = broker.read_file("src/main.py", **_identity()).metadata.content_hash
        with pytest.raises(FileWorkspaceAccessDenied):
            broker.rename_path("src/main.py", "scratch/main.py", expected_content_hash=source, expected_base_sha=base, **_identity())
    finally:
        broker.close()


def test_cross_user_application_instance_and_read_only_actor_access_fail_closed(tmp_path: Path) -> None:
    broker, _ = _broker(tmp_path)
    try:
        opened = broker.read_file("src/main.py", **_identity())
        assert broker.read_file("src/main.py", actor_id="actor.bob", application_id=APP, instance_id=INSTANCE).content
        with pytest.raises(FileWorkspaceAccessDenied):
            broker.prepare_write("src/main.py", "answer = 42\n", expected_content_hash=opened.metadata.content_hash, expected_base_sha=opened.metadata.base_sha, actor_id="actor.bob", application_id=APP, instance_id=INSTANCE)
        for identity in (
            {"actor_id": "actor.mallory", "application_id": APP, "instance_id": INSTANCE},
            {"actor_id": ALICE, "application_id": "stateport.other", "instance_id": INSTANCE},
            {"actor_id": ALICE, "application_id": APP, "instance_id": "project.other"},
        ):
            with pytest.raises(FileWorkspaceAccessDenied):
                broker.read_file("src/main.py", **identity)
    finally:
        broker.close()


def test_a12_commit_rejects_ancestor_rebound_after_root_descriptor_capture(tmp_path: Path) -> None:
    project = _project(tmp_path)
    broker = FileWorkspaceBroker(_profile(project), lease_directory=tmp_path / "leases")
    try:
        opened = broker.read_file("src/main.py", **_identity())
        pending = broker.prepare_write(
            "src/main.py", "answer = 42\n",
            expected_content_hash=opened.metadata.content_hash,
            expected_base_sha=opened.metadata.base_sha,
            **_identity(),
        )
        preview = broker.preview_diff(pending.prepared_write_id, **_identity())

        def rebound_path_ancestor(_: str) -> None:
            (project / "src").rename(project / "captured-src")
            (project / "src").mkdir()
            # Matching content proves the rejection is identity-bound rather
            # than an incidental hash mismatch.
            (project / "src" / "main.py").write_text("answer = 41\n", encoding="utf-8")

        broker._before_replace = rebound_path_ancestor

        with pytest.raises(FileWorkspaceStale, match="path ancestor changed"):
            broker.commit_write(
                pending.prepared_write_id,
                confirmed_diff_digest=preview.diff_digest,
                **_identity(),
            )
        assert (project / "captured-src" / "main.py").read_text(encoding="utf-8") == "answer = 41\n"
        assert (project / "src" / "main.py").read_text(encoding="utf-8") == "answer = 41\n"
        assert not list((project / "captured-src").glob(".stateport-write-*.tmp"))
    finally:
        broker.close()


def test_a12_rename_destination_creation_race_never_overwrites_either_file(tmp_path: Path) -> None:
    broker, project = _broker(tmp_path)
    source = project / "src" / "race.py"
    source.write_text("source = True\n", encoding="utf-8")
    try:
        opened = broker.read_file("src/race.py", **_identity())

        def create_destination(_: str) -> None:
            (project / "src" / "winner.py").write_text("concurrent = True\n", encoding="utf-8")

        broker._before_destructive = create_destination
        with pytest.raises(FileWorkspaceStale, match="destination appeared"):
            broker.rename_path(
                "src/race.py", "src/winner.py",
                expected_content_hash=opened.metadata.content_hash,
                expected_base_sha=opened.metadata.base_sha,
                **_identity(),
            )
        assert source.read_text(encoding="utf-8") == "source = True\n"
        assert (project / "src" / "winner.py").read_text(encoding="utf-8") == "concurrent = True\n"
    finally:
        broker.close()


def test_a12_create_file_uses_the_same_atomic_no_replace_boundary(tmp_path: Path, monkeypatch) -> None:
    broker, project = _broker(tmp_path)
    original_rename = broker_module._rename_no_replace
    try:
        base = broker.profile_description(**_identity())["baseSha"]
        pending = broker.create_file(
            "src/new.py", "candidate = True\n",
            expected_base_sha=base,
            **_identity(),
        )
        preview = broker.preview_diff(pending.prepared_write_id, **_identity())

        def collide_after_final_presence_check(
            source_parent: int,
            source_name: str,
            destination_parent: int,
            destination_name: str,
        ) -> None:
            descriptor = os.open(
                destination_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=destination_parent,
            )
            try:
                os.write(descriptor, b"concurrent = True\n")
            finally:
                os.close(descriptor)
            original_rename(source_parent, source_name, destination_parent, destination_name)

        monkeypatch.setattr(broker_module, "_rename_no_replace", collide_after_final_presence_check)
        with pytest.raises(FileWorkspaceStale, match="destination appeared"):
            broker.commit_write(
                pending.prepared_write_id,
                confirmed_diff_digest=preview.diff_digest,
                **_identity(),
            )
        assert (project / "src" / "new.py").read_text(encoding="utf-8") == "concurrent = True\n"
        assert not list((project / "src").glob(".stateport-write-*.tmp"))
        broker.discard_write(pending.prepared_write_id, **_identity())
    finally:
        broker.close()


def test_a12_late_git_base_drift_aborts_at_irrevocable_commit_boundary(tmp_path: Path) -> None:
    broker, project = _broker(tmp_path)
    try:
        opened = broker.read_file("src/main.py", **_identity())
        pending = broker.prepare_write(
            "src/main.py", "answer = 42\n",
            expected_content_hash=opened.metadata.content_hash,
            expected_base_sha=opened.metadata.base_sha,
            **_identity(),
        )
        preview = broker.preview_diff(pending.prepared_write_id, **_identity())

        def drift_base(_: str) -> None:
            (project / "scratch" / "late-base.md").write_text("late drift\n", encoding="utf-8")
            _git(project, "add", "scratch/late-base.md")
            _git(project, "commit", "-q", "-m", "late drift")

        broker._before_replace = drift_base
        with pytest.raises(FileWorkspaceStale, match="commit boundary"):
            broker.commit_write(
                pending.prepared_write_id,
                confirmed_diff_digest=preview.diff_digest,
                **_identity(),
            )
        assert (project / "src" / "main.py").read_text(encoding="utf-8") == "answer = 41\n"
        assert not list((project / "src").glob(".stateport-write-*.tmp"))
        broker.discard_write(pending.prepared_write_id, **_identity())
    finally:
        broker.close()


@pytest.mark.parametrize("operation", ("rename", "delete"))
def test_a12_destructive_mutations_recheck_git_base_at_the_irreversible_boundary(
    tmp_path: Path,
    operation: str,
) -> None:
    broker, project = _broker(tmp_path)
    source = project / "src" / "boundary.py"
    source.write_text("kept = True\n", encoding="utf-8")
    _git(project, "add", "src/boundary.py")
    _git(project, "commit", "-q", "-m", "boundary source")
    try:
        opened = broker.read_file("src/boundary.py", **_identity())

        def drift_base(_: str) -> None:
            (project / "scratch" / "destructive-base.md").write_text("late drift\n", encoding="utf-8")
            _git(project, "add", "scratch/destructive-base.md")
            _git(project, "commit", "-q", "-m", "destructive late drift")

        broker._before_destructive = drift_base
        with pytest.raises(FileWorkspaceStale, match=f"{operation} boundary"):
            if operation == "rename":
                broker.rename_path(
                    "src/boundary.py", "src/renamed.py",
                    expected_content_hash=opened.metadata.content_hash,
                    expected_base_sha=opened.metadata.base_sha,
                    **_identity(),
                )
            else:
                broker.delete_path(
                    "src/boundary.py",
                    expected_content_hash=opened.metadata.content_hash,
                    expected_base_sha=opened.metadata.base_sha,
                    **_identity(),
                )
        assert source.read_text(encoding="utf-8") == "kept = True\n"
        assert not (project / "src" / "renamed.py").exists()
    finally:
        broker.close()


def test_a12_cataloged_root_identity_is_required_at_broker_construction(tmp_path: Path) -> None:
    project = _project(tmp_path)
    current = _profile(project)
    profile = replace(
        current,
        expected_root_identity=(current.expected_root_identity[0], current.expected_root_identity[1] + 1),
    )
    with pytest.raises(FileWorkspacePathError, match="cataloged filesystem identity"):
        FileWorkspaceBroker(profile, lease_directory=tmp_path / "leases")


def test_a12_bounded_credential_patterns_block_values_but_not_similar_source_names(tmp_path: Path) -> None:
    broker, project = _broker(tmp_path)
    blocked = (
        "src/access_token.txt", "src/deploy.credentials.json", "src/client.keystore",
        "src/private/secrets/config.yaml", "src/service-account.json", "src/api_key.txt",
    )
    for path in blocked:
        target = project / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("fixture value\n", encoding="utf-8")
    (project / "src" / "tokenizer.py").write_text("kind = 'tokenizer'\n", encoding="utf-8")
    (project / "src" / "secretary.py").write_text("role = 'secretary'\n", encoding="utf-8")
    try:
        for path in blocked:
            with pytest.raises(FileWorkspaceTypeRefused, match="credential-like"):
                broker.read_file(path, **_identity())
        assert "tokenizer" in broker.read_file("src/tokenizer.py", **_identity()).content
        assert "secretary" in broker.read_file("src/secretary.py", **_identity()).content
    finally:
        broker.close()


def test_a12_expired_prepared_write_releases_lease_without_same_broker_request(tmp_path: Path) -> None:
    project = _project(tmp_path)

    class Clock:
        value = time.time()

        def __call__(self) -> float:
            return self.value

    clock = Clock()
    first = FileWorkspaceBroker(
        _profile(project), lease_directory=tmp_path / "leases", clock=clock,
        reaper_maximum_sleep_seconds=0.01,
    )
    second = FileWorkspaceBroker(_profile(project), lease_directory=tmp_path / "leases")
    reaper = first._reaper
    try:
        opened = first.read_file("src/main.py", **_identity())
        first.prepare_write(
            "src/main.py", "answer = 42\n",
            expected_content_hash=opened.metadata.content_hash,
            expected_base_sha=opened.metadata.base_sha,
            **_identity(),
        )
        clock.value += first.profile.pending_write_lifetime_seconds + 1
        deadline = time.monotonic() + 2
        accepted = None
        while time.monotonic() < deadline:
            try:
                current = second.read_file("src/main.py", **_identity())
                accepted = second.prepare_write(
                    "src/main.py", "answer = 43\n",
                    expected_content_hash=current.metadata.content_hash,
                    expected_base_sha=current.metadata.base_sha,
                    **_identity(),
                )
                break
            except FileWorkspaceLeaseDenied:
                time.sleep(0.02)
        assert accepted is not None, "expired lease was not autonomously released"
        second.discard_write(accepted.prepared_write_id, **_identity())
    finally:
        first.close()
        second.close()
    assert not reaper.is_alive()


@pytest.mark.parametrize("race", ("ancestor", "content", "head"))
def test_a12r2_commit_boundary_rolls_back_every_post_check_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    race: str,
) -> None:
    broker, project, base_state = _broker_with_mutable_base(tmp_path)
    original_exchange = broker_module._rename_exchange
    raced = False
    try:
        opened = broker.read_file("src/main.py", **_identity())
        pending = broker.prepare_write(
            "src/main.py", "answer = 42\n",
            expected_content_hash=opened.metadata.content_hash,
            expected_base_sha=opened.metadata.base_sha,
            **_identity(),
        )
        preview = broker.preview_diff(pending.prepared_write_id, **_identity())

        def exchange_at_syscall(*args) -> None:
            nonlocal raced
            if not raced:
                raced = True
                if race == "ancestor":
                    (project / "src").rename(project / "captured-src")
                    (project / "src").mkdir()
                    (project / "src" / "main.py").write_text("answer = 41\n", encoding="utf-8")
                elif race == "content":
                    (project / "src" / "main.py").write_text("concurrent = True\n", encoding="utf-8")
                else:
                    base_state["head"] = "b" * 40
            original_exchange(*args)

        monkeypatch.setattr(broker_module, "_rename_exchange", exchange_at_syscall)
        with pytest.raises(FileWorkspaceStale, match="boundary"):
            broker.commit_write(
                pending.prepared_write_id,
                confirmed_diff_digest=preview.diff_digest,
                **_identity(),
            )

        if race == "ancestor":
            assert (project / "captured-src" / "main.py").read_text(encoding="utf-8") == "answer = 41\n"
            assert (project / "src" / "main.py").read_text(encoding="utf-8") == "answer = 41\n"
            inspected = project / "captured-src"
        else:
            expected = "concurrent = True\n" if race == "content" else "answer = 41\n"
            assert (project / "src" / "main.py").read_text(encoding="utf-8") == expected
            inspected = project / "src"
        assert not list(inspected.glob(".stateport-*.tmp"))
        broker.discard_write(pending.prepared_write_id, **_identity())
    finally:
        broker.close()


def test_a12r2_normal_git_writer_is_refused_while_the_mutation_boundary_is_locked(tmp_path: Path) -> None:
    broker, project = _broker(tmp_path)
    commit_attempts: list[int] = []
    try:
        opened = broker.read_file("src/main.py", **_identity())
        pending = broker.prepare_write(
            "src/main.py", "answer = 42\n",
            expected_content_hash=opened.metadata.content_hash,
            expected_base_sha=opened.metadata.base_sha,
            **_identity(),
        )
        preview = broker.preview_diff(pending.prepared_write_id, **_identity())

        def attempt_git_commit(operation: str) -> None:
            assert operation == "commitWrite"
            (project / "scratch" / "locked-head.md").write_text("locked\n", encoding="utf-8")
            _git(project, "add", "scratch/locked-head.md")
            result = subprocess.run(
                ["git", "-C", str(project), "commit", "-q", "-m", "must be refused"],
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            commit_attempts.append(result.returncode)

        broker._at_mutation_boundary = attempt_git_commit
        receipt = broker.commit_write(
            pending.prepared_write_id,
            confirmed_diff_digest=preview.diff_digest,
            **_identity(),
        )
        assert commit_attempts and commit_attempts[0] != 0
        assert receipt.base_sha == opened.metadata.base_sha == _git(project, "rev-parse", "HEAD")
        assert (project / "src" / "main.py").read_text(encoding="utf-8") == "answer = 42\n"
    finally:
        broker.close()


def test_internal_git_transactions_disable_repository_configured_hooks(tmp_path: Path) -> None:
    project = _project(tmp_path)
    hooks = project / "evil-hooks"
    hooks.mkdir()
    marker = project / ".git" / "reference-transaction-ran"
    hook = hooks / "reference-transaction"
    hook.write_text(
        "#!/bin/sh\nprintf '%s\\n' \"$1\" >> .git/reference-transaction-ran\n",
        encoding="utf-8",
    )
    hook.chmod(0o755)
    _git(project, "config", "core.hooksPath", "evil-hooks")
    broker = FileWorkspaceBroker(_profile(project), lease_directory=tmp_path / "leases")
    try:
        opened = broker.read_file("src/main.py", **_identity())
        pending = broker.prepare_write(
            "src/main.py",
            "answer = 42\n",
            expected_content_hash=opened.metadata.content_hash,
            expected_base_sha=opened.metadata.base_sha,
            **_identity(),
        )
        preview = broker.preview_diff(pending.prepared_write_id, **_identity())
        receipt = broker.commit_write(
            pending.prepared_write_id,
            confirmed_diff_digest=preview.diff_digest,
            **_identity(),
        )
        assert receipt.post_hash == _sha("answer = 42\n")
        assert not marker.exists()
    finally:
        broker.close()


def test_git_lock_cleanup_failure_persists_restart_quarantine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, project = _broker(tmp_path)
    original_release = broker_module._GitHeadLock.release
    pending = None
    try:
        opened = first.read_file("src/main.py", **_identity())
        pending = first.prepare_write(
            "src/main.py",
            "answer = 42\n",
            expected_content_hash=opened.metadata.content_hash,
            expected_base_sha=opened.metadata.base_sha,
            **_identity(),
        )
        preview = first.preview_diff(pending.prepared_write_id, **_identity())

        def release_but_report_failure(lock) -> bool:
            assert original_release(lock) is True
            return False

        monkeypatch.setattr(
            broker_module._GitHeadLock,
            "release",
            release_but_report_failure,
        )
        with pytest.raises(FileWorkspaceAtomicWriteError, match="quarantined"):
            first.commit_write(
                pending.prepared_write_id,
                confirmed_diff_digest=preview.diff_digest,
                **_identity(),
            )
        assert (project / "src" / "main.py").read_text(encoding="utf-8") == "answer = 41\n"
        assert first.quarantine_status(**_identity())["quarantined"] is True
        first.discard_write(pending.prepared_write_id, **_identity())
    finally:
        first.close()

    second = FileWorkspaceBroker(_profile(project), lease_directory=tmp_path / "leases")
    try:
        opened = second.read_file("src/main.py", **_identity())
        with pytest.raises(FileWorkspaceLeaseDenied, match="recovery|cleanup"):
            second.prepare_write(
                "src/main.py",
                "answer = 43\n",
                expected_content_hash=opened.metadata.content_hash,
                expected_base_sha=opened.metadata.base_sha,
                **_identity(),
            )
    finally:
        second.close()


def test_writer_lease_cleanup_failure_persists_restart_quarantine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, project = _broker(tmp_path)
    original_release = broker_module.InstanceLease.release
    pending = None
    try:
        opened = first.read_file("src/main.py", **_identity())
        pending = first.prepare_write(
            "src/main.py",
            "answer = 42\n",
            expected_content_hash=opened.metadata.content_hash,
            expected_base_sha=opened.metadata.base_sha,
            **_identity(),
        )

        def release_then_fail(lease) -> None:
            original_release(lease)
            raise OSError("simulated close failure")

        monkeypatch.setattr(
            broker_module.InstanceLease,
            "release",
            release_then_fail,
        )
        with pytest.raises(FileWorkspaceAtomicWriteError, match="quarantined"):
            first.discard_write(pending.prepared_write_id, **_identity())
        assert first.quarantine_status(**_identity())["quarantined"] is True
        monkeypatch.setattr(
            broker_module.InstanceLease,
            "release",
            original_release,
        )
    finally:
        first.close()

    second = FileWorkspaceBroker(_profile(project), lease_directory=tmp_path / "leases")
    try:
        opened = second.read_file("src/main.py", **_identity())
        with pytest.raises(FileWorkspaceLeaseDenied, match="recovery|cleanup"):
            second.prepare_write(
                "src/main.py",
                "answer = 43\n",
                expected_content_hash=opened.metadata.content_hash,
                expected_base_sha=opened.metadata.base_sha,
                **_identity(),
            )
    finally:
        second.close()


def test_release_failure_records_quarantine_before_another_broker_can_acquire(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, project = _broker(tmp_path)
    second = FileWorkspaceBroker(_profile(project), lease_directory=tmp_path / "leases")
    opened = first.read_file("src/main.py", **_identity())
    pending = first.prepare_write(
        "src/main.py",
        "answer = 42\n",
        expected_content_hash=opened.metadata.content_hash,
        expected_base_sha=opened.metadata.base_sha,
        **_identity(),
    )
    original_release = broker_module.InstanceLease.release
    kernel_unlocked = threading.Event()
    continue_failure = threading.Event()
    first_result: list[BaseException] = []
    second_result: list[object] = []

    def release_then_pause(lease) -> None:
        original_release(lease)
        kernel_unlocked.set()
        assert continue_failure.wait(timeout=2)
        raise OSError("simulated close failure after kernel unlock")

    def discard_first() -> None:
        try:
            first.discard_write(pending.prepared_write_id, **_identity())
        except BaseException as exc:  # noqa: BLE001 - assert the cross-thread result below
            first_result.append(exc)

    def prepare_second() -> None:
        try:
            current = second.read_file("src/main.py", **_identity())
            second_result.append(
                second.prepare_write(
                    "src/main.py",
                    "answer = 43\n",
                    expected_content_hash=current.metadata.content_hash,
                    expected_base_sha=current.metadata.base_sha,
                    **_identity(),
                )
            )
        except BaseException as exc:  # noqa: BLE001 - assert the cross-thread result below
            second_result.append(exc)

    monkeypatch.setattr(broker_module.InstanceLease, "release", release_then_pause)
    discard_thread = threading.Thread(target=discard_first)
    prepare_thread = threading.Thread(target=prepare_second)
    try:
        discard_thread.start()
        assert kernel_unlocked.wait(timeout=2)
        prepare_thread.start()
        time.sleep(0.05)
        assert prepare_thread.is_alive(), "waiting broker crossed the quarantine transition"
        continue_failure.set()
        discard_thread.join(timeout=2)
        prepare_thread.join(timeout=2)
        assert not discard_thread.is_alive() and not prepare_thread.is_alive()
        assert len(first_result) == 1
        assert isinstance(first_result[0], FileWorkspaceAtomicWriteError)
        assert len(second_result) == 1
        assert isinstance(second_result[0], FileWorkspaceLeaseDenied)
        assert first.quarantine_status(**_identity())["quarantined"] is True
        assert (project / "src" / "main.py").read_text(encoding="utf-8") == "answer = 41\n"
    finally:
        continue_failure.set()
        if discard_thread.ident is not None:
            discard_thread.join(timeout=2)
        if prepare_thread.ident is not None:
            prepare_thread.join(timeout=2)
        monkeypatch.setattr(broker_module.InstanceLease, "release", original_release)
        first.close()
        second.close()


def test_commit_rechecks_quarantine_after_diff_preview(tmp_path: Path) -> None:
    broker, project = _broker(tmp_path)
    pending = None
    try:
        opened = broker.read_file("src/main.py", **_identity())
        pending = broker.prepare_write(
            "src/main.py",
            "answer = 43\n",
            expected_content_hash=opened.metadata.content_hash,
            expected_base_sha=opened.metadata.base_sha,
            **_identity(),
        )
        preview = broker.preview_diff(pending.prepared_write_id, **_identity())
        broker._persist_quarantine(
            "lease_cleanup_required",
            recovery_artifact_count=0,
        )
        with pytest.raises(FileWorkspaceLeaseDenied, match="recovery|cleanup"):
            broker.commit_write(
                pending.prepared_write_id,
                confirmed_diff_digest=preview.diff_digest,
                **_identity(),
            )
        assert (project / "src" / "main.py").read_text(encoding="utf-8") == "answer = 41\n"
    finally:
        if pending is not None:
            broker.discard_write(pending.prepared_write_id, **_identity())
        broker.close()


def test_post_exchange_writer_is_preserved_with_original_and_browser_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    broker, project = _broker(tmp_path)
    original_exchange = broker_module._rename_exchange
    external = b"external-after-exchange = True\n"
    raced = False
    try:
        opened = broker.read_file("src/main.py", **_identity())
        pending = broker.prepare_write(
            "src/main.py",
            "answer = 42\n",
            expected_content_hash=opened.metadata.content_hash,
            expected_base_sha=opened.metadata.base_sha,
            **_identity(),
        )
        preview = broker.preview_diff(pending.prepared_write_id, **_identity())

        def exchange_then_write(*args) -> None:
            nonlocal raced
            original_exchange(*args)
            if not raced:
                raced = True
                (project / "src" / "main.py").write_bytes(external)

        monkeypatch.setattr(broker_module, "_rename_exchange", exchange_then_write)
        with pytest.raises(FileWorkspaceAtomicWriteError, match="quarantined"):
            broker.commit_write(
                pending.prepared_write_id,
                confirmed_diff_digest=preview.diff_digest,
                **_identity(),
            )
        assert raced is True
        assert (project / "src" / "main.py").read_bytes() == external
        values = _recovery_values(project)
        assert b"answer = 41\n" in values
        assert b"answer = 42\n" in values
        assert broker.quarantine_status(**_identity())["quarantined"] is True
        assert "+answer = 42" in broker.preview_diff(
            pending.prepared_write_id,
            **_identity(),
        ).diff
        broker.discard_write(pending.prepared_write_id, **_identity())
    finally:
        broker.close()


def test_post_create_writer_is_preserved_with_browser_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    broker, project = _broker(tmp_path)
    original_rename = broker_module._rename_no_replace
    external = b"external-create = True\n"
    raced = False
    try:
        base = broker.profile_description(**_identity())["baseSha"]
        pending = broker.create_file(
            "src/new.py",
            "browser_candidate = True\n",
            expected_base_sha=base,
            **_identity(),
        )
        preview = broker.preview_diff(pending.prepared_write_id, **_identity())

        def rename_then_write(*args) -> None:
            nonlocal raced
            original_rename(*args)
            if not raced:
                raced = True
                (project / "src" / "new.py").write_bytes(external)

        monkeypatch.setattr(broker_module, "_rename_no_replace", rename_then_write)
        with pytest.raises(FileWorkspaceAtomicWriteError, match="quarantined"):
            broker.commit_write(
                pending.prepared_write_id,
                confirmed_diff_digest=preview.diff_digest,
                **_identity(),
            )
        assert (project / "src" / "new.py").read_bytes() == external
        assert b"browser_candidate = True\n" in _recovery_values(project)
        broker.discard_write(pending.prepared_write_id, **_identity())
    finally:
        broker.close()


@pytest.mark.parametrize("operation", ("rename", "delete"))
def test_post_path_syscall_writer_is_preserved_and_quarantined(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    broker, project = _broker(tmp_path)
    original_rename = broker_module._rename_no_replace
    external = f"external_{operation} = True\n".encode("utf-8")
    raced = False
    try:
        opened = broker.read_file("src/main.py", **_identity())

        def rename_then_write(*args) -> None:
            nonlocal raced
            original_rename(*args)
            if not raced:
                raced = True
                target = "renamed.py" if operation == "rename" else "main.py"
                (project / "src" / target).write_bytes(external)

        monkeypatch.setattr(broker_module, "_rename_no_replace", rename_then_write)
        with pytest.raises(FileWorkspaceAtomicWriteError, match="quarantined"):
            if operation == "rename":
                broker.rename_path(
                    "src/main.py",
                    "src/renamed.py",
                    expected_content_hash=opened.metadata.content_hash,
                    expected_base_sha=opened.metadata.base_sha,
                    **_identity(),
                )
            else:
                broker.delete_path(
                    "src/main.py",
                    expected_content_hash=opened.metadata.content_hash,
                    expected_base_sha=opened.metadata.base_sha,
                    **_identity(),
                )
        external_path = project / "src" / (
            "renamed.py" if operation == "rename" else "main.py"
        )
        assert external_path.read_bytes() == external
        assert b"answer = 41\n" in _recovery_values(project)
        assert broker.quarantine_status(**_identity())["quarantined"] is True
    finally:
        broker.close()


@pytest.mark.parametrize("operation", ("write", "delete"))
def test_post_finalization_writer_is_preserved_with_recovery_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    broker, project = _broker(tmp_path)
    original_unlink = broker_module.os.unlink
    external = f"external_final_{operation} = True\n".encode("utf-8")
    raced = False
    pending = None
    try:
        opened = broker.read_file("src/main.py", **_identity())
        if operation == "write":
            pending = broker.prepare_write(
                "src/main.py",
                "answer = 42\n",
                expected_content_hash=opened.metadata.content_hash,
                expected_base_sha=opened.metadata.base_sha,
                **_identity(),
            )
            preview = broker.preview_diff(pending.prepared_write_id, **_identity())

        def unlink_then_write(path, *args, **kwargs) -> None:
            nonlocal raced
            name = os.fsdecode(path)
            target_prefix = (
                ".stateport-write-" if operation == "write" else ".stateport-delete-"
            )
            original_unlink(path, *args, **kwargs)
            if not raced and name.startswith(target_prefix):
                raced = True
                (project / "src" / "main.py").write_bytes(external)

        monkeypatch.setattr(broker_module.os, "unlink", unlink_then_write)
        with pytest.raises(FileWorkspaceAtomicWriteError, match="quarantined"):
            if operation == "write":
                broker.commit_write(
                    pending.prepared_write_id,
                    confirmed_diff_digest=preview.diff_digest,
                    **_identity(),
                )
            else:
                broker.delete_path(
                    "src/main.py",
                    expected_content_hash=opened.metadata.content_hash,
                    expected_base_sha=opened.metadata.base_sha,
                    **_identity(),
                )
        assert raced is True
        assert (project / "src" / "main.py").read_bytes() == external
        values = _recovery_values(project)
        assert b"answer = 41\n" in values
        if operation == "write":
            assert b"answer = 42\n" in values
            broker.discard_write(pending.prepared_write_id, **_identity())
    finally:
        broker.close()


@pytest.mark.parametrize("operation", ("commit", "delete"))
def test_a12r2_irreversible_cleanup_rechecks_head_and_restores_before_refusing_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    broker, project, base_state = _broker_with_mutable_base(tmp_path)
    original_unlink = broker_module.os.unlink
    raced = False
    pending = None
    try:
        opened = broker.read_file("src/main.py", **_identity())
        if operation == "commit":
            pending = broker.prepare_write(
                "src/main.py", "answer = 42\n",
                expected_content_hash=opened.metadata.content_hash,
                expected_base_sha=opened.metadata.base_sha,
                **_identity(),
            )
            preview = broker.preview_diff(pending.prepared_write_id, **_identity())

        def unlink_at_irreversible_boundary(path, *args, **kwargs) -> None:
            nonlocal raced
            name = os.fsdecode(path)
            target_prefix = ".stateport-write-" if operation == "commit" else ".stateport-delete-"
            if not raced and name.startswith(target_prefix):
                raced = True
                base_state["head"] = "d" * 40
            original_unlink(path, *args, **kwargs)

        monkeypatch.setattr(broker_module.os, "unlink", unlink_at_irreversible_boundary)
        with pytest.raises(FileWorkspaceStale, match="finalization"):
            if operation == "commit":
                broker.commit_write(
                    pending.prepared_write_id,
                    confirmed_diff_digest=preview.diff_digest,
                    **_identity(),
                )
            else:
                broker.delete_path(
                    "src/main.py",
                    expected_content_hash=opened.metadata.content_hash,
                    expected_base_sha=opened.metadata.base_sha,
                    **_identity(),
                )
        assert raced is True
        assert (project / "src" / "main.py").read_text(encoding="utf-8") == "answer = 41\n"
        assert not list((project / "src").glob(".stateport-*.tmp"))
        if pending is not None:
            broker.discard_write(pending.prepared_write_id, **_identity())
    finally:
        broker.close()


@pytest.mark.parametrize("operation", ("rename", "delete"))
@pytest.mark.parametrize("race", ("ancestor", "content", "head"))
def test_a12r2_path_mutation_boundary_rolls_back_without_a_false_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    race: str,
) -> None:
    broker, project, base_state = _broker_with_mutable_base(tmp_path)
    original_rename = broker_module._rename_no_replace
    raced = False
    try:
        opened = broker.read_file("src/main.py", **_identity())

        def rename_at_syscall(*args) -> None:
            nonlocal raced
            if not raced:
                raced = True
                if race == "ancestor":
                    (project / "src").rename(project / "captured-src")
                    (project / "src").mkdir()
                    (project / "src" / "main.py").write_text("answer = 41\n", encoding="utf-8")
                elif race == "content":
                    (project / "src" / "main.py").write_text("concurrent = True\n", encoding="utf-8")
                else:
                    base_state["head"] = "c" * 40
            original_rename(*args)

        monkeypatch.setattr(broker_module, "_rename_no_replace", rename_at_syscall)
        ambiguous_rename_content = operation == "rename" and race == "content"
        expected_error = (
            FileWorkspaceAtomicWriteError
            if ambiguous_rename_content
            else FileWorkspaceStale
        )
        expected_message = "quarantined" if ambiguous_rename_content else "boundary"
        with pytest.raises(expected_error, match=expected_message):
            if operation == "rename":
                broker.rename_path(
                    "src/main.py", "src/renamed.py",
                    expected_content_hash=opened.metadata.content_hash,
                    expected_base_sha=opened.metadata.base_sha,
                    **_identity(),
                )
            else:
                broker.delete_path(
                    "src/main.py",
                    expected_content_hash=opened.metadata.content_hash,
                    expected_base_sha=opened.metadata.base_sha,
                    **_identity(),
                )

        root = project / "captured-src" if race == "ancestor" else project / "src"
        if ambiguous_rename_content:
            assert not (root / "main.py").exists()
            assert (root / "renamed.py").read_text(encoding="utf-8") == "concurrent = True\n"
            assert b"answer = 41\n" in _recovery_values(project)
            assert broker.quarantine_status(**_identity())["quarantined"] is True
            return
        expected = "concurrent = True\n" if race == "content" else "answer = 41\n"
        assert (root / "main.py").read_text(encoding="utf-8") == expected
        assert not (root / "renamed.py").exists()
        assert not list(root.glob(".stateport-*.tmp"))
        if race == "ancestor":
            assert (project / "src" / "main.py").read_text(encoding="utf-8") == "answer = 41\n"
    finally:
        broker.close()


def test_quarantine_survives_restart_refuses_every_write_and_clears_explicitly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, project = _broker(tmp_path)
    original_rename = broker_module._rename_no_replace
    external = b"restart-external-marker = True\n"
    pending = None
    try:
        base = first.profile_description(**_identity())["baseSha"]
        pending = first.create_file(
            "src/restart.py",
            "browser-recovery-marker = True\n",
            expected_base_sha=base,
            **_identity(),
        )
        preview = first.preview_diff(pending.prepared_write_id, **_identity())
        raced = False

        def rename_then_write(*args) -> None:
            nonlocal raced
            original_rename(*args)
            if not raced:
                raced = True
                (project / "src" / "restart.py").write_bytes(external)

        monkeypatch.setattr(broker_module, "_rename_no_replace", rename_then_write)
        with pytest.raises(FileWorkspaceAtomicWriteError, match="quarantined"):
            first.commit_write(
                pending.prepared_write_id,
                confirmed_diff_digest=preview.diff_digest,
                **_identity(),
            )
        first.discard_write(pending.prepared_write_id, **_identity())
    finally:
        first.close()

    second = FileWorkspaceBroker(_profile(project), lease_directory=tmp_path / "leases")
    try:
        status = second.quarantine_status(**_identity())
        assert status["quarantined"] is True
        assert status["identityMatches"] is True
        quarantine = status["quarantine"]
        assert quarantine["recoveryArtifactCount"] >= 1
        record_path = second._quarantine_directory / second._quarantine_record_name
        serialized = record_path.read_text(encoding="utf-8")
        for forbidden in (
            str(project),
            "src/restart.py",
            "restart-external-marker",
            "browser-recovery-marker",
        ):
            assert forbidden not in serialized
            assert forbidden not in repr(status)

        opened = second.read_file("src/main.py", **_identity())
        write_calls = (
            lambda: second.prepare_write(
                "src/main.py",
                "answer = 43\n",
                expected_content_hash=opened.metadata.content_hash,
                expected_base_sha=opened.metadata.base_sha,
                **_identity(),
            ),
            lambda: second.create_file(
                "src/blocked.py",
                "blocked = True\n",
                expected_base_sha=opened.metadata.base_sha,
                **_identity(),
            ),
            lambda: second.rename_path(
                "src/main.py",
                "src/blocked-rename.py",
                expected_content_hash=opened.metadata.content_hash,
                expected_base_sha=opened.metadata.base_sha,
                **_identity(),
            ),
            lambda: second.delete_path(
                "src/main.py",
                expected_content_hash=opened.metadata.content_hash,
                expected_base_sha=opened.metadata.base_sha,
                **_identity(),
            ),
        )
        for call in write_calls:
            with pytest.raises(FileWorkspaceLeaseDenied, match="recovery|cleanup"):
                call()

        digest = quarantine["quarantineDigest"]
        with pytest.raises(FileWorkspaceLeaseDenied, match="digest"):
            second.clear_quarantine(
                expected_quarantine_digest="sha256:" + "0" * 64,
                recovery_disposition="recovery_artifacts_resolved",
                **_identity(),
            )
        with pytest.raises(FileWorkspaceLeaseDenied, match="disposition"):
            second.clear_quarantine(
                expected_quarantine_digest=digest,
                recovery_disposition="ignored",
                **_identity(),
            )
        with pytest.raises(FileWorkspaceLeaseDenied, match="remain"):
            second.clear_quarantine(
                expected_quarantine_digest=digest,
                recovery_disposition="recovery_artifacts_resolved",
                **_identity(),
            )

        for artifact in _recovery_artifacts(project):
            artifact.unlink()
        cleared = second.clear_quarantine(
            expected_quarantine_digest=digest,
            recovery_disposition="recovery_artifacts_resolved",
            **_identity(),
        )
        assert cleared["quarantineDigest"] == digest
        assert second.quarantine_status(**_identity())["quarantined"] is False
        for forbidden in (str(project), "restart-external-marker", "src/restart.py"):
            assert forbidden not in repr(cleared)
        accepted = second.prepare_write(
            "src/main.py",
            "answer = 43\n",
            expected_content_hash=opened.metadata.content_hash,
            expected_base_sha=opened.metadata.base_sha,
            **_identity(),
        )
        second.discard_write(accepted.prepared_write_id, **_identity())
    finally:
        second.close()


def test_invalid_quarantine_record_fails_closed_after_restart(tmp_path: Path) -> None:
    first, project = _broker(tmp_path)
    record_path = first._quarantine_directory / first._quarantine_record_name
    try:
        first._persist_quarantine(
            "commit_recovery_required",
            recovery_artifact_count=0,
        )
    finally:
        first.close()
    record_path.write_text("{not-valid-json\n", encoding="utf-8")
    record_path.chmod(0o600)

    second = FileWorkspaceBroker(_profile(project), lease_directory=tmp_path / "leases")
    try:
        with pytest.raises(FileWorkspaceLeaseDenied, match="record is invalid"):
            second.quarantine_status(**_identity())
        opened = second.read_file("src/main.py", **_identity())
        with pytest.raises(FileWorkspaceLeaseDenied, match="record is invalid"):
            second.prepare_write(
                "src/main.py",
                "answer = 42\n",
                expected_content_hash=opened.metadata.content_hash,
                expected_base_sha=opened.metadata.base_sha,
                **_identity(),
            )
    finally:
        second.close()


def test_quarantine_is_bound_to_instance_and_original_root_identity(tmp_path: Path) -> None:
    first, project = _broker(tmp_path)
    try:
        first._persist_quarantine(
            "commit_recovery_required",
            recovery_artifact_count=0,
        )
        digest = first.quarantine_status(**_identity())["quarantine"][
            "quarantineDigest"
        ]
    finally:
        first.close()

    project.rename(tmp_path / "orphaned-project")
    replacement = _project(tmp_path)
    second = FileWorkspaceBroker(
        _profile(replacement),
        lease_directory=tmp_path / "leases",
    )
    try:
        status = second.quarantine_status(**_identity())
        assert status["quarantined"] is True
        assert status["identityMatches"] is False
        base = second.profile_description(**_identity())["baseSha"]
        with pytest.raises(FileWorkspaceLeaseDenied, match="different root identity"):
            second.create_file(
                "src/blocked.py",
                "blocked = True\n",
                expected_base_sha=base,
                **_identity(),
            )
        with pytest.raises(FileWorkspaceLeaseDenied, match="root identity"):
            second.clear_quarantine(
                expected_quarantine_digest=digest,
                recovery_disposition="recovery_artifacts_resolved",
                **_identity(),
            )
        assert second.quarantine_status(**_identity())["quarantined"] is True
    finally:
        second.close()


def test_recovery_scan_ignores_noncanonical_names_without_false_quarantine(
    tmp_path: Path,
) -> None:
    broker, project = _broker(tmp_path)
    benign = project / "src" / ".stateport-recovery-not-a-token.tmp"
    benign.write_text("ordinary user file\n", encoding="utf-8")
    try:
        broker._quarantine_unresolved("commit_recovery_required")
        status = broker.quarantine_status(**_identity())
        assert status["quarantine"]["recoveryArtifactCount"] == 0
        broker.clear_quarantine(
            expected_quarantine_digest=status["quarantine"]["quarantineDigest"],
            recovery_disposition="recovery_artifacts_resolved",
            **_identity(),
        )
        assert benign.read_text(encoding="utf-8") == "ordinary user file\n"
    finally:
        broker.close()


def test_recovery_scan_refuses_a_tampered_strict_artifact_name(tmp_path: Path) -> None:
    broker, project = _broker(tmp_path)
    target = project / "src" / "ordinary.txt"
    target.write_text("ordinary\n", encoding="utf-8")
    tampered = project / "src" / (
        ".stateport-recovery-" + "a" * 32 + ".tmp"
    )
    tampered.symlink_to(target)
    try:
        broker._persist_quarantine(
            "commit_recovery_required",
            recovery_artifact_count=0,
        )
        status = broker.quarantine_status(**_identity())
        with pytest.raises(FileWorkspaceLeaseDenied, match="identity changed"):
            broker.clear_quarantine(
                expected_quarantine_digest=status["quarantine"][
                    "quarantineDigest"
                ],
                recovery_disposition="recovery_artifacts_resolved",
                **_identity(),
            )
        assert target.read_text(encoding="utf-8") == "ordinary\n"
    finally:
        broker.close()


def test_concurrent_broker_clear_requires_the_instance_lease(
    tmp_path: Path,
) -> None:
    project = _project(tmp_path)
    first = FileWorkspaceBroker(_profile(project), lease_directory=tmp_path / "leases")
    first._persist_quarantine(
        "commit_recovery_required",
        recovery_artifact_count=0,
    )
    second = FileWorkspaceBroker(_profile(project), lease_directory=tmp_path / "leases")
    entered = threading.Event()
    proceed = threading.Event()
    outcome: list[object] = []
    original_count = first._count_recovery_artifacts
    digest = first.quarantine_status(**_identity())["quarantine"]["quarantineDigest"]

    def blocked_count() -> int:
        entered.set()
        assert proceed.wait(timeout=5)
        return original_count()

    def clear_first() -> None:
        try:
            outcome.append(
                first.clear_quarantine(
                    expected_quarantine_digest=digest,
                    recovery_disposition="recovery_artifacts_resolved",
                    **_identity(),
                )
            )
        except BaseException as exc:  # surfaced in the main test thread
            outcome.append(exc)

    first._count_recovery_artifacts = blocked_count
    thread = threading.Thread(target=clear_first, daemon=True)
    try:
        thread.start()
        assert entered.wait(timeout=5)
        with pytest.raises(FileWorkspaceLeaseDenied, match="writer lease"):
            second.clear_quarantine(
                expected_quarantine_digest=digest,
                recovery_disposition="recovery_artifacts_resolved",
                **_identity(),
            )
        proceed.set()
        thread.join(timeout=5)
        assert not thread.is_alive()
        assert len(outcome) == 1 and isinstance(outcome[0], dict)
        assert second.quarantine_status(**_identity())["quarantined"] is False
        opened = second.read_file("src/main.py", **_identity())
        accepted = second.prepare_write(
            "src/main.py",
            "answer = 42\n",
            expected_content_hash=opened.metadata.content_hash,
            expected_base_sha=opened.metadata.base_sha,
            **_identity(),
        )
        second.discard_write(accepted.prepared_write_id, **_identity())
    finally:
        proceed.set()
        thread.join(timeout=5)
        first.close()
        second.close()


def test_studystate_and_non_development_profiles_cannot_be_constructed(tmp_path: Path) -> None:
    project = _project(tmp_path)
    values = dict(
        profile_id="profile.study",
        application_id="studydd",
        application_kind="development",
        instance_id="study.demo",
        project_root=project,
        expected_root_identity=(os.lstat(project).st_dev, os.lstat(project).st_ino),
        effective_capabilities=frozenset({"workbench", "file_viewer", "editor"}),
        actor_permissions={ALICE: frozenset({"file.read", "file.write"})},
        path_rules=(PathPolicyRule("rule.files", "src", "subtree", "application_owned", True, True, True, True, True),),
    )
    profile = FileWorkspaceProfile(**values)
    with pytest.raises(ValueError, match="StudyState"):
        FileWorkspaceBroker(profile, lease_directory=tmp_path / "leases")
    values["application_id"] = "learning.other"
    values["application_kind"] = "study"
    with pytest.raises(ValueError, match="development"):
        FileWorkspaceProfile(**values)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
