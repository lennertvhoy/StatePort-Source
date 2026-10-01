#!/usr/bin/env python3
"""Focused acceptance tests for the authoritative local instance catalog."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sys
import tempfile
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "instance-catalog" / "src"))

from instance_catalog import (  # noqa: E402
    CATALOG_FORMAT,
    CatalogError,
    CatalogSchemaError,
    DuplicateInstanceError,
    InstanceCatalog,
    PathSafetyError,
)


def _catalog(root: Path) -> InstanceCatalog:
    return InstanceCatalog(root / ".stateport" / "instances.json", root / "instances")


def test_stable_identity_survives_device_change_and_move(tmp_path: Path) -> None:
    target = tmp_path / "instances/project"
    target.mkdir(parents=True)
    catalog = _catalog(tmp_path)
    original = catalog.register(target, instance_id="project")
    document = json.loads(catalog.catalog_path.read_text())
    document["entries"][0]["filesystem"]["device"] += 1000
    catalog.catalog_path.write_text(json.dumps(document))
    assert catalog.get("project").path_state == "present"
    target.rename(target.with_name("moved"))
    moved = catalog.get("project")
    assert (moved.path_state, moved.path) == ("moved", "moved")
    assert moved.metadata["filesystemId"] == original.metadata["filesystemId"]
    with pytest.raises(DuplicateInstanceError):
        catalog.register("moved", instance_id="duplicate")


@pytest.mark.parametrize("mutation", ["filesystem", "directory", "legacy_after_change"])
def test_stable_identity_refuses_unproved_replacement(tmp_path: Path, mutation: str) -> None:
    target = tmp_path / "instances/project"
    target.mkdir(parents=True)
    catalog = _catalog(tmp_path)
    catalog.register(target, instance_id="project")
    document = json.loads(catalog.catalog_path.read_text())
    row = document["entries"][0]
    if mutation == "filesystem":
        row["metadata"]["filesystemId"] = "statvfs:0000000000000001"
    elif mutation == "directory":
        target.rename(tmp_path / "retained-original")
        target.mkdir()
    else:
        del row["metadata"]["filesystemId"]
        row["filesystem"]["device"] += 1000
    catalog.catalog_path.write_text(json.dumps(document))
    assert catalog.get("project").path_state == "stale"


def test_legacy_identity_upgrade_and_metadata_compare_and_swap(tmp_path: Path) -> None:
    target = tmp_path / "instances/project"
    target.mkdir(parents=True)
    catalog = _catalog(tmp_path)
    initial = catalog.register(target, instance_id="project")
    document = json.loads(catalog.catalog_path.read_text())
    del document["entries"][0]["metadata"]["filesystemId"]
    catalog.catalog_path.write_text(json.dumps(document))
    upgraded = catalog.get("project")
    assert upgraded.metadata["filesystemId"] == initial.metadata["filesystemId"]
    catalog.merge_metadata("project", {"other": "concurrent change"})
    assert catalog.merge_metadata_if_matches(upgraded, {"stale": True}) is None
    assert "stale" not in catalog.get("project").metadata


def test_opened_identity_keeps_device_check_within_observation(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "instances/project"
    target.mkdir(parents=True)
    catalog = _catalog(tmp_path)
    real_fstat = os.fstat
    wanted = target.stat().st_ino
    def changed(fd):
        value = real_fstat(fd)
        if value.st_ino == wanted:
            fields = list(value)
            fields[2] += 1000
            return os.stat_result(fields)
        return value
    monkeypatch.setattr(os, "fstat", changed)
    with pytest.raises(PathSafetyError, match="changed during identity"):
        catalog.register(target, instance_id="project")


def test_register_and_import_are_read_only_and_never_capture_content() -> None:
    with tempfile.TemporaryDirectory(prefix="stateport-catalog-") as raw:
        root = Path(raw)
        instances = root / "instances"
        instances.mkdir()
        first = instances / "first"
        second = instances / "second"
        first.mkdir()
        second.mkdir()
        (first / "learner-notes.txt").write_text("private learner content", encoding="utf-8")
        catalog = _catalog(root)

        registered = catalog.register("first", instance_id="first-id")
        imported = catalog.import_instance(second, name="Imported second", instance_id="second-id")

        assert registered.adoption_mode == "registered"
        assert imported.adoption_mode == "imported"
        assert registered.read_only is True
        assert first.is_dir() and second.is_dir()
        raw_catalog = (root / ".stateport" / "instances.json").read_text(encoding="utf-8")
        assert "private learner content" not in raw_catalog
        assert "learner-notes.txt" not in raw_catalog
        assert json.loads(raw_catalog)["formatVersion"] == CATALOG_FORMAT


def test_path_confinement_and_symlinks_fail_closed() -> None:
    with tempfile.TemporaryDirectory(prefix="stateport-catalog-safety-") as raw:
        root = Path(raw)
        instances = root / "instances"
        instances.mkdir()
        (instances / "safe").mkdir()
        outside = root / "outside"
        outside.mkdir()
        catalog = _catalog(root)

        for unsafe in (outside, "../outside", "/tmp/not-an-instance"):
            try:
                catalog.register(unsafe)
            except (PathSafetyError, FileNotFoundError):
                pass
            else:
                raise AssertionError(f"unsafe path was accepted: {unsafe}")

        (instances / "link").symlink_to(outside, target_is_directory=True)
        try:
            catalog.register("link")
        except PathSafetyError:
            pass
        else:
            raise AssertionError("symlink instance path was accepted")
        try:
            catalog.register(instances / "link")
        except PathSafetyError:
            pass
        else:
            raise AssertionError("absolute symlink instance path was accepted")

        symlinked_root = root / "root-link"
        symlinked_root.symlink_to(instances, target_is_directory=True)
        try:
            InstanceCatalog(root / "other.json", symlinked_root)
        except PathSafetyError:
            pass
        else:
            raise AssertionError("symlink instances root was accepted")


def test_refresh_marks_replaced_paths_unsafe_and_adoption_cannot_duplicate_moves() -> None:
    with tempfile.TemporaryDirectory(prefix="stateport-catalog-revalidation-") as raw:
        root = Path(raw)
        instances = root / "instances"
        instances.mkdir()
        original = instances / "original"
        original.mkdir()
        catalog = _catalog(root)
        record = catalog.register(original, instance_id="identity-id")

        original.rename(instances / "moved")
        try:
            catalog.register(instances / "moved", instance_id="duplicate-id")
        except DuplicateInstanceError:
            pass
        else:
            raise AssertionError("a moved directory was adopted twice")

        outside = root / "outside"
        outside.mkdir()
        (instances / "moved").rmdir()
        (instances / "moved").symlink_to(outside, target_is_directory=True)
        unsafe = catalog.get(record.instance_id)
        assert unsafe.path_state == "unsafe"


def test_refresh_revalidates_moved_and_stale_paths() -> None:
    with tempfile.TemporaryDirectory(prefix="stateport-catalog-refresh-") as raw:
        root = Path(raw)
        instances = root / "instances"
        instances.mkdir()
        original = instances / "original"
        original.mkdir()
        catalog = _catalog(root)
        record = catalog.register(original, instance_id="move-me")

        original.rename(instances / "moved")
        moved = catalog.get(record.instance_id)
        assert moved.path == "moved"
        assert moved.path_state == "moved"
        assert moved.previous_paths == ("original",)

        (instances / "moved").rmdir()
        (instances / "moved").mkdir()
        stale = catalog.get(record.instance_id)
        assert stale.path == "moved"
        assert stale.path_state == "stale"

        (instances / "moved").rmdir()
        missing = catalog.get(record.instance_id)
        assert missing.path_state == "missing"


def test_atomic_replacement_rebind_requires_both_exact_filesystem_identities() -> None:
    with tempfile.TemporaryDirectory(prefix="stateport-catalog-rebind-") as raw:
        root = Path(raw)
        instances = root / "instances"
        instances.mkdir()
        target = instances / "project"
        target.mkdir()
        catalog = _catalog(root)
        original = catalog.register(target, instance_id="replace-me")

        displaced = instances / "displaced"
        target.rename(displaced)
        target.mkdir()
        replacement = target.stat()
        expected = {
            "device": replacement.st_dev,
            "inode": replacement.st_ino,
            "kind": "directory",
        }
        try:
            catalog.rebind_replaced_directory(
                original.instance_id,
                path=original.path,
                previous_filesystem=expected,
                expected_filesystem=expected,
                created_at=original.created_at,
            )
        except CatalogError:
            pass
        else:
            raise AssertionError("replacement rebind accepted the wrong prior identity")

        rebound = catalog.rebind_replaced_directory(
            original.instance_id,
            path=original.path,
            previous_filesystem=original.filesystem.to_dict(),
            expected_filesystem=expected,
            created_at=original.created_at,
        )
        assert rebound.path_state == "present"
        assert rebound.filesystem.to_dict() == expected


def test_rename_archive_unarchive_and_forget_never_touch_directory() -> None:
    with tempfile.TemporaryDirectory(prefix="stateport-catalog-actions-") as raw:
        root = Path(raw)
        (root / "instances").mkdir()
        instance = root / "instances" / "project"
        instance.mkdir()
        catalog = _catalog(root)
        record = catalog.register(instance, name="Project", instance_id="project-id")

        renamed = catalog.rename(record.instance_id, "Renamed project")
        assert renamed.name == "Renamed project"
        assert instance.is_dir()
        assert catalog.archive(record.instance_id).status == "archived"
        assert catalog.list(include_archived=False) == ()
        assert catalog.unarchive(record.instance_id).status == "active"

        forgotten = catalog.forget(record.instance_id)
        assert forgotten.instance_id == record.instance_id
        assert instance.is_dir()
        assert catalog.list(refresh=False) == ()


def test_schema_and_duplicate_guards_are_authoritative() -> None:
    with tempfile.TemporaryDirectory(prefix="stateport-catalog-schema-") as raw:
        root = Path(raw)
        (root / "instances").mkdir()
        (root / "instances" / "one").mkdir()
        catalog = _catalog(root)
        catalog.register("one", instance_id="one-id")
        try:
            catalog.register("one", instance_id="two-id")
        except DuplicateInstanceError:
            pass
        else:
            raise AssertionError("duplicate path was accepted")

        catalog_path = root / ".stateport" / "instances.json"
        document = json.loads(catalog_path.read_text(encoding="utf-8"))
        document["formatVersion"] = "stateport.instance-catalog/v0"
        catalog_path.write_text(json.dumps(document), encoding="utf-8")
        try:
            catalog.list(refresh=False)
        except CatalogSchemaError:
            pass
        else:
            raise AssertionError("unsupported schema version was accepted")


def test_concurrent_writers_preserve_both_entries() -> None:
    with tempfile.TemporaryDirectory(prefix="stateport-catalog-concurrency-") as raw:
        root = Path(raw)
        instances = root / "instances"
        instances.mkdir()
        for name in ("a", "b", "c", "d"):
            (instances / name).mkdir()
        catalog = _catalog(root)

        def register(name: str) -> str:
            return catalog.register(name, instance_id=f"id-{name}").instance_id

        with ThreadPoolExecutor(max_workers=4) as pool:
            assert sorted(pool.map(register, ("a", "b", "c", "d"))) == ["id-a", "id-b", "id-c", "id-d"]
        assert [record.instance_id for record in catalog.list(refresh=False)] == ["id-a", "id-b", "id-c", "id-d"]


if __name__ == "__main__":
    for test in (
        test_register_and_import_are_read_only_and_never_capture_content,
        test_path_confinement_and_symlinks_fail_closed,
        test_refresh_marks_replaced_paths_unsafe_and_adoption_cannot_duplicate_moves,
        test_refresh_revalidates_moved_and_stale_paths,
        test_atomic_replacement_rebind_requires_both_exact_filesystem_identities,
        test_rename_archive_unarchive_and_forget_never_touch_directory,
        test_schema_and_duplicate_guards_are_authoritative,
        test_concurrent_writers_preserve_both_entries,
    ):
        test()
    print("PASS")
