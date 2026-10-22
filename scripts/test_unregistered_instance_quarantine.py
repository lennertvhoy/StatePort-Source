"""A crash between creating an instance directory and registering it must not strand the directory.

Found by the kill -9 durability row: the install, portable import and restore write the destination before the
catalog entry, so a kill in between left an invisible directory that blocked retrying the same id.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for source_root in sorted((ROOT / "packages").glob("*/src")):
    sys.path.insert(0, str(source_root))

from stateport_persistent_app import LocalLayout  # noqa: E402
from stateport_persistent_app.app import PersistentCatalog  # noqa: E402


def _catalog(tmp_path: Path) -> tuple[PersistentCatalog, LocalLayout]:
    layout = LocalLayout(tmp_path / "config", tmp_path / "data", tmp_path / "state")
    layout.initialize()
    return PersistentCatalog(layout), layout


def test_unregistered_directories_are_quarantined_not_deleted(tmp_path: Path) -> None:
    catalog, layout = _catalog(tmp_path)
    kept = layout.instances_root / "kept"
    kept.mkdir()
    (kept / "instance.yaml").write_text("x: 1\n")
    catalog._canonical().register(kept, instance_id="kept")
    orphan = layout.instances_root / "half-installed"
    orphan.mkdir()
    (orphan / "state.txt").write_text("partial\n")
    staging = layout.instances_root / ".copy.restore-abc"
    staging.mkdir()

    moved = catalog.quarantine_unregistered_instance_directories()

    assert sorted(moved) == [".copy.restore-abc", "half-installed"]
    assert kept.is_dir() and not orphan.exists() and not staging.exists()
    quarantined = list((layout.data_root / "quarantine" / "unregistered-instances").glob("half-installed-*"))
    assert len(quarantined) == 1 and (quarantined[0] / "state.txt").read_text() == "partial\n"
    assert catalog.quarantine_unregistered_instance_directories() == []  # idempotent


def test_unreadable_catalog_moves_nothing(tmp_path: Path) -> None:
    catalog, layout = _catalog(tmp_path)
    (layout.instances_root / "precious").mkdir()
    layout.catalog_file.parent.mkdir(parents=True, exist_ok=True)
    layout.catalog_file.write_text("{ not json")
    assert catalog.quarantine_unregistered_instance_directories() == []
    assert (layout.instances_root / "precious").is_dir()


def test_missing_catalog_moves_nothing(tmp_path: Path) -> None:
    catalog, layout = _catalog(tmp_path)
    (layout.instances_root / "precious").mkdir(exist_ok=True)
    if layout.catalog_file.exists():
        layout.catalog_file.unlink()
    assert catalog.quarantine_unregistered_instance_directories() == []
    assert (layout.instances_root / "precious").is_dir()


def test_listing_instances_does_not_reread_the_catalog_once_per_instance(tmp_path: Path, monkeypatch) -> None:
    """GET /v1/instances was O(n^2): each listed instance triggered catalog.get (full load, validate, rewrite)."""
    from stateport_persistent_app import PersistentApp

    layout = LocalLayout(tmp_path / "config", tmp_path / "data", tmp_path / "state")
    layout.initialize()
    app = PersistentApp(layout)
    for n in range(4):
        root = layout.instances_root / f"inst-{n}"
        root.mkdir()
        app.catalog._canonical().register(root, instance_id=f"inst-{n}")
    calls: list[str] = []
    original = PersistentCatalog.get

    def counting_get(self, instance_id):  # noqa: ANN001
        calls.append(instance_id)
        return original(self, instance_id)

    monkeypatch.setattr(PersistentCatalog, "get", counting_get)
    assert len(app.instance_list_public()) == 4
    assert calls == []
