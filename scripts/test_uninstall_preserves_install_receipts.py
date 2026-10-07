#!/usr/bin/env python3
"""Uninstall must preserve the install receipts, and must NOT pretend to do more.

The install receipt is the only product-owned carrier of an instance's
application binding: it records the ``applicationId`` and ``catalogIdentity``
that bind the instance to the application experience policy, and the catalog
that also held that binding is removed by the same uninstall. Measured on a
populated durable root, ``uninstall_metadata`` used to remove ``state_root``
outright, taking every receipt with it, and the one surviving durable record
mentions ``applicationId`` zero times -- so an identical reinstall had nothing
left to restore the binding from.

These tests pin the preservation, the byte fidelity, the unchanged
content-preservation half, AND the honest limit: the catalog is still removed,
so this change does not make reinstall work and must not be read as if it did.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import run_template_lifecycle_journey  # noqa: F401,E402  (side effect: sys.path bootstrap)

from stateport_persistent_app import LocalLayout, PersistentApp  # noqa: E402

RECEIPT = {
    "formatVersion": "stateport.template-install-receipt/v1",
    "instanceId": "actual-projectstate-v6",
    "applicationId": "stateport.template.projectstate",
    "baseGit": "bb5a0444e3dd49fecbe6a3c33b61f00016d32591",
    "effects": {
        "managedCopyCreated": True,
        "managedGitHistoryCreated": True,
        "networkAccess": False,
        "repositoryCommandsExecuted": False,
        "sourceRepositoryMutation": False,
    },
    "catalogIdentity": {
        "applicationId": "stateport.template.projectstate",
        "instanceId": "actual-projectstate-v6",
        "createdAt": "2026-09-27T11:06:04.231681Z",
        "filesystemIdentityDigest": "sha256:7403993e2e87db1106f60f1991b034208cc34b686680e397dfc66b972c644f24",
    },
}


def _app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[PersistentApp, LocalLayout]:
    for name, leaf in (("CONFIG", "config"), ("DATA", "data"), ("STATE", "state")):
        monkeypatch.setenv("XDG_" + name + "_HOME", str(tmp_path / leaf))
    layout = LocalLayout.from_environment()
    layout.initialize()
    return PersistentApp(layout), layout


def _write_receipt(layout: LocalLayout, name: str, payload: dict) -> Path:
    directory = layout.operations_root / "template-imports"
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / name
    target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target


def test_uninstall_preserves_install_receipts_with_their_application_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app, layout = _app(tmp_path, monkeypatch)
    written = _write_receipt(layout, "actual-projectstate-v6.json", RECEIPT)
    original = written.read_bytes()

    receipt = app.setup_uninstall()

    # The receipt is still where the product reads it from, byte for byte.
    assert receipt["installReceiptsPreserved"] == ["actual-projectstate-v6.json"]
    assert written.is_file()
    assert written.read_bytes() == original
    # ...and the application binding inside it is intact, which is the whole point.
    preserved = json.loads(written.read_text(encoding="utf-8"))
    assert preserved["applicationId"] == "stateport.template.projectstate"
    assert preserved["catalogIdentity"]["applicationId"] == "stateport.template.projectstate"
    assert preserved["effects"]["sourceRepositoryMutation"] is False


def test_uninstall_preserves_every_receipt_not_just_the_first(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app, layout = _app(tmp_path, monkeypatch)
    for instance_id, application_id in (
        ("actual-projectstate-v6", "stateport.template.projectstate"),
        ("actual-studystate", "stateport.template.studystate"),
        ("actual-statespec-template", "stateport.template.statespec"),
    ):
        _write_receipt(
            layout,
            f"{instance_id}.json",
            {**RECEIPT, "instanceId": instance_id, "applicationId": application_id},
        )

    receipt = app.setup_uninstall()

    assert receipt["installReceiptsPreserved"] == [
        "actual-projectstate-v6.json",
        "actual-statespec-template.json",
        "actual-studystate.json",
    ]
    surviving = sorted(p.name for p in (layout.operations_root / "template-imports").glob("*.json"))
    assert surviving == receipt["installReceiptsPreserved"]
    assert {json.loads((layout.operations_root / "template-imports" / name).read_text())["applicationId"]
            for name in surviving} == {
        "stateport.template.projectstate",
        "stateport.template.statespec",
        "stateport.template.studystate",
    }


def test_preservation_is_not_claimed_vacuously_when_there_are_no_receipts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A field that always said "preserved" would be indistinguishable from a removed check."""
    app, _layout = _app(tmp_path, monkeypatch)

    receipt = app.setup_uninstall()

    assert receipt["installReceiptsPreserved"] == []


def test_content_preservation_half_is_unchanged_by_this_fix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Preserving receipts must not trade away the behaviour that was already correct."""
    app, layout = _app(tmp_path, monkeypatch)
    _write_receipt(layout, "actual-projectstate-v6.json", RECEIPT)
    instance = layout.instances_root / "actual-projectstate-v6"
    (instance / "docs").mkdir(parents=True)
    marker = instance / "docs" / "KEEP.md"
    marker.write_text("# kept\n", encoding="utf-8")
    before = marker.read_bytes()

    receipt = app.setup_uninstall()

    assert receipt["instancesPreserved"] is True
    assert instance.is_dir()
    assert marker.read_bytes() == before
    assert receipt["backupsPreserved"] is True


def test_this_fix_does_not_claim_to_make_reinstall_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The honest limit, pinned so a later change cannot quietly overstate this one.

    Preserving the receipt keeps the application binding RECOVERABLE. It does not
    re-register the instance: the catalog is still removed, so a reinstall still
    starts from an empty catalog. If a future change makes the catalog survive,
    this test fails and the claim has to be revisited deliberately.
    """
    app, layout = _app(tmp_path, monkeypatch)
    _write_receipt(layout, "actual-projectstate-v6.json", RECEIPT)
    # A fresh layout has no catalog file until something registers, so write one
    # with a real entry: the removal of the catalog is the load-bearing half of
    # this limit, and it has to be observable to be pinned.
    layout.catalog_file.parent.mkdir(parents=True, exist_ok=True)
    layout.catalog_file.write_text(
        json.dumps(
            {
                "formatVersion": "stateport.instance-catalog/v1",
                "entries": [{"instanceId": "actual-projectstate-v6", "name": "ProjectState"}],
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    assert app.layout.catalog_file.is_file()

    app.setup_uninstall()

    assert not app.layout.catalog_file.is_file()
    app.setup_init()
    # `initialize` recreates the catalog DIRECTORY but not the document, so the
    # reinstalled install holds no entry for the instance either way.
    entries = (
        json.loads(app.layout.catalog_file.read_text(encoding="utf-8"))["entries"]
        if app.layout.catalog_file.is_file()
        else []
    )
    assert [e for e in entries if e.get("instanceId") == "actual-projectstate-v6"] == []
    # The receipt is still there to restore the binding FROM, which is the whole
    # difference this change makes and the limit of what it makes possible.
    assert (layout.operations_root / "template-imports" / "actual-projectstate-v6.json").is_file()
