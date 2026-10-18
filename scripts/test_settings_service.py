"""Focused tests for the typed durable settings boundary."""

from __future__ import annotations

from pathlib import Path
import threading

import pytest

ROOT = Path(__file__).resolve().parents[1]
import sys

for relative in (
    "packages/persistent-app/src",
    "packages/statedd-core/src",
    "packages/template-validator/src",
    "packages/instance-backup/src",
    "packages/instance-catalog/src",
    "packages/diagnostics/src",
):
    path = ROOT / relative
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from stateport_persistent_app.settings import SettingsError, SettingsStore  # noqa: E402


def test_projection_is_typed_and_exposes_requested_effective_and_policy_values(tmp_path: Path) -> None:
    store = SettingsStore(tmp_path / "global.json", scope="global")
    projection = store.projection()
    assert projection["formatVersion"] == "stateport.settings-projection/v1"
    fields = {field["key"]: field for section in projection["sections"] for field in section["fields"]}
    assert fields["context.mode"]["value"] == "Use Application Settings → Context"
    assert fields["context.mode"]["editable"] is False
    assert fields["runtime.networkPolicy"]["effectiveValue"] == "disabled"
    assert fields["runtime.networkPolicy"]["editable"] is False
    assert projection["effectivePolicy"]["mostRestrictiveWins"] is True


def test_patch_persists_exact_values_and_creates_rollback_receipt(tmp_path: Path) -> None:
    path = tmp_path / "global.json"
    store = SettingsStore(path, scope="global")
    changed = store.patch(expected_revision=0, changes={"general.defaultLandingView": "catalog", "notifications.level": "all"})
    assert changed["receipt"]["action"] == "settings.patch"
    assert changed["projection"]["revision"] == 1

    restarted = SettingsStore(path, scope="global")
    assert restarted.projection()["revision"] == 1
    values = {field["key"]: field["value"] for section in restarted.projection()["sections"] for field in section["fields"]}
    assert values["general.defaultLandingView"] == "catalog"
    history = restarted.projection()["recentReceipts"]
    assert len(history) == 1
    assert set(history[0]) == {
        "formatVersion", "receiptId", "scope", "instanceId", "action",
        "status", "revision", "changes", "previousValues", "effectivePolicy",
        "createdAt",
    }
    assert history[0]["scope"] == "global"
    assert history[0]["instanceId"] is None
    assert history[0]["revision"] == 1
    assert history[0]["changes"] == {
        "general.defaultLandingView": "catalog",
        "notifications.level": "all",
    }
    assert history[0]["previousValues"] == {
        "general.defaultLandingView": "home",
        "notifications.level": "important",
    }
    receipt_id = history[0]["receiptId"]
    with pytest.raises(SettingsError, match="stale"):
        restarted.rollback(expected_revision=0, receipt_id=receipt_id)
    rolled_back = restarted.rollback(expected_revision=1, receipt_id=receipt_id)
    assert rolled_back["projection"]["revision"] == 2
    values = {field["key"]: field["value"] for section in rolled_back["projection"]["sections"] for field in section["fields"]}
    assert values["general.defaultLandingView"] == "home"
    assert values["notifications.level"] == "important"
    assert rolled_back["receipt"]["action"] == "settings.rollback"


def test_projection_bounds_recent_rollback_targets_to_ten(tmp_path: Path) -> None:
    store = SettingsStore(tmp_path / "global.json", scope="global")
    appearance = "dark"
    for revision in range(12):
        store.patch(
            expected_revision=revision,
            changes={"general.appearance": appearance},
        )
        appearance = "light" if appearance == "dark" else "dark"
    history = store.projection()["recentReceipts"]
    assert len(history) == 10
    assert [receipt["revision"] for receipt in history] == list(range(12, 2, -1))


def test_settings_fail_closed_for_stale_revision_unsupported_or_policy_owned_changes(tmp_path: Path) -> None:
    store = SettingsStore(tmp_path / "global.json", scope="global")
    with pytest.raises(SettingsError, match="stale"):
        store.patch(expected_revision=1, changes={"general.defaultLandingView": "catalog"})
    with pytest.raises(SettingsError, match="policy"):
        store.patch(expected_revision=0, changes={"runtime.networkPolicy": "enabled"})
    with pytest.raises(SettingsError, match="supported options"):
        store.patch(expected_revision=0, changes={"general.defaultLandingView": "unsafe"})


def test_application_settings_do_not_expose_global_only_writable_preferences(tmp_path: Path) -> None:
    path = tmp_path / "application.json"
    store = SettingsStore(path, scope="application", instance_id="project-one")
    projection = store.projection()
    fields = {field["key"]: field for section in projection["sections"] for field in section["fields"]}
    assert "general.defaultLandingView" not in fields
    assert "general.appearance" not in fields
    assert "notifications.level" not in fields
    with pytest.raises(SettingsError, match="unknown settings field"):
        store.patch(expected_revision=0, changes={"general.appearance": "dark"})


def test_application_settings_migrate_old_global_only_values_without_displaying_them(tmp_path: Path) -> None:
    path = tmp_path / "application.json"
    path.write_text(
        '{"formatVersion":"stateport.settings-store/v1","scope":"application",'
        '"instanceId":"project-one","revision":1,"values":{'
        '"general.defaultLandingView":"catalog","general.appearance":"dark",'
        '"notifications.level":"all"},"receipts":[]}',
        encoding="utf-8",
    )
    store = SettingsStore(path, scope="application", instance_id="project-one")
    assert store.projection()["revision"] == 1
    assert all(
        field["key"] not in {"general.defaultLandingView", "general.appearance", "notifications.level"}
        for section in store.projection()["sections"]
        for field in section["fields"]
    )


def test_settings_store_rejects_malformed_identity(tmp_path: Path) -> None:
    path = tmp_path / "application.json"
    path.write_text('{"formatVersion":"wrong","scope":"global","instanceId":null}', encoding="utf-8")
    with pytest.raises(SettingsError, match="identity or format"):
        SettingsStore(path, scope="application", instance_id="project-one")


def test_settings_store_rejects_symlinked_parent_and_unvalidated_receipt(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(SettingsError, match="parent must not be a symlink"):
        SettingsStore(link / "global.json", scope="global")

    path = tmp_path / "malformed-receipt.json"
    path.write_text(
        '{"formatVersion":"stateport.settings-store/v1","scope":"global","instanceId":null,"revision":1,'
        '"values":{},"receipts":[{"formatVersion":"wrong"}]}',
        encoding="utf-8",
    )
    with pytest.raises(SettingsError, match="receipt is malformed"):
        SettingsStore(path, scope="global")


def test_settings_store_migrates_retired_retention_key_but_rejects_new_unknown_keys(tmp_path: Path) -> None:
    retired = tmp_path / "retired.json"
    retired.write_text(
        '{"formatVersion":"stateport.settings-store/v1","scope":"global","instanceId":null,"revision":0,'
        '"values":{"conversation.retentionDays":90},"receipts":[]}',
        encoding="utf-8",
    )
    projection = SettingsStore(retired, scope="global").projection()
    assert not any(field["key"] == "conversation.retentionDays" for section in projection["sections"] for field in section["fields"])

    unknown = tmp_path / "unknown.json"
    unknown.write_text(
        '{"formatVersion":"stateport.settings-store/v1","scope":"global","instanceId":null,"revision":0,'
        '"values":{"not.a.real.setting":true},"receipts":[]}',
        encoding="utf-8",
    )
    with pytest.raises(SettingsError, match="unknown field"):
        SettingsStore(unknown, scope="global")


def test_concurrent_settings_writes_accept_only_one_revision_bound_mutation(tmp_path: Path) -> None:
    path = tmp_path / "global.json"
    SettingsStore(path, scope="global")
    stores = [SettingsStore(path, scope="global"), SettingsStore(path, scope="global")]
    barrier = threading.Barrier(2)
    outcomes: list[str] = []

    def mutate(store: SettingsStore, value: str) -> None:
        barrier.wait()
        try:
            store.patch(expected_revision=0, changes={"general.appearance": value})
        except SettingsError as exc:
            outcomes.append(str(exc))
        else:
            outcomes.append("applied")

    threads = [threading.Thread(target=mutate, args=(stores[0], "light")), threading.Thread(target=mutate, args=(stores[1], "dark"))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(outcomes) == ["applied", "settings revision is stale; reload the effective projection"]
    assert SettingsStore(path, scope="global").projection()["revision"] == 1
