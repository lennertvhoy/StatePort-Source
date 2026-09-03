#!/usr/bin/env python3
"""Focused contract tests for the append-only lifecycle policy helpers."""

from __future__ import annotations

import copy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "statedd-core" / "src"))

from statedd_core.append_only_policy import (  # noqa: E402
    APPEND_ONLY_ROLLBACK_MODE,
    AppendOnlyLifecyclePolicy,
    MigrationMarker,
    apply_append_only_update,
    plan_append_only_marker,
    rollback_append_only_update,
)
from statedd_core.lifecycle_errors import LifecycleError  # noqa: E402


def _policy() -> tuple[AppendOnlyLifecyclePolicy, MigrationMarker]:
    marker = MigrationMarker(
        marker_id="lesson-records-v2",
        source_schema="lesson-record/v1",
        target_schema="lesson-record/v2",
        sensitivity="private",
    )
    return (
        AppendOnlyLifecyclePolicy.create(
            "state/lessons.jsonl", sensitivity="private", registered_markers=(marker,)
        ),
        marker,
    )


def _history() -> list[dict[str, object]]:
    return [
        {
            "recordId": "lesson:001",
            "recordType": "historical",
            "sensitivity": "private",
            "status": "completed",
        },
        {
            "recordId": "lesson:002",
            "recordType": "historical",
            "sensitivity": "private",
            "status": "in_progress",
        },
    ]


def _raises(action, text: str) -> None:
    try:
        action()
    except LifecycleError as exc:
        assert text in str(exc), str(exc)
    else:
        raise AssertionError(f"expected LifecycleError containing {text!r}")


def test_registered_marker_append_preserves_history_and_sensitivity() -> None:
    policy, marker = _policy()
    history = _history()
    original = copy.deepcopy(history)

    update = plan_append_only_marker(history, marker, policy)
    applied = apply_append_only_update(history, update)

    assert history == original
    assert applied[:2] == original
    assert applied[-1] == marker.as_record()
    assert all(record["sensitivity"] == "private" for record in applied)
    assert update.sensitivity == "private"
    assert update.rollback_snapshot == original
    assert update.as_dict()["rollback"]["mode"] == APPEND_ONLY_ROLLBACK_MODE


def test_generic_rewrite_or_insert_is_rejected() -> None:
    policy, marker = _policy()
    update = plan_append_only_marker(_history(), marker, policy)

    rewritten = update.after
    rewritten[0]["status"] = "rewritten"
    _raises(
        lambda: apply_append_only_update(rewritten, update),
        "historical records must remain unchanged",
    )

    inserted = [update.after[-1], *update.before]
    _raises(
        lambda: apply_append_only_update(inserted, update),
        "historical records must remain unchanged",
    )


def test_unknown_and_duplicate_markers_are_rejected() -> None:
    policy, marker = _policy()
    history = _history()
    unknown = MigrationMarker(
        marker_id="unregistered",
        source_schema="lesson-record/v2",
        target_schema="lesson-record/v3",
        sensitivity="private",
    )
    _raises(
        lambda: plan_append_only_marker(history, unknown, policy),
        "not registered",
    )

    update = plan_append_only_marker(history, marker, policy)
    _raises(
        lambda: plan_append_only_marker(update.after, marker, policy),
        "already present",
    )


def test_marker_and_history_sensitivity_must_not_change() -> None:
    policy, marker = _policy()
    wrong_marker = MigrationMarker(
        marker_id="lesson-records-v2",
        source_schema="lesson-record/v1",
        target_schema="lesson-record/v2",
        sensitivity="secret",
    )
    _raises(
        lambda: plan_append_only_marker(_history(), wrong_marker, policy),
        "registered definition",
    )

    changed = _history()
    changed[0]["sensitivity"] = "public"
    _raises(
        lambda: plan_append_only_marker(changed, marker, policy),
        "sensitivity does not match policy",
    )


def test_rollback_restores_exact_snapshot_but_never_later_history() -> None:
    policy, marker = _policy()
    history = _history()
    update = plan_append_only_marker(history, marker, policy)
    applied = apply_append_only_update(history, update)

    restored = rollback_append_only_update(applied, update)
    assert restored == history
    assert restored is not history

    later = applied + [
        {
            "recordId": "lesson:003",
            "recordType": "historical",
            "sensitivity": "private",
            "status": "new",
        }
    ]
    _raises(
        lambda: rollback_append_only_update(later, update),
        "would rewrite records added after this update",
    )


def test_registered_marker_history_remains_valid_for_a_later_marker() -> None:
    first = MigrationMarker(
        marker_id="lesson-records-v2",
        source_schema="lesson-record/v1",
        target_schema="lesson-record/v2",
        sensitivity="private",
    )
    second = MigrationMarker(
        marker_id="lesson-records-v3",
        source_schema="lesson-record/v2",
        target_schema="lesson-record/v3",
        sensitivity="private",
    )
    policy = AppendOnlyLifecyclePolicy.create(
        "state/lessons.jsonl",
        sensitivity="private",
        registered_markers=(first, second),
    )

    first_update = plan_append_only_marker(_history(), first, policy)
    first_applied = apply_append_only_update(_history(), first_update)
    second_update = plan_append_only_marker(first_applied, second, policy)
    second_applied = apply_append_only_update(first_applied, second_update)

    assert second_applied[: len(first_applied)] == first_applied
    assert [record["markerId"] for record in second_applied[-2:]] == [
        "lesson-records-v2",
        "lesson-records-v3",
    ]


def test_staged_append_tampering_and_control_paths_fail_closed() -> None:
    policy, marker = _policy()
    update = plan_append_only_marker(_history(), marker, policy)
    update._after[0]["status"] = "tampered"
    _raises(
        lambda: apply_append_only_update(update.before, update),
        "update digest is invalid",
    )
    _raises(
        lambda: AppendOnlyLifecyclePolicy.create(
            "../outside.jsonl", sensitivity="private", registered_markers=(marker,)
        ),
        "safe relative data path",
    )


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
    print("PASS")
