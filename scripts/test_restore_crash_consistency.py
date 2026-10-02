"""Crash-point sweep over every durable filesystem write of a governed restore apply.

A simulated kill -9 (a BaseException, so no `except Exception` rollback runs) is injected before each
durable write (write, fsync, mkdir, rename, link, unlink, directory sync, subprocess) of apply_restore.
After each simulated kill the service "restarts" (a fresh PersistentApp over the same files) and must
show exactly one consistent outcome:
  * restore not applied: no destination directory, no catalog entry, no receipt; the source is untouched
    and a fresh restore plan -> approve -> apply succeeds; or
  * restore completed: destination whole and registered, receipt recorded; a re-plan onto the same
    destination is refused with the specific `restore_destination_exists` code.
A re-plan must never fail with a generic error.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from test_governed_restore import _app, _digest_tree, _instance  # noqa: E402
from stateport_persistent_app import LocalLayout, PersistentApp  # noqa: E402
from stateport_persistent_app.app import AppError, ApprovalError  # noqa: E402

SOURCE, DEST = "restore-source", "restore-result"


class _Crash(BaseException):
    """Stands in for SIGKILL: not an Exception, so no rollback handler runs."""


class _CrashPoints:
    """Counts durable-write events; raises before event number `crash_at`."""

    OS_CALLS = ("write", "fsync", "mkdir", "rename", "replace", "link", "symlink", "unlink", "rmdir", "ftruncate", "fchmod")

    def __init__(self, monkeypatch: pytest.MonkeyPatch, crash_at: int | None) -> None:
        self.crash_at, self.events, self.armed = crash_at, [], False
        for name in self.OS_CALLS:
            self._patch(monkeypatch, os, name, name)
        self._patch(monkeypatch, subprocess, "run", "subprocess")
        self._patch(monkeypatch, subprocess, "Popen", "subprocess")
        import instance_backup as ib

        self._patch(monkeypatch, ib, "_rename_noreplace", "rename-noreplace")

    def _patch(self, monkeypatch, owner, name: str, label: str) -> None:
        real = getattr(owner, name)

        def hooked(*args, **kwargs):
            if self.armed:
                self.events.append(label)
                if self.crash_at is not None and len(self.events) == self.crash_at:
                    raise _Crash(f"killed before {label} #{len(self.events)}")
            return real(*args, **kwargs)

        monkeypatch.setattr(owner, name, hooked)


def _restart(workdir: Path) -> PersistentApp:
    """What AppServer startup does before serving: quarantine unregistered directories, then reconcile restores."""
    app = PersistentApp(LocalLayout.from_environment())
    app.catalog.quarantine_unregistered_instance_directories()
    reconcile = getattr(app, "reconcile_interrupted_restores", None)  # absent before the fix
    if reconcile is not None:
        reconcile()
    return app


def _plan_approve(app: PersistentApp, receipt_id: str):
    plan = app.restore_plan(SOURCE, backup_receipt_id=receipt_id, destination_instance_id=DEST, destination_name="Recovered fixture")
    approval = app.approve_restore(SOURCE, plan_digest=plan["planDigest"], actor_id="test-operator", actor_role="local_operator")
    return plan, approval


def _one(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tag: str, crash_at: int | None):
    workdir = tmp_path / tag
    workdir.mkdir()
    app = _app(workdir, monkeypatch)  # fresh state root per crash point (catalog binds directory identity)
    _instance(app)
    receipt_id = app.backup(SOURCE)["backupReceipt"]["receiptId"]
    plan, approval = _plan_approve(app, receipt_id)
    source_before = _digest_tree(app.layout.instances_root / SOURCE)
    points = _CrashPoints(monkeypatch, crash_at)
    points.armed = True
    crashed = False
    try:
        app.apply_restore(SOURCE, plan_digest=plan["planDigest"], approval_digest=approval["approvalDigest"])
    except _Crash:
        crashed = True
    points.armed = False
    # restart: a fresh process over the same files, with the service's startup housekeeping
    restarted = _restart(tmp_path / tag)
    target = restarted.layout.instances_root / DEST
    registered = any(item.get("instanceId") == DEST for item in restarted.catalog.list())
    assert _digest_tree(restarted.layout.instances_root / SOURCE) == source_before, "source changed"
    receipts = restarted._restore_artifact_digests("receipts")
    if plan["planDigest"] in receipts:
        # outcome "after": whole, registered, receipt recorded
        assert target.is_dir() and registered, (target.is_dir(), registered)
        assert restarted.catalog.get(DEST)["pathState"] == "present"
        assert (target / "instance.yaml").is_file() and (target / ".statedd" / "lock.yaml").is_file()
        with pytest.raises(AppError) as refused:
            _plan_approve(restarted, receipt_id)
        assert getattr(refused.value, "cause_code", None) == "restore_destination_exists", repr(refused.value)
        assert restarted.recovery_status(SOURCE)["restore"]["status"] == "validated"
        outcome = "after"
    else:
        # outcome "before": nothing of the restore is visible, nothing needs an operator
        assert not registered and not target.exists(), "restore half-landed without a receipt"
        assert not restarted._source_access_path(DEST).exists()
        status = restarted.recovery_status(SOURCE)["restore"]
        assert status["operatorInspectionRequired"] is False and status["stagingRetained"] is False, status
        assert status["status"] in {"approved", "failed"}, status
        if status["status"] == "failed":
            assert status["failureReasonCode"] == "restore_interrupted", status
        # a second start finds nothing left to do
        assert _restart(tmp_path / tag).recovery_status(SOURCE)["restore"] == status
        if crash_at % 2:
            # the already approved plan can simply be applied again (while its approval is valid)
            receipt = restarted.apply_restore(SOURCE, plan_digest=plan["planDigest"], approval_digest=approval["approvalDigest"])
        else:
            # a fresh plan must succeed (the same second included), never fail generically
            plan2, approval2 = _plan_approve(restarted, receipt_id)
            receipt = restarted.apply_restore(SOURCE, plan_digest=plan2["planDigest"], approval_digest=approval2["approvalDigest"])
        assert receipt["status"] == "validated"
        assert restarted.catalog.get(DEST)["pathState"] == "present"
        assert restarted.recovery_status(SOURCE)["restore"]["status"] == "validated"
        outcome = "before"
    return points.events, crashed, outcome


def test_crash_at_every_durable_write_of_restore_leaves_one_consistent_outcome(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    events, crashed, outcome = _one(tmp_path, monkeypatch, "dry", None)
    assert not crashed and outcome == "after"
    assert len(events) > 20, events
    outcomes: dict[str, int] = {}
    failures: list[str] = []
    for crash_at in range(1, len(events) + 1):
        try:
            _ev, was_crashed, outcome = _one(tmp_path, monkeypatch, f"c{crash_at}", crash_at)
            assert was_crashed
            outcomes[outcome] = outcomes.get(outcome, 0) + 1
        except Exception as exc:  # noqa: BLE001
            failures.append(f"crash before event {crash_at} ({events[crash_at - 1]}): {type(exc).__name__}: {str(exc)[:200]}")
        shutil.rmtree(tmp_path / f"c{crash_at}", ignore_errors=True)
    assert not failures, "\n".join(failures)
    assert set(outcomes) == {"before", "after"}, outcomes


def test_same_second_approval_repeat_is_idempotent_and_conflicts_are_specific(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The reported defect: plan+approve repeated within one second (a fast restart) failed with a generic 400."""
    import stateport_persistent_app.app as persistent_app_module
    from datetime import datetime as real_datetime

    class FixedClock(real_datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 10, 2, 12, 0, 0, tzinfo=tz)

    app = _app(tmp_path, monkeypatch)
    _instance(app)
    receipt_id = app.backup(SOURCE)["backupReceipt"]["receiptId"]
    monkeypatch.setattr(persistent_app_module, "datetime", FixedClock)
    first = _plan_approve(app, receipt_id)
    assert _plan_approve(app, receipt_id) == first
    # a different record under an existing identity is refused with its own code, not a generic one
    plan, _approval = first
    forged = dict(plan, destinationName="Someone else")
    with pytest.raises(AppError) as conflict:
        app._publish_restore_artifact(
            "plans", plan["planDigest"], forged, format_version="stateport.restore-plan/v1", digest_field="planDigest",
        )
    assert conflict.value.cause_code == "restore_artifact_conflict"


def test_reconcile_never_rolls_back_an_instance_that_predates_the_interrupted_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import json

    app = _app(tmp_path, monkeypatch)
    _instance(app)
    receipt_id = app.backup(SOURCE)["backupReceipt"]["receiptId"]
    plan, approval = _plan_approve(app, receipt_id)
    receipt = app.apply_restore(SOURCE, plan_digest=plan["planDigest"], approval_digest=approval["approvalDigest"])
    assert receipt["status"] == "validated"
    # a journal entry of some other plan for the same destination, claimed to start after the instance existed
    intent = {
        "formatVersion": "stateport.restore-intent/v1", "operation": "restore_new_instance",
        "sourceInstanceId": SOURCE, "destinationInstanceId": DEST, "planDigest": "sha256:" + "a" * 64,
        "approvalDigest": "sha256:" + "b" * 64, "attemptId": "0" * 16, "startedAt": "2999-01-01T00:00:00Z",
    }
    from stateport_persistent_app.app import _digest

    intent["intentDigest"] = _digest(intent)
    app._write_restore_artifact_new("intents", intent["intentDigest"], intent)
    before = _digest_tree(app.layout.instances_root / DEST)
    restarted = _restart(tmp_path)
    assert restarted.catalog.get(DEST)["pathState"] == "present"
    assert _digest_tree(restarted.layout.instances_root / DEST) == before
    failures = restarted._restore_artifact_digests("failures")
    assert len(failures) == 1
    record = json.loads(restarted._restore_artifact_path("failures", failures[0]).read_text())
    assert record["reasonCode"] == "restore_interrupted" and record["catalogRegistered"] is True
    assert record["operatorInspectionRequired"] is True and record["intentDigest"] == intent["intentDigest"]
    assert _restart(tmp_path)._restore_artifact_digests("failures") == failures  # resolved: nothing more to do
