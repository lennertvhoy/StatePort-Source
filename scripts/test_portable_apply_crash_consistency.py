"""Crash-point sweep over every durable write of a governed apply.

Invariant checked after a simulated kill -9 at ANY point and a service restart: exactly one
consistent outcome. Either "before" (instance tree untouched, run not applied, no sealed applied
bundle) or "after" (tree changed AND run applied AND closed with a receipt AND sealed applied
bundle). Never a sealed applied bundle for a run that is not applied; never a changed tree for a
run that is not applied.
"""
from __future__ import annotations

from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from test_portable_apply_integrity import (  # noqa: E402
    PortableExecutionService,
    _approved_proposal,
    digest_snapshot,
    snapshot_files,
)
import stateport_portable_execution.runtime as portable_runtime  # noqa: E402
from stateport_portable_execution.store import RunStore  # noqa: E402


class _Crash(BaseException):
    """Stands in for SIGKILL: not an Exception, so no `except Exception` rollback runs."""


class _CrashPoints:
    """Counts durable-write events of the apply path; raises before event number `crash_at`."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, crash_at: int | None) -> None:
        self.crash_at, self.events = crash_at, []
        self.armed = False
        self._patch(monkeypatch, RunStore, "_save", "run-store-save")
        self._patch(monkeypatch, PortableExecutionService, "_persist_apply_snapshot", "snapshot-persist")
        self._patch(monkeypatch, PortableExecutionService, "_discard_apply_snapshot", "snapshot-discard")
        self._patch(monkeypatch, PortableExecutionService, "_write_run_bundle", "bundle-seal")
        self._patch(monkeypatch, portable_runtime, "restore_snapshot", "canonical-commit")

    def _patch(self, monkeypatch, owner, name: str, label: str) -> None:
        real = getattr(owner, name)

        def hooked(*args, **kwargs):
            if self.armed:
                self.events.append(label)
                if self.crash_at is not None and len(self.events) == self.crash_at:
                    raise _Crash(f"killed before {label} #{len(self.events)}")
            return real(*args, **kwargs)

        monkeypatch.setattr(owner, name, hooked)


def _outcome(app, service_after, instance_root: Path, run_id: str, before_digest: str) -> str:
    run = service_after.store.get(run_id)
    assert run is not None
    status = run["status"]
    after_digest = digest_snapshot(snapshot_files(instance_root))
    sealed = list(service_after.bundle_root.glob(f"{run_id}-applied"))
    leftovers = [p.name for p in service_after.bundle_root.glob(f"{run_id}-applied*") if p.name != f"{run_id}-applied"]
    assert not any(name.endswith(".tmp") for name in leftovers), leftovers
    assert run["lifecycleState"] != "APPLYING" and status not in {"applying"}, status
    if status == "applied":
        assert run["lifecycleState"] == "CLOSED", run["lifecycleState"]
        assert after_digest == run["canonicalStateAfter"] != before_digest
        assert run.get("closureReceipt") and run.get("receiptId") == run["closureReceipt"]["receiptId"]
        assert len(sealed) == 1, "applied run lacks its sealed applied bundle"
        service_after._validate_run_closure_receipt(run, run["closureReceipt"])
        return "after"
    assert after_digest == before_digest, f"tree changed but run is {status}"
    assert not sealed, f"sealed applied bundle {sealed[0].name} exists but the run is {status}"
    assert not run.get("receipt") and not run.get("closureReceipt") and not run.get("appliedRunBundle"), (
        f"run {status} still claims an applied receipt/bundle"
    )
    return "before:" + status


def _one(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tag: str, crash_at: int | None):
    service, app, instance_root, run_id = _approved_proposal(tmp_path, monkeypatch, tag)
    before_digest = digest_snapshot(snapshot_files(instance_root))
    points = _CrashPoints(monkeypatch, crash_at)
    points.armed = True
    crashed = False
    try:
        service.apply_proposal(run_id)
    except _Crash:
        crashed = True
    points.armed = False
    # the killed process is gone: its supervisor identity (this very process) must read as dead
    monkeypatch.setattr(PortableExecutionService, "_supervisor_alive", staticmethod(lambda _recorded: False))
    restarted = PortableExecutionService(app, ROOT)
    outcome = _outcome(app, restarted, instance_root, run_id, before_digest)
    # restarting again changes nothing (recovery is idempotent)
    again = PortableExecutionService(app, ROOT)
    assert again.store.get(run_id) == restarted.store.get(run_id)
    return points.events, crashed, outcome


def test_crash_at_every_durable_write_of_apply_leaves_one_consistent_outcome(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    events, crashed, outcome = _one(tmp_path, monkeypatch, "dry", None)
    assert not crashed and outcome == "after"
    assert "bundle-seal" in events and "canonical-commit" in events and events.count("run-store-save") >= 8
    outcomes: dict[str, int] = {}
    for crash_at in range(1, len(events) + 1):
        _ev, crashed, outcome = _one(tmp_path, monkeypatch, f"c{crash_at}", crash_at)
        assert crashed
        outcomes[outcome] = outcomes.get(outcome, 0) + 1
    assert set(outcomes) <= {"after", "before:apply_failed", "before:interrupted", "before:state_change_approved"}, outcomes
    assert any(name.startswith("before") for name in outcomes)


def test_failure_after_the_bundle_seal_does_not_leave_a_sealed_applied_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _app, instance_root, run_id = _approved_proposal(tmp_path, monkeypatch, "post-seal")
    before_digest = digest_snapshot(snapshot_files(instance_root))

    def refuse(self, record):  # the failure lands after the bundle is sealed, before the run closes
        raise portable_runtime.PortableExecutionError("closure receipt unavailable")

    monkeypatch.setattr(PortableExecutionService, "_build_run_closure_receipt", refuse)
    with pytest.raises(portable_runtime.PortableExecutionError):
        service.apply_proposal(run_id)
    run = service.store.get(run_id)
    assert run["status"] == "apply_failed"
    assert digest_snapshot(snapshot_files(instance_root)) == before_digest
    assert not list(service.bundle_root.glob(f"{run_id}-applied"))
    assert run.get("appliedRunBundle") is None and run.get("closureReceipt") is None
    assert len(list(service.bundle_root.glob(f"{run_id}-applied.rolled-back"))) == 1


def test_startup_retires_orphaned_applied_bundles_but_keeps_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, app, _instance_root, run_id = _approved_proposal(tmp_path, monkeypatch, "orphans")
    applied = service.apply_proposal(run_id)["run"]
    other = service.prepare(applied["instanceId"], "checklistdd.complete-item/v1", "synthetic", {"itemId": "second-item"})["run"]["runId"]
    sealed = service.bundle_root / f"{other}-applied"
    (sealed / "SHA256SUMS").parent.mkdir(parents=True)
    (sealed / "SHA256SUMS").write_text("", encoding="utf-8")
    partial = service.bundle_root / f"{other}-applied.tmp"
    partial.mkdir()
    PortableExecutionService(app, ROOT)
    assert (service.bundle_root / f"{run_id}-applied").is_dir()  # a genuinely applied run is untouched
    assert not sealed.exists() and not partial.exists()
    assert (service.bundle_root / f"{other}-applied.rolled-back" / "SHA256SUMS").is_file()
    assert (service.bundle_root / f"{other}-applied.incomplete").is_dir()
