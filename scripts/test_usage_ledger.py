#!/usr/bin/env python3
"""Acceptance tests for the durable quota usage ledger."""

from __future__ import annotations

import sqlite3
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages/quota-engine/src"))

from quota_engine import (
    QuotaPolicy,
    ReservationConflictError,
    ReservationStateError,
    SCHEMA_VERSION,
    UsageLedger,
    UsageLedgerError,
)


class MutableClock:
    def __init__(self, value: datetime):
        self.value = value

    def __call__(self) -> datetime:
        return self.value


def test_schema_is_versioned_and_database_path_rejects_symlinks() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        real = root / "real"
        real.mkdir()
        linked = root / "linked"
        linked.symlink_to(real, target_is_directory=True)
        try:
            UsageLedger(linked / "usage.sqlite3")
        except UsageLedgerError as exc:
            assert "symlink" in str(exc)
        else:
            raise AssertionError("usage database paths must reject symlink traversal")

        path = real / "usage.sqlite3"
        UsageLedger(path)
        with sqlite3.connect(path) as connection:
            assert connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION


def test_reservations_count_immediately_and_ids_are_immutable() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        clock = MutableClock(datetime(2026, 7, 11, 8, 0, tzinfo=timezone.utc))
        ledger = UsageLedger(Path(tmpdir) / "usage.sqlite3", clock=clock)
        policy = QuotaPolicy(runs_per_day=2, messages_per_day=1, monthly_euro_estimate=1.0)

        first = ledger.reserve("run-1", "subject-a", "run", policy, estimated_cost=0.4)
        assert first.allowed and not first.idempotent
        assert first.reservation.status == "active"
        assert ledger.snapshot("subject-a").runs_today == 1
        assert ledger.snapshot("subject-a").monthly_euro_estimate == 0.4
        assert ledger.snapshot("subject-b").runs_today == 0

        repeated = ledger.reserve("run-1", "subject-a", "run", policy, estimated_cost=0.4)
        assert repeated.allowed and repeated.idempotent
        assert ledger.snapshot("subject-a").runs_today == 1

        for changed in (
            ("subject-b", "run", 0.4, policy),
            ("subject-a", "message", 0.4, policy),
            ("subject-a", "run", 0.5, policy),
            ("subject-a", "run", 0.4, QuotaPolicy(runs_per_day=3)),
        ):
            try:
                ledger.reserve("run-1", changed[0], changed[1], changed[3], estimated_cost=changed[2])
            except ReservationConflictError:
                pass
            else:
                raise AssertionError("reservation ids must have immutable bindings")

        message = ledger.reserve("message-1", "subject-a", "message", policy, estimated_cost=0.1)
        assert message.allowed
        denied = ledger.reserve("message-2", "subject-a", "message", policy, estimated_cost=0.1)
        assert not denied.allowed and denied.reservation.status == "denied"
        assert ledger.reserve("message-2", "subject-a", "message", policy, estimated_cost=0.1).idempotent
        snapshot = ledger.snapshot("subject-a")
        assert snapshot.messages_today == 1
        assert snapshot.monthly_euro_estimate == 0.5

        mutation = ledger.reserve(
            "mutation-1",
            "subject-a",
            "mutation",
            policy,
            estimated_cost=0.1,
        )
        assert mutation.allowed
        snapshot = ledger.snapshot("subject-a")
        assert snapshot.runs_today == 1 and snapshot.messages_today == 1
        assert abs(snapshot.monthly_euro_estimate - 0.6) < 1e-12

        released = ledger.release("run-1")
        assert released.reservation.status == "released" and not released.idempotent
        assert ledger.release("run-1").idempotent
        snapshot = ledger.snapshot("subject-a")
        assert snapshot.runs_today == 0
        assert abs(snapshot.monthly_euro_estimate - 0.2) < 1e-12
        try:
            ledger.commit("run-1", actual_cost=0.2)
        except ReservationStateError:
            pass
        else:
            raise AssertionError("released reservations must remain terminal")


def test_commit_is_once_idempotent_and_persists_across_restart() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "usage.sqlite3"
        clock = MutableClock(datetime(2026, 7, 11, 9, 0, tzinfo=timezone.utc))
        policy = QuotaPolicy(runs_per_day=2, monthly_euro_estimate=1.0)
        ledger = UsageLedger(path, clock=clock)
        ledger.reserve("run-1", "subject-a", "run", policy, estimated_cost=0.6)

        committed = ledger.commit("run-1", actual_cost=0.25)
        assert committed.reservation.status == "committed"
        assert committed.reservation.actual_cost == 0.25
        assert not committed.idempotent
        assert ledger.commit("run-1", actual_cost=0.25).idempotent
        try:
            ledger.commit("run-1", actual_cost=0.3)
        except ReservationConflictError:
            pass
        else:
            raise AssertionError("a committed actual cost must be immutable")
        try:
            ledger.commit("unknown", actual_cost=-1)
        except UsageLedgerError:
            pass
        else:
            raise AssertionError("actual cost must be non-negative")

        reloaded = UsageLedger(path, clock=clock)
        record = reloaded.get("run-1")
        assert record is not None and record.status == "committed"
        assert record.actual_cost == 0.25
        assert reloaded.snapshot("subject-a").monthly_euro_estimate == 0.25
        second = reloaded.reserve("run-2", "subject-a", "run", policy, estimated_cost=0.75)
        assert second.allowed
        third = reloaded.reserve("run-3", "subject-a", "run", policy, estimated_cost=0.0)
        assert not third.allowed
        try:
            reloaded.release("run-1")
        except ReservationStateError:
            pass
        else:
            raise AssertionError("committed reservations cannot be released")


def test_usage_buckets_are_subject_scoped_and_derived_in_utc() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        local_zone = timezone(timedelta(hours=-5))
        clock = MutableClock(datetime(2026, 1, 31, 20, 30, tzinfo=local_zone))
        ledger = UsageLedger(Path(tmpdir) / "usage.sqlite3", clock=clock)
        policy = QuotaPolicy(runs_per_day=2, monthly_euro_estimate=1.0)
        reservation = ledger.reserve("run-1", "subject-a", "run", policy, estimated_cost=0.2)
        assert reservation.reservation.usage_day == "2026-02-01"
        assert reservation.reservation.usage_month == "2026-02"

        clock.value = datetime(2026, 2, 2, 1, 0, tzinfo=timezone.utc)
        next_day = ledger.snapshot("subject-a")
        assert next_day.runs_today == 0
        assert next_day.monthly_euro_estimate == 0.2

        clock.value = datetime(2026, 3, 1, 0, 0, tzinfo=timezone.utc)
        next_month = ledger.snapshot("subject-a")
        assert next_month.runs_today == 0
        assert next_month.monthly_euro_estimate == 0.0
        assert ledger.snapshot("subject-b") == type(next_month)()


def test_concurrent_reservations_cannot_oversubscribe() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "usage.sqlite3"
        fixed = datetime(2026, 7, 11, 10, 0, tzinfo=timezone.utc)
        ledgers = (UsageLedger(path, clock=lambda: fixed), UsageLedger(path, clock=lambda: fixed))
        policy = QuotaPolicy(runs_per_day=1)
        barrier = threading.Barrier(2)

        def reserve(index: int):
            barrier.wait(timeout=5)
            return ledgers[index].reserve(
                f"run-{index}", "subject-a", "run", policy
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = tuple(pool.map(reserve, (0, 1)))

        assert sorted(outcome.allowed for outcome in outcomes) == [False, True]
        assert sorted(outcome.reservation.status for outcome in outcomes) == ["active", "denied"]
        assert ledgers[0].snapshot("subject-a").runs_today == 1
        assert UsageLedger(path, clock=lambda: fixed).snapshot("subject-a").runs_today == 1


if __name__ == "__main__":
    for name, test in sorted(globals().items()):
        if name.startswith("test_") and callable(test):
            test()
    print("PASS")
