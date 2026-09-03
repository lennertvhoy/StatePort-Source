#!/usr/bin/env python3
"""Focused acceptance tests for durable jobs and real instance leases."""

from __future__ import annotations

import json
import sys
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages/governed-runner/src"))

from governed_runner import (
    InstanceLease,
    InstanceLeaseBusy,
    InstanceLeaseError,
    JobConflictError,
    JobLeaseError,
    JobQueue,
    JobQueueError,
    JobStateError,
)


class MutableClock:
    def __init__(self) -> None:
        self.value = datetime(2026, 7, 11, 8, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.value

    def advance(self, **values: float) -> None:
        self.value += timedelta(**values)


def _payload(operation: str = "echo") -> dict[str, object]:
    return {
        "formatVersion": "stateport.job-payload/v1",
        "operation": operation,
        "instanceId": "demo",
    }


def _assert_raises(expected: type[BaseException], function, *args, **kwargs) -> BaseException:
    try:
        function(*args, **kwargs)
    except expected as exc:
        return exc
    raise AssertionError(f"expected {expected.__name__}")


def test_enqueue_is_versioned_idempotent_immutable_and_restart_persistent() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        clock = MutableClock()
        path = Path(tmpdir) / ".stateport" / "jobs.sqlite"
        queue = JobQueue(path, clock=clock)
        created = queue.enqueue(idempotency_key="request-1", payload=_payload())
        repeated = queue.enqueue(idempotency_key="request-1", payload=_payload())
        assert created == repeated
        assert created["formatVersion"] == "stateport.job/v1"
        assert created["payloadVersion"] == "stateport.job-payload/v1"
        assert created["payloadDigest"].startswith("sha256:")
        assert created["status"] == "queued" and created["attemptCount"] == 0
        _assert_raises(
            JobConflictError,
            queue.enqueue,
            idempotency_key="request-1",
            payload=_payload("different"),
        )
        created["payload"]["operation"] = "caller mutation"
        assert queue.get(created["jobId"])["payload"]["operation"] == "echo"

        restarted = JobQueue(path, clock=clock)
        assert restarted.get(created["jobId"])["payloadDigest"] == repeated["payloadDigest"]
        assert [item["jobId"] for item in restarted.list()] == [created["jobId"]]


def test_queue_rejects_unversioned_payload_and_symlinked_storage() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        queue = JobQueue(root / "jobs.sqlite")
        _assert_raises(
            JobQueueError,
            queue.enqueue,
            idempotency_key="missing-version",
            payload={"operation": "echo"},
        )

        real_db = root / "real.sqlite"
        JobQueue(real_db)
        symlink_db = root / "linked.sqlite"
        symlink_db.symlink_to(real_db)
        _assert_raises(JobQueueError, JobQueue, symlink_db)

        real_parent = root / "real-parent"
        real_parent.mkdir()
        linked_parent = root / "linked-parent"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        _assert_raises(JobQueueError, JobQueue, linked_parent / "jobs.sqlite")


def test_fifo_claim_heartbeat_expiry_recovery_and_terminal_immutability() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        clock = MutableClock()
        queue = JobQueue(Path(tmpdir) / "jobs.sqlite", clock=clock)
        first = queue.enqueue(idempotency_key="first", payload=_payload("first"))
        second = queue.enqueue(idempotency_key="second", payload=_payload("second"))

        claimed = queue.claim(worker_id="worker-a", lease_seconds=10)
        assert claimed["jobId"] == first["jobId"]
        assert claimed["attemptCount"] == 1
        assert claimed["lease"]["owner"] == "worker-a"
        token = claimed["lease"]["token"]
        assert isinstance(token, str) and len(token) >= 32
        _assert_raises(
            JobLeaseError,
            queue.complete,
            first["jobId"],
            "wrong-token",
            result={"ok": True},
        )

        clock.advance(seconds=5)
        heartbeat = queue.heartbeat(first["jobId"], token, lease_seconds=10)
        assert heartbeat["lease"]["expiresAt"] > claimed["lease"]["expiresAt"]
        clock.advance(seconds=11)
        _assert_raises(
            JobLeaseError,
            queue.complete,
            first["jobId"],
            token,
            result={"ok": True},
        )

        recovered = queue.claim(worker_id="worker-b", lease_seconds=10)
        assert recovered["jobId"] == first["jobId"]
        assert recovered["attemptCount"] == 2
        assert recovered["lease"]["token"] != token
        completed = queue.complete(
            first["jobId"], recovered["lease"]["token"], result={"ok": True}
        )
        assert completed["status"] == "succeeded" and completed["lease"] is None
        _assert_raises(JobStateError, queue.cancel, first["jobId"])
        _assert_raises(
            JobStateError,
            queue.fail,
            first["jobId"],
            recovered["lease"]["token"],
            error="late failure",
        )

        next_claim = queue.claim(worker_id="worker-c", lease_seconds=10)
        assert next_claim["jobId"] == second["jobId"]
        failed = queue.fail(
            second["jobId"], next_claim["lease"]["token"], error={"code": "test"}
        )
        assert failed["status"] == "failed" and failed["error"] == {"code": "test"}

        third = queue.enqueue(idempotency_key="third", payload=_payload("third"))
        cancelled = queue.cancel(third["jobId"], reason="operator decision")
        assert cancelled["status"] == "cancelled"
        assert queue.claim(worker_id="worker-d") is None
        assert len(queue.list(status="succeeded")) == 1
        assert len(queue.list(status="failed")) == 1
        assert len(queue.list(status="cancelled")) == 1


def test_atomic_concurrent_claim_has_one_winner() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "jobs.sqlite"
        JobQueue(path).enqueue(idempotency_key="one", payload=_payload())
        barrier = threading.Barrier(3)
        results: list[dict[str, object] | None] = []
        errors: list[BaseException] = []

        def claim(worker: str) -> None:
            try:
                queue = JobQueue(path)
                barrier.wait(timeout=3)
                results.append(queue.claim(worker_id=worker, lease_seconds=60))
            except BaseException as exc:  # Preserve thread failures for the assertion.
                errors.append(exc)

        threads = [
            threading.Thread(target=claim, args=("worker-a",)),
            threading.Thread(target=claim, args=("worker-b",)),
        ]
        for thread in threads:
            thread.start()
        barrier.wait(timeout=3)
        for thread in threads:
            thread.join(timeout=5)
        assert not errors
        assert len(results) == 2
        assert sum(result is not None for result in results) == 1
        assert sum(result is None for result in results) == 1


def test_owned_lease_can_be_requeued_but_not_by_stale_or_wrong_owner() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        clock = MutableClock()
        queue = JobQueue(Path(tmpdir) / "jobs.sqlite", clock=clock)
        job = queue.enqueue(idempotency_key="defer", payload=_payload())
        claimed = queue.claim(worker_id="worker-a", lease_seconds=10)
        token = claimed["lease"]["token"]
        _assert_raises(
            JobLeaseError,
            queue.requeue,
            job["jobId"],
            "wrong-token",
        )
        deferred = queue.requeue(
            job["jobId"], token, reason="instance writer is busy"
        )
        assert deferred["status"] == "queued" and deferred["lease"] is None
        reclaimed = queue.claim(worker_id="worker-b", lease_seconds=10)
        clock.advance(seconds=11)
        _assert_raises(
            JobLeaseError,
            queue.requeue,
            job["jobId"],
            reclaimed["lease"]["token"],
        )


def test_instance_lease_uses_real_flock_and_ignores_stale_metadata() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        instance = root / "instance"
        instance.mkdir()
        lease_directory = root / ".stateport" / "leases"
        first = InstanceLease(lease_directory, instance, owner="worker-a")
        second = InstanceLease(lease_directory, instance, owner="worker-b")
        assert first.key == second.key

        with first:
            assert first.acquired
            metadata = json.loads(first.lock_path.read_text(encoding="utf-8"))
            assert metadata["authority"] == "fcntl.flock"
            _assert_raises(InstanceLeaseBusy, second.acquire)
        assert not first.acquired

        first.lock_path.write_text('{"owner":"not-authority"}\n', encoding="utf-8")
        with second:
            assert second.acquired
        assert not second.acquired


def test_instance_lease_rejects_symlinked_operational_directory_and_lock() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        instance = root / "instance"
        instance.mkdir()
        real_leases = root / "real-leases"
        real_leases.mkdir()
        linked_leases = root / "linked-leases"
        linked_leases.symlink_to(real_leases, target_is_directory=True)
        _assert_raises(InstanceLeaseError, InstanceLease, linked_leases, instance)

        lease = InstanceLease(real_leases, instance)
        target = root / "outside.lock"
        target.write_text("outside", encoding="utf-8")
        lease.lock_path.symlink_to(target)
        _assert_raises(InstanceLeaseError, lease.acquire)
        assert target.read_text(encoding="utf-8") == "outside"


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
    print("PASS")
