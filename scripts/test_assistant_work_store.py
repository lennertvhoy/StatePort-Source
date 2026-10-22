#!/usr/bin/env python3
"""Focused tests for the durable assistant message-work authority."""

from __future__ import annotations

import sqlite3
import sys
import tempfile
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "persistent-app" / "src"))

from stateport_persistent_app.assistant_work import (  # noqa: E402
    AssistantWorkConflict,
    AssistantWorkLeaseError,
    AssistantWorkStore,
)


class Clock:
    def __init__(self, value: float = 1_750_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def enqueue(store: AssistantWorkStore, suffix: str = "one") -> dict[str, object]:
    return store.enqueue(
        instance_id="instance.study",
        application_id="studystate",
        conversation_id="conv.test",
        message_id=f"msg.{suffix}",
        participant_id="local-operator:instance.study",
        source_sequence=1,
    )


def provider_result(text: str = "Durable answer") -> dict[str, object]:
    return {
        "assistantText": text,
        "runtime": {
            "id": "runtime.codex.local",
            "digest": "sha256:" + "a" * 64,
        },
        "adapter": {"id": "codex-cli", "version": "1.2.3"},
        "provider": {"id": "codex-local"},
        "model": {"id": "gpt-5.6-codex"},
        "usage": {"availability": "unavailable"},
        "durationMs": 123,
        "cleanup": "not_required",
    }


def test_atomic_enqueue_and_claim_are_single_owner() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "assistant.sqlite3"
        store = AssistantWorkStore(path)
        enqueue(store)
        barrier = threading.Barrier(3)
        outcomes: list[object] = []

        def claim(worker: str) -> None:
            barrier.wait(timeout=3)
            outcomes.append(AssistantWorkStore(path).claim_next(worker_id=worker))

        threads = [
            threading.Thread(target=claim, args=("worker.one",)),
            threading.Thread(target=claim, args=("worker.two",)),
        ]
        for thread in threads:
            thread.start()
        barrier.wait(timeout=3)
        for thread in threads:
            thread.join(timeout=5)

        claims = [item for item in outcomes if item is not None]
        assert len(claims) == 1
        assert claims[0].phase == "invoke"
        assert AssistantWorkStore(path).get_by_message("msg.one")["state"] == "invoking"


def test_enqueue_is_idempotent_but_identity_reuse_conflicts() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        store = AssistantWorkStore(Path(tmp) / "assistant.sqlite3")
        first = enqueue(store)
        assert enqueue(store) == first
        with pytest.raises(AssistantWorkConflict):
            store.enqueue(
                instance_id="instance.other",
                application_id="studystate",
                conversation_id="conv.test",
                message_id="msg.one",
                participant_id="local-operator:instance.study",
                source_sequence=1,
            )


def test_provider_result_is_durable_before_reply_acknowledgement() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "assistant.sqlite3"
        store = AssistantWorkStore(path)
        enqueue(store)
        invocation = store.claim_next(worker_id="worker.invoke")
        assert invocation is not None and invocation.phase == "invoke"
        stored = store.store_provider_result(
            work_id=invocation.work_id,
            attempt_id=invocation.attempt_id,
            lease_token=invocation.lease_token,
            result=provider_result(),
        )
        assert stored["eventType"] == "provider.result_stored"

        restarted = AssistantWorkStore(path)
        delivery = restarted.claim_next(worker_id="worker.deliver")
        assert delivery is not None and delivery.phase == "deliver"
        assert delivery.provider_result["assistantText"] == "Durable answer"
        restarted.record_reply(
            work_id=delivery.work_id,
            attempt_id=delivery.attempt_id,
            lease_token=delivery.lease_token,
            reply_message_id="msg.assistant",
        )
        record = restarted.get(delivery.work_id)
        assert record["state"] == "completed"
        assert record["replyMessageId"] == "msg.assistant"
        assert record["providerResultDigest"].startswith("sha256:")


def test_expired_invocation_fails_closed_without_requeue_or_reinvocation() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        clock = Clock()
        path = Path(tmp) / "assistant.sqlite3"
        store = AssistantWorkStore(path, clock=clock)
        enqueue(store)
        claim = store.claim_next(worker_id="worker.one", lease_seconds=5)
        assert claim is not None
        clock.advance(6)
        result = AssistantWorkStore(path, clock=clock).reconcile_expired_leases()
        assert result == {"invocationsInterrupted": 1, "deliveriesRequeued": 0}
        record = AssistantWorkStore(path, clock=clock).get(claim.work_id)
        assert record["state"] == "failed"
        assert record["error"]["code"] == "provider_outcome_unknown_after_lease_expiry"
        assert AssistantWorkStore(path, clock=clock).claim_next(worker_id="worker.two") is None


def test_expired_delivery_requeues_existing_result_without_provider_reinvoke() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        clock = Clock()
        path = Path(tmp) / "assistant.sqlite3"
        store = AssistantWorkStore(path, clock=clock)
        enqueue(store)
        invoke = store.claim_next(worker_id="worker.invoke", lease_seconds=5)
        assert invoke is not None
        store.store_provider_result(
            work_id=invoke.work_id,
            attempt_id=invoke.attempt_id,
            lease_token=invoke.lease_token,
            result=provider_result(),
        )
        delivery = store.claim_next(worker_id="worker.deliver", lease_seconds=5)
        assert delivery is not None and delivery.phase == "deliver"
        clock.advance(6)
        result = store.reconcile_expired_leases()
        assert result == {"invocationsInterrupted": 0, "deliveriesRequeued": 1}
        retried = store.claim_next(worker_id="worker.retry")
        assert retried is not None and retried.phase == "deliver"
        assert retried.attempt_id == delivery.attempt_id
        assert retried.provider_result["assistantText"] == "Durable answer"


def test_wrong_lease_cannot_store_result_and_event_journal_is_contiguous() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "assistant.sqlite3"
        store = AssistantWorkStore(path)
        work = enqueue(store)
        claim = store.claim_next(worker_id="worker.one")
        assert claim is not None
        with pytest.raises(AssistantWorkLeaseError):
            store.store_provider_result(
                work_id=claim.work_id,
                attempt_id=claim.attempt_id,
                lease_token="x" * 40,
                result=provider_result(),
            )
        store.store_provider_result(
            work_id=claim.work_id,
            attempt_id=claim.attempt_id,
            lease_token=claim.lease_token,
            result=provider_result(),
        )
        events = store.event_journal(str(work["workId"]))
        assert [event["sequence"] for event in events] == list(range(1, len(events) + 1))
        assert [event["eventType"] for event in events] == [
            "work.queued",
            "attempt.started",
            "provider.result_stored",
        ]

        connection = sqlite3.connect(path)
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE assistant_events SET payload_json = '{}' "
                "WHERE work_id = ? AND sequence = 1",
                (work["workId"],),
            )
        connection.close()


def test_credential_like_metadata_key_is_rejected_before_persistence() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "assistant.sqlite3"
        store = AssistantWorkStore(path)
        enqueue(store)
        claim = store.claim_next(worker_id="worker.one")
        assert claim is not None
        unsafe = provider_result()
        unsafe["runtime"] = {"id": "runtime.codex.local", "apiKey": "SENTINEL"}
        with pytest.raises(Exception, match="credential-like"):
            store.store_provider_result(
                work_id=claim.work_id,
                attempt_id=claim.attempt_id,
                lease_token=claim.lease_token,
                result=unsafe,
            )
        assert "SENTINEL" not in path.read_bytes().decode("utf-8", errors="ignore")
