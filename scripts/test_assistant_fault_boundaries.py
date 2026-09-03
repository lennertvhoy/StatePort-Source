#!/usr/bin/env python3
"""Fault-injection tests for the durable assistant outcome boundaries."""

from __future__ import annotations

from dataclasses import dataclass
import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "conversation-service" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "execution-host" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "external-engine-runtime" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "codex-adapter" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "persistent-app" / "src"))

from external_engine_runtime import ProcessIdentity  # noqa: E402
from stateport_persistent_app.assistant_processor import AssistantProcessor  # noqa: E402
from stateport_persistent_app.assistant_reconciliation import (  # noqa: E402
    AssistantReconciliationState,
)
from stateport_persistent_app.assistant_resilient_runtime import (  # noqa: E402
    ResilientAssistantWorkStore,
)
from stateport_persistent_app.assistant_work import AssistantWorkError  # noqa: E402
from stateport_persistent_app.provider_router import (  # noqa: E402
    ProviderInvocation,
    ProviderRouterError,
)


@dataclass
class Message:
    message_id: str = "msg.user"
    conversation_id: str = "conv.study"
    application_id: str = "studystate"
    instance_id: str = "instance.study"
    sequence: int = 1
    kind: str = "user_message"
    body: str = "What should I study next?"


@dataclass
class Reply:
    message_id: str


class FakeConversations:
    def __init__(self, *, fail_deliveries: int = 0) -> None:
        self.fail_deliveries = fail_deliveries
        self.delivery_attempts = 0
        self.sent: list[dict[str, object]] = []
        self.messages: list[dict[str, object]] = [
            {
                "messageId": "msg.user",
                "conversationId": "conv.study",
                "applicationId": "studystate",
                "instanceId": "instance.study",
                "sequence": 1,
                "kind": "user_message",
                "body": "What should I study next?",
                "replyToMessageId": None,
            }
        ]

    def presentation(self, *, participant_id: str, conversation_id: str):
        assert participant_id == "local-operator:instance.study"
        assert conversation_id == "conv.study"
        return {
            "applicationBinding": {
                "applicationId": "studystate",
                "instanceId": "instance.study",
            },
            "messages": [dict(item) for item in self.messages],
        }

    def send_internal(
        self,
        *,
        participant_id: str,
        conversation_id: str,
        body: str,
        kind: str,
        source_message_id: str,
    ) -> Reply:
        assert participant_id == "local-operator:instance.study"
        assert kind == "assistant_message"
        self.delivery_attempts += 1
        if self.delivery_attempts <= self.fail_deliveries:
            raise OSError("injected conversation write failure")
        value = {
            "messageId": "msg.assistant",
            "conversationId": conversation_id,
            "applicationId": "studystate",
            "instanceId": "instance.study",
            "sequence": len(self.messages) + 1,
            "kind": "assistant_message",
            "body": body,
            "replyToMessageId": source_message_id,
        }
        self.messages.append(value)
        self.sent.append(value)
        return Reply("msg.assistant")


class SuccessfulRouter:
    def __init__(self) -> None:
        self.invocations = 0
        self.runtime_profile = {
            "formatVersion": "stateport.provider-router/v1",
            "profileDigest": "sha256:" + "a" * 64,
            "provider": {"id": "codex-local"},
            "model": {"id": "fixture"},
            "budgets": {"timeSeconds": 20},
        }

    def invoke(self, **kwargs) -> ProviderInvocation:
        self.invocations += 1
        identity = ProcessIdentity(
            321,
            321,
            "7",
            "generation." + "b" * 64,
        )
        if kwargs.get("on_started"):
            kwargs["on_started"](identity)
        if kwargs.get("on_finished"):
            kwargs["on_finished"](identity)
        return ProviderInvocation(
            assistant_text="Review the weakest objective first.",
            runtime_profile=self.runtime_profile,
            adapter={"id": "codex-cli", "version": "fixture"},
            provider={"id": "codex-local"},
            model={"id": "fixture"},
            usage={"availability": "unavailable"},
            duration_ms=12,
            cleanup="not_required",
            normalized_events=(),
        )


class FailingRouter(SuccessfulRouter):
    def invoke(self, **kwargs) -> ProviderInvocation:
        self.invocations += 1
        raise ProviderRouterError("injected_provider_failure")


class CommitThenRaiseStore(ResilientAssistantWorkStore):
    """Simulate a lost DB acknowledgement after the result commit succeeded."""

    def store_provider_result(self, **kwargs):
        super().store_provider_result(**kwargs)
        raise OSError("injected lost result-persistence acknowledgement")


def processor(
    root: Path,
    conversations: FakeConversations,
    router: SuccessfulRouter,
    *,
    store: ResilientAssistantWorkStore | None = None,
) -> AssistantProcessor:
    return AssistantProcessor(
        conversations,  # type: ignore[arg-type]
        work_store=store or ResilientAssistantWorkStore(root / "assistant.sqlite3"),
        router=router,  # type: ignore[arg-type]
        staging_root=root / "staging",
        conversation_store_path=None,
        reconciliation_state=AssistantReconciliationState(
            root / "reconciliation.json"
        ),
        worker_id="assistant.fault-test",
    )


def enqueue(current: AssistantProcessor) -> dict[str, object]:
    return current.enqueue(
        Message(),  # type: ignore[arg-type]
        participant_id="local-operator:instance.study",
    )


def test_provider_failure_is_terminal_without_fake_reply_or_retry_storm() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        conversations = FakeConversations()
        router = FailingRouter()
        current = processor(root, conversations, router)
        queued = enqueue(current)

        assert current.process_once()
        record = current.work_store.get(str(queued["workId"]))
        assert record["state"] == "failed"
        assert record["error"]["code"] == "provider_invocation_failed"
        assert conversations.sent == []
        assert router.invocations == 1
        assert current.process_once() is False
        assert router.invocations == 1


def test_lost_result_commit_acknowledgement_delivers_without_reinvocation() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        conversations = FakeConversations()
        router = SuccessfulRouter()
        committing_store = CommitThenRaiseStore(root / "assistant.sqlite3")
        current = processor(
            root,
            conversations,
            router,
            store=committing_store,
        )
        queued = enqueue(current)

        assert current.process_once()
        durable = ResilientAssistantWorkStore(root / "assistant.sqlite3").get(
            str(queued["workId"])
        )
        assert durable["state"] == "result_ready"
        assert durable["providerResultDigest"].startswith("sha256:")
        assert conversations.sent == []
        assert router.invocations == 1

        restarted = processor(root, conversations, router)
        assert restarted.process_once()
        completed = restarted.work_store.get(str(queued["workId"]))
        assert completed["state"] == "completed"
        assert completed["replyMessageId"] == "msg.assistant"
        assert router.invocations == 1


def test_reply_write_failure_requeues_durable_result_and_redelivers() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        conversations = FakeConversations(fail_deliveries=1)
        router = SuccessfulRouter()
        current = processor(root, conversations, router)
        queued = enqueue(current)

        assert current.process_once()  # invoke → durable result_ready
        assert current.process_once()  # first delivery fails → result_ready
        retryable = current.work_store.get(str(queued["workId"]))
        assert retryable["state"] == "result_ready"
        assert retryable["providerResultDigest"].startswith("sha256:")
        assert router.invocations == 1
        assert conversations.sent == []

        restarted = processor(root, conversations, router)
        assert restarted.process_once()
        completed = restarted.work_store.get(str(queued["workId"]))
        assert completed["state"] == "completed"
        assert completed["replyMessageId"] == "msg.assistant"
        assert conversations.delivery_attempts == 2
        assert router.invocations == 1


def test_durable_artifacts_exclude_credentials_and_environment_snapshots(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        monkeypatch.setenv("OPENAI_API_KEY", "SENTINEL_PRIVATE_VALUE")
        monkeypatch.setenv("STATEPORT_PRIVATE_CANARY", "SENTINEL_PRIVATE_VALUE")
        conversations = FakeConversations()
        router = SuccessfulRouter()
        current = processor(root, conversations, router)
        queued = enqueue(current)

        assert current.process_once()
        record = current.work_store.get(str(queued["workId"]))
        journal = current.work_store.event_journal(str(queued["workId"]))
        persisted = (root / "assistant.sqlite3").read_bytes()
        for forbidden in (
            b"OPENAI_API_KEY",
            b"STATEPORT_PRIVATE_CANARY",
            b"SENTINEL_PRIVATE_VALUE",
            b"Authorization",
            b"Bearer ",
        ):
            assert forbidden not in persisted
            assert forbidden.decode("utf-8") not in repr(record)
            assert forbidden.decode("utf-8") not in repr(journal)

        claim = current.work_store.claim_next(worker_id="assistant.secret-test")
        assert claim is not None and claim.phase == "deliver"
        with pytest.raises(AssistantWorkError, match="credential-like"):
            current.work_store.record_process_identity(
                work_id=claim.work_id,
                attempt_id=claim.attempt_id,
                lease_token=claim.lease_token,
                process_identity={"pid": 1, "environment": {"OPENAI_API_KEY": "x"}},
                runtime_profile=router.runtime_profile,
            )
