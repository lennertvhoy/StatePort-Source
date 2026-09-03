#!/usr/bin/env python3
"""Focused acceptance tests for shared web/Telegram conversation contracts."""

from __future__ import annotations

from pathlib import Path
import json
import socket
import sqlite3
import sys
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "packages" / "conversation-service" / "src"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

from stateport_conversation import (  # noqa: E402
    ChannelBinding,
    CompressionPolicy,
    ConversationAuthorizationError,
    ConversationConflictError,
    ConversationContractError,
    ConversationNotFoundError,
    ConversationService,
    HandoffPolicy,
    ParticipantIdentity,
    TelegramFixtureAdapter,
    WebFixtureAdapter,
    canonical_digest,
)


NOW = "2026-07-14T20:00:00Z"
ALL_PERMISSIONS = (
    "conversation.create",
    "conversation.bind",
    "conversation.read",
    "conversation.send",
    "conversation.respond",
    "conversation.deliver",
    "conversation.propose",
    "conversation.delete",
)


def participant(
    participant_id: str,
    *,
    actor_id: str | None = None,
    application: str = "stateport.development-reference",
    instance: str = "project-one",
    permissions: tuple[str, ...] = ALL_PERMISSIONS,
    kind: str = "human",
) -> ParticipantIdentity:
    return ParticipantIdentity.from_dict(
        {
            "formatVersion": ParticipantIdentity.FORMAT,
            "participantId": participant_id,
            "actorId": actor_id or participant_id,
            "displayName": participant_id.replace("-", " ").title(),
            "kind": kind,
            "applicationIds": [application],
            "instanceIds": [instance],
            "permissions": list(permissions),
        }
    )


def fixture_service(
    policy: str = "mirror_to_all",
    *,
    store_path: Path | None = None,
) -> tuple[ConversationService, object, ChannelBinding, ChannelBinding]:
    service = ConversationService(clock=lambda: NOW, store_path=store_path)
    service.register_participant(participant("owner"))
    thread = service.create_thread(
        participant_id="owner",
        application_id="stateport.development-reference",
        instance_id="project-one",
        title="Project conversation",
        delivery_policy=policy,
    )
    identity = canonical_digest({"actor": "owner"})
    web = service.bind_channel(
        participant_id="owner",
        conversation_id=thread.conversation_id,
        channel="web",
        external_identity_digest=identity,
        external_conversation_digest=canonical_digest({"browser": "local", "instance": "project-one"}),
    )
    telegram = service.bind_channel(
        participant_id="owner",
        conversation_id=thread.conversation_id,
        channel="telegram",
        external_identity_digest=identity,
        external_conversation_digest=canonical_digest({"chat": "synthetic-project-one"}),
    )
    return service, thread, web, telegram


def web_fixture(binding: ChannelBinding, message_id: str, text: str, *, reply: str | None = None, echo: str | None = None, attachments: list[dict[str, object]] | None = None) -> dict[str, object]:
    return {
        "formatVersion": WebFixtureAdapter.FORMAT,
        "bindingId": binding.binding_id,
        "clientMessageId": message_id,
        "sentAt": NOW,
        "text": text,
        "replyToExternalMessageId": reply,
        "attachments": attachments or [],
        "echoGuard": echo,
    }


def telegram_fixture(
    binding: ChannelBinding,
    message_id: str,
    text: str,
    *,
    update_id: str | None = None,
    reply: str | None = None,
    echo: str | None = None,
) -> dict[str, object]:
    return {
        "formatVersion": TelegramFixtureAdapter.FORMAT,
        "bindingId": binding.binding_id,
        "updateId": update_id or f"update-{message_id}",
        "message": {
            "messageId": message_id,
            "chatIdentityDigest": binding.external_conversation_digest,
            "senderIdentityDigest": binding.external_identity_digest,
            "sentAt": NOW,
            "text": text,
            "replyToMessageId": reply,
            "attachments": [],
            "echoGuard": echo,
        },
    }


def ingest_web(service: ConversationService, binding: ChannelBinding, message_id: str = "web-1", text: str = "Hello", **kwargs: object):
    inbound = WebFixtureAdapter().normalize(binding, web_fixture(binding, message_id, text, **kwargs))
    return service.ingest(participant_id="owner", inbound=inbound)


def ingest_telegram(service: ConversationService, binding: ChannelBinding, message_id: str = "tg-1", text: str = "Hello", **kwargs: object):
    inbound = TelegramFixtureAdapter().normalize(binding, telegram_fixture(binding, message_id, text, **kwargs))
    return service.ingest(participant_id="owner", inbound=inbound)


def test_contracts_are_versioned_strict_and_secret_safe() -> None:
    service, thread, web, _telegram = fixture_service()
    assert thread.to_dict()["formatVersion"] == "stateport.conversation-thread/v1"
    assert web.to_dict()["formatVersion"] == "stateport.channel-binding/v1"
    assert ChannelBinding.from_dict(web.to_dict()) == web
    invalid = web.to_dict()
    invalid["botToken"] = "fixture-value-that-must-not-cross"
    with pytest.raises(ConversationContractError, match="credential-like"):
        ChannelBinding.from_dict(invalid)
    assert not hasattr(service, "persist")


def test_web_and_telegram_share_one_conversation_identity_and_monotonic_order() -> None:
    service, thread, web, telegram = fixture_service()
    telegram_message = ingest_telegram(service, telegram, "tg-older", "Telegram first").message
    web_message = ingest_web(service, web, "web-newer", "Web second").message
    assert telegram_message is not None and web_message is not None
    assert telegram_message.conversation_id == web_message.conversation_id == thread.conversation_id
    assert (telegram_message.sequence, web_message.sequence) == (1, 2)
    page, cursor = service.list_messages(participant_id="owner", conversation_id=thread.conversation_id, limit=1)
    assert [item.message_id for item in page] == [telegram_message.message_id]
    second, final = service.list_messages(participant_id="owner", conversation_id=thread.conversation_id, cursor=cursor)
    assert [item.message_id for item in second] == [web_message.message_id]
    assert final.after_sequence == 2 and final.thread_revision == 2


def test_provider_retries_and_external_message_duplicates_create_exactly_one_message() -> None:
    service, thread, web, telegram = fixture_service()
    first = ingest_web(service, web, "web-retry", "Exactly once")
    retry = ingest_web(service, web, "web-retry", "Exactly once")
    assert first.status == "accepted" and retry.status == "duplicate" and retry.duplicate is True
    assert retry.message == first.message
    with pytest.raises(ConversationConflictError, match="different content"):
        ingest_web(service, web, "web-retry", "Changed content")
    telegram_first = ingest_telegram(service, telegram, "tg-retry", "Telegram exactly once", update_id="update-a")
    telegram_retry = ingest_telegram(service, telegram, "tg-retry", "Telegram exactly once", update_id="update-b")
    assert telegram_retry.status == "duplicate" and telegram_retry.message == telegram_first.message
    messages, cursor = service.list_messages(participant_id="owner", conversation_id=thread.conversation_id)
    assert len(messages) == 2 and cursor.thread_revision == 2


def test_provider_event_identity_cannot_be_reused_for_different_messages() -> None:
    service, _thread, _web, telegram = fixture_service()
    ingest_telegram(service, telegram, "tg-one", "One", update_id="same-update")
    with pytest.raises(ConversationConflictError, match="reused"):
        ingest_telegram(service, telegram, "tg-two", "Two", update_id="same-update")


def test_reply_relationship_and_attachment_metadata_are_preserved_without_content_storage() -> None:
    service, _thread, web, _telegram = fixture_service()
    first = ingest_web(service, web, "web-parent", "Parent").message
    attachment = {
        "attachmentId": "attachment-1",
        "name": "evidence.txt",
        "mediaType": "text/plain",
        "sizeBytes": 12,
        "digest": canonical_digest(b"public fixture".hex()),
    }
    reply = ingest_web(service, web, "web-reply", "Reply", reply="web-parent", attachments=[attachment]).message
    assert first is not None and reply is not None
    assert reply.reply_to_message_id == first.message_id
    assert reply.attachments[0].to_dict() == attachment
    assert set(reply.attachments[0].to_dict()) == {"attachmentId", "name", "mediaType", "sizeBytes", "digest"}
    with pytest.raises(ConversationConflictError, match="reply target"):
        ingest_web(service, web, "web-bad-reply", "Bad reply", reply="unknown")


@pytest.mark.parametrize(
    ("policy", "expected"),
    [
        ("source_channel_only", {"web": "full"}),
        ("mirror_to_all", {"web": "full", "telegram": "full"}),
        ("web_primary", {"web": "full", "telegram": "notification"}),
        ("telegram_primary", {"web": "archive", "telegram": "full"}),
    ],
)
def test_delivery_policy_is_channel_neutral_and_explicit(policy: str, expected: dict[str, str]) -> None:
    service, thread, web, _telegram = fixture_service(policy)
    incoming = ingest_web(service, web).message
    assert incoming is not None
    response = service.send_internal(participant_id="owner", conversation_id=thread.conversation_id, body="Response", source_message_id=incoming.message_id)
    deliveries = service.plan_deliveries(participant_id="owner", message_id=response.message_id)
    assert {item.channel: item.delivery_mode for item in deliveries} == expected
    assert all(item.delivery_policy == policy and item.status == "planned" for item in deliveries)


def test_outbound_external_identity_and_echo_guard_prevent_web_telegram_loops() -> None:
    service, thread, web, telegram = fixture_service("mirror_to_all")
    incoming = ingest_telegram(service, telegram, "tg-in", "Please respond").message
    assert incoming is not None
    response = service.send_internal(participant_id="owner", conversation_id=thread.conversation_id, body="Bounded response", source_message_id=incoming.message_id)
    deliveries = service.plan_deliveries(participant_id="owner", message_id=response.message_id)
    telegram_delivery = next(item for item in deliveries if item.channel == "telegram")
    delivered = service.record_delivery(
        participant_id="owner",
        delivery_id=telegram_delivery.delivery_id,
        status="delivered",
        external_message_id="tg-outbound-1",
    )
    echoed = ingest_telegram(
        service,
        telegram,
        "tg-outbound-1",
        "Bounded response",
        update_id="echo-update",
        echo=delivered.echo_guard,
    )
    assert echoed.status == "echo_suppressed" and echoed.message is None
    messages, _cursor = service.list_messages(participant_id="owner", conversation_id=thread.conversation_id)
    assert [item.kind for item in messages] == ["user_message", "assistant_message"]
    assert next(item for item in deliveries if item.channel == "web").delivery_mode == "full"


def test_typed_state_proposal_is_separate_and_cannot_mutate_canonical_state() -> None:
    service, thread, web, _telegram = fixture_service()
    origin = ingest_web(service, web, "web-proposal", "Please update the goal").message
    assert origin is not None
    proposal, reference = service.propose_state_change(
        participant_id="owner",
        conversation_id=thread.conversation_id,
        originating_message_id=origin.message_id,
        base_identity=canonical_digest({"git": "fixture-base"}),
        payload_digest=canonical_digest({"goal": "public-safe-fixture"}),
        summary="A typed state proposal is ready for approval.",
    )
    assert proposal.authority == "proposal_noncanonical"
    assert proposal.mutation_boundary == "typed_transaction_required"
    assert reference.kind == "state_proposal_reference"
    assert reference.proposal_reference == proposal.proposal_id
    assert reference.canonical_state_effect == "none"
    assert not hasattr(service, "apply_state_proposal")
    presentation = service.presentation(participant_id="owner", conversation_id=thread.conversation_id)
    assert presentation["stateProposals"] == [proposal.to_dict()]
    assert presentation["authority"]["canonicalState"] == "typed_transactions_only"


def test_run_and_tool_events_are_collapsed_and_approvals_receipts_are_visible() -> None:
    service, thread, _web, _telegram = fixture_service()
    run = service.send_internal(participant_id="owner", conversation_id=thread.conversation_id, body="Validation started", kind="run_event")
    tool = service.send_internal(participant_id="owner", conversation_id=thread.conversation_id, body="Read fixture", kind="tool_event")
    assert run.collapsed_by_default is True and tool.collapsed_by_default is True
    view = service.presentation(
        participant_id="owner",
        conversation_id=thread.conversation_id,
        pending_approval_references=("approval-1",),
        run_receipt_references=("receipt-1",),
    )
    assert view["component"] == "conversation_thread"
    assert view["applicationBinding"] == {"applicationId": thread.application_id, "instanceId": thread.instance_id}
    assert all(item["display"]["collapsedByDefault"] for item in view["messages"])
    assert view["pendingApprovals"] == [{"reference": "approval-1"}]
    assert view["receipts"] == [{"reference": "receipt-1"}]


def test_cross_user_binding_read_and_send_fail_closed() -> None:
    service, thread, web, _telegram = fixture_service()
    service.register_participant(participant("outsider", instance="other-instance"))
    with pytest.raises(ConversationAuthorizationError):
        service.bind_channel(
            participant_id="outsider",
            conversation_id=thread.conversation_id,
            channel="web",
            external_identity_digest=canonical_digest({"actor": "outsider"}),
            external_conversation_digest=canonical_digest({"browser": "outsider"}),
        )
    with pytest.raises(ConversationAuthorizationError):
        service.presentation(participant_id="outsider", conversation_id=thread.conversation_id)
    inbound = WebFixtureAdapter().normalize(web, web_fixture(web, "web-owner", "Owner only"))
    with pytest.raises(ConversationAuthorizationError):
        service.ingest(participant_id="outsider", inbound=inbound)


def test_binding_cannot_be_enumerated_or_reassigned_to_another_thread() -> None:
    service, thread, _web, telegram = fixture_service()
    service.register_participant(participant("second", instance="project-two"))
    second = service.create_thread(
        participant_id="second",
        application_id="stateport.development-reference",
        instance_id="project-two",
        title="Second",
    )
    with pytest.raises(ConversationConflictError, match="already bound"):
        service.bind_channel(
            participant_id="second",
            conversation_id=second.conversation_id,
            channel="telegram",
            external_identity_digest=telegram.external_identity_digest,
            external_conversation_digest=telegram.external_conversation_digest,
        )
    with pytest.raises(ConversationAuthorizationError):
        service.binding(participant_id="second", binding_id=telegram.binding_id)
    assert thread.conversation_id != second.conversation_id


def test_fixture_adapters_are_deterministic_and_have_no_live_send_surface() -> None:
    _service, _thread, web, telegram = fixture_service()
    web_adapter = WebFixtureAdapter()
    telegram_adapter = TelegramFixtureAdapter()
    source = web_fixture(web, "client-stable", "Stable")
    assert web_adapter.normalize(web, source) == web_adapter.normalize(web, source)
    telegram_source = telegram_fixture(telegram, "message-stable", "Stable", update_id="update-stable")
    assert telegram_adapter.normalize(telegram, telegram_source) == telegram_adapter.normalize(telegram, telegram_source)
    assert not hasattr(web_adapter, "send") and not hasattr(telegram_adapter, "send")
    invalid = telegram_fixture(telegram, "wrong-chat", "No")
    invalid["message"]["chatIdentityDigest"] = canonical_digest({"chat": "other"})
    with pytest.raises(ConversationContractError, match="not bound"):
        telegram_adapter.normalize(telegram, invalid)


def test_compression_and_handoff_are_policy_contracts_not_execution_in_this_service() -> None:
    service, thread, _web, _telegram = fixture_service()
    assert CompressionPolicy.from_dict(thread.compression_policy.to_dict()) == thread.compression_policy
    assert HandoffPolicy.from_dict(thread.handoff_policy.to_dict()) == thread.handoff_policy
    assert not hasattr(service, "compress") and not hasattr(service, "handoff")
    view = service.presentation(participant_id="owner", conversation_id=thread.conversation_id)
    assert view["authority"]["compressionExecution"] == "owned_by_context_lifecycle_not_this_service"


def test_new_process_service_has_no_default_transcript_persistence() -> None:
    service, thread, web, _telegram = fixture_service()
    ingest_web(service, web)
    restarted = ConversationService(clock=lambda: NOW)
    with pytest.raises(ConversationNotFoundError):
        restarted.presentation(participant_id="owner", conversation_id=thread.conversation_id)


def test_sqlite_store_preserves_threads_messages_and_state_proposals_across_restart(tmp_path: Path) -> None:
    store = tmp_path / "conversation.sqlite3"
    service, thread, web, _telegram = fixture_service(store_path=store)
    origin = ingest_web(service, web, "web-durable", "Remember this operational message").message
    assert origin is not None
    proposal, reference = service.propose_state_change(
        participant_id="owner",
        conversation_id=thread.conversation_id,
        originating_message_id=origin.message_id,
        base_identity=canonical_digest({"git": "fixture-base"}),
        payload_digest=canonical_digest({"goal": "public-safe-fixture"}),
        summary="A durable typed state proposal is ready.",
    )
    restarted = ConversationService(clock=lambda: NOW, store_path=store)
    restored = restarted.presentation(participant_id="owner", conversation_id=thread.conversation_id)
    assert restored["thread"]["conversationId"] == thread.conversation_id
    assert [item["messageId"] for item in restored["messages"]] == [origin.message_id, reference.message_id]
    assert restored["stateProposals"] == [proposal.to_dict()]
    assert restored["authority"]["retention"] == "explicit_capture"


def test_sqlite_store_preserves_web_and_telegram_deduplication_across_restart(tmp_path: Path) -> None:
    store = tmp_path / "conversation.sqlite3"
    service, _thread, web, telegram = fixture_service(store_path=store)
    web_first = ingest_web(service, web, "web-durable", "Web exactly once")
    telegram_first = ingest_telegram(service, telegram, "tg-durable", "Telegram exactly once", update_id="durable-update")
    restarted = ConversationService(clock=lambda: NOW, store_path=store)
    web_retry = ingest_web(restarted, web, "web-durable", "Web exactly once")
    telegram_retry = ingest_telegram(restarted, telegram, "tg-durable", "Telegram exactly once", update_id="durable-update")
    assert web_first.status == telegram_first.status == "accepted"
    assert web_retry.status == "duplicate" and web_retry.message == web_first.message
    assert telegram_retry.status == "duplicate" and telegram_retry.message == telegram_first.message


def test_sqlite_store_preserves_delivery_receipts_and_echo_guards_across_restart(tmp_path: Path) -> None:
    store = tmp_path / "conversation.sqlite3"
    service, thread, _web, telegram = fixture_service(store_path=store)
    incoming = ingest_telegram(service, telegram, "tg-inbound", "Please respond").message
    assert incoming is not None
    response = service.send_internal(
        participant_id="owner",
        conversation_id=thread.conversation_id,
        body="Bounded durable response",
        source_message_id=incoming.message_id,
    )
    delivery = next(item for item in service.plan_deliveries(participant_id="owner", message_id=response.message_id) if item.channel == "telegram")
    delivered = service.record_delivery(
        participant_id="owner",
        delivery_id=delivery.delivery_id,
        status="delivered",
        external_message_id="tg-durable-outbound",
    )
    restarted = ConversationService(clock=lambda: NOW, store_path=store)
    echoed = ingest_telegram(
        restarted,
        telegram,
        "tg-durable-outbound",
        "Bounded durable response",
        update_id="durable-echo-update",
        echo=delivered.echo_guard,
    )
    restored = restarted.presentation(participant_id="owner", conversation_id=thread.conversation_id)
    assert echoed.status == "echo_suppressed"
    assert any(item["deliveryId"] == delivery.delivery_id and item["status"] == "delivered" for item in restored["messages"][-1]["display"]["deliveryState"])


def test_transcript_export_clear_receipt_and_restart_preserve_thread_identity(tmp_path: Path) -> None:
    store = tmp_path / "conversation.sqlite3"
    service, thread, web, _telegram = fixture_service(store_path=store)
    first = ingest_web(service, web, "lifecycle-message", "Export and clear this operational message").message
    assert first is not None
    status = service.retention_status(participant_id="owner", conversation_id=thread.conversation_id)
    assert status.message_count == 1 and status.storage == "durable_local"
    exported, export_receipt = service.export_transcript(
        participant_id="owner", conversation_id=thread.conversation_id, request_id="export-request-1"
    )
    assert export_receipt.operation == "export"
    assert exported.to_dict()["messages"][0]["messageId"] == first.message_id
    replayed_export, replayed_receipt = service.export_transcript(
        participant_id="owner", conversation_id=thread.conversation_id, request_id="export-request-1"
    )
    assert replayed_export.export_id == exported.export_id
    assert replayed_receipt.receipt_id == export_receipt.receipt_id
    cleared = service.clear_transcript(
        participant_id="owner", conversation_id=thread.conversation_id, request_id="clear-request-1"
    )
    assert cleared.operation == "clear"
    assert cleared.removed["messages"] == 1
    empty = service.presentation(participant_id="owner", conversation_id=thread.conversation_id)
    assert empty["messages"] == []
    restarted = ConversationService(clock=lambda: NOW, store_path=store)
    restored = restarted.presentation(participant_id="owner", conversation_id=thread.conversation_id)
    assert restored["thread"]["conversationId"] == thread.conversation_id
    assert restored["messages"] == []
    assert [item["operation"] for item in restored["lifecycleReceipts"]] == ["export", "clear"]
    assert ingest_web(restarted, web, "lifecycle-message", "Reuse after explicit clear").status == "accepted"


def test_transcript_clear_requires_explicit_delete_permission(tmp_path: Path) -> None:
    store = tmp_path / "conversation.sqlite3"
    service, thread, web, _telegram = fixture_service(store_path=store)
    service.register_participant(participant("reader", permissions=("conversation.read",)))
    ingest_web(service, web, "permission-message", "Private operational message")
    with pytest.raises(ConversationAuthorizationError):
        service.clear_transcript(participant_id="reader", conversation_id=thread.conversation_id, request_id="clear-denied")


def test_malformed_sqlite_store_fails_closed(tmp_path: Path) -> None:
    store = tmp_path / "conversation.sqlite3"
    service, _thread, _web, _telegram = fixture_service(store_path=store)
    assert service is not None
    with sqlite3.connect(store) as database:
        database.execute("UPDATE participants SET payload = '{}' ")
    with pytest.raises(ConversationContractError, match="participant identity is missing"):
        ConversationService(store_path=store)


def test_malformed_delivery_cannot_cross_conversation_scope(tmp_path: Path) -> None:
    store = tmp_path / "conversation.sqlite3"
    service, thread, _web, _telegram = fixture_service(store_path=store)
    inbound = ingest_web(service, _web, "scope-message", "Scope check").message
    assert inbound is not None
    response = service.send_internal(participant_id="owner", conversation_id=thread.conversation_id, body="Scope response", source_message_id=inbound.message_id)
    delivery = service.plan_deliveries(participant_id="owner", message_id=response.message_id)[0]
    with sqlite3.connect(store) as database:
        payload = json.loads(database.execute("SELECT payload FROM deliveries WHERE delivery_id = ?", (delivery.delivery_id,)).fetchone()[0])
        payload["conversationId"] = "conversation-from-another-scope"
        database.execute("UPDATE deliveries SET payload = ? WHERE delivery_id = ?", (json.dumps(payload), delivery.delivery_id))
    with pytest.raises(ConversationContractError, match="delivery receipt is inconsistent"):
        ConversationService(store_path=store)


def test_failed_sqlite_write_restores_in_memory_state_before_retry(tmp_path: Path) -> None:
    store = tmp_path / "conversation.sqlite3"
    service, thread, web, _telegram = fixture_service(store_path=store)
    inbound = ingest_web(service, web, "write-failure-inbound", "Write failure check").message
    assert inbound is not None
    real_connection = service._store

    class FailOnceConnection:
        def __init__(self, connection):
            self.connection = connection
            self.failed = False

        def execute(self, statement, *parameters):
            if not self.failed and str(statement).strip() == "DELETE FROM participants":
                self.failed = True
                raise sqlite3.OperationalError("synthetic persistence failure")
            return self.connection.execute(statement, *parameters)

        def __getattr__(self, name):
            return getattr(self.connection, name)

    service._store = FailOnceConnection(real_connection)
    with pytest.raises(ConversationContractError, match="conversation store write failed"):
        service.send_internal(participant_id="owner", conversation_id=thread.conversation_id, body="Must not survive", source_message_id=inbound.message_id)
    service._store = real_connection
    assert len(service.presentation(participant_id="owner", conversation_id=thread.conversation_id)["messages"]) == 1
    service.send_internal(participant_id="owner", conversation_id=thread.conversation_id, body="Retry after failure", source_message_id=inbound.message_id)
    assert len(service.presentation(participant_id="owner", conversation_id=thread.conversation_id)["messages"]) == 2


def test_real_local_web_service_exposes_one_app_attached_noncanonical_thread(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for relative in (
        "packages/statedd-core/src",
        "packages/template-validator/src",
        "packages/persistent-app/src",
        "packages/instance-backup/src",
        "packages/instance-catalog/src",
        "packages/diagnostics/src",
        "apps/runner/src",
    ):
        path = ROOT / relative
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    from stateport_persistent_app import LocalLayout, PersistentApp

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    instance = app.layout.instances_root / "project-one"
    instance.mkdir()
    app.catalog.register(
        instance,
        instance_id="project-one",
        name="Synthetic Project",
        source={
            "templateId": "stateport.development-reference",
            "resolvedCommit": "fixture:conversation",
            "resolvedTree": "conversation-tree",
            "manifestDigest": canonical_digest({"fixture": "conversation"}),
        },
    )
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = int(probe.getsockname()[1])

    def session_identity() -> tuple[str, str]:
        with urlopen(f"http://127.0.0.1:{port}/session") as response:
            value = json.loads(response.read())["result"]
            return response.headers["Set-Cookie"].split(";", 1)[0], value["csrfToken"]

    def get(path: str, cookie: str | None = None) -> dict[str, object]:
        headers = {"Cookie": cookie} if cookie else {}
        with urlopen(Request(f"http://127.0.0.1:{port}{path}", headers=headers)) as response:
            return json.loads(response.read())["result"]

    def post_message(cookie: str, csrf: str, client_id: str) -> dict[str, object]:
        body = json.dumps(
            {
                "clientMessageId": client_id,
                "text": "Continue the public-safe fixture",
                "replyToExternalMessageId": None,
                "attachments": [],
            }
        ).encode()
        request = Request(
            f"http://127.0.0.1:{port}/v1/instances/project-one/conversation/messages",
            data=body,
            method="POST",
            headers={
                "Cookie": cookie,
                "Content-Type": "application/json",
                "Origin": f"http://127.0.0.1:{port}",
                "X-StatePort-CSRF": csrf,
            },
        )
        with urlopen(request) as response:
            return json.loads(response.read())["result"]

    def post_lifecycle(cookie: str, csrf: str, operation: str, request_id: str, conversation_id: str) -> dict[str, object]:
        payload = {"expectedConversationId": conversation_id, "requestId": request_id}
        if operation == "clear":
            payload["confirmation"] = "CLEAR_CONVERSATION"
        request = Request(
            f"http://127.0.0.1:{port}/v1/instances/project-one/conversation/{operation}",
            data=json.dumps(payload).encode(),
            method="POST",
            headers={
                "Cookie": cookie,
                "Content-Type": "application/json",
                "Origin": f"http://127.0.0.1:{port}",
                "X-StatePort-CSRF": csrf,
            },
        )
        with urlopen(request) as response:
            return json.loads(response.read())["result"]

    app.service_start(port=port)
    try:
        with pytest.raises(HTTPError) as denied:
            get("/v1/instances/project-one/conversation")
        assert denied.value.code == 401
        cookie, csrf = session_identity()
        experience = get("/v1/instances/project-one/experience", cookie)
        assert experience["conversation"]["enabled"] is True
        empty = get("/v1/instances/project-one/conversation", cookie)
        assert empty["formatVersion"] == "stateport.conversation-presentation/v1"
        assert empty["applicationBinding"] == {"applicationId": "stateport.development-reference", "instanceId": "project-one"}
        assert empty["messages"] == []
        spoofed = Request(
            f"http://127.0.0.1:{port}/v1/instances/project-one/conversation/messages",
            data=json.dumps({
                "clientMessageId": "web-spoofed-actor",
                "text": "Do not accept a browser-selected actor.",
                "replyToExternalMessageId": None,
                "attachments": [],
                "actorId": "platform-operator",
            }).encode(),
            method="POST",
            headers={
                "Cookie": cookie,
                "Content-Type": "application/json",
                "Origin": f"http://127.0.0.1:{port}",
                "X-StatePort-CSRF": csrf,
            },
        )
        with pytest.raises(HTTPError) as actor_spoof_refused:
            urlopen(spoofed)
        assert actor_spoof_refused.value.code == 400
        accepted = post_message(cookie, csrf, "web-fixed-1")
        assert accepted["ingest"]["status"] == "accepted"
        assert len(accepted["presentation"]["messages"]) == 1
        duplicate = post_message(cookie, csrf, "web-fixed-1")
        assert duplicate["ingest"]["status"] == "duplicate"
        assert len(duplicate["presentation"]["messages"]) == 1
        assert duplicate["presentation"]["messages"][0]["canonicalStateEffect"] == "none"
        first_thread = duplicate["presentation"]["thread"]["conversationId"]
    finally:
        app.service_stop()

    # The application service uses the StatePort state-root store. A restart
    # restores operational continuity only; it never becomes canonical state.
    app.service_start(port=port)
    try:
        cookie, csrf = session_identity()
        restarted = get("/v1/instances/project-one/conversation", cookie)
        assert len(restarted["messages"]) == 1
        assert restarted["thread"]["conversationId"] == first_thread
        retention = get("/v1/instances/project-one/conversation/retention", cookie)
        assert retention["storage"] == "durable_local" and retention["messageCount"] == 1
        exported = post_lifecycle(cookie, csrf, "export", "http-export-1", first_thread)
        assert exported["receipt"]["operation"] == "export"
        assert exported["export"]["messages"][0]["body"] == "Continue the public-safe fixture"
        export_receipt_id = exported["receipt"]["receiptId"]
        receipt_index = get("/v1/instances/project-one/receipts", cookie)
        indexed_export = next(
            item
            for item in receipt_index["receipts"]
            if item["receiptId"] == export_receipt_id
        )
        assert indexed_export["action"] == "conversation.export"
        assert indexed_export["status"] == "completed_without_change"
        assert indexed_export["sourceKind"] == "conversation_lifecycle"
        cleared = post_lifecycle(cookie, csrf, "clear", "http-clear-1", first_thread)
        assert cleared["receipt"]["operation"] == "clear"
        assert cleared["canonicalStateEffect"] == "none"
        clear_receipt_id = cleared["receipt"]["receiptId"]
        receipt_index = get("/v1/instances/project-one/receipts", cookie)
        assert {
            item["action"]
            for item in receipt_index["receipts"]
            if item["receiptId"] in {export_receipt_id, clear_receipt_id}
        } == {"conversation.export", "conversation.clear"}
        clear_detail = get(
            f"/v1/instances/project-one/receipts/{clear_receipt_id}",
            cookie,
        )
        clear_projection = clear_detail["receipt"]["payload"]
        assert clear_projection["canonicalStateEffect"] == "none"
        assert clear_projection["relatedConversationId"] == first_thread
        assert clear_projection["lifecycleReceipt"] == cleared["receipt"]
        after_clear = get("/v1/instances/project-one/conversation", cookie)
        assert after_clear["messages"] == []
    finally:
        app.service_stop()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
