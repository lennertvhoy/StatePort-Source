#!/usr/bin/env python3
"""Deterministic acceptance tests for the Telegram polling boundary."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from threading import Event
from typing import Any, Mapping, Sequence
from urllib.parse import parse_qs
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
for relative in ("apps/telegram-adapter/src", "packages/conversation-service/src"):
    path = ROOT / relative
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from stateport_conversation import (  # noqa: E402
    ChannelBinding,
    ConversationService,
    ParticipantIdentity,
    WebFixtureAdapter,
    canonical_digest,
)
from stateport_telegram_adapter import (  # noqa: E402
    LiveTelegramApproval,
    PollingCursorStore,
    TelegramBotApiTransport,
    TelegramCredentials,
    TelegramPermanentError,
    TelegramPollingRuntime,
    TelegramTransientError,
    TelegramUpdateNormalizer,
)


NOW = "2026-07-15T09:00:00Z"
PROVIDER_TIME = 1_752_572_800
PERMISSIONS = (
    "conversation.create",
    "conversation.bind",
    "conversation.read",
    "conversation.send",
    "conversation.respond",
    "conversation.deliver",
    "conversation.propose",
)


def credential_value() -> str:
    return "123456:" + "publicfixturematerial" * 2


@dataclass
class FixtureBatchTransport:
    batches: list[Sequence[Mapping[str, Any]]]
    failures: list[BaseException] | None = None
    cancel_on_call: tuple[Event, int] | None = None

    def __post_init__(self) -> None:
        self.calls: list[dict[str, int]] = []
        self.failures = list(self.failures or [])

    def get_updates(self, *, offset: int, timeout_seconds: int, limit: int) -> Sequence[Mapping[str, Any]]:
        self.calls.append({"offset": offset, "timeout": timeout_seconds, "limit": limit})
        if self.cancel_on_call and len(self.calls) == self.cancel_on_call[1]:
            self.cancel_on_call[0].set()
        if self.failures:
            raise self.failures.pop(0)
        return self.batches.pop(0) if self.batches else []


@dataclass(frozen=True)
class FixtureAck:
    status: str


def telegram_update(
    update_id: int,
    message_id: int,
    chat_id: int,
    sender_id: int,
    text: str | None = "Continue the public-safe fixture",
    *,
    reply_to: int | None = None,
) -> dict[str, object]:
    message: dict[str, object] = {
        "message_id": message_id,
        "date": PROVIDER_TIME,
        "chat": {"id": chat_id, "type": "private"},
        "from": {"id": sender_id, "is_bot": False},
    }
    if text is not None:
        message["text"] = text
    if reply_to is not None:
        message["reply_to_message"] = {"message_id": reply_to}
    return {"update_id": update_id, "message": message}


def service_fixture(tmp_path: Path):
    credentials = TelegramCredentials(credential_value())
    chat_id = -1_001_234_567_890
    sender_id = 7_654_321
    participant = ParticipantIdentity.from_dict(
        {
            "formatVersion": ParticipantIdentity.FORMAT,
            "participantId": "owner",
            "actorId": "owner",
            "displayName": "Owner",
            "kind": "human",
            "applicationIds": ["stateport.development-reference"],
            "instanceIds": ["project-one"],
            "permissions": list(PERMISSIONS),
        }
    )
    service = ConversationService(clock=lambda: NOW, identity_seed="telegram-fixture")
    service.register_participant(participant)
    thread = service.create_thread(
        participant_id="owner",
        application_id="stateport.development-reference",
        instance_id="project-one",
        title="Project conversation",
        delivery_policy="mirror_to_all",
    )
    telegram = service.bind_channel(
        participant_id="owner",
        conversation_id=thread.conversation_id,
        channel="telegram",
        external_identity_digest=credentials.identity_digest("sender", sender_id),
        external_conversation_digest=credentials.identity_digest("chat", chat_id),
    )
    web = service.bind_channel(
        participant_id="owner",
        conversation_id=thread.conversation_id,
        channel="web",
        external_identity_digest=canonical_digest({"actor": "owner"}),
        external_conversation_digest=canonical_digest({"browser": "local", "instance": "project-one"}),
    )
    store = PollingCursorStore(tmp_path / "telegram-state", telegram.binding_id)
    return credentials, chat_id, sender_id, service, thread, telegram, web, store


def test_credentials_require_exact_approval_hidden_input_and_redact_representation() -> None:
    approval = LiveTelegramApproval(
        "approval:telegram-pilot",
        "binding:project-one",
        "sha256:" + "a" * 64,
        allow_polling=True,
    )
    observed: list[str] = []
    credentials = TelegramCredentials.prompt(approval, prompt_fn=lambda prompt: observed.append(prompt) or credential_value())
    assert observed == ["Telegram bot credential (input hidden): "]
    assert credential_value() not in repr(credentials)
    assert "redacted" in repr(credentials)
    with pytest.raises(TypeError, match="approval"):
        TelegramCredentials.prompt(None, prompt_fn=lambda _prompt: credential_value())  # type: ignore[arg-type]


def test_identity_binding_is_keyed_deterministic_and_namespace_separated() -> None:
    first = TelegramCredentials(credential_value())
    second = TelegramCredentials(credential_value())
    assert first.identity_digest("chat", -100) == second.identity_digest("chat", -100)
    assert first.identity_digest("chat", -100) != first.identity_digest("sender", -100)
    assert "-100" not in first.identity_digest("chat", -100)


def test_polling_ingests_once_mirrors_to_web_and_survives_restart(tmp_path: Path) -> None:
    credentials, chat_id, sender_id, service, thread, telegram, web, store = service_fixture(tmp_path)
    batches = [
        [
            telegram_update(40, 10, chat_id, sender_id),
            telegram_update(41, 10, chat_id, sender_id),
            {"update_id": 42, "edited_message": {"message_id": 10}},
        ]
    ]
    transport = FixtureBatchTransport(batches)
    runtime = TelegramPollingRuntime(
        transport,
        TelegramUpdateNormalizer(telegram, credentials),
        store,
        lambda inbound: service.ingest(participant_id="owner", inbound=inbound),
    )
    result = runtime.poll_once(timeout_seconds=0)
    assert result.to_dict() == {
        "startOffset": 0,
        "nextOffset": 43,
        "received": 3,
        "accepted": 1,
        "duplicates": 1,
        "echoesSuppressed": 0,
        "ignored": 1,
    }
    assert store.load().next_offset == 43
    assert PollingCursorStore(tmp_path / "telegram-state", telegram.binding_id).load().next_offset == 43
    messages, cursor = service.list_messages(participant_id="owner", conversation_id=thread.conversation_id)
    assert [item.body for item in messages] == ["Continue the public-safe fixture"]
    assert cursor.thread_revision == 1

    web_inbound = WebFixtureAdapter().normalize(
        web,
        {
            "formatVersion": WebFixtureAdapter.FORMAT,
            "bindingId": web.binding_id,
            "clientMessageId": "web-after-telegram",
            "sentAt": NOW,
            "text": "Continue from web",
            "replyToExternalMessageId": None,
            "attachments": [],
            "echoGuard": None,
        },
    )
    web_message = service.ingest(participant_id="owner", inbound=web_inbound).message
    assert web_message is not None and web_message.sequence == 2
    response = service.send_internal(
        participant_id="owner",
        conversation_id=thread.conversation_id,
        body="Shared reply",
        source_message_id=web_message.message_id,
    )
    plans = service.plan_deliveries(participant_id="owner", message_id=response.message_id)
    assert {item.channel: item.delivery_mode for item in plans} == {"telegram": "full", "web": "full"}


def test_cursor_advances_only_after_sink_acknowledgement(tmp_path: Path) -> None:
    credentials, chat_id, sender_id, _service, _thread, telegram, _web, store = service_fixture(tmp_path)
    seen: list[str] = []

    def sink(inbound):
        seen.append(inbound.external_message_id)
        if len(seen) == 2:
            raise RuntimeError("controlled sink interruption")
        return FixtureAck("accepted")

    runtime = TelegramPollingRuntime(
        FixtureBatchTransport([[telegram_update(8, 1, chat_id, sender_id), telegram_update(9, 2, chat_id, sender_id)]]),
        TelegramUpdateNormalizer(telegram, credentials),
        store,
        sink,
    )
    with pytest.raises(RuntimeError, match="controlled"):
        runtime.poll_once(timeout_seconds=0)
    assert seen == ["1", "2"]
    assert store.load().next_offset == 9

    replayed: list[str] = []
    restarted = TelegramPollingRuntime(
        FixtureBatchTransport([[telegram_update(9, 2, chat_id, sender_id)]]),
        TelegramUpdateNormalizer(telegram, credentials),
        PollingCursorStore(tmp_path / "telegram-state", telegram.binding_id),
        lambda inbound: replayed.append(inbound.external_message_id) or FixtureAck("accepted"),
    )
    restarted.poll_once(timeout_seconds=0)
    assert replayed == ["2"]
    assert store.load().next_offset == 10


def test_unbound_identity_invalid_order_and_unacknowledged_sink_fail_closed(tmp_path: Path) -> None:
    credentials, chat_id, sender_id, _service, _thread, telegram, _web, store = service_fixture(tmp_path)
    normalizer = TelegramUpdateNormalizer(telegram, credentials)
    secret_text = "content-must-not-appear-in-errors"
    with pytest.raises(TelegramPermanentError) as unbound:
        normalizer.normalize(telegram_update(1, 1, chat_id + 1, sender_id, secret_text))
    assert unbound.value.code == "unbound_chat"
    assert secret_text not in str(unbound.value) and str(chat_id + 1) not in str(unbound.value)
    assert store.load().next_offset == 0

    out_of_order = TelegramPollingRuntime(
        FixtureBatchTransport([[telegram_update(3, 3, chat_id, sender_id), telegram_update(2, 2, chat_id, sender_id)]]),
        normalizer,
        store,
        lambda _inbound: FixtureAck("accepted"),
    )
    with pytest.raises(TelegramPermanentError, match="ordering"):
        out_of_order.poll_once(timeout_seconds=0)
    assert store.load().next_offset == 0

    refused = TelegramPollingRuntime(
        FixtureBatchTransport([[telegram_update(4, 4, chat_id, sender_id)]]),
        normalizer,
        store,
        lambda _inbound: FixtureAck("failed"),
    )
    with pytest.raises(TelegramPermanentError, match="acknowledge"):
        refused.poll_once(timeout_seconds=0)
    assert store.load().next_offset == 0


def test_cursor_file_is_private_content_free_monotonic_and_symlink_safe(tmp_path: Path) -> None:
    store = PollingCursorStore(tmp_path / "state", "binding:fixture")
    store.save(12)
    raw = store.path.read_text(encoding="utf-8")
    assert json.loads(raw) == {"formatVersion": "stateport.telegram-polling-cursor/v1", "nextOffset": 12}
    assert store.path.stat().st_mode & 0o777 == 0o600
    assert "message" not in raw and "chat" not in raw and "binding" not in raw
    with pytest.raises(TelegramPermanentError) as backwards:
        store.save(11)
    assert backwards.value.code == "cursor_regression"

    unsafe = tmp_path / "unsafe"
    unsafe.symlink_to(tmp_path / "state", target_is_directory=True)
    with pytest.raises(TelegramPermanentError) as symlinked:
        PollingCursorStore(unsafe, "binding:fixture")
    assert symlinked.value.code == "unsafe_cursor_path"

    with store.lease():
        with pytest.raises(TelegramTransientError) as busy:
            with store.lease():
                pass
    assert busy.value.code == "poller_lease_busy"


def test_bounded_transient_retry_can_cancel_without_leaking_processes(tmp_path: Path) -> None:
    credentials, _chat_id, _sender_id, _service, _thread, telegram, _web, store = service_fixture(tmp_path)
    cancel = Event()
    transport = FixtureBatchTransport(
        [[]],
        failures=[TelegramTransientError("controlled transient failure", code="fixture_transient")],
        cancel_on_call=(cancel, 2),
    )
    runtime = TelegramPollingRuntime(
        transport,
        TelegramUpdateNormalizer(telegram, credentials),
        store,
        lambda _inbound: FixtureAck("accepted"),
    )
    runtime.run(cancel, timeout_seconds=0, retry_delays=(0.0,))
    assert len(transport.calls) == 2 and cancel.is_set()


class FixtureResponse:
    def __init__(self, payload: object) -> None:
        self.body = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, limit: int) -> bytes:
        return self.body[:limit]


def test_bot_api_transport_is_approval_scoped_and_machine_readable_without_network() -> None:
    calls: list[tuple[str, dict[str, list[str]], float]] = []

    def opener(request, *, timeout: float):
        fields = parse_qs(request.data.decode("ascii"))
        calls.append((request.full_url.rsplit("/", 1)[-1], fields, timeout))
        if request.full_url.endswith("/getUpdates"):
            return FixtureResponse({"ok": True, "result": [{"update_id": 5}]})
        return FixtureResponse({"ok": True, "result": {"message_id": 77}})

    credentials = TelegramCredentials(credential_value())
    poll_only = TelegramBotApiTransport(
        credentials,
        LiveTelegramApproval(
            "approval:poll",
            "binding:fixture",
            credentials.identity_digest("chat", -100),
            allow_polling=True,
        ),
        opener=opener,
    )
    assert poll_only.get_updates(offset=5, timeout_seconds=0, limit=1) == [{"update_id": 5}]
    with pytest.raises(TelegramPermanentError) as sending_denied:
        poll_only.send_message(chat_id=-100, text="Fixture")
    assert sending_denied.value.code == "sending_not_approved"

    approved = TelegramBotApiTransport(
        credentials,
        LiveTelegramApproval(
            "approval:send",
            "binding:fixture",
            credentials.identity_digest("chat", -100),
            allow_polling=True,
            allow_sending=True,
        ),
        opener=opener,
    )
    assert approved.send_message(chat_id=-100, text="Fixture", reply_to_message_id=3) == 77
    with pytest.raises(TelegramPermanentError) as wrong_target:
        approved.send_message(chat_id=-101, text="Fixture")
    assert wrong_target.value.code == "unbound_send_target"
    assert [call[0] for call in calls] == ["getUpdates", "sendMessage"]
    assert calls[0][1]["offset"] == ["5"] and calls[0][1]["allowed_updates"] == ['["message"]']
    assert credential_value() not in repr(poll_only) and "redacted" in repr(poll_only)


def test_live_transport_approval_must_match_normalized_channel_binding(tmp_path: Path) -> None:
    credentials, _chat_id, _sender_id, _service, _thread, telegram, _web, store = service_fixture(tmp_path)
    transport = TelegramBotApiTransport(
        credentials,
        LiveTelegramApproval(
            "approval:mismatch",
            "binding:other",
            telegram.external_conversation_digest,
            allow_polling=True,
        ),
        opener=lambda *_args, **_kwargs: FixtureResponse({"ok": True, "result": []}),
    )
    with pytest.raises(TelegramPermanentError) as mismatch:
        TelegramPollingRuntime(
            transport,
            TelegramUpdateNormalizer(telegram, credentials),
            store,
            lambda _inbound: FixtureAck("accepted"),
        )
    assert mismatch.value.code == "approval_binding_mismatch"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
