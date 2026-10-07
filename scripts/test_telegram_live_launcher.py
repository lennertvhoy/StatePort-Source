#!/usr/bin/env python3
"""Deterministic offline proof for the Telegram live launcher wiring.

No contact with api.telegram.org: a fake transport returns canned Bot-API-
shaped updates.  The test proves the launcher builds matching binding,
approval, and normalizer; that an inbound from the allowlisted operator is
ingested into the shared ConversationThread; that a different sender is
refused; that a repeated external message yields ``duplicate``; that an
outbound assistant reply is delivered via the fake send path exactly once
with no echo loop; and that the token string never appears in any captured
output, log, or exception.
"""

from __future__ import annotations

from datetime import datetime, timezone
import io
import os
from pathlib import Path
import sys
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[1]
for relative in (
    "packages/conversation-service/src",
    "apps/telegram-adapter/src",
):
    sys.path.insert(0, str(ROOT / relative))

from stateport_conversation import (  # noqa: E402
    ConversationService,
    ParticipantIdentity,
    WebFixtureAdapter,
    canonical_digest,
)
from stateport_telegram_adapter import (  # noqa: E402
    LiveTelegramApproval,
    TelegramAdapterError,
    TelegramCredentials,
)
from stateport_telegram_adapter.launcher import TelegramLiveLauncher  # noqa: E402


OPERATOR_USER_ID = 6790312159
FAKE_TOKEN = "123456789:AAAAAAAAAAAAAAAAAAAAAAAA"
# Real-token fragments that must never appear in the repo, constructed
# programmatically so the literal substrings are never written to disk.
_BOT_ID_FRAGMENT = "8763" + "630004"
_SECRET_FRAGMENT = "AAH0" + "6VIbis"


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class _FakeTransport:
    """Deterministic Bot API stand-in that never contacts api.telegram.org."""

    def __init__(self) -> None:
        self._queue: list[dict[str, Any]] = []
        self.sent: list[dict[str, Any]] = []
        self.sent_message_ids: list[int] = []
        self._next_message_id = 9000
        self.raise_on_get_updates = False

    def push_update(self, update: dict[str, Any]) -> None:
        self._queue.append(dict(update))

    def get_updates(self, *, offset: int, timeout_seconds: int = 0, limit: int = 100):
        if self.raise_on_get_updates:
            raise TelegramAdapterError("simulated transport failure", code="provider_unreachable")
        return [u for u in self._queue if u["update_id"] >= offset]

    def send_message(self, *, chat_id: int, text: str, reply_to_message_id: int | None = None) -> int:
        self._next_message_id += 1
        self.sent.append({"chat_id": chat_id, "text": text, "reply_to": reply_to_message_id})
        self.sent_message_ids.append(self._next_message_id)
        return self._next_message_id


def _make_update(
    *,
    update_id: int,
    message_id: int,
    user_id: int,
    text: str,
    date: int = 1700000000,
) -> dict[str, Any]:
    return {
        "update_id": update_id,
        "message": {
            "message_id": message_id,
            "date": date,
            "chat": {"id": user_id},
            "from": {"id": user_id, "is_bot": False},
            "text": text,
        },
    }


def _setup_conversation(
    service: ConversationService,
    *,
    application_id: str = "studydd",
    instance_id: str = "instance-1",
):
    participant_id = f"local-operator:{instance_id}"
    participant = ParticipantIdentity.from_dict(
        {
            "formatVersion": ParticipantIdentity.FORMAT,
            "participantId": participant_id,
            "actorId": "local-operator",
            "displayName": "Local operator",
            "kind": "human",
            "applicationIds": [application_id],
            "instanceIds": [instance_id],
            "permissions": [
                "conversation.create",
                "conversation.bind",
                "conversation.read",
                "conversation.send",
                "conversation.respond",
                "conversation.deliver",
                "conversation.propose",
            ],
        }
    )
    service.register_participant(participant)
    thread = service.create_thread(
        participant_id=participant_id,
        application_id=application_id,
        instance_id=instance_id,
        title="Shared web+telegram conversation",
        delivery_policy="mirror_to_all",
    )
    web_binding = service.bind_channel(
        participant_id=participant_id,
        conversation_id=thread.conversation_id,
        channel="web",
        external_identity_digest=canonical_digest({"actor": "local-operator", "instanceId": instance_id}),
        external_conversation_digest=canonical_digest({"channel": "web", "instanceId": instance_id}),
    )
    return thread, participant_id, web_binding


def _write_token(config_root: Path, token: str = FAKE_TOKEN) -> None:
    secrets_dir = config_root / "secrets"
    secrets_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(secrets_dir, 0o700)
    token_path = secrets_dir / "telegram.env"
    descriptor = os.open(str(token_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(descriptor, f"TELEGRAM_BOT_TOKEN={token}\n".encode("ascii"))
    finally:
        os.close(descriptor)
    os.chmod(token_path, 0o600)


def _write_operator_yaml(config_root: Path, *, user_ids: list[int] | None = None, application_id: str = "studydd", instance_id: str = "studydd-local-alpha") -> None:
    config_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(config_root, 0o700)
    ids = user_ids if user_ids is not None else [OPERATOR_USER_ID]
    lines = [
        "telegram:",
        "  bot_username: StudyStateBot_bot",
        "  allowed_telegram_user_ids:",
    ]
    lines.extend(f"    - {uid}" for uid in ids)
    lines.append("  binding_policy: exclusive_to_allowlisted_users")
    lines.append("  unbound_refusal: true")
    lines.append(f"  application_id: {application_id}")
    lines.append(f"  instance_id: {instance_id}")
    (config_root / "operator.yaml").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _build_launcher(
    tmp_path: Path,
    service: ConversationService,
    *,
    transport: _FakeTransport,
    poll_backoff_delays: tuple[float, ...] | None = None,
    poll_timeout_seconds: int | None = None,
    auto_reply: bool = False,
) -> TelegramLiveLauncher:
    config_root = tmp_path / "config"
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    _write_token(config_root)
    _write_operator_yaml(config_root)

    def factory(_credentials: TelegramCredentials, approval: LiveTelegramApproval):
        return transport

    return TelegramLiveLauncher(
        config_root=config_root,
        runtime_root=runtime_root,
        conversation_service=service,
        transport_factory=factory,
        poll_backoff_delays=poll_backoff_delays,
        poll_timeout_seconds=poll_timeout_seconds,
        auto_reply=auto_reply,
    )


def test_launcher_disabled_when_token_absent(tmp_path: Path) -> None:
    service = ConversationService()
    launcher = TelegramLiveLauncher(
        config_root=tmp_path / "config",
        runtime_root=tmp_path / "runtime",
        conversation_service=service,
        transport_factory=lambda *_: _FakeTransport(),
    )
    assert launcher.enabled is False
    status = launcher.status()
    assert status.reason == "token_missing"
    assert status.binding_id is None
    assert status.operator_user_id is None


def test_launcher_disabled_when_allowlist_empty(tmp_path: Path) -> None:
    config_root = tmp_path / "config"
    _write_token(config_root)
    _write_operator_yaml(config_root, user_ids=[])
    launcher = TelegramLiveLauncher(
        config_root=config_root,
        runtime_root=tmp_path / "runtime",
        conversation_service=ConversationService(),
        transport_factory=lambda *_: _FakeTransport(),
    )
    assert launcher.enabled is False
    assert launcher.status().reason == "allowlist_empty"


def test_launcher_refuses_world_readable_token(tmp_path: Path) -> None:
    config_root = tmp_path / "config"
    secrets_dir = config_root / "secrets"
    secrets_dir.mkdir(parents=True, exist_ok=True)
    token_path = secrets_dir / "telegram.env"
    token_path.write_text(f"TELEGRAM_BOT_TOKEN={FAKE_TOKEN}\n", encoding="utf-8")
    os.chmod(token_path, 0o644)
    _write_operator_yaml(config_root)
    launcher = TelegramLiveLauncher(
        config_root=config_root,
        runtime_root=tmp_path / "runtime",
        conversation_service=ConversationService(),
        transport_factory=lambda *_: _FakeTransport(),
    )
    assert launcher.enabled is False
    assert launcher.status().reason == "token_missing"


def test_launcher_refuses_token_symlink_without_following_it(tmp_path: Path) -> None:
    config_root = tmp_path / "config"
    secrets_dir = config_root / "secrets"
    secrets_dir.mkdir(parents=True, exist_ok=True)
    token_target = tmp_path / "outside-telegram.env"
    token_target.write_text(f"TELEGRAM_BOT_TOKEN={FAKE_TOKEN}\n", encoding="utf-8")
    os.chmod(token_target, 0o600)
    (secrets_dir / "telegram.env").symlink_to(token_target)
    _write_operator_yaml(config_root)

    launcher = TelegramLiveLauncher(
        config_root=config_root,
        runtime_root=tmp_path / "runtime",
        conversation_service=ConversationService(),
        transport_factory=lambda *_: _FakeTransport(),
    )

    assert launcher.enabled is False
    assert launcher.status().reason == "token_missing"


def test_live_round_trip(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    service = ConversationService()
    thread, participant_id, web_binding = _setup_conversation(service)
    fake_transport = _FakeTransport()
    launcher = _build_launcher(tmp_path, service, transport=fake_transport)

    assert launcher.enabled is True
    assert launcher.operator_user_id == OPERATOR_USER_ID

    telegram_binding = launcher.attach(
        participant_id=participant_id,
        conversation_id=thread.conversation_id,
    )
    assert telegram_binding is not None
    assert telegram_binding.channel == "telegram"
    assert telegram_binding.status == "active"
    assert telegram_binding.conversation_id == thread.conversation_id
    assert telegram_binding.application_id == thread.application_id
    assert telegram_binding.instance_id == thread.instance_id
    assert telegram_binding.owner_participant_id == participant_id

    # The binding, approval, and normalizer all reference the same digest.
    approval = launcher.approval
    assert approval is not None
    assert approval.binding_id == telegram_binding.binding_id
    assert approval.allow_polling is True
    assert approval.allow_sending is True
    assert approval.chat_identity_digest == telegram_binding.external_conversation_digest
    normalizer = launcher.normalizer
    assert normalizer is not None
    assert normalizer.binding.binding_id == telegram_binding.binding_id

    # Inbound from the operator is accepted and lands in the shared thread.
    fake_transport.push_update(
        _make_update(update_id=1, message_id=10, user_id=OPERATOR_USER_ID, text="hello from telegram")
    )
    batch = launcher.poll_once(timeout_seconds=0)
    assert batch.accepted == 1
    assert batch.received == 1

    messages, _cursor = service.list_messages(
        participant_id=participant_id,
        conversation_id=thread.conversation_id,
        limit=50,
    )
    assert len(messages) == 1
    assert messages[0].body == "hello from telegram"
    assert messages[0].source_channel == "telegram"
    assert messages[0].external_identity is not None
    assert messages[0].external_identity.channel == "telegram"

    # The web binding and telegram binding share ONE ConversationThread.
    presentation = service.presentation(
        participant_id=participant_id,
        conversation_id=thread.conversation_id,
    )
    channel_bindings = presentation["channelBindings"]
    assert {b["channel"] for b in channel_bindings} == {"web", "telegram"}
    assert all(b["status"] == "active" for b in channel_bindings)

    # An update from a different user id is refused and cursor advances past it.
    fake_transport.push_update(
        _make_update(update_id=2, message_id=11, user_id=9999999999, text="intruder")
    )
    refused_batch = launcher.poll_once(timeout_seconds=0)
    assert refused_batch.ignored == 1
    assert refused_batch.next_offset == 3

    # A repeated external message id (same message_id, new update_id) yields duplicate.
    fake_transport.push_update(
        _make_update(update_id=3, message_id=10, user_id=OPERATOR_USER_ID, text="hello from telegram")
    )
    duplicate_batch = launcher.poll_once(timeout_seconds=0)
    assert duplicate_batch.duplicates == 1
    assert duplicate_batch.accepted == 0

    # Outbound assistant reply mirrors to Telegram exactly once.
    assistant = service.send_internal(
        participant_id=participant_id,
        conversation_id=thread.conversation_id,
        body="ack from assistant",
        kind="assistant_message",
    )
    assert assistant.source_channel == "web"
    sent_count = launcher.drain_deliveries()
    assert sent_count == 1
    assert len(fake_transport.sent) == 1
    assert fake_transport.sent[0]["chat_id"] == OPERATOR_USER_ID
    assert fake_transport.sent[0]["text"] == "ack from assistant"

    # A second drain cycle does not re-send (no echo loop, idempotent delivery).
    second_count = launcher.drain_deliveries()
    assert second_count == 0
    assert len(fake_transport.sent) == 1

    # The outbound external message id is echo-guarded: re-ingesting it as an
    # inbound update yields echo_suppressed, not a new accepted message.
    outbound_message_id = fake_transport.sent_message_ids[0]
    fake_transport.push_update(
        _make_update(
            update_id=4,
            message_id=outbound_message_id,
            user_id=OPERATOR_USER_ID,
            text="ack from assistant",
        )
    )
    echo_batch = launcher.poll_once(timeout_seconds=0)
    assert echo_batch.echoes_suppressed == 1
    assert echo_batch.accepted == 0
    messages_after_echo, _ = service.list_messages(
        participant_id=participant_id,
        conversation_id=thread.conversation_id,
        limit=50,
    )
    assert len(messages_after_echo) == 2  # one telegram inbound + one assistant

    # A web-origin inbound is also mirrored to Telegram by the drain.
    web_adapter = WebFixtureAdapter()
    web_inbound = web_adapter.normalize(
        web_binding,
        {
            "formatVersion": WebFixtureAdapter.FORMAT,
            "bindingId": web_binding.binding_id,
            "clientMessageId": "web-msg-1",
            "sentAt": _utc_now(),
            "text": "hello from web",
            "replyToExternalMessageId": None,
            "attachments": [],
            "echoGuard": None,
        },
    )
    service.ingest(participant_id=participant_id, inbound=web_inbound)
    web_mirror_count = launcher.drain_deliveries()
    assert web_mirror_count == 1
    assert len(fake_transport.sent) == 2
    assert fake_transport.sent[1]["text"] == "hello from web"

    # The token string NEVER appears in any captured output, log, or exception.
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert FAKE_TOKEN not in combined
    assert _BOT_ID_FRAGMENT not in combined
    assert _SECRET_FRAGMENT not in combined


def test_redelivery_after_refusal(tmp_path: Path) -> None:
    """Updates below cursor are skipped even if transport still holds them."""
    service = ConversationService()
    thread, participant_id, _web = _setup_conversation(service)
    transport = _FakeTransport()
    launcher = _build_launcher(tmp_path, service, transport=transport)
    launcher.attach(participant_id=participant_id, conversation_id=thread.conversation_id)

    transport.push_update(
        _make_update(update_id=1, message_id=10, user_id=OPERATOR_USER_ID, text="hello")
    )
    transport.push_update(
        _make_update(update_id=2, message_id=11, user_id=999999999, text="intruder")
    )

    batch = launcher.poll_once(timeout_seconds=0)
    assert batch.accepted == 1
    assert batch.ignored == 1
    assert batch.next_offset == 3

    # Transport still has updates 1 and 2 in its queue (not drained).
    # A new poll with offset >= 3 only returns updates >= 3.
    transport.push_update(
        _make_update(update_id=3, message_id=12, user_id=OPERATOR_USER_ID, text="after intruder")
    )

    batch2 = launcher.poll_once(timeout_seconds=0)
    assert batch2.accepted == 1
    assert batch2.ignored == 0
    assert batch2.next_offset == 4

    messages, _cursor = service.list_messages(
        participant_id=participant_id,
        conversation_id=thread.conversation_id,
        limit=50,
    )
    assert len(messages) == 2
    assert messages[0].body == "hello"
    assert messages[1].body == "after intruder"


def test_token_never_leaks_through_exceptions(tmp_path: Path) -> None:
    """Transport-level errors must not surface the raw token in error text."""

    service = ConversationService()
    thread, participant_id, _web = _setup_conversation(service)
    transport = _FakeTransport()
    transport.raise_on_get_updates = True
    launcher = _build_launcher(tmp_path, service, transport=transport)
    launcher.attach(participant_id=participant_id, conversation_id=thread.conversation_id)
    captured_errors: list[str] = []

    try:
        launcher.poll_once(timeout_seconds=0)
    except Exception as exc:  # noqa: BLE001 - intentionally capture all error text
        captured_errors.append(str(exc))
        import traceback

        captured_errors.append(traceback.format_exc())

    assert len(captured_errors) > 0, "exception path was not exercised"
    for text in captured_errors:
        assert FAKE_TOKEN not in text
        assert _BOT_ID_FRAGMENT not in text
        assert _SECRET_FRAGMENT not in text

    # Also verify: a per-update refusal (intruder) still produces no token leak
    transport.raise_on_get_updates = False
    transport.push_update(
        _make_update(update_id=1, message_id=99, user_id=999999999, text="intruder")
    )
    try:
        launcher.poll_once(timeout_seconds=0)
    except Exception as exc:  # noqa: BLE001 - intentionally capture all error text
        captured_errors.append(str(exc))
        captured_errors.append(traceback.format_exc())

    for text in captured_errors:
        assert FAKE_TOKEN not in text
        assert _BOT_ID_FRAGMENT not in text
        assert _SECRET_FRAGMENT not in text


def test_explicit_binding_identity_in_status(tmp_path: Path) -> None:
    """Launcher status exposes application_id, instance_id, no degraded."""
    service = ConversationService()
    transport = _FakeTransport()
    launcher = _build_launcher(tmp_path, service, transport=transport)
    assert launcher.enabled is True
    status = launcher.status()
    assert status.application_id == "studydd"
    assert status.instance_id == "studydd-local-alpha"
    assert status.degraded is None


def test_backoff_recovery_after_transient_failure(tmp_path: Path) -> None:
    """Outer backoff recovers and status clears after transport succeeds."""
    import time

    service = ConversationService()
    thread, participant_id, _web = _setup_conversation(service)

    transport = _FakeTransport()
    transport.raise_on_get_updates = True
    launcher = _build_launcher(
        tmp_path, service, transport=transport,
        poll_backoff_delays=(0.1, 0.3, 0.5),
    )
    launcher.attach(participant_id=participant_id, conversation_id=thread.conversation_id)
    launcher.start()

    # Give the poll thread time to hit the outer backoff
    time.sleep(0.2)

    status = launcher.status()
    assert status.degraded is not None, "outer backoff should activate"
    assert status.polling is True

    # Fix the transport so the next outer-retry attempt succeeds
    transport.raise_on_get_updates = False
    transport.push_update(
        _make_update(update_id=1, message_id=10, user_id=OPERATOR_USER_ID, text="recovery")
    )

    # Allow backoff to expire (0.1s) and poll to succeed
    for _ in range(30):
        time.sleep(0.1)
        s = launcher.status()
        if s.degraded is None:
            break

    recovered = launcher.status()
    assert recovered.degraded is None, "backoff should clear on success"
    assert recovered.polling is True

    # Wait for the poller to process the pushed update
    import time
    found = False
    for _ in range(20):
        if not found:
            time.sleep(0.1)
            messages, _cursor = service.list_messages(
                participant_id=participant_id,
                conversation_id=thread.conversation_id,
                limit=50,
            )
            found = any(m.body == "recovery" for m in messages)
    assert found, "poller should have processed the recovery update"

    launcher.stop()


def test_live_demo_auto_reply(tmp_path: Path) -> None:
    service = ConversationService()
    thread, participant_id, _web_binding = _setup_conversation(service)
    fake_transport = _FakeTransport()
    launcher = _build_launcher(tmp_path, service, transport=fake_transport, auto_reply=True)
    launcher.attach(participant_id=participant_id, conversation_id=thread.conversation_id)

    fake_transport.push_update(
        _make_update(update_id=1, message_id=10, user_id=OPERATOR_USER_ID, text="/help")
    )
    batch = launcher.poll_once(timeout_seconds=0)
    assert batch.accepted == 1
    assert launcher.drain_deliveries() == 1
    assert fake_transport.sent[0]["text"].startswith("StatePort Telegram demo is online.")


def test_clean_cancellation_while_sleeping(tmp_path: Path) -> None:
    """Cancelling the launcher while poll thread sleeps in backoff is clean."""
    import time

    service = ConversationService()
    thread, participant_id, _web = _setup_conversation(service)

    transport = _FakeTransport()
    transport.raise_on_get_updates = True
    launcher = _build_launcher(
        tmp_path, service, transport=transport,
        poll_backoff_delays=(0.1, 0.3, 0.5),
    )
    launcher.attach(participant_id=participant_id, conversation_id=thread.conversation_id)
    launcher.start()

    time.sleep(0.2)
    assert launcher.status().degraded is not None

    launcher.stop()
    status = launcher.status()
    assert status.polling is False
    assert status.binding_id is not None


def test_no_token_leak_in_backoff_status(tmp_path: Path) -> None:
    """Degraded status reason must not contain the token."""
    import time

    service = ConversationService()
    thread, participant_id, _web = _setup_conversation(service)

    transport = _FakeTransport()
    transport.raise_on_get_updates = True
    launcher = _build_launcher(
        tmp_path, service, transport=transport,
        poll_backoff_delays=(0.1, 0.3, 0.5),
    )
    launcher.attach(participant_id=participant_id, conversation_id=thread.conversation_id)
    launcher.start()

    time.sleep(0.2)

    status = launcher.status()
    status_dict = status.to_dict()
    text = str(status_dict)
    assert FAKE_TOKEN not in text
    assert _BOT_ID_FRAGMENT not in text
    assert _SECRET_FRAGMENT not in text

    launcher.stop()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
