"""Deterministic, credential-free channel fixture adapters.

These adapters normalize already-delivered test payloads.  They do not open a
socket, read an environment credential, register a webhook, or send a message.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Mapping

from .contracts import AttachmentMetadata, ChannelBinding, ConversationContractError


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def _object(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ConversationContractError(f"{label} must be an object")
    return value


def _strict(value: Mapping[str, Any], label: str, required: set[str], optional: set[str] | None = None) -> None:
    optional = optional or set()
    if set(value) - required - optional or required - set(value):
        raise ConversationContractError(f"{label} has an invalid shape")


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ConversationContractError(f"{label} is not a safe identifier")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ConversationContractError(f"{label} must be a sha256 digest")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 16 * 1024 or "\x00" in value:
        raise ConversationContractError(f"{label} must be a non-empty bounded string")
    return value


def _timestamp(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z") or len(value) > 40:
        raise ConversationContractError(f"{label} must be a bounded UTC timestamp")
    # MessageEnvelope performs the full date-time parse at the service boundary.
    return value


def _attachments(value: object) -> tuple[AttachmentMetadata, ...]:
    if not isinstance(value, list) or len(value) > 16:
        raise ConversationContractError("fixture attachments must be a bounded array")
    return tuple(AttachmentMetadata.from_dict(item) for item in value)


@dataclass(frozen=True)
class NormalizedInbound:
    channel: str
    binding_id: str
    external_message_id: str
    provider_event_id: str
    sender_identity_digest: str
    sent_at: str
    body: str
    reply_to_external_message_id: str | None
    attachments: tuple[AttachmentMetadata, ...]
    echo_guard: str | None


class WebFixtureAdapter:
    """Normalize same-origin web fixture input without performing I/O."""

    FORMAT = "stateport.web-message-fixture/v1"
    channel = "web"

    def normalize(self, binding: ChannelBinding, source: object) -> NormalizedInbound:
        if binding.channel != self.channel or binding.status != "active":
            raise ConversationContractError("web fixture requires an active web binding")
        value = _object(source, "web message fixture")
        required = {"formatVersion", "bindingId", "clientMessageId", "sentAt", "text", "replyToExternalMessageId", "attachments", "echoGuard"}
        _strict(value, "web message fixture", required)
        if value["formatVersion"] != self.FORMAT or value["bindingId"] != binding.binding_id:
            raise ConversationContractError("web fixture identity does not match its binding")
        reply = None if value["replyToExternalMessageId"] is None else _identifier(value["replyToExternalMessageId"], "web reply identity")
        echo = None if value["echoGuard"] is None else _digest(value["echoGuard"], "web echo guard")
        external_id = _identifier(value["clientMessageId"], "web client message id")
        return NormalizedInbound(
            channel=self.channel,
            binding_id=binding.binding_id,
            external_message_id=external_id,
            provider_event_id=external_id,
            sender_identity_digest=binding.external_identity_digest,
            sent_at=_timestamp(value["sentAt"], "web message sent at"),
            body=_text(value["text"], "web message text"),
            reply_to_external_message_id=reply,
            attachments=_attachments(value["attachments"]),
            echo_guard=echo,
        )


class TelegramFixtureAdapter:
    """Normalize public-safe Telegram-shaped fixtures without a bot client."""

    FORMAT = "stateport.telegram-message-fixture/v1"
    channel = "telegram"

    def normalize(self, binding: ChannelBinding, source: object) -> NormalizedInbound:
        if binding.channel != self.channel or binding.status != "active":
            raise ConversationContractError("Telegram fixture requires an active Telegram binding")
        value = _object(source, "Telegram message fixture")
        _strict(value, "Telegram message fixture", {"formatVersion", "bindingId", "updateId", "message"})
        if value["formatVersion"] != self.FORMAT or value["bindingId"] != binding.binding_id:
            raise ConversationContractError("Telegram fixture identity does not match its binding")
        message = _object(value["message"], "Telegram fixture message")
        required = {
            "messageId", "chatIdentityDigest", "senderIdentityDigest", "sentAt", "text",
            "replyToMessageId", "attachments", "echoGuard",
        }
        _strict(message, "Telegram fixture message", required)
        if _digest(message["chatIdentityDigest"], "Telegram chat identity") != binding.external_conversation_digest:
            raise ConversationContractError("Telegram chat identity is not bound to this conversation")
        reply = None if message["replyToMessageId"] is None else _identifier(message["replyToMessageId"], "Telegram reply identity")
        echo = None if message["echoGuard"] is None else _digest(message["echoGuard"], "Telegram echo guard")
        return NormalizedInbound(
            channel=self.channel,
            binding_id=binding.binding_id,
            external_message_id=_identifier(message["messageId"], "Telegram message id"),
            provider_event_id=_identifier(value["updateId"], "Telegram update id"),
            sender_identity_digest=_digest(message["senderIdentityDigest"], "Telegram sender identity"),
            sent_at=_timestamp(message["sentAt"], "Telegram message sent at"),
            body=_text(message["text"], "Telegram message text"),
            reply_to_external_message_id=reply,
            attachments=_attachments(message["attachments"]),
            echo_guard=echo,
        )
