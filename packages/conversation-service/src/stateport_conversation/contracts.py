"""Strict wire contracts for channel-neutral, noncanonical conversation state.

The contracts in this module describe operational continuity.  They do not
grant channel access, mutate canonical application state, run compression, or
send anything to an external provider.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
import json
import re
from typing import Any, Mapping


CHANNELS = frozenset({"web", "telegram"})
DELIVERY_POLICIES = frozenset(
    {"source_channel_only", "mirror_to_all", "web_primary", "telegram_primary"}
)
MESSAGE_KINDS = frozenset(
    {
        "user_message",
        "assistant_message",
        "system_message",
        "run_event",
        "tool_event",
        "state_proposal_reference",
    }
)

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_PERMISSION = re.compile(r"^[a-z][a-z0-9._-]{1,127}$")
_MEDIA_TYPE = re.compile(r"^[a-z0-9][a-z0-9.+-]{0,63}/[a-z0-9][a-z0-9.+-]{0,127}$")
_SECRET_KEY = re.compile(
    r"(?:api[_-]?key|authorization|cookie|credential|password|secret|token|private[_-]?key)",
    re.I,
)


class ConversationContractError(ValueError):
    """Raised when data crosses a conversation contract incorrectly."""


def canonical_digest(value: Any) -> str:
    if hasattr(value, "to_dict"):
        value = value.to_dict()
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + sha256(encoded).hexdigest()


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ConversationContractError(f"{label} must be an object")
    return value


def _keys(value: Mapping[str, Any], label: str, required: set[str], optional: set[str] | None = None) -> None:
    optional = optional or set()
    missing = sorted(required - set(value))
    unknown = sorted(set(value) - required - optional)
    if missing:
        raise ConversationContractError(f"{label} is missing: {', '.join(missing)}")
    if unknown:
        raise ConversationContractError(f"{label} contains unknown fields: {', '.join(unknown)}")


def _text(value: object, label: str, *, maximum: int = 4096, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or len(value) > maximum or (not allow_empty and not value.strip()):
        qualifier = "bounded" if allow_empty else "non-empty bounded"
        raise ConversationContractError(f"{label} must be a {qualifier} string")
    if "\x00" in value:
        raise ConversationContractError(f"{label} contains a null byte")
    return value


def _identifier(value: object, label: str) -> str:
    result = _text(value, label, maximum=256)
    if not _ID.fullmatch(result):
        raise ConversationContractError(f"{label} is not a safe identifier")
    return result


def _digest(value: object, label: str) -> str:
    result = _text(value, label, maximum=71)
    if not _DIGEST.fullmatch(result):
        raise ConversationContractError(f"{label} must be a sha256 digest")
    return result


def _timestamp(value: object, label: str) -> str:
    result = _text(value, label, maximum=40)
    if not result.endswith("Z"):
        raise ConversationContractError(f"{label} must be a UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(result[:-1] + "+00:00")
    except ValueError as exc:
        raise ConversationContractError(f"{label} is not a valid timestamp") from exc
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise ConversationContractError(f"{label} must be UTC")
    return result


def _strings(
    value: object,
    label: str,
    *,
    nonempty: bool = False,
    maximum_items: int = 128,
    permissions: bool = False,
) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > maximum_items or (nonempty and not value):
        raise ConversationContractError(f"{label} must be a bounded array")
    items = tuple(_text(item, label, maximum=128) for item in value)
    if len(set(items)) != len(items):
        raise ConversationContractError(f"{label} must not contain duplicates")
    if permissions and any(not _PERMISSION.fullmatch(item) for item in items):
        raise ConversationContractError(f"{label} contains an invalid permission")
    return items


def _ratio(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConversationContractError(f"{label} must be numeric")
    result = float(value)
    if not 0 < result < 1:
        raise ConversationContractError(f"{label} must be greater than zero and less than one")
    return result


def _no_secret_fields(value: object, label: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ConversationContractError(f"{label} keys must be strings")
            if _SECRET_KEY.search(key):
                raise ConversationContractError(f"credential-like field is forbidden at {label}.{key}")
            _no_secret_fields(item, f"{label}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _no_secret_fields(item, f"{label}[{index}]")


@dataclass(frozen=True)
class ParticipantIdentity:
    FORMAT = "stateport.participant-identity/v1"

    participant_id: str
    actor_id: str
    display_name: str
    kind: str
    application_ids: tuple[str, ...]
    instance_ids: tuple[str, ...]
    permissions: tuple[str, ...]

    @classmethod
    def from_dict(cls, source: object) -> "ParticipantIdentity":
        _no_secret_fields(source)
        value = _mapping(source, "participant identity")
        required = {"formatVersion", "participantId", "actorId", "displayName", "kind", "applicationIds", "instanceIds", "permissions"}
        _keys(value, "participant identity", required)
        if value["formatVersion"] != cls.FORMAT:
            raise ConversationContractError("unsupported participant identity format")
        if value["kind"] not in {"human", "application", "system"}:
            raise ConversationContractError("participant kind is unsupported")
        return cls(
            _identifier(value["participantId"], "participant id"),
            _identifier(value["actorId"], "actor id"),
            _text(value["displayName"], "participant display name", maximum=80),
            str(value["kind"]),
            tuple(_identifier(item, "participant application id") for item in _strings(value["applicationIds"], "participant application ids", nonempty=True)),
            tuple(_identifier(item, "participant instance id") for item in _strings(value["instanceIds"], "participant instance ids", nonempty=True)),
            _strings(value["permissions"], "participant permissions", nonempty=True, permissions=True),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "participantId": self.participant_id,
            "actorId": self.actor_id,
            "displayName": self.display_name,
            "kind": self.kind,
            "applicationIds": list(self.application_ids),
            "instanceIds": list(self.instance_ids),
            "permissions": list(self.permissions),
        }

    def permits(self, application_id: str, instance_id: str, permission: str) -> bool:
        return application_id in self.application_ids and instance_id in self.instance_ids and permission in self.permissions


@dataclass(frozen=True)
class ExternalMessageIdentity:
    FORMAT = "stateport.external-message-identity/v1"

    channel: str
    binding_id: str
    external_message_id: str
    deduplication_key: str
    direction: str

    @classmethod
    def from_dict(cls, source: object) -> "ExternalMessageIdentity":
        value = _mapping(source, "external message identity")
        _keys(value, "external message identity", {"formatVersion", "channel", "bindingId", "externalMessageId", "deduplicationKey", "direction"})
        if value["formatVersion"] != cls.FORMAT:
            raise ConversationContractError("unsupported external message identity format")
        if value["channel"] not in CHANNELS:
            raise ConversationContractError("external message channel is unsupported")
        if value["direction"] not in {"inbound", "outbound"}:
            raise ConversationContractError("external message direction is unsupported")
        return cls(
            str(value["channel"]),
            _identifier(value["bindingId"], "external message binding id"),
            _identifier(value["externalMessageId"], "external message id"),
            _digest(value["deduplicationKey"], "external message deduplication key"),
            str(value["direction"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "channel": self.channel,
            "bindingId": self.binding_id,
            "externalMessageId": self.external_message_id,
            "deduplicationKey": self.deduplication_key,
            "direction": self.direction,
        }


@dataclass(frozen=True)
class ChannelBinding:
    FORMAT = "stateport.channel-binding/v1"

    binding_id: str
    conversation_id: str
    application_id: str
    instance_id: str
    channel: str
    owner_participant_id: str
    external_identity_digest: str
    external_conversation_digest: str
    status: str
    created_at: str

    @classmethod
    def from_dict(cls, source: object) -> "ChannelBinding":
        _no_secret_fields(source)
        value = _mapping(source, "channel binding")
        required = {
            "formatVersion", "bindingId", "conversationId", "applicationId", "instanceId", "channel",
            "ownerParticipantId", "externalIdentityDigest", "externalConversationDigest", "status", "createdAt",
        }
        _keys(value, "channel binding", required)
        if value["formatVersion"] != cls.FORMAT:
            raise ConversationContractError("unsupported channel binding format")
        if value["channel"] not in CHANNELS:
            raise ConversationContractError("channel binding channel is unsupported")
        if value["status"] not in {"active", "revoked"}:
            raise ConversationContractError("channel binding status is unsupported")
        return cls(
            _identifier(value["bindingId"], "binding id"),
            _identifier(value["conversationId"], "binding conversation id"),
            _identifier(value["applicationId"], "binding application id"),
            _identifier(value["instanceId"], "binding instance id"),
            str(value["channel"]),
            _identifier(value["ownerParticipantId"], "binding owner participant id"),
            _digest(value["externalIdentityDigest"], "external identity digest"),
            _digest(value["externalConversationDigest"], "external conversation digest"),
            str(value["status"]),
            _timestamp(value["createdAt"], "binding created at"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "bindingId": self.binding_id,
            "conversationId": self.conversation_id,
            "applicationId": self.application_id,
            "instanceId": self.instance_id,
            "channel": self.channel,
            "ownerParticipantId": self.owner_participant_id,
            "externalIdentityDigest": self.external_identity_digest,
            "externalConversationDigest": self.external_conversation_digest,
            "status": self.status,
            "createdAt": self.created_at,
        }


@dataclass(frozen=True)
class ConversationContextPolicy:
    FORMAT = "stateport.conversation-context-policy/v1"

    included_categories: tuple[str, ...]
    excluded_categories: tuple[str, ...]
    authority: str
    state_proposal_mode: str
    transcript_retention: str

    @classmethod
    def from_dict(cls, source: object) -> "ConversationContextPolicy":
        value = _mapping(source, "conversation context policy")
        required = {"formatVersion", "includedCategories", "excludedCategories", "authority", "stateProposalMode", "transcriptRetention"}
        _keys(value, "conversation context policy", required)
        if value["formatVersion"] != cls.FORMAT:
            raise ConversationContractError("unsupported conversation context policy format")
        included = _strings(value["includedCategories"], "included context categories", nonempty=True)
        excluded = _strings(value["excludedCategories"], "excluded context categories")
        if set(included) & set(excluded):
            raise ConversationContractError("context categories cannot be both included and excluded")
        if value["authority"] != "operational_noncanonical":
            raise ConversationContractError("conversation transcript must remain operational and noncanonical")
        if value["stateProposalMode"] != "typed_transaction_only":
            raise ConversationContractError("canonical changes require typed state proposals")
        if value["transcriptRetention"] not in {"memory_only", "explicit_capture"}:
            raise ConversationContractError("transcript retention mode is unsupported")
        return cls(included, excluded, str(value["authority"]), str(value["stateProposalMode"]), str(value["transcriptRetention"]))

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "includedCategories": list(self.included_categories),
            "excludedCategories": list(self.excluded_categories),
            "authority": self.authority,
            "stateProposalMode": self.state_proposal_mode,
            "transcriptRetention": self.transcript_retention,
        }


@dataclass(frozen=True)
class CompressionPolicy:
    FORMAT = "stateport.compression-policy/v1"

    mode: str
    trigger_ratio: float
    preserve: tuple[str, ...]

    @classmethod
    def from_dict(cls, source: object) -> "CompressionPolicy":
        value = _mapping(source, "compression policy")
        _keys(value, "compression policy", {"formatVersion", "mode", "triggerRatio", "preserve"})
        if value["formatVersion"] != cls.FORMAT:
            raise ConversationContractError("unsupported compression policy format")
        if value["mode"] not in {"off", "manual", "automatic"}:
            raise ConversationContractError("compression policy mode is unsupported")
        return cls(str(value["mode"]), _ratio(value["triggerRatio"], "compression trigger ratio"), _strings(value["preserve"], "compression preserve categories", nonempty=True))

    def to_dict(self) -> dict[str, Any]:
        return {"formatVersion": self.FORMAT, "mode": self.mode, "triggerRatio": self.trigger_ratio, "preserve": list(self.preserve)}


@dataclass(frozen=True)
class HandoffPolicy:
    FORMAT = "stateport.handoff-policy/v1"

    mode: str
    trigger_ratio: float
    create_artifact: bool
    require_receipt: bool

    @classmethod
    def from_dict(cls, source: object) -> "HandoffPolicy":
        value = _mapping(source, "handoff policy")
        _keys(value, "handoff policy", {"formatVersion", "mode", "triggerRatio", "createArtifact", "requireReceipt"})
        if value["formatVersion"] != cls.FORMAT:
            raise ConversationContractError("unsupported handoff policy format")
        if value["mode"] not in {"off", "manual", "automatic"}:
            raise ConversationContractError("handoff policy mode is unsupported")
        if not isinstance(value["createArtifact"], bool) or not isinstance(value["requireReceipt"], bool):
            raise ConversationContractError("handoff artifact and receipt settings must be boolean")
        if value["mode"] == "automatic" and (not value["createArtifact"] or not value["requireReceipt"]):
            raise ConversationContractError("automatic handoff requires an artifact and receipt")
        return cls(str(value["mode"]), _ratio(value["triggerRatio"], "handoff trigger ratio"), value["createArtifact"], value["requireReceipt"])

    def to_dict(self) -> dict[str, Any]:
        return {"formatVersion": self.FORMAT, "mode": self.mode, "triggerRatio": self.trigger_ratio, "createArtifact": self.create_artifact, "requireReceipt": self.require_receipt}


@dataclass(frozen=True)
class ConversationThread:
    FORMAT = "stateport.conversation-thread/v1"

    conversation_id: str
    application_id: str
    instance_id: str
    title: str
    created_by: str
    created_at: str
    status: str
    delivery_policy: str
    context_policy: ConversationContextPolicy
    compression_policy: CompressionPolicy
    handoff_policy: HandoffPolicy

    @classmethod
    def from_dict(cls, source: object) -> "ConversationThread":
        _no_secret_fields(source)
        value = _mapping(source, "conversation thread")
        required = {
            "formatVersion", "conversationId", "applicationId", "instanceId", "title", "createdBy", "createdAt",
            "status", "deliveryPolicy", "contextPolicy", "compressionPolicy", "handoffPolicy",
        }
        _keys(value, "conversation thread", required)
        if value["formatVersion"] != cls.FORMAT:
            raise ConversationContractError("unsupported conversation thread format")
        if value["status"] not in {"active", "closed"}:
            raise ConversationContractError("conversation thread status is unsupported")
        if value["deliveryPolicy"] not in DELIVERY_POLICIES:
            raise ConversationContractError("conversation delivery policy is unsupported")
        return cls(
            _identifier(value["conversationId"], "conversation id"),
            _identifier(value["applicationId"], "conversation application id"),
            _identifier(value["instanceId"], "conversation instance id"),
            _text(value["title"], "conversation title", maximum=120),
            _identifier(value["createdBy"], "conversation creator"),
            _timestamp(value["createdAt"], "conversation created at"),
            str(value["status"]),
            str(value["deliveryPolicy"]),
            ConversationContextPolicy.from_dict(value["contextPolicy"]),
            CompressionPolicy.from_dict(value["compressionPolicy"]),
            HandoffPolicy.from_dict(value["handoffPolicy"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "conversationId": self.conversation_id,
            "applicationId": self.application_id,
            "instanceId": self.instance_id,
            "title": self.title,
            "createdBy": self.created_by,
            "createdAt": self.created_at,
            "status": self.status,
            "deliveryPolicy": self.delivery_policy,
            "contextPolicy": self.context_policy.to_dict(),
            "compressionPolicy": self.compression_policy.to_dict(),
            "handoffPolicy": self.handoff_policy.to_dict(),
        }


@dataclass(frozen=True)
class AttachmentMetadata:
    attachment_id: str
    name: str
    media_type: str
    size_bytes: int
    digest: str

    @classmethod
    def from_dict(cls, source: object) -> "AttachmentMetadata":
        value = _mapping(source, "attachment metadata")
        _keys(value, "attachment metadata", {"attachmentId", "name", "mediaType", "sizeBytes", "digest"})
        name = _text(value["name"], "attachment name", maximum=160)
        if "/" in name or "\\" in name or name in {".", ".."}:
            raise ConversationContractError("attachment name must not contain a path")
        media_type = _text(value["mediaType"], "attachment media type", maximum=192).lower()
        if not _MEDIA_TYPE.fullmatch(media_type):
            raise ConversationContractError("attachment media type is invalid")
        size = value["sizeBytes"]
        if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= 25 * 1024 * 1024:
            raise ConversationContractError("attachment size is invalid")
        return cls(_identifier(value["attachmentId"], "attachment id"), name, media_type, size, _digest(value["digest"], "attachment digest"))

    def to_dict(self) -> dict[str, Any]:
        return {"attachmentId": self.attachment_id, "name": self.name, "mediaType": self.media_type, "sizeBytes": self.size_bytes, "digest": self.digest}


@dataclass(frozen=True)
class MessageEnvelope:
    FORMAT = "stateport.message-envelope/v1"

    message_id: str
    conversation_id: str
    application_id: str
    instance_id: str
    sender_participant_id: str
    source_channel: str
    source_binding_id: str | None
    sequence: int
    created_at: str
    observed_at: str
    kind: str
    body: str
    reply_to_message_id: str | None
    attachments: tuple[AttachmentMetadata, ...]
    external_identity: ExternalMessageIdentity | None
    authority: str
    canonical_state_effect: str
    proposal_reference: str | None
    collapsed_by_default: bool
    deduplication_key: str

    @classmethod
    def from_dict(cls, source: object) -> "MessageEnvelope":
        _no_secret_fields(source)
        value = _mapping(source, "message envelope")
        required = {
            "formatVersion", "messageId", "conversationId", "applicationId", "instanceId", "senderParticipantId",
            "sourceChannel", "sourceBindingId", "sequence", "createdAt", "observedAt", "kind", "body",
            "replyToMessageId", "attachments", "externalIdentity", "authority", "canonicalStateEffect",
            "proposalReference", "collapsedByDefault", "deduplicationKey",
        }
        _keys(value, "message envelope", required)
        if value["formatVersion"] != cls.FORMAT:
            raise ConversationContractError("unsupported message envelope format")
        if value["sourceChannel"] not in CHANNELS:
            raise ConversationContractError("message source channel is unsupported")
        if value["kind"] not in MESSAGE_KINDS:
            raise ConversationContractError("message kind is unsupported")
        sequence = value["sequence"]
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence <= 0:
            raise ConversationContractError("message sequence must be a positive integer")
        if not isinstance(value["attachments"], list) or len(value["attachments"]) > 16:
            raise ConversationContractError("message attachments must be a bounded array")
        attachments = tuple(AttachmentMetadata.from_dict(item) for item in value["attachments"])
        if len({item.attachment_id for item in attachments}) != len(attachments):
            raise ConversationContractError("attachment identities must be unique")
        external = None if value["externalIdentity"] is None else ExternalMessageIdentity.from_dict(value["externalIdentity"])
        source_binding = None if value["sourceBindingId"] is None else _identifier(value["sourceBindingId"], "message source binding id")
        reply = None if value["replyToMessageId"] is None else _identifier(value["replyToMessageId"], "message reply identity")
        proposal = None if value["proposalReference"] is None else _identifier(value["proposalReference"], "message proposal reference")
        if value["authority"] != "operational_noncanonical" or value["canonicalStateEffect"] != "none":
            raise ConversationContractError("conversation messages cannot be canonical state")
        if not isinstance(value["collapsedByDefault"], bool):
            raise ConversationContractError("message collapsedByDefault must be boolean")
        if value["kind"] in {"run_event", "tool_event"} and not value["collapsedByDefault"]:
            raise ConversationContractError("run and tool events must be collapsed by default")
        if value["kind"] == "state_proposal_reference" and proposal is None:
            raise ConversationContractError("state proposal messages require a separate proposal reference")
        if value["kind"] != "state_proposal_reference" and proposal is not None:
            raise ConversationContractError("only state proposal reference messages may carry a proposal reference")
        return cls(
            _identifier(value["messageId"], "message id"),
            _identifier(value["conversationId"], "message conversation id"),
            _identifier(value["applicationId"], "message application id"),
            _identifier(value["instanceId"], "message instance id"),
            _identifier(value["senderParticipantId"], "message sender participant id"),
            str(value["sourceChannel"]),
            source_binding,
            sequence,
            _timestamp(value["createdAt"], "message created at"),
            _timestamp(value["observedAt"], "message observed at"),
            str(value["kind"]),
            _text(value["body"], "message body", maximum=16 * 1024),
            reply,
            attachments,
            external,
            str(value["authority"]),
            str(value["canonicalStateEffect"]),
            proposal,
            value["collapsedByDefault"],
            _digest(value["deduplicationKey"], "message deduplication key"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "messageId": self.message_id,
            "conversationId": self.conversation_id,
            "applicationId": self.application_id,
            "instanceId": self.instance_id,
            "senderParticipantId": self.sender_participant_id,
            "sourceChannel": self.source_channel,
            "sourceBindingId": self.source_binding_id,
            "sequence": self.sequence,
            "createdAt": self.created_at,
            "observedAt": self.observed_at,
            "kind": self.kind,
            "body": self.body,
            "replyToMessageId": self.reply_to_message_id,
            "attachments": [item.to_dict() for item in self.attachments],
            "externalIdentity": self.external_identity.to_dict() if self.external_identity else None,
            "authority": self.authority,
            "canonicalStateEffect": self.canonical_state_effect,
            "proposalReference": self.proposal_reference,
            "collapsedByDefault": self.collapsed_by_default,
            "deduplicationKey": self.deduplication_key,
        }


@dataclass(frozen=True)
class TranscriptRetentionStatus:
    """Explicit retention state; automatic expiry is deliberately not executed here."""

    FORMAT = "stateport.transcript-retention-status/v1"

    conversation_id: str
    application_id: str
    instance_id: str
    retention: str
    storage: str
    status: str
    message_count: int
    expiry_status: str
    expires_at: None
    evaluated_at: str

    @classmethod
    def from_dict(cls, source: object) -> "TranscriptRetentionStatus":
        _no_secret_fields(source)
        value = _mapping(source, "transcript retention status")
        _keys(
            value,
            "transcript retention status",
            {
                "formatVersion", "conversationId", "applicationId", "instanceId", "retention", "storage",
                "status", "messageCount", "expiryStatus", "expiresAt", "evaluatedAt",
            },
        )
        if value["formatVersion"] != cls.FORMAT:
            raise ConversationContractError("unsupported transcript retention status format")
        if value["retention"] not in {"memory_only", "explicit_capture"}:
            raise ConversationContractError("transcript retention status has an unsupported retention mode")
        expected_storage = "process_memory" if value["retention"] == "memory_only" else "durable_local"
        if value["storage"] != expected_storage:
            raise ConversationContractError("transcript retention storage does not match retention mode")
        if value["status"] not in {"empty", "retained"}:
            raise ConversationContractError("transcript retention status is unsupported")
        if isinstance(value["messageCount"], bool) or not isinstance(value["messageCount"], int) or value["messageCount"] < 0:
            raise ConversationContractError("transcript retention message count must be non-negative")
        if (value["status"] == "empty") != (value["messageCount"] == 0):
            raise ConversationContractError("transcript retention status does not match message count")
        if value["expiryStatus"] != "no_automatic_expiry_scheduled" or value["expiresAt"] is not None:
            raise ConversationContractError("transcript expiry execution is not supported")
        return cls(
            _identifier(value["conversationId"], "retention conversation id"),
            _identifier(value["applicationId"], "retention application id"),
            _identifier(value["instanceId"], "retention instance id"),
            str(value["retention"]),
            str(value["storage"]),
            str(value["status"]),
            value["messageCount"],
            str(value["expiryStatus"]),
            None,
            _timestamp(value["evaluatedAt"], "retention evaluated at"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "conversationId": self.conversation_id,
            "applicationId": self.application_id,
            "instanceId": self.instance_id,
            "retention": self.retention,
            "storage": self.storage,
            "status": self.status,
            "messageCount": self.message_count,
            "expiryStatus": self.expiry_status,
            "expiresAt": self.expires_at,
            "evaluatedAt": self.evaluated_at,
        }


@dataclass(frozen=True)
class TranscriptLifecycleReceipt:
    """Durable structural evidence for transcript export or erasure."""

    FORMAT = "stateport.transcript-lifecycle-receipt/v1"

    receipt_id: str
    request_id: str
    operation: str
    application_id: str
    instance_id: str
    conversation_id: str
    performed_by: str
    occurred_at: str
    thread_identity: str
    binding_policy: str
    removed: Mapping[str, int]
    authority: str
    canonical_state_effect: str

    @classmethod
    def from_dict(cls, source: object) -> "TranscriptLifecycleReceipt":
        _no_secret_fields(source)
        value = _mapping(source, "transcript lifecycle receipt")
        _keys(
            value,
            "transcript lifecycle receipt",
            {
                "formatVersion", "receiptId", "requestId", "operation", "applicationId", "instanceId",
                "conversationId", "performedBy", "occurredAt", "threadIdentity", "bindingPolicy", "removed",
                "authority", "canonicalStateEffect",
            },
        )
        if value["formatVersion"] != cls.FORMAT:
            raise ConversationContractError("unsupported transcript lifecycle receipt format")
        if value["operation"] not in {"clear", "export"}:
            raise ConversationContractError("transcript lifecycle operation is unsupported")
        expected_thread = "preserved"
        expected_binding = "preserved"
        if value["threadIdentity"] != expected_thread or value["bindingPolicy"] != expected_binding:
            raise ConversationContractError("transcript lifecycle identity policy does not match operation")
        removed_value = _mapping(value["removed"], "transcript lifecycle removed counts")
        removed_keys = {"messages", "deliveries", "deduplicationEntries", "proposals", "echoGuards"}
        _keys(removed_value, "transcript lifecycle removed counts", removed_keys)
        removed: dict[str, int] = {}
        for key in removed_keys:
            count = removed_value[key]
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise ConversationContractError("transcript lifecycle removed counts must be non-negative integers")
            removed[key] = count
        if value["authority"] != "operational_noncanonical" or value["canonicalStateEffect"] != "none":
            raise ConversationContractError("transcript lifecycle cannot affect canonical state")
        return cls(
            _identifier(value["receiptId"], "lifecycle receipt id"),
            _identifier(value["requestId"], "lifecycle request id"),
            str(value["operation"]),
            _identifier(value["applicationId"], "lifecycle application id"),
            _identifier(value["instanceId"], "lifecycle instance id"),
            _identifier(value["conversationId"], "lifecycle conversation id"),
            _identifier(value["performedBy"], "lifecycle participant id"),
            _timestamp(value["occurredAt"], "lifecycle occurred at"),
            str(value["threadIdentity"]),
            str(value["bindingPolicy"]),
            removed,
            str(value["authority"]),
            str(value["canonicalStateEffect"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "receiptId": self.receipt_id,
            "requestId": self.request_id,
            "operation": self.operation,
            "applicationId": self.application_id,
            "instanceId": self.instance_id,
            "conversationId": self.conversation_id,
            "performedBy": self.performed_by,
            "occurredAt": self.occurred_at,
            "threadIdentity": self.thread_identity,
            "bindingPolicy": self.binding_policy,
            "removed": dict(self.removed),
            "authority": self.authority,
            "canonicalStateEffect": self.canonical_state_effect,
        }


@dataclass(frozen=True)
class TranscriptExport:
    """A portable transcript view limited to metadata and message envelopes."""

    FORMAT = "stateport.transcript-export/v1"

    export_id: str
    generated_at: str
    metadata: Mapping[str, Any]
    messages: tuple[MessageEnvelope, ...]

    @classmethod
    def from_dict(cls, source: object) -> "TranscriptExport":
        _no_secret_fields(source)
        value = _mapping(source, "transcript export")
        _keys(value, "transcript export", {"formatVersion", "exportId", "generatedAt", "metadata", "messages"})
        if value["formatVersion"] != cls.FORMAT:
            raise ConversationContractError("unsupported transcript export format")
        metadata = _mapping(value["metadata"], "transcript export metadata")
        _keys(
            metadata,
            "transcript export metadata",
            {"conversationId", "applicationId", "instanceId", "threadStatus", "retentionStatus"},
        )
        if metadata["threadStatus"] not in {"active", "closed"}:
            raise ConversationContractError("transcript export thread status is unsupported")
        retention = TranscriptRetentionStatus.from_dict(metadata["retentionStatus"])
        if (
            retention.conversation_id != metadata["conversationId"]
            or retention.application_id != metadata["applicationId"]
            or retention.instance_id != metadata["instanceId"]
        ):
            raise ConversationContractError("transcript export retention scope is inconsistent")
        if not isinstance(value["messages"], list) or len(value["messages"]) > 10000:
            raise ConversationContractError("transcript export messages must be bounded")
        messages = tuple(MessageEnvelope.from_dict(item) for item in value["messages"])
        if len(messages) != retention.message_count:
            raise ConversationContractError("transcript export message count is inconsistent")
        for position, message in enumerate(messages, start=1):
            if (
                message.sequence != position
                or message.conversation_id != retention.conversation_id
                or message.application_id != retention.application_id
                or message.instance_id != retention.instance_id
            ):
                raise ConversationContractError("transcript export message scope is inconsistent")
        checked_metadata = {
            "conversationId": _identifier(metadata["conversationId"], "export conversation id"),
            "applicationId": _identifier(metadata["applicationId"], "export application id"),
            "instanceId": _identifier(metadata["instanceId"], "export instance id"),
            "threadStatus": str(metadata["threadStatus"]),
            "retentionStatus": retention.to_dict(),
        }
        return cls(
            _identifier(value["exportId"], "transcript export id"),
            _timestamp(value["generatedAt"], "transcript export generated at"),
            checked_metadata,
            messages,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "exportId": self.export_id,
            "generatedAt": self.generated_at,
            "metadata": dict(self.metadata),
            "messages": [item.to_dict() for item in self.messages],
        }


@dataclass(frozen=True)
class ConversationCursor:
    FORMAT = "stateport.conversation-cursor/v1"

    conversation_id: str
    after_sequence: int
    thread_revision: int
    issued_at: str

    @classmethod
    def from_dict(cls, source: object) -> "ConversationCursor":
        value = _mapping(source, "conversation cursor")
        _keys(value, "conversation cursor", {"formatVersion", "conversationId", "afterSequence", "threadRevision", "issuedAt"})
        if value["formatVersion"] != cls.FORMAT:
            raise ConversationContractError("unsupported conversation cursor format")
        for key in ("afterSequence", "threadRevision"):
            if isinstance(value[key], bool) or not isinstance(value[key], int) or value[key] < 0:
                raise ConversationContractError(f"cursor {key} must be a non-negative integer")
        if value["afterSequence"] > value["threadRevision"]:
            raise ConversationContractError("cursor sequence cannot exceed its thread revision")
        return cls(_identifier(value["conversationId"], "cursor conversation id"), value["afterSequence"], value["threadRevision"], _timestamp(value["issuedAt"], "cursor issued at"))

    def to_dict(self) -> dict[str, Any]:
        return {"formatVersion": self.FORMAT, "conversationId": self.conversation_id, "afterSequence": self.after_sequence, "threadRevision": self.thread_revision, "issuedAt": self.issued_at}


@dataclass(frozen=True)
class DeliveryReceipt:
    FORMAT = "stateport.delivery-receipt/v1"

    delivery_id: str
    message_id: str
    conversation_id: str
    binding_id: str
    channel: str
    delivery_policy: str
    delivery_mode: str
    status: str
    created_at: str
    external_message_id: str | None
    echo_guard: str
    failure_reason: str | None

    @classmethod
    def from_dict(cls, source: object) -> "DeliveryReceipt":
        _no_secret_fields(source)
        value = _mapping(source, "delivery receipt")
        required = {
            "formatVersion", "deliveryId", "messageId", "conversationId", "bindingId", "channel", "deliveryPolicy",
            "deliveryMode", "status", "createdAt", "externalMessageId", "echoGuard", "failureReason",
        }
        _keys(value, "delivery receipt", required)
        if value["formatVersion"] != cls.FORMAT:
            raise ConversationContractError("unsupported delivery receipt format")
        if value["channel"] not in CHANNELS or value["deliveryPolicy"] not in DELIVERY_POLICIES:
            raise ConversationContractError("delivery channel or policy is unsupported")
        if value["deliveryMode"] not in {"full", "notification", "archive", "suppressed"}:
            raise ConversationContractError("delivery mode is unsupported")
        if value["status"] not in {"planned", "delivered", "failed", "suppressed"}:
            raise ConversationContractError("delivery status is unsupported")
        external_id = None if value["externalMessageId"] is None else _identifier(value["externalMessageId"], "delivery external message id")
        failure = None if value["failureReason"] is None else _identifier(value["failureReason"], "delivery failure reason")
        if value["status"] == "delivered" and external_id is None:
            raise ConversationContractError("delivered receipt requires an external message identity")
        if value["status"] == "failed" and failure is None:
            raise ConversationContractError("failed receipt requires a bounded failure reason")
        return cls(
            _identifier(value["deliveryId"], "delivery id"),
            _identifier(value["messageId"], "delivery message id"),
            _identifier(value["conversationId"], "delivery conversation id"),
            _identifier(value["bindingId"], "delivery binding id"),
            str(value["channel"]),
            str(value["deliveryPolicy"]),
            str(value["deliveryMode"]),
            str(value["status"]),
            _timestamp(value["createdAt"], "delivery created at"),
            external_id,
            _digest(value["echoGuard"], "delivery echo guard"),
            failure,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "deliveryId": self.delivery_id,
            "messageId": self.message_id,
            "conversationId": self.conversation_id,
            "bindingId": self.binding_id,
            "channel": self.channel,
            "deliveryPolicy": self.delivery_policy,
            "deliveryMode": self.delivery_mode,
            "status": self.status,
            "createdAt": self.created_at,
            "externalMessageId": self.external_message_id,
            "echoGuard": self.echo_guard,
            "failureReason": self.failure_reason,
        }


@dataclass(frozen=True)
class StateProposal:
    """A noncanonical typed proposal reference kept outside transcript bodies."""

    FORMAT = "stateport.conversation-state-proposal/v1"

    proposal_id: str
    conversation_id: str
    application_id: str
    instance_id: str
    originating_message_id: str
    base_identity: str
    payload_digest: str
    status: str
    created_at: str
    authority: str
    mutation_boundary: str

    @classmethod
    def from_dict(cls, source: object) -> "StateProposal":
        _no_secret_fields(source)
        value = _mapping(source, "conversation state proposal")
        required = {
            "formatVersion", "proposalId", "conversationId", "applicationId", "instanceId", "originatingMessageId",
            "baseIdentity", "payloadDigest", "status", "createdAt", "authority", "mutationBoundary",
        }
        _keys(value, "conversation state proposal", required)
        if value["formatVersion"] != cls.FORMAT:
            raise ConversationContractError("unsupported conversation state proposal format")
        if value["status"] != "proposed" or value["authority"] != "proposal_noncanonical" or value["mutationBoundary"] != "typed_transaction_required":
            raise ConversationContractError("state proposal cannot bypass canonical transaction authority")
        return cls(
            _identifier(value["proposalId"], "proposal id"),
            _identifier(value["conversationId"], "proposal conversation id"),
            _identifier(value["applicationId"], "proposal application id"),
            _identifier(value["instanceId"], "proposal instance id"),
            _identifier(value["originatingMessageId"], "proposal originating message id"),
            _digest(value["baseIdentity"], "proposal base identity"),
            _digest(value["payloadDigest"], "proposal payload digest"),
            str(value["status"]),
            _timestamp(value["createdAt"], "proposal created at"),
            str(value["authority"]),
            str(value["mutationBoundary"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "proposalId": self.proposal_id,
            "conversationId": self.conversation_id,
            "applicationId": self.application_id,
            "instanceId": self.instance_id,
            "originatingMessageId": self.originating_message_id,
            "baseIdentity": self.base_identity,
            "payloadDigest": self.payload_digest,
            "status": self.status,
            "createdAt": self.created_at,
            "authority": self.authority,
            "mutationBoundary": self.mutation_boundary,
        }
