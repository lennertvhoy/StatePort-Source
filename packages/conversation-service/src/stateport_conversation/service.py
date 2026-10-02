"""Channel-neutral conversation coordination with an optional durable store.

Without ``store_path`` the service is intentionally in-memory for lightweight
fixtures.  A supplied store is an operational SQLite transcript only: it never
contains provider credentials, provider reasoning, or canonical application
state.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import copy
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
from threading import RLock
from typing import Callable, Iterable, Sequence

from .adapters import NormalizedInbound
from .contracts import (
    CHANNELS,
    DELIVERY_POLICIES,
    ChannelBinding,
    CompressionPolicy,
    ConversationContextPolicy,
    ConversationContractError,
    ConversationCursor,
    ConversationThread,
    DeliveryReceipt,
    ExternalMessageIdentity,
    HandoffPolicy,
    MessageEnvelope,
    ParticipantIdentity,
    StateProposal,
    TranscriptExport,
    TranscriptLifecycleReceipt,
    TranscriptRetentionStatus,
    canonical_digest,
)


class ConversationAuthorizationError(PermissionError):
    """Raised when a participant crosses an application or channel scope."""


class ConversationNotFoundError(KeyError):
    """Raised when an operational conversation identity is unknown."""


class ConversationConflictError(ValueError):
    """Raised when an immutable conversation identity is reused differently."""


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def default_context_policy(*, transcript_retention: str = "memory_only") -> ConversationContextPolicy:
    return ConversationContextPolicy.from_dict(
        {
            "formatVersion": ConversationContextPolicy.FORMAT,
            "includedCategories": ["active_application", "active_task", "approvals", "receipts"],
            "excludedCategories": ["credentials", "raw_tool_logs", "unapproved_state_proposals"],
            "authority": "operational_noncanonical",
            "stateProposalMode": "typed_transaction_only",
            "transcriptRetention": transcript_retention,
        }
    )


def default_compression_policy() -> CompressionPolicy:
    # Contract only.  This service does not execute compression.
    return CompressionPolicy.from_dict(
        {
            "formatVersion": CompressionPolicy.FORMAT,
            "mode": "automatic",
            "triggerRatio": 0.72,
            "preserve": ["active_task", "decisions", "approvals", "unresolved_risks", "exact_git_identities"],
        }
    )


def default_handoff_policy() -> HandoffPolicy:
    # Contract only.  The context-lifecycle implementation owns artifact creation.
    return HandoffPolicy.from_dict(
        {
            "formatVersion": HandoffPolicy.FORMAT,
            "mode": "automatic",
            "triggerRatio": 0.88,
            "createArtifact": True,
            "requireReceipt": True,
        }
    )


@dataclass(frozen=True)
class IngestResult:
    status: str
    message: MessageEnvelope | None
    duplicate: bool
    reason: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "message": self.message.to_dict() if self.message else None,
            "duplicate": self.duplicate,
            "reason": self.reason,
        }


class ConversationService:
    """Serialize message identity, authorization, ordering, and delivery plans."""

    PRESENTATION_FORMAT = "stateport.conversation-presentation/v1"

    STORE_FORMAT = "stateport.conversation-store/v1"

    _LIFECYCLE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")

    def __init__(
        self,
        *,
        clock: Callable[[], str] = utc_now,
        identity_seed: str | None = None,
        store_path: str | Path | None = None,
    ) -> None:
        self._clock = clock
        self._identity_seed = identity_seed or secrets.token_hex(16)
        self._lock = RLock()
        self._counter = 0
        self._participants: dict[str, ParticipantIdentity] = {}
        self._threads: dict[str, ConversationThread] = {}
        self._threads_by_scope: dict[tuple[str, str], str] = {}
        self._bindings: dict[str, ChannelBinding] = {}
        self._binding_scope: dict[tuple[str, str], str] = {}
        self._messages: dict[str, list[MessageEnvelope]] = {}
        self._message_index: dict[str, MessageEnvelope] = {}
        self._external_index: dict[tuple[str, str], str] = {}
        self._provider_event_index: dict[tuple[str, str, str], str] = {}
        self._deliveries: dict[str, DeliveryReceipt] = {}
        self._delivery_index: dict[tuple[str, str], str] = {}
        self._outbound_external: dict[tuple[str, str], str] = {}
        self._echo_guards: set[str] = set()
        self._proposals: dict[str, StateProposal] = {}
        self._lifecycle_receipts: dict[str, TranscriptLifecycleReceipt] = {}
        self._lifecycle_by_request: dict[str, str] = {}
        self._store: sqlite3.Connection | None = None
        self._store_path: Path | None = None
        self._durable_snapshot: dict[str, object] | None = None
        if store_path is not None:
            self._open_store(Path(store_path), identity_seed=identity_seed)

    def _open_store(self, path: Path, *, identity_seed: str | None) -> None:
        """Open and completely validate a local operational SQLite store."""

        try:
            if path.exists() and (not path.is_file() or path.is_symlink()):
                raise ConversationContractError("conversation store path must be a regular file")
            existed = path.exists()
            if existed and path.stat().st_size == 0:
                raise ConversationContractError("conversation store is malformed")
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(path.parent, 0o700)
            connection = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False)
            connection.execute("PRAGMA foreign_keys = ON")
            self._store = connection
            self._store_path = path
            self._create_store_schema()
            metadata = dict(connection.execute("SELECT key, value FROM metadata"))
            if not metadata:
                if existed:
                    raise ConversationContractError("conversation store metadata is missing")
                seed = identity_seed or self._identity_seed
                connection.execute("BEGIN IMMEDIATE")
                try:
                    connection.executemany(
                        "INSERT INTO metadata(key, value) VALUES (?, ?)",
                        (("format", self.STORE_FORMAT), ("identity_seed", seed), ("counter", "0")),
                    )
                    connection.execute("COMMIT")
                except Exception:
                    connection.execute("ROLLBACK")
                    raise
                metadata = {"format": self.STORE_FORMAT, "identity_seed": seed, "counter": "0"}
                os.chmod(path, 0o600)
            if set(metadata) != {"format", "identity_seed", "counter"} or metadata["format"] != self.STORE_FORMAT:
                raise ConversationContractError("conversation store format is unsupported")
            if not metadata["identity_seed"] or len(metadata["identity_seed"]) > 128:
                raise ConversationContractError("conversation store identity seed is invalid")
            if not metadata["counter"].isdigit():
                raise ConversationContractError("conversation store counter is invalid")
            self._identity_seed = metadata["identity_seed"]
            self._counter = int(metadata["counter"])
            self._load_store()
            self._durable_snapshot = self._state_snapshot()
        except (OSError, sqlite3.Error, UnicodeError, json.JSONDecodeError, ConversationContractError) as exc:
            if self._store is not None:
                self._store.close()
            self._store = None
            self._store_path = None
            if isinstance(exc, ConversationContractError):
                raise
            raise ConversationContractError("conversation store is malformed or unavailable") from exc

    def _create_store_schema(self) -> None:
        assert self._store is not None
        self._store.executescript(
            """
            CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS participants (participant_id TEXT PRIMARY KEY, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS threads (conversation_id TEXT PRIMARY KEY, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS bindings (binding_id TEXT PRIMARY KEY, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS messages (message_id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL, sequence INTEGER NOT NULL, payload TEXT NOT NULL, UNIQUE(conversation_id, sequence));
            CREATE TABLE IF NOT EXISTS external_messages (binding_id TEXT NOT NULL, external_message_id TEXT NOT NULL, message_id TEXT NOT NULL, PRIMARY KEY(binding_id, external_message_id));
            CREATE TABLE IF NOT EXISTS provider_events (channel TEXT NOT NULL, binding_id TEXT NOT NULL, provider_event_id TEXT NOT NULL, message_id TEXT NOT NULL, PRIMARY KEY(channel, binding_id, provider_event_id));
            CREATE TABLE IF NOT EXISTS deliveries (delivery_id TEXT PRIMARY KEY, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS outbound_external (binding_id TEXT NOT NULL, external_message_id TEXT NOT NULL, delivery_id TEXT NOT NULL, PRIMARY KEY(binding_id, external_message_id));
            CREATE TABLE IF NOT EXISTS echo_guards (echo_guard TEXT PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS proposals (proposal_id TEXT PRIMARY KEY, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS lifecycle_receipts (receipt_id TEXT PRIMARY KEY, payload TEXT NOT NULL);
            """
        )

    @staticmethod
    def _stored_contract(payload: object, contract: object, label: str):
        if not isinstance(payload, str):
            raise ConversationContractError(f"stored {label} is malformed")
        decoded = json.loads(payload)
        return contract.from_dict(decoded)

    def _load_store(self) -> None:
        """Rebuild all service indexes and reject any inconsistent record."""

        assert self._store is not None
        participants: dict[str, ParticipantIdentity] = {}
        threads: dict[str, ConversationThread] = {}
        bindings: dict[str, ChannelBinding] = {}
        messages: dict[str, list[MessageEnvelope]] = {}
        message_index: dict[str, MessageEnvelope] = {}
        deliveries: dict[str, DeliveryReceipt] = {}
        proposals: dict[str, StateProposal] = {}
        lifecycle_receipts: dict[str, TranscriptLifecycleReceipt] = {}
        for identifier, payload in self._store.execute("SELECT participant_id, payload FROM participants"):
            item = self._stored_contract(payload, ParticipantIdentity, "participant")
            if identifier != item.participant_id or item.participant_id in participants:
                raise ConversationContractError("stored participant identity is inconsistent")
            participants[item.participant_id] = item
        for identifier, payload in self._store.execute("SELECT conversation_id, payload FROM threads"):
            item = self._stored_contract(payload, ConversationThread, "thread")
            if identifier != item.conversation_id or item.created_by not in participants or item.conversation_id in threads:
                raise ConversationContractError("stored conversation thread is inconsistent")
            threads[item.conversation_id] = item
            messages[item.conversation_id] = []
        threads_by_scope: dict[tuple[str, str], str] = {}
        for item in threads.values():
            scope = (item.application_id, item.instance_id)
            if scope in threads_by_scope:
                raise ConversationContractError("stored conversation thread scope is ambiguous")
            threads_by_scope[scope] = item.conversation_id
        for identifier, payload in self._store.execute("SELECT binding_id, payload FROM bindings"):
            item = self._stored_contract(payload, ChannelBinding, "binding")
            thread = threads.get(item.conversation_id)
            if (
                identifier != item.binding_id
                or thread is None
                or item.owner_participant_id not in participants
                or (item.application_id, item.instance_id) != (thread.application_id, thread.instance_id)
                or item.binding_id in bindings
            ):
                raise ConversationContractError("stored channel binding is inconsistent")
            bindings[item.binding_id] = item
        binding_scope: dict[tuple[str, str], str] = {}
        for item in bindings.values():
            scope = (item.channel, item.external_conversation_digest)
            if scope in binding_scope:
                raise ConversationContractError("stored channel binding scope is ambiguous")
            binding_scope[scope] = item.binding_id
        for identifier, conversation_id, sequence, payload in self._store.execute("SELECT message_id, conversation_id, sequence, payload FROM messages ORDER BY conversation_id, sequence"):
            item = self._stored_contract(payload, MessageEnvelope, "message")
            thread = threads.get(conversation_id)
            if (
                identifier != item.message_id
                or conversation_id != item.conversation_id
                or sequence != item.sequence
                or thread is None
                or item.sender_participant_id not in participants
                or (item.application_id, item.instance_id) != (thread.application_id, thread.instance_id)
                or item.sequence != len(messages[conversation_id]) + 1
                or item.message_id in message_index
            ):
                raise ConversationContractError("stored message is inconsistent")
            if item.source_binding_id is not None:
                binding = bindings.get(item.source_binding_id)
                if binding is None or binding.conversation_id != conversation_id or binding.channel != item.source_channel:
                    raise ConversationContractError("stored message source binding is inconsistent")
            if item.reply_to_message_id is not None and item.reply_to_message_id not in message_index:
                raise ConversationContractError("stored message reply reference is inconsistent")
            messages[conversation_id].append(item)
            message_index[item.message_id] = item
        for identifier, payload in self._store.execute("SELECT delivery_id, payload FROM deliveries"):
            item = self._stored_contract(payload, DeliveryReceipt, "delivery receipt")
            message = message_index.get(item.message_id)
            binding = bindings.get(item.binding_id)
            if (
                identifier != item.delivery_id
                or message is None
                or binding is None
                or item.conversation_id != message.conversation_id
                or item.conversation_id != binding.conversation_id
                or item.channel != binding.channel
                or item.delivery_policy != threads[item.conversation_id].delivery_policy
                or item.delivery_id in deliveries
            ):
                raise ConversationContractError("stored delivery receipt is inconsistent")
            deliveries[item.delivery_id] = item
        for identifier, payload in self._store.execute("SELECT proposal_id, payload FROM proposals"):
            item = self._stored_contract(payload, StateProposal, "state proposal")
            thread = threads.get(item.conversation_id)
            origin = message_index.get(item.originating_message_id)
            if (
                identifier != item.proposal_id
                or thread is None
                or origin is None
                or origin.conversation_id != item.conversation_id
                or (item.application_id, item.instance_id) != (thread.application_id, thread.instance_id)
                or item.proposal_id in proposals
            ):
                raise ConversationContractError("stored state proposal is inconsistent")
            proposals[item.proposal_id] = item
        for identifier, payload in self._store.execute("SELECT receipt_id, payload FROM lifecycle_receipts"):
            item = self._stored_contract(payload, TranscriptLifecycleReceipt, "transcript lifecycle receipt")
            if (
                identifier != item.receipt_id
                or item.performed_by not in participants
                or item.receipt_id in lifecycle_receipts
            ):
                raise ConversationContractError("stored transcript lifecycle receipt is inconsistent")
            current_thread = threads.get(item.conversation_id)
            current_bindings = [binding for binding in bindings.values() if binding.conversation_id == item.conversation_id]
            if item.operation == "delete":
                if current_thread is not None or current_bindings:
                    raise ConversationContractError("stored deleted transcript identity is inconsistent")
            elif current_thread is not None and (
                current_thread.application_id != item.application_id or current_thread.instance_id != item.instance_id
            ):
                raise ConversationContractError("stored cleared transcript scope is inconsistent")
            lifecycle_receipts[item.receipt_id] = item

        external_index = {
            (item.external_identity.binding_id, item.external_identity.external_message_id): item.message_id
            for item in message_index.values()
            if item.external_identity is not None and item.external_identity.direction == "inbound"
        }
        if len(external_index) != sum(item.external_identity is not None for item in message_index.values()):
            raise ConversationContractError("stored inbound external identities are ambiguous")
        persisted_external = {(binding_id, external_id): message_id for binding_id, external_id, message_id in self._store.execute("SELECT binding_id, external_message_id, message_id FROM external_messages")}
        if persisted_external != external_index:
            raise ConversationContractError("stored external deduplication index is inconsistent")
        provider_event_index: dict[tuple[str, str, str], str] = {}
        for channel, binding_id, event_id, message_id in self._store.execute("SELECT channel, binding_id, provider_event_id, message_id FROM provider_events"):
            binding = bindings.get(binding_id)
            message = message_index.get(message_id)
            if (
                not isinstance(event_id, str)
                or not event_id
                or len(event_id) > 256
                or binding is None
                or message is None
                or channel != binding.channel
                or message.external_identity is None
                or message.external_identity.binding_id != binding_id
            ):
                raise ConversationContractError("stored provider deduplication index is inconsistent")
            provider_event_index[(channel, binding_id, event_id)] = message_id
        if len(provider_event_index) != len(external_index) or set(provider_event_index.values()) != set(external_index.values()):
            raise ConversationContractError("stored provider deduplication index is incomplete")
        delivery_index: dict[tuple[str, str], str] = {}
        for item in deliveries.values():
            key = (item.message_id, item.binding_id)
            if key in delivery_index:
                raise ConversationContractError("stored delivery index is ambiguous")
            delivery_index[key] = item.delivery_id
        outbound_external = {
            (item.binding_id, item.external_message_id): item.delivery_id
            for item in deliveries.values()
            if item.status == "delivered" and item.external_message_id is not None
        }
        persisted_outbound = {(binding_id, external_id): delivery_id for binding_id, external_id, delivery_id in self._store.execute("SELECT binding_id, external_message_id, delivery_id FROM outbound_external")}
        if persisted_outbound != outbound_external or set(outbound_external) & set(external_index):
            raise ConversationContractError("stored outbound deduplication index is inconsistent")
        echo_guards = {item.echo_guard for item in deliveries.values() if item.status == "delivered"}
        persisted_echoes = {item[0] for item in self._store.execute("SELECT echo_guard FROM echo_guards")}
        if persisted_echoes != echo_guards:
            raise ConversationContractError("stored echo guard index is inconsistent")
        lifecycle_by_request: dict[str, str] = {}
        for item in lifecycle_receipts.values():
            if item.request_id in lifecycle_by_request:
                raise ConversationContractError("stored transcript lifecycle request is ambiguous")
            lifecycle_by_request[item.request_id] = item.receipt_id

        self._participants = participants
        self._threads = threads
        self._threads_by_scope = threads_by_scope
        self._bindings = bindings
        self._binding_scope = binding_scope
        self._messages = messages
        self._message_index = message_index
        self._external_index = external_index
        self._provider_event_index = provider_event_index
        self._deliveries = deliveries
        self._delivery_index = delivery_index
        self._outbound_external = outbound_external
        self._echo_guards = echo_guards
        self._proposals = proposals
        self._lifecycle_receipts = lifecycle_receipts
        self._lifecycle_by_request = lifecycle_by_request

    def _persist_locked(self) -> None:
        """Replace the durable operational snapshot in one SQLite transaction."""

        if self._store is None:
            return
        try:
            durable_snapshot = self._durable_snapshot or self._state_snapshot()
        except Exception as exc:
            raise ConversationContractError("conversation store snapshot failed") from exc
        try:
            self._store.execute("BEGIN IMMEDIATE")
            for table in (
                "participants", "threads", "bindings", "messages", "external_messages", "provider_events",
                "deliveries", "outbound_external", "echo_guards", "proposals", "lifecycle_receipts",
            ):
                self._store.execute(f"DELETE FROM {table}")
            encode = lambda value: json.dumps(value.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            self._store.executemany("INSERT INTO participants VALUES (?, ?)", ((item.participant_id, encode(item)) for item in self._participants.values()))
            self._store.executemany("INSERT INTO threads VALUES (?, ?)", ((item.conversation_id, encode(item)) for item in self._threads.values()))
            self._store.executemany("INSERT INTO bindings VALUES (?, ?)", ((item.binding_id, encode(item)) for item in self._bindings.values()))
            self._store.executemany(
                "INSERT INTO messages VALUES (?, ?, ?, ?)",
                ((item.message_id, item.conversation_id, item.sequence, encode(item)) for item in self._message_index.values()),
            )
            self._store.executemany("INSERT INTO external_messages VALUES (?, ?, ?)", ((binding_id, external_id, message_id) for (binding_id, external_id), message_id in self._external_index.items()))
            self._store.executemany("INSERT INTO provider_events VALUES (?, ?, ?, ?)", ((channel, binding_id, event_id, message_id) for (channel, binding_id, event_id), message_id in self._provider_event_index.items()))
            self._store.executemany("INSERT INTO deliveries VALUES (?, ?)", ((item.delivery_id, encode(item)) for item in self._deliveries.values()))
            self._store.executemany("INSERT INTO outbound_external VALUES (?, ?, ?)", ((binding_id, external_id, delivery_id) for (binding_id, external_id), delivery_id in self._outbound_external.items()))
            self._store.executemany("INSERT INTO echo_guards VALUES (?)", ((guard,) for guard in self._echo_guards))
            self._store.executemany("INSERT INTO proposals VALUES (?, ?)", ((item.proposal_id, encode(item)) for item in self._proposals.values()))
            self._store.executemany("INSERT INTO lifecycle_receipts VALUES (?, ?)", ((item.receipt_id, encode(item)) for item in self._lifecycle_receipts.values()))
            self._store.execute("UPDATE metadata SET value = ? WHERE key = 'counter'", (str(self._counter),))
            self._store.execute("COMMIT")
            self._durable_snapshot = self._state_snapshot()
            return
        except (sqlite3.Error, UnicodeError, TypeError, ValueError) as exc:
            if self._store.in_transaction:
                self._store.execute("ROLLBACK")
            self._restore_snapshot(durable_snapshot)
            raise ConversationContractError("conversation store write failed") from exc

    def _state_snapshot(self) -> dict[str, object]:
        return {
            "participants": copy.deepcopy(self._participants),
            "threads": copy.deepcopy(self._threads),
            "threads_by_scope": copy.deepcopy(self._threads_by_scope),
            "bindings": copy.deepcopy(self._bindings),
            "binding_scope": copy.deepcopy(self._binding_scope),
            "messages": copy.deepcopy(self._messages),
            "message_index": copy.deepcopy(self._message_index),
            "external_index": copy.deepcopy(self._external_index),
            "provider_event_index": copy.deepcopy(self._provider_event_index),
            "deliveries": copy.deepcopy(self._deliveries),
            "delivery_index": copy.deepcopy(self._delivery_index),
            "outbound_external": copy.deepcopy(self._outbound_external),
            "echo_guards": copy.deepcopy(self._echo_guards),
            "proposals": copy.deepcopy(self._proposals),
            "lifecycle_receipts": copy.deepcopy(self._lifecycle_receipts),
            "lifecycle_by_request": copy.deepcopy(self._lifecycle_by_request),
            "counter": self._counter,
        }

    def _restore_snapshot(self, snapshot: dict[str, object]) -> None:
        self._participants = snapshot["participants"]  # type: ignore[assignment]
        self._threads = snapshot["threads"]  # type: ignore[assignment]
        self._threads_by_scope = snapshot["threads_by_scope"]  # type: ignore[assignment]
        self._bindings = snapshot["bindings"]  # type: ignore[assignment]
        self._binding_scope = snapshot["binding_scope"]  # type: ignore[assignment]
        self._messages = snapshot["messages"]  # type: ignore[assignment]
        self._message_index = snapshot["message_index"]  # type: ignore[assignment]
        self._external_index = snapshot["external_index"]  # type: ignore[assignment]
        self._provider_event_index = snapshot["provider_event_index"]  # type: ignore[assignment]
        self._deliveries = snapshot["deliveries"]  # type: ignore[assignment]
        self._delivery_index = snapshot["delivery_index"]  # type: ignore[assignment]
        self._outbound_external = snapshot["outbound_external"]  # type: ignore[assignment]
        self._echo_guards = snapshot["echo_guards"]  # type: ignore[assignment]
        self._proposals = snapshot["proposals"]  # type: ignore[assignment]
        self._lifecycle_receipts = snapshot["lifecycle_receipts"]  # type: ignore[assignment]
        self._lifecycle_by_request = snapshot["lifecycle_by_request"]  # type: ignore[assignment]
        self._counter = int(snapshot["counter"])

    def _now(self) -> str:
        # Parsing through a small cursor prevents injected clocks from creating
        # invalid wire data.
        value = self._clock()
        ConversationCursor.from_dict(
            {
                "formatVersion": ConversationCursor.FORMAT,
                "conversationId": "clock-check",
                "afterSequence": 0,
                "threadRevision": 0,
                "issuedAt": value,
            }
        )
        return value

    def _new_id(self, prefix: str, material: object) -> str:
        self._counter += 1
        digest = canonical_digest({"serviceSeed": self._identity_seed, "counter": self._counter, "material": material})
        return f"{prefix}-{digest.removeprefix('sha256:')[:24]}"

    def register_participant(self, participant: ParticipantIdentity) -> ParticipantIdentity:
        checked = ParticipantIdentity.from_dict(participant.to_dict())
        with self._lock:
            current = self._participants.get(checked.participant_id)
            if current is not None and current != checked:
                raise ConversationConflictError("participant identity is already bound differently")
            self._participants[checked.participant_id] = checked
            self._persist_locked()
            return checked

    def ensure_service_participant_permission(self, *, participant_id: str, permission: str) -> ParticipantIdentity:
        """Migrate the fixed local service actor when a new service permission is added.

        This is intentionally narrower than general participant registration: only
        the StatePort-owned local operator identity may receive a compatibility
        permission during a service restart.
        """

        if not isinstance(permission, str) or not permission or any(char.isspace() for char in permission):
            raise ConversationContractError("service participant permission is invalid")
        with self._lock:
            current = self._participant(participant_id)
            if current.actor_id != "local-operator" or not participant_id.startswith("local-operator:"):
                raise ConversationAuthorizationError("only the fixed local operator may be migrated")
            if permission in current.permissions:
                return current
            updated = ParticipantIdentity.from_dict(
                {
                    **current.to_dict(),
                    "permissions": [*current.permissions, permission],
                }
            )
            self._participants[participant_id] = updated
            self._persist_locked()
            return updated

    def _participant(self, participant_id: str) -> ParticipantIdentity:
        participant = self._participants.get(participant_id)
        if participant is None:
            raise ConversationAuthorizationError("conversation participant is not registered")
        return participant

    def _thread(self, conversation_id: str) -> ConversationThread:
        thread = self._threads.get(conversation_id)
        if thread is None:
            raise ConversationNotFoundError("conversation thread was not found")
        return thread

    def _authorize(self, participant_id: str, thread: ConversationThread, permission: str) -> ParticipantIdentity:
        return self._authorize_scope(participant_id, thread.application_id, thread.instance_id, permission)

    def _authorize_scope(self, participant_id: str, application_id: str, instance_id: str, permission: str) -> ParticipantIdentity:
        participant = self._participant(participant_id)
        if not participant.permits(application_id, instance_id, permission):
            raise ConversationAuthorizationError("participant is not authorized for this conversation operation")
        return participant

    def create_thread(
        self,
        *,
        participant_id: str,
        application_id: str,
        instance_id: str,
        title: str,
        delivery_policy: str = "source_channel_only",
        context_policy: ConversationContextPolicy | None = None,
        compression_policy: CompressionPolicy | None = None,
        handoff_policy: HandoffPolicy | None = None,
    ) -> ConversationThread:
        if delivery_policy not in DELIVERY_POLICIES:
            raise ConversationContractError("conversation delivery policy is unsupported")
        with self._lock:
            existing_id = self._threads_by_scope.get((application_id, instance_id))
            if existing_id is not None:
                existing = self._thread(existing_id)
                self._authorize(participant_id, existing, "conversation.read")
                return existing
            participant = self._participant(participant_id)
            if not participant.permits(application_id, instance_id, "conversation.create"):
                raise ConversationAuthorizationError("participant cannot create a conversation for this application instance")
            created_at = self._now()
            conversation_id = self._new_id("conv", {"applicationId": application_id, "instanceId": instance_id, "createdAt": created_at})
            thread = ConversationThread.from_dict(
                {
                    "formatVersion": ConversationThread.FORMAT,
                    "conversationId": conversation_id,
                    "applicationId": application_id,
                    "instanceId": instance_id,
                    "title": title,
                    "createdBy": participant_id,
                    "createdAt": created_at,
                    "status": "active",
                    "deliveryPolicy": delivery_policy,
                    "contextPolicy": (
                        context_policy
                        or default_context_policy(
                            transcript_retention="explicit_capture" if self._store is not None else "memory_only"
                        )
                    ).to_dict(),
                    "compressionPolicy": (compression_policy or default_compression_policy()).to_dict(),
                    "handoffPolicy": (handoff_policy or default_handoff_policy()).to_dict(),
                }
            )
            self._threads[conversation_id] = thread
            self._threads_by_scope[(application_id, instance_id)] = conversation_id
            self._messages[conversation_id] = []
            self._persist_locked()
            return thread

    def thread(self, *, participant_id: str, conversation_id: str) -> ConversationThread:
        with self._lock:
            thread = self._thread(conversation_id)
            self._authorize(participant_id, thread, "conversation.read")
            return thread

    def bind_channel(
        self,
        *,
        participant_id: str,
        conversation_id: str,
        channel: str,
        external_identity_digest: str,
        external_conversation_digest: str,
    ) -> ChannelBinding:
        if channel not in CHANNELS:
            raise ConversationContractError("conversation channel is unsupported")
        with self._lock:
            thread = self._thread(conversation_id)
            self._authorize(participant_id, thread, "conversation.bind")
            scope = (channel, external_conversation_digest)
            existing_id = self._binding_scope.get(scope)
            if existing_id is not None:
                existing = self._bindings[existing_id]
                if (
                    existing.conversation_id != conversation_id
                    or existing.owner_participant_id != participant_id
                    or existing.external_identity_digest != external_identity_digest
                ):
                    raise ConversationConflictError("external channel identity is already bound to another conversation")
                return existing
            created_at = self._now()
            binding_id = self._new_id("binding", {"conversationId": conversation_id, "channel": channel, "scope": external_conversation_digest})
            binding = ChannelBinding.from_dict(
                {
                    "formatVersion": ChannelBinding.FORMAT,
                    "bindingId": binding_id,
                    "conversationId": conversation_id,
                    "applicationId": thread.application_id,
                    "instanceId": thread.instance_id,
                    "channel": channel,
                    "ownerParticipantId": participant_id,
                    "externalIdentityDigest": external_identity_digest,
                    "externalConversationDigest": external_conversation_digest,
                    "status": "active",
                    "createdAt": created_at,
                }
            )
            self._bindings[binding_id] = binding
            self._binding_scope[scope] = binding_id
            self._persist_locked()
            return binding

    def binding(self, *, participant_id: str, binding_id: str) -> ChannelBinding:
        with self._lock:
            binding = self._bindings.get(binding_id)
            if binding is None:
                raise ConversationNotFoundError("channel binding was not found")
            self._authorize(participant_id, self._thread(binding.conversation_id), "conversation.read")
            return binding

    def revoke_binding(self, *, participant_id: str, binding_id: str) -> ChannelBinding:
        with self._lock:
            binding = self.binding(participant_id=participant_id, binding_id=binding_id)
            thread = self._thread(binding.conversation_id)
            self._authorize(participant_id, thread, "conversation.bind")
            if binding.owner_participant_id != participant_id:
                raise ConversationAuthorizationError("only the binding owner may revoke it")
            if binding.status == "revoked":
                return binding
            updated = replace(binding, status="revoked")
            self._bindings[binding_id] = ChannelBinding.from_dict(updated.to_dict())
            self._persist_locked()
            return self._bindings[binding_id]

    def ingest(self, *, participant_id: str, inbound: NormalizedInbound) -> IngestResult:
        with self._lock:
            binding = self._bindings.get(inbound.binding_id)
            if binding is None or binding.status != "active":
                raise ConversationNotFoundError("active channel binding was not found")
            if inbound.channel != binding.channel or inbound.sender_identity_digest != binding.external_identity_digest:
                raise ConversationAuthorizationError("inbound channel or sender identity is not bound")
            if binding.owner_participant_id != participant_id:
                raise ConversationAuthorizationError("participant does not own the inbound channel binding")
            thread = self._thread(binding.conversation_id)
            self._authorize(participant_id, thread, "conversation.send")
            external_key = (binding.binding_id, inbound.external_message_id)
            if inbound.echo_guard in self._echo_guards or external_key in self._outbound_external:
                return IngestResult("echo_suppressed", None, False, "stateport_outbound_echo")
            existing_id = self._external_index.get(external_key)
            if existing_id is not None:
                existing = self._message_index[existing_id]
                expected_reply = None
                if inbound.reply_to_external_message_id is not None:
                    expected_reply = self._external_index.get((binding.binding_id, inbound.reply_to_external_message_id))
                if (
                    existing.body != inbound.body
                    or existing.created_at != inbound.sent_at
                    or existing.reply_to_message_id != expected_reply
                    or existing.attachments != inbound.attachments
                ):
                    raise ConversationConflictError("external message identity was reused with different content")
                return IngestResult("duplicate", existing, True, "provider_retry")
            provider_key = (binding.channel, binding.binding_id, inbound.provider_event_id)
            existing_provider_message = self._provider_event_index.get(provider_key)
            if existing_provider_message is not None:
                existing = self._message_index[existing_provider_message]
                if existing.external_identity is None or existing.external_identity.external_message_id != inbound.external_message_id:
                    raise ConversationConflictError("provider event identity was reused for a different message")
                return IngestResult("duplicate", existing, True, "provider_event_retry")
            reply_id = None
            if inbound.reply_to_external_message_id is not None:
                reply_id = self._external_index.get((binding.binding_id, inbound.reply_to_external_message_id))
                if reply_id is None:
                    raise ConversationConflictError("reply target is not known in this channel binding")
            sequence = len(self._messages[thread.conversation_id]) + 1
            observed_at = self._now()
            dedupe = canonical_digest({"channel": binding.channel, "bindingId": binding.binding_id, "externalMessageId": inbound.external_message_id})
            message_id = self._new_id("msg", {"conversationId": thread.conversation_id, "sequence": sequence, "deduplicationKey": dedupe})
            external = ExternalMessageIdentity.from_dict(
                {
                    "formatVersion": ExternalMessageIdentity.FORMAT,
                    "channel": binding.channel,
                    "bindingId": binding.binding_id,
                    "externalMessageId": inbound.external_message_id,
                    "deduplicationKey": dedupe,
                    "direction": "inbound",
                }
            )
            message = MessageEnvelope.from_dict(
                {
                    "formatVersion": MessageEnvelope.FORMAT,
                    "messageId": message_id,
                    "conversationId": thread.conversation_id,
                    "applicationId": thread.application_id,
                    "instanceId": thread.instance_id,
                    "senderParticipantId": participant_id,
                    "sourceChannel": binding.channel,
                    "sourceBindingId": binding.binding_id,
                    "sequence": sequence,
                    "createdAt": inbound.sent_at,
                    "observedAt": observed_at,
                    "kind": "user_message",
                    "body": inbound.body,
                    "replyToMessageId": reply_id,
                    "attachments": [item.to_dict() for item in inbound.attachments],
                    "externalIdentity": external.to_dict(),
                    "authority": "operational_noncanonical",
                    "canonicalStateEffect": "none",
                    "proposalReference": None,
                    "collapsedByDefault": False,
                    "deduplicationKey": dedupe,
                }
            )
            self._append_message(message)
            self._external_index[external_key] = message.message_id
            self._provider_event_index[provider_key] = message.message_id
            self._persist_locked()
            return IngestResult("accepted", message, False)

    def _append_message(self, message: MessageEnvelope) -> None:
        messages = self._messages[message.conversation_id]
        if message.sequence != len(messages) + 1 or message.message_id in self._message_index:
            raise ConversationConflictError("message sequence or identity is not append-only")
        messages.append(message)
        self._message_index[message.message_id] = message

    def send_internal(
        self,
        *,
        participant_id: str,
        conversation_id: str,
        body: str,
        kind: str = "assistant_message",
        source_message_id: str | None = None,
    ) -> MessageEnvelope:
        if kind not in {"assistant_message", "system_message", "run_event", "tool_event"}:
            raise ConversationContractError("internal message kind is unsupported")
        with self._lock:
            thread = self._thread(conversation_id)
            self._authorize(participant_id, thread, "conversation.respond")
            source_channel = "web"
            source_binding_id = None
            reply_to = None
            if source_message_id is not None:
                source = self._message_index.get(source_message_id)
                if source is None or source.conversation_id != conversation_id:
                    raise ConversationConflictError("response source message is not in this conversation")
                source_channel = source.source_channel
                source_binding_id = source.source_binding_id
                reply_to = source.message_id
            message = self._append_internal(
                participant_id=participant_id,
                thread=thread,
                body=body,
                kind=kind,
                source_channel=source_channel,
                source_binding_id=source_binding_id,
                reply_to_message_id=reply_to,
                proposal_reference=None,
            )
            self._persist_locked()
            return message

    def _append_internal(
        self,
        *,
        participant_id: str,
        thread: ConversationThread,
        body: str,
        kind: str,
        source_channel: str,
        source_binding_id: str | None,
        reply_to_message_id: str | None,
        proposal_reference: str | None,
    ) -> MessageEnvelope:
        sequence = len(self._messages[thread.conversation_id]) + 1
        created_at = self._now()
        dedupe = canonical_digest(
            {
                "conversationId": thread.conversation_id,
                "sequence": sequence,
                "sender": participant_id,
                "kind": kind,
                "bodyDigest": canonical_digest(body),
            }
        )
        message_id = self._new_id("msg", {"conversationId": thread.conversation_id, "sequence": sequence, "deduplicationKey": dedupe})
        message = MessageEnvelope.from_dict(
            {
                "formatVersion": MessageEnvelope.FORMAT,
                "messageId": message_id,
                "conversationId": thread.conversation_id,
                "applicationId": thread.application_id,
                "instanceId": thread.instance_id,
                "senderParticipantId": participant_id,
                "sourceChannel": source_channel,
                "sourceBindingId": source_binding_id,
                "sequence": sequence,
                "createdAt": created_at,
                "observedAt": created_at,
                "kind": kind,
                "body": body,
                "replyToMessageId": reply_to_message_id,
                "attachments": [],
                "externalIdentity": None,
                "authority": "operational_noncanonical",
                "canonicalStateEffect": "none",
                "proposalReference": proposal_reference,
                "collapsedByDefault": kind in {"run_event", "tool_event"},
                "deduplicationKey": dedupe,
            }
        )
        self._append_message(message)
        return message

    def propose_state_change(
        self,
        *,
        participant_id: str,
        conversation_id: str,
        originating_message_id: str,
        base_identity: str,
        payload_digest: str,
        summary: str,
    ) -> tuple[StateProposal, MessageEnvelope]:
        with self._lock:
            thread = self._thread(conversation_id)
            self._authorize(participant_id, thread, "conversation.propose")
            origin = self._message_index.get(originating_message_id)
            if origin is None or origin.conversation_id != conversation_id:
                raise ConversationConflictError("state proposal origin is not in this conversation")
            created_at = self._now()
            proposal_id = self._new_id("proposal", {"conversationId": conversation_id, "origin": originating_message_id, "payloadDigest": payload_digest})
            proposal = StateProposal.from_dict(
                {
                    "formatVersion": StateProposal.FORMAT,
                    "proposalId": proposal_id,
                    "conversationId": conversation_id,
                    "applicationId": thread.application_id,
                    "instanceId": thread.instance_id,
                    "originatingMessageId": originating_message_id,
                    "baseIdentity": base_identity,
                    "payloadDigest": payload_digest,
                    "status": "proposed",
                    "createdAt": created_at,
                    "authority": "proposal_noncanonical",
                    "mutationBoundary": "typed_transaction_required",
                }
            )
            self._proposals[proposal_id] = proposal
            reference = self._append_internal(
                participant_id=participant_id,
                thread=thread,
                body=summary,
                kind="state_proposal_reference",
                source_channel=origin.source_channel,
                source_binding_id=origin.source_binding_id,
                reply_to_message_id=originating_message_id,
                proposal_reference=proposal_id,
            )
            self._persist_locked()
            return proposal, reference

    def list_messages(
        self,
        *,
        participant_id: str,
        conversation_id: str,
        cursor: ConversationCursor | None = None,
        limit: int = 50,
    ) -> tuple[tuple[MessageEnvelope, ...], ConversationCursor]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
            raise ConversationContractError("conversation page limit must be from 1 through 200")
        with self._lock:
            thread = self._thread(conversation_id)
            self._authorize(participant_id, thread, "conversation.read")
            messages = self._messages[conversation_id]
            after = 0
            if cursor is not None:
                checked = ConversationCursor.from_dict(cursor.to_dict())
                if checked.conversation_id != conversation_id or checked.after_sequence > len(messages) or checked.thread_revision > len(messages):
                    raise ConversationConflictError("conversation cursor does not match the current thread")
                after = checked.after_sequence
            page = tuple(messages[after:after + limit])
            final_sequence = page[-1].sequence if page else after
            next_cursor = ConversationCursor.from_dict(
                {
                    "formatVersion": ConversationCursor.FORMAT,
                    "conversationId": conversation_id,
                    "afterSequence": final_sequence,
                    "threadRevision": len(messages),
                    "issuedAt": self._now(),
                }
            )
            return page, next_cursor

    def plan_deliveries(self, *, participant_id: str, message_id: str) -> tuple[DeliveryReceipt, ...]:
        with self._lock:
            message = self._message_index.get(message_id)
            if message is None:
                raise ConversationNotFoundError("message was not found")
            thread = self._thread(message.conversation_id)
            self._authorize(participant_id, thread, "conversation.deliver")
            active = sorted(
                (item for item in self._bindings.values() if item.conversation_id == thread.conversation_id and item.status == "active"),
                key=lambda item: (item.channel, item.binding_id),
            )
            targets: list[tuple[ChannelBinding, str]] = []
            if thread.delivery_policy == "source_channel_only":
                targets = [(item, "full") for item in active if item.channel == message.source_channel]
            elif thread.delivery_policy == "mirror_to_all":
                targets = [(item, "full") for item in active]
            elif thread.delivery_policy == "web_primary":
                targets = [(item, "full" if item.channel == "web" else "notification") for item in active]
            elif thread.delivery_policy == "telegram_primary":
                targets = [(item, "full" if item.channel == "telegram" else "archive") for item in active]
            receipts: list[DeliveryReceipt] = []
            changed = False
            for binding, mode in targets:
                key = (message_id, binding.binding_id)
                existing_id = self._delivery_index.get(key)
                if existing_id is not None:
                    receipts.append(self._deliveries[existing_id])
                    continue
                created_at = self._now()
                echo_guard = canonical_digest({"messageId": message_id, "bindingId": binding.binding_id, "mode": mode})
                delivery_id = self._new_id("delivery", {"messageId": message_id, "bindingId": binding.binding_id})
                receipt = DeliveryReceipt.from_dict(
                    {
                        "formatVersion": DeliveryReceipt.FORMAT,
                        "deliveryId": delivery_id,
                        "messageId": message_id,
                        "conversationId": thread.conversation_id,
                        "bindingId": binding.binding_id,
                        "channel": binding.channel,
                        "deliveryPolicy": thread.delivery_policy,
                        "deliveryMode": mode,
                        "status": "planned",
                        "createdAt": created_at,
                        "externalMessageId": None,
                        "echoGuard": echo_guard,
                        "failureReason": None,
                    }
                )
                self._deliveries[delivery_id] = receipt
                self._delivery_index[key] = delivery_id
                receipts.append(receipt)
                changed = True
            if changed:
                self._persist_locked()
            return tuple(receipts)

    def record_delivery(
        self,
        *,
        participant_id: str,
        delivery_id: str,
        status: str,
        external_message_id: str | None = None,
        failure_reason: str | None = None,
    ) -> DeliveryReceipt:
        with self._lock:
            current = self._deliveries.get(delivery_id)
            if current is None:
                raise ConversationNotFoundError("delivery receipt was not found")
            thread = self._thread(current.conversation_id)
            self._authorize(participant_id, thread, "conversation.deliver")
            if current.status != "planned":
                if current.status == status and current.external_message_id == external_message_id and current.failure_reason == failure_reason:
                    return current
                raise ConversationConflictError("delivery receipt has already reached a terminal state")
            updated = DeliveryReceipt.from_dict(
                {
                    **current.to_dict(),
                    "status": status,
                    "externalMessageId": external_message_id,
                    "failureReason": failure_reason,
                }
            )
            if updated.status == "delivered" and updated.external_message_id is not None:
                key = (updated.binding_id, updated.external_message_id)
                if key in self._external_index:
                    raise ConversationConflictError("outbound identity collides with an inbound message")
                self._outbound_external[key] = updated.delivery_id
                self._echo_guards.add(updated.echo_guard)
            self._deliveries[delivery_id] = updated
            self._persist_locked()
            return updated

    def presentation(
        self,
        *,
        participant_id: str,
        conversation_id: str,
        pending_approval_references: Sequence[str] = (),
        run_receipt_references: Sequence[str] = (),
    ) -> dict[str, object]:
        with self._lock:
            thread = self._thread(conversation_id)
            self._authorize(participant_id, thread, "conversation.read")
            messages = self._messages[conversation_id]
            deliveries_by_message: dict[str, list[DeliveryReceipt]] = {}
            for receipt in self._deliveries.values():
                if receipt.conversation_id == conversation_id:
                    deliveries_by_message.setdefault(receipt.message_id, []).append(receipt)
            rendered_messages: list[dict[str, object]] = []
            for message in messages:
                deliveries = sorted(deliveries_by_message.get(message.message_id, []), key=lambda item: (item.channel, item.binding_id))
                value: dict[str, object] = message.to_dict()
                value["display"] = {
                    "collapsedByDefault": message.kind in {"run_event", "tool_event"},
                    "deliveryState": [item.to_dict() for item in deliveries],
                    "inboundAccepted": message.external_identity is not None and message.external_identity.direction == "inbound",
                }
                rendered_messages.append(value)
            bindings = sorted(
                (item for item in self._bindings.values() if item.conversation_id == conversation_id),
                key=lambda item: (item.channel, item.binding_id),
            )
            proposals = sorted(
                (item for item in self._proposals.values() if item.conversation_id == conversation_id),
                key=lambda item: item.created_at,
            )
            return {
                "formatVersion": self.PRESENTATION_FORMAT,
                "component": "conversation_thread",
                "applicationBinding": {"applicationId": thread.application_id, "instanceId": thread.instance_id},
                "thread": thread.to_dict(),
                "channelBindings": [
                    {"bindingId": item.binding_id, "channel": item.channel, "status": item.status}
                    for item in bindings
                ],
                "messages": rendered_messages,
                "pendingApprovals": [{"reference": item} for item in self._safe_references(pending_approval_references)],
                "receipts": [{"reference": item} for item in self._safe_references(run_receipt_references)],
                "stateProposals": [item.to_dict() for item in proposals],
                "authority": {
                    "transcript": "operational_noncanonical",
                    "canonicalState": "typed_transactions_only",
                    "compressionExecution": "owned_by_context_lifecycle_not_this_service",
                    "retention": thread.context_policy.transcript_retention,
                },
                "retentionStatus": self._retention_status_locked(thread).to_dict(),
                "lifecycleReceipts": [
                    item.to_dict()
                    for item in sorted(
                        (item for item in self._lifecycle_receipts.values() if item.conversation_id == conversation_id),
                        key=lambda item: item.occurred_at,
                    )
                ],
            }

    def _retention_status_locked(self, thread: ConversationThread) -> TranscriptRetentionStatus:
        messages = self._messages[thread.conversation_id]
        return TranscriptRetentionStatus.from_dict(
            {
                "formatVersion": TranscriptRetentionStatus.FORMAT,
                "conversationId": thread.conversation_id,
                "applicationId": thread.application_id,
                "instanceId": thread.instance_id,
                "retention": thread.context_policy.transcript_retention,
                "storage": "durable_local" if self._store is not None else "process_memory",
                "status": "retained" if messages else "empty",
                "messageCount": len(messages),
                "expiryStatus": "no_automatic_expiry_scheduled",
                "expiresAt": None,
                "evaluatedAt": self._now(),
            }
        )

    @staticmethod
    def _lifecycle_request(request_id: str) -> str:
        if not isinstance(request_id, str) or not ConversationService._LIFECYCLE_ID.fullmatch(request_id):
            raise ConversationContractError("conversation lifecycle request id is invalid")
        return request_id

    def retention_status(self, *, participant_id: str, conversation_id: str) -> TranscriptRetentionStatus:
        with self._lock:
            thread = self._thread(conversation_id)
            self._authorize(participant_id, thread, "conversation.read")
            return self._retention_status_locked(thread)

    def export_transcript(
        self,
        *,
        participant_id: str,
        conversation_id: str,
        request_id: str,
    ) -> tuple[TranscriptExport, TranscriptLifecycleReceipt]:
        request_id = self._lifecycle_request(request_id)
        with self._lock:
            thread = self._thread(conversation_id)
            self._authorize(participant_id, thread, "conversation.read")
            existing_id = self._lifecycle_by_request.get(request_id)
            if existing_id is not None:
                existing = self._lifecycle_receipts[existing_id]
                if existing.operation != "export" or existing.conversation_id != conversation_id:
                    raise ConversationConflictError("conversation lifecycle request identity was reused differently")
            retention = self._retention_status_locked(thread)
            export_id = f"transcript-export-{canonical_digest({'conversationId': conversation_id, 'requestId': request_id}).removeprefix('sha256:')[:24]}"
            export = TranscriptExport.from_dict(
                {
                    "formatVersion": TranscriptExport.FORMAT,
                    "exportId": export_id,
                    "generatedAt": self._now(),
                    "metadata": {
                        "conversationId": conversation_id,
                        "applicationId": thread.application_id,
                        "instanceId": thread.instance_id,
                        "threadStatus": thread.status,
                        "retentionStatus": retention.to_dict(),
                    },
                    "messages": [item.to_dict() for item in self._messages[conversation_id]],
                }
            )
            if existing_id is not None:
                return export, existing
            receipt = TranscriptLifecycleReceipt.from_dict(
                {
                    "formatVersion": TranscriptLifecycleReceipt.FORMAT,
                    "receiptId": self._new_id("transcript-receipt", {"operation": "export", "conversationId": conversation_id, "requestId": request_id}),
                    "requestId": request_id,
                    "operation": "export",
                    "applicationId": thread.application_id,
                    "instanceId": thread.instance_id,
                    "conversationId": conversation_id,
                    "performedBy": participant_id,
                    "occurredAt": self._now(),
                    "threadIdentity": "preserved",
                    "bindingPolicy": "preserved",
                    "removed": {"messages": 0, "deliveries": 0, "deduplicationEntries": 0, "proposals": 0, "echoGuards": 0},
                    "authority": "operational_noncanonical",
                    "canonicalStateEffect": "none",
                }
            )
            self._lifecycle_receipts[receipt.receipt_id] = receipt
            self._lifecycle_by_request[request_id] = receipt.receipt_id
            self._persist_locked()
            return export, receipt

    def clear_transcript(
        self,
        *,
        participant_id: str,
        conversation_id: str,
        request_id: str,
    ) -> TranscriptLifecycleReceipt:
        request_id = self._lifecycle_request(request_id)
        with self._lock:
            thread = self._thread(conversation_id)
            self._authorize(participant_id, thread, "conversation.delete")
            existing_id = self._lifecycle_by_request.get(request_id)
            if existing_id is not None:
                existing = self._lifecycle_receipts[existing_id]
                if existing.operation != "clear" or existing.conversation_id != conversation_id:
                    raise ConversationConflictError("conversation lifecycle request identity was reused differently")
                return existing
            messages = tuple(self._messages[conversation_id])
            message_ids = {item.message_id for item in messages}
            delivery_ids = {item.delivery_id for item in self._deliveries.values() if item.conversation_id == conversation_id}
            proposal_ids = {item.proposal_id for item in self._proposals.values() if item.conversation_id == conversation_id}
            external_keys = {key for key, message_id in self._external_index.items() if message_id in message_ids}
            provider_keys = {key for key, message_id in self._provider_event_index.items() if message_id in message_ids}
            outbound_keys = {key for key, delivery_id in self._outbound_external.items() if delivery_id in delivery_ids}
            echo_guards = {item.echo_guard for item in self._deliveries.values() if item.delivery_id in delivery_ids}
            self._messages[conversation_id] = []
            for message_id in message_ids:
                self._message_index.pop(message_id, None)
            for key in external_keys:
                self._external_index.pop(key, None)
            for key in provider_keys:
                self._provider_event_index.pop(key, None)
            for delivery_id in delivery_ids:
                item = self._deliveries.pop(delivery_id)
                self._delivery_index.pop((item.message_id, item.binding_id), None)
            for key in outbound_keys:
                self._outbound_external.pop(key, None)
            self._echo_guards.difference_update(echo_guards)
            for proposal_id in proposal_ids:
                self._proposals.pop(proposal_id, None)
            receipt = TranscriptLifecycleReceipt.from_dict(
                {
                    "formatVersion": TranscriptLifecycleReceipt.FORMAT,
                    "receiptId": self._new_id("transcript-receipt", {"operation": "clear", "conversationId": conversation_id, "requestId": request_id}),
                    "requestId": request_id,
                    "operation": "clear",
                    "applicationId": thread.application_id,
                    "instanceId": thread.instance_id,
                    "conversationId": conversation_id,
                    "performedBy": participant_id,
                    "occurredAt": self._now(),
                    "threadIdentity": "preserved",
                    "bindingPolicy": "preserved",
                    "removed": {
                        "messages": len(messages),
                        "deliveries": len(delivery_ids),
                        "deduplicationEntries": len(external_keys) + len(provider_keys) + len(outbound_keys),
                        "proposals": len(proposal_ids),
                        "echoGuards": len(echo_guards),
                    },
                    "authority": "operational_noncanonical",
                    "canonicalStateEffect": "none",
                }
            )
            self._lifecycle_receipts[receipt.receipt_id] = receipt
            self._lifecycle_by_request[request_id] = receipt.receipt_id
            self._persist_locked()
            return receipt

    @staticmethod
    def _safe_references(values: Iterable[str]) -> tuple[str, ...]:
        results: list[str] = []
        for item in values:
            if not isinstance(item, str) or not item or len(item) > 256 or any(char.isspace() for char in item):
                raise ConversationContractError("presentation reference is invalid")
            results.append(item)
        if len(set(results)) != len(results) or len(results) > 128:
            raise ConversationContractError("presentation references must be bounded and unique")
        return tuple(results)
