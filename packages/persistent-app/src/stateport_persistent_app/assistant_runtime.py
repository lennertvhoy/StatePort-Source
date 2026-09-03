"""Durable assistant processor for one application-bound AI loop."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import stat
import threading
import traceback
from typing import Callable

from external_engine_runtime import ProcessIdentity, TemporaryWorkspace
from stateport_conversation import ConversationService, MessageEnvelope, canonical_digest

from .assistant_reconciliation import AssistantReconciliationState
from .assistant_work import AssistantClaim, AssistantWorkError, AssistantWorkStore
from .provider_router import ProviderRouter, ProviderRouterError

_MAX_CONTEXT_BYTES = 28 * 1024
_MAX_CONTEXT_MESSAGE_BYTES = 20 * 1024
_MAX_INSTANCE_CONTEXT_BYTES = 12 * 1024
_MAX_INSTANCE_CONTEXT_SOURCE_BYTES = _MAX_INSTANCE_CONTEXT_BYTES + 1
_MIN_INSTANCE_CONTEXT_FILE_BYTES = 1024
_MAX_SAFE_PROVIDER_SECONDS = 3500
_AUTO = object()

_ATM10_CONTEXT_FILES = (
    ("STATUS.md", 0),
    ("NEXT_ACTIONS.md", 0),
    ("guide/ATM10_6.1_FLUX_NETWORKS_STARTER.md", 0),
    ("state/ATM_STAR_PROGRESS.yaml", 0),
    ("PROJECT_STATE.yaml", 0),
    ("guide/ATM10_6.1_SPEEDRUN_RUNBOOK.md", 2048),
)

_ATM10_CONTEXT_UNAVAILABLE = """Read-only ATM10 guide source context is unavailable.
Do not present a recommendation as source-backed or claim any in-game fact is
verified. State this briefly, explain that the registered guide files could not
be read, and ask the operator to restore the registered guide source before
continuing."""

_ATM10_RESPONSE_GUIDANCE = """ATM10 guide response contract:
- Lead with one decision: name exactly one immediate action, not a menu or
  audit. The player is in the game and needs to know what to click, craft,
  place, or check right now.
- State the minimum viable target: exact count of the system being built
  and why that number. Separate optional upgrades from prerequisites.
  Never require a Flux Controller or multiple Points when one Plug plus
  one Point is the minimum transfer proof.
- Give exact recursive shopping lists when source evidence exists: expand
  intermediates to raw inputs, account for batch output and surplus, and
  label each number as exact, JEI-check, or estimate. If a recipe page is
  missing, ask for that one page, not a broad inventory.
- Explain acquisition of missing prerequisites: name the item, the exact
  quantity needed, and the fastest route from the player's current stage.
  Do not say "get some X"; say "3 Ender Pearls via Warped Forest or
  existing HNN route."
- Provide ordered build and configuration steps: where to place each
  block, which GUI settings to change, and what name to give private
  networks. Use actual ATM10 UI names.
- Finish with a visible done condition: the observable result that proves
  the step is complete (for example, "RS Controller stays powered with
  old cable removed").
- Name one queued next action after the current step passes.
- Label capabilities as reported, verified, unknown, blocked, or planned.
  Never silently promote reported claims to live facts. Live JEI outranks
  mod defaults, community guides, and repo research.
- Do not lead with repository governance, bootstrap administration,
  delivery policy, or broad system audits when the player asked for the
  next gameplay action.
- Never invent counts, rates, recipes, machine availability, or
  completion. If something is unknown, make verification the specific
  action."""


class AssistantProcessor:
    """Claim durable message work, invoke one router, and persist one reply."""

    def __init__(
        self,
        conversations: ConversationService,
        *,
        work_store: AssistantWorkStore | None = None,
        router: ProviderRouter | None = None,
        staging_root: Path | None = None,
        conversation_store_path: Path | None | object = _AUTO,
        reconciliation_state: AssistantReconciliationState | None = None,
        poll_interval: float = 1.0,
        worker_id: str = "assistant.local",
        log_writer: Callable[[str], None] | None = None,
    ) -> None:
        config_root = Path(
            os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")
        ) / "stateport"
        state_root = Path(
            os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")
        ) / "stateport"
        self._conversations = conversations
        self._work = work_store or AssistantWorkStore(
            state_root / "assistant-work.sqlite3"
        )
        if router is None:
            profile_path = config_root / "provider-router.json"
            if not profile_path.exists():
                model = os.environ.get("STATEPORT_CODEX_MODEL", "").strip()
                if not model:
                    raise ProviderRouterError(
                        "STATEPORT_CODEX_MODEL must be explicitly configured "
                        "before enabling the assistant processor"
                    )
                ProviderRouter.configure_codex(
                    profile_path,
                    model_identifier=model,
                )
            router = ProviderRouter(profile_path)
        self._router = router
        self._claim_lease_seconds = self._lease_seconds_for_router(router)
        self._staging_root = staging_root or state_root / "assistant-staging"
        if not self._staging_root.is_absolute():
            raise ValueError("assistant staging root must be absolute")
        self._staging_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self._staging_root.is_symlink() or not self._staging_root.is_dir():
            raise ValueError("assistant staging root must be a real directory")
        if conversation_store_path is _AUTO:
            conversation_store_path = state_root / "conversation.sqlite3"
        if conversation_store_path is not None and (
            not conversation_store_path.is_absolute()
            or conversation_store_path.is_symlink()
        ):
            raise ValueError(
                "conversation store path must be an absolute regular path"
            )
        self._conversation_store_path = conversation_store_path
        self._reconciliation = reconciliation_state or AssistantReconciliationState(
            state_root / "assistant-reconciliation.json"
        )
        if poll_interval <= 0:
            raise ValueError("assistant poll interval must be positive")
        self._poll_interval = poll_interval
        self._worker_id = worker_id
        self._log = log_writer
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name="stateport-assistant-processor",
            daemon=True,
        )
        # Activation is completed during construction. AppServer constructs the
        # processor before binding its listener, so historical messages cannot
        # race the first background poll and be mistaken for new work.
        self._activated = False
        self.activate()

    @staticmethod
    def _lease_seconds_for_router(router: ProviderRouter) -> int:
        profile = router.runtime_profile
        budgets = profile.get("budgets") if isinstance(profile, dict) else None
        configured = budgets.get("timeSeconds") if isinstance(budgets, dict) else 60
        if (
            isinstance(configured, bool)
            or not isinstance(configured, int)
            or configured < 1
        ):
            raise ProviderRouterError(
                "provider runtime profile has no valid time budget"
            )
        if configured > _MAX_SAFE_PROVIDER_SECONDS:
            raise ProviderRouterError(
                "provider time budget exceeds the durable assistant lease safety bound"
            )
        return max(120, configured + 60)

    def start(self) -> None:
        if not self._thread.is_alive():
            self._thread.start()

    def shutdown(self, *, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=timeout)

    @property
    def running(self) -> bool:
        return self._thread.is_alive() and not self._stop.is_set()

    @property
    def router(self) -> ProviderRouter:
        return self._router

    @property
    def work_store(self) -> AssistantWorkStore:
        return self._work

    def enqueue(
        self,
        message: MessageEnvelope,
        *,
        participant_id: str,
    ) -> dict[str, object]:
        if message.kind != "user_message":
            raise AssistantWorkError(
                "only user messages can create assistant work"
            )
        return self.enqueue_identity(
            instance_id=message.instance_id,
            application_id=message.application_id,
            conversation_id=message.conversation_id,
            message_id=message.message_id,
            participant_id=participant_id,
            source_sequence=message.sequence,
        )

    def enqueue_identity(
        self,
        *,
        instance_id: str,
        application_id: str,
        conversation_id: str,
        message_id: str,
        participant_id: str,
        source_sequence: int,
    ) -> dict[str, object]:
        return self._work.enqueue(
            instance_id=instance_id,
            application_id=application_id,
            conversation_id=conversation_id,
            message_id=message_id,
            participant_id=participant_id,
            source_sequence=source_sequence,
        )

    def _read_conversation_rows(
        self,
    ) -> list[tuple[str, str, int, dict[str, object], dict[str, object]]]:
        path = self._conversation_store_path
        if path is None or not path.is_file():
            return []
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                f"file:{path.as_posix()}?mode=ro",
                uri=True,
                timeout=5,
            )
            rows = connection.execute(
                "SELECT m.message_id,m.conversation_id,m.sequence,m.payload,t.payload "
                "FROM messages m JOIN threads t "
                "ON t.conversation_id=m.conversation_id "
                "ORDER BY m.conversation_id,m.sequence"
            ).fetchall()
        except sqlite3.Error as exc:
            raise AssistantWorkError(
                "conversation store could not be reconciled"
            ) from exc
        finally:
            if connection is not None:
                connection.close()
        parsed: list[
            tuple[str, str, int, dict[str, object], dict[str, object]]
        ] = []
        for message_id, conversation_id, sequence, raw_message, raw_thread in rows:
            try:
                message = json.loads(raw_message)
                thread = json.loads(raw_thread)
            except (TypeError, json.JSONDecodeError) as exc:
                raise AssistantWorkError(
                    "conversation store contains malformed assistant input"
                ) from exc
            if not isinstance(message, dict) or not isinstance(thread, dict):
                raise AssistantWorkError(
                    "conversation store contains malformed assistant input"
                )
            parsed.append(
                (
                    str(message_id),
                    str(conversation_id),
                    int(sequence),
                    message,
                    thread,
                )
            )
        return parsed

    @staticmethod
    def _positions(
        rows: list[tuple[str, str, int, dict[str, object], dict[str, object]]],
    ) -> dict[str, int]:
        positions: dict[str, int] = {}
        for _message_id, conversation_id, sequence, _message, _thread in rows:
            positions[conversation_id] = max(
                positions.get(conversation_id, 0),
                sequence,
            )
        return positions

    def activate(self) -> bool:
        """Snapshot pre-existing transcript positions before accepting work."""

        if self._activated:
            return False
        created = self._reconciliation.initialize(
            self._positions(self._read_conversation_rows())
        )
        self._activated = True
        return created

    def reconcile_messages(self) -> int:
        """Enqueue only messages arriving after explicit processor activation."""

        if not self._activated:
            self.activate()
        rows = self._read_conversation_rows()
        replied_to = {
            str(message.get("replyToMessageId"))
            for _id, _conversation, _sequence, message, _thread in rows
            if message.get("kind")
            in {"assistant_message", "system_message"}
            and isinstance(message.get("replyToMessageId"), str)
            and message.get("replyToMessageId")
        }
        enqueued = 0
        for message_id, conversation_id, sequence, message, thread in rows:
            if sequence <= self._reconciliation.cursor(conversation_id):
                continue
            if (
                message.get("messageId") != message_id
                or message.get("conversationId") != conversation_id
                or message.get("sequence") != sequence
                or thread.get("conversationId") != conversation_id
                or message.get("applicationId") != thread.get("applicationId")
                or message.get("instanceId") != thread.get("instanceId")
            ):
                raise AssistantWorkError(
                    "conversation assistant identities are inconsistent"
                )
            if message.get("kind") == "user_message" and message_id not in replied_to:
                participant_id = thread.get("createdBy")
                if not isinstance(participant_id, str) or not participant_id:
                    raise AssistantWorkError(
                        "conversation assistant participant is unavailable"
                    )
                before = self._work.get_by_message(message_id)
                self.enqueue_identity(
                    instance_id=str(message["instanceId"]),
                    application_id=str(message["applicationId"]),
                    conversation_id=conversation_id,
                    message_id=message_id,
                    participant_id=participant_id,
                    source_sequence=sequence,
                )
                if before is None:
                    enqueued += 1
            self._reconciliation.advance(conversation_id, sequence)
        return enqueued

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                processed = self.process_once()
            except Exception:
                processed = False
                self._log_event(
                    "assistant_processor_poll_error",
                    traceback.format_exc(),
                )
            if not processed:
                self._stop.wait(timeout=self._poll_interval)

    def process_once(self) -> bool:
        self.reconcile_messages()
        claim = self._work.claim_next(
            worker_id=self._worker_id,
            lease_seconds=self._claim_lease_seconds,
        )
        if claim is None:
            return False
        if claim.phase == "invoke":
            self._invoke(claim)
        elif claim.phase == "deliver":
            self._deliver(claim)
        else:
            raise AssistantWorkError(
                "assistant claim phase is unsupported"
            )
        return True

    def _invoke(self, claim: AssistantClaim) -> None:
        try:
            objective, context_digest = self._conversation_objective(claim)
            with TemporaryWorkspace(
                self._staging_root,
                prefix=(
                    f"{claim.work_id.removeprefix('assistant.')[:16]}-"
                ),
            ) as staging:
                invocation = self._router.invoke(
                    work_id=claim.work_id,
                    attempt_id=claim.attempt_id,
                    attempt_ordinal=claim.attempt_ordinal,
                    instance_id=claim.instance_id,
                    conversation_id=claim.conversation_id,
                    message_id=claim.message_id,
                    source_sequence=claim.source_sequence,
                    objective=objective,
                    context_digest=context_digest,
                    staging_root=staging,
                    cancel_event=self._stop,
                    on_started=lambda identity: self._record_process_identity(
                        claim,
                        identity,
                    ),
                )
            self._work.store_provider_result(
                work_id=claim.work_id,
                attempt_id=claim.attempt_id,
                lease_token=claim.lease_token,
                result=invocation.durable_result(),
            )
        except ProviderRouterError as exc:
            self._fail_claim(
                claim,
                "provider_invocation_failed",
                str(exc),
            )
        except Exception as exc:
            self._fail_claim(
                claim,
                "assistant_invocation_failed",
                str(exc) or type(exc).__name__,
            )

    def _record_process_identity(
        self,
        claim: AssistantClaim,
        identity: ProcessIdentity,
    ) -> None:
        self._work.record_process_identity(
            work_id=claim.work_id,
            attempt_id=claim.attempt_id,
            lease_token=claim.lease_token,
            process_identity={
                "pid": identity.pid,
                "processGroupId": identity.process_group_id,
                "startTimeTicks": identity.start_time_ticks,
                "processGeneration": identity.process_generation,
            },
            runtime_profile=self._router.runtime_profile,
        )

    def _deliver(self, claim: AssistantClaim) -> None:
        result = claim.provider_result
        text = result.get("assistantText") if isinstance(result, dict) else None
        if not isinstance(text, str) or not text.strip():
            self._fail_claim(
                claim,
                "assistant_result_invalid",
                "durable provider result has no assistant text",
            )
            return
        try:
            reply_id = self._existing_reply_id(claim)
            if reply_id is None:
                reply = self._conversations.send_internal(
                    participant_id=claim.participant_id,
                    conversation_id=claim.conversation_id,
                    body=text,
                    kind="assistant_message",
                    source_message_id=claim.message_id,
                )
                reply_id = reply.message_id
            self._work.record_reply(
                work_id=claim.work_id,
                attempt_id=claim.attempt_id,
                lease_token=claim.lease_token,
                reply_message_id=reply_id,
            )
        except Exception as exc:
            self._fail_claim(
                claim,
                "assistant_delivery_failed",
                str(exc) or type(exc).__name__,
            )

    def _existing_reply_id(self, claim: AssistantClaim) -> str | None:
        presentation = self._conversations.presentation(
            participant_id=claim.participant_id,
            conversation_id=claim.conversation_id,
        )
        matches = [
            item.get("messageId")
            for item in presentation.get("messages", [])
            if isinstance(item, dict)
            and item.get("kind") == "assistant_message"
            and item.get("replyToMessageId") == claim.message_id
        ]
        bounded = [
            item for item in matches if isinstance(item, str) and item
        ]
        if len(bounded) > 1:
            raise AssistantWorkError(
                "multiple assistant replies exist for one source message"
            )
        return bounded[0] if bounded else None

    @staticmethod
    def _bounded_body(body: str) -> str:
        encoded = body.encode("utf-8")
        if len(encoded) <= _MAX_CONTEXT_MESSAGE_BYTES:
            return body
        prefix = encoded[:_MAX_CONTEXT_MESSAGE_BYTES].decode(
            "utf-8",
            errors="ignore",
        )
        return prefix + "\n[Message truncated at the context boundary.]"

    def _conversation_objective(
        self,
        claim: AssistantClaim,
    ) -> tuple[str, str]:
        presentation = self._conversations.presentation(
            participant_id=claim.participant_id,
            conversation_id=claim.conversation_id,
        )
        if presentation.get("applicationBinding") != {
            "applicationId": claim.application_id,
            "instanceId": claim.instance_id,
        }:
            raise AssistantWorkError(
                "conversation application binding changed after enqueue"
            )
        source_found = False
        selected: list[dict[str, object]] = []
        for item in presentation.get("messages", []):
            if not isinstance(item, dict):
                continue
            sequence = item.get("sequence")
            if (
                isinstance(sequence, bool)
                or not isinstance(sequence, int)
                or sequence > claim.source_sequence
            ):
                continue
            if item.get("messageId") == claim.message_id:
                source_found = True
            body = item.get("body")
            selected.append(
                {
                    "messageId": item.get("messageId"),
                    "sequence": sequence,
                    "kind": item.get("kind"),
                    "body": (
                        self._bounded_body(body)
                        if isinstance(body, str)
                        else ""
                    ),
                    "replyToMessageId": item.get("replyToMessageId"),
                }
            )
        if not source_found:
            raise AssistantWorkError(
                "queued source message is no longer present in the conversation"
            )

        instance_context = self._read_instance_context(claim)
        if instance_context == _ATM10_CONTEXT_UNAVAILABLE:
            raise AssistantWorkError(
                "ATM10 guide source context is unavailable; "
                "no provider invocation was attempted"
            )
        omitted = 0
        included = list(selected)
        while len(included) > 1:
            candidate = self._render_objective(
                claim,
                included,
                omitted,
                instance_context=instance_context,
            )
            if len(candidate.encode("utf-8")) <= _MAX_CONTEXT_BYTES:
                break
            included.pop(0)
            omitted += 1
        objective = self._render_objective(
            claim,
            included,
            omitted,
            instance_context=instance_context,
        )
        if len(objective.encode("utf-8")) > _MAX_CONTEXT_BYTES and instance_context:
            without_instance_context = self._render_objective(
                claim,
                included,
                omitted,
            )
            context_overhead = (
                len(
                    self._render_objective(
                        claim,
                        included,
                        omitted,
                        instance_context="x",
                    ).encode("utf-8")
                )
                - len(without_instance_context.encode("utf-8"))
                - 1
            )
            available_context_bytes = max(
                0,
                _MAX_CONTEXT_BYTES
                - len(without_instance_context.encode("utf-8"))
                - context_overhead,
            )
            instance_context = self._truncate_context(
                instance_context,
                available_context_bytes,
            )
            objective = self._render_objective(
                claim,
                included,
                omitted,
                instance_context=instance_context,
            )
        if len(objective.encode("utf-8")) > _MAX_CONTEXT_BYTES:
            raise AssistantWorkError(
                "latest conversation message exceeds the bounded model context"
            )
        context_manifest = {
            "formatVersion": "stateport.assistant-context/v1",
            "instanceId": claim.instance_id,
            "conversationId": claim.conversation_id,
            "sourceMessageId": claim.message_id,
            "sourceSequence": claim.source_sequence,
            "policy": "recent_messages_and_explicit_instance_context/v1",
            "omittedMessageCount": omitted,
            "messages": included,
            "instanceContext": {
                "policy": (
                    "atm10_read_only_guide_files/v1"
                    if instance_context
                    else "none"
                ),
                "digest": (
                    canonical_digest({"text": instance_context})
                    if instance_context
                    else None
                ),
                "bytes": len(instance_context.encode("utf-8")),
            },
            "renderedObjectiveDigest": canonical_digest({"objective": objective}),
        }
        return objective, canonical_digest(context_manifest)

    @staticmethod
    def _truncate_context(value: str, limit: int) -> str:
        """Keep a UTF-8-safe source-context prefix with an honest marker."""

        if limit <= 0:
            return ""
        encoded = value.encode("utf-8")
        if len(encoded) <= limit:
            return value
        marker = "\n[Source context truncated at the assistant context boundary.]"
        marker_bytes = marker.encode("utf-8")
        if limit <= len(marker_bytes):
            return marker_bytes[:limit].decode("utf-8", errors="ignore")
        prefix = encoded[: limit - len(marker_bytes)].decode(
            "utf-8",
            errors="ignore",
        )
        return prefix + marker

    @staticmethod
    def _read_instance_context(claim: AssistantClaim) -> str:
        """Read a small, explicit, read-only context slice for known guides.

        Conversation history alone is insufficient for source-backed operator
        guides. The allowlist is intentionally application-specific and never
        follows paths supplied by the user or the model.
        """
        files_by_application = {
            "atm10.speedrun-guide": _ATM10_CONTEXT_FILES,
        }
        relative_files = files_by_application.get(claim.application_id, ())
        if not relative_files:
            return ""
        try:
            data_root = Path(
                os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")
            ).expanduser().resolve() / "stateport"
            catalog_path = data_root / "catalog" / "external-instances.json"
            catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
            entries = catalog.get("entries", [])
            entry = next(
                (
                    item
                    for item in entries
                    if isinstance(item, dict)
                    and item.get("instanceId") == claim.instance_id
                    and item.get("applicationId") == claim.application_id
                ),
                None,
            )
            if not isinstance(entry, dict):
                return _ATM10_CONTEXT_UNAVAILABLE
            filesystem = entry.get("filesystem")
            raw_path = entry.get("path")
            if (
                entry.get("formatVersion") != "stateport.external-catalog-entry/v1"
                or entry.get("status") != "active"
                or not isinstance(filesystem, dict)
                or set(filesystem) != {"device", "inode", "kind"}
                or filesystem.get("kind") != "directory"
                or any(
                    isinstance(filesystem.get(key), bool)
                    or not isinstance(filesystem.get(key), int)
                    or filesystem.get(key) < 0
                    for key in ("device", "inode")
                )
                or not isinstance(raw_path, str)
            ):
                return _ATM10_CONTEXT_UNAVAILABLE
            source_path = Path(raw_path).expanduser()
            if not source_path.is_absolute():
                return _ATM10_CONTEXT_UNAVAILABLE
            root = Path(os.path.abspath(source_path))
            ancestor = Path(root.anchor)
            for part in root.parts[1:]:
                ancestor /= part
                if ancestor.exists() and ancestor.is_symlink():
                    return _ATM10_CONTEXT_UNAVAILABLE
            root_info = os.lstat(root)
            if (
                not stat.S_ISDIR(root_info.st_mode)
                or stat.S_ISLNK(root_info.st_mode)
                or (root_info.st_dev, root_info.st_ino)
                != (filesystem["device"], filesystem["inode"])
            ):
                return _ATM10_CONTEXT_UNAVAILABLE
            root = root.resolve(strict=True)
        except (
            OSError,
            UnicodeError,
            json.JSONDecodeError,
            KeyError,
            TypeError,
            ValueError,
        ):
            return _ATM10_CONTEXT_UNAVAILABLE
        sources: list[tuple[str, str, bool]] = []
        for relative, max_read in relative_files:
            path = root / relative
            try:
                current = root
                for part in Path(relative).parts:
                    current /= part
                    metadata = os.lstat(current)
                    if stat.S_ISLNK(metadata.st_mode):
                        raise OSError("guide source path must not contain a symlink")
                candidate = path.resolve(strict=True)
                candidate.relative_to(root)
                if not stat.S_ISREG(os.lstat(candidate).st_mode):
                    continue
                read_limit = max_read if max_read > 0 else _MAX_INSTANCE_CONTEXT_SOURCE_BYTES
                with candidate.open("rb") as source:
                    raw = source.read(read_limit)
                    source_overflow = bool(source.read(1))
                text = raw.decode("utf-8", errors="ignore")
            except (OSError, UnicodeError, ValueError):
                continue
            if text:
                sources.append((relative, text, source_overflow))
        if not sources:
            return _ATM10_CONTEXT_UNAVAILABLE

        prefix = (
            "Read-only current instance context (source files; not permission to mutate):\n"
        )
        remaining = _MAX_INSTANCE_CONTEXT_BYTES - len(prefix.encode("utf-8"))
        sections: list[str] = []
        for index, (relative, text, source_overflow) in enumerate(sources):
            header = f"[{relative}]\n"
            separator_bytes = len(b"\n\n") if sections else 0
            later_reserve = sum(
                len(f"[{later_relative}]\n".encode("utf-8"))
                + min(
                    _MIN_INSTANCE_CONTEXT_FILE_BYTES,
                    len(later_text.encode("utf-8")),
                )
                for later_relative, later_text, _later_overflow in sources[index + 1 :]
            ) + len(b"\n\n") * len(sources[index + 1 :])
            content_budget = (
                remaining
                - separator_bytes
                - later_reserve
                - len(header.encode("utf-8"))
            )
            if content_budget <= 0:
                continue
            text_bytes = len(text.encode("utf-8"))
            bounded = AssistantProcessor._truncate_context(
                text,
                min(text_bytes, content_budget),
            ) if source_overflow or text_bytes > content_budget else text
            section = header + bounded
            sections.append(section)
            remaining -= separator_bytes + len(section.encode("utf-8"))
            if remaining <= 0:
                break
        if not sections:
            return _ATM10_CONTEXT_UNAVAILABLE
        return prefix + "\n\n".join(sections)

    @staticmethod
    def _render_objective(
        claim: AssistantClaim,
        messages: list[dict[str, object]],
        omitted: int,
        *,
        instance_context: str = "",
    ) -> str:
        lines = [
            f"Application: {claim.application_id}",
            f"Instance: {claim.instance_id}",
            "Conversation context:",
        ]
        if omitted:
            lines.append(
                f"[Omitted {omitted} earlier message(s) due to the explicit context bound.]"
            )
        for item in messages:
            kind = item.get("kind")
            role = (
                "User"
                if kind == "user_message"
                else "Assistant"
                if kind == "assistant_message"
                else "System"
            )
            body = item.get("body")
            if isinstance(body, str):
                lines.append(f"{role}: {body}")
        if instance_context:
            lines.extend(("", instance_context))
        if claim.application_id == "atm10.speedrun-guide":
            lines.extend(("", _ATM10_RESPONSE_GUIDANCE))
        return "\n\n".join(lines)

    def _fail_claim(
        self,
        claim: AssistantClaim,
        code: str,
        message: str,
    ) -> None:
        try:
            self._work.fail(
                work_id=claim.work_id,
                attempt_id=claim.attempt_id,
                lease_token=claim.lease_token,
                code=code,
                message=message[:2048],
            )
        except Exception:
            self._log_event(
                "assistant_processor_failure_persist_error",
                f"work={claim.work_id} error={traceback.format_exc()}",
            )

    def _log_event(self, event: str, detail: str) -> None:
        if self._log is not None:
            try:
                self._log(
                    f"assistant_processor event={event} {detail}\n"
                )
            except Exception:
                pass


__all__ = ["AssistantProcessor"]
