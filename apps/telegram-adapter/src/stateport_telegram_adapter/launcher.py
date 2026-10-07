"""Sanctioned launcher wiring the polling adapter into one ConversationThread.

This is the only sanctioned place that ties the security-hardened polling
boundary to a running :class:`ConversationService`.  It loads the operator-
approved bot credential from the XDG config root, builds an exclusive
``ChannelBinding`` for the single allowlisted operator user, starts the long-
poll thread, and drains outbound deliveries so a web-origin assistant reply
mirrors to Telegram.

``__main__.py`` deliberately cannot start a bot: it only validates hidden
credential entry.  Production wiring flows exclusively through this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import re
import secrets
import stat
import threading
from typing import Any, Callable, Mapping

from stateport_conversation import (
    ChannelBinding,
    ConversationService,
    IngestResult,
    NormalizedInbound,
)

from .polling import (
    LiveTelegramApproval,
    PollBatchResult,
    PollingCursorStore,
    PollingTransport,
    TelegramAdapterError,
    TelegramBotApiTransport,
    TelegramCredentials,
    TelegramPermanentError,
    TelegramPollingRuntime,
    TelegramUpdateNormalizer,
)


_APPROVAL_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_POLL_TIMEOUT_SECONDS = 30
_DRAIN_INTERVAL_SECONDS = 1.0
_STOP_JOIN_TIMEOUT = 5.0
_POLL_BACKOFF_DELAYS = (5.0, 15.0, 30.0, 60.0, 120.0)
_MAX_TOKEN_FILE_BYTES = 4096


@dataclass(frozen=True)
class LauncherStatus:
    """Redacted, path-free projection of the launcher state."""

    enabled: bool
    reason: str | None
    degraded: str | None
    operator_user_id: int | None
    application_id: str | None
    instance_id: str | None
    conversation_id: str | None
    binding_id: str | None
    polling: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "reason": self.reason,
            "degraded": self.degraded,
            "operatorUserId": self.operator_user_id,
            "applicationId": self.application_id,
            "instanceId": self.instance_id,
            "conversationId": self.conversation_id,
            "bindingId": self.binding_id,
            "polling": self.polling,
        }


def _default_transport_factory(
    credentials: TelegramCredentials,
    approval: LiveTelegramApproval,
) -> PollingTransport:
    return TelegramBotApiTransport(credentials, approval)


class TelegramLiveLauncher:
    """Wire the polling adapter into one ConversationThread.

    The launcher is constructed once at service startup.  It auto-disables
    when the token file is absent, has unsafe permissions, or the operator
    allowlist is empty, so the persistent service starts exactly as today.
    Once attached to a conversation, the Telegram bot is exclusive to the
    single allowlisted operator user id; no other sender or chat is accepted.
    """

    def __init__(
        self,
        *,
        config_root: Path,
        runtime_root: Path,
        conversation_service: ConversationService,
        operator_user_id: int | None = None,
        application_id: str | None = None,
        instance_id: str | None = None,
        transport_factory: Callable[[TelegramCredentials, LiveTelegramApproval], PollingTransport] | None = None,
        poll_backoff_delays: tuple[float, ...] | None = None,
        poll_timeout_seconds: int | None = None,
        auto_reply: bool = False,
    ) -> None:
        self._config_root = Path(config_root)
        self._runtime_root = Path(runtime_root)
        self._conversation_service = conversation_service
        self._auto_reply = auto_reply
        self._transport_factory = transport_factory or _default_transport_factory
        self._poll_backoff_delays = poll_backoff_delays if poll_backoff_delays is not None else _POLL_BACKOFF_DELAYS
        self._poll_timeout_seconds = poll_timeout_seconds if poll_timeout_seconds is not None else _POLL_TIMEOUT_SECONDS
        self._operator_user_id: int | None = None
        self._application_id: str | None = None
        self._instance_id: str | None = None
        self._credentials: TelegramCredentials | None = None
        self._reason: str | None = None
        self._degraded_reason: str | None = None
        self._binding: ChannelBinding | None = None
        self._approval: LiveTelegramApproval | None = None
        self._transport: PollingTransport | None = None
        self._normalizer: TelegramUpdateNormalizer | None = None
        self._cursor_store: PollingCursorStore | None = None
        self._runtime: TelegramPollingRuntime | None = None
        self._participant_id: str | None = None
        self._conversation_id: str | None = None
        self._cancel_event: threading.Event | None = None
        self._poll_thread: threading.Thread | None = None
        self._drain_thread: threading.Thread | None = None
        self._last_delivered_sequence = 0
        self._sent_external_ids: set[str] = set()
        self._load(operator_user_id, application_id, instance_id)

    def _load(self, operator_user_id: int | None, application_id: str | None = None, instance_id: str | None = None) -> None:
        token_path = self._config_root / "secrets" / "telegram.env"
        operator_path = self._config_root / "operator.yaml"
        token = _load_token(token_path)
        if token is None:
            self._reason = "token_missing"
            return
        allowed_ids = _load_allowed_user_ids(operator_path)
        if not allowed_ids:
            self._reason = "allowlist_empty"
            return
        if operator_user_id is None:
            if len(allowed_ids) != 1:
                self._reason = "allowlist_ambiguous"
                return
            operator_user_id = next(iter(allowed_ids))
        elif operator_user_id not in allowed_ids:
            self._reason = "operator_not_allowlisted"
            return
        app_id = application_id or _load_application_id(operator_path)
        inst_id = instance_id or _load_instance_id(operator_path)
        if not app_id or not inst_id:
            self._reason = "binding_not_configured"
            return
        try:
            credentials = TelegramCredentials(token)
        except (TypeError, ValueError):
            self._reason = "token_invalid_shape"
            return
        self._credentials = credentials
        self._operator_user_id = operator_user_id
        self._application_id = app_id
        self._instance_id = inst_id
        self._reason = None

    @property
    def enabled(self) -> bool:
        return self._credentials is not None and self._operator_user_id is not None

    @property
    def attached(self) -> bool:
        return self._binding is not None

    @property
    def binding(self) -> ChannelBinding | None:
        return self._binding

    @property
    def approval(self) -> LiveTelegramApproval | None:
        return self._approval

    @property
    def normalizer(self) -> TelegramUpdateNormalizer | None:
        return self._normalizer

    @property
    def operator_user_id(self) -> int | None:
        return self._operator_user_id

    @property
    def application_id(self) -> str | None:
        return self._application_id

    @property
    def instance_id(self) -> str | None:
        return self._instance_id

    def status(self) -> LauncherStatus:
        return LauncherStatus(
            enabled=self.enabled,
            reason=self._reason,
            degraded=self._degraded_reason,
            operator_user_id=self._operator_user_id,
            application_id=self._application_id,
            instance_id=self._instance_id,
            conversation_id=self._conversation_id,
            binding_id=self._binding.binding_id if self._binding else None,
            polling=self._poll_thread is not None and self._poll_thread.is_alive(),
        )

    def attach(
        self,
        *,
        participant_id: str,
        conversation_id: str,
    ) -> ChannelBinding | None:
        """Bind the Telegram channel onto an existing ConversationThread."""

        if not self.enabled:
            return None
        if self._binding is not None:
            return self._binding
        assert self._credentials is not None
        assert self._operator_user_id is not None
        thread = self._conversation_service.thread(
            participant_id=participant_id,
            conversation_id=conversation_id,
        )
        sender_digest = self._credentials.identity_digest("sender", self._operator_user_id)
        chat_digest = self._credentials.identity_digest("chat", self._operator_user_id)
        binding = self._conversation_service.bind_channel(
            participant_id=participant_id,
            conversation_id=conversation_id,
            channel="telegram",
            external_identity_digest=sender_digest,
            external_conversation_digest=chat_digest,
        )
        reference = _stable_reference(thread.application_id, thread.instance_id)
        approval = LiveTelegramApproval(
            reference=reference,
            binding_id=binding.binding_id,
            chat_identity_digest=chat_digest,
            allow_polling=True,
            allow_sending=True,
        )
        transport = self._transport_factory(self._credentials, approval)
        normalizer = TelegramUpdateNormalizer(binding, self._credentials)
        cursor_store = PollingCursorStore(
            state_root=self._runtime_root / "telegram",
            route_reference=reference,
        )
        sink = _SinkAdapter(self._conversation_service, participant_id, self._auto_reply_to)
        runtime = TelegramPollingRuntime(transport, normalizer, cursor_store, sink)
        self._binding = binding
        self._approval = approval
        self._transport = transport
        self._normalizer = normalizer
        self._cursor_store = cursor_store
        self._runtime = runtime
        self._participant_id = participant_id
        self._conversation_id = conversation_id
        return binding

    def _auto_reply_to(self, result: IngestResult) -> None:
        """Provide a bounded live-demo reply after accepted Telegram input."""

        if not self._auto_reply or result.status != "accepted" or result.message is None:
            return
        if self._conversation_id is None or self._participant_id is None:
            return
        text = result.message.body.strip()
        command = text.casefold()
        if command in {"/start", "/help"}:
            body = (
                "StatePort Telegram demo is online.\n\n"
                "Inbound messages are accepted, deduplicated, and routed to the shared conversation.\n"
                "Send any text to receive a delivery acknowledgement."
            )
        else:
            body = f"Received by StatePort: {text}"
        self._conversation_service.send_internal(
            participant_id=self._participant_id,
            conversation_id=self._conversation_id,
            body=body,
            kind="assistant_message",
        )

    def start(self) -> None:
        """Start the poller and outbound-drain threads (daemon, bounded)."""

        if not self.attached or self._poll_thread is not None:
            return
        self._cancel_event = threading.Event()
        self._poll_thread = threading.Thread(
            target=self._run_poll,
            name="stateport-telegram-poller",
            daemon=True,
        )
        self._drain_thread = threading.Thread(
            target=self._run_drain,
            name="stateport-telegram-drain",
            daemon=True,
        )
        self._poll_thread.start()
        self._drain_thread.start()

    def stop(self) -> None:
        """Signal cancellation, join bounded, and let the cursor lease release."""

        event = self._cancel_event
        if event is not None:
            event.set()
        poll_thread = self._poll_thread
        if poll_thread is not None and poll_thread.is_alive():
            poll_thread.join(timeout=_STOP_JOIN_TIMEOUT)
        drain_thread = self._drain_thread
        if drain_thread is not None and drain_thread.is_alive():
            drain_thread.join(timeout=_STOP_JOIN_TIMEOUT)
        self._poll_thread = None
        self._drain_thread = None
        self._cancel_event = None

    def _run_poll(self) -> None:
        assert self._cancel_event is not None
        assert self._runtime is not None
        backoff_index = 0
        while not self._cancel_event.is_set():
            self._degraded_reason = None
            try:
                self._runtime.run(self._cancel_event, timeout_seconds=self._poll_timeout_seconds)
            except TelegramAdapterError as exc:
                if self._cancel_event.is_set():
                    return
                self._degraded_reason = getattr(exc, 'code', 'adapter_error') or 'adapter_error'
                delays = self._poll_backoff_delays
                delay = delays[backoff_index] if backoff_index < len(delays) else delays[-1]
                backoff_index = min(backoff_index + 1, len(delays) - 1)
                if self._cancel_event.wait(delay):
                    return

    def _run_drain(self) -> None:
        assert self._cancel_event is not None
        while not self._cancel_event.is_set():
            try:
                self.drain_deliveries()
            except Exception:
                # Outbound drain failures are transient and must not crash the
                # service.  Planned receipts remain planned for the next cycle.
                pass
            self._cancel_event.wait(_DRAIN_INTERVAL_SECONDS)

    def poll_once(self, *, timeout_seconds: int = 0, limit: int = 100) -> PollBatchResult:
        """Single synchronous poll for deterministic tests."""

        if self._runtime is None:
            raise RuntimeError("telegram launcher is not attached")
        return self._runtime.poll_once(timeout_seconds=timeout_seconds, limit=limit)

    def drain_deliveries(self) -> int:
        """Mirror pending outbound messages to Telegram, respecting echo guards.

        Messages whose source channel is ``telegram`` are skipped (never echoed
        back).  Only ``web``-origin assistant/internal messages are mirrored.
        """

        if not self.attached or self._transport is None or self._participant_id is None:
            return 0
        assert self._binding is not None
        assert self._conversation_id is not None
        messages, _cursor = self._conversation_service.list_messages(
            participant_id=self._participant_id,
            conversation_id=self._conversation_id,
            limit=200,
        )
        sent = 0
        for message in messages:
            if message.sequence <= self._last_delivered_sequence:
                continue
            if message.source_channel == "telegram":
                self._last_delivered_sequence = message.sequence
                continue
            try:
                receipts = self._conversation_service.plan_deliveries(
                    participant_id=self._participant_id,
                    message_id=message.message_id,
                )
                telegram_receipt = next(
                    (
                        receipt
                        for receipt in receipts
                        if receipt.channel == "telegram"
                        and receipt.binding_id == self._binding.binding_id
                    ),
                    None,
                )
                if telegram_receipt is None or telegram_receipt.status != "planned":
                    self._last_delivered_sequence = message.sequence
                    continue
                assert self._operator_user_id is not None
                external_id = self._transport.send_message(
                    chat_id=self._operator_user_id,
                    text=message.body,
                )
                external_id_str = str(external_id)
                self._conversation_service.record_delivery(
                    participant_id=self._participant_id,
                    delivery_id=telegram_receipt.delivery_id,
                    status="delivered",
                    external_message_id=external_id_str,
                )
                self._sent_external_ids.add(external_id_str)
            except Exception:
                # Stop at the first failure so the next drain cycle retries
                # from this message without skipping pending receipts.
                break
            self._last_delivered_sequence = message.sequence
            sent += 1
        return sent


class _SinkAdapter:
    """Bridge NormalizedInbound to ConversationService.ingest.

    ``IngestResult.status`` is already ``accepted``/``duplicate``/
    ``echo_suppressed`` — the exact ack vocabulary the poller requires — so
    no adaptation is needed and the poller's ack contract is preserved.
    """

    __slots__ = ("_service", "_participant_id", "_on_ingest")

    def __init__(self, service: ConversationService, participant_id: str, on_ingest: Callable[[IngestResult], None] | None = None) -> None:
        self._service = service
        self._participant_id = participant_id
        self._on_ingest = on_ingest

    def __call__(self, inbound: NormalizedInbound) -> IngestResult:
        result = self._service.ingest(participant_id=self._participant_id, inbound=inbound)
        if self._on_ingest is not None:
            self._on_ingest(result)
        return result


def _stable_reference(application_id: str, instance_id: str) -> str:
    raw = f"stateport.telegram.live.{application_id}.{instance_id}"
    cleaned = re.sub(r"[^A-Za-z0-9._:-]", "-", raw)
    if not _APPROVAL_REFERENCE.fullmatch(cleaned):
        cleaned = f"stateport.telegram.{secrets.token_hex(8)}"
    return cleaned[:200]


def _load_token(path: Path) -> str | None:
    """Read a bounded bot credential through a no-follow file descriptor."""

    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        # StatePort's supported launcher target is Linux.  On a platform that
        # cannot atomically reject a final-component symlink, fail closed
        # instead of falling back to a vulnerable check-then-open sequence.
        return None
    flags = os.O_RDONLY | no_follow | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            return None
        if metadata.st_mode & 0o077:
            return None
        if metadata.st_size > _MAX_TOKEN_FILE_BYTES:
            return None

        payload = bytearray()
        while len(payload) <= _MAX_TOKEN_FILE_BYTES:
            chunk = os.read(
                descriptor,
                min(4096, _MAX_TOKEN_FILE_BYTES + 1 - len(payload)),
            )
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > _MAX_TOKEN_FILE_BYTES:
            return None
    except OSError:
        return None
    finally:
        os.close(descriptor)

    try:
        text = bytes(payload).decode("utf-8")
    except UnicodeDecodeError:
        return None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("TELEGRAM_BOT_TOKEN="):
            return line[len("TELEGRAM_BOT_TOKEN="):].strip() or None
    return None


def _load_telegram_section(path: Path) -> Mapping[str, Any] | None:
    """Parse and return the raw ``telegram`` section of operator.yaml."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    value: object
    try:
        import yaml  # type: ignore[import-not-found]
        value = yaml.safe_load(text)
    except Exception:
        value = _parse_operator_yaml(text)
    if not isinstance(value, Mapping):
        return None
    telegram = value.get("telegram")
    if not isinstance(telegram, Mapping):
        return None
    return telegram


def _load_application_id(path: Path) -> str | None:
    section = _load_telegram_section(path)
    if section is None:
        return None
    raw = section.get("application_id")
    return str(raw) if isinstance(raw, str) and raw else None


def _load_instance_id(path: Path) -> str | None:
    section = _load_telegram_section(path)
    if section is None:
        return None
    raw = section.get("instance_id")
    return str(raw) if isinstance(raw, str) and raw else None


def _load_allowed_user_ids(path: Path) -> set[int]:
    """Parse the fixed-shape operator.yaml allowlist, with or without PyYAML."""

    telegram = _load_telegram_section(path)
    if telegram is None:
        return set()
    raw_ids = telegram.get("allowed_telegram_user_ids")
    if not isinstance(raw_ids, list):
        return set()
    ids: set[int] = set()
    for item in raw_ids:
        if isinstance(item, bool):
            continue
        if isinstance(item, int) and item > 0:
            ids.add(item)
        elif isinstance(item, str) and item.isdigit():
            ids.add(int(item))
    return ids


def _parse_operator_yaml(text: str) -> Mapping[str, Any]:
    """Hand-parse the fixed-shape operator.yaml when PyYAML is unavailable."""

    result: dict[str, Any] = {}
    current_section: dict[str, Any] | None = None
    current_list: list[Any] | None = None
    for raw_line in text.splitlines():
        stripped = raw_line.rstrip()
        if not stripped or stripped.lstrip().startswith("#"):
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        line = stripped.lstrip()
        if indent == 0 and line.endswith(":"):
            current_section = {}
            current_list = None
            result[line[:-1]] = current_section
        elif indent == 2 and current_section is not None and line.endswith(":"):
            current_list = []
            current_section[line[:-1]] = current_list
        elif indent >= 4 and line.startswith("- ") and current_list is not None:
            item_text = line[2:].strip()
            if item_text.isdigit():
                current_list.append(int(item_text))
            elif item_text in {"true", "false"}:
                current_list.append(item_text == "true")
            else:
                current_list.append(item_text)
        elif indent == 2 and current_section is not None and ":" in line:
            key, _, value_text = line.partition(":")
            cleaned = value_text.strip()
            if cleaned.isdigit():
                current_section[key.strip()] = int(cleaned)
            elif cleaned in {"true", "false"}:
                current_section[key.strip()] = cleaned == "true"
            else:
                current_section[key.strip()] = cleaned
    return result
