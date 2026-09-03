"""Restart-safe, approval-gated Telegram long-polling boundary.

The runtime in this module does not own conversation state and cannot execute a
StatePort action.  It verifies one already-authorized channel binding, maps a
bounded Telegram update to ``NormalizedInbound``, and hands that value to an
injected StatePort conversation sink.  Only an acknowledged sink result may
advance the durable provider cursor.

No live transport is constructed implicitly.  A caller must supply an exact
live approval and credentials obtained through a non-echoing prompt.  Tests use
injected deterministic transports and never contact Telegram.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import getpass
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import stat
import threading
from typing import Any, Callable, Iterator, Mapping, Protocol, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from stateport_conversation import ChannelBinding, NormalizedInbound


_APPROVAL_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_BOT_CREDENTIAL = re.compile(r"^[0-9]{5,20}:[A-Za-z0-9_-]{20,80}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_CURSOR_FORMAT = "stateport.telegram-polling-cursor/v1"
_MAX_PROVIDER_BODY = 4 * 1024 * 1024
_MAX_UPDATES = 100
_MAX_TEXT = 16 * 1024
_MAX_JSON_DEPTH = 12
_API_ORIGIN = "https://api.telegram.org"
_SAFE_ACK_STATUSES = frozenset({"accepted", "duplicate", "echo_suppressed"})
_PER_UPDATE_REFUSAL_CODES = frozenset({
    "invalid_update",
    "invalid_update_identity",
    "bot_sender_refused",
    "unbound_chat",
    "unbound_sender",
    "invalid_reply",
})


class TelegramAdapterError(RuntimeError):
    """Safe adapter failure which never includes provider payload or credentials."""

    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message)
        self.code = code


class TelegramTransientError(TelegramAdapterError):
    """Retryable transport failure."""


class TelegramPermanentError(TelegramAdapterError):
    """Non-retryable configuration or provider-contract failure."""


@dataclass(frozen=True)
class LiveTelegramApproval:
    """Exact operator approval required before a network client can exist."""

    reference: str
    binding_id: str
    chat_identity_digest: str
    allow_polling: bool
    allow_sending: bool = False

    def __post_init__(self) -> None:
        if not _APPROVAL_REFERENCE.fullmatch(self.reference):
            raise ValueError("live Telegram approval reference is invalid")
        if not _APPROVAL_REFERENCE.fullmatch(self.binding_id):
            raise ValueError("live Telegram binding reference is invalid")
        if not _DIGEST.fullmatch(self.chat_identity_digest):
            raise ValueError("live Telegram chat identity digest is invalid")
        if not isinstance(self.allow_polling, bool) or not isinstance(self.allow_sending, bool):
            raise TypeError("live Telegram approval flags must be booleans")
        if not self.allow_polling and not self.allow_sending:
            raise ValueError("live Telegram approval must authorize an exact operation")


class TelegramCredentials:
    """In-memory credential wrapper with a deliberately redacted representation."""

    __slots__ = ("__credential", "__identity_key")

    def __init__(self, credential: str) -> None:
        if not isinstance(credential, str) or not _BOT_CREDENTIAL.fullmatch(credential):
            raise ValueError("Telegram bot credential has an invalid shape")
        self.__credential = credential
        self.__identity_key = hmac.new(
            credential.encode("utf-8"),
            b"stateport.telegram.identity-binding/v1",
            hashlib.sha256,
        ).digest()

    def __repr__(self) -> str:
        return "TelegramCredentials(<redacted>)"

    @classmethod
    def prompt(
        cls,
        approval: LiveTelegramApproval,
        *,
        prompt_fn: Callable[[str], str] = getpass.getpass,
    ) -> "TelegramCredentials":
        """Read the bot credential without terminal echo after approval exists."""

        if not isinstance(approval, LiveTelegramApproval):
            raise TypeError("an exact live Telegram approval is required before credential entry")
        return cls(prompt_fn("Telegram bot credential (input hidden): ").strip())

    def identity_digest(self, namespace: str, provider_identity: int) -> str:
        if namespace not in {"chat", "sender"}:
            raise ValueError("Telegram identity namespace is unsupported")
        provider_identity = _validate_provider_identity(provider_identity)
        digest = hmac.new(
            self.__identity_key,
            f"{namespace}:{provider_identity}".encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        return f"sha256:{digest}"

    def _endpoint(self, method: str) -> str:
        if method not in {"getUpdates", "sendMessage"}:
            raise ValueError("Telegram Bot API method is unsupported")
        return f"{_API_ORIGIN}/bot{self.__credential}/{method}"


class PollingTransport(Protocol):
    """Injected polling transport used by the coordinator."""

    def get_updates(self, *, offset: int, timeout_seconds: int, limit: int) -> Sequence[Mapping[str, Any]]:
        """Return an ordered batch of provider updates."""


class TelegramBotApiTransport:
    """Minimal Bot API transport which exists only behind exact live approval."""

    def __init__(
        self,
        credentials: TelegramCredentials,
        approval: LiveTelegramApproval,
        *,
        opener: Callable[..., Any] = urlopen,
    ) -> None:
        if not isinstance(credentials, TelegramCredentials):
            raise TypeError("Telegram credentials must use the redacting credential wrapper")
        if not isinstance(approval, LiveTelegramApproval):
            raise TypeError("an exact live Telegram approval is required")
        self.__credentials = credentials
        self.approval = approval
        self._opener = opener

    def __repr__(self) -> str:
        return f"TelegramBotApiTransport(approval={self.approval.reference!r}, credential=<redacted>)"

    def _call(self, method: str, fields: Mapping[str, object], *, timeout: float) -> object:
        request = Request(
            self.__credentials._endpoint(method),
            data=urlencode(fields).encode("ascii"),
            method="POST",
            headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            with self._opener(request, timeout=timeout) as response:
                body = response.read(_MAX_PROVIDER_BODY + 1)
        except HTTPError as exc:
            if exc.code == 429 or 500 <= exc.code <= 599:
                raise TelegramTransientError("Telegram provider request is temporarily unavailable", code="provider_transient") from None
            raise TelegramPermanentError("Telegram provider refused the request", code="provider_refused") from None
        except (URLError, TimeoutError, OSError):
            raise TelegramTransientError("Telegram provider could not be reached", code="provider_unavailable") from None
        if len(body) > _MAX_PROVIDER_BODY:
            raise TelegramPermanentError("Telegram provider response exceeded the safety limit", code="provider_response_too_large")
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise TelegramPermanentError("Telegram provider response was invalid", code="invalid_provider_response") from None
        if not isinstance(payload, Mapping) or not isinstance(payload.get("ok"), bool):
            raise TelegramPermanentError("Telegram provider response was invalid", code="invalid_provider_response")
        if payload["ok"] is not True:
            error_code = payload.get("error_code")
            if error_code == 429 or not isinstance(error_code, bool) and isinstance(error_code, int) and 500 <= error_code <= 599:
                raise TelegramTransientError("Telegram provider request is temporarily unavailable", code="provider_transient")
            raise TelegramPermanentError("Telegram provider refused the request", code="provider_refused")
        if "result" not in payload:
            raise TelegramPermanentError("Telegram provider response was invalid", code="invalid_provider_response")
        return payload["result"]

    def get_updates(self, *, offset: int, timeout_seconds: int = 30, limit: int = _MAX_UPDATES) -> Sequence[Mapping[str, Any]]:
        if not self.approval.allow_polling:
            raise TelegramPermanentError("live Telegram polling is not approved", code="polling_not_approved")
        _validate_offset(offset)
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or not 0 <= timeout_seconds <= 50:
            raise ValueError("Telegram polling timeout must be between 0 and 50 seconds")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= _MAX_UPDATES:
            raise ValueError("Telegram polling limit must be between 1 and 100")
        result = self._call(
            "getUpdates",
            {
                "offset": offset,
                "timeout": timeout_seconds,
                "limit": limit,
                "allowed_updates": json.dumps(["message"], separators=(",", ":")),
            },
            timeout=float(timeout_seconds + 10),
        )
        if not isinstance(result, list) or len(result) > limit or any(not isinstance(item, Mapping) for item in result):
            raise TelegramPermanentError("Telegram update batch was invalid", code="invalid_update_batch")
        return result

    def send_message(self, *, chat_id: int, text: str, reply_to_message_id: int | None = None) -> int:
        """Perform one explicitly approved L3 send and return its provider id."""

        if not self.approval.allow_sending:
            raise TelegramPermanentError("live Telegram sending is not approved", code="sending_not_approved")
        chat_id = _validate_provider_identity(chat_id)
        if not hmac.compare_digest(self.__credentials.identity_digest("chat", chat_id), self.approval.chat_identity_digest):
            raise TelegramPermanentError("Telegram send target is not the approved binding", code="unbound_send_target")
        _validate_text(text)
        fields: dict[str, object] = {"chat_id": chat_id, "text": text}
        if reply_to_message_id is not None:
            fields["reply_to_message_id"] = _validate_message_id(reply_to_message_id)
        result = self._call("sendMessage", fields, timeout=20.0)
        if not isinstance(result, Mapping):
            raise TelegramPermanentError("Telegram send response was invalid", code="invalid_send_response")
        return _validate_message_id(result.get("message_id"))


@dataclass(frozen=True)
class PollingCursor:
    next_offset: int

    def to_dict(self) -> dict[str, object]:
        return {"formatVersion": _CURSOR_FORMAT, "nextOffset": self.next_offset}


class PollingCursorStore:
    """Atomic, monotonic polling checkpoint without message or identity content."""

    def __init__(self, state_root: Path, route_reference: str) -> None:
        if not _APPROVAL_REFERENCE.fullmatch(route_reference):
            raise ValueError("Telegram cursor route reference is invalid")
        self.root = Path(state_root)
        for candidate in (self.root, *self.root.parents):
            if candidate.exists() and candidate.is_symlink():
                raise TelegramPermanentError("Telegram cursor path cannot contain symlinks", code="unsafe_cursor_path")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        route_digest = hashlib.sha256(route_reference.encode("utf-8")).hexdigest()[:32]
        self.directory = self.root / route_digest
        if self.directory.exists() and self.directory.is_symlink():
            raise TelegramPermanentError("Telegram cursor directory cannot be a symlink", code="unsafe_cursor_path")
        self.directory.mkdir(mode=0o700, exist_ok=True)
        if self.directory.is_symlink():
            raise TelegramPermanentError("Telegram cursor directory cannot be a symlink", code="unsafe_cursor_path")
        os.chmod(self.directory, 0o700)
        self.path = self.directory / "polling-cursor.json"
        self.lock_path = self.directory / "polling-cursor.lock"

    def load(self) -> PollingCursor:
        if self.path.is_symlink():
            raise TelegramPermanentError("Telegram cursor file is unsafe", code="unsafe_cursor_file")
        if not self.path.exists():
            return PollingCursor(0)
        metadata = self.path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_size > 4096:
            raise TelegramPermanentError("Telegram cursor file is unsafe", code="unsafe_cursor_file")
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            raise TelegramPermanentError("Telegram cursor file is invalid", code="invalid_cursor") from None
        if not isinstance(payload, Mapping) or set(payload) != {"formatVersion", "nextOffset"} or payload["formatVersion"] != _CURSOR_FORMAT:
            raise TelegramPermanentError("Telegram cursor file is invalid", code="invalid_cursor")
        return PollingCursor(_validate_offset(payload["nextOffset"]))

    def save(self, next_offset: int) -> PollingCursor:
        next_offset = _validate_offset(next_offset)
        current = self.load()
        if next_offset < current.next_offset:
            raise TelegramPermanentError("Telegram cursor cannot move backwards", code="cursor_regression")
        cursor = PollingCursor(next_offset)
        temporary = self.directory / f".polling-cursor.{os.getpid()}.{threading.get_ident()}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(temporary, flags, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(cursor.to_dict(), handle, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            directory_descriptor = os.open(self.directory, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        finally:
            temporary.unlink(missing_ok=True)
        return cursor

    @contextmanager
    def lease(self) -> Iterator[None]:
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.lock_path, flags, 0o600)
        try:
            os.chmod(self.lock_path, 0o600)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise TelegramTransientError("another Telegram poller owns this route", code="poller_lease_busy") from None
            yield
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)


class TelegramUpdateNormalizer:
    """Map one bounded Bot API update to one authorized conversation input."""

    def __init__(self, binding: ChannelBinding, credentials: TelegramCredentials) -> None:
        if binding.channel != "telegram" or binding.status != "active":
            raise ValueError("Telegram update normalizer requires an active Telegram binding")
        if not isinstance(credentials, TelegramCredentials):
            raise TypeError("Telegram identity mapping requires redacting credentials")
        self.binding = binding
        self.credentials = credentials

    def normalize(self, update: Mapping[str, Any]) -> tuple[int, NormalizedInbound | None]:
        _bounded_json(update, "Telegram update")
        update_id = _validate_update_id(update.get("update_id"))
        message = update.get("message")
        if message is None:
            return update_id, None
        if not isinstance(message, Mapping):
            raise TelegramPermanentError("Telegram message update was invalid", code="invalid_update")
        message_id = _validate_message_id(message.get("message_id"))
        sent_at = _provider_timestamp(message.get("date"))
        chat = message.get("chat")
        sender = message.get("from")
        if not isinstance(chat, Mapping) or not isinstance(sender, Mapping):
            raise TelegramPermanentError("Telegram message identity was invalid", code="invalid_update_identity")
        if sender.get("is_bot") is not False:
            raise TelegramPermanentError("Telegram bot-authored input is not accepted", code="bot_sender_refused")
        chat_id = _validate_provider_identity(chat.get("id"))
        sender_id = _validate_provider_identity(sender.get("id"))
        chat_digest = self.credentials.identity_digest("chat", chat_id)
        sender_digest = self.credentials.identity_digest("sender", sender_id)
        if not hmac.compare_digest(chat_digest, self.binding.external_conversation_digest):
            raise TelegramPermanentError("Telegram chat is not authorized for this binding", code="unbound_chat")
        if not hmac.compare_digest(sender_digest, self.binding.external_identity_digest):
            raise TelegramPermanentError("Telegram sender is not authorized for this binding", code="unbound_sender")
        text = message.get("text")
        if text is None:
            # Non-text messages are acknowledged without copying content or
            # creating work.  Future attachment support must remain metadata-only.
            return update_id, None
        _validate_text(text)
        reply_id: str | None = None
        reply = message.get("reply_to_message")
        if reply is not None:
            if not isinstance(reply, Mapping):
                raise TelegramPermanentError("Telegram reply identity was invalid", code="invalid_reply")
            reply_id = str(_validate_message_id(reply.get("message_id")))
        return update_id, NormalizedInbound(
            channel="telegram",
            binding_id=self.binding.binding_id,
            external_message_id=str(message_id),
            provider_event_id=str(update_id),
            sender_identity_digest=sender_digest,
            sent_at=sent_at,
            body=text,
            reply_to_external_message_id=reply_id,
            attachments=(),
            echo_guard=None,
        )


@dataclass(frozen=True)
class PollBatchResult:
    start_offset: int
    next_offset: int
    received: int
    accepted: int
    duplicates: int
    echoes_suppressed: int
    ignored: int

    def to_dict(self) -> dict[str, int]:
        return {
            "startOffset": self.start_offset,
            "nextOffset": self.next_offset,
            "received": self.received,
            "accepted": self.accepted,
            "duplicates": self.duplicates,
            "echoesSuppressed": self.echoes_suppressed,
            "ignored": self.ignored,
        }


class TelegramPollingRuntime:
    """Poll, normalize, acknowledge through StatePort, then checkpoint."""

    def __init__(
        self,
        transport: PollingTransport,
        normalizer: TelegramUpdateNormalizer,
        cursor_store: PollingCursorStore,
        sink: Callable[[NormalizedInbound], object],
    ) -> None:
        if not hasattr(transport, "get_updates") or not callable(transport.get_updates):
            raise TypeError("Telegram polling transport must provide get_updates")
        if not callable(sink):
            raise TypeError("Telegram polling sink must be callable")
        self.transport = transport
        self.normalizer = normalizer
        self.cursor_store = cursor_store
        self.sink = sink
        if isinstance(transport, TelegramBotApiTransport):
            if (
                transport.approval.binding_id != normalizer.binding.binding_id
                or not hmac.compare_digest(
                    transport.approval.chat_identity_digest,
                    normalizer.binding.external_conversation_digest,
                )
            ):
                raise TelegramPermanentError("live Telegram approval does not match the channel binding", code="approval_binding_mismatch")

    def poll_once(self, *, timeout_seconds: int = 30, limit: int = _MAX_UPDATES) -> PollBatchResult:
        with self.cursor_store.lease():
            start = self.cursor_store.load().next_offset
            raw_updates = self.transport.get_updates(offset=start, timeout_seconds=timeout_seconds, limit=limit)
            if not isinstance(raw_updates, Sequence) or isinstance(raw_updates, (str, bytes)) or len(raw_updates) > limit:
                raise TelegramPermanentError("Telegram update batch was invalid", code="invalid_update_batch")
            update_ids = [
                _validate_update_id(item.get("update_id"))
                if isinstance(item, Mapping)
                else _raise_invalid_update()
                for item in raw_updates
            ]
            if update_ids != sorted(set(update_ids)):
                raise TelegramPermanentError("Telegram update ordering was invalid", code="invalid_update_order")
            accepted = duplicates = echoes = ignored = 0
            next_offset = start
            for raw_update, update_id in zip(raw_updates, update_ids, strict=True):
                if update_id < next_offset:
                    ignored += 1
                    continue
                try:
                    normalized_id, inbound = self.normalizer.normalize(raw_update)
                except TelegramPermanentError as exc:
                    if exc.code in _PER_UPDATE_REFUSAL_CODES:
                        ignored += 1
                        next_offset = update_id + 1
                        self.cursor_store.save(next_offset)
                        continue
                    raise
                if normalized_id != update_id:
                    raise TelegramPermanentError("Telegram update identity changed during normalization", code="invalid_update")
                if inbound is None:
                    ignored += 1
                else:
                    result = self.sink(inbound)
                    status = getattr(result, "status", None)
                    if status not in _SAFE_ACK_STATUSES:
                        raise TelegramPermanentError("StatePort did not acknowledge the Telegram update", code="sink_not_acknowledged")
                    if status == "accepted":
                        accepted += 1
                    elif status == "duplicate":
                        duplicates += 1
                    else:
                        echoes += 1
                next_offset = update_id + 1
                self.cursor_store.save(next_offset)
            return PollBatchResult(start, next_offset, len(raw_updates), accepted, duplicates, echoes, ignored)

    def run(
        self,
        cancel_event: threading.Event,
        *,
        timeout_seconds: int = 30,
        retry_delays: tuple[float, ...] = (1.0, 2.0, 5.0, 10.0, 30.0),
    ) -> None:
        """Run bounded transient retries until cancellation or permanent failure."""

        if not isinstance(cancel_event, threading.Event):
            raise TypeError("Telegram cancellation must use threading.Event")
        failures = 0
        while not cancel_event.is_set():
            try:
                self.poll_once(timeout_seconds=timeout_seconds)
                failures = 0
            except TelegramTransientError:
                if failures >= len(retry_delays):
                    raise TelegramTransientError("Telegram polling retry budget was exhausted", code="retry_exhausted") from None
                delay = retry_delays[failures]
                failures += 1
                if cancel_event.wait(delay):
                    return


def _validate_offset(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2**63 - 1:
        raise TelegramPermanentError("Telegram polling offset is invalid", code="invalid_offset")
    return value


def _validate_update_id(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**63 - 1:
        raise TelegramPermanentError("Telegram update identity is invalid", code="invalid_update")
    return value


def _validate_message_id(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 2**63 - 1:
        raise TelegramPermanentError("Telegram message identity is invalid", code="invalid_message")
    return value


def _validate_provider_identity(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value == 0 or abs(value) > 2**63 - 1:
        raise TelegramPermanentError("Telegram provider identity is invalid", code="invalid_identity")
    return value


def _validate_text(value: object) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > _MAX_TEXT or "\x00" in value:
        raise TelegramPermanentError("Telegram message text is invalid", code="invalid_message_text")
    return value


def _provider_timestamp(value: object) -> str:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 253402300799:
        raise TelegramPermanentError("Telegram message timestamp is invalid", code="invalid_timestamp")
    try:
        return datetime.fromtimestamp(value, timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        raise TelegramPermanentError("Telegram message timestamp is invalid", code="invalid_timestamp") from None


def _bounded_json(value: object, label: str) -> None:
    def visit(item: object, depth: int) -> None:
        if depth > _MAX_JSON_DEPTH:
            raise TelegramPermanentError(f"{label} exceeded the nesting limit", code="provider_payload_too_deep")
        if isinstance(item, Mapping):
            if len(item) > 128 or any(not isinstance(key, str) or len(key) > 128 for key in item):
                raise TelegramPermanentError(f"{label} was invalid", code="invalid_provider_payload")
            for nested in item.values():
                visit(nested, depth + 1)
        elif isinstance(item, list):
            if len(item) > 128:
                raise TelegramPermanentError(f"{label} was invalid", code="invalid_provider_payload")
            for nested in item:
                visit(nested, depth + 1)
        elif isinstance(item, float) and not math.isfinite(item):
            raise TelegramPermanentError(f"{label} was invalid", code="invalid_provider_payload")
        elif item is not None and not isinstance(item, (str, int, float, bool)):
            raise TelegramPermanentError(f"{label} was invalid", code="invalid_provider_payload")

    if not isinstance(value, Mapping):
        raise TelegramPermanentError(f"{label} was invalid", code="invalid_provider_payload")
    visit(value, 0)
    try:
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise TelegramPermanentError(f"{label} was invalid", code="invalid_provider_payload") from None
    if len(encoded) > _MAX_PROVIDER_BODY:
        raise TelegramPermanentError(f"{label} exceeded the safety limit", code="provider_payload_too_large")


def _raise_invalid_update() -> int:
    raise TelegramPermanentError("Telegram update was invalid", code="invalid_update")
