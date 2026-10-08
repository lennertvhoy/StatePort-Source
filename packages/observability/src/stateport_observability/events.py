"""Bounded, local-only JSONL operational events.

These events are diagnostics, never canonical evidence.  Callers may emit only
the fixed scalar fields below; request bodies, headers, commands, paths, free-
form payloads, exception text, and traceback data have no representation in the
contract.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Any, Callable, Mapping, Protocol

EVENT_SCHEMA = "stateport.operational-event/v1"
MAX_RECORD_BYTES = 8_192
_LEVELS = {"debug": 10, "info": 20, "warning": 30, "error": 40}
_ALLOWED_FIELDS = {
    "requestId",
    "resultCode",
    "durationMs",
    "method",
    "route",
    "status",
    "responseBytes",
    "instanceId",
    "deploymentId",
    "capsuleId",
    "workspaceLeaseId",
    "revision",
    "receiptDigest",
    "jobId",
    "runId",
    "workerId",
    "executionEnabled",
    "ready",
    "droppedEvents",
    "errorDigest",
}
_STRING_LIMIT = 512
_EVENT_NAME = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_SAFE_ROUTE = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$")
_SECRET_PATTERNS = (
    re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)\b(?:token|password|secret|api[_-]?key)\s*[:=]\s*[^\s,;]+"),
    re.compile(r"(?i)://[^/@\s:]+:[^/@\s]+@"),
)


class EventSink(Protocol):
    """Minimal sink boundary; implementations must remain local."""

    def write(self, record: bytes) -> None: ...


def parse_log_level(value: str | None) -> str:
    """Return a strict operational log level or fail startup."""

    level = (value or "info").strip().lower()
    if level not in _LEVELS:
        raise ValueError("STATEPORT_LOG_LEVEL must be debug, info, warning, or error")
    return level


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _redact(value: str) -> str:
    bounded = value[:_STRING_LIMIT]
    for pattern in _SECRET_PATTERNS:
        bounded = pattern.sub("[REDACTED]", bounded)
    return bounded


def _scalar(field: str, value: Any) -> str | int | float | bool | None:
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if value != value or value in {float("inf"), float("-inf")}:
            raise ValueError(f"{field} must be finite")
        return round(value, 3)
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a JSON scalar")
    result = _redact(value)
    if field == "route" and not _SAFE_ROUTE.fullmatch(result):
        raise ValueError("route must be a normalized path without a query")
    return result


def build_event(
    *,
    service: str,
    event: str,
    level: str,
    fields: Mapping[str, Any],
    timestamp_factory: Callable[[], str],
) -> bytes:
    """Build one complete bounded JSONL record from allowlisted scalars."""

    normalized_level = parse_log_level(level)
    if not _EVENT_NAME.fullmatch(service) or not _EVENT_NAME.fullmatch(event):
        raise ValueError("service and event must be stable lowercase identifiers")
    unknown = set(fields) - _ALLOWED_FIELDS
    if unknown:
        raise ValueError(f"unsupported operational event fields: {sorted(unknown)}")
    record: dict[str, Any] = {
        "schema": EVENT_SCHEMA,
        "timestamp": timestamp_factory(),
        "level": normalized_level,
        "service": service,
        "event": event,
    }
    for key in sorted(fields):
        value = _scalar(key, fields[key])
        if value is not None:
            record[key] = value
    encoded = (json.dumps(record, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode(
        "utf-8"
    )
    if len(encoded) > MAX_RECORD_BYTES:
        raise ValueError("operational event exceeds the bounded record size")
    return encoded


class NullSink:
    """Explicit local no-op sink."""

    def write(self, record: bytes) -> None:
        del record


class JsonStreamSink:
    """Write complete JSONL records to a local binary or text stream."""

    def __init__(self, stream: IO[Any]):
        self._stream = stream
        self._lock = threading.Lock()

    def write(self, record: bytes) -> None:
        with self._lock:
            target = getattr(self._stream, "buffer", self._stream)
            if target is self._stream and not "b" in getattr(self._stream, "mode", ""):
                self._stream.write(record.decode("utf-8"))
            else:
                target.write(record)
            self._stream.flush()


class RotatingJsonFileSink:
    """Bounded local JSONL storage with symlink refusal and mode 0600."""

    def __init__(self, path: Path | str, *, max_bytes: int = 1_048_576, max_files: int = 3):
        self.path = Path(path)
        if max_bytes < MAX_RECORD_BYTES or max_bytes > 1_073_741_824:
            raise ValueError("max_bytes must be between one event and 1 GiB")
        if max_files < 1 or max_files > 100:
            raise ValueError("max_files must be between 1 and 100")
        self.max_bytes = max_bytes
        self.max_files = max_files
        self._lock = threading.Lock()
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._refuse_symlink(self.path)

    @staticmethod
    def _refuse_symlink(path: Path) -> None:
        if path.is_symlink():
            raise OSError(f"refusing operational log symlink: {path.name}")

    def _open(self) -> int:
        self._refuse_symlink(self.path)
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(self.path, flags, 0o600)
        os.fchmod(fd, 0o600)
        return fd

    def _rotate(self) -> None:
        oldest = self.path.with_name(f"{self.path.name}.{self.max_files}")
        if oldest.exists() or oldest.is_symlink():
            self._refuse_symlink(oldest)
            oldest.unlink()
        for index in range(self.max_files - 1, 0, -1):
            source = self.path.with_name(f"{self.path.name}.{index}")
            destination = self.path.with_name(f"{self.path.name}.{index + 1}")
            if source.exists() or source.is_symlink():
                self._refuse_symlink(source)
                self._refuse_symlink(destination)
                os.replace(source, destination)
        if self.path.exists() or self.path.is_symlink():
            self._refuse_symlink(self.path)
            os.replace(self.path, self.path.with_name(f"{self.path.name}.1"))

    def write(self, record: bytes) -> None:
        if not record.endswith(b"\n") or len(record) > MAX_RECORD_BYTES:
            raise ValueError("sink accepts one complete bounded JSONL record")
        with self._lock:
            self._refuse_symlink(self.path)
            current_size = self.path.stat().st_size if self.path.exists() else 0
            if current_size and current_size + len(record) > self.max_bytes:
                self._rotate()
            fd = self._open()
            try:
                os.write(fd, record)
                os.fsync(fd)
            finally:
                os.close(fd)


class OperationalObserver:
    """Non-throwing diagnostic observer with deterministic filtering."""

    def __init__(
        self,
        service: str,
        sink: EventSink,
        *,
        minimum_level: str = "info",
        timestamp_factory: Callable[[], str] = _timestamp,
    ):
        if not _EVENT_NAME.fullmatch(service):
            raise ValueError("service must be a stable lowercase identifier")
        self.service = service
        self.sink = sink
        self.minimum_level = parse_log_level(minimum_level)
        self.timestamp_factory = timestamp_factory
        self.dropped_events = 0

    def emit(self, event: str, *, level: str = "info", **fields: Any) -> bool:
        """Emit locally, returning false instead of perturbing product state."""

        try:
            normalized = parse_log_level(level)
            if _LEVELS[normalized] < _LEVELS[self.minimum_level]:
                return True
            record = build_event(
                service=self.service,
                event=event,
                level=normalized,
                fields=fields,
                timestamp_factory=self.timestamp_factory,
            )
            self.sink.write(record)
            return True
        except Exception:  # noqa: BLE001 - diagnostics may never change product truth
            self.dropped_events += 1
            return False


class NullObserver(OperationalObserver):
    def __init__(self, service: str = "stateport"):
        super().__init__(service, NullSink())


def observer_from_environment(service: str) -> OperationalObserver:
    """Construct the default local stdout observer; no network exporter exists."""

    return OperationalObserver(
        service,
        JsonStreamSink(sys.stdout),
        minimum_level=parse_log_level(os.environ.get("STATEPORT_LOG_LEVEL")),
    )


def exception_digest(exc: BaseException) -> str:
    """Return a stable diagnostic class digest without persisting exception text."""

    identity = f"{type(exc).__module__}.{type(exc).__qualname__}".encode("utf-8")
    return "sha256:" + hashlib.sha256(identity).hexdigest()
