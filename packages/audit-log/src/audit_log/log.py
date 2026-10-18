from __future__ import annotations

import hashlib
import json
import os
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
from pathlib import Path
from typing import Any, Iterable


@dataclass(frozen=True)
class AuditEvent:
    sequence: int
    event_type: str
    actor: str
    subject: str
    timestamp: str
    data: dict[str, Any]
    previous_hash: str
    hash: str

    def to_dict(self) -> dict[str, Any]:
        return {"sequence": self.sequence, "eventType": self.event_type, "actor": self.actor,
                "subject": self.subject, "timestamp": self.timestamp, "data": self.data,
                "previousHash": self.previous_hash, "hash": self.hash}


class AuditLog:
    def __init__(self, path: Path | str | None = None):
        self.path = Path(path) if path is not None else None
        self.lock_path = (
            self.path.with_name(f".{self.path.name}.lock")
            if self.path is not None
            else None
        )
        self._events: list[AuditEvent] = []
        if self.path is not None and (
            self.path.is_symlink()
            or (self.lock_path is not None and self.lock_path.is_symlink())
        ):
            raise ValueError("audit log paths may not be symlinks")
        if self.path and self.path.exists():
            self._load()

    def _load(self) -> None:
        if self.path is None or not self.path.exists():
            self._events = []
            return
        if self.path.is_symlink():
            raise ValueError("audit log path may not be a symlink")
        self._events = [
            self._decode(line)
            for line in self.path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        if not self.verify():
            raise ValueError("audit log integrity check failed")

    @contextmanager
    def _write_lock(self):
        if self.path is None or self.lock_path is None:
            yield
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.parent.is_symlink() or self.lock_path.is_symlink():
            raise ValueError("audit log paths may not be symlinks")
        with self.lock_path.open("a+b") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _append_current(self, *, event_type: str, actor: str, subject: str, timestamp: str, data: dict[str, Any] | None = None) -> AuditEvent:
        previous = self._events[-1].hash if self._events else "genesis"
        sequence = len(self._events) + 1
        payload = {"sequence": sequence, "eventType": event_type, "actor": actor, "subject": subject,
                   "timestamp": timestamp, "data": data or {}, "previousHash": previous}
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        event = AuditEvent(sequence=sequence, event_type=event_type, actor=actor, subject=subject,
                           timestamp=timestamp, data=data or {}, previous_hash=previous,
                           hash="sha256:" + digest)
        self._events.append(event)
        if self.path:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event.to_dict(), sort_keys=True) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        return event

    def append(self, *, event_type: str, actor: str, subject: str, timestamp: str, data: dict[str, Any] | None = None) -> AuditEvent:
        if not all(isinstance(value, str) and value.strip() for value in (event_type, actor, subject, timestamp)):
            raise ValueError("event_type, actor, subject, and timestamp are required")
        with self._write_lock():
            if self.path is not None:
                self._load()
            return self._append_current(
                event_type=event_type,
                actor=actor,
                subject=subject,
                timestamp=timestamp,
                data=data,
            )

    def append_once(self, *, event_type: str, actor: str, subject: str, timestamp: str, data: dict[str, Any], correlation_keys: Iterable[str]) -> tuple[AuditEvent, bool]:
        """Atomically append unless an event has the same correlation values."""

        if not all(isinstance(value, str) and value.strip() for value in (event_type, actor, subject, timestamp)):
            raise ValueError("event_type, actor, subject, and timestamp are required")
        keys = tuple(correlation_keys)
        if not keys or not all(isinstance(key, str) and key in data for key in keys):
            raise ValueError("correlation_keys must name fields present in data")
        with self._write_lock():
            if self.path is not None:
                self._load()
            for event in self._events:
                if event.event_type == event_type and all(
                    event.data.get(key) == data[key] for key in keys
                ):
                    return event, True
            return (
                self._append_current(
                    event_type=event_type,
                    actor=actor,
                    subject=subject,
                    timestamp=timestamp,
                    data=data,
                ),
                False,
            )

    def verify(self) -> bool:
        previous = "genesis"
        for index, event in enumerate(self._events, 1):
            payload = {"sequence": event.sequence, "eventType": event.event_type, "actor": event.actor,
                       "subject": event.subject, "timestamp": event.timestamp, "data": event.data,
                       "previousHash": event.previous_hash}
            expected = "sha256:" + hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            if event.sequence != index or event.previous_hash != previous or event.hash != expected:
                return False
            previous = event.hash
        return True

    @staticmethod
    def _decode(line: str) -> AuditEvent:
        data = json.loads(line)
        return AuditEvent(sequence=data["sequence"], event_type=data["eventType"], actor=data["actor"], subject=data["subject"], timestamp=data["timestamp"], data=data["data"], previous_hash=data["previousHash"], hash=data["hash"])

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        if self.path is not None:
            self._load()
        return tuple(self._events)
