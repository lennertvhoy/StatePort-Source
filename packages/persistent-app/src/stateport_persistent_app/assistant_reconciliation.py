"""Durable transcript cursors for assistant-message reconciliation.

The first activation snapshots existing conversation positions instead of
silently invoking historical user messages. Later restarts resume from the last
successfully considered message; enqueue remains idempotent if a crash occurs
between enqueue and cursor advancement.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import tempfile
import threading
from typing import Mapping

FORMAT = "stateport.assistant-reconciliation/v1"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")


class AssistantReconciliationError(RuntimeError):
    pass


class AssistantReconciliationState:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(os.path.abspath(os.fspath(path)))
        if self.path.exists() and (self.path.is_symlink() or not self.path.is_file()):
            raise AssistantReconciliationError("assistant reconciliation path is unsafe")
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.path.parent.is_symlink() or self.path.is_symlink():
            raise AssistantReconciliationError("assistant reconciliation path is unsafe")
        self._lock = threading.Lock()

    def _read(self) -> dict[str, int] | None:
        if not self.path.exists():
            return None
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise AssistantReconciliationError(
                "assistant reconciliation state is unreadable"
            ) from exc
        if not isinstance(value, dict) or set(value) != {"formatVersion", "cursors"}:
            raise AssistantReconciliationError(
                "assistant reconciliation state shape is invalid"
            )
        if value["formatVersion"] != FORMAT or not isinstance(value["cursors"], dict):
            raise AssistantReconciliationError(
                "assistant reconciliation state format is unsupported"
            )
        cursors: dict[str, int] = {}
        for conversation_id, sequence in value["cursors"].items():
            if (
                not isinstance(conversation_id, str)
                or _ID.fullmatch(conversation_id) is None
                or isinstance(sequence, bool)
                or not isinstance(sequence, int)
                or sequence < 0
            ):
                raise AssistantReconciliationError(
                    "assistant reconciliation cursor is invalid"
                )
            cursors[conversation_id] = sequence
        return cursors

    def _write(self, cursors: Mapping[str, int]) -> None:
        value = {"formatVersion": FORMAT, "cursors": dict(sorted(cursors.items()))}
        temporary: Path | None = None
        try:
            descriptor, raw = tempfile.mkstemp(
                prefix=".assistant-reconciliation.", suffix=".tmp", dir=self.path.parent
            )
            temporary = Path(raw)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(
                    value,
                    handle,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                )
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.path)
            temporary = None
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    def initialize(self, positions: Mapping[str, int]) -> bool:
        checked: dict[str, int] = {}
        for conversation_id, sequence in positions.items():
            if (
                not isinstance(conversation_id, str)
                or _ID.fullmatch(conversation_id) is None
                or isinstance(sequence, bool)
                or not isinstance(sequence, int)
                or sequence < 0
            ):
                raise AssistantReconciliationError(
                    "assistant activation position is invalid"
                )
            checked[conversation_id] = sequence
        with self._lock:
            current = self._read()
            if current is not None:
                return False
            self._write(checked)
            return True

    def cursor(self, conversation_id: str) -> int:
        if not isinstance(conversation_id, str) or _ID.fullmatch(conversation_id) is None:
            raise AssistantReconciliationError("conversation identity is invalid")
        with self._lock:
            current = self._read()
            if current is None:
                raise AssistantReconciliationError(
                    "assistant reconciliation has not been initialized"
                )
            return current.get(conversation_id, 0)

    def advance(self, conversation_id: str, sequence: int) -> None:
        if not isinstance(conversation_id, str) or _ID.fullmatch(conversation_id) is None:
            raise AssistantReconciliationError("conversation identity is invalid")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
            raise AssistantReconciliationError("conversation sequence is invalid")
        with self._lock:
            current = self._read()
            if current is None:
                raise AssistantReconciliationError(
                    "assistant reconciliation has not been initialized"
                )
            previous = current.get(conversation_id, 0)
            if sequence < previous:
                raise AssistantReconciliationError(
                    "assistant reconciliation cursor cannot move backward"
                )
            if sequence == previous:
                return
            current[conversation_id] = sequence
            self._write(current)

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._read() or {})


__all__ = ["AssistantReconciliationError", "AssistantReconciliationState"]
