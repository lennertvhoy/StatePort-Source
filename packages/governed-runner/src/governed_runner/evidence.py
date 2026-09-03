"""Bounded, redacted operational evidence journals for governed attempts.

This module is deliberately an evidence persistence boundary.  It neither
claims jobs from :mod:`governed_runner.jobs` nor executes, retries, repairs,
or mutates StateDD data.  A semantic attempt is a durable parent-job/run
record and is not a JobQueue lease claim or its ``attemptCount``.
"""

from __future__ import annotations

import json
import math
import os
import re
import signal
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from runtime_contracts import AgentEvent, RunReceipt, canonical_digest


EVIDENCE_STORE_SCHEMA = "stateport.operational-evidence-schema/v1"
ATTEMPT_CLASSIFICATIONS = frozenset({
    "completed", "failed", "cancelled", "interrupted", "timed_out",
})
_TERMINAL_EVENTS = frozenset({"run.completed", "run.failed", "run.cancelled"})
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SECRET_KEY = re.compile(
    r"(?:api[_-]?key|authorization|cookie|credential|password|secret|"
    r"access[_-]?token|refresh[_-]?token|private[_-]?key)", re.I,
)
_SECRET_VALUE = re.compile(
    r"(?:-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----|\bbearer\s+[A-Za-z0-9._~+/-]{8,}|"
    r"\b(?:api[_-]?key|token|secret|password)\s*(?:[:=]|\s)\s*[^\s,;]+|"
    r"\b(?:sk|pk|rk|gh[pousr]|glpat|github_pat|xox[baprs])[-_][A-Za-z0-9._-]{8,}|"
    r"\bAKIA[A-Z0-9]{16}\b|"
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})", re.I,
)
_SECRET_HEADER = re.compile(
    r"(?im)\b(?:proxy-authorization|authorization|set-cookie|cookie)\s*:\s*[^\r\n]+"
)
_SECRET_ENV = re.compile(
    r"(?im)\b[A-Za-z][A-Za-z0-9_]*(?:api[_-]?key|token|secret|password|cookie|"
    r"authorization|credential|private[_-]?key)\s*=\s*(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;]+)"
)
_SECRET_URI_USERINFO = re.compile(
    r"(?i)\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^@/\s]+@"
)
_AVAILABILITY = frozenset({"exact", "approximate", "unavailable"})
_PROCESS_STATES = frozenset({
    "active", "reaped", "orphan_terminated", "not_found",
    "identity_mismatch", "cleanup_failed",
})
_NON_EXECUTABLE_PROCESS_STATES = frozenset({"Z", "X", "x"})


class EvidenceStoreError(ValueError):
    """Base error for invalid or unsafe evidence operations."""


class EvidenceConflictError(EvidenceStoreError):
    """An immutable semantic identity or receipt conflicts."""


class EvidenceIntegrityError(EvidenceStoreError):
    """Persisted journal evidence is malformed or has been corrupted."""


class EvidenceStateError(EvidenceStoreError):
    """The requested evidence transition is not legal."""


def _id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise EvidenceStoreError(f"{field} must be a bounded contract identifier")
    if _SECRET_VALUE.search(value):
        raise EvidenceStoreError(f"{field} contains credential-like material")
    return value


def _canonical(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise EvidenceStoreError(f"value must be JSON serializable: {exc}") from exc


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _process_identity(pid: int) -> tuple[str, int, int, str] | None:
    """Return Linux state, process group, session, and start identity."""

    try:
        value = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        fields = value.rsplit(")", 1)[1].strip().split()
        state, process_group, session, started = (
            fields[0], int(fields[2]), int(fields[3]), fields[19],
        )
        if state not in frozenset("RSDZTWtXxIKP") or not started.isdigit():
            return None
        return state, process_group, session, started
    except (OSError, IndexError, ValueError):
        return None


def _process_start_ticks(pid: int) -> str | None:
    identity = _process_identity(pid)
    return None if identity is None else identity[3]


def _process_is_alive(pid: int, start_time_ticks: str) -> bool:
    identity = _process_identity(pid)
    return (
        identity is not None
        and identity[0] not in _NON_EXECUTABLE_PROCESS_STATES
        and identity[3] == start_time_ticks
    )


def _safe_database_path(path: Path | str) -> Path:
    if not isinstance(path, (Path, str)) or not os.fspath(path):
        raise EvidenceStoreError("evidence database path is required")
    target = Path(os.path.abspath(os.fspath(path)))
    cursor = Path(target.anchor)
    for part in target.parts[1:-1]:
        cursor = cursor / part
        if cursor.is_symlink():
            raise EvidenceStoreError("evidence database path may not traverse a symlink")
        if cursor.exists() and not cursor.is_dir():
            raise EvidenceStoreError("evidence database parent must be a directory")
    target.parent.mkdir(parents=True, exist_ok=True)
    cursor = Path(target.anchor)
    for part in target.parts[1:-1]:
        cursor = cursor / part
        if cursor.is_symlink() or (cursor.exists() and not cursor.is_dir()):
            raise EvidenceStoreError("evidence database path became unsafe")
    if target.is_symlink():
        raise EvidenceStoreError("evidence database may not be a symlink")
    if target.exists() and not target.is_file():
        raise EvidenceStoreError("evidence database must be a regular file")
    for suffix in ("-journal", "-wal", "-shm"):
        if Path(str(target) + suffix).is_symlink():
            raise EvidenceStoreError("evidence database sidecar may not be a symlink")
    return target


def _redact_string(value: str, categories: set[str]) -> str:
    """Redact common transport, environment, URI, and token representations."""

    result = value
    for pattern, category in (
        (_SECRET_HEADER, "credential_like_header"),
        (_SECRET_ENV, "credential_like_environment"),
        (_SECRET_URI_USERINFO, "credential_like_uri_userinfo"),
        (_SECRET_VALUE, "credential_like_value"),
    ):
        if pattern.search(result):
            categories.add(category)
            result = pattern.sub("[REDACTED]", result)
    return result


def _redact(value: Any, categories: set[str], depth: int = 0) -> Any:
    """Recursively remove credential-named fields and replace secret values."""

    if depth > 32:
        raise EvidenceStoreError("evidence nesting exceeds the 32-level bound")
    if isinstance(value, Mapping):
        if len(value) > 128:
            raise EvidenceStoreError("evidence mapping exceeds the 128-field bound")
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise EvidenceStoreError("evidence mappings require string keys")
            if _SECRET_KEY.search(key):
                categories.add("credential_like_key")
                continue
            result[key] = _redact(item, categories, depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        if len(value) > 128:
            raise EvidenceStoreError("evidence list exceeds the 128-item bound")
        return [_redact(item, categories, depth + 1) for item in value]
    if isinstance(value, str):
        return _redact_string(value, categories)
    if value is None or isinstance(value, (str, int, float, bool)):
        if isinstance(value, float) and not math.isfinite(value):
            raise EvidenceStoreError("evidence scalar values must be finite")
        return value
    raise EvidenceStoreError("evidence values must be bounded JSON data")


def _normalize_event(value: Mapping[str, Any]) -> tuple[AgentEvent, set[str]]:
    if not isinstance(value, Mapping):
        raise EvidenceStoreError("event must be a mapping")
    categories: set[str] = set()
    normalized = _redact(value, categories)
    if not isinstance(normalized, dict):  # Defensive; _redact preserves mappings.
        raise EvidenceStoreError("event normalization failed")
    normalized["redactionResult"] = {
        "status": "applied" if categories else "not_needed",
        "categories": sorted(categories),
    }
    try:
        return AgentEvent.from_dict(normalized), categories
    except ValueError as exc:
        raise EvidenceStoreError(f"invalid normalized AgentEvent: {exc}") from exc


def _normalize_adapter_metadata(value: Mapping[str, Any] | None) -> tuple[dict[str, Any] | None, set[str]]:
    if value is None:
        return None, set()
    if not isinstance(value, Mapping):
        raise EvidenceStoreError("adapter_metadata must be a mapping")
    categories: set[str] = set()
    normalized = _redact(value, categories)
    encoded = _canonical(normalized)
    if len(encoded.encode("utf-8")) > 16_384:
        raise EvidenceStoreError("adapter_metadata exceeds the 16KiB bound")
    return normalized, categories


def _reject_credential_material(value: Mapping[str, Any], field: str) -> None:
    """Reject credential-shaped data in immutable structures we cannot rewrite."""

    categories: set[str] = set()
    normalized = _redact(value, categories)
    if categories or normalized != value:
        raise EvidenceStoreError(f"{field} contains credential-like material")


def _observation(value: Mapping[str, Any] | None) -> dict[str, dict[str, Any]]:
    default = {
        "latency": {"availability": "unavailable", "milliseconds": None},
        "tools": {"availability": "unavailable", "count": None},
        "interventions": {"availability": "unavailable", "count": None},
    }
    if value is None:
        return default
    if not isinstance(value, Mapping) or not set(value).issubset(default):
        raise EvidenceStoreError("observations has an invalid shape")
    result = {key: dict(item) for key, item in default.items()}
    names = {"latency": "milliseconds", "tools": "count", "interventions": "count"}
    for key, amount_name in names.items():
        if key not in value:
            continue
        item = value[key]
        if not isinstance(item, Mapping) or set(item) != {"availability", amount_name}:
            raise EvidenceStoreError(f"observations.{key} has an invalid shape")
        availability, amount = item["availability"], item[amount_name]
        if availability not in _AVAILABILITY:
            raise EvidenceStoreError(f"observations.{key}.availability is invalid")
        if availability == "unavailable":
            if amount is not None:
                raise EvidenceStoreError(f"unavailable observations.{key} must not invent a value")
        elif isinstance(amount, bool) or not isinstance(amount, int) or amount < 0:
            raise EvidenceStoreError(f"observations.{key}.{amount_name} is invalid")
        result[key] = {"availability": availability, amount_name: amount}
    return result


def _attempt_result(classification: str) -> str:
    return "passed" if classification == "completed" else "failed"


class OperationalEvidenceStore:
    """SQLite-backed semantic attempts, normalized journals, and receipts.

    The store serializes writes with ``BEGIN IMMEDIATE``.  It never consults a
    JobQueue lease or changes a queue record, so semantic attempt numbering is
    intentionally independent of the queue's persisted ``attemptCount``.
    """

    def __init__(
        self, path: Path | str, *, max_events: int = 512,
        max_journal_bytes: int = 1_048_576, timeout_seconds: float = 5.0,
    ) -> None:
        if isinstance(max_events, bool) or not isinstance(max_events, int) or max_events <= 0:
            raise EvidenceStoreError("max_events must be a positive integer")
        if isinstance(max_journal_bytes, bool) or not isinstance(max_journal_bytes, int) or max_journal_bytes <= 0:
            raise EvidenceStoreError("max_journal_bytes must be a positive integer")
        if (isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float))
                or not math.isfinite(float(timeout_seconds)) or timeout_seconds <= 0):
            raise EvidenceStoreError("timeout_seconds must be positive")
        self.path = _safe_database_path(path)
        self.max_events = max_events
        self.max_journal_bytes = max_journal_bytes
        self.timeout_seconds = float(timeout_seconds)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        _safe_database_path(self.path)
        try:
            conn = sqlite3.connect(self.path, timeout=self.timeout_seconds, isolation_level=None)
        except sqlite3.Error as exc:
            raise EvidenceStoreError(f"evidence database could not be opened: {exc}") from exc
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout = {int(self.timeout_seconds * 1000)}")
        conn.execute("PRAGMA foreign_keys = ON")
        if self.path.is_symlink() or not self.path.is_file():
            conn.close()
            raise EvidenceStoreError("evidence database changed during open")
        return conn

    def _initialize(self) -> None:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("CREATE TABLE IF NOT EXISTS evidence_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            row = conn.execute("SELECT value FROM evidence_metadata WHERE key = 'schema'").fetchone()
            if row is None:
                conn.execute("INSERT INTO evidence_metadata(key, value) VALUES('schema', ?)", (EVIDENCE_STORE_SCHEMA,))
            elif row["value"] != EVIDENCE_STORE_SCHEMA:
                raise EvidenceStoreError("evidence database schema version is not supported")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS evidence_attempts (
                    semantic_number INTEGER NOT NULL CHECK(semantic_number >= 1),
                    parent_job_id TEXT NOT NULL,
                    attempt_id TEXT NOT NULL UNIQUE,
                    run_id TEXT NOT NULL UNIQUE,
                    state TEXT NOT NULL CHECK(state IN ('open','terminal')),
                    classification TEXT CHECK(classification IN ('completed','failed','cancelled','interrupted','timed_out')),
                    observations_json TEXT NOT NULL,
                    receipt_json TEXT,
                    receipt_digest TEXT,
                    PRIMARY KEY(parent_job_id, semantic_number)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS evidence_events (
                    attempt_id TEXT NOT NULL REFERENCES evidence_attempts(attempt_id),
                    sequence INTEGER NOT NULL,
                    event_id TEXT NOT NULL UNIQUE,
                    event_json TEXT NOT NULL,
                    adapter_metadata_json TEXT,
                    PRIMARY KEY(attempt_id, sequence)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS supervised_processes (
                    process_id TEXT PRIMARY KEY,
                    attempt_id TEXT NOT NULL REFERENCES evidence_attempts(attempt_id),
                    run_id TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    pid INTEGER NOT NULL CHECK(pid > 1),
                    process_group_id INTEGER NOT NULL CHECK(process_group_id > 1),
                    start_time_ticks TEXT NOT NULL,
                    process_generation TEXT NOT NULL,
                    supervisor_pid INTEGER NOT NULL CHECK(supervisor_pid > 1),
                    supervisor_start_time_ticks TEXT NOT NULL,
                    workspace_digest TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('active','reaped','orphan_terminated','not_found','identity_mismatch','cleanup_failed')),
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    UNIQUE(pid, start_time_ticks)
                )
            """)
            process_columns = {
                item["name"]
                for item in conn.execute("PRAGMA table_info(supervised_processes)").fetchall()
            }
            if "process_generation" not in process_columns:
                # Legacy active rows deliberately remain NULL and therefore
                # fail closed during reconciliation; new registrations always
                # persist the generation marker before exec is released.
                conn.execute(
                    "ALTER TABLE supervised_processes ADD COLUMN process_generation TEXT"
                )
            conn.execute("""
                CREATE TABLE IF NOT EXISTS managed_recovery_contexts (
                    attempt_id TEXT PRIMARY KEY REFERENCES evidence_attempts(attempt_id),
                    run_id TEXT NOT NULL UNIQUE,
                    supervisor_pid INTEGER NOT NULL CHECK(supervisor_pid > 1),
                    supervisor_start_time_ticks TEXT NOT NULL,
                    context_json TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('active','recovered','closed')),
                    registered_at TEXT NOT NULL,
                    finished_at TEXT
                )
            """)
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS evidence_attempt_identity_immutable
                BEFORE UPDATE OF semantic_number, parent_job_id, attempt_id, run_id, observations_json ON evidence_attempts
                BEGIN SELECT RAISE(ABORT, 'semantic attempt identity is immutable'); END
            """)
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS evidence_attempt_terminal_immutable
                BEFORE UPDATE ON evidence_attempts WHEN OLD.state = 'terminal'
                BEGIN SELECT RAISE(ABORT, 'terminal attempts are immutable'); END
            """)
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS evidence_events_update_immutable
                BEFORE UPDATE ON evidence_events
                BEGIN SELECT RAISE(ABORT, 'journal events are immutable'); END
            """)
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS evidence_events_delete_immutable
                BEFORE DELETE ON evidence_events
                BEGIN SELECT RAISE(ABORT, 'journal events are immutable'); END
            """)
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS supervised_process_identity_immutable
                BEFORE UPDATE OF process_id, attempt_id, run_id, phase, pid, process_group_id,
                    start_time_ticks, process_generation, supervisor_pid, supervisor_start_time_ticks,
                    workspace_digest, started_at ON supervised_processes
                BEGIN SELECT RAISE(ABORT, 'supervised process identity is immutable'); END
            """)
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS supervised_process_generation_immutable
                BEFORE UPDATE OF process_generation ON supervised_processes
                BEGIN SELECT RAISE(ABORT, 'supervised process generation is immutable'); END
            """)
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS managed_recovery_identity_immutable
                BEFORE UPDATE OF attempt_id, run_id, supervisor_pid,
                    supervisor_start_time_ticks, context_json, registered_at
                    ON managed_recovery_contexts
                BEGIN SELECT RAISE(ABORT, 'managed recovery identity is immutable'); END
            """)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def _decode(value: str, field: str) -> Any:
        try:
            return json.loads(value)
        except (TypeError, json.JSONDecodeError) as exc:
            raise EvidenceIntegrityError(f"stored {field} is invalid JSON") from exc

    def _attempt_row(self, conn: sqlite3.Connection, attempt_id: str) -> sqlite3.Row:
        row = conn.execute("SELECT * FROM evidence_attempts WHERE attempt_id = ?", (attempt_id,)).fetchone()
        if row is None:
            raise EvidenceStateError("semantic attempt was not found")
        return row

    def _journal(self, conn: sqlite3.Connection, row: sqlite3.Row) -> tuple[list[dict[str, Any]], int, str]:
        rows = conn.execute("SELECT * FROM evidence_events WHERE attempt_id = ? ORDER BY sequence", (row["attempt_id"],)).fetchall()
        events: list[dict[str, Any]] = []
        total = 0
        terminal_count = 0
        event_ids: set[str] = set()
        for expected, item in enumerate(rows):
            if item["sequence"] != expected:
                raise EvidenceIntegrityError("journal sequence is not contiguous")
            data = self._decode(item["event_json"], "event JSON")
            try:
                event = AgentEvent.from_dict(data).to_dict()
            except ValueError as exc:
                raise EvidenceIntegrityError(f"stored AgentEvent is invalid: {exc}") from exc
            if (event["jobId"], event["attemptId"], event["runId"]) != (row["parent_job_id"], row["attempt_id"], row["run_id"]):
                raise EvidenceIntegrityError("journal event identity does not match its semantic attempt")
            if event["sequence"] != expected or event["eventId"] != item["event_id"]:
                raise EvidenceIntegrityError("journal event sequence or identity was corrupted")
            if event["eventId"] in event_ids:
                raise EvidenceIntegrityError("journal event identifiers are not unique")
            event_ids.add(event["eventId"])
            encoded = _canonical(event)
            if encoded != item["event_json"]:
                raise EvidenceIntegrityError("journal event is not stored canonically")
            if item["adapter_metadata_json"] is not None:
                metadata = self._decode(item["adapter_metadata_json"], "adapter metadata")
                if not isinstance(metadata, Mapping):
                    raise EvidenceIntegrityError("stored adapter metadata is not a mapping")
                categories: set[str] = set()
                normalized_metadata = _redact(metadata, categories)
                if categories or normalized_metadata != metadata:
                    raise EvidenceIntegrityError("stored adapter metadata contains credential-like material")
                metadata_json = _canonical(metadata)
                if metadata_json != item["adapter_metadata_json"] or len(metadata_json.encode("utf-8")) > 16_384:
                    raise EvidenceIntegrityError("stored adapter metadata is not canonical or bounded")
            total += len(encoded.encode("utf-8"))
            if event["eventType"] in _TERMINAL_EVENTS:
                terminal_count += 1
                if expected != len(rows) - 1:
                    raise EvidenceIntegrityError("terminal event is not final")
            events.append(event)
        if len(events) > self.max_events or total > self.max_journal_bytes:
            raise EvidenceIntegrityError("stored journal exceeds configured bounds")
        if events and events[0]["eventType"] != "run.started":
            raise EvidenceIntegrityError("journal does not start with run.started")
        if row["state"] == "terminal":
            if terminal_count != 1 or row["classification"] not in ATTEMPT_CLASSIFICATIONS:
                raise EvidenceIntegrityError("terminal attempt lacks exactly one terminal event")
            if not self._terminal_matches(events[-1]["eventType"], row["classification"]):
                raise EvidenceIntegrityError("terminal event classification is invalid")
            if row["receipt_json"] is None or row["receipt_digest"] is None:
                raise EvidenceIntegrityError("terminal attempt lacks an immutable receipt")
            receipt_data = self._decode(row["receipt_json"], "receipt JSON")
            if not isinstance(receipt_data, Mapping):
                raise EvidenceIntegrityError("stored RunReceipt is not a mapping")
            try:
                _reject_credential_material(receipt_data, "stored RunReceipt")
            except EvidenceStoreError as exc:
                raise EvidenceIntegrityError(str(exc)) from exc
            try:
                receipt = RunReceipt.from_dict(receipt_data)
            except ValueError as exc:
                raise EvidenceIntegrityError(f"stored RunReceipt is invalid: {exc}") from exc
            if receipt.canonical_json() != row["receipt_json"] or receipt.digest != row["receipt_digest"]:
                raise EvidenceIntegrityError("stored RunReceipt is not canonical or has the wrong digest")
            parsed = receipt.to_dict()
            digest = canonical_digest(events)
            if (
                (parsed["parentJobId"], parsed["attemptId"], parsed["runId"])
                != (row["parent_job_id"], row["attempt_id"], row["run_id"])
                or parsed["journal"] != {"eventCount": len(events), "digest": digest}
                or parsed["digests"]["eventJournal"] != digest
            ):
                raise EvidenceIntegrityError("stored RunReceipt does not bind the canonical journal")
            if parsed["attemptChain"][-1]["classification"] != row["classification"]:
                raise EvidenceIntegrityError("stored RunReceipt eventual attempt contradicts the terminal classification")
        elif terminal_count:
            raise EvidenceIntegrityError("open attempt contains a terminal event")
        return events, total, canonical_digest(events)

    @staticmethod
    def _record_attempt(row: sqlite3.Row, events: list[dict[str, Any]], digest: str) -> dict[str, Any]:
        receipt = None
        if row["receipt_json"] is not None:
            try:
                receipt = json.loads(row["receipt_json"])
            except json.JSONDecodeError as exc:
                raise EvidenceIntegrityError("stored receipt is invalid JSON") from exc
        try:
            observations = json.loads(row["observations_json"])
        except json.JSONDecodeError as exc:
            raise EvidenceIntegrityError("stored observations are invalid JSON") from exc
        return {
            "parentJobId": row["parent_job_id"], "attemptId": row["attempt_id"], "runId": row["run_id"],
            "semanticAttemptNumber": row["semantic_number"], "state": row["state"],
            "classification": row["classification"], "observations": observations,
            "eventCount": len(events), "journalDigest": digest, "receipt": receipt,
        }

    @staticmethod
    def _managed_recovery_registration(
        attempt: str, run: str, context: Mapping[str, Any],
    ) -> tuple[str, int, str]:
        """Validate and encode one credential-free managed recovery context."""

        if not isinstance(context, Mapping) or set(context) != {
            "formatVersion", "workflow", "task", "runtime", "context",
            "agent", "runSpec", "instanceRoot", "stagingRoot",
        } or context.get("formatVersion") != "stateport.managed-recovery-context/v1":
            raise EvidenceStoreError("managed recovery context has an invalid shape")
        for name in ("instanceRoot", "stagingRoot"):
            value = context.get(name)
            if not isinstance(value, str) or not Path(value).is_absolute():
                raise EvidenceStoreError("managed recovery workspace identity is invalid")
        encoded = _canonical(dict(context))
        if len(encoded.encode("utf-8")) > 1_048_576 or _SECRET_VALUE.search(encoded):
            raise EvidenceStoreError("managed recovery context is unsafe or oversized")
        owner_pid = os.getpid()
        owner_ticks = _process_start_ticks(owner_pid)
        if owner_pid <= 1 or owner_ticks is None:
            raise EvidenceStoreError("managed recovery supervisor identity is unavailable")
        _id(attempt, "attempt_id")
        _id(run, "run_id")
        return encoded, owner_pid, owner_ticks

    def create_attempt(self, *, parent_job_id: str, attempt_id: str, run_id: str,
                       observations: Mapping[str, Any] | None = None,
                       managed_recovery_context: Mapping[str, Any] | None = None) -> dict[str, Any]:
        parent, attempt, run = _id(parent_job_id, "parent_job_id"), _id(attempt_id, "attempt_id"), _id(run_id, "run_id")
        observation = _observation(observations)
        recovery = (
            None
            if managed_recovery_context is None
            else self._managed_recovery_registration(
                attempt, run, managed_recovery_context,
            )
        )
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            semantic_number = conn.execute(
                "SELECT COALESCE(MAX(semantic_number), 0) + 1 AS value FROM evidence_attempts WHERE parent_job_id = ?",
                (parent,),
            ).fetchone()["value"]
            try:
                conn.execute("INSERT INTO evidence_attempts(semantic_number, parent_job_id, attempt_id, run_id, state, observations_json) VALUES(?, ?, ?, ?, 'open', ?)", (semantic_number, parent, attempt, run, _canonical(observation)))
            except sqlite3.IntegrityError as exc:
                raise EvidenceConflictError("parent job, attempt, or run identity already exists") from exc
            if recovery is not None:
                encoded, owner_pid, owner_ticks = recovery
                try:
                    conn.execute(
                        """INSERT INTO managed_recovery_contexts(
                            attempt_id, run_id, supervisor_pid,
                            supervisor_start_time_ticks, context_json, state,
                            registered_at
                        ) VALUES(?, ?, ?, ?, ?, 'active', ?)""",
                        (attempt, run, owner_pid, owner_ticks, encoded, _utc_now()),
                    )
                except sqlite3.IntegrityError as exc:
                    raise EvidenceConflictError(
                        "managed recovery context already exists"
                    ) from exc
            row = self._attempt_row(conn, attempt)
            conn.commit()
            return self._record_attempt(row, [], canonical_digest([]))
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def _terminal_matches(event_type: str, classification: str) -> bool:
        return {
            "completed": event_type == "run.completed",
            "cancelled": event_type == "run.cancelled",
            "failed": event_type == "run.failed",
            "interrupted": event_type == "run.failed",
            "timed_out": event_type == "run.failed",
        }.get(classification, False)

    def append_event(self, event_value: Mapping[str, Any], *, adapter_metadata: Mapping[str, Any] | None = None,
                     classification: str | None = None, receipt: Mapping[str, Any] | None = None) -> dict[str, Any]:
        event, event_categories = _normalize_event(event_value)
        data = event.to_dict()
        metadata, metadata_categories = _normalize_adapter_metadata(adapter_metadata)
        if metadata_categories:
            data["redactionResult"] = {"status": "applied", "categories": sorted(event_categories | metadata_categories)}
            event = AgentEvent.from_dict(data)
            data = event.to_dict()
        is_terminal = data["eventType"] in _TERMINAL_EVENTS
        if is_terminal:
            if classification not in ATTEMPT_CLASSIFICATIONS or not self._terminal_matches(data["eventType"], classification):
                raise EvidenceStateError("terminal event classification is invalid")
            if receipt is None:
                raise EvidenceStateError("terminal event requires its immutable RunReceipt")
        elif classification is not None or receipt is not None:
            raise EvidenceStateError("only a terminal event may carry classification or receipt")
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = self._attempt_row(conn, data["attemptId"])
            events, total, _ = self._journal(conn, row)
            if row["state"] != "open":
                raise EvidenceStateError("terminal semantic attempts are immutable")
            if (data["jobId"], data["attemptId"], data["runId"]) != (row["parent_job_id"], row["attempt_id"], row["run_id"]):
                raise EvidenceStateError("event identity does not match its semantic attempt")
            if data["sequence"] != len(events):
                raise EvidenceStateError("journal sequence must be contiguous and monotonic")
            if not events and data["eventType"] != "run.started":
                raise EvidenceStateError("journal must start with run.started")
            if events and data["eventType"] == "run.started":
                raise EvidenceStateError("run.started may occur only once")
            encoded = event.canonical_json()
            if len(events) + 1 > self.max_events or total + len(encoded.encode("utf-8")) > self.max_journal_bytes:
                raise EvidenceStateError("journal exceeds configured bounds")
            final_events = events + [data]
            if is_terminal:
                if not isinstance(receipt, Mapping):
                    raise EvidenceStoreError("receipt must be a mapping")
                _reject_credential_material(receipt, "RunReceipt")
                try:
                    parsed_receipt = RunReceipt.from_dict(receipt)
                except ValueError as exc:
                    raise EvidenceStoreError(f"invalid RunReceipt: {exc}") from exc
                receipt_data = parsed_receipt.to_dict()
                digest = canonical_digest(final_events)
                if (receipt_data["parentJobId"], receipt_data["attemptId"], receipt_data["runId"]) != (row["parent_job_id"], row["attempt_id"], row["run_id"]):
                    raise EvidenceStateError("receipt identity does not match its semantic attempt")
                if receipt_data["journal"] != {"eventCount": len(final_events), "digest": digest} or receipt_data["digests"]["eventJournal"] != digest:
                    raise EvidenceStateError("receipt journal count or digest does not match the canonical journal")
                if receipt_data["attemptChain"][-1]["classification"] != classification:
                    raise EvidenceStateError("receipt eventual attempt contradicts the terminal classification")
            try:
                conn.execute("INSERT INTO evidence_events(attempt_id, sequence, event_id, event_json, adapter_metadata_json) VALUES(?, ?, ?, ?, ?)", (row["attempt_id"], data["sequence"], data["eventId"], encoded, _canonical(metadata) if metadata is not None else None))
            except sqlite3.IntegrityError as exc:
                raise EvidenceConflictError("event id or journal sequence already exists") from exc
            if is_terminal:
                receipt_json = parsed_receipt.canonical_json()
                conn.execute("UPDATE evidence_attempts SET state = 'terminal', classification = ?, receipt_json = ?, receipt_digest = ? WHERE attempt_id = ?", (classification, receipt_json, parsed_receipt.digest, row["attempt_id"]))
            final_row = self._attempt_row(conn, row["attempt_id"])
            conn.commit()
            return self._record_attempt(final_row, final_events, canonical_digest(final_events))
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def get_attempt(self, attempt_id: str) -> dict[str, Any]:
        identifier = _id(attempt_id, "attempt_id")
        conn = self._connect()
        try:
            row = self._attempt_row(conn, identifier)
            events, _, digest = self._journal(conn, row)
            return self._record_attempt(row, events, digest)
        finally:
            conn.close()

    def journal(self, attempt_id: str) -> tuple[dict[str, Any], ...]:
        identifier = _id(attempt_id, "attempt_id")
        conn = self._connect()
        try:
            row = self._attempt_row(conn, identifier)
            events, _, _ = self._journal(conn, row)
            return tuple(events)
        finally:
            conn.close()

    def adapter_metadata(self, event_id: str) -> dict[str, Any] | None:
        identifier = _id(event_id, "event_id")
        conn = self._connect()
        try:
            row = conn.execute("SELECT adapter_metadata_json FROM evidence_events WHERE event_id = ?", (identifier,)).fetchone()
            if row is None:
                return None
            return None if row["adapter_metadata_json"] is None else self._decode(row["adapter_metadata_json"], "adapter metadata")
        finally:
            conn.close()

    def register_supervised_process(
        self, *, run_id: str, attempt_id: str, pid: int,
        process_group_id: int | None, start_time_ticks: str | None,
        process_generation: str | None,
        staging_root: Path | str, phase: str = "backend",
        supervisor_pid: int | None = None,
        supervisor_start_time_ticks: str | None = None,
    ) -> dict[str, Any]:
        """Persist exact process-group identity before managed work can proceed."""

        run, attempt = _id(run_id, "run_id"), _id(attempt_id, "attempt_id")
        process_phase = _id(phase, "process phase")
        if (
            isinstance(pid, bool) or not isinstance(pid, int) or pid <= 1
            or isinstance(process_group_id, bool) or not isinstance(process_group_id, int)
            or process_group_id != pid
            or not isinstance(start_time_ticks, str) or not start_time_ticks.isdigit()
            or not isinstance(process_generation, str)
            or not re.fullmatch(r"generation\.[0-9a-f]{64}", process_generation)
        ):
            raise EvidenceStoreError("supervised process requires an exact session-leader identity")
        observed = _process_identity(pid)
        if (
            observed is None
            or observed[1:] != (process_group_id, pid, start_time_ticks)
            or self._process_generation(pid) != process_generation
        ):
            raise EvidenceStoreError(
                "supervised process generation could not be proven before exec"
            )
        owner_pid = os.getpid() if supervisor_pid is None else supervisor_pid
        owner_ticks = (
            _process_start_ticks(owner_pid)
            if supervisor_start_time_ticks is None
            else supervisor_start_time_ticks
        )
        if (
            isinstance(owner_pid, bool) or not isinstance(owner_pid, int) or owner_pid <= 1
            or not isinstance(owner_ticks, str) or not owner_ticks.isdigit()
        ):
            raise EvidenceStoreError("supervisor process identity is unavailable")
        workspace = Path(staging_root)
        try:
            workspace = workspace.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise EvidenceStoreError("supervised staging workspace is unavailable") from exc
        if workspace.is_symlink() or not workspace.is_dir():
            raise EvidenceStoreError("supervised staging workspace must be a non-symlink directory")
        workspace_digest = canonical_digest({"stagingWorkspace": workspace.as_posix()})
        process_id = "process." + canonical_digest({
            "runId": run, "pid": pid, "startTimeTicks": start_time_ticks,
        })[7:]
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = self._attempt_row(conn, attempt)
            if row["run_id"] != run or row["state"] != "open":
                raise EvidenceStateError("supervised process does not belong to an open attempt")
            try:
                conn.execute(
                    """INSERT INTO supervised_processes(
                        process_id, attempt_id, run_id, phase, pid, process_group_id,
                        start_time_ticks, process_generation,
                        supervisor_pid, supervisor_start_time_ticks,
                        workspace_digest, state, started_at
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)""",
                    (
                        process_id, attempt, run, process_phase, pid, process_group_id,
                        start_time_ticks, process_generation, owner_pid, owner_ticks,
                        workspace_digest, _utc_now(),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise EvidenceConflictError("supervised process identity already exists") from exc
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
        return {
            "processId": process_id, "runId": run, "attemptId": attempt,
            "phase": process_phase,
            "pid": pid, "processGroupId": process_group_id,
            "startTimeTicks": start_time_ticks, "workspaceDigest": workspace_digest,
            "processGenerationDigest": canonical_digest(process_generation),
            "state": "active",
        }

    def complete_supervised_process(
        self, *, run_id: str, pid: int, start_time_ticks: str | None,
    ) -> dict[str, Any]:
        run = _id(run_id, "run_id")
        if not isinstance(start_time_ticks, str) or not start_time_ticks.isdigit():
            raise EvidenceStoreError("supervised process completion lacks start identity")
        conn = self._connect()
        completion: dict[str, Any] | None = None
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM supervised_processes WHERE run_id = ? AND pid = ? AND start_time_ticks = ?",
                (run, pid, start_time_ticks),
            ).fetchone()
            if row is None or row["state"] != "active":
                raise EvidenceStateError("active supervised process was not found")
            state = "reaped"
            action = "group_absent_after_wait"
            leader = _process_identity(row["pid"])
            members = self._exact_session_members(
                row["process_group_id"], row["pid"],
            )
            generation = row["process_generation"] or ""
            generation_members = self._exact_generation_members(generation)
            if members is None or generation_members is None or (
                leader is not None
                and leader[1:] != (
                    row["process_group_id"], row["pid"], row["start_time_ticks"],
                )
            ):
                state, action = "cleanup_failed", "operator_cleanup_required"
            elif members or generation_members:
                if self._terminate_exact_session(
                    row["process_group_id"], row["pid"], generation,
                ):
                    action = "terminated_exact_remaining_process_group"
                else:
                    state, action = "cleanup_failed", "operator_cleanup_required"
            elif self._process_group_exists(row["process_group_id"]):
                state, action = "cleanup_failed", "operator_cleanup_required"
            conn.execute(
                "UPDATE supervised_processes SET state = ?, finished_at = ? WHERE process_id = ?",
                (state, _utc_now(), row["process_id"]),
            )
            conn.commit()
            completion = {
                "processId": row["process_id"], "runId": run,
                "phase": row["phase"], "state": state,
                "completionAction": action,
            }
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
        assert completion is not None
        if completion["state"] == "cleanup_failed":
            raise EvidenceStateError(
                "supervised process group cleanup could not be proven"
            )
        return completion

    @staticmethod
    def _process_group_exists(process_group_id: int) -> bool:
        try:
            os.killpg(process_group_id, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True

    @staticmethod
    def _process_generation(pid: int) -> str | None:
        try:
            values = Path(f"/proc/{pid}/environ").read_bytes().split(b"\0")
        except OSError:
            return None
        prefix = b"STATEPORT_PROCESS_GENERATION="
        matches = [value[len(prefix):] for value in values if value.startswith(prefix)]
        if len(matches) != 1:
            return None
        try:
            result = matches[0].decode("ascii")
        except UnicodeDecodeError:
            return None
        return result if re.fullmatch(r"generation\.[0-9a-f]{64}", result) else None

    @staticmethod
    def _exact_session_members(
        process_group_id: int, session_id: int,
    ) -> tuple[tuple[int, str, str], ...] | None:
        """Observe members still bound to the recorded Linux group and session.

        A session leader may exit before its descendants.  Treating a missing
        leader PID as proof that its group is gone would release the writer
        lease while those descendants can still mutate staging.  The group and
        session pair remains the durable kernel relationship for that case.
        ``None`` means procfs could not be enumerated and therefore cleanup
        cannot be proven.
        """

        try:
            entries = tuple(Path("/proc").iterdir())
        except OSError:
            return None
        members: list[tuple[int, str, str]] = []
        for entry in entries:
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            identity = _process_identity(pid)
            if identity is None:
                continue
            state, current_group, current_session, started = identity
            if current_group == process_group_id and current_session == session_id:
                members.append((pid, started, state))
        return tuple(sorted(members))

    @classmethod
    def _exact_generation_members(
        cls, process_generation: str,
    ) -> tuple[tuple[int, str, str, int, int], ...] | None:
        """Observe every process that still carries one run generation.

        A supervised descendant can call ``setsid`` or ``setpgid`` and leave
        the original session while retaining the marker installed before
        exec.  Session membership is therefore a containment signal, not the
        complete ownership boundary.  The random generation is scanned in
        addition to the original session so such descendants cannot be
        reported absent merely because their PGID/SID changed.
        """

        if not re.fullmatch(r"generation\.[0-9a-f]{64}", process_generation):
            return None
        try:
            entries = tuple(Path("/proc").iterdir())
        except OSError:
            return None
        members: list[tuple[int, str, str, int, int]] = []
        for entry in entries:
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            identity = _process_identity(pid)
            if identity is None or cls._process_generation(pid) != process_generation:
                continue
            state, group, session, started = identity
            members.append((pid, started, state, group, session))
        return tuple(sorted(members))

    @classmethod
    def _terminate_exact_session(
        cls, process_group_id: int, session_id: int,
        process_generation: str,
    ) -> bool:
        """Terminate revalidated session members and detached generation heirs.

        Individual PID signals avoid a process-group-ID reuse race. Repeated
        scans catch both descendants forked inside the original session and
        generation-bound descendants that create another session. Success
        requires the exact observed set to disappear or contain only zombie or
        dead members that can no longer execute or mutate staging.
        """

        for selected_signal, duration in (
            (signal.SIGTERM, 0.25),
            (signal.SIGKILL, 1.0),
        ):
            deadline = time.monotonic() + duration
            while True:
                session_members = cls._exact_session_members(
                    process_group_id, session_id,
                )
                generation_members = cls._exact_generation_members(
                    process_generation,
                )
                if session_members is None or generation_members is None:
                    return False
                targets: dict[int, tuple[str, str]] = {
                    pid: (started, state)
                    for pid, started, state, _group, _session in generation_members
                }
                for pid, started, state in session_members:
                    if (
                        state not in _NON_EXECUTABLE_PROCESS_STATES
                        and cls._process_generation(pid) != process_generation
                    ):
                        # A live member in the recorded session without the
                        # pre-exec marker is not owned strongly enough to signal.
                        return False
                    targets.setdefault(pid, (started, state))
                if not targets:
                    return not cls._process_group_exists(process_group_id)
                if all(
                    state in _NON_EXECUTABLE_PROCESS_STATES
                    for _started, state in targets.values()
                ):
                    for pid in targets:
                        cls._reap_if_child(pid)
                    return True
                for pid, (started, state) in targets.items():
                    cls._reap_if_child(pid)
                    if state in _NON_EXECUTABLE_PROCESS_STATES:
                        continue
                    # Revalidate start identity and generation immediately
                    # before signalling. The process may have changed its
                    # group/session since the preceding scan.
                    current = _process_identity(pid)
                    if current is None or current[3] != started:
                        continue
                    if current[0] in _NON_EXECUTABLE_PROCESS_STATES:
                        cls._reap_if_child(pid)
                        continue
                    if cls._process_generation(pid) != process_generation:
                        # Numeric process and session identifiers are reusable.
                        # Never signal a member without the pre-exec generation
                        # marker that was durably recorded for this run.
                        return False
                    try:
                        os.kill(pid, selected_signal)
                    except ProcessLookupError:
                        continue
                    except PermissionError:
                        return False
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.01)
        session_members = cls._exact_session_members(process_group_id, session_id)
        generation_members = cls._exact_generation_members(process_generation)
        if session_members is None or generation_members is None:
            return False
        for pid, _started, _state in session_members:
            cls._reap_if_child(pid)
        for pid, _started, _state, _group, _session in generation_members:
            cls._reap_if_child(pid)
        session_members = cls._exact_session_members(process_group_id, session_id)
        generation_members = cls._exact_generation_members(process_generation)
        if session_members is None or generation_members is None:
            return False
        remaining_states = (
            [state for _pid, _started, state in session_members]
            + [state for _pid, _started, state, _group, _session in generation_members]
        )
        if remaining_states:
            return all(
                state in _NON_EXECUTABLE_PROCESS_STATES
                for state in remaining_states
            )
        return not cls._process_group_exists(process_group_id)

    @staticmethod
    def _reap_if_child(pid: int) -> None:
        try:
            os.waitpid(pid, os.WNOHANG)
        except (ChildProcessError, OSError):
            pass

    def reconcile_supervised_processes(self) -> list[dict[str, Any]]:
        """Reap only abandoned groups whose PID, PGID, and start identity match."""

        conn = self._connect()
        observations: list[dict[str, Any]] = []
        try:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                "SELECT * FROM supervised_processes WHERE state = 'active' ORDER BY started_at, process_id"
            ).fetchall()
            for row in rows:
                owner_alive = _process_is_alive(
                    row["supervisor_pid"], row["supervisor_start_time_ticks"],
                )
                if owner_alive:
                    observations.append({
                        "processId": row["process_id"], "runId": row["run_id"],
                        "state": "active", "recoveryAction": "owner_alive_no_action",
                    })
                    continue
                leader = _process_identity(row["pid"])
                members = self._exact_session_members(
                    row["process_group_id"], row["pid"],
                )
                generation = row["process_generation"] or ""
                generation_members = self._exact_generation_members(generation)
                if members is None or generation_members is None:
                    state, action = "cleanup_failed", "operator_cleanup_required"
                elif leader is not None and (
                    leader[1] != row["process_group_id"]
                    or leader[2] != row["pid"]
                    or leader[3] != row["start_time_ticks"]
                    or row["process_group_id"] != row["pid"]
                ):
                    state, action = "identity_mismatch", "refused_unbound_signal"
                elif not members and not generation_members:
                    if self._process_group_exists(row["process_group_id"]):
                        state, action = "identity_mismatch", "refused_unbound_signal"
                    else:
                        state, action = "not_found", "already_absent"
                else:
                    if self._terminate_exact_session(
                        row["process_group_id"], row["pid"],
                        generation,
                    ):
                        state, action = "orphan_terminated", "terminated_exact_process_group"
                    else:
                        state, action = "cleanup_failed", "operator_cleanup_required"
                conn.execute(
                    "UPDATE supervised_processes SET state = ?, finished_at = ? WHERE process_id = ?",
                    (state, _utc_now(), row["process_id"]),
                )
                observations.append({
                    "processId": row["process_id"], "runId": row["run_id"],
                    "state": state, "recoveryAction": action,
                })
            conn.commit()
            return observations
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def supervised_processes(self) -> tuple[dict[str, Any], ...]:
        conn = self._connect()
        try:
            rows = conn.execute(
                """SELECT process_id, attempt_id, run_id, pid, process_group_id,
                    phase, start_time_ticks, process_generation,
                    workspace_digest, state,
                    started_at, finished_at
                    FROM supervised_processes ORDER BY started_at, process_id"""
            ).fetchall()
            return tuple({
                "processId": row["process_id"], "attemptId": row["attempt_id"],
                "runId": row["run_id"], "pid": row["pid"],
                "phase": row["phase"],
                "processGroupId": row["process_group_id"],
                "startTimeTicks": row["start_time_ticks"],
                "processGenerationDigest": (
                    None if row["process_generation"] is None
                    else canonical_digest(row["process_generation"])
                ),
                "workspaceDigest": row["workspace_digest"], "state": row["state"],
                "startedAt": row["started_at"], "finishedAt": row["finished_at"],
            } for row in rows)
        finally:
            conn.close()

    def register_managed_recovery_context(
        self, *, attempt_id: str, run_id: str, context: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Persist the typed local context needed to close a crash-abandoned attempt."""

        attempt, run = _id(attempt_id, "attempt_id"), _id(run_id, "run_id")
        encoded, owner_pid, owner_ticks = self._managed_recovery_registration(
            attempt, run, context,
        )
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = self._attempt_row(conn, attempt)
            if row["run_id"] != run or row["state"] != "open":
                raise EvidenceStateError("managed recovery context requires its open attempt")
            try:
                conn.execute(
                    """INSERT INTO managed_recovery_contexts(
                        attempt_id, run_id, supervisor_pid,
                        supervisor_start_time_ticks, context_json, state,
                        registered_at
                    ) VALUES(?, ?, ?, ?, ?, 'active', ?)""",
                    (attempt, run, owner_pid, owner_ticks, encoded, _utc_now()),
                )
            except sqlite3.IntegrityError as exc:
                raise EvidenceConflictError("managed recovery context already exists") from exc
            conn.commit()
            return {"attemptId": attempt, "runId": run, "state": "active"}
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def managed_recovery_candidates(self) -> tuple[dict[str, Any], ...]:
        """Return only owner-dead, process-safe, still-open managed attempts."""

        conn = self._connect()
        try:
            rows = conn.execute(
                """SELECT c.*, a.state AS attempt_state
                   FROM managed_recovery_contexts c
                   JOIN evidence_attempts a ON a.attempt_id = c.attempt_id
                   WHERE c.state = 'active'
                   ORDER BY c.registered_at, c.attempt_id"""
            ).fetchall()
            candidates: list[dict[str, Any]] = []
            for row in rows:
                if row["attempt_state"] != "open" or _process_is_alive(
                    row["supervisor_pid"], row["supervisor_start_time_ticks"],
                ):
                    continue
                process_rows = conn.execute(
                    """SELECT phase, state FROM supervised_processes
                       WHERE attempt_id = ? ORDER BY started_at, process_id""",
                    (row["attempt_id"],),
                ).fetchall()
                states = tuple(item["state"] for item in process_rows)
                if any(
                    state not in {"reaped", "orphan_terminated", "not_found"}
                    for state in states
                ):
                    continue
                try:
                    context = self._decode(row["context_json"], "managed recovery context")
                except EvidenceIntegrityError:
                    raise
                if not isinstance(context, dict):
                    raise EvidenceIntegrityError("managed recovery context is not an object")
                candidates.append({
                    "attemptId": row["attempt_id"], "runId": row["run_id"],
                    "context": context, "processStates": list(states),
                    "processPhases": [item["phase"] for item in process_rows],
                })
            return tuple(candidates)
        finally:
            conn.close()

    def managed_instance_blockers(
        self, instance_root: Path | str,
    ) -> tuple[dict[str, Any], ...]:
        """Return unresolved open attempts that quarantine one exact instance."""

        try:
            canonical = Path(instance_root).resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise EvidenceStoreError("managed instance identity is unavailable") from exc
        if canonical.is_symlink() or not canonical.is_dir():
            raise EvidenceStoreError("managed instance must be a non-symlink directory")
        conn = self._connect()
        try:
            rows = conn.execute(
                """SELECT c.*, a.state AS attempt_state
                   FROM managed_recovery_contexts c
                   JOIN evidence_attempts a ON a.attempt_id = c.attempt_id
                   WHERE c.state = 'active' AND a.state = 'open'
                   ORDER BY c.registered_at, c.attempt_id"""
            ).fetchall()
            blockers: list[dict[str, Any]] = []
            for row in rows:
                context = self._decode(
                    row["context_json"], "managed recovery context",
                )
                if not isinstance(context, dict):
                    raise EvidenceIntegrityError(
                        "managed recovery context is not an object"
                    )
                if context.get("instanceRoot") != canonical.as_posix():
                    continue
                process_rows = conn.execute(
                    """SELECT phase, state FROM supervised_processes
                       WHERE attempt_id = ? ORDER BY started_at, process_id""",
                    (row["attempt_id"],),
                ).fetchall()
                blockers.append({
                    "attemptId": row["attempt_id"],
                    "runId": row["run_id"],
                    "ownerAlive": _process_is_alive(
                        row["supervisor_pid"], row["supervisor_start_time_ticks"],
                    ),
                    "processStates": [item["state"] for item in process_rows],
                    "processPhases": [item["phase"] for item in process_rows],
                })
            return tuple(blockers)
        finally:
            conn.close()

    def finish_managed_recovery_context(
        self, *, run_id: str, state: str,
    ) -> dict[str, str]:
        run = _id(run_id, "run_id")
        if state not in {"recovered", "closed"}:
            raise EvidenceStoreError("managed recovery terminal state is invalid")
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM managed_recovery_contexts WHERE run_id = ?",
                (run,),
            ).fetchone()
            if row is None or row["state"] != "active":
                raise EvidenceStateError("active managed recovery context was not found")
            conn.execute(
                "UPDATE managed_recovery_contexts SET state = ?, finished_at = ? WHERE run_id = ?",
                (state, _utc_now(), run),
            )
            conn.commit()
            return {"runId": run, "state": state}
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def _total(items: list[dict[str, Any]], key: str, amount_name: str) -> dict[str, Any]:
        if not items or any(item[key]["availability"] == "unavailable" for item in items):
            return {"availability": "unavailable", amount_name: None}
        availability = "approximate" if any(item[key]["availability"] == "approximate" for item in items) else "exact"
        return {"availability": availability, amount_name: sum(item[key][amount_name] for item in items)}

    @staticmethod
    def _usage(attempts: list[dict[str, Any]]) -> dict[str, Any]:
        if not attempts or any(item["receipt"] is None for item in attempts):
            return {"availability": "unavailable", "token": None, "costMinor": None}
        receipts = [item["receipt"] for item in attempts]
        if any(item["usage"]["availability"] == "unavailable" for item in receipts):
            return {"availability": "unavailable", "token": None, "costMinor": None}
        availability = "approximate" if any(item["usage"]["availability"] == "approximate" for item in receipts) else "exact"
        return {"availability": availability, "token": sum(item["usage"]["token"] for item in receipts), "costMinor": sum(item["usage"]["costMinor"] for item in receipts)}

    def parent_summary(self, parent_job_id: str) -> dict[str, Any]:
        parent = _id(parent_job_id, "parent_job_id")
        conn = self._connect()
        try:
            rows = conn.execute("SELECT * FROM evidence_attempts WHERE parent_job_id = ? ORDER BY semantic_number", (parent,)).fetchall()
            if not rows:
                raise EvidenceStateError("parent job has no semantic attempts")
            attempts: list[dict[str, Any]] = []
            for row in rows:
                events, _, digest = self._journal(conn, row)
                attempts.append(self._record_attempt(row, events, digest))
            execution_attempts = [
                dict(entry, runId=item["runId"], semanticAttemptId=item["attemptId"])
                for item in attempts
                for entry in ((item["receipt"] or {}).get("attemptChain", []))
            ]
            if not execution_attempts:
                raise EvidenceIntegrityError("terminal parent evidence lacks explicit attempt accounting")
            first = execution_attempts[0]
            final = execution_attempts[-1]
            effects = [dict(effect, attemptId=item["attemptId"]) for item in attempts for effect in ((item["receipt"] or {}).get("sideEffects", []))]
            usage = self._usage(attempts)
            return {
                "parentJobId": parent,
                "semanticAttemptCount": len(attempts),
                "firstAttempt": {"attemptId": first["attemptId"], "runId": first["runId"], "classification": first["classification"], "result": first["result"]},
                "eventual": {"attemptId": final["attemptId"], "runId": final["runId"], "classification": final["classification"], "result": final["result"]},
                "attempts": attempts,
                "executionAttemptCount": len(execution_attempts),
                "executionAttempts": execution_attempts,
                "totals": {
                    "latency": self._total([item["observations"] for item in attempts], "latency", "milliseconds"),
                    "usage": usage,
                    "cost": {
                        "availability": usage["availability"],
                        "costMinor": usage["costMinor"],
                    },
                    "tools": self._total([item["observations"] for item in attempts], "tools", "count"),
                    "interventions": self._total([item["observations"] for item in attempts], "interventions", "count"),
                },
                "sideEffects": effects,
            }
        finally:
            conn.close()


__all__ = [
    "ATTEMPT_CLASSIFICATIONS", "EVIDENCE_STORE_SCHEMA", "EvidenceConflictError",
    "EvidenceIntegrityError", "EvidenceStateError", "EvidenceStoreError",
    "OperationalEvidenceStore",
]
