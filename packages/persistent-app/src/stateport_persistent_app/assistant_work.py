"""Durable assistant work claims and replayable execution events.

Operational only: this store never owns canonical application state or provider
credentials. It guarantees one accepted message is invoked at most once
automatically, stores the provider result before reply delivery, and makes
delivery safely retryable after restart.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time
from typing import Any, Callable, Mapping

SCHEMA = "stateport.assistant-work-schema/v1"
WORK_FORMAT = "stateport.assistant-work/v1"
EVENT_FORMAT = "stateport.assistant-event/v1"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SECRET_KEY = re.compile(
    r"(?:api[_-]?key|authorization|cookie|credential|password|secret|"
    r"access[_-]?token|refresh[_-]?token|lease[_-]?token)", re.I
)
_STATES = frozenset(
    {"queued", "invoking", "result_ready", "delivering", "completed", "failed", "cancelled"}
)
_EVENTS = frozenset(
    {
        "work.queued", "attempt.started", "process.started",
        "provider.result_stored", "delivery.started", "reply.persisted",
        "attempt.failed", "attempt.interrupted",
    }
)


class AssistantWorkError(RuntimeError):
    pass


class AssistantWorkConflict(AssistantWorkError):
    pass


class AssistantWorkStateError(AssistantWorkError):
    pass


class AssistantWorkLeaseError(AssistantWorkError):
    pass


@dataclass(frozen=True)
class AssistantClaim:
    work_id: str
    attempt_id: str
    phase: str
    lease_token: str
    lease_expires_at: str
    instance_id: str
    application_id: str
    conversation_id: str
    message_id: str
    participant_id: str
    source_sequence: int
    attempt_ordinal: int
    provider_result: dict[str, Any] | None


def _canonical(value: object) -> str:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise AssistantWorkError("assistant work value is not canonical JSON") from exc


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode()).hexdigest()


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise AssistantWorkError(f"{field} is not a bounded identifier")
    return value


def _reject_secret_keys(value: object, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise AssistantWorkError(f"{path} keys must be strings")
            if _SECRET_KEY.search(key):
                raise AssistantWorkError(f"credential-like field is forbidden at {path}.{key}")
            _reject_secret_keys(item, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_secret_keys(item, f"{path}[{index}]")


def _safe_path(value: Path | str) -> Path:
    path = Path(os.path.abspath(os.fspath(value)))
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise AssistantWorkError("assistant work store path is unsafe")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.is_symlink() or path.is_symlink():
        raise AssistantWorkError("assistant work store path is unsafe")
    return path


class AssistantWorkStore:
    def __init__(self, path: Path | str, *, clock: Callable[[], float] = time.time) -> None:
        self.path = _safe_path(path)
        self._clock = clock
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            _safe_path(self.path), timeout=5, isolation_level=None, check_same_thread=False
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA journal_mode = WAL")
        if self.path.is_symlink() or not self.path.is_file():
            connection.close()
            raise AssistantWorkError("assistant work store changed during open")
        return connection

    def _initialize(self) -> None:
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "CREATE TABLE IF NOT EXISTS assistant_metadata "
                "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            row = db.execute(
                "SELECT value FROM assistant_metadata WHERE key='schema'"
            ).fetchone()
            if row is None:
                db.execute(
                    "INSERT INTO assistant_metadata(key,value) VALUES('schema',?)", (SCHEMA,)
                )
            elif row["value"] != SCHEMA:
                raise AssistantWorkError("assistant work schema is unsupported")
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS assistant_work (
                    work_id TEXT PRIMARY KEY,
                    instance_id TEXT NOT NULL,
                    application_id TEXT NOT NULL,
                    conversation_id TEXT NOT NULL,
                    message_id TEXT NOT NULL UNIQUE,
                    participant_id TEXT NOT NULL,
                    source_sequence INTEGER NOT NULL CHECK(source_sequence >= 1),
                    state TEXT NOT NULL CHECK(state IN (
                      'queued','invoking','result_ready','delivering',
                      'completed','failed','cancelled')),
                    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
                    active_attempt_id TEXT,
                    lease_owner TEXT,
                    lease_token_hash TEXT,
                    lease_expires_epoch REAL,
                    provider_result_json TEXT,
                    provider_result_digest TEXT,
                    reply_message_id TEXT,
                    error_json TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS assistant_work_state
                    ON assistant_work(state,created_at,work_id);
                CREATE TABLE IF NOT EXISTS assistant_attempts (
                    attempt_id TEXT PRIMARY KEY,
                    work_id TEXT NOT NULL REFERENCES assistant_work(work_id),
                    ordinal INTEGER NOT NULL CHECK(ordinal >= 1),
                    state TEXT NOT NULL CHECK(state IN (
                      'running','result_ready','delivering','completed',
                      'failed','interrupted')),
                    runtime_profile_json TEXT,
                    process_identity_json TEXT,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    result_digest TEXT,
                    error_json TEXT,
                    UNIQUE(work_id,ordinal)
                );
                CREATE TABLE IF NOT EXISTS assistant_events (
                    work_id TEXT NOT NULL REFERENCES assistant_work(work_id),
                    sequence INTEGER NOT NULL CHECK(sequence >= 1),
                    event_id TEXT NOT NULL UNIQUE,
                    attempt_id TEXT,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    PRIMARY KEY(work_id,sequence)
                );
                CREATE TRIGGER IF NOT EXISTS assistant_events_update_immutable
                BEFORE UPDATE ON assistant_events
                BEGIN SELECT RAISE(ABORT,'assistant events are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS assistant_events_delete_immutable
                BEFORE DELETE ON assistant_events
                BEGIN SELECT RAISE(ABORT,'assistant events are immutable'); END;
                """
            )
            db.commit()
            os.chmod(self.path, 0o600)
        except Exception:
            if db.in_transaction:
                db.rollback()
            raise
        finally:
            db.close()

    def _epoch(self) -> float:
        value = float(self._clock())
        if value < 0:
            raise AssistantWorkError("assistant work clock is invalid")
        return value

    @staticmethod
    def _iso(epoch: float) -> str:
        return (
            datetime.fromtimestamp(epoch, timezone.utc)
            .replace(microsecond=0).isoformat().replace("+00:00", "Z")
        )

    @staticmethod
    def _lease_hash(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    @staticmethod
    def _mapping(value: object, field: str) -> dict[str, Any] | None:
        if value is None:
            return None
        decoded = json.loads(str(value))
        if not isinstance(decoded, dict):
            raise AssistantWorkError(f"stored {field} is malformed")
        return decoded

    def _event(
        self,
        db: sqlite3.Connection,
        work_id: str,
        attempt_id: str | None,
        event_type: str,
        payload: Mapping[str, Any],
        occurred_at: str,
    ) -> dict[str, Any]:
        if event_type not in _EVENTS:
            raise AssistantWorkError("assistant event type is unsupported")
        _reject_secret_keys(payload)
        encoded = _canonical(dict(payload))
        if len(encoded.encode()) > 128 * 1024:
            raise AssistantWorkError("assistant event payload exceeds 128KiB")
        row = db.execute(
            "SELECT COALESCE(MAX(sequence),0)+1 AS sequence "
            "FROM assistant_events WHERE work_id=?", (work_id,)
        ).fetchone()
        sequence = int(row["sequence"])
        event_id = f"event.{work_id}.{sequence}"
        db.execute(
            "INSERT INTO assistant_events VALUES(?,?,?,?,?,?,?)",
            (work_id, sequence, event_id, attempt_id, event_type, encoded, occurred_at),
        )
        return {
            "formatVersion": EVENT_FORMAT, "workId": work_id, "sequence": sequence,
            "eventId": event_id, "attemptId": attempt_id, "eventType": event_type,
            "payload": dict(payload), "occurredAt": occurred_at,
        }

    def enqueue(
        self,
        *,
        instance_id: str,
        application_id: str,
        conversation_id: str,
        message_id: str,
        participant_id: str,
        source_sequence: int,
    ) -> dict[str, Any]:
        ids = {
            "instance_id": _identifier(instance_id, "instance_id"),
            "application_id": _identifier(application_id, "application_id"),
            "conversation_id": _identifier(conversation_id, "conversation_id"),
            "message_id": _identifier(message_id, "message_id"),
            "participant_id": _identifier(participant_id, "participant_id"),
        }
        if isinstance(source_sequence, bool) or not isinstance(source_sequence, int) or source_sequence < 1:
            raise AssistantWorkError("source_sequence must be a positive integer")
        work_id = "assistant." + _digest(
            {"conversationId": conversation_id, "messageId": message_id}
        )[7:39]
        now = self._iso(self._epoch())
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute(
                "SELECT * FROM assistant_work WHERE message_id=?", (message_id,)
            ).fetchone()
            if existing is not None:
                expected = (
                    work_id, instance_id, application_id, conversation_id,
                    message_id, participant_id, source_sequence,
                )
                actual = tuple(
                    existing[key] for key in (
                        "work_id", "instance_id", "application_id", "conversation_id",
                        "message_id", "participant_id", "source_sequence",
                    )
                )
                if actual != expected:
                    raise AssistantWorkConflict(
                        "assistant message identity was reused with different work facts"
                    )
                db.commit()
                return self._record(existing)
            db.execute(
                "INSERT INTO assistant_work("
                "work_id,instance_id,application_id,conversation_id,message_id,"
                "participant_id,source_sequence,state,created_at,updated_at"
                ") VALUES(?,?,?,?,?,?,?,'queued',?,?)",
                (work_id, *ids.values(), source_sequence, now, now),
            )
            self._event(
                db, work_id, None, "work.queued",
                {"instanceId": instance_id, "conversationId": conversation_id, "messageId": message_id},
                now,
            )
            row = db.execute("SELECT * FROM assistant_work WHERE work_id=?", (work_id,)).fetchone()
            db.commit()
            return self._record(row)
        except sqlite3.IntegrityError as exc:
            if db.in_transaction:
                db.rollback()
            raise AssistantWorkConflict("assistant work identity is not unique") from exc
        except Exception:
            if db.in_transaction:
                db.rollback()
            raise
        finally:
            db.close()

    def reconcile_expired_leases(self) -> dict[str, int]:
        epoch, interrupted, requeued = self._epoch(), 0, 0
        now = self._iso(epoch)
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute(
                "SELECT * FROM assistant_work WHERE state IN ('invoking','delivering') "
                "AND lease_expires_epoch<=? ORDER BY created_at,work_id", (epoch,)
            ).fetchall()
            for row in rows:
                work_id, attempt_id = row["work_id"], row["active_attempt_id"]
                if row["state"] == "invoking":
                    error = {
                        "code": "provider_outcome_unknown_after_lease_expiry",
                        "message": "Automatic reinvocation is refused because the provider outcome is unknown.",
                    }
                    db.execute(
                        "UPDATE assistant_work SET state='failed',error_json=?,"
                        "lease_owner=NULL,lease_token_hash=NULL,lease_expires_epoch=NULL,"
                        "updated_at=? WHERE work_id=?",
                        (_canonical(error), now, work_id),
                    )
                    db.execute(
                        "UPDATE assistant_attempts SET state='interrupted',finished_at=?,error_json=? "
                        "WHERE attempt_id=? AND state='running'",
                        (now, _canonical(error), attempt_id),
                    )
                    self._event(
                        db, work_id, attempt_id, "attempt.interrupted",
                        {"reason": error["code"]}, now,
                    )
                    interrupted += 1
                else:
                    db.execute(
                        "UPDATE assistant_work SET state='result_ready',lease_owner=NULL,"
                        "lease_token_hash=NULL,lease_expires_epoch=NULL,updated_at=? WHERE work_id=?",
                        (now, work_id),
                    )
                    db.execute(
                        "UPDATE assistant_attempts SET state='result_ready' "
                        "WHERE attempt_id=? AND state='delivering'", (attempt_id,)
                    )
                    requeued += 1
            db.commit()
            return {"invocationsInterrupted": interrupted, "deliveriesRequeued": requeued}
        except Exception:
            if db.in_transaction:
                db.rollback()
            raise
        finally:
            db.close()

    def claim_next(self, *, worker_id: str, lease_seconds: int = 120) -> AssistantClaim | None:
        owner = _identifier(worker_id, "worker_id")
        if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int) or not 5 <= lease_seconds <= 3600:
            raise AssistantWorkError("lease_seconds must be between 5 and 3600")
        self.reconcile_expired_leases()
        epoch, token = self._epoch(), secrets.token_urlsafe(32)
        expires, now = epoch + lease_seconds, self._iso(epoch)
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM assistant_work WHERE state='result_ready' "
                "ORDER BY created_at,work_id LIMIT 1"
            ).fetchone()
            phase = "deliver"
            if row is None:
                row = db.execute(
                    "SELECT * FROM assistant_work WHERE state='queued' "
                    "ORDER BY created_at,work_id LIMIT 1"
                ).fetchone()
                phase = "invoke"
            if row is None:
                db.commit()
                return None
            work_id = str(row["work_id"])
            if phase == "invoke":
                ordinal = int(row["attempt_count"]) + 1
                attempt_id = f"attempt.{work_id}.{ordinal}"
                db.execute(
                    "INSERT INTO assistant_attempts(attempt_id,work_id,ordinal,state,started_at) "
                    "VALUES(?,?,?,'running',?)", (attempt_id, work_id, ordinal, now)
                )
                db.execute(
                    "UPDATE assistant_work SET state='invoking',attempt_count=?,active_attempt_id=?,"
                    "lease_owner=?,lease_token_hash=?,lease_expires_epoch=?,updated_at=? "
                    "WHERE work_id=? AND state='queued'",
                    (ordinal, attempt_id, owner, self._lease_hash(token), expires, now, work_id),
                )
                self._event(db, work_id, attempt_id, "attempt.started", {"ordinal": ordinal}, now)
            else:
                ordinal, attempt_id = int(row["attempt_count"]), str(row["active_attempt_id"] or "")
                if not attempt_id:
                    raise AssistantWorkStateError("result-ready work has no active attempt")
                db.execute(
                    "UPDATE assistant_work SET state='delivering',lease_owner=?,lease_token_hash=?,"
                    "lease_expires_epoch=?,updated_at=? WHERE work_id=? AND state='result_ready'",
                    (owner, self._lease_hash(token), expires, now, work_id),
                )
                db.execute(
                    "UPDATE assistant_attempts SET state='delivering' "
                    "WHERE attempt_id=? AND state='result_ready'", (attempt_id,)
                )
                self._event(db, work_id, attempt_id, "delivery.started", {}, now)
            current = db.execute("SELECT * FROM assistant_work WHERE work_id=?", (work_id,)).fetchone()
            db.commit()
            return AssistantClaim(
                work_id, attempt_id, phase, token, self._iso(expires),
                current["instance_id"], current["application_id"], current["conversation_id"],
                current["message_id"], current["participant_id"], int(current["source_sequence"]),
                ordinal, self._mapping(current["provider_result_json"], "provider result"),
            )
        except Exception:
            if db.in_transaction:
                db.rollback()
            raise
        finally:
            db.close()

    def _lease(
        self,
        db: sqlite3.Connection,
        work_id: str,
        attempt_id: str,
        lease_token: str,
        state: str,
    ) -> sqlite3.Row:
        _identifier(work_id, "work_id")
        _identifier(attempt_id, "attempt_id")
        if not isinstance(lease_token, str) or len(lease_token) < 32:
            raise AssistantWorkLeaseError("assistant lease token is invalid")
        row = db.execute("SELECT * FROM assistant_work WHERE work_id=?", (work_id,)).fetchone()
        if (
            row is None or row["state"] != state or row["active_attempt_id"] != attempt_id
            or not row["lease_token_hash"]
            or not secrets.compare_digest(row["lease_token_hash"], self._lease_hash(lease_token))
            or row["lease_expires_epoch"] is None
            or float(row["lease_expires_epoch"]) <= self._epoch()
        ):
            raise AssistantWorkLeaseError("assistant work lease is not owned")
        return row

    def record_process_identity(
        self,
        *,
        work_id: str,
        attempt_id: str,
        lease_token: str,
        process_identity: Mapping[str, Any],
        runtime_profile: Mapping[str, Any],
    ) -> dict[str, Any]:
        _reject_secret_keys(process_identity)
        _reject_secret_keys(runtime_profile)
        process_json, runtime_json = _canonical(dict(process_identity)), _canonical(dict(runtime_profile))
        if len(process_json) > 16384 or len(runtime_json) > 16384:
            raise AssistantWorkError("assistant process identity exceeds bounds")
        now, db = self._iso(self._epoch()), self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            self._lease(db, work_id, attempt_id, lease_token, "invoking")
            db.execute(
                "UPDATE assistant_attempts SET process_identity_json=?,runtime_profile_json=? "
                "WHERE attempt_id=? AND state='running'",
                (process_json, runtime_json, attempt_id),
            )
            event = self._event(
                db, work_id, attempt_id, "process.started",
                {
                    "runtimeProfileDigest": _digest(runtime_profile),
                    "processIdentityDigest": _digest(process_identity),
                },
                now,
            )
            db.commit()
            return event
        except Exception:
            if db.in_transaction:
                db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def _provider_result(value: Mapping[str, Any]) -> dict[str, Any]:
        required = {"assistantText", "runtime", "adapter", "provider", "model", "usage"}
        optional = {"durationMs", "cleanup"}
        if not isinstance(value, Mapping) or set(value) - (required | optional) or not required.issubset(value):
            raise AssistantWorkError("provider result shape is invalid")
        text = value["assistantText"]
        if not isinstance(text, str) or not text.strip() or len(text.encode()) > 256 * 1024:
            raise AssistantWorkError("provider assistant text is invalid")
        for key in required - {"assistantText"}:
            if not isinstance(value[key], Mapping):
                raise AssistantWorkError(f"provider result {key} is invalid")
        _reject_secret_keys(value)
        result = dict(value)
        if len(_canonical(result).encode()) > 320 * 1024:
            raise AssistantWorkError("provider result exceeds bounds")
        return result

    def store_provider_result(
        self,
        *,
        work_id: str,
        attempt_id: str,
        lease_token: str,
        result: Mapping[str, Any],
    ) -> dict[str, Any]:
        result = self._provider_result(result)
        encoded, result_digest = _canonical(result), _digest(result)
        now, db = self._iso(self._epoch()), self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            self._lease(db, work_id, attempt_id, lease_token, "invoking")
            db.execute(
                "UPDATE assistant_work SET state='result_ready',provider_result_json=?,"
                "provider_result_digest=?,lease_owner=NULL,lease_token_hash=NULL,"
                "lease_expires_epoch=NULL,updated_at=? WHERE work_id=?",
                (encoded, result_digest, now, work_id),
            )
            db.execute(
                "UPDATE assistant_attempts SET state='result_ready',result_digest=? "
                "WHERE attempt_id=? AND state='running'", (result_digest, attempt_id)
            )
            event = self._event(
                db, work_id, attempt_id, "provider.result_stored",
                {
                    "resultDigest": result_digest,
                    **{key: dict(result[key]) for key in ("runtime", "adapter", "provider", "model", "usage")},
                },
                now,
            )
            db.commit()
            return event
        except Exception:
            if db.in_transaction:
                db.rollback()
            raise
        finally:
            db.close()

    def record_reply(
        self,
        *,
        work_id: str,
        attempt_id: str,
        lease_token: str,
        reply_message_id: str,
    ) -> dict[str, Any]:
        reply_id = _identifier(reply_message_id, "reply_message_id")
        now, db = self._iso(self._epoch()), self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            row = self._lease(db, work_id, attempt_id, lease_token, "delivering")
            if row["provider_result_digest"] is None:
                raise AssistantWorkStateError("provider result must be durable before reply")
            db.execute(
                "UPDATE assistant_work SET state='completed',reply_message_id=?,lease_owner=NULL,"
                "lease_token_hash=NULL,lease_expires_epoch=NULL,updated_at=? WHERE work_id=?",
                (reply_id, now, work_id),
            )
            db.execute(
                "UPDATE assistant_attempts SET state='completed',finished_at=? "
                "WHERE attempt_id=? AND state='delivering'", (now, attempt_id)
            )
            event = self._event(
                db, work_id, attempt_id, "reply.persisted",
                {"replyMessageId": reply_id, "resultDigest": row["provider_result_digest"]}, now
            )
            db.commit()
            return event
        except Exception:
            if db.in_transaction:
                db.rollback()
            raise
        finally:
            db.close()

    def fail(
        self,
        *,
        work_id: str,
        attempt_id: str,
        lease_token: str,
        code: str,
        message: str,
    ) -> dict[str, Any]:
        if not isinstance(code, str) or re.fullmatch(r"[a-z][a-z0-9_]{2,127}", code) is None:
            raise AssistantWorkError("assistant failure code is invalid")
        if not isinstance(message, str) or not message or len(message) > 2048:
            raise AssistantWorkError("assistant failure message is invalid")
        error, now, db = {"code": code, "message": message}, self._iso(self._epoch()), self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT state FROM assistant_work WHERE work_id=?", (work_id,)).fetchone()
            if row is None or row["state"] not in {"invoking", "delivering"}:
                raise AssistantWorkStateError("assistant work is not active")
            self._lease(db, work_id, attempt_id, lease_token, row["state"])
            db.execute(
                "UPDATE assistant_work SET state='failed',error_json=?,lease_owner=NULL,"
                "lease_token_hash=NULL,lease_expires_epoch=NULL,updated_at=? WHERE work_id=?",
                (_canonical(error), now, work_id),
            )
            db.execute(
                "UPDATE assistant_attempts SET state='failed',finished_at=?,error_json=? "
                "WHERE attempt_id=?", (now, _canonical(error), attempt_id)
            )
            event = self._event(
                db, work_id, attempt_id, "attempt.failed", error, now
            )
            db.commit()
            return event
        except Exception:
            if db.in_transaction:
                db.rollback()
            raise
        finally:
            db.close()

    def event_journal(
        self, work_id: str, *, after_sequence: int = 0, limit: int = 200
    ) -> tuple[dict[str, Any], ...]:
        work_id = _identifier(work_id, "work_id")
        if isinstance(after_sequence, bool) or not isinstance(after_sequence, int) or after_sequence < 0:
            raise AssistantWorkError("after_sequence is invalid")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise AssistantWorkError("event limit is invalid")
        db = self._connect()
        try:
            rows = db.execute(
                "SELECT * FROM assistant_events WHERE work_id=? AND sequence>? "
                "ORDER BY sequence LIMIT ?", (work_id, after_sequence, limit)
            ).fetchall()
            events, expected = [], after_sequence + 1
            for row in rows:
                if int(row["sequence"]) != expected:
                    raise AssistantWorkError("assistant event journal has a sequence gap")
                events.append(
                    {
                        "formatVersion": EVENT_FORMAT, "workId": work_id,
                        "sequence": int(row["sequence"]), "eventId": row["event_id"],
                        "attemptId": row["attempt_id"], "eventType": row["event_type"],
                        "payload": self._mapping(row["payload_json"], "event payload"),
                        "occurredAt": row["occurred_at"],
                    }
                )
                expected += 1
            return tuple(events)
        finally:
            db.close()

    def get_by_message(self, message_id: str) -> dict[str, Any] | None:
        message_id = _identifier(message_id, "message_id")
        db = self._connect()
        try:
            row = db.execute(
                "SELECT * FROM assistant_work WHERE message_id=?", (message_id,)
            ).fetchone()
            return None if row is None else self._record(row)
        finally:
            db.close()

    def get(self, work_id: str) -> dict[str, Any]:
        work_id = _identifier(work_id, "work_id")
        db = self._connect()
        try:
            row = db.execute("SELECT * FROM assistant_work WHERE work_id=?", (work_id,)).fetchone()
            if row is None:
                raise AssistantWorkError("assistant work was not found")
            result = self._record(row)
            attempts = db.execute(
                "SELECT * FROM assistant_attempts WHERE work_id=? ORDER BY ordinal", (work_id,)
            ).fetchall()
            result["attempts"] = [
                {
                    "attemptId": item["attempt_id"], "ordinal": int(item["ordinal"]),
                    "state": item["state"],
                    "runtimeProfile": self._mapping(item["runtime_profile_json"], "runtime profile"),
                    "processIdentity": self._mapping(item["process_identity_json"], "process identity"),
                    "startedAt": item["started_at"], "finishedAt": item["finished_at"],
                    "resultDigest": item["result_digest"],
                    "error": self._mapping(item["error_json"], "attempt error"),
                }
                for item in attempts
            ]
            return result
        finally:
            db.close()

    def _record(self, row: sqlite3.Row) -> dict[str, Any]:
        if row["state"] not in _STATES:
            raise AssistantWorkError("assistant work state is invalid")
        if row["provider_result_digest"] is not None and _DIGEST.fullmatch(row["provider_result_digest"]) is None:
            raise AssistantWorkError("provider result digest is invalid")
        return {
            "formatVersion": WORK_FORMAT, "workId": row["work_id"],
            "instanceId": row["instance_id"], "applicationId": row["application_id"],
            "conversationId": row["conversation_id"], "messageId": row["message_id"],
            "participantId": row["participant_id"], "sourceSequence": int(row["source_sequence"]),
            "state": row["state"], "attemptCount": int(row["attempt_count"]),
            "activeAttemptId": row["active_attempt_id"],
            "providerResult": self._mapping(row["provider_result_json"], "provider result"),
            "providerResultDigest": row["provider_result_digest"],
            "replyMessageId": row["reply_message_id"],
            "error": self._mapping(row["error_json"], "assistant error"),
            "createdAt": row["created_at"], "updatedAt": row["updated_at"],
        }


__all__ = [
    "AssistantClaim", "AssistantWorkConflict", "AssistantWorkError",
    "AssistantWorkLeaseError", "AssistantWorkStateError", "AssistantWorkStore",
]
