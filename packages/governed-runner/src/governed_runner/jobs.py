"""Durable local job queue with atomic SQLite admission and leasing."""

from __future__ import annotations

import hashlib
import json
import math
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping


JOB_FORMAT = "stateport.job/v1"
JOB_QUEUE_SCHEMA = "stateport.job-queue-schema/v1"
CONTAINER_JOB_PAYLOAD_FORMAT = "stateport.container-job/v1"
CONTAINER_ECHO_COMMAND = ("python3", "-m", "runner", "/stateport/instance")
JOB_STATES = frozenset({"queued", "leased", "succeeded", "failed", "cancelled"})
TERMINAL_JOB_STATES = frozenset({"succeeded", "failed", "cancelled"})


class JobQueueError(ValueError):
    """Base error for invalid queue storage, input, or transitions."""


class JobConflictError(JobQueueError):
    """An idempotency key or explicit job id conflicts with immutable data."""


class JobLeaseError(JobQueueError):
    """A lease is missing, expired, or does not match the supplied token."""


class JobStateError(JobQueueError):
    """A job cannot transition from its current state."""


def _required_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise JobQueueError(f"{field} must be a non-empty string")
    return value.strip()


def _utc_timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise JobQueueError("queue clock must return a timezone-aware datetime")
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _lease_duration(value: Any) -> timedelta:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or value <= 0
    ):
        raise JobQueueError("lease_seconds must be a positive finite number")
    return timedelta(seconds=float(value))


def _canonical_mapping(value: Any, field: str) -> tuple[dict[str, Any], str]:
    if not isinstance(value, Mapping):
        raise JobQueueError(f"{field} must be a JSON object")
    try:
        encoded = json.dumps(
            dict(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        decoded = json.loads(encoded)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise JobQueueError(f"{field} must be JSON serializable: {exc}") from exc
    if not isinstance(decoded, dict):
        raise JobQueueError(f"{field} must be a JSON object")
    return decoded, encoded


def _absolute_without_symlink_resolution(path: Path | str) -> Path:
    if not isinstance(path, (Path, str)) or not os.fspath(path):
        raise JobQueueError("job database path is required")
    return Path(os.path.abspath(os.fspath(path)))


def _assert_path_components_safe(path: Path, *, include_leaf: bool) -> None:
    cursor = Path(path.anchor)
    parts = path.parts[1:] if path.is_absolute() else path.parts
    checked = parts if include_leaf else parts[:-1]
    for part in checked:
        cursor = cursor / part
        if cursor.is_symlink():
            raise JobQueueError("job database path may not traverse a symlink")
        if cursor.exists() and not cursor.is_dir():
            raise JobQueueError("job database parent must be a directory")


def _safe_database_path(path: Path | str) -> Path:
    target = _absolute_without_symlink_resolution(path)
    _assert_path_components_safe(target, include_leaf=False)
    target.parent.mkdir(parents=True, exist_ok=True)
    _assert_path_components_safe(target, include_leaf=False)
    if target.is_symlink():
        raise JobQueueError("job database may not be a symlink")
    if target.exists() and not target.is_file():
        raise JobQueueError("job database must be a regular file")
    for suffix in ("-journal", "-wal", "-shm"):
        if Path(str(target) + suffix).is_symlink():
            raise JobQueueError("job database sidecars may not be symlinks")
    return target


class JobQueue:
    """SQLite-backed FIFO queue for one local operational control plane.

    Each method opens its own connection. Mutating operations use
    ``BEGIN IMMEDIATE`` so enqueue idempotency and lease claims remain atomic
    across threads, processes, and queue-object restarts.
    """

    def __init__(
        self,
        path: Path | str,
        *,
        clock: Callable[[], datetime] | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(float(timeout_seconds))
            or timeout_seconds <= 0
        ):
            raise JobQueueError("timeout_seconds must be a positive finite number")
        self.path = _safe_database_path(path)
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._timeout_seconds = float(timeout_seconds)
        self._initialize()

    def _now(self) -> tuple[datetime, str]:
        value = self._clock()
        return value.astimezone(timezone.utc), _utc_timestamp(value)

    def _connect(self) -> sqlite3.Connection:
        _safe_database_path(self.path)
        try:
            connection = sqlite3.connect(
                self.path,
                timeout=self._timeout_seconds,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute(f"PRAGMA busy_timeout = {int(self._timeout_seconds * 1000)}")
            connection.execute("PRAGMA foreign_keys = ON")
        except sqlite3.Error as exc:
            raise JobQueueError(f"job database could not be opened: {exc}") from exc
        if self.path.is_symlink() or not self.path.is_file():
            connection.close()
            raise JobQueueError("job database changed during open")
        return connection

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS queue_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            row = connection.execute(
                "SELECT value FROM queue_metadata WHERE key = 'schema'"
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO queue_metadata(key, value) VALUES('schema', ?)",
                    (JOB_QUEUE_SCHEMA,),
                )
            elif row["value"] != JOB_QUEUE_SCHEMA:
                raise JobQueueError("job database schema version is not supported")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS jobs (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL UNIQUE,
                    format_version TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    payload_version TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    payload_digest TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('queued','leased','succeeded','failed','cancelled')),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
                    lease_owner TEXT,
                    lease_token TEXT,
                    lease_expires_at TEXT,
                    result_json TEXT,
                    error_json TEXT
                )
                """
            )
            connection.execute(
                """
                CREATE TRIGGER IF NOT EXISTS jobs_payload_immutable
                BEFORE UPDATE OF job_id, format_version, idempotency_key,
                    payload_version, payload_json, payload_digest, created_at
                ON jobs
                BEGIN
                    SELECT RAISE(ABORT, 'job identity and payload are immutable');
                END
                """
            )
            connection.execute(
                """
                CREATE TRIGGER IF NOT EXISTS jobs_terminal_immutable
                BEFORE UPDATE ON jobs
                WHEN OLD.status IN ('succeeded','failed','cancelled')
                BEGIN
                    SELECT RAISE(ABORT, 'terminal jobs are immutable');
                END
                """
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _decode_json(value: str | None, field: str) -> Any:
        if value is None:
            return None
        try:
            return json.loads(value)
        except json.JSONDecodeError as exc:
            raise JobQueueError(f"stored {field} is invalid JSON") from exc

    @classmethod
    def _record(cls, row: sqlite3.Row) -> dict[str, Any]:
        lease = None
        if row["status"] == "leased":
            lease = {
                "owner": row["lease_owner"],
                "token": row["lease_token"],
                "expiresAt": row["lease_expires_at"],
            }
        return {
            "formatVersion": row["format_version"],
            "sequence": row["sequence"],
            "jobId": row["job_id"],
            "idempotencyKey": row["idempotency_key"],
            "payloadVersion": row["payload_version"],
            "payload": cls._decode_json(row["payload_json"], "payload"),
            "payloadDigest": row["payload_digest"],
            "status": row["status"],
            "createdAt": row["created_at"],
            "updatedAt": row["updated_at"],
            "attemptCount": row["attempt_count"],
            "lease": lease,
            "result": cls._decode_json(row["result_json"], "result"),
            "error": cls._decode_json(row["error_json"], "error"),
        }

    def enqueue(
        self,
        *,
        idempotency_key: str,
        payload: Mapping[str, Any],
        job_id: str | None = None,
    ) -> dict[str, Any]:
        key = _required_string(idempotency_key, "idempotency_key")
        normalized, payload_json = _canonical_mapping(payload, "payload")
        payload_version = _required_string(normalized.get("formatVersion"), "payload.formatVersion")
        digest = "sha256:" + hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
        requested_job_id = _required_string(job_id, "job_id") if job_id is not None else None
        generated_job_id = requested_job_id or "job:" + secrets.token_hex(16)
        _, now = self._now()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT * FROM jobs WHERE idempotency_key = ?", (key,)
            ).fetchone()
            if existing is not None:
                if existing["payload_digest"] != digest:
                    raise JobConflictError("idempotency key is bound to a different payload")
                if requested_job_id is not None and existing["job_id"] != requested_job_id:
                    raise JobConflictError("idempotency key is bound to a different job id")
                connection.commit()
                return self._record(existing)
            try:
                connection.execute(
                    """
                    INSERT INTO jobs(
                        job_id, format_version, idempotency_key, payload_version,
                        payload_json, payload_digest, status, created_at, updated_at
                    ) VALUES(?, ?, ?, ?, ?, ?, 'queued', ?, ?)
                    """,
                    (
                        generated_job_id,
                        JOB_FORMAT,
                        key,
                        payload_version,
                        payload_json,
                        digest,
                        now,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise JobConflictError("job id or idempotency key already exists") from exc
            row = connection.execute(
                "SELECT * FROM jobs WHERE job_id = ?", (generated_job_id,)
            ).fetchone()
            connection.commit()
            return self._record(row)
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def claim(self, *, worker_id: str, lease_seconds: float = 60.0) -> dict[str, Any] | None:
        owner = _required_string(worker_id, "worker_id")
        duration = _lease_duration(lease_seconds)
        current, now = self._now()
        expires = _utc_timestamp(current + duration)
        token = secrets.token_urlsafe(32)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            candidate = connection.execute(
                """
                SELECT * FROM jobs
                WHERE status = 'queued'
                   OR (status = 'leased' AND lease_expires_at <= ?)
                ORDER BY sequence ASC
                LIMIT 1
                """,
                (now,),
            ).fetchone()
            if candidate is None:
                connection.commit()
                return None
            connection.execute(
                """
                UPDATE jobs
                SET status = 'leased', updated_at = ?, attempt_count = attempt_count + 1,
                    lease_owner = ?, lease_token = ?, lease_expires_at = ?,
                    result_json = NULL, error_json = NULL
                WHERE sequence = ?
                """,
                (now, owner, token, expires, candidate["sequence"]),
            )
            row = connection.execute(
                "SELECT * FROM jobs WHERE sequence = ?", (candidate["sequence"],)
            ).fetchone()
            connection.commit()
            return self._record(row)
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _leased_for_update(
        connection: sqlite3.Connection,
        job_id: str,
        lease_token: str,
        now: str,
    ) -> sqlite3.Row:
        row = connection.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
        if row is None:
            raise JobStateError("job was not found")
        if row["status"] in TERMINAL_JOB_STATES:
            raise JobStateError("terminal jobs are immutable")
        if row["status"] != "leased":
            raise JobLeaseError("job is not leased")
        if row["lease_token"] != lease_token:
            raise JobLeaseError("lease token does not match")
        if row["lease_expires_at"] is None or row["lease_expires_at"] <= now:
            raise JobLeaseError("job lease has expired")
        return row

    def heartbeat(
        self,
        job_id: str,
        lease_token: str,
        *,
        lease_seconds: float = 60.0,
    ) -> dict[str, Any]:
        identifier = _required_string(job_id, "job_id")
        credential = _required_string(lease_token, "lease_token")
        duration = _lease_duration(lease_seconds)
        current, now = self._now()
        expires = _utc_timestamp(current + duration)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._leased_for_update(connection, identifier, credential, now)
            connection.execute(
                "UPDATE jobs SET updated_at = ?, lease_expires_at = ? WHERE job_id = ?",
                (now, expires, identifier),
            )
            row = connection.execute("SELECT * FROM jobs WHERE job_id = ?", (identifier,)).fetchone()
            connection.commit()
            return self._record(row)
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _finish(
        self,
        job_id: str,
        lease_token: str,
        *,
        status: str,
        result: Mapping[str, Any] | None = None,
        error: Mapping[str, Any] | str | None = None,
    ) -> dict[str, Any]:
        identifier = _required_string(job_id, "job_id")
        credential = _required_string(lease_token, "lease_token")
        if status not in {"succeeded", "failed"}:
            raise JobStateError("finish status must be succeeded or failed")
        result_json = None
        error_json = None
        if result is not None:
            _, result_json = _canonical_mapping(result, "result")
        if isinstance(error, str):
            error_json = json.dumps(
                {"message": error}, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            )
        elif error is not None:
            _, error_json = _canonical_mapping(error, "error")
        _, now = self._now()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._leased_for_update(connection, identifier, credential, now)
            connection.execute(
                """
                UPDATE jobs
                SET status = ?, updated_at = ?, lease_owner = NULL,
                    lease_token = NULL, lease_expires_at = NULL,
                    result_json = ?, error_json = ?
                WHERE job_id = ?
                """,
                (status, now, result_json, error_json, identifier),
            )
            row = connection.execute("SELECT * FROM jobs WHERE job_id = ?", (identifier,)).fetchone()
            connection.commit()
            return self._record(row)
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def complete(
        self,
        job_id: str,
        lease_token: str,
        *,
        result: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self._finish(job_id, lease_token, status="succeeded", result=result)

    def fail(
        self,
        job_id: str,
        lease_token: str,
        *,
        error: Mapping[str, Any] | str,
    ) -> dict[str, Any]:
        return self._finish(job_id, lease_token, status="failed", error=error)

    def cancel(self, job_id: str, *, reason: str = "") -> dict[str, Any]:
        identifier = _required_string(job_id, "job_id")
        if not isinstance(reason, str):
            raise JobQueueError("reason must be a string")
        error_json = json.dumps(
            {"reason": reason}, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        _, now = self._now()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                "SELECT * FROM jobs WHERE job_id = ?", (identifier,)
            ).fetchone()
            if current is None:
                raise JobStateError("job was not found")
            if current["status"] in TERMINAL_JOB_STATES:
                raise JobStateError("terminal jobs are immutable")
            connection.execute(
                """
                UPDATE jobs
                SET status = 'cancelled', updated_at = ?, lease_owner = NULL,
                    lease_token = NULL, lease_expires_at = NULL, error_json = ?
                WHERE job_id = ?
                """,
                (now, error_json, identifier),
            )
            row = connection.execute("SELECT * FROM jobs WHERE job_id = ?", (identifier,)).fetchone()
            connection.commit()
            return self._record(row)
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def requeue(
        self,
        job_id: str,
        lease_token: str,
        *,
        reason: str = "",
    ) -> dict[str, Any]:
        """Return an owned, unexpired lease to FIFO admission without finishing it."""

        identifier = _required_string(job_id, "job_id")
        credential = _required_string(lease_token, "lease_token")
        if not isinstance(reason, str):
            raise JobQueueError("reason must be a string")
        error_json = (
            json.dumps(
                {"reason": reason},
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            if reason
            else None
        )
        _, now = self._now()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._leased_for_update(connection, identifier, credential, now)
            connection.execute(
                """
                UPDATE jobs
                SET status = 'queued', updated_at = ?, lease_owner = NULL,
                    lease_token = NULL, lease_expires_at = NULL,
                    result_json = NULL, error_json = ?
                WHERE job_id = ?
                """,
                (now, error_json, identifier),
            )
            row = connection.execute(
                "SELECT * FROM jobs WHERE job_id = ?", (identifier,)
            ).fetchone()
            connection.commit()
            return self._record(row)
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def get(self, job_id: str) -> dict[str, Any] | None:
        identifier = _required_string(job_id, "job_id")
        connection = self._connect()
        try:
            row = connection.execute("SELECT * FROM jobs WHERE job_id = ?", (identifier,)).fetchone()
            return self._record(row) if row is not None else None
        finally:
            connection.close()

    def list(self, *, status: str | None = None) -> tuple[dict[str, Any], ...]:
        if status is not None and status not in JOB_STATES:
            raise JobQueueError("status is not a recognized job state")
        connection = self._connect()
        try:
            if status is None:
                rows = connection.execute("SELECT * FROM jobs ORDER BY sequence ASC").fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM jobs WHERE status = ? ORDER BY sequence ASC", (status,)
                ).fetchall()
            return tuple(self._record(row) for row in rows)
        finally:
            connection.close()


__all__ = [
    "CONTAINER_ECHO_COMMAND",
    "CONTAINER_JOB_PAYLOAD_FORMAT",
    "JOB_FORMAT",
    "JOB_QUEUE_SCHEMA",
    "JOB_STATES",
    "TERMINAL_JOB_STATES",
    "JobConflictError",
    "JobLeaseError",
    "JobQueue",
    "JobQueueError",
    "JobStateError",
]
