"""Durable, subject-scoped quota reservations backed by stdlib SQLite.

The ledger stores operational admission metadata.  Estimated and actual costs
are quota-control inputs only; they are not invoices or billing records.
"""

from __future__ import annotations

import math
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from quota_engine.engine import QuotaDecision, QuotaEngine, QuotaPolicy, UsageSnapshot


SCHEMA_VERSION = 1
_ACTIVE_USAGE_STATUSES = ("active", "committed")
_OPERATIONS = {"run", "message", "mutation"}
_STATUSES = {"active", "committed", "released", "denied"}


class UsageLedgerError(ValueError):
    """A fail-closed ledger configuration, persistence, or input error."""


class ReservationConflictError(UsageLedgerError):
    """A reservation id is already bound to different immutable inputs."""


class ReservationStateError(UsageLedgerError):
    """A requested transition is invalid for the reservation's current state."""


@dataclass(frozen=True)
class UsageReservation:
    reservation_id: str
    subject_id: str
    operation: str
    estimated_cost: float
    actual_cost: float | None
    status: str
    reserved_at: str
    terminal_at: str | None
    usage_day: str
    usage_month: str
    policy: QuotaPolicy
    usage_before: UsageSnapshot
    decision_code: str
    decision_reason: str
    admitted: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "formatVersion": "stateport.usage-reservation/v1",
            "reservationId": self.reservation_id,
            "subjectId": self.subject_id,
            "operation": self.operation,
            "estimatedCost": self.estimated_cost,
            "actualCost": self.actual_cost,
            "status": self.status,
            "reservedAt": self.reserved_at,
            "terminalAt": self.terminal_at,
            "usageDay": self.usage_day,
            "usageMonth": self.usage_month,
            "policy": self.policy.__dict__.copy(),
            "usageBefore": self.usage_before.__dict__.copy(),
            "decision": {
                "allowed": self.admitted,
                "code": self.decision_code,
                "reason": self.decision_reason,
            },
        }


@dataclass(frozen=True)
class ReservationOutcome:
    reservation: UsageReservation
    decision: QuotaDecision
    idempotent: bool

    @property
    def allowed(self) -> bool:
        return self.decision.allowed


@dataclass(frozen=True)
class ReservationTransition:
    reservation: UsageReservation
    idempotent: bool


class UsageLedger:
    """Persist atomic quota reservations without becoming workflow state.

    A fresh SQLite connection is used for every operation.  ``BEGIN
    IMMEDIATE`` serializes snapshot-and-reserve decisions across processes so
    concurrent callers cannot independently admit the same remaining quota.
    """

    def __init__(
        self,
        path: Path | str,
        *,
        clock: Callable[[], datetime] | None = None,
        timeout_seconds: float = 30.0,
    ) -> None:
        raw_path = os.fspath(path)
        if not isinstance(raw_path, str) or not raw_path.strip():
            raise UsageLedgerError("usage ledger path must be non-empty")
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
            raise UsageLedgerError("timeout_seconds must be numeric")
        if not math.isfinite(float(timeout_seconds)) or timeout_seconds <= 0:
            raise UsageLedgerError("timeout_seconds must be finite and positive")
        self.path = Path(os.path.abspath(os.path.expanduser(raw_path)))
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._timeout_seconds = float(timeout_seconds)
        self._prepare_path()
        self._initialize()

    def _prepare_path(self) -> None:
        self._reject_symlinks()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._reject_symlinks()
        if self.path.exists() and not self.path.is_file():
            raise UsageLedgerError("usage ledger path must be a regular file")

    def _reject_symlinks(self) -> None:
        for candidate in (*reversed(self.path.parents), self.path):
            if candidate.is_symlink():
                raise UsageLedgerError("usage ledger path may not traverse a symlink")
        for suffix in ("-journal", "-shm", "-wal"):
            if Path(f"{self.path}{suffix}").is_symlink():
                raise UsageLedgerError("usage ledger sidecar may not be a symlink")

    def _connect(self) -> sqlite3.Connection:
        self._prepare_path()
        try:
            connection = sqlite3.connect(
                self.path,
                timeout=self._timeout_seconds,
                isolation_level=None,
            )
        except sqlite3.Error as exc:
            raise UsageLedgerError(f"usage ledger could not be opened: {exc}") from exc
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(f"PRAGMA busy_timeout = {int(self._timeout_seconds * 1000)}")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            try:
                connection.execute("PRAGMA journal_mode = WAL")
                connection.execute("PRAGMA synchronous = FULL")
                connection.execute("BEGIN IMMEDIATE")
                version = int(connection.execute("PRAGMA user_version").fetchone()[0])
                if version == 0:
                    existing = connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                    ).fetchall()
                    if existing:
                        raise UsageLedgerError("usage ledger database is non-empty and unversioned")
                    connection.execute(
                        """
                        CREATE TABLE usage_reservations (
                            reservation_id TEXT PRIMARY KEY,
                            subject_id TEXT NOT NULL,
                            operation TEXT NOT NULL CHECK (operation IN ('run', 'message', 'mutation')),
                            estimated_cost REAL NOT NULL CHECK (estimated_cost >= 0),
                            actual_cost REAL CHECK (actual_cost IS NULL OR actual_cost >= 0),
                            status TEXT NOT NULL CHECK (status IN ('active', 'committed', 'released', 'denied')),
                            reserved_at TEXT NOT NULL,
                            terminal_at TEXT,
                            usage_day TEXT NOT NULL,
                            usage_month TEXT NOT NULL,
                            runs_per_day INTEGER,
                            messages_per_day INTEGER,
                            monthly_euro_estimate REAL,
                            runs_before INTEGER NOT NULL CHECK (runs_before >= 0),
                            messages_before INTEGER NOT NULL CHECK (messages_before >= 0),
                            monthly_cost_before REAL NOT NULL CHECK (monthly_cost_before >= 0),
                            decision_allowed INTEGER NOT NULL CHECK (decision_allowed IN (0, 1)),
                            decision_code TEXT NOT NULL,
                            decision_reason TEXT NOT NULL,
                            CHECK (
                                (status = 'active' AND actual_cost IS NULL AND terminal_at IS NULL AND decision_allowed = 1)
                                OR (status = 'committed' AND actual_cost IS NOT NULL AND terminal_at IS NOT NULL AND decision_allowed = 1)
                                OR (status = 'released' AND actual_cost IS NULL AND terminal_at IS NOT NULL AND decision_allowed = 1)
                                OR (status = 'denied' AND actual_cost IS NULL AND terminal_at IS NOT NULL AND decision_allowed = 0)
                            )
                        )
                        """
                    )
                    connection.execute(
                        "CREATE INDEX usage_reservations_daily ON usage_reservations(subject_id, usage_day, status, operation)"
                    )
                    connection.execute(
                        "CREATE INDEX usage_reservations_monthly ON usage_reservations(subject_id, usage_month, status)"
                    )
                    connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                elif version != SCHEMA_VERSION:
                    raise UsageLedgerError(
                        f"unsupported usage ledger schema version: {version}"
                    )
                table = connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'usage_reservations'"
                ).fetchone()
                if table is None:
                    raise UsageLedgerError("usage ledger schema is incomplete")
                connection.commit()
            except (sqlite3.Error, UsageLedgerError) as exc:
                connection.rollback()
                if isinstance(exc, UsageLedgerError):
                    raise
                raise UsageLedgerError(f"usage ledger initialization failed: {exc}") from exc

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime):
            raise UsageLedgerError("usage ledger clock must return a datetime")
        if value.tzinfo is None or value.utcoffset() is None:
            raise UsageLedgerError("usage ledger clock must return a timezone-aware datetime")
        return value.astimezone(timezone.utc)

    @staticmethod
    def _timestamp(value: datetime) -> str:
        return value.isoformat(timespec="microseconds").replace("+00:00", "Z")

    @staticmethod
    def _identifier(value: object, name: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise UsageLedgerError(f"{name} must be a non-empty string")
        return value.strip()

    @staticmethod
    def _cost(value: object, name: str) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise UsageLedgerError(f"{name} must be numeric")
        result = float(value)
        if not math.isfinite(result) or result < 0:
            raise UsageLedgerError(f"{name} must be finite and non-negative")
        return result

    @classmethod
    def _validate_policy(cls, policy: object) -> QuotaPolicy:
        if not isinstance(policy, QuotaPolicy):
            raise UsageLedgerError("policy must be a QuotaPolicy")
        if policy.monthly_euro_estimate is not None:
            cls._cost(policy.monthly_euro_estimate, "monthly_euro_estimate")
        return policy

    @staticmethod
    def _row_policy(row: sqlite3.Row) -> QuotaPolicy:
        return QuotaPolicy(
            runs_per_day=row["runs_per_day"],
            messages_per_day=row["messages_per_day"],
            monthly_euro_estimate=row["monthly_euro_estimate"],
        )

    @classmethod
    def _row_reservation(cls, row: sqlite3.Row) -> UsageReservation:
        status = str(row["status"])
        if status not in _STATUSES:
            raise UsageLedgerError("usage ledger contains an invalid reservation status")
        actual_cost = None if row["actual_cost"] is None else float(row["actual_cost"])
        terminal_at = None if row["terminal_at"] is None else str(row["terminal_at"])
        admitted = bool(row["decision_allowed"])
        valid_state = (
            status == "active" and actual_cost is None and terminal_at is None and admitted
        ) or (
            status == "committed" and actual_cost is not None and terminal_at is not None and admitted
        ) or (
            status == "released" and actual_cost is None and terminal_at is not None and admitted
        ) or (
            status == "denied" and actual_cost is None and terminal_at is not None and not admitted
        )
        if not valid_state:
            raise UsageLedgerError("usage ledger contains an inconsistent reservation state")
        return UsageReservation(
            reservation_id=str(row["reservation_id"]),
            subject_id=str(row["subject_id"]),
            operation=str(row["operation"]),
            estimated_cost=float(row["estimated_cost"]),
            actual_cost=actual_cost,
            status=status,
            reserved_at=str(row["reserved_at"]),
            terminal_at=terminal_at,
            usage_day=str(row["usage_day"]),
            usage_month=str(row["usage_month"]),
            policy=cls._row_policy(row),
            usage_before=UsageSnapshot(
                runs_today=int(row["runs_before"]),
                messages_today=int(row["messages_before"]),
                monthly_euro_estimate=float(row["monthly_cost_before"]),
            ),
            decision_code=str(row["decision_code"]),
            decision_reason=str(row["decision_reason"]),
            admitted=admitted,
        )

    @staticmethod
    def _decision(reservation: UsageReservation) -> QuotaDecision:
        return QuotaDecision(
            allowed=reservation.admitted,
            code=reservation.decision_code,
            reason=reservation.decision_reason,
            usage=reservation.usage_before,
            limits=reservation.policy,
        )

    @staticmethod
    def _policy_binding(policy: QuotaPolicy) -> tuple[int | None, int | None, float | None]:
        monthly = None if policy.monthly_euro_estimate is None else float(policy.monthly_euro_estimate)
        return policy.runs_per_day, policy.messages_per_day, monthly

    @classmethod
    def _assert_binding(
        cls,
        reservation: UsageReservation,
        *,
        subject_id: str,
        operation: str,
        estimated_cost: float,
        policy: QuotaPolicy,
    ) -> None:
        existing = (
            reservation.subject_id,
            reservation.operation,
            reservation.estimated_cost,
            cls._policy_binding(reservation.policy),
        )
        requested = (
            subject_id,
            operation,
            estimated_cost,
            cls._policy_binding(policy),
        )
        if existing != requested:
            raise ReservationConflictError(
                "reservation id is already bound to different immutable inputs"
            )

    @staticmethod
    def _snapshot_in_transaction(
        connection: sqlite3.Connection,
        subject_id: str,
        usage_day: str,
        usage_month: str,
    ) -> UsageSnapshot:
        row = connection.execute(
            """
            SELECT
                COALESCE(SUM(CASE
                    WHEN usage_day = ? AND operation = 'run' AND status IN ('active', 'committed')
                    THEN 1 ELSE 0 END), 0) AS runs_today,
                COALESCE(SUM(CASE
                    WHEN usage_day = ? AND operation = 'message' AND status IN ('active', 'committed')
                    THEN 1 ELSE 0 END), 0) AS messages_today,
                COALESCE(SUM(CASE
                    WHEN usage_month = ? AND status = 'active' THEN estimated_cost
                    WHEN usage_month = ? AND status = 'committed' THEN actual_cost
                    ELSE 0 END), 0.0) AS monthly_cost
            FROM usage_reservations
            WHERE subject_id = ?
            """,
            (usage_day, usage_day, usage_month, usage_month, subject_id),
        ).fetchone()
        return UsageSnapshot(
            runs_today=int(row["runs_today"]),
            messages_today=int(row["messages_today"]),
            monthly_euro_estimate=float(row["monthly_cost"]),
        )

    def snapshot(self, subject_id: str) -> UsageSnapshot:
        subject = self._identifier(subject_id, "subject_id")
        now = self._now()
        with self._connect() as connection:
            try:
                return self._snapshot_in_transaction(
                    connection,
                    subject,
                    now.date().isoformat(),
                    now.strftime("%Y-%m"),
                )
            except sqlite3.Error as exc:
                raise UsageLedgerError(f"usage snapshot failed: {exc}") from exc

    def get(self, reservation_id: str) -> UsageReservation | None:
        identifier = self._identifier(reservation_id, "reservation_id")
        with self._connect() as connection:
            try:
                row = connection.execute(
                    "SELECT * FROM usage_reservations WHERE reservation_id = ?",
                    (identifier,),
                ).fetchone()
            except sqlite3.Error as exc:
                raise UsageLedgerError(f"usage reservation lookup failed: {exc}") from exc
        return None if row is None else self._row_reservation(row)

    def reserve(
        self,
        reservation_id: str,
        subject_id: str,
        operation: str,
        policy: QuotaPolicy,
        *,
        estimated_cost: float = 0.0,
    ) -> ReservationOutcome:
        identifier = self._identifier(reservation_id, "reservation_id")
        subject = self._identifier(subject_id, "subject_id")
        operation = self._identifier(operation, "operation")
        if operation not in _OPERATIONS:
            raise UsageLedgerError("operation must be run, message, or mutation")
        policy = self._validate_policy(policy)
        cost = self._cost(estimated_cost, "estimated_cost")
        now = self._now()
        timestamp = self._timestamp(now)
        usage_day = now.date().isoformat()
        usage_month = now.strftime("%Y-%m")

        with self._connect() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM usage_reservations WHERE reservation_id = ?",
                    (identifier,),
                ).fetchone()
                if row is not None:
                    reservation = self._row_reservation(row)
                    self._assert_binding(
                        reservation,
                        subject_id=subject,
                        operation=operation,
                        estimated_cost=cost,
                        policy=policy,
                    )
                    connection.commit()
                    return ReservationOutcome(
                        reservation,
                        self._decision(reservation),
                        idempotent=True,
                    )

                usage = self._snapshot_in_transaction(
                    connection, subject, usage_day, usage_month
                )
                operation_policy = QuotaPolicy(
                    runs_per_day=policy.runs_per_day if operation == "run" else None,
                    messages_per_day=policy.messages_per_day if operation == "message" else None,
                    monthly_euro_estimate=policy.monthly_euro_estimate,
                )
                evaluated = QuotaEngine(operation_policy).evaluate(
                    usage,
                    operation=operation,
                    estimated_cost=cost,
                )
                decision = QuotaDecision(
                    evaluated.allowed,
                    evaluated.code,
                    evaluated.reason,
                    usage,
                    policy,
                )
                status = "active" if decision.allowed else "denied"
                terminal_at = None if decision.allowed else timestamp
                connection.execute(
                    """
                    INSERT INTO usage_reservations (
                        reservation_id, subject_id, operation, estimated_cost,
                        actual_cost, status, reserved_at, terminal_at, usage_day,
                        usage_month, runs_per_day, messages_per_day,
                        monthly_euro_estimate, runs_before, messages_before,
                        monthly_cost_before, decision_allowed, decision_code,
                        decision_reason
                    ) VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        identifier,
                        subject,
                        operation,
                        cost,
                        status,
                        timestamp,
                        terminal_at,
                        usage_day,
                        usage_month,
                        policy.runs_per_day,
                        policy.messages_per_day,
                        policy.monthly_euro_estimate,
                        usage.runs_today,
                        usage.messages_today,
                        usage.monthly_euro_estimate,
                        int(decision.allowed),
                        decision.code,
                        decision.reason,
                    ),
                )
                row = connection.execute(
                    "SELECT * FROM usage_reservations WHERE reservation_id = ?",
                    (identifier,),
                ).fetchone()
                connection.commit()
                return ReservationOutcome(
                    self._row_reservation(row), decision, idempotent=False
                )
            except (sqlite3.Error, UsageLedgerError) as exc:
                connection.rollback()
                if isinstance(exc, UsageLedgerError):
                    raise
                raise UsageLedgerError(f"usage reservation failed: {exc}") from exc

    def commit(self, reservation_id: str, *, actual_cost: float) -> ReservationTransition:
        identifier = self._identifier(reservation_id, "reservation_id")
        cost = self._cost(actual_cost, "actual_cost")
        timestamp = self._timestamp(self._now())
        with self._connect() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM usage_reservations WHERE reservation_id = ?",
                    (identifier,),
                ).fetchone()
                if row is None:
                    raise ReservationStateError("usage reservation was not found")
                reservation = self._row_reservation(row)
                if reservation.status == "committed":
                    if reservation.actual_cost != cost:
                        raise ReservationConflictError(
                            "committed reservation is bound to a different actual cost"
                        )
                    connection.commit()
                    return ReservationTransition(reservation, idempotent=True)
                if reservation.status != "active":
                    raise ReservationStateError(
                        f"only active reservations can be committed, not {reservation.status}"
                    )
                connection.execute(
                    """
                    UPDATE usage_reservations
                    SET status = 'committed', actual_cost = ?, terminal_at = ?
                    WHERE reservation_id = ? AND status = 'active'
                    """,
                    (cost, timestamp, identifier),
                )
                row = connection.execute(
                    "SELECT * FROM usage_reservations WHERE reservation_id = ?",
                    (identifier,),
                ).fetchone()
                connection.commit()
                return ReservationTransition(
                    self._row_reservation(row), idempotent=False
                )
            except (sqlite3.Error, UsageLedgerError) as exc:
                connection.rollback()
                if isinstance(exc, UsageLedgerError):
                    raise
                raise UsageLedgerError(f"usage reservation commit failed: {exc}") from exc

    def release(self, reservation_id: str) -> ReservationTransition:
        identifier = self._identifier(reservation_id, "reservation_id")
        timestamp = self._timestamp(self._now())
        with self._connect() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM usage_reservations WHERE reservation_id = ?",
                    (identifier,),
                ).fetchone()
                if row is None:
                    raise ReservationStateError("usage reservation was not found")
                reservation = self._row_reservation(row)
                if reservation.status == "released":
                    connection.commit()
                    return ReservationTransition(reservation, idempotent=True)
                if reservation.status != "active":
                    raise ReservationStateError(
                        f"only active reservations can be released, not {reservation.status}"
                    )
                connection.execute(
                    """
                    UPDATE usage_reservations
                    SET status = 'released', terminal_at = ?
                    WHERE reservation_id = ? AND status = 'active'
                    """,
                    (timestamp, identifier),
                )
                row = connection.execute(
                    "SELECT * FROM usage_reservations WHERE reservation_id = ?",
                    (identifier,),
                ).fetchone()
                connection.commit()
                return ReservationTransition(
                    self._row_reservation(row), idempotent=False
                )
            except (sqlite3.Error, UsageLedgerError) as exc:
                connection.rollback()
                if isinstance(exc, UsageLedgerError):
                    raise
                raise UsageLedgerError(f"usage reservation release failed: {exc}") from exc


__all__ = [
    "ReservationConflictError",
    "ReservationOutcome",
    "ReservationStateError",
    "ReservationTransition",
    "SCHEMA_VERSION",
    "UsageLedger",
    "UsageLedgerError",
    "UsageReservation",
]
