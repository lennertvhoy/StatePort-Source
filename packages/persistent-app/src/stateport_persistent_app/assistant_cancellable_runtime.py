"""Per-work cancellation for the durable assistant processor.

This module extends the existing durable processor without creating a second
conversation or execution authority. Cancellation remains operational state in
the assistant-work SQLite store. A work item is recorded as ``cancelled`` only
after the hardened process supervisor has returned and the exact generated
process group is confirmed absent.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import secrets
import signal
import threading
import time
from typing import Any

from external_engine_runtime import ProcessIdentity, TemporaryWorkspace

from .assistant_runtime import AssistantProcessor as DurableAssistantProcessor
from .assistant_work import (
    AssistantClaim,
    AssistantWorkError,
    AssistantWorkStateError,
    AssistantWorkStore,
    _canonical,
)
from .provider_router import ProviderRouterError

_CANCEL_CODE = re.compile(r"^[a-z][a-z0-9_]{2,127}$")
_DISCONNECT_GRACE_SECONDS = 1.5


@dataclass(frozen=True)
class AssistantStreamLease:
    work_id: str
    message_id: str
    token: str


class _AnyCancelEvent:
    def __init__(self, *events: threading.Event) -> None:
        self._events = events

    def is_set(self) -> bool:
        return any(event.is_set() for event in self._events)


class CancellableAssistantWorkStore(AssistantWorkStore):
    """Add atomic cancellation transitions to the existing work authority."""

    @staticmethod
    def _cancel_error(code: str, message: str) -> dict[str, str]:
        if not isinstance(code, str) or _CANCEL_CODE.fullmatch(code) is None:
            raise AssistantWorkError("assistant cancellation code is invalid")
        if not isinstance(message, str) or not message or len(message) > 2048:
            raise AssistantWorkError("assistant cancellation message is invalid")
        return {"code": code, "message": message}

    def request_cancel(
        self,
        *,
        work_id: str,
        code: str,
        message: str,
    ) -> dict[str, Any]:
        """Cancel queued work or request cancellation of one active invocation.

        ``requested`` is deliberately distinct from ``cancelled``. Active work
        becomes cancelled only through :meth:`mark_cancelled`, after process
        cleanup has been independently confirmed by the processor.
        """

        error = self._cancel_error(code, message)
        now = self._iso(self._epoch())
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM assistant_work WHERE work_id=?",
                (work_id,),
            ).fetchone()
            if row is None:
                raise AssistantWorkError("assistant work was not found")
            state = str(row["state"])
            attempt_id = row["active_attempt_id"]
            if state == "queued":
                db.execute(
                    "UPDATE assistant_work SET state='cancelled',error_json=?,"
                    "lease_owner=NULL,lease_token_hash=NULL,lease_expires_epoch=NULL,"
                    "updated_at=? WHERE work_id=? AND state='queued'",
                    (_canonical(error), now, work_id),
                )
                self._event(
                    db,
                    work_id,
                    None,
                    "attempt.interrupted",
                    {"reason": code, "cancelled": True},
                    now,
                )
                db.commit()
                return {
                    "formatVersion": "stateport.assistant-cancellation/v1",
                    "workId": work_id,
                    "state": "cancelled",
                    "status": "cancelled",
                    "reason": code,
                }
            if state == "invoking":
                db.commit()
                return {
                    "formatVersion": "stateport.assistant-cancellation/v1",
                    "workId": work_id,
                    "attemptId": attempt_id,
                    "state": "invoking",
                    "status": "requested",
                    "reason": code,
                }
            if state == "cancelled":
                db.commit()
                return {
                    "formatVersion": "stateport.assistant-cancellation/v1",
                    "workId": work_id,
                    "attemptId": attempt_id,
                    "state": "cancelled",
                    "status": "cancelled",
                    "reason": code,
                }
            db.commit()
            return {
                "formatVersion": "stateport.assistant-cancellation/v1",
                "workId": work_id,
                "attemptId": attempt_id,
                "state": state,
                "status": "not_cancellable",
                "reason": code,
            }
        except Exception:
            if db.in_transaction:
                db.rollback()
            raise
        finally:
            db.close()

    def mark_cancelled(
        self,
        *,
        work_id: str,
        attempt_id: str,
        lease_token: str,
        code: str,
        message: str,
        cleanup: str,
    ) -> dict[str, Any]:
        """Record confirmed process cancellation under the active lease."""

        error = self._cancel_error(code, message)
        if cleanup not in {
            "terminated",
            "killed",
            "already_exited",
            "forced_kill",
            "finished_before_cancel",
        }:
            raise AssistantWorkError("assistant cancellation cleanup is unverified")
        now = self._iso(self._epoch())
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            self._lease(db, work_id, attempt_id, lease_token, "invoking")
            db.execute(
                "UPDATE assistant_work SET state='cancelled',error_json=?,"
                "lease_owner=NULL,lease_token_hash=NULL,lease_expires_epoch=NULL,"
                "updated_at=? WHERE work_id=? AND state='invoking'",
                (_canonical(error), now, work_id),
            )
            db.execute(
                "UPDATE assistant_attempts SET state='interrupted',finished_at=?,"
                "error_json=? WHERE attempt_id=? AND state='running'",
                (now, _canonical({**error, "cleanup": cleanup}), attempt_id),
            )
            event = self._event(
                db,
                work_id,
                attempt_id,
                "attempt.interrupted",
                {
                    "reason": code,
                    "cancelled": True,
                    "cleanup": cleanup,
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


class AssistantProcessor(DurableAssistantProcessor):
    """Durable assistant processor with per-work stream cancellation."""

    def __init__(self, *args: Any, work_store: AssistantWorkStore | None = None, **kwargs: Any) -> None:
        if work_store is None:
            state_root = (
                Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state"))
                / "stateport"
            )
            cancellable_store = CancellableAssistantWorkStore(
                state_root / "assistant-work.sqlite3"
            )
        elif isinstance(work_store, CancellableAssistantWorkStore):
            cancellable_store = work_store
        else:
            # Re-open the same durable authority through the cancellation-aware
            # subclass. No state is copied and no second database is created.
            cancellable_store = CancellableAssistantWorkStore(work_store.path)
        super().__init__(*args, work_store=cancellable_store, **kwargs)
        self._cancel_mutex = threading.Lock()
        self._work_cancel_events: dict[str, threading.Event] = {}
        self._work_cancel_reasons: dict[str, str] = {}
        self._stream_tokens: dict[str, set[str]] = {}
        self._disconnect_timers: dict[str, threading.Timer] = {}

    @property
    def work_store(self) -> CancellableAssistantWorkStore:
        store = self._work
        if not isinstance(store, CancellableAssistantWorkStore):
            raise AssistantWorkError("assistant cancellation store is unavailable")
        return store

    def _event_for_work(self, work_id: str) -> threading.Event:
        with self._cancel_mutex:
            return self._work_cancel_events.setdefault(work_id, threading.Event())

    def attach_stream(self, message_id: str) -> AssistantStreamLease:
        record = self.work_store.get_by_message(message_id)
        if record is None:
            raise AssistantWorkError("assistant work was not found")
        work_id = str(record["workId"])
        token = secrets.token_urlsafe(24)
        with self._cancel_mutex:
            timer = self._disconnect_timers.pop(work_id, None)
            if timer is not None:
                timer.cancel()
            self._stream_tokens.setdefault(work_id, set()).add(token)
        return AssistantStreamLease(work_id, message_id, token)

    def detach_stream(
        self,
        lease: AssistantStreamLease,
        *,
        disconnected: bool,
    ) -> None:
        with self._cancel_mutex:
            listeners = self._stream_tokens.get(lease.work_id)
            if listeners is not None:
                listeners.discard(lease.token)
                if not listeners:
                    self._stream_tokens.pop(lease.work_id, None)
            if not disconnected or lease.work_id in self._stream_tokens:
                return
            previous = self._disconnect_timers.pop(lease.work_id, None)
            if previous is not None:
                previous.cancel()
            timer = threading.Timer(
                _DISCONNECT_GRACE_SECONDS,
                self._cancel_after_disconnect,
                args=(lease.work_id, lease.message_id),
            )
            timer.daemon = True
            self._disconnect_timers[lease.work_id] = timer
            timer.start()

    def _cancel_after_disconnect(self, work_id: str, message_id: str) -> None:
        with self._cancel_mutex:
            self._disconnect_timers.pop(work_id, None)
            if work_id in self._stream_tokens:
                return
        try:
            self.cancel_message(
                message_id,
                reason="stream_disconnected",
                message="The last assistant event stream disconnected before completion.",
            )
        except AssistantWorkError:
            # Work may have completed during the grace period. Completion is the
            # durable authority; a late disconnect never rewrites it.
            return

    def cancel_message(
        self,
        message_id: str,
        *,
        reason: str = "user_cancelled",
        message: str = "The assistant attempt was cancelled by the user.",
    ) -> dict[str, Any]:
        record = self.work_store.get_by_message(message_id)
        if record is None:
            raise AssistantWorkError("assistant work was not found")
        work_id = str(record["workId"])
        result = self.work_store.request_cancel(
            work_id=work_id,
            code=reason,
            message=message,
        )
        if result["status"] == "requested":
            event = self._event_for_work(work_id)
            with self._cancel_mutex:
                self._work_cancel_reasons[work_id] = reason
            event.set()
        return result

    @staticmethod
    def _matching_group_members(identity: ProcessIdentity) -> tuple[int, ...]:
        if (
            os.name != "posix"
            or identity.process_group_id is None
            or identity.process_generation is None
            or not Path("/proc").is_dir()
        ):
            return ()
        expected_marker = (
            "STATEPORT_PROCESS_GENERATION=" + identity.process_generation
        ).encode("utf-8")
        members: list[int] = []
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                stat_fields = (
                    (entry / "stat")
                    .read_text(encoding="utf-8")
                    .rsplit(")", 1)[1]
                    .strip()
                    .split()
                )
                process_group = int(stat_fields[2])
                environment = (entry / "environ").read_bytes().split(b"\0")
            except (OSError, IndexError, ValueError):
                continue
            if (
                process_group == identity.process_group_id
                and expected_marker in environment
            ):
                members.append(int(entry.name))
        return tuple(sorted(members))

    @classmethod
    def _ensure_process_group_reaped(
        cls,
        identity: ProcessIdentity | None,
        *,
        process_finished: bool,
    ) -> tuple[bool, str]:
        if identity is None:
            return (process_finished, "finished_before_cancel" if process_finished else "unverified")
        members = cls._matching_group_members(identity)
        if not members:
            return (True, "finished_before_cancel" if process_finished else "already_exited")
        if identity.process_group_id is None:
            return (False, "unverified")
        try:
            os.killpg(identity.process_group_id, signal.SIGKILL)
        except ProcessLookupError:
            return (True, "already_exited")
        except OSError:
            return (False, "unverified")
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            if not cls._matching_group_members(identity):
                return (True, "forced_kill")
            time.sleep(0.02)
        return (False, "unverified")

    def _invoke(self, claim: AssistantClaim) -> None:
        cancel_event = self._event_for_work(claim.work_id)
        started: list[ProcessIdentity] = []
        finished: list[ProcessIdentity] = []

        def on_started(identity: ProcessIdentity) -> None:
            started.append(identity)
            self._record_process_identity(claim, identity)

        def on_finished(identity: ProcessIdentity) -> None:
            finished.append(identity)

        try:
            objective, context_digest = self._conversation_objective(claim)
            with TemporaryWorkspace(
                self._staging_root,
                prefix=f"{claim.work_id.removeprefix('assistant.')[:16]}-",
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
                    cancel_event=_AnyCancelEvent(self._stop, cancel_event),
                    on_started=on_started,
                    on_finished=on_finished,
                )
            if cancel_event.is_set() or self._stop.is_set():
                self._record_confirmed_cancellation(
                    claim,
                    started=started,
                    finished=finished,
                    process_finished=True,
                )
                return
            self.work_store.store_provider_result(
                work_id=claim.work_id,
                attempt_id=claim.attempt_id,
                lease_token=claim.lease_token,
                result=invocation.durable_result(),
            )
        except ProviderRouterError as exc:
            if str(exc) == "provider_cancelled" or cancel_event.is_set() or self._stop.is_set():
                self._record_confirmed_cancellation(
                    claim,
                    started=started,
                    finished=finished,
                    process_finished=bool(finished),
                )
            else:
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
        finally:
            with self._cancel_mutex:
                self._work_cancel_events.pop(claim.work_id, None)
                self._work_cancel_reasons.pop(claim.work_id, None)
                timer = self._disconnect_timers.pop(claim.work_id, None)
                if timer is not None:
                    timer.cancel()

    def _record_confirmed_cancellation(
        self,
        claim: AssistantClaim,
        *,
        started: list[ProcessIdentity],
        finished: list[ProcessIdentity],
        process_finished: bool,
    ) -> None:
        identity = finished[-1] if finished else started[-1] if started else None
        reaped, cleanup = self._ensure_process_group_reaped(
            identity,
            process_finished=process_finished,
        )
        if not reaped:
            self._fail_claim(
                claim,
                "provider_cancellation_cleanup_failed",
                "The provider cancellation could not prove that the process group was reaped.",
            )
            return
        with self._cancel_mutex:
            reason = self._work_cancel_reasons.get(
                claim.work_id,
                "processor_shutdown" if self._stop.is_set() else "user_cancelled",
            )
        message = (
            "The assistant attempt was cancelled after its event stream disconnected."
            if reason == "stream_disconnected"
            else "The assistant attempt was cancelled by the user."
            if reason == "user_cancelled"
            else "The assistant attempt was cancelled during processor shutdown."
        )
        try:
            self.work_store.mark_cancelled(
                work_id=claim.work_id,
                attempt_id=claim.attempt_id,
                lease_token=claim.lease_token,
                code=reason,
                message=message,
                cleanup=cleanup,
            )
        except AssistantWorkStateError:
            # A result may have become durable in the same instant as a late
            # disconnect. Durable result/delivery wins; cancellation never
            # rewrites a completed outcome.
            return

    def shutdown(self, *, timeout: float = 5.0) -> None:
        with self._cancel_mutex:
            for work_id, event in self._work_cancel_events.items():
                self._work_cancel_reasons.setdefault(work_id, "processor_shutdown")
                event.set()
            for timer in self._disconnect_timers.values():
                timer.cancel()
            self._disconnect_timers.clear()
        super().shutdown(timeout=timeout)


__all__ = [
    "AssistantProcessor",
    "AssistantStreamLease",
    "CancellableAssistantWorkStore",
]
