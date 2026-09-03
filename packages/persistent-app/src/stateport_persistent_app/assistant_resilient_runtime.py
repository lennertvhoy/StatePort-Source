"""Fault-resilient delivery for the per-work-cancellable assistant runtime."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .assistant_cancellable_runtime import (
    AssistantProcessor as CancellableAssistantProcessor,
    CancellableAssistantWorkStore,
)
from .assistant_work import (
    AssistantClaim,
    AssistantWorkError,
    AssistantWorkStateError,
    _canonical,
)

_MAX_AUTOMATIC_DELIVERY_RETRIES = 3


class ResilientAssistantWorkStore(CancellableAssistantWorkStore):
    """Return failed reply delivery to the durable result outbox."""

    def requeue_delivery(
        self,
        *,
        work_id: str,
        attempt_id: str,
        lease_token: str,
        code: str,
        message: str,
    ) -> dict[str, Any]:
        if not isinstance(message, str) or not message or len(message) > 2048:
            raise AssistantWorkError("assistant delivery failure message is invalid")
        now = self._iso(self._epoch())
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            row = self._lease(
                db,
                work_id,
                attempt_id,
                lease_token,
                "delivering",
            )
            if row["provider_result_digest"] is None:
                raise AssistantWorkStateError(
                    "provider result must remain durable before redelivery"
                )
            retry_rows = db.execute(
                "SELECT payload_json FROM assistant_events "
                "WHERE work_id=? AND event_type='attempt.interrupted' "
                "ORDER BY sequence",
                (work_id,),
            ).fetchall()
            retries = 0
            for item in retry_rows:
                try:
                    payload = json.loads(str(item["payload_json"]))
                except json.JSONDecodeError:
                    continue
                if isinstance(payload, dict) and payload.get("retryableDelivery") is True:
                    retries += 1
            failure = {"code": code, "message": message}
            if retries + 1 >= _MAX_AUTOMATIC_DELIVERY_RETRIES:
                db.execute(
                    "UPDATE assistant_work SET state='failed',error_json=?,"
                    "lease_owner=NULL,lease_token_hash=NULL,lease_expires_epoch=NULL,"
                    "updated_at=? WHERE work_id=? AND state='delivering'",
                    (_canonical(failure), now, work_id),
                )
                db.execute(
                    "UPDATE assistant_attempts SET state='failed',finished_at=?,"
                    "error_json=? WHERE attempt_id=? AND state='delivering'",
                    (now, _canonical(failure), attempt_id),
                )
                event = self._event(
                    db,
                    work_id,
                    attempt_id,
                    "attempt.failed",
                    {
                        **failure,
                        "deliveryRetriesExhausted": True,
                        "retryCount": retries + 1,
                    },
                    now,
                )
                db.commit()
                return {
                    "formatVersion": "stateport.assistant-delivery-retry/v1",
                    "workId": work_id,
                    "status": "failed",
                    "retryCount": retries + 1,
                    "event": event,
                }
            db.execute(
                "UPDATE assistant_work SET state='result_ready',error_json=?,"
                "lease_owner=NULL,lease_token_hash=NULL,lease_expires_epoch=NULL,"
                "updated_at=? WHERE work_id=? AND state='delivering'",
                (_canonical(failure), now, work_id),
            )
            db.execute(
                "UPDATE assistant_attempts SET state='result_ready',error_json=? "
                "WHERE attempt_id=? AND state='delivering'",
                (_canonical(failure), attempt_id),
            )
            event = self._event(
                db,
                work_id,
                attempt_id,
                "attempt.interrupted",
                {
                    "reason": code,
                    "retryableDelivery": True,
                    "retryCount": retries + 1,
                },
                now,
            )
            db.commit()
            return {
                "formatVersion": "stateport.assistant-delivery-retry/v1",
                "workId": work_id,
                "status": "result_ready",
                "retryCount": retries + 1,
                "event": event,
            }
        except Exception:
            if db.in_transaction:
                db.rollback()
            raise
        finally:
            db.close()


class AssistantProcessor(CancellableAssistantProcessor):
    """Cancellation-aware processor with restart-safe reply redelivery."""

    def __init__(
        self,
        *args: Any,
        work_store: CancellableAssistantWorkStore | None = None,
        **kwargs: Any,
    ) -> None:
        if work_store is None:
            import os

            state_root = (
                Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state"))
                / "stateport"
            )
            resilient_store = ResilientAssistantWorkStore(
                state_root / "assistant-work.sqlite3"
            )
        elif isinstance(work_store, ResilientAssistantWorkStore):
            resilient_store = work_store
        else:
            resilient_store = ResilientAssistantWorkStore(work_store.path)
        super().__init__(*args, work_store=resilient_store, **kwargs)

    @property
    def work_store(self) -> ResilientAssistantWorkStore:
        store = self._work
        if not isinstance(store, ResilientAssistantWorkStore):
            raise AssistantWorkError("assistant resilient delivery store is unavailable")
        return store

    def _deliver(self, claim: AssistantClaim) -> None:
        result = claim.provider_result
        text = result.get("assistantText") if isinstance(result, dict) else None
        if not isinstance(text, str) or not text.strip():
            self._fail_claim(
                claim,
                "assistant_result_invalid",
                "durable provider result has no assistant text",
            )
            return
        try:
            reply_id = self._existing_reply_id(claim)
            if reply_id is None:
                reply = self._conversations.send_internal(
                    participant_id=claim.participant_id,
                    conversation_id=claim.conversation_id,
                    body=text,
                    kind="assistant_message",
                    source_message_id=claim.message_id,
                )
                reply_id = reply.message_id
            self.work_store.record_reply(
                work_id=claim.work_id,
                attempt_id=claim.attempt_id,
                lease_token=claim.lease_token,
                reply_message_id=reply_id,
            )
        except Exception as exc:
            try:
                outcome = self.work_store.requeue_delivery(
                    work_id=claim.work_id,
                    attempt_id=claim.attempt_id,
                    lease_token=claim.lease_token,
                    code="assistant_delivery_failed",
                    message=(str(exc) or type(exc).__name__)[:2048],
                )
                self._log_event(
                    "assistant_delivery_requeued",
                    f"work={claim.work_id} status={outcome['status']} "
                    f"retry={outcome['retryCount']}",
                )
            except AssistantWorkStateError:
                # A reply or completion may already be durable despite a lost
                # acknowledgement. Never rewrite that outcome as failed.
                return


__all__ = [
    "AssistantProcessor",
    "ResilientAssistantWorkStore",
]
