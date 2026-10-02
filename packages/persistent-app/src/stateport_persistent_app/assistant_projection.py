"""Read-only browser projections for durable assistant work."""

from __future__ import annotations

import sqlite3
from typing import Any

from .assistant_work import AssistantWorkError, AssistantWorkStore

_FORMAT = "stateport.assistant-work-projection/v1"
_VISIBLE_STATES = frozenset(
    {"queued", "invoking", "result_ready", "delivering", "failed", "cancelled"}
)


def conversation_work_projection(
    store: AssistantWorkStore,
    *,
    conversation_id: str,
    limit: int = 100,
) -> dict[str, Any]:
    """Return bounded non-secret work status for one conversation.

    Provider output remains in the event/reply path. This projection exposes
    only enough identity and state to reconstruct transient UI placeholders
    after a refresh.
    """

    if not isinstance(conversation_id, str) or not conversation_id:
        raise AssistantWorkError("conversation identity is invalid")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
        raise AssistantWorkError("assistant work projection limit is invalid")
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(
            f"file:{store.path.as_posix()}?mode=ro",
            uri=True,
            timeout=5,
        )
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT w.work_id,w.message_id,w.source_sequence,w.state,"
            "w.active_attempt_id,w.error_json,w.created_at,w.updated_at,"
            "MAX(e.sequence) AS last_event_sequence "
            "FROM assistant_work w "
            "LEFT JOIN assistant_events e ON e.work_id=w.work_id "
            "WHERE w.conversation_id=? "
            "AND w.state IN ('queued','invoking','result_ready','delivering','failed','cancelled') "
            "GROUP BY w.work_id "
            "ORDER BY w.source_sequence,w.created_at,w.work_id LIMIT ?",
            (conversation_id, limit),
        ).fetchall()
    except sqlite3.Error as exc:
        raise AssistantWorkError(
            "assistant work projection could not be read"
        ) from exc
    finally:
        if connection is not None:
            connection.close()

    items: list[dict[str, Any]] = []
    for row in rows:
        record = store.get(str(row["work_id"]))
        state = str(record["state"])
        if state not in _VISIBLE_STATES or record["conversationId"] != conversation_id:
            raise AssistantWorkError(
                "assistant work projection changed during read"
            )
        sequence = row["last_event_sequence"]
        last_event_id = (
            f"event.{record['workId']}.{int(sequence)}"
            if sequence is not None
            else None
        )
        error = record.get("error")
        safe_error = None
        if isinstance(error, dict):
            code = error.get("code")
            message = error.get("message")
            safe_error = {
                "code": code if isinstance(code, str) else "assistant_failed",
                "message": (
                    message[:2048]
                    if isinstance(message, str) and message
                    else "The assistant attempt failed."
                ),
            }
        items.append(
            {
                "formatVersion": _FORMAT,
                "workId": record["workId"],
                "messageId": record["messageId"],
                "sourceSequence": record["sourceSequence"],
                "state": state,
                "attemptId": record["activeAttemptId"],
                "lastEventId": last_event_id,
                "error": safe_error,
                "createdAt": record["createdAt"],
                "updatedAt": record["updatedAt"],
            }
        )
    return {
        "formatVersion": "stateport.assistant-work-list/v1",
        "conversationId": conversation_id,
        "items": items,
    }


__all__ = ["conversation_work_projection"]
