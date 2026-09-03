"""Assistant-aware AppServer entry with per-work stream cancellation.

This remains a thin extension of the existing same-origin AppServer. It adds
one authenticated cancellation route and stream-lifetime coordination; every
unrelated GET/POST/WebSocket route delegates unchanged to the established
handlers.
"""

from __future__ import annotations

import argparse
import sys
import time
from urllib.parse import unquote, urlsplit

from stateport_persistent_app import service_process
from stateport_persistent_app import service_entry as base_entry
from stateport_persistent_app.assistant_work import AssistantWorkError


def cancellation_path(path: str) -> tuple[str, str] | None:
    parts = [unquote(part) for part in path.split("/") if part]
    if (
        len(parts) == 7
        and parts[:2] == ["v1", "instances"]
        and parts[3:5] == ["conversation", "messages"]
        and parts[6] == "cancel"
        and base_entry._ROUTE_ID.fullmatch(parts[2]) is not None
        and base_entry._ROUTE_ID.fullmatch(parts[5]) is not None
    ):
        return parts[2], parts[5]
    return None


class CancellableAssistantHandler(base_entry.AssistantHandler):
    def _assistant_event_payload(
        self,
        event: dict[str, object],
        record: dict[str, object],
    ) -> tuple[str, dict[str, object]]:
        payload = event.get("payload")
        if (
            event.get("eventType") == "attempt.interrupted"
            and isinstance(payload, dict)
            and payload.get("cancelled") is True
        ):
            return "assistant_cancelled", {
                "formatVersion": "stateport.assistant-stream-event/v1",
                "workId": event["workId"],
                "messageId": record["messageId"],
                "attemptId": event.get("attemptId"),
                "sequence": event["sequence"],
                "occurredAt": event["occurredAt"],
                "status": "cancelled",
                "error": record.get("error"),
                "cleanup": payload.get("cleanup"),
            }
        return super()._assistant_event_payload(event, record)

    def _handle_assistant_cancel(
        self,
        instance_id: str,
        message_id: str,
    ) -> None:
        if not self._valid_request_host():
            self._error(
                421,
                "request host does not match the loopback service",
                "invalid_host",
            )
            return
        if not self._session():
            self._error(
                401,
                "local browser session is required",
                "session_required",
            )
            return
        try:
            self._mutation_security("assistant cancellation")
            body = self._body()
            if set(body) != {"reason"} or body.get("reason") != "user_stop":
                raise ValueError("assistant cancellation request shape is invalid")
        except PermissionError:
            self._error(
                403,
                "assistant cancellation authorization failed",
                "assistant_cancellation_denied",
            )
            return
        except (ValueError, UnicodeError):
            self._error(
                400,
                "assistant cancellation request is invalid",
                "assistant_cancellation_invalid",
            )
            return

        processor = getattr(self.server, "_assistant_processor", None)
        if processor is None:
            self._error(
                503,
                "assistant processing is not enabled for this service",
                "assistant_processor_unavailable",
            )
            return
        try:
            processor.reconcile_messages()
            record = processor.work_store.get_by_message(message_id)
            if record is None or record.get("instanceId") != instance_id:
                self._error(
                    404,
                    "assistant work was not found",
                    "assistant_work_not_found",
                )
                return
            scope = self._assistant_scope(instance_id)
            if scope is None:
                return
            thread, _participant_id, _binding = scope
            if record.get("conversationId") != thread.conversation_id:
                self._error(
                    409,
                    "assistant work conversation identity changed",
                    "assistant_work_stale",
                )
                return
            result = processor.cancel_message(
                message_id,
                reason="user_cancelled",
                message="The assistant attempt was cancelled by the user.",
            )
        except AssistantWorkError:
            self._error(
                409,
                "assistant cancellation could not be recorded",
                "assistant_cancellation_refused",
            )
            return
        self._send(200, {"ok": True, "result": result})

    def _handle_assistant_events(
        self,
        instance_id: str,
        message_id: str,
    ) -> None:
        if not self._valid_request_host():
            self._error(
                421,
                "request host does not match the loopback service",
                "invalid_host",
            )
            return
        if not self._session():
            self._error(
                401,
                "local browser session is required",
                "session_required",
            )
            return
        processor = getattr(self.server, "_assistant_processor", None)
        if processor is None:
            self._error(
                503,
                "assistant processing is not enabled for this service",
                "assistant_processor_unavailable",
            )
            return
        try:
            processor.reconcile_messages()
        except Exception:
            self._error(
                503,
                "assistant message reconciliation failed",
                "assistant_reconciliation_failed",
            )
            return
        record = processor.work_store.get_by_message(message_id)
        if record is None or record.get("instanceId") != instance_id:
            self._error(
                404,
                "assistant work was not found",
                "assistant_work_not_found",
            )
            return
        scope = self._assistant_scope(instance_id)
        if scope is None:
            return
        thread, _participant_id, _binding = scope
        if record.get("conversationId") != thread.conversation_id:
            self._error(
                409,
                "assistant work conversation identity changed",
                "assistant_work_stale",
            )
            return
        try:
            after = base_entry.parse_event_cursor(
                self.headers.get("Last-Event-ID"),
                str(record["workId"]),
            )
            stream_lease = processor.attach_stream(message_id)
        except ValueError:
            self._error(
                409,
                "assistant event cursor is stale",
                "assistant_cursor_stale",
            )
            return
        except AssistantWorkError:
            self._error(
                409,
                "assistant stream could not attach to durable work",
                "assistant_stream_attach_refused",
            )
            return

        self._assistant_sse_headers()
        deadline = time.monotonic() + base_entry._STREAM_TIMEOUT_SECONDS
        next_sequence = after
        last_heartbeat = time.monotonic()
        disconnected = False
        try:
            while time.monotonic() < deadline:
                record = processor.work_store.get(str(record["workId"]))
                events = processor.work_store.event_journal(
                    str(record["workId"]),
                    after_sequence=next_sequence,
                    limit=200,
                )
                for item in events:
                    try:
                        event_name, data = self._assistant_event_payload(
                            item,
                            record,
                        )
                    except AssistantWorkError as exc:
                        self._assistant_sse(
                            event_id=str(item["eventId"]),
                            event="assistant_error",
                            data={
                                "formatVersion": "stateport.assistant-stream-event/v1",
                                "workId": record["workId"],
                                "messageId": record["messageId"],
                                "status": "failed",
                                "error": {
                                    "code": "assistant_event_invalid",
                                    "message": str(exc)[:512],
                                },
                            },
                        )
                        return
                    self._assistant_sse(
                        event_id=str(item["eventId"]),
                        event=event_name,
                        data=data,
                    )
                    next_sequence = int(item["sequence"])
                if record.get("state") in base_entry._TERMINAL_STATES:
                    if not events and record.get("state") == "cancelled":
                        self._assistant_sse(
                            event_id=None,
                            event="assistant_cancelled",
                            data={
                                "formatVersion": "stateport.assistant-stream-event/v1",
                                "workId": record["workId"],
                                "messageId": record["messageId"],
                                "status": "cancelled",
                                "error": record.get("error"),
                            },
                        )
                    elif not events and record.get("state") != "completed":
                        self._assistant_sse(
                            event_id=None,
                            event="assistant_error",
                            data={
                                "formatVersion": "stateport.assistant-stream-event/v1",
                                "workId": record["workId"],
                                "messageId": record["messageId"],
                                "status": record["state"],
                                "error": record.get("error"),
                            },
                        )
                    return
                now = time.monotonic()
                if now - last_heartbeat >= 2.0:
                    self._assistant_sse(
                        event_id=None,
                        event="heartbeat",
                        data={
                            "workId": record["workId"],
                            "afterSequence": next_sequence,
                        },
                    )
                    last_heartbeat = now
                time.sleep(0.1)
            self._assistant_sse(
                event_id=None,
                event="stream_timeout",
                data={
                    "formatVersion": "stateport.assistant-stream-event/v1",
                    "workId": record["workId"],
                    "messageId": record["messageId"],
                    "afterSequence": next_sequence,
                },
            )
        except (BrokenPipeError, ConnectionResetError, OSError):
            disconnected = True
        finally:
            processor.detach_stream(
                stream_lease,
                disconnected=disconnected,
            )

    def do_POST(self) -> None:  # noqa: N802
        parsed = cancellation_path(urlsplit(self.path).path)
        if parsed is None:
            super().do_POST()
            return
        instance_id, message_id = parsed
        self._handle_assistant_cancel(instance_id, message_id)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--owned-service-marker", default=None)
    known, remaining = parser.parse_known_args(argv)
    if known.owned_service_marker not in {
        None,
        "stateport_persistent_app.service_process",
    }:
        raise SystemExit("invalid StatePort service ownership marker")
    service_process.Handler = CancellableAssistantHandler
    return service_process.main(remaining)


if __name__ == "__main__":
    sys.exit(main())
