"""Thin service entry that adds durable assistant-work projections and events.

The existing AppServer remains the sole HTTP/static/WebSocket authority. This
module subclasses only the request handler and delegates every unrelated route
unchanged to ``service_process``.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from urllib.parse import unquote, urlsplit

from stateport_persistent_app import service_process as base
from stateport_persistent_app.assistant_projection import (
    conversation_work_projection,
)
from stateport_persistent_app.assistant_work import AssistantWorkError


_EVENT_ID = re.compile(r"^event\.(assistant\.[0-9a-f]{32})\.([1-9][0-9]*)$")
_ROUTE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_TERMINAL_STATES = frozenset({"completed", "failed", "cancelled"})
_STREAM_TIMEOUT_SECONDS = 300.0


def parse_event_cursor(value: str | None, work_id: str) -> int:
    if value is None or not value.strip():
        return 0
    match = _EVENT_ID.fullmatch(value.strip())
    if match is None or match.group(1) != work_id:
        raise ValueError("assistant event cursor does not match this work item")
    return int(match.group(2))


def event_stream_path(path: str) -> tuple[str, str] | None:
    parts = [unquote(part) for part in path.split("/") if part]
    if (
        len(parts) == 7
        and parts[:2] == ["v1", "instances"]
        and parts[3] == "conversation"
        and parts[4] == "messages"
        and parts[6] == "events"
        and _ROUTE_ID.fullmatch(parts[2]) is not None
        and _ROUTE_ID.fullmatch(parts[5]) is not None
    ):
        return parts[2], parts[5]
    return None


def work_projection_path(path: str) -> str | None:
    parts = [unquote(part) for part in path.split("/") if part]
    if (
        len(parts) == 5
        and parts[:2] == ["v1", "instances"]
        and parts[3:] == ["conversation", "assistant-work"]
        and _ROUTE_ID.fullmatch(parts[2]) is not None
    ):
        return parts[2]
    return None


class AssistantHandler(base.Handler):
    def _assistant_scope(self, instance_id: str):
        try:
            return self.server.conversation_for_instance(instance_id)
        except Exception:
            self._error(
                404,
                "instance conversation was not found",
                "conversation_not_found",
            )
            return None

    def _handle_assistant_work_projection(self, instance_id: str) -> None:
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
        scope = self._assistant_scope(instance_id)
        if scope is None:
            return
        thread, _participant_id, _binding = scope
        processor = getattr(self.server, "_assistant_processor", None)
        if processor is None:
            self._send(
                200,
                {
                    "ok": True,
                    "result": {
                        "formatVersion": "stateport.assistant-work-list/v1",
                        "conversationId": thread.conversation_id,
                        "enabled": False,
                        "items": [],
                    },
                },
            )
            return
        try:
            processor.reconcile_messages()
            projection = conversation_work_projection(
                processor.work_store,
                conversation_id=thread.conversation_id,
            )
        except AssistantWorkError:
            self._error(
                503,
                "assistant work projection is unavailable",
                "assistant_projection_unavailable",
            )
            return
        self._send(
            200,
            {
                "ok": True,
                "result": {
                    **projection,
                    "enabled": True,
                    "runtime": processor.router.runtime_profile,
                },
            },
        )

    def _assistant_sse_headers(self) -> None:
        self.send_response(200)
        self.send_header(
            "Content-Type",
            "text/event-stream; charset=utf-8",
        )
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; connect-src 'self'",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.end_headers()

    def _assistant_sse(
        self,
        *,
        event_id: str | None,
        event: str,
        data: object,
    ) -> None:
        lines: list[str] = []
        if event_id is not None:
            lines.append(f"id: {event_id}")
        lines.append(f"event: {event}")
        payload = json.dumps(
            data,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        for line in payload.splitlines() or [""]:
            lines.append(f"data: {line}")
        lines.extend(("", ""))
        self.wfile.write("\n".join(lines).encode("utf-8"))
        self.wfile.flush()

    def _assistant_event_payload(
        self,
        event: dict[str, object],
        record: dict[str, object],
    ) -> tuple[str, dict[str, object]]:
        event_type = str(event["eventType"])
        payload = event.get("payload")
        bounded = dict(payload) if isinstance(payload, dict) else {}
        common = {
            "formatVersion": "stateport.assistant-stream-event/v1",
            "workId": event["workId"],
            "messageId": record["messageId"],
            "attemptId": event.get("attemptId"),
            "sequence": event["sequence"],
            "occurredAt": event["occurredAt"],
        }
        if event_type == "provider.result_stored":
            result = record.get("providerResult")
            if (
                not isinstance(result, dict)
                or not isinstance(result.get("assistantText"), str)
            ):
                raise AssistantWorkError(
                    "durable provider result is missing from stream"
                )
            return "assistant_result", {
                **common,
                "text": result["assistantText"],
                "runtime": result.get("runtime"),
                "adapter": result.get("adapter"),
                "provider": result.get("provider"),
                "model": result.get("model"),
                "usage": result.get("usage"),
            }
        if event_type == "reply.persisted":
            return "message_end", {
                **common,
                "status": "completed",
                "replyMessageId": bounded.get("replyMessageId"),
            }
        if event_type in {"attempt.failed", "attempt.interrupted"}:
            return "assistant_error", {
                **common,
                "status": "failed",
                "error": bounded,
            }
        return "assistant_event", {
            **common,
            "type": event_type,
            "payload": bounded,
        }

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
            after = parse_event_cursor(
                self.headers.get("Last-Event-ID"),
                str(record["workId"]),
            )
        except ValueError:
            self._error(
                409,
                "assistant event cursor is stale",
                "assistant_cursor_stale",
            )
            return

        self._assistant_sse_headers()
        deadline = time.monotonic() + _STREAM_TIMEOUT_SECONDS
        next_sequence = after
        last_heartbeat = time.monotonic()
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
                                "formatVersion": (
                                    "stateport.assistant-stream-event/v1"
                                ),
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
                if record.get("state") in _TERMINAL_STATES:
                    if not events and record.get("state") != "completed":
                        self._assistant_sse(
                            event_id=None,
                            event="assistant_error",
                            data={
                                "formatVersion": (
                                    "stateport.assistant-stream-event/v1"
                                ),
                                "workId": record["workId"],
                                "messageId": record["messageId"],
                                "status": record["state"],
                                "error": record.get("error"),
                            },
                        )
                    return
                now = time.monotonic()
                if now - last_heartbeat >= 15:
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
                    "formatVersion": (
                        "stateport.assistant-stream-event/v1"
                    ),
                    "workId": record["workId"],
                    "messageId": record["messageId"],
                    "afterSequence": next_sequence,
                },
            )
        except (BrokenPipeError, ConnectionResetError, OSError):
            return

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        instance_id = work_projection_path(path)
        if instance_id is not None:
            self._handle_assistant_work_projection(instance_id)
            return
        parsed = event_stream_path(path)
        if parsed is None:
            super().do_GET()
            return
        stream_instance_id, message_id = parsed
        self._handle_assistant_events(
            stream_instance_id,
            message_id,
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--owned-service-marker", default=None)
    known, remaining = parser.parse_known_args(argv)
    if known.owned_service_marker not in {
        None,
        "stateport_persistent_app.service_process",
    }:
        raise SystemExit("invalid StatePort service ownership marker")
    base.Handler = AssistantHandler
    return base.main(remaining)


if __name__ == "__main__":
    sys.exit(main())
