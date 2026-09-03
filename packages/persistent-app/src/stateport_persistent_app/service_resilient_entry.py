"""Final thin AppServer entry for durable assistant cancellation and redelivery."""

from __future__ import annotations

import argparse
import sys

from stateport_persistent_app import service_process
from stateport_persistent_app.service_entry import AssistantHandler
from stateport_persistent_app.service_cancellation_entry import (
    CancellableAssistantHandler,
)


class ResilientAssistantHandler(CancellableAssistantHandler):
    """Keep retryable reply delivery visible without declaring model failure."""

    def _assistant_event_payload(
        self,
        event: dict[str, object],
        record: dict[str, object],
    ) -> tuple[str, dict[str, object]]:
        payload = event.get("payload")
        if (
            event.get("eventType") == "attempt.interrupted"
            and isinstance(payload, dict)
            and payload.get("retryableDelivery") is True
        ):
            return "assistant_event", {
                "formatVersion": "stateport.assistant-stream-event/v1",
                "workId": event["workId"],
                "messageId": record["messageId"],
                "attemptId": event.get("attemptId"),
                "sequence": event["sequence"],
                "occurredAt": event["occurredAt"],
                "type": "delivery.requeued",
                "payload": dict(payload),
            }
        return super()._assistant_event_payload(event, record)

    def do_POST(self) -> None:  # noqa: N802
        # Per-work cancellation is deliberately bound to the final SSE
        # disconnect. Do not expose a second public mutation surface merely to
        # duplicate that authority; all ordinary POST routes delegate to the
        # established AppServer handler.
        AssistantHandler.do_POST(self)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--owned-service-marker", default=None)
    known, remaining = parser.parse_known_args(argv)
    if known.owned_service_marker not in {
        None,
        "stateport_persistent_app.service_process",
    }:
        raise SystemExit("invalid StatePort service ownership marker")
    service_process.Handler = ResilientAssistantHandler
    return service_process.main(remaining)


if __name__ == "__main__":
    sys.exit(main())
