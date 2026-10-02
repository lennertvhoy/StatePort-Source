"""Injected transport and deterministic local execution for API-native runs."""

from __future__ import annotations

from dataclasses import dataclass
import threading
import time
from typing import Any, Callable, Iterable, Iterator, Mapping, Protocol

from .errors import (
    ApiNativeError,
    CancellationError,
    IdempotencyConflictError,
    NetworkPolicyError,
    RetryExhaustedError,
    RunSpecBindingError,
    TimeoutError,
    TransportError,
    classify_retry,
)
from .models import (
    EVENT_FORMAT,
    API_NATIVE_FORMAT,
    InboundEvent,
    OutboundEvent,
    RunSpecBinding,
    Telemetry,
    TelemetryMetric,
    TelemetryQuality,
    ToolCall,
    TransportRequest,
    canonical_json,
    validate_tool_call,
)


class InjectedTransport(Protocol):
    """Provider-neutral transport supplied by the caller."""

    def stream(self, request: TransportRequest, *, deadline: float, cancel_event: threading.Event) -> Iterable[InboundEvent | Mapping[str, Any]]:
        """Yield provider-neutral inbound events; never receive credentials."""


def _check_control(deadline: float, cancel_event: threading.Event) -> None:
    if cancel_event.is_set():
        raise CancellationError("run cancellation was requested")
    if time.monotonic() >= deadline:
        raise TimeoutError("run exceeded its timeout")


def normalize_inbound_event(value: InboundEvent | Mapping[str, Any], binding: RunSpecBinding, idempotency_key: str, expected_sequence: int) -> InboundEvent:
    """Parse one strict event and enforce its identity/ordering envelope."""

    try:
        event = value if isinstance(value, InboundEvent) else InboundEvent.from_dict(value)
    except (TypeError, ValueError) as exc:
        raise TransportError(f"invalid inbound event: {exc}", code="invalid_inbound_event") from exc
    if (event.run_id, event.run_spec_digest, event.idempotency_key) != (binding.run_id, binding.run_spec_digest, idempotency_key):
        raise RunSpecBindingError("inbound event is not bound to the active RunSpec")
    if event.model != binding.model or event.configuration != binding.configuration:
        raise RunSpecBindingError("inbound event model/configuration identity does not match the request")
    if event.sequence != expected_sequence:
        raise TransportError("inbound event sequence is not contiguous", code="event_sequence_error")
    return event


def _metric_add(values: list[TelemetryMetric]) -> TelemetryMetric:
    if not values or any(item.quality is TelemetryQuality.UNAVAILABLE for item in values):
        return TelemetryMetric.unavailable()
    quality = TelemetryQuality.APPROXIMATE if any(item.quality is TelemetryQuality.APPROXIMATE for item in values) else TelemetryQuality.EXACT
    return TelemetryMetric(quality, sum(item.value for item in values if item.value is not None))


@dataclass(frozen=True)
class AdapterResult:
    binding: RunSpecBinding
    request_digest: str
    idempotency_key: str
    events: tuple[InboundEvent, ...]
    status: str
    attempts: int
    telemetry: Telemetry
    error: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": API_NATIVE_FORMAT,
            "runId": self.binding.run_id,
            "runSpecDigest": self.binding.run_spec_digest,
            "requestDigest": self.request_digest,
            "idempotencyKey": self.idempotency_key,
            "model": self.binding.model.to_dict(),
            "configuration": self.binding.configuration.to_dict(),
            "network": self.binding.network_policy.to_dict(),
            "status": self.status,
            "attempts": self.attempts,
            "events": [event.to_dict() for event in self.events],
            "telemetry": self.telemetry.to_dict(),
            "error": self.error,
        }


class ApiNativeAdapter:
    """Run an API-native request through an injected, provider-neutral transport."""

    def __init__(self, transport: InjectedTransport, *, clock: Callable[[], float] = time.monotonic) -> None:
        if not hasattr(transport, "stream") or not callable(transport.stream):
            raise TypeError("transport must provide stream(request, deadline, cancel_event)")
        self.transport = transport
        self._clock = clock
        self._idempotent: dict[str, tuple[str, tuple[InboundEvent, ...]]] = {}
        self._attempt_counts: dict[str, int] = {}
        self._lock = threading.Lock()
        self._cancelled: set[str] = set()
        self._cancel_events: dict[str, threading.Event] = {}

    def describe(self) -> dict[str, Any]:
        return {
            "formatVersion": API_NATIVE_FORMAT,
            "kind": "api_native",
            "providerNeutral": True,
            "credentials": "not accepted or stored",
            "network": "declared by RunSpec binding and enforced by injected transport",
            "eventFormat": EVENT_FORMAT,
        }

    def cancel(self, run_id: str) -> None:
        if not run_id:
            raise ValueError("run_id is required")
        self._cancelled.add(run_id)
        with self._lock:
            event = self._cancel_events.get(run_id)
            if event is not None:
                event.set()

    def outbound_event(self, request: TransportRequest) -> OutboundEvent:
        return OutboundEvent(
            event_id=f"request:{request.identity_key}", sequence=0, run_id=request.binding.run_id,
            run_spec_digest=request.binding.run_spec_digest, idempotency_key=request.identity_key,
            model=request.binding.model, configuration=request.binding.configuration,
            event_type="request",
            payload={
                "messages": [message.to_dict() for message in request.messages],
                "tools": [tool.to_dict() for tool in request.tools],
                "timeoutSeconds": request.timeout_seconds,
            },
        )

    def stream(self, request: TransportRequest, *, cancel_event: threading.Event | None = None) -> Iterator[InboundEvent]:
        """Yield normalized events, retrying only classified transient failures."""

        self._validate_request(request)
        cancel_event = cancel_event or threading.Event()
        key = request.identity_key
        with self._lock:
            self._cancel_events[request.binding.run_id] = cancel_event
            if request.binding.run_id in self._cancelled:
                cancel_event.set()
        with self._lock:
            previous = self._idempotent.get(key)
            if previous is not None:
                if previous[0] != request.request_digest:
                    raise IdempotencyConflictError("idempotency key was reused for a different request")
                yield from previous[1]
                return

        last_error: ApiNativeError | None = None
        try:
            for attempt in range(1, request.max_attempts + 1):
                self._attempt_counts[key] = attempt
                if request.binding.run_id in self._cancelled:
                    raise CancellationError("run cancellation was requested")
                deadline = self._clock() + float(request.timeout_seconds)
                events: list[InboundEvent] = []
                try:
                    source = self.transport.stream(request, deadline=deadline, cancel_event=cancel_event)
                    for raw in source:
                        _check_control(deadline, cancel_event)
                        event = normalize_inbound_event(raw, request.binding, key, len(events))
                        events.append(event)
                        yield event
                        if event.event_type == "response.failed":
                            raise TransportError(event.payload["message"], code=event.payload["code"], retry_classification=event.payload["retryClass"])
                        if event.event_type == "response.completed":
                            with self._lock:
                                self._idempotent[key] = (request.request_digest, tuple(events))
                            return
                    raise TransportError("transport ended without response.completed", code="incomplete_stream")
                except ApiNativeError as exc:
                    last_error = exc
                    if exc.retry_classification.retryable and attempt < request.max_attempts and not events:
                        continue
                    if exc.retry_classification.retryable and attempt >= request.max_attempts:
                        if request.max_attempts == 1:
                            raise
                        raise RetryExhaustedError("transient transport failure exhausted retry budget", details={"attempts": attempt, "lastError": exc.to_dict()}) from exc
                    raise
                except BaseException as exc:
                    classification = classify_retry(exc)
                    wrapped = TransportError(str(exc), retry_classification=classification)
                    last_error = wrapped
                    if classification.retryable and attempt < request.max_attempts and not events:
                        continue
                    if classification.retryable:
                        if request.max_attempts == 1:
                            raise wrapped from exc
                        raise RetryExhaustedError("transport failure exhausted retry budget", details={"attempts": attempt, "lastError": wrapped.to_dict()}) from exc
                    raise wrapped from exc
            raise RetryExhaustedError("transport retry loop exhausted", details={"lastError": last_error.to_dict() if last_error else None})
        finally:
            with self._lock:
                if self._cancel_events.get(request.binding.run_id) is cancel_event:
                    del self._cancel_events[request.binding.run_id]

    def execute(self, request: TransportRequest, *, cancel_event: threading.Event | None = None) -> AdapterResult:
        events: list[InboundEvent] = []
        try:
            for event in self.stream(request, cancel_event=cancel_event):
                events.append(event)
        except ApiNativeError as exc:
            status = "cancelled" if exc.code == "cancelled" else "failed"
            return AdapterResult(request.binding, request.request_digest, request.identity_key, tuple(events), status, self._attempt_counts.get(request.identity_key, 1), _telemetry(events), exc.to_dict())
        return AdapterResult(request.binding, request.request_digest, request.identity_key, tuple(events), "completed", self._attempt_counts.get(request.identity_key, 1), _telemetry(events))

    def validate_tool_call(self, request: TransportRequest, event: InboundEvent, approval: Any = None) -> None:
        if event.event_type != "tool.call":
            raise ValueError("event is not a tool call")
        validate_tool_call(ToolCall.from_dict(event.payload), request.tools, request.binding, approval)

    def _validate_request(self, request: TransportRequest) -> None:
        if not isinstance(request, TransportRequest):
            raise TypeError("request must be a TransportRequest")
        if request.binding.network_policy.mode != "disabled":
            raise NetworkPolicyError("the local API-native foundation accepts only disabled network policy")


def _telemetry(events: list[InboundEvent] | tuple[InboundEvent, ...]) -> Telemetry:
    metrics: list[Telemetry] = []
    for event in events:
        if event.event_type == "usage":
            metrics.append(Telemetry.from_dict(event.payload))
    if not metrics:
        return Telemetry(TelemetryMetric.unavailable(), TelemetryMetric.unavailable())
    return Telemetry(_metric_add([item.tokens for item in metrics]), _metric_add([item.cost for item in metrics]), _metric_add([item.latency_ms for item in metrics]))


@dataclass
class LocalDeterministicTransport:
    """Deterministic fixture transport; no endpoint or credential support."""

    events: tuple[InboundEvent | Mapping[str, Any], ...]
    failures: tuple[BaseException, ...] = ()
    delay_seconds: float = 0.0

    def __post_init__(self) -> None:
        self.calls = 0
        self.requests: list[OutboundEvent] = []

    def stream(self, request: TransportRequest, *, deadline: float, cancel_event: threading.Event) -> Iterable[InboundEvent | Mapping[str, Any]]:
        self.calls += 1
        self.requests.append(OutboundEvent(
            event_id=f"request:{request.identity_key}", sequence=0, run_id=request.binding.run_id,
            run_spec_digest=request.binding.run_spec_digest, idempotency_key=request.identity_key,
            model=request.binding.model, configuration=request.binding.configuration, event_type="request",
            payload={"messages": [item.to_dict() for item in request.messages], "tools": [item.to_dict() for item in request.tools], "timeoutSeconds": request.timeout_seconds},
        ))
        if request.binding.network_policy.mode != "disabled":
            raise NetworkPolicyError("deterministic transport cannot use network-enabled policy")
        if cancel_event.is_set():
            raise CancellationError("run cancellation was requested")
        if self.delay_seconds:
            if time.monotonic() + self.delay_seconds >= deadline:
                raise TimeoutError("deterministic transport delay exceeded the deadline")
            end = time.monotonic() + self.delay_seconds
            while time.monotonic() < end:
                if cancel_event.is_set():
                    raise CancellationError("run cancellation was requested")
                time.sleep(min(0.005, max(0.0, end - time.monotonic())))
        if self.failures and self.calls <= len(self.failures):
            failure = self.failures[self.calls - 1]
            if isinstance(failure, BaseException):
                raise failure
        yield from self.events
