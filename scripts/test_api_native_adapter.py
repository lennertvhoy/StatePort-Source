"""Focused deterministic tests for the API-native adapter foundation."""

from __future__ import annotations

import copy
from pathlib import Path
import sys
import threading

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "execution-host" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "api-native-adapter" / "src"))

from execution_host.contracts import AgentRunSpec, CapabilityRequest  # noqa: E402
from api_native_adapter import (  # noqa: E402
    AdapterResult,
    ApiNativeAdapter,
    ApprovalBoundary,
    ConfigurationIdentity,
    InboundEvent,
    LocalDeterministicTransport,
    Message,
    ModelIdentity,
    NetworkPolicy,
    RetryClassification,
    Telemetry,
    TelemetryMetric,
    TelemetryQuality,
    ToolCall,
    ToolDefinition,
    TransportError,
    TransportRequest,
    classify_retry,
    redact,
)
from api_native_adapter.errors import (  # noqa: E402
    ApprovalRequiredError,
    IdempotencyConflictError,
    NetworkPolicyError,
    RunSpecBindingError,
    ToolCallValidationError,
    TimeoutError,
)
from api_native_adapter.models import EVENT_FORMAT, RunSpecBinding  # noqa: E402


def make_spec(**changes: object) -> AgentRunSpec:
    value = AgentRunSpec(
        "run:api-native",
        "instance:api-native",
        "revision:test",
        "deterministic adapter test",
        "statepack:test",
        "sha256:" + "a" * 64,
        (CapabilityRequest("nonInteractiveExecution"),),
        (),
        "test",
        "api-native-test",
        "1.0.0",
        "test-model",
        "external_manual",
        ("tool:read",),
        "offline",
        {"token": 100, "costMinor": 10, "timeSeconds": 10, "steps": 3},
        ("python3 scripts/validate_repo.py",),
        ("evidence/result.json",),
        {"host": "local", "model": "test-model"},
        approval_required_level="external_manual",
        repository_instructions=("Read AGENTS.md.",),
    )
    return value if not changes else AgentRunSpec(**{**value.__dict__, **changes})


def make_request(*, policy: NetworkPolicy | None = None, max_attempts: int = 1, timeout_seconds: float = 1.0, key: str = "idem:one") -> tuple[TransportRequest, RunSpecBinding]:
    spec = make_spec()
    binding = RunSpecBinding.from_run_spec(
        spec,
        provider="fixture",
        model_revision="fixture-rev-1",
        configuration=ConfigurationIdentity.from_config("local-default", {"temperature": 0}),
        network_policy=policy or NetworkPolicy.disabled(),
    )
    return TransportRequest(binding, (Message("user", "hello"),), idempotency_key=key, max_attempts=max_attempts, timeout_seconds=timeout_seconds), binding


def event(binding: RunSpecBinding, key: str, sequence: int, event_type: str, payload: dict[str, object]) -> dict[str, object]:
    return InboundEvent(
        f"event:{sequence}", sequence, binding.run_id, binding.run_spec_digest, key,
        binding.model, binding.configuration, event_type, payload,
    ).to_dict()


def response_events(binding: RunSpecBinding, key: str) -> tuple[dict[str, object], ...]:
    telemetry = Telemetry(
        TelemetryMetric(TelemetryQuality.EXACT, 12),
        TelemetryMetric(TelemetryQuality.APPROXIMATE, 0.25),
        TelemetryMetric(TelemetryQuality.EXACT, 3),
    )
    return (
        event(binding, key, 0, "response.started", {"providerRequestId": "fixture-request"}),
        event(binding, key, 1, "text.delta", {"text": "hello"}),
        event(binding, key, 2, "usage", telemetry.to_dict()),
        event(binding, key, 3, "response.completed", {"finishReason": "stop"}),
    )


def test_strict_events_normalize_and_preserve_model_config_identity() -> None:
    request, binding = make_request()
    transport = LocalDeterministicTransport(response_events(binding, request.identity_key))
    adapter = ApiNativeAdapter(transport)

    result = adapter.execute(request)

    assert isinstance(result, AdapterResult)
    assert result.status == "completed"
    assert [item.event_type for item in result.events] == ["response.started", "text.delta", "usage", "response.completed"]
    assert result.events[1].payload == {"text": "hello"}
    assert result.telemetry.tokens.to_dict() == {"quality": "exact", "value": 12}
    assert result.telemetry.cost.to_dict() == {"quality": "approximate", "value": 0.25}
    assert adapter.outbound_event(request).to_dict()["formatVersion"] == EVENT_FORMAT

    malformed = copy.deepcopy(response_events(binding, request.identity_key)[0])
    malformed["unexpected"] = True
    with pytest.raises(TransportError, match="invalid inbound event"):
        list(ApiNativeAdapter(LocalDeterministicTransport((malformed,))).stream(request))


def test_runspec_binding_rejects_wrong_event_and_wrong_model_identity() -> None:
    request, binding = make_request()
    wrong = event(binding, request.identity_key, 0, "response.started", {"providerRequestId": "fixture-request"})
    wrong["runSpecDigest"] = "sha256:" + "b" * 64
    transport = LocalDeterministicTransport((wrong,))
    with pytest.raises(RunSpecBindingError):
        list(ApiNativeAdapter(transport).stream(request))

    other_binding = RunSpecBinding(
        binding.run_id, binding.run_spec_digest,
        ModelIdentity("fixture", "other-model", binding.model.revision),
        binding.configuration, binding.network_policy, binding.permitted_capabilities,
        binding.backend_id, binding.adapter_id, binding.adapter_version,
        binding.statepack_reference, binding.statepack_digest,
    )
    mismatch = event(other_binding, request.identity_key, 0, "response.started", {"providerRequestId": "fixture-request"})
    with pytest.raises(RunSpecBindingError):
        list(ApiNativeAdapter(LocalDeterministicTransport((mismatch,))).stream(request))


def test_retry_classification_and_idempotency_are_deterministic() -> None:
    request, binding = make_request(max_attempts=2)
    transport = LocalDeterministicTransport(response_events(binding, request.identity_key), failures=(ConnectionError("temporary"),))
    adapter = ApiNativeAdapter(transport)

    first = adapter.execute(request)
    second = adapter.execute(request)

    assert first.status == "completed" and first.attempts == 2
    assert second.events == first.events and second.attempts == 2
    assert transport.calls == 2
    assert classify_retry(ConnectionError("temporary")) is RetryClassification.TRANSIENT
    assert classify_retry(ValueError("bad request")) is RetryClassification.UNKNOWN

    different = TransportRequest(binding, (Message("user", "different"),), idempotency_key=request.idempotency_key)
    with pytest.raises(IdempotencyConflictError):
        list(adapter.stream(different))


def test_timeout_and_cancellation_are_fail_closed() -> None:
    request, binding = make_request(timeout_seconds=0.001)
    timeout_result = ApiNativeAdapter(LocalDeterministicTransport(response_events(binding, request.identity_key), delay_seconds=0.01)).execute(request)
    assert timeout_result.status == "failed" and timeout_result.error["code"] == "timeout"

    cancelled_request, _ = make_request(key="idem:cancel")
    adapter = ApiNativeAdapter(LocalDeterministicTransport(response_events(binding, cancelled_request.identity_key)))
    adapter.cancel(cancelled_request.binding.run_id)
    cancelled = adapter.execute(cancelled_request)
    assert cancelled.status == "cancelled" and cancelled.error["code"] == "cancelled"

    event_cancel = threading.Event(); event_cancel.set()
    cancelled_again = adapter.execute(cancelled_request, cancel_event=event_cancel)
    assert cancelled_again.status == "cancelled"


def test_network_policy_and_tool_approval_boundary() -> None:
    request, binding = make_request(policy=NetworkPolicy("allowlist", ("example.test",)))
    with pytest.raises(NetworkPolicyError):
        list(ApiNativeAdapter(LocalDeterministicTransport(())).stream(request))

    safe_request, safe_binding = make_request()
    tool = ToolDefinition(
        "read_file", "tool:read",
        {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"], "additionalProperties": False},
        requires_approval=True,
    )
    safe_request = TransportRequest(safe_binding, safe_request.messages, (tool,), idempotency_key="idem:tool")
    call = ToolCall("call:1", "read_file", {"path": "README.md"}, "tool:read")
    tool_event = InboundEvent("event:0", 0, safe_binding.run_id, safe_binding.run_spec_digest, safe_request.identity_key, safe_binding.model, safe_binding.configuration, "tool.call", call.to_dict())
    adapter = ApiNativeAdapter(LocalDeterministicTransport(()))
    with pytest.raises(ApprovalRequiredError):
        adapter.validate_tool_call(safe_request, tool_event)
    adapter.validate_tool_call(safe_request, tool_event, ApprovalBoundary("approval:1", ("call:1",), ("tool:read",)))

    denied = ToolCall("call:2", "read_file", {"path": "README.md"}, "tool:write")
    denied_event = InboundEvent("event:1", 1, safe_binding.run_id, safe_binding.run_spec_digest, safe_request.identity_key, safe_binding.model, safe_binding.configuration, "tool.call", denied.to_dict())
    with pytest.raises(Exception, match="capability"):
        adapter.validate_tool_call(safe_request, denied_event)


def test_telemetry_unavailable_is_honest_and_redaction_is_recursive() -> None:
    request, _ = make_request(key="idem:no-usage")
    result = ApiNativeAdapter(LocalDeterministicTransport(())).execute(request)
    assert result.status == "failed"
    assert result.telemetry.tokens.quality is TelemetryQuality.UNAVAILABLE
    assert result.telemetry.tokens.value is None

    value = {"authorization": "Bearer abc.def.ghi", "nested": [{"apiKey": "not-persisted"}], "message": "Bearer xyz"}
    assert redact(value) == {"authorization": "[REDACTED]", "nested": [{"apiKey": "[REDACTED]"}], "message": "Bearer [REDACTED]"}
    with pytest.raises(ValueError, match="credential-like"):
        ConfigurationIdentity.from_config("bad", {"apiKey": "fixture-only"})


def test_strict_model_rejects_non_contiguous_stream_and_invalid_tool_arguments() -> None:
    request, binding = make_request(key="idem:sequence")
    malformed = response_events(binding, request.identity_key)
    malformed = (malformed[0], malformed[2])
    with pytest.raises(TransportError, match="sequence"):
        list(ApiNativeAdapter(LocalDeterministicTransport(malformed)).stream(request))

    tool = ToolDefinition("read_file", "tool:read", {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"], "additionalProperties": False})
    bad_call = ToolCall("call:bad", "read_file", {"path": 42}, "tool:read")
    bad_event = InboundEvent("event:0", 0, binding.run_id, binding.run_spec_digest, request.identity_key, binding.model, binding.configuration, "tool.call", bad_call.to_dict())
    adapter = ApiNativeAdapter(LocalDeterministicTransport(()))
    with pytest.raises(ToolCallValidationError, match="must be string"):
        adapter.validate_tool_call(TransportRequest(binding, request.messages, (tool,), idempotency_key=request.identity_key), bad_event, ApprovalBoundary("approval:1", ("call:bad",), ("tool:read",)))
