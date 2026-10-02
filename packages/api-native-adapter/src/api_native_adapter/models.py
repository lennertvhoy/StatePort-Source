"""Strict provider-neutral models for API-native execution.

The models in this module are deliberately independent from any provider SDK.
They describe the boundary between StatePort and an injected transport.  A
transport may be backed by a provider in a future slice, but this package does
not own credentials, endpoints, or provider-specific request loops.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import re
from typing import Any, Mapping, Sequence


API_NATIVE_FORMAT = "stateport.api-native-adapter/v1"
EVENT_FORMAT = "stateport.api-native-event/v1"
TELEMETRY_QUALITIES = frozenset({"exact", "approximate", "unavailable"})
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SECRET_KEY = re.compile(
    r"(?:api[_-]?key|authorization|cookie|credential|password|secret|access[_-]?token|refresh[_-]?token)",
    re.I,
)


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest_for(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _identifier(value: Any, name: str) -> str:
    value = _string(value, name)
    if not _ID.fullmatch(value):
        raise ValueError(f"{name} has invalid characters")
    return value


def _digest(value: Any, name: str) -> str:
    value = _string(value, name)
    if not _DIGEST.fullmatch(value):
        raise ValueError(f"{name} must be a sha256 digest")
    return value


def _exact_mapping(value: Any, name: str, keys: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ValueError(f"{name} has an invalid shape")
    if any(not isinstance(key, str) for key in value):
        raise ValueError(f"{name} keys must be strings")
    return value


def _string_tuple(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or any(not isinstance(item, str) or not item.strip() for item in value):
        raise ValueError(f"{name} must be a list of non-empty strings")
    result = tuple(value)
    if len(set(result)) != len(result):
        raise ValueError(f"{name} must not contain duplicates")
    return result


def _json_value(value: Any, name: str = "value") -> None:
    if value is None or isinstance(value, (str, int, float, bool)):
        if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
            raise ValueError(f"{name} contains a non-finite number")
        return
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ValueError(f"{name} object keys must be strings")
        for key, item in value.items():
            _json_value(item, f"{name}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _json_value(item, f"{name}[{index}]")
        return
    raise ValueError(f"{name} is not JSON-compatible")


def reject_secrets(value: Any, path: str = "$") -> None:
    """Reject credential-shaped fields before they reach a transport."""

    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{path} keys must be strings")
            if _SECRET_KEY.search(key):
                raise ValueError(f"credential-like field is forbidden at {path}.{key}")
            reject_secrets(item, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            reject_secrets(item, f"{path}[{index}]")


_REDACT_KEY = re.compile(
    r"(?:api[_-]?key|authorization|cookie|credential|password|secret|access[_-]?token|refresh[_-]?token|private[_-]?key)",
    re.I,
)
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")


def redact(value: Any) -> Any:
    """Return a recursively redacted copy suitable for diagnostics/audit."""

    if isinstance(value, Mapping):
        return {
            key: "[REDACTED]" if _REDACT_KEY.search(key) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return _BEARER.sub("Bearer [REDACTED]", value)
    return value


class TelemetryQuality(str, Enum):
    EXACT = "exact"
    APPROXIMATE = "approximate"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class TelemetryMetric:
    quality: TelemetryQuality
    value: float | int | None

    def __post_init__(self) -> None:
        if self.quality.value not in TELEMETRY_QUALITIES:
            raise ValueError("invalid telemetry quality")
        if self.quality is TelemetryQuality.UNAVAILABLE and self.value is not None:
            raise ValueError("unavailable telemetry must have a null value")
        if self.value is not None and (isinstance(self.value, bool) or not isinstance(self.value, (int, float))):
            raise ValueError("telemetry value must be numeric or null")
        if isinstance(self.value, float) and (self.value != self.value or self.value in (float("inf"), float("-inf"))):
            raise ValueError("telemetry value must be finite")

    @classmethod
    def unavailable(cls) -> "TelemetryMetric":
        return cls(TelemetryQuality.UNAVAILABLE, None)

    def to_dict(self) -> dict[str, Any]:
        return {"quality": self.quality.value, "value": self.value}

    @classmethod
    def from_dict(cls, value: Any, name: str = "telemetry") -> "TelemetryMetric":
        data = _exact_mapping(value, name, {"quality", "value"})
        try:
            quality = TelemetryQuality(data["quality"])
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{name}.quality is invalid") from exc
        return cls(quality, data["value"])


@dataclass(frozen=True)
class Telemetry:
    tokens: TelemetryMetric
    cost: TelemetryMetric
    latency_ms: TelemetryMetric = TelemetryMetric(TelemetryQuality.UNAVAILABLE, None)

    def to_dict(self) -> dict[str, Any]:
        return {"tokens": self.tokens.to_dict(), "cost": self.cost.to_dict(), "latencyMs": self.latency_ms.to_dict()}

    @classmethod
    def from_dict(cls, value: Any) -> "Telemetry":
        data = _exact_mapping(value, "telemetry", {"tokens", "cost", "latencyMs"})
        return cls(
            TelemetryMetric.from_dict(data["tokens"], "telemetry.tokens"),
            TelemetryMetric.from_dict(data["cost"], "telemetry.cost"),
            TelemetryMetric.from_dict(data["latencyMs"], "telemetry.latencyMs"),
        )


@dataclass(frozen=True)
class ModelIdentity:
    provider: str
    model: str
    revision: str

    def __post_init__(self) -> None:
        _identifier(self.provider, "model.provider")
        _string(self.model, "model.model")
        _string(self.revision, "model.revision")

    def to_dict(self) -> dict[str, str]:
        return {"provider": self.provider, "model": self.model, "revision": self.revision}

    @classmethod
    def from_dict(cls, value: Any) -> "ModelIdentity":
        data = _exact_mapping(value, "model identity", {"provider", "model", "revision"})
        return cls(data["provider"], data["model"], data["revision"])


@dataclass(frozen=True)
class ConfigurationIdentity:
    name: str
    digest: str

    def __post_init__(self) -> None:
        _identifier(self.name, "configuration.name")
        _digest(self.digest, "configuration.digest")

    @classmethod
    def from_config(cls, name: str, configuration: Mapping[str, Any]) -> "ConfigurationIdentity":
        if not isinstance(configuration, Mapping):
            raise ValueError("configuration must be a mapping")
        _json_value(configuration, "configuration")
        reject_secrets(configuration)
        return cls(name, digest_for(configuration))

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "digest": self.digest}

    @classmethod
    def from_dict(cls, value: Any) -> "ConfigurationIdentity":
        data = _exact_mapping(value, "configuration identity", {"name", "digest"})
        return cls(data["name"], data["digest"])


@dataclass(frozen=True)
class NetworkPolicy:
    """An explicit network declaration; it is not an authorization grant."""

    mode: str
    allowed_hosts: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.mode not in {"disabled", "allowlist", "unrestricted"}:
            raise ValueError("network policy mode is invalid")
        hosts = _string_tuple(self.allowed_hosts, "network.allowedHosts")
        if self.mode == "disabled" and hosts:
            raise ValueError("disabled network policy cannot list allowed hosts")
        if self.mode == "allowlist" and not hosts:
            raise ValueError("allowlist network policy requires allowed hosts")
        if self.mode == "unrestricted" and hosts:
            raise ValueError("unrestricted network policy cannot list allowed hosts")
        object.__setattr__(self, "allowed_hosts", hosts)

    @classmethod
    def disabled(cls) -> "NetworkPolicy":
        return cls("disabled")

    def to_dict(self) -> dict[str, Any]:
        return {"mode": self.mode, "allowedHosts": list(self.allowed_hosts)}

    @classmethod
    def from_dict(cls, value: Any) -> "NetworkPolicy":
        data = _exact_mapping(value, "network policy", {"mode", "allowedHosts"})
        return cls(data["mode"], _string_tuple(data["allowedHosts"], "network.allowedHosts"))


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    capability: str
    parameters: Mapping[str, Any]
    requires_approval: bool = True

    def __post_init__(self) -> None:
        _identifier(self.name, "tool.name")
        _identifier(self.capability, "tool.capability")
        if not isinstance(self.parameters, Mapping):
            raise ValueError("tool.parameters must be a JSON schema mapping")
        _json_value(self.parameters, "tool.parameters")
        if self.parameters.get("type") != "object":
            raise ValueError("tool.parameters.type must be object")
        if not isinstance(self.requires_approval, bool):
            raise ValueError("tool.requiresApproval must be boolean")
        reject_secrets(self.parameters)

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "capability": self.capability, "parameters": dict(self.parameters), "requiresApproval": self.requires_approval}

    @classmethod
    def from_dict(cls, value: Any) -> "ToolDefinition":
        data = _exact_mapping(value, "tool definition", {"name", "capability", "parameters", "requiresApproval"})
        return cls(data["name"], data["capability"], data["parameters"], data["requiresApproval"])


@dataclass(frozen=True)
class ToolCall:
    call_id: str
    name: str
    arguments: Mapping[str, Any]
    capability: str

    def __post_init__(self) -> None:
        _identifier(self.call_id, "tool call id")
        _identifier(self.name, "tool call name")
        _identifier(self.capability, "tool call capability")
        if not isinstance(self.arguments, Mapping):
            raise ValueError("tool call arguments must be an object")
        _json_value(self.arguments, "tool call arguments")
        reject_secrets(self.arguments)

    def to_dict(self) -> dict[str, Any]:
        return {"callId": self.call_id, "name": self.name, "arguments": dict(self.arguments), "capability": self.capability}

    @classmethod
    def from_dict(cls, value: Any) -> "ToolCall":
        data = _exact_mapping(value, "tool call", {"callId", "name", "arguments", "capability"})
        return cls(data["callId"], data["name"], data["arguments"], data["capability"])


@dataclass(frozen=True)
class ApprovalBoundary:
    approval_reference: str | None
    approved_call_ids: tuple[str, ...] = ()
    approved_capabilities: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.approval_reference is not None:
            _identifier(self.approval_reference, "approval reference")
        object.__setattr__(self, "approved_call_ids", _string_tuple(self.approved_call_ids, "approved call ids"))
        object.__setattr__(self, "approved_capabilities", _string_tuple(self.approved_capabilities, "approved capabilities"))


@dataclass(frozen=True)
class RunSpecBinding:
    run_id: str
    run_spec_digest: str
    model: ModelIdentity
    configuration: ConfigurationIdentity
    network_policy: NetworkPolicy
    permitted_capabilities: tuple[str, ...]
    backend_id: str
    adapter_id: str
    adapter_version: str
    statepack_reference: str
    statepack_digest: str

    def __post_init__(self) -> None:
        _identifier(self.run_id, "run_id")
        _digest(self.run_spec_digest, "run_spec_digest")
        _string_tuple(self.permitted_capabilities, "permitted_capabilities")
        _identifier(self.backend_id, "backend_id")
        _identifier(self.adapter_id, "adapter_id")
        _string(self.adapter_version, "adapter_version")
        _string(self.statepack_reference, "statepack_reference")
        _digest(self.statepack_digest, "statepack_digest")
        object.__setattr__(self, "permitted_capabilities", tuple(self.permitted_capabilities))

    @classmethod
    def from_run_spec(
        cls,
        run_spec: Any,
        *,
        provider: str,
        model_revision: str,
        configuration: ConfigurationIdentity,
        network_policy: NetworkPolicy,
    ) -> "RunSpecBinding":
        required = ("run_id", "digest", "model_identifier", "backend_id", "adapter_id", "adapter_version", "statepack_reference", "statepack_digest", "permitted_capabilities")
        missing = [name for name in required if not hasattr(run_spec, name)]
        if missing:
            raise ValueError(f"RunSpec is missing binding fields: {', '.join(missing)}")
        return cls(
            run_spec.run_id,
            run_spec.digest,
            ModelIdentity(provider, run_spec.model_identifier, model_revision),
            configuration,
            network_policy,
            tuple(run_spec.permitted_capabilities),
            run_spec.backend_id,
            run_spec.adapter_id,
            run_spec.adapter_version,
            run_spec.statepack_reference,
            run_spec.statepack_digest,
        )

    def assert_run_spec(self, run_spec: Any) -> None:
        if not hasattr(run_spec, "digest") or run_spec.digest != self.run_spec_digest or run_spec.run_id != self.run_id:
            raise ValueError("transport request is not bound to the exact RunSpec")
        if run_spec.model_identifier != self.model.model:
            raise ValueError("model identity does not match the RunSpec")
        if (run_spec.backend_id, run_spec.adapter_id, run_spec.adapter_version) != (self.backend_id, self.adapter_id, self.adapter_version):
            raise ValueError("adapter identity does not match the RunSpec")

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": API_NATIVE_FORMAT,
            "runId": self.run_id,
            "runSpecDigest": self.run_spec_digest,
            "model": self.model.to_dict(),
            "configuration": self.configuration.to_dict(),
            "network": self.network_policy.to_dict(),
            "permittedCapabilities": list(self.permitted_capabilities),
            "backend": {"id": self.backend_id, "adapter": {"id": self.adapter_id, "version": self.adapter_version}},
            "statePack": {"reference": self.statepack_reference, "digest": self.statepack_digest},
        }


@dataclass(frozen=True)
class Message:
    role: str
    content: str

    def __post_init__(self) -> None:
        if self.role not in {"system", "user", "assistant", "tool"}:
            raise ValueError("message.role is invalid")
        _string(self.content, "message.content")

    def to_dict(self) -> dict[str, str]:
        return {"role": self.role, "content": self.content}

    @classmethod
    def from_dict(cls, value: Any) -> "Message":
        data = _exact_mapping(value, "message", {"role", "content"})
        return cls(data["role"], data["content"])


@dataclass(frozen=True)
class TransportRequest:
    binding: RunSpecBinding
    messages: tuple[Message, ...]
    tools: tuple[ToolDefinition, ...] = ()
    idempotency_key: str = ""
    timeout_seconds: float = 30.0
    max_attempts: int = 1

    def __post_init__(self) -> None:
        if not self.messages:
            raise ValueError("at least one message is required")
        if any(not isinstance(item, Message) for item in self.messages):
            raise ValueError("messages must contain Message objects")
        if any(not isinstance(item, ToolDefinition) for item in self.tools):
            raise ValueError("tools must contain ToolDefinition objects")
        if self.idempotency_key:
            _identifier(self.idempotency_key, "idempotency_key")
        if isinstance(self.timeout_seconds, bool) or not isinstance(self.timeout_seconds, (int, float)) or self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if isinstance(self.max_attempts, bool) or not isinstance(self.max_attempts, int) or not 1 <= self.max_attempts <= 10:
            raise ValueError("max_attempts must be between 1 and 10")
        if len({tool.name for tool in self.tools}) != len(self.tools):
            raise ValueError("tool names must be unique")
        reject_secrets(self.to_dict())

    @property
    def request_digest(self) -> str:
        return digest_for(self.to_dict())

    @property
    def identity_key(self) -> str:
        return self.idempotency_key or f"{self.binding.run_id}:{self.request_digest}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": API_NATIVE_FORMAT,
            "binding": self.binding.to_dict(),
            "messages": [item.to_dict() for item in self.messages],
            "tools": [item.to_dict() for item in self.tools],
            "idempotencyKey": self.idempotency_key or None,
            "timeoutSeconds": self.timeout_seconds,
            "maxAttempts": self.max_attempts,
        }


_OUTBOUND_TYPES = {"request", "tool.result", "cancel"}
_INBOUND_TYPES = {"response.started", "text.delta", "tool.call", "usage", "response.completed", "response.failed", "heartbeat"}


@dataclass(frozen=True)
class OutboundEvent:
    event_id: str
    sequence: int
    run_id: str
    run_spec_digest: str
    idempotency_key: str
    model: ModelIdentity
    configuration: ConfigurationIdentity
    event_type: str
    payload: Mapping[str, Any]

    def __post_init__(self) -> None:
        _identifier(self.event_id, "event_id")
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int) or self.sequence < 0:
            raise ValueError("event sequence must be a non-negative integer")
        _identifier(self.run_id, "run_id"); _digest(self.run_spec_digest, "run_spec_digest"); _identifier(self.idempotency_key, "idempotency_key")
        if self.event_type not in _OUTBOUND_TYPES:
            raise ValueError("outbound event type is invalid")
        _json_value(self.payload, "outbound payload")
        reject_secrets(self.to_dict())
        if self.event_type == "cancel":
            _exact_mapping(self.payload, "cancel payload", {"reason"})
            _string(self.payload["reason"], "cancel reason")
        elif self.event_type == "request":
            _exact_mapping(self.payload, "request payload", {"messages", "tools", "timeoutSeconds"})
            if not isinstance(self.payload["messages"], list) or not self.payload["messages"]:
                raise ValueError("request messages must be a non-empty list")
            for item in self.payload["messages"]: Message.from_dict(item)
            if not isinstance(self.payload["tools"], list):
                raise ValueError("request tools must be a list")
            for item in self.payload["tools"]: ToolDefinition.from_dict(item)
            if isinstance(self.payload["timeoutSeconds"], bool) or not isinstance(self.payload["timeoutSeconds"], (int, float)) or self.payload["timeoutSeconds"] <= 0:
                raise ValueError("request timeoutSeconds must be positive")
        elif self.event_type == "tool.result":
            _exact_mapping(self.payload, "tool result payload", {"callId", "content", "isError"})
            _identifier(self.payload["callId"], "tool result callId")
            _string(self.payload["content"], "tool result content")
            if not isinstance(self.payload["isError"], bool):
                raise ValueError("tool result isError must be boolean")

    def to_dict(self) -> dict[str, Any]:
        return {"formatVersion": EVENT_FORMAT, "direction": "outbound", "eventId": self.event_id, "sequence": self.sequence, "runId": self.run_id, "runSpecDigest": self.run_spec_digest, "idempotencyKey": self.idempotency_key, "model": self.model.to_dict(), "configuration": self.configuration.to_dict(), "eventType": self.event_type, "payload": dict(self.payload)}

    @classmethod
    def from_dict(cls, value: Any) -> "OutboundEvent":
        data = _exact_mapping(value, "outbound event", {"formatVersion", "direction", "eventId", "sequence", "runId", "runSpecDigest", "idempotencyKey", "model", "configuration", "eventType", "payload"})
        if data["formatVersion"] != EVENT_FORMAT or data["direction"] != "outbound":
            raise ValueError("outbound event format or direction is invalid")
        return cls(data["eventId"], data["sequence"], data["runId"], data["runSpecDigest"], data["idempotencyKey"], ModelIdentity.from_dict(data["model"]), ConfigurationIdentity.from_dict(data["configuration"]), data["eventType"], data["payload"])


@dataclass(frozen=True)
class InboundEvent:
    event_id: str
    sequence: int
    run_id: str
    run_spec_digest: str
    idempotency_key: str
    model: ModelIdentity
    configuration: ConfigurationIdentity
    event_type: str
    payload: Mapping[str, Any]

    def __post_init__(self) -> None:
        _identifier(self.event_id, "event_id")
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int) or self.sequence < 0:
            raise ValueError("event sequence must be a non-negative integer")
        _identifier(self.run_id, "run_id"); _digest(self.run_spec_digest, "run_spec_digest"); _identifier(self.idempotency_key, "idempotency_key")
        if self.event_type not in _INBOUND_TYPES:
            raise ValueError("inbound event type is invalid")
        _json_value(self.payload, "inbound payload")
        reject_secrets(self.to_dict())
        expected = {
            "response.started": {"providerRequestId"}, "text.delta": {"text"},
            "tool.call": {"callId", "name", "arguments", "capability"},
            "usage": {"tokens", "cost", "latencyMs"}, "response.completed": {"finishReason"},
            "response.failed": {"code", "message", "retryClass"}, "heartbeat": set(),
        }[self.event_type]
        _exact_mapping(self.payload, f"{self.event_type} payload", expected)
        if self.event_type == "text.delta": _string(self.payload["text"], "text delta")
        if self.event_type == "response.started": _identifier(self.payload["providerRequestId"], "providerRequestId")
        if self.event_type == "tool.call": ToolCall.from_dict(self.payload)
        if self.event_type == "usage":
            Telemetry.from_dict(self.payload)
        if self.event_type == "response.failed":
            _identifier(self.payload["code"], "error code"); _string(self.payload["message"], "error message")
            _string(self.payload["retryClass"], "retry class")

    def to_dict(self) -> dict[str, Any]:
        return {"formatVersion": EVENT_FORMAT, "direction": "inbound", "eventId": self.event_id, "sequence": self.sequence, "runId": self.run_id, "runSpecDigest": self.run_spec_digest, "idempotencyKey": self.idempotency_key, "model": self.model.to_dict(), "configuration": self.configuration.to_dict(), "eventType": self.event_type, "payload": dict(self.payload)}

    @classmethod
    def from_dict(cls, value: Any) -> "InboundEvent":
        data = _exact_mapping(value, "inbound event", {"formatVersion", "direction", "eventId", "sequence", "runId", "runSpecDigest", "idempotencyKey", "model", "configuration", "eventType", "payload"})
        if data["formatVersion"] != EVENT_FORMAT or data["direction"] != "inbound":
            raise ValueError("inbound event format or direction is invalid")
        return cls(data["eventId"], data["sequence"], data["runId"], data["runSpecDigest"], data["idempotencyKey"], ModelIdentity.from_dict(data["model"]), ConfigurationIdentity.from_dict(data["configuration"]), data["eventType"], data["payload"])


def validate_tool_call(call: ToolCall, tools: Sequence[ToolDefinition], binding: RunSpecBinding, approval: ApprovalBoundary | None = None) -> None:
    """Validate a model tool call without executing it.

    Approval is an explicit second boundary.  A valid tool call that needs
    approval raises ``ApprovalRequiredError`` until an exact call id and
    approval reference are supplied.
    """

    from .errors import ApprovalRequiredError, ToolCallValidationError

    definitions = {tool.name: tool for tool in tools}
    definition = definitions.get(call.name)
    if definition is None:
        raise ToolCallValidationError("unknown_tool", f"tool {call.name!r} is not declared")
    if definition.capability != call.capability:
        raise ToolCallValidationError("capability_mismatch", "tool call capability does not match its declaration")
    if call.capability not in binding.permitted_capabilities:
        raise ToolCallValidationError("capability_denied", "tool capability is not permitted by the RunSpec")
    try:
        _validate_json_schema(call.arguments, definition.parameters)
    except ValueError as exc:
        raise ToolCallValidationError("invalid_arguments", str(exc)) from exc
    if definition.requires_approval:
        if approval is None or approval.approval_reference is None or call.call_id not in approval.approved_call_ids or call.capability not in approval.approved_capabilities:
            raise ApprovalRequiredError(call.call_id, call.capability)


def _validate_json_schema(value: Any, schema: Mapping[str, Any], path: str = "arguments") -> None:
    schema_type = schema.get("type")
    if schema_type == "object":
        if not isinstance(value, Mapping): raise ValueError(f"{path} must be an object")
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        if not isinstance(properties, Mapping) or not isinstance(required, list) or any(not isinstance(item, str) for item in required):
            raise ValueError("tool schema has invalid properties/required")
        for key in required:
            if key not in value: raise ValueError(f"{path}.{key} is required")
        if schema.get("additionalProperties", True) is False and any(key not in properties for key in value):
            raise ValueError(f"{path} contains an undeclared property")
        for key, item in value.items():
            if key in properties:
                _validate_json_schema(item, properties[key], f"{path}.{key}")
        return
    checks = {"string": lambda item: isinstance(item, str), "integer": lambda item: isinstance(item, int) and not isinstance(item, bool), "number": lambda item: isinstance(item, (int, float)) and not isinstance(item, bool), "boolean": lambda item: isinstance(item, bool), "array": lambda item: isinstance(item, list)}
    if schema_type in checks and not checks[schema_type](value):
        raise ValueError(f"{path} must be {schema_type}")
