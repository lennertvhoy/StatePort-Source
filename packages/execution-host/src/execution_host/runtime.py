"""Provider-neutral runtime operations and truthful host-surface observations.

The operation types extend the existing ``BackendCapabilities`` and
``AgentRunSpec`` abstractions.  They carry transient supervision data only;
provider sessions, transcripts, credentials, and canonical workflow state do
not belong here.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping, Protocol

from .contracts import AgentRunSpec, BackendCapabilities


_OPERATION_STATUSES = frozenset(
    {
        "completed",
        "failed",
        "interrupted",
        "timed_out",
        "cancelled",
        "cancellation_requested",
        "unsupported",
        "not_running",
    }
)
_HEALTH_STATUSES = frozenset({"healthy", "degraded", "unavailable"})
_MATRIX_STATUSES = frozenset(
    {
        "implemented",
        "environment_gated",
        "not_implemented",
        "unsupported",
        "unverified",
        "ineligible",
    }
)
PROVIDER_OPERATION_FIELDS = (
    "detection",
    "preparation",
    "processInvocation",
    "eventStreaming",
    "resume",
    "cancel",
    "structuredOutput",
    "filesystemDiffCapture",
    "liveModelExecution",
    "authenticationReadiness",
    "spendReadiness",
    "productionEligibility",
)


def _bounded_string(value: Any, name: str, *, limit: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f"{name} must be a non-empty bounded string")
    return value


def _bounded_mapping(
    value: Mapping[str, Any], name: str, *, byte_limit: int = 16_384
) -> Mapping[str, Any]:
    if (
        not isinstance(value, Mapping)
        or len(value) > 128
        or any(not isinstance(key, str) for key in value)
    ):
        raise ValueError(f"{name} must be a bounded string-keyed mapping")
    try:
        plain = dict(value)
        encoded = json.dumps(
            plain,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be bounded JSON data") from exc
    if len(encoded.encode("utf-8")) > byte_limit:
        raise ValueError(f"{name} exceeds its byte bound")
    return MappingProxyType(plain)


@dataclass(frozen=True)
class BackendEvent:
    """One transient provider-neutral event awaiting journal normalization."""

    event_type: str
    summary: str
    attributes: Mapping[str, Any]
    adapter_metadata: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        _bounded_string(self.event_type, "event_type", limit=64)
        _bounded_string(self.summary, "summary")
        attributes = _bounded_mapping(self.attributes, "attributes")
        if len(attributes) > 32:
            raise ValueError("attributes exceeds the 32-field AgentEvent bound")
        for value in attributes.values():
            if not isinstance(value, (str, int, float, bool, type(None))):
                raise ValueError("event attributes must be scalar observations")
            if isinstance(value, str) and len(value) > 1024:
                raise ValueError("event attribute strings must be bounded")
        object.__setattr__(self, "attributes", attributes)
        if self.adapter_metadata is not None:
            object.__setattr__(
                self,
                "adapter_metadata",
                _bounded_mapping(self.adapter_metadata, "adapter_metadata"),
            )


@dataclass(frozen=True)
class BackendOperationResult:
    """Honest terminal outcome for one explicit runtime operation."""

    operation: str
    run_id: str
    status: str
    events: tuple[BackendEvent, ...] = ()
    failure_classification: str | None = None
    process: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.operation not in {"start", "resume", "cancel"}:
            raise ValueError("runtime operation is invalid")
        _bounded_string(self.run_id, "run_id", limit=128)
        if self.status not in _OPERATION_STATUSES:
            raise ValueError("runtime operation status is invalid")
        if (
            not isinstance(self.events, tuple)
            or len(self.events) > 512
            or any(not isinstance(item, BackendEvent) for item in self.events)
        ):
            raise ValueError("runtime operation events are invalid or unbounded")
        if self.failure_classification is not None:
            _bounded_string(
                self.failure_classification, "failure_classification", limit=128
            )
        if self.process is not None:
            object.__setattr__(
                self, "process", _bounded_mapping(self.process, "process")
            )

    def to_dict(self) -> dict[str, Any]:
        """Return persistence-safe outcome metadata, never raw event content."""

        return {
            "operation": self.operation,
            "runId": self.run_id,
            "status": self.status,
            "failureClassification": self.failure_classification,
            "terminationClassification": "success" if self.failure_classification is None else "worker_nonzero_exit",
            "eventCount": len(self.events),
            "process": dict(self.process or {}),
        }


@dataclass(frozen=True)
class BackendHealth:
    backend_id: str
    status: str
    active_runs: int
    test_only: bool
    detail: str

    def __post_init__(self) -> None:
        _bounded_string(self.backend_id, "backend_id", limit=128)
        if self.status not in _HEALTH_STATUSES:
            raise ValueError("backend health status is invalid")
        if (
            isinstance(self.active_runs, bool)
            or not isinstance(self.active_runs, int)
            or self.active_runs < 0
        ):
            raise ValueError("active_runs must be a non-negative integer")
        if not isinstance(self.test_only, bool):
            raise ValueError("test_only must be boolean")
        _bounded_string(self.detail, "detail", limit=512)

    def to_dict(self) -> dict[str, Any]:
        return {
            "backendId": self.backend_id,
            "status": self.status,
            "activeRuns": self.active_runs,
            "testOnly": self.test_only,
            "detail": self.detail,
        }


BackendEventSink = Callable[[BackendEvent], None]


class AgentBackend(Protocol):
    """Replaceable managed backend mapped to the existing host contracts."""

    def capabilities(self) -> BackendCapabilities: ...
    def start(
        self,
        run_spec: AgentRunSpec,
        staging_root: Path,
        *,
        environment: Mapping[str, str],
        event_sink: BackendEventSink,
    ) -> BackendOperationResult: ...
    def resume(
        self,
        run_spec: AgentRunSpec,
        staging_root: Path,
        *,
        environment: Mapping[str, str],
        event_sink: BackendEventSink,
    ) -> BackendOperationResult: ...
    def cancel(self, run_id: str) -> BackendOperationResult: ...
    def health(self) -> BackendHealth: ...


def _claim(status: str, basis: str) -> dict[str, str]:
    if status not in _MATRIX_STATUSES:
        raise ValueError("operation matrix status is invalid")
    return {
        "status": status,
        "basis": _bounded_string(basis, "operation matrix basis", limit=512),
    }


def provider_operation_matrix() -> dict[str, Any]:
    """Return static implementation truth without probing hosts or auth state."""

    rows = {
        "codex": {
            "detection": _claim(
                "implemented",
                "Executable/version/help metadata probe only; credentials are not inspected.",
            ),
            "preparation": _claim(
                "implemented", "A staging-bound ephemeral JSON command builder exists."
            ),
            "processInvocation": _claim(
                "environment_gated",
                "The bounded process path exists; no authenticated live invocation is qualified.",
            ),
            "eventStreaming": _claim(
                "not_implemented",
                "The current CLI path retains output and decodes JSONL only after process completion.",
            ),
            "resume": _claim(
                "unsupported",
                "The current Codex CLI adapter declares sessionResume unsupported.",
            ),
            "cancel": _claim(
                "implemented",
                "The shared process runtime accepts cancellation and reaps the process group.",
            ),
            "structuredOutput": _claim(
                "environment_gated",
                "Typed artifact/JSONL handling exists without a live provider proof.",
            ),
            "filesystemDiffCapture": _claim(
                "not_implemented",
                "The Codex path is not connected to managed cockpit diff capture.",
            ),
            "liveModelExecution": _claim(
                "environment_gated",
                "No credential, paid-model, or live smoke is performed by this slice.",
            ),
            "authenticationReadiness": _claim(
                "unverified",
                "Supported authentication material is deliberately not inspected.",
            ),
            "spendReadiness": _claim(
                "unverified", "Quota and spend coverage are not observed or inferred."
            ),
            "productionEligibility": _claim(
                "ineligible",
                "The existing adapter is explicitly productionEligible false.",
            ),
        },
        "opencode": {
            "detection": _claim(
                "implemented",
                "Executable/version metadata probe only; credentials are not inspected.",
            ),
            "preparation": _claim(
                "implemented",
                "OpenCodeContainerBackend prepares staging and command via OpenCodeAdapter.",
            ),
            "processInvocation": _claim(
                "implemented",
                "Rootless Podman container launch via ContainerOpenCodeEnforcer.",
            ),
            "eventStreaming": _claim(
                "implemented",
                "CTO-normalized event mapping in OpenCodeContainerBackend.start().",
            ),
            "resume": _claim(
                "unsupported",
                "OpenCode sessionResume declared unsupported by adapter.",
            ),
            "cancel": _claim(
                "implemented",
                "ContainerOpenCodeEnforcer.execute() accepts cancel_event + cleanup.",
            ),
            "structuredOutput": _claim(
                "implemented",
                "OpenCodeAdapter._parse_events() extracts structured JSONL events.",
            ),
            "filesystemDiffCapture": _claim(
                "implemented",
                "OpenCodeAdapter._extract_changed_files() captures file inventory.",
            ),
            "liveModelExecution": _claim(
                "environment_gated",
                "DeepSeek V4 Flash requires operator authentication.",
            ),
            "authenticationReadiness": _claim(
                "unverified",
                "Authentication material not inspected by adapter.",
            ),
            "spendReadiness": _claim(
                "unverified", "Quota and spend coverage not observed."
            ),
            "productionEligibility": _claim(
                "ineligible",
                "The staging container exists, but isolated post-agent validation is not implemented; the backend is explicitly productionEligible false.",
            ),
        },
        "pi": {
            "detection": _claim(
                "implemented",
                "Executable/version metadata probe only; credentials are not inspected.",
            ),
            "preparation": _claim(
                "not_implemented", "No Pi adapter preparation path exists."
            ),
            "processInvocation": _claim(
                "not_implemented", "No Pi SDK or RPC process is started."
            ),
            "eventStreaming": _claim(
                "not_implemented", "No Pi event normalization exists."
            ),
            "resume": _claim(
                "not_implemented", "No Pi session resumption is integrated."
            ),
            "cancel": _claim(
                "not_implemented", "No Pi runtime is attached to cancellation."
            ),
            "structuredOutput": _claim(
                "not_implemented", "No Pi structured-result integration exists."
            ),
            "filesystemDiffCapture": _claim(
                "not_implemented", "No Pi run is connected to cockpit diff capture."
            ),
            "liveModelExecution": _claim(
                "environment_gated",
                "Pi remains a reference direction with no live invocation.",
            ),
            "authenticationReadiness": _claim(
                "unverified",
                "Supported authentication material is deliberately not inspected.",
            ),
            "spendReadiness": _claim(
                "unverified", "Quota and spend coverage are not observed or inferred."
            ),
            "productionEligibility": _claim(
                "ineligible", "Pi is an unimplemented optional reference adapter."
            ),
        },
    }
    for provider, operations in rows.items():
        if set(operations) != set(PROVIDER_OPERATION_FIELDS):
            raise ValueError(f"{provider} operation matrix is incomplete")
    return {
        "formatVersion": "stateport.provider-operation-matrix/v1",
        "observation": "static_implementation_truth_no_provider_or_credential_probe",
        "providers": [
            {"provider": provider, "operations": operations}
            for provider, operations in rows.items()
        ],
    }


__all__ = [
    "AgentBackend",
    "BackendEvent",
    "BackendEventSink",
    "BackendHealth",
    "BackendOperationResult",
    "PROVIDER_OPERATION_FIELDS",
    "provider_operation_matrix",
]
