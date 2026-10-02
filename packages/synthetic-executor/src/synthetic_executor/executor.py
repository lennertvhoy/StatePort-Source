"""Deterministic, non-production execution of scripted agent-run scenarios.

This module is deliberately a reference fixture rather than an agent host.  It
does not read or write a workspace, start a process, access a network, call a
model provider, or execute the validation commands in an ``AgentRunSpec``.
Every tool call and file mutation is represented as a deterministic proposal.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
from typing import Any, Mapping

from execution_host.contracts import (
    AGENT_RUN_SPEC_FORMAT,
    RUN_RESULT_FORMAT,
    AgentRunSpec,
    BackendCapabilities,
    require_accepted,
    validate_run_result,
)


FORMAT_VERSION = "stateport.synthetic-executor/v1"
EVENT_FORMAT_VERSION = "stateport.synthetic-event/v1"
SYNTHETIC_BACKEND_ID = "synthetic"
SYNTHETIC_ADAPTER_ID = "synthetic-executor"
SYNTHETIC_ADAPTER_VERSION = "1.0.0"
SYNTHETIC_USAGE_MARKER = "synthetic-deterministic-v1"
_GENESIS = "genesis"
_EVENT_TIME = "1970-01-01T00:00:00Z"
_CAPABILITY_NAMES = (
    "structuredEvents",
    "nonInteractiveExecution",
    "cancellation",
    "sessionResume",
    "repositoryInstructions",
    "customTools",
    "mcpEquivalent",
    "approvalIntegration",
    "sandboxSupport",
    "changedFileReporting",
    "tokenTelemetry",
    "costTelemetry",
)
_TOOL_NAMES = frozenset({"statepack.read", "file_change.propose"})
_SCENARIO_NAMES = frozenset(
    {
        "success",
        "approval_required",
        "rejected_action",
        "cancellation",
        "timeout",
        "malformed_event",
        "validation_failure",
        "no_op",
    }
)


class Scenario(str, Enum):
    """The complete set of deterministic scripts supported by this fixture."""

    SUCCESS = "success"
    APPROVAL_REQUIRED = "approval_required"
    REJECTED_ACTION = "rejected_action"
    CANCELLATION = "cancellation"
    TIMEOUT = "timeout"
    MALFORMED_EVENT = "malformed_event"
    VALIDATION_FAILURE = "validation_failure"
    NO_OP = "no_op"


class SyntheticEventError(ValueError):
    """Raised when a synthetic event envelope is not structurally valid."""


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _safe_path(value: Any) -> str:
    if not isinstance(value, str) or not value or value.startswith("/"):
        raise ValueError("proposal path must be a non-empty relative path")
    parts = value.replace("\\", "/").split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("proposal path must be normalized and relative")
    return value.replace("\\", "/")


def _scenario(value: Scenario | str) -> Scenario:
    try:
        return value if isinstance(value, Scenario) else Scenario(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"unknown synthetic scenario: {value!r}") from exc


@dataclass(frozen=True)
class SyntheticToolRequest:
    """A tool request that is only observed; no tool implementation is called."""

    request_id: str
    tool: str
    arguments: Mapping[str, Any]

    def __post_init__(self) -> None:
        if not self.request_id or not self.request_id.startswith("tool-"):
            raise ValueError("request_id must be a deterministic synthetic tool ID")
        if self.tool not in _TOOL_NAMES:
            raise ValueError("synthetic tool is not in the fixed tool set")
        if not isinstance(self.arguments, Mapping):
            raise TypeError("tool arguments must be a mapping")

    def to_dict(self) -> dict[str, Any]:
        return {
            "requestId": self.request_id,
            "tool": self.tool,
            "arguments": dict(self.arguments),
            "simulated": True,
        }


@dataclass(frozen=True)
class ChangedFileProposal:
    """A proposed file change; the executor never materializes it."""

    path: str
    operation: str
    content: str
    reason: str

    def __post_init__(self) -> None:
        _safe_path(self.path)
        if self.operation not in {"create", "modify"}:
            raise ValueError("proposal operation must be create or modify")
        if not isinstance(self.content, str):
            raise TypeError("proposal content must be text")
        if not self.reason:
            raise ValueError("proposal reason is required")

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "operation": self.operation,
            "contentDigest": _digest(self.content),
            "content": self.content,
            "reason": self.reason,
            "status": "proposed",
            "materialized": False,
        }


@dataclass(frozen=True)
class SyntheticUsage:
    """Synthetic counters, kept separate from RunResult's honest telemetry."""

    marker: str = SYNTHETIC_USAGE_MARKER
    token_units: int = 17
    cost_minor: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "marker": self.marker,
            "tokenUnits": self.token_units,
            "costMinor": self.cost_minor,
            "realProviderUsage": False,
        }


@dataclass(frozen=True)
class SyntheticExecution:
    """Trace plus contract result for one scripted scenario."""

    scenario: Scenario
    events: tuple[dict[str, Any], ...]
    tool_requests: tuple[dict[str, Any], ...]
    changed_file_proposals: tuple[dict[str, Any], ...]
    run_result: dict[str, Any]
    event_digest: str
    usage: SyntheticUsage = SyntheticUsage()
    production_eligible: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": FORMAT_VERSION,
            "scenario": self.scenario.value,
            "productionEligible": self.production_eligible,
            "events": [dict(event) for event in self.events],
            "eventDigest": self.event_digest,
            "toolRequests": [dict(request) for request in self.tool_requests],
            "changedFileProposals": [dict(proposal) for proposal in self.changed_file_proposals],
            "usage": self.usage.to_dict(),
            "runResult": dict(self.run_result),
        }


def _event(
    run_id: str,
    sequence: int,
    event_type: str,
    payload: Mapping[str, Any],
    previous_digest: str,
) -> dict[str, Any]:
    body = {
        "formatVersion": EVENT_FORMAT_VERSION,
        "runId": run_id,
        "sequence": sequence,
        "timestamp": _EVENT_TIME,
        "eventType": event_type,
        "payload": dict(payload),
        "previousDigest": previous_digest,
    }
    return {**body, "digest": _digest(body)}


def validate_events(events: Any, *, run_id: str | None = None) -> tuple[dict[str, Any], ...]:
    """Validate and return an event stream without executing anything.

    Event order and the hash chain are part of the fixture contract.  This
    helper intentionally rejects unknown keys, gaps, changed payloads, and
    malformed events so callers can use it as an authoritative local check.
    """

    if not isinstance(events, (list, tuple)) or not events:
        raise SyntheticEventError("events must be a non-empty list")
    expected_previous = _GENESIS
    checked: list[dict[str, Any]] = []
    for expected_sequence, event in enumerate(events, 1):
        if not isinstance(event, Mapping):
            raise SyntheticEventError("event must be an object")
        required = {
            "formatVersion",
            "runId",
            "sequence",
            "timestamp",
            "eventType",
            "payload",
            "previousDigest",
            "digest",
        }
        if set(event) != required:
            raise SyntheticEventError("event has an invalid shape")
        if event["formatVersion"] != EVENT_FORMAT_VERSION:
            raise SyntheticEventError("event has an invalid formatVersion")
        if run_id is not None and event["runId"] != run_id:
            raise SyntheticEventError("event runId does not match the requested run")
        if event["sequence"] != expected_sequence:
            raise SyntheticEventError("event sequence is not contiguous")
        if event["timestamp"] != _EVENT_TIME:
            raise SyntheticEventError("event timestamp is not deterministic")
        if not isinstance(event["eventType"], str) or not event["eventType"]:
            raise SyntheticEventError("eventType must be a non-empty string")
        if not isinstance(event["payload"], Mapping):
            raise SyntheticEventError("event payload must be an object")
        if event["previousDigest"] != expected_previous:
            raise SyntheticEventError("event hash chain is broken")
        body = dict(event)
        actual_digest = body.pop("digest")
        if actual_digest != _digest(body):
            raise SyntheticEventError("event digest does not match event content")
        expected_previous = actual_digest
        checked.append(dict(event))
    return tuple(checked)


class SyntheticExecutor:
    """A deterministic execution-host adapter with no production path."""

    production_eligible = False

    def describe_capabilities(self) -> BackendCapabilities:
        return BackendCapabilities(
            SYNTHETIC_BACKEND_ID,
            SYNTHETIC_ADAPTER_ID,
            SYNTHETIC_ADAPTER_VERSION,
            "portable",
            {name: "supported" for name in _CAPABILITY_NAMES},
            ("external_manual",),
            (),
            True,
            False,
        )

    def prepare(self, run_spec: AgentRunSpec, *, scenario: Scenario | str = Scenario.SUCCESS) -> dict[str, Any]:
        self._check_spec(run_spec)
        selected = _scenario(scenario)
        return {
            "formatVersion": FORMAT_VERSION,
            "runSpec": run_spec,
            "scenario": selected.value,
            "productionEligible": False,
        }

    def execute(
        self,
        prepared_run: Mapping[str, Any] | AgentRunSpec,
        *,
        scenario: Scenario | str | None = None,
    ) -> dict[str, Any]:
        """Return only the unchanged RunResult contract for adapter callers."""

        trace = self.run(prepared_run, scenario=scenario)
        return trace.run_result

    def run(
        self,
        prepared_run: Mapping[str, Any] | AgentRunSpec,
        *,
        scenario: Scenario | str | None = None,
    ) -> SyntheticExecution:
        if isinstance(prepared_run, AgentRunSpec):
            run_spec = prepared_run
            selected = _scenario(scenario or Scenario.SUCCESS)
        elif isinstance(prepared_run, Mapping):
            run_spec = prepared_run.get("runSpec")
            if not isinstance(run_spec, AgentRunSpec):
                raise TypeError("prepared run must contain an AgentRunSpec")
            selected = _scenario(scenario or prepared_run.get("scenario", Scenario.SUCCESS))
            if prepared_run.get("productionEligible") is not False:
                raise ValueError("synthetic prepared runs must be production-ineligible")
        else:
            raise TypeError("run requires an AgentRunSpec or prepared run")
        self._check_spec(run_spec)
        events, requests, proposals, status, failure, validations = self._script(run_spec, selected)
        checked_events = validate_events(events, run_id=run_spec.run_id)
        result = self._result(
            run_spec,
            status=status,
            failure=failure,
            requests=requests,
            proposals=proposals,
            validations=validations,
            event_digest=checked_events[-1]["digest"],
        )
        validate_run_result(result, run_spec)
        return SyntheticExecution(
            selected,
            checked_events,
            tuple(requests),
            tuple(proposals),
            result,
            checked_events[-1]["digest"],
        )

    def execute_trace(self, prepared_run: Mapping[str, Any] | AgentRunSpec, *, scenario: Scenario | str | None = None) -> SyntheticExecution:
        """Explicit trace-oriented alias for callers that need events."""

        return self.run(prepared_run, scenario=scenario)

    def cancel(self, run_id: str) -> None:
        """Validate a cancellation identity; run state is never kept in memory."""

        if not isinstance(run_id, str) or not run_id.strip():
            raise ValueError("run_id is required")

    def _check_spec(self, run_spec: AgentRunSpec) -> None:
        if not isinstance(run_spec, AgentRunSpec):
            raise TypeError("synthetic executor requires an AgentRunSpec")
        if run_spec.to_dict().get("formatVersion") != AGENT_RUN_SPEC_FORMAT:
            raise ValueError("unsupported AgentRunSpec format")
        require_accepted(run_spec, self.describe_capabilities())

    @staticmethod
    def _script(
        spec: AgentRunSpec, scenario: Scenario
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], str, str | None, list[dict[str, Any]]]:
        requests: list[dict[str, Any]] = []
        proposals: list[dict[str, Any]] = []
        validations: list[dict[str, Any]] = []
        events: list[dict[str, Any]] = []
        previous = _GENESIS

        def add(event_type: str, payload: Mapping[str, Any]) -> None:
            nonlocal previous
            value = _event(spec.run_id, len(events) + 1, event_type, payload, previous)
            events.append(value)
            previous = value["digest"]

        add(
            "run.started",
            {
                "runSpecDigest": spec.digest,
                "backend": spec.backend_id,
                "adapter": spec.adapter_id,
                "productionEligible": False,
                "scenario": scenario.value,
            },
        )

        def request(request_id: str, tool: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
            value = SyntheticToolRequest(request_id, tool, arguments).to_dict()
            requests.append(value)
            add("tool.requested", value)
            return value

        def propose() -> dict[str, Any]:
            value = ChangedFileProposal(
                "proposals/synthetic-change.txt",
                "create",
                "synthetic executor proposal\n",
                "scripted deterministic change proposal",
            ).to_dict()
            proposals.append(value)
            add("file.change_proposed", value)
            return value

        if scenario == Scenario.NO_OP:
            add("run.no_op", {"reason": "scripted scenario requests no action"})
            return events + [_event(spec.run_id, len(events) + 1, "run.completed", {"status": "completed"}, previous)], requests, proposals, "completed", None, validations

        request("tool-001", "statepack.read", {"reference": spec.statepack_reference, "digest": spec.statepack_digest})
        if scenario == Scenario.APPROVAL_REQUIRED:
            add("approval.required", {"requiredLevel": spec.approval_required_level or "external_manual", "action": "file_change.propose"})
            add("run.paused", {"reason": "approval required", "status": "prepared"})
            return events, requests, proposals, "prepared", "approval_required", validations
        if scenario == Scenario.REJECTED_ACTION:
            request("tool-002", "file_change.propose", {"path": "proposals/synthetic-change.txt", "operation": "create"})
            add("action.rejected", {"action": "file_change.propose", "reason": "synthetic policy rejection"})
            add("run.failed", {"failureClassification": "rejected_action"})
            return events, requests, proposals, "failed", "rejected_action", validations
        if scenario == Scenario.CANCELLATION:
            add("run.cancelled", {"reason": "synthetic cancellation request"})
            return events, requests, proposals, "cancelled", "cancelled", validations
        if scenario == Scenario.TIMEOUT:
            add("execution.timeout", {"budget": "timeSeconds", "elapsed": "deterministic_limit"})
            return events, requests, proposals, "failed", "timeout", validations
        if scenario == Scenario.MALFORMED_EVENT:
            add("event.malformed", {"reason": "scripted event omitted a required tool field", "recovered": True})
            add("run.failed", {"failureClassification": "malformed_event"})
            return events, requests, proposals, "failed", "malformed_event", validations

        request("tool-002", "file_change.propose", {"path": "proposals/synthetic-change.txt", "operation": "create"})
        proposal = propose()
        if scenario == Scenario.VALIDATION_FAILURE:
            validation = {"validator": "synthetic-validator", "status": "failed", "details": "scripted validation failure", "executed": False}
            validations.append(validation)
            add("validation.completed", validation)
            add("run.failed", {"failureClassification": "validation_failure", "proposalDigest": proposal["contentDigest"]})
            return events, requests, proposals, "failed", "validation_failure", validations

        validation = {"validator": "synthetic-validator", "status": "passed", "details": "deterministic proposal shape accepted", "executed": False}
        validations.append(validation)
        add("validation.completed", validation)
        add("run.completed", {"status": "completed", "proposalDigest": proposal["contentDigest"]})
        return events, requests, proposals, "completed", None, validations

    @staticmethod
    def _result(
        spec: AgentRunSpec,
        *,
        status: str,
        failure: str | None,
        requests: list[dict[str, Any]],
        proposals: list[dict[str, Any]],
        validations: list[dict[str, Any]],
        event_digest: str,
    ) -> dict[str, Any]:
        warnings = [
            "synthetic executor; no model, provider, network, shell, or workspace execution occurred",
            f"usage marker: {SYNTHETIC_USAGE_MARKER}",
            "validation commands were recorded but not executed",
        ]
        if failure == "approval_required":
            warnings.append("action proposal is pending external approval")
        # This is the termination of the synthetic executor, not the logical
        # outcome it models.  Typed rejection and validation-failure artifacts
        # are produced successfully; only the explicit termination scenarios
        # model cancellation or timeout.
        termination = {
            "cancelled": "cancelled",
            "timeout": "timeout",
        }.get(failure, "success")
        return {
            "formatVersion": RUN_RESULT_FORMAT,
            "runId": spec.run_id,
            "runSpecDigest": spec.digest,
            "backend": {"id": spec.backend_id, "adapter": {"id": spec.adapter_id, "version": spec.adapter_version}},
            "model": spec.model_identifier,
            "authenticationRouteClass": spec.authentication_route_class,
            "statePack": {"reference": spec.statepack_reference, "digest": spec.statepack_digest},
            "toolPolicy": {"permittedCapabilities": list(spec.permitted_capabilities)},
            "sandbox": {"profile": spec.sandbox_profile},
            "executionStatus": status,
            "verificationStatus": "synthetic_test_only",
            "timestamps": {"startedAt": _EVENT_TIME, "finishedAt": _EVENT_TIME},
            "failureClassification": failure,
            "terminationClassification": termination,
            "usage": {"token": {"quality": "unavailable", "value": None}, "cost": {"quality": "unavailable", "value": None}},
            "changedFiles": proposals,
            "validationOutcomes": validations,
            "producedArtifacts": [
                {"kind": "synthetic_event_stream", "digest": event_digest, "materialized": False},
                {"kind": "synthetic_usage_marker", "marker": SYNTHETIC_USAGE_MARKER, "materialized": False},
            ],
            "approvalReference": spec.approval_reference,
            "auditReferences": [f"synthetic-event-chain:{event_digest}"],
            "warnings": warnings,
            "degradations": [],
        }


def assert_production_ineligible(executor: SyntheticExecutor) -> None:
    """Fail closed if a caller attempts to use this fixture as production."""

    capabilities = executor.describe_capabilities()
    if capabilities.production_eligible or not capabilities.test_only or executor.production_eligible:
        raise ValueError("synthetic executor must remain production-ineligible")


__all__ = [
    "ChangedFileProposal",
    "EVENT_FORMAT_VERSION",
    "FORMAT_VERSION",
    "Scenario",
    "SYNTHETIC_ADAPTER_ID",
    "SYNTHETIC_ADAPTER_VERSION",
    "SYNTHETIC_BACKEND_ID",
    "SYNTHETIC_USAGE_MARKER",
    "SyntheticEventError",
    "SyntheticExecution",
    "SyntheticExecutor",
    "SyntheticToolRequest",
    "SyntheticUsage",
    "assert_production_ineligible",
    "validate_events",
]
