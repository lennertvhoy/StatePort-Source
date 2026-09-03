from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping

APPLICATION_DESCRIPTOR_FORMAT = "stateport.application/v1"
ACTION_CONTRACT_FORMAT = "stateport.application-action/v1"
ENGINE_PROFILE_FORMAT = "stateport.execution-engine/v1"
RUN_FORMAT = "stateport.governed-action-run/v1"

# The persisted lifecycle is deliberately separate from the older `status`
# projection consumed by existing StatePort clients.  This lets the service
# preserve compatibility while making every approval, execution, mutation,
# and recovery boundary explicit and machine-checkable.
LIFECYCLE_STATES = (
    "DRAFT", "COMPILED", "BLOCKED_CAPABILITY", "AWAITING_RUN_APPROVAL",
    "APPROVED", "STARTING", "RUNNING", "SUCCEEDED", "FAILED", "CANCELLED",
    "INTERRUPTED", "TIMED_OUT", "RESULT_VALIDATED", "NO_MUTATION",
    "PROPOSAL_CREATED", "AWAITING_PROPOSAL_APPROVAL", "PROPOSAL_REJECTED",
    "APPLYING", "APPLIED", "POST_VALIDATED", "CLOSED", "ROLLED_BACK",
)

LIFECYCLE_TRANSITIONS = {
    "DRAFT": {"COMPILED", "CANCELLED", "FAILED"},
    "COMPILED": {"BLOCKED_CAPABILITY", "AWAITING_RUN_APPROVAL", "FAILED", "CANCELLED"},
    "BLOCKED_CAPABILITY": {"FAILED", "CLOSED"},
    "AWAITING_RUN_APPROVAL": {"APPROVED", "CANCELLED", "FAILED"},
    "APPROVED": {"STARTING", "CANCELLED", "FAILED"},
    "STARTING": {"RUNNING", "FAILED", "TIMED_OUT", "INTERRUPTED", "CANCELLED"},
    "RUNNING": {"SUCCEEDED", "FAILED", "CANCELLED", "INTERRUPTED", "TIMED_OUT"},
    "SUCCEEDED": {"RESULT_VALIDATED", "FAILED"},
    "RESULT_VALIDATED": {"NO_MUTATION", "PROPOSAL_CREATED", "FAILED"},
    "NO_MUTATION": {"CLOSED"},
    "PROPOSAL_CREATED": {"AWAITING_PROPOSAL_APPROVAL", "PROPOSAL_REJECTED", "FAILED"},
    "AWAITING_PROPOSAL_APPROVAL": {"PROPOSAL_REJECTED", "APPLYING", "FAILED"},
    "PROPOSAL_REJECTED": {"CLOSED"},
    "APPLYING": {"APPLIED", "ROLLED_BACK", "FAILED", "INTERRUPTED"},
    "APPLIED": {"POST_VALIDATED", "ROLLED_BACK", "FAILED", "INTERRUPTED"},
    "POST_VALIDATED": {"CLOSED", "ROLLED_BACK", "FAILED", "INTERRUPTED"},
    "FAILED": {"CLOSED", "ROLLED_BACK"},
    "CANCELLED": {"CLOSED"},
    "INTERRUPTED": {"STARTING", "CANCELLED", "CLOSED", "FAILED"},
    "TIMED_OUT": {"CLOSED", "STARTING"},
    "ROLLED_BACK": {"CLOSED"},
    "CLOSED": set(),
}

LEGACY_TO_LIFECYCLE = {
    "requested": "DRAFT", "planned": "COMPILED", "awaiting_approval": "AWAITING_RUN_APPROVAL",
    "approved": "APPROVED", "preparing": "STARTING", "prepared": "STARTING",
    "running": "RUNNING", "awaiting_tool_approval": "RUNNING", "cancelling": "CANCELLED",
    "cancelled": "CANCELLED", "interrupted": "INTERRUPTED", "timed_out": "TIMED_OUT",
    "failed": "FAILED", "completed": "SUCCEEDED", "result_validating": "RESULT_VALIDATED",
    "result_rejected": "FAILED", "state_change_proposed": "PROPOSAL_CREATED",
    "state_change_approved": "AWAITING_PROPOSAL_APPROVAL", "state_change_rejected": "PROPOSAL_REJECTED",
    "applying": "APPLYING", "applied": "APPLIED", "apply_failed": "ROLLED_BACK", "archived": "CLOSED",
}


def lifecycle_for_status(status: str | None) -> str:
    """Map a legacy status to the explicit persisted lifecycle vocabulary."""

    lifecycle = LEGACY_TO_LIFECYCLE.get(status or "")
    if lifecycle is None:
        raise ValueError(f"unknown legacy run status: {status}")
    return lifecycle


def allowed_lifecycle_transition(current: str, target: str) -> bool:
    # Legacy compatibility statuses such as `cancelling` and the final
    # `completed` bookkeeping step can project the same canonical state twice;
    # that is still an explicit, auditable transition rather than a bypass.
    return current == target or target in LIFECYCLE_TRANSITIONS.get(current, set())

RUN_STATES = (
    "requested", "planned", "awaiting_approval", "approved", "preparing", "prepared",
    "running", "awaiting_tool_approval", "cancelling", "cancelled", "interrupted", "timed_out", "failed",
    "completed", "result_validating", "result_rejected", "state_change_proposed",
    "state_change_approved", "state_change_rejected", "applying", "applied", "apply_failed", "archived",
)

_TRANSITIONS = {
    "requested": {"planned", "failed"},
    "planned": {"awaiting_approval", "failed"},
    "awaiting_approval": {"approved", "cancelled", "state_change_rejected", "failed"},
    "approved": {"preparing", "cancelled", "failed"},
    "preparing": {"prepared", "failed", "timed_out"},
    "prepared": {"running", "cancelled", "failed"},
    "running": {"completed", "result_validating", "cancelling", "cancelled", "interrupted", "timed_out", "failed"},
    "cancelling": {"cancelled", "failed"},
    "completed": {"result_validating", "archived"},
    "result_validating": {"state_change_proposed", "completed", "result_rejected", "failed"},
    "state_change_proposed": {"state_change_approved", "state_change_rejected", "archived"},
    "state_change_approved": {"applying", "failed"},
    "state_change_rejected": {"archived"},
    "applying": {"applied", "apply_failed", "failed", "interrupted"},
    "applied": {"archived", "apply_failed", "failed", "interrupted"},
    "failed": {"archived"},
    "cancelled": {"archived"},
    "timed_out": {"archived"},
    "interrupted": {"planned", "approved", "cancelled", "archived", "failed"},
    "result_rejected": {"archived"},
    "apply_failed": {"archived"},
    "archived": set(),
}


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(value if isinstance(value, bytes) else _canonical(value)).hexdigest()


def _required(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value


@dataclass(frozen=True)
class ApplicationDescriptor:
    application_id: str
    display_name: str
    description: str
    source_profile: str
    privacy_classification: str
    production_eligible: bool
    actions_path: str

    def to_dict(self) -> dict[str, Any]:
        return {"formatVersion": APPLICATION_DESCRIPTOR_FORMAT, "applicationId": self.application_id, "displayName": self.display_name, "description": self.description, "sourceProfile": self.source_profile, "privacyClassification": self.privacy_classification, "productionEligible": self.production_eligible, "actionsPath": self.actions_path}


@dataclass(frozen=True)
class ActionContract:
    action_id: str
    display_name: str
    purpose: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    context_policy: dict[str, Any]
    required_capabilities: tuple[str, ...]
    optional_capabilities: tuple[str, ...]
    mutation_policy: str
    network_policy: str
    tool_policy: str
    timeout_seconds: int
    budget_defaults: dict[str, int]
    validation_policy: dict[str, Any]
    supported_engine_degradations: tuple[str, ...]
    expected_evidence_artifacts: tuple[str, ...]
    executor_command: str | None = None

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ActionContract":
        if not isinstance(value.get("formatVersion"), str) or not value["formatVersion"].endswith(".action/v1"):
            raise ValueError("unsupported application action contract")
        action_id = value.get("id", value.get("actionId"))
        if not isinstance(action_id, str) or not action_id:
            raise ValueError("application action contract requires an id")
        return cls(
            action_id,
            str(value["displayName"]),
            str(value["purpose"]),
            dict(value.get("inputSchema", {})),
            dict(value.get("outputSchema", {})),
            dict(value["contextPolicy"]),
            tuple(value.get("requiredCapabilities", ())),
            tuple(value.get("optionalCapabilities", ())),
            str(value.get("mutationPolicy", "none")),
            str(value.get("networkPolicy", "disabled")),
            str(value.get("toolPolicy", "none")),
            int(value.get("timeoutSeconds", 30)),
            dict(value.get("budgetDefaults", {})),
            dict(value.get("validationPolicy", {})),
            tuple(value.get("supportedEngineDegradations", ())),
            tuple(value.get("expectedEvidenceArtifacts", ())),
            str(value["executorCommand"]) if isinstance(value.get("executorCommand"), str) else None,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": ACTION_CONTRACT_FORMAT,
            "actionId": self.action_id,
            "displayName": self.display_name,
            "purpose": self.purpose,
            "inputSchema": self.input_schema,
            "outputSchema": self.output_schema,
            "contextPolicy": self.context_policy,
            "requiredCapabilities": list(self.required_capabilities),
            "optionalCapabilities": list(self.optional_capabilities),
            "mutationPolicy": self.mutation_policy,
            "networkPolicy": self.network_policy,
            "toolPolicy": self.tool_policy,
            "timeoutSeconds": self.timeout_seconds,
            "budgetDefaults": self.budget_defaults,
            "validationPolicy": self.validation_policy,
            "supportedEngineDegradations": list(self.supported_engine_degradations),
            "expectedEvidenceArtifacts": list(self.expected_evidence_artifacts),
            "executorCommand": self.executor_command,
        }


@dataclass(frozen=True)
class EngineProfile:
    engine_id: str
    adapter_id: str
    adapter_version: str
    availability: str
    installed_version: str
    authentication_route_class: str
    capabilities: dict[str, str]
    model_identity: str
    production_eligible: bool
    limitations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"formatVersion": ENGINE_PROFILE_FORMAT, "engineId": self.engine_id, "adapterId": self.adapter_id, "adapterVersion": self.adapter_version, "availability": self.availability, "installedVersion": self.installed_version, "authenticationRouteClass": self.authentication_route_class, "capabilities": dict(sorted(self.capabilities.items())), "modelIdentity": self.model_identity, "productionEligible": self.production_eligible, "limitations": list(self.limitations)}


def allowed_transition(current: str, target: str) -> bool:
    return target in _TRANSITIONS.get(current, set())
