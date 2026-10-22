from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
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


# Public template contract (docs/TEMPLATE_CONTRACT.md). Every policy field is a
# closed vocabulary: an unknown value is refused instead of being carried as an
# opaque string that no enforcement point understands.
EXECUTOR_KINDS = ("script", "agent")
MUTATION_POLICIES = ("none", "propose_only")
NETWORK_POLICIES = ("disabled", "model_provider_only")
TOOL_POLICIES = ("none", "edit")
AGENT_ACTION_CLASSES = ("agent.edit-state",)
EXECUTOR_ORIGINS = ("application", "instance")
MAX_AGENT_INSTRUCTIONS = 4000
MAX_WRITABLE_PATHS = 64
_ACTION_CLASS = re.compile(r"^[a-z][a-z0-9-]{0,31}(?:\.[a-z][a-z0-9-]{0,31}){1,3}$")


def _enum(value: Any, field: str, allowed: tuple[str, ...], default: str) -> str:
    if value is None:
        return default
    if not isinstance(value, str) or value not in allowed:
        raise ValueError(f"{field} must be one of: {', '.join(allowed)}")
    return value


def safe_relative_path(value: Any, field: str, *, allow_prefix: bool = False) -> str:
    """Return a repository-relative POSIX path or prefix (``dir/``), refusing escapes."""

    if not isinstance(value, str) or not value or len(value) > 512:
        raise ValueError(f"{field} must be a non-empty relative path")
    if "\\" in value or "\x00" in value or value.startswith("/"):
        raise ValueError(f"{field} is not a safe relative path")
    is_prefix = value.endswith("/")
    if is_prefix and not allow_prefix:
        raise ValueError(f"{field} must name a file, not a directory prefix")
    body = value[:-1] if is_prefix else value
    if body == ".":
        if not is_prefix:
            raise ValueError(f"{field} is not a safe relative path")
        return "./"
    parts = body.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError(f"{field} is not a safe relative path")
    return body + ("/" if is_prefix else "")


def _writable_paths(value: Any, *, field: str = "writablePaths") -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)) or len(value) > MAX_WRITABLE_PATHS:
        raise ValueError(f"{field} must be a list of at most {MAX_WRITABLE_PATHS} paths")
    paths = tuple(safe_relative_path(item, f"{field} entry", allow_prefix=True) for item in value)
    if len(set(paths)) != len(paths):
        raise ValueError(f"{field} entries must be unique")
    return tuple(sorted(paths))


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
    # `script` runs the declared executor; `agent` asks a model to edit a staged
    # copy and StatePort turns the observed file changes into one proposal.
    executor_kind: str = "script"
    instructions: str | None = None
    action_class: str | None = None
    writable_paths: tuple[str, ...] = ()
    # Narrowing by exclusion: paths this action may never write even where the
    # layout makes them instance-owned (e.g. ProjectState's PROJECT.md for
    # next-action). Like writablePaths it can only remove authority.
    protected_paths: tuple[str, ...] = ()
    # Set only by StatePort's loader, never read from a contract: `instance`
    # marks a reviewed executor shipped inside an imported application.
    executor_origin: str = "application"
    executor_action_name: str | None = None

    def __post_init__(self) -> None:
        _enum(self.executor_kind, "executorKind", EXECUTOR_KINDS, "script")
        _enum(self.mutation_policy, "mutationPolicy", MUTATION_POLICIES, "none")
        _enum(self.network_policy, "networkPolicy", NETWORK_POLICIES, "disabled")
        _enum(self.tool_policy, "toolPolicy", TOOL_POLICIES, "none")
        _enum(self.executor_origin, "executorOrigin", EXECUTOR_ORIGINS, "application")
        if self.timeout_seconds <= 0 or self.timeout_seconds > 3600:
            raise ValueError("timeoutSeconds must be between 1 and 3600")
        if self.executor_kind == "agent":
            if not isinstance(self.instructions, str) or not self.instructions.strip():
                raise ValueError("agent actions require instructions")
            if len(self.instructions) > MAX_AGENT_INSTRUCTIONS:
                raise ValueError(f"agent instructions exceed {MAX_AGENT_INSTRUCTIONS} characters")
            if self.network_policy != "model_provider_only":
                raise ValueError("agent actions require networkPolicy model_provider_only")
            if self.mutation_policy != "propose_only":
                raise ValueError("agent actions require mutationPolicy propose_only")
            if self.tool_policy != "edit":
                raise ValueError("agent actions require toolPolicy edit")
            if self.action_class not in AGENT_ACTION_CLASSES or not _ACTION_CLASS.fullmatch(str(self.action_class)):
                raise ValueError("agent actions require a known actionClass: " + ", ".join(AGENT_ACTION_CLASSES))
            if self.executor_command is not None:
                raise ValueError("agent actions do not declare an executorCommand")
            if self.executor_origin != "application":
                raise ValueError("agent actions cannot carry an instance executor")
        else:
            if self.instructions is not None or self.action_class is not None:
                raise ValueError("script actions do not declare instructions or actionClass")
            if self.network_policy != "disabled":
                raise ValueError("script actions require networkPolicy disabled")
            if self.tool_policy != "none":
                raise ValueError("script actions require toolPolicy none")
        if (self.writable_paths or self.protected_paths) and self.mutation_policy != "propose_only":
            raise ValueError("writablePaths and protectedPaths are only meaningful for propose_only actions")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ActionContract":
        if not isinstance(value.get("formatVersion"), str) or not value["formatVersion"].endswith(".action/v1"):
            raise ValueError("unsupported application action contract")
        action_id = value.get("id", value.get("actionId"))
        if not isinstance(action_id, str) or not action_id:
            raise ValueError("application action contract requires an id")
        executor_kind = _enum(value.get("executorKind"), "executorKind", EXECUTOR_KINDS, "script")
        agent = executor_kind == "agent"
        instructions = value.get("instructions")
        if instructions is not None and not isinstance(instructions, str):
            raise ValueError("instructions must be text")
        action_class = value.get("actionClass")
        if action_class is not None and not isinstance(action_class, str):
            raise ValueError("actionClass must be text")
        timeout = value.get("timeoutSeconds", 300 if agent else 30)
        if isinstance(timeout, bool) or not isinstance(timeout, int):
            raise ValueError("timeoutSeconds must be an integer")
        return cls(
            action_id,
            str(value["displayName"]),
            str(value["purpose"]),
            dict(value.get("inputSchema", {})),
            dict(value.get("outputSchema", {})),
            dict(value["contextPolicy"]),
            tuple(value.get("requiredCapabilities", ())),
            tuple(value.get("optionalCapabilities", ())),
            _enum(value.get("mutationPolicy"), "mutationPolicy", MUTATION_POLICIES, "propose_only" if agent else "none"),
            _enum(value.get("networkPolicy"), "networkPolicy", NETWORK_POLICIES, "model_provider_only" if agent else "disabled"),
            _enum(value.get("toolPolicy"), "toolPolicy", TOOL_POLICIES, "edit" if agent else "none"),
            timeout,
            dict(value.get("budgetDefaults", {})),
            dict(value.get("validationPolicy", {})),
            tuple(value.get("supportedEngineDegradations", ())),
            tuple(value.get("expectedEvidenceArtifacts", ())),
            str(value["executorCommand"]) if isinstance(value.get("executorCommand"), str) else None,
            executor_kind,
            instructions,
            (action_class if action_class is not None else ("agent.edit-state" if agent else None)),
            _writable_paths(value.get("writablePaths")),
            _writable_paths(value.get("protectedPaths"), field="protectedPaths"),
        )

    def to_dict(self) -> dict[str, Any]:
        # The new contract fields are emitted only when they differ from the
        # script default, so the digest of every pre-existing script action
        # (and therefore every in-flight approval bound to it) is unchanged.
        extension: dict[str, Any] = {}
        if self.executor_kind != "script":
            extension.update({
                "executorKind": self.executor_kind,
                "instructions": self.instructions,
                "actionClass": self.action_class,
            })
        if self.writable_paths:
            extension["writablePaths"] = list(self.writable_paths)
        if self.protected_paths:
            extension["protectedPaths"] = list(self.protected_paths)
        if self.executor_origin != "application":
            extension["executorOrigin"] = self.executor_origin
            extension["executorActionName"] = self.executor_action_name
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
            **extension,
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
