"""Portable, fail-closed execution-host contracts.

These contracts describe a proposed or observed run.  They do not execute an
agent and deliberately keep credentials, host session state, and canonical
instance mutation outside the contract boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any, Mapping


BACKEND_CAPABILITIES_FORMAT = "stateport.backend-capabilities/v1"
AGENT_RUN_SPEC_FORMAT = "stateport.agent-run-spec/v1"
RUN_RESULT_FORMAT = "stateport.run-result/v1"
TERMINATION_CLASSIFICATIONS = frozenset({
    "launch_failure",
    "timeout",
    "cancelled",
    "output_limit",
    "worker_nonzero_exit",
    "result_artifact_missing",
    "result_artifact_invalid",
    "success",
})
CAPABILITY_STATUSES = frozenset({"native", "emulated", "supported", "partial", "unsupported", "unavailable", "environment-gated", "unknown"})
INTEGRATION_TIERS = frozenset({"portable", "managed", "reference", "api_native"})
USAGE_QUALITIES = frozenset({"exact", "approximate", "unavailable"})
_CAPABILITY_NAMES = frozenset({
    "structuredEvents", "nonInteractiveExecution", "cancellation", "sessionResume",
    "repositoryInstructions", "customTools", "mcpEquivalent", "approvalIntegration",
    "sandboxSupport", "changedFileReporting", "tokenTelemetry", "costTelemetry",
})
_SECRET_KEY = re.compile(r"(?:api[_-]?key|authorization|cookie|credential|password|secret|access[_-]?token|refresh[_-]?token)", re.I)
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _id(value: Any, name: str) -> str:
    value = _string(value, name)
    if not _ID.fullmatch(value):
        raise ValueError(f"{name} has invalid characters")
    return value


def _mapping(value: Any, name: str, keys: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ValueError(f"{name} has an invalid shape")
    return value


def _strings(value: Any, name: str, *, path_safe: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value):
        raise ValueError(f"{name} must be a list of non-empty strings")
    values = tuple(value)
    if len(set(values)) != len(values):
        raise ValueError(f"{name} must not contain duplicates")
    if path_safe:
        for item in values:
            if item.startswith("/") or ".." in item.split("/") or "\\" in item:
                raise ValueError(f"{name} contains a path outside the run artifact root")
    return values


def _no_secrets(value: Any, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{path} keys must be strings")
            if _SECRET_KEY.search(key):
                raise ValueError(f"credential-like field is forbidden at {path}.{key}")
            _no_secrets(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _no_secrets(item, f"{path}[{index}]")


def _budget(value: Any) -> dict[str, int]:
    data = _mapping(value, "budgets", {"token", "costMinor", "timeSeconds", "steps"})
    result: dict[str, int] = {}
    for name, amount in data.items():
        if isinstance(amount, bool) or not isinstance(amount, int) or amount < 0:
            raise ValueError(f"budgets.{name} must be a non-negative integer")
        result[name] = amount
    return result


@dataclass(frozen=True)
class BackendCapabilities:
    backend_id: str
    adapter_id: str
    adapter_version: str
    integration_tier: str
    capabilities: dict[str, str]
    authentication_route_classes: tuple[str, ...]
    adapter_permissions: tuple[str, ...] = ()
    test_only: bool = False
    production_eligible: bool = True

    def __post_init__(self) -> None:
        _id(self.backend_id, "backend_id")
        _id(self.adapter_id, "adapter_id")
        _string(self.adapter_version, "adapter_version")
        if self.integration_tier not in INTEGRATION_TIERS:
            raise ValueError("integration_tier is invalid")
        if set(self.capabilities) != _CAPABILITY_NAMES or any(value not in CAPABILITY_STATUSES for value in self.capabilities.values()):
            raise ValueError("capabilities must declare every v1 capability with a valid status")
        _strings(list(self.authentication_route_classes), "authentication_route_classes")
        _strings(list(self.adapter_permissions), "adapter_permissions")
        if self.test_only and self.production_eligible:
            raise ValueError("test-only adapters cannot be production eligible")

    def to_dict(self) -> dict[str, Any]:
        return {"formatVersion": BACKEND_CAPABILITIES_FORMAT, "backend": {"id": self.backend_id}, "adapter": {"id": self.adapter_id, "version": self.adapter_version, "testOnly": self.test_only, "productionEligible": self.production_eligible}, "integrationTier": self.integration_tier, "capabilities": dict(sorted(self.capabilities.items())), "authenticationRouteClasses": list(self.authentication_route_classes), "adapterPermissions": list(self.adapter_permissions)}

    @classmethod
    def from_dict(cls, value: Any) -> "BackendCapabilities":
        _no_secrets(value)
        data = _mapping(value, "backend capabilities", {"formatVersion", "backend", "adapter", "integrationTier", "capabilities", "authenticationRouteClasses", "adapterPermissions"})
        if data["formatVersion"] != BACKEND_CAPABILITIES_FORMAT:
            raise ValueError("backend capabilities has an invalid formatVersion")
        backend = _mapping(data["backend"], "backend", {"id"})
        adapter = _mapping(data["adapter"], "adapter", {"id", "version", "testOnly", "productionEligible"})
        if not isinstance(adapter["testOnly"], bool) or not isinstance(adapter["productionEligible"], bool):
            raise ValueError("adapter eligibility fields must be booleans")
        if not isinstance(data["capabilities"], Mapping):
            raise ValueError("capabilities must be a mapping")
        return cls(str(backend["id"]), str(adapter["id"]), str(adapter["version"]), data["integrationTier"], dict(data["capabilities"]), _strings(data["authenticationRouteClasses"], "authenticationRouteClasses"), _strings(data["adapterPermissions"], "adapterPermissions"), adapter["testOnly"], adapter["productionEligible"])


@dataclass(frozen=True)
class CapabilityRequest:
    name: str
    allow_partial: bool = False

    def __post_init__(self) -> None:
        if self.name not in _CAPABILITY_NAMES:
            raise ValueError("unknown capability name")

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.name, "allowPartial": self.allow_partial}


@dataclass(frozen=True)
class AgentRunSpec:
    run_id: str
    instance_id: str
    source_revision: str
    objective: str
    statepack_reference: str
    statepack_digest: str
    required_capabilities: tuple[CapabilityRequest, ...]
    optional_capabilities: tuple[str, ...]
    backend_id: str
    adapter_id: str
    adapter_version: str
    model_identifier: str
    authentication_route_class: str
    permitted_capabilities: tuple[str, ...]
    sandbox_profile: str
    budgets: dict[str, int]
    validation_commands: tuple[str, ...]
    required_output_artifacts: tuple[str, ...]
    benchmark_configuration: dict[str, str]
    approval_reference: str | None = None
    approval_required_level: str | None = None
    repository_instructions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _id(self.run_id, "run_id"); _id(self.instance_id, "instance_id")
        for name in ("source_revision", "objective", "statepack_reference", "statepack_digest", "model_identifier", "authentication_route_class", "sandbox_profile"):
            _string(getattr(self, name), name)
        if not self.statepack_digest.startswith("sha256:") or len(self.statepack_digest) != 71:
            raise ValueError("statepack_digest must be a sha256 digest")
        if not self.required_capabilities:
            raise ValueError("at least one required capability is required")
        names = [item.name for item in self.required_capabilities]
        if len(set(names)) != len(names) or set(names) & set(self.optional_capabilities):
            raise ValueError("capability requests must be unique")
        _strings(list(self.optional_capabilities), "optional_capabilities")
        _id(self.backend_id, "backend_id"); _id(self.adapter_id, "adapter_id"); _string(self.adapter_version, "adapter_version")
        _strings(list(self.permitted_capabilities), "permitted_capabilities")
        _budget(self.budgets); _strings(list(self.validation_commands), "validation_commands")
        _strings(list(self.required_output_artifacts), "required_output_artifacts", path_safe=True)
        _strings(list(self.repository_instructions), "repository_instructions")
        if (self.approval_reference is None) == (self.approval_required_level is None):
            raise ValueError("exactly one approval reference or required level is required")
        if self.approval_reference is not None: _id(self.approval_reference, "approval_reference")
        if self.approval_required_level is not None: _string(self.approval_required_level, "approval_required_level")
        if not isinstance(self.benchmark_configuration, dict) or any(not isinstance(k, str) or not isinstance(v, str) or not k or not v for k, v in self.benchmark_configuration.items()):
            raise ValueError("benchmark_configuration must be a string mapping")
        _no_secrets(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {"formatVersion": AGENT_RUN_SPEC_FORMAT, "runId": self.run_id, "instance": {"id": self.instance_id, "sourceRevision": self.source_revision}, "objective": self.objective, "statePack": {"reference": self.statepack_reference, "digest": self.statepack_digest}, "capabilities": {"required": [item.to_dict() for item in self.required_capabilities], "optional": list(self.optional_capabilities)}, "backend": {"id": self.backend_id, "adapter": {"id": self.adapter_id, "version": self.adapter_version}}, "model": self.model_identifier, "authenticationRouteClass": self.authentication_route_class, "toolPolicy": {"permittedCapabilities": list(self.permitted_capabilities)}, "approval": {"reference": self.approval_reference, "requiredLevel": self.approval_required_level}, "sandbox": {"profile": self.sandbox_profile}, "budgets": self.budgets, "validationCommands": list(self.validation_commands), "requiredOutputArtifacts": list(self.required_output_artifacts), "benchmarkConfiguration": dict(sorted(self.benchmark_configuration.items())), "repositoryInstructions": list(self.repository_instructions)}

    def canonical_json(self) -> str: return _canonical(self.to_dict())
    @property
    def digest(self) -> str: return "sha256:" + hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()

    @classmethod
    def from_dict(cls, value: Any) -> "AgentRunSpec":
        _no_secrets(value)
        data = _mapping(value, "run spec", {"formatVersion", "runId", "instance", "objective", "statePack", "capabilities", "backend", "model", "authenticationRouteClass", "toolPolicy", "approval", "sandbox", "budgets", "validationCommands", "requiredOutputArtifacts", "benchmarkConfiguration", "repositoryInstructions"})
        if data["formatVersion"] != AGENT_RUN_SPEC_FORMAT: raise ValueError("run spec has an invalid formatVersion")
        instance = _mapping(data["instance"], "instance", {"id", "sourceRevision"}); pack = _mapping(data["statePack"], "statePack", {"reference", "digest"})
        caps = _mapping(data["capabilities"], "capabilities", {"required", "optional"}); backend = _mapping(data["backend"], "backend", {"id", "adapter"}); adapter = _mapping(backend["adapter"], "adapter", {"id", "version"})
        tool = _mapping(data["toolPolicy"], "toolPolicy", {"permittedCapabilities"}); approval = _mapping(data["approval"], "approval", {"reference", "requiredLevel"}); sandbox = _mapping(data["sandbox"], "sandbox", {"profile"})
        if not isinstance(caps["required"], list): raise ValueError("capabilities.required must be a list")
        required = []
        for item in caps["required"]:
            req = _mapping(item, "required capability", {"id", "allowPartial"})
            if not isinstance(req["allowPartial"], bool): raise ValueError("allowPartial must be boolean")
            required.append(CapabilityRequest(req["id"], req["allowPartial"]))
        if approval["reference"] is not None and not isinstance(approval["reference"], str): raise ValueError("approval.reference must be string or null")
        if approval["requiredLevel"] is not None and not isinstance(approval["requiredLevel"], str): raise ValueError("approval.requiredLevel must be string or null")
        return cls(data["runId"], instance["id"], instance["sourceRevision"], data["objective"], pack["reference"], pack["digest"], tuple(required), _strings(caps["optional"], "capabilities.optional"), backend["id"], adapter["id"], adapter["version"], data["model"], data["authenticationRouteClass"], _strings(tool["permittedCapabilities"], "toolPolicy.permittedCapabilities"), sandbox["profile"], _budget(data["budgets"]), _strings(data["validationCommands"], "validationCommands"), _strings(data["requiredOutputArtifacts"], "requiredOutputArtifacts", path_safe=True), dict(data["benchmarkConfiguration"]), approval["reference"], approval["requiredLevel"], _strings(data["repositoryInstructions"], "repositoryInstructions"))


def negotiate(spec: AgentRunSpec, capabilities: BackendCapabilities) -> dict[str, Any]:
    """Negotiate capabilities without treating unknown or partial as support."""
    if (spec.backend_id, spec.adapter_id, spec.adapter_version) != (capabilities.backend_id, capabilities.adapter_id, capabilities.adapter_version):
        raise ValueError("adapter identity/version does not match the RunSpec")
    if spec.authentication_route_class not in capabilities.authentication_route_classes:
        raise ValueError("authentication route class is not supported by adapter")
    excess = set(capabilities.adapter_permissions) - set(spec.permitted_capabilities)
    if excess: raise ValueError("adapter permissions exceed the RunSpec")
    accepted: list[str] = []; rejected: list[dict[str, str]] = []; degraded: list[dict[str, str]] = []
    for request in spec.required_capabilities:
        status = capabilities.capabilities.get(request.name, "unknown")
        if status in {"native", "supported"} or (status in {"emulated", "partial"} and request.allow_partial): accepted.append(request.name)
        else: rejected.append({"id": request.name, "status": status, "reason": "required capability is not fully supported"})
    for name in spec.optional_capabilities:
        status = capabilities.capabilities.get(name, "unknown")
        if status in {"native", "supported"}: accepted.append(name)
        else: degraded.append({"id": name, "status": status, "reason": "optional capability unavailable or partial"})
    return {"formatVersion": "stateport.capability-negotiation/v1", "accepted": sorted(accepted), "rejected": rejected, "degraded": degraded, "acceptedRun": not rejected, "adapter": {"id": capabilities.adapter_id, "version": capabilities.adapter_version}}


def require_accepted(spec: AgentRunSpec, capabilities: BackendCapabilities) -> dict[str, Any]:
    result = negotiate(spec, capabilities)
    if not result["acceptedRun"]: raise ValueError("capability negotiation rejected the RunSpec")
    return result


def validate_run_result(value: Any, spec: AgentRunSpec) -> dict[str, Any]:
    _no_secrets(value)
    data = _mapping(value, "run result", {"formatVersion", "runId", "runSpecDigest", "backend", "model", "authenticationRouteClass", "statePack", "toolPolicy", "sandbox", "executionStatus", "verificationStatus", "timestamps", "failureClassification", "terminationClassification", "usage", "changedFiles", "validationOutcomes", "producedArtifacts", "approvalReference", "auditReferences", "warnings", "degradations"})
    if data["formatVersion"] != RUN_RESULT_FORMAT: raise ValueError("run result has an invalid formatVersion")
    if data["runId"] != spec.run_id or data["runSpecDigest"] != spec.digest: raise ValueError("run result is not bound to this exact RunSpec")
    if data["terminationClassification"] not in TERMINATION_CLASSIFICATIONS:
        raise ValueError("run result termination classification is invalid")
    # Worker termination and the logical run outcome are separate facts.  A
    # worker may exit successfully after returning a typed rejection,
    # approval requirement, or failed validation.  The inverse is not safe:
    # an abnormal worker termination must always retain a failure class.
    if (
        data["terminationClassification"] != "success"
        and data["failureClassification"] is None
    ):
        raise ValueError("non-successful termination requires a failure classification")
    backend = _mapping(data["backend"], "result backend", {"id", "adapter"}); adapter = _mapping(backend["adapter"], "result adapter", {"id", "version"})
    if (backend["id"], adapter["id"], adapter["version"]) != (spec.backend_id, spec.adapter_id, spec.adapter_version): raise ValueError("run result backend identity does not match RunSpec")
    pack = _mapping(data["statePack"], "result statePack", {"reference", "digest"})
    if pack["reference"] != spec.statepack_reference or pack["digest"] != spec.statepack_digest: raise ValueError("run result StatePack identity does not match RunSpec")
    usage = _mapping(data["usage"], "usage", {"token", "cost"})
    for item in usage.values():
        entry = _mapping(item, "usage metric", {"quality", "value"})
        if entry["quality"] not in USAGE_QUALITIES or (entry["quality"] == "unavailable" and entry["value"] is not None): raise ValueError("usage telemetry is dishonest")
    if data["executionStatus"] == "exported_for_external_execution" and data["verificationStatus"] != "result_unverified": raise ValueError("portable export must be unverified")
    return dict(data)


def portable_export(spec: AgentRunSpec) -> dict[str, Any]:
    """Emit a manual handoff with no claim of StatePort host execution."""
    return {"formatVersion": "stateport.portable-run-export/v1", "status": "exported_for_external_execution", "verificationStatus": "result_unverified", "runSpec": spec.to_dict(), "runSpecDigest": spec.digest, "statePack": {"reference": spec.statepack_reference, "digest": spec.statepack_digest}, "repositoryInstructions": list(spec.repository_instructions), "validationRequirements": list(spec.validation_commands), "expectedResultContract": RUN_RESULT_FORMAT, "limitations": ["StatePort did not execute an agent", "StatePort did not observe tools", "StatePort did not enforce host approvals", "StatePort did not measure host usage"]}
