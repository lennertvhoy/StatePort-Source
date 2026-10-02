"""Strict, immutable wire contracts for governed portable agent work.

These declarations record intent and evidence.  They deliberately do not start
hosts, persist a journal, select a provider, or grant a capability.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any, Mapping


_SECRET = re.compile(r"(?:api[_-]?key|authorization|cookie|credential|password|secret|access[_-]?token|refresh[_-]?token|private[_-]?key)", re.I)
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40,64}$")
_MODES = frozenset({"agent_native", "assisted", "managed"})
_SIDE_EFFECTS = frozenset({"none", "idempotent", "compensated", "external", "filesystem_transaction", "unknown"})
_CAPABILITY_STATUS = frozenset({"native", "supported", "partial", "unsupported", "unavailable", "environment_gated"})
_OBSERVATION_QUALITY = frozenset({"observed", "reported", "inferred", "unavailable"})
_AUTHENTICATION_ROUTE_CLASSES = frozenset({"operator_authenticated", "service_identity", "anonymous", "not_applicable", "unavailable"})
_AUTHENTICATION_OWNER_CLASSES = frozenset({"operator", "organization", "service", "none", "unavailable"})
_EVENT_TYPES = frozenset({
    "run.started", "session.created", "message.delta", "command.started",
    "command.completed", "file.changed", "approval.requested", "usage.updated",
    "run.completed", "run.failed", "run.cancelled",
})
NORMALIZED_AGENT_EVENT_TYPES = _EVENT_TYPES
_OUTCOME = frozenset({"pending", "passed", "failed", "not_run", "not_applicable"})


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def canonical_digest(value: Any) -> str:
    """Return a stable sha256 digest of JSON-compatible contract data."""
    if hasattr(value, "to_dict"):
        value = value.to_dict()
    return "sha256:" + sha256(_canonical(value).encode("utf-8")).hexdigest()


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def _mapping(value: Any, name: str, keys: set[str], *, optional: set[str] | None = None) -> Mapping[str, Any]:
    optional = optional or set()
    if not isinstance(value, Mapping) or not set(value).issubset(keys | optional) or not keys.issubset(value):
        raise ValueError(f"{name} has an invalid shape")
    return value


def _string(value: Any, name: str, *, limit: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f"{name} must be a non-empty bounded string")
    return value


def _id(value: Any, name: str) -> str:
    value = _string(value, name, limit=128)
    if not _ID.fullmatch(value):
        raise ValueError(f"{name} has invalid characters")
    return value


def _digest(value: Any, name: str) -> str:
    value = _string(value, name, limit=71)
    if not _SHA.fullmatch(value):
        raise ValueError(f"{name} must be a sha256 digest")
    return value


def _git_sha(value: Any, name: str) -> str:
    value = _string(value, name, limit=64)
    if not _GIT_SHA.fullmatch(value):
        raise ValueError(f"{name} must be an immutable Git SHA")
    return value


def _path(value: Any, name: str) -> str:
    value = _string(value, name)
    path = Path(value)
    if path.is_absolute() or "\\" in value or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"{name} must be a repository-relative non-traversing path")
    return value


def _strings(value: Any, name: str, *, paths: bool = False, nonempty: bool = False, limit: int = 128) -> tuple[str, ...]:
    if not isinstance(value, list) or (nonempty and not value) or len(value) > limit:
        raise ValueError(f"{name} must be a bounded list" + (" with at least one item" if nonempty else ""))
    result = tuple(_path(item, name) if paths else _string(item, name) for item in value)
    if len(set(result)) != len(result):
        raise ValueError(f"{name} must not contain duplicates")
    return result


def _no_secrets(value: Any, location: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{location} keys must be strings")
            if _SECRET.search(key):
                raise ValueError(f"credential-like field is forbidden at {location}.{key}")
            _no_secrets(item, f"{location}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _no_secrets(item, f"{location}[{index}]")


def _budget(value: Any, name: str = "budgets") -> Mapping[str, int]:
    data = _mapping(value, name, {"token", "costMinor", "timeSeconds", "steps"})
    for key, amount in data.items():
        if isinstance(amount, bool) or not isinstance(amount, int) or amount < 0:
            raise ValueError(f"{name}.{key} must be a non-negative integer")
    return data


def _command(value: Any, name: str) -> Mapping[str, Any]:
    data = _mapping(value, name, {"command", "timeoutSeconds"})
    _strings(data["command"], f"{name}.command", nonempty=True, limit=32)
    if isinstance(data["timeoutSeconds"], bool) or not isinstance(data["timeoutSeconds"], int) or data["timeoutSeconds"] <= 0:
        raise ValueError(f"{name}.timeoutSeconds must be a positive integer")
    return data


def _outcome(value: Any, name: str) -> Mapping[str, Any]:
    data = _mapping(value, name, {"status", "evidence"})
    if data["status"] not in _OUTCOME:
        raise ValueError(f"{name}.status is invalid")
    _strings(data["evidence"], f"{name}.evidence", paths=True)
    return data


class _Contract:
    FORMAT = ""

    def __init__(self, data: Mapping[str, Any]) -> None:
        self._data = _freeze(data)

    def to_dict(self) -> dict[str, Any]:
        return _thaw(self._data)

    def canonical_json(self) -> str:
        return _canonical(self.to_dict())

    @property
    def digest(self) -> str:
        return canonical_digest(self)

    @classmethod
    def from_dict(cls, value: Any):
        _no_secrets(value)
        data = cls._validate(value)
        return cls(data)

    parse = from_dict


class WorkflowDeclaration(_Contract):
    """Template-owned workflow semantics, intentionally independent of a run profile."""

    FORMAT = "stateport.workflow/v1"

    @classmethod
    def _validate(cls, value: Any) -> Mapping[str, Any]:
        data = _mapping(value, "workflow declaration", {"formatVersion", "id", "task", "preflight", "execution", "verify", "failure", "closure"}, optional={"profileReferences"})
        if data["formatVersion"] != cls.FORMAT:
            raise ValueError("workflow declaration has an invalid formatVersion")
        _id(data["id"], "workflow id")
        task = _mapping(data["task"], "workflow task", {"kind"})
        _id(task["kind"], "workflow task.kind")
        _command(data["preflight"], "workflow preflight")
        execution = _mapping(data["execution"], "workflow execution", {"supportedModes", "defaultMode"})
        modes = _strings(execution["supportedModes"], "workflow execution.supportedModes", nonempty=True)
        if any(mode not in _MODES for mode in modes) or execution["defaultMode"] not in modes:
            raise ValueError("workflow execution modes are invalid")
        _command(data["verify"], "workflow verify")
        failure = _mapping(data["failure"], "workflow failure", {"defaultAction", "sideEffectClass", "automaticRetryAllowed"})
        if failure["defaultAction"] != "report_and_stop" or failure["sideEffectClass"] not in _SIDE_EFFECTS or not isinstance(failure["automaticRetryAllowed"], bool):
            raise ValueError("workflow failure is invalid")
        if failure["automaticRetryAllowed"] and failure["sideEffectClass"] not in {"none", "idempotent"}:
            raise ValueError("automatic retries require a safe side-effect class")
        closure = _mapping(data["closure"], "workflow closure", {"requireCleanWorktree", "requireReceipt"})
        if closure != {"requireCleanWorktree": True, "requireReceipt": True}:
            raise ValueError("workflow closure requires a clean worktree and receipt")
        if "profileReferences" in data:
            refs = _mapping(data["profileReferences"], "workflow profileReferences", set(), optional={"runtime", "context", "agent"})
            if not refs:
                raise ValueError("workflow profileReferences cannot be empty")
            for kind, ref in refs.items():
                _string(ref, f"workflow profileReferences.{kind}")
        return data


class TaskManifest(_Contract):
    FORMAT = "stateport.task-manifest/v1"

    @classmethod
    def _validate(cls, value: Any) -> Mapping[str, Any]:
        required = {"formatVersion", "jobId", "taskId", "identity", "requestedMode", "repository", "instance", "baseSha", "allowedPaths", "ownership", "inputs", "preflight", "execution", "verification", "outputs", "failure", "budgets", "sideEffects", "closure"}
        data = _mapping(value, "task manifest", required)
        if data["formatVersion"] != cls.FORMAT:
            raise ValueError("task manifest has an invalid formatVersion")
        _id(data["jobId"], "jobId"); _id(data["taskId"], "taskId")
        identity = _mapping(data["identity"], "task identity", set(), optional={"application", "action", "developmentWorkflow"})
        application_action = {"application", "action"}.issubset(identity)
        development = "developmentWorkflow" in identity
        if application_action == development or (application_action and set(identity) != {"application", "action"}) or (development and set(identity) != {"developmentWorkflow"}):
            raise ValueError("task identity requires application+action or developmentWorkflow exactly")
        for key, item in identity.items(): _id(item, f"task identity.{key}")
        if data["requestedMode"] not in _MODES: raise ValueError("requestedMode is invalid")
        repository = _mapping(data["repository"], "repository", {"id", "digest"})
        _id(repository["id"], "repository.id"); _digest(repository["digest"], "repository.digest")
        instance = _mapping(data["instance"], "instance", {"id", "digest"})
        _id(instance["id"], "instance.id"); _digest(instance["digest"], "instance.digest")
        _git_sha(data["baseSha"], "baseSha")
        allowed = _strings(data["allowedPaths"], "allowedPaths", paths=True, nonempty=True)
        ownership = data["ownership"]
        if not isinstance(ownership, Mapping) or not ownership: raise ValueError("ownership must be a non-empty mapping")
        for path, owner in ownership.items():
            _path(path, "ownership path"); _id(owner, "ownership owner")
        if not set(ownership).issubset(allowed): raise ValueError("ownership paths must be allowed paths")
        inputs = data["inputs"]
        if not isinstance(inputs, list) or len(inputs) > 128: raise ValueError("inputs must be a bounded array")
        seen_inputs: set[str] = set()
        for item in inputs:
            input_data = _mapping(item, "typed input", {"name", "type", "required"}, optional={"valueDigest"})
            name = _id(input_data["name"], "input.name")
            if name in seen_inputs: raise ValueError("input names must be unique")
            seen_inputs.add(name); _id(input_data["type"], "input.type")
            if not isinstance(input_data["required"], bool): raise ValueError("input.required must be boolean")
            if "valueDigest" in input_data: _digest(input_data["valueDigest"], "input.valueDigest")
        _command(data["preflight"], "task preflight")
        execution = _mapping(data["execution"], "task execution", {"requirements"})
        _strings(execution["requirements"], "task execution.requirements", nonempty=True)
        _command(data["verification"], "task verification")
        outputs = data["outputs"]
        if not isinstance(outputs, list) or not outputs or len(outputs) > 128: raise ValueError("outputs must be a non-empty bounded array")
        for item in outputs:
            output = _mapping(item, "output", {"name", "path", "type"})
            _id(output["name"], "output.name"); _path(output["path"], "output.path"); _id(output["type"], "output.type")
        failure = _mapping(data["failure"], "task failure", {"action", "rollbackRequired"})
        if failure["action"] != "report_and_stop" or not isinstance(failure["rollbackRequired"], bool): raise ValueError("task failure must report and stop")
        _budget(data["budgets"])
        if not isinstance(data["sideEffects"], list): raise ValueError("sideEffects must be an array")
        for item in data["sideEffects"]:
            effect = _mapping(item, "side effect", {"id", "classification", "automaticRetryAllowed", "approvalRequired"})
            _id(effect["id"], "side effect id")
            if effect["classification"] not in _SIDE_EFFECTS or not isinstance(effect["automaticRetryAllowed"], bool) or not isinstance(effect["approvalRequired"], bool): raise ValueError("side effect is invalid")
            if effect["automaticRetryAllowed"] and effect["classification"] not in {"none", "idempotent"}: raise ValueError("unsafe automatic retry is forbidden")
        closure = _mapping(data["closure"], "task closure", {"requireCleanWorktree", "requireReceipt"})
        if closure != {"requireCleanWorktree": True, "requireReceipt": True}: raise ValueError("task closure requirements are mandatory")
        return data


class RuntimeProfile(_Contract):
    FORMAT = "stateport.runtime-profile/v1"

    @classmethod
    def _validate(cls, value: Any) -> Mapping[str, Any]:
        required = {"formatVersion", "runtimeId", "mode", "harness", "adapter", "provider", "reasoning", "authentication", "toolContract", "sandbox", "network", "environmentAllowlist", "budgets", "resume", "capabilityRequirements", "degradations"}
        data = _mapping(value, "runtime profile", required)
        if data["formatVersion"] != cls.FORMAT: raise ValueError("runtime profile has an invalid formatVersion")
        _id(data["runtimeId"], "runtimeId")
        if data["mode"] not in _MODES: raise ValueError("runtime mode is invalid")
        for name in ("harness", "adapter"):
            item = _mapping(data[name], name, {"id", "version"}); _id(item["id"], f"{name}.id"); _string(item["version"], f"{name}.version")
        provider = _mapping(data["provider"], "provider", {"id", "model"}); _id(provider["id"], "provider.id"); _string(provider["model"], "provider.model")
        reasoning = _mapping(data["reasoning"], "reasoning", {"classification"}); _id(reasoning["classification"], "reasoning.classification")
        auth = _mapping(data["authentication"], "authentication", {"classification", "owner"}); _id(auth["classification"], "authentication.classification"); _id(auth["owner"], "authentication.owner")
        tools = _mapping(data["toolContract"], "toolContract", {"allowed", "denied"})
        allowed = _strings(tools["allowed"], "toolContract.allowed"); denied = _strings(tools["denied"], "toolContract.denied")
        if set(allowed) & set(denied): raise ValueError("tool contract cannot both allow and deny a tool")
        sandbox = _mapping(data["sandbox"], "sandbox", {"profile", "filesystem"}); _id(sandbox["profile"], "sandbox.profile"); _id(sandbox["filesystem"], "sandbox.filesystem")
        network = _mapping(data["network"], "network", {"policy", "allowlist"})
        if network["policy"] not in {"disabled", "allowlisted", "enabled", "unproven"}: raise ValueError("network policy is invalid")
        allowlist = _strings(network["allowlist"], "network.allowlist")
        if network["policy"] == "disabled" and allowlist: raise ValueError("disabled network cannot have an allowlist")
        if network["policy"] == "allowlisted" and not allowlist: raise ValueError("allowlisted network requires entries")
        if network["policy"] == "unproven" and allowlist: raise ValueError("unproven network isolation cannot claim an enforced allowlist")
        _strings(data["environmentAllowlist"], "environmentAllowlist")
        _budget(data["budgets"])
        resume = _mapping(data["resume"], "resume", {"supported", "strategy"})
        if not isinstance(resume["supported"], bool) or resume["strategy"] not in {"none", "best_effort", "required"} or (not resume["supported"] and resume["strategy"] != "none"): raise ValueError("resume is invalid")
        requirements = data["capabilityRequirements"]
        if not isinstance(requirements, Mapping): raise ValueError("capabilityRequirements must be an object")
        for capability, status in requirements.items():
            _id(capability, "capability requirement");
            if status not in _CAPABILITY_STATUS: raise ValueError("capability requirement status is invalid")
        _strings(data["degradations"], "degradations")
        return data


class ContextManifest(_Contract):
    FORMAT = "stateport.context-manifest/v1"

    @classmethod
    def _validate(cls, value: Any) -> Mapping[str, Any]:
        required = {"formatVersion", "contextId", "canonicalSources", "generatedSources", "includedCategories", "excludedCategories", "provenance", "hashes", "redactions", "summaries", "budgetDecisions", "authorityClassification"}
        data = _mapping(value, "context manifest", required)
        if data["formatVersion"] != cls.FORMAT: raise ValueError("context manifest has an invalid formatVersion")
        _id(data["contextId"], "contextId")
        for name in ("canonicalSources", "generatedSources"):
            sources = data[name]
            if not isinstance(sources, list) or len(sources) > 128: raise ValueError(f"{name} must be a bounded array")
            for item in sources:
                source = _mapping(item, "context source", {"id", "path", "digest", "authority"})
                _id(source["id"], "source.id"); _path(source["path"], "source.path"); _digest(source["digest"], "source.digest"); _id(source["authority"], "source.authority")
        if not data["canonicalSources"]: raise ValueError("at least one canonical source is required")
        included = _strings(data["includedCategories"], "includedCategories", nonempty=True)
        excluded = _strings(data["excludedCategories"], "excludedCategories")
        if set(included) & set(excluded): raise ValueError("context categories cannot be both included and excluded")
        provenance = data["provenance"]
        if not isinstance(provenance, Mapping) or not provenance: raise ValueError("provenance must be a non-empty mapping")
        for source_id, origin in provenance.items(): _id(source_id, "provenance source id"); _string(origin, "provenance origin")
        hashes = data["hashes"]
        if not isinstance(hashes, Mapping) or not hashes: raise ValueError("hashes must be a non-empty mapping")
        for source_id, digest in hashes.items(): _id(source_id, "hash source id"); _digest(digest, "hash digest")
        _strings(data["redactions"], "redactions")
        summaries = data["summaries"]
        if not isinstance(summaries, list) or len(summaries) > 128: raise ValueError("summaries must be a bounded array")
        for item in summaries:
            summary = _mapping(item, "summary", {"sourceId", "digest"}); _id(summary["sourceId"], "summary.sourceId"); _digest(summary["digest"], "summary.digest")
        decisions = _mapping(data["budgetDecisions"], "budgetDecisions", {"tokenBudget", "estimatedTokens", "decision"})
        for key in ("tokenBudget", "estimatedTokens"):
            if isinstance(decisions[key], bool) or not isinstance(decisions[key], int) or decisions[key] < 0: raise ValueError(f"budgetDecisions.{key} is invalid")
        if decisions["estimatedTokens"] > decisions["tokenBudget"] or decisions["decision"] not in {"accepted", "truncated", "rejected"}: raise ValueError("context budget decision is invalid")
        if data["authorityClassification"] not in {"canonical", "generated", "mixed"}: raise ValueError("authorityClassification is invalid")
        return data


class AgentProfile(_Contract):
    FORMAT = "stateport.agent-profile/v1"

    @classmethod
    def _validate(cls, value: Any) -> Mapping[str, Any]:
        required = {"formatVersion", "agentId", "role", "task", "tools", "permissions", "procedures", "output", "closure", "degradations"}
        data = _mapping(value, "agent profile", required)
        if data["formatVersion"] != cls.FORMAT: raise ValueError("agent profile has an invalid formatVersion")
        _id(data["agentId"], "agentId"); _id(data["role"], "role")
        task = _mapping(data["task"], "agent task", {"kind", "instructions"}); _id(task["kind"], "agent task.kind"); _strings(task["instructions"], "agent task.instructions", nonempty=True)
        _strings(data["tools"], "agent tools")
        permissions = _mapping(data["permissions"], "agent permissions", {"requested", "prohibited"})
        requested = _strings(permissions["requested"], "permissions.requested"); prohibited = _strings(permissions["prohibited"], "permissions.prohibited")
        if set(requested) & set(prohibited): raise ValueError("agent permissions conflict")
        _strings(data["procedures"], "agent procedures", nonempty=True)
        output = _mapping(data["output"], "agent output", {"format", "requiredFields"}); _string(output["format"], "output.format"); _strings(output["requiredFields"], "output.requiredFields", nonempty=True)
        closure = _mapping(data["closure"], "agent closure", {"requireVerification", "requireReceipt"})
        if closure != {"requireVerification": True, "requireReceipt": True}: raise ValueError("agent closure requirements are mandatory")
        _strings(data["degradations"], "agent degradations")
        return data


class AgentEvent(_Contract):
    FORMAT = "stateport.agent-event/v1"

    @classmethod
    def _validate(cls, value: Any) -> Mapping[str, Any]:
        required = {"formatVersion", "eventId", "jobId", "attemptId", "runId", "producer", "sequence", "eventType", "timestamp", "payload", "redactionResult", "observationQuality"}
        data = _mapping(value, "agent event", required)
        if data["formatVersion"] != cls.FORMAT: raise ValueError("agent event has an invalid formatVersion")
        for key in ("eventId", "jobId", "attemptId", "runId"): _id(data[key], key)
        producer = _mapping(data["producer"], "event producer", {"id", "kind", "version"})
        _id(producer["id"], "producer.id"); _id(producer["kind"], "producer.kind"); _string(producer["version"], "producer.version")
        if isinstance(data["sequence"], bool) or not isinstance(data["sequence"], int) or data["sequence"] < 0: raise ValueError("sequence must be a non-negative integer")
        if data["eventType"] not in _EVENT_TYPES: raise ValueError("eventType is not a normalized vocabulary member")
        if not isinstance(data["timestamp"], str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T[^\n]+Z", data["timestamp"]): raise ValueError("timestamp must be UTC RFC3339-like")
        payload = _mapping(data["payload"], "event payload", {"summary", "attributes"})
        _string(payload["summary"], "payload.summary", limit=4096)
        if not isinstance(payload["attributes"], Mapping) or len(payload["attributes"]) > 32: raise ValueError("payload.attributes must be bounded")
        for key, item in payload["attributes"].items():
            _id(key, "payload attribute key")
            if not isinstance(item, (str, int, float, bool, type(None))) or (isinstance(item, str) and len(item) > 1024): raise ValueError("payload attributes must be bounded scalar observations")
        if len(_canonical(payload).encode("utf-8")) > 16384: raise ValueError("payload exceeds the 16KiB event bound")
        redaction = _mapping(data["redactionResult"], "redactionResult", {"status", "categories"})
        if redaction["status"] not in {"not_needed", "applied", "unavailable"}: raise ValueError("redactionResult.status is invalid")
        _strings(redaction["categories"], "redactionResult.categories")
        if data["observationQuality"] not in _OBSERVATION_QUALITY: raise ValueError("observationQuality is invalid")
        return data


class RunReceipt(_Contract):
    FORMAT = "stateport.run-receipt/v1"

    @classmethod
    def _validate(cls, value: Any) -> Mapping[str, Any]:
        required = {"formatVersion", "runId", "parentJobId", "attemptId", "taskId", "baseGit", "finalGit", "mode", "runtimeIdentity", "capabilityNegotiation", "digests", "references", "preflight", "journal", "attemptChain", "first", "eventual", "verification", "fileChanges", "permissions", "approvals", "usage", "sideEffects", "rollback", "closure", "evidence"}
        data = _mapping(value, "run receipt", required)
        if data["formatVersion"] != cls.FORMAT: raise ValueError("run receipt has an invalid formatVersion")
        for key in ("runId", "parentJobId", "attemptId", "taskId"): _id(data[key], key)
        _git_sha(data["baseGit"], "baseGit"); _git_sha(data["finalGit"], "finalGit")
        if data["mode"] not in _MODES: raise ValueError("receipt mode is invalid")
        runtime_identity = _mapping(data["runtimeIdentity"], "runtimeIdentity", {"harness", "adapter", "provider", "model", "authenticationRoute"})
        for name in ("harness", "adapter"):
            component = _mapping(runtime_identity[name], f"runtimeIdentity.{name}", {"id", "version", "classification"})
            _id(component["id"], f"runtimeIdentity.{name}.id")
            _string(component["version"], f"runtimeIdentity.{name}.version", limit=128)
            _id(component["classification"], f"runtimeIdentity.{name}.classification")
        for name in ("provider", "model"):
            component = _mapping(runtime_identity[name], f"runtimeIdentity.{name}", {"id", "classification"})
            _id(component["id"], f"runtimeIdentity.{name}.id")
            _id(component["classification"], f"runtimeIdentity.{name}.classification")
        authentication_route = _mapping(runtime_identity["authenticationRoute"], "runtimeIdentity.authenticationRoute", {"classification", "ownerClassification"})
        if authentication_route["classification"] not in _AUTHENTICATION_ROUTE_CLASSES or authentication_route["ownerClassification"] not in _AUTHENTICATION_OWNER_CLASSES:
            raise ValueError("runtimeIdentity.authenticationRoute is invalid")
        negotiation = _mapping(data["capabilityNegotiation"], "capabilityNegotiation", {"requested", "effective", "unavailable", "acceptedDegradations", "observationQuality"})
        requested = _strings(negotiation["requested"], "capabilityNegotiation.requested")
        effective = _strings(negotiation["effective"], "capabilityNegotiation.effective")
        unavailable = _strings(negotiation["unavailable"], "capabilityNegotiation.unavailable")
        if not set(effective).issubset(requested) or not set(unavailable).issubset(requested) or set(effective) & set(unavailable):
            raise ValueError("capabilityNegotiation must partition requested capabilities")
        degradations = negotiation["acceptedDegradations"]
        if not isinstance(degradations, list) or len(degradations) > 128:
            raise ValueError("capabilityNegotiation.acceptedDegradations must be a bounded array")
        degraded_capabilities: set[str] = set()
        for item in degradations:
            degradation = _mapping(item, "accepted degradation", {"capability", "reason"})
            capability = _id(degradation["capability"], "accepted degradation.capability")
            _id(degradation["reason"], "accepted degradation.reason")
            if capability in degraded_capabilities:
                raise ValueError("accepted degradation capabilities must be unique")
            degraded_capabilities.add(capability)
        if not degraded_capabilities.issubset(unavailable):
            raise ValueError("accepted degradations must reference unavailable capabilities")
        if negotiation["observationQuality"] not in _OBSERVATION_QUALITY:
            raise ValueError("capabilityNegotiation.observationQuality is invalid")
        digests = _mapping(data["digests"], "receipt digests", {"workflowDeclaration", "taskManifest", "runtimeProfile", "contextManifest", "agentProfile", "agentRunSpec", "eventJournal"})
        for key, digest in digests.items(): _digest(digest, f"digests.{key}")
        references = _mapping(data["references"], "receipt references", {"runResult", "runBundle"})
        for key, reference in references.items():
            ref = _mapping(reference, f"reference {key}", {"id", "digest"}); _id(ref["id"], f"reference {key}.id"); _digest(ref["digest"], f"reference {key}.digest")
        for key in ("preflight", "first", "eventual", "verification"): _outcome(data[key], key)
        journal = _mapping(data["journal"], "journal", {"eventCount", "digest"})
        if isinstance(journal["eventCount"], bool) or not isinstance(journal["eventCount"], int) or journal["eventCount"] < 0: raise ValueError("journal.eventCount is invalid")
        _digest(journal["digest"], "journal.digest")
        chain = data["attemptChain"]
        if not isinstance(chain, list) or not chain or len(chain) > 32:
            raise ValueError("attemptChain must contain one to thirty-two explicit attempts")
        attempt_ids: set[str] = set()
        for ordinal, item in enumerate(chain, start=1):
            attempt = _mapping(item, "attemptChain item", {"attemptId", "ordinal", "operation", "classification", "result", "automatic", "evidence"})
            identifier = _id(attempt["attemptId"], "attemptChain.attemptId")
            if identifier in attempt_ids or attempt["ordinal"] != ordinal:
                raise ValueError("attemptChain identities must be unique and ordinals contiguous")
            attempt_ids.add(identifier)
            _id(attempt["operation"], "attemptChain.operation")
            if attempt["classification"] not in {"completed", "failed", "cancelled", "interrupted", "timed_out"}:
                raise ValueError("attemptChain classification is invalid")
            if attempt["result"] not in {"passed", "failed"} or ((attempt["classification"] == "completed") != (attempt["result"] == "passed")):
                raise ValueError("attemptChain result contradicts its classification")
            if not isinstance(attempt["automatic"], bool) or attempt["automatic"]:
                raise ValueError("this receipt version permits only explicit non-automatic attempts")
            _strings(attempt["evidence"], "attemptChain.evidence", paths=True, nonempty=True)
        if data["first"]["status"] != chain[0]["result"] or data["eventual"]["status"] != chain[-1]["result"]:
            raise ValueError("first and eventual outcomes must match the explicit attemptChain")
        changes = _mapping(data["fileChanges"], "fileChanges", {"changedPaths", "allowed", "digest"})
        _strings(changes["changedPaths"], "fileChanges.changedPaths", paths=True)
        if not isinstance(changes["allowed"], bool): raise ValueError("fileChanges.allowed must be boolean")
        _digest(changes["digest"], "fileChanges.digest")
        permissions = _mapping(data["permissions"], "permissions", {"requested", "effective"})
        _strings(permissions["requested"], "permissions.requested"); _strings(permissions["effective"], "permissions.effective")
        approvals = _mapping(data["approvals"], "approvals", {"required", "references"})
        if not isinstance(approvals["required"], bool): raise ValueError("approvals.required must be boolean")
        _strings(approvals["references"], "approvals.references")
        usage = _mapping(data["usage"], "usage", {"availability", "token", "costMinor"})
        if usage["availability"] not in {"exact", "approximate", "unavailable"}: raise ValueError("usage.availability is invalid")
        for key in ("token", "costMinor"):
            amount = usage[key]
            if amount is not None and (isinstance(amount, bool) or not isinstance(amount, int) or amount < 0): raise ValueError(f"usage.{key} is invalid")
        if usage["availability"] == "unavailable" and (usage["token"] is not None or usage["costMinor"] is not None): raise ValueError("unavailable usage must not invent values")
        if usage["availability"] != "unavailable" and (usage["token"] is None or usage["costMinor"] is None): raise ValueError("available usage requires both values")
        if not isinstance(data["sideEffects"], list): raise ValueError("receipt sideEffects must be an array")
        for item in data["sideEffects"]:
            effect = _mapping(item, "receipt side effect", {"id", "classification", "outcome"})
            _id(effect["id"], "receipt side effect id")
            if effect["classification"] not in _SIDE_EFFECTS or effect["outcome"] not in {"not_attempted", "completed", "failed", "unknown"}: raise ValueError("receipt side effect is invalid")
        rollback = _mapping(data["rollback"], "rollback", {"required", "status"})
        if not isinstance(rollback["required"], bool) or rollback["status"] not in {"not_required", "not_attempted", "completed", "failed"}: raise ValueError("rollback is invalid")
        closure = _mapping(data["closure"], "closure", {"status", "reason"})
        if closure["status"] not in {"open", "closed", "failed"}: raise ValueError("closure status is invalid")
        _string(closure["reason"], "closure.reason")
        _strings(data["evidence"], "evidence", paths=True)
        if closure["status"] == "closed":
            if data["preflight"]["status"] != "passed" or data["verification"]["status"] != "passed" or not changes["allowed"] or not data["evidence"]:
                raise ValueError("closed receipt requires passed gates, an allowed diff, and evidence")
        return data


def load_workflow_declaration(value: str | Path | Mapping[str, Any]) -> WorkflowDeclaration:
    """Strictly load a JSON or YAML ``stateport.workflow/v1`` declaration."""
    if isinstance(value, Mapping):
        return WorkflowDeclaration.from_dict(value)
    path = Path(value)
    text = path.read_text(encoding="utf-8") if path.exists() else str(value)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        try:
            from statedd_core.yaml import parse_yaml_text
        except ModuleNotFoundError as exc:
            raise ValueError("YAML workflow loading requires statedd_core") from exc
        data = parse_yaml_text(text)
        if isinstance(data, Mapping):
            # StateDD's deliberately small YAML reader preserves flow-style
            # sequences as scalars. Normalize only the two argv-bearing gates
            # so quoted YAML forms such as ["python3", "check.py"] retain
            # their wire meaning; ordinary scalar shell commands still fail
            # WorkflowDeclaration's strict argv validation below.
            data = dict(data)
            for gate_name in ("preflight", "verify"):
                gate = data.get(gate_name)
                if not isinstance(gate, Mapping) or not isinstance(gate.get("command"), str):
                    continue
                try:
                    argv = json.loads(gate["command"])
                except json.JSONDecodeError:
                    continue
                if isinstance(argv, list):
                    normalized_gate = dict(gate)
                    normalized_gate["command"] = argv
                    data[gate_name] = normalized_gate
    return WorkflowDeclaration.from_dict(data)
