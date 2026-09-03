"""Typed contracts for the alpha.4 local-rootless runtime slice.

These contracts describe authority and observed identity.  They do not grant a
host mount, socket, credential, network route, or process launch by themselves.
The execution host remains the enforcement point.
"""
from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any, Mapping

from .contracts import (
    _Contract,
    _digest,
    _git_sha,
    _id,
    _mapping,
    _no_secrets,
    _string,
    _strings,
)


def _bounded_int(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer in [{minimum}, {maximum}]")
    return value


def _absolute_runtime_path(value: Any, name: str) -> str:
    value = _string(value, name, limit=256)
    path = PurePosixPath(value)
    if not path.is_absolute() or "\\" in value or ".." in path.parts or "" in path.parts:
        raise ValueError(f"{name} must be an absolute non-traversing POSIX path")
    return value


def _argv(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or len(value) > 32:
        raise ValueError(f"{name} must be a bounded non-empty argv")
    result = tuple(_string(item, f"{name}[{index}]", limit=256) for index, item in enumerate(value))
    if any("\x00" in item for item in result):
        raise ValueError(f"{name} contains a NUL byte")
    return result


def _resources(value: Any, name: str = "resources") -> dict[str, int]:
    data = _mapping(value, name, {"memoryMaxBytes", "cpuQuotaPercent", "pidsMax", "diskMaxBytes"})
    return {
        "memoryMaxBytes": _bounded_int(data["memoryMaxBytes"], f"{name}.memoryMaxBytes", 16 * 1024 * 1024, 8 * 1024**3),
        "cpuQuotaPercent": _bounded_int(data["cpuQuotaPercent"], f"{name}.cpuQuotaPercent", 1, 800),
        "pidsMax": _bounded_int(data["pidsMax"], f"{name}.pidsMax", 16, 4096),
        "diskMaxBytes": _bounded_int(data["diskMaxBytes"], f"{name}.diskMaxBytes", 16 * 1024 * 1024, 1024**4),
    }


def _network(value: Any, name: str = "networkProfile", *, allow_gateway: bool = False) -> dict[str, Any]:
    data = _mapping(value, name, {"mode", "allowlist"})
    modes = {"disabled", "developer", "model-gateway-only"} if allow_gateway else {"disabled", "developer"}
    if data["mode"] not in modes:
        raise ValueError(f"{name}.mode is invalid")
    allowlist = _strings(data["allowlist"], f"{name}.allowlist")
    if data["mode"] == "disabled" and allowlist:
        raise ValueError(f"{name}.allowlist must be empty when networking is disabled")
    if data["mode"] == "model-gateway-only" and allowlist:
        raise ValueError(f"{name}.allowlist must be empty for the StatePort gateway route")
    return {"mode": data["mode"], "allowlist": list(allowlist)}


def _cache_volumes(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 16:
        raise ValueError("cacheVolumes must be a bounded array")
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in value:
        data = _mapping(item, "cache volume", {"volumeId", "mountPath", "readOnly"})
        volume_id = _id(data["volumeId"], "cache volume.volumeId")
        if volume_id in seen:
            raise ValueError("cache volume ids must be unique")
        seen.add(volume_id)
        mount = _absolute_runtime_path(data["mountPath"], "cache volume.mountPath")
        if not mount.startswith("/workspace/"):
            raise ValueError("cache volume.mountPath must be below /workspace")
        if not isinstance(data["readOnly"], bool):
            raise ValueError("cache volume.readOnly must be boolean")
        result.append({"volumeId": volume_id, "mountPath": mount, "readOnly": data["readOnly"]})
    return result


class WorkspaceSpec(_Contract):
    """Persistent, rootless developer workspace declaration."""

    FORMAT = "stateport.workspace-spec/v1"

    @classmethod
    def _validate(cls, value: Any) -> Mapping[str, Any]:
        _no_secrets(value)
        data = _mapping(
            value,
            "workspace specification",
            {"formatVersion", "workspaceId", "imageDigest", "workspacePath", "shell", "resources", "networkProfile", "cacheVolumes", "lifecyclePolicy"},
        )
        if data["formatVersion"] != cls.FORMAT:
            raise ValueError("workspace specification has an invalid formatVersion")
        workspace_id = _id(data["workspaceId"], "workspaceId")
        image_digest = _digest(data["imageDigest"], "imageDigest")
        if data["workspacePath"] != "/workspace":
            raise ValueError("workspacePath must be exactly /workspace")
        shell = _argv(data["shell"], "shell")
        resources = _resources(data["resources"])
        network = _network(data["networkProfile"])
        caches = _cache_volumes(data["cacheVolumes"])
        lifecycle = _mapping(data["lifecyclePolicy"], "lifecyclePolicy", {"idleTimeoutSeconds", "stopAfterIdle", "preserveDataOnRemove"})
        idle = _bounded_int(lifecycle["idleTimeoutSeconds"], "lifecyclePolicy.idleTimeoutSeconds", 0, 30 * 24 * 3600)
        if not isinstance(lifecycle["stopAfterIdle"], bool) or lifecycle["preserveDataOnRemove"] is not True:
            raise ValueError("workspace data must be preserved when a container is removed")
        return {
            "formatVersion": cls.FORMAT,
            "workspaceId": workspace_id,
            "imageDigest": image_digest,
            "workspacePath": "/workspace",
            "shell": list(shell),
            "resources": resources,
            "networkProfile": network,
            "cacheVolumes": caches,
            "lifecyclePolicy": {"idleTimeoutSeconds": idle, "stopAfterIdle": lifecycle["stopAfterIdle"], "preserveDataOnRemove": True},
        }


class WorkspaceRuntimeIdentity(_Contract):
    """Observed identity and state of one persistent workspace container."""

    FORMAT = "stateport.workspace-runtime-identity/v1"

    @classmethod
    def _validate(cls, value: Any) -> Mapping[str, Any]:
        _no_secrets(value)
        data = _mapping(value, "workspace runtime identity", {"formatVersion", "workspaceId", "containerId", "imageDigest", "runtimeUser", "status", "revision", "health", "observedAt"})
        if data["formatVersion"] != cls.FORMAT:
            raise ValueError("workspace runtime identity has an invalid formatVersion")
        _id(data["workspaceId"], "workspaceId")
        _id(data["containerId"], "containerId")
        _digest(data["imageDigest"], "imageDigest")
        user = _mapping(data["runtimeUser"], "runtimeUser", {"uid", "gid"})
        _bounded_int(user["uid"], "runtimeUser.uid", 1, 2**31 - 1)
        _bounded_int(user["gid"], "runtimeUser.gid", 1, 2**31 - 1)
        if data["status"] not in {"created", "running", "stopped", "recreating", "removed", "interrupted", "unavailable"}:
            raise ValueError("workspace runtime status is invalid")
        _git_sha(data["revision"], "revision")
        health = _mapping(data["health"], "workspace health", {"status", "detail"})
        if health["status"] not in {"healthy", "degraded", "unhealthy", "unknown"}:
            raise ValueError("workspace health status is invalid")
        _string(health["detail"], "workspace health.detail", limit=1024)
        _string(data["observedAt"], "observedAt", limit=64)
        return dict(data)


class AgentRunSpecification(_Contract):
    """A managed run bound to staging, a provider route, and a base revision.

    The wire format is deliberately distinct from the governed-runner
    ``stateport.agent-run-spec/v1`` job declaration: this contract is the
    alpha.4 execution binding (staging path, provider route, authority
    grant), not a benchmark/run-bundle job spec.
    """

    FORMAT = "stateport.managed-agent-run/v1"

    @classmethod
    def _validate(cls, value: Any) -> Mapping[str, Any]:
        _no_secrets(value)
        data = _mapping(value, "agent run specification", {"formatVersion", "runId", "workspaceId", "baseRevision", "stagingPath", "imageDigest", "provider", "model", "networkProfile", "authorityGrantDigest", "budgets", "resources", "validationCommands"})
        if data["formatVersion"] != cls.FORMAT:
            raise ValueError("agent run specification has an invalid formatVersion")
        for field in ("runId", "workspaceId"):
            _id(data[field], field)
        _git_sha(data["baseRevision"], "baseRevision")
        _absolute_runtime_path(data["stagingPath"], "stagingPath")
        if data["stagingPath"] == "/workspace":
            raise ValueError("agent staging must not be the persistent workspace mount")
        _digest(data["imageDigest"], "imageDigest")
        _id(data["provider"], "provider")
        _id(data["model"], "model")
        network = _network(data["networkProfile"], allow_gateway=True)
        if network["mode"] not in {"disabled", "model-gateway-only"}:
            raise ValueError("managed agent network must be disabled or StatePort-gateway-only")
        _digest(data["authorityGrantDigest"], "authorityGrantDigest")
        budgets = _mapping(data["budgets"], "agent budgets", {"timeSeconds", "token", "costMinor", "steps"})
        for key in budgets:
            _bounded_int(budgets[key], f"budgets.{key}", 0, 2**31 - 1)
        resources = _resources(data["resources"], "agent resources")
        commands = data["validationCommands"]
        if not isinstance(commands, list) or len(commands) > 16:
            raise ValueError("validationCommands must be a bounded array")
        normalized_commands = []
        for index, command in enumerate(commands):
            normalized_commands.append(list(_argv(command, f"validationCommands[{index}]")))
        return {**dict(data), "networkProfile": network, "budgets": dict(budgets), "resources": resources, "validationCommands": normalized_commands}


class ValidatorSpec(_Contract):
    """Independent validator launch declaration; all isolation is mandatory."""

    FORMAT = "stateport.validator-spec/v1"

    @classmethod
    def _validate(cls, value: Any) -> Mapping[str, Any]:
        _no_secrets(value)
        data = _mapping(value, "validator specification", {"formatVersion", "validatorId", "imageDigest", "stagingPath", "commands", "resources", "timeoutSeconds", "outputByteBound", "network", "stagingReadOnly", "providerAccess", "runtimeSocketAccess", "hostMounts"})
        if data["formatVersion"] != cls.FORMAT:
            raise ValueError("validator specification has an invalid formatVersion")
        _id(data["validatorId"], "validatorId")
        _digest(data["imageDigest"], "imageDigest")
        _absolute_runtime_path(data["stagingPath"], "stagingPath")
        if not data["stagingPath"].startswith("/"):
            raise ValueError("validator stagingPath must be absolute")
        commands = data["commands"]
        if not isinstance(commands, list) or not commands:
            raise ValueError("validator commands must be non-empty")
        normalized_commands = [list(_argv(item, f"commands[{index}]")) for index, item in enumerate(commands)]
        resources = _resources(data["resources"], "validator resources")
        if resources["memoryMaxBytes"] > 1024**3 or resources["diskMaxBytes"] > 4 * 1024**3:
            raise ValueError("validator resource limits exceed the execution-host bounds")
        timeout_seconds = _bounded_int(data["timeoutSeconds"], "timeoutSeconds", 1, 3600)
        output_byte_bound = _bounded_int(data["outputByteBound"], "outputByteBound", 1, 4 * 1024 * 1024)
        if data["network"] != "disabled":
            raise ValueError("validator network must be disabled in alpha.4")
        for field in ("stagingReadOnly", "providerAccess", "runtimeSocketAccess"):
            if data[field] is not (True if field == "stagingReadOnly" else False):
                raise ValueError(f"validator {field} violates isolation")
        if data["hostMounts"] != []:
            raise ValueError("validator host mounts must be empty")
        return {
            **dict(data),
            "commands": normalized_commands,
            "resources": resources,
            "timeoutSeconds": timeout_seconds,
            "outputByteBound": output_byte_bound,
        }


class PromotionSpec(_Contract):
    """Approval-bound, base-checked candidate promotion declaration."""

    FORMAT = "stateport.promotion-spec/v1"

    @classmethod
    def _validate(cls, value: Any) -> Mapping[str, Any]:
        _no_secrets(value)
        data = _mapping(value, "promotion specification", {"formatVersion", "promotionId", "workspaceId", "candidateId", "expectedBaseRevision", "candidateRevision", "diffDigest", "validatorEvidenceDigest", "approvalId", "rollbackPointDigest"})
        if data["formatVersion"] != cls.FORMAT:
            raise ValueError("promotion specification has an invalid formatVersion")
        for field in ("promotionId", "workspaceId", "candidateId", "approvalId"):
            _id(data[field], field)
        _git_sha(data["expectedBaseRevision"], "expectedBaseRevision")
        _git_sha(data["candidateRevision"], "candidateRevision")
        for field in ("diffDigest", "validatorEvidenceDigest", "rollbackPointDigest"):
            _digest(data[field], field)
        return dict(data)


class PromotionReceipt(_Contract):
    """Durable, append-only record of a StatePort-authoritative promotion decision.

    The flat binding fields mirror the checked ``PromotionSpec`` claims.  The
    nested sections keep the evidence categories distinct: the agent claim, the
    independently observed process result, the validator evidence, the human
    approval identity, the recorded rollback point, and the StatePort promotion
    decision are never collapsed into a single success flag.  The
    ``receiptDigest`` is the canonical digest of the receipt body excluding
    itself; it is verified on reload by the promotion service.
    """

    FORMAT = "stateport.promotion-receipt/v1"

    @classmethod
    def _validate(cls, value: Any) -> Mapping[str, Any]:
        _no_secrets(value)
        data = _mapping(
            value,
            "promotion receipt",
            {
                "formatVersion", "promotionId", "workspaceId", "candidateId",
                "expectedBaseRevision", "candidateRevision",
                "diffDigest", "validatorEvidenceDigest", "approvalId", "rollbackPointDigest",
                "specDigest", "observedAt", "receiptDigest",
                "agentClaim", "observedProcessResult", "validatorEvidence",
                "approval", "rollbackPoint", "promotionDecision",
            },
        )
        if data["formatVersion"] != cls.FORMAT:
            raise ValueError("promotion receipt has an invalid formatVersion")
        for field in ("promotionId", "workspaceId", "candidateId", "approvalId"):
            _id(data[field], field)
        _git_sha(data["expectedBaseRevision"], "expectedBaseRevision")
        _git_sha(data["candidateRevision"], "candidateRevision")
        for field in ("diffDigest", "validatorEvidenceDigest", "rollbackPointDigest", "specDigest", "receiptDigest"):
            _digest(data[field], field)
        _string(data["observedAt"], "observedAt", limit=64)
        agent_claim = _mapping(data["agentClaim"], "agentClaim", {"baseRevision", "diffDigest", "validatorEvidenceDigest"})
        _git_sha(agent_claim["baseRevision"], "agentClaim.baseRevision")
        _digest(agent_claim["diffDigest"], "agentClaim.diffDigest")
        _digest(agent_claim["validatorEvidenceDigest"], "agentClaim.validatorEvidenceDigest")
        observed = _mapping(data["observedProcessResult"], "observedProcessResult", {"currentRevision", "diffDigest", "baseRevisionMatched"})
        _git_sha(observed["currentRevision"], "observedProcessResult.currentRevision")
        _digest(observed["diffDigest"], "observedProcessResult.diffDigest")
        if not isinstance(observed["baseRevisionMatched"], bool):
            raise ValueError("observedProcessResult.baseRevisionMatched must be boolean")
        validator_evidence = _mapping(data["validatorEvidence"], "validatorEvidence", {"evidenceDigest", "validatorId", "evidenceMatched"})
        _digest(validator_evidence["evidenceDigest"], "validatorEvidence.evidenceDigest")
        _id(validator_evidence["validatorId"], "validatorEvidence.validatorId")
        if not isinstance(validator_evidence["evidenceMatched"], bool):
            raise ValueError("validatorEvidence.evidenceMatched must be boolean")
        approval = _mapping(data["approval"], "approval", {"approvalId", "status", "actor", "boundCandidateId", "approvalMatched"})
        _id(approval["approvalId"], "approval.approvalId")
        if approval["status"] not in {"approved", "rejected", "cancelled", "pending"}:
            raise ValueError("approval.status is invalid")
        _id(approval["actor"], "approval.actor")
        _id(approval["boundCandidateId"], "approval.boundCandidateId")
        if not isinstance(approval["approvalMatched"], bool):
            raise ValueError("approval.approvalMatched must be boolean")
        rollback = _mapping(data["rollbackPoint"], "rollbackPoint", {"digest", "prePromotionRevision", "rollbackPointMatched"})
        _digest(rollback["digest"], "rollbackPoint.digest")
        if rollback["prePromotionRevision"] is not None:
            _git_sha(rollback["prePromotionRevision"], "rollbackPoint.prePromotionRevision")
        if not isinstance(rollback["rollbackPointMatched"], bool):
            raise ValueError("rollbackPoint.rollbackPointMatched must be boolean")
        decision = _mapping(data["promotionDecision"], "promotionDecision", {"decision", "reason", "checks"})
        if decision["decision"] not in {"promoted", "refused"}:
            raise ValueError("promotionDecision.decision is invalid")
        _string(decision["reason"], "promotionDecision.reason", limit=1024)
        checks = _mapping(decision["checks"], "promotionDecision.checks", {"baseRevision", "approval", "diffDigest", "validatorEvidence", "rollbackPoint"})
        for key, value_ok in checks.items():
            if not isinstance(value_ok, bool):
                raise ValueError(f"promotionDecision.checks.{key} must be boolean")
        if decision["decision"] == "promoted":
            if not all(checks.values()):
                raise ValueError("a promoted receipt requires every binding check to pass")
            if approval["status"] != "approved" or not approval["approvalMatched"]:
                raise ValueError("a promoted receipt requires an approved candidate-bound approval")
        return dict(data)


class RuntimeHealthProjection(_Contract):
    """Honest control-plane projection of prerequisites and current lifecycle."""

    FORMAT = "stateport.runtime-health-projection/v1"

    @classmethod
    def _validate(cls, value: Any) -> Mapping[str, Any]:
        _no_secrets(value)
        data = _mapping(value, "runtime health projection", {"formatVersion", "executionHost", "workspace", "modelProvider", "modelGateway", "validator", "currentRun", "pendingApproval", "promotion"})
        if data["formatVersion"] != cls.FORMAT:
            raise ValueError("runtime health projection has an invalid formatVersion")
        host = _mapping(data["executionHost"], "executionHost", {"status", "socketPresent", "identity", "detail"})
        if host["status"] not in {"healthy", "degraded", "absent", "unavailable", "interrupted"} or not isinstance(host["socketPresent"], bool):
            raise ValueError("executionHost health is invalid")
        _string(host["identity"], "executionHost.identity", limit=256)
        _string(host["detail"], "executionHost.detail", limit=1024)
        for field in ("workspace", "currentRun", "pendingApproval", "promotion"):
            if data[field] is not None and not isinstance(data[field], Mapping):
                raise ValueError(f"{field} must be an object or null")
        for field in ("modelProvider", "modelGateway", "validator"):
            section = _mapping(data[field], field, {"status", "detail"})
            if section["status"] not in {"ready", "unavailable", "unverified", "failed"}:
                raise ValueError(f"{field}.status is invalid")
            _string(section["detail"], f"{field}.detail", limit=1024)
        return dict(data)


_LEASE_STATES = frozenset({"granted", "renewed", "expired", "released", "revoked"})


def _iso_timestamp(value: Any, name: str) -> str:
    value = _string(value, name, limit=64)
    if not value.endswith("Z") or "\n" in value:
        raise ValueError(f"{name} must be a bounded UTC timestamp")
    return value


class RunLease(_Contract):
    """Typed, instance-scoped lease that guards a single managed agent run.

    A lease snapshots the shared-in-flight claim for one workspace and is the
    typed surface that run lifecycle ``RunAuthority`` service and the
    idempotent shutdown path both operate against.  Its transitions are
    strictly ordered:

    ``granted -> renewed -> expired -> released`` with ``revoked`` reachable
    from any active state as a forced release.  A lease never carries a
    provider handle, token, socket path, or secret; ``claim_path`` is the
    in-run authority claim file only.
    """

    FORMAT = "stateport.run-lease/v1"

    @classmethod
    def _validate(cls, value: Any) -> Mapping[str, Any]:
        _no_secrets(value)
        data = _mapping(
            value,
            "run lease",
            {"formatVersion", "leaseId", "runId", "workspaceId", "executorKind", "imageDigest", "claimPath", "startedAt", "expiresAt", "state"},
        )
        if data["formatVersion"] != cls.FORMAT:
            raise ValueError("run lease has an invalid formatVersion")
        _id(data["leaseId"], "leaseId")
        _id(data["runId"], "runId")
        _id(data["workspaceId"], "workspaceId")
        _id(data["executorKind"], "executorKind")
        _digest(data["imageDigest"], "imageDigest")
        _absolute_runtime_path(data["claimPath"], "claimPath")
        _iso_timestamp(data["startedAt"], "startedAt")
        _iso_timestamp(data["expiresAt"], "expiresAt")
        if data["state"] not in _LEASE_STATES:
            raise ValueError("run lease state is invalid")
        return dict(data)


_EVIDENCE_OUTCOMES = frozenset({"completed", "failed", "cancelled", "refused"})


class RunEvidence(_Contract):
    """Authority-gated record that binds a managed run to its observed result.

    The flat fields bind exactly what is observable and never a credential:
    ``runId``, ``workspaceId``, ``executorKind``, ``imageDigest``,
    ``startedAt``, ``endedAt``, ``outcome``, ``exitReason``,
    ``digestOfOutput``, and ``leaseId``.  A finished run whose grant was
    revoked is recorded ``refused``, never a success; an evidence digest is
    recomputable from the fields alone (round-trip).
    """

    FORMAT = "stateport.run-evidence/v1"

    @classmethod
    def _validate(cls, value: Any) -> Mapping[str, Any]:
        _no_secrets(value)
        data = _mapping(
            value,
            "run evidence",
            {"formatVersion", "runId", "workspaceId", "executorKind", "imageDigest", "startedAt", "endedAt", "outcome", "exitReason", "digestOfOutput", "leaseId"},
            optional={"executedProcess"},
        )
        if data["formatVersion"] != cls.FORMAT:
            raise ValueError("run evidence has an invalid formatVersion")
        _id(data["runId"], "runId")
        _id(data["workspaceId"], "workspaceId")
        _id(data["executorKind"], "executorKind")
        _digest(data["imageDigest"], "imageDigest")
        _iso_timestamp(data["startedAt"], "startedAt")
        _iso_timestamp(data["endedAt"], "endedAt")
        if data["outcome"] not in _EVIDENCE_OUTCOMES:
            raise ValueError("run evidence outcome is invalid")
        _string(data["exitReason"], "exitReason", limit=1024)
        _digest(data["digestOfOutput"], "digestOfOutput")
        _id(data["leaseId"], "leaseId")
        if "executedProcess" in data:
            process = _mapping(
                data["executedProcess"],
                "executedProcess",
                {"executor", "pid", "exitCode", "durationSeconds", "digestOfOutput"},
                optional={"containerWorkloadId", "observedImageDigest"},
            )
            _id(process["executor"], "executedProcess.executor")
            if process["pid"] is not None:
                _bounded_int(process["pid"], "executedProcess.pid", 0, 2**31 - 1)
                if process["pid"] == 0:
                    raise ValueError("executedProcess.pid must belong to a real executed process")
            elif "containerWorkloadId" not in process:
                raise ValueError(
                    "executedProcess must bind a real pid or a daemon-observed container workload id"
                )
            if "containerWorkloadId" in process:
                _id(process["containerWorkloadId"], "executedProcess.containerWorkloadId")
            if "observedImageDigest" in process:
                _digest(process["observedImageDigest"], "executedProcess.observedImageDigest")
            _bounded_int(process["exitCode"], "executedProcess.exitCode", -2**16, 2**16 - 1)
            _bounded_int(process["durationSeconds"], "executedProcess.durationSeconds", 0, 2**31 - 1)
            _digest(process["digestOfOutput"], "executedProcess.digestOfOutput")
        return dict(data)


# Names used by the alpha.4 architecture brief.  Keep the canonical class
# names explicit while making the public vocabulary convenient for adapters.
PersistentWorkspaceSpec = WorkspaceSpec
AgentRunSpec = AgentRunSpecification


__all__ = [
    "AgentRunSpec",
    "AgentRunSpecification",
    "PersistentWorkspaceSpec",
    "PromotionReceipt",
    "PromotionSpec",
    "RunEvidence",
    "RunLease",
    "RuntimeHealthProjection",
    "ValidatorSpec",
    "WorkspaceRuntimeIdentity",
    "WorkspaceSpec",
]
