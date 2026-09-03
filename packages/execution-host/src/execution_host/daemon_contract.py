"""Typed execution-host daemon contract (fail-closed, sealed workloads).

The daemon speaks a versioned JSON contract over a group-confined Unix
socket.  Workloads are sealed typed shapes — the client supplies only typed
fields and the daemon owns every container argument; arbitrary command lines
do not exist in this contract.  No HTTP and no mTLS in the alpha: the
confinement boundary is the host socket directory ownership plus peer
credentials.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath
import re
from typing import Any, Mapping


OPERATION_FORMAT = "stateport.execution-host-operation/v1"
RECEIPT_FORMAT = "stateport.execution-host-receipt/v1"
DEPLOYMENT_CONTROL_CONTEXT_FORMAT = "stateport.deployment-control-context/v1"
CONTRACT_VERSION = 2
CLIENT_COMPATIBILITY = {"minimum": 1, "maximum": 2}

WORKLOAD_KINDS = ("agent-run", "capsule-service", "browser-journey", "terminal", "workspace", "validator-run")
DEPLOYMENT_OPERATIONS = (
    "probeDeploymentTarget",
    "applyDeployment",
    "updateDeployment",
    "observeDeployment",
    "collectDeploymentLogs",
    "restartDeployment",
    "removeDeploymentRuntime",
    "backupDeploymentData",
    "restoreDeploymentData",
    "purgeDeploymentData",
)
DEPLOYMENT_ARCHIVE_OPERATIONS = frozenset({"applyDeployment", "updateDeployment"})
OPERATIONS = (
    "describeCapabilities",
    "createWorkload",
    "start",
    "stop",
    "status",
    "logs",
    "cancel",
    "removeWorkload",
    "openTerminal",
    "resizeTerminal",
    "signalTerminal",
    "closeTerminal",
    "execWorkload",
    "listWorkloads",
    "collectGarbage",
    "runValidator",
    *DEPLOYMENT_OPERATIONS,
)
WORKLOAD_STATES = (
    "created",
    "running",
    "stopped",
    "exited",
    "timed_out",
    "cancelled",
    "interrupted",
    "failed",
    "cleanup_failed",
    "removed",
)
# stopped is deliberately NON-terminal and workspace-only: a stopped
# workspace keeps its container and daemon-owned volume and can start again.
# cleanup_failed is deliberately NON-terminal: the workload is supervised
# until its residual container is verifiably gone or the failure is
# escalated with durable evidence.
TERMINAL_STATES = frozenset({"exited", "timed_out", "cancelled", "interrupted", "failed", "removed"})

MAX_REQUEST_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
MAX_TIMEOUT_SECONDS = 86400
MAX_REQUEST_TIMEOUT_SECONDS = 600
MAX_DEPLOYMENT_REQUEST_TIMEOUT_SECONDS = 1200
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_WORK_SECONDS = 3600
MAX_EMIT_BYTES = 16 * 1024 * 1024
MAX_WORKLOADS = 64
MAX_DEPLOYMENT_CONTEXT_BYTES = 512 * 1024 * 1024
MAX_DEPLOYMENT_ARCHIVE_BYTES = MAX_DEPLOYMENT_CONTEXT_BYTES + 64 * 1024 * 1024
MAX_DEPLOYMENT_OVERLAY_BYTES = 2 * 1024 * 1024
MAX_DEPLOYMENT_FILES = 10_000
MAX_BACKUP_ARCHIVE_BYTES = 1024 * 1024 * 1024
MAX_BACKUP_ARCHIVE_MEMBERS = 100_000
DEFAULT_MEMORY_MAX_BYTES = 268435456
MAX_MEMORY_MAX_BYTES = 1073741824
DEFAULT_PIDS_MAX = 128
MAX_PIDS_MAX = 512

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._/:-]{0,255}@sha256:[0-9a-f]{64}$")
_SECRET_KEY = re.compile(
    r"(?:api[_-]?key|authorization|cookie|credential|password|secret|access[_-]?token|refresh[_-]?token)",
    re.I,
)

# Per-kind sealed parameter identity fields.  Values are validated below;
# nothing in a spec is ever spliced into a command line.
_KIND_IDENTITY_FIELDS = {
    "agent-run": {"runSpecDigest", "statePackReference"},
    "capsule-service": {"serviceName"},
    "browser-journey": {"journeyId"},
    "terminal": {"sessionId"},
    # A workspace binds only to a daemon-owned named volume.  Host paths and
    # arbitrary mount strings are intentionally not representable here.
    "workspace": {"workspaceId", "workspaceSpecDigest", "volumeName"},
    # A validator run is sealed tighter than any other kind: read-only
    # immutable staging, no network, no provider access, no runtime socket,
    # no host mounts, exactly one digest-bound command.
    "validator-run": {
        "validatorId",
        "validatorSpecDigest",
        "stagingIdentityDigest",
        "stagingPath",
        "commandDigest",
        "command",
    },
}

_WORKSPACE_VOLUME_PREFIX = "stateport-workspace-"
_SIGNAL_NAMES = frozenset({"SIGINT", "SIGQUIT", "SIGTSTP"})


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _id(value: Any, name: str) -> str:
    value = _string(value, name)
    if not _ID.fullmatch(value):
        raise ValueError(f"{name} has invalid characters")
    return value


def _digest(value: Any, name: str) -> str:
    value = _string(value, name)
    if not _DIGEST.fullmatch(value):
        raise ValueError(f"{name} must be a sha256 digest")
    return value


def _int(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer in [{minimum}, {maximum}]")
    return value


def _mapping(value: Any, name: str, keys: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ValueError(f"{name} has an invalid shape")
    return value


def _no_secrets(value: Any, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{path} keys must be strings")
            if _SECRET_KEY.search(key):
                # The deployment schema carries an explicit secret-reference
                # array. Slice A supports no broker, so only the exact empty
                # representation may cross this boundary.
                if key in {"secrets", "secretCapabilities"} and item == []:
                    continue
                raise ValueError(f"credential-like field is forbidden at {path}.{key}")
            _no_secrets(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _no_secrets(item, f"{path}[{index}]")


def validate_image_reference(value: Any) -> str:
    reference = _string(value, "image.reference")
    if not _IMAGE.fullmatch(reference):
        raise ValueError("image.reference must be a digest-pinned lowercase OCI reference")
    return reference


def _posix_absolute(value: Any, name: str) -> str:
    value = _string(value, name)
    path = PurePosixPath(value)
    if not path.is_absolute() or "\\" in value or ".." in path.parts or "" in path.parts:
        raise ValueError(f"{name} must be an absolute non-traversing POSIX path")
    return value


def _bounded_argv(value: Any, name: str) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > 32:
        raise ValueError(f"{name} must be a bounded non-empty argv")
    result = [_string(item, f"{name}[{index}]") for index, item in enumerate(value)]
    if any(len(item) > 256 or "\x00" in item for item in result):
        raise ValueError(f"{name} entries are invalid")
    return result


def _workspace_cache_volumes(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 16:
        raise ValueError("parameters.cacheVolumes must be a bounded array")
    result: list[dict[str, Any]] = []
    seen_mounts: set[str] = set()
    seen_ids: set[str] = set()
    for item in value:
        data = _mapping(item, "parameters.cacheVolumes[]", {"volumeId", "mountPath", "readOnly"})
        volume_id = _id(data["volumeId"], "parameters.cacheVolumes[].volumeId")
        mount = _posix_absolute(data["mountPath"], "parameters.cacheVolumes[].mountPath")
        if any(character in mount for character in ",:"):
            raise ValueError("parameters.cacheVolumes[].mountPath carries unsafe characters")
        if not mount.startswith("/workspace/") or mount in seen_mounts:
            raise ValueError("parameters.cacheVolumes mount paths must be unique and below /workspace")
        if volume_id in seen_ids:
            raise ValueError("parameters.cacheVolumes volume ids must be unique")
        if not isinstance(data["readOnly"], bool):
            raise ValueError("parameters.cacheVolumes[].readOnly must be boolean")
        seen_mounts.add(mount)
        seen_ids.add(volume_id)
        result.append({"volumeId": volume_id, "mountPath": mount, "readOnly": data["readOnly"]})
    return result


def validate_workload_spec(value: Any) -> dict[str, Any]:
    """Validate a sealed workload spec; unknown kinds and fields refuse."""

    _no_secrets(value)
    data = _mapping(
        value, "workload spec", {"kind", "workloadId", "image", "parameters", "timeoutSeconds", "outputByteBound", "resources"}
    )
    kind = data["kind"]
    if kind not in WORKLOAD_KINDS:
        raise ValueError(f"unknown sealed workload kind: {kind!r}")
    workload_id = _id(data["workloadId"], "workloadId")
    image = _mapping(data["image"], "image", {"reference"})
    reference = validate_image_reference(image["reference"])
    parameters = data["parameters"]
    param_allowed = set(_KIND_IDENTITY_FIELDS[kind]) | {"workSeconds", "emitBytes"}
    if kind == "agent-run":
        # Optional base revision binding for authority-bound managed runs.
        param_allowed |= {"baseRevision"}
    if kind == "workspace":
        # Every WorkspaceSpec field stays representable: base identity,
        # lifecycle, shell, network mode, caches, and resource ceilings.
        param_allowed |= {
            "baseRevision",
            "stopAfterIdle",
            "shell",
            "networkMode",
            "cacheVolumes",
            "cpuQuotaPercent",
            "diskMaxBytes",
        }
    if kind == "validator-run":
        # Fixed isolation policy fields; every one must hold its sealed value.
        param_allowed |= {
            "network",
            "stagingReadOnly",
            "providerAccess",
            "runtimeSocketAccess",
            "hostMounts",
        }
    if (
        not isinstance(parameters, Mapping)
        or not set(parameters).issubset(param_allowed)
        or not set(_KIND_IDENTITY_FIELDS[kind]).issubset(parameters)
    ):
        raise ValueError("parameters has an invalid shape")
    normalized_parameters: dict[str, Any] = {}
    for field in sorted(_KIND_IDENTITY_FIELDS[kind]):
        raw = parameters[field]
        if field in {"runSpecDigest", "workspaceSpecDigest", "validatorSpecDigest", "stagingIdentityDigest", "commandDigest"}:
            normalized_parameters[field] = _digest(raw, f"parameters.{field}")
        elif field == "statePackReference":
            normalized_parameters[field] = _string(raw, f"parameters.{field}")
        elif field == "stagingPath":
            normalized_parameters[field] = _posix_absolute(raw, f"parameters.{field}")
        elif field == "command":
            normalized_parameters[field] = _bounded_argv(raw, f"parameters.{field}")
        elif field == "volumeName":
            normalized_parameters[field] = _id(raw, f"parameters.{field}")
            if not normalized_parameters[field].startswith(_WORKSPACE_VOLUME_PREFIX):
                raise ValueError("parameters.volumeName must be daemon-owned")
        else:
            normalized_parameters[field] = _id(raw, f"parameters.{field}")
    if kind == "validator-run":
        if parameters.get("network") != "disabled":
            raise ValueError("validator-run parameters.network must be disabled")
        normalized_parameters["network"] = "disabled"
        if parameters.get("stagingReadOnly") is not True:
            raise ValueError("validator-run parameters.stagingReadOnly must be true")
        normalized_parameters["stagingReadOnly"] = True
        for flag in ("providerAccess", "runtimeSocketAccess"):
            if parameters.get(flag) is not False:
                raise ValueError(f"validator-run parameters.{flag} must be false")
            normalized_parameters[flag] = False
        if parameters.get("hostMounts") != []:
            raise ValueError("validator-run parameters.hostMounts must be empty")
        normalized_parameters["hostMounts"] = []
        observed_command_digest = canonical_digest(normalized_parameters["command"])
        if normalized_parameters["commandDigest"] != observed_command_digest:
            raise ValueError(
                "validator-run parameters.commandDigest does not match parameters.command"
            )
    if "baseRevision" in parameters:
        raw = parameters["baseRevision"]
        if not isinstance(raw, str) or not _GIT_SHA.fullmatch(raw):
            raise ValueError("parameters.baseRevision must be a full lowercase git sha")
        normalized_parameters["baseRevision"] = raw
    if kind == "workspace":
        if normalized_parameters["workspaceId"] != workload_id:
            raise ValueError("parameters.workspaceId must equal workloadId")
        if normalized_parameters["volumeName"] != _WORKSPACE_VOLUME_PREFIX + workload_id:
            raise ValueError("parameters.volumeName must be the workload's daemon-owned volume")
        stop_after_idle = parameters.get("stopAfterIdle", True)
        if not isinstance(stop_after_idle, bool):
            raise ValueError("parameters.stopAfterIdle must be boolean")
        normalized_parameters["stopAfterIdle"] = stop_after_idle
        shell = _bounded_argv(parameters.get("shell", ["/bin/sh"]), "parameters.shell")
        _posix_absolute(shell[0], "parameters.shell[0]")
        normalized_parameters["shell"] = shell
        network_mode = parameters.get("networkMode", "none")
        if network_mode not in {"none", "developer"}:
            raise ValueError("parameters.networkMode is invalid")
        normalized_parameters["networkMode"] = network_mode
        normalized_parameters["cacheVolumes"] = _workspace_cache_volumes(
            parameters.get("cacheVolumes", [])
        )
        normalized_parameters["cpuQuotaPercent"] = _int(
            parameters.get("cpuQuotaPercent", 100), "parameters.cpuQuotaPercent", 1, 800
        )
        normalized_parameters["diskMaxBytes"] = _int(
            parameters.get("diskMaxBytes", 268435456),
            "parameters.diskMaxBytes",
            16 * 1024 * 1024,
            4 * 1024**3,
        )
    normalized_parameters["workSeconds"] = _int(
        parameters.get("workSeconds", 0), "parameters.workSeconds", 0, MAX_WORK_SECONDS
    )
    normalized_parameters["emitBytes"] = _int(
        parameters.get("emitBytes", 0), "parameters.emitBytes", 0, MAX_EMIT_BYTES
    )
    if kind in {"agent-run", "validator-run"}:
        resources = _mapping(
            data["resources"],
            "resources",
            {"memoryMaxBytes", "cpuQuotaPercent", "pidsMax", "diskMaxBytes"},
        )
        normalized_resources = {
            "memoryMaxBytes": _int(
                resources["memoryMaxBytes"], "resources.memoryMaxBytes", 16 * 1024 * 1024, MAX_MEMORY_MAX_BYTES
            ),
            "pidsMax": _int(resources["pidsMax"], "resources.pidsMax", 16, MAX_PIDS_MAX),
            "cpuQuotaPercent": _int(resources["cpuQuotaPercent"], "resources.cpuQuotaPercent", 1, 800),
            "diskMaxBytes": _int(
                resources["diskMaxBytes"], "resources.diskMaxBytes", 16 * 1024 * 1024, 4 * 1024**3
            ),
        }
    else:
        resources = _mapping(data["resources"], "resources", {"memoryMaxBytes", "pidsMax"})
        normalized_resources = {
            "memoryMaxBytes": _int(
                resources["memoryMaxBytes"], "resources.memoryMaxBytes", 16 * 1024 * 1024, MAX_MEMORY_MAX_BYTES
            ),
            "pidsMax": _int(resources["pidsMax"], "resources.pidsMax", 16, MAX_PIDS_MAX),
        }
    normalized = {
        "kind": kind,
        "workloadId": workload_id,
        "image": {"reference": reference},
        "parameters": normalized_parameters,
        "timeoutSeconds": _int(data["timeoutSeconds"], "timeoutSeconds", 1, MAX_TIMEOUT_SECONDS),
        "outputByteBound": _int(data["outputByteBound"], "outputByteBound", 1, MAX_OUTPUT_BYTES),
        "resources": normalized_resources,
    }
    return normalized


def _deployment_spec(value: Any) -> dict[str, Any]:
    try:
        from stateport_deployment.contracts import validate_deployment_spec
        from stateport_deployment.errors import DeploymentError

        spec = validate_deployment_spec(value, materialized=True)
    except ImportError as exc:
        raise ValueError("deployment contract support is unavailable") from exc
    except DeploymentError as exc:
        raise ValueError(f"deployment spec is invalid: {exc}") from exc
    if any(service["secrets"] for service in spec["services"]):
        raise ValueError("deployment secrets require an unavailable explicit broker")
    return spec


def _deployment_plan(value: Any) -> dict[str, Any]:
    try:
        from stateport_deployment.contracts import validate_plan
        from stateport_deployment.errors import DeploymentError

        plan = validate_plan(value)
    except ImportError as exc:
        raise ValueError("deployment contract support is unavailable") from exc
    except DeploymentError as exc:
        raise ValueError(f"deployment plan is invalid: {exc}") from exc
    if any(service["secrets"] for service in plan["spec"]["services"]):
        raise ValueError("deployment secrets require an unavailable explicit broker")
    return plan


def _optional_digest(value: Any, name: str) -> str | None:
    return None if value is None else _digest(value, name)


def _digest_mapping(value: Any, name: str) -> dict[str, str]:
    if not isinstance(value, Mapping) or len(value) > 256:
        raise ValueError(f"{name} must be a bounded object")
    return {
        _id(key, f"{name} key"): _digest(item, f"{name} value")
        for key, item in value.items()
    }


def _id_mapping(value: Any, name: str) -> dict[str, str]:
    if not isinstance(value, Mapping) or len(value) > 256:
        raise ValueError(f"{name} must be a bounded object")
    return {
        _id(key, f"{name} key"): _id(item, f"{name} value")
        for key, item in value.items()
    }


def _optional_mapping(value: Any, name: str) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object or null")
    try:
        encoded = canonical_json(value).encode("utf-8")
        normalized = json.loads(encoded)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must contain canonical JSON values") from exc
    if len(encoded) > MAX_REQUEST_BYTES or not isinstance(normalized, dict):
        raise ValueError(f"{name} exceeds the bounded object contract")
    return normalized


def _bounded_mapping(value: Any, name: str) -> dict[str, Any]:
    normalized = _optional_mapping(value, name)
    if normalized is None:
        raise ValueError(f"{name} must be an object")
    return normalized


def _archive_metadata(value: Any) -> dict[str, Any]:
    data = _mapping(
        value,
        "deployment source archive",
        {"formatVersion", "archiveDigest", "archiveBytes", "contextDigest", "fileCount"},
    )
    if data["formatVersion"] != "stateport.deployment-context-archive/v1":
        raise ValueError("deployment source archive format is unsupported")
    return {
        "formatVersion": data["formatVersion"],
        "archiveDigest": _digest(data["archiveDigest"], "sourceArchive.archiveDigest"),
        "archiveBytes": _int(
            data["archiveBytes"], "sourceArchive.archiveBytes", 1, MAX_DEPLOYMENT_ARCHIVE_BYTES
        ),
        "contextDigest": _digest(data["contextDigest"], "sourceArchive.contextDigest"),
        "fileCount": _int(data["fileCount"], "sourceArchive.fileCount", 1, MAX_DEPLOYMENT_FILES),
    }


def _deployment_id(value: Any, spec: Mapping[str, Any]) -> str:
    deployment_id = _id(value, "deploymentId")
    if spec["metadata"]["deploymentId"] != deployment_id:
        raise ValueError("deploymentId does not match the deployment contract")
    return deployment_id


def _failpoint(value: Any) -> str | None:
    if value is None:
        return None
    if value not in {
        "after_volume_creation",
        "after_image_build",
        "after_first_service_creation",
        "after_predecessor_stopped",
    }:
        raise ValueError("deployment failpoint is unsupported")
    return str(value)


_DEPLOYMENT_AUTHORITY_ACTIONS = {
    "applyDeployment": {"apply_deployment"},
    "updateDeployment": {"apply_deployment"},
    "observeDeployment": {"observe_deployment", "apply_deployment"},
    "collectDeploymentLogs": {
        "collect_deployment_logs",
        "remove_deployment_runtime",
    },
    "restartDeployment": {"restart_deployment"},
    "removeDeploymentRuntime": {"remove_deployment_runtime"},
    "backupDeploymentData": {"backup_deployment_data"},
    "restoreDeploymentData": {"restore_deployment_data"},
    "purgeDeploymentData": {"purge_deployment_data"},
}


def _deployment_backup(value: Any) -> dict[str, Any]:
    data = _mapping(
        value,
        "deployment backup",
        {
            "backupId",
            "backupDigest",
            "sourceRevision",
            "createdAt",
            "status",
            "storage",
            "restoredAt",
        },
    )
    backup_id = _id(data["backupId"], "backup.backupId")
    if data["status"] != "available" or data["restoredAt"] is not None:
        raise ValueError("deployment backup must be available before restore")
    storage_data = data["storage"]
    if not isinstance(storage_data, Mapping) or not storage_data:
        raise ValueError("deployment backup storage must be a non-empty object")
    storage: dict[str, Any] = {}
    for raw_storage_id, raw_item in sorted(storage_data.items()):
        storage_id = _id(raw_storage_id, "backup.storage id")
        item = _mapping(
            raw_item,
            "backup storage",
            {"artifactId", "contentDigest", "fileCount", "bytes"},
        )
        if item["artifactId"] != f"{backup_id}/{storage_id}.tar":
            raise ValueError("deployment backup artifact identity differs")
        storage[storage_id] = {
            "artifactId": item["artifactId"],
            "contentDigest": _digest(
                item["contentDigest"], "backup.storage.contentDigest"
            ),
            "fileCount": _int(
                item["fileCount"],
                "backup.storage.fileCount",
                0,
                MAX_BACKUP_ARCHIVE_MEMBERS,
            ),
            "bytes": _int(
                item["bytes"],
                "backup.storage.bytes",
                0,
                MAX_BACKUP_ARCHIVE_BYTES,
            ),
        }
    identity = {
        "backupId": backup_id,
        "sourceRevision": _digest(
            data["sourceRevision"], "backup.sourceRevision"
        ),
        "createdAt": _iso_z(data["createdAt"], "backup.createdAt"),
        "storage": storage,
    }
    backup_digest = _digest(data["backupDigest"], "backup.backupDigest")
    if backup_digest != canonical_digest(identity):
        raise ValueError("deployment backup digest does not match its exact identity")
    return {
        **identity,
        "backupDigest": backup_digest,
        "status": "available",
        "restoredAt": None,
    }


def build_deployment_control_context(
    operation_id: str, authority: Mapping[str, Any]
) -> dict[str, Any]:
    """Bind one host request to the claimed canonical control-plane decision."""

    body = {
        "formatVersion": DEPLOYMENT_CONTROL_CONTEXT_FORMAT,
        "operationId": _id(operation_id, "controlContext.operationId"),
        "authority": _bounded_mapping(authority, "controlContext.authority"),
    }
    return {**body, "contextDigest": canonical_digest(body)}


def _deployment_control_context(
    value: Any,
    *,
    operation: str,
    deployment_id: str,
    plan_digest: str | None = None,
) -> dict[str, Any]:
    data = _mapping(
        value,
        "deployment control context",
        {"formatVersion", "operationId", "authority", "contextDigest"},
    )
    if data["formatVersion"] != DEPLOYMENT_CONTROL_CONTEXT_FORMAT:
        raise ValueError("deployment control context format is unsupported")
    operation_id = _id(data["operationId"], "controlContext.operationId")
    authority = _mapping(
        data["authority"],
        "controlContext.authority",
        {
            "requestId",
            "decisionDigest",
            "action",
            "actorId",
            "grantId",
            "grantDigest",
            "runId",
            "profile",
            "policy",
            "scope",
            "decision",
            "sourceIdentity",
            "reservationId",
            "reservationDigest",
            "claimId",
            "claimDigest",
        },
    )
    normalized_authority = _bounded_mapping(
        authority, "controlContext.authority"
    )
    for field in (
        "requestId",
        "action",
        "actorId",
        "grantId",
        "reservationId",
        "claimId",
    ):
        _id(authority[field], f"controlContext.authority.{field}")
    for field in (
        "decisionDigest",
        "grantDigest",
        "reservationDigest",
        "claimDigest",
    ):
        _digest(authority[field], f"controlContext.authority.{field}")
    run_id = _digest(authority["runId"], "controlContext.authority.runId")
    if authority["action"] not in _DEPLOYMENT_AUTHORITY_ACTIONS[operation]:
        raise ValueError("deployment authority action does not match the host operation")
    if plan_digest is not None and run_id != plan_digest:
        raise ValueError("deployment authority runId does not match the exact plan")

    scope = authority["scope"]
    decision = authority["decision"]
    if not isinstance(scope, Mapping) or not isinstance(decision, Mapping):
        raise ValueError("deployment authority scope and decision must be objects")
    decision_body = {key: item for key, item in decision.items() if key != "decisionDigest"}
    authorized_by = decision.get("authorizedBy")
    decision_scope = decision.get("scope")
    if (
        decision.get("schema") != "stateport.authority-decision/v1"
        or decision.get("decision") != "authorized"
        or decision.get("requestId") != authority["requestId"]
        or decision.get("decisionDigest") != authority["decisionDigest"]
        or canonical_digest(decision_body) != authority["decisionDigest"]
        or decision.get("action") != authority["action"]
        or decision.get("actorId") != authority["actorId"]
        or not isinstance(authorized_by, Mapping)
        or authorized_by.get("type") != "grant"
        or authorized_by.get("id") != authority["grantId"]
        or authorized_by.get("digest") != authority["grantDigest"]
        or decision_scope != scope
        or scope.get("applicationId") != deployment_id
        or scope.get("runId") != run_id
    ):
        raise ValueError(
            "deployment authority decision does not bind the exact action, deployment, and run"
        )
    body = {
        "formatVersion": DEPLOYMENT_CONTROL_CONTEXT_FORMAT,
        "operationId": operation_id,
        "authority": normalized_authority,
    }
    if data["contextDigest"] != canonical_digest(body):
        raise ValueError("deployment control context digest does not match")
    return {**body, "contextDigest": data["contextDigest"]}


def deployment_host_operation_id(
    operation: str,
    payload: Mapping[str, Any],
) -> str:
    """Derive a stable host operation identity from exact normalized bytes."""

    seed = {"operation": operation, "payload": dict(payload)}
    return "deployment-" + canonical_digest(seed)[7:39]


def _validate_deployment_payload(operation: str, payload: Any) -> dict[str, Any]:
    if operation == "probeDeploymentTarget":
        if payload is not None:
            raise ValueError("probeDeploymentTarget must not carry a payload")
        return {}
    if operation == "applyDeployment":
        data = _mapping(
            payload,
            "applyDeployment payload",
            {
                "deploymentId",
                "plan",
                "sourceArchive",
                "failpoint",
                "controlContext",
            },
        )
        plan = _deployment_plan(data["plan"])
        if plan["operation"] != "apply":
            raise ValueError("applyDeployment requires an apply plan")
        deployment_id = _deployment_id(data["deploymentId"], plan["spec"])
        return {
            "deploymentId": deployment_id,
            "plan": plan,
            "sourceArchive": _archive_metadata(data["sourceArchive"]),
            "failpoint": _failpoint(data["failpoint"]),
            "controlContext": _deployment_control_context(
                data["controlContext"],
                operation=operation,
                deployment_id=deployment_id,
                plan_digest=plan["planDigest"],
            ),
        }
    if operation == "updateDeployment":
        data = _mapping(
            payload,
            "updateDeployment payload",
            {
                "deploymentId",
                "plan",
                "predecessorPlan",
                "predecessorImages",
                "infrastructure",
                "sourceArchive",
                "failpoint",
                "controlContext",
            },
        )
        plan = _deployment_plan(data["plan"])
        predecessor = _deployment_plan(data["predecessorPlan"])
        if (
            plan["operation"] not in {"update", "rollback"}
            or plan["predecessorRevision"] != predecessor["planDigest"]
            or predecessor["spec"]["metadata"]["deploymentId"]
            != plan["spec"]["metadata"]["deploymentId"]
        ):
            raise ValueError("updateDeployment plan lineage is invalid")
        deployment_id = _deployment_id(data["deploymentId"], plan["spec"])
        return {
            "deploymentId": deployment_id,
            "plan": plan,
            "predecessorPlan": predecessor,
            "predecessorImages": _digest_mapping(
                data["predecessorImages"], "predecessorImages"
            ),
            "infrastructure": _optional_mapping(data["infrastructure"], "infrastructure"),
            "sourceArchive": _archive_metadata(data["sourceArchive"]),
            "failpoint": _failpoint(data["failpoint"]),
            "controlContext": _deployment_control_context(
                data["controlContext"],
                operation=operation,
                deployment_id=deployment_id,
                plan_digest=plan["planDigest"],
            ),
        }

    shapes = {
        "observeDeployment": {
            "deploymentId", "spec", "expectedRevision", "expectedImages", "verifyHealth", "infrastructure", "controlContext"
        },
        "collectDeploymentLogs": {
            "deploymentId", "spec", "serviceId", "tail", "expectedRevision", "controlContext"
        },
        "restartDeployment": {
            "deploymentId", "spec", "expectedRevision", "expectedImages", "infrastructure", "controlContext"
        },
        "removeDeploymentRuntime": {
            "deploymentId", "spec", "expectedRevision", "recoveryOperation", "controlContext"
        },
        "backupDeploymentData": {
            "deploymentId", "spec", "backupId", "planDigest", "expectedVolumes", "expectedRevision", "expectedImages", "infrastructure", "controlContext"
        },
        "restoreDeploymentData": {
            "deploymentId", "spec", "backup", "planDigest", "expectedVolumes", "expectedRevision", "expectedImages", "infrastructure", "controlContext"
        },
        "purgeDeploymentData": {
            "deploymentId", "spec", "expectedVolumes", "expectedRevision", "recoverInterrupted", "controlContext"
        },
    }
    data = _mapping(payload, f"{operation} payload", shapes[operation])
    spec = _deployment_spec(data["spec"])
    result: dict[str, Any] = {
        "deploymentId": _deployment_id(data["deploymentId"], spec),
        "spec": spec,
    }
    plan_digest = (
        _digest(data["planDigest"], "planDigest")
        if operation in {"backupDeploymentData", "restoreDeploymentData"}
        else None
    )
    result["controlContext"] = _deployment_control_context(
        data["controlContext"],
        operation=operation,
        deployment_id=result["deploymentId"],
        plan_digest=plan_digest,
    )
    if operation == "observeDeployment":
        if not isinstance(data["verifyHealth"], bool):
            raise ValueError("verifyHealth must be boolean")
        result.update(
            expectedRevision=_optional_digest(data["expectedRevision"], "expectedRevision"),
            expectedImages=_digest_mapping(data["expectedImages"], "expectedImages"),
            verifyHealth=data["verifyHealth"],
            infrastructure=_optional_mapping(data["infrastructure"], "infrastructure"),
        )
    elif operation == "collectDeploymentLogs":
        result.update(
            serviceId=(None if data["serviceId"] is None else _id(data["serviceId"], "serviceId")),
            tail=_int(data["tail"], "tail", 1, 1000),
            expectedRevision=_optional_digest(data["expectedRevision"], "expectedRevision"),
        )
    elif operation == "restartDeployment":
        result.update(
            expectedRevision=_optional_digest(data["expectedRevision"], "expectedRevision"),
            expectedImages=_digest_mapping(data["expectedImages"], "expectedImages"),
            infrastructure=_optional_mapping(data["infrastructure"], "infrastructure"),
        )
    elif operation == "removeDeploymentRuntime":
        recovery = data["recoveryOperation"]
        if recovery not in {None, "apply", "remove"}:
            raise ValueError("recoveryOperation is unsupported")
        result.update(
            expectedRevision=_optional_digest(data["expectedRevision"], "expectedRevision"),
            recoveryOperation=recovery,
        )
    elif operation in {"backupDeploymentData", "restoreDeploymentData"}:
        result.update(
            planDigest=plan_digest,
            expectedVolumes=_id_mapping(
                data["expectedVolumes"], "expectedVolumes"
            ),
            expectedRevision=_digest(
                data["expectedRevision"], "expectedRevision"
            ),
            expectedImages=_digest_mapping(
                data["expectedImages"], "expectedImages"
            ),
            infrastructure=_optional_mapping(
                data["infrastructure"], "infrastructure"
            ),
        )
        if operation == "backupDeploymentData":
            result["backupId"] = _id(data["backupId"], "backupId")
        else:
            result["backup"] = _deployment_backup(data["backup"])
    else:
        if not isinstance(data["recoverInterrupted"], bool):
            raise ValueError("recoverInterrupted must be boolean")
        result.update(
            expectedVolumes=_id_mapping(data["expectedVolumes"], "expectedVolumes"),
            expectedRevision=_digest(data["expectedRevision"], "expectedRevision"),
            recoverInterrupted=data["recoverInterrupted"],
        )
    return result


def validate_operation_request(value: Any) -> dict[str, Any]:
    """Validate one daemon request envelope (no peer identity; that is observed)."""

    _no_secrets(value)
    if not isinstance(value, Mapping):
        raise ValueError("operation request has an invalid shape")
    base_keys = {"formatVersion", "operationId", "operation", "requester", "timeoutSeconds", "outputByteBound"}
    if set(value) != base_keys and set(value) != base_keys | {"payload"}:
        raise ValueError("operation request has an invalid shape")
    data = value
    if data["formatVersion"] != OPERATION_FORMAT:
        raise ValueError("operation request has an invalid formatVersion")
    operation = data["operation"]
    if operation not in OPERATIONS:
        raise ValueError(f"unknown operation: {operation!r}")
    no_payload_operations = {
        "describeCapabilities",
        "listWorkloads",
        "collectGarbage",
        "probeDeploymentTarget",
    }
    if operation in no_payload_operations and "payload" in data:
        raise ValueError(f"{operation} must not carry a payload")
    if operation not in no_payload_operations and "payload" not in data:
        raise ValueError(f"{operation} requires a payload")
    requester = _mapping(data["requester"], "requester", {"grantId", "authorityGrantDigest"})
    normalized = {
        "formatVersion": OPERATION_FORMAT,
        "operationId": _id(data["operationId"], "operationId"),
        "operation": operation,
        "requester": {
            "grantId": _id(requester["grantId"], "requester.grantId"),
            "authorityGrantDigest": _digest(
                requester["authorityGrantDigest"], "requester.authorityGrantDigest"
            ),
        },
        "timeoutSeconds": _int(
            data["timeoutSeconds"],
            "timeoutSeconds",
            1,
            (
                MAX_DEPLOYMENT_REQUEST_TIMEOUT_SECONDS
                if operation in DEPLOYMENT_OPERATIONS
                else MAX_REQUEST_TIMEOUT_SECONDS
            ),
        ),
        "outputByteBound": _int(data["outputByteBound"], "outputByteBound", 1, MAX_OUTPUT_BYTES),
    }
    return normalized


def validate_request_payload(request: Mapping[str, Any], payload: Any) -> dict[str, Any]:
    """Validate the operation-specific payload of an already-validated request."""

    operation = request["operation"]
    if operation in {"createWorkload", "runValidator"}:
        data = _mapping(payload, f"{operation} payload", {"workload"})
        workload = validate_workload_spec(data["workload"])
        if operation == "runValidator" and workload["kind"] != "validator-run":
            raise ValueError("runValidator requires a validator-run workload")
        return {"workload": workload}
    if operation in {"start", "stop", "status", "logs", "cancel", "removeWorkload"}:
        data = _mapping(payload, f"{operation} payload", {"workloadId"})
        return {"workloadId": _id(data["workloadId"], "workloadId")}
    if operation == "openTerminal":
        data = _mapping(payload, "openTerminal payload", {"workloadId", "sessionId", "columns", "rows"})
        return {
            "workloadId": _id(data["workloadId"], "workloadId"),
            "sessionId": _id(data["sessionId"], "sessionId"),
            "columns": _int(data["columns"], "columns", 1, 1000),
            "rows": _int(data["rows"], "rows", 1, 1000),
        }
    if operation == "resizeTerminal":
        data = _mapping(payload, "resizeTerminal payload", {"sessionId", "columns", "rows"})
        return {
            "sessionId": _id(data["sessionId"], "sessionId"),
            "columns": _int(data["columns"], "columns", 1, 1000),
            "rows": _int(data["rows"], "rows", 1, 1000),
        }
    if operation == "signalTerminal":
        data = _mapping(payload, "signalTerminal payload", {"sessionId", "signal"})
        signal = _string(data["signal"], "signal")
        if signal not in _SIGNAL_NAMES:
            raise ValueError("signalTerminal carries an unsupported signal")
        return {"sessionId": _id(data["sessionId"], "sessionId"), "signal": signal}
    if operation == "closeTerminal":
        data = _mapping(payload, "closeTerminal payload", {"sessionId"})
        return {"sessionId": _id(data["sessionId"], "sessionId")}
    if operation == "execWorkload":
        data = _mapping(payload, "execWorkload payload", {"workloadId", "argv"})
        argv = _bounded_argv(data["argv"], "execWorkload argv")
        return {"workloadId": _id(data["workloadId"], "workloadId"), "argv": argv}
    if operation in DEPLOYMENT_OPERATIONS:
        return _validate_deployment_payload(operation, payload)
    if operation == "listWorkloads":
        if payload is not None:
            raise ValueError("listWorkloads must not carry a payload")
        return {}
    if payload is not None:
        raise ValueError(f"{operation} must not carry a payload")
    return {}


GRANT_FORMAT = "stateport.execution-host-grant/v2"
LEGACY_GRANT_FORMAT = "stateport.execution-host-grant/v1"
GRANT_BUDGET_KEYS = (
    "maxTimeoutSeconds",
    "maxOutputBytes",
    "maxMemoryMaxBytes",
    "maxPidsMax",
    "maxActiveWorkloads",
    "maxCpuQuotaPercent",
    "maxDiskMaxBytes",
)


def _iso_z(value: Any, name: str) -> str:
    value = _string(value, name)
    if not value.endswith("Z") or "\n" in value or len(value) > 64:
        raise ValueError(f"{name} must be a bounded UTC timestamp")
    return value


def validate_grant_document(value: Any) -> dict[str, Any]:
    """Validate one provisioned execution-host authority grant.

    A grant binds an exact peer uid, an exact operation set, an exact
    workload scope, the permitted workload kinds, the complete canonical
    sealed-spec digest of every creatable workload (which itself binds the
    network profile, shell/exec policy, staging/base identity, and
    cache/volume scope), a digest-pinned image, an optional base revision,
    an expiry, a revocation epoch, and full resource/action budgets.  The
    daemon refuses any request whose grant document digest does not equal
    the digest the client presented, so a grant cannot be fabricated or
    paraphrased.
    """

    _no_secrets(value)
    base_keys = {
        "formatVersion", "grantId", "peerUid", "operations", "workloadIds",
        "workloadKinds", "workloadSpecDigests", "imageReference", "baseRevision",
        "issuedAt", "expiresAt", "revocationEpoch", "budgets",
    }
    if not isinstance(value, Mapping):
        raise ValueError("authority grant has an invalid shape")
    format_version = value.get("formatVersion")
    valid_keys = set(value) == base_keys or (
        format_version == GRANT_FORMAT
        and set(value) == base_keys | {"deploymentScope"}
    )
    if not valid_keys:
        raise ValueError("authority grant has an invalid shape")
    data = value
    if format_version not in {GRANT_FORMAT, LEGACY_GRANT_FORMAT}:
        raise ValueError("authority grant has an invalid formatVersion")
    grant_id = _id(data["grantId"], "grantId")
    peer_uid = _int(data["peerUid"], "peerUid", 0, 2**31 - 1)
    operations = data["operations"]
    if (
        not isinstance(operations, list)
        or not operations
        or len(operations) > len(OPERATIONS)
        or any(operation not in OPERATIONS for operation in operations)
        or len(set(operations)) != len(operations)
    ):
        raise ValueError("authority grant operations must be a unique subset of the contract operations")
    deployment_operations = set(operations) & set(DEPLOYMENT_OPERATIONS)
    deployment_scope: dict[str, Any] | None = None
    if deployment_operations:
        if format_version != GRANT_FORMAT or "deploymentScope" not in data:
            raise ValueError(
                "a grant with deployment operations requires a v2 deploymentScope"
            )
        raw_scope = _mapping(
            data["deploymentScope"],
            "deploymentScope",
            {
                "authorityMode",
                "targetAdapter",
                "targetId",
                "allowDataPurge",
                "maxArchiveBytes",
                "maxFiles",
            },
        )
        if raw_scope["authorityMode"] != "canonical-control-plane":
            raise ValueError("deploymentScope.authorityMode is unsupported")
        if raw_scope["targetAdapter"] != "rootless-podman-local":
            raise ValueError("deploymentScope.targetAdapter is unsupported")
        target_id = _id(raw_scope["targetId"], "deploymentScope.targetId")
        if not isinstance(raw_scope["allowDataPurge"], bool):
            raise ValueError("deploymentScope.allowDataPurge must be boolean")
        if "purgeDeploymentData" in deployment_operations and not raw_scope["allowDataPurge"]:
            raise ValueError(
                "a grant covering purgeDeploymentData must explicitly allow data purge"
            )
        deployment_scope = {
            "authorityMode": "canonical-control-plane",
            "targetAdapter": "rootless-podman-local",
            "targetId": target_id,
            "allowDataPurge": raw_scope["allowDataPurge"],
            "maxArchiveBytes": _int(
                raw_scope["maxArchiveBytes"],
                "deploymentScope.maxArchiveBytes",
                1,
                MAX_DEPLOYMENT_ARCHIVE_BYTES,
            ),
            "maxFiles": _int(
                raw_scope["maxFiles"],
                "deploymentScope.maxFiles",
                1,
                MAX_DEPLOYMENT_FILES,
            ),
        }
    elif "deploymentScope" in data:
        raise ValueError("deploymentScope requires at least one deployment operation")
    workload_ids = data["workloadIds"]
    if (
        not isinstance(workload_ids, list)
        or not workload_ids
        or len(workload_ids) > 256
        or len(set(workload_ids)) != len(workload_ids)
    ):
        raise ValueError("authority grant workloadIds must be a bounded unique list")
    normalized_ids = [_id(item, "workloadIds[]") for item in workload_ids]
    workload_kinds = data["workloadKinds"]
    if (
        not isinstance(workload_kinds, list)
        or not workload_kinds
        or any(kind not in WORKLOAD_KINDS for kind in workload_kinds)
        or len(set(workload_kinds)) != len(workload_kinds)
    ):
        raise ValueError("authority grant workloadKinds must be a unique subset of the workload kinds")
    spec_digests = data["workloadSpecDigests"]
    if not isinstance(spec_digests, Mapping) or len(spec_digests) > 256:
        raise ValueError("authority grant workloadSpecDigests must be a bounded object")
    normalized_digests: dict[str, str] = {}
    for key, digest in spec_digests.items():
        normalized_digests[_id(key, "workloadSpecDigests key")] = _digest(
            digest, "workloadSpecDigests value"
        )
    if set(normalized_digests) - set(normalized_ids):
        raise ValueError("authority grant workloadSpecDigests names workloads outside its scope")
    if {"createWorkload", "runValidator"} & set(operations) and set(normalized_digests) != set(normalized_ids):
        raise ValueError(
            "a grant that may create workloads must bind the complete canonical "
            "sealed-spec digest of every workload in its scope"
        )
    image_reference = validate_image_reference(data["imageReference"])
    base_revision = data["baseRevision"]
    if base_revision is not None and (not isinstance(base_revision, str) or not _GIT_SHA.fullmatch(base_revision)):
        raise ValueError("authority grant baseRevision must be null or a full lowercase git sha")
    issued_at = _iso_z(data["issuedAt"], "issuedAt")
    expires_at = _iso_z(data["expiresAt"], "expiresAt")
    revocation_epoch = _int(data["revocationEpoch"], "revocationEpoch", 0, 2**31 - 1)
    budgets = _mapping(data["budgets"], "budgets", set(GRANT_BUDGET_KEYS))
    normalized_budgets = {
        "maxTimeoutSeconds": _int(budgets["maxTimeoutSeconds"], "budgets.maxTimeoutSeconds", 1, MAX_TIMEOUT_SECONDS),
        "maxOutputBytes": _int(budgets["maxOutputBytes"], "budgets.maxOutputBytes", 1, MAX_OUTPUT_BYTES),
        "maxMemoryMaxBytes": _int(budgets["maxMemoryMaxBytes"], "budgets.maxMemoryMaxBytes", 16 * 1024 * 1024, MAX_MEMORY_MAX_BYTES),
        "maxPidsMax": _int(budgets["maxPidsMax"], "budgets.maxPidsMax", 16, MAX_PIDS_MAX),
        "maxActiveWorkloads": _int(budgets["maxActiveWorkloads"], "budgets.maxActiveWorkloads", 1, 256),
        "maxCpuQuotaPercent": _int(budgets["maxCpuQuotaPercent"], "budgets.maxCpuQuotaPercent", 1, 800),
        "maxDiskMaxBytes": _int(budgets["maxDiskMaxBytes"], "budgets.maxDiskMaxBytes", 16 * 1024 * 1024, 4 * 1024**3),
    }
    normalized = {
        "formatVersion": format_version,
        "grantId": grant_id,
        "peerUid": peer_uid,
        "operations": list(operations),
        "workloadIds": normalized_ids,
        "workloadKinds": list(workload_kinds),
        "workloadSpecDigests": normalized_digests,
        "imageReference": image_reference,
        "baseRevision": base_revision,
        "issuedAt": issued_at,
        "expiresAt": expires_at,
        "revocationEpoch": revocation_epoch,
        "budgets": normalized_budgets,
    }
    if deployment_scope is not None:
        normalized["deploymentScope"] = deployment_scope
    return normalized


def validate_revocation_document(value: Any) -> dict[str, Any]:
    """Validate the grant-store revocation/pause/epoch document."""

    data = _mapping(value, "revocation document", {"revokedGrantIds", "pausedGrantIds", "revocationEpoch"})
    result: dict[str, Any] = {"revocationEpoch": _int(data["revocationEpoch"], "revocationEpoch", 0, 2**31 - 1)}
    for field in ("revokedGrantIds", "pausedGrantIds"):
        items = data[field]
        if not isinstance(items, list) or len(items) > 4096:
            raise ValueError(f"{field} must be a bounded list")
        result[field] = [_id(item, f"{field}[]") for item in items]
    return result


def refusal_receipt(
    request_digest: str,
    operation_id: str,
    peer: Mapping[str, Any],
    reason: str,
    detail: str,
    *,
    received_at: str,
    completed_at: str,
) -> dict[str, Any]:
    return {
        "formatVersion": RECEIPT_FORMAT,
        "operationId": operation_id,
        "requestDigest": request_digest,
        "accepted": False,
        "refusal": {"reason": _id(reason, "refusal.reason"), "detail": str(detail)[:500]},
        "requester": dict(peer),
        "result": None,
        "observed": {
            "engine": None,
            "engineVersion": None,
            "imageDigest": None,
            "exitStatus": None,
            "startedAt": None,
            "finishedAt": None,
        },
        "cleanup": {"outcome": "not-required", "detail": "request refused before execution"},
        "timestamps": {"receivedAt": received_at, "completedAt": completed_at},
    }


def validate_receipt(value: Any) -> dict[str, Any]:
    _no_secrets(value)
    data = _mapping(
        value,
        "execution receipt",
        {
            "formatVersion",
            "operationId",
            "requestDigest",
            "accepted",
            "refusal",
            "requester",
            "result",
            "observed",
            "cleanup",
            "timestamps",
        },
    )
    if data["formatVersion"] != RECEIPT_FORMAT:
        raise ValueError("receipt has an invalid formatVersion")
    _id(data["operationId"], "operationId")
    _digest(data["requestDigest"], "requestDigest")
    if not isinstance(data["accepted"], bool):
        raise ValueError("receipt.accepted must be boolean")
    if data["accepted"]:
        if data["refusal"] is not None:
            raise ValueError("accepted receipt must not carry a refusal")
    else:
        refusal = _mapping(data["refusal"], "refusal", {"reason", "detail"})
        _id(refusal["reason"], "refusal.reason")
        _string(refusal["detail"], "refusal.detail")
    requester = _mapping(data["requester"], "receipt.requester", {"uid", "gid", "pid", "grantId"})
    for field in ("uid", "gid", "pid"):
        _int(requester[field], f"requester.{field}", -1, 2**31)
    _id(requester["grantId"], "requester.grantId")
    observed = _mapping(
        data["observed"],
        "observed",
        {"engine", "engineVersion", "imageDigest", "exitStatus", "startedAt", "finishedAt"},
    )
    for field in ("engine", "engineVersion", "imageDigest", "startedAt", "finishedAt"):
        if observed[field] is not None and not isinstance(observed[field], str):
            raise ValueError(f"observed.{field} must be a string or null")
    if observed["exitStatus"] is not None:
        _int(observed["exitStatus"], "observed.exitStatus", -1, 255)
    cleanup = _mapping(data["cleanup"], "cleanup", {"outcome", "detail"})
    if cleanup["outcome"] not in {"not-required", "performed", "failed"}:
        raise ValueError("cleanup.outcome is invalid")
    _string(cleanup["detail"], "cleanup.detail")
    _mapping(data["timestamps"], "timestamps", {"receivedAt", "completedAt"})
    return dict(data)
