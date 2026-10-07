"""Strict deployment specification, plan, and state contracts."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import re
from typing import Any, Mapping

from .errors import DeploymentRefusal
from .util import COMMIT, DIGEST, digest_value, relative_posix, safe_id


DEPLOYMENT_SCHEMA = "stateport.deployment/v1"
PLAN_SCHEMA = "stateport.deployment-plan/v1"
STATE_SCHEMA = "stateport.deployment-state/v1"
RECEIPT_SCHEMA = "stateport.deployment-receipt/v1"
INSPECTION_SCHEMA = "stateport.deployment-inspection/v1"
TARGET_ADAPTER = "rootless-podman-local"
ARCHITECTURE = "linux-amd64"
DEFAULT_RUNTIME_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

LIFECYCLE_STATES = frozenset(
    {
        "discovered",
        "planned",
        "awaiting_approval",
        "approved",
        "applying",
        "verifying",
        "healthy",
        "degraded",
        "failed",
        "update_planned",
        "updating",
        "rollback_required",
        "rolling_back",
        "removed_runtime_data_retained",
        "purged",
        "reconciliation_required",
    }
)

TRANSITIONS: dict[str, frozenset[str]] = {
    "discovered": frozenset({"planned", "failed"}),
    "planned": frozenset({"awaiting_approval", "failed"}),
    "awaiting_approval": frozenset({"approved", "healthy", "failed", "planned"}),
    "approved": frozenset({"applying", "updating", "failed", "reconciliation_required"}),
    "applying": frozenset({"verifying", "purged", "failed", "rollback_required", "reconciliation_required"}),
    "verifying": frozenset({"healthy", "degraded", "failed", "rollback_required", "reconciliation_required"}),
    "healthy": frozenset({"degraded", "update_planned", "removed_runtime_data_retained", "reconciliation_required"}),
    "degraded": frozenset({"healthy", "failed", "update_planned", "rollback_required", "removed_runtime_data_retained", "reconciliation_required"}),
    "failed": frozenset({"planned", "removed_runtime_data_retained", "reconciliation_required"}),
    "update_planned": frozenset({"awaiting_approval", "updating", "failed"}),
    "updating": frozenset({"verifying", "rollback_required", "failed", "reconciliation_required"}),
    "rollback_required": frozenset({"rolling_back", "failed", "reconciliation_required"}),
    "rolling_back": frozenset({"healthy", "failed", "reconciliation_required"}),
    "removed_runtime_data_retained": frozenset({"planned", "purged", "reconciliation_required"}),
    "purged": frozenset({"reconciliation_required"}),
    "reconciliation_required": frozenset({"healthy", "degraded", "failed", "removed_runtime_data_retained", "purged"}),
}

_SECRET_KEY = re.compile(r"(?:secret|token|password|credential|api[_-]?key)", re.I)
_SECRET_VALUE = re.compile(
    r"(?:-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,}|AKIA[A-Z0-9]{16}|STATEPORT_TEST_SECRET_[A-Za-z0-9_-]+)"
)
_IMAGE = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}\Z")
_RUNTIME_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
_AUTHORITY_GRANT_ID = re.compile(
    r"grant_[A-Za-z0-9][A-Za-z0-9._-]{2,95}\Z"
)


def _runtime_id(value: object, label: str) -> str:
    if not isinstance(value, str) or _RUNTIME_ID.fullmatch(value) is None:
        raise DeploymentRefusal(
            "invalid_identity", f"{label} must be a lowercase runtime-safe identifier"
        )
    return value


def _mapping(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise DeploymentRefusal("invalid_contract", f"{label} has an invalid shape")
    return dict(value)


def _sequence(value: object, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise DeploymentRefusal("invalid_contract", f"{label} must be a list")
    return list(value)


def _positive_int(value: object, label: str, *, maximum: int = 65535) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise DeploymentRefusal("invalid_contract", f"{label} is invalid")
    return value


def _nonnegative_int(value: object, label: str, *, maximum: int = 65535) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise DeploymentRefusal("invalid_contract", f"{label} is invalid")
    return value


def _bounded_text(value: object, label: str, *, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise DeploymentRefusal("invalid_contract", f"{label} is invalid")
    return value


def validate_transition(current: str, target: str) -> None:
    if current not in LIFECYCLE_STATES or target not in LIFECYCLE_STATES:
        raise DeploymentRefusal("invalid_transition", "deployment lifecycle state is unknown")
    if target not in TRANSITIONS[current]:
        raise DeploymentRefusal(
            "invalid_transition", f"deployment may not transition from {current} to {target}"
        )


def _validate_source(value: object, *, materialized: bool) -> dict[str, Any]:
    source = _mapping(
        value,
        {
            "repositoryIdentity",
            "repositoryRoot",
            "projectPath",
            "commit",
            "treeDigest",
            "dirty",
            "dirtyDigest",
            "dirtyPolicy",
            "descriptorDigest",
        },
        "source",
    )
    if source["dirtyPolicy"] != "refuse":
        raise DeploymentRefusal("invalid_contract", "source dirtyPolicy must be refuse")
    source["projectPath"] = relative_posix(source["projectPath"], "source projectPath")
    nullable = ("repositoryIdentity", "repositoryRoot", "commit", "treeDigest", "dirty", "dirtyDigest", "descriptorDigest")
    if materialized and any(source[name] is None for name in nullable):
        raise DeploymentRefusal("source_identity_missing", "materialized source identity is incomplete")
    if source["repositoryIdentity"] is not None and DIGEST.fullmatch(str(source["repositoryIdentity"])) is None:
        raise DeploymentRefusal("invalid_contract", "repositoryIdentity must be sha256")
    if source["repositoryRoot"] is not None:
        repository_root = _bounded_text(
            source["repositoryRoot"], "repositoryRoot"
        )
        if not repository_root.startswith("/"):
            raise DeploymentRefusal(
                "unsafe_path", "repositoryRoot must be an absolute Linux path"
            )
    if source["commit"] is not None and COMMIT.fullmatch(str(source["commit"])) is None:
        raise DeploymentRefusal("invalid_contract", "source commit is invalid")
    for name in ("treeDigest", "dirtyDigest", "descriptorDigest"):
        if source[name] is not None and DIGEST.fullmatch(str(source[name])) is None:
            raise DeploymentRefusal("invalid_contract", f"source {name} must be sha256")
    if source["dirty"] not in {None, False}:
        raise DeploymentRefusal("dirty_source", "deployment source must be clean")
    return source


def _validate_service(value: object, network_ids: set[str], *, materialized: bool) -> dict[str, Any]:
    service = _mapping(
        value,
        {
            "id",
            "sourcePath",
            "build",
            "image",
            "runtime",
            "ports",
            "health",
            "resources",
            "storage",
            "secrets",
            "environment",
            "networks",
        },
        "service",
    )
    service["id"] = _runtime_id(service["id"], "service id")
    service["sourcePath"] = relative_posix(service["sourcePath"], "service sourcePath")
    build = _mapping(service["build"], {"mode", "context", "containerfile", "generated"}, "service build")
    if build["mode"] not in {"source", "image"}:
        raise DeploymentRefusal("invalid_contract", "build mode must be source or image")
    build["context"] = relative_posix(build["context"], "build context")
    build["containerfile"] = relative_posix(build["containerfile"], "containerfile", allow_dot=False)
    if not isinstance(build["generated"], bool):
        raise DeploymentRefusal("invalid_contract", "build generated must be boolean")
    image = _mapping(service["image"], {"reference", "acceptedDigest"}, "service image")
    if build["mode"] == "image":
        if not isinstance(image["reference"], str) or _IMAGE.fullmatch(image["reference"]) is None:
            raise DeploymentRefusal("mutable_image", "image deployments require an immutable digest reference")
    elif image["reference"] is not None:
        raise DeploymentRefusal("invalid_contract", "source builds may not carry a runtime image reference")
    if image["acceptedDigest"] is not None:
        raise DeploymentRefusal(
            "invalid_contract",
            "accepted image identity belongs to observed deployment state, not a proposal",
        )

    runtime = _mapping(service["runtime"], {"command", "workdir", "user", "readOnlyRoot"}, "service runtime")
    command = _sequence(runtime["command"], "runtime command")
    if not command or any(
        not isinstance(item, str)
        or not item
        or "\x00" in item
        or len(item) > 4096
        or _SECRET_VALUE.search(item)
        for item in command
    ):
        raise DeploymentRefusal("invalid_command", "runtime command must be a bounded argv vector")
    runtime["command"] = command
    runtime["workdir"] = _bounded_text(runtime["workdir"], "runtime workdir", maximum=256)
    if not runtime["workdir"].startswith("/") or ".." in runtime["workdir"].split("/"):
        raise DeploymentRefusal("unsafe_path", "runtime workdir must be an absolute container path")
    user = _mapping(runtime["user"], {"mode", "uid", "gid"}, "runtime user")
    if (
        user["mode"] != "nonroot"
        or isinstance(user["uid"], bool)
        or not isinstance(user["uid"], int)
        or not 1 <= user["uid"] <= 2**31 - 1
        or isinstance(user["gid"], bool)
        or not isinstance(user["gid"], int)
        or not 1 <= user["gid"] <= 2**31 - 1
    ):
        raise DeploymentRefusal("root_runtime", "deployment services must run as a non-root numeric user")
    if runtime["readOnlyRoot"] is not True:
        raise DeploymentRefusal("unsafe_runtime", "deployment root filesystem must be read-only")

    ports: list[dict[str, Any]] = []
    port_names: set[str] = set()
    for raw in _sequence(service["ports"], "service ports"):
        port = _mapping(raw, {"name", "containerPort", "hostAddress", "hostPort"}, "service port")
        port["name"] = _runtime_id(port["name"], "port name")
        if port["name"] in port_names:
            raise DeploymentRefusal("invalid_contract", "service port names must be unique")
        port_names.add(port["name"])
        port["containerPort"] = _positive_int(port["containerPort"], "container port")
        port["hostPort"] = _nonnegative_int(port["hostPort"], "host port")
        if port["hostAddress"] not in {"127.0.0.1", "::1"}:
            raise DeploymentRefusal(
                "public_port_forbidden",
                "Slice A permits loopback host ports only",
            )
        ports.append(port)
    service["ports"] = ports

    health = _mapping(
        service["health"],
        {"type", "path", "portName", "command", "intervalSeconds", "timeoutSeconds", "startPeriodSeconds"},
        "service health",
    )
    if health["type"] not in {"http", "command"}:
        raise DeploymentRefusal("missing_health", "service health type must be http or command")
    if health["type"] == "http":
        if not isinstance(health["path"], str) or not health["path"].startswith("/") or "\x00" in health["path"]:
            raise DeploymentRefusal("invalid_contract", "HTTP health path is invalid")
        if health["portName"] not in port_names:
            raise DeploymentRefusal("invalid_contract", "HTTP health must reference a declared port")
    elif health["path"] is not None or health["portName"] is not None:
        raise DeploymentRefusal("invalid_contract", "command health may not carry HTTP fields")
    health_command = _sequence(health["command"], "health command")
    if not health_command or any(
        not isinstance(item, str)
        or not item
        or "\x00" in item
        or len(item) > 4096
        or _SECRET_VALUE.search(item)
        for item in health_command
    ):
        raise DeploymentRefusal("missing_health", "health command must be a bounded argv vector")
    health["command"] = health_command
    for name in ("intervalSeconds", "timeoutSeconds", "startPeriodSeconds"):
        health[name] = _positive_int(health[name], f"health {name}", maximum=3600)

    resources = _mapping(service["resources"], {"memoryLimit", "cpuLimit", "pidsLimit"}, "service resources")
    if not isinstance(resources["memoryLimit"], str) or re.fullmatch(r"[1-9][0-9]*(?:[kKmMgG])?", resources["memoryLimit"]) is None:
        raise DeploymentRefusal("invalid_contract", "memory limit is invalid")
    if isinstance(resources["cpuLimit"], bool) or not isinstance(resources["cpuLimit"], (int, float)) or not 0 < float(resources["cpuLimit"]) <= 64:
        raise DeploymentRefusal("invalid_contract", "CPU limit is invalid")
    resources["cpuLimit"] = float(resources["cpuLimit"])
    resources["pidsLimit"] = _positive_int(resources["pidsLimit"], "pids limit", maximum=32768)

    storage: list[dict[str, Any]] = []
    storage_ids: set[str] = set()
    for raw in _sequence(service["storage"], "service storage"):
        item = _mapping(raw, {"id", "mountPath", "persistence"}, "storage")
        item["id"] = _runtime_id(item["id"], "storage id")
        if item["id"] in storage_ids:
            raise DeploymentRefusal("invalid_contract", "service storage ids must be unique")
        storage_ids.add(item["id"])
        mount = _bounded_text(item["mountPath"], "storage mountPath", maximum=256)
        unsafe_roots = ("/etc", "/var", "/run", "/home", "/proc", "/sys", "/dev", "/usr", "/boot", "/root")
        if not mount.startswith("/") or ".." in mount.split("/") or mount == "/" or any(mount == root or mount.startswith(root + "/") for root in unsafe_roots):
            raise DeploymentRefusal("unsafe_mount", "storage mountPath is unsafe")
        if item["persistence"] not in {"ephemeral", "retained", "backup_required", "externally_managed"}:
            raise DeploymentRefusal("invalid_contract", "storage persistence is invalid")
        storage.append(item)
    service["storage"] = storage

    secrets: list[dict[str, str]] = []
    secret_ids: set[str] = set()
    for raw in _sequence(service["secrets"], "service secrets"):
        secret = _mapping(raw, {"id", "binding"}, "service secret")
        secret["id"] = _runtime_id(secret["id"], "secret id")
        if secret["id"] in secret_ids:
            raise DeploymentRefusal("invalid_contract", "service secret ids must be unique")
        secret_ids.add(secret["id"])
        if (
            not isinstance(secret["binding"], str)
            or re.fullmatch(r"secret-broker://[A-Za-z0-9][A-Za-z0-9._/-]{0,255}", secret["binding"]) is None
            or ".." in secret["binding"].split("/")
            or _SECRET_VALUE.search(secret["binding"])
        ):
            raise DeploymentRefusal("secret_value_forbidden", "secrets must use broker identifiers, never values")
        secrets.append({"id": secret["id"], "binding": secret["binding"]})
    service["secrets"] = secrets

    if not isinstance(service["environment"], Mapping):
        raise DeploymentRefusal("invalid_contract", "service environment must be an object")
    environment: dict[str, str] = {}
    for key, value in service["environment"].items():
        if not isinstance(key, str) or re.fullmatch(r"[A-Z_][A-Z0-9_]{0,127}", key) is None or _SECRET_KEY.search(key):
            raise DeploymentRefusal("secret_value_forbidden", "secret-like environment keys must use secret bindings")
        if not isinstance(value, str) or len(value) > 4096 or "\x00" in value or _SECRET_VALUE.search(value):
            raise DeploymentRefusal("secret_value_forbidden", "environment contains an unsafe value")
        environment[key] = value
    environment.setdefault("PATH", DEFAULT_RUNTIME_PATH)
    environment.setdefault("HOME", "/tmp")
    service["environment"] = dict(sorted(environment.items()))
    networks = _sequence(service["networks"], "service networks")
    if not networks or any(item not in network_ids for item in networks) or len(networks) != len(set(networks)):
        raise DeploymentRefusal("invalid_contract", "service networks must reference unique declared networks")
    service["networks"] = networks
    service["build"], service["image"], service["runtime"] = build, image, runtime
    service["health"], service["resources"] = health, resources
    return service


def validate_deployment_spec(value: object, *, materialized: bool = True) -> dict[str, Any]:
    spec = _mapping(
        value,
        {"schema", "metadata", "source", "target", "services", "networks", "authority", "policy"},
        "deployment specification",
    )
    if spec["schema"] != DEPLOYMENT_SCHEMA:
        raise DeploymentRefusal("unsupported_schema", f"deployment schema must be {DEPLOYMENT_SCHEMA}")
    metadata = _mapping(spec["metadata"], {"deploymentId", "applicationId", "name"}, "deployment metadata")
    metadata["deploymentId"] = _runtime_id(metadata["deploymentId"], "deployment id")
    metadata["applicationId"] = _runtime_id(metadata["applicationId"], "application id")
    metadata["name"] = _bounded_text(metadata["name"], "deployment name", maximum=160)
    source = _validate_source(spec["source"], materialized=materialized)
    target = _mapping(spec["target"], {"adapter", "targetId", "architecture", "identityDigest"}, "deployment target")
    if target["adapter"] != TARGET_ADAPTER or target["targetId"] != "local" or target["architecture"] != ARCHITECTURE:
        raise DeploymentRefusal("unsupported_target", "Slice A supports local Linux AMD64 rootless Podman only")
    if materialized and (not isinstance(target["identityDigest"], str) or DIGEST.fullmatch(target["identityDigest"]) is None):
        raise DeploymentRefusal("target_identity_missing", "materialized target identity is incomplete")
    if not materialized and target["identityDigest"] is not None and DIGEST.fullmatch(str(target["identityDigest"])) is None:
        raise DeploymentRefusal("invalid_contract", "target identity digest is invalid")

    networks: list[dict[str, Any]] = []
    network_ids: set[str] = set()
    for raw in _sequence(spec["networks"], "deployment networks"):
        network = _mapping(raw, {"id", "public"}, "network")
        network["id"] = _runtime_id(network["id"], "network id")
        if network["id"] in network_ids or not isinstance(network["public"], bool):
            raise DeploymentRefusal("invalid_contract", "networks must have unique ids and boolean public state")
        if network["public"]:
            raise DeploymentRefusal("public_network_forbidden", "Slice A does not support public container networks")
        network_ids.add(network["id"])
        networks.append(network)
    if not networks:
        raise DeploymentRefusal("invalid_contract", "at least one private network is required")
    services = [_validate_service(item, network_ids, materialized=materialized) for item in _sequence(spec["services"], "services")]
    if not services or len({item["id"] for item in services}) != len(services):
        raise DeploymentRefusal("invalid_contract", "deployment service ids must be non-empty and unique")
    storage_owners: dict[str, tuple[str, str]] = {}
    for service in services:
        for item in service["storage"]:
            identity = (item["mountPath"], item["persistence"])
            prior = storage_owners.get(item["id"])
            if prior is not None and prior != identity:
                raise DeploymentRefusal(
                    "storage_identity_conflict",
                    "shared storage ids must have identical mount and persistence semantics",
                )
            storage_owners[item["id"]] = identity

    authority = _mapping(spec["authority"], {"grantId", "requireApproval", "automaticWithReceipt"}, "deployment authority")
    if authority["grantId"] is not None:
        if (
            not isinstance(authority["grantId"], str)
            or _AUTHORITY_GRANT_ID.fullmatch(authority["grantId"]) is None
        ):
            raise DeploymentRefusal(
                "invalid_identity",
                "grant id must use the canonical authority grant identity",
            )
    approvals = _sequence(authority["requireApproval"], "required approvals")
    allowed_approvals = {"first_apply", "non_loopback_port", "secret_binding", "destructive_replacement", "data_purge"}
    if any(item not in allowed_approvals for item in approvals) or len(approvals) != len(set(approvals)) or "first_apply" not in approvals:
        raise DeploymentRefusal("invalid_contract", "deployment approval policy is invalid")
    automatic = _sequence(authority["automaticWithReceipt"], "automatic actions")
    allowed_automatic = {"health_check", "restart", "log_collection", "observe", "remove_runtime_preserve_data"}
    if any(item not in allowed_automatic for item in automatic) or len(automatic) != len(set(automatic)):
        raise DeploymentRefusal("invalid_contract", "automatic deployment policy is invalid")
    authority["requireApproval"], authority["automaticWithReceipt"] = approvals, automatic
    policy = _mapping(spec["policy"], {"ordinaryRemovePreservesData", "rollbackOnFailedHealth"}, "deployment policy")
    if policy["ordinaryRemovePreservesData"] is not True or policy["rollbackOnFailedHealth"] is not True:
        raise DeploymentRefusal("invalid_contract", "mandatory data and rollback policy is missing")

    spec.update(metadata=metadata, source=source, target=target, services=services, networks=networks, authority=authority, policy=policy)
    return deepcopy(spec)


def plan_digest(plan: Mapping[str, Any]) -> str:
    unsigned = dict(plan)
    unsigned.pop("planDigest", None)
    # revisionId is defined as the plan digest of a revision plan; it is
    # excluded so the identity can be computed without a fixpoint.
    unsigned.pop("revisionId", None)
    return digest_value(unsigned)


def deployment_creation_changes(spec: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Return the exact, reviewable first-apply change set for a valid spec."""

    changes: list[dict[str, Any]] = []
    for network in spec["networks"]:
        changes.append(
            {
                "kind": "network",
                "action": "create",
                "id": network["id"],
                "public": network["public"],
            }
        )
    for service in spec["services"]:
        service_id = service["id"]
        changes.append(
            {
                "kind": "service",
                "action": "create",
                "id": service_id,
                "buildMode": service["build"]["mode"],
                "networks": list(service["networks"]),
            }
        )
        changes.append(
            {
                "kind": "image",
                "action": (
                    "build" if service["build"]["mode"] == "source" else "pull"
                ),
                "id": service_id,
                "serviceId": service_id,
                "reference": service["image"]["reference"],
                "acceptedDigest": service["image"]["acceptedDigest"],
            }
        )
        for port in service["ports"]:
            changes.append(
                {
                    "kind": "port",
                    "action": "bind",
                    "id": f"{service_id}.{port['name']}",
                    "serviceId": service_id,
                    "name": port["name"],
                    "containerPort": port["containerPort"],
                    "hostAddress": port["hostAddress"],
                    "hostPort": port["hostPort"],
                }
            )
        for storage in service["storage"]:
            changes.append(
                {
                    "kind": "storage",
                    "action": "mount",
                    "id": f"{service_id}.{storage['id']}",
                    "serviceId": service_id,
                    "storageId": storage["id"],
                    "mountPath": storage["mountPath"],
                    "persistence": storage["persistence"],
                }
            )
        for secret in service["secrets"]:
            changes.append(
                {
                    "kind": "secret_binding",
                    "action": "bind",
                    "id": f"{service_id}.{secret['id']}",
                    "serviceId": service_id,
                    "secretId": secret["id"],
                    "binding": secret["binding"],
                }
            )
    return changes


def deployment_update_changes(
    prior_spec: Mapping[str, Any], new_spec: Mapping[str, Any]
) -> list[dict[str, Any]]:
    """Return the exact, reviewable change set moving an accepted spec to a new one.

    Every entry keeps the full creation-shape detail of the resource it names;
    only the ``action`` verb differs (``create``, ``update``, ``remove``).
    """

    changes: list[dict[str, Any]] = []
    prior_source = prior_spec["source"]
    new_source = new_spec["source"]
    if prior_source != new_source:
        changes.append(
            {
                "kind": "source",
                "action": "update",
                "id": "source",
                "fromCommit": prior_source["commit"],
                "toCommit": new_source["commit"],
                "fromTreeDigest": prior_source["treeDigest"],
                "toTreeDigest": new_source["treeDigest"],
                "fromDirtyDigest": prior_source["dirtyDigest"],
                "toDirtyDigest": new_source["dirtyDigest"],
                "fromDescriptorDigest": prior_source["descriptorDigest"],
                "toDescriptorDigest": new_source["descriptorDigest"],
            }
        )
    prior = deployment_creation_changes(prior_spec)
    new = deployment_creation_changes(new_spec)
    prior_by_key = {(item["kind"], item["id"]): item for item in prior}
    new_by_key = {(item["kind"], item["id"]): item for item in new}
    for item in new:
        key = (item["kind"], item["id"])
        previous = prior_by_key.get(key)
        if previous is None:
            changes.append(item)
        elif previous != item:
            changed = deepcopy(item)
            changed["action"] = "update"
            changes.append(changed)
    for item in prior:
        if (item["kind"], item["id"]) not in new_by_key:
            removed = deepcopy(item)
            removed["action"] = "remove"
            changes.append(removed)
    return changes


def validate_plan(value: object, *, now: datetime | None = None) -> dict[str, Any]:
    operation = value.get("operation") if isinstance(value, Mapping) else None
    base_keys = {"schema", "planId", "planDigest", "operation", "predecessorRevision", "createdAt", "expiresAt", "spec", "sourceInventory", "changes", "risks", "destructiveEffects", "dataRetentionEffects", "authorityDecision", "overlay", "evidencePath"}
    revision_keys = {"revisionId", "supersedes", "rollbackOf"}
    backup_keys = {"backupId"}
    restore_keys = {"backupId", "backupDigest"}
    expected_keys = (
        base_keys | revision_keys
        if operation in {"update", "rollback"}
        else (
            base_keys | backup_keys
            if operation == "backup_data"
            else base_keys | restore_keys if operation == "restore_data" else base_keys
        )
    )
    plan = _mapping(value, expected_keys, "deployment plan")
    if plan["schema"] != PLAN_SCHEMA:
        raise DeploymentRefusal("unsupported_schema", "deployment plan schema is unsupported")
    safe_id(plan["planId"], "plan id")
    if plan["operation"] not in {
        "apply",
        "update",
        "rollback",
        "backup_data",
        "restore_data",
        "purge_data",
    }:
        raise DeploymentRefusal("invalid_contract", "deployment plan operation is invalid")
    predecessor = plan["predecessorRevision"]
    if (
        (plan["operation"] == "apply" and predecessor is not None)
        or (
            plan["operation"]
            in {"update", "rollback", "backup_data", "restore_data", "purge_data"}
            and (
                not isinstance(predecessor, str)
                or DIGEST.fullmatch(predecessor) is None
            )
        )
    ):
        raise DeploymentRefusal(
            "invalid_contract", "deployment plan predecessor is invalid"
        )
    if plan["operation"] in {"update", "rollback"}:
        if (
            plan["supersedes"] != predecessor
            or plan["revisionId"] != plan["planDigest"]
            or (
                plan["operation"] == "update"
                and plan["rollbackOf"] is not None
            )
            or (
                plan["operation"] == "rollback"
                and (
                    not isinstance(plan["rollbackOf"], str)
                    or DIGEST.fullmatch(plan["rollbackOf"]) is None
                    or plan["rollbackOf"] == predecessor
                )
            )
        ):
            raise DeploymentRefusal(
                "invalid_contract", "deployment revision lineage is invalid"
            )
    if plan["operation"] in {"backup_data", "restore_data"}:
        safe_id(plan["backupId"], "backup id")
        if plan["operation"] == "restore_data" and (
            not isinstance(plan["backupDigest"], str)
            or DIGEST.fullmatch(plan["backupDigest"]) is None
        ):
            raise DeploymentRefusal(
                "invalid_contract", "restore plan backup digest is invalid"
            )
    if not isinstance(plan["planDigest"], str) or plan["planDigest"] != plan_digest(plan):
        raise DeploymentRefusal("plan_digest_mismatch", "deployment plan digest is invalid")
    try:
        created = datetime.fromisoformat(str(plan["createdAt"]).replace("Z", "+00:00"))
        expires = datetime.fromisoformat(str(plan["expiresAt"]).replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise DeploymentRefusal("invalid_contract", "deployment plan timestamps are invalid") from exc
    if (
        created.tzinfo is None
        or expires.tzinfo is None
        or created.utcoffset() != timezone.utc.utcoffset(created)
        or expires.utcoffset() != timezone.utc.utcoffset(expires)
        or created.microsecond
        or expires.microsecond
        or plan["createdAt"] != created.isoformat().replace("+00:00", "Z")
        or plan["expiresAt"] != expires.isoformat().replace("+00:00", "Z")
        or expires <= created
        or (expires - created).total_seconds() > 86400
    ):
        raise DeploymentRefusal("invalid_contract", "deployment plan expiry is invalid")
    if now is not None and (
        now.tzinfo is None or now.utcoffset() != timezone.utc.utcoffset(now)
    ):
        raise DeploymentRefusal("invalid_contract", "plan validation time must be aware UTC")
    if now is not None and now >= expires:
        raise DeploymentRefusal("plan_expired", "deployment plan expired; prepare a new exact plan")
    plan["spec"] = validate_deployment_spec(plan["spec"], materialized=True)
    if plan["spec"]["authority"]["grantId"] is None:
        raise DeploymentRefusal(
            "authority_required",
            "a materialized deployment plan must bind an exact grant",
        )
    inventory = _sequence(plan["sourceInventory"], "source inventory")
    if not inventory:
        raise DeploymentRefusal("invalid_contract", "deployment source inventory may not be empty")
    normalized_inventory: list[dict[str, str]] = []
    for raw in inventory:
        item = _mapping(
            raw,
            {"path", "mode", "objectId", "contentDigest"},
            "source inventory item",
        )
        item["path"] = relative_posix(item["path"], "source inventory path", allow_dot=False)
        if (
            item["mode"] not in {"100644", "100755"}
            or not isinstance(item["objectId"], str)
            or re.fullmatch(r"[0-9a-f]{40,64}", item["objectId"]) is None
            or not isinstance(item["contentDigest"], str)
            or DIGEST.fullmatch(item["contentDigest"]) is None
        ):
            raise DeploymentRefusal("invalid_contract", "source inventory item is invalid")
        normalized_inventory.append(item)
    if normalized_inventory != sorted(normalized_inventory, key=lambda item: item["path"]) or len({item["path"] for item in normalized_inventory}) != len(normalized_inventory):
        raise DeploymentRefusal("invalid_contract", "source inventory must be sorted and unique")
    if digest_value(normalized_inventory) != plan["spec"]["source"]["treeDigest"]:
        raise DeploymentRefusal("source_identity_mismatch", "source inventory does not match the exact tree digest")
    plan["sourceInventory"] = normalized_inventory
    for name in ("changes", "risks", "destructiveEffects", "dataRetentionEffects"):
        if not isinstance(plan[name], list) or len(plan[name]) > 1024:
            raise DeploymentRefusal("invalid_contract", f"plan {name} must be a list")
    decision = _mapping(plan["authorityDecision"], {"status", "required", "reason"}, "authority decision")
    if decision["status"] != "awaiting_approval" or not isinstance(decision["required"], list) or not decision["required"]:
        raise DeploymentRefusal("invalid_contract", "deployment plan must await exact approval")
    if (
        plan["operation"] in {"apply", "update", "rollback"}
        and decision["required"]
        != plan["spec"]["authority"]["requireApproval"]
    ):
        raise DeploymentRefusal(
            "invalid_contract",
            "plan approval requirements must exactly match deployment authority",
        )
    if not isinstance(decision["reason"], str) or not decision["reason"] or len(decision["reason"]) > 1024:
        raise DeploymentRefusal("invalid_contract", "deployment plan approval reason is invalid")
    if plan["operation"] in {"apply", "update", "rollback"}:
        storage: dict[str, str] = {}
        for service in plan["spec"]["services"]:
            for item in service["storage"]:
                storage[item["id"]] = item["persistence"]
        expected_retention = [
            {
                "storageId": storage_id,
                "persistence": persistence,
                "ordinaryRemove": (
                    "removed" if persistence == "ephemeral" else "retained"
                ),
            }
            for storage_id, persistence in sorted(storage.items())
        ]
        if plan["operation"] == "apply":
            exact_changes = plan["changes"] != deployment_creation_changes(plan["spec"])
        else:
            # Exact diff equality against the superseded revision is enforced
            # by the store, which owns the predecessor plan; here the shape
            # must be exact so no undocumented effect can hide in a plan.
            exact_changes = any(
                not isinstance(item, Mapping)
                or "kind" not in item
                or "id" not in item
                or item.get("action")
                not in {"create", "update", "remove", "bind", "mount", "build", "pull"}
                for item in plan["changes"]
            )
        if (
            exact_changes
            or plan["destructiveEffects"] != []
            or plan["dataRetentionEffects"] != expected_retention
            or any(
                not isinstance(item, str)
                or item
                not in {
                    "non_loopback_port",
                    "secret_binding_unavailable_in_slice_a",
                }
                for item in plan["risks"]
            )
            or len(plan["risks"]) != len(set(plan["risks"]))
        ):
            raise DeploymentRefusal(
                "invalid_contract", "apply plan effects are not exact"
            )
    elif plan["operation"] == "purge_data":
        changes = plan["changes"]
        effects = plan["destructiveEffects"]
        if (
            not changes
            or any(
                not isinstance(item, Mapping)
                or set(item) != {"kind", "action", "id"}
                or item.get("kind") != "storage"
                or item.get("action") != "purge"
                for item in changes
            )
            or len({item["id"] for item in changes}) != len(changes)
            or len(effects) != len(changes)
            or any(
                not isinstance(item, Mapping)
                or set(item) != {"kind", "name", "irreversible"}
                or item.get("kind") != "volume"
                or not isinstance(item.get("name"), str)
                or not item.get("name")
                or item.get("irreversible") is not True
                for item in effects
            )
            or plan["risks"] != ["irreversible_data_loss"]
            or len(plan["dataRetentionEffects"]) != 1
            or not isinstance(plan["dataRetentionEffects"][0], Mapping)
            or set(plan["dataRetentionEffects"][0]) != {"from", "to"}
            or plan["dataRetentionEffects"][0].get("from")
            not in {"retained", "retained_after_failed_apply"}
            or plan["dataRetentionEffects"][0].get("to") != "purged"
            or decision["required"] != ["data_purge"]
        ):
            raise DeploymentRefusal(
                "invalid_contract", "purge plan effects are not exact"
            )
    else:
        backup_id = plan["backupId"]
        storage_ids = sorted(
            {
                item["id"]
                for service in plan["spec"]["services"]
                for item in service["storage"]
                if item["persistence"] == "retained"
            }
        )
        action = "backup" if plan["operation"] == "backup_data" else "restore"
        expected_changes = [
            {
                "kind": "storage",
                "action": action,
                "id": storage_id,
                "backupId": backup_id,
            }
            for storage_id in storage_ids
        ]
        expected_risks = (
            ["service_pause"]
            if plan["operation"] == "backup_data"
            else ["service_pause", "data_replacement"]
        )
        expected_retention = [
            {
                "backupId": backup_id,
                "from": "present",
                "to": (
                    "snapshot_available"
                    if plan["operation"] == "backup_data"
                    else "restored_from_snapshot"
                ),
            }
        ]
        required = (
            ["data_backup"]
            if plan["operation"] == "backup_data"
            else ["data_restore"]
        )
        expected_destructive = (
            []
            if plan["operation"] == "backup_data"
            else [
                {"kind": "volume", "name": item, "irreversible": True}
                for item in sorted(
                    effect.get("name")
                    for effect in plan["destructiveEffects"]
                    if isinstance(effect, Mapping)
                    and isinstance(effect.get("name"), str)
                )
            ]
        )
        if (
            not storage_ids
            or plan["changes"] != expected_changes
            or plan["risks"] != expected_risks
            or plan["destructiveEffects"] != expected_destructive
            or (
                plan["operation"] == "restore_data"
                and len(plan["destructiveEffects"]) != len(storage_ids)
            )
            or plan["dataRetentionEffects"] != expected_retention
            or decision["required"] != required
        ):
            raise DeploymentRefusal(
                "invalid_contract", "backup or restore plan effects are not exact"
            )
    if not isinstance(plan["overlay"], Mapping) or any(not isinstance(key, str) or not isinstance(item, str) for key, item in plan["overlay"].items()):
        raise DeploymentRefusal("invalid_contract", "deployment overlay is invalid")
    for key in plan["overlay"]:
        relative_posix(key, "overlay path", allow_dot=False)
    if not isinstance(plan["evidencePath"], str) or not plan["evidencePath"]:
        raise DeploymentRefusal("invalid_contract", "plan evidencePath is invalid")
    return deepcopy(plan)


__all__ = [
    "ARCHITECTURE",
    "DEPLOYMENT_SCHEMA",
    "INSPECTION_SCHEMA",
    "LIFECYCLE_STATES",
    "PLAN_SCHEMA",
    "RECEIPT_SCHEMA",
    "STATE_SCHEMA",
    "TARGET_ADAPTER",
    "TRANSITIONS",
    "deployment_creation_changes",
    "deployment_update_changes",
    "plan_digest",
    "validate_deployment_spec",
    "validate_plan",
    "validate_transition",
]
