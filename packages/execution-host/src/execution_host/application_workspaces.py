"""Exact workspace bindings and independently authorized root-only issuance.

The renderer and readers never issue authority. The separate root transaction
publishes only caller-verified exact grants, under the shared revocation lock.
"""
from __future__ import annotations

import json
import fcntl
from datetime import datetime
import re
import secrets
import os
from pathlib import Path
import stat
from typing import Any, Callable, Mapping

from . import daemon_contract as contract

FORMAT = "stateport.application-workspace-bindings/v1"
MAX_BYTES = 1024 * 1024


def catalog_identity(entry: Mapping[str, Any]) -> str:
    metadata = entry.get("metadata") or {}
    identity = {
        "instanceId": entry.get("instanceId"),
        "applicationId": entry.get("applicationId"),
        "filesystem": entry.get("filesystem"),
        "source": metadata.get("source", entry.get("observedSource")),
        "managedIncarnation": metadata.get("managedIncarnation"),
    }
    # Preserve old grants until a record is upgraded, then bind the observed
    # persistent filesystem identity into every newly reviewed workspace grant.
    if "filesystemId" in metadata:
        identity["filesystemId"] = metadata["filesystemId"]
    return contract.canonical_digest(identity)


def validate_bindings(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, dict) or set(value) != {"formatVersion", "bindings"} or value["formatVersion"] != FORMAT:
        raise ValueError("application workspace binding document has invalid shape")
    rows = value["bindings"]
    if not isinstance(rows, list) or len(rows) > 64:
        raise ValueError("application workspace bindings must be bounded")
    instances: set[str] = set()
    workloads: set[str] = {"default-dev"}
    result = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"grantId", "authorityGrantDigest", "workload"}:
            raise ValueError("application workspace binding has invalid shape")
        contract._id(row["grantId"], "grantId")
        contract._digest(row["authorityGrantDigest"], "authorityGrantDigest")
        spec = contract.validate_workload_spec(row["workload"])
        if spec != row["workload"] or spec["kind"] != "workspace" or "ownership" not in spec["parameters"]:
            raise ValueError("application workspace binding requires an exact normalized owned workspace")
        instance = spec["parameters"]["ownership"]["instanceId"]
        if instance in instances or spec["workloadId"] in workloads:
            raise ValueError("application workspace bindings overlap")
        instances.add(instance)
        workloads.add(spec["workloadId"])
        result.append(dict(row))
    return result


def read_bindings(path: Path, *, operator_uid: int = 65532) -> list[dict[str, Any]]:
    """Read fresh on every operation; symlink/replacement/writable paths refuse.

    Production ownership is root or the confined execution-host UID. The web
    service never receives grant-store access. Explicit UID injection exists for
    local daemon tests and is not exposed to HTTP or environment configuration.
    """
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("application workspace binding path must be absolute")
    # Descriptor-relative traversal pins every parent against rename/symlink races.
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for index, component in enumerate(path.parts[1:]):
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if index < len(path.parts) - 2:
                flags |= os.O_DIRECTORY
            child = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if info.st_uid not in {0, operator_uid}:
                raise ValueError("application workspace binding path has untrusted ownership")
            if info.st_mode & 0o022 and not (stat.S_ISDIR(info.st_mode) and info.st_mode & stat.S_ISVTX and info.st_uid == 0):
                raise ValueError("application workspace binding path is writable by another identity")
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_BYTES:
            raise ValueError("application workspace bindings are not a bounded regular file")
        data = os.read(fd, MAX_BYTES + 1)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) or len(data) != before.st_size:
            raise ValueError("application workspace bindings changed during read")
        return validate_bindings(json.loads(data))
    finally:
        os.close(fd)


TRANSPORT_FORMAT = "stateport.application-workspace-bindings/v2"


def _validate_workspace_budget(spec: Mapping[str, Any], grant: Mapping[str, Any]) -> None:
    budgets = grant["budgets"]
    demands = {
        "maxTimeoutSeconds": spec["timeoutSeconds"],
        "maxOutputBytes": spec["outputByteBound"],
        "maxMemoryMaxBytes": spec["resources"]["memoryMaxBytes"],
        "maxPidsMax": spec["resources"]["pidsMax"],
        "maxCpuQuotaPercent": spec["parameters"].get("cpuQuotaPercent", 100),
        "maxDiskMaxBytes": spec["parameters"].get("diskMaxBytes", 16 * 1024 * 1024),
    }
    if any(demand > budgets[key] for key, demand in demands.items()):
        raise ValueError("workspace specification exceeds its exact grant budget")


def validate_binding_transport(value: Any) -> list[dict[str, Any]]:
    """Validate untrusted grant preimages; this NEVER authenticates authority.

    Before catalog/source/terminal effects the caller must authenticate each
    presented digest with the private daemon over its independently trusted
    fixed socket. No actor/history/context claim is authenticated by this format.
    """
    if not isinstance(value, dict) or set(value) != {"formatVersion", "bindings"} or value["formatVersion"] != TRANSPORT_FORMAT:
        raise ValueError("workspace transport requires exact v2 format")
    rows = value["bindings"]
    if not isinstance(rows, list) or len(rows) > 64:
        raise ValueError("workspace transport must be bounded")
    logical = []
    result = []
    for raw in rows:
        if not isinstance(raw, dict) or set(raw) != {"grantId", "authorityGrantDigest", "workload", "grant"}:
            raise ValueError("workspace transport row has invalid shape")
        row = {key: raw[key] for key in ("grantId", "authorityGrantDigest", "workload")}
        spec = validate_bindings({"formatVersion": FORMAT, "bindings": [row]})[0]["workload"]
        grant = contract.validate_grant_document(raw["grant"])
        wid = spec["workloadId"]
        if (grant != raw["grant"] or grant["grantId"] != row["grantId"]
                or contract.canonical_digest(grant) != row["authorityGrantDigest"]
                or grant["peerUid"] != _CONTROL_UID
                or grant["workloadIds"] != [wid] or grant["workloadKinds"] != ["workspace"]
                or grant["workloadSpecDigests"] != {wid: contract.canonical_digest(spec)}
                or grant["imageReference"] != spec["image"]["reference"]
                or grant["baseRevision"] != spec["parameters"].get("baseRevision")
                or not {"createWorkload", "listWorkloads"} <= set(grant["operations"])
                or not set(grant["operations"]) <= set(_TERMINAL_PROFILE_OPERATIONS)):
            raise ValueError("workspace transport grant does not bind exact workspace authority")
        _validate_workspace_budget(spec, grant)
        logical.append(row)
        result.append({**row, "grant": grant})
    validate_bindings({"formatVersion": FORMAT, "bindings": logical})
    # Detach the validated snapshot from mutable caller-owned input.
    return json.loads(contract.canonical_json(result))


def read_binding_transport(path: Path) -> list[dict[str, Any]]:
    """Read bounded UNTRUSTED v2 transport, never fall back to v1 or owner trust.

    Arbitrary filesystem UIDs (including overflow UIDs) convey no authority.
    Descriptor-relative no-follow traversal pins the read; changed bytes refuse.
    An absent/empty transport is not permission to select a default or host path.
    """
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("workspace transport path must be absolute")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for index, component in enumerate(path.parts[1:]):
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if index < len(path.parts) - 2:
                flags |= os.O_DIRECTORY
            child = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= MAX_BYTES:
            raise ValueError("workspace transport must be a bounded single-link regular file")
        data = os.read(fd, MAX_BYTES + 1)
        if _fingerprint(before) != _fingerprint(os.fstat(fd)) or len(data) != before.st_size:
            raise ValueError("workspace transport changed during read")
        return validate_binding_transport(json.loads(data))
    finally:
        os.close(fd)


def render_bindings(reviewed: Any) -> dict[str, Any]:
    """Render public binding metadata from exact operator-reviewed grant inputs.

    This does not issue, approve, install or write a grant. The existing private
    daemon grant store remains the sole authority. The operator must separately
    publish those exact grants through the trusted provisioning boundary.
    """
    if not isinstance(reviewed, list) or not 1 <= len(reviewed) <= 64:
        raise ValueError("reviewed inputs must be a bounded nonempty list")
    rows = []
    for item in reviewed:
        if not isinstance(item, dict) or set(item) != {"catalogEntry", "workload", "grant"}:
            raise ValueError("reviewed input requires catalogEntry, workload and grant")
        spec = contract.validate_workload_spec(item["workload"])
        grant = contract.validate_grant_document(item["grant"])
        owner = spec["parameters"].get("ownership")
        entry = item["catalogEntry"]
        if not isinstance(owner, dict) or not isinstance(entry, dict) or owner["instanceId"] != entry.get("instanceId") or owner["applicationId"] != entry.get("applicationId") or owner["catalogIdentityDigest"] != catalog_identity(entry):
            raise ValueError("workspace ownership differs from reviewed catalog identity")
        if grant["workloadSpecDigests"].get(spec["workloadId"]) != contract.canonical_digest(spec) or spec["workloadId"] not in grant["workloadIds"] or spec["image"]["reference"] != grant["imageReference"]:
            raise ValueError("reviewed grant does not bind the exact sealed workspace")
        rows.append({"grantId": grant["grantId"], "authorityGrantDigest": contract.canonical_digest(grant), "workload": spec})
    value = {"formatVersion": FORMAT, "bindings": rows}
    validate_bindings(value)
    return value


REQUEST_FORMAT = "stateport.workspace-authority-request/v1"
SOURCE_REQUEST_FORMAT = "stateport.workspace-authority-request/v2"
RECEIPT_FORMAT = "stateport.workspace-authority-receipt/v1"
_ROOT_UID = 0
_EXEC_UID = 65532
_CONTROL_UID = 65531
ISSUER_LOCK_NAME = ".workspace-authority.lock"
_WORKSPACE_OPERATIONS = frozenset({
    "createWorkload", "listWorkloads", "status", "logs", "start", "stop",
    "cancel", "removeWorkload", "execWorkload",
})


TERMINAL_PROFILE_ID = "stateport.empty-workspace-terminal/v1"
SOURCE_PROFILE_ID = "stateport.reviewed-source-workspace-terminal/v1"
AUTHORITY_PROFILE_FORMAT = "stateport.workspace-authority-profile/v1"
_TERMINAL_PROFILE_OPERATIONS = (
    "createWorkload", "listWorkloads", "status", "logs", "start", "stop",
    "cancel", "removeWorkload", "execWorkload", "openTerminal", "resizeTerminal",
    "signalTerminal", "closeTerminal",
)


def terminal_authority_profile(workload_template: Any) -> dict[str, Any]:
    """Bind an exact reviewed template AND explicit terminal operation policy.

    The root issuer and browser must supply their pinned installed template;
    arbitrary transport templates do not become approved through this helper.
    Existing workspace grants and workload-only profile digests are unchanged.
    """
    spec = contract.validate_workload_spec(workload_template)
    if (spec != workload_template or spec["kind"] != "workspace" or spec["workloadId"] != "default-dev"
            or spec["parameters"].get("workspaceId") != "default-dev"
            or spec["parameters"].get("shell") != ["/bin/sh"]
            or spec["parameters"].get("networkMode") != "none"
            or spec["parameters"].get("cacheVolumes") != []
            or "ownership" in spec["parameters"] or "sourceSeed" in spec["parameters"]):
        raise ValueError("terminal authority profile requires an exact empty isolated workspace template")
    return json.loads(contract.canonical_json({"formatVersion": AUTHORITY_PROFILE_FORMAT,
        "profileId": TERMINAL_PROFILE_ID, "sourceMode": "empty", "workload": spec,
        "operations": list(_TERMINAL_PROFILE_OPERATIONS)}))


def validate_terminal_authority_profile(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"formatVersion", "profileId", "sourceMode", "workload", "operations"}:
        raise ValueError("terminal authority profile has invalid shape")
    expected = terminal_authority_profile(value["workload"])
    if value != expected:
        raise ValueError("terminal authority profile differs from the fixed operation policy")
    return expected


def source_authority_profile(workload_template: Any) -> dict[str, Any]:
    """A distinct installed policy; the existing empty policy never widens."""
    profile = terminal_authority_profile(workload_template)
    return {**profile, "formatVersion": "stateport.workspace-authority-profile/v2",
            "profileId": SOURCE_PROFILE_ID, "sourceMode": "reviewed-commit"}


def validate_source_authority_profile(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"formatVersion", "profileId", "sourceMode", "workload", "operations"}:
        raise ValueError("source authority profile has invalid shape")
    expected = source_authority_profile(value["workload"])
    if value != expected:
        raise ValueError("source authority profile differs from the fixed operation policy")
    return expected


def _instant(value: Any) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value):
        raise ValueError("authority timestamps must be UTC seconds ending in Z")
    return datetime.fromisoformat(value[:-1] + "+00:00")


def validate_workspace_authority_request(raw: Any) -> dict[str, Any]:
    keys = {"formatVersion", "instanceId", "applicationId", "catalogIdentityDigest",
            "issuerContextDigest", "profileDigest", "sourceMode", "createdAt",
            "expiresAt", "grantExpiresAt", "requestDigest"}
    source_request = isinstance(raw, dict) and raw.get("formatVersion") == SOURCE_REQUEST_FORMAT
    if source_request:
        keys |= {"source", "sourceDigest"}
    if not isinstance(raw, dict) or set(raw) != keys or raw["formatVersion"] not in {REQUEST_FORMAT, SOURCE_REQUEST_FORMAT}:
        raise ValueError("workspace authority request has invalid shape")
    for key in ("instanceId", "applicationId"):
        contract._id(raw[key], key)
    for key in ("catalogIdentityDigest", "issuerContextDigest", "profileDigest", "requestDigest"):
        contract._digest(raw[key], key)
    if raw["sourceMode"] != ("reviewed-commit" if source_request else "empty"):
        raise ValueError("workspace authority source mode is unsupported")
    if source_request:
        from .workspace_source import validate_source_commit
        source = validate_source_commit(raw["source"])
        if source != raw["source"] or raw["sourceDigest"] != contract.canonical_digest(source):
            raise ValueError("workspace authority source commitment differs")
    created, expires, grant_expires = (_instant(raw[key]) for key in ("createdAt", "expiresAt", "grantExpiresAt"))
    if not 0 < (expires - created).total_seconds() <= 3600 or grant_expires <= created:
        raise ValueError("workspace authority review or grant expiry is invalid")
    if contract.canonical_digest({key: value for key, value in raw.items() if key != "requestDigest"}) != raw["requestDigest"]:
        raise ValueError("workspace authority request digest differs")
    return json.loads(contract.canonical_json(raw))


def workspace_authority_workload_id(request: Mapping[str, Any]) -> str:
    """Stable workspace identity for one catalog incarnation and fixed profile."""
    identity = {key: request[key] for key in ("instanceId", "catalogIdentityDigest", "profileDigest")}
    if request.get("formatVersion") == SOURCE_REQUEST_FORMAT:
        identity["sourceDigest"] = request["sourceDigest"]
    return "workspace-" + contract.canonical_digest(identity)[7:39]


def workspace_authority_workload_spec(request: Mapping[str, Any], template: Mapping[str, Any]) -> dict[str, Any]:
    """Derive only the fixed template and exact operator-reviewed source facts."""
    workload_id = workspace_authority_workload_id(request)
    spec = json.loads(contract.canonical_json(template))
    spec["workloadId"] = workload_id
    spec["parameters"].update(workspaceId=workload_id, volumeName="stateport-workspace-" + workload_id,
        ownership={"instanceId": request["instanceId"], "applicationId": request["applicationId"],
                   "catalogIdentityDigest": request["catalogIdentityDigest"], "runId": None})
    if request.get("formatVersion") == SOURCE_REQUEST_FORMAT:
        source = request["source"]
        spec["parameters"]["baseRevision"] = source["baseRevision"]
        seed = {key: source[key] for key in ("sourceInventory", "sourceArchive", "descriptorDigest")}
        review = {"workloadId": workload_id, "image": spec["image"]["reference"],
                  "ownership": spec["parameters"]["ownership"], "baseRevision": source["baseRevision"], **seed}
        spec["parameters"]["sourceSeed"] = {**seed, "reviewDigest": contract.canonical_digest(review)}
    return contract.validate_workload_spec(spec)


def _fingerprint(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _authority_directory(path: Path, *, owner: int, private: bool) -> int:
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("authority directory must be an absolute confined path")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            if info.st_uid not in {0, _ROOT_UID, _EXEC_UID} or (info.st_mode & 0o022 and not sticky_root):
                raise ValueError("authority path has untrusted ownership or permissions")
        info = os.fstat(fd)
        if info.st_uid != owner or (private and stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError("authority directory ownership or private mode differs")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _authority_read(directory: int, name: str, *, owner: int, mode: int, optional: bool = False) -> tuple[bytes, tuple[int, ...]] | None:
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    except FileNotFoundError:
        if optional:
            return None
        raise ValueError("required authority state is missing") from None
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != owner
                or stat.S_IMODE(before.st_mode) != mode or not 0 < before.st_size <= MAX_BYTES):
            raise ValueError("authority file ownership, type, mode or size differs")
        data = os.read(fd, MAX_BYTES + 1)
        if _fingerprint(before) != _fingerprint(os.fstat(fd)) or len(data) != before.st_size:
            raise ValueError("authority file changed during read")
        return data, _fingerprint(before)
    finally:
        os.close(fd)


def _authority_bytes(value: Any) -> bytes:
    data = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(data) > MAX_BYTES:
        raise ValueError("authority document exceeds size bound")
    return data


def _authority_create(directory: int, name: str, data: bytes, *, owner: int, mode: int) -> None:
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=directory)
    try:
        os.fchmod(fd, mode)
        if os.fstat(fd).st_uid != owner:
            os.fchown(fd, owner, owner)
        offset = 0
        while offset < len(data):
            offset += os.write(fd, data[offset:])
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(directory)


def _authority_cas(directory: int, name: str, expected: tuple[bytes, tuple[int, ...]] | None,
                   data: bytes, *, owner: int, mode: int) -> None:
    """Replace under ISSUER_LOCK_NAME after exact byte/inode comparison.

    Every legitimate StatePort issuer AND revocation writer must acquire the
    same grant-directory lock before read/modify/write. This is a cooperating
    writer CAS, not protection against arbitrary concurrent root modification.
    """
    observed = _authority_read(directory, name, owner=owner, mode=mode, optional=True)
    if observed != expected:
        raise ValueError("authority state changed before publication")
    if expected is None:
        _authority_create(directory, name, data, owner=owner, mode=mode)
        return
    temporary = ".workspace-authority-" + secrets.token_hex(16)
    _authority_create(directory, temporary, data, owner=owner, mode=mode)
    try:
        if _authority_read(directory, name, owner=owner, mode=mode) != expected:
            raise ValueError("authority state changed before replacement")
        os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass


def _authority_checkpoint(phase: str) -> None:
    """Internal fault-test seam; production never substitutes authority checks."""


def issue_workspace_authority(request: Any, *, grant: Any, binding: Any,
                              context_digest: str, operator: Any,
                              grants_dir: Path, bindings_path: Path, receipt_dir: Path,
                              verify_current: Callable[[], None], clock: Callable[[], str],
                              binding_format: str = FORMAT, authority_profile: Any = None) -> dict[str, Any]:
    """Publish already independently authorized exact workspace authority.

    This is a root issuer API, never an HTTP authorization endpoint. The caller
    resolves installed context, operator, catalog and fixed profile independently
    and rechecks them in verify_current. All cooperating revocation writers MUST
    hold grants_dir/ISSUER_LOCK_NAME; missing/corrupt revocation never resets.
    Pre-activation interruption leaves the grant paused until an exact live retry.
    Post-activation recovery requires a durable exact activation observation;
    unobservable crash gaps refuse automatic success reconstruction. Initial lock
    creation also holds the verified grants directory flock until lock open.
    binding_format opts fresh installations into untrusted v2 transport; existing
    documents and transaction journals are never implicitly migrated. Receipts
    retain the logical three-field binding digest, excluding the grant preimage.
    Terminal operations require authority_profile: the exact whole policy digest
    must be operator-reviewed in request.profileDigest. The caller independently
    selects its signed installed template; the default profile is never widened.
    """
    if os.geteuid() != _ROOT_UID:
        raise ValueError("workspace authority publication requires the root issuer")
    request = validate_workspace_authority_request(request)
    grant = contract.validate_grant_document(grant)
    row = validate_bindings({"formatVersion": FORMAT, "bindings": [binding]})[0]
    spec = row["workload"]
    owner = spec["parameters"]["ownership"]
    expected_grant_id = "workspace-grant-" + request["requestDigest"][7:39]
    workload_id = workspace_authority_workload_id(request)
    source_request = request["formatVersion"] == SOURCE_REQUEST_FORMAT
    if source_request and authority_profile is None:
        raise ValueError("source authority requires its independently installed profile")
    if authority_profile is not None:
        authority_profile = (validate_source_authority_profile(authority_profile) if source_request
                             else validate_terminal_authority_profile(authority_profile))
        if binding_format != TRANSPORT_FORMAT or contract.canonical_digest(authority_profile) != request["profileDigest"]:
            raise ValueError("terminal authority profile does not match exact reviewed request")
        expected_spec = workspace_authority_workload_spec(request, authority_profile["workload"])
        if spec != expected_spec or grant["operations"] != authority_profile["operations"]:
            raise ValueError("terminal grant differs from exact profile workload or operations")
    allowed_operations = set(_TERMINAL_PROFILE_OPERATIONS) if authority_profile is not None else _WORKSPACE_OPERATIONS
    if (context_digest != request["issuerContextDigest"] or grant["grantId"] != expected_grant_id
            or row["grantId"] != expected_grant_id or row["authorityGrantDigest"] != contract.canonical_digest(grant)
            or spec["workloadId"] != workload_id or owner["instanceId"] != request["instanceId"]
            or owner["applicationId"] != request["applicationId"] or owner["catalogIdentityDigest"] != request["catalogIdentityDigest"]
            or owner["runId"] is not None or ("sourceSeed" in spec["parameters"]) != source_request
            or grant["peerUid"] != _CONTROL_UID or grant["workloadIds"] != [workload_id]
            or grant["workloadKinds"] != ["workspace"]
            or grant["workloadSpecDigests"] != {workload_id: contract.canonical_digest(spec)}
            or grant["imageReference"] != spec["image"]["reference"]
            or grant["baseRevision"] != spec["parameters"].get("baseRevision")
            or not set(grant["operations"]) <= allowed_operations or "createWorkload" not in grant["operations"]
            or grant["issuedAt"] != request["createdAt"] or grant["expiresAt"] != request["grantExpiresAt"]):
        raise ValueError("workspace grant differs from exact reviewed authority")
    if (not isinstance(operator, dict) or set(operator) != {"user", "uid", "gid"}
            or not isinstance(operator["user"], str) or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", operator["user"])
            or type(operator["uid"]) is not int or type(operator["gid"]) is not int
            or operator["uid"] <= 0 or operator["gid"] <= 0):
        raise ValueError("workspace operator identity is invalid")
    if bindings_path.name in {"", ".", ".."}:
        raise ValueError("workspace binding path is invalid")
    if binding_format not in {FORMAT, TRANSPORT_FORMAT}:
        raise ValueError("unsupported workspace publication format")
    public_row = {**row, "grant": grant} if binding_format == TRANSPORT_FORMAT else row
    validate_public = validate_binding_transport if binding_format == TRANSPORT_FORMAT else validate_bindings
    validate_public({"formatVersion": binding_format, "bindings": [public_row]})
    inputs = {"request": request, "grant": grant, "binding": row, "contextDigest": context_digest, "operator": operator}
    if binding_format != FORMAT:
        inputs["bindingFormat"] = binding_format
    if authority_profile is not None:
        inputs["authorityProfile"] = authority_profile
    frozen = _authority_bytes(inputs)
    grant_bytes = _authority_bytes(grant)
    token = request["requestDigest"][7:]
    grants_fd = _authority_directory(grants_dir, owner=_EXEC_UID, private=True)
    bindings_fd = receipt_fd = public_receipt_fd = lock_fd = -1
    try:
        bindings_fd = _authority_directory(bindings_path.parent, owner=_ROOT_UID, private=False)
        public_receipt_fd = _authority_directory(receipt_dir, owner=_ROOT_UID, private=False)
        try:
            os.mkdir(".transactions", mode=0o700, dir_fd=public_receipt_fd)
            os.fsync(public_receipt_fd)
        except FileExistsError:
            pass
        receipt_fd = _authority_directory(receipt_dir / ".transactions", owner=_ROOT_UID, private=True)
        # Serialize first creation on the already verified directory inode so
        # another issuer cannot observe a partially initialized lock file.
        fcntl.flock(grants_fd, fcntl.LOCK_EX)
        try:
            try:
                _authority_create(grants_fd, ISSUER_LOCK_NAME, b"workspace authority lock\n", owner=_EXEC_UID, mode=0o600)
            except FileExistsError:
                pass
            _authority_read(grants_fd, ISSUER_LOCK_NAME, owner=_EXEC_UID, mode=0o600)
            lock_fd = os.open(ISSUER_LOCK_NAME, os.O_RDWR | os.O_NOFOLLOW, dir_fd=grants_fd)
        finally:
            fcntl.flock(grants_fd, fcntl.LOCK_UN)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        if _fingerprint(os.fstat(lock_fd)) != _authority_read(grants_fd, ISSUER_LOCK_NAME, owner=_EXEC_UID, mode=0o600)[1]:
            raise ValueError("workspace authority lock identity changed")
        grant_name = expected_grant_id + ".json"
        prepared_name, receipt_name = token + ".prepared.json", token + ".json"

        def current() -> None:
            if _authority_bytes(inputs) != frozen:
                raise ValueError("authority inputs changed during issuance")
            now = _instant(clock())
            if not _instant(request["createdAt"]) <= now < _instant(request["expiresAt"]) or now >= _instant(grant["expiresAt"]):
                raise ValueError("workspace authority review or grant expired")
            if verify_current() is not None:
                raise ValueError("authority revalidation must explicitly complete without a result")
            if _authority_bytes(inputs) != frozen:
                raise ValueError("authority inputs changed during revalidation")
            # Re-open the published directory paths: fd-only writes to a renamed
            # directory must never count as live authority publication.
            for path, opened, uid, private in ((grants_dir, grants_fd, _EXEC_UID, True), (bindings_path.parent, bindings_fd, _ROOT_UID, False), (receipt_dir, public_receipt_fd, _ROOT_UID, False), (receipt_dir / ".transactions", receipt_fd, _ROOT_UID, True)):
                check = _authority_directory(path, owner=uid, private=private)
                try:
                    if os.fstat(check).st_ino != os.fstat(opened).st_ino or os.fstat(check).st_dev != os.fstat(opened).st_dev:
                        raise ValueError("authority directory identity changed")
                finally:
                    os.close(check)

        def revocation() -> tuple[dict[str, Any], tuple[bytes, tuple[int, ...]]]:
            observed = _authority_read(grants_fd, "revocation.json", owner=_EXEC_UID, mode=0o600)
            value = contract.validate_revocation_document(json.loads(observed[0]))
            if value["revocationEpoch"] != grant["revocationEpoch"] or expected_grant_id in value["revokedGrantIds"]:
                raise ValueError("workspace authority was revoked or its epoch changed")
            return value, observed

        def observation(observed: tuple[bytes, tuple[int, ...]]) -> bytes:
            return _authority_bytes({"document": json.loads(observed[0]), "fingerprint": list(observed[1])})

        def require_observation(name: str, observed: tuple[bytes, tuple[int, ...]]) -> None:
            saved = _authority_read(receipt_fd, token + name, owner=_ROOT_UID, mode=0o600, optional=True)
            if saved is None or saved[0] != observation(observed):
                raise ValueError("workspace authority revocation observation changed or recovery is unproven")

        def verify_result(result: Any) -> None:
            expected = {"formatVersion": RECEIPT_FORMAT, "status": "issued", "requestDigest": request["requestDigest"],
                        "issuerContextDigest": context_digest, "profileDigest": request["profileDigest"],
                        "instanceId": request["instanceId"], "applicationId": request["applicationId"],
                        "grantId": expected_grant_id, "authorityGrantDigest": row["authorityGrantDigest"],
                        "workloadId": workload_id, "workloadDigest": contract.canonical_digest(spec),
                        "bindingDigest": contract.canonical_digest(row), "operator": operator}
            if (not isinstance(result, dict) or set(result) != set(expected) | {"activatedAt", "receiptDigest"}
                    or any(result.get(key) != value for key, value in expected.items())
                    or result["receiptDigest"] != contract.canonical_digest({key: value for key, value in result.items() if key != "receiptDigest"})):
                raise ValueError("workspace authority receipt differs from immutable request")
            _instant(result["activatedAt"])

        current()
        rev, rev_observed = revocation()
        old_receipt = _authority_read(public_receipt_fd, receipt_name, owner=_ROOT_UID, mode=0o644, optional=True)
        prepared = _authority_read(receipt_fd, prepared_name, owner=_ROOT_UID, mode=0o600, optional=True)
        if prepared is not None and prepared[0] != frozen:
            raise ValueError("workspace authority immutable request differs")
        old_grant = _authority_read(grants_fd, grant_name, owner=_EXEC_UID, mode=0o600, optional=True)
        if old_grant is not None and old_grant[0] != grant_bytes:
            raise ValueError("workspace authority grant collision")
        public = _authority_read(bindings_fd, bindings_path.name, owner=_ROOT_UID, mode=0o644, optional=True)
        document = json.loads(public[0]) if public is not None else {"formatVersion": binding_format, "bindings": []}
        rows = validate_public(document)
        matches = [item for item in rows if item["workload"]["workloadId"] == workload_id or item["workload"]["parameters"]["ownership"]["instanceId"] == request["instanceId"]]
        if matches and matches != [public_row]:
            raise ValueError("workspace_authority_renewal_unsupported")
        if old_receipt is not None:
            result = json.loads(old_receipt[0])
            verify_result(result)
            if (prepared is None or old_grant is None or matches != [public_row]
                    or expected_grant_id in rev["pausedGrantIds"]
                    or result.get("receiptDigest") != contract.canonical_digest({key: value for key, value in result.items() if key != "receiptDigest"})
                    or result.get("requestDigest") != request["requestDigest"]):
                raise ValueError("published workspace authority changed")
            return result
        if prepared is None:
            if old_grant is not None or matches or expected_grant_id in rev["pausedGrantIds"]:
                raise ValueError("workspace authority preexists without owned transaction")
            _authority_create(receipt_fd, prepared_name, frozen, owner=_ROOT_UID, mode=0o600)
        elif old_grant is not None and expected_grant_id not in rev["pausedGrantIds"]:
            # Activation may have completed before its receipt write. Only an
            # immutable activation intent can establish that exact crash window.
            intent = _authority_read(receipt_fd, token + ".activating.json", owner=_ROOT_UID, mode=0o600, optional=True)
            if intent is None or matches != [public_row]:
                raise ValueError("workspace authority pause was removed outside its transaction")
            activation = _authority_read(receipt_fd, token + ".activated.json", owner=_ROOT_UID, mode=0o600, optional=True)
            recorded = json.loads(activation[0]) if activation is not None else None
            if not isinstance(recorded, dict) or set(recorded) != {"revocation", "receipt"} or recorded["revocation"] != json.loads(observation(rev_observed)):
                raise ValueError("workspace authority activation recovery is unproven")
            result = recorded["receipt"]
            verify_result(result)
            _authority_create(public_receipt_fd, receipt_name, _authority_bytes(result), owner=_ROOT_UID, mode=0o644)
            return result
        _authority_checkpoint("prepared")
        if expected_grant_id not in rev["pausedGrantIds"]:
            paused = {**rev, "pausedGrantIds": [*rev["pausedGrantIds"], expected_grant_id]}
            contract.validate_revocation_document(paused)
            _authority_cas(grants_fd, "revocation.json", rev_observed, _authority_bytes(paused), owner=_EXEC_UID, mode=0o600)
            paused_observed = _authority_read(grants_fd, "revocation.json", owner=_EXEC_UID, mode=0o600)
            _authority_create(receipt_fd, token + ".paused.json", observation(paused_observed), owner=_ROOT_UID, mode=0o600)
        else:
            require_observation(".paused.json", rev_observed)
        _authority_checkpoint("paused")
        if old_grant is None:
            _authority_create(grants_fd, grant_name, grant_bytes, owner=_EXEC_UID, mode=0o600)
        _authority_checkpoint("grant-written")
        current()
        rev, rev_observed = revocation()
        if expected_grant_id not in rev["pausedGrantIds"]:
            raise ValueError("workspace authority is no longer paused before binding")
        require_observation(".paused.json", rev_observed)
        if not matches:
            published = {"formatVersion": binding_format, "bindings": [*rows, public_row]}
            validate_public(published)
            _authority_cas(bindings_fd, bindings_path.name, public, _authority_bytes(published), owner=_ROOT_UID, mode=0o644)
        _authority_checkpoint("binding-published")
        current()
        rev, rev_observed = revocation()
        if expected_grant_id not in rev["pausedGrantIds"]:
            raise ValueError("workspace authority is no longer paused before activation")
        require_observation(".paused.json", rev_observed)
        exact_public = _authority_read(bindings_fd, bindings_path.name, owner=_ROOT_UID, mode=0o644)
        exact_grant = _authority_read(grants_fd, grant_name, owner=_EXEC_UID, mode=0o600)
        if public_row not in validate_public(json.loads(exact_public[0])) or exact_grant[0] != grant_bytes:
            raise ValueError("workspace authority publication changed before activation")
        result = {"formatVersion": RECEIPT_FORMAT, "status": "issued", "requestDigest": request["requestDigest"],
                  "issuerContextDigest": context_digest, "profileDigest": request["profileDigest"],
                  "instanceId": request["instanceId"], "applicationId": request["applicationId"],
                  "grantId": expected_grant_id, "authorityGrantDigest": row["authorityGrantDigest"],
                  "workloadId": workload_id, "workloadDigest": contract.canonical_digest(spec),
                  "bindingDigest": contract.canonical_digest(row), "operator": operator, "activatedAt": clock()}
        _instant(result["activatedAt"])
        result["receiptDigest"] = contract.canonical_digest(result)
        intent_name = token + ".activating.json"
        intent = _authority_read(receipt_fd, intent_name, owner=_ROOT_UID, mode=0o600, optional=True)
        if intent is None:
            _authority_create(receipt_fd, intent_name, _authority_bytes(result), owner=_ROOT_UID, mode=0o600)
        else:
            result = json.loads(intent[0])
            verify_result(result)
        _authority_checkpoint("before-activation")
        current()
        if (_authority_read(bindings_fd, bindings_path.name, owner=_ROOT_UID, mode=0o644) != exact_public
                or _authority_read(grants_fd, grant_name, owner=_EXEC_UID, mode=0o600) != exact_grant):
            raise ValueError("workspace authority binding or grant changed before activation")
        # The exact snapshot compared by CAS precedes the fault seam and the
        # final authority recheck; any intervening epoch/pause/revocation refuses.
        activated = {**rev, "pausedGrantIds": [item for item in rev["pausedGrantIds"] if item != expected_grant_id]}
        _authority_cas(grants_fd, "revocation.json", rev_observed, _authority_bytes(activated), owner=_EXEC_UID, mode=0o600)
        activated_observed = _authority_read(grants_fd, "revocation.json", owner=_EXEC_UID, mode=0o600)
        result["activatedAt"] = clock()
        _instant(result["activatedAt"])
        result["receiptDigest"] = contract.canonical_digest({key: value for key, value in result.items() if key != "receiptDigest"})
        activation_record = {"revocation": json.loads(observation(activated_observed)), "receipt": result}
        _authority_create(receipt_fd, token + ".activated.json", _authority_bytes(activation_record), owner=_ROOT_UID, mode=0o600)
        _authority_checkpoint("activated")
        _authority_create(public_receipt_fd, receipt_name, _authority_bytes(result), owner=_ROOT_UID, mode=0o644)
        return result
    finally:
        for fd in (lock_fd, receipt_fd, public_receipt_fd, bindings_fd, grants_fd):
            if fd >= 0:
                os.close(fd)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Render exact operator-reviewed application workspace bindings; never writes or issues grants")
    parser.add_argument("--reviewed-input", required=True, type=Path, help="JSON list of catalogEntry/workload/grant records reviewed by the operator")
    arguments = parser.parse_args()
    try:
        raw = arguments.reviewed_input.read_bytes()
        if len(raw) > MAX_BYTES:
            raise ValueError("reviewed input exceeds size limit")
        print(json.dumps(render_bindings(json.loads(raw)), indent=2, sort_keys=True))
    except (OSError, ValueError) as exc:
        parser.exit(2, f"Application workspace binding refused: {exc}\n")
