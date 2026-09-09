"""Sanctioned control-plane proxy for the execution-host daemon.

This is the ONLY web-side boundary that speaks the confined execution-host
contract.  The browser never touches the Unix execution socket: every request
arrives over the same-origin ``/v1/*`` session+CSRF surface, is validated here
(authenticated caller, capability, grant, operation id, request digest,
target, resource limits), and is forwarded to the daemon through the typed
``ExecutionHostClient`` over the group-confined socket.

Security posture (fail closed):

- The proxy is constructed only when ``STATEPORT_EXECUTION_SOCKET`` and a
  provisioned grant identity are present; otherwise every operation reports
  ``unavailable`` with an explicit reason.
- Every daemon receipt is bound to the exact request digest and operation id
  by the client; the proxy never fabricates container state.
- Read operations require only the session gate (enforced by the caller).
  State-changing operations additionally require the CSRF mutation gate
  (enforced by the caller) and a live, non-expired grant covering the exact
  workload.
- Bounded responses: logs are capped at the client output byte bound and the
  proxy never serializes raw socket paths or container host identities.
"""

from __future__ import annotations

import os
import json
import stat
import base64
import selectors
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
import tempfile
from typing import Any, Callable, Mapping

from execution_host.application_workspaces import (FORMAT as BINDINGS_FORMAT, TRANSPORT_FORMAT, SOURCE_PROFILE_ID,
    TERMINAL_PROFILE_ID, catalog_identity, read_bindings, read_binding_transport, source_authority_profile,
    terminal_authority_profile)
from execution_host import daemon_contract
from execution_host.client import (
    ExecutionHostClient,
    ExecutionHostContractError,
    ExecutionHostRefusal,
    ExecutionHostTransportError,
)
from stateport_release.execution_host_provisioning import (
    DEFAULT_GRANT_ID as PROVISIONED_DEFAULT_GRANT_ID,
    DEFAULT_WORKSPACE_ID,
    DEFAULT_WORKSPACE_SPEC_DIGEST,
    ReleaseContractError,
    default_sealed_workspace_workload,
)

DEFAULT_GRANT_ID = PROVISIONED_DEFAULT_GRANT_ID
MAX_LOG_BYTES = 256 * 1024
MAX_STATUS_ENTRIES = 128
MAX_COMMIT_OBJECT_BYTES = 64 * 1024
_WORKLOAD_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_OPERATIONS = frozenset(
    {
        "describeCapabilities",
        "createWorkload",
        "listWorkloads",
        "status",
        "logs",
        "start",
        "stop",
        "cancel",
        "removeWorkload",
        "execWorkload",
    }
)
_MUTATING_OPERATIONS = frozenset(
    {"createWorkload", "start", "stop", "cancel", "removeWorkload", "execWorkload"}
)


def _read_reviewed_commit_object(root: Path, commit: str) -> str:
    """Read one commit object with a hard output bound as the service user."""
    if os.geteuid() == 0:
        raise ValueError("reviewed source preparation requires an ordinary service identity")
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise ValueError("reviewed source commit identity is invalid")
    # Use the deployment package's no-replace-objects configuration and disable
    # user/system config, hooks, and fsmonitor.  Keep only the bounded witness
    # in memory; diagnostics are drained and discarded.
    from stateport_deployment.inspection import sanitized_git_command, sanitized_git_environment
    env = sanitized_git_environment()
    env["PATH"] = "/usr/bin:/bin"
    try:
        process = subprocess.Popen(
            sanitized_git_command(root, "cat-file", "commit", commit),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
    except OSError as exc:
        raise ValueError("reviewed source commit object could not be read") from exc
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    raw = bytearray()
    deadline = time.monotonic() + 30
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                process.kill()
                process.wait(timeout=5)
                raise ValueError("reviewed source commit object read timed out")
            for key, _events in selector.select(timeout=remaining):
                chunk = os.read(key.fileobj.fileno(), MAX_COMMIT_OBJECT_BYTES + 1)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.data == "stdout":
                    raw.extend(chunk)
                    if len(raw) > MAX_COMMIT_OBJECT_BYTES:
                        process.kill()
                        process.wait(timeout=5)
                        raise ValueError("reviewed source commit object exceeds its byte bound")
                # Git diagnostics are deliberately drained and never retained.
        if process.wait(timeout=5) != 0:
            raise ValueError("reviewed source commit object could not be read")
    except (OSError, subprocess.TimeoutExpired) as exc:
        try:
            process.kill()
            process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            pass
        raise ValueError("reviewed source commit object could not be read") from exc
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    if not raw:
        raise ValueError("reviewed source commit object is empty")
    return base64.b64encode(bytes(raw)).decode("ascii")


def _workspace_source_archive(entry: Mapping[str, Any], archive: Any, *, commit_witness: bool = False) -> dict[str, Any]:
    """Identify installed template source using its real repository and descriptor."""
    from stateport_deployment.inspection import git_source_identity
    from .template_adapters import TemplateAdapterRegistry
    from execution_host.deployment_staging import build_deployment_archive

    if commit_witness and os.geteuid() == 0:
        raise ValueError("reviewed source preparation requires an ordinary service identity")
    root = Path(str(entry["path"]))
    if commit_witness:
        try:
            resolved = root.resolve(strict=True)
        except OSError as exc:
            raise ValueError("application source root is unavailable") from exc
        git_metadata = resolved / ".git"
        if (root != resolved or not resolved.is_dir() or git_metadata.is_symlink()
                or not (git_metadata.is_dir() or git_metadata.is_file())):
            raise ValueError("application source path must be the exact Git repository root")
        root = resolved
    descriptor = TemplateAdapterRegistry().require(root)
    descriptor_digest = daemon_contract.canonical_digest(descriptor)
    identity = git_source_identity(root, descriptor_digest=descriptor_digest)
    if commit_witness and identity.repository_root != str(root.resolve()):
        raise ValueError("application source path must be the exact Git repository root")
    if identity.dirty:
        raise ValueError("application source has changes outside its reviewed committed revision")
    inventory = [{key: row[key] for key in ("path", "mode", "contentDigest")} for row in identity.inventory]
    context = []
    for row in inventory:
        context.append({"path": row["path"], "mode": row["mode"], "size": (root / row["path"]).stat().st_size, "sha256": row["contentDigest"]})
    metadata = build_deployment_archive(archive, plan={"sourceInventory": inventory, "overlay": {}}, context_root=root, overlay_root=root, context_digest=daemon_contract.canonical_digest(context))
    current = git_source_identity(root, descriptor_digest=daemon_contract.canonical_digest(TemplateAdapterRegistry().require(root)))
    if current != identity:
        raise ValueError("application source changed during archive review")
    result = {"baseRevision": identity.commit, "sourceInventory": inventory, "sourceArchive": metadata, "descriptorDigest": descriptor_digest}
    if commit_witness:
        result["commitObject"] = _read_reviewed_commit_object(root, identity.commit)
    return result


def prepare_workspace_source_seed(entry: Mapping[str, Any], workload: Mapping[str, Any]) -> dict[str, Any]:
    """Trusted operator review helper; emits a spec, never issues or writes grants."""
    import copy
    spec = copy.deepcopy(dict(workload))
    with tempfile.TemporaryFile("w+b") as archive:
        source = _workspace_source_archive(entry, archive)
    owner = spec["parameters"]["ownership"]
    if owner["catalogIdentityDigest"] != catalog_identity(entry) or owner["instanceId"] != entry["instanceId"] or owner["applicationId"] != entry["applicationId"]:
        raise ValueError("workspace source review differs from application ownership")
    spec["parameters"]["baseRevision"] = source.pop("baseRevision")
    review = {"workloadId": spec["workloadId"], "image": spec["image"]["reference"], "ownership": owner, "baseRevision": spec["parameters"]["baseRevision"], **source}
    spec["parameters"]["sourceSeed"] = {**source, "reviewDigest": daemon_contract.canonical_digest(review)}
    return daemon_contract.validate_workload_spec(spec)


class ExecutionHostProxyError(RuntimeError):
    """Typed proxy failure surfaced as a bounded API error."""

    def __init__(self, code: str, detail: str, *, status: int = 409) -> None:
        super().__init__(detail)
        self.code = code
        self.status = status


class ExecutionHostProxy:
    def __init__(
        self,
        *,
        socket_path: str | os.PathLike[str] | None = None,
        grant_id: str | None = None,
        authority_grant_digest: str | None = None,
        timeout_seconds: int = 30,
        catalog_entry: Callable[[str], Mapping[str, Any]] | None = None,
        catalog_entries: Callable[[], list[dict[str, Any]]] | None = None,
        instance_runs: Callable[[str], list[dict[str, Any]]] | None = None,
        bindings_path: str | os.PathLike[str] | None = None,
        bindings_owner_uid: int = 65532,
        authority_directory: str | os.PathLike[str] | None = None,
        bindings_format: str | None = None,
    ) -> None:
        self._socket_from_constructor = socket_path is not None
        self._socket_path = str(socket_path) if socket_path is not None else os.environ.get("STATEPORT_EXECUTION_SOCKET", "")
        self._grant_id = grant_id or os.environ.get("STATEPORT_EXECUTION_GRANT_ID", DEFAULT_GRANT_ID)
        self._grant_digest = authority_grant_digest or os.environ.get("STATEPORT_EXECUTION_GRANT_DIGEST", "")
        self._timeout_seconds = timeout_seconds
        # These values come only from the installed signed unit, never HTTP.
        self._workspace_image = os.environ.get("STATEPORT_EXECUTION_HOST_WORKSPACE_IMAGE_REFERENCE")
        self._workspace_spec_digest = os.environ.get("STATEPORT_EXECUTION_HOST_WORKSPACE_SPEC_DIGEST")
        self._catalog_entries = catalog_entries
        self._catalog_entry = catalog_entry
        self._instance_runs = instance_runs
        self._bindings_path = str(bindings_path) if bindings_path is not None else os.environ.get("STATEPORT_APPLICATION_WORKSPACE_BINDINGS", "")
        self._bindings_owner_uid = bindings_owner_uid
        self._bindings_format = bindings_format if bindings_format is not None else os.environ.get("STATEPORT_APPLICATION_WORKSPACE_BINDINGS_FORMAT", BINDINGS_FORMAT)
        self._authority_directory = str(authority_directory) if authority_directory is not None else os.environ.get("STATEPORT_WORKSPACE_AUTHORITY_DIRECTORY", "")
        self._client: ExecutionHostClient | None = None
        self._deployment_adapter: Any | None = None

    # ------------------------------------------------------------ readiness

    def _transport_ready(self) -> str | None:
        if (self._bindings_format == TRANSPORT_FORMAT or self._workspace_image is not None or self._workspace_spec_digest is not None) and not self._socket_from_constructor and self._socket_path != "/run/stateport-execution/control.sock":
            return "execution_socket_not_fixed"
        if not self._socket_path:
            return "execution_socket_not_configured"
        if not Path(self._socket_path).is_absolute():
            return "execution_socket_invalid"
        return None

    def _client_ready(self) -> tuple[ExecutionHostClient | None, str | None]:
        reason = self._transport_ready()
        if reason:
            return None, reason
        if not self._socket_path:
            return None, "execution_socket_not_configured"
        try:
            path = Path(self._socket_path)
        except (TypeError, ValueError) as exc:
            return None, f"execution_socket_invalid: {exc}"
        if not path.is_absolute():
            return None, "execution_socket_invalid"
        if not self._grant_digest:
            bindings = self._bindings()
            if bindings:
                row = bindings[0]
                return ExecutionHostClient(path, grant_id=row["grantId"], authority_grant_digest=row["authorityGrantDigest"], timeout_seconds=self._timeout_seconds, output_byte_bound=MAX_LOG_BYTES), None
            return None, "execution_grant_not_configured"
        if self._client is None:
            self._client = ExecutionHostClient(
                path,
                grant_id=self._grant_id,
                authority_grant_digest=self._grant_digest,
                timeout_seconds=self._timeout_seconds,
                output_byte_bound=MAX_LOG_BYTES,
            )
        return self._client, None

    def status(self) -> dict[str, Any]:
        """Return a bounded, truthful execution-host health surface."""
        client, reason = self._client_ready()
        if client is None:
            return {
                "status": "unavailable",
                "reason": reason,
                "grantId": self._grant_id,
                "grantBound": bool(self._grant_digest),
            }
        try:
            receipt = client.describe_capabilities()
        except ExecutionHostTransportError:
            return {
                "status": "unavailable",
                "reason": "execution_host_unreachable",
                "detail": "the confined execution host did not answer",
                "grantId": client.grant_id,
                "grantBound": True,
            }
        except (ExecutionHostRefusal, ExecutionHostContractError):
            return {
                "status": "unavailable",
                "reason": "execution_host_refused",
                "detail": "the execution host refused or invalidated the capability probe",
                "grantId": client.grant_id,
                "grantBound": True,
            }
        result = receipt.get("result")
        if not isinstance(result, Mapping):
            return {
                "status": "unavailable",
                "reason": "execution_host_protocol_violation",
                "grantId": client.grant_id,
                "grantBound": True,
            }
        peer = result.get("peerIdentity")
        return {
            "status": "available",
            "contractVersion": result.get("contractVersion"),
            "engine": (receipt.get("observed") or {}).get("engine"),
            "engineVersion": (receipt.get("observed") or {}).get("engineVersion"),
            "peerIdentity": (
                {"mechanism": peer.get("mechanism")}
                if isinstance(peer, Mapping) and isinstance(peer.get("mechanism"), str)
                else None
            ),
            "workloadKinds": result.get("workloadKinds"),
            "grantId": client.grant_id,
            "grantBound": True,
        }

    # ------------------------------------------------------- typed operations

    def _require_client(self) -> ExecutionHostClient:
        client, reason = self._client_ready()
        if client is None:
            raise ExecutionHostProxyError(
                "execution_unavailable", f"execution host is unavailable: {reason}", status=503
            )
        return client

    @staticmethod
    def _validate_workload_id(workload_id: Any) -> str:
        if not isinstance(workload_id, str) or _WORKLOAD_ID.fullmatch(workload_id) is None:
            raise ExecutionHostProxyError("invalid_workload_id", "workload id is invalid", status=400)
        return workload_id

    @staticmethod
    def _list_projection(
        receipt: Mapping[str, Any], *, recovery_fields: bool = False
    ) -> dict[str, Any]:
        """Require the shape consumed by default and application list views."""
        result = receipt.get("result")
        workloads = result.get("workloads") if isinstance(result, Mapping) else None
        if (
            receipt.get("accepted") is not True
            or not isinstance(result, Mapping)
            or not isinstance(workloads, list)
        ):
            raise ExecutionHostProxyError(
                "execution_protocol_violation",
                "execution host returned an invalid listWorkloads projection",
                status=502,
            )
        seen: set[str] = set()
        for row in workloads:
            workload_id = row.get("workloadId") if isinstance(row, Mapping) else None
            if (
                not isinstance(workload_id, str)
                or _WORKLOAD_ID.fullmatch(workload_id) is None
                or workload_id in seen
                or (
                    recovery_fields
                    and (
                        not isinstance(row.get("state"), str)
                        or (
                            "sourceSeed" in row
                            and not isinstance(row.get("sourceSeed"), Mapping)
                        )
                    )
                )
            ):
                raise ExecutionHostProxyError(
                    "execution_protocol_violation",
                    "execution host returned an invalid listWorkloads projection",
                    status=502,
                )
            seen.add(workload_id)
        return dict(result)

    def describe(self) -> dict[str, Any]:
        return self.status()

    def deployment_adapter(self) -> Any:
        """Return the sanctioned deployment-effect client for the web app."""

        if self._deployment_adapter is None:
            from stateport_deployment.execution_host import (  # noqa: PLC0415
                ExecutionHostDeploymentAdapter,
            )

            self._deployment_adapter = ExecutionHostDeploymentAdapter.configured(
                socket_path=self._socket_path,
                grant_id=self._grant_id,
                authority_grant_digest=self._grant_digest,
                output_byte_bound=MAX_LOG_BYTES,
            )
        return self._deployment_adapter

    def _authority_document(self, path: Path, *, trusted_owner: bool = True) -> dict[str, Any]:
        """Bounded fresh descriptor-relative public read; never writes authority."""
        if not path.is_absolute() or ".." in path.parts:
            raise ValueError("invalid public authority path")
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
                if trusted_owner and info.st_uid not in {0, self._bindings_owner_uid}:
                    raise ValueError("untrusted public authority owner")
                if trusted_owner and info.st_mode & 0o022 and not (stat.S_ISDIR(info.st_mode) and info.st_mode & stat.S_ISVTX and info.st_uid == 0):
                    raise ValueError("unsafe public authority permissions")
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= 1024 * 1024:
                raise ValueError("invalid public authority document")
            raw = os.read(fd, 1024 * 1024 + 1)
            after = os.fstat(fd)
            if (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns) or len(raw) != before.st_size:
                raise ValueError("public authority changed during read")
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError("invalid public authority document")
            return value
        finally:
            os.close(fd)

    def _workspace_issuer(self) -> dict[str, Any]:
        if not self._authority_directory:
            raise ValueError("workspace issuer is not configured")
        raw = self._authority_document(Path(self._authority_directory) / "issuer.json", trusted_owner=self._bindings_format != TRANSPORT_FORMAT)
        if set(raw) != {"formatVersion", "issuerContextDigest", "profileId", "profileDigest", "sourceMode", "profile", "grantExpiresAtLimit", "operator"} or raw["formatVersion"] not in {"stateport.workspace-issuer-public/v1", "stateport.workspace-issuer-public/v2", "stateport.workspace-issuer-public/v3"}:
            raise ValueError("invalid public issuer")
        terminal_profile = raw["formatVersion"] in {"stateport.workspace-issuer-public/v2", "stateport.workspace-issuer-public/v3"}
        source_profile = raw["formatVersion"] == "stateport.workspace-issuer-public/v3"
        expected_id = SOURCE_PROFILE_ID if source_profile else (TERMINAL_PROFILE_ID if terminal_profile else "stateport.empty-workspace/v1")
        expected_mode = "reviewed-commit" if source_profile else "empty"
        if raw["profileId"] != expected_id or raw["sourceMode"] != expected_mode:
            raise ValueError("unsupported issuer profile")
        template = self._default_workspace_workload()
        expected_profile = source_authority_profile(template) if source_profile else (terminal_authority_profile(template) if terminal_profile else template)
        daemon_contract._digest(raw["issuerContextDigest"], "issuerContextDigest")
        if raw["profile"] != expected_profile or raw["profileDigest"] != daemon_contract.canonical_digest(expected_profile):
            raise ValueError("issuer profile changed")
        if not isinstance(raw["grantExpiresAtLimit"], str) or re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", raw["grantExpiresAtLimit"]) is None:
            raise ValueError("invalid issuer expiry")
        expiry = datetime.strptime(raw["grantExpiresAtLimit"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        if expiry <= datetime.now(timezone.utc):
            raise ValueError("issuer grant expiry elapsed")
        operator = raw["operator"]
        if not isinstance(operator, dict) or set(operator) != {"user", "uid", "gid"} or not isinstance(operator["user"], str) or any(type(operator[key]) is not int or operator[key] < 0 for key in ("uid", "gid")):
            raise ValueError("invalid issuer operator")
        projection = {key: raw[key] for key in ("issuerContextDigest", "profileId", "profileDigest", "sourceMode", "profile", "grantExpiresAtLimit")}
        if terminal_profile:
            projection["profile"] = expected_profile["workload"]
            projection["operations"] = expected_profile["operations"]
        return projection

    def _workspace_issued_receipt(self, binding: Mapping[str, Any]) -> dict[str, Any] | None:
        directory = Path(self._authority_directory) / "receipts"
        if not directory.exists():
            return None
        # Bound discovery; each candidate is independently descriptor-checked.
        paths = []
        for index, path in enumerate(directory.iterdir()):
            if index >= 256:
                raise ValueError("workspace receipt discovery exceeds bound")
            if re.fullmatch(r"[a-f0-9]{64}\.json", path.name):
                paths.append(path)
                if len(paths) > 256:
                    raise ValueError("workspace receipt discovery exceeds bound")
        matches = []
        owner = binding["workload"]["parameters"]["ownership"]
        for path in paths:
            row = self._authority_document(path)
            expected_keys = {"formatVersion", "status", "requestDigest", "issuerContextDigest", "profileDigest", "instanceId", "applicationId", "grantId", "authorityGrantDigest", "workloadId", "workloadDigest", "bindingDigest", "operator", "activatedAt", "receiptDigest"}
            if set(row) != expected_keys or row["formatVersion"] != "stateport.workspace-authority-receipt/v1" or row["status"] != "issued":
                raise ValueError("invalid public issuance receipt")
            if row["receiptDigest"] != daemon_contract.canonical_digest({key: value for key, value in row.items() if key != "receiptDigest"}) or row["requestDigest"] != "sha256:" + path.stem:
                raise ValueError("issuance receipt identity changed")
            for key in ("requestDigest", "issuerContextDigest", "profileDigest", "authorityGrantDigest", "workloadDigest", "bindingDigest", "receiptDigest"):
                daemon_contract._digest(row[key], key)
            for key in ("instanceId", "applicationId", "grantId", "workloadId"):
                daemon_contract._id(row[key], key)
            datetime.strptime(row["activatedAt"], "%Y-%m-%dT%H:%M:%SZ")
            operator = row["operator"]
            if not isinstance(operator, dict) or set(operator) != {"user", "uid", "gid"} or not isinstance(operator["user"], str) or any(type(operator[key]) is not int or operator[key] < 0 for key in ("uid", "gid")):
                raise ValueError("invalid receipt operator")
            if row["instanceId"] == owner["instanceId"] and row["applicationId"] == owner["applicationId"] and row["grantId"] == binding["grantId"] and row["authorityGrantDigest"] == binding["authorityGrantDigest"] and row["workloadId"] == binding["workload"]["workloadId"] and row["workloadDigest"] == daemon_contract.canonical_digest(binding["workload"]) and row["bindingDigest"] == daemon_contract.canonical_digest(binding):
                matches.append(row)
        return max(matches, key=lambda row: (row["activatedAt"], row["receiptDigest"])) if matches else None

    def workspace_authority(self, instance_id: Any) -> dict[str, Any]:
        iid = self._validate_workload_id(instance_id)
        try:
            if self._catalog_entry is None:
                raise ValueError("catalog unavailable")
            entry = self._catalog_entry(iid)
            if entry["instanceId"] != iid:
                raise ValueError("catalog identity changed")
        except Exception as exc:
            raise ExecutionHostProxyError("workspace_catalog_stale", "The installed application identity is unavailable; refresh the application.") from exc
        result: dict[str, Any] = {"instanceId": iid, "applicationId": entry["applicationId"], "displayName": entry.get("name", entry["applicationId"]), "catalogIdentityDigest": catalog_identity(entry), "status": "unavailable"}
        try:
            result["issuer"] = self._workspace_issuer()
            result["status"] = "available"
        except (OSError, ValueError, TypeError, KeyError, ReleaseContractError, ExecutionHostProxyError):
            result["refusal"] = {"reason": "workspace_issuer_unavailable", "detail": "Trusted workspace request preparation is unavailable. An OS operator must inspect the installation context; no authority was issued."}
        if self._authority_directory:
            try:
                binding = self.application_binding(iid)
                if binding is not None:
                    result["status"] = "unavailable"
                    result["refusal"] = {"reason": "workspace_authority_renewal_unsupported", "detail": "An exact workspace binding already exists. This issuer supports fresh authority only; renewal or replacement requires a separately supported operator procedure."}
                receipt = None
                if binding is not None:
                    if self._bindings_format == TRANSPORT_FORMAT:
                        logical = {key: binding[key] for key in ("grantId", "authorityGrantDigest", "workload")}
                        receipt = {"status": "daemon-verified-grant", "grantId": binding["grantId"], "authorityGrantDigest": binding["authorityGrantDigest"], "workloadId": binding["workload"]["workloadId"], "workloadDigest": daemon_contract.canonical_digest(binding["workload"]), "bindingDigest": daemon_contract.canonical_digest(logical)}
                    else:
                        receipt = self._workspace_issued_receipt(binding)
                if receipt is not None:
                    result["issued"] = receipt
                    # Recorded issuance is not a claim of current daemon authority.
                    result["status"] = "issued"
            except (OSError, ValueError, TypeError, KeyError, ExecutionHostProxyError):
                result["status"] = "unavailable"
                result["refusal"] = {"reason": "workspace_issuance_unverified", "detail": "The current binding or issuance receipt could not be verified. No current authority is claimed."}
        return result

    def prepare_workspace_authority(self, instance_id: Any, *, profile_digest: Any, source_mode: Any, grant_expires_at: Any) -> dict[str, Any]:
        from execution_host.application_workspaces import REQUEST_FORMAT, SOURCE_REQUEST_FORMAT, validate_workspace_authority_request
        from execution_host.deployment_staging import DeploymentStagingError
        from stateport_deployment.errors import DeploymentRefusal
        review = self.workspace_authority(instance_id)
        issuer = review.get("issuer")
        if review["status"] != "available" or issuer is None:
            raise ExecutionHostProxyError("workspace_issuer_unavailable", "Workspace authority request preparation is unavailable.", status=503)
        if profile_digest != issuer["profileDigest"] or source_mode != issuer["sourceMode"]:
            raise ExecutionHostProxyError("workspace_authority_review_stale", "The operator profile changed; refresh and review it again.")
        now = datetime.now(timezone.utc).replace(microsecond=0)
        try:
            if not isinstance(grant_expires_at, str) or re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", grant_expires_at) is None:
                raise ValueError("invalid grant expiry")
            expiry = datetime.strptime(grant_expires_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            if expiry <= now or grant_expires_at > issuer["grantExpiresAtLimit"]:
                raise ValueError("invalid grant expiry")
        except (ValueError, TypeError) as exc:
            raise ExecutionHostProxyError("workspace_authority_request_invalid", "Choose an exact UTC authority expiry in the future and within the displayed installation limit.", status=400) from exc
        body = {"formatVersion": REQUEST_FORMAT, "instanceId": review["instanceId"], "applicationId": review["applicationId"], "catalogIdentityDigest": review["catalogIdentityDigest"], "issuerContextDigest": issuer["issuerContextDigest"], "profileDigest": issuer["profileDigest"], "sourceMode": issuer["sourceMode"], "createdAt": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "expiresAt": (now + timedelta(minutes=15)).strftime("%Y-%m-%dT%H:%M:%SZ"), "grantExpiresAt": grant_expires_at}
        source_mode_review = issuer["sourceMode"] == "reviewed-commit"
        try:
            if source_mode_review:
                if self._catalog_entry is None:
                    raise ValueError("application catalog is unavailable for source review")
                entry = self._catalog_entry(review["instanceId"])
                if (entry["instanceId"] != review["instanceId"] or entry["applicationId"] != review["applicationId"] or catalog_identity(entry) != review["catalogIdentityDigest"]):
                    raise ValueError("application catalog changed before source review")
                with tempfile.TemporaryFile("w+b") as archive:
                    source = _workspace_source_archive(entry, archive, commit_witness=True)
                body["formatVersion"] = SOURCE_REQUEST_FORMAT
                body["source"] = source
                body["sourceDigest"] = daemon_contract.canonical_digest(source)
            request = validate_workspace_authority_request({**body, "requestDigest": daemon_contract.canonical_digest(body)})
        except (OSError, TypeError, ValueError, DeploymentStagingError, DeploymentRefusal) as exc:
            if source_mode_review:
                raise ExecutionHostProxyError("workspace_source_review_failed", "The reviewed application source could not be verified; no authority request was prepared.", status=409) from exc
            raise ExecutionHostProxyError("workspace_authority_request_invalid", "The authority request could not be validated.", status=400) from exc
        # Recheck the live catalog and publication before returning a request;
        # the root issuer independently revalidates them before issuing authority.
        current = self.workspace_authority(instance_id)
        if current != review:
            raise ExecutionHostProxyError("workspace_authority_review_stale", "Application or issuer identity changed during preparation; refresh.")
        return {"request": request, "review": review}

    def _bindings(self) -> list[dict[str, Any]]:
        if self._bindings_format not in {BINDINGS_FORMAT, TRANSPORT_FORMAT}:
            raise ExecutionHostProxyError("workspace_bindings_invalid", "Workspace binding transport configuration is unsupported", status=503)
        if not self._bindings_path:
            if self._bindings_format == TRANSPORT_FORMAT:
                raise ExecutionHostProxyError("workspace_bindings_invalid", "Workspace binding transport is unavailable", status=503)
            return []
        try:
            if self._bindings_format == TRANSPORT_FORMAT:
                return read_binding_transport(Path(self._bindings_path))
            return read_bindings(Path(self._bindings_path), operator_uid=self._bindings_owner_uid)
        except (OSError, ValueError) as exc:
            raise ExecutionHostProxyError("workspace_bindings_invalid", "Operator workspace bindings are missing, unsafe or invalid", status=503) from exc

    def _validate_binding(self, binding: Mapping[str, Any]) -> Mapping[str, Any]:
        owner = binding["workload"]["parameters"]["ownership"]
        try:
            if self._catalog_entry is None:
                raise ValueError("catalog unavailable")
            entry = self._catalog_entry(owner["instanceId"])
            if entry["applicationId"] != owner["applicationId"] or catalog_identity(entry) != owner["catalogIdentityDigest"]:
                raise ValueError("catalog identity changed")
            if owner["runId"] is not None and (self._instance_runs is None or not any(
                row.get("runId") == owner["runId"] and row.get("instanceId") == owner["instanceId"]
                for row in self._instance_runs(owner["instanceId"])
            )):
                raise ValueError("run does not belong to this instance")
            return entry
        except Exception as exc:
            raise ExecutionHostProxyError("workspace_binding_stale", "The application, catalog revision or run no longer matches operator workspace authority") from exc

    def _binding_client(self, binding: Mapping[str, Any], *, operation: str = "listWorkloads") -> ExecutionHostClient:
        reason = self._transport_ready()
        if reason:
            raise ExecutionHostProxyError("execution_unavailable", "Execution transport is unavailable", status=503)
        budgets = binding["grant"]["budgets"] if self._bindings_format == TRANSPORT_FORMAT else None
        client = ExecutionHostClient(Path(self._socket_path), grant_id=binding["grantId"],
            authority_grant_digest=binding["authorityGrantDigest"],
            timeout_seconds=min(self._timeout_seconds, budgets["maxTimeoutSeconds"]) if budgets else self._timeout_seconds,
            output_byte_bound=min(MAX_LOG_BYTES, budgets["maxOutputBytes"]) if budgets else MAX_LOG_BYTES)
        if self._bindings_format == TRANSPORT_FORMAT:
            # Public preimage equality is not authority. Only the fixed configured
            # daemon's exact request-bound accepted receipt authenticates it.
            required = {operation}
            if operation == "openTerminal":
                required.update({"resizeTerminal", "signalTerminal", "closeTerminal"})
            if not required <= set(binding["grant"]["operations"]):
                raise ExecutionHostProxyError("workspace_operation_not_granted", "The exact workspace grant does not authorize this operation", status=403)
            observed = self._call("listWorkloads", client.list_workloads)
            if not observed["accepted"]:
                raise ExecutionHostProxyError("workspace_authority_refused", "The execution daemon refused the exact workspace grant", status=403)
            self._list_projection(observed)
        self._validate_binding(binding)
        return client

    def _workload_client(self, workload_id: str, *, operation: str = "listWorkloads") -> ExecutionHostClient:
        if self._bindings_format == TRANSPORT_FORMAT and workload_id == DEFAULT_WORKSPACE_ID:
            return self._require_client()
        for binding in self._bindings():
            if binding["workload"]["workloadId"] == workload_id:
                return self._binding_client(binding, operation=operation)
        if self._bindings_format == TRANSPORT_FORMAT or not self._grant_digest:
            raise ExecutionHostProxyError("workspace_authority_missing", "No exact authority is configured for this workspace")
        return self._require_client()

    def application_binding(self, instance_id: str, *, operation: str = "listWorkloads") -> Mapping[str, Any] | None:
        binding = next((row for row in self._bindings() if row["workload"]["parameters"]["ownership"]["instanceId"] == instance_id), None)
        if binding is not None:
            if self._bindings_format == TRANSPORT_FORMAT:
                self._binding_client(binding, operation=operation)
            else:
                self._validate_binding(binding)
        return binding

    def application_client(self, instance_id: str, *, operation: str = "openTerminal") -> tuple[Mapping[str, Any], ExecutionHostClient] | None:
        binding = next((row for row in self._bindings() if row["workload"]["parameters"]["ownership"]["instanceId"] == instance_id), None)
        if binding is None:
            if self._bindings_format == TRANSPORT_FORMAT:
                raise ExecutionHostProxyError("workspace_authority_missing", "Ask an operator to issue exact application workspace authority; host terminal fallback is unavailable", status=403)
            return None
        return binding, self._binding_client(binding, operation=operation)

    def create_application(self, instance_id: Any, *, source_review_digest: Any = None) -> dict[str, Any]:
        iid = self._validate_workload_id(instance_id)
        binding = next((row for row in self._bindings() if row["workload"]["parameters"]["ownership"]["instanceId"] == iid), None)
        if binding is None:
            raise ExecutionHostProxyError("workspace_authority_missing", "An operator must provision an exact application workspace grant before creation")
        client = self._binding_client(binding, operation="createWorkload")
        spec = binding["workload"]
        seed = spec["parameters"].get("sourceSeed")
        if seed is not None:
            if source_review_digest != seed["reviewDigest"]:
                raise ExecutionHostProxyError("workspace_source_review_stale", "Confirm the exact operator-approved source review before creating this workspace")
            observed = self._list_projection(
                self._call("listWorkloads", client.list_workloads),
                recovery_fields=True,
            )["workloads"]
            if any(row["workloadId"] == spec["workloadId"] and row["state"] in {"removed", "interrupted"} and row.get("sourceSeed", {}).get("status") == "complete" for row in observed):
                return self._call("createWorkload", lambda: client.create_workspace(spec), workload_id=spec["workloadId"])
            with tempfile.TemporaryFile("w+b") as archive:
                try:
                    source = _workspace_source_archive(self._validate_binding(binding), archive)
                    expected = {"baseRevision": spec["parameters"]["baseRevision"], **{key: value for key, value in seed.items() if key != "reviewDigest"}}
                    if source != expected:
                        raise ValueError("installed source differs from the operator-reviewed profile")
                except Exception as exc:
                    raise ExecutionHostProxyError("workspace_source_stale", "Application source identity could not be verified against the approved inventory") from exc
                from execution_host.deployment_staging import reopen_archive_read_only
                source_fd = reopen_archive_read_only(archive)
                try:
                    return self._call("createWorkload", lambda: client.create_workspace(spec, source_fd=source_fd), workload_id=spec["workloadId"])
                finally:
                    os.close(source_fd)
        if source_review_digest is not None:
            raise ExecutionHostProxyError("workspace_source_review_stale", "This profile does not authorize source seeding")
        return self._call("createWorkload", lambda: client.create_workspace(spec), workload_id=spec["workloadId"])

    def list(self) -> dict[str, Any]:
        binding_error = None
        try:
            bindings = self._bindings()
        except ExecutionHostProxyError as exc:
            if self._bindings_format != TRANSPORT_FORMAT:
                raise
            bindings = []
            binding_error = exc.code
        result = self._call("listWorkloads", self._require_client().list_workloads) if self._grant_digest or (not bindings and self._catalog_entries is None) else {"accepted": False, "refusal": {"reason": "default_grant_not_configured"}}
        if not bindings and self._catalog_entries is None:
            if result.get("accepted"):
                self._list_projection(result)
            return result
        profiles = []
        rows = list(self._list_projection(result)["workloads"]) if result.get("accepted") else []
        for binding in bindings:
            spec = binding["workload"]
            owner = spec["parameters"]["ownership"]
            profile = {"instanceId": owner["instanceId"], "applicationId": owner["applicationId"], "workloadId": spec["workloadId"], "status": "available"}
            try:
                client = self._binding_client(binding)
                if self._bindings_format == TRANSPORT_FORMAT:
                    profile["allowedOperations"] = list(binding["grant"]["operations"])
                    profile["terminalAvailable"] = {"openTerminal", "resizeTerminal", "signalTerminal", "closeTerminal", "status"} <= set(binding["grant"]["operations"])
                entry = self._validate_binding(binding)
                profile["displayName"] = entry.get("name", owner["applicationId"])
                observed = self._call("listWorkloads", client.list_workloads)
                if observed["accepted"] is not True:
                    profile.update(status="unavailable", reason=observed.get("refusal", {}).get("reason", "authority_refused"))
                else:
                    observed_result = self._list_projection(observed)
                    # Both binding formats use the daemon's authenticated list
                    # observation. Legacy v1 carries no grant preimage, so it
                    # must never infer terminal or lifecycle authority from a
                    # different/default grant or from a workload's name.
                    operations = observed_result.get("allowedOperations")
                    if operations is not None:
                        if (not isinstance(operations, list)
                                or any(not isinstance(op, str) or op not in daemon_contract.OPERATIONS for op in operations)
                                or len(set(operations)) != len(operations)
                                or (self._bindings_format == TRANSPORT_FORMAT
                                    and set(operations) != set(binding["grant"]["operations"]))):
                            raise ExecutionHostProxyError("workspace_operations_invalid", "The execution host did not confirm the exact workspace operations.")
                        profile["allowedOperations"] = list(operations)
                        profile["terminalAvailable"] = {"openTerminal", "resizeTerminal", "signalTerminal", "closeTerminal", "status"} <= set(operations)
                    rows.extend(row for row in observed_result["workloads"] if row["workloadId"] == spec["workloadId"] and row["workloadId"] not in {item["workloadId"] for item in rows})
            except ExecutionHostProxyError as exc:
                profile.update(status="unavailable", reason=exc.code)
            if "sourceSeed" in spec["parameters"] and profile["status"] == "available":
                seed = spec["parameters"]["sourceSeed"]
                profile["sourceReview"] = {"reviewDigest": seed["reviewDigest"], "baseRevision": spec["parameters"]["baseRevision"], "descriptorDigest": seed["descriptorDigest"], "archiveDigest": seed["sourceArchive"]["archiveDigest"], "archiveBytes": seed["sourceArchive"]["archiveBytes"], "fileCount": len(seed["sourceInventory"]), "paths": [row["path"] for row in seed["sourceInventory"]]}
            profiles.append(profile)
        if self._catalog_entries is not None:
            bound_instances = {profile["instanceId"] for profile in profiles}
            for entry in self._catalog_entries():
                if entry["instanceId"] not in bound_instances:
                    profiles.append({"instanceId": entry["instanceId"], "applicationId": entry["applicationId"], "displayName": entry.get("name", entry["applicationId"]), "status": "unavailable", "reason": binding_error or "workspace_authority_missing", "workloadId": ""})
        # This is a composite read projection, not a single daemon receipt.
        projection = {"workloads": rows, "applicationWorkspaces": profiles}
        if not result.get("accepted"):
            projection["defaultWorkspaceRefusal"] = result.get("refusal")
        return {"accepted": True, "result": projection}

    def status_of(self, workload_id: Any) -> dict[str, Any]:
        wid = self._validate_workload_id(workload_id)
        return self._call("status", lambda: self._workload_client(wid, operation="status").status(wid), workload_id=wid)

    def logs(self, workload_id: Any) -> dict[str, Any]:
        wid = self._validate_workload_id(workload_id)
        return self._call("logs", lambda: self._workload_client(wid, operation="logs").logs(wid), workload_id=wid)

    def _default_workspace_workload(self) -> dict[str, Any]:
        """Resolve the installed template; dynamic use requires live base authority.

        The daemon checks the same fixed image/spec pair against its private
        control-plane-default grant before accepting that grant's list request.
        Application grants remain independent of this preparation/default path.
        """
        dynamic = self._workspace_image is not None or self._workspace_spec_digest is not None
        try:
            if dynamic:
                if not self._workspace_image or not self._workspace_spec_digest:
                    raise ValueError("incomplete installed workspace image pair")
                workload = daemon_contract.workspace_template_for_image(self._workspace_image)
                expected_digest = daemon_contract._digest(self._workspace_spec_digest, "workspaceSpecDigest")
            else:
                workload = default_sealed_workspace_workload()
                expected_digest = DEFAULT_WORKSPACE_SPEC_DIGEST
            if workload.get("workloadId") != DEFAULT_WORKSPACE_ID or daemon_contract.canonical_digest(workload) != expected_digest:
                raise ValueError("installed workspace spec digest mismatch")
        except (ReleaseContractError, ValueError, TypeError) as exc:
            raise ExecutionHostProxyError("default_workload_contract_invalid", "The installed workspace image and sealed profile do not match.", status=503) from exc
        if dynamic:
            self._require_default_grant()
            receipt = self._call("listWorkloads", self._require_client().list_workloads)
            if not receipt["accepted"]:
                raise ExecutionHostProxyError("default_workload_authority_unavailable", "The installed workspace profile could not be verified against current private default authority.", status=503)
            result = receipt.get("result")
            projected = result.get("workspaceProfile") if isinstance(result, Mapping) else None
            expected = {"imageReference": self._workspace_image, "workloadSpecDigest": expected_digest}
            if not isinstance(projected, Mapping) or dict(projected) != expected:
                raise ExecutionHostProxyError("default_workload_profile_mismatch", "The execution host did not confirm the exact installed workspace image and profile.", status=503)
        return workload

    def _require_default_grant(self) -> None:
        if not self._grant_digest:
            raise ExecutionHostProxyError("default_grant_required", "The default workspace grant is not configured")
        if self._grant_id != DEFAULT_GRANT_ID:
            raise ExecutionHostProxyError("default_grant_required", "canonical default workspace creation requires the provisioned default grant")

    def create_default(self) -> dict[str, Any]:
        self._require_default_grant()
        workload = self._default_workspace_workload()
        return self._call(
            "createWorkload",
            lambda: self._require_client().create_workspace(workload),
            workload_id=DEFAULT_WORKSPACE_ID,
        )

    def start(self, workload_id: Any) -> dict[str, Any]:
        wid = self._validate_workload_id(workload_id)
        return self._call("start", lambda: self._workload_client(wid, operation="start").start(wid), workload_id=wid)

    def stop(self, workload_id: Any) -> dict[str, Any]:
        wid = self._validate_workload_id(workload_id)
        return self._call("stop", lambda: self._workload_client(wid, operation="stop").stop(wid), workload_id=wid)

    def cancel(self, workload_id: Any) -> dict[str, Any]:
        wid = self._validate_workload_id(workload_id)
        return self._call("cancel", lambda: self._workload_client(wid, operation="cancel").cancel(wid), workload_id=wid)

    def remove(self, workload_id: Any) -> dict[str, Any]:
        wid = self._validate_workload_id(workload_id)
        return self._call(
            "removeWorkload", lambda: self._workload_client(wid, operation="removeWorkload").remove_workload(wid), workload_id=wid
        )

    def exec(self, workload_id: Any, argv: Any, *, timeout_seconds: int | None = None) -> dict[str, Any]:
        wid = self._validate_workload_id(workload_id)
        if (
            not isinstance(argv, list)
            or not argv
            or len(argv) > 32
            or not all(isinstance(item, str) and item and len(item) <= 256 for item in argv)
        ):
            raise ExecutionHostProxyError("invalid_argv", "exec argv must be a bounded non-empty string list", status=400)
        return self._call(
            "execWorkload",
            lambda: self._workload_client(wid, operation="execWorkload").exec_workload(
                wid, argv, timeout_seconds=timeout_seconds
            ),
            workload_id=wid,
        )

    def _call(
        self,
        operation: str,
        invoke: Callable[[], Mapping[str, Any]],
        *,
        workload_id: str | None = None,
    ) -> dict[str, Any]:
        if operation not in _OPERATIONS:
            raise ExecutionHostProxyError("unsupported_operation", "operation is unsupported", status=400)
        try:
            receipt = invoke()
        except ExecutionHostRefusal as exc:
            receipt = exc.receipt
        except ExecutionHostTransportError as exc:
            raise ExecutionHostProxyError(
                "execution_unavailable", "execution host is unavailable", status=503
            ) from exc
        except ExecutionHostContractError as exc:
            raise ExecutionHostProxyError(
                "execution_protocol_violation", "execution host returned an invalid receipt", status=502
            ) from exc
        return self._bounded_result(receipt, operation=operation, workload_id=workload_id)

    @staticmethod
    def _bounded_result(
        receipt: Mapping[str, Any], *, operation: str, workload_id: str | None = None
    ) -> dict[str, Any]:
        raw_result = receipt.get("result")
        if isinstance(raw_result, Mapping):
            result: object = dict(raw_result)
        elif isinstance(raw_result, list):
            result = [dict(item) if isinstance(item, Mapping) else item for item in raw_result]
        else:
            result = None
        bounded = {
            "operationId": receipt.get("operationId"),
            "accepted": receipt.get("accepted") is True,
            "result": result,
        }
        observed = receipt.get("observed")
        if isinstance(observed, Mapping):
            bounded["observed"] = {
                key: observed.get(key)
                for key in ("engine", "engineVersion", "imageDigest", "exitStatus", "startedAt", "finishedAt")
                if key in observed
            }
        refusal = receipt.get("refusal")
        if isinstance(refusal, Mapping):
            bounded["refusal"] = {
                "reason": refusal.get("reason"),
                "detail": str(refusal.get("detail", ""))[:280],
            }
        timestamps = receipt.get("timestamps")
        completed_at = timestamps.get("completedAt") if isinstance(timestamps, Mapping) else None
        operation_id = receipt.get("operationId")
        request_digest = receipt.get("requestDigest")
        if isinstance(operation_id, str) and isinstance(completed_at, str) and isinstance(request_digest, str):
            receipt_projection: dict[str, Any] = {
                "formatVersion": "stateport.execution-host-operation-receipt/v1",
                "receiptId": f"execution-host-{operation_id}",
                "receiptType": "stateport.execution-host-operation-receipt/v1",
                "action": f"execution_host.{operation}",
                "status": "accepted" if bounded["accepted"] else "refused",
                "createdAt": completed_at,
                "sourceKind": "execution_host",
                "operationId": operation_id,
                "requestDigest": request_digest,
                "resultDigest": daemon_contract.canonical_digest(result),
                "workloadId": workload_id,
                "observed": bounded.get("observed", {}),
            }
            owner = result.get("ownership") if isinstance(result, Mapping) else None
            if isinstance(owner, Mapping):
                receipt_projection["ownership"] = dict(owner)
                receipt_projection["applicationId"] = owner.get("applicationId")
                receipt_projection["instanceId"] = owner.get("instanceId")
                receipt_projection["runId"] = owner.get("runId")
            output = result.get("output") if isinstance(result, Mapping) else None
            if isinstance(output, str):
                receipt_projection["outputDigest"] = daemon_contract.canonical_digest(output)
                receipt_projection["outputBytes"] = len(output.encode("utf-8"))
            if isinstance(bounded.get("refusal"), Mapping):
                receipt_projection["refusal"] = bounded["refusal"]
            bounded["receipt"] = receipt_projection
        return bounded


__all__ = ["DEFAULT_GRANT_ID", "ExecutionHostProxy", "ExecutionHostProxyError"]
