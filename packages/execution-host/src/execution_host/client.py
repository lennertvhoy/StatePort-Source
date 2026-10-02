"""Typed Unix-socket client for the execution-host daemon.

Speaks ``stateport.execution-host-operation/v1`` NDJSON over the confined
socket.  Transport failures (absent socket, refused connection) and daemon
refusals are distinct typed errors; every receipt is contract-validated and
bound to the exact request digest before it is returned.
"""

from __future__ import annotations

import array
import fcntl
import hashlib
import json
import os
import socket
import stat
import uuid
from pathlib import Path
from typing import Any, Mapping

from . import daemon_contract as contract


class ExecutionHostError(RuntimeError):
    """Base class for typed client failures."""


class ExecutionHostTransportError(ExecutionHostError):
    """The confined socket is absent, refused, or broke mid-request."""


class ExecutionHostRefusal(ExecutionHostError):
    """The daemon executed a refusal receipt for this request."""

    def __init__(self, receipt: Mapping[str, Any]) -> None:
        refusal = receipt.get("refusal") or {}
        super().__init__(f"{refusal.get('reason')}: {refusal.get('detail')}")
        self.receipt = dict(receipt)
        self.reason = str(refusal.get("reason"))


class ExecutionHostContractError(ExecutionHostError):
    """The peer answered with bytes outside the receipt contract."""


class ExecutionHostClient:
    def __init__(
        self,
        socket_path: str | Path,
        *,
        grant_id: str,
        authority_grant_digest: str,
        timeout_seconds: int = 30,
        output_byte_bound: int = contract.MAX_OUTPUT_BYTES,
    ) -> None:
        self._socket_path = Path(socket_path)
        self._grant_id = grant_id
        self._grant_digest = authority_grant_digest
        self._timeout_seconds = timeout_seconds
        self._output_byte_bound = output_byte_bound

    @property
    def socket_path(self) -> Path:
        """Return the immutable confined-socket binding for this client."""
        return self._socket_path

    @property
    def grant_id(self) -> str:
        """Return the provisioned execution-host grant id."""
        return self._grant_id

    @property
    def authority_grant_digest(self) -> str:
        """Return the exact provisioned grant digest sent on every request."""
        return self._grant_digest

    def _exchange(
        self,
        line: bytes,
        effective_timeout: int,
        *,
        source_fd: int | None = None,
    ) -> bytes:
        """Exchange one request with the confined daemon transport.

        Kept as a narrow transport seam so tests can exercise this concrete
        typed client while the request and receipt contracts remain active.
        """
        if not self._socket_path.exists():
            raise ExecutionHostTransportError(
                f"socket-absent: {self._socket_path} does not exist; the execution host is not provisioned or not running"
            )
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(effective_timeout + 5)
        try:
            try:
                connection.connect(str(self._socket_path))
            except OSError as exc:
                raise ExecutionHostTransportError(
                    f"socket-refused: cannot connect to {self._socket_path}: {exc}"
                ) from exc
            if source_fd is None:
                connection.sendall(line)
            else:
                try:
                    observed = os.fstat(source_fd)
                    access_mode = fcntl.fcntl(source_fd, fcntl.F_GETFL) & os.O_ACCMODE
                    os.lseek(source_fd, 0, os.SEEK_SET)
                except OSError as exc:
                    raise ExecutionHostTransportError(
                        "source-descriptor-invalid: deployment archive is unavailable"
                    ) from exc
                if not stat.S_ISREG(observed.st_mode) or access_mode != os.O_RDONLY:
                    raise ExecutionHostTransportError(
                        "source-descriptor-invalid: deployment archive is not a read-only regular file"
                    )
                descriptor = array.array("i", [source_fd])
                sent = connection.sendmsg(
                    [line],
                    [(socket.SOL_SOCKET, socket.SCM_RIGHTS, descriptor.tobytes())],
                )
                if sent <= 0:
                    raise ExecutionHostTransportError(
                        "socket-closed: daemon did not accept the deployment descriptor"
                    )
                if sent < len(line):
                    connection.sendall(line[sent:])
            buffer = b""
            while b"\n" not in buffer:
                chunk = connection.recv(65536)
                if not chunk:
                    raise ExecutionHostTransportError("socket-closed: daemon hung up mid-request")
                buffer += chunk
                if len(buffer) > contract.MAX_RESPONSE_BYTES:
                    raise ExecutionHostTransportError("daemon response exceeded the byte bound")
            return buffer
        except socket.timeout as exc:
            raise ExecutionHostTransportError(
                "socket-timeout: daemon did not answer within the request timeout"
            ) from exc
        except OSError as exc:
            raise ExecutionHostTransportError(
                f"socket-broken: daemon transport failed: {exc}"
            ) from exc
        finally:
            connection.close()

    def _request(
        self,
        operation: str,
        payload: Mapping[str, Any] | None = None,
        *,
        timeout_seconds: int | None = None,
        source_fd: int | None = None,
        operation_id: str | None = None,
    ) -> dict[str, Any]:
        effective_timeout = timeout_seconds if timeout_seconds is not None else self._timeout_seconds
        request: dict[str, Any] = {
            "formatVersion": contract.OPERATION_FORMAT,
            "operationId": operation_id or f"op-{uuid.uuid4().hex[:24]}",
            "operation": operation,
            "requester": {
                "grantId": self._grant_id,
                "authorityGrantDigest": self._grant_digest,
            },
            "timeoutSeconds": effective_timeout,
            "outputByteBound": self._output_byte_bound,
        }
        if payload is not None:
            request["payload"] = dict(payload)
        validated_request = contract.validate_operation_request(request)
        normalized_payload = contract.validate_request_payload(
            validated_request, request.get("payload")
        )
        if operation in contract.DEPLOYMENT_OPERATIONS and operation != (
            "probeDeploymentTarget"
        ):
            derived_operation_id = contract.deployment_host_operation_id(
                operation, normalized_payload
            )
            if operation_id is not None and operation_id != derived_operation_id:
                raise ValueError(
                    "deployment operation_id does not bind the exact control context and payload"
                )
            request["operationId"] = derived_operation_id
        line = (contract.canonical_json(request) + "\n").encode("utf-8")
        buffer = self._exchange(line, effective_timeout, source_fd=source_fd)
        try:
            receipt = json.loads(buffer.split(b"\n", 1)[0])
            receipt = contract.validate_receipt(receipt)
        except (ValueError, TypeError) as exc:
            raise ExecutionHostContractError(f"daemon receipt violates the contract: {exc}") from exc
        if receipt["operationId"] != request["operationId"]:
            raise ExecutionHostContractError("receipt is not bound to this request operation id")
        if receipt["requestDigest"] != contract.canonical_digest(request):
            raise ExecutionHostContractError("receipt is not bound to this exact request digest")
        if not receipt["accepted"]:
            raise ExecutionHostRefusal(receipt)
        return receipt

    def describe_capabilities(self) -> dict[str, Any]:
        return self._request("describeCapabilities")

    def create_workload(self, spec: Mapping[str, Any], *, source_fd: int | None = None) -> dict[str, Any]:
        return self._request("createWorkload", {"workload": dict(spec)}, source_fd=source_fd)

    def create_workspace(self, spec: Mapping[str, Any], *, source_fd: int | None = None) -> dict[str, Any]:
        """Create a sealed workspace workload; host paths are not accepted."""
        if spec.get("kind") != "workspace":
            raise ValueError("create_workspace requires a workspace workload")
        return self.create_workload(spec, source_fd=source_fd)

    def run_validator(self, workload: Mapping[str, Any]) -> dict[str, Any]:
        """Run one sealed validator workload end-to-end with digest evidence."""
        if workload.get("kind") != "validator-run":
            raise ValueError("run_validator requires a validator-run workload")
        return self._request("runValidator", {"workload": dict(workload)})

    def open_terminal(
        self, workload_id: str, session_id: str, *, columns: int, rows: int, expected_container_identity_digest: str | None = None
    ) -> dict[str, Any]:
        return self._request(
            "openTerminal",
            {
                **({"expectedContainerIdentityDigest": expected_container_identity_digest} if expected_container_identity_digest is not None else {}),
                "workloadId": workload_id,
                "sessionId": session_id,
                "columns": columns,
                "rows": rows,
            },
        )

    def resize_terminal(self, session_id: str, *, columns: int, rows: int) -> dict[str, Any]:
        return self._request(
            "resizeTerminal",
            {"sessionId": session_id, "columns": columns, "rows": rows},
        )

    def signal_terminal(self, session_id: str, *, signal: str) -> dict[str, Any]:
        return self._request("signalTerminal", {"sessionId": session_id, "signal": signal})

    def close_terminal(self, session_id: str) -> dict[str, Any]:
        return self._request("closeTerminal", {"sessionId": session_id})

    def exec_workload(
        self,
        workload_id: str,
        argv: list[str],
        *,
        timeout_seconds: int | None = None,
    ) -> dict[str, Any]:
        """Run one typed argv in a running workspace; no shell joining."""
        return self._request(
            "execWorkload",
            {"workloadId": workload_id, "argv": list(argv)},
            timeout_seconds=timeout_seconds,
        )

    def list_workloads(self) -> dict[str, Any]:
        return self._request("listWorkloads")

    def start(self, workload_id: str) -> dict[str, Any]:
        return self._request("start", {"workloadId": workload_id})

    def stop(self, workload_id: str) -> dict[str, Any]:
        return self._request("stop", {"workloadId": workload_id})

    def status(self, workload_id: str) -> dict[str, Any]:
        return self._request("status", {"workloadId": workload_id})

    def logs(self, workload_id: str) -> dict[str, Any]:
        return self._request("logs", {"workloadId": workload_id})

    def cancel(self, workload_id: str) -> dict[str, Any]:
        return self._request("cancel", {"workloadId": workload_id})

    def remove_workload(self, workload_id: str) -> dict[str, Any]:
        return self._request("removeWorkload", {"workloadId": workload_id})

    def collect_garbage(self) -> dict[str, Any]:
        return self._request("collectGarbage")

    # ----------------------------------------------------- deployment effects

    def probe_deployment_target(self) -> dict[str, Any]:
        return self._request("probeDeploymentTarget")

    def apply_deployment(
        self,
        plan: Mapping[str, Any],
        source_archive: Mapping[str, Any],
        *,
        source_fd: int,
        control_context: Mapping[str, Any],
        failpoint: str | None = None,
        operation_id: str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "applyDeployment",
            {
                "deploymentId": plan["spec"]["metadata"]["deploymentId"],
                "plan": dict(plan),
                "sourceArchive": dict(source_archive),
                "failpoint": failpoint,
                "controlContext": dict(control_context),
            },
            source_fd=source_fd,
            operation_id=operation_id,
        )

    def update_deployment(
        self,
        plan: Mapping[str, Any],
        *,
        predecessor_plan: Mapping[str, Any],
        predecessor_images: Mapping[str, str],
        infrastructure: Mapping[str, Any] | None,
        source_archive: Mapping[str, Any],
        source_fd: int,
        control_context: Mapping[str, Any],
        failpoint: str | None = None,
        operation_id: str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "updateDeployment",
            {
                "deploymentId": plan["spec"]["metadata"]["deploymentId"],
                "plan": dict(plan),
                "predecessorPlan": dict(predecessor_plan),
                "predecessorImages": dict(predecessor_images),
                "infrastructure": (
                    dict(infrastructure) if isinstance(infrastructure, Mapping) else None
                ),
                "sourceArchive": dict(source_archive),
                "failpoint": failpoint,
                "controlContext": dict(control_context),
            },
            source_fd=source_fd,
            operation_id=operation_id,
        )

    def observe_deployment(
        self,
        spec: Mapping[str, Any],
        *,
        expected_revision: str | None,
        expected_images: Mapping[str, str] | None,
        verify_health: bool,
        infrastructure: Mapping[str, Any] | None,
        control_context: Mapping[str, Any],
        operation_id: str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "observeDeployment",
            {
                "deploymentId": spec["metadata"]["deploymentId"],
                "spec": dict(spec),
                "expectedRevision": expected_revision,
                "expectedImages": dict(expected_images or {}),
                "verifyHealth": verify_health,
                "infrastructure": (
                    dict(infrastructure) if isinstance(infrastructure, Mapping) else None
                ),
                "controlContext": dict(control_context),
            },
            operation_id=operation_id,
        )

    def collect_deployment_logs(
        self,
        spec: Mapping[str, Any],
        *,
        service_id: str | None,
        tail: int,
        expected_revision: str | None,
        control_context: Mapping[str, Any],
        operation_id: str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "collectDeploymentLogs",
            {
                "deploymentId": spec["metadata"]["deploymentId"],
                "spec": dict(spec),
                "serviceId": service_id,
                "tail": tail,
                "expectedRevision": expected_revision,
                "controlContext": dict(control_context),
            },
            operation_id=operation_id,
        )

    def restart_deployment(
        self,
        spec: Mapping[str, Any],
        *,
        expected_revision: str | None,
        expected_images: Mapping[str, str] | None,
        infrastructure: Mapping[str, Any] | None,
        control_context: Mapping[str, Any],
        operation_id: str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "restartDeployment",
            {
                "deploymentId": spec["metadata"]["deploymentId"],
                "spec": dict(spec),
                "expectedRevision": expected_revision,
                "expectedImages": dict(expected_images or {}),
                "infrastructure": (
                    dict(infrastructure) if isinstance(infrastructure, Mapping) else None
                ),
                "controlContext": dict(control_context),
            },
            operation_id=operation_id,
        )

    def remove_deployment_runtime(
        self,
        spec: Mapping[str, Any],
        *,
        expected_revision: str | None,
        recovery_operation: str | None,
        control_context: Mapping[str, Any],
        operation_id: str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "removeDeploymentRuntime",
            {
                "deploymentId": spec["metadata"]["deploymentId"],
                "spec": dict(spec),
                "expectedRevision": expected_revision,
                "recoveryOperation": recovery_operation,
                "controlContext": dict(control_context),
            },
            operation_id=operation_id,
        )

    def backup_deployment_data(
        self,
        spec: Mapping[str, Any],
        *,
        backup_id: str,
        plan_digest: str,
        expected_volumes: Mapping[str, str],
        expected_revision: str,
        expected_images: Mapping[str, str],
        infrastructure: Mapping[str, Any] | None,
        control_context: Mapping[str, Any],
        operation_id: str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "backupDeploymentData",
            {
                "deploymentId": spec["metadata"]["deploymentId"],
                "spec": dict(spec),
                "backupId": backup_id,
                "planDigest": plan_digest,
                "expectedVolumes": dict(expected_volumes),
                "expectedRevision": expected_revision,
                "expectedImages": dict(expected_images),
                "infrastructure": (
                    dict(infrastructure)
                    if isinstance(infrastructure, Mapping)
                    else None
                ),
                "controlContext": dict(control_context),
            },
            operation_id=operation_id,
        )

    def restore_deployment_data(
        self,
        spec: Mapping[str, Any],
        *,
        backup: Mapping[str, Any],
        plan_digest: str,
        expected_volumes: Mapping[str, str],
        expected_revision: str,
        expected_images: Mapping[str, str],
        infrastructure: Mapping[str, Any] | None,
        control_context: Mapping[str, Any],
        operation_id: str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "restoreDeploymentData",
            {
                "deploymentId": spec["metadata"]["deploymentId"],
                "spec": dict(spec),
                "backup": dict(backup),
                "planDigest": plan_digest,
                "expectedVolumes": dict(expected_volumes),
                "expectedRevision": expected_revision,
                "expectedImages": dict(expected_images),
                "infrastructure": (
                    dict(infrastructure)
                    if isinstance(infrastructure, Mapping)
                    else None
                ),
                "controlContext": dict(control_context),
            },
            operation_id=operation_id,
        )

    def purge_deployment_data(
        self,
        spec: Mapping[str, Any],
        *,
        expected_volumes: Mapping[str, str],
        expected_revision: str,
        recover_interrupted: bool,
        control_context: Mapping[str, Any],
        operation_id: str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "purgeDeploymentData",
            {
                "deploymentId": spec["metadata"]["deploymentId"],
                "spec": dict(spec),
                "expectedVolumes": dict(expected_volumes),
                "expectedRevision": expected_revision,
                "recoverInterrupted": recover_interrupted,
                "controlContext": dict(control_context),
            },
            operation_id=operation_id,
        )
