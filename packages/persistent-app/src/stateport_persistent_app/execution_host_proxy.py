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
from pathlib import Path
import re
from typing import Any, Callable, Mapping

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
    ) -> None:
        self._socket_path = str(socket_path) if socket_path is not None else os.environ.get("STATEPORT_EXECUTION_SOCKET", "")
        self._grant_id = grant_id or os.environ.get("STATEPORT_EXECUTION_GRANT_ID", DEFAULT_GRANT_ID)
        self._grant_digest = authority_grant_digest or os.environ.get("STATEPORT_EXECUTION_GRANT_DIGEST", "")
        self._timeout_seconds = timeout_seconds
        self._client: ExecutionHostClient | None = None
        self._deployment_adapter: Any | None = None

    # ------------------------------------------------------------ readiness

    def _client_ready(self) -> tuple[ExecutionHostClient | None, str | None]:
        if not self._socket_path:
            return None, "execution_socket_not_configured"
        try:
            path = Path(self._socket_path)
        except (TypeError, ValueError) as exc:
            return None, f"execution_socket_invalid: {exc}"
        if not path.is_absolute():
            return None, "execution_socket_invalid"
        if not self._grant_digest:
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
                "grantId": self._grant_id,
                "grantBound": True,
            }
        except (ExecutionHostRefusal, ExecutionHostContractError):
            return {
                "status": "unavailable",
                "reason": "execution_host_refused",
                "detail": "the execution host refused or invalidated the capability probe",
                "grantId": self._grant_id,
                "grantBound": True,
            }
        result = receipt.get("result")
        if not isinstance(result, Mapping):
            return {
                "status": "unavailable",
                "reason": "execution_host_protocol_violation",
                "grantId": self._grant_id,
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
            "grantId": self._grant_id,
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

    def list(self) -> dict[str, Any]:
        return self._call("listWorkloads", self._require_client().list_workloads)

    def status_of(self, workload_id: Any) -> dict[str, Any]:
        wid = self._validate_workload_id(workload_id)
        return self._call("status", lambda: self._require_client().status(wid), workload_id=wid)

    def logs(self, workload_id: Any) -> dict[str, Any]:
        wid = self._validate_workload_id(workload_id)
        return self._call("logs", lambda: self._require_client().logs(wid), workload_id=wid)

    def create_default(self) -> dict[str, Any]:
        if self._grant_id != DEFAULT_GRANT_ID:
            raise ExecutionHostProxyError(
                "default_grant_required",
                "canonical default workspace creation requires the provisioned default grant",
            )
        try:
            workload = default_sealed_workspace_workload()
        except ReleaseContractError as exc:
            raise ExecutionHostProxyError(
                "default_workload_contract_invalid",
                "the canonical default workspace contract is unavailable",
                status=503,
            ) from exc
        if (
            workload.get("workloadId") != DEFAULT_WORKSPACE_ID
            or daemon_contract.canonical_digest(workload) != DEFAULT_WORKSPACE_SPEC_DIGEST
        ):
            raise ExecutionHostProxyError(
                "default_workload_contract_invalid",
                "the canonical default workspace contract is unavailable",
                status=503,
            )
        return self._call(
            "createWorkload",
            lambda: self._require_client().create_workspace(workload),
            workload_id=DEFAULT_WORKSPACE_ID,
        )

    def start(self, workload_id: Any) -> dict[str, Any]:
        wid = self._validate_workload_id(workload_id)
        return self._call("start", lambda: self._require_client().start(wid), workload_id=wid)

    def stop(self, workload_id: Any) -> dict[str, Any]:
        wid = self._validate_workload_id(workload_id)
        return self._call("stop", lambda: self._require_client().stop(wid), workload_id=wid)

    def cancel(self, workload_id: Any) -> dict[str, Any]:
        wid = self._validate_workload_id(workload_id)
        return self._call("cancel", lambda: self._require_client().cancel(wid), workload_id=wid)

    def remove(self, workload_id: Any) -> dict[str, Any]:
        wid = self._validate_workload_id(workload_id)
        return self._call(
            "removeWorkload", lambda: self._require_client().remove_workload(wid), workload_id=wid
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
            lambda: self._require_client().exec_workload(
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
            output = result.get("output") if isinstance(result, Mapping) else None
            if isinstance(output, str):
                receipt_projection["outputDigest"] = daemon_contract.canonical_digest(output)
                receipt_projection["outputBytes"] = len(output.encode("utf-8"))
            if isinstance(bounded.get("refusal"), Mapping):
                receipt_projection["refusal"] = bounded["refusal"]
            bounded["receipt"] = receipt_projection
        return bounded


__all__ = ["DEFAULT_GRANT_ID", "ExecutionHostProxy", "ExecutionHostProxyError"]
