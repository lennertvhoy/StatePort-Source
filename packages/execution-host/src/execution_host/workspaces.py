"""Persistent workspace lifecycle adapter over the execution-host client.

Translates a canonical ``stateport.workspace-spec/v1`` declaration (the
``WorkspaceSpec`` contract from ``packages/runtime-contracts``) into the
sealed daemon ``workspace`` workload kind.  Every WorkspaceSpec field is
carried: the exact validated spec is bound by digest, lifecycle policy drives
the daemon's inactivity supervision, the shell argv stays a typed argv, and
resources map onto the sealed ceilings.  Fields the execution host cannot
enforce are never silently presented as enforced: a developer-network egress
allowlist is refused, while the portable Podman named-volume disk quota is
durably reported as unsupported in the daemon receipt. Host paths are not
representable: data lives only in daemon-owned named volumes.
"""
from __future__ import annotations

import re
from typing import Any, Mapping

from runtime_contracts.alpha4 import WorkspaceSpec

from . import daemon_contract as contract
from .client import ExecutionHostClient


_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")


class WorkspaceRuntimeError(RuntimeError):
    """Workspace specification or execution-host lifecycle refusal."""


def sealed_workspace_workload(
    spec_value: Mapping[str, Any],
    *,
    image_reference: str,
    base_revision: str | None = None,
) -> dict[str, Any]:
    """Translate one WorkspaceSpec into a validated sealed daemon workload."""

    try:
        spec = WorkspaceSpec.from_dict(spec_value)
    except ValueError as exc:
        raise WorkspaceRuntimeError(f"workspace specification is invalid: {exc}") from exc
    validated = spec.to_dict()
    try:
        contract.validate_image_reference(image_reference)
    except ValueError as exc:
        raise WorkspaceRuntimeError("workspace image must be digest-pinned") from exc
    if not image_reference.endswith("@" + validated["imageDigest"]):
        raise WorkspaceRuntimeError("workspace image reference does not match the declared digest")
    if base_revision is not None and _GIT_SHA.fullmatch(base_revision) is None:
        raise WorkspaceRuntimeError("workspace base revision must be a full lowercase git sha")
    lifecycle = validated["lifecyclePolicy"]
    network = validated["networkProfile"]
    if network["mode"] == "developer" and network["allowlist"]:
        raise WorkspaceRuntimeError(
            "the execution host cannot enforce a developer-network egress "
            "allowlist in this slice; use an empty allowlist or disabled networking"
        )
    resources = validated["resources"]
    parameters: dict[str, Any] = {
        "workspaceId": validated["workspaceId"],
        "workspaceSpecDigest": spec.digest,
        "volumeName": "stateport-workspace-" + validated["workspaceId"],
        "stopAfterIdle": lifecycle["stopAfterIdle"],
        "shell": list(validated["shell"]),
        "networkMode": "developer" if network["mode"] == "developer" else "none",
        "cacheVolumes": [dict(item) for item in validated["cacheVolumes"]],
        "cpuQuotaPercent": resources["cpuQuotaPercent"],
        "diskMaxBytes": resources["diskMaxBytes"],
        "workSeconds": 0,
        "emitBytes": 0,
    }
    if base_revision is not None:
        parameters["baseRevision"] = base_revision
    workload = {
        "kind": "workspace",
        "workloadId": validated["workspaceId"],
        "image": {"reference": image_reference},
        "parameters": parameters,
        # For the workspace kind the sealed timeout is the INACTIVITY bound
        # (WorkspaceSpec lifecyclePolicy.idleTimeoutSeconds), not a lifetime.
        "timeoutSeconds": max(
            1, min(int(lifecycle["idleTimeoutSeconds"]), contract.MAX_TIMEOUT_SECONDS)
        ),
        "outputByteBound": 65536,
        "resources": {
            "memoryMaxBytes": resources["memoryMaxBytes"],
            "pidsMax": resources["pidsMax"],
        },
    }
    try:
        return contract.validate_workload_spec(workload)
    except ValueError as exc:
        raise WorkspaceRuntimeError(f"sealed workspace workload is invalid: {exc}") from exc


class WorkspaceRuntime:
    """Drive persistent workspace lifecycle through the confined daemon client."""

    def __init__(self, client: ExecutionHostClient, *, image_reference: str) -> None:
        try:
            contract.validate_image_reference(image_reference)
        except ValueError as exc:
            raise WorkspaceRuntimeError("workspace image must be digest-pinned") from exc
        self._client = client
        self._image_reference = image_reference

    def create(self, spec: Mapping[str, Any], *, base_revision: str | None = None) -> dict[str, Any]:
        workload = sealed_workspace_workload(
            spec, image_reference=self._image_reference, base_revision=base_revision
        )
        return self._client.create_workspace(workload)

    def list(self) -> dict[str, Any]:
        """Real grant-scoped enumeration from daemon state."""
        return self._client.list_workloads()

    def inspect(self, workspace_id: str) -> dict[str, Any]:
        return self._client.status(workspace_id)

    def runtime_identity(self, workspace_id: str) -> dict[str, Any]:
        """Return the execution-host-observed runtime identity for a workspace.

        Used by revision/promotion tooling to read container state, image
        digest, and current revision through the execution host only.
        """
        return self._client.status(workspace_id)

    def start(self, workspace_id: str) -> dict[str, Any]:
        return self._client.start(workspace_id)

    def stop(self, workspace_id: str) -> dict[str, Any]:
        return self._client.stop(workspace_id)

    def restart(self, workspace_id: str) -> dict[str, Any]:
        self.stop(workspace_id)
        return self.start(workspace_id)

    def remove(self, workspace_id: str) -> dict[str, Any]:
        """Remove only the container; the daemon-owned volume is preserved."""
        return self._client.remove_workload(workspace_id)


__all__ = ["WorkspaceRuntime", "WorkspaceRuntimeError", "sealed_workspace_workload"]
