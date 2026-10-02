"""Minimal host adapter protocol and a test-only deterministic adapter."""
from __future__ import annotations
from typing import Any, Protocol
from execution_host.contracts import AgentRunSpec, BackendCapabilities, RUN_RESULT_FORMAT, require_accepted


class ExecutionHostAdapter(Protocol):
    def describe_capabilities(self) -> BackendCapabilities: ...
    def prepare(self, run_spec: AgentRunSpec) -> dict[str, Any]: ...
    def execute(self, prepared_run: dict[str, Any]) -> dict[str, Any]: ...
    def cancel(self, run_id: str) -> None: ...


class SyntheticTestAdapter:
    """Deterministic test fixture; never eligible for production execution."""
    def describe_capabilities(self) -> BackendCapabilities:
        return BackendCapabilities("synthetic", "synthetic-test", "1.0.0", "portable", {name: "supported" for name in ("structuredEvents", "nonInteractiveExecution", "cancellation", "sessionResume", "repositoryInstructions", "customTools", "mcpEquivalent", "approvalIntegration", "sandboxSupport", "changedFileReporting", "tokenTelemetry", "costTelemetry")}, ("external_manual",), (), True, False)
    def prepare(self, run_spec: AgentRunSpec) -> dict[str, Any]:
        return {"runSpec": run_spec, "negotiation": require_accepted(run_spec, self.describe_capabilities())}
    def execute(self, prepared_run: dict[str, Any]) -> dict[str, Any]:
        spec = prepared_run["runSpec"]
        return {"formatVersion": RUN_RESULT_FORMAT, "runId": spec.run_id, "runSpecDigest": spec.digest, "backend": {"id": spec.backend_id, "adapter": {"id": spec.adapter_id, "version": spec.adapter_version}}, "model": spec.model_identifier, "authenticationRouteClass": spec.authentication_route_class, "statePack": {"reference": spec.statepack_reference, "digest": spec.statepack_digest}, "toolPolicy": {"permittedCapabilities": list(spec.permitted_capabilities)}, "sandbox": {"profile": spec.sandbox_profile}, "executionStatus": "completed", "verificationStatus": "synthetic_test_only", "timestamps": {"startedAt": "1970-01-01T00:00:00Z", "finishedAt": "1970-01-01T00:00:00Z"}, "failureClassification": None, "terminationClassification": "success", "usage": {"token": {"quality": "unavailable", "value": None}, "cost": {"quality": "unavailable", "value": None}}, "changedFiles": [], "validationOutcomes": [], "producedArtifacts": [], "approvalReference": spec.approval_reference, "auditReferences": [], "warnings": ["synthetic test adapter; no real host execution occurred"], "degradations": prepared_run["negotiation"]["degraded"]}
    def cancel(self, run_id: str) -> None:
        if not run_id: raise ValueError("run_id is required")


def assert_production_eligible(adapter: ExecutionHostAdapter) -> None:
    capabilities = adapter.describe_capabilities()
    if capabilities.test_only or not capabilities.production_eligible:
        raise ValueError("test-only adapter is not eligible for production")
