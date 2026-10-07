"""Focused contract tests for BL-HOST-001; no real host is invoked."""
from __future__ import annotations
import copy
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "execution-host" / "src"))
from execution_host.adapter import SyntheticTestAdapter, assert_production_eligible
from execution_host.contracts import AgentRunSpec, BackendCapabilities, CapabilityRequest, negotiate, portable_export, validate_run_result
sys.path.insert(0, str(ROOT / "scripts"))
from statedd_validate_schema import validate_json_schema


def caps(**changes):
    statuses = {name: "supported" for name in ("structuredEvents", "nonInteractiveExecution", "cancellation", "sessionResume", "repositoryInstructions", "customTools", "mcpEquivalent", "approvalIntegration", "sandboxSupport", "changedFileReporting", "tokenTelemetry", "costTelemetry")}
    statuses.update(changes.pop("statuses", {}))
    return BackendCapabilities("test", "test-adapter", "1.0.0", "portable", statuses, ("external_manual",), changes.pop("permissions", ()), **changes)


def spec(**changes):
    value = AgentRunSpec("run:test", "instance:test", "revision:test", "test objective", "statepack:test", "sha256:" + "a" * 64, (CapabilityRequest("repositoryInstructions"), CapabilityRequest("nonInteractiveExecution")), ("tokenTelemetry",), "test", "test-adapter", "1.0.0", "test-model", "external_manual", (), "external-manual", {"token": 1, "costMinor": 0, "timeSeconds": 1, "steps": 1}, ("python3 scripts/validate_repo.py",), ("evidence/result.json",), {"backend": "test", "adapter": "test-adapter", "adapterVersion": "1.0.0", "model": "test-model"}, approval_required_level="external_manual", repository_instructions=("Read AGENTS.md.",))
    return value if not changes else AgentRunSpec(**{**value.__dict__, **changes})


def result(run_spec):
    return {"formatVersion": "stateport.run-result/v1", "runId": run_spec.run_id, "runSpecDigest": run_spec.digest, "backend": {"id": run_spec.backend_id, "adapter": {"id": run_spec.adapter_id, "version": run_spec.adapter_version}}, "model": run_spec.model_identifier, "authenticationRouteClass": run_spec.authentication_route_class, "statePack": {"reference": run_spec.statepack_reference, "digest": run_spec.statepack_digest}, "toolPolicy": {"permittedCapabilities": []}, "sandbox": {"profile": run_spec.sandbox_profile}, "executionStatus": "completed", "verificationStatus": "synthetic_test_only", "timestamps": {"startedAt": "1970-01-01T00:00:00Z", "finishedAt": "1970-01-01T00:00:00Z"}, "failureClassification": None, "terminationClassification": "success", "usage": {"token": {"quality": "unavailable", "value": None}, "cost": {"quality": "unavailable", "value": None}}, "changedFiles": [], "validationOutcomes": [], "producedArtifacts": [], "approvalReference": None, "auditReferences": [], "warnings": [], "degradations": []}


def test_runspec_serialization_and_digest_are_deterministic():
    assert spec().canonical_json() == AgentRunSpec.from_dict(spec().to_dict()).canonical_json()
    assert spec().digest == AgentRunSpec.from_dict(spec().to_dict()).digest


def test_successful_negotiation_and_optional_degradation():
    negotiated = negotiate(spec(), caps(statuses={"tokenTelemetry": "unsupported"}))
    assert negotiated["acceptedRun"] and negotiated["degraded"] == [{"id": "tokenTelemetry", "status": "unsupported", "reason": "optional capability unavailable or partial"}]


@pytest.mark.parametrize("status", ["unsupported", "unknown", "partial"])
def test_required_capability_rejections(status):
    assert not negotiate(spec(), caps(statuses={"repositoryInstructions": status}))["acceptedRun"]


def test_allowed_partial_required_capability_and_permission_escalation_rejection():
    partial = spec(required_capabilities=(CapabilityRequest("repositoryInstructions", True), CapabilityRequest("nonInteractiveExecution")))
    assert negotiate(partial, caps(statuses={"repositoryInstructions": "partial"}))["acceptedRun"]
    with pytest.raises(ValueError, match="permissions exceed"):
        negotiate(spec(), caps(permissions=("write",)))


def test_secret_like_fields_unknown_fields_and_path_escape_are_rejected():
    data = spec().to_dict(); data["apiKey"] = "nope"
    with pytest.raises(ValueError): AgentRunSpec.from_dict(data)
    data = spec().to_dict(); data["benchmarkConfiguration"]["apiKey"] = "nope"
    with pytest.raises(ValueError): AgentRunSpec.from_dict(data)
    with pytest.raises(ValueError): spec(required_output_artifacts=("../escape",))


def test_run_result_is_bound_to_exact_runspec_and_honest_telemetry():
    valid = result(spec()); assert validate_run_result(valid, spec())["runId"] == "run:test"
    wrong = copy.deepcopy(valid); wrong["runId"] = "run:other"
    with pytest.raises(ValueError): validate_run_result(wrong, spec())
    wrong = copy.deepcopy(valid); wrong["runSpecDigest"] = "sha256:" + "b" * 64
    with pytest.raises(ValueError): validate_run_result(wrong, spec())
    wrong = copy.deepcopy(valid); wrong["usage"]["token"] = {"quality": "unavailable", "value": 1}
    with pytest.raises(ValueError): validate_run_result(wrong, spec())


def test_worker_termination_is_distinct_from_a_typed_logical_failure():
    logical_failure = result(spec())
    logical_failure["executionStatus"] = "failed"
    logical_failure["failureClassification"] = "validation_failure"
    assert validate_run_result(logical_failure, spec())["terminationClassification"] == "success"

    unsafe = result(spec())
    unsafe["terminationClassification"] = "timeout"
    with pytest.raises(ValueError, match="requires a failure classification"):
        validate_run_result(unsafe, spec())


def test_portable_export_claims_no_execution_and_synthetic_adapter_is_production_rejected():
    exported = portable_export(spec())
    assert exported["status"] == "exported_for_external_execution" and exported["verificationStatus"] == "result_unverified"
    adapter = SyntheticTestAdapter()
    with pytest.raises(ValueError, match="not eligible"): assert_production_eligible(adapter)
    synthetic_spec = spec(backend_id="synthetic", adapter_id="synthetic-test")
    prepared = adapter.prepare(synthetic_spec)
    assert validate_run_result(adapter.execute(prepared), synthetic_spec)["statePack"]["digest"] == synthetic_spec.statepack_digest


def test_public_schemas_match_contract_models_and_cli_proves_manual_vertical_path():
    for name, value in (("backend-capabilities.v1.schema.json", caps().to_dict()), ("agent-run-spec.v1.schema.json", spec().to_dict()), ("run-result.v1.schema.json", result(spec()))):
        schema = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
        assert not validate_json_schema(value, schema), name
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir); template = workspace / "template"; instance = workspace / "instance"
        shutil.copytree(ROOT / "templates" / "classdd", template)
        from statedd_core import create_instance
        create_instance(template, instance, instance_id="demo", name="Demo", owner_name="Alice", owner_handle="@alice")
        plan = subprocess.run([str(ROOT / "stateport"), "run", "plan", str(instance), "--template-path", str(template), "--capabilities", str(ROOT / "fixtures/host/synthetic-capabilities.json")], cwd=ROOT, capture_output=True, text=True, check=False)
        assert plan.returncode == 0, plan.stdout + plan.stderr
        payload = json.loads(plan.stdout)
        assert payload["portableExport"]["verificationStatus"] == "result_unverified"
