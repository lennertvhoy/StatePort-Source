#!/usr/bin/env python3
"""Focused conformance tests for the declarative runtime-contract boundary."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "runtime-contracts" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "statedd-core" / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from runtime_contracts import (  # noqa: E402
    AgentEvent, AgentProfile, ContextManifest, RunReceipt, RuntimeProfile,
    TaskManifest, WorkflowDeclaration, load_workflow_declaration,
)
from statedd_validate_schema import validate_json_schema  # noqa: E402


DIGEST = "sha256:" + "a" * 64
SHA = "a" * 40


def command(*argv: str) -> dict[str, object]:
    return {"command": list(argv), "timeoutSeconds": 60}


def workflow_data():
    return {
        "formatVersion": "stateport.workflow/v1", "id": "workflow.demo",
        "task": {"kind": "development"}, "preflight": command("git", "diff", "--check"),
        "execution": {"supportedModes": ["agent_native", "assisted"], "defaultMode": "agent_native"},
        "verify": command("python3", "scripts/test_runtime_contracts.py"),
        "failure": {"defaultAction": "report_and_stop", "sideEffectClass": "none", "automaticRetryAllowed": False},
        "closure": {"requireCleanWorktree": True, "requireReceipt": True},
        "profileReferences": {"runtime": "profiles/local.yaml", "agent": "profiles/coder.yaml"},
    }


def task_data():
    return {
        "formatVersion": "stateport.task-manifest/v1", "jobId": "job.demo", "taskId": "task.demo",
        "identity": {"application": "stateport", "action": "repair_contracts"}, "requestedMode": "agent_native",
        "repository": {"id": "stateport", "digest": DIGEST}, "instance": {"id": "instance.demo", "digest": DIGEST},
        "baseSha": SHA, "allowedPaths": ["packages/runtime-contracts/src/runtime_contracts/contracts.py"],
        "ownership": {"packages/runtime-contracts/src/runtime_contracts/contracts.py": "stateport"},
        "inputs": [{"name": "assignment", "type": "text", "required": True, "valueDigest": DIGEST}],
        "preflight": command("git", "diff", "--check"), "execution": {"requirements": ["leased_worktree", "base_sha_bound"]},
        "verification": command("python3", "scripts/test_runtime_contracts.py"),
        "outputs": [{"name": "receipt", "path": "evidence/receipt.json", "type": "run_receipt"}],
        "failure": {"action": "report_and_stop", "rollbackRequired": True},
        "budgets": {"token": 1, "costMinor": 0, "timeSeconds": 1, "steps": 1},
        "sideEffects": [{"id": "filesystem", "classification": "none", "automaticRetryAllowed": False, "approvalRequired": False}],
        "closure": {"requireCleanWorktree": True, "requireReceipt": True},
    }


def runtime_data():
    return {
        "formatVersion": "stateport.runtime-profile/v1", "runtimeId": "runtime.demo", "mode": "agent_native",
        "harness": {"id": "repository", "version": "1"}, "adapter": {"id": "none", "version": "1"},
        "provider": {"id": "provider_neutral", "model": "unselected"}, "reasoning": {"classification": "unspecified"},
        "authentication": {"classification": "operator_authenticated", "owner": "operator"},
        "toolContract": {"allowed": ["shell"], "denied": ["network"]}, "sandbox": {"profile": "workspace", "filesystem": "bounded"},
        "network": {"policy": "disabled", "allowlist": []}, "environmentAllowlist": ["LANG"],
        "budgets": {"token": 1, "costMinor": 0, "timeSeconds": 1, "steps": 1},
        "resume": {"supported": False, "strategy": "none"}, "capabilityRequirements": {"read_repository": "supported"}, "degradations": [],
    }


def context_data():
    source = {"id": "agents", "path": "AGENTS.md", "digest": DIGEST, "authority": "stateport"}
    return {
        "formatVersion": "stateport.context-manifest/v1", "contextId": "context.demo", "canonicalSources": [source], "generatedSources": [],
        "includedCategories": ["instructions"], "excludedCategories": ["credentials"], "provenance": {"agents": "repository"}, "hashes": {"agents": DIGEST},
        "redactions": ["credentials"], "summaries": [{"sourceId": "agents", "digest": DIGEST}],
        "budgetDecisions": {"tokenBudget": 100, "estimatedTokens": 50, "decision": "accepted"}, "authorityClassification": "canonical",
    }


def agent_data():
    return {
        "formatVersion": "stateport.agent-profile/v1", "agentId": "agent.demo", "role": "contract_owner",
        "task": {"kind": "development", "instructions": ["Read repository instructions."]}, "tools": ["shell"],
        "permissions": {"requested": ["read_repository"], "prohibited": ["network"]}, "procedures": ["validate_before_close"],
        "output": {"format": "stateport.run-receipt/v1", "requiredFields": ["closure", "evidence"]},
        "closure": {"requireVerification": True, "requireReceipt": True}, "degradations": [],
    }


def outcome(status="passed"):
    return {"status": status, "evidence": ["evidence/check.txt"]}


def receipt_data():
    return {
        "formatVersion": "stateport.run-receipt/v1", "runId": "run.demo", "parentJobId": "job.demo", "attemptId": "attempt.1", "taskId": "task.demo",
        "baseGit": SHA, "finalGit": SHA, "mode": "agent_native",
        "runtimeIdentity": {
            "harness": {"id": "repository", "version": "1", "classification": "agent_native"},
            "adapter": {"id": "none", "version": "1", "classification": "not_applicable"},
            "provider": {"id": "provider_neutral", "classification": "provider_neutral"},
            "model": {"id": "unselected", "classification": "unselected"},
            "authenticationRoute": {"classification": "operator_authenticated", "ownerClassification": "operator"},
        },
        "capabilityNegotiation": {
            "requested": ["read_repository", "network"], "effective": ["read_repository"], "unavailable": ["network"],
            "acceptedDegradations": [{"capability": "network", "reason": "operator_policy"}], "observationQuality": "observed",
        },
        "digests": {key: DIGEST for key in ("workflowDeclaration", "taskManifest", "runtimeProfile", "contextManifest", "agentProfile", "agentRunSpec", "eventJournal")},
        "references": {"runResult": {"id": "result.demo", "digest": DIGEST}, "runBundle": {"id": "bundle.demo", "digest": DIGEST}},
        "preflight": outcome(), "journal": {"eventCount": 11, "digest": DIGEST},
        "attemptChain": [{"attemptId": "attempt.1.1", "ordinal": 1, "operation": "execution_start", "classification": "completed", "result": "passed", "automatic": False, "evidence": ["evidence/check.txt"]}],
        "first": outcome(), "eventual": outcome(), "verification": outcome(),
        "fileChanges": {"changedPaths": [], "allowed": True, "digest": DIGEST},
        "permissions": {"requested": ["read_repository"], "effective": ["read_repository"]}, "approvals": {"required": False, "references": []},
        "usage": {"availability": "exact", "token": 1, "costMinor": 0},
        "sideEffects": [{"id": "filesystem", "classification": "none", "outcome": "not_attempted"}],
        "rollback": {"required": False, "status": "not_required"}, "closure": {"status": "closed", "reason": "verified"}, "evidence": ["evidence/check.txt"],
    }


def event_data(event_type="run.started"):
    return {
        "formatVersion": "stateport.agent-event/v1", "eventId": "event.1", "jobId": "job.demo", "attemptId": "attempt.1", "runId": "run.demo",
        "producer": {"id": "adapter.demo", "kind": "adapter", "version": "1"}, "sequence": 0, "eventType": event_type,
        "timestamp": "2026-07-14T00:00:00Z", "payload": {"summary": "normalized event", "attributes": {"sequence": 0}},
        "redactionResult": {"status": "not_needed", "categories": []}, "observationQuality": "observed",
    }


@pytest.mark.parametrize("model,data", [
    (WorkflowDeclaration, workflow_data()), (TaskManifest, task_data()), (RuntimeProfile, runtime_data()),
    (ContextManifest, context_data()), (AgentProfile, agent_data()), (RunReceipt, receipt_data()),
])
def test_contract_round_trips_and_digests(model, data):
    value = model.from_dict(data)
    assert value.to_dict() == data
    assert value.digest == model.from_dict(value.to_dict()).digest


def test_runtime_profile_can_record_unproven_network_isolation_without_an_allowlist():
    data = runtime_data()
    data["network"] = {"policy": "unproven", "allowlist": []}
    assert RuntimeProfile.from_dict(data).to_dict()["network"]["policy"] == "unproven"
    data["network"]["allowlist"] = ["example.invalid"]
    with pytest.raises(ValueError, match="cannot claim an enforced allowlist"):
        RuntimeProfile.from_dict(data)


def test_loader_accepts_exact_workflow_yaml_without_selected_runtime_or_context(tmp_path):
    yaml_text = """formatVersion: stateport.workflow/v1
id: workflow.demo
task:
  kind: development
preflight:
  command: ["git", "diff", "--check"]
  timeoutSeconds: 60
execution:
  supportedModes:
    - agent_native
    - assisted
  defaultMode: agent_native
verify:
  command: ["python3", "scripts/test_runtime_contracts.py"]
  timeoutSeconds: 60
failure:
  defaultAction: report_and_stop
  sideEffectClass: none
  automaticRetryAllowed: false
closure:
  requireCleanWorktree: true
  requireReceipt: true
profileReferences:
  runtime: profiles/local.yaml
"""
    path = tmp_path / "workflow.yaml"
    path.write_text(yaml_text, encoding="utf-8")
    workflow = load_workflow_declaration(path)
    assert workflow.to_dict()["formatVersion"] == "stateport.workflow/v1"
    assert "runtime" not in workflow.to_dict() and "context" not in workflow.to_dict()
    assert workflow.to_dict()["preflight"]["command"] == ["git", "diff", "--check"]

    path.write_text(yaml_text.replace('["git", "diff", "--check"]', "git diff --check"), encoding="utf-8")
    with pytest.raises(ValueError):
        load_workflow_declaration(path)


def test_all_normalized_event_vocabulary_round_trips_and_matches_schema():
    schema = json.loads((ROOT / "schemas" / "agent-event.v1.schema.json").read_text(encoding="utf-8"))
    vocabulary = ["run.started", "session.created", "message.delta", "command.started", "command.completed", "file.changed", "approval.requested", "usage.updated", "run.completed", "run.failed", "run.cancelled"]
    for event_type in vocabulary:
        payload = event_data(event_type)
        assert AgentEvent.from_dict(payload).to_dict() == payload
        assert not validate_json_schema(payload, schema), event_type


def test_all_schemas_accept_their_complete_contract():
    models = {
        "workflow-declaration.v1.schema.json": workflow_data(), "task-manifest.v1.schema.json": task_data(),
        "runtime-profile.v1.schema.json": runtime_data(), "context-manifest.v1.schema.json": context_data(),
        "agent-profile.v1.schema.json": agent_data(), "agent-event.v1.schema.json": event_data(), "run-receipt.v1.schema.json": receipt_data(),
    }
    for schema_name, payload in models.items():
        schema = json.loads((ROOT / "schemas" / schema_name).read_text(encoding="utf-8"))
        assert not validate_json_schema(payload, schema), schema_name


def test_workflow_rejects_selected_runtime_context_and_unsafe_retry():
    payload = workflow_data(); payload["runtime"] = runtime_data()
    with pytest.raises(ValueError): WorkflowDeclaration.from_dict(payload)
    payload = workflow_data(); payload["failure"]["automaticRetryAllowed"] = True
    assert WorkflowDeclaration.from_dict(payload).to_dict()["failure"]["automaticRetryAllowed"] is True
    payload["failure"]["sideEffectClass"] = "external"
    with pytest.raises(ValueError): WorkflowDeclaration.from_dict(payload)


@pytest.mark.parametrize("factory,schema_name,field", [
    (workflow_data, "workflow-declaration.v1.schema.json", "preflight"),
    (workflow_data, "workflow-declaration.v1.schema.json", "verify"),
    (task_data, "task-manifest.v1.schema.json", "preflight"),
    (task_data, "task-manifest.v1.schema.json", "verification"),
])
@pytest.mark.parametrize("invalid_command", ["git diff --check", []])
def test_preflight_and_verification_require_nonempty_argv(factory, schema_name, field, invalid_command):
    payload = factory()
    payload[field]["command"] = invalid_command
    model = WorkflowDeclaration if factory is workflow_data else TaskManifest
    with pytest.raises(ValueError):
        model.from_dict(payload)
    schema = json.loads((ROOT / "schemas" / schema_name).read_text(encoding="utf-8"))
    assert validate_json_schema(payload, schema)


@pytest.mark.parametrize("factory,schema_name,field", [
    (workflow_data, "workflow-declaration.v1.schema.json", "preflight"),
    (workflow_data, "workflow-declaration.v1.schema.json", "verify"),
    (task_data, "task-manifest.v1.schema.json", "preflight"),
    (task_data, "task-manifest.v1.schema.json", "verification"),
])
def test_preflight_and_verification_require_positive_timeout(factory, schema_name, field):
    payload = factory()
    payload[field]["timeoutSeconds"] = 0
    model = WorkflowDeclaration if factory is workflow_data else TaskManifest
    with pytest.raises(ValueError):
        model.from_dict(payload)
    schema = json.loads((ROOT / "schemas" / schema_name).read_text(encoding="utf-8"))
    assert validate_json_schema(payload, schema)


def test_filesystem_transactions_are_accepted_but_never_automatic_retry_safe():
    workflow = workflow_data(); workflow["failure"].update(sideEffectClass="filesystem_transaction", automaticRetryAllowed=False)
    assert WorkflowDeclaration.from_dict(workflow).to_dict()["failure"]["sideEffectClass"] == "filesystem_transaction"
    workflow_schema = json.loads((ROOT / "schemas" / "workflow-declaration.v1.schema.json").read_text(encoding="utf-8"))
    assert not validate_json_schema(workflow, workflow_schema)
    workflow["failure"]["automaticRetryAllowed"] = True
    with pytest.raises(ValueError): WorkflowDeclaration.from_dict(workflow)
    assert validate_json_schema(workflow, workflow_schema)

    task = task_data(); task["sideEffects"][0].update(classification="filesystem_transaction", automaticRetryAllowed=False)
    assert TaskManifest.from_dict(task).to_dict()["sideEffects"][0]["classification"] == "filesystem_transaction"
    task_schema = json.loads((ROOT / "schemas" / "task-manifest.v1.schema.json").read_text(encoding="utf-8"))
    assert not validate_json_schema(task, task_schema)
    task["sideEffects"][0]["automaticRetryAllowed"] = True
    with pytest.raises(ValueError): TaskManifest.from_dict(task)
    assert validate_json_schema(task, task_schema)

    receipt = receipt_data(); receipt["sideEffects"][0]["classification"] = "filesystem_transaction"
    assert RunReceipt.from_dict(receipt).to_dict()["sideEffects"][0]["classification"] == "filesystem_transaction"
    receipt_schema = json.loads((ROOT / "schemas" / "run-receipt.v1.schema.json").read_text(encoding="utf-8"))
    assert not validate_json_schema(receipt, receipt_schema)


def test_task_identity_exact_identity_and_unsafe_retry_fail_closed():
    payload = task_data(); payload["identity"] = {"application": "stateport"}
    with pytest.raises(ValueError): TaskManifest.from_dict(payload)
    payload = task_data(); payload["repository"] = {"id": "stateport"}
    with pytest.raises(ValueError): TaskManifest.from_dict(payload)
    payload = task_data(); payload["sideEffects"][0]["classification"] = "external"; payload["sideEffects"][0]["automaticRetryAllowed"] = True
    with pytest.raises(ValueError): TaskManifest.from_dict(payload)
    payload = task_data(); payload["sideEffects"][0]["automaticRetryAllowed"] = True
    assert TaskManifest.from_dict(payload).to_dict()["sideEffects"][0]["automaticRetryAllowed"] is True


def test_profiles_reject_credentials_conflicting_permissions_and_budget_lies():
    payload = runtime_data(); payload["authentication"]["apiKey"] = "not-allowed"
    with pytest.raises(ValueError): RuntimeProfile.from_dict(payload)
    payload = agent_data(); payload["permissions"]["prohibited"] = ["read_repository"]
    with pytest.raises(ValueError): AgentProfile.from_dict(payload)
    payload = context_data(); payload["budgetDecisions"]["estimatedTokens"] = 101
    with pytest.raises(ValueError): ContextManifest.from_dict(payload)


def test_event_payload_is_bounded_and_redaction_is_explicit():
    payload = event_data(); payload["payload"]["summary"] = "x" * 4097
    with pytest.raises(ValueError): AgentEvent.from_dict(payload)
    payload = event_data(); del payload["redactionResult"]
    with pytest.raises(ValueError): AgentEvent.from_dict(payload)
    payload = event_data("provider.raw")
    with pytest.raises(ValueError): AgentEvent.from_dict(payload)


def test_receipt_references_result_bundle_and_usage_availability_without_inventing_values():
    payload = receipt_data(); del payload["references"]["runBundle"]
    with pytest.raises(ValueError): RunReceipt.from_dict(payload)


def test_receipt_requires_explicit_runtime_identity_and_capability_negotiation():
    payload = receipt_data(); del payload["runtimeIdentity"]
    with pytest.raises(ValueError): RunReceipt.from_dict(payload)
    receipt_schema = json.loads((ROOT / "schemas" / "run-receipt.v1.schema.json").read_text(encoding="utf-8"))
    assert validate_json_schema(payload, receipt_schema)

    payload = receipt_data(); payload["runtimeIdentity"]["authenticationRoute"]["apiKey"] = "not-allowed"
    with pytest.raises(ValueError): RunReceipt.from_dict(payload)
    assert validate_json_schema(payload, receipt_schema)

    payload = receipt_data(); payload["capabilityNegotiation"]["unavailable"] = ["unrequested_capability"]
    with pytest.raises(ValueError): RunReceipt.from_dict(payload)

    payload = receipt_data(); payload["capabilityNegotiation"]["acceptedDegradations"] = [{"capability": "read_repository", "reason": "operator_policy"}]
    with pytest.raises(ValueError): RunReceipt.from_dict(payload)

    payload = receipt_data(); payload["capabilityNegotiation"]["observationQuality"] = "guessed"
    with pytest.raises(ValueError): RunReceipt.from_dict(payload)
    assert validate_json_schema(payload, receipt_schema)
    payload = receipt_data(); payload["usage"] = {"availability": "unavailable", "token": 1, "costMinor": 0}
    with pytest.raises(ValueError): RunReceipt.from_dict(payload)
    payload = receipt_data(); payload["verification"] = outcome("not_run")
    with pytest.raises(ValueError): RunReceipt.from_dict(payload)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
