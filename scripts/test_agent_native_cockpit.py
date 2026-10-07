#!/usr/bin/env python3
"""Public-safe adversarial tests for the bounded agent-native cockpit."""
from __future__ import annotations

import os
from hashlib import sha256
import shutil
import sys
import tempfile
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for relative in (
    "packages/runtime-contracts/src",
    "packages/execution-host/src",
    "packages/external-engine-runtime/src",
    "packages/governed-runner/src",
    "packages/run-bundle/src",
):
    sys.path.insert(0, str(ROOT / relative))

from execution_host.contracts import AgentRunSpec, CapabilityRequest  # noqa: E402
from governed_runner import AgentNativeCockpit, CockpitError, CockpitStateError, InstanceLeaseBusy, OperationalEvidenceStore  # noqa: E402
from run_bundle import RunBundleWriter  # noqa: E402
from runtime_contracts import AgentProfile, ContextManifest, RuntimeProfile, TaskManifest, WorkflowDeclaration  # noqa: E402


DIGEST = "sha256:" + "b" * 64


def command(code: str, timeout: int = 5) -> dict[str, object]:
    return {"command": [sys.executable, "-c", code], "timeoutSeconds": timeout}


def git(root: Path, *args: str) -> str:
    import subprocess
    return subprocess.check_output(("git", *args), cwd=root, text=True).strip()


def repository(root: Path) -> tuple[Path, Path, str]:
    canonical, staging = root / "canonical", root / "staging"
    canonical.mkdir()
    git(canonical, "init", "-q")
    git(canonical, "config", "user.email", "test@example.invalid")
    git(canonical, "config", "user.name", "Test")
    (canonical / "owned.txt").write_text("base\n", encoding="utf-8")
    git(canonical, "add", "owned.txt")
    git(canonical, "commit", "-qm", "base")
    shutil.copytree(canonical, staging, symlinks=True)
    return canonical, staging, git(canonical, "rev-parse", "HEAD")


def contracts(sha: str, *, preflight: str = "pass", verify: str = "pass"):
    preflight_command, verify_command = command(preflight), command(verify)
    workflow = WorkflowDeclaration.from_dict({
        "formatVersion": "stateport.workflow/v1", "id": "workflow.cockpit", "task": {"kind": "maintenance"},
        "preflight": preflight_command, "execution": {"supportedModes": ["agent_native"], "defaultMode": "agent_native"}, "verify": verify_command,
        "failure": {"defaultAction": "report_and_stop", "sideEffectClass": "none", "automaticRetryAllowed": False}, "closure": {"requireCleanWorktree": True, "requireReceipt": True},
    })
    task = TaskManifest.from_dict({
        "formatVersion": "stateport.task-manifest/v1", "jobId": "job.cockpit", "taskId": "task.cockpit", "identity": {"application": "stateport", "action": "maintenance"}, "requestedMode": "agent_native",
        "repository": {"id": "stateport", "digest": DIGEST}, "instance": {"id": "instance.cockpit", "digest": DIGEST}, "baseSha": sha,
        "allowedPaths": ["owned.txt"], "ownership": {"owned.txt": "stateport"}, "inputs": [], "preflight": preflight_command,
        "execution": {"requirements": ["leased_worktree", "base_sha_bound", "staging_only"]}, "verification": verify_command,
        "outputs": [{"name": "receipt", "path": "evidence/receipt.json", "type": "run_receipt"}], "failure": {"action": "report_and_stop", "rollbackRequired": False},
        "budgets": {"token": 1, "costMinor": 0, "timeSeconds": 5, "steps": 1}, "sideEffects": [], "closure": {"requireCleanWorktree": True, "requireReceipt": True},
    })
    runtime = RuntimeProfile.from_dict({
        "formatVersion": "stateport.runtime-profile/v1", "runtimeId": "runtime.cockpit", "mode": "agent_native", "harness": {"id": "repository", "version": "1"}, "adapter": {"id": "external", "version": "1"},
        "provider": {"id": "provider_neutral", "model": "unselected"}, "reasoning": {"classification": "unspecified"}, "authentication": {"classification": "not_applicable", "owner": "none"},
        "toolContract": {"allowed": ["structuredEvents"], "denied": ["network"]}, "sandbox": {"profile": "declared_only", "filesystem": "unproven"}, "network": {"policy": "disabled", "allowlist": []}, "environmentAllowlist": ["PATH"],
        "budgets": {"token": 1, "costMinor": 0, "timeSeconds": 5, "steps": 1}, "resume": {"supported": False, "strategy": "none"}, "capabilityRequirements": {"structuredEvents": "supported"}, "degradations": ["isolation_unproven"],
    })
    context = ContextManifest.from_dict({
        "formatVersion": "stateport.context-manifest/v1", "contextId": "context.cockpit", "canonicalSources": [{"id": "agents", "path": "AGENTS.md", "digest": DIGEST, "authority": "stateport"}], "generatedSources": [], "includedCategories": ["instructions"], "excludedCategories": ["credentials"], "provenance": {"agents": "repository"}, "hashes": {"agents": DIGEST}, "redactions": ["credentials"], "summaries": [], "budgetDecisions": {"tokenBudget": 10, "estimatedTokens": 1, "decision": "accepted"}, "authorityClassification": "canonical",
    })
    agent = AgentProfile.from_dict({
        "formatVersion": "stateport.agent-profile/v1", "agentId": "agent.external", "role": "maintainer", "task": {"kind": "maintenance", "instructions": ["Use the prepared staging repository."]}, "tools": ["structuredEvents"], "permissions": {"requested": ["structuredEvents"], "prohibited": ["network"]}, "procedures": ["verify_before_close"], "output": {"format": "stateport.run-receipt/v1", "requiredFields": ["closure"]}, "closure": {"requireVerification": True, "requireReceipt": True}, "degradations": ["no_provider_session"],
    })
    spec = AgentRunSpec("run.cockpit", "instance.cockpit", sha, "maintenance", "context:context.cockpit", context.digest, (CapabilityRequest("structuredEvents"),), (), "external", "external", "1", "unselected", "not_applicable", ("structuredEvents",), "declared_only", {"token": 1, "costMinor": 0, "timeSeconds": 5, "steps": 1}, tuple(verify_command["command"]), ("evidence/receipt.json",), {"mode": "agent_native"}, approval_required_level="operator", repository_instructions=("AGENTS.md",))
    return workflow, task, runtime, context, agent, spec


def result(spec: AgentRunSpec) -> dict[str, object]:
    return {"formatVersion": "stateport.run-result/v1", "runId": spec.run_id, "runSpecDigest": spec.digest, "backend": {"id": spec.backend_id, "adapter": {"id": spec.adapter_id, "version": spec.adapter_version}}, "model": spec.model_identifier, "authenticationRouteClass": spec.authentication_route_class, "statePack": {"reference": spec.statepack_reference, "digest": spec.statepack_digest}, "toolPolicy": {"permittedCapabilities": list(spec.permitted_capabilities)}, "sandbox": {"profile": spec.sandbox_profile}, "executionStatus": "completed", "verificationStatus": "externally_observed", "timestamps": {"startedAt": "2026-07-14T00:00:00Z", "finishedAt": "2026-07-14T00:00:01Z"}, "failureClassification": None, "terminationClassification": "success", "usage": {"token": {"quality": "unavailable", "value": None}, "cost": {"quality": "unavailable", "value": None}}, "changedFiles": [], "validationOutcomes": [], "producedArtifacts": [], "approvalReference": None, "auditReferences": [], "warnings": [], "degradations": []}


def bundle(root: Path, spec: AgentRunSpec) -> dict[str, object]:
    return RunBundleWriter(root / "bundle").write(manifest={"runId": spec.run_id}, artifacts={"execution/agent-run-spec.json": spec.to_dict(), "execution/capability-negotiation.json": {}, "identities/state-before.json": {"base": "known"}})


def cockpit(root: Path) -> AgentNativeCockpit:
    return AgentNativeCockpit(OperationalEvidenceStore(root / "evidence.sqlite"), root / "leases", owner="test")


def identity_kwargs() -> dict[str, object]:
    return {
        "repository_identity": {"id": "stateport", "digest": DIGEST},
        "instance_identity": {"id": "instance.cockpit", "digest": DIGEST},
    }


def evidence_attempt_id(run_id: str) -> str:
    return "attempt." + sha256(run_id.encode("utf-8")).hexdigest()


def test_success_closes_with_immutable_receipt_and_journal_binding() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp); canonical, staging, sha = repository(root); items = contracts(sha); service = cockpit(root)
        service.prepare(*items, instance_root=canonical, staging_root=staging, **identity_kwargs())
        service.adopt(items[-1].run_id, items[-1]); service.verify(items[-1].run_id)
        receipt = service.close(items[-1].run_id, run_result=result(items[-1]), run_result_id="result.cockpit", run_bundle=bundle(root, items[-1]))
        attempt = service.evidence_store.get_attempt(evidence_attempt_id(items[-1].run_id))
        assert receipt.to_dict()["closure"]["status"] == "closed"
        assert receipt.to_dict()["usage"] == {"availability": "unavailable", "token": None, "costMinor": None}
        assert attempt["receipt"] == receipt.to_dict() and attempt["journalDigest"] == receipt.to_dict()["journal"]["digest"]


def test_preflight_failure_is_report_and_stop() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp); canonical, staging, sha = repository(root); items = contracts(sha, preflight="import sys; sys.exit(7)"); service = cockpit(root); job = service.prepare(*items, instance_root=canonical, staging_root=staging, **identity_kwargs())
        assert job.report_and_stop and job.report_reason == "preflight_failed" and job.preflight and job.preflight.returncode == 7
        receipt = service.close(items[-1].run_id, run_result=result(items[-1]), run_result_id="result.cockpit", run_bundle=bundle(root, items[-1]))
        assert receipt.to_dict()["verification"]["status"] == "not_run" and not job.lease.acquired


def test_verification_failure_closes_failed_receipt() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp); canonical, staging, sha = repository(root); items = contracts(sha, verify="import sys; sys.exit(8)"); service = cockpit(root)
        service.prepare(*items, instance_root=canonical, staging_root=staging, **identity_kwargs()); service.adopt(items[-1].run_id, items[-1]); job = service.verify(items[-1].run_id)
        assert job.report_and_stop
        receipt = service.close(items[-1].run_id, run_result=result(items[-1]), run_result_id="result.cockpit", run_bundle=bundle(root, items[-1]))
        assert receipt.to_dict()["closure"] == {"status": "failed", "reason": "verification_failed"}


def test_timeout_reaps_process_group() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp); canonical, staging, sha = repository(root); marker = root / "child.pid"
        code = f"import pathlib,subprocess,sys,time; p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); pathlib.Path({str(marker)!r}).write_text(str(p.pid)); time.sleep(30)"
        items = contracts(sha, preflight=code)
        job = cockpit(root).prepare(*items, instance_root=canonical, staging_root=staging, **identity_kwargs())
        assert job.preflight and job.preflight.timed_out and job.report_and_stop
        pid = int(marker.read_text(encoding="utf-8")); time.sleep(0.1)
        with pytest.raises(ProcessLookupError): os.kill(pid, 0)
        job.lease.release()


def test_lease_conflict_and_duplicate_identity_fail_closed() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp); canonical, staging, sha = repository(root); items = contracts(sha); first = cockpit(root); first.prepare(*items, instance_root=canonical, staging_root=staging, **identity_kwargs())
        with pytest.raises(InstanceLeaseBusy): cockpit(root).prepare(*items, instance_root=canonical, staging_root=staging, **identity_kwargs())
        with pytest.raises(CockpitStateError): first.prepare(*items, instance_root=canonical, staging_root=staging, **identity_kwargs())
        first._jobs[items[-1].run_id].lease.release()


def test_base_sha_drift_and_out_of_order_calls_are_rejected() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp); canonical, staging, sha = repository(root); items = contracts(sha); service = cockpit(root); job = service.prepare(*items, instance_root=canonical, staging_root=staging, **identity_kwargs())
        with pytest.raises(CockpitStateError): service.verify(items[-1].run_id)
        (staging / "owned.txt").write_text("drift\n", encoding="utf-8"); git(staging, "add", "owned.txt"); git(staging, "commit", "-qm", "drift")
        rejected = service.adopt(items[-1].run_id, items[-1])
        assert rejected.report_and_stop and rejected.report_reason == "base_sha_drift"
        receipt = service.close(items[-1].run_id, run_result=result(items[-1]), run_result_id="result.cockpit", run_bundle=bundle(root, items[-1]))
        assert receipt.to_dict()["verification"]["status"] == "not_run" and not job.lease.acquired


def test_symlink_escape_and_forbidden_diff_are_reported() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp); canonical, staging, sha = repository(root); outside = root / "outside"; outside.write_text("x", encoding="utf-8")
        items = contracts(sha); service = cockpit(root); service.prepare(*items, instance_root=canonical, staging_root=staging, **identity_kwargs()); service.adopt(items[-1].run_id, items[-1])
        (staging / "escaped").symlink_to(outside); git(staging, "add", "escaped")
        job = service.verify(items[-1].run_id)
        assert job.report_and_stop and job.report_reason == "unsafe_staging_path"
        receipt = service.close(items[-1].run_id, run_result=result(items[-1]), run_result_id="result.cockpit", run_bundle=bundle(root, items[-1]))
        assert receipt.to_dict()["fileChanges"]["allowed"] is False


def test_forbidden_untracked_diff_is_reported_and_never_applied() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp); canonical, staging, sha = repository(root); items = contracts(sha); service = cockpit(root)
        service.prepare(*items, instance_root=canonical, staging_root=staging, **identity_kwargs()); service.adopt(items[-1].run_id, items[-1])
        (staging / "forbidden.txt").write_text("not canonical\n", encoding="utf-8")
        job = service.verify(items[-1].run_id)
        assert job.report_and_stop and job.report_reason == "forbidden_diff"
        receipt = service.close(items[-1].run_id, run_result=result(items[-1]), run_result_id="result.cockpit", run_bundle=bundle(root, items[-1]))
        assert receipt.to_dict()["fileChanges"]["changedPaths"] == ["forbidden.txt"]
        assert not (canonical / "forbidden.txt").exists()


def test_allowed_dirty_diff_is_only_a_reference_to_existing_proposal_boundary() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp); canonical, staging, sha = repository(root); items = contracts(sha); service = cockpit(root)
        service.prepare(*items, instance_root=canonical, staging_root=staging, **identity_kwargs()); service.adopt(items[-1].run_id, items[-1])
        (staging / "owned.txt").write_text("proposal only\n", encoding="utf-8")
        job = service.verify(items[-1].run_id)
        assert job.report_and_stop and job.pending_proposal and job.pending_proposal.to_dict()["changedPaths"] == ["owned.txt"]
        receipt = service.close(items[-1].run_id, run_result=result(items[-1]), run_result_id="result.cockpit", run_bundle=bundle(root, items[-1]))
        assert receipt.to_dict()["closure"]["reason"] == "pending_governed_proposal"
        assert (canonical / "owned.txt").read_text(encoding="utf-8") == "base\n"


def test_cross_contract_mismatch_is_rejected_before_lease() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp); canonical, staging, sha = repository(root); items = list(contracts(sha)); bad = items[-1].to_dict(); bad["statePack"]["reference"] = "context:other"; items[-1] = AgentRunSpec.from_dict(bad)
        with pytest.raises(CockpitError, match="context identity"):
            cockpit(root).prepare(*items, instance_root=canonical, staging_root=staging, **identity_kwargs())


def test_observed_identity_and_disjoint_workspace_are_mandatory() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp); canonical, staging, sha = repository(root); items = contracts(sha)
        wrong = identity_kwargs(); wrong["repository_identity"] = {"id": "other", "digest": DIGEST}
        with pytest.raises(CockpitError, match="observed repository identity"):
            cockpit(root).prepare(*items, instance_root=canonical, staging_root=staging, **wrong)
        nested = canonical / "nested-staging"
        shutil.copytree(staging, nested, symlinks=True)
        with pytest.raises(CockpitError, match="nested"):
            cockpit(root).prepare(*items, instance_root=canonical, staging_root=nested, **identity_kwargs())


def test_preflight_mutation_and_post_verification_drift_fail_closed() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp); canonical, staging, sha = repository(root)
        items = contracts(sha, preflight="from pathlib import Path; Path('owned.txt').write_text('mutated')")
        service = cockpit(root)
        job = service.prepare(*items, instance_root=canonical, staging_root=staging, **identity_kwargs())
        assert job.report_and_stop and job.report_reason == "preflight_mutation"
        receipt = service.close(items[-1].run_id, run_result=result(items[-1]), run_result_id="result.cockpit", run_bundle=bundle(root, items[-1]))
        assert receipt.to_dict()["preflight"]["status"] == "failed"

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp); canonical, staging, sha = repository(root); items = contracts(sha); service = cockpit(root)
        service.prepare(*items, instance_root=canonical, staging_root=staging, **identity_kwargs())
        service.adopt(items[-1].run_id, items[-1]); service.verify(items[-1].run_id)
        (staging / "after-verification.txt").write_text("drift\n", encoding="utf-8")
        receipt = service.close(items[-1].run_id, run_result=result(items[-1]), run_result_id="result.cockpit", run_bundle=bundle(root, items[-1]))
        assert receipt.to_dict()["closure"] == {"status": "failed", "reason": "snapshot_drift_after_verification"}


def test_run_bundle_and_run_result_runtime_identities_are_verified() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp); canonical, staging, sha = repository(root); items = contracts(sha); service = cockpit(root)
        service.prepare(*items, instance_root=canonical, staging_root=staging, **identity_kwargs())
        service.adopt(items[-1].run_id, items[-1]); service.verify(items[-1].run_id)
        bad_result = result(items[-1]); bad_result["toolPolicy"] = {"permittedCapabilities": []}
        with pytest.raises(CockpitError, match="runtime or tool identity"):
            service.close(items[-1].run_id, run_result=bad_result, run_result_id="result.cockpit", run_bundle=bundle(root, items[-1]))
        existing = root / "bundle"
        shutil.rmtree(existing)
        written = bundle(root, items[-1])
        (Path(written["path"]) / "execution" / "agent-run-spec.json").write_text("{}", encoding="utf-8")
        with pytest.raises(CockpitError, match="runBundle verification"):
            service.close(items[-1].run_id, run_result=result(items[-1]), run_result_id="result.cockpit", run_bundle=written)
        service._jobs[items[-1].run_id].lease.release()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
