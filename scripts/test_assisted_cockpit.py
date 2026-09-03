#!/usr/bin/env python3
"""Public-safe conformance tests for the thin assisted cockpit handoff."""
from __future__ import annotations

import copy
import shutil
import tempfile
from pathlib import Path

import pytest

import test_agent_native_cockpit as native

from execution_host.contracts import AgentRunSpec
from governed_runner import AssistedCockpit, AssistedHandoff, CockpitError, CockpitStateError, OperationalEvidenceStore
from runtime_contracts import RuntimeProfile, TaskManifest, WorkflowDeclaration


EXTERNAL_AGENT = {"id": "human.terra", "classification": "human_controlled"}


def assisted_contracts(sha: str, *, preflight: str = "pass", verify: str = "pass"):
    workflow, task, runtime, context, agent, spec = native.contracts(sha, preflight=preflight, verify=verify)
    workflow_data = workflow.to_dict(); workflow_data["execution"] = {"supportedModes": ["agent_native", "assisted"], "defaultMode": "assisted"}
    task_data = task.to_dict(); task_data["requestedMode"] = "assisted"
    runtime_data = runtime.to_dict(); runtime_data["mode"] = "assisted"
    spec_data = spec.to_dict(); spec_data["benchmarkConfiguration"] = {"mode": "assisted"}
    return (
        WorkflowDeclaration.from_dict(workflow_data), TaskManifest.from_dict(task_data), RuntimeProfile.from_dict(runtime_data),
        context, agent, AgentRunSpec.from_dict(spec_data),
    )


def cockpit(root: Path) -> AssistedCockpit:
    return AssistedCockpit(OperationalEvidenceStore(root / "evidence.sqlite"), root / "leases", owner="test-assisted")


def prepare(service: AssistedCockpit, items, canonical: Path, staging: Path):
    return service.prepare(
        *items, instance_root=canonical, staging_root=staging,
        external_agent=EXTERNAL_AGENT, **native.identity_kwargs(),
    )


def adopt(service: AssistedCockpit, items, handoff: AssistedHandoff):
    return service.adopt(items[-1].run_id, items[-1], handoff.to_dict(), external_agent=EXTERNAL_AGENT)


def test_assisted_success_noop_closes_through_the_shared_receipt_path() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp); canonical, staging, sha = native.repository(root); items = assisted_contracts(sha); service = cockpit(root)
        job = prepare(service, items, canonical, staging)
        assert job.assisted_handoff and job.assisted_handoff.runtime_profile.digest == items[2].digest
        assert job.assisted_handoff.workflow.digest == items[0].digest
        assert job.assisted_handoff.task_manifest.digest == items[1].digest
        assert job.assisted_handoff.context_manifest.digest == items[3].digest
        assert job.assisted_handoff.agent_profile.digest == items[4].digest
        adopt(service, items, job.assisted_handoff); service.verify(items[-1].run_id)
        receipt = service.close(items[-1].run_id, run_result=native.result(items[-1]), run_result_id="result.cockpit", run_bundle=native.bundle(root, items[-1]))
        assert receipt.to_dict()["mode"] == "assisted"
        assert receipt.to_dict()["closure"] == {"status": "closed", "reason": "verified_no_canonical_mutation"}
        assert not job.lease.acquired


def test_assisted_rejects_wrong_caller_observed_identity_before_handoff() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp); canonical, staging, sha = native.repository(root); items = assisted_contracts(sha)
        identities = native.identity_kwargs(); identities["instance_identity"] = {"id": "instance.other", "digest": native.DIGEST}
        with pytest.raises(CockpitError, match="observed instance identity"):
            cockpit(root).prepare(
                *items, instance_root=canonical, staging_root=staging,
                external_agent=EXTERNAL_AGENT, **identities,
            )


def test_handoff_has_typed_digest_bound_public_safe_shape() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp); canonical, staging, sha = native.repository(root); items = assisted_contracts(sha); job = prepare(cockpit(root), items, canonical, staging)
        assert job.assisted_handoff
        payload = job.assisted_handoff.to_dict()
        assert set(payload) == {
            "formatVersion", "runId", "workflowDeclaration", "workflowDeclarationDigest",
            "taskManifest", "taskManifestDigest", "contextManifest", "contextManifestDigest",
            "agentProfile", "agentProfileDigest", "agentRunSpec", "agentRunSpecDigest",
            "runtimeProfile", "runtimeProfileDigest", "externalAgent", "digest",
        }
        assert AssistedHandoff.from_dict(payload).to_dict() == payload
        forbidden_top_level = {"providerSessionId", "chatHistory", "prompt", "auth", "workspacePath"}
        assert forbidden_top_level.isdisjoint(payload)
        assert set(payload["externalAgent"]) == {"id", "classification"}
        with pytest.raises(TypeError):
            job.assisted_handoff.external_agent["id"] = "human.mutated"  # type: ignore[index]


@pytest.mark.parametrize("field", [
    "workflowDeclarationDigest", "taskManifestDigest", "contextManifestDigest",
    "agentProfileDigest", "agentRunSpecDigest", "runtimeProfileDigest",
])
def test_assisted_handoff_rejects_any_prepared_contract_digest_drift(field: str) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp); canonical, staging, sha = native.repository(root); items = assisted_contracts(sha); job = prepare(cockpit(root), items, canonical, staging)
        assert job.assisted_handoff
        payload = job.assisted_handoff.to_dict(); payload[field] = "sha256:" + "0" * 64
        with pytest.raises(CockpitError, match="digest"):
            AssistedHandoff.from_dict(payload)


@pytest.mark.parametrize("field,value", [
    ("providerSessionId", "provider-session"), ("chatHistory", []), ("auth", "credential-material"),
])
def test_assisted_handoff_rejects_hidden_provider_session_chat_and_auth_fields(field: str, value: object) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp); canonical, staging, sha = native.repository(root); items = assisted_contracts(sha); job = prepare(cockpit(root), items, canonical, staging)
        assert job.assisted_handoff
        payload = job.assisted_handoff.to_dict(); payload[field] = value
        with pytest.raises(CockpitError, match="unknown, hidden"):
            AssistedHandoff.from_dict(payload)


def test_assisted_adoption_binds_exact_spec_handoff_and_human_identity_once() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp); canonical, staging, sha = native.repository(root); items = assisted_contracts(sha); service = cockpit(root); job = prepare(service, items, canonical, staging)
        assert job.assisted_handoff
        bad_digest = job.assisted_handoff.to_dict(); bad_digest["digest"] = "sha256:" + "0" * 64
        with pytest.raises(CockpitError, match="digest"):
            service.adopt(items[-1].run_id, items[-1], bad_digest, external_agent=EXTERNAL_AGENT)
        with pytest.raises(CockpitError, match="exact prepared"):
            service.adopt(items[-1].run_id, items[-1], job.assisted_handoff, external_agent={"id": "human.other", "classification": "human_controlled"})
        adopt(service, items, job.assisted_handoff)
        with pytest.raises(CockpitStateError):
            adopt(service, items, job.assisted_handoff)
        job.lease.release()


def test_assisted_preflight_and_verification_failures_match_agent_native_report_and_stop() -> None:
    for failing_gate, expected in (("preflight", "preflight_failed"), ("verify", "verification_failed")):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); canonical, staging, sha = native.repository(root)
            items = assisted_contracts(sha, **{failing_gate: "import sys; sys.exit(9)"}); service = cockpit(root); job = prepare(service, items, canonical, staging)
            if failing_gate == "verify":
                assert job.assisted_handoff; adopt(service, items, job.assisted_handoff); service.verify(items[-1].run_id)
            else:
                assert job.assisted_handoff is None
            assert job.report_and_stop and job.report_reason == expected
            receipt = service.close(items[-1].run_id, run_result=native.result(items[-1]), run_result_id="result.cockpit", run_bundle=native.bundle(root, items[-1]))
            assert receipt.to_dict()["closure"] == {"status": "failed", "reason": expected}


def test_assisted_snapshot_drift_and_runbundle_tampering_fail_through_shared_checks() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp); canonical, staging, sha = native.repository(root); items = assisted_contracts(sha); service = cockpit(root); job = prepare(service, items, canonical, staging)
        assert job.assisted_handoff; adopt(service, items, job.assisted_handoff); service.verify(items[-1].run_id)
        (staging / "after-verification.txt").write_text("drift\n", encoding="utf-8")
        receipt = service.close(items[-1].run_id, run_result=native.result(items[-1]), run_result_id="result.cockpit", run_bundle=native.bundle(root, items[-1]))
        assert receipt.to_dict()["closure"] == {"status": "failed", "reason": "snapshot_drift_after_verification"}

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp); canonical, staging, sha = native.repository(root); items = assisted_contracts(sha); service = cockpit(root); job = prepare(service, items, canonical, staging)
        assert job.assisted_handoff; adopt(service, items, job.assisted_handoff); service.verify(items[-1].run_id)
        written = native.bundle(root, items[-1]); (Path(written["path"]) / "execution" / "agent-run-spec.json").write_text("{}", encoding="utf-8")
        with pytest.raises(CockpitError, match="runBundle verification"):
            service.close(items[-1].run_id, run_result=native.result(items[-1]), run_result_id="result.cockpit", run_bundle=written)
        job.lease.release()


def _normalise_mode_bound_receipt(receipt: dict[str, object]) -> dict[str, object]:
    """Remove only identities whose digest is necessarily mode/handoff-bound."""
    normalized = copy.deepcopy(receipt)
    normalized["mode"] = "mode-normalized"
    runtime = normalized["runtimeIdentity"]
    assert isinstance(runtime, dict)
    runtime["harness"]["classification"] = "mode-normalized"  # type: ignore[index]
    runtime["adapter"]["classification"] = "mode-normalized"  # type: ignore[index]
    digests = normalized["digests"]
    assert isinstance(digests, dict)
    for key in ("workflowDeclaration", "taskManifest", "runtimeProfile", "agentRunSpec", "eventJournal"):
        digests[key] = "mode-normalized"
    references = normalized["references"]
    assert isinstance(references, dict)
    references["runResult"] = {"id": "mode-normalized", "digest": "mode-normalized"}
    references["runBundle"] = {"id": "mode-normalized", "digest": "mode-normalized"}
    journal = normalized["journal"]
    assert isinstance(journal, dict)
    journal["digest"] = "mode-normalized"
    journal["eventCount"] = 0
    return normalized


def test_assisted_receipt_has_agent_native_logical_parity_for_same_fixture() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp); canonical, staging, sha = native.repository(root)
        native_items = native.contracts(sha); native_service = native.cockpit(root / "native")
        native_job = native_service.prepare(*native_items, instance_root=canonical, staging_root=staging, **native.identity_kwargs())
        native_service.adopt(native_items[-1].run_id, native_items[-1]); native_service.verify(native_items[-1].run_id)
        native_receipt = native_service.close(native_items[-1].run_id, run_result=native.result(native_items[-1]), run_result_id="result.cockpit", run_bundle=native.bundle(root / "native", native_items[-1])).to_dict()

        assisted_canonical, assisted_staging = root / "assisted-canonical", root / "assisted-staging"
        shutil.copytree(canonical, assisted_canonical, symlinks=True)
        shutil.copytree(staging, assisted_staging, symlinks=True)
        assisted_sha = native.git(assisted_canonical, "rev-parse", "HEAD")
        assisted_items = assisted_contracts(assisted_sha); assisted_service = cockpit(root / "assisted-service")
        assisted_job = prepare(assisted_service, assisted_items, assisted_canonical, assisted_staging)
        assert assisted_job.assisted_handoff; adopt(assisted_service, assisted_items, assisted_job.assisted_handoff); assisted_service.verify(assisted_items[-1].run_id)
        assisted_receipt = assisted_service.close(assisted_items[-1].run_id, run_result=native.result(assisted_items[-1]), run_result_id="result.cockpit", run_bundle=native.bundle(root / "assisted-service", assisted_items[-1])).to_dict()
        assert _normalise_mode_bound_receipt(assisted_receipt) == _normalise_mode_bound_receipt(native_receipt)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
