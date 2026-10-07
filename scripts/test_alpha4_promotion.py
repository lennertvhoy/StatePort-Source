#!/usr/bin/env python3
"""Focused tests for the StatePort-authoritative promotion transaction.

Promotion is a control-plane decision owned by StatePort.  These tests prove
the required path:

    validator evidence -> candidate diff -> base revision check -> approval
    gate -> promote only if base revision still matches -> durable promotion
    receipt -> rollback point preserved -> rejected candidate does not alter
    workspace state.

    The execution host, agent provider, and validator never promote.  The public
    physical mutation surface reads StatePort-owned approval/evidence stores and
    computes the revision and diff itself; caller-constructed observations are
    used only by the non-mutating low-level refusal tests.
"""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import re
import subprocess
import sys
import threading

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "runtime-contracts" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "execution-host" / "src"))

from execution_host.promotion import (  # noqa: E402
    PromotionError,
    PromotionObservations,
    PromotionService,
)
from execution_host.workspace_revisions import WorkspaceRevisionTracker  # noqa: E402
from runtime_contracts import PromotionReceipt, PromotionSpec, canonical_digest  # noqa: E402

BASE_SHA = "a" * 40
CAND_SHA = "b" * 40
ALT_SHA = "c" * 40
DIFF_DIGEST = "sha256:" + "a" * 64
EVIDENCE_DIGEST = "sha256:" + "e" * 64
OTHER_DIGEST = "sha256:" + "f" * 64
UNRECORDED_DIGEST = "sha256:" + "0" * 64

_SECRET = re.compile(
    r"(?:api[_-]?key|authorization|cookie|credential|password|secret|"
    r"access[_-]?token|refresh[_-]?token|private[_-]?key)",
    re.I,
)


def promotion_spec(**overrides) -> dict[str, object]:
    value: dict[str, object] = {
        "formatVersion": "stateport.promotion-spec/v1",
        "promotionId": "promotion.demo",
        "workspaceId": "workspace.demo",
        "candidateId": "candidate.demo",
        "expectedBaseRevision": BASE_SHA,
        "candidateRevision": CAND_SHA,
        "diffDigest": DIFF_DIGEST,
        "validatorEvidenceDigest": EVIDENCE_DIGEST,
        "approvalId": "approval.demo",
        "rollbackPointDigest": UNRECORDED_DIGEST,
    }
    value.update(overrides)
    return value


def observations(*specs, **overrides) -> PromotionObservations:
    spec = specs[0] if specs else promotion_spec()
    spec_digest = PromotionSpec.from_dict(spec).digest
    base = PromotionObservations(
        current_revision=BASE_SHA,
        diff_digest=DIFF_DIGEST,
        validator_evidence_digest=EVIDENCE_DIGEST,
        validator_id="validator.demo",
        validator_status="passed",
        approval_id="approval.demo",
        approval_status="approved",
        approval_actor="operator.alice",
        approval_bound_candidate_id="candidate.demo",
        approval_bound_spec_digest=spec_digest,
    )
    return replace(base, **overrides)


def _service(tmp_path: Path) -> PromotionService:
    return PromotionService(tmp_path / "state")


def _record_rollback(service: PromotionService, revision: str = BASE_SHA) -> str:
    record = service.record_rollback_point(
        workspace_id="workspace.demo",
        pre_promotion_revision=revision,
        observed_at="2026-01-01T00:00:00Z",
    )
    return record["rollbackPointDigest"]


def test_promotion_without_physical_transition_is_refused(tmp_path: Path):
    service = _service(tmp_path)
    digest = _record_rollback(service)
    spec = promotion_spec(rollbackPointDigest=digest)
    receipt = service.promote(spec, observations=observations(spec, ), observed_at="2026-01-01T00:00:01Z")
    assert receipt["promotionDecision"]["decision"] == "refused"
    assert receipt["promotionDecision"]["reason"] == "physical_transition_required"
    assert all(receipt["promotionDecision"]["checks"].values())
    assert receipt["expectedBaseRevision"] == BASE_SHA
    assert service.verify_receipt_digest(receipt) is True
    assert service.is_promoted("promotion.demo") is False


def test_promotion_refuses_on_stale_base_revision(tmp_path: Path):
    service = _service(tmp_path)
    # The workspace advanced past the candidate's declared base revision.
    digest = _record_rollback(service, revision=ALT_SHA)
    spec = promotion_spec(expectedBaseRevision=BASE_SHA, rollbackPointDigest=digest)
    receipt = service.promote(
        spec,
        observations=observations(spec, current_revision=ALT_SHA),
        observed_at="2026-01-01T00:00:01Z",
    )
    assert receipt["promotionDecision"]["decision"] == "refused"
    assert receipt["promotionDecision"]["checks"]["baseRevision"] is False
    assert "baseRevision" in receipt["promotionDecision"]["reason"]
    assert service.is_promoted("promotion.demo") is False


def test_promotion_refuses_on_missing_approval(tmp_path: Path):
    service = _service(tmp_path)
    digest = _record_rollback(service)
    spec = promotion_spec(rollbackPointDigest=digest)
    receipt = service.promote(
        spec,
        observations=observations(spec, approval_status="pending"),
        observed_at="2026-01-01T00:00:01Z",
    )
    assert receipt["promotionDecision"]["decision"] == "refused"
    assert receipt["promotionDecision"]["checks"]["approval"] is False
    assert receipt["approval"]["approvalMatched"] is False
    assert receipt["approval"]["status"] == "pending"


def test_promotion_refuses_on_approval_bound_to_a_different_candidate(tmp_path: Path):
    service = _service(tmp_path)
    digest = _record_rollback(service)
    spec = promotion_spec(rollbackPointDigest=digest)
    receipt = service.promote(
        spec,
        observations=observations(spec, approval_bound_candidate_id="candidate.other"),
        observed_at="2026-01-01T00:00:01Z",
    )
    assert receipt["promotionDecision"]["decision"] == "refused"
    assert receipt["promotionDecision"]["checks"]["approval"] is False
    assert receipt["approval"]["boundCandidateId"] == "candidate.other"


def test_promotion_refuses_on_mismatched_diff_digest(tmp_path: Path):
    service = _service(tmp_path)
    digest = _record_rollback(service)
    spec = promotion_spec(rollbackPointDigest=digest)
    receipt = service.promote(
        spec,
        observations=observations(spec, diff_digest=OTHER_DIGEST),
        observed_at="2026-01-01T00:00:01Z",
    )
    assert receipt["promotionDecision"]["decision"] == "refused"
    assert receipt["promotionDecision"]["checks"]["diffDigest"] is False
    assert receipt["observedProcessResult"]["diffDigest"] == OTHER_DIGEST


def test_promotion_refuses_on_mismatched_validator_evidence_digest(tmp_path: Path):
    service = _service(tmp_path)
    digest = _record_rollback(service)
    spec = promotion_spec(rollbackPointDigest=digest)
    receipt = service.promote(
        spec,
        observations=observations(spec, validator_evidence_digest=OTHER_DIGEST),
        observed_at="2026-01-01T00:00:01Z",
    )
    assert receipt["promotionDecision"]["decision"] == "refused"
    assert receipt["promotionDecision"]["checks"]["validatorEvidence"] is False
    assert receipt["validatorEvidence"]["evidenceMatched"] is False


def test_promotion_refuses_on_missing_rollback_point(tmp_path: Path):
    service = _service(tmp_path)
    spec = promotion_spec(rollbackPointDigest=UNRECORDED_DIGEST)
    receipt = service.promote(spec, observations=observations(spec, ), observed_at="2026-01-01T00:00:01Z")
    assert receipt["promotionDecision"]["decision"] == "refused"
    assert receipt["promotionDecision"]["checks"]["rollbackPoint"] is False
    assert receipt["rollbackPoint"]["rollbackPointMatched"] is False
    assert receipt["rollbackPoint"]["prePromotionRevision"] is None
    assert service.verify_rollback_point(UNRECORDED_DIGEST) is None


def test_rejected_promotion_does_not_mutate_workspace_state(tmp_path: Path):
    service = _service(tmp_path)
    digest = _record_rollback(service)
    spec = promotion_spec(rollbackPointDigest=digest)

    refused = service.promote(
        spec,
        observations=observations(spec, diff_digest=OTHER_DIGEST),
        observed_at="2026-01-01T00:00:01Z",
    )
    assert refused["promotionDecision"]["decision"] == "refused"

    # The persistent workspace is untouched: the rollback point is intact and
    # still names the same pre-promotion revision, the refusal is the only
    # receipt recorded, and no promotion is recorded for this candidate.
    rollback = service.verify_rollback_point(digest)
    assert rollback is not None
    assert rollback["prePromotionRevision"] == BASE_SHA
    assert service.is_promoted("promotion.demo") is False
    receipts = list((tmp_path / "state" / "promotions").glob("*.json"))
    assert len(receipts) == 1
    reloaded = service.load_receipt("promotion.demo")
    assert reloaded["promotionDecision"]["decision"] == "refused"


def test_receipt_is_durable_and_reloadable(tmp_path: Path):
    service = _service(tmp_path)
    digest = _record_rollback(service)
    spec = promotion_spec(rollbackPointDigest=digest)
    receipt = service.promote(spec, observations=observations(spec, ), observed_at="2026-01-01T00:00:01Z")
    path = tmp_path / "state" / "promotions" / "promotion.demo.json"
    assert path.is_file()
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    assert on_disk == receipt
    reloaded = service.load_receipt("promotion.demo")
    assert reloaded == receipt
    assert service.verify_receipt_digest(reloaded) is True


def test_receipt_replay_is_idempotent(tmp_path: Path):
    service = _service(tmp_path)
    digest = _record_rollback(service)
    spec = promotion_spec(rollbackPointDigest=digest)
    first = service.promote(spec, observations=observations(spec, ), observed_at="2026-01-01T00:00:01Z")
    # The observations no longer match the spec on the second call, but the
    # exact same approved request replays the stored receipt without re-running
    # the checks or mutating state again.
    second = service.promote(
        spec,
        observations=observations(spec, diff_digest=OTHER_DIGEST),
        observed_at="2099-12-31T00:00:00Z",
    )
    assert second == first
    assert second["observedAt"] == "2026-01-01T00:00:01Z"
    assert second["promotionDecision"]["checks"]["diffDigest"] is True
    assert len(list((tmp_path / "state" / "promotions").glob("*.json"))) == 1


def test_receipt_replay_with_different_digest_refuses(tmp_path: Path):
    service = _service(tmp_path)
    digest = _record_rollback(service)
    spec = promotion_spec(rollbackPointDigest=digest)
    service.promote(spec, observations=observations(spec, ), observed_at="2026-01-01T00:00:01Z")
    conflicting = promotion_spec(diffDigest=OTHER_DIGEST)
    assert conflicting["promotionId"] == spec["promotionId"]
    assert PromotionSpec.from_dict(conflicting).digest != PromotionSpec.from_dict(spec).digest
    with pytest.raises(PromotionError, match="different promotion spec"):
        service.promote(conflicting, observations=observations(conflicting))


def test_refused_promotion_is_also_durable_and_idempotent(tmp_path: Path):
    service = _service(tmp_path)
    digest = _record_rollback(service)
    spec = promotion_spec(rollbackPointDigest=digest)
    first = service.promote(
        spec,
        observations=observations(spec, diff_digest=OTHER_DIGEST),
        observed_at="2026-01-01T00:00:01Z",
    )
    assert first["promotionDecision"]["decision"] == "refused"
    second = service.promote(spec, observations=observations(spec, ), observed_at="2099-12-31T00:00:00Z")
    assert second == first
    assert second["promotionDecision"]["decision"] == "refused"


def test_receipt_contains_all_required_distinguishable_fields(tmp_path: Path):
    service = _service(tmp_path)
    digest = _record_rollback(service)
    spec = promotion_spec(rollbackPointDigest=digest)
    receipt = service.promote(spec, observations=observations(spec, ), observed_at="2026-01-01T00:00:01Z")
    required_flat = {
        "formatVersion", "promotionId", "workspaceId", "candidateId",
        "expectedBaseRevision", "candidateRevision", "diffDigest",
        "validatorEvidenceDigest", "approvalId", "rollbackPointDigest",
        "promotionDecision", "observedAt", "receiptDigest",
    }
    assert required_flat.issubset(receipt)
    for section in (
        "agentClaim", "observedProcessResult", "validatorEvidence",
        "approval", "rollbackPoint", "promotionDecision",
    ):
        assert isinstance(receipt[section], dict)

    # The six categories are distinct, not collapsed into a success flag.
    assert receipt["agentClaim"]["baseRevision"] == BASE_SHA
    assert receipt["observedProcessResult"]["currentRevision"] == BASE_SHA
    assert receipt["observedProcessResult"]["baseRevisionMatched"] is True
    assert receipt["validatorEvidence"]["evidenceDigest"] == EVIDENCE_DIGEST
    assert receipt["validatorEvidence"]["validatorId"] == "validator.demo"
    assert receipt["approval"]["actor"] == "operator.alice"
    assert receipt["approval"]["boundCandidateId"] == "candidate.demo"
    assert receipt["rollbackPoint"]["prePromotionRevision"] == BASE_SHA
    assert receipt["promotionDecision"]["decision"] == "refused"
    assert receipt["promotionDecision"]["checks"] == {
        "baseRevision": True, "approval": True, "diffDigest": True,
        "validatorEvidence": True, "rollbackPoint": True,
    }
    assert receipt["formatVersion"] == PromotionReceipt.FORMAT


def test_rollback_point_is_recorded_and_verifiable(tmp_path: Path):
    service = _service(tmp_path)
    record = service.record_rollback_point(
        workspace_id="workspace.demo",
        pre_promotion_revision=BASE_SHA,
        observed_at="2026-01-01T00:00:00Z",
    )
    verified = service.verify_rollback_point(record["rollbackPointDigest"])
    assert verified is not None
    assert verified["prePromotionRevision"] == BASE_SHA
    assert verified["workspaceId"] == "workspace.demo"
    assert verified["rollbackPointDigest"] == record["rollbackPointDigest"]
    assert service.verify_rollback_point(UNRECORDED_DIGEST) is None
    # Recording the same point twice is content-addressed and stable.
    again = service.record_rollback_point(
        workspace_id="workspace.demo",
        pre_promotion_revision=BASE_SHA,
        observed_at="2099-01-01T00:00:00Z",
    )
    assert again["rollbackPointDigest"] == record["rollbackPointDigest"]


def test_no_secrets_appear_in_receipts(tmp_path: Path):
    service = _service(tmp_path)
    digest = _record_rollback(service)
    spec = promotion_spec(rollbackPointDigest=digest)
    receipt = service.promote(spec, observations=observations(spec, ), observed_at="2026-01-01T00:00:01Z")

    def has_secret_key(node) -> bool:
        if isinstance(node, dict):
            for key, value in node.items():
                if _SECRET.search(str(key)):
                    return True
                if has_secret_key(value):
                    return True
        elif isinstance(node, list):
            return any(has_secret_key(item) for item in node)
        return False

    assert has_secret_key(receipt) is False
    # PromotionReceipt.from_dict runs _no_secrets on reload, so a receipt with a
    # credential-like field could never be reloaded.
    assert service.load_receipt("promotion.demo") is not None


def test_promotion_receipt_contract_round_trips_and_rejects_inconsistent(tmp_path: Path):
    service = _service(tmp_path)
    digest = _record_rollback(service)
    spec = promotion_spec(rollbackPointDigest=digest)
    receipt = service.promote(spec, observations=observations(spec, ), observed_at="2026-01-01T00:00:01Z")
    assert PromotionReceipt.from_dict(receipt).to_dict() == receipt

    # A promoted receipt that secretly carries a failed check is rejected by the
    # contract -- the categories cannot lie about the decision.
    tampered = json.loads(json.dumps(receipt))
    tampered["promotionDecision"]["decision"] = "promoted"
    tampered["promotionDecision"]["reason"] = "all_bindings_matched"
    tampered["promotionDecision"]["checks"]["diffDigest"] = False
    with pytest.raises(ValueError, match="promoted receipt requires every binding check"):
        PromotionReceipt.from_dict(tampered)

    # A promoted receipt claiming an unapproved approval is rejected.
    unapproved = json.loads(json.dumps(receipt))
    unapproved["approval"]["status"] = "pending"
    unapproved["approval"]["approvalMatched"] = False
    unapproved["promotionDecision"]["checks"]["approval"] = False
    unapproved["promotionDecision"]["decision"] = "refused"
    unapproved["promotionDecision"]["reason"] = "bindings_failed:approval"
    assert PromotionReceipt.from_dict(unapproved).to_dict()["promotionDecision"]["decision"] == "refused"


# ---------------------------------------------------------------------------
# Optional physical workspace transition (promote_with_transition).
#
# These tests prove the real git path with real repositories and revisions.
# The default promote() behavior exercised above is unchanged.
# ---------------------------------------------------------------------------


def _git(path: Path, *argv: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(path), *argv],
        capture_output=True,
        text=True,
        check=True,
    )


def _git_head(path: Path) -> str:
    return _git(path, "rev-parse", "HEAD").stdout.strip()


def _init_git_repo(path: Path) -> str:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", str(path)], capture_output=True, text=True, check=True)
    _git(path, "config", "user.email", "test@example.invalid")
    _git(path, "config", "user.name", "StatePort Test")
    (path / "README.md").write_text("base\n", encoding="utf-8")
    _git(path, "add", ".")
    _git(path, "commit", "-m", "base")
    return _git_head(path)


def _git_commit(path: Path, content: str, message: str) -> str:
    (path / "README.md").write_text(content, encoding="utf-8")
    _git(path, "add", ".")
    _git(path, "commit", "-m", message)
    return _git_head(path)


def _real_workspace(tmp_path: Path) -> tuple[Path, str, str]:
    """Create a real workspace repo at its base commit and a descendant candidate.

    Returns ``(repo_path, base_sha, candidate_sha)`` with HEAD reset to base.
    """

    workspace_root = tmp_path / "ws"
    workspace_root.mkdir(parents=True, exist_ok=True)
    repo = workspace_root / "demo"
    base = _init_git_repo(repo)
    candidate = _git_commit(repo, "candidate\n", "candidate")
    _git(repo, "reset", "--hard", base)
    assert _git_head(repo) == base
    return repo, base, candidate


def _real_spec(
    base: str,
    candidate: str,
    rollback_digest: str,
    promotion_id: str = "promotion.demo",
) -> dict[str, object]:
    spec = promotion_spec(
        promotionId=promotion_id,
        expectedBaseRevision=base,
        candidateRevision=candidate,
        rollbackPointDigest=rollback_digest,
    )
    return spec


def _record_real_rollback(service: PromotionService, base: str) -> str:
    return service.record_rollback_point(
        workspace_id="workspace.demo",
        pre_promotion_revision=base,
        observed_at="2026-01-01T00:00:00Z",
    )["rollbackPointDigest"]


def _has_secret(node) -> bool:
    if isinstance(node, dict):
        for key, value in node.items():
            if _SECRET.search(str(key)) or _has_secret(value):
                return True
    elif isinstance(node, list):
        return any(_has_secret(item) for item in node)
    elif isinstance(node, str):
        return _SECRET.search(node) is not None
    return False


def _authoritative_inputs(
    spec: dict[str, object],
    *,
    load_approval=None,
    load_validator_evidence=None,
    compute_diff_digest=None,
) -> dict[str, object]:
    if load_approval is None:
        approval = {
            "approvalId": spec["approvalId"],
            "status": "approved",
            "actor": "operator.alice",
            "boundCandidateId": spec["candidateId"],
            "boundSpecDigest": PromotionSpec.from_dict(spec).digest,
        }
        load_approval = lambda approval_id: (
            dict(approval) if approval_id == spec["approvalId"] else None
        )
    if load_validator_evidence is None:
        evidence = {
            "evidenceDigest": spec["validatorEvidenceDigest"],
            "validatorId": "validator.demo",
            "classification": "passed",
        }
        load_validator_evidence = lambda digest: (
            dict(evidence) if digest == spec["validatorEvidenceDigest"] else None
        )
    if compute_diff_digest is None:
        compute_diff_digest = lambda _base, _candidate: spec["diffDigest"]
    return {
        "load_approval": load_approval,
        "load_validator_evidence": load_validator_evidence,
        "compute_diff_digest": compute_diff_digest,
    }


def _record_bound_intent(
    service: PromotionService,
    spec: dict[str, object],
    repo: Path,
    tracker: WorkspaceRevisionTracker,
) -> dict[str, object]:
    promotion = PromotionSpec.from_dict(spec)
    spec_data = promotion.to_dict()
    identity = tracker.workspace_identity(repo)
    authority = _authoritative_inputs(spec)
    snapshot = service._snapshot(  # noqa: SLF001
        spec_data,
        spec_digest=promotion.digest,
        observe_revision=lambda: tracker.observe_revision(
            repo, expected_identity=identity
        ),
        **authority,
    )
    intent = service._intent_record(  # noqa: SLF001
        spec_data,
        promotion.digest,
        snapshot,
        identity,
        "2026-01-01T00:00:01Z",
    )
    return service._record_intent(spec_data["promotionId"], intent)  # noqa: SLF001


def test_physical_promotion_advances_workspace_and_records_transition(tmp_path: Path):
    repo, base, candidate = _real_workspace(tmp_path)
    service = _service(tmp_path)
    rollback_digest = _record_real_rollback(service, base)
    tracker = WorkspaceRevisionTracker(
        tmp_path / "state",
        workspace_root=tmp_path / "ws",
        staging_root=tmp_path / "staging",
    )
    spec = _real_spec(base, candidate, rollback_digest)
    receipt = service.promote_with_transition(
        spec,
        **_authoritative_inputs(spec),
        workspace_path=repo,
        revision_tracker=tracker,
        observed_at="2026-01-01T00:00:01Z",
    )

    assert receipt["promotionDecision"]["decision"] == "promoted"
    assert receipt["observedProcessResult"]["currentRevision"] == base
    assert receipt["rollbackPoint"]["prePromotionRevision"] == base
    assert receipt["expectedBaseRevision"] == base
    assert receipt["candidateRevision"] == candidate
    assert _git_head(repo) == candidate

    transitions = tracker.load_transitions("workspace.demo")
    assert len(transitions) == 1
    assert transitions[0]["status"] == "succeeded"
    assert transitions[0]["prePromotionRevision"] == base
    assert transitions[0]["postPromotionRevision"] == candidate
    assert transitions[0]["promotionId"] == "promotion.demo"


def test_physical_promotion_failure_leaves_workspace_unchanged(tmp_path: Path):
    repo, base, _candidate = _real_workspace(tmp_path)
    service = _service(tmp_path)
    rollback_digest = _record_real_rollback(service, base)
    tracker = WorkspaceRevisionTracker(
        tmp_path / "state",
        workspace_root=tmp_path / "ws",
        staging_root=tmp_path / "staging",
    )
    bogus_candidate = "d" * 40
    spec = _real_spec(base, bogus_candidate, rollback_digest)
    with pytest.raises(PromotionError):
        service.promote_with_transition(
            spec,
            **_authoritative_inputs(spec),
            workspace_path=repo,
            revision_tracker=tracker,
            observed_at="2026-01-01T00:00:01Z",
        )

    assert _git_head(repo) == base
    transitions = tracker.load_transitions("workspace.demo")
    assert len(transitions) == 1
    assert transitions[0]["status"] == "failed"
    assert transitions[0]["prePromotionRevision"] == base
    assert transitions[0]["postPromotionRevision"] == base
    assert "git_transition_failed" in transitions[0]["reason"]
    receipt = service.load_receipt("promotion.demo")
    assert receipt is not None
    assert receipt["promotionDecision"]["decision"] == "refused"
    assert service.is_promoted("promotion.demo") is False
    assert service.verify_rollback_point(rollback_digest)["prePromotionRevision"] == base


def test_interrupted_physical_transition_is_recorded_and_not_promoted(tmp_path: Path, monkeypatch):
    repo, base, candidate = _real_workspace(tmp_path)
    service = _service(tmp_path)
    rollback_digest = _record_real_rollback(service, base)
    tracker = WorkspaceRevisionTracker(
        tmp_path / "state",
        workspace_root=tmp_path / "ws",
        staging_root=tmp_path / "staging",
    )
    spec = _real_spec(base, candidate, rollback_digest, promotion_id="promotion.interrupted")
    monkeypatch.setattr(
        service,
        "_run_git_transition",
        lambda _path, _candidate, **_kwargs: ("interrupted", "test interruption"),
    )

    with pytest.raises(PromotionError, match="requires recovery"):
        service.promote_with_transition(
            spec,
            **_authoritative_inputs(spec),
            workspace_path=repo,
            revision_tracker=tracker,
            observed_at="2026-01-01T00:00:01Z",
        )

    transition = tracker.load_transitions("workspace.demo")[0]
    assert transition["status"] == "interrupted"
    receipt = service.load_receipt("promotion.interrupted")
    assert receipt is None
    assert service.is_promoted("promotion.interrupted") is False
    assert service.verify_rollback_point(rollback_digest)["prePromotionRevision"] == base


def test_physical_promotion_receipt_binds_pre_promotion_revision(tmp_path: Path):
    repo, base, candidate = _real_workspace(tmp_path)
    service = _service(tmp_path)
    rollback_digest = _record_real_rollback(service, base)
    tracker = WorkspaceRevisionTracker(
        tmp_path / "state",
        workspace_root=tmp_path / "ws",
        staging_root=tmp_path / "staging",
    )
    spec = _real_spec(base, candidate, rollback_digest)
    receipt = service.promote_with_transition(
        spec,
        **_authoritative_inputs(spec),
        workspace_path=repo,
        revision_tracker=tracker,
        observed_at="2026-01-01T00:00:01Z",
    )

    assert receipt["promotionDecision"]["decision"] == "promoted"
    assert receipt["rollbackPoint"]["prePromotionRevision"] == base
    assert receipt["observedProcessResult"]["currentRevision"] == base
    transition = tracker.load_transitions("workspace.demo")[0]
    assert transition["prePromotionRevision"] == base == receipt["rollbackPoint"]["prePromotionRevision"]


def test_physical_promotion_refused_decision_records_no_transition(tmp_path: Path):
    repo, base, _candidate = _real_workspace(tmp_path)
    service = _service(tmp_path)
    rollback_digest = _record_real_rollback(service, base)
    tracker = WorkspaceRevisionTracker(
        tmp_path / "state",
        workspace_root=tmp_path / "ws",
        staging_root=tmp_path / "staging",
    )
    spec = _real_spec(base, _candidate, rollback_digest)
    refused = service.promote_with_transition(
        spec,
        **_authoritative_inputs(
            spec, compute_diff_digest=lambda _base, _candidate: OTHER_DIGEST
        ),
        workspace_path=repo,
        revision_tracker=tracker,
        observed_at="2026-01-01T00:00:01Z",
    )
    assert refused["promotionDecision"]["decision"] == "refused"
    assert tracker.load_transitions("workspace.demo") == []
    assert _git_head(repo) == base


def test_concurrent_promotion_on_same_workspace_refuses_second(tmp_path: Path):
    repo, base, candidate = _real_workspace(tmp_path)
    service = _service(tmp_path)
    rollback_digest = _record_real_rollback(service, base)
    gate = threading.Event()
    entered = threading.Event()

    class BlockingTracker(WorkspaceRevisionTracker):
        def observe_revision(self, workspace_path, *, expected_identity=None):
            if not entered.is_set():
                entered.set()
                assert gate.wait(timeout=5)
            return super().observe_revision(
                workspace_path, expected_identity=expected_identity
            )

    tracker = BlockingTracker(
        tmp_path / "state",
        workspace_root=tmp_path / "ws",
        staging_root=tmp_path / "staging",
    )
    spec = _real_spec(base, candidate, rollback_digest)
    first_errors: list[BaseException] = []

    def run_first() -> None:
        try:
                service.promote_with_transition(
                    spec,
                    **_authoritative_inputs(spec),
                    workspace_path=repo,
                    revision_tracker=tracker,
                observed_at="2026-01-01T00:00:01Z",
            )
        except BaseException as exc:
            first_errors.append(exc)

    first = threading.Thread(target=run_first)
    first.start()
    assert entered.wait(timeout=5)

    second_errors: list[BaseException] = []

    def run_second() -> None:
        try:
                service.promote_with_transition(
                    spec,
                    **_authoritative_inputs(spec),
                    workspace_path=repo,
                    revision_tracker=tracker,
                observed_at="2026-01-01T00:00:02Z",
            )
        except BaseException as exc:
            second_errors.append(exc)

    second = threading.Thread(target=run_second)
    second.start()
    second.join(timeout=5)
    gate.set()
    first.join(timeout=5)

    assert len(second_errors) == 1
    assert isinstance(second_errors[0], PromotionError)
    assert "promotion_in_progress" in str(second_errors[0])
    assert first_errors == []
    assert _git_head(repo) == candidate


def test_no_secrets_in_physical_promotion_records(tmp_path: Path):
    repo, base, candidate = _real_workspace(tmp_path)
    service = _service(tmp_path)
    rollback_digest = _record_real_rollback(service, base)
    tracker = WorkspaceRevisionTracker(
        tmp_path / "state",
        workspace_root=tmp_path / "ws",
        staging_root=tmp_path / "staging",
    )
    spec = _real_spec(base, candidate, rollback_digest)
    receipt = service.promote_with_transition(
        spec,
        **_authoritative_inputs(spec),
        workspace_path=repo,
        revision_tracker=tracker,
        observed_at="2026-01-01T00:00:01Z",
    )
    assert _has_secret(receipt) is False
    assert _has_secret(tracker.load_transitions("workspace.demo")) is False
    for path in (tmp_path / "state").rglob("*.json"):
        assert _SECRET.search(path.read_text(encoding="utf-8")) is None


# ---------------------------------------------------------- repaired seams


def test_tampered_receipt_is_refused_on_load(tmp_path: Path):
    service = _service(tmp_path)
    spec = promotion_spec()
    receipt = service.promote(spec, observations=observations(spec, ), observed_at="2026-01-01T00:00:00Z")
    path = tmp_path / "state" / "promotions" / "promotion.demo.json"
    stored = json.loads(path.read_text(encoding="utf-8"))
    stored["promotionDecision"]["reason"] = "tampered-by-attacker"
    path.write_text(json.dumps(stored, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with pytest.raises(PromotionError, match="tampered|digest recomputation"):
        service.load_receipt("promotion.demo")
    with pytest.raises(PromotionError):
        service.promote(spec, observations=observations(spec, ), observed_at="2026-01-01T00:00:02Z")
    assert receipt["promotionDecision"]["decision"] == "refused"


def _approval_store(**record):
    store = {} if not record else {"approval.demo": record}
    return lambda approval_id: store.get(approval_id)


def _evidence_store(digest=EVIDENCE_DIGEST, validator_id="validator.demo", classification="passed"):
    return lambda claimed: (
        {"evidenceDigest": digest, "validatorId": validator_id, "classification": classification}
        if claimed == digest
        else None
    )


def test_observe_and_promote_sources_only_authoritative_records(tmp_path: Path):
    service = _service(tmp_path)
    rollback = _record_rollback(service)
    spec = promotion_spec(rollbackPointDigest=rollback)
    receipt = service.observe_and_promote(
        spec,
        observe_revision=lambda: BASE_SHA,
        load_approval=_approval_store(
            approvalId="approval.demo",
            status="approved",
            actor="operator.alice",
            boundCandidateId="candidate.demo",
            boundSpecDigest=PromotionSpec.from_dict(spec).digest,
        ),
        load_validator_evidence=_evidence_store(),
        compute_diff_digest=lambda base, candidate: DIFF_DIGEST,
        observed_at="2026-01-01T00:00:00Z",
    )
    assert receipt["approval"]["status"] == "approved"
    assert receipt["approval"]["actor"] == "operator.alice"
    assert receipt["promotionDecision"]["checks"]["approval"] is True
    assert receipt["promotionDecision"]["checks"]["validatorEvidence"] is True


def test_observe_and_promote_refuses_when_store_has_no_approval(tmp_path: Path):
    service = _service(tmp_path)
    rollback = _record_rollback(service)
    spec = promotion_spec(rollbackPointDigest=rollback)
    receipt = service.observe_and_promote(
        spec,
        observe_revision=lambda: BASE_SHA,
        load_approval=_approval_store(),
        load_validator_evidence=_evidence_store(),
        compute_diff_digest=lambda base, candidate: DIFF_DIGEST,
        observed_at="2026-01-01T00:00:00Z",
    )
    assert receipt["promotionDecision"]["decision"] == "refused"
    assert receipt["promotionDecision"]["checks"]["approval"] is False
    assert receipt["approval"]["status"] == "pending"


def test_observe_and_promote_refuses_when_evidence_is_unresolvable(tmp_path: Path):
    service = _service(tmp_path)
    rollback = _record_rollback(service)
    spec = promotion_spec(rollbackPointDigest=rollback)
    receipt = service.observe_and_promote(
        spec,
        observe_revision=lambda: BASE_SHA,
        load_approval=_approval_store(
            approvalId="approval.demo",
            status="approved",
            actor="operator.alice",
            boundCandidateId="candidate.demo",
            boundSpecDigest=PromotionSpec.from_dict(spec).digest,
        ),
        load_validator_evidence=lambda claimed: None,
        compute_diff_digest=lambda base, candidate: DIFF_DIGEST,
        observed_at="2026-01-01T00:00:00Z",
    )
    assert receipt["promotionDecision"]["decision"] == "refused"
    assert receipt["promotionDecision"]["checks"]["validatorEvidence"] is False


def _real_promotion(tmp_path: Path):
    repo, base, candidate = _real_workspace(tmp_path)
    service = _service(tmp_path)
    rollback_digest = _record_real_rollback(service, base)
    tracker = WorkspaceRevisionTracker(
        tmp_path / "state",
        workspace_root=tmp_path / "ws",
        staging_root=tmp_path / "staging",
    )
    spec = _real_spec(base, candidate, rollback_digest)
    receipt = service.promote_with_transition(
        spec,
        **_authoritative_inputs(spec),
        workspace_path=repo,
        revision_tracker=tracker,
        observed_at="2026-01-01T00:00:01Z",
    )
    assert receipt["promotionDecision"]["decision"] == "promoted"
    return repo, base, candidate, service, tracker, spec


def test_recover_classifies_promoted_and_rolled_back(tmp_path: Path):
    repo, base, candidate, service, tracker, spec = _real_promotion(tmp_path)
    recovered = service.recover_promotion(
        spec,
        revision_tracker=tracker,
        workspace_path=repo,
    )
    assert recovered["classification"] == "promoted"
    _git(repo, "reset", "--hard", base)
    recovered = service.recover_promotion(
        spec,
        revision_tracker=tracker,
        workspace_path=repo,
    )
    assert recovered["classification"] == "rolled_back"


def test_recover_classifies_unapplied_and_applied_unreceipted(tmp_path: Path):
    repo, base, candidate, service, tracker, spec = _real_promotion(tmp_path)
    unrelated = _real_spec(
        base, candidate, spec["rollbackPointDigest"], promotion_id="promotion.never-ran"
    )
    unapplied = service.recover_promotion(
        unrelated,
        revision_tracker=tracker,
        workspace_path=repo,
    )
    assert unapplied["classification"] == "quarantined"
    # Crash between transition success and receipt write: remove the receipt.
    (tmp_path / "state" / "promotions" / "promotion.demo.json").unlink()
    recovered = service.recover_promotion(
        spec,
        revision_tracker=tracker,
        workspace_path=repo,
    )
    assert recovered["classification"] == "applied_unreceipted"


def test_recover_quarantines_interrupted_transition(tmp_path: Path):
    repo, base, candidate = _real_workspace(tmp_path)
    service = _service(tmp_path)
    tracker = WorkspaceRevisionTracker(
        tmp_path / "state",
        workspace_root=tmp_path / "ws",
        staging_root=tmp_path / "staging",
    )
    tracker.record_transition(
        workspace_id="workspace.demo",
        workspace_path=repo,
        promotion_id="promotion.demo",
        pre_revision=base,
        post_revision=None,
        status="interrupted",
        reason="post_revision_observe_failed",
        observed_at="2026-01-01T00:00:00Z",
    )
    recovered = service.recover_promotion(
        _real_spec(base, candidate, UNRECORDED_DIGEST),
        revision_tracker=tracker,
        workspace_path=repo,
    )
    assert recovered["classification"] == "quarantined"


def test_recover_classifies_refused_receipt(tmp_path: Path):
    repo, base, _c = _real_workspace(tmp_path)
    service = _service(tmp_path)
    tracker = WorkspaceRevisionTracker(
        tmp_path / "state",
        workspace_root=tmp_path / "ws",
        staging_root=tmp_path / "staging",
    )
    spec = _real_spec(base, _c, UNRECORDED_DIGEST)
    receipt = service.promote(
        spec,
        observations=observations(spec, current_revision=base),
        observed_at="2026-01-01T00:00:00Z",
    )
    assert receipt["promotionDecision"]["decision"] == "refused"
    recovered = service.recover_promotion(
        spec,
        revision_tracker=tracker,
        workspace_path=repo,
    )
    assert recovered["classification"] == "refused"


def test_cross_process_flock_blocks_second_promoter(tmp_path: Path):
    import fcntl
    import os

    repo, base, candidate = _real_workspace(tmp_path)
    service = _service(tmp_path)
    rollback_digest = _record_real_rollback(service, base)
    tracker = WorkspaceRevisionTracker(
        tmp_path / "state",
        workspace_root=tmp_path / "ws",
        staging_root=tmp_path / "staging",
    )
    spec = _real_spec(base, candidate, rollback_digest)
    locks_dir = tmp_path / "state" / "promotions" / ".locks"
    locks_dir.mkdir(parents=True, exist_ok=True)
    held = os.open(str(locks_dir / "workspace.demo.lock"), os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        with pytest.raises(PromotionError, match="promotion_in_progress"):
            service.promote_with_transition(
                spec,
                **_authoritative_inputs(spec),
                workspace_path=repo,
                revision_tracker=tracker,
                observed_at="2026-01-01T00:00:01Z",
            )
        assert _git_head(repo) == base
    finally:
        fcntl.flock(held, fcntl.LOCK_UN)
        os.close(held)


# ------------------------------------------------ steer-7 hardening tests


def test_approval_not_bound_to_full_spec_digest_is_refused(tmp_path: Path):
    service = _service(tmp_path)
    digest = _record_rollback(service)
    spec = promotion_spec(rollbackPointDigest=digest)
    obs = observations(spec, approval_bound_spec_digest=OTHER_DIGEST)
    receipt = service.promote(spec, observations=obs, observed_at="2026-01-01T00:00:01Z")
    assert receipt["promotionDecision"]["decision"] == "refused"
    assert receipt["promotionDecision"]["checks"]["approval"] is False


def test_validator_evidence_without_passed_status_is_refused(tmp_path: Path):
    service = _service(tmp_path)
    digest = _record_rollback(service)
    spec = promotion_spec(rollbackPointDigest=digest)
    obs = observations(spec, validator_status="failed")
    receipt = service.promote(spec, observations=obs, observed_at="2026-01-01T00:00:01Z")
    assert receipt["promotionDecision"]["decision"] == "refused"
    assert receipt["promotionDecision"]["checks"]["validatorEvidence"] is False


def test_observe_and_promote_refuses_failed_validator_classification(tmp_path: Path):
    service = _service(tmp_path)
    rollback = _record_rollback(service)
    spec = promotion_spec(rollbackPointDigest=rollback)
    receipt = service.observe_and_promote(
        spec,
        observe_revision=lambda: BASE_SHA,
        load_approval=_approval_store(
            approvalId="approval.demo",
            status="approved",
            actor="operator.alice",
            boundCandidateId="candidate.demo",
            boundSpecDigest=PromotionSpec.from_dict(spec).digest,
        ),
        load_validator_evidence=_evidence_store(classification="failed"),
        compute_diff_digest=lambda base, candidate: DIFF_DIGEST,
        observed_at="2026-01-01T00:00:00Z",
    )
    assert receipt["promotionDecision"]["decision"] == "refused"
    assert receipt["promotionDecision"]["checks"]["validatorEvidence"] is False


def test_observe_and_promote_refuses_approval_bound_to_other_spec(tmp_path: Path):
    service = _service(tmp_path)
    rollback = _record_rollback(service)
    spec = promotion_spec(rollbackPointDigest=rollback)
    receipt = service.observe_and_promote(
        spec,
        observe_revision=lambda: BASE_SHA,
        load_approval=_approval_store(
            approvalId="approval.demo",
            status="approved",
            actor="operator.alice",
            boundCandidateId="candidate.demo",
            boundSpecDigest=OTHER_DIGEST,
        ),
        load_validator_evidence=_evidence_store(),
        compute_diff_digest=lambda base, candidate: DIFF_DIGEST,
        observed_at="2026-01-01T00:00:00Z",
    )
    assert receipt["promotionDecision"]["checks"]["approval"] is False
    assert receipt["promotionDecision"]["decision"] == "refused"


def test_hooks_and_repository_code_never_execute_during_transition(tmp_path: Path):
    repo, base, candidate = _real_workspace(tmp_path)
    hook = repo / ".git" / "hooks" / "pre-merge-commit"
    hook.write_text("#!/bin/sh\necho PWND > ../hook-executed.txt\nexit 1\n", encoding="utf-8")
    hook.chmod(0o755)
    service = _service(tmp_path)
    rollback_digest = _record_real_rollback(service, base)
    tracker = WorkspaceRevisionTracker(
        tmp_path / "state",
        workspace_root=tmp_path / "ws",
        staging_root=tmp_path / "staging",
    )
    spec = _real_spec(base, candidate, rollback_digest)
    receipt = service.promote_with_transition(
        spec,
        **_authoritative_inputs(spec),
        workspace_path=repo,
        revision_tracker=tracker,
        observed_at="2026-01-01T00:00:01Z",
    )
    assert receipt["promotionDecision"]["decision"] == "promoted"
    assert _git_head(repo) == candidate
    assert not (repo / ".git" / "hook-executed.txt").exists()
    assert not (repo / "hook-executed.txt").exists()
    # The intent was durable before the mutation.
    intent = json.loads(
        (service.state_dir / "promotion-intents" / "promotion.demo.json").read_text()
    )
    assert intent["specDigest"] == PromotionSpec.from_dict(spec).digest
    assert intent["candidateRevision"] == candidate


def test_repository_filter_drivers_block_the_transition(tmp_path: Path):
    repo, base, candidate = _real_workspace(tmp_path)
    _git(repo, "config", "filter.danger.clean", "sed s/a/b/")
    service = _service(tmp_path)
    rollback_digest = _record_real_rollback(service, base)
    tracker = WorkspaceRevisionTracker(
        tmp_path / "state",
        workspace_root=tmp_path / "ws",
        staging_root=tmp_path / "staging",
    )
    spec = _real_spec(base, candidate, rollback_digest)
    with pytest.raises(
        PromotionError, match="repository_configures_executable_or_indirect_behavior"
    ):
        service.promote_with_transition(
            spec,
            **_authoritative_inputs(spec),
            workspace_path=repo,
            revision_tracker=tracker,
            observed_at="2026-01-01T00:00:01Z",
        )
    assert _git_head(repo) == base


def test_repository_config_includes_block_the_transition(tmp_path: Path):
    repo, base, candidate = _real_workspace(tmp_path)
    included = tmp_path / "included-git-config"
    included.write_text(
        "[filter \"danger\"]\n\tclean = /tmp/attacker-filter\n",
        encoding="utf-8",
    )
    _git(repo, "config", "include.path", str(included))
    service = _service(tmp_path)
    rollback_digest = _record_real_rollback(service, base)
    tracker = WorkspaceRevisionTracker(
        tmp_path / "state",
        workspace_root=tmp_path / "ws",
        staging_root=tmp_path / "staging",
    )
    spec = _real_spec(base, candidate, rollback_digest)

    with pytest.raises(
        PromotionError, match="repository_configures_executable_or_indirect_behavior"
    ):
        service.promote_with_transition(
            spec,
            **_authoritative_inputs(spec),
            workspace_path=repo,
            revision_tracker=tracker,
        )
    assert _git_head(repo) == base


def test_receipt_creation_is_cas_and_never_overwrites(tmp_path: Path):
    service = _service(tmp_path)
    digest = _record_rollback(service)
    spec = promotion_spec(rollbackPointDigest=digest)
    first = service.promote(spec, observations=observations(spec), observed_at="2026-01-01T00:00:01Z")
    # Direct CAS probe: a conflicting receipt under the same id cannot replace it.
    conflicting = dict(first, observedAt="2099-01-01T00:00:00Z")
    conflicting["receiptDigest"] = canonical_digest(
        {key: value for key, value in conflicting.items() if key != "receiptDigest"}
    )
    with pytest.raises(PromotionError, match="different content"):
        service._record_receipt(conflicting)  # noqa: SLF001
    assert service.load_receipt(spec["promotionId"]) == first


def test_recovery_classifies_merge_before_record_crash_and_completes(tmp_path: Path):
    repo, base, candidate = _real_workspace(tmp_path)
    service = _service(tmp_path)
    rollback_digest = _record_real_rollback(service, base)
    tracker = WorkspaceRevisionTracker(
        tmp_path / "state",
        workspace_root=tmp_path / "ws",
        staging_root=tmp_path / "staging",
    )
    spec = _real_spec(base, candidate, rollback_digest)
    # Simulate a crash AFTER the merge but BEFORE the transition record and
    # receipt: intent durable, HEAD at candidate, nothing else.
    _record_bound_intent(service, spec, repo, tracker)
    _git(repo, "merge", "--ff-only", candidate)
    assert _git_head(repo) == candidate

    recovered = service.recover_promotion(
        spec,
        revision_tracker=tracker,
        workspace_path=repo,
    )
    assert recovered["classification"] == "applied_unreceipted"

    receipt = service.recover_and_complete(
        spec,
        **_authoritative_inputs(spec),
        workspace_path=repo,
        revision_tracker=tracker,
    )
    assert receipt["promotionDecision"]["decision"] == "promoted"
    assert service.is_promoted("promotion.demo")
    transitions = tracker.load_transitions("workspace.demo")
    assert transitions[-1]["reason"] == "recovery-completed"
    # Replaying completion is idempotent.
    again = service.recover_and_complete(
        spec,
        **_authoritative_inputs(spec),
        workspace_path=repo,
        revision_tracker=tracker,
    )
    assert again == receipt


def test_recovery_reports_unapplied_when_head_is_still_base(tmp_path: Path):
    repo, base, candidate = _real_workspace(tmp_path)
    service = _service(tmp_path)
    rollback_digest = _record_real_rollback(service, base)
    tracker = WorkspaceRevisionTracker(
        tmp_path / "state",
        workspace_root=tmp_path / "ws",
        staging_root=tmp_path / "staging",
    )
    spec = _real_spec(base, candidate, rollback_digest)
    _record_bound_intent(service, spec, repo, tracker)
    recovered = service.recover_promotion(
        spec,
        revision_tracker=tracker,
        workspace_path=repo,
    )
    assert recovered["classification"] == "unapplied"
    completed = service.recover_and_complete(
        spec,
        **_authoritative_inputs(spec),
        workspace_path=repo,
        revision_tracker=tracker,
    )
    assert completed["classification"] == "unapplied"
    assert service.load_receipt("promotion.demo") is None


def test_recovery_quarantines_an_unexpected_revision(tmp_path: Path):
    repo, base, candidate = _real_workspace(tmp_path)
    service = _service(tmp_path)
    rollback_digest = _record_real_rollback(service, base)
    tracker = WorkspaceRevisionTracker(
        tmp_path / "state",
        workspace_root=tmp_path / "ws",
        staging_root=tmp_path / "staging",
    )
    spec = _real_spec(base, candidate, rollback_digest)
    _record_bound_intent(service, spec, repo, tracker)
    _git(repo, "checkout", "-q", "-b", "intruder")
    _git_commit(repo, "intruder\n", "intruder")
    recovered = service.recover_promotion(
        spec,
        revision_tracker=tracker,
        workspace_path=repo,
    )
    assert recovered["classification"] == "quarantined"
    with pytest.raises(PromotionError, match="quarantined"):
        service.recover_and_complete(
            spec,
            **_authoritative_inputs(spec),
            workspace_path=repo,
            revision_tracker=tracker,
        )


def test_replay_after_merge_before_record_crash_completes_instead_of_burning(tmp_path: Path):
    # Finding: a natural replay after a crash between merge and receipt used
    # to record a durable REFUSED receipt, poisoning the promotionId forever.
    repo, base, candidate = _real_workspace(tmp_path)
    service = _service(tmp_path)
    rollback_digest = _record_real_rollback(service, base)
    tracker = WorkspaceRevisionTracker(
        tmp_path / "state",
        workspace_root=tmp_path / "ws",
        staging_root=tmp_path / "staging",
    )
    spec = _real_spec(base, candidate, rollback_digest)
    _record_bound_intent(service, spec, repo, tracker)
    _git(repo, "merge", "--ff-only", candidate)
    receipt = service.promote_with_transition(
        spec,
        **_authoritative_inputs(spec),
        workspace_path=repo,
        revision_tracker=tracker,
        observed_at="2026-01-01T00:00:02Z",
    )
    assert receipt["promotionDecision"]["decision"] == "promoted"
    assert service.is_promoted("promotion.demo")


def test_git_environment_is_fully_neutralized(tmp_path: Path, monkeypatch):
    # The sanitized transition still merges on a real repo under a poisoned env.
    repo, base, candidate = _real_workspace(tmp_path)
    service = _service(tmp_path)
    rollback_digest = _record_real_rollback(service, base)
    tracker = WorkspaceRevisionTracker(
        tmp_path / "state",
        workspace_root=tmp_path / "ws",
        staging_root=tmp_path / "staging",
    )
    spec = _real_spec(base, candidate, rollback_digest)
    monkeypatch.setenv("GIT_DIR", "/nonexistent-evil-git-dir")
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", "'core.hooksPath=/tmp/evil-hooks'")
    monkeypatch.setenv("GIT_WORK_TREE", "/nonexistent-evil-worktree")
    monkeypatch.setenv("LD_PRELOAD", "/nonexistent-evil-preload.so")
    monkeypatch.setenv("PATH", str(tmp_path / "attacker-bin"))
    env = tracker.git_environment()
    assert "GIT_DIR" not in env
    assert "GIT_WORK_TREE" not in env
    assert "GIT_CONFIG_PARAMETERS" not in env
    assert "LD_PRELOAD" not in env
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["GIT_NO_REPLACE_OBJECTS"] == "1"
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    receipt = service.promote_with_transition(
        spec,
        **_authoritative_inputs(spec),
        workspace_path=repo,
        revision_tracker=tracker,
    )
    assert receipt["promotionDecision"]["decision"] == "promoted"
    assert tracker.observe_revision(repo) == candidate


def test_corrupt_git_config_fails_the_filter_probe_closed(tmp_path: Path):
    repo, base, candidate = _real_workspace(tmp_path)
    tracker = WorkspaceRevisionTracker(
        tmp_path / "state",
        workspace_root=tmp_path / "ws",
        staging_root=tmp_path / "staging",
    )
    identity = tracker.workspace_identity(repo)
    with open(repo / ".git" / "config", "a", encoding="utf-8") as handle:
        handle.write("\n[broken\n")
    status, reason = PromotionService._run_git_transition(  # noqa: SLF001
        repo,
        candidate,
        revision_tracker=tracker,
        identity=identity,
        before_mutation=lambda: None,
    )
    assert status == "failed"
    assert reason == "repository_config_probe_failed"
    # The workspace content was untouched (plain git cannot even read HEAD
    # under the corrupt config; the file system is the honest witness).
    assert (repo / "README.md").read_text(encoding="utf-8") == "base\n"


# ------------------------------------------------ owner-review hardening


def test_public_mutator_rejects_fabricated_observations(tmp_path: Path):
    repo, base, candidate = _real_workspace(tmp_path)
    service = _service(tmp_path)
    rollback = _record_real_rollback(service, base)
    tracker = WorkspaceRevisionTracker(
        tmp_path / "state",
        workspace_root=tmp_path / "ws",
        staging_root=tmp_path / "staging",
    )
    spec = _real_spec(base, candidate, rollback)

    with pytest.raises(TypeError, match="observations"):
        service.promote_with_transition(
            spec,
            observations=observations(spec, current_revision=base),
            workspace_path=repo,
            revision_tracker=tracker,
        )

    assert _git_head(repo) == base
    assert service.load_receipt("promotion.demo") is None
    assert not (service.state_dir / "promotion-intents" / "promotion.demo.json").exists()


def test_authority_is_not_read_before_both_workspace_locks(tmp_path: Path):
    import fcntl
    import os

    repo, base, candidate = _real_workspace(tmp_path)
    service = _service(tmp_path)
    rollback = _record_real_rollback(service, base)
    tracker = WorkspaceRevisionTracker(
        tmp_path / "state",
        workspace_root=tmp_path / "ws",
        staging_root=tmp_path / "staging",
    )
    spec = _real_spec(base, candidate, rollback)
    calls: list[str] = []
    authority = _authoritative_inputs(
        spec,
        load_approval=lambda _approval_id: calls.append("approval") or None,
        load_validator_evidence=lambda _digest: calls.append("evidence") or None,
        compute_diff_digest=lambda _base, _candidate: calls.append("diff") or DIFF_DIGEST,
    )
    locks_dir = service.state_dir / "promotions" / ".locks"
    locks_dir.mkdir(parents=True, exist_ok=True)
    held = os.open(locks_dir / "workspace.demo.lock", os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        with pytest.raises(PromotionError, match="promotion_in_progress"):
            service.observe_and_promote_with_transition(
                spec,
                **authority,
                workspace_path=repo,
                revision_tracker=tracker,
            )
    finally:
        fcntl.flock(held, fcntl.LOCK_UN)
        os.close(held)
    assert calls == []
    assert _git_head(repo) == base


@pytest.mark.parametrize("drifting_record", ["approval", "evidence"])
def test_authoritative_record_drift_before_mutation_fails_closed(
    tmp_path: Path, drifting_record: str
):
    repo, base, candidate = _real_workspace(tmp_path)
    service = _service(tmp_path)
    rollback = _record_real_rollback(service, base)
    tracker = WorkspaceRevisionTracker(
        tmp_path / "state",
        workspace_root=tmp_path / "ws",
        staging_root=tmp_path / "staging",
    )
    spec = _real_spec(base, candidate, rollback)
    calls = {"approval": 0, "evidence": 0}

    def load_approval(_approval_id):
        calls["approval"] += 1
        return {
            "approvalId": spec["approvalId"],
            "status": "approved",
            "actor": "operator.alice",
            "boundCandidateId": spec["candidateId"],
            "boundSpecDigest": PromotionSpec.from_dict(spec).digest,
            "recordVersion": (
                2 if drifting_record == "approval" and calls["approval"] >= 3 else 1
            ),
        }

    def load_evidence(_digest):
        calls["evidence"] += 1
        return {
            "evidenceDigest": spec["validatorEvidenceDigest"],
            "validatorId": "validator.demo",
            "classification": "passed",
            "recordVersion": (
                2 if drifting_record == "evidence" and calls["evidence"] >= 3 else 1
            ),
        }

    with pytest.raises(PromotionError, match="requires recovery"):
        service.observe_and_promote_with_transition(
            spec,
            **_authoritative_inputs(
                spec,
                load_approval=load_approval,
                load_validator_evidence=load_evidence,
            ),
            workspace_path=repo,
            revision_tracker=tracker,
        )

    assert calls[drifting_record] >= 3
    assert _git_head(repo) == base
    assert service.load_receipt("promotion.demo") is None
    intent = service._load_intent("promotion.demo")  # noqa: SLF001
    assert intent is not None


@pytest.mark.parametrize("record_kind", ["intent", "receipt"])
def test_cas_link_failure_never_leaves_partial_final_record(
    tmp_path: Path, monkeypatch, record_kind: str
):
    import execution_host.promotion as promotion_module

    repo, base, candidate = _real_workspace(tmp_path)
    service = _service(tmp_path)
    rollback = _record_real_rollback(service, base)
    tracker = WorkspaceRevisionTracker(
        tmp_path / "state",
        workspace_root=tmp_path / "ws",
        staging_root=tmp_path / "staging",
    )
    spec = _real_spec(base, candidate, rollback)
    target = (
        service.state_dir / "promotion-intents" / "promotion.demo.json"
        if record_kind == "intent"
        else service.state_dir / "promotions" / "promotion.demo.json"
    )
    real_link = promotion_module.os.link

    def fail_target(source, destination, **kwargs):
        if Path(destination) == target:
            raise OSError("simulated power loss before CAS publication")
        return real_link(source, destination, **kwargs)

    monkeypatch.setattr(promotion_module.os, "link", fail_target)
    if record_kind == "intent":
        with pytest.raises(PromotionError, match="CAS publication failed"):
            service.promote_with_transition(
                spec,
                **_authoritative_inputs(spec),
                workspace_path=repo,
                revision_tracker=tracker,
            )
    else:
        with pytest.raises(PromotionError, match="CAS publication failed"):
            service.promote(
                spec,
                observations=observations(spec, current_revision=base),
                observed_at="2026-01-01T00:00:00Z",
            )

    assert not target.exists()
    assert list(target.parent.glob(f".{target.name}.*.tmp")) == []
    assert _git_head(repo) == base


@pytest.mark.parametrize("record_kind", ["intent", "receipt"])
def test_recovery_quarantines_malformed_durable_records(tmp_path: Path, record_kind: str):
    repo, base, candidate = _real_workspace(tmp_path)
    service = _service(tmp_path)
    rollback = _record_real_rollback(service, base)
    tracker = WorkspaceRevisionTracker(
        tmp_path / "state",
        workspace_root=tmp_path / "ws",
        staging_root=tmp_path / "staging",
    )
    spec = _real_spec(base, candidate, rollback)
    target = (
        service.state_dir / "promotion-intents" / "promotion.demo.json"
        if record_kind == "intent"
        else service.state_dir / "promotions" / "promotion.demo.json"
    )
    target.write_bytes(b'{"formatVersion":')

    recovered = service.recover_promotion(
        spec,
        revision_tracker=tracker,
        workspace_path=repo,
    )
    assert recovered["classification"] == "quarantined"
    assert "malformed" in recovered["detail"]
    with pytest.raises(PromotionError, match="malformed"):
        (
            service._load_intent("promotion.demo")  # noqa: SLF001
            if record_kind == "intent"
            else service.load_receipt("promotion.demo")
        )


def test_receipt_cas_requires_byte_identical_replay(tmp_path: Path):
    service = _service(tmp_path)
    rollback = _record_rollback(service)
    spec = promotion_spec(rollbackPointDigest=rollback)
    receipt = service.promote(
        spec,
        observations=observations(spec),
        observed_at="2026-01-01T00:00:00Z",
    )
    assert service._record_receipt(receipt) == receipt  # noqa: SLF001
    path = service.state_dir / "promotions" / "promotion.demo.json"
    path.write_text(json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")
    with pytest.raises(PromotionError, match="different content"):
        service._record_receipt(receipt)  # noqa: SLF001


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("workspaceId", "workspace.other"),
        ("expectedBaseRevision", "1" * 40),
        ("candidateRevision", "2" * 40),
        ("diffDigest", OTHER_DIGEST),
    ],
)
def test_recovery_quarantines_spec_binding_confusion(
    tmp_path: Path, field: str, value: str
):
    repo, base, candidate = _real_workspace(tmp_path)
    service = _service(tmp_path)
    rollback = _record_real_rollback(service, base)
    tracker = WorkspaceRevisionTracker(
        tmp_path / "state",
        workspace_root=tmp_path / "ws",
        staging_root=tmp_path / "staging",
    )
    spec = _real_spec(base, candidate, rollback)
    _record_bound_intent(service, spec, repo, tracker)
    _git(repo, "merge", "--ff-only", candidate)
    conflicting = dict(spec)
    conflicting[field] = value

    recovered = service.recover_promotion(
        conflicting,
        revision_tracker=tracker,
        workspace_path=repo,
    )
    assert recovered["classification"] == "quarantined"


def test_recovery_quarantines_a_different_workspace_path(tmp_path: Path):
    repo, base, candidate = _real_workspace(tmp_path)
    service = _service(tmp_path)
    rollback = _record_real_rollback(service, base)
    tracker = WorkspaceRevisionTracker(
        tmp_path / "state",
        workspace_root=tmp_path / "ws",
        staging_root=tmp_path / "staging",
    )
    spec = _real_spec(base, candidate, rollback)
    _record_bound_intent(service, spec, repo, tracker)
    _git(repo, "merge", "--ff-only", candidate)
    other = tmp_path / "ws" / "other"
    subprocess.run(
        ["git", "clone", "-q", str(repo), str(other)],
        capture_output=True,
        text=True,
        check=True,
    )

    recovered = service.recover_promotion(
        spec,
        revision_tracker=tracker,
        workspace_path=other,
    )
    assert recovered["classification"] == "quarantined"
    assert "workspace" in recovered["detail"]


def test_recovery_will_not_complete_a_dirty_applied_workspace(tmp_path: Path):
    repo, base, candidate = _real_workspace(tmp_path)
    service = _service(tmp_path)
    rollback = _record_real_rollback(service, base)
    tracker = WorkspaceRevisionTracker(
        tmp_path / "state",
        workspace_root=tmp_path / "ws",
        staging_root=tmp_path / "staging",
    )
    spec = _real_spec(base, candidate, rollback)
    _record_bound_intent(service, spec, repo, tracker)
    _git(repo, "merge", "--ff-only", candidate)
    (repo / "README.md").write_text("dirty after apply\n", encoding="utf-8")

    with pytest.raises(PromotionError, match="workspace safety|not_clean"):
        service.recover_and_complete(
            spec,
            **_authoritative_inputs(spec),
            workspace_path=repo,
            revision_tracker=tracker,
        )
    assert service.load_receipt("promotion.demo") is None


def test_applied_but_failed_git_result_is_recoverable_not_refused(tmp_path: Path, monkeypatch):
    repo, base, candidate = _real_workspace(tmp_path)
    service = _service(tmp_path)
    rollback = _record_real_rollback(service, base)
    tracker = WorkspaceRevisionTracker(
        tmp_path / "state",
        workspace_root=tmp_path / "ws",
        staging_root=tmp_path / "staging",
    )
    spec = _real_spec(base, candidate, rollback)

    def applied_but_failed(_path, _candidate, **kwargs):
        assert kwargs["before_mutation"]() is None
        _git(repo, "merge", "--ff-only", candidate)
        return "failed", "simulated_ambiguous_failure"

    monkeypatch.setattr(service, "_run_git_transition", applied_but_failed)
    with pytest.raises(PromotionError, match="requires recovery"):
        service.promote_with_transition(
            spec,
            **_authoritative_inputs(spec),
            workspace_path=repo,
            revision_tracker=tracker,
        )
    assert _git_head(repo) == candidate
    assert service.load_receipt("promotion.demo") is None
    recovered = service.recover_promotion(
        spec,
        revision_tracker=tracker,
        workspace_path=repo,
    )
    assert recovered["classification"] == "applied_unreceipted"
    receipt = service.recover_and_complete(
        spec,
        **_authoritative_inputs(spec),
        workspace_path=repo,
        revision_tracker=tracker,
    )
    assert receipt["promotionDecision"]["decision"] == "promoted"


def test_refused_receipt_with_physically_applied_candidate_is_quarantined(tmp_path: Path):
    repo, base, candidate = _real_workspace(tmp_path)
    service = _service(tmp_path)
    tracker = WorkspaceRevisionTracker(
        tmp_path / "state",
        workspace_root=tmp_path / "ws",
        staging_root=tmp_path / "staging",
    )
    spec = _real_spec(base, candidate, UNRECORDED_DIGEST)
    refused = service.promote(
        spec,
        observations=observations(spec, current_revision=base),
        observed_at="2026-01-01T00:00:00Z",
    )
    assert refused["promotionDecision"]["decision"] == "refused"
    _git(repo, "merge", "--ff-only", candidate)

    with pytest.raises(PromotionError, match="physically applied"):
        service.promote_with_transition(
            spec,
            **_authoritative_inputs(spec),
            workspace_path=repo,
            revision_tracker=tracker,
        )
    recovered = service.recover_promotion(
        spec,
        revision_tracker=tracker,
        workspace_path=repo,
    )
    assert recovered["classification"] == "quarantined"


def test_authority_drift_after_merge_never_writes_refused_receipt(tmp_path: Path):
    repo, base, candidate = _real_workspace(tmp_path)
    service = _service(tmp_path)
    rollback = _record_real_rollback(service, base)
    tracker = WorkspaceRevisionTracker(
        tmp_path / "state",
        workspace_root=tmp_path / "ws",
        staging_root=tmp_path / "staging",
    )
    spec = _real_spec(base, candidate, rollback)
    approval_calls = 0

    def load_approval(_approval_id):
        nonlocal approval_calls
        approval_calls += 1
        return {
            "approvalId": spec["approvalId"],
            "status": "approved",
            "actor": "operator.alice",
            "boundCandidateId": spec["candidateId"],
            "boundSpecDigest": PromotionSpec.from_dict(spec).digest,
            "recordVersion": 2 if approval_calls >= 4 else 1,
        }

    with pytest.raises(PromotionError, match="after mutation"):
        service.promote_with_transition(
            spec,
            **_authoritative_inputs(spec, load_approval=load_approval),
            workspace_path=repo,
            revision_tracker=tracker,
        )
    assert _git_head(repo) == candidate
    assert service.load_receipt("promotion.demo") is None
    recovered = service.recover_promotion(
        spec,
        revision_tracker=tracker,
        workspace_path=repo,
    )
    assert recovered["classification"] == "applied_unreceipted"
    with pytest.raises(PromotionError, match="drifted"):
        service.recover_and_complete(
            spec,
            **_authoritative_inputs(spec, load_approval=load_approval),
            workspace_path=repo,
            revision_tracker=tracker,
        )
    assert service.load_receipt("promotion.demo") is None


def test_workspace_swap_immediately_before_merge_is_quarantined(tmp_path: Path):
    repo, base, candidate = _real_workspace(tmp_path)
    attacker = tmp_path / "ws" / "attacker"
    attacker_head = _init_git_repo(attacker)
    service = _service(tmp_path)
    rollback = _record_real_rollback(service, base)
    tracker = WorkspaceRevisionTracker(
        tmp_path / "state",
        workspace_root=tmp_path / "ws",
        staging_root=tmp_path / "staging",
    )
    spec = _real_spec(base, candidate, rollback)
    approval_calls = 0
    original = tmp_path / "ws" / "original-moved"

    def swap_during_final_authority_read(_approval_id):
        nonlocal approval_calls
        approval_calls += 1
        if approval_calls == 3:
            repo.rename(original)
            attacker.rename(repo)
        return {
            "approvalId": spec["approvalId"],
            "status": "approved",
            "actor": "operator.alice",
            "boundCandidateId": spec["candidateId"],
            "boundSpecDigest": PromotionSpec.from_dict(spec).digest,
        }

    with pytest.raises(PromotionError, match="quarantined|requires recovery"):
        service.promote_with_transition(
            spec,
            **_authoritative_inputs(
                spec, load_approval=swap_during_final_authority_read
            ),
            workspace_path=repo,
            revision_tracker=tracker,
        )
    assert _git_head(original) == base
    assert _git_head(repo) == attacker_head
    assert service.load_receipt("promotion.demo") is None
