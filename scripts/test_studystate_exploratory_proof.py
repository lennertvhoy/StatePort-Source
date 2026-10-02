from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts/studystate_exploratory_proof.py"
SPEC = importlib.util.spec_from_file_location("studystate_exploratory_proof", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
proof = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(proof)


def _run_git(root: Path, *arguments: str) -> str:
    environment = {
        **os.environ,
        "GIT_AUTHOR_NAME": "StatePort Test",
        "GIT_AUTHOR_EMAIL": "stateport@example.invalid",
        "GIT_COMMITTER_NAME": "StatePort Test",
        "GIT_COMMITTER_EMAIL": "stateport@example.invalid",
    }
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    return result.stdout.strip()


def test_proof_observes_persistence_and_exact_plan_undo_without_broad_claims() -> None:
    identity = {
        "gitCommit": "a" * 40,
        "gitTree": "b" * 40,
        "worktreeClean": True,
        "proofCommand": {"path": proof.SCRIPT_RELATIVE, "digest": "sha256:" + "c" * 64},
    }
    fixture_before = proof.fixture_tree_snapshot(ROOT)
    report = proof.build_proof(identity)
    fixture_after = proof.fixture_tree_snapshot(ROOT)

    assert report["runClass"] == "exploratory_pre_candidate"
    assert report["releaseCandidate"] is None
    assert report["humanAcceptance"] == "not_applicable"
    assert report["result"] == "passed"
    assert report["sourceIdentity"] == identity
    assert fixture_after == fixture_before
    assert {
        entry[1]
        for entry in fixture_after
        if "__pycache__" in Path(entry[1]).parts or Path(entry[1]).suffix == ".pyc"
    } == {
        entry[1]
        for entry in fixture_before
        if "__pycache__" in Path(entry[1]).parts or Path(entry[1]).suffix == ".pyc"
    }
    assert report["mutation"]["proposalId"].startswith("proposal-")
    assert report["mutation"]["closureReceiptId"].startswith("governed-run.")
    assert report["mutation"]["observedPlanDigest"] != report["initialState"]["planDigest"]
    assert report["reinstantiation"] == {
        "observedPlanDigest": report["mutation"]["observedPlanDigest"],
        "observedStateFileDigest": report["mutation"]["observedStateFileDigest"],
        "persistenceObserved": True,
        "canUndo": True,
    }
    assert report["undo"]["restoredPlanDigest"] == report["initialState"]["planDigest"]
    assert report["undo"]["observedPlanDigest"] == report["initialState"]["planDigest"]
    assert report["undo"]["exactPriorPlanDigestRestored"] is True
    assert report["undo"]["stateFileByteDigestRestored"] is False
    assert report["deterministicAssertion"] == {
        "formatVersion": "stateport.studystate-exploratory-proof-assertion/v1",
        "sourceCommit": identity["gitCommit"],
        "sourceTree": identity["gitTree"],
        "fixtureDigest": report["fixtureIdentity"]["fixtureDigest"],
        "initialPlanDigest": report["initialState"]["planDigest"],
        "mutatedPlanDigest": report["mutation"]["observedPlanDigest"],
        "restoredPlanDigest": report["undo"]["observedPlanDigest"],
        "mutationProposalId": report["mutation"]["proposalId"],
        "undoProposalId": report["undo"]["proposalId"],
        "persistenceObserved": True,
        "exactPriorPlanDigestRestored": True,
        "runClass": "exploratory_pre_candidate",
        "releaseCandidate": None,
        "humanAcceptance": "not_applicable",
    }
    assert report["deterministicAssertionDigest"] == proof._digest(
        report["deterministicAssertion"]
    )
    assert report["claimBoundary"] == {
        "automatedLocalProof": "passed",
        "browserValidation": "not_performed",
        "providerValidation": "not_performed",
        "remoteValidation": "not_performed",
        "releaseAcceptance": "not_applicable",
        "humanValidation": "not_performed",
        "note": (
            "Undo restored the exact durable learning-plan digest and observable "
            "learning projection; timestamped transition history is not claimed "
            "to be byte-identical to the initial file."
        ),
    }
    unsigned = dict(report)
    assert unsigned.pop("bundleDigest") == proof._digest(unsigned)
    serialized = json.dumps(report, sort_keys=True)
    assert "stateport-studystate-proof-" not in serialized
    assert "releaseCandidate" in serialized

    repeated = proof.build_proof(identity)
    assert repeated["deterministicAssertion"] == report["deterministicAssertion"]
    assert repeated["deterministicAssertionDigest"] == report["deterministicAssertionDigest"]


def test_repository_identity_fails_closed_on_mismatch_and_dirty_source(tmp_path: Path) -> None:
    repository = tmp_path / "source"
    (repository / "scripts").mkdir(parents=True)
    (repository / proof.SCRIPT_RELATIVE).write_text("proof\n", encoding="utf-8")
    _run_git(repository, "init", "--initial-branch=main", "--template=")
    _run_git(repository, "add", "--all")
    _run_git(repository, "commit", "--no-verify", "-m", "fixture")
    head = _run_git(repository, "rev-parse", "HEAD")

    identity = proof.repository_identity(repository, head)
    assert identity["gitCommit"] == head
    assert identity["worktreeClean"] is True
    with pytest.raises(proof.ProofError, match="does not match"):
        proof.repository_identity(repository, "f" * 40)

    (repository / "drift.txt").write_text("untracked\n", encoding="utf-8")
    with pytest.raises(proof.ProofError, match="dirty"):
        proof.repository_identity(repository, head)


def test_bundle_write_is_create_only_and_rejects_symlinked_parent(tmp_path: Path) -> None:
    report = {"formatVersion": "test/v1"}
    output = tmp_path / "proof.json"
    proof.write_bundle(output, report)
    assert json.loads(output.read_text(encoding="utf-8")) == report
    with pytest.raises(proof.ProofError, match="overwrite"):
        proof.write_bundle(output, report)

    real = tmp_path / "real"
    real.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)
    with pytest.raises(proof.ProofError, match="symlink"):
        proof.write_bundle(linked / "proof.json", report)
