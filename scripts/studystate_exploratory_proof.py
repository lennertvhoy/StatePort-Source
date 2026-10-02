#!/usr/bin/env python3
"""Generate an exact-head, provider-free StudyState exploratory proof bundle.

This command exercises the public-safe StudyState fixture through StatePort's
governed portable-execution service.  It applies one exact evidence proposal,
discards and recreates the service objects from their durable roots, observes
the persisted state, and applies the exact Undo proposal.  The resulting JSON
is exploratory local evidence only; it is not release, browser, provider,
remote, or human-acceptance evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_RELATIVE = "scripts/studystate_exploratory_proof.py"
INSTANCE_ID = "studystate-exploratory-proof"
REFLECTION = "I completed the fictional governed evidence exercise."
_GIT_OID = re.compile(r"^[0-9a-f]{40,64}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")

for relative in (
    "packages/persistent-app/src",
    "packages/portable-execution/src",
    "packages/execution-host/src",
    "packages/external-engine-runtime/src",
    "packages/codex-adapter/src",
    "packages/run-bundle/src",
    "packages/statedd-core/src",
    "packages/template-validator/src",
    "packages/instance-backup/src",
    "packages/instance-catalog/src",
    "packages/diagnostics/src",
    "packages/statebench/src",
    "packages/governed-runner/src",
):
    sys.path.insert(0, str(ROOT / relative))

from stateport_persistent_app import LocalLayout, PersistentApp  # noqa: E402
from stateport_portable_execution.runtime import PortableExecutionService  # noqa: E402


class ProofError(ValueError):
    """A fail-closed exploratory-proof boundary error."""


def _canonical(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def _digest(value: Any) -> str:
    payload = value if isinstance(value, bytes) else _canonical(value)
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        shell=False,
    )
    if result.returncode:
        raise ProofError("StatePort source identity could not be resolved from Git")
    return result.stdout.strip()


def repository_identity(root: Path, expected_head: str) -> dict[str, Any]:
    """Resolve and verify a clean, exact StatePort source identity."""

    if not isinstance(expected_head, str) or _GIT_OID.fullmatch(expected_head) is None:
        raise ProofError("--expected-head must be one exact Git object ID")
    source = root.resolve(strict=True)
    if source.is_symlink() or not (source / ".git").exists():
        raise ProofError("StatePort source must be a non-symlinked Git worktree")
    head = _git(source, "rev-parse", "HEAD")
    if head != expected_head:
        raise ProofError("StatePort HEAD does not match --expected-head")
    status = _git(source, "status", "--porcelain=v1", "--untracked-files=all")
    if status:
        raise ProofError("StatePort source worktree is dirty; commit or remove drift first")
    tree = _git(source, "rev-parse", "HEAD^{tree}")
    if _GIT_OID.fullmatch(tree) is None:
        raise ProofError("StatePort source tree identity is invalid")
    tracked = _git(source, "ls-files", "--error-unmatch", SCRIPT_RELATIVE)
    if tracked != SCRIPT_RELATIVE:
        raise ProofError("exploratory proof command is not tracked at the exact source HEAD")
    return {
        "gitCommit": head,
        "gitTree": tree,
        "worktreeClean": True,
        "proofCommand": {
            "path": SCRIPT_RELATIVE,
            "digest": _digest((source / SCRIPT_RELATIVE).read_bytes()),
        },
    }


def _fixture_digest(root: Path) -> str:
    fixture = root / "fixtures/apps/studystate-sample"
    if fixture.is_symlink() or not fixture.is_dir():
        raise ProofError("StudyState public-safe fixture is missing or unsafe")
    digest = hashlib.sha256()
    for path in sorted(fixture.rglob("*")):
        if path.is_symlink():
            raise ProofError("StudyState public-safe fixture may not contain symlinks")
        if not path.is_file() or "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        relative = path.relative_to(fixture).as_posix().encode("utf-8")
        payload = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return "sha256:" + digest.hexdigest()


def fixture_tree_snapshot(root: Path) -> tuple[tuple[Any, ...], ...]:
    """Snapshot every fixture entry, including caches, without following links."""

    fixture = root / "fixtures/apps/studystate-sample"
    if fixture.is_symlink() or not fixture.is_dir():
        raise ProofError("StudyState public-safe fixture is missing or unsafe")
    entries: list[tuple[Any, ...]] = []
    for path in sorted(fixture.rglob("*"), key=lambda item: item.relative_to(fixture).as_posix()):
        relative = path.relative_to(fixture).as_posix()
        info = path.lstat()
        mode = info.st_mode & 0o7777
        if path.is_symlink():
            entries.append(("symlink", relative, mode, os.readlink(path)))
        elif path.is_dir():
            entries.append(("directory", relative, mode))
        elif path.is_file():
            entries.append(("file", relative, mode, _digest(path.read_bytes())))
        else:
            entries.append(("other", relative, mode))
    return tuple(entries)


def _file_digest(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ProofError("durable StudyState learning state is missing or unsafe")
    return _digest(path.read_bytes())


def _revision(result: dict[str, Any]) -> int:
    nested = result.get("run")
    run = nested if isinstance(nested, dict) else result
    revision = run.get("revision")
    if isinstance(revision, bool) or not isinstance(revision, int):
        raise ProofError("governed run did not return an exact revision")
    return revision


def _apply_action(
    service: PortableExecutionService,
    *,
    action_id: str,
    inputs: dict[str, Any],
) -> dict[str, Any]:
    prepared = service.prepare(INSTANCE_ID, action_id, "synthetic", inputs)
    run = prepared.get("run")
    if not isinstance(run, dict) or not isinstance(run.get("runId"), str):
        raise ProofError("governed run preparation did not return an exact identity")
    run_id = run["runId"]
    approved = service.approve_run(
        run_id,
        expected_instance_id=INSTANCE_ID,
        expected_revision=_revision(prepared),
    )
    proposed = service.execute(
        run_id,
        expected_instance_id=INSTANCE_ID,
        expected_revision=_revision(approved),
    )
    proposed_run = proposed.get("run")
    proposal = proposed_run.get("proposal") if isinstance(proposed_run, dict) else None
    if not isinstance(proposal, dict) or not isinstance(proposal.get("proposalId"), str):
        raise ProofError("governed action did not create an exact state-change proposal")
    proposal_approved = service.approve_proposal(
        run_id,
        expected_instance_id=INSTANCE_ID,
        expected_revision=_revision(proposed),
    )
    applied = service.apply_proposal(
        run_id,
        expected_instance_id=INSTANCE_ID,
        expected_revision=_revision(proposal_approved),
    )
    applied_run = applied.get("run")
    closure = applied_run.get("closureReceipt") if isinstance(applied_run, dict) else None
    exact_digests = (
        applied_run.get("proposalDigest") if isinstance(applied_run, dict) else None,
        closure.get("canonicalStateBefore") if isinstance(closure, dict) else None,
        closure.get("canonicalStateAfter") if isinstance(closure, dict) else None,
        closure.get("appliedRunBundleDigest") if isinstance(closure, dict) else None,
    )
    if (
        not isinstance(applied_run, dict)
        or applied_run.get("status") != "applied"
        or not isinstance(closure, dict)
        or not isinstance(closure.get("receiptId"), str)
        or closure.get("proposalId") != proposal["proposalId"]
        or any(not isinstance(value, str) or _SHA256.fullmatch(value) is None for value in exact_digests)
        or closure.get("claimState") != {
            "applied": True,
            "locallyValidated": True,
            "humanAccepted": False,
            "remotelyAccepted": False,
        }
    ):
        raise ProofError("governed action did not close with an exact apply receipt")
    return {
        "runId": run_id,
        "proposalId": proposal["proposalId"],
        "proposalDigest": applied_run.get("proposalDigest"),
        "closureReceiptId": closure["receiptId"],
        "closureReceiptDigest": _digest(closure),
        "canonicalStateBefore": closure.get("canonicalStateBefore"),
        "canonicalStateAfter": closure.get("canonicalStateAfter"),
        "appliedRunBundleDigest": closure.get("appliedRunBundleDigest"),
        "claimState": closure.get("claimState"),
        "proposalOperation": proposal.get("operation"),
    }


def _package_state(app: PersistentApp) -> dict[str, Any]:
    inspected = app.inspect(INSTANCE_ID)
    value = inspected.get("packageState")
    if not isinstance(value, dict):
        raise ProofError("StudyState package projection is unavailable")
    return value


def _build_proof(source_identity: dict[str, Any], *, root: Path) -> dict[str, Any]:
    """Exercise mutation, durable re-instantiation, and exact plan Undo."""

    source = root.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="stateport-studystate-proof-") as raw:
        temporary = Path(raw)
        layout = LocalLayout(
            config_root=temporary / "config/stateport",
            data_root=temporary / "data/stateport",
            state_root=temporary / "state/stateport",
        )
        first_app = PersistentApp(layout)
        first_app.setup_init()
        first_service = PortableExecutionService(first_app, source)
        installed = first_service.install_fixture_instance(
            "studystate.sample", INSTANCE_ID, "StudyState Exploratory Proof",
        )
        installation_identity = (
            installed.get("baseGit"),
            installed.get("receipt", {}).get("receiptId"),
            installed.get("receipt", {}).get("receiptDigest"),
        )
        if (
            not isinstance(installation_identity[0], str)
            or _GIT_OID.fullmatch(installation_identity[0]) is None
            or not isinstance(installation_identity[1], str)
            or not installation_identity[1].startswith("application-install.")
            or not isinstance(installation_identity[2], str)
            or _SHA256.fullmatch(installation_identity[2]) is None
        ):
            raise ProofError("StudyState fixture installation lacks exact receipt identity")
        instance_root = layout.instances_root / INSTANCE_ID
        learning_path = instance_root / "state/LEARNING.yaml"
        initial = _package_state(first_app)
        initial_state_file = _file_digest(learning_path)
        initial_plan = initial.get("planDigest")
        if not isinstance(initial_plan, str):
            raise ProofError("initial StudyState plan digest is unavailable")

        mutation = _apply_action(
            first_service,
            action_id="studystate.sample.record-evidence/v1",
            inputs={
                "activityId": "evidence-practice",
                "evidenceSummary": REFLECTION,
            },
        )
        after_mutation = _package_state(first_app)
        mutated_plan = after_mutation.get("planDigest")
        mutated_state_file = _file_digest(learning_path)
        if mutated_plan == initial_plan or after_mutation.get("goalProgressPercent") != 50:
            raise ProofError("StudyState evidence mutation was not observed durably")

        # Deliberately discard both objects.  The second pair reconstructs all
        # catalog, instance, run, and receipt state from the same durable roots.
        del first_service
        del first_app
        restarted_app = PersistentApp(layout)
        restarted_service = PortableExecutionService(restarted_app, source)
        after_reinstantiation = _package_state(restarted_app)
        restarted_state_file = _file_digest(learning_path)
        persistence_observed = (
            after_reinstantiation.get("planDigest") == mutated_plan
            and restarted_state_file == mutated_state_file
            and after_reinstantiation.get("goalProgressPercent") == 50
            and after_reinstantiation.get("canUndo") is True
        )
        if not persistence_observed:
            raise ProofError("StudyState mutation did not survive durable service re-instantiation")

        undo = _apply_action(
            restarted_service,
            action_id="studystate.sample.undo-last-evidence/v1",
            inputs={"expectedPlanDigest": mutated_plan},
        )
        restored = _package_state(restarted_app)
        restored_state_file = _file_digest(learning_path)
        exact_plan_restored = (
            restored.get("planDigest") == initial_plan
            and restored.get("goalProgressPercent") == 0
            and restored.get("canUndo") is False
            and restored.get("evidence") == []
            and isinstance(undo.get("proposalOperation"), dict)
            and undo["proposalOperation"].get("restoredPlanDigest") == initial_plan
        )
        if not exact_plan_restored:
            raise ProofError("StudyState Undo did not restore the exact prior plan digest")

        report: dict[str, Any] = {
            "formatVersion": "stateport.studystate-exploratory-proof-bundle/v1",
            "runClass": "exploratory_pre_candidate",
            "releaseCandidate": None,
            "humanAcceptance": "not_applicable",
            "result": "passed",
            "sourceIdentity": source_identity,
            "fixtureIdentity": {
                "applicationId": "studystate.sample",
                "fixtureDigest": _fixture_digest(source),
                "instanceId": INSTANCE_ID,
                "instanceBaseGit": installed.get("baseGit"),
                "installReceiptId": installed.get("receipt", {}).get("receiptId"),
                "installReceiptDigest": installed.get("receipt", {}).get("receiptDigest"),
            },
            "executionBoundary": {
                "runtime": "local_direct_portable_execution",
                "engine": "synthetic",
                "fixtureNetworkPolicy": "disabled",
                "providerContacted": False,
                "externalNetworkCallsIssuedByProofCommand": False,
                "networkIsolation": "not_instrumented",
                "browserUsed": False,
                "serviceProcessStarted": False,
                "durableReinstantiation": (
                    "new PersistentApp and PortableExecutionService objects reconstructed "
                    "from the same disposable on-disk roots"
                ),
            },
            "initialState": {
                "planDigest": initial_plan,
                "stateFileDigest": initial_state_file,
                "goalProgressPercent": initial.get("goalProgressPercent"),
                "evidenceCount": len(initial.get("evidence", [])),
            },
            "mutation": {
                **{key: value for key, value in mutation.items() if key != "proposalOperation"},
                "activityId": mutation["proposalOperation"].get("activityId"),
                "reflectionDigest": _digest(REFLECTION.encode("utf-8")),
                "observedPlanDigest": mutated_plan,
                "observedStateFileDigest": mutated_state_file,
                "observedGoalProgressPercent": after_mutation.get("goalProgressPercent"),
            },
            "reinstantiation": {
                "observedPlanDigest": after_reinstantiation.get("planDigest"),
                "observedStateFileDigest": restarted_state_file,
                "persistenceObserved": persistence_observed,
                "canUndo": after_reinstantiation.get("canUndo"),
            },
            "undo": {
                **{key: value for key, value in undo.items() if key != "proposalOperation"},
                "expectedCurrentPlanDigest": undo["proposalOperation"].get(
                    "expectedCurrentPlanDigest"
                ),
                "restoredPlanDigest": undo["proposalOperation"].get(
                    "restoredPlanDigest"
                ),
                "observedPlanDigest": restored.get("planDigest"),
                "observedStateFileDigest": restored_state_file,
                "exactPriorPlanDigestRestored": exact_plan_restored,
                "stateFileByteDigestRestored": restored_state_file == initial_state_file,
                "observedGoalProgressPercent": restored.get("goalProgressPercent"),
                "observedEvidenceCount": len(restored.get("evidence", [])),
            },
            "claimBoundary": {
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
            },
        }
        deterministic_assertion = {
            "formatVersion": "stateport.studystate-exploratory-proof-assertion/v1",
            "sourceCommit": source_identity.get("gitCommit"),
            "sourceTree": source_identity.get("gitTree"),
            "fixtureDigest": report["fixtureIdentity"]["fixtureDigest"],
            "initialPlanDigest": initial_plan,
            "mutatedPlanDigest": mutated_plan,
            "restoredPlanDigest": restored.get("planDigest"),
            "mutationProposalId": mutation["proposalId"],
            "undoProposalId": undo["proposalId"],
            "persistenceObserved": persistence_observed,
            "exactPriorPlanDigestRestored": exact_plan_restored,
            "runClass": report["runClass"],
            "releaseCandidate": report["releaseCandidate"],
            "humanAcceptance": report["humanAcceptance"],
        }
        report["deterministicAssertion"] = deterministic_assertion
        report["deterministicAssertionDigest"] = _digest(deterministic_assertion)
        report["identitySemantics"] = {
            "deterministicAssertionDigest": (
                "stable for the same exact source, fixture, plan transitions, and claim boundary"
            ),
            "bundleDigest": (
                "binds this individual observation, including run-specific receipts and "
                "timestamp-bearing durable state hashes"
            ),
        }
        report["bundleDigest"] = _digest(report)
        return report


def build_proof(source_identity: dict[str, Any], *, root: Path = ROOT) -> dict[str, Any]:
    """Build a proof while enforcing that its source fixture stays read-only."""

    source = root.resolve(strict=True)
    before = fixture_tree_snapshot(source)
    previous_environment = os.environ.get("PYTHONDONTWRITEBYTECODE")
    previous_runtime_flag = sys.dont_write_bytecode
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    sys.dont_write_bytecode = True
    try:
        return _build_proof(source_identity, root=source)
    finally:
        sys.dont_write_bytecode = previous_runtime_flag
        if previous_environment is None:
            os.environ.pop("PYTHONDONTWRITEBYTECODE", None)
        else:
            os.environ["PYTHONDONTWRITEBYTECODE"] = previous_environment
        after = fixture_tree_snapshot(source)
        if after != before:
            raise ProofError(
                "exploratory proof changed its source StudyState fixture"
            )


def _safe_output(path: Path) -> Path:
    candidate = Path(os.path.abspath(path))
    if candidate.name in {"", ".", ".."}:
        raise ProofError("--output must name a new JSON file")
    parent = candidate.parent
    if not parent.is_dir() or parent.is_symlink():
        raise ProofError("--output parent must be an existing non-symlinked directory")
    cursor = Path(parent.anchor)
    for part in parent.parts[1:]:
        cursor /= part
        if cursor.is_symlink():
            raise ProofError("--output may not traverse a symlink")
    if candidate.exists() or candidate.is_symlink():
        raise ProofError("refusing to overwrite an existing proof bundle")
    return candidate


def write_bundle(path: Path, report: dict[str, Any]) -> None:
    target = _safe_output(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(target, flags, 0o600)
    except FileExistsError as exc:
        raise ProofError("refusing to overwrite an existing proof bundle") from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(_canonical(report))
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        target.unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-head", required=True, help="exact clean StatePort Git HEAD")
    parser.add_argument("--output", type=Path, required=True, help="new JSON bundle path")
    arguments = parser.parse_args(argv)
    try:
        identity = repository_identity(ROOT, arguments.expected_head)
        report = build_proof(identity)
        write_bundle(arguments.output, report)
    except (OSError, ProofError, subprocess.SubprocessError, ValueError) as exc:
        print(f"StudyState exploratory proof refused: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({
        "ok": True,
        "output": arguments.output.name,
        "bundleDigest": report["bundleDigest"],
        "runClass": report["runClass"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
