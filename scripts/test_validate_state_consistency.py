#!/usr/bin/env python3
"""Regression tests for the current-state contradiction validator.

Fixtures build real git topologies (main + review branch) with TRACKED,
committed state files, mirroring the typed head model: STATUS.md and
PROJECT_STATE.yaml live on a review branch ahead of main, the canonical
branch is named (main) with its exact head derived from Git refs at
validation time. Legacy fixtures use only stateBinding.behaviouralHead;
dual-head fixtures also bind the independently typed repository-control
commit through stateBinding.controlHead.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts" / "validate_state_consistency.py"

sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "packages" / "statedd-core" / "src"))

import validate_state_consistency as vsc

REVIEW_BRANCH = "agent/review-001"


def _git(root: Path, *args: str) -> str:
    # Inject committer identity for every fixture call (including merge/rebase)
    # so the suite passes on machines without a global git identity.
    completed = subprocess.run(
        [
            "git",
            "-c",
            "user.email=stateport-tests@example.com",
            "-c",
            "user.name=StatePort Tests",
            *args,
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    return completed.stdout.strip()


def _commit(root: Path, message: str) -> str:
    _git(
        root,
        "-c",
        "user.email=test@example.com",
        "-c",
        "user.name=Test",
        "commit",
        "-m",
        message,
    )
    return _git(root, "rev-parse", "HEAD")


def _commit_files(root: Path, files: dict[str, str], message: str) -> str:
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        _git(root, "add", relative)
    return _commit(root, message)


def _state_files(
    *,
    behavioural: str,
    control: str | None = None,
    branch: str = "main",
    review_branch: str | None = REVIEW_BRANCH,
    review_status: str | None = None,
    canonical_observed: str = "0" * 40,
    release_freeze: str = "false",
    incident_status: str = "lifted",
    incident: bool = True,
    duplicate_incident: bool = False,
    policy: str = "state_only_descendant",
    canonical_line: str | None = None,
    status_body: str = "All good.\n",
    next_actions_body: str = "Nothing contradicting.\n",
    projection_workflow: bool = False,
    projection_status: str = "enforced",
    directive_base: str | None = None,
    updated_at: str = "2026-08-20T00:00:00Z",
    archived_prior_work: str | list[str] | None = None,
    commit_archives: bool = False,
    active_slice_id: str = "BL-FIXTURE",
    active_problems_ids: tuple[str, ...] | None = None,
    active_slice_status: str = "active",
    active_slice_decision: str = "Keep the fixture bounded.",
    active_slice_work: str = "Render and validate the fixture.",
    prior_work_entries: tuple[str, ...] = (),
    known_next_action_policy: str = "execute_bounded_local_milestone_without_scope_expansion",
    resource_pressure_policy: str = "throttle_or_stop_with_safe_handoff",
    safe_boundary_handoff: str = "required",
) -> dict[str, str]:
    canonical_header = canonical_line or (
        f"**Canonical:** branch `{branch}`; the exact canonical head is derived "
        "from Git at validation time (last observed "
        f"`{canonical_observed}` as a typed historical observation)\n"
    )
    review_line = (
        f"**Review Branch:** `{review_branch}` (head derived from the branch ref at validation time)\n"
        if review_branch is not None
        else ""
    )
    control_line = (
        f"**Control Head:** `{control}` (typed-head policy/validator binding)\n"
        if control is not None
        else ""
    )
    status = (
        "# Status\n"
        "\n"
        f"{canonical_header}"
        f"{review_line}"
        f"**Behavioural Head:** `{behavioural}` (state binding: state_only_descendant)\n"
        f"{control_line}"
        "\n"
        "Phase: operating;\n"
        "\n"
        "## Current truth\n"
        "\n"
        f"{status_body}"
    )
    next_actions = (
        "# NEXT_ACTIONS\n"
        "\n"
        "**Max Items:** 4\n"
        "\n"
        "## P1 Some work\n"
        "\n"
        f"{next_actions_body}"
        "\n"
        "## Completed since last update (2026-07-22)\n"
        "\n"
        "- historical notes.\n"
    )
    incidents_block = ""
    if incident:
        incidents_block = (
            "incidents:\n"
            '  - id: "INC-2026-07-21-RELEASE-FREEZE-P0"\n'
            f"    status: {incident_status}\n"
        )
        if duplicate_incident:
            incidents_block += (
                '  - id: "INC-2026-07-22-RELEASE-FREEZE-P0-DUPLICATE"\n'
                f"    status: {incident_status}\n"
            )
    review_block = "  review:\n"
    if review_status is not None:
        review_block += f"    status: {review_status}\n"
    if review_branch is not None:
        review_block += f"    branch: {review_branch}\n"
    control_field = f"    controlHead: {control}\n" if control is not None else ""
    metadata_block = (
        "metadata:\n"
        f'  updated_at: "{updated_at}"\n'
        if projection_workflow
        else ""
    )
    workflow_projection_fields = (
        "  statedd_mode: operating\n"
        "  release_status: fixture_release_status\n"
        if projection_workflow
        else ""
    )
    directive_block = (
        "owner_directive:\n"
        "  id: OD-FIXTURE\n"
        "  status: active\n"
        "  objective: validate_canonical_state_projection\n"
        "  scope:\n"
        "    prohibitedChanges:\n"
        "      - publication\n"
        "  authority:\n"
        "    J1Implementation: authorized_source_only\n"
        "    heavyOperations: not_authorized\n"
        if projection_workflow
        else ""
    )
    if directive_base is not None:
        directive_block += (
            "  base:\n"
            f"    stateportHead: {directive_base}\n"
        )
    projection_block = (
        "  release:\n"
        "    publishedVersion: 0.0.0-fixture\n"
        "    supportTier: unvalidated\n"
        "    installerReady: false\n"
        "    ownerAccepted: false\n"
        "    signedTargetId: fixture-target\n"
        f"    canonicalSourceCommit: {behavioural}\n"
        "    releaseIndexSha256: fixture-index\n"
        "    ownerInstallReceipt: absent\n"
        "    cleanInstallReceipt: absent\n"
        "  evidence:\n"
        "    alpha9PrivateStatus: inadmissible\n"
        "    releaseContract: docs/release/RELEASE_CONTRACT.yaml\n"
        "  stateWorkflow:\n"
        f"    formatVersion: {vsc.STATE_WORKFLOW_FORMAT}\n"
        "    canonicalCurrentState: PROJECT_STATE.yaml\n"
        "    projections:\n"
        "      status: STATUS.md\n"
        "      nextActions: NEXT_ACTIONS.md\n"
        "    history:\n"
        "      - WORKLOG.md\n"
        "      - docs/EVIDENCE_LOG.md\n"
        "      - docs/history/state/\n"
        f"    status: {projection_status}\n"
        "    stateOnlyReconciliationBudget: one_per_completed_vertical_slice\n"
        "    releaseContractSummary: All fixture release requirements remain binding.\n"
        "    activeSlice:\n"
        f"      id: {active_slice_id}\n"
        "      priority: P0\n"
        "      title: Validate fixture projection\n"
        f"      status: {active_slice_status}\n"
        "      authorityKey: J1Implementation\n"
        "      summary: Fixture projection is active.\n"
        f"      decision: {active_slice_decision}\n"
        f"      work: {active_slice_work}\n"
        "      exit: Exact projections pass.\n"
        if projection_workflow
        else ""
    )
    prior_work_block = "  priorWork:\n" "    indexStatus: loaded\n"
    if prior_work_entries:
        prior_work_block += "    entries:\n"
        for entry_id in prior_work_entries:
            missing_artifact = (
                "J2_receipt" if entry_id == "phase0_full_j1" else "phase0_receipt"
            )
            prior_work_block += (
                f"      - {{id: {entry_id}, question: did_{entry_id}, "
                f"verdict: yes_{entry_id}_passed, evidence: [receipt/{entry_id}.json], "
                "validity: exact_fixture_evidence, changedPrecondition: "
                f"{entry_id}_closed, missingArtifact: {missing_artifact}}}\n"
            )
    else:
        prior_work_block += "    entries: []\n"
    if archived_prior_work is not None:
        prior_work_block += "    archivedPriorWork:\n"
        if isinstance(archived_prior_work, str):
            prior_work_block += f"      archive: {archived_prior_work}\n"
        else:
            prior_work_block += "      archive:\n"
            for value in archived_prior_work:
                prior_work_block += f"        - {value}\n"
    problems_block = ""
    if active_problems_ids is not None:
        problems_block = "active_problems:\n"
        for problem_id in active_problems_ids:
            problems_block += f"  - {{id: {problem_id}, status: open}}\n"
    extra_files: dict[str, str] = {}
    if commit_archives and archived_prior_work is not None:
        archive_values = (
            [archived_prior_work]
            if isinstance(archived_prior_work, str)
            else list(archived_prior_work)
        )
        for value in archive_values:
            extra_files[value] = "# rotated fixture archive\n"
    projection_tail = (
        "known_limits:\n"
        "  - fixture_limit\n"
        "project:\n"
        "  phase: operating\n"
        if projection_workflow
        else ""
    )
    project_state = (
        f"{metadata_block}"
        "workflow:\n"
        f"{workflow_projection_fields}"
        f"  release_freeze: {release_freeze}\n"
        f"{incidents_block}"
        f"{directive_block}"
        "current_state:\n"
        "  repository:\n"
        f"    canonicalBranch: {branch}\n"
        "    canonicalHeadObserved:\n"
        f"      commit: {canonical_observed}\n"
        '      observedAt: "2026-07-25"\n'
        "      classification: historical_observation\n"
        f"{review_block}"
        "  stateBinding:\n"
        f"    behaviouralHead: {behavioural}\n"
        f"{control_field}"
        f"    reconciliationPolicy: {policy}\n"
        "  executionControls:\n"
        "    activePriority: fixture_delivery\n"
        "    ownerPromptPolicy: human_only\n"
        f"    knownNextActionPolicy: {known_next_action_policy}\n"
        "    technicalFailurePolicy: one_bounded_correction_then_handoff\n"
        f"    resourcePressurePolicy: {resource_pressure_policy}\n"
        f"    safeBoundaryHandoff: {safe_boundary_handoff}\n"
        "    stateBeforeKnownAction: required_at_phase_boundary\n"
        "    stateReconciliationPolicy: once_at_phase_boundary\n"
        "    diagnosticRerunPolicy: one_bounded_correction_only\n"
        "    reportPolicy: report_at_phase_boundary_or_human_only_gate\n"
        "    swapOccupancyPolicy: warning_only\n"
        "    hostAuthenticationDependency: forbidden_for_resource_admission\n"
        "    maxHeavyOperationsConcurrent: 1\n"
        "    priorWorkLookupRequired: true\n"
        "    equivalentInvestigationRerunPolicy: material_delta_only\n"
        "    unknownCauseHeavyRetryLimit: 0\n"
        "    heavyRerunRequiresIsolatedProof: true\n"
        "    phaseTransitionRequiresEvidenceIndex: true\n"
        "    latestOwnerPriorityWins: true\n"
        "    toolInvocationCorrectionLimit: 1\n"
        "    installerReadinessRequiresExactTargetPublicReceipt: true\n"
        "    imageRebuildRequiresInvalidatedDependencyEdge: true\n"
        f"{prior_work_block}"
        f"{projection_block}"
        f"{projection_tail}"
    )
    project_state = project_state + problems_block
    if projection_workflow:
        parsed = vsc.parse_yaml_text(project_state)
        assert isinstance(parsed, dict)
        rendered = vsc.render_current_state_projections(parsed, project_state)
        status = rendered["STATUS.md"]
        next_actions = rendered["NEXT_ACTIONS.md"]
    return {
        "STATUS.md": status,
        "NEXT_ACTIONS.md": next_actions,
        "PROJECT_STATE.yaml": project_state,
        **extra_files,
    }


def make_repo(tmp_path: Path, **state_kwargs: str) -> tuple[Path, str]:
    """main with one behavioural commit; review branch with committed state files.

    Returns (repo_root, main_sha). The state files name main as the canonical
    branch and main_sha as the behavioural head, so the fixture passes by
    default. State files are always committed and tracked.
    """
    root = tmp_path / "repo"
    root.mkdir(parents=True)
    _git(root, "init", "-b", "main")
    main_sha = _commit_files(root, {"app.py": "print('v1')\n"}, "feat: base product")
    _git(root, "checkout", "-b", REVIEW_BRANCH)
    files = _state_files(
        behavioural=main_sha, canonical_observed=main_sha, **state_kwargs
    )
    _commit_files(root, files, "docs(state): bind state files")
    return root, main_sha


def rebind(root: Path, *, behavioural: str, **state_kwargs: str) -> str:
    """State-only follow-up commit that rebinds the supplied typed heads."""
    files = _state_files(behavioural=behavioural, **state_kwargs)
    return _commit_files(root, files, "docs(state): rebind typed heads")


def rule_ids(findings: list[vsc.Finding]) -> set[str]:
    return {finding.rule for finding in findings}


# ---------------------------------------------------------------------------
# Pass cases
# ---------------------------------------------------------------------------


def test_real_repo_has_only_pending_rebind_findings() -> None:
    """Until the state-only binding commit lands, the only allowed findings
    on the real repo are typed-head rebind findings over an authorized pending
    product or control slice; after reconciliation, no findings at all."""
    findings = vsc.validate_repo_state(ROOT)
    assert {finding.rule for finding in findings} <= {
        "stale-head",
        "stale-control-head",
        "reconciliation-budget",
        "canonical-ref-divergence",
    }, findings


def test_minimal_repo_passes(tmp_path: Path) -> None:
    root, _ = make_repo(tmp_path)
    assert vsc.validate_repo_state(root) == []


def test_canonical_state_projections_pass_and_drift_fails(tmp_path: Path) -> None:
    root = _projection_reconciliation_repo(tmp_path)
    assert vsc.validate_repo_state(root) == []
    status_text = (root / "STATUS.md").read_text(encoding="utf-8")
    assert "BL-FIXTURE" in status_text
    assert "All fixture release requirements remain binding." in status_text
    assert "Alpha.9" not in status_text
    next_text = (root / "NEXT_ACTIONS.md").read_text(encoding="utf-8")
    for sentence in (
        "Owner interaction: human-only.",
        "Only the current sealed phase executes automatically; scope expansion requires a new owner directive.",
        "Resource pressure is handled by throttling or a safe handoff.",
        "Swap occupancy alone never blocks execution.",
        "A safe-boundary handoff is required after each bounded phase.",
    ):
        assert sentence in status_text
        assert sentence in next_text

    status = root / "STATUS.md"
    status.write_text(status.read_text(encoding="utf-8") + "manual drift\n", encoding="utf-8")
    assert "projection-drift" in rule_ids(vsc.validate_repo_state(root))

    assert vsc.materialize_current_state_projections(root) == (
        "STATUS.md",
        "NEXT_ACTIONS.md",
    )
    assert vsc.validate_repo_state(root) == []


def test_projection_write_refuses_invalid_canonical_anchors(tmp_path: Path) -> None:
    root = _projection_reconciliation_repo(tmp_path)
    status_before = (root / "STATUS.md").read_bytes()
    state_path = root / "PROJECT_STATE.yaml"
    state_path.write_text(
        state_path.read_text(encoding="utf-8").replace(
            "  release_freeze: false\n", "  release_freeze: true\n"
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="freeze-incident-closed"):
        vsc.materialize_current_state_projections(root)

    assert (root / "STATUS.md").read_bytes() == status_before


def test_projection_write_rolls_back_a_partial_replace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _projection_reconciliation_repo(tmp_path)
    before = {
        name: (root / name).read_bytes() for name in ("STATUS.md", "NEXT_ACTIONS.md")
    }
    real_replace = Path.replace

    def fail_next_actions(source: Path, target: Path) -> Path:
        if target.name == "NEXT_ACTIONS.md" and ".rollback." not in source.name:
            raise OSError("simulated projection replace failure")
        return real_replace(source, target)

    monkeypatch.setattr(Path, "replace", fail_next_actions)
    with pytest.raises(OSError, match="simulated projection replace failure"):
        vsc.materialize_current_state_projections(root)

    assert {
        name: (root / name).read_bytes() for name in ("STATUS.md", "NEXT_ACTIONS.md")
    } == before


def test_projection_workflow_cannot_disable_enforcement(tmp_path: Path) -> None:
    root = _projection_reconciliation_repo(tmp_path)
    state_path = root / "PROJECT_STATE.yaml"
    state_path.write_text(
        state_path.read_text(encoding="utf-8").replace(
            "    status: enforced\n", "    status: implementation_active\n"
        ),
        encoding="utf-8",
    )
    assert "state-workflow-contract" in rule_ids(vsc.validate_repo_state(root))


def test_project_dna_requires_canonical_state_workflow(tmp_path: Path) -> None:
    root, _ = make_repo(tmp_path)
    (root / "PROJECT_DNA.yaml").write_text("project: fixture\n", encoding="utf-8")
    assert "state-workflow-anchor" in rule_ids(vsc.validate_repo_state(root))


def _projection_reconciliation_repo(tmp_path: Path, **state_kwargs: str) -> Path:
    root = tmp_path / "projection-repo"
    root.mkdir(parents=True)
    _git(root, "init", "-b", "main")
    behavioural = _commit_files(root, {"app.py": "print('v1')\n"}, "feat: product")
    control = _commit_files(
        root,
        {"scripts/validate_state_consistency.py": "# control\n"},
        "feat(control): policy",
    )
    files = _state_files(
        behavioural=behavioural,
        control=control,
        review_branch=None,
        review_status="closed",
        canonical_observed=behavioural,
        projection_workflow=True,
        projection_status="enforced",
        **state_kwargs,
    )
    _commit_files(root, files, "docs(state): reconcile completed slice")
    return root


def test_completed_slice_has_one_final_reconciliation(tmp_path: Path) -> None:
    root = _projection_reconciliation_repo(tmp_path)
    assert vsc.validate_repo_state(root) == []


def test_bounded_local_override_projects_required_safe_handoff(tmp_path: Path) -> None:
    root = _projection_reconciliation_repo(
        tmp_path,
        known_next_action_policy="execute_bounded_local_milestone_without_scope_expansion",
        resource_pressure_policy="throttle_or_stop_with_safe_handoff",
        safe_boundary_handoff="required",
    )
    status_text = (root / "STATUS.md").read_text(encoding="utf-8")
    next_text = (root / "NEXT_ACTIONS.md").read_text(encoding="utf-8")
    for sentence in (
        "Only the current sealed phase executes automatically; scope expansion requires a new owner directive.",
        "Resource pressure is handled by throttling or a safe handoff.",
        "A safe-boundary handoff is required after each bounded phase.",
    ):
        assert sentence in status_text
        assert sentence in next_text
    assert "Safe-boundary handoffs are forbidden." not in status_text
    assert "Safe-boundary handoffs are forbidden." not in next_text
    assert vsc.validate_repo_state(root) == []


def test_second_state_only_commit_exceeds_reconciliation_budget(tmp_path: Path) -> None:
    root = _projection_reconciliation_repo(tmp_path)
    _commit_files(
        root,
        {"STATUS.md": "second reconciliation\n"},
        "docs(state): rewrite canonical projection again",
    )
    assert "reconciliation-budget" in rule_ids(vsc.validate_repo_state(root))


def test_ledger_only_bookkeeping_after_a_reconciliation_is_not_churn(
    tmp_path: Path,
) -> None:
    root = _projection_reconciliation_repo(tmp_path)
    _commit_files(root, {"WORKLOG.md": "slice bookkeeping\n"}, "docs(state): worklog entry")
    assert vsc.validate_repo_state(root) == []


def _directive_base_slice_repo(
    tmp_path: Path,
    *,
    second_product: str,
    extra_churn: bool = False,
    in_flight_checkpoints: int = 0,
) -> Path:
    """Directive-base fixture closing two vertical outcomes under OD-FIXTURE."""
    root = tmp_path / "directive-budget-repo"
    root.mkdir(parents=True)
    _git(root, "init", "-b", "main")
    behavioural1 = _commit_files(root, {"app.py": "print('v1')\n"}, "feat: product one")
    control = _commit_files(
        root,
        {"scripts/validate_state_consistency.py": "# control\n"},
        "feat(control): policy",
    )
    files = _state_files(
        behavioural=behavioural1,
        control=control,
        review_branch=None,
        review_status="closed",
        canonical_observed=behavioural1,
        projection_workflow=True,
        projection_status="enforced",
        directive_base=behavioural1,
    )
    _commit_files(root, files, "docs(state): reconcile slice one")
    for index in range(in_flight_checkpoints):
        checkpoint = _state_files(
            behavioural=behavioural1,
            control=control,
            review_branch=None,
            review_status="closed",
            canonical_observed=behavioural1,
            projection_workflow=True,
            projection_status="enforced",
            directive_base=behavioural1,
            active_slice_status="fixture_in_flight",
            updated_at=f"2026-08-20T00:{index + 1:02d}:00Z",
        )
        _commit_files(
            root,
            checkpoint,
            f"docs(state): record in-flight checkpoint {index + 1}",
        )
    if extra_churn:
        _commit_files(root, {"STATUS.md": "churn\n"}, "docs(state): canonical churn")
    behavioural2 = _commit_files(root, {"app.py": second_product}, "feat: product two")
    files2 = _state_files(
        behavioural=behavioural2,
        control=control,
        review_branch=None,
        review_status="closed",
        canonical_observed=behavioural2,
        projection_workflow=True,
        projection_status="enforced",
        directive_base=behavioural1,
    )
    _commit_files(root, files2, "docs(state): reconcile slice two")
    return root


def test_directive_base_allows_one_reconciliation_per_vertical_outcome(
    tmp_path: Path,
) -> None:
    root = _directive_base_slice_repo(tmp_path, second_product="print('v2')\n")
    assert vsc.validate_repo_state(root) == []


def test_consecutive_state_only_commits_exceed_directive_base_budget(
    tmp_path: Path,
) -> None:
    root = _directive_base_slice_repo(
        tmp_path, second_product="print('v3')\n", extra_churn=True
    )
    assert "reconciliation-budget" in rule_ids(vsc.validate_repo_state(root))


def _evidence_only_phase_transition_repo(
    tmp_path: Path,
    *,
    advance_queue: bool = True,
    add_evidence: bool = True,
    rewrite_existing_evidence: bool = False,
    rewrite_unrelated_state: bool = False,
    in_flight: bool = False,
    inject_unknown_evidence_field: bool = False,
    malformed_new_evidence: bool = False,
    incoherent_next_gate: bool = False,
    quoted_empty_evidence: bool = False,
    null_new_evidence_id: bool = False,
    negative_closure: bool = False,
    queue_token_collision: bool = False,
    malformed_active_problem: bool = False,
    omit_pending_delimiter: bool = False,
    split_old_gate_across_fields: bool = False,
    punctuation_only_gate_change: bool = False,
) -> Path:
    root = tmp_path / "evidence-phase-repo"
    root.mkdir(parents=True)
    _git(root, "init", "-b", "main")
    behavioural = _commit_files(root, {"app.py": "print('v1')\n"}, "feat: product")
    control = _commit_files(
        root,
        {"scripts/validate_state_consistency.py": "# control\n"},
        "feat(control): policy",
    )
    initial = _state_files(
        behavioural=behavioural,
        control=control,
        review_branch=None,
        review_status="closed",
        canonical_observed=behavioural,
        projection_workflow=True,
        projection_status="enforced",
        directive_base=behavioural,
        active_problems_ids=("BL-FIXTURE",),
        active_slice_status=(
            "candidate_assembled__phase0_in_flight"
            if in_flight
            else (
                "candidate_assembled_phase0_pending"
                if omit_pending_delimiter
                else "candidate_assembled__phase0_pending"
            )
        ),
        active_slice_decision="Run candidate-bound Phase 0.",
        active_slice_work="Phase 0 then full J1.",
        prior_work_entries=("candidate_assembly",),
    )
    if split_old_gate_across_fields:
        initial["PROJECT_STATE.yaml"] = initial["PROJECT_STATE.yaml"].replace(
            "__phase0_pending", "__full_J1_pending", 1
        )
    if punctuation_only_gate_change:
        initial["PROJECT_STATE.yaml"] = initial["PROJECT_STATE.yaml"].replace(
            "__phase0_pending", "__J2_pending", 1
        )
    _commit_files(root, initial, "docs(state): record candidate assembly")

    transitioned = _state_files(
        behavioural=behavioural,
        control=control,
        review_branch=None,
        review_status="closed",
        canonical_observed=behavioural,
        projection_workflow=True,
        projection_status="enforced",
        directive_base=behavioural,
        updated_at="2026-08-20T01:00:00Z",
        active_problems_ids=("BL-FIXTURE",),
        active_slice_status=(
            "phase0_and_full_j1_passed__J2_in_flight"
            if in_flight
            else (
                (
                    "phase0_and_full_j1_passed_J2_pending"
                    if omit_pending_delimiter
                    else "phase0_and_full_j1_passed__J2_pending"
                )
                if advance_queue
                else "candidate_assembled__phase0_pending"
            )
        ),
        active_slice_decision=(
            "Run an unrelated gate."
            if incoherent_next_gate
            else (
                "Run J20 template upgrade."
                if queue_token_collision
                else (
                    "Run J2 template upgrade."
                    if advance_queue or in_flight
                    else "Run candidate-bound Phase 0."
                )
            )
        ),
        active_slice_work=(
            "An unrelated gate remains."
            if incoherent_next_gate
            else (
                "J20 then remaining journeys."
                if queue_token_collision
                else (
                    "J2 then remaining journeys."
                    if advance_queue or in_flight
                    else "Phase 0 then full J1."
                )
            )
        ),
        prior_work_entries=(
            ("candidate_assembly", "phase0_full_j1")
            if add_evidence
            else ("candidate_assembly",)
        ),
    )
    if rewrite_existing_evidence:
        transitioned["PROJECT_STATE.yaml"] = transitioned["PROJECT_STATE.yaml"].replace(
            "verdict: yes_candidate_assembly_passed",
            "verdict: yes_candidate_assembly_rewritten",
            1,
        )
    if quoted_empty_evidence:
        transitioned["PROJECT_STATE.yaml"] = transitioned["PROJECT_STATE.yaml"].replace(
            "evidence: [receipt/phase0_full_j1.json]",
            'evidence: [""]',
            1,
        )
    if null_new_evidence_id:
        transitioned["PROJECT_STATE.yaml"] = transitioned["PROJECT_STATE.yaml"].replace(
            "- {id: phase0_full_j1",
            "- {id: null",
            1,
        )
    if negative_closure:
        transitioned["PROJECT_STATE.yaml"] = transitioned["PROJECT_STATE.yaml"].replace(
            "changedPrecondition: phase0_full_j1_closed",
            "changedPrecondition: phase0_not_closed",
            1,
        )
    if malformed_active_problem:
        transitioned["PROJECT_STATE.yaml"] = transitioned["PROJECT_STATE.yaml"].replace(
            "- {id: BL-FIXTURE, status: open}",
            "- id: BL-FIXTURE",
            1,
        )
    if split_old_gate_across_fields:
        transitioned["PROJECT_STATE.yaml"] = transitioned["PROJECT_STATE.yaml"].replace(
            "question: did_phase0_full_j1",
            "question: did_full",
            1,
        ).replace(
            "changedPrecondition: phase0_full_j1_closed",
            "changedPrecondition: J1_closed",
            1,
        )
    if punctuation_only_gate_change:
        transitioned["PROJECT_STATE.yaml"] = transitioned["PROJECT_STATE.yaml"].replace(
            "__J2_pending", "__J2!_pending", 1
        ).replace(
            "question: did_phase0_full_j1",
            "question: did_J2",
            1,
        ).replace(
            "changedPrecondition: phase0_full_j1_closed",
            "changedPrecondition: J2_closed",
            1,
        )
    if inject_unknown_evidence_field:
        transitioned["PROJECT_STATE.yaml"] = transitioned["PROJECT_STATE.yaml"].replace(
            "- {id: candidate_assembly",
            "- {note: altered, id: candidate_assembly",
            1,
        )
    if malformed_new_evidence:
        transitioned["PROJECT_STATE.yaml"] = transitioned["PROJECT_STATE.yaml"].replace(
            "evidence: [receipt/phase0_full_j1.json]",
            "evidence: [,]",
            1,
        )
    if rewrite_unrelated_state:
        transitioned["PROJECT_STATE.yaml"] = transitioned["PROJECT_STATE.yaml"].replace(
            "activePriority: fixture_delivery",
            "activePriority: unrelated_rewrite",
            1,
        )
    _commit_files(root, transitioned, "docs(state): record evidence-only phase transition")
    return root


def test_evidence_indexed_phase_transition_is_not_reconciliation_churn(
    tmp_path: Path,
) -> None:
    root = _evidence_only_phase_transition_repo(tmp_path)
    assert vsc.validate_repo_state(root) == []


def test_phase_transition_without_new_evidence_remains_reconciliation_churn(
    tmp_path: Path,
) -> None:
    root = _evidence_only_phase_transition_repo(tmp_path, add_evidence=False)
    assert "reconciliation-budget" in rule_ids(vsc.validate_repo_state(root))


def test_new_evidence_without_queue_progress_remains_reconciliation_churn(
    tmp_path: Path,
) -> None:
    root = _evidence_only_phase_transition_repo(tmp_path, advance_queue=False)
    assert "reconciliation-budget" in rule_ids(vsc.validate_repo_state(root))


def test_phase_transition_cannot_rewrite_existing_evidence(tmp_path: Path) -> None:
    root = _evidence_only_phase_transition_repo(tmp_path, rewrite_existing_evidence=True)
    assert "reconciliation-budget" in rule_ids(vsc.validate_repo_state(root))


def test_phase_transition_cannot_rewrite_unrelated_state(tmp_path: Path) -> None:
    root = _evidence_only_phase_transition_repo(tmp_path, rewrite_unrelated_state=True)
    assert "reconciliation-budget" in rule_ids(vsc.validate_repo_state(root))


def test_evidence_does_not_exempt_repeated_in_flight_checkpoints(tmp_path: Path) -> None:
    root = _evidence_only_phase_transition_repo(tmp_path, in_flight=True)
    assert "reconciliation-budget" in rule_ids(vsc.validate_repo_state(root))


def test_phase_transition_rejects_unknown_evidence_fields(tmp_path: Path) -> None:
    root = _evidence_only_phase_transition_repo(
        tmp_path, inject_unknown_evidence_field=True
    )
    assert "reconciliation-budget" in rule_ids(vsc.validate_repo_state(root))


def test_phase_transition_rejects_malformed_evidence_list(tmp_path: Path) -> None:
    root = _evidence_only_phase_transition_repo(tmp_path, malformed_new_evidence=True)
    assert "reconciliation-budget" in rule_ids(vsc.validate_repo_state(root))


def test_phase_transition_requires_new_gate_in_queue_text(tmp_path: Path) -> None:
    root = _evidence_only_phase_transition_repo(tmp_path, incoherent_next_gate=True)
    assert "reconciliation-budget" in rule_ids(vsc.validate_repo_state(root))


def test_phase_transition_rejects_quoted_empty_evidence(tmp_path: Path) -> None:
    root = _evidence_only_phase_transition_repo(tmp_path, quoted_empty_evidence=True)
    assert "reconciliation-budget" in rule_ids(vsc.validate_repo_state(root))


def test_phase_transition_rejects_null_evidence_id(tmp_path: Path) -> None:
    root = _evidence_only_phase_transition_repo(tmp_path, null_new_evidence_id=True)
    assert "reconciliation-budget" in rule_ids(vsc.validate_repo_state(root))


def test_phase_transition_rejects_negative_closure_wording(tmp_path: Path) -> None:
    root = _evidence_only_phase_transition_repo(tmp_path, negative_closure=True)
    assert "reconciliation-budget" in rule_ids(vsc.validate_repo_state(root))


def test_phase_transition_rejects_gate_token_collision(tmp_path: Path) -> None:
    root = _evidence_only_phase_transition_repo(tmp_path, queue_token_collision=True)
    assert "reconciliation-budget" in rule_ids(vsc.validate_repo_state(root))


def test_phase_transition_rejects_malformed_active_problem(tmp_path: Path) -> None:
    root = _evidence_only_phase_transition_repo(tmp_path, malformed_active_problem=True)
    newer, older = _git(root, "rev-list", "--max-count=2", "HEAD").splitlines()
    assert not vsc._is_evidence_indexed_phase_transition(root, older, newer)
    assert vsc.validate_repo_state(root)


def test_phase_transition_requires_terminal_gate_delimiter(tmp_path: Path) -> None:
    root = _evidence_only_phase_transition_repo(tmp_path, omit_pending_delimiter=True)
    assert "reconciliation-budget" in rule_ids(vsc.validate_repo_state(root))


def test_phase_transition_does_not_join_old_gate_across_evidence_fields(
    tmp_path: Path,
) -> None:
    root = _evidence_only_phase_transition_repo(
        tmp_path, split_old_gate_across_fields=True
    )
    assert "reconciliation-budget" in rule_ids(vsc.validate_repo_state(root))


def test_phase_transition_rejects_punctuation_only_gate_change(tmp_path: Path) -> None:
    root = _evidence_only_phase_transition_repo(
        tmp_path, punctuation_only_gate_change=True
    )
    assert "reconciliation-budget" in rule_ids(vsc.validate_repo_state(root))


def test_pure_history_rotation_may_follow_a_reconciliation(tmp_path: Path) -> None:
    """Hygiene-mandated archive rotation is not reconciliation churn."""
    root = _directive_base_slice_repo(tmp_path, second_product="print('v4')\n")
    _commit_files(
        root,
        {"docs/history/state/WORKLOG-2026-01-01.md": "# archived\n"},
        "history: rotate worklog entries to the dated archive",
    )
    assert vsc.validate_repo_state(root) == []


def test_in_flight_checkpoint_is_not_reconciliation_churn(tmp_path: Path) -> None:
    root = _directive_base_slice_repo(
        tmp_path,
        second_product="print('v4')\n",
        in_flight_checkpoints=1,
    )
    assert vsc.validate_repo_state(root) == []


def test_consecutive_in_flight_checkpoints_remain_reconciliation_churn(
    tmp_path: Path,
) -> None:
    root = _directive_base_slice_repo(
        tmp_path,
        second_product="print('v5')\n",
        in_flight_checkpoints=2,
    )
    assert "reconciliation-budget" in rule_ids(vsc.validate_repo_state(root))


def test_missing_execution_controls_fail(tmp_path: Path) -> None:
    root, _ = make_repo(tmp_path)
    path = root / "PROJECT_STATE.yaml"
    text = path.read_text(encoding="utf-8")
    text = re.sub(r"  executionControls:\n(?:    .*\n)+", "", text)
    path.write_text(text, encoding="utf-8")
    assert "execution-control-anchor" in rule_ids(vsc.validate_repo_state(root))


def test_unknown_cause_heavy_retry_fails(tmp_path: Path) -> None:
    root, _ = make_repo(tmp_path)
    path = root / "PROJECT_STATE.yaml"
    text = path.read_text(encoding="utf-8").replace(
        "    unknownCauseHeavyRetryLimit: 0\n",
        "    unknownCauseHeavyRetryLimit: 1\n",
    )
    path.write_text(text, encoding="utf-8")
    assert "execution-control-anchor" in rule_ids(vsc.validate_repo_state(root))


def test_active_public_release_requires_uninterrupted_execution_contract(tmp_path: Path) -> None:
    root = _projection_reconciliation_repo(tmp_path)
    path = root / "PROJECT_STATE.yaml"
    text = path.read_text(encoding="utf-8").replace(
        "  id: OD-FIXTURE\n", "  id: PUBLIC-RELEASE-TEST\n"
    ).replace(
        "  status: active\n", "  status: active_until_public_release_ready_or_explicitly_superseded\n", 1
    ).replace(
        "    safeBoundaryHandoff: required\n", "    safeBoundaryHandoff: forbidden\n"
    )
    path.write_text(text, encoding="utf-8")
    assert "execution-control-anchor" in rule_ids(vsc.validate_repo_state(root))
    assert "owner-directive-anchor" in rule_ids(vsc.validate_repo_state(root))


def test_image_rebuild_dependency_edge_control_is_required(tmp_path: Path) -> None:
    root, _ = make_repo(tmp_path)
    path = root / "PROJECT_STATE.yaml"
    text = path.read_text(encoding="utf-8").replace(
        "    imageRebuildRequiresInvalidatedDependencyEdge: true\n", ""
    )
    path.write_text(text, encoding="utf-8")
    assert "execution-control-anchor" in rule_ids(vsc.validate_repo_state(root))


def _enable_installer(root: Path, *, receipt_overrides: dict[str, str] | None = None) -> None:
    values = {
        "status": "succeeded",
        "transport": "anonymous_public_command",
        "runtime": "windows11-wsl2-ubuntu2404",
        "staged": "false",
        "shimmed": "false",
        "version": "0.1.0-alpha.7",
        "releaseIndexSha256": "a" * 64,
        "signedPayloadDigest": "sha256:" + "b" * 64,
        "sourceCommit": "c" * 40,
        "sourceTree": "d" * 40,
        "bootstrapSha256": "e" * 64,
        "path": "receipts/alpha7-public-install.json",
    }
    values.update(receipt_overrides or {})
    lines = [
        "  release:",
        "    publishedVersion: 0.1.0-alpha.7",
        "    installation_enabled: true",
        f"    releaseIndexSha256: {'a' * 64}",
        f"    signedPayloadDigest: sha256:{'b' * 64}",
        f"    canonicalSourceCommit: {'c' * 40}",
        f"    canonicalSourceTree: {'d' * 40}",
        f"    bootstrapSha256: {'e' * 64}",
        "    exactTargetReceipt:",
    ]
    lines.extend(f"      {key}: {value}" for key, value in values.items())
    path = root / "PROJECT_STATE.yaml"
    path.write_text(path.read_text(encoding="utf-8") + "\n" + "\n".join(lines) + "\n", encoding="utf-8")


def test_installer_enablement_requires_exact_public_target_receipt(tmp_path: Path) -> None:
    root, _ = make_repo(tmp_path)
    _enable_installer(root, receipt_overrides={"transport": "staged_rehearsal"})
    assert "installer-readiness-receipt" in rule_ids(vsc.validate_repo_state(root))


def test_installer_enablement_accepts_exact_public_target_receipt(tmp_path: Path) -> None:
    root, _ = make_repo(tmp_path)
    _enable_installer(root)
    assert "installer-readiness-receipt" not in rule_ids(vsc.validate_repo_state(root))


def test_state_only_descendant_passes(tmp_path: Path) -> None:
    """behaviouralHead ancestor + state-only commits since -> pass."""
    root, main_sha = make_repo(tmp_path)
    _commit_files(
        root,
        {"WORKLOG.md": "history entry\n", "docs/EVIDENCE_LOG.md": "evidence\n"},
        "docs(state): append-only history update",
    )
    rebind(root, behavioural=main_sha)
    assert vsc.validate_repo_state(root) == []


def test_dated_state_archive_descendant_passes(tmp_path: Path) -> None:
    """A narrowly named dated state rotation remains state-only authority."""
    root, main_sha = make_repo(tmp_path)
    _commit_files(
        root,
        {
            "docs/history/state/WORKLOG-2026-07-29.md": "rotated history\n",
            "docs/history/state/EVIDENCE_LOG-2026-07-29-alpha5.md": "release evidence\n",
        },
        "docs(state): rotate dated worklog",
    )
    rebind(root, behavioural=main_sha)
    assert vsc.validate_repo_state(root) == []


def test_arbitrary_state_history_path_does_not_gain_authority(tmp_path: Path) -> None:
    """The archive directory is not a blanket state-only allowlist."""
    root, _ = make_repo(tmp_path)
    _commit_files(
        root,
        {"docs/history/state/NOTES-2026-07-29.md": "not a typed state archive\n"},
        "docs: add arbitrary history note",
    )
    findings = vsc.validate_repo_state(root)
    assert "stale-head" in rule_ids(findings), findings


def test_dual_behavioural_and_control_heads_pass(tmp_path: Path) -> None:
    """Product and typed-head protocol commits bind independently."""
    root, behavioural = make_repo(tmp_path)
    control = _commit_files(
        root,
        {"AGENTS.md": "typed-head control contract\n"},
        "chore(control): update typed-head contract",
    )
    rebind(root, behavioural=behavioural, control=control)
    assert vsc.validate_repo_state(root) == []


def test_product_after_control_passes_when_behavioural_head_is_rebound(
    tmp_path: Path,
) -> None:
    """Product changes do not stale an independently bound control head."""
    root, _ = make_repo(tmp_path)
    control = _commit_files(
        root,
        {"AGENTS.md": "typed-head control contract\n"},
        "chore(control): update typed-head contract",
    )
    behavioural = _commit_files(
        root,
        {"feature.py": "print('new behaviour')\n"},
        "feat: add newer product behaviour",
    )
    rebind(root, behavioural=behavioural, control=control)
    assert vsc.validate_repo_state(root) == []


def test_normal_merge_with_state_only_descendant_passes(tmp_path: Path) -> None:
    """Behavioural branch merged normally; state-only descendant after -> pass."""
    root, _ = make_repo(tmp_path)
    _git(root, "checkout", "-b", "feat", "main")
    feature_sha = _commit_files(root, {"feature.py": "print('f')\n"}, "feat: work")
    _git(root, "checkout", REVIEW_BRANCH)
    _git(root, "merge", "--no-ff", "-m", "merge feat", "feat")
    rebind(root, behavioural=feature_sha)
    assert vsc.validate_repo_state(root) == []


def test_post_merge_state_only_reconciliation_passes(tmp_path: Path) -> None:
    """A further state-only reconciliation commit after the merge still passes."""
    root, _ = make_repo(tmp_path)
    _git(root, "checkout", "-b", "feat", "main")
    feature_sha = _commit_files(root, {"feature.py": "print('f')\n"}, "feat: work")
    _git(root, "checkout", REVIEW_BRANCH)
    _git(root, "merge", "--no-ff", "-m", "merge feat", "feat")
    rebind(root, behavioural=feature_sha)
    _commit_files(
        root, {"WORKLOG.md": "post-merge reconciliation\n"}, "docs(state): reconcile"
    )
    assert vsc.validate_repo_state(root) == []


def test_fast_forward_integration_passes(tmp_path: Path) -> None:
    """Fast-forward of the complete review line into main, ending with a
    state-only rebind on main -> pass (topology b)."""
    root, _ = make_repo(tmp_path)
    feature_sha = _commit_files(root, {"feature.py": "print('f')\n"}, "feat: work")
    rebind(root, behavioural=feature_sha)
    _git(root, "checkout", "main")
    _git(root, "merge", "--ff-only", REVIEW_BRANCH)
    _commit_files(
        root, {"WORKLOG.md": "post-ff reconciliation\n"}, "docs(state): reconcile on main"
    )
    assert vsc.validate_repo_state(root) == []


def test_merge_into_main_with_state_only_reconciliation_passes(tmp_path: Path) -> None:
    """The real acceptance sequence (topology a): product commit on the review
    branch, behavioural rebind, merge commit of the review branch INTO main,
    then a state-only reconciliation commit on main -> pass on the final main
    checkout with the canonical head derived from git."""
    root, _ = make_repo(tmp_path)
    feature_sha = _commit_files(root, {"feature.py": "print('f')\n"}, "feat: work")
    rebind(root, behavioural=feature_sha)
    _git(root, "checkout", "main")
    _git(root, "merge", "--no-ff", "-m", "merge review line into main", REVIEW_BRANCH)
    _commit_files(
        root,
        {"WORKLOG.md": "post-merge reconciliation\n"},
        "docs(state): reconcile on main",
    )
    assert _git(root, "branch", "--show-current") == "main"
    assert vsc.validate_repo_state(root) == []


def test_historical_scope_mentions_do_not_trigger(tmp_path: Path) -> None:
    root, _ = make_repo(
        tmp_path,
        status_body=(
            "All good.\n"
            "\n"
            "## Historical (2026-07-21, pre-merge) — old freeze\n"
            "\n"
            "At the time the release freeze was still active and main is frozen.\n"
            "The AI vertical was then unmerged.\n"
            "No current result is remotely merged.\n"
            "`agent/bl-ai-vertical-002` carried the work.\n"
            "\n"
            "### Historical — deeper detail\n"
            "\n"
            "This does not lift the freeze.\n"
        ),
        next_actions_body=(
            "Nothing contradicting.\n"
            "\n"
            "## Completed since last update (2026-07-22)\n"
            "\n"
            "- the release freeze is still active; main is frozen; the\n"
            "  AI vertical is unmerged; `agent/bl-ai-vertical-002` lives.\n"
        ),
    )
    assert vsc.validate_repo_state(root) == []


def test_annotated_deleted_branch_mentions_do_not_trigger(tmp_path: Path) -> None:
    root, _ = make_repo(
        tmp_path,
        status_body=(
            "- re-acceptance proceeds from closed-PR refs or a recut branch\n"
            "  (`agent/kimi-frontend-integration` and\n"
            "  `agent/acceptance-sidebar-mascot` were both deleted 2026-07-25).\n"
            "\n"
            "PR #11 merged into the deleted\n"
            "`agent/public-release-closure-001`.\n"
        ),
        next_actions_body=(
            "main was fast-forwarded to the reviewed\n"
            "`agent/bl-ai-vertical-002` line; PR #7 marked merged.\n"
        ),
    )
    assert vsc.validate_repo_state(root) == []


def test_historical_block_under_historical_heading_passes(tmp_path: Path) -> None:
    root, _ = make_repo(
        tmp_path,
        status_body=(
            "All good.\n"
            "\n"
            "### Historical containment record (kept as history)\n"
            "\n"
            "- Historical revert notes live here.\n"
        ),
    )
    assert vsc.validate_repo_state(root) == []


# ---------------------------------------------------------------------------
# Fail cases: text rules (freeze-language rules derive from the freeze flag;
# merge/branch/acceptance rules run regardless of it)
# ---------------------------------------------------------------------------


def test_freeze_active_rule_triggers(tmp_path: Path) -> None:
    root, _ = make_repo(
        tmp_path, status_body="The P0 platform release freeze is still active.\n"
    )
    assert "freeze-active" in rule_ids(vsc.validate_repo_state(root))


def test_truthful_active_freeze_passes(tmp_path: Path) -> None:
    """freeze: true + active incident + current text saying the freeze is
    still active is truthful and must pass."""
    root, _ = make_repo(
        tmp_path,
        release_freeze="true",
        incident_status="active",
        status_body=(
            "The P0 platform release freeze is still active and main is frozen.\n"
        ),
    )
    assert vsc.validate_repo_state(root) == []


def test_freeze_lifted_claim_rejected_when_freeze_true(tmp_path: Path) -> None:
    """When the freeze is genuinely active, current-scope text claiming it is
    lifted or thawed is rejected."""
    for index, body in enumerate(
        (
            "The release freeze is lifted.\n",
            "The platform freeze has been thawed.\n",
            "This directive lifted the release freeze.\n",
        )
    ):
        root, _ = make_repo(
            tmp_path / str(index),
            release_freeze="true",
            incident_status="active",
            status_body=body,
        )
        findings = vsc.validate_repo_state(root)
        assert "freeze-lifted-claim" in rule_ids(findings), (body, findings)


def test_merge_acceptance_rules_run_regardless_of_freeze(tmp_path: Path) -> None:
    """An active freeze must not disable the merge/branch/acceptance rules."""
    root, _ = make_repo(
        tmp_path,
        release_freeze="true",
        incident_status="active",
        status_body=(
            "The release freeze is still active.\n"
            "The AI vertical is currently unmerged.\n"
            "No current result is reviewed or merged.\n"
        ),
    )
    findings = rule_ids(vsc.validate_repo_state(root))
    assert "vertical-unmerged" in findings, findings
    assert "acceptance-not-merged" in findings, findings


def test_frozen_main_rule_triggers(tmp_path: Path) -> None:
    for index, body in enumerate(
        ("The frozen `main` line awaits review.\n", "Note: main is frozen.\n")
    ):
        root, _ = make_repo(tmp_path / str(index), status_body=body)
        findings = vsc.validate_repo_state(root)
        assert "frozen-main" in rule_ids(findings), (body, findings)


def test_freeze_not_lifted_rule_triggers(tmp_path: Path) -> None:
    root, _ = make_repo(
        tmp_path,
        next_actions_body="This evidence does not lift the release freeze.\n",
    )
    assert "freeze-not-lifted" in rule_ids(vsc.validate_repo_state(root))


def test_vertical_unmerged_rule_triggers(tmp_path: Path) -> None:
    root, _ = make_repo(
        tmp_path, status_body="The AI vertical is currently unmerged.\n"
    )
    assert "vertical-unmerged" in rule_ids(vsc.validate_repo_state(root))


def test_unmerged_without_vertical_context_does_not_trigger(tmp_path: Path) -> None:
    root, _ = make_repo(
        tmp_path, status_body="PR #8/#10 closed unmerged, archived elsewhere.\n"
    )
    assert "vertical-unmerged" not in rule_ids(vsc.validate_repo_state(root))


def test_previously_unmerged_now_merged_does_not_trigger(tmp_path: Path) -> None:
    root, _ = make_repo(
        tmp_path,
        status_body=(
            "The previously unmerged AI vertical is now merged.\n"
            "The AI vertical, then unmerged, was merged to `main` via PR #7.\n"
        ),
    )
    assert "vertical-unmerged" not in rule_ids(vsc.validate_repo_state(root))


def test_acceptance_not_merged_rule_triggers(tmp_path: Path) -> None:
    root, _ = make_repo(
        tmp_path, status_body="No current result is reviewed or merged.\n"
    )
    assert "acceptance-not-merged" in rule_ids(vsc.validate_repo_state(root))


def test_acceptance_not_merged_rule_is_case_insensitive(tmp_path: Path) -> None:
    root, _ = make_repo(
        tmp_path, status_body="no current result is remotely merged.\n"
    )
    assert "acceptance-not-merged" in rule_ids(vsc.validate_repo_state(root))


def test_stale_deleted_branch_rule_triggers(tmp_path: Path) -> None:
    root, _ = make_repo(
        tmp_path,
        status_body="Work continues on `agent/bl-ai-vertical-002` today.\n",
    )
    assert "stale-deleted-branch" in rule_ids(vsc.validate_repo_state(root))


# ---------------------------------------------------------------------------
# Fail cases: typed head model
# ---------------------------------------------------------------------------


def test_dual_behavioural_head_rejects_state_only_commit(tmp_path: Path) -> None:
    """Regression: a reconciliation commit cannot become behavioural truth."""
    root, _ = make_repo(tmp_path)
    control = _commit_files(
        root,
        {"AGENTS.md": "typed-head control contract\n"},
        "chore(control): update typed-head contract",
    )
    state_only = _commit_files(
        root,
        {"WORKLOG.md": "state-only reconciliation\n"},
        "chore(state): reconcile evidence",
    )
    rebind(root, behavioural=state_only, control=control)
    findings = vsc.validate_repo_state(root)
    assert "behavioural-head-type" in rule_ids(findings), findings


def test_dual_control_head_rejects_state_only_commit(tmp_path: Path) -> None:
    """A state-only reconciliation commit cannot become control truth."""
    root, behavioural = make_repo(tmp_path)
    _commit_files(
        root,
        {"AGENTS.md": "typed-head control contract\n"},
        "chore(control): update typed-head contract",
    )
    state_only = _commit_files(
        root,
        {"WORKLOG.md": "state-only reconciliation\n"},
        "chore(state): reconcile evidence",
    )
    rebind(root, behavioural=behavioural, control=state_only)
    findings = vsc.validate_repo_state(root)
    assert "control-head-type" in rule_ids(findings), findings


def test_new_control_change_requires_control_rebind(tmp_path: Path) -> None:
    """A later typed-head protocol change stales only the control binding."""
    root, behavioural = make_repo(tmp_path)
    control = _commit_files(
        root,
        {"AGENTS.md": "typed-head control contract\n"},
        "chore(control): update typed-head contract",
    )
    rebind(root, behavioural=behavioural, control=control)
    _commit_files(
        root,
        {"PROJECT_DNA.yaml": "typed_head_contract: revised\n"},
        "chore(control): revise typed-head architecture",
    )
    findings = vsc.validate_repo_state(root)
    assert "stale-control-head" in rule_ids(findings), findings
    assert "stale-head" not in rule_ids(findings), findings


def test_workspace_lifecycle_control_allowlist_is_exact() -> None:
    expected = {
        "apps/admin-cli/src/admin_cli/authority.py",
        "apps/admin-cli/src/admin_cli/workspaces.py",
        "config/authority-policy.v1.yaml",
        "config/agent-routing-policy.yaml",
        "config/workspace-lifecycle.v1.yaml",
        "packages/governed-runner/src/governed_runner/authority.py",
        "packages/governed-runner/src/governed_runner/workspaces.py",
        "packages/statebench/src/statebench/devloop.py",
        "schemas/authority-action-receipt.v1.schema.json",
        "schemas/authority-grant.v1.schema.json",
        "schemas/authority-policy.v1.schema.json",
        "schemas/workspace-lease.v1.schema.json",
        "scripts/test_authority_policy.py",
        "scripts/test_agent_routing_policy.py",
        "scripts/local_closure_gate.py",
        "scripts/test_workspace_authority_integration.py",
        "scripts/validate_authority_policy.py",
        "scripts/validate_agent_routing_policy.py",
        "scripts/test_workspace_lifecycle.py",
        "scripts/validate_workspace_lifecycle.py",
    }
    assert all(vsc._is_control_path(path) for path in expected)
    assert vsc._is_control_path("packages/governed-runner/src/governed_runner/other.py") is False
    assert vsc._is_control_path("schemas/unrelated-runtime.schema.json") is False


def test_qualification_execution_tools_are_behavioural_paths() -> None:
    assert vsc._is_control_path("infra/qualification/wsl2_rehearsal.py") is False
    assert vsc._is_control_path("scripts/qualification/build_j1_candidate.py") is False


def test_control_head_disagreement_fails(tmp_path: Path) -> None:
    root, behavioural = make_repo(tmp_path)
    control = _commit_files(
        root,
        {"AGENTS.md": "typed-head control contract\n"},
        "chore(control): update typed-head contract",
    )
    rebind(root, behavioural=behavioural, control=control)
    _rewrite_project_state(root, {"controlHead": "a" * 40})
    findings = vsc.validate_repo_state(root)
    assert "control-head-disagreement" in rule_ids(findings), findings


def test_control_head_requires_both_state_anchors(tmp_path: Path) -> None:
    root, behavioural = make_repo(tmp_path)
    control = _commit_files(
        root,
        {"AGENTS.md": "typed-head control contract\n"},
        "chore(control): update typed-head contract",
    )
    files = _state_files(behavioural=behavioural, control=control)
    files["STATUS.md"] = re.sub(r"^\*\*Control Head:.*\n", "", files["STATUS.md"], flags=re.MULTILINE)
    _commit_files(root, files, "docs(state): omit one control anchor")
    findings = vsc.validate_repo_state(root)
    assert "head-anchor-missing" in rule_ids(findings), findings


def test_stale_head_product_file_in_delta(tmp_path: Path) -> None:
    """behaviouralHead ancestor + product file in delta -> stale-head fail."""
    root, _ = make_repo(tmp_path)
    _commit_files(root, {"scripts/example.py": "print('product work')\n"}, "feat: code")
    findings = vsc.validate_repo_state(root)
    assert "stale-head" in rule_ids(findings), findings
    assert any(
        "scripts/example.py" in finding.matched
        for finding in findings
        if finding.rule == "stale-head"
    ), findings


def test_docs_release_delta_fails(tmp_path: Path) -> None:
    """docs/release/** is authority-bearing and NOT in the state-only allowlist."""
    root, _ = make_repo(tmp_path)
    _commit_files(
        root,
        {"docs/release/ledger.yaml": "decision: port\n"},
        "docs(release): authority-bearing ledger change",
    )
    findings = vsc.validate_repo_state(root)
    assert "stale-head" in rule_ids(findings), findings
    assert any(
        "docs/release/ledger.yaml" in finding.matched
        for finding in findings
        if finding.rule == "stale-head"
    ), findings


def test_uncommitted_product_change_fails(tmp_path: Path) -> None:
    """Tracked worktree changes since behaviouralHead also fail closed."""
    root, _ = make_repo(tmp_path)
    (root / "app.py").write_text("print('v2')\n", encoding="utf-8")
    findings = vsc.validate_repo_state(root)
    assert "stale-head" in rule_ids(findings), findings


def test_canonical_branch_disagreement_fails(tmp_path: Path) -> None:
    """STATUS.md says main while the state file names another canonical branch."""
    root, _ = make_repo(
        tmp_path,
        branch="other",
        canonical_line=(
            "**Canonical:** branch `main`; the exact canonical head is derived "
            "from Git at validation time\n"
        ),
    )
    findings = vsc.validate_repo_state(root)
    assert "canonical-head-truth" in rule_ids(findings), findings


def test_canonical_branch_must_be_main_fails(tmp_path: Path) -> None:
    """A canonical branch other than main is rejected even when both files agree."""
    root, _ = make_repo(tmp_path, branch="other")
    findings = vsc.validate_repo_state(root)
    assert "canonical-head-truth" in rule_ids(findings), findings


def test_canonical_head_falls_back_to_origin_ref(tmp_path: Path) -> None:
    """Detached-HEAD CI checkouts may lack the local branch ref; the
    remote-tracking ref origin/<branch> must satisfy the canonical check."""
    root, main_sha = make_repo(tmp_path)
    _git(root, "update-ref", "refs/remotes/origin/main", main_sha)
    _git(root, "branch", "-D", "main")
    assert vsc.validate_repo_state(root) == []


def test_canonical_ref_divergence_fails(tmp_path: Path) -> None:
    """When BOTH local main and origin/main exist they must be equal: a stale
    local main must not mask a newer remote (and vice versa)."""
    root, main_sha = make_repo(tmp_path)
    _git(root, "checkout", "main")
    new_main = _commit_files(root, {"app.py": "print('v2')\n"}, "feat: advance main")
    _git(root, "checkout", REVIEW_BRANCH)
    _git(root, "update-ref", "refs/remotes/origin/main", main_sha)
    findings = vsc.validate_repo_state(root)
    assert "canonical-ref-divergence" in rule_ids(findings), findings
    divergence = [
        finding for finding in findings if finding.rule == "canonical-ref-divergence"
    ][0]
    assert new_main in divergence.matched and main_sha in divergence.matched
    assert "fetch" in divergence.fact


def test_persisted_canonical_head_in_state_fails(tmp_path: Path) -> None:
    """A repository.head field persisting an exact canonical SHA as current
    truth is forbidden; only typed historical observations may keep SHAs."""
    root, main_sha = make_repo(tmp_path)
    path = root / "PROJECT_STATE.yaml"
    text = path.read_text(encoding="utf-8")
    text = text.replace(
        "    canonicalBranch: main\n",
        f"    canonicalBranch: main\n    head: {main_sha}\n",
    )
    path.write_text(text, encoding="utf-8")
    findings = vsc.validate_repo_state(root)
    assert "canonical-head-persisted" in rule_ids(findings), findings


def test_old_style_status_canonical_line_fails(tmp_path: Path) -> None:
    """The old '**Canonical:** branch `main` at `<short>` (<sha40>)' form binds
    the branch to an exact SHA as current truth and is rejected."""
    root, _ = make_repo(
        tmp_path,
        canonical_line=(
            f"**Canonical:** branch `main` at `ccccccc` ({'c' * 40})\n"
        ),
    )
    findings = vsc.validate_repo_state(root)
    assert "canonical-head-persisted" in rule_ids(findings), findings


def test_review_head_persisted_in_state_fails(tmp_path: Path) -> None:
    """review.headObserved must not persist an exact review head; the head
    derives from the branch ref at validation time."""
    root, main_sha = make_repo(tmp_path)
    path = root / "PROJECT_STATE.yaml"
    text = path.read_text(encoding="utf-8")
    text = text.replace(
        f"    branch: {REVIEW_BRANCH}\n",
        f"    branch: {REVIEW_BRANCH}\n    headObserved: {main_sha}\n",
    )
    path.write_text(text, encoding="utf-8")
    findings = vsc.validate_repo_state(root)
    assert "review-head-persisted" in rule_ids(findings), findings


def test_review_branch_unresolvable_fails(tmp_path: Path) -> None:
    """The review branch named in state must resolve as a local or remote ref."""
    root, _ = make_repo(tmp_path, review_branch="agent/does-not-exist")
    findings = vsc.validate_repo_state(root)
    assert "review-head" in rule_ids(findings), findings


def test_review_status_closed_unresolvable_branch_passes(tmp_path: Path) -> None:
    """A closed review needs no resolvable branch: canonical main must keep
    validating after the merged review branch is deleted."""
    root, _ = make_repo(
        tmp_path, review_status="closed", review_branch="agent/does-not-exist"
    )
    assert vsc.validate_repo_state(root) == []


def test_review_status_closed_without_branch_passes(tmp_path: Path) -> None:
    """A closed review may omit the branch field entirely."""
    root, _ = make_repo(tmp_path, review_status="closed", review_branch=None)
    assert vsc.validate_repo_state(root) == []


def test_review_status_invalid_fails(tmp_path: Path) -> None:
    """review.status must be active or closed; anything else fails closed."""
    root, _ = make_repo(tmp_path, review_status="archived")
    findings = vsc.validate_repo_state(root)
    assert "review-status" in rule_ids(findings), findings


def test_squash_merge_fails_head_not_ancestor(tmp_path: Path) -> None:
    """A squashed behavioural commit names a non-ancestor ref."""
    root, _ = make_repo(tmp_path)
    _git(root, "checkout", "-b", "feat", "main")
    feature_sha = _commit_files(root, {"feature.py": "print('f')\n"}, "feat: work")
    _git(root, "checkout", REVIEW_BRANCH)
    _git(root, "merge", "--squash", "feat")
    _commit(root, "feat: squashed work")
    rebind(root, behavioural=feature_sha)
    findings = vsc.validate_repo_state(root)
    assert "head-not-ancestor" in rule_ids(findings), findings


def test_rebase_fails_with_actionable_message(tmp_path: Path) -> None:
    """Rewritten ancestry fails closed and tells the operator to rebind."""
    root, _ = make_repo(tmp_path)
    behavioural = _commit_files(root, {"feature.py": "print('f')\n"}, "feat: work")
    rebind(root, behavioural=behavioural)
    _git(root, "checkout", "-b", "base2", "main")
    _commit_files(root, {"base2.py": "print('b')\n"}, "feat: divergent base")
    _git(root, "checkout", REVIEW_BRANCH)
    _git(root, "rebase", "base2")
    findings = vsc.validate_repo_state(root)
    assert "head-not-ancestor" in rule_ids(findings), findings
    assert any(
        "rebind" in finding.fact.lower()
        for finding in findings
        if finding.rule == "head-not-ancestor"
    ), findings


def test_short_sha_in_formal_fields_fails(tmp_path: Path) -> None:
    root, main_sha = make_repo(tmp_path)
    findings = vsc.validate_repo_state(
        _rewrite_project_state(root, {"behaviouralHead": main_sha[:7]})
    )
    assert "sha-format" in rule_ids(findings), findings


def _rewrite_project_state(root: Path, replacements: dict[str, str]) -> Path:
    path = root / "PROJECT_STATE.yaml"
    text = path.read_text(encoding="utf-8")
    for key, value in replacements.items():
        text = re.sub(rf"({key}: )[0-9a-f]{{40}}", rf"\g<1>{value}", text)
    path.write_text(text, encoding="utf-8")
    return root


def test_behavioural_head_disagreement_fails(tmp_path: Path) -> None:
    root, main_sha = make_repo(tmp_path)
    _rewrite_project_state(root, {"behaviouralHead": "a" * 40})
    findings = vsc.validate_repo_state(root)
    assert "head-disagreement" in rule_ids(findings), findings


def test_wrong_reconciliation_policy_fails(tmp_path: Path) -> None:
    root, _ = make_repo(tmp_path, policy="any_descendant")
    findings = vsc.validate_repo_state(root)
    assert "reconciliation-policy" in rule_ids(findings), findings


def test_archive_ref_plan_delta_fails(tmp_path: Path) -> None:
    """Regression: docs/release/ARCHIVE_REF_PLAN.yaml is authority-bearing and
    NOT a state-only doc; changing it after behaviouralHead fails the gate."""
    root, _ = make_repo(tmp_path)
    _commit_files(
        root,
        {"docs/release/ARCHIVE_REF_PLAN.yaml": "plan: durable archive refs\n"},
        "docs(release): archive ref plan",
    )
    findings = vsc.validate_repo_state(root)
    assert "stale-head" in rule_ids(findings), findings
    assert any(
        "docs/release/ARCHIVE_REF_PLAN.yaml" in finding.matched
        for finding in findings
        if finding.rule == "stale-head"
    ), findings


def test_advanced_target_main_fails(tmp_path: Path) -> None:
    """Topology c: an unrelated product commit lands on main after the
    behavioural rebind; the behavioural delta names it and the gate fails."""
    root, _ = make_repo(tmp_path)
    feature_sha = _commit_files(root, {"feature.py": "print('f')\n"}, "feat: work")
    rebind(root, behavioural=feature_sha)
    _git(root, "checkout", "main")
    _git(root, "merge", "--no-ff", "-m", "merge review line into main", REVIEW_BRANCH)
    _commit_files(root, {"hotfix.py": "print('h')\n"}, "feat: unrelated commit on main")
    findings = vsc.validate_repo_state(root)
    assert "stale-head" in rule_ids(findings), findings
    assert any(
        "hotfix.py" in finding.matched
        for finding in findings
        if finding.rule == "stale-head"
    ), findings


def test_squash_merge_into_main_fails_actionable(tmp_path: Path) -> None:
    """Topology d: squash-merging the review line into main breaks ancestry;
    the failure message names the rule and gives explicit rebind instructions."""
    root, _ = make_repo(tmp_path)
    feature_sha = _commit_files(root, {"feature.py": "print('f')\n"}, "feat: work")
    rebind(root, behavioural=feature_sha)
    _git(root, "checkout", "main")
    _git(root, "merge", "--squash", REVIEW_BRANCH)
    _commit(root, "feat: squashed review line")
    findings = vsc.validate_repo_state(root)
    assert "head-not-ancestor" in rule_ids(findings), findings
    assert any(
        "re-record behaviouralhead" in finding.fact.lower()
        for finding in findings
        if finding.rule == "head-not-ancestor"
    ), findings


def test_rebase_merge_into_main_fails_actionable(tmp_path: Path) -> None:
    """Topology d: rebasing the review line onto main and fast-forwarding main
    rewrites the recorded behavioural head; the failure is actionable."""
    root, _ = make_repo(tmp_path)
    feature_sha = _commit_files(root, {"feature.py": "print('f')\n"}, "feat: work")
    rebind(root, behavioural=feature_sha)
    _git(root, "checkout", "main")
    _commit_files(root, {"base2.py": "print('b')\n"}, "feat: divergent base")
    _git(root, "checkout", REVIEW_BRANCH)
    _git(root, "rebase", "main")
    _git(root, "checkout", "main")
    _git(root, "merge", "--ff-only", REVIEW_BRANCH)
    findings = vsc.validate_repo_state(root)
    assert "head-not-ancestor" in rule_ids(findings), findings
    assert any(
        "re-record behaviouralhead" in finding.fact.lower()
        for finding in findings
        if finding.rule == "head-not-ancestor"
    ), findings


# ---------------------------------------------------------------------------
# Fail cases: freeze anchors, structure, fail-closed git
# ---------------------------------------------------------------------------


def test_freeze_incident_open_while_freeze_false_triggers(tmp_path: Path) -> None:
    root, _ = make_repo(tmp_path, incident_status="open")
    findings = vsc.validate_repo_state(root)
    assert "freeze-incident-open" in rule_ids(findings), findings


def test_freeze_incident_lifted_while_freeze_true_triggers(tmp_path: Path) -> None:
    root, _ = make_repo(tmp_path, release_freeze="true", incident_status="lifted")
    findings = vsc.validate_repo_state(root)
    assert "freeze-incident-closed" in rule_ids(findings), findings


def test_freeze_true_with_active_incident_is_consistent(tmp_path: Path) -> None:
    root, _ = make_repo(tmp_path, release_freeze="true", incident_status="active")
    findings = vsc.validate_repo_state(root)
    assert "freeze-incident-open" not in rule_ids(findings)
    assert "freeze-incident-closed" not in rule_ids(findings)


def test_freeze_incident_missing_fails(tmp_path: Path) -> None:
    """Exactly one RELEASE-FREEZE incident record is required; none fails closed."""
    root, _ = make_repo(tmp_path, incident=False)
    findings = vsc.validate_repo_state(root)
    assert "freeze-incident-missing" in rule_ids(findings), findings


def test_freeze_incident_duplicate_fails(tmp_path: Path) -> None:
    """Exactly one RELEASE-FREEZE incident record is required; two fail closed."""
    root, _ = make_repo(tmp_path, duplicate_incident=True)
    findings = vsc.validate_repo_state(root)
    assert "freeze-incident-duplicate" in rule_ids(findings), findings


def test_freeze_incident_unrecognized_status_fails(tmp_path: Path) -> None:
    """An incident status that agrees with neither flag direction fails closed."""
    root, _ = make_repo(tmp_path, incident_status="monitoring")
    findings = vsc.validate_repo_state(root)
    assert "freeze-incident-status" in rule_ids(findings), findings


def test_historical_paragraph_in_current_scope_fails(tmp_path: Path) -> None:
    root, _ = make_repo(
        tmp_path,
        status_body="Historical containment record (kept as history):\n",
    )
    findings = vsc.validate_repo_state(root)
    assert "historical-outside-heading" in rule_ids(findings), findings


def test_section_after_completed_fails(tmp_path: Path) -> None:
    root, _ = make_repo(
        tmp_path,
        next_actions_body=(
            "Nothing contradicting.\n"
            "\n"
            "## Completed since last update (2026-07-22)\n"
            "\n"
            "- historical notes.\n"
            "\n"
            "## Late section\n"
            "\n"
            "Out of place.\n"
        ),
    )
    findings = vsc.validate_repo_state(root)
    assert "completed-not-final" in rule_ids(findings), findings


def test_git_failure_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    for relative, content in _state_files(
        behavioural="c" * 40, canonical_observed="c" * 40
    ).items():
        (root / relative).write_text(content, encoding="utf-8")
    findings = vsc.validate_repo_state(root)
    assert "head-unverifiable" in rule_ids(findings), findings


def test_git_timeout_fails_closed(tmp_path: Path) -> None:
    root, _ = make_repo(tmp_path)
    with mock.patch(
        "validate_state_consistency.subprocess.run",
        side_effect=vsc.subprocess.TimeoutExpired(cmd="git", timeout=30),
    ):
        findings = vsc.validate_repo_state(root)
    assert "head-unverifiable" in rule_ids(findings), findings


def test_cli_exit_codes(tmp_path: Path) -> None:
    root, _ = make_repo(tmp_path / "clean")
    ok = subprocess.run(
        [sys.executable, str(VALIDATOR), str(root)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert ok.returncode == 0, ok.stdout + ok.stderr

    bad, _ = make_repo(tmp_path / "bad", status_body="main is frozen.\n")
    failed = subprocess.run(
        [sys.executable, str(VALIDATOR), str(bad)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert failed.returncode == 1
    assert "frozen-main" in failed.stdout


# ---------------------------------------------------------------------------
# Anchor integrity: archived prior-work pointers, updated_at, queue sync
# ---------------------------------------------------------------------------

FIXTURE_ARCHIVE_A = "docs/history/state/PROJECT_STATE-2026-01-01-chain.yaml"
FIXTURE_ARCHIVE_B = "docs/history/state/WORKLOG-2026-01-02.md"


def test_prior_work_archive_pointer_committed_passes(tmp_path: Path) -> None:
    root = _projection_reconciliation_repo(
        tmp_path / "pass",
        archived_prior_work=FIXTURE_ARCHIVE_A,
        commit_archives=True,
    )
    assert vsc.validate_repo_state(root) == []


def test_prior_work_archive_pointer_list_form_passes(tmp_path: Path) -> None:
    root = _projection_reconciliation_repo(
        tmp_path / "list",
        archived_prior_work=[FIXTURE_ARCHIVE_A, FIXTURE_ARCHIVE_B],
        commit_archives=True,
    )
    assert vsc.validate_repo_state(root) == []


def test_prior_work_archive_pointer_dangling_fails(tmp_path: Path) -> None:
    root = _projection_reconciliation_repo(
        tmp_path / "dangling", archived_prior_work=FIXTURE_ARCHIVE_A
    )
    findings = vsc.validate_repo_state(root)
    assert "prior-work-archive-pointer" in rule_ids(findings)
    assert any("missing or uncommitted" in finding.matched for finding in findings)


def test_prior_work_archive_pointer_untracked_fails(tmp_path: Path) -> None:
    root = _projection_reconciliation_repo(
        tmp_path / "untracked", archived_prior_work=FIXTURE_ARCHIVE_A
    )
    target = root / FIXTURE_ARCHIVE_A
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("# present on disk but never committed\n", encoding="utf-8")
    findings = vsc.validate_repo_state(root)
    assert "prior-work-archive-pointer" in rule_ids(findings)
    assert any(
        "missing or uncommitted" in finding.matched for finding in findings
    )


def test_prior_work_archive_pointer_undated_name_fails(tmp_path: Path) -> None:
    root = _projection_reconciliation_repo(
        tmp_path / "undated",
        archived_prior_work="docs/history/state/random-notes.yaml",
        commit_archives=True,
    )
    findings = vsc.validate_repo_state(root)
    assert "prior-work-archive-pointer" in rule_ids(findings)
    assert any("dated" in finding.matched for finding in findings)


def test_metadata_updated_at_must_be_tz_aware_iso8601(tmp_path: Path) -> None:
    for index, bad_value in enumerate(("yesterday", "2026-08-20T00:00:00")):
        root = _projection_reconciliation_repo(
            tmp_path / f"bad-{index}", updated_at=bad_value
        )
        findings = vsc.validate_repo_state(root)
        assert "updated-at-format" in rule_ids(findings), (bad_value, findings)
    good_root = _projection_reconciliation_repo(
        tmp_path / "good", updated_at="2026-08-23T18:42:00+02:00"
    )
    assert vsc.validate_repo_state(good_root) == []


def test_active_slice_id_must_appear_in_active_problems(tmp_path: Path) -> None:
    desynced = _projection_reconciliation_repo(
        tmp_path / "desynced", active_problems_ids=("BL-OTHER",)
    )
    findings = vsc.validate_repo_state(desynced)
    assert "active-slice-problem-desync" in rule_ids(findings)
    aligned = _projection_reconciliation_repo(
        tmp_path / "aligned",
        active_problems_ids=("BL-FIXTURE", "BL-OTHER"),
    )
    assert vsc.validate_repo_state(aligned) == []


def test_active_problems_requires_statespec_compatible_block_sequence(
    tmp_path: Path,
) -> None:
    root = _projection_reconciliation_repo(
        tmp_path / "inline", active_problems_ids=("BL-FIXTURE",)
    )
    state_path = root / "PROJECT_STATE.yaml"
    state = state_path.read_text(encoding="utf-8")
    state_path.write_text(
        state.replace(
            "active_problems:\n  - {id: BL-FIXTURE, status: open}\n",
            "active_problems: [{id: BL-FIXTURE, status: open}]\n",
        ),
        encoding="utf-8",
    )
    assert "active-problems-encoding" in rule_ids(vsc.validate_repo_state(root))


def test_write_projections_refuses_over_budget_state(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _projection_reconciliation_repo(tmp_path / "over-budget")
    (root / "docs" / "history" / "state").mkdir(parents=True)
    state_path = root / "PROJECT_STATE.yaml"
    state = state_path.read_text(encoding="utf-8")
    line_count = len(state.splitlines())
    state_path.write_text(
        state.rstrip("\n")
        + "\n"
        + "\n".join("# padding" for _ in range(221 - line_count))
        + "\n",
        encoding="utf-8",
    )

    assert vsc.main(["validate_state_consistency.py", str(root), "--write-projections"]) == 1
    output = capsys.readouterr().out
    assert "PROJECT_STATE.yaml: 221 lines exceeds 220-line budget" in output
    assert "current-state hygiene must pass before commit" in output


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))


def _dual_line_rebind_repo(tmp_path: Path, *, same_line: bool) -> Path:
    """Two adjacent state-only commits rebinding different or equal heads."""
    root = tmp_path / ("dual-line-" + ("same" if same_line else "split"))
    root.mkdir(parents=True)
    _git(root, "init", "-b", "main")
    behavioural1 = _commit_files(root, {"app.py": "print('v1')\n"}, "feat: product one")
    control1 = _commit_files(
        root, {"scripts/validate_state_consistency.py": "# control\n"}, "feat(control): policy"
    )
    files = _state_files(
        behavioural=behavioural1,
        control=control1,
        review_branch=None,
        review_status="closed",
        canonical_observed=behavioural1,
        projection_workflow=True,
        projection_status="enforced",
        directive_base=behavioural1,
    )
    _commit_files(root, files, "docs(state): reconcile slice one")
    product2 = _commit_files(root, {"app.py": "print('v2')\n"}, "feat: product two")
    control2 = _commit_files(
        root, {"scripts/validate_state_consistency.py": "# control two\n"}, "feat(control): policy two"
    )
    if same_line:
        product3 = _commit_files(root, {"app.py": "print('v3')\n"}, "feat: product three")
        steps = [
            ({"behavioural": product2, "control": control1}, "docs(state): rebind behavioural"),
            ({"behavioural": product3, "control": control2}, "docs(state): rebind behavioural again"),
        ]
    else:
        steps = [
            ({"behavioural": product2, "control": control1}, "docs(state): rebind behavioural line"),
            ({"behavioural": product2, "control": control2}, "docs(state): rebind control line"),
        ]
    for heads, label in steps:
        bound = _state_files(
            behavioural=heads["behavioural"],
            control=heads["control"],
            review_branch=None,
            review_status="closed",
            canonical_observed=heads["behavioural"],
            projection_workflow=True,
            projection_status="enforced",
            directive_base=behavioural1,
        )
        _commit_files(root, bound, label)
    return root


def test_sequential_single_line_rebinds_of_different_heads_are_not_churn(
    tmp_path: Path,
) -> None:
    root = _dual_line_rebind_repo(tmp_path, same_line=False)
    assert vsc.validate_repo_state(root) == []


def test_repeated_rebinds_of_the_same_head_line_remain_churn(tmp_path: Path) -> None:
    root = _dual_line_rebind_repo(tmp_path, same_line=True)
    assert "reconciliation-budget" in rule_ids(vsc.validate_repo_state(root))
