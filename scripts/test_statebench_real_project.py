#!/usr/bin/env python3
"""Deterministic and adversarial tests for StateBench real-project v1."""

from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import jsonschema
import pytest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "packages" / "statebench" / "src"
RELEASE_CONTRACTS = ROOT / "packages" / "release-contracts" / "src"
for _extra in (SOURCE, RELEASE_CONTRACTS):
    if str(_extra) not in sys.path:
        sys.path.insert(0, str(_extra))

from statebench import (  # noqa: E402
    REAL_PROJECT_BANNER,
    REAL_PROJECT_SCENARIO_FORMAT,
    ParentJobAccounting,
    RealProjectCalibrationReport,
    RealProjectContractError,
    RealProjectFixtureBuilder,
    RealProjectScenario,
    SyntheticRealProjectHarness,
)
from statebench.real_project_models import (  # noqa: E402
    AttemptTrace,
    BacklogDecisionTrace,
    ClosureTrace,
    DelegationTrace,
    HumanIntervention,
    ProjectBootstrapTrace,
    RepairTrace,
    ReviewTrace,
    SliceSelectionTrace,
)


FIXTURE = ROOT / "fixtures" / "statebench" / "real-project" / "reference-task-service"


@pytest.fixture(scope="module")
def calibration(tmp_path_factory: pytest.TempPathFactory):
    root = tmp_path_factory.mktemp("statebench-real-project")
    prepared = RealProjectFixtureBuilder(FIXTURE).materialize(root / "prepared")
    report = SyntheticRealProjectHarness().run_pair(prepared, root / "paired-runs")
    return root, prepared, report


def _run_initial(evaluator: Path, source: Path) -> tuple[bool, bool]:
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    public_code = (
        "import runpy,sys; "
        f"sys.path.insert(0,{str(source / 'src')!r}); "
        f"runpy.run_path({str(source / 'public_tests' / 'visible_check.py')!r},run_name='__main__')"
    )
    public = subprocess.run(
        [sys.executable, "-c", public_code],
        cwd=source,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    protected = subprocess.run(
        [sys.executable, str(evaluator), str(source)],
        cwd=evaluator.parent,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    payload = json.loads(protected.stdout.strip().splitlines()[-1])
    return public.returncode == 0, payload["passed"]


def _walk_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | set().union(
            *(_walk_keys(item) for item in value.values()), set()
        )
    if isinstance(value, list):
        return set().union(*(_walk_keys(item) for item in value), set())
    return set()


def test_scenario_is_strict_versioned_and_schema_valid(calibration) -> None:
    _, prepared, _ = calibration
    scenario = prepared.scenario
    assert scenario.to_dict()["formatVersion"] == REAL_PROJECT_SCENARIO_FORMAT
    assert RealProjectScenario.FORMAT == REAL_PROJECT_SCENARIO_FORMAT
    schema = json.loads(
        (ROOT / "schemas" / "statebench-real-project.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.Draft202012Validator(schema).validate(scenario.to_dict())
    invalid = scenario.to_dict()
    invalid["universalScore"] = 1
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(invalid)


def test_fixture_is_public_safe_medium_sized_and_not_stateport_itself(
    calibration,
) -> None:
    _, prepared, _ = calibration
    scenario = prepared.scenario
    assert scenario.scenario_id == "project-scenario-reference-task-service"
    assert "stateport" not in scenario.scenario_id
    assert scenario.privacy_classification == "public_safe"
    assert scenario.production_eligible is False
    assert len(scenario.project_modules) == 6
    assert {item.rsplit(".", 1)[-1] for item in scenario.project_modules} == {
        "models",
        "api",
        "persistence",
        "service",
        "cli",
        "web",
    }
    assert len(scenario.milestones) == 3
    assert scenario.repository_bundle_digest.startswith("sha256:")


def test_visible_test_trap_passes_before_hidden_invariants(calibration) -> None:
    _, prepared, _ = calibration
    visible, protected = _run_initial(
        prepared.protected_evaluator, prepared.source_repository
    )
    assert visible is True
    assert protected is False
    assert "Intentionally incomplete visible check" in (
        prepared.source_repository / "public_tests" / "visible_check.py"
    ).read_text(encoding="utf-8")


def test_evaluator_assets_are_outside_candidate_bundle_and_results(calibration) -> None:
    root, prepared, report = calibration
    assert prepared.protected_evaluator.parent != prepared.source_repository
    assert prepared.protected_evaluator.parent not in prepared.source_repository.parents
    for strategy in ("single_agent", "cto_orchestrated"):
        worktree = root / "paired-runs" / strategy / "worktree"
        assert not list(worktree.rglob("evaluate.py"))
        assert not list(worktree.rglob("hidden-tests*"))
    serialized = report.canonical_json()
    assert str(prepared.protected_evaluator) not in serialized
    assert "errorClass" not in serialized


def test_pair_holds_scenario_runtime_profiles_tools_budgets_and_evaluator_constant(
    calibration,
) -> None:
    _, _, report = calibration
    assert report.equal_configuration_proven is True
    assert {run.workflow.strategy for run in report.runs} == {
        "single_agent",
        "cto_orchestrated",
    }
    assert len({run.workflow.held_constant_digest for run in report.runs}) == 1
    left, right = report.runs
    assert (
        left.workflow.scenario_digest
        == right.workflow.scenario_digest
        == report.scenario.digest
    )
    assert left.workflow.runtime_configuration == right.workflow.runtime_configuration
    assert left.workflow.model_profiles == right.workflow.model_profiles
    assert left.workflow.evaluator_identity == right.workflow.evaluator_identity
    assert left.workflow.runtime_configuration.tools == ("filesystem", "git")


def test_interruption_continuation_and_parent_job_accounting_are_explicit(
    calibration,
) -> None:
    _, _, report = calibration
    for run in report.runs:
        accounting = run.accounting
        assert isinstance(accounting, ParentJobAccounting)
        assert accounting.first_attempt_success is False
        assert accounting.eventual_success is True
        assert accounting.recovered_success is True
        assert [attempt.outcome for attempt in accounting.attempts] == [
            "interrupted_checkpoint",
            "recovered_success",
        ]
        assert all(
            attempt.parent_job_id == run.parent_job_id
            for attempt in accounting.attempts
        )
        totals = accounting.to_dict()["totals"]
        assert totals["toolCalls"] == sum(
            item.tool_calls for item in accounting.attempts
        )
        assert totals["fileWrites"] == sum(
            item.file_writes for item in accounting.attempts
        )
        assert totals["inputTokens"] is None
        assert totals["monetaryCostMinor"] is None


def test_trace_captures_every_required_multi_stage_event_in_order(calibration) -> None:
    _, _, report = calibration
    required = (
        ProjectBootstrapTrace,
        BacklogDecisionTrace,
        SliceSelectionTrace,
        DelegationTrace,
        AttemptTrace,
        HumanIntervention,
        RepairTrace,
        AttemptTrace,
        ReviewTrace,
        ClosureTrace,
    )
    for run in report.runs:
        assert tuple(type(event) for event in run.trace.events) == required
        assert tuple(event.sequence for event in run.trace.events) == tuple(
            range(1, 11)
        )
        assert all(
            event.parent_job_id == run.parent_job_id for event in run.trace.events
        )
        repair = run.trace.events[6]
        assert isinstance(repair, RepairTrace)
        assert repair.added_permissions == ()


def test_independent_review_binds_exact_commit_tree_tests_and_scenario(
    calibration,
) -> None:
    root, _, report = calibration
    for run in report.runs:
        review = run.trace.events[8]
        assert isinstance(review, ReviewTrace)
        assert review.commit == run.final_commit
        assert review.tree == run.final_tree
        assert review.scenario_digest == report.scenario.digest
        assert review.test_result_digest == run.handoff.validation_digest
        assert review.reviewer_profile != review.implementer_profile
        assert review.read_only is True
        assert review.clean_detached_worktree is True
        review_worktree = (
            root / "paired-runs" / run.workflow.strategy / "review-worktree"
        )
        status = subprocess.run(
            [
                "git",
                "-C",
                str(review_worktree),
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        assert status == ""


def test_git_closure_preserves_unrelated_dirty_work_and_remote_equality(
    calibration,
) -> None:
    root, _, report = calibration
    for run in report.runs:
        closure = run.trace.events[-1]
        assert isinstance(closure, ClosureTrace)
        assert closure.commit == closure.remote_commit == run.final_commit
        assert closure.remote_equal is True
        assert closure.unrelated_work_preserved is True
        worktree = root / "paired-runs" / run.workflow.strategy / "worktree"
        status = subprocess.run(
            [
                "git",
                "-C",
                str(worktree),
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.rstrip("\n")
        assert status == " M operator-notes.txt"
        assert (worktree / "operator-notes.txt").read_text(encoding="utf-8") == (
            "operator draft retained across both attempts\n"
        )


def test_handoff_is_truthful_and_bound_to_exact_closure(calibration) -> None:
    _, _, report = calibration
    for run in report.runs:
        handoff = run.handoff
        assert handoff.scenario_digest == report.scenario.digest
        assert handoff.base_commit == report.scenario.initial_commit
        assert handoff.final_commit == run.final_commit
        assert handoff.final_tree == run.final_tree
        assert handoff.completed_milestones == ("M1", "M2", "M3")
        assert handoff.pending_work == ()
        assert handoff.review_digest == run.trace.events[8].digest
        assert "Stop" in handoff.next_action
        assert run.trace.events[-1].handoff_digest == handoff.digest
        assert run.trace.events[-1].receipt_digest == run.receipt_digest


def test_metrics_separate_hard_outcomes_efficiency_orchestration_and_context(
    calibration,
) -> None:
    _, _, report = calibration
    for run in report.runs:
        metrics = run.metrics.to_dict()
        assert set(metrics) == {
            "formatVersion",
            "hardOutcomes",
            "efficiency",
            "orchestration",
            "context",
        }
        hard = metrics["hardOutcomes"]
        assert hard["firstAttemptSuccess"] is False
        assert hard["eventualSuccess"] is True
        assert hard["criticalViolationCount"] == 0
        assert hard["gitClosurePassed"] is True
        assert metrics["efficiency"]["activeModelTimeMs"] is None
        assert metrics["efficiency"]["inputTokens"] is None
        assert metrics["efficiency"]["monetaryCostMinor"] is None
        assert metrics["orchestration"]["backlogSelectionPrecision"] is None
        assert metrics["context"]["statePackSizeBytes"] is None


def test_report_has_no_universal_score_or_superiority_claim(calibration) -> None:
    _, _, report = calibration
    value = report.to_dict()
    keys = _walk_keys(value)
    assert "universalScore" not in keys
    assert value["superiorityClaim"] is False
    assert value["comparisonClassification"] == "harness_behavior_only"
    assert value["banner"] == REAL_PROJECT_BANNER
    assert "does not establish" in value["banner"]
    assert all(
        run.performance_claim is False and run.calibration_only is True
        for run in report.runs
    )


def test_pair_rejects_configuration_drift_and_superiority_claim(calibration) -> None:
    _, _, report = calibration
    first, second = report.runs
    drifted_workflow = replace(
        second.workflow,
        evaluator_identity="different-evaluator-v1",
    )
    drifted_run = replace(second, workflow=drifted_workflow)
    with pytest.raises(RealProjectContractError, match="held constant"):
        RealProjectCalibrationReport(
            scenario=report.scenario,
            runs=(first, drifted_run),
            limitations=report.limitations,
        )
    with pytest.raises(RealProjectContractError, match="superiority"):
        RealProjectCalibrationReport(
            scenario=report.scenario,
            runs=report.runs,
            limitations=report.limitations,
            superiority_claim=True,
        )


def test_trace_rejects_reordered_or_out_of_scope_repair_artifacts(calibration) -> None:
    _, _, report = calibration
    run = report.runs[0]
    with pytest.raises(RealProjectContractError, match="lifecycle stage"):
        replace(run.trace, events=run.trace.events[:-1])

    repair = run.trace.events[6]
    assert isinstance(repair, RepairTrace)
    out_of_scope = replace(repair, changed_paths=("outside-approved-slice.py",))
    events = (*run.trace.events[:6], out_of_scope, *run.trace.events[7:])
    with pytest.raises(RealProjectContractError, match="approved slice"):
        replace(run.trace, events=events)

    with pytest.raises(RealProjectContractError, match="increase permissions"):
        replace(repair, added_permissions=("network",))


def test_run_rejects_review_handoff_or_receipt_identity_tampering(calibration) -> None:
    _, _, report = calibration
    run = report.runs[0]
    review = run.trace.events[8]
    assert isinstance(review, ReviewTrace)
    mismatched_review = replace(review, commit=report.scenario.initial_commit)
    events = (*run.trace.events[:8], mismatched_review, run.trace.events[9])
    with pytest.raises(RealProjectContractError, match="final attempt"):
        replace(run.trace, events=events)

    changed_handoff = replace(run.handoff, decisions=("tampered decision",))
    with pytest.raises(RealProjectContractError, match="digest-bound"):
        replace(run, handoff=changed_handoff)

    with pytest.raises(RealProjectContractError, match="closure trace"):
        replace(run, receipt_digest="sha256:" + "0" * 64)

    hidden_retry_cost = replace(
        run.metrics,
        efficiency=replace(
            run.metrics.efficiency,
            tool_calls=run.metrics.efficiency.tool_calls - 1,
        ),
    )
    with pytest.raises(RealProjectContractError, match="attempt costs"):
        replace(run, metrics=hidden_retry_cost)


def test_fixture_builder_rejects_symlinks(calibration, tmp_path: Path) -> None:
    del calibration
    fixture = tmp_path / "fixture"
    shutil.copytree(FIXTURE, fixture)
    target = fixture / "src" / "reference_app" / "web.py"
    target.unlink()
    target.symlink_to(fixture / "README.md")
    with pytest.raises(RealProjectContractError, match="inventory drifted"):
        RealProjectFixtureBuilder(fixture).materialize(tmp_path / "prepared")


def test_scenario_contract_rejects_small_or_non_public_projects(calibration) -> None:
    _, prepared, _ = calibration
    scenario = prepared.scenario
    with pytest.raises(RealProjectContractError, match="several modules"):
        replace(scenario, project_modules=("reference_app.api",))
    with pytest.raises(RealProjectContractError, match="public-safe"):
        replace(scenario, privacy_classification="private")
    with pytest.raises(RealProjectContractError, match="production-ineligible"):
        replace(scenario, production_eligible=True)


def test_report_is_canonical_and_contains_no_absolute_fixture_paths(
    calibration,
) -> None:
    root, prepared, report = calibration
    first = report.canonical_json()
    second = report.canonical_json()
    assert first == second
    assert str(root) not in first
    assert str(prepared.source_repository) not in first
    assert str(prepared.repository_bundle) not in first
    assert report.scenario.repository_bundle_path == "reference-task-service.bundle"


def test_fixture_and_paired_report_are_reproducible(
    calibration, tmp_path: Path
) -> None:
    _, prepared, report = calibration
    repeated = RealProjectFixtureBuilder(FIXTURE).materialize(tmp_path / "prepared")
    repeated_report = SyntheticRealProjectHarness().run_pair(
        repeated, tmp_path / "paired-runs"
    )
    assert repeated.scenario.digest == prepared.scenario.digest
    assert (
        repeated.repository_bundle.read_bytes()
        == prepared.repository_bundle.read_bytes()
    )
    assert repeated_report.canonical_json() == report.canonical_json()


def test_real_project_contract_type_is_publicly_exported() -> None:
    assert RealProjectScenario.FORMAT == REAL_PROJECT_SCENARIO_FORMAT
