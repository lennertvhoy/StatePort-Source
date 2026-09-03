"""Deterministic paired-run comparison aggregation for StateBench v0."""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Iterable

from .models import BenchmarkRunResult, ResultTier
from .scorecards import Scorecards, build_scorecards


def _delta(candidate: int | float | None, baseline: int | float | None) -> float | None:
    if candidate is None or baseline is None:
        return None
    return float(candidate) - float(baseline)


def _mean(values: Iterable[float | None]) -> float | None:
    usable = [value for value in values if value is not None]
    if not usable:
        return None
    return math.fsum(usable) / len(usable)


@dataclass(frozen=True)
class PairedComparison:
    pair_key: tuple[str, str, int]
    baseline_run_id: str
    candidate_run_id: str
    task_success_delta: int
    quality_score_delta: float
    context_tokens_delta: float | None
    context_token_share_delta: float | None
    total_tokens_delta: float | None
    files_loaded_delta: float | None
    files_changed_delta: float | None
    runtime_ms_delta: float | None
    estimated_cost_delta: float | None
    interventions_delta: float | None
    validation_failures_delta: int
    unnecessary_questions_delta: float | None
    continuity_success_delta: int
    state_correctness_delta: int
    safety_violations_delta: int
    privacy_violations_delta: int
    truncation_delta: int


@dataclass(frozen=True)
class PairedComparisonAggregate:
    baseline_configuration_id: str
    candidate_configuration_id: str
    pair_count: int
    comparisons: tuple[PairedComparison, ...]
    baseline_scorecards: Scorecards
    candidate_scorecards: Scorecards
    mean_task_success_delta: float | None
    mean_quality_score_delta: float | None
    mean_context_tokens_delta: float | None
    mean_total_tokens_delta: float | None
    mean_runtime_ms_delta: float | None
    mean_estimated_cost_delta: float | None
    result_tier: ResultTier = ResultTier.SELF_REPORTED


def _validate_unique(runs: tuple[BenchmarkRunResult, ...], label: str) -> None:
    ids = [run.run_id for run in runs]
    if len(ids) != len(set(ids)):
        raise ValueError(f"{label} run_id values must be unique")
    keys = [run.pair_key for run in runs]
    if len(keys) != len(set(keys)):
        raise ValueError(f"{label} runs must have one result per task/pair/repetition")
    configuration_ids = {run.configuration_id for run in runs}
    if len(configuration_ids) != 1:
        raise ValueError(f"{label} runs must use one configuration")


def compare_paired_runs(
    baseline: BenchmarkRunResult, candidate: BenchmarkRunResult
) -> PairedComparison:
    if baseline.pair_key != candidate.pair_key:
        raise ValueError("baseline and candidate runs are not a matching pair")
    if baseline.configuration_id == candidate.configuration_id:
        raise ValueError("paired runs must use different configurations")
    return PairedComparison(
        pair_key=baseline.pair_key,
        baseline_run_id=baseline.run_id,
        candidate_run_id=candidate.run_id,
        task_success_delta=int(candidate.task_success) - int(baseline.task_success),
        quality_score_delta=candidate.quality_score - baseline.quality_score,
        context_tokens_delta=_delta(candidate.context_tokens, baseline.context_tokens),
        context_token_share_delta=_delta(candidate.context_token_share, baseline.context_token_share),
        total_tokens_delta=_delta(candidate.total_tokens, baseline.total_tokens),
        files_loaded_delta=_delta(candidate.files_loaded, baseline.files_loaded),
        files_changed_delta=_delta(candidate.files_changed, baseline.files_changed),
        runtime_ms_delta=_delta(candidate.runtime_ms, baseline.runtime_ms),
        estimated_cost_delta=_delta(candidate.estimated_cost, baseline.estimated_cost),
        interventions_delta=_delta(candidate.interventions, baseline.interventions),
        validation_failures_delta=candidate.validation_failures - baseline.validation_failures,
        unnecessary_questions_delta=_delta(candidate.unnecessary_questions, baseline.unnecessary_questions),
        continuity_success_delta=int(candidate.continuity_success) - int(baseline.continuity_success),
        state_correctness_delta=int(candidate.deterministic_state_correct)
        - int(baseline.deterministic_state_correct),
        safety_violations_delta=candidate.safety_violations - baseline.safety_violations,
        privacy_violations_delta=candidate.privacy_violations - baseline.privacy_violations,
        truncation_delta=int(candidate.truncation) - int(baseline.truncation),
    )


def aggregate_paired_runs(
    baseline_runs: Iterable[BenchmarkRunResult],
    candidate_runs: Iterable[BenchmarkRunResult],
    *,
    result_tier: ResultTier = ResultTier.SELF_REPORTED,
) -> PairedComparisonAggregate:
    if not isinstance(result_tier, ResultTier):
        raise TypeError("result_tier must be a ResultTier")
    baseline = tuple(sorted(baseline_runs, key=lambda run: run.pair_key + (run.run_id,)))
    candidate = tuple(sorted(candidate_runs, key=lambda run: run.pair_key + (run.run_id,)))
    if not baseline or not candidate:
        raise ValueError("both baseline and candidate runs are required")
    _validate_unique(baseline, "baseline")
    _validate_unique(candidate, "candidate")
    baseline_by_key = {run.pair_key: run for run in baseline}
    candidate_by_key = {run.pair_key: run for run in candidate}
    if set(baseline_by_key) != set(candidate_by_key):
        raise ValueError("baseline and candidate must contain the same paired task runs")
    comparisons = tuple(
        compare_paired_runs(baseline_by_key[key], candidate_by_key[key])
        for key in sorted(baseline_by_key)
    )
    return PairedComparisonAggregate(
        baseline_configuration_id=baseline[0].configuration_id,
        candidate_configuration_id=candidate[0].configuration_id,
        pair_count=len(comparisons),
        comparisons=comparisons,
        baseline_scorecards=build_scorecards(baseline),
        candidate_scorecards=build_scorecards(candidate),
        mean_task_success_delta=_mean(item.task_success_delta for item in comparisons),
        mean_quality_score_delta=_mean(item.quality_score_delta for item in comparisons),
        mean_context_tokens_delta=_mean(item.context_tokens_delta for item in comparisons),
        mean_total_tokens_delta=_mean(item.total_tokens_delta for item in comparisons),
        mean_runtime_ms_delta=_mean(item.runtime_ms_delta for item in comparisons),
        mean_estimated_cost_delta=_mean(item.estimated_cost_delta for item in comparisons),
        result_tier=result_tier,
    )


@dataclass(frozen=True)
class ResultTierEvidence:
    """Explicit evidence gates for the provenance label on a result."""

    configuration_complete: bool = False
    paired_runs_complete: bool = False
    deterministic_validators_passed: bool = False
    state_integrity_gate_passed: bool = False
    private_holdout_passed: bool = False
    human_review_completed: bool = False
    operator_approved: bool = False


def classify_result_tier(evidence: ResultTierEvidence) -> ResultTier:
    """Return the highest evidence tier whose gates are all satisfied."""

    verified = (
        evidence.configuration_complete
        and evidence.paired_runs_complete
        and evidence.deterministic_validators_passed
        and evidence.state_integrity_gate_passed
    )
    official = verified and evidence.private_holdout_passed and evidence.human_review_completed and evidence.operator_approved
    if official:
        return ResultTier.OFFICIAL
    if verified:
        return ResultTier.VERIFIED
    return ResultTier.SELF_REPORTED
