"""Separate StateBench v0 scorecards.

The scorecards intentionally expose dimensions independently.  None of the
functions in this module selects a universal winner or turns trade-offs into a
performance claim.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Iterable

from .models import BenchmarkRunResult


def _mean(values: Iterable[int | float | None]) -> float | None:
    usable = [float(value) for value in values if value is not None]
    if not usable:
        return None
    return math.fsum(usable) / len(usable)


def _rate(values: Iterable[bool]) -> float | None:
    values = list(values)
    if not values:
        return None
    return sum(1 for value in values if value) / len(values)


@dataclass(frozen=True)
class QualityScorecard:
    sample_size: int
    task_success_rate: float | None
    deterministic_validation_rate: float | None
    mean_quality_score: float | None
    safety_violation_rate: float | None


@dataclass(frozen=True)
class ContextScorecard:
    sample_size: int
    measured_context_samples: int
    mean_context_tokens: float | None
    mean_context_token_share: float | None
    mean_files_loaded: float | None
    truncation_rate: float | None


@dataclass(frozen=True)
class CostScorecard:
    sample_size: int
    measured_cost_samples: int
    mean_total_tokens: float | None
    mean_runtime_ms: float | None
    mean_estimated_cost: float | None


@dataclass(frozen=True)
class ContinuityScorecard:
    sample_size: int
    continuity_success_rate: float | None
    mean_interventions: float | None
    mean_unnecessary_questions: float | None


@dataclass(frozen=True)
class StateIntegrityScorecard:
    sample_size: int
    state_correctness_rate: float | None
    validation_failure_rate: float | None
    mean_files_changed: float | None
    safety_violation_rate: float | None
    privacy_violation_rate: float | None


@dataclass(frozen=True)
class Scorecards:
    quality: QualityScorecard
    context: ContextScorecard
    cost: CostScorecard
    continuity: ContinuityScorecard
    state_integrity: StateIntegrityScorecard


@dataclass(frozen=True)
class BalancedTradeoff:
    """Optional caller-supplied trade-off weights; never an official ranking."""

    quality_weight: float
    context_weight: float
    cost_weight: float
    continuity_weight: float
    state_integrity_weight: float

    def __post_init__(self) -> None:
        weights = (
            self.quality_weight,
            self.context_weight,
            self.cost_weight,
            self.continuity_weight,
            self.state_integrity_weight,
        )
        if any(not math.isfinite(weight) or weight < 0 for weight in weights):
            raise ValueError("trade-off weights must be finite and non-negative")
        if sum(weights) <= 0:
            raise ValueError("at least one trade-off weight is required")


def build_scorecards(runs: Iterable[BenchmarkRunResult]) -> Scorecards:
    ordered = tuple(sorted(runs, key=lambda run: (run.task_id, run.repetition, run.pair_id, run.run_id)))
    size = len(ordered)
    measured_context = sum(run.context_tokens is not None for run in ordered)
    measured_cost = sum(
        run.total_tokens is not None or run.runtime_ms is not None or run.estimated_cost is not None
        for run in ordered
    )
    return Scorecards(
        quality=QualityScorecard(
            sample_size=size,
            task_success_rate=_rate(run.task_success for run in ordered),
            deterministic_validation_rate=_rate(
                run.deterministic_state_correct and run.validation_failures == 0 for run in ordered
            ),
            mean_quality_score=_mean(run.quality_score for run in ordered),
            safety_violation_rate=_rate(run.safety_violations > 0 for run in ordered),
        ),
        context=ContextScorecard(
            sample_size=size,
            measured_context_samples=measured_context,
            mean_context_tokens=_mean(run.context_tokens for run in ordered),
            mean_context_token_share=_mean(run.context_token_share for run in ordered),
            mean_files_loaded=_mean(run.files_loaded for run in ordered),
            truncation_rate=_rate(run.truncation for run in ordered),
        ),
        cost=CostScorecard(
            sample_size=size,
            measured_cost_samples=measured_cost,
            mean_total_tokens=_mean(run.total_tokens for run in ordered),
            mean_runtime_ms=_mean(run.runtime_ms for run in ordered),
            mean_estimated_cost=_mean(run.estimated_cost for run in ordered),
        ),
        continuity=ContinuityScorecard(
            sample_size=size,
            continuity_success_rate=_rate(run.continuity_success for run in ordered),
            mean_interventions=_mean(run.interventions for run in ordered),
            mean_unnecessary_questions=_mean(run.unnecessary_questions for run in ordered),
        ),
        state_integrity=StateIntegrityScorecard(
            sample_size=size,
            state_correctness_rate=_rate(run.deterministic_state_correct for run in ordered),
            validation_failure_rate=_rate(run.validation_failures > 0 for run in ordered),
            mean_files_changed=_mean(run.files_changed for run in ordered),
            safety_violation_rate=_rate(run.safety_violations > 0 for run in ordered),
            privacy_violation_rate=_rate(run.privacy_violations > 0 for run in ordered),
        ),
    )
