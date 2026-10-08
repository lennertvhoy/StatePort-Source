#!/usr/bin/env python3
"""Focused acceptance tests for the canonical StateBench public API."""

from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages/statebench/src"))

from statebench import (
    BenchmarkRunResult,
    BenchmarkSuiteManifest,
    CandidateManifest,
    ConfigurationManifest,
    ResultTier,
    ResultTierEvidence,
    aggregate_paired_runs,
    classify_result_tier,
)


def _candidate() -> CandidateManifest:
    return CandidateManifest(
        candidate_id="classdd-0.1.0",
        template_id="classdd",
        template_version="0.1.0",
        source_repository="https://example.invalid/classdd.git",
        source_commit="0123456789abcdef",
        modules=("core",),
        generator_id="classdd-context",
        generator_version="1",
    )


def _config(policy: str = "eager") -> ConfigurationManifest:
    candidate = _candidate()
    return ConfigurationManifest(
        suite_id="suite-1",
        suite_version="1.0.0",
        task_id="task-1",
        candidate_id=candidate.candidate_id,
        candidate_commit=candidate.source_commit,
        template_id=candidate.template_id,
        template_version=candidate.template_version,
        modules=candidate.modules,
        context_policy=policy,
        statepack_profile="compact",
        token_budget=256,
        state_mode="persistent",
        model="test-model",
        tokenization="test-tokenizer",
        runner="local",
        tools=("filesystem",),
    )


def _run(
    config: ConfigurationManifest,
    *,
    run_id: str,
    pair_id: str,
    repetition: int,
    quality: float,
    context_tokens: int,
    total_tokens: int,
) -> BenchmarkRunResult:
    return BenchmarkRunResult(
        run_id=run_id,
        configuration_id=config.configuration_id,
        task_id="task-1",
        repetition=repetition,
        pair_id=pair_id,
        task_success=True,
        quality_score=quality,
        deterministic_state_correct=True,
        context_tokens=context_tokens,
        context_token_share=context_tokens / total_tokens,
        total_tokens=total_tokens,
        files_loaded=2,
        files_changed=0,
        runtime_ms=10.0,
        estimated_cost=0.01,
        interventions=0,
        continuity_success=True,
    )


def test_complete_configuration_identity_is_deterministic() -> None:
    first = _config()
    second = _config()
    changed = _config("modular")

    assert first.configuration_id == second.configuration_id
    assert first.canonical_json() == second.canonical_json()
    assert first.configuration_id != changed.configuration_id
    assert _candidate().manifest_digest == _candidate().manifest_digest
    assert _candidate().supported_context_policies == (
        "eager",
        "compact_context",
        "modular",
    )
    assert first.to_dict()["contextPolicy"] == "eager"
    assert first.to_dict()["statepack"]["tokenBudget"] == 256
    suite = BenchmarkSuiteManifest("suite-1", "1.0.0", ("task-1",), 2)
    assert suite.candidate_context_policies == (
        "eager",
        "compact_context",
        "modular",
    )


def test_paired_aggregation_is_deterministic_and_keeps_scorecards_separate() -> None:
    baseline_config = _config("eager")
    candidate_config = _config("modular")
    baseline = (
        replace(
            _run(baseline_config, run_id="base-2", pair_id="pair-b", repetition=1, quality=0.6, context_tokens=120, total_tokens=220),
            truncation=True,
            validation_failures=2,
            safety_violations=1,
            privacy_violations=1,
        ),
        _run(baseline_config, run_id="base-1", pair_id="pair-a", repetition=0, quality=0.5, context_tokens=100, total_tokens=200),
    )
    candidate = (
        _run(candidate_config, run_id="candidate-1", pair_id="pair-a", repetition=0, quality=0.8, context_tokens=80, total_tokens=160),
        _run(candidate_config, run_id="candidate-2", pair_id="pair-b", repetition=1, quality=0.9, context_tokens=90, total_tokens=180),
    )
    evidence = ResultTierEvidence(
        configuration_complete=True,
        paired_runs_complete=True,
        deterministic_validators_passed=True,
        state_integrity_gate_passed=True,
    )

    first = aggregate_paired_runs(baseline, candidate, result_tier=classify_result_tier(evidence))
    second = aggregate_paired_runs(reversed(baseline), reversed(candidate), result_tier=ResultTier.VERIFIED)

    assert first == second
    assert first.pair_count == 2
    assert first.result_tier is ResultTier.VERIFIED
    assert [item.pair_key for item in first.comparisons] == [
        ("task-1", "pair-a", 0),
        ("task-1", "pair-b", 1),
    ]
    assert abs(first.mean_quality_score_delta - 0.3) < 1e-12
    assert first.mean_context_tokens_delta == -25.0
    assert first.baseline_scorecards.quality.sample_size == 2
    assert first.baseline_scorecards.quality.safety_violation_rate == 0.5
    assert first.baseline_scorecards.context.truncation_rate == 0.5
    assert first.baseline_scorecards.state_integrity.validation_failure_rate == 0.5
    assert first.baseline_scorecards.state_integrity.safety_violation_rate == 0.5
    assert first.baseline_scorecards.state_integrity.privacy_violation_rate == 0.5
    assert first.candidate_scorecards.context.mean_context_tokens == 85.0
    assert first.candidate_scorecards.context.truncation_rate == 0.0

    try:
        aggregate_paired_runs(baseline, candidate[:1])
    except ValueError as exc:
        assert "same paired task runs" in str(exc)
    else:
        raise AssertionError("incomplete paired evidence must be rejected")


def test_result_tiers_require_all_evidence_gates() -> None:
    assert classify_result_tier(ResultTierEvidence()) is ResultTier.SELF_REPORTED

    verified = ResultTierEvidence(
        configuration_complete=True,
        paired_runs_complete=True,
        deterministic_validators_passed=True,
        state_integrity_gate_passed=True,
    )
    assert classify_result_tier(verified) is ResultTier.VERIFIED
    assert classify_result_tier(
        ResultTierEvidence(
            **{
                **verified.__dict__,
                "private_holdout_passed": True,
                "human_review_completed": True,
                "operator_approved": True,
            }
        )
    ) is ResultTier.OFFICIAL


if __name__ == "__main__":
    test_complete_configuration_identity_is_deterministic()
    test_paired_aggregation_is_deterministic_and_keeps_scorecards_separate()
    test_result_tiers_require_all_evidence_gates()
    print("PASS")
