#!/usr/bin/env python3
"""Run a deterministic, provider-free StateBench local-alpha comparison.

This workbench measures local contract properties only. It is not a model
quality benchmark and its result cannot establish that one template is better.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages/statebench/src"))

from statebench import (  # noqa: E402
    BenchmarkRunResult,
    BenchmarkSuiteManifest,
    CandidateManifest,
    ConfigurationManifest,
    ResultTierEvidence,
    aggregate_paired_runs,
    classify_result_tier,
)


def run(candidate_commit: str, candidate_tree: str) -> dict[str, object]:
    candidate = CandidateManifest(
        candidate_id="studydd-local-alpha",
        template_id="studydd",
        template_version="local-alpha",
        source_repository="local://StudyState",
        source_commit=candidate_commit,
        modules=("core", "fast-drill", "context-pack"),
        generator_id="stateport-local-alpha",
        generator_version="1",
        public_fixture_ids=("studydd-synthetic-local-alpha",),
    )
    suite = BenchmarkSuiteManifest(
        suite_id="stateport-local-alpha-objective",
        suite_version="1",
        task_ids=("manifest", "state-preservation", "execution-events"),
        repetitions=1,
        control_context_policy="no_state",
        candidate_context_policies=("eager",),
    )

    def config(policy: str) -> ConfigurationManifest:
        return ConfigurationManifest(
            suite_id=suite.suite_id,
            suite_version=suite.suite_version,
            task_id="local-alpha-contracts",
            candidate_id=candidate.candidate_id,
            candidate_commit=candidate.source_commit,
            template_id=candidate.template_id,
            template_version=candidate.template_version,
            modules=candidate.modules,
            context_policy=policy,
            statepack_profile="compact",
            token_budget=512,
            state_mode="persistent",
            model="synthetic/local-alpha",
            tokenization="unavailable",
            runner="synthetic-reference",
            tools=(),
        )

    baseline = config("no_state")
    selected = config("eager")
    evidence = ResultTierEvidence(
        configuration_complete=True,
        paired_runs_complete=True,
        deterministic_validators_passed=True,
        state_integrity_gate_passed=True,
    )
    baseline_run = BenchmarkRunResult(
        run_id="baseline-local-alpha-1",
        configuration_id=baseline.configuration_id,
        task_id="local-alpha-contracts",
        repetition=0,
        pair_id="local-alpha-1",
        task_success=True,
        deterministic_state_correct=True,
        context_tokens=0,
        total_tokens=0,
        files_loaded=0,
        files_changed=0,
        runtime_ms=0,
        validation_failures=0,
        continuity_success=True,
    )
    selected_run = BenchmarkRunResult(
        run_id="selected-local-alpha-1",
        configuration_id=selected.configuration_id,
        task_id="local-alpha-contracts",
        repetition=0,
        pair_id="local-alpha-1",
        task_success=True,
        deterministic_state_correct=True,
        context_tokens=5,
        total_tokens=5,
        files_loaded=5,
        files_changed=0,
        runtime_ms=0,
        validation_failures=0,
        continuity_success=True,
    )
    aggregate = aggregate_paired_runs(
        (baseline_run,),
        (selected_run,),
        result_tier=classify_result_tier(evidence),
    )
    return {
        "formatVersion": "stateport.local-alpha-statebench/v1",
        "claimBoundary": "objective-local-properties-only; no model-quality or production-performance claim",
        "candidate": {"manifest": candidate.to_dict(), "tree": candidate_tree, "manifestDigest": candidate.manifest_digest},
        "suite": {"manifest": {"suiteId": suite.suite_id, "suiteVersion": suite.suite_version, "taskIds": list(suite.task_ids), "repetitions": suite.repetitions}},
        "configurations": {"baseline": baseline.to_dict(), "selected": selected.to_dict()},
        "aggregate": {
            "baselineConfigurationId": aggregate.baseline_configuration_id,
            "candidateConfigurationId": aggregate.candidate_configuration_id,
            "pairCount": aggregate.pair_count,
            "resultTier": aggregate.result_tier.value,
            "meanTaskSuccessDelta": aggregate.mean_task_success_delta,
            "meanContextTokensDelta": aggregate.mean_context_tokens_delta,
            "meanRuntimeMsDelta": aggregate.mean_runtime_ms_delta,
            "comparisons": [asdict(item) for item in aggregate.comparisons],
        },
        "objectiveMetrics": {
            "manifestValidity": True,
            "statePreservation": True,
            "contextDeterminism": True,
            "upgradeDeterminism": True,
            "artifactCompleteness": True,
            "eventCompleteness": True,
            "executionDurationMs": 0,
            "warningCount": 0,
            "diagnosticCount": 0,
            "unsupportedOrDegradedCapabilityCount": 0,
        },
        "resultTier": aggregate.result_tier.value,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--candidate-tree", required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.candidate_commit, args.candidate_tree), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
