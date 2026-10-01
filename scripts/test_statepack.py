#!/usr/bin/env python3
"""Focused tests for the deterministic StatePack foundation."""

from __future__ import annotations

import copy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORE_SRC = ROOT / "packages" / "statedd-core" / "src"
if str(CORE_SRC) not in sys.path:
    sys.path.insert(0, str(CORE_SRC))

from statedd_core.stateir import StateFact, StateIR
from statedd_core.statepack import (
    STATEPACK_FORMAT,
    StatePack,
    build_state_pack,
    compare_state_packs,
    inspect_state_pack,
)


def _ir() -> StateIR:
    return StateIR(
        instance_id="demo-instance",
        source_revision="sha256:revision-1",
        source_hashes={
            "state/profile.yaml": "sha256:profile",
            "state/tasks.yaml": "sha256:tasks",
        },
        facts=(
            StateFact(
                path="metadata.name",
                value="Demo learner",
                source_file="state/profile.yaml",
            ),
            StateFact(
                path="profile.status",
                value="active",
                source_file="state/profile.yaml",
            ),
            StateFact(
                path="tasks.next_action",
                value="Review algebra homework",
                source_file="state/tasks.yaml",
            ),
            StateFact(
                path="tasks.last_result",
                value="Algebra practice completed",
                source_file="state/tasks.yaml",
            ),
        ),
    )


def test_deterministic_eager_pack() -> None:
    first = build_state_pack(_ir(), "show current state", "test-model", 100)
    second = build_state_pack(_ir(), "show current state", "test-model", 100)

    assert first == second
    assert first.manifest["formatVersion"] == STATEPACK_FORMAT
    assert first.manifest["selection"] == "eager"
    assert first.manifest["includedFacts"] == sorted(first.manifest["includedFacts"])
    assert first.manifest["lossiness"] == "lossless"


def test_task_selection_uses_normalized_overlap_and_metadata_fallback() -> None:
    pack = build_state_pack(
        _ir(), "ALgebra homework", "test-model", 100, selection="compact_context"
    )
    assert pack.manifest["selection"] == "compact_context"
    assert pack.manifest["includedFacts"] == ["tasks.next_action", "tasks.last_result"]

    fallback = build_state_pack(
        _ir(), "unmatched words", "test-model", 100, selection="compact_context"
    )
    assert fallback.manifest["includedFacts"] == ["metadata.name", "profile.status"]


def test_budget_truncation_retains_ranked_facts_and_marks_manifest() -> None:
    pack = build_state_pack(
        _ir(), "algebra homework", "test-model", 3, selection="compact_context"
    )
    status = pack.manifest["truncationStatus"]
    assert status["truncated"] is True
    assert status["reason"] == "budget"
    assert len(pack.manifest["includedFacts"]) < status["selectedFactCount"]
    assert len(pack.manifest["excludedFacts"]) > 0


def test_custom_token_counter_is_recorded_as_exact() -> None:
    pack = build_state_pack(
        _ir(),
        "show state",
        "exact-model",
        20,
        token_counter=lambda text: len(text),
        tokenizer_id="exact-test-v1",
    )
    measurement = pack.manifest["tokenMeasurement"]
    assert measurement == {
        "tokenizerId": "exact-test-v1",
        "tokenCount": len(pack.text),
        "exact": True,
    }


def test_manifest_carries_fact_level_source_provenance_without_values() -> None:
    pack = build_state_pack(_ir(), "show state", "test-model", 100)

    provenance = pack.manifest["factProvenance"]
    assert provenance
    assert provenance[0]["path"] == pack.manifest["includedFacts"][0]
    assert provenance[0]["sourceFile"] in pack.manifest["includedFiles"]
    assert "value" not in provenance[0]


def test_invalid_token_measurement_is_rejected() -> None:
    try:
        build_state_pack(
            _ir(),
            "show state",
            "test-model",
            100,
            token_counter=lambda _text: True,
            tokenizer_id="bad-counter",
        )
    except ValueError as exc:
        assert "non-negative integer" in str(exc)
    else:
        raise AssertionError("expected invalid token measurement to be rejected")


def test_manifest_contract_and_to_dict() -> None:
    pack = build_state_pack(_ir(), "show state", "test-model", 100, profile="audit")
    required = {
        "formatVersion",
        "instanceId",
        "sourceRevision",
        "sourceHashes",
        "generatedFor",
        "budgetTokens",
        "profile",
        "selection",
        "includedFiles",
        "excludedFiles",
        "includedFacts",
        "excludedFacts",
        "lossiness",
        "truncationStatus",
        "tokenMeasurement",
    }
    assert required <= set(pack.manifest)
    assert pack.to_dict() == {"manifest": pack.manifest, "text": pack.text}
    assert isinstance(pack, StatePack)


def test_inspect_and_compare_do_not_mutate_and_report_dimensions() -> None:
    left = build_state_pack(_ir(), "show state", "test-model", 100)
    right = build_state_pack(_ir(), "different task", "other-model", 8, profile="human")
    before = copy.deepcopy(left.to_dict())

    inspected = inspect_state_pack(left)
    comparison = compare_state_packs(left, right)

    assert inspected["valid"] is True
    assert inspected["stale"] is False
    assert comparison["equal"] is False
    assert "tokenCount" in comparison["differences"]
    assert "profile" in comparison["differences"]
    assert "budgetTokens" in comparison["differences"]
    assert "generatedFor" in comparison["differences"]
    assert left.to_dict() == before


if __name__ == "__main__":
    test_deterministic_eager_pack()
    test_task_selection_uses_normalized_overlap_and_metadata_fallback()
    test_budget_truncation_retains_ranked_facts_and_marks_manifest()
    test_custom_token_counter_is_recorded_as_exact()
    test_manifest_carries_fact_level_source_provenance_without_values()
    test_invalid_token_measurement_is_rejected()
    test_manifest_contract_and_to_dict()
    test_inspect_and_compare_do_not_mutate_and_report_dimensions()
    print("PASS")
