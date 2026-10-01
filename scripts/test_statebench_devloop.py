"""Focused synthetic-Git tests for the StateBench DevLoop profile."""

from __future__ import annotations

from datetime import date
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import yaml

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "statebench" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "run-bundle" / "src"))

from statebench import (  # noqa: E402
    DEVLOOP_EVALUATION_FORMAT,
    DEVLOOP_TRACE_FORMAT,
    HELD_CONSTANT_CONFIGURATION,
    DevLoopCollectionError,
    DevLoopCollectionFailure,
    DevLoopCollectionSpec,
    DevLoopCollector,
    DevLoopEvaluator,
    DevLoopMetricEvidence,
    MetricObservation,
    ObservationQuality,
    PathClassification,
    classify_path,
    structural_trace_from_dict,
)


def _git(repository: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repository), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _commit(repository: Path, changes: dict[str, str], message: str, second: int) -> str:
    for name, content in changes.items():
        path = repository / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_AUTHOR_NAME": "Synthetic DevLoop",
            "GIT_AUTHOR_EMAIL": "devloop@example.invalid",
            "GIT_COMMITTER_NAME": "Synthetic DevLoop",
            "GIT_COMMITTER_EMAIL": "devloop@example.invalid",
            "GIT_AUTHOR_DATE": f"2000-01-01T00:00:{second:02d}+0000",
            "GIT_COMMITTER_DATE": f"2000-01-01T00:00:{second:02d}+0000",
        }
    )
    subprocess.run(["git", "-C", str(repository), "add", "--all"], check=True, env=environment)
    subprocess.run(
        ["git", "-C", str(repository), "commit", "-m", message],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    return _git(repository, "rev-parse", "HEAD")


def _repository(root: Path) -> tuple[Path, dict[str, str]]:
    repository = root / "repository"
    repository.mkdir()
    subprocess.run(["git", "-C", str(repository), "init", "-q", "-b", "main"], check=True)
    b0 = _commit(repository, {"src/app.py": "value = 1\n"}, "initial behavior", 1)
    s0 = _commit(repository, {"STATUS.md": "baseline\n"}, "baseline state", 2)
    b1 = _commit(
        repository,
        {
            "src/app.py": "value = 2\n",
            "tests/test_app.py": "def test_value(): pass\n",
            "scripts/validate_feature.py": "print('ok')\n",
            "docs/guide.md": "guide\n",
            "config/example.yaml": "enabled: true\n",
            "customer-secret-alice.txt": "private fixture marker\n",
        },
        "never persist conversation: customer alice secret",
        3,
    )
    b2 = _commit(
        repository,
        {"src/app.py": "value = 1\n", "customer-secret-alice.txt": "private fixture marker\n"},
        "restore product tree subset",
        4,
    )
    s1 = _commit(repository, {"STATUS.md": "current\n", "WORKLOG.md": "history\n"}, "current state", 5)
    (repository / "discarded-conversation-secret.txt").write_text("must stay untouched\n", encoding="utf-8")
    return repository, {"b0": b0, "s0": s0, "b1": b1, "b2": b2, "s1": s1}


def _spec(heads: dict[str, str], **overrides: str) -> DevLoopCollectionSpec:
    values = {
        "repository_id": "synthetic-repository",
        "base_behavioural_head": heads["b0"],
        "current_behavioural_head": heads["b2"],
        "base_state_head": heads["s0"],
        "current_state_head": heads["s1"],
    }
    values.update(overrides)
    return DevLoopCollectionSpec(**values)


def test_path_classification_is_typed_and_deterministic() -> None:
    assert classify_path("src/app.py") is PathClassification.PRODUCT
    assert classify_path("tests/test_app.py") is PathClassification.TESTS
    assert classify_path("scripts/validate_repo.py") is PathClassification.VALIDATION_TOOLING
    assert classify_path("config/policy.yaml") is PathClassification.POLICY
    assert classify_path("docs/guide.md") is PathClassification.DOCUMENTATION
    assert classify_path("PROJECT_STATE.yaml") is PathClassification.STATE_ONLY


def test_collector_is_read_only_and_emits_only_bounded_structural_facts() -> None:
    with tempfile.TemporaryDirectory() as temp:
        repository, heads = _repository(Path(temp))
        before = _git(repository, "status", "--porcelain=v1", "-z")
        trace = DevLoopCollector(repository).collect(_spec(heads))
        after = _git(repository, "status", "--porcelain=v1", "-z")
        assert before == after
        assert trace.to_dict()["formatVersion"] == DEVLOOP_TRACE_FORMAT
        assert trace.behavioural_distance == 3
        assert trace.state_distance == 3
        assert trace.state_commits_after_behavioural_head == 1
        assert len(trace.commits) == 3
        assert trace.commits[-1].state_only is True
        encoded = trace.canonical_json()
        assert "customer-secret-alice" not in encoded
        assert "discarded-conversation-secret" not in encoded
        assert "never persist conversation" not in encoded
        assert str(repository) not in encoded
        assert '"containsRawDiffs":false' in encoded
        assert '"containsRawPaths":false' in encoded
        loaded = structural_trace_from_dict(json.loads(encoded))
        assert loaded.canonical_json() == encoded
        injected = json.loads(encoded)
        injected["commits"][0]["rawPaths"] = ["secret/customer.txt"]
        with pytest.raises(ValueError, match="unsupported fields"):
            structural_trace_from_dict(injected)

        altered_collector = json.loads(encoded)
        altered_collector["collector"]["version"] = "untrusted"
        with pytest.raises(ValueError, match="collector identity"):
            structural_trace_from_dict(altered_collector)

        altered_ancestry = json.loads(encoded)
        altered_ancestry["ancestry"]["validated"] = False
        with pytest.raises(ValueError, match="successful ancestry"):
            structural_trace_from_dict(altered_ancestry)

        altered_totals = json.loads(encoded)
        altered_totals["pathClassTotals"]["product"] += 1
        with pytest.raises(ValueError, match="totals contradict"):
            structural_trace_from_dict(altered_totals)

        contradictory_state = json.loads(encoded)
        contradictory_state["commits"][0]["stateOnly"] = True
        with pytest.raises(ValueError, match="state-only classification"):
            structural_trace_from_dict(contradictory_state)


def test_divergence_missing_history_and_mistyped_state_fail_closed() -> None:
    with tempfile.TemporaryDirectory() as temp:
        repository, heads = _repository(Path(temp))
        collector = DevLoopCollector(repository)

        with pytest.raises(DevLoopCollectionError) as missing:
            collector.collect(_spec(heads, base_behavioural_head="f" * 40))
        assert missing.value.code is DevLoopCollectionFailure.MISSING_HISTORY
        assert missing.value.requires_full_rescan is True

        _git(repository, "switch", "-q", "-c", "diverged", heads["s0"])
        divergent = _commit(repository, {"src/diverged.py": "value = 1\n"}, "diverged", 6)
        _git(repository, "switch", "-q", "main")
        with pytest.raises(DevLoopCollectionError) as divergence:
            collector.collect(_spec(heads, current_behavioural_head=divergent))
        assert divergence.value.code is DevLoopCollectionFailure.DIVERGENT_HISTORY
        assert divergence.value.requires_full_rescan is True

        bad_state = _commit(repository, {"src/late.py": "late = True\n"}, "behavior after typed head", 7)
        with pytest.raises(DevLoopCollectionError) as mistyped:
            collector.collect(_spec(heads, current_state_head=bad_state))
        assert mistyped.value.code is DevLoopCollectionFailure.INVALID_STATE_DESCENDANT
        assert mistyped.value.requires_full_rescan is True


def test_evaluator_preserves_a_fixed_vector_without_inventing_observations() -> None:
    with tempfile.TemporaryDirectory() as temp:
        repository, heads = _repository(Path(temp))
        trace = DevLoopCollector(repository).collect(_spec(heads))
        report = DevLoopEvaluator().evaluate(
            report_id="devloop-report-1",
            slice_id="BL-EXAMPLE-001",
            trace=trace,
            configuration=HELD_CONSTANT_CONFIGURATION,
            observations=(
                DevLoopMetricEvidence(
                    MetricObservation(
                        "first_pass_slice_success",
                        True,
                        ObservationQuality.EXACT,
                        "boolean",
                    ),
                    ("test-receipt-1",),
                ),
                DevLoopMetricEvidence(
                    MetricObservation(
                        "failure_discovery_stage",
                        "focused_test",
                        ObservationQuality.EXACT,
                        "stage",
                    ),
                    ("test-receipt-1",),
                ),
            ),
        )
        encoded = report.to_dict()
        assert encoded["formatVersion"] == DEVLOOP_EVALUATION_FORMAT
        assert encoded["configurationQuality"] == "exact"
        assert encoded["authoritativePerformanceClaim"] is False
        assert encoded["automaticPolicyMutation"] is False
        assert encoded["promotionDecision"] is None
        metrics = {item["name"]: item for item in encoded["resultVector"]}
        assert metrics["first_pass_slice_success"]["value"] is True
        assert metrics["rework_ratio"] == {
            "name": "rework_ratio",
            "value": None,
            "quality": "unavailable",
            "unit": "ratio",
            "evidenceReferences": [],
        }
        assert len(metrics) == 32
        assert encoded["workspaceLifecycleGate"]["status"] == "not_evaluated"
        assert encoded["workspaceLifecycleGate"]["processQualityScorePermitted"] is False


def test_evaluator_rejects_unsupported_or_unsubstantiated_observations() -> None:
    with pytest.raises(ValueError, match="require at least one evidence"):
        DevLoopMetricEvidence(
            MetricObservation("false_closure_count", 1, ObservationQuality.EXACT, "count")
        )
    with pytest.raises(ValueError, match="non-negative integer"):
        DevLoopEvaluator()._validate_metric(
            MetricObservation("human_steering_count", -1, ObservationQuality.EXACT, "count"),
            "count",
        )


def test_workspace_leak_is_a_hard_devloop_failure_even_when_product_passes() -> None:
    with tempfile.TemporaryDirectory() as temp:
        repository, heads = _repository(Path(temp))
        trace = DevLoopCollector(repository).collect(_spec(heads))
        observations = [
            DevLoopMetricEvidence(
                MetricObservation("first_pass_slice_success", True, ObservationQuality.EXACT, "boolean"),
                ("product-tests",),
            )
        ]
        for name in (
            "worktrees_leaked",
            "unclassified_workspace_count",
            "expired_lease_count",
            "cleanup_failures",
            "closure_gate_workspace_failures",
        ):
            observations.append(
                DevLoopMetricEvidence(
                    MetricObservation(name, 1 if name == "worktrees_leaked" else 0, ObservationQuality.EXACT, "count"),
                    ("workspace-cleanup-receipt",),
                )
            )
        report = DevLoopEvaluator().evaluate(
            report_id="devloop-leak-regression",
            slice_id="BL-CONVERGENCE-001",
            trace=trace,
            configuration=HELD_CONSTANT_CONFIGURATION,
            observations=observations,
        ).to_dict()
        assert report["resultVector"][0]["value"] is True
        assert report["workspaceLifecycleGate"] == {
            "status": "failed",
            "blockingMetrics": ["worktrees_leaked"],
            "unavailableMetrics": [],
            "processQualityScorePermitted": False,
        }


def test_escaped_workspace_accumulation_is_a_permanent_fixture() -> None:
    fixture = yaml.safe_load(
        (ROOT / "fixtures/statebench/workspace-lifecycle-incident-2026-07-29.yaml").read_text(
            encoding="utf-8"
        )
    )
    assert fixture == {
        "schema": "statebench.workspace-lifecycle-escaped-process-fixture/v1",
        "fixtureId": "workspace-lifecycle-incident-2026-07-29",
        "incidentId": "INC-2026-07-27-AUTONOMOUS-CONVERGENCE",
        "observedOn": date(2026, 7, 29),
        "peak_registered_worktrees": 89,
        "local_branches": 84,
        "owner_intervention_required": True,
        "owner_intervention_should_have_been_required": False,
        "classification": "major_process_incident",
        "use": "permanent_regression_fixture",
        "authoritativePerformanceClaim": False,
    }
