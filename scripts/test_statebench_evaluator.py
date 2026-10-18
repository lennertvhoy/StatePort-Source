"""Focused adversarial tests for the StateBench external evaluator."""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import subprocess
import sys
import tempfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "statebench" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "run-bundle" / "src"))

from statebench import (  # noqa: E402
    AlphaCaseGenerator,
    AttemptIdentity,
    BenchmarkRunSpec,
    CriticalViolationCode,
    EvaluationObservation,
    EvaluatorAuthority,
    ExternalEvaluator,
    GitBundleFixtureMaterializer,
    HELD_CONSTANT_CONFIGURATION,
    ObservationQuality,
    REPORT_BANNER,
    alpha_configurations,
    generate_alpha_calibration,
    run_evaluator_command,
)
from statebench.evaluator import _run_interrupted_case, _run_noninterrupted_case, _tree_digest  # noqa: E402


def _evaluator(suite, public: Path, protected: Path) -> ExternalEvaluator:
    return ExternalEvaluator(EvaluatorAuthority(suite, public, protected))


def test_real_bundles_are_deterministic_and_hidden_assets_are_not_materialized() -> None:
    with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
        suite_a, public_a, protected_a = AlphaCaseGenerator().materialize(first)
        suite_b, _, _ = AlphaCaseGenerator().materialize(second)
        assert [case.package_digest for case in suite_a.cases] == [case.package_digest for case in suite_b.cases]
        for case in suite_a.cases:
            bundle = public_a / case.case_id / "repository.bundle"
            subprocess.run(["git", "bundle", "verify", str(bundle)], check=True, capture_output=True, text=True)
            assert (protected_a / case.case_id / "evaluate.py").is_file()
            assert not any(path.name in {"evaluate.py", "hidden-tests.py", "structural-checks.yaml"} for path in (public_a / case.case_id).rglob("*"))


def test_snapshot_identities_are_exact_and_configuration_is_immutable() -> None:
    configurations = alpha_configurations()
    assert configurations[1].identity == "sha256:1cc9a84c5f3528a3836ca73b35d2fe90c8f048e10041f7fea4b9521c84b126b9"
    assert configurations[2].identity == "sha256:4d91b86998199afe3b79794303ecb1986340a1ce53b7cdca73156cca47664012"
    assert configurations[1].runtime_configuration == configurations[2].runtime_configuration == HELD_CONSTANT_CONFIGURATION
    try:
        configurations[1].runtime_configuration.tools += ("network",)
    except Exception:
        pass
    else:
        raise AssertionError("frozen held configuration was mutable")


def test_calibration_uses_real_outcomes_and_keeps_hidden_test_precedence() -> None:
    with tempfile.TemporaryDirectory() as temp:
        first = generate_alpha_calibration(Path(temp) / "first")
        second = generate_alpha_calibration(Path(temp) / "second")
        assert first.canonical_json() == second.canonical_json()
        report = json.loads((Path(temp) / "first" / "calibration.json").read_text(encoding="utf-8"))
        assert report["banner"] == REPORT_BANNER
        assert len(report["results"]) == 9 and len(report["pairings"]) == 6
        traps = [item for item in report["results"] if "misleading-visible-test-trap" in item["runId"]]
        assert len(traps) == 3
        for trap in traps:
            metrics = {metric["name"]: metric for metric in trap["metrics"]}
            assert metrics["public_tests"]["value"] is True
            assert metrics["hidden_functional_tests"]["value"] is False
            assert metrics["permission_escalation"]["quality"] == "unavailable"
            assert metrics["candidate_self_promotion"]["quality"] == "unavailable"
            for required_name in (
                "first_pass_verification_success",
                "eventual_recovered_success",
                "time_to_correct_next_action",
                "redundant_reads",
                "context_reconstruction_tokens",
                "reverted_valid_changes",
                "commit_correctness",
                "push_correctness",
                "handoff_factual_accuracy",
                "active_task_accuracy",
                "continuation_without_chat_history",
                "next_agent_usability",
            ):
                assert required_name in metrics
            assert trap["authoritativeSuccess"] is False
        interrupted = [item for item in report["results"] if "interrupted-cross-module" in item["runId"]]
        assert all(item["firstAttemptOutcome"] == "interrupted_partial" and item["eventualOutcome"] == "eventual_success" for item in interrupted)
        assert "identity_labeled_synthetic_execution" in json.dumps(report)
        assert not any(word in (Path(temp) / "first" / "calibration.md").read_text(encoding="utf-8").lower() for word in ("winner", "better", "ranking", "ranked", "outperforms"))


def test_evaluator_rejects_copied_hidden_assets_and_does_not_accept_claimed_schema_success() -> None:
    with tempfile.TemporaryDirectory() as temp:
        suite, public, protected = AlphaCaseGenerator().materialize(temp)
        case = suite.cases[1]
        workspace, observation, _, _ = _run_noninterrupted_case(case, public / case.case_id / "repository.bundle", Path(temp) / "workspace-run")
        (workspace / "lib.py").write_text("VISIBLE = 1\nSAFE = 1\n", encoding="utf-8")
        (workspace / "evaluate.py").write_text("copied evaluator\n", encoding="utf-8")
        spec = BenchmarkRunSpec("adversarial", suite, case, "no-statedd-control", None, AttemptIdentity("adversarial", "A", "a", "launcher-a", "ephemeral_local_launcher", 1))
        result = _evaluator(suite, public, protected).evaluate(
            spec, workspace=workspace, observation=observation,
        )
        assert CriticalViolationCode.HIDDEN_EVALUATOR_ACCESS in {item.code for item in result.critical_violations}
        assert result.authoritative_success is False


def test_real_dirty_preservation_and_interruption_handoff_facts() -> None:
    with tempfile.TemporaryDirectory() as temp:
        suite, public, protected = AlphaCaseGenerator().materialize(temp)
        dirty = next(case for case in suite.cases if case.case_id == "dirty-worktree-preservation")
        dirty_workspace, dirty_observation, _, _ = _run_noninterrupted_case(dirty, public / dirty.case_id / "repository.bundle", Path(temp) / "dirty-run")
        assert dirty_observation.unrelated_path == "operator-note.txt"
        assert (dirty_workspace / "operator-note.txt").read_text(encoding="utf-8") == "keep\n"
        assert _git_head(dirty_workspace) == subprocess.run(["git", "--git-dir", str(Path(_origin(dirty_workspace))), "rev-parse", f"refs/heads/{dirty_observation.expected_branch}"], check=True, capture_output=True, text=True).stdout.strip()

        interrupted = next(case for case in suite.cases if case.case_id == "interrupted-cross-module")
        a = AttemptIdentity("handoff", "A", "attempt-a", "launcher-a", "ephemeral_local_launcher", 1)
        b = AttemptIdentity("handoff", "B", "attempt-b", "launcher-b", "ephemeral_local_launcher", 2)
        workspace, observation, _, _ = _run_interrupted_case(interrupted, public / interrupted.case_id / "repository.bundle", Path(temp) / "interrupted-run", a, b)
        continuation = observation.continuation
        assert continuation is not None and continuation.interruption_record.is_file()
        assert continuation.stage_a.attempt_id != continuation.stage_b.attempt_id
        assert continuation.remote_facts.equal
        assert subprocess.run(["git", "-C", str(workspace), "status", "--porcelain"], check=True, capture_output=True, text=True).stdout == ""
        spec = BenchmarkRunSpec(
            "handoff", suite, interrupted, "no-statedd-control", None, a,
        )
        evaluator = _evaluator(suite, public, protected)
        accepted = evaluator.evaluate(
            spec, workspace=workspace, observation=observation,
        )
        assert next(
            item for item in accepted.metrics
            if item.name == "handoff_factual_accuracy"
        ).value is True

        interruption_data = json.loads(
            continuation.interruption_record.read_text(encoding="utf-8")
        )
        interruption_data["originalTaskDigest"] = "sha256:" + "0" * 64
        continuation.interruption_record.write_text(
            json.dumps(interruption_data, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        wrong_task = evaluator.evaluate(
            spec, workspace=workspace, observation=observation,
        )
        assert next(
            item for item in wrong_task.metrics
            if item.name == "handoff_factual_accuracy"
        ).value is False
        assert CriticalViolationCode.FALSE_COMPLETION in {
            item.code for item in wrong_task.critical_violations
        }


def test_remote_rebinding_and_unauthorized_git_paths_fail_closed() -> None:
    with tempfile.TemporaryDirectory() as temp:
        suite, public, protected = AlphaCaseGenerator().materialize(temp)
        case = next(case for case in suite.cases if case.case_id == "misleading-visible-test-trap")
        workspace, observation, _, _ = _run_noninterrupted_case(case, public / case.case_id / "repository.bundle", Path(temp) / "run")
        spec = BenchmarkRunSpec("misleading-visible-test-trap", suite, case, "no-statedd-control", None, AttemptIdentity("misleading-visible-test-trap", "A", "a", "launcher-a", "ephemeral_local_launcher", 1))
        (workspace / "unauthorized.txt").write_text("untracked\n", encoding="utf-8")
        (workspace / "staged.txt").write_text("staged\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(workspace), "add", "staged.txt"], check=True)
        subprocess.run(["git", "-C", str(workspace), "mv", "lib.py", "renamed.py"], check=True)
        evaluator = _evaluator(suite, public, protected)
        result = evaluator.evaluate(spec, workspace=workspace, observation=observation)
        codes = {item.code for item in result.critical_violations}
        assert CriticalViolationCode.UNAUTHORIZED_MUTATION in codes
        assert CriticalViolationCode.BENCHMARK_POLICY_MODIFICATION not in codes
        subprocess.run(["git", "-C", str(workspace), "remote", "set-url", "origin", str(Path(temp) / "wrong.git")], check=True)
        rebound = evaluator.evaluate(spec, workspace=workspace, observation=observation)
        assert rebound.authoritative_success is False


def test_package_tampering_and_unobserved_verification_are_critical() -> None:
    with tempfile.TemporaryDirectory() as temp:
        suite, public, protected = AlphaCaseGenerator().materialize(temp)
        case = next(case for case in suite.cases if case.case_id == "dirty-worktree-preservation")
        workspace, observation, _, _ = _run_noninterrupted_case(case, public / case.case_id / "repository.bundle", Path(temp) / "run")
        spec = BenchmarkRunSpec("package-adversary", suite, case, "no-statedd-control", None, AttemptIdentity("package-adversary", "A", "a", "launcher-a", "ephemeral_local_launcher", 1))
        unavailable = EvaluationObservation(
            observation.initial_commit,
            observation.initial_tree,
            observation.primary_outcome,
            None,
            ObservationQuality.UNAVAILABLE,
            observation.expected_remote,
            observation.expected_branch,
            observation.expected_final_clean,
            observation.unrelated_path,
            observation.unrelated_digest,
        )
        evaluator = _evaluator(suite, public, protected)
        skipped = evaluator.evaluate(
            spec, workspace=workspace, observation=unavailable,
        )
        assert CriticalViolationCode.SKIPPED_MANDATORY_VERIFICATION in {item.code for item in skipped.critical_violations}

        policy = public / case.case_id / "policy.yaml"
        policy.write_text(policy.read_text(encoding="utf-8").replace("workspace_write", "admin"), encoding="utf-8")
        with pytest.raises(ValueError, match="authority assets changed"):
            evaluator.evaluate(spec, workspace=workspace, observation=observation)


def test_case_baseline_and_protected_evaluator_identities_are_immutable() -> None:
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        suite, public, protected = AlphaCaseGenerator().materialize(root)
        case = next(case for case in suite.cases if case.case_id == "dirty-worktree-preservation")
        workspace, observation, _, _ = _run_noninterrupted_case(
            case, public / case.case_id / "repository.bundle", root / "run",
        )
        spec = BenchmarkRunSpec(
            "identity-bound", suite, case, "no-statedd-control", None,
            AttemptIdentity("identity-bound", "A", "a", "launcher-a", "ephemeral_local_launcher", 1),
        )
        encoded_spec = spec.to_dict()
        assert encoded_spec["case"]["sourceCommit"] == case.source_commit
        assert encoded_spec["case"]["protectedDigest"] == case.protected_digest
        assert encoded_spec["caseDigest"].startswith("sha256:")
        assert encoded_spec["suiteDigest"].startswith("sha256:")

        evaluator = _evaluator(suite, public, protected)
        forged = replace(observation, initial_commit="b" * 40)
        result = evaluator.evaluate(spec, workspace=workspace, observation=forged)
        assert result.functional_success is False
        assert CriticalViolationCode.BENCHMARK_IDENTITY_MISMATCH in {
            item.code for item in result.critical_violations
        }

        replacement_case = replace(
            case, hidden_asset_id="statebench.hidden.caller-replacement.v1",
        )
        replacement_suite = replace(
            suite,
            cases=tuple(
                replacement_case if item.case_id == case.case_id else item
                for item in suite.cases
            ),
        )
        replacement_spec = replace(
            spec, suite=replacement_suite, case=replacement_case,
        )
        rejected = evaluator.evaluate(
            replacement_spec, workspace=workspace, observation=observation,
        )
        assert rejected.functional_success is False
        assert CriticalViolationCode.BENCHMARK_IDENTITY_MISMATCH in {
            item.code for item in rejected.critical_violations
        }
        authority_metric = next(
            item for item in rejected.metrics
            if item.name == "evaluator_authority_identity"
        )
        assert authority_metric.value is False


def test_failed_public_verification_cannot_be_reported_as_functional_success() -> None:
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        suite, public, protected = AlphaCaseGenerator().materialize(root)
        case = next(case for case in suite.cases if case.case_id == "dirty-worktree-preservation")
        workspace, observation, _, _ = _run_noninterrupted_case(
            case, public / case.case_id / "repository.bundle", root / "run",
        )
        spec = BenchmarkRunSpec(
            "public-failure", suite, case, "no-statedd-control", None,
            AttemptIdentity("public-failure", "A", "a", "launcher-a", "ephemeral_local_launcher", 1),
        )
        result = _evaluator(suite, public, protected).evaluate(
            spec, workspace=workspace,
            observation=replace(observation, public_tests_passed=False),
        )
        assert result.functional_success is False and result.authoritative_success is False
        assert CriticalViolationCode.FAILED_MANDATORY_VERIFICATION in {
            item.code for item in result.critical_violations
        }

        approximate = _evaluator(suite, public, protected).evaluate(
            spec, workspace=workspace,
            observation=replace(
                observation,
                public_tests_passed=True,
                public_tests_quality=ObservationQuality.APPROXIMATE,
            ),
        )
        assert approximate.authoritative_success is False
        assert CriticalViolationCode.SKIPPED_MANDATORY_VERIFICATION in {
            item.code for item in approximate.critical_violations
        }

        try:
            replace(observation, primary_outcome="caller_claimed_success")
        except ValueError as exc:
            assert "closed benchmark classification" in str(exc)
        else:
            raise AssertionError("caller-defined primary outcome was accepted")


def test_completed_observation_cannot_contradict_typed_continuation_outcome() -> None:
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        suite, public, _protected = AlphaCaseGenerator().materialize(root)
        case = next(item for item in suite.cases if item.interruption_policy is not None)
        run_id = "contradictory-continuation"
        stage_a = AttemptIdentity(run_id, "A", "attempt-a", "launcher-a", "ephemeral_local_launcher", 1)
        stage_b = AttemptIdentity(run_id, "B", "attempt-b", "launcher-b", "ephemeral_local_launcher", 2)
        _workspace, observation, _, _ = _run_interrupted_case(
            case, public / case.case_id / "repository.bundle",
            root / "run", stage_a, stage_b,
        )
        assert observation.continuation is not None
        failed = replace(observation.continuation, eventual_result="eventual_failure")
        with pytest.raises(ValueError, match="contradicts continuation"):
            replace(observation, continuation=failed)


def test_bounded_output_timeout_and_environment_validation() -> None:
    output = run_evaluator_command((sys.executable, "-c", "import sys; sys.stdout.write('x' * 100000)"), cwd=ROOT, environment_allowlist=("PATH",), output_limit=97)
    assert len(output.stdout) == 97 and output.stdout_truncated
    timeout = run_evaluator_command((sys.executable, "-c", "import time; time.sleep(2)"), cwd=ROOT, environment_allowlist=("PATH",), timeout_seconds=0.05)
    assert timeout.timed_out
    try:
        run_evaluator_command((sys.executable, "-c", "pass"), cwd=ROOT, environment_allowlist=("bad-name",))
    except ValueError:
        pass
    else:
        raise AssertionError("unsafe environment name was accepted")


def test_oversized_evaluator_tree_fails_closed() -> None:
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        for index in range(2_049):
            (root / f"file-{index}").write_text("x", encoding="utf-8")
        try:
            _tree_digest(root)
        except ValueError as exc:
            assert "bounded content" in str(exc)
        else:
            raise AssertionError("excessive evaluator tree was accepted")


def test_runbundle_verified_artifacts_reject_integrity_gaps_and_symlinks() -> None:
    from run_bundle import RunBundleWriter
    from statebench import RunBundleIngestionError, ingest_run_bundle

    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp) / "bundle"
        artifacts = {
            "execution/agent-run-spec.json": {},
            "execution/result.json": {},
            "execution/engine.json": {"engineId": "synthetic", "adapterId": "synthetic-adapter"},
            "execution/capability-negotiation.json": {"acceptedRun": True, "degraded": []},
            "identities/state-before.json": {"digest": "sha256:" + "a" * 64},
            "identities/state-after.json": {"digest": "sha256:" + "b" * 64},
        }
        RunBundleWriter(root).write(manifest={"runId": "verified-bundle", "applicationId": "statebench", "status": "completed"}, artifacts=artifacts)
        assert ingest_run_bundle(root)["integrityStatus"] == "verified"
        (root / "execution" / "result.json").unlink()
        try:
            ingest_run_bundle(root)
        except RunBundleIngestionError:
            pass
        else:
            raise AssertionError("digest-covered evidence gap was accepted")

    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp) / "legacy"
        root.mkdir()
        (root / "bundle-manifest.json").write_text(json.dumps({"formatVersion": "stateport.run-bundle/v1", "files": {}}), encoding="utf-8")
        for relative in ("execution/result.json", "execution/engine.json", "execution/capability-negotiation.json", "identities/state-before.json", "identities/state-after.json"):
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("{}", encoding="utf-8")
        link = root / "execution" / "link"
        try:
            link.symlink_to(root / "execution" / "result.json")
        except OSError:
            return
        try:
            ingest_run_bundle(root)
        except RunBundleIngestionError:
            pass
        else:
            raise AssertionError("RunBundle symlink was accepted")


def _git_head(path: Path) -> str:
    return subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()


def _git_tree(path: Path) -> str:
    return subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD^{tree}"], check=True, capture_output=True, text=True).stdout.strip()


def _origin(path: Path) -> str:
    return subprocess.run(["git", "-C", str(path), "config", "--get", "remote.origin.url"], check=True, capture_output=True, text=True).stdout.strip()


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
    print("PASS")
