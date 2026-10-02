#!/usr/bin/env python3
"""Focused tests for the isolated local historical benchmark foundation."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "historical-benchmark" / "src"))

from historical_benchmark import (  # noqa: E402
    BenchmarkTask,
    ConfigurationIdentity,
    HistoricalCandidate,
    ValidationResult,
    Validator,
    benchmark_candidate,
    rank_candidates,
    resolve_historical_candidates,
)


def _git(cwd: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=cwd, text=True, capture_output=True, check=False)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def _repo(parent: Path) -> Path:
    repository = parent / "candidate-repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "user.name", "StatePort synthetic test")
    _git(repository, "config", "user.email", "stateport-test@example.invalid")
    (repository / "artifact.txt").write_text("accepted-v1\n", encoding="utf-8")
    _git(repository, "add", ".")
    _git(repository, "commit", "-qm", "accepted historical candidate")
    (repository / "artifact.txt").write_text("rejected\n", encoding="utf-8")
    _git(repository, "commit", "-qam", "rejected historical candidate")
    (repository / "artifact.txt").write_text("accepted-v2\n", encoding="utf-8")
    _git(repository, "commit", "-qam", "accepted current candidate")
    return repository


def _validator() -> Validator:
    def validate(root: Path, task: BenchmarkTask) -> ValidationResult:
        artifact = root / task.artifact_path
        if not artifact.is_file():
            return ValidationResult(False, "artifact is missing")
        return ValidationResult(artifact.read_text(encoding="utf-8").startswith("accepted"))

    return Validator("synthetic.accepted-prefix/v1", validate)


def _task(validator_id: str) -> BenchmarkTask:
    return BenchmarkTask("copy-artifact", "artifact.txt", "result/artifact.txt", validator_id)


def test_resolver_returns_full_local_history_without_fetching() -> None:
    with tempfile.TemporaryDirectory(prefix="stateport-historical-resolver-") as raw:
        repository = _repo(Path(raw))
        candidates = resolve_historical_candidates(repository, limit=3, repository_id="synthetic/repository")
        assert len(candidates) == 3
        assert candidates[0].repository == "synthetic/repository"
        assert candidates[0].commit != candidates[1].commit
        assert all(len(candidate.commit) == 40 and len(candidate.tree) == 40 for candidate in candidates)
        assert candidates[0].read_file("artifact.txt") == b"accepted-v2\n"
        assert candidates[1].read_file("artifact.txt") == b"rejected\n"


def test_configuration_identity_changes_for_every_required_dimension() -> None:
    base = dict(
        repository="synthetic/repository",
        commit="a" * 40,
        tree="b" * 40,
        adapter="fake-local/v1",
        context_policy="eager",
        task_set=("task-a", "task-b"),
        validator="validator/v1",
    )
    identity = ConfigurationIdentity(**base)
    assert identity.configuration_id == ConfigurationIdentity(**base).configuration_id
    for field, value in (
        ("repository", "synthetic/other"),
        ("commit", "c" * 40),
        ("tree", "d" * 40),
        ("adapter", "fake-local/v2"),
        ("context_policy", "compact"),
        ("task_set", ("task-a", "task-c")),
        ("validator", "validator/v2"),
    ):
        changed = dict(base)
        changed[field] = value
        assert ConfigurationIdentity(**changed).configuration_id != identity.configuration_id


def test_fake_benchmark_scores_only_local_validity_determinism_and_artifacts() -> None:
    with tempfile.TemporaryDirectory(prefix="stateport-historical-benchmark-") as raw:
        repository = _repo(Path(raw))
        candidates = resolve_historical_candidates(repository, limit=3, repository_id="synthetic/repository")
        validator = _validator()
        task = _task(validator.validator_id)
        current = benchmark_candidate(candidates[0], [task], validator, context_policy="eager")
        rejected = benchmark_candidate(candidates[1], [task], validator, context_policy="eager")
        assert current.validity_rate == 1.0
        assert current.determinism_rate == 1.0
        assert current.artifact_presence_rate == 1.0
        assert current.mean_artifact_file_count == 1.0
        assert current.mean_artifact_bytes == len(b"accepted-v2\n")
        assert current.objective_score == 1.0
        assert rejected.validity_rate == 0.0
        assert rejected.artifact_presence_rate == 1.0
        assert rejected.objective_score < current.objective_score
        assert rank_candidates((rejected, current))[0].candidate.commit == current.candidate.commit


def test_missing_candidate_file_is_a_failed_local_run_not_an_exception() -> None:
    with tempfile.TemporaryDirectory(prefix="stateport-historical-missing-") as raw:
        repository = _repo(Path(raw))
        candidate = resolve_historical_candidates(repository, limit=1, repository_id="synthetic/repository")[0]
        validator = _validator()
        missing = BenchmarkTask("missing", "does-not-exist.txt", "result/artifact.txt", validator.validator_id)
        result = benchmark_candidate(candidate, [missing], validator, context_policy="eager")
        assert result.validity_rate == 0.0
        assert result.artifact_presence_rate == 0.0
        assert result.runs[0].validation_details


def test_candidate_rejects_unsafe_repository_paths() -> None:
    candidate = HistoricalCandidate("synthetic/repository", "a" * 40, "b" * 40, "HEAD")
    try:
        candidate.read_file("../outside")
    except ValueError as exc:
        assert "repository-relative" in str(exc)
    else:
        raise AssertionError("unsafe path was accepted")
