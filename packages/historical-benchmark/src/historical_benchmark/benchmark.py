"""Historical candidate benchmark orchestration and objective scorecards."""

from __future__ import annotations

from dataclasses import dataclass
import math
from pathlib import Path
import tempfile

from .contracts import BenchmarkTask, ConfigurationIdentity, HistoricalCandidate, Validator
from .fake_runner import DeterministicFakeRunner, FakeRunResult


@dataclass(frozen=True)
class HistoricalBenchmarkResult:
    candidate: HistoricalCandidate
    configuration: ConfigurationIdentity
    runs: tuple[FakeRunResult, ...]
    validity_rate: float
    determinism_rate: float
    artifact_presence_rate: float
    mean_artifact_file_count: float
    mean_artifact_bytes: float
    objective_score: float


def _rate(values: list[bool]) -> float:
    return math.fsum(1.0 for value in values if value) / len(values) if values else 0.0


def benchmark_candidate(
    candidate: HistoricalCandidate,
    tasks: tuple[BenchmarkTask, ...] | list[BenchmarkTask],
    validator: Validator,
    *,
    context_policy: str,
    adapter: str = "fake-local/v1",
    repetitions: int = 2,
    runner: DeterministicFakeRunner | None = None,
) -> HistoricalBenchmarkResult:
    """Run a candidate using only deterministic local artifact operations."""

    if isinstance(repetitions, bool) or not isinstance(repetitions, int) or repetitions <= 0:
        raise ValueError("repetitions must be a positive integer")
    ordered_tasks = tuple(sorted(tasks, key=lambda task: task.task_id))
    if not ordered_tasks:
        raise ValueError("at least one benchmark task is required")
    if any(task.validator_id != validator.validator_id for task in ordered_tasks):
        raise ValueError("all tasks must use the supplied validator")
    configuration = ConfigurationIdentity(
        repository=candidate.repository,
        commit=candidate.commit,
        tree=candidate.tree,
        adapter=adapter,
        context_policy=context_policy,
        task_set=tuple(task.task_id for task in ordered_tasks),
        validator=validator.validator_id,
    )
    active_runner = runner or DeterministicFakeRunner(adapter)
    if active_runner.adapter != adapter:
        raise ValueError("runner adapter does not match configuration adapter")
    with tempfile.TemporaryDirectory(prefix="stateport-historical-benchmark-") as raw_root:
        root = Path(raw_root)
        runs: list[FakeRunResult] = []
        for task in ordered_tasks:
            for repetition in range(repetitions):
                output_root = root / task.task_id / str(repetition)
                runs.append(
                    active_runner.run(
                        candidate,
                        configuration,
                        task,
                        validator,
                        repetition=repetition,
                        output_root=output_root,
                    )
                )
    determinism: list[bool] = []
    for task in ordered_tasks:
        task_runs = [run for run in runs if run.task_id == task.task_id]
        first = task_runs[0]
        determinism.append(
            all(
                (run.valid, run.artifact_present, run.deterministic_artifact_digest)
                == (first.valid, first.artifact_present, first.deterministic_artifact_digest)
                for run in task_runs[1:]
            )
        )
    validity_rate = _rate([run.valid for run in runs])
    artifact_presence_rate = _rate([run.artifact_present for run in runs])
    determinism_rate = _rate(determinism)
    mean_file_count = math.fsum(run.artifact_file_count for run in runs) / len(runs)
    mean_bytes = math.fsum(run.artifact_bytes for run in runs) / len(runs)
    objective_score = math.fsum((validity_rate, determinism_rate, artifact_presence_rate)) / 3.0
    return HistoricalBenchmarkResult(
        candidate=candidate,
        configuration=configuration,
        runs=tuple(runs),
        validity_rate=validity_rate,
        determinism_rate=determinism_rate,
        artifact_presence_rate=artifact_presence_rate,
        mean_artifact_file_count=mean_file_count,
        mean_artifact_bytes=mean_bytes,
        objective_score=objective_score,
    )


def rank_candidates(results: list[HistoricalBenchmarkResult] | tuple[HistoricalBenchmarkResult, ...]) -> tuple[HistoricalBenchmarkResult, ...]:
    """Return a deterministic ordering; this is not a claim of general superiority."""

    return tuple(
        sorted(
            results,
            key=lambda result: (
                -result.objective_score,
                -result.validity_rate,
                -result.determinism_rate,
                -result.artifact_presence_rate,
                result.candidate.commit,
            ),
        )
    )


__all__ = ["HistoricalBenchmarkResult", "benchmark_candidate", "rank_candidates"]
