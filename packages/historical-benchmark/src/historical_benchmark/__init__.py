"""Local-only historical candidate resolution and deterministic benchmarking."""

from .benchmark import (
    HistoricalBenchmarkResult,
    benchmark_candidate,
    rank_candidates,
)
from .contracts import (
    ConfigurationIdentity,
    HistoricalCandidate,
    ValidationResult,
    Validator,
    BenchmarkTask,
)
from .fake_runner import DeterministicFakeRunner, FakeRunResult
from .resolver import resolve_historical_candidates

__all__ = [
    "BenchmarkTask",
    "ConfigurationIdentity",
    "DeterministicFakeRunner",
    "FakeRunResult",
    "HistoricalBenchmarkResult",
    "HistoricalCandidate",
    "ValidationResult",
    "Validator",
    "benchmark_candidate",
    "rank_candidates",
    "resolve_historical_candidates",
]
