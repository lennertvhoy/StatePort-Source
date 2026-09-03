"""Immutable StateBench v0 manifests and run records."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import math
from typing import Any, Iterable


STATEBENCH_FORMAT = "statebench/v0"
CANDIDATE_MANIFEST_FORMAT = "statebench.candidate/v0"
CONFIGURATION_MANIFEST_FORMAT = "statebench.configuration/v0"
SUITE_MANIFEST_FORMAT = "statebench.suite/v0"


def _tuple(values: Iterable[Any]) -> tuple[Any, ...]:
    """Copy an input iterable into an immutable, deterministic tuple."""

    return tuple(values)


def _require(value: str, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _non_negative(value: int | float, name: str) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be numeric")
    if not math.isfinite(float(value)) or value < 0:
        raise ValueError(f"{name} must be finite and non-negative")
    return value


def _bounded(value: float, name: str) -> float:
    _non_negative(value, name)
    if value > 1:
        raise ValueError(f"{name} must be between 0 and 1")
    return float(value)


def _json_value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    return value


def _canonical_json(value: Any) -> str:
    return json.dumps(_json_value(value), sort_keys=True, separators=(",", ":"))


class ResultTier(str, Enum):
    """Evidence provenance, not a quality ranking."""

    SELF_REPORTED = "self_reported"
    VERIFIED = "verified"
    OFFICIAL = "official"


@dataclass(frozen=True)
class CandidateManifest:
    """The immutable, upstream candidate identity consumed by StateBench."""

    candidate_id: str
    template_id: str
    template_version: str
    source_repository: str
    source_commit: str
    supported_context_policies: tuple[str, ...] = ("eager", "compact_context", "modular")
    default_context_policy: str = "eager"
    statepack_profiles: tuple[str, ...] = ("human", "compact", "ultra", "audit", "task")
    statepack_format_version: str = "statepack/v1"
    generator_id: str = ""
    generator_version: str = ""
    modules: tuple[str, ...] = ()
    schema_refs: tuple[str, ...] = ()
    self_test_ids: tuple[str, ...] = ()
    public_fixture_ids: tuple[str, ...] = ()
    format_version: str = CANDIDATE_MANIFEST_FORMAT

    def __post_init__(self) -> None:
        for name in (
            "candidate_id",
            "template_id",
            "template_version",
            "source_repository",
            "source_commit",
        ):
            _require(getattr(self, name), name)
        _require(self.format_version, "format_version")
        object.__setattr__(self, "supported_context_policies", _tuple(self.supported_context_policies))
        object.__setattr__(self, "statepack_profiles", _tuple(self.statepack_profiles))
        object.__setattr__(self, "modules", _tuple(self.modules))
        object.__setattr__(self, "schema_refs", _tuple(self.schema_refs))
        object.__setattr__(self, "self_test_ids", _tuple(self.self_test_ids))
        object.__setattr__(self, "public_fixture_ids", _tuple(self.public_fixture_ids))
        if self.default_context_policy not in self.supported_context_policies:
            raise ValueError("default_context_policy must be supported by the candidate")
        for name, values in (
            ("supported_context_policies", self.supported_context_policies),
            ("statepack_profiles", self.statepack_profiles),
            ("modules", self.modules),
        ):
            if any(not isinstance(value, str) or not value.strip() for value in values):
                raise ValueError(f"{name} must contain non-empty strings")

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.format_version,
            "candidateId": self.candidate_id,
            "templateId": self.template_id,
            "templateVersion": self.template_version,
            "source": {"repository": self.source_repository, "commit": self.source_commit},
            "supportedContextPolicies": list(self.supported_context_policies),
            "defaultContextPolicy": self.default_context_policy,
            "statepackProfiles": list(self.statepack_profiles),
            "statepackFormatVersion": self.statepack_format_version,
            "generator": {"id": self.generator_id, "version": self.generator_version},
            "modules": list(self.modules),
            "schemaRefs": list(self.schema_refs),
            "selfTestIds": list(self.self_test_ids),
            "publicFixtureIds": list(self.public_fixture_ids),
        }

    def canonical_json(self) -> str:
        return _canonical_json(self.to_dict())

    @property
    def manifest_digest(self) -> str:
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ConfigurationManifest:
    """Complete benchmark configuration; comparisons must retain every field."""

    suite_id: str
    suite_version: str
    task_id: str
    candidate_id: str
    candidate_commit: str
    template_id: str
    template_version: str
    modules: tuple[str, ...] = ()
    context_policy: str = "eager"
    statepack_profile: str = "compact"
    statepack_format_version: str = "statepack/v1"
    token_budget: int = 0
    state_mode: str = "persistent"
    model: str = ""
    tokenization: str = ""
    runner: str = "local"
    tools: tuple[str, ...] = ()
    configuration_id: str = ""
    format_version: str = CONFIGURATION_MANIFEST_FORMAT

    def __post_init__(self) -> None:
        for name in (
            "suite_id",
            "suite_version",
            "task_id",
            "candidate_id",
            "candidate_commit",
            "template_id",
            "template_version",
            "context_policy",
            "state_mode",
            "runner",
        ):
            _require(getattr(self, name), name)
        _require(self.format_version, "format_version")
        if isinstance(self.token_budget, bool) or not isinstance(self.token_budget, int):
            raise TypeError("token_budget must be an integer")
        if self.token_budget < 0:
            raise ValueError("token_budget must be non-negative")
        object.__setattr__(self, "modules", _tuple(self.modules))
        object.__setattr__(self, "tools", _tuple(self.tools))
        if any(not isinstance(value, str) or not value.strip() for value in self.modules + self.tools):
            raise ValueError("modules and tools must contain non-empty strings")
        if not self.configuration_id:
            object.__setattr__(self, "configuration_id", self._identity())
        else:
            _require(self.configuration_id, "configuration_id")

    def _identity(self) -> str:
        data = self.to_dict(include_identity=False)
        return hashlib.sha256(_canonical_json(data).encode("utf-8")).hexdigest()[:24]

    def to_dict(self, *, include_identity: bool = True) -> dict[str, Any]:
        result: dict[str, Any] = {
            "formatVersion": self.format_version,
            "suite": {"id": self.suite_id, "version": self.suite_version},
            "taskId": self.task_id,
            "candidate": {
                "id": self.candidate_id,
                "commit": self.candidate_commit,
                "templateId": self.template_id,
                "templateVersion": self.template_version,
            },
            "modules": list(self.modules),
            "contextPolicy": self.context_policy,
            "statepack": {
                "profile": self.statepack_profile,
                "formatVersion": self.statepack_format_version,
                "tokenBudget": self.token_budget,
            },
            "stateMode": self.state_mode,
            "model": self.model,
            "tokenization": self.tokenization,
            "runner": self.runner,
            "tools": list(self.tools),
        }
        if include_identity:
            result["configurationId"] = self.configuration_id
        return result

    def canonical_json(self) -> str:
        return _canonical_json(self.to_dict())


@dataclass(frozen=True)
class BenchmarkTask:
    """A task reference; fixture contents stay outside the benchmark records."""

    task_id: str
    suite_id: str
    suite_version: str
    name: str
    objective: str
    fixture_id: str
    validator_id: str
    public: bool = True
    tags: tuple[str, ...] = ()
    format_version: str = STATEBENCH_FORMAT

    def __post_init__(self) -> None:
        for name in ("task_id", "suite_id", "suite_version", "name", "objective", "fixture_id", "validator_id"):
            _require(getattr(self, name), name)
        object.__setattr__(self, "tags", _tuple(self.tags))
        if any(not isinstance(value, str) or not value.strip() for value in self.tags):
            raise ValueError("tags must contain non-empty strings")


@dataclass(frozen=True)
class BenchmarkSuiteManifest:
    """Versioned suite metadata without embedding public or private fixture data."""

    suite_id: str
    suite_version: str
    task_ids: tuple[str, ...]
    repetitions: int
    control_context_policy: str = "no_state"
    candidate_context_policies: tuple[str, ...] = ("eager", "compact_context", "modular")
    format_version: str = SUITE_MANIFEST_FORMAT

    def __post_init__(self) -> None:
        _require(self.suite_id, "suite_id")
        _require(self.suite_version, "suite_version")
        if isinstance(self.repetitions, bool) or not isinstance(self.repetitions, int) or self.repetitions <= 0:
            raise ValueError("repetitions must be a positive integer")
        object.__setattr__(self, "task_ids", _tuple(self.task_ids))
        object.__setattr__(self, "candidate_context_policies", _tuple(self.candidate_context_policies))
        if not self.task_ids or any(not isinstance(value, str) or not value.strip() for value in self.task_ids):
            raise ValueError("task_ids must contain at least one non-empty string")
        if not isinstance(self.control_context_policy, str) or not self.control_context_policy.strip():
            raise ValueError("suite context policies must be declared")
        if not self.candidate_context_policies or any(
            not isinstance(value, str) or not value.strip()
            for value in self.candidate_context_policies
        ):
            raise ValueError("suite candidate context policies must be non-empty strings")


@dataclass(frozen=True)
class BenchmarkRunResult:
    """One completed task execution and its measured evidence.

    ``None`` means a metric was not measured.  Zero means it was measured as
    zero.  This distinction prevents missing instrumentation from becoming a
    misleading improvement.
    """

    run_id: str
    configuration_id: str
    task_id: str
    repetition: int
    pair_id: str
    task_success: bool
    quality_score: float = 0.0
    deterministic_state_correct: bool = False
    context_tokens: int | None = None
    context_token_share: float | None = None
    total_tokens: int | None = None
    files_loaded: int | None = None
    files_changed: int | None = None
    runtime_ms: float | None = None
    estimated_cost: float | None = None
    interventions: int | None = None
    validation_failures: int = 0
    unnecessary_questions: int | None = None
    continuity_success: bool = False
    safety_violations: int = 0
    privacy_violations: int = 0
    truncation: bool = False
    status: str = "completed"
    notes: str = ""

    def __post_init__(self) -> None:
        for name in ("run_id", "configuration_id", "task_id", "pair_id", "status"):
            _require(getattr(self, name), name)
        if isinstance(self.repetition, bool) or not isinstance(self.repetition, int) or self.repetition < 0:
            raise ValueError("repetition must be a non-negative integer")
        if not isinstance(self.task_success, bool) or not isinstance(self.deterministic_state_correct, bool):
            raise TypeError("success and state correctness fields must be bool")
        if not isinstance(self.continuity_success, bool):
            raise TypeError("continuity_success must be bool")
        _bounded(self.quality_score, "quality_score")
        for name in (
            "context_tokens",
            "total_tokens",
            "files_loaded",
            "files_changed",
            "interventions",
            "validation_failures",
            "unnecessary_questions",
            "safety_violations",
            "privacy_violations",
        ):
            value = getattr(self, name)
            if value is not None:
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise ValueError(f"{name} must be a non-negative integer or None")
        for name in ("runtime_ms", "estimated_cost"):
            value = getattr(self, name)
            if value is not None:
                _non_negative(value, name)
        if self.context_token_share is not None:
            _bounded(self.context_token_share, "context_token_share")

    @property
    def pair_key(self) -> tuple[str, str, int]:
        return (self.task_id, self.pair_id, self.repetition)
