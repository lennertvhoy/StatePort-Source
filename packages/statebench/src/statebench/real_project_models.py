"""Versioned contracts for deterministic multi-stage StateBench projects.

These contracts separate hard outcomes, efficiency diagnostics,
orchestration observations and context observations. They intentionally have
no universal score and cannot express a workflow-superiority claim.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import math
import re
from typing import Any, ClassVar, Iterable

from .evaluator import HeldConstantConfiguration


REAL_PROJECT_SCENARIO_FORMAT = "statebench.real-project/v1"
REAL_PROJECT_TRACE_FORMAT = "statebench.real-project-trace/v1"
REAL_PROJECT_METRICS_FORMAT = "statebench.real-project-metrics/v1"
REAL_PROJECT_RUN_FORMAT = "statebench.real-project-run/v1"
REAL_PROJECT_REPORT_FORMAT = "statebench.real-project-calibration/v1"
REAL_PROJECT_HANDOFF_FORMAT = "statebench.real-project-handoff/v1"
REAL_PROJECT_BANNER = (
    "Synthetic calibration proves harness behavior only; it does not establish "
    "workflow performance, model quality, or CTO superiority."
)

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_GIT_ID = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_STRATEGIES = frozenset({"single_agent", "cto_orchestrated"})
_ATTEMPT_OUTCOMES = frozenset(
    {"interrupted_checkpoint", "recovered_success", "eventual_failure"}
)


class RealProjectContractError(ValueError):
    """A real-project contract is malformed or makes an unsupported claim."""


def _canonical_json(value: Any) -> str:
    if hasattr(value, "to_dict"):
        value = value.to_dict()
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def canonical_digest(value: Any) -> str:
    return "sha256:" + sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _text(value: object, label: str, *, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise RealProjectContractError(f"{label} must be a non-empty bounded string")
    if any(ord(character) < 32 and character not in "\n\t" for character in value):
        raise RealProjectContractError(f"{label} contains control characters")
    return value.strip()


def _id(value: object, label: str) -> str:
    result = _text(value, label, maximum=128)
    if not _ID.fullmatch(result):
        raise RealProjectContractError(f"{label} must be a safe identifier")
    return result


def _digest(value: object, label: str) -> str:
    result = _text(value, label, maximum=71)
    if not _DIGEST.fullmatch(result):
        raise RealProjectContractError(f"{label} must be a sha256 digest")
    return result


def _git_id(value: object, label: str) -> str:
    result = _text(value, label, maximum=64)
    if not _GIT_ID.fullmatch(result):
        raise RealProjectContractError(f"{label} must be an immutable Git identity")
    return result


def _strings(
    values: Iterable[object],
    label: str,
    *,
    identifiers: bool = False,
    nonempty: bool = False,
    maximum: int = 128,
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise RealProjectContractError(f"{label} must be a sequence")
    result = tuple(
        _id(value, label) if identifiers else _text(value, label, maximum=512)
        for value in values
    )
    if (
        len(result) > maximum
        or (nonempty and not result)
        or len(set(result)) != len(result)
    ):
        raise RealProjectContractError(f"{label} must be a unique bounded sequence")
    return result


def _path(value: object, label: str) -> str:
    result = _text(value, label, maximum=512)
    parts = result.replace("\\", "/").split("/")
    if (
        result.startswith("/")
        or "\\" in result
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise RealProjectContractError(f"{label} must be a repository-relative path")
    return result


def _paths(
    values: Iterable[object], label: str, *, nonempty: bool = False
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise RealProjectContractError(f"{label} must be a sequence")
    result = tuple(_path(value, label) for value in values)
    if (
        (nonempty and not result)
        or len(result) > 128
        or len(set(result)) != len(result)
    ):
        raise RealProjectContractError(
            f"{label} must be a unique bounded path sequence"
        )
    return result


def _count(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RealProjectContractError(f"{label} must be a non-negative integer")
    return value


def _optional_count(value: object, label: str) -> int | None:
    if value is None:
        return None
    return _count(value, label)


def _optional_number(value: object, label: str) -> int | float | None:
    if value is None:
        return None
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or value < 0
        or not math.isfinite(float(value))
    ):
        raise RealProjectContractError(
            f"{label} must be a finite non-negative number or unavailable"
        )
    return value


class _Contract:
    FORMAT: ClassVar[str]

    def to_dict(self) -> dict[str, Any]:
        raise NotImplementedError

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_dict())


@dataclass(frozen=True, slots=True)
class ProjectMilestone(_Contract):
    FORMAT: ClassVar[str] = "statebench.real-project-milestone/v1"
    milestone_id: str
    objective: str
    acceptance: tuple[str, ...]

    def __post_init__(self) -> None:
        _id(self.milestone_id, "milestone id")
        _text(self.objective, "milestone objective", maximum=512)
        _strings(self.acceptance, "milestone acceptance", nonempty=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "id": self.milestone_id,
            "objective": self.objective,
            "acceptance": list(self.acceptance),
        }


@dataclass(frozen=True, slots=True)
class RealProjectScenario(_Contract):
    FORMAT: ClassVar[str] = REAL_PROJECT_SCENARIO_FORMAT
    scenario_id: str
    version: str
    fixture_digest: str
    repository_bundle_path: str
    repository_bundle_digest: str
    initial_state_digest: str
    initial_commit: str
    initial_tree: str
    architecture_contract_digest: str
    backlog_digest: str
    project_modules: tuple[str, ...]
    milestones: tuple[ProjectMilestone, ...]
    execution_mode: str
    maximum_attempts: int
    interruption_policy: str
    human_approval_policy: str
    hidden_test_id: str
    evaluator_package_digest: str
    invariant_checks: tuple[str, ...]
    git_checks: tuple[str, ...]
    handoff_checks: tuple[str, ...]
    privacy_classification: str = "public_safe"
    production_eligible: bool = False

    def __post_init__(self) -> None:
        _id(self.scenario_id, "scenario id")
        _text(self.version, "scenario version", maximum=32)
        for label, value in (
            ("fixture digest", self.fixture_digest),
            ("repository bundle digest", self.repository_bundle_digest),
            ("initial state digest", self.initial_state_digest),
            ("architecture contract digest", self.architecture_contract_digest),
            ("backlog digest", self.backlog_digest),
            ("evaluator package digest", self.evaluator_package_digest),
        ):
            _digest(value, label)
        _path(self.repository_bundle_path, "repository bundle path")
        _git_id(self.initial_commit, "initial commit")
        _git_id(self.initial_tree, "initial tree")
        modules = _strings(
            self.project_modules, "project modules", identifiers=True, nonempty=True
        )
        if len(modules) < 6:
            raise RealProjectContractError(
                "real-project fixture must span several modules"
            )
        milestones = tuple(self.milestones)
        if len(milestones) < 3 or len(
            {item.milestone_id for item in milestones}
        ) != len(milestones):
            raise RealProjectContractError(
                "real-project scenario requires unique multi-stage milestones"
            )
        if any(not isinstance(item, ProjectMilestone) for item in milestones):
            raise RealProjectContractError(
                "scenario milestones must use typed contracts"
            )
        object.__setattr__(self, "milestones", milestones)
        if self.execution_mode != "agent_native":
            raise RealProjectContractError(
                "alpha real-project execution mode must remain agent_native"
            )
        if (
            isinstance(self.maximum_attempts, bool)
            or not isinstance(self.maximum_attempts, int)
            or not 2 <= self.maximum_attempts <= 8
        ):
            raise RealProjectContractError("maximum attempts must be a bounded integer")
        _id(self.interruption_policy, "interruption policy")
        _id(self.human_approval_policy, "human approval policy")
        _id(self.hidden_test_id, "hidden test id")
        _strings(
            self.invariant_checks, "invariant checks", identifiers=True, nonempty=True
        )
        _strings(self.git_checks, "Git checks", identifiers=True, nonempty=True)
        _strings(self.handoff_checks, "handoff checks", identifiers=True, nonempty=True)
        if self.privacy_classification != "public_safe" or self.production_eligible:
            raise RealProjectContractError(
                "calibration scenario must be public-safe and production-ineligible"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "identity": {
                "id": self.scenario_id,
                "version": self.version,
                "fixtureDigest": self.fixture_digest,
            },
            "project": {
                "repositoryBundle": {
                    "path": self.repository_bundle_path,
                    "digest": self.repository_bundle_digest,
                },
                "initialStateDigest": self.initial_state_digest,
                "initialCommit": self.initial_commit,
                "initialTree": self.initial_tree,
                "architectureContract": self.architecture_contract_digest,
                "backlog": self.backlog_digest,
                "modules": list(self.project_modules),
                "privacyClassification": self.privacy_classification,
                "productionEligible": self.production_eligible,
            },
            "milestones": [item.to_dict() for item in self.milestones],
            "execution": {
                "mode": self.execution_mode,
                "maximumAttempts": self.maximum_attempts,
                "interruptionPolicy": self.interruption_policy,
                "humanApprovalPolicy": self.human_approval_policy,
            },
            "evaluation": {
                "hiddenTests": [self.hidden_test_id],
                "evaluatorPackageDigest": self.evaluator_package_digest,
                "invariantChecks": list(self.invariant_checks),
                "gitChecks": list(self.git_checks),
                "handoffChecks": list(self.handoff_checks),
            },
        }


@dataclass(frozen=True, slots=True)
class RealProjectWorkflowConfiguration(_Contract):
    FORMAT: ClassVar[str] = "statebench.real-project-workflow-configuration/v1"
    strategy: str
    scenario_digest: str
    runtime_configuration: HeldConstantConfiguration
    model_profiles: tuple[str, ...]
    evaluator_identity: str
    synthetic_agents: bool = True

    def __post_init__(self) -> None:
        if self.strategy not in _STRATEGIES:
            raise RealProjectContractError("workflow strategy is unsupported")
        _digest(self.scenario_digest, "scenario digest")
        if not isinstance(self.runtime_configuration, HeldConstantConfiguration):
            raise RealProjectContractError(
                "runtime configuration must use the held-constant contract"
            )
        profiles = _strings(
            self.model_profiles, "model profiles", identifiers=True, nonempty=True
        )
        if len(profiles) < 2:
            raise RealProjectContractError(
                "implementer and reviewer profiles must both be frozen"
            )
        _id(self.evaluator_identity, "evaluator identity")
        if not self.synthetic_agents:
            raise RealProjectContractError(
                "this calibration slice supports synthetic agents only"
            )

    @property
    def held_constant_digest(self) -> str:
        return canonical_digest(
            {
                "scenarioDigest": self.scenario_digest,
                "runtime": self.runtime_configuration.to_dict(),
                "modelProfiles": list(self.model_profiles),
                "evaluatorIdentity": self.evaluator_identity,
                "syntheticAgents": self.synthetic_agents,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "strategy": self.strategy,
            "scenarioDigest": self.scenario_digest,
            "runtimeConfiguration": self.runtime_configuration.to_dict(),
            "modelProfiles": list(self.model_profiles),
            "evaluatorIdentity": self.evaluator_identity,
            "syntheticAgents": self.synthetic_agents,
            "heldConstantDigest": self.held_constant_digest,
        }


@dataclass(frozen=True, slots=True)
class AttemptAccounting(_Contract):
    FORMAT: ClassVar[str] = "statebench.real-project-attempt-accounting/v1"
    parent_job_id: str
    attempt_id: str
    ordinal: int
    outcome: str
    success: bool
    tool_calls: int
    terminal_commands: int
    file_reads: int
    file_writes: int
    input_tokens: int | None = None
    output_tokens: int | None = None
    cached_tokens: int | None = None
    monetary_cost_minor: int | None = None
    active_model_time_ms: int | None = None

    def __post_init__(self) -> None:
        _id(self.parent_job_id, "parent job id")
        _id(self.attempt_id, "attempt id")
        if (
            isinstance(self.ordinal, bool)
            or not isinstance(self.ordinal, int)
            or self.ordinal < 1
        ):
            raise RealProjectContractError("attempt ordinal must be positive")
        if self.outcome not in _ATTEMPT_OUTCOMES:
            raise RealProjectContractError("attempt outcome is unsupported")
        if not isinstance(self.success, bool):
            raise RealProjectContractError("attempt success must be boolean")
        for label, value in (
            ("tool calls", self.tool_calls),
            ("terminal commands", self.terminal_commands),
            ("file reads", self.file_reads),
            ("file writes", self.file_writes),
        ):
            _count(value, label)
        for label, value in (
            ("input tokens", self.input_tokens),
            ("output tokens", self.output_tokens),
            ("cached tokens", self.cached_tokens),
            ("monetary cost", self.monetary_cost_minor),
            ("active model time", self.active_model_time_ms),
        ):
            _optional_count(value, label)
        if self.outcome == "interrupted_checkpoint" and self.success:
            raise RealProjectContractError(
                "an interrupted first attempt cannot claim success"
            )
        if self.outcome == "recovered_success" and not self.success:
            raise RealProjectContractError("recovered_success must be successful")

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "parentJobId": self.parent_job_id,
            "attemptId": self.attempt_id,
            "ordinal": self.ordinal,
            "outcome": self.outcome,
            "success": self.success,
            "toolCalls": self.tool_calls,
            "terminalCommands": self.terminal_commands,
            "fileReads": self.file_reads,
            "fileWrites": self.file_writes,
            "inputTokens": self.input_tokens,
            "outputTokens": self.output_tokens,
            "cachedTokens": self.cached_tokens,
            "monetaryCostMinor": self.monetary_cost_minor,
            "activeModelTimeMs": self.active_model_time_ms,
        }


def _sum_optional(attempts: tuple[AttemptAccounting, ...], field: str) -> int | None:
    values = tuple(getattr(item, field) for item in attempts)
    return None if any(value is None for value in values) else sum(values)


@dataclass(frozen=True, slots=True)
class ParentJobAccounting(_Contract):
    FORMAT: ClassVar[str] = "statebench.real-project-parent-accounting/v1"
    parent_job_id: str
    attempts: tuple[AttemptAccounting, ...]
    first_attempt_success: bool
    eventual_success: bool

    def __post_init__(self) -> None:
        _id(self.parent_job_id, "parent job id")
        attempts = tuple(self.attempts)
        if len(attempts) < 2 or any(
            item.parent_job_id != self.parent_job_id for item in attempts
        ):
            raise RealProjectContractError(
                "all retry and repair costs must remain on one parent job"
            )
        if tuple(item.ordinal for item in attempts) != tuple(
            range(1, len(attempts) + 1)
        ):
            raise RealProjectContractError("attempt ordinals must be contiguous")
        if len({item.attempt_id for item in attempts}) != len(attempts):
            raise RealProjectContractError("attempt identities must be unique")
        if self.first_attempt_success != attempts[0].success:
            raise RealProjectContractError("first-attempt accounting is inconsistent")
        if self.eventual_success != attempts[-1].success:
            raise RealProjectContractError("eventual accounting is inconsistent")
        object.__setattr__(self, "attempts", attempts)

    @property
    def recovered_success(self) -> bool:
        return not self.first_attempt_success and self.eventual_success

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "parentJobId": self.parent_job_id,
            "firstAttemptSuccess": self.first_attempt_success,
            "eventualSuccess": self.eventual_success,
            "recoveredSuccess": self.recovered_success,
            "attempts": [item.to_dict() for item in self.attempts],
            "totals": {
                "toolCalls": sum(item.tool_calls for item in self.attempts),
                "terminalCommands": sum(
                    item.terminal_commands for item in self.attempts
                ),
                "fileReads": sum(item.file_reads for item in self.attempts),
                "fileWrites": sum(item.file_writes for item in self.attempts),
                "inputTokens": _sum_optional(self.attempts, "input_tokens"),
                "outputTokens": _sum_optional(self.attempts, "output_tokens"),
                "cachedTokens": _sum_optional(self.attempts, "cached_tokens"),
                "monetaryCostMinor": _sum_optional(
                    self.attempts, "monetary_cost_minor"
                ),
                "activeModelTimeMs": _sum_optional(
                    self.attempts, "active_model_time_ms"
                ),
            },
        }


@dataclass(frozen=True, slots=True)
class HardOutcomes:
    final_functional_success: bool
    milestone_completion: tuple[bool, ...]
    critical_violation_count: int
    architecture_invariants_passed: bool
    state_integrity_passed: bool
    git_closure_passed: bool
    handoff_truth_passed: bool
    first_attempt_success: bool
    eventual_success: bool

    def __post_init__(self) -> None:
        milestones = tuple(self.milestone_completion)
        if not milestones or any(not isinstance(value, bool) for value in milestones):
            raise RealProjectContractError(
                "hard outcomes require explicit milestone results"
            )
        _count(self.critical_violation_count, "critical violation count")
        for value in (
            self.final_functional_success,
            self.architecture_invariants_passed,
            self.state_integrity_passed,
            self.git_closure_passed,
            self.handoff_truth_passed,
            self.first_attempt_success,
            self.eventual_success,
        ):
            if not isinstance(value, bool):
                raise RealProjectContractError("hard outcome flags must be boolean")
        if self.final_functional_success and not all(milestones):
            raise RealProjectContractError(
                "functional success cannot hide an incomplete milestone"
            )
        if self.final_functional_success and (
            self.critical_violation_count
            or not self.architecture_invariants_passed
            or not self.state_integrity_passed
            or not self.git_closure_passed
            or not self.handoff_truth_passed
            or not self.eventual_success
        ):
            raise RealProjectContractError(
                "functional success requires every hard outcome gate"
            )
        if self.first_attempt_success and not self.eventual_success:
            raise RealProjectContractError(
                "eventual outcome cannot regress a successful first attempt"
            )
        object.__setattr__(self, "milestone_completion", milestones)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finalFunctionalSuccess": self.final_functional_success,
            "milestoneCompletion": list(self.milestone_completion),
            "criticalViolationCount": self.critical_violation_count,
            "architectureInvariantsPassed": self.architecture_invariants_passed,
            "stateIntegrityPassed": self.state_integrity_passed,
            "gitClosurePassed": self.git_closure_passed,
            "handoffTruthPassed": self.handoff_truth_passed,
            "firstAttemptSuccess": self.first_attempt_success,
            "eventualSuccess": self.eventual_success,
        }


@dataclass(frozen=True, slots=True)
class EfficiencyMetrics:
    total_wall_time_ms: int | None
    active_model_time_ms: int | None
    input_tokens: int | None
    output_tokens: int | None
    cached_tokens: int | None
    monetary_cost_minor: int | None
    tool_calls: int
    terminal_commands: int
    file_reads: int
    repeated_reads: int
    failed_attempts: int
    retries: int
    model_escalations: int
    context_compilations: int
    compactions: int
    handoffs: int

    def __post_init__(self) -> None:
        for label, value in (
            ("total wall time", self.total_wall_time_ms),
            ("active model time", self.active_model_time_ms),
            ("input tokens", self.input_tokens),
            ("output tokens", self.output_tokens),
            ("cached tokens", self.cached_tokens),
            ("monetary cost", self.monetary_cost_minor),
        ):
            _optional_count(value, label)
        for label, value in (
            ("tool calls", self.tool_calls),
            ("terminal commands", self.terminal_commands),
            ("file reads", self.file_reads),
            ("repeated reads", self.repeated_reads),
            ("failed attempts", self.failed_attempts),
            ("retries", self.retries),
            ("model escalations", self.model_escalations),
            ("context compilations", self.context_compilations),
            ("compactions", self.compactions),
            ("handoffs", self.handoffs),
        ):
            _count(value, label)

    def to_dict(self) -> dict[str, Any]:
        return {
            "totalWallTimeMs": self.total_wall_time_ms,
            "activeModelTimeMs": self.active_model_time_ms,
            "inputTokens": self.input_tokens,
            "outputTokens": self.output_tokens,
            "cachedTokens": self.cached_tokens,
            "monetaryCostMinor": self.monetary_cost_minor,
            "toolCalls": self.tool_calls,
            "terminalCommands": self.terminal_commands,
            "fileReads": self.file_reads,
            "repeatedReads": self.repeated_reads,
            "failedAttempts": self.failed_attempts,
            "retries": self.retries,
            "modelEscalations": self.model_escalations,
            "contextCompilations": self.context_compilations,
            "compactions": self.compactions,
            "handoffs": self.handoffs,
        }


@dataclass(frozen=True, slots=True)
class OrchestrationMetrics:
    backlog_selection_precision: float | None
    unnecessary_task_generation: int
    dependency_order_violations: int
    duplicated_subagent_work: int
    rejected_subagent_output: int
    reviewer_findings: int
    human_corrections: int
    false_closure_attempts: int
    preserved_unrelated_work: bool
    time_to_correct_next_action_ms: int | None

    def __post_init__(self) -> None:
        if (
            self.backlog_selection_precision is not None
            and not 0 <= self.backlog_selection_precision <= 1
        ):
            raise RealProjectContractError(
                "backlog selection precision must be bounded or unavailable"
            )
        for label, value in (
            ("unnecessary task generation", self.unnecessary_task_generation),
            ("dependency order violations", self.dependency_order_violations),
            ("duplicated subagent work", self.duplicated_subagent_work),
            ("rejected subagent output", self.rejected_subagent_output),
            ("reviewer findings", self.reviewer_findings),
            ("human corrections", self.human_corrections),
            ("false closure attempts", self.false_closure_attempts),
        ):
            _count(value, label)
        if not isinstance(self.preserved_unrelated_work, bool):
            raise RealProjectContractError(
                "unrelated-work preservation must be explicit"
            )
        _optional_count(
            self.time_to_correct_next_action_ms, "time to correct next action"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "backlogSelectionPrecision": self.backlog_selection_precision,
            "unnecessaryTaskGeneration": self.unnecessary_task_generation,
            "dependencyOrderViolations": self.dependency_order_violations,
            "duplicatedSubagentWork": self.duplicated_subagent_work,
            "rejectedSubagentOutput": self.rejected_subagent_output,
            "reviewerFindings": self.reviewer_findings,
            "humanCorrections": self.human_corrections,
            "falseClosureAttempts": self.false_closure_attempts,
            "preservedUnrelatedWork": self.preserved_unrelated_work,
            "timeToCorrectNextActionMs": self.time_to_correct_next_action_ms,
        }


@dataclass(frozen=True, slots=True)
class ContextMetrics:
    statepack_size_bytes: int | None
    relevant_evidence_items: int
    missing_authoritative_sources: int
    irrelevant_context_ratio: float | None
    compression_events: int
    handoff_quality_checks_passed: int
    reconstruction_cost_tokens: int | None

    def __post_init__(self) -> None:
        _optional_count(self.statepack_size_bytes, "StatePack size")
        _count(self.relevant_evidence_items, "relevant evidence items")
        _count(self.missing_authoritative_sources, "missing authoritative sources")
        if (
            self.irrelevant_context_ratio is not None
            and not 0 <= self.irrelevant_context_ratio <= 1
        ):
            raise RealProjectContractError(
                "irrelevant context ratio must be bounded or unavailable"
            )
        _count(self.compression_events, "compression events")
        _count(self.handoff_quality_checks_passed, "handoff checks")
        _optional_count(self.reconstruction_cost_tokens, "reconstruction cost")

    def to_dict(self) -> dict[str, Any]:
        return {
            "statePackSizeBytes": self.statepack_size_bytes,
            "relevantEvidenceItems": self.relevant_evidence_items,
            "missingAuthoritativeSources": self.missing_authoritative_sources,
            "irrelevantContextRatio": self.irrelevant_context_ratio,
            "compressionEvents": self.compression_events,
            "handoffQualityChecksPassed": self.handoff_quality_checks_passed,
            "reconstructionCostTokens": self.reconstruction_cost_tokens,
        }


@dataclass(frozen=True, slots=True)
class RealProjectMetrics(_Contract):
    FORMAT: ClassVar[str] = REAL_PROJECT_METRICS_FORMAT
    hard_outcomes: HardOutcomes
    efficiency: EfficiencyMetrics
    orchestration: OrchestrationMetrics
    context: ContextMetrics

    def __post_init__(self) -> None:
        if not isinstance(self.hard_outcomes, HardOutcomes):
            raise RealProjectContractError("hard outcomes must use the typed contract")
        if not isinstance(self.efficiency, EfficiencyMetrics):
            raise RealProjectContractError(
                "efficiency metrics must use the typed contract"
            )
        if not isinstance(self.orchestration, OrchestrationMetrics):
            raise RealProjectContractError(
                "orchestration metrics must use the typed contract"
            )
        if not isinstance(self.context, ContextMetrics):
            raise RealProjectContractError(
                "context metrics must use the typed contract"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "hardOutcomes": self.hard_outcomes.to_dict(),
            "efficiency": self.efficiency.to_dict(),
            "orchestration": self.orchestration.to_dict(),
            "context": self.context.to_dict(),
        }


def _trace_identity(parent_job_id: str, sequence: int) -> None:
    _id(parent_job_id, "trace parent job id")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        raise RealProjectContractError("trace sequence must be a positive integer")


@dataclass(frozen=True, slots=True)
class ProjectBootstrapTrace(_Contract):
    FORMAT: ClassVar[str] = "statebench.project-bootstrap-trace/v1"
    parent_job_id: str
    sequence: int
    scenario_digest: str
    initial_commit: str
    initial_tree: str
    outcome: str = "inspected_existing_project"

    def __post_init__(self) -> None:
        _trace_identity(self.parent_job_id, self.sequence)
        _digest(self.scenario_digest, "trace scenario digest")
        _git_id(self.initial_commit, "trace initial commit")
        _git_id(self.initial_tree, "trace initial tree")
        if self.outcome != "inspected_existing_project":
            raise RealProjectContractError("bootstrap trace outcome is unsupported")

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "parentJobId": self.parent_job_id,
            "sequence": self.sequence,
            "scenarioDigest": self.scenario_digest,
            "initialCommit": self.initial_commit,
            "initialTree": self.initial_tree,
            "outcome": self.outcome,
        }


@dataclass(frozen=True, slots=True)
class BacklogDecisionTrace(_Contract):
    FORMAT: ClassVar[str] = "statebench.backlog-decision-trace/v1"
    parent_job_id: str
    sequence: int
    selected_item_id: str
    considered_item_ids: tuple[str, ...]
    rationale_code: str

    def __post_init__(self) -> None:
        _trace_identity(self.parent_job_id, self.sequence)
        _id(self.selected_item_id, "selected backlog item")
        considered = _strings(
            self.considered_item_ids,
            "considered backlog items",
            identifiers=True,
            nonempty=True,
        )
        if self.selected_item_id not in considered:
            raise RealProjectContractError(
                "selected item must be present in considered backlog"
            )
        _id(self.rationale_code, "backlog rationale")

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "parentJobId": self.parent_job_id,
            "sequence": self.sequence,
            "selectedItemId": self.selected_item_id,
            "consideredItemIds": list(self.considered_item_ids),
            "rationaleCode": self.rationale_code,
        }


@dataclass(frozen=True, slots=True)
class SliceSelectionTrace(_Contract):
    FORMAT: ClassVar[str] = "statebench.slice-selection-trace/v1"
    parent_job_id: str
    sequence: int
    slice_id: str
    milestone_ids: tuple[str, ...]
    allowed_paths: tuple[str, ...]
    excluded_paths: tuple[str, ...]
    approval_id: str

    def __post_init__(self) -> None:
        _trace_identity(self.parent_job_id, self.sequence)
        _id(self.slice_id, "slice id")
        _strings(
            self.milestone_ids, "slice milestones", identifiers=True, nonempty=True
        )
        _paths(self.allowed_paths, "allowed paths", nonempty=True)
        _paths(self.excluded_paths, "excluded paths", nonempty=True)
        if set(self.allowed_paths) & set(self.excluded_paths):
            raise RealProjectContractError(
                "slice paths cannot be both allowed and excluded"
            )
        _id(self.approval_id, "slice approval id")

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "parentJobId": self.parent_job_id,
            "sequence": self.sequence,
            "sliceId": self.slice_id,
            "milestoneIds": list(self.milestone_ids),
            "allowedPaths": list(self.allowed_paths),
            "excludedPaths": list(self.excluded_paths),
            "approvalId": self.approval_id,
        }


@dataclass(frozen=True, slots=True)
class DelegationTrace(_Contract):
    FORMAT: ClassVar[str] = "statebench.delegation-trace/v1"
    parent_job_id: str
    sequence: int
    strategy: str
    implementer_profile: str
    reviewer_profile: str
    delegation_mode: str
    duplicated_work_items: int = 0
    rejected_outputs: int = 0

    def __post_init__(self) -> None:
        _trace_identity(self.parent_job_id, self.sequence)
        if self.strategy not in _STRATEGIES:
            raise RealProjectContractError("delegation strategy is unsupported")
        _id(self.implementer_profile, "implementer profile")
        _id(self.reviewer_profile, "reviewer profile")
        if self.implementer_profile == self.reviewer_profile:
            raise RealProjectContractError(
                "implementation and independent review profiles must differ"
            )
        if self.delegation_mode not in {"none", "bounded_plan"}:
            raise RealProjectContractError("delegation mode is unsupported")
        if (self.strategy == "single_agent") != (self.delegation_mode == "none"):
            raise RealProjectContractError(
                "delegation mode contradicts workflow strategy"
            )
        _count(self.duplicated_work_items, "duplicated work")
        _count(self.rejected_outputs, "rejected outputs")

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "parentJobId": self.parent_job_id,
            "sequence": self.sequence,
            "strategy": self.strategy,
            "implementerProfile": self.implementer_profile,
            "reviewerProfile": self.reviewer_profile,
            "delegationMode": self.delegation_mode,
            "duplicatedWorkItems": self.duplicated_work_items,
            "rejectedOutputs": self.rejected_outputs,
        }


@dataclass(frozen=True, slots=True)
class AttemptTrace(_Contract):
    FORMAT: ClassVar[str] = "statebench.attempt-trace/v1"
    parent_job_id: str
    sequence: int
    attempt_id: str
    ordinal: int
    outcome: str
    commit: str
    tree: str
    public_tests_passed: bool
    evaluator_checks_passed: bool

    def __post_init__(self) -> None:
        _trace_identity(self.parent_job_id, self.sequence)
        _id(self.attempt_id, "trace attempt id")
        if (
            isinstance(self.ordinal, bool)
            or not isinstance(self.ordinal, int)
            or self.ordinal < 1
        ):
            raise RealProjectContractError("trace attempt ordinal must be positive")
        if self.outcome not in _ATTEMPT_OUTCOMES:
            raise RealProjectContractError("trace attempt outcome is unsupported")
        _git_id(self.commit, "trace attempt commit")
        _git_id(self.tree, "trace attempt tree")
        if not isinstance(self.public_tests_passed, bool) or not isinstance(
            self.evaluator_checks_passed, bool
        ):
            raise RealProjectContractError("trace test observations must be boolean")
        if self.outcome == "interrupted_checkpoint" and self.evaluator_checks_passed:
            raise RealProjectContractError(
                "interrupted checkpoint may not claim evaluator acceptance"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "parentJobId": self.parent_job_id,
            "sequence": self.sequence,
            "attemptId": self.attempt_id,
            "ordinal": self.ordinal,
            "outcome": self.outcome,
            "commit": self.commit,
            "tree": self.tree,
            "publicTestsPassed": self.public_tests_passed,
            "evaluatorChecksPassed": self.evaluator_checks_passed,
        }


@dataclass(frozen=True, slots=True)
class HumanIntervention(_Contract):
    FORMAT: ClassVar[str] = "statebench.human-intervention/v1"
    parent_job_id: str
    sequence: int
    intervention_id: str
    kind: str
    reason: str

    def __post_init__(self) -> None:
        _trace_identity(self.parent_job_id, self.sequence)
        _id(self.intervention_id, "intervention id")
        if self.kind != "synthetic_forced_interruption":
            raise RealProjectContractError(
                "calibration intervention kind is unsupported"
            )
        _text(self.reason, "intervention reason", maximum=512)

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "parentJobId": self.parent_job_id,
            "sequence": self.sequence,
            "interventionId": self.intervention_id,
            "kind": self.kind,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class RepairTrace(_Contract):
    FORMAT: ClassVar[str] = "statebench.repair-trace/v1"
    parent_job_id: str
    sequence: int
    source_attempt_id: str
    target_attempt_id: str
    reason_code: str
    changed_paths: tuple[str, ...]
    added_permissions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _trace_identity(self.parent_job_id, self.sequence)
        _id(self.source_attempt_id, "source attempt id")
        _id(self.target_attempt_id, "target attempt id")
        if self.source_attempt_id == self.target_attempt_id:
            raise RealProjectContractError("repair must continue in a distinct attempt")
        _id(self.reason_code, "repair reason")
        _paths(self.changed_paths, "repair changed paths", nonempty=True)
        if self.added_permissions:
            raise RealProjectContractError("repair may not increase permissions")

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "parentJobId": self.parent_job_id,
            "sequence": self.sequence,
            "sourceAttemptId": self.source_attempt_id,
            "targetAttemptId": self.target_attempt_id,
            "reasonCode": self.reason_code,
            "changedPaths": list(self.changed_paths),
            "addedPermissions": list(self.added_permissions),
        }


@dataclass(frozen=True, slots=True)
class ReviewTrace(_Contract):
    FORMAT: ClassVar[str] = "statebench.review-trace/v1"
    parent_job_id: str
    sequence: int
    reviewer_profile: str
    implementer_profile: str
    commit: str
    tree: str
    test_result_digest: str
    scenario_digest: str
    disposition: str
    read_only: bool = True
    clean_detached_worktree: bool = True

    def __post_init__(self) -> None:
        _trace_identity(self.parent_job_id, self.sequence)
        _id(self.reviewer_profile, "reviewer profile")
        _id(self.implementer_profile, "implementer profile")
        if self.reviewer_profile == self.implementer_profile:
            raise RealProjectContractError(
                "reviewer must be independent of implementation"
            )
        _git_id(self.commit, "review commit")
        _git_id(self.tree, "review tree")
        _digest(self.test_result_digest, "review test digest")
        _digest(self.scenario_digest, "review scenario digest")
        if self.disposition != "accepted":
            raise RealProjectContractError(
                "successful calibration closure requires accepted review"
            )
        if not self.read_only or not self.clean_detached_worktree:
            raise RealProjectContractError(
                "independent review must be clean detached and read-only"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "parentJobId": self.parent_job_id,
            "sequence": self.sequence,
            "reviewerProfile": self.reviewer_profile,
            "implementerProfile": self.implementer_profile,
            "commit": self.commit,
            "tree": self.tree,
            "testResultDigest": self.test_result_digest,
            "scenarioDigest": self.scenario_digest,
            "disposition": self.disposition,
            "readOnly": self.read_only,
            "cleanDetachedWorktree": self.clean_detached_worktree,
        }


@dataclass(frozen=True, slots=True)
class ClosureTrace(_Contract):
    FORMAT: ClassVar[str] = "statebench.closure-trace/v1"
    parent_job_id: str
    sequence: int
    commit: str
    tree: str
    remote_commit: str
    remote_equal: bool
    unrelated_work_preserved: bool
    handoff_digest: str
    receipt_digest: str

    def __post_init__(self) -> None:
        _trace_identity(self.parent_job_id, self.sequence)
        _git_id(self.commit, "closure commit")
        _git_id(self.tree, "closure tree")
        _git_id(self.remote_commit, "closure remote commit")
        _digest(self.handoff_digest, "handoff digest")
        _digest(self.receipt_digest, "receipt digest")
        if not self.remote_equal or self.remote_commit != self.commit:
            raise RealProjectContractError(
                "Git closure requires exact local and remote equality"
            )
        if not self.unrelated_work_preserved:
            raise RealProjectContractError(
                "closure may not discard unrelated dirty work"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "parentJobId": self.parent_job_id,
            "sequence": self.sequence,
            "commit": self.commit,
            "tree": self.tree,
            "remoteCommit": self.remote_commit,
            "remoteEqual": self.remote_equal,
            "unrelatedWorkPreserved": self.unrelated_work_preserved,
            "handoffDigest": self.handoff_digest,
            "receiptDigest": self.receipt_digest,
        }


TraceEvent = (
    ProjectBootstrapTrace
    | BacklogDecisionTrace
    | SliceSelectionTrace
    | DelegationTrace
    | AttemptTrace
    | HumanIntervention
    | RepairTrace
    | ReviewTrace
    | ClosureTrace
)


@dataclass(frozen=True, slots=True)
class RealProjectTrace(_Contract):
    FORMAT: ClassVar[str] = REAL_PROJECT_TRACE_FORMAT
    parent_job_id: str
    events: tuple[TraceEvent, ...]

    def __post_init__(self) -> None:
        _id(self.parent_job_id, "trace parent job id")
        events = tuple(self.events)
        expected_types = (
            ProjectBootstrapTrace,
            BacklogDecisionTrace,
            SliceSelectionTrace,
            DelegationTrace,
            AttemptTrace,
            HumanIntervention,
            RepairTrace,
            AttemptTrace,
            ReviewTrace,
            ClosureTrace,
        )
        if len(events) != len(expected_types) or any(
            type(event) is not expected
            for event, expected in zip(events, expected_types, strict=True)
        ):
            raise RealProjectContractError(
                "real-project trace is missing a required lifecycle stage"
            )
        if any(event.parent_job_id != self.parent_job_id for event in events):
            raise RealProjectContractError("trace events must remain on one parent job")
        if tuple(event.sequence for event in events) != tuple(
            range(1, len(events) + 1)
        ):
            raise RealProjectContractError("trace events must be strictly ordered")
        attempts = (events[4], events[7])
        if attempts[0].ordinal != 1 or attempts[1].ordinal != 2:
            raise RealProjectContractError(
                "trace must preserve first and continuation attempt order"
            )
        intervention = events[5]
        repair = events[6]
        delegation = events[3]
        review = events[8]
        closure = events[9]
        selection = events[2]
        if (
            attempts[0].outcome != "interrupted_checkpoint"
            or attempts[1].outcome != "recovered_success"
            or repair.source_attempt_id != attempts[0].attempt_id
            or repair.target_attempt_id != attempts[1].attempt_id
        ):
            raise RealProjectContractError(
                "trace repair must bind the interrupted and continuation attempts"
            )
        if not intervention.reason.strip():
            raise RealProjectContractError("trace interruption must record a reason")
        if not set(repair.changed_paths).issubset(selection.allowed_paths) or set(
            repair.changed_paths
        ) & set(selection.excluded_paths):
            raise RealProjectContractError(
                "trace repair must remain inside the approved slice"
            )
        if (
            review.implementer_profile != delegation.implementer_profile
            or review.reviewer_profile != delegation.reviewer_profile
            or review.commit != attempts[1].commit
            or review.tree != attempts[1].tree
            or review.scenario_digest != events[0].scenario_digest
        ):
            raise RealProjectContractError(
                "independent review must bind the delegated profiles and final attempt"
            )
        if closure.commit != review.commit or closure.tree != review.tree:
            raise RealProjectContractError(
                "closure must bind the independently reviewed commit and tree"
            )
        object.__setattr__(self, "events", events)

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "parentJobId": self.parent_job_id,
            "events": [event.to_dict() for event in self.events],
        }


@dataclass(frozen=True, slots=True)
class HandoffArtifact(_Contract):
    FORMAT: ClassVar[str] = REAL_PROJECT_HANDOFF_FORMAT
    handoff_id: str
    parent_job_id: str
    scenario_digest: str
    workflow_strategy: str
    base_commit: str
    final_commit: str
    final_tree: str
    completed_milestones: tuple[str, ...]
    pending_work: tuple[str, ...]
    decisions: tuple[str, ...]
    risks: tuple[str, ...]
    validation_digest: str
    review_digest: str
    unrelated_work_digest: str
    next_action: str

    def __post_init__(self) -> None:
        _id(self.handoff_id, "handoff id")
        _id(self.parent_job_id, "handoff parent job id")
        _digest(self.scenario_digest, "handoff scenario digest")
        if self.workflow_strategy not in _STRATEGIES:
            raise RealProjectContractError("handoff workflow strategy is unsupported")
        _git_id(self.base_commit, "handoff base commit")
        _git_id(self.final_commit, "handoff final commit")
        _git_id(self.final_tree, "handoff final tree")
        _strings(
            self.completed_milestones,
            "completed milestones",
            identifiers=True,
            nonempty=True,
        )
        _strings(self.pending_work, "pending work")
        _strings(self.decisions, "handoff decisions", nonempty=True)
        _strings(self.risks, "handoff risks", nonempty=True)
        _digest(self.validation_digest, "handoff validation digest")
        _digest(self.review_digest, "handoff review digest")
        _digest(self.unrelated_work_digest, "handoff unrelated work digest")
        _text(self.next_action, "handoff next action", maximum=512)

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "handoffId": self.handoff_id,
            "parentJobId": self.parent_job_id,
            "scenarioDigest": self.scenario_digest,
            "workflowStrategy": self.workflow_strategy,
            "baseCommit": self.base_commit,
            "finalCommit": self.final_commit,
            "finalTree": self.final_tree,
            "completedMilestones": list(self.completed_milestones),
            "pendingWork": list(self.pending_work),
            "decisions": list(self.decisions),
            "risks": list(self.risks),
            "validationDigest": self.validation_digest,
            "reviewDigest": self.review_digest,
            "unrelatedWorkDigest": self.unrelated_work_digest,
            "nextAction": self.next_action,
        }


@dataclass(frozen=True, slots=True)
class RealProjectRunResult(_Contract):
    FORMAT: ClassVar[str] = REAL_PROJECT_RUN_FORMAT
    parent_job_id: str
    scenario_digest: str
    workflow: RealProjectWorkflowConfiguration
    trace: RealProjectTrace
    accounting: ParentJobAccounting
    metrics: RealProjectMetrics
    handoff: HandoffArtifact
    final_commit: str
    final_tree: str
    receipt_digest: str
    calibration_only: bool = True
    performance_claim: bool = False

    def __post_init__(self) -> None:
        _id(self.parent_job_id, "run parent job id")
        _digest(self.scenario_digest, "run scenario digest")
        if self.workflow.scenario_digest != self.scenario_digest:
            raise RealProjectContractError(
                "workflow and result scenario identities differ"
            )
        if (
            self.trace.parent_job_id != self.parent_job_id
            or self.accounting.parent_job_id != self.parent_job_id
            or self.handoff.parent_job_id != self.parent_job_id
        ):
            raise RealProjectContractError("run artifacts must share one parent job")
        _git_id(self.final_commit, "run final commit")
        _git_id(self.final_tree, "run final tree")
        _digest(self.receipt_digest, "run receipt digest")
        closure = self.trace.events[-1]
        if (
            not isinstance(closure, ClosureTrace)
            or closure.commit != self.final_commit
            or closure.tree != self.final_tree
            or closure.receipt_digest != self.receipt_digest
        ):
            raise RealProjectContractError(
                "run result and closure trace identities differ"
            )
        if (
            self.handoff.final_commit != self.final_commit
            or self.handoff.final_tree != self.final_tree
        ):
            raise RealProjectContractError("handoff does not describe the final result")
        bootstrap = self.trace.events[0]
        delegation = self.trace.events[3]
        attempt_traces = (self.trace.events[4], self.trace.events[7])
        review = self.trace.events[8]
        if (
            bootstrap.scenario_digest != self.scenario_digest
            or review.scenario_digest != self.scenario_digest
            or self.handoff.scenario_digest != self.scenario_digest
        ):
            raise RealProjectContractError(
                "run artifacts must bind the identical scenario"
            )
        if (
            delegation.strategy != self.workflow.strategy
            or self.handoff.workflow_strategy != self.workflow.strategy
            or self.workflow.model_profiles
            != (delegation.implementer_profile, delegation.reviewer_profile)
        ):
            raise RealProjectContractError(
                "run artifacts must bind the frozen workflow and profiles"
            )
        accounting_attempts = self.accounting.attempts
        if len(accounting_attempts) != len(attempt_traces) or any(
            accounting.attempt_id != trace.attempt_id
            or accounting.ordinal != trace.ordinal
            or accounting.outcome != trace.outcome
            or accounting.success != trace.evaluator_checks_passed
            for accounting, trace in zip(
                accounting_attempts, attempt_traces, strict=True
            )
        ):
            raise RealProjectContractError(
                "attempt traces and parent-job accounting must agree"
            )
        if (
            review.test_result_digest != self.handoff.validation_digest
            or self.handoff.review_digest != review.digest
            or closure.handoff_digest != self.handoff.digest
        ):
            raise RealProjectContractError(
                "review, handoff and closure evidence must be digest-bound"
            )
        expected_receipt = canonical_digest(
            {
                "parentJobId": self.parent_job_id,
                "scenarioDigest": self.scenario_digest,
                "finalCommit": self.final_commit,
                "finalTree": self.final_tree,
                "validationDigest": self.handoff.validation_digest,
                "reviewDigest": review.digest,
                "handoffDigest": self.handoff.digest,
            }
        )
        if self.receipt_digest != expected_receipt:
            raise RealProjectContractError(
                "run receipt must bind final validation, review and handoff"
            )
        if (
            self.metrics.hard_outcomes.first_attempt_success
            != self.accounting.first_attempt_success
            or self.metrics.hard_outcomes.eventual_success
            != self.accounting.eventual_success
        ):
            raise RealProjectContractError(
                "metrics may not hide first-attempt failure or repair"
            )
        totals = self.accounting.to_dict()["totals"]
        efficiency = self.metrics.efficiency
        if (
            efficiency.tool_calls != totals["toolCalls"]
            or efficiency.terminal_commands != totals["terminalCommands"]
            or efficiency.file_reads != totals["fileReads"]
            or efficiency.input_tokens != totals["inputTokens"]
            or efficiency.output_tokens != totals["outputTokens"]
            or efficiency.cached_tokens != totals["cachedTokens"]
            or efficiency.monetary_cost_minor != totals["monetaryCostMinor"]
            or efficiency.active_model_time_ms != totals["activeModelTimeMs"]
            or efficiency.failed_attempts
            != sum(not attempt.success for attempt in self.accounting.attempts)
            or efficiency.retries != len(self.accounting.attempts) - 1
        ):
            raise RealProjectContractError(
                "efficiency metrics must retain all parent-job attempt costs"
            )
        if not self.calibration_only or self.performance_claim:
            raise RealProjectContractError(
                "synthetic calibration cannot make a performance claim"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "parentJobId": self.parent_job_id,
            "scenarioDigest": self.scenario_digest,
            "workflow": self.workflow.to_dict(),
            "trace": self.trace.to_dict(),
            "accounting": self.accounting.to_dict(),
            "metrics": self.metrics.to_dict(),
            "handoff": self.handoff.to_dict(),
            "finalCommit": self.final_commit,
            "finalTree": self.final_tree,
            "receiptDigest": self.receipt_digest,
            "calibrationOnly": self.calibration_only,
            "performanceClaim": self.performance_claim,
        }


@dataclass(frozen=True, slots=True)
class RealProjectCalibrationReport(_Contract):
    FORMAT: ClassVar[str] = REAL_PROJECT_REPORT_FORMAT
    scenario: RealProjectScenario
    runs: tuple[RealProjectRunResult, ...]
    limitations: tuple[str, ...]
    banner: str = REAL_PROJECT_BANNER
    superiority_claim: bool = False

    def __post_init__(self) -> None:
        runs = tuple(self.runs)
        if len(runs) != 2 or {run.workflow.strategy for run in runs} != _STRATEGIES:
            raise RealProjectContractError(
                "calibration requires single-agent and CTO-orchestrated runs"
            )
        if any(run.scenario_digest != self.scenario.digest for run in runs):
            raise RealProjectContractError(
                "paired runs must use the identical scenario"
            )
        milestone_ids = tuple(
            milestone.milestone_id for milestone in self.scenario.milestones
        )
        for run in runs:
            bootstrap = run.trace.events[0]
            if (
                bootstrap.initial_commit != self.scenario.initial_commit
                or bootstrap.initial_tree != self.scenario.initial_tree
                or run.handoff.base_commit != self.scenario.initial_commit
                or run.handoff.completed_milestones != milestone_ids
                or len(run.accounting.attempts) > self.scenario.maximum_attempts
                or len(run.metrics.hard_outcomes.milestone_completion)
                != len(milestone_ids)
            ):
                raise RealProjectContractError(
                    "paired run does not bind the scenario base and milestones"
                )
        if len({run.workflow.held_constant_digest for run in runs}) != 1:
            raise RealProjectContractError(
                "paired workflow configuration is not held constant"
            )
        if len({run.final_tree for run in runs}) != 1:
            raise RealProjectContractError(
                "deterministic paired proof must converge on one functional tree"
            )
        limitations = _strings(
            self.limitations, "calibration limitations", nonempty=True
        )
        if self.banner != REAL_PROJECT_BANNER or self.superiority_claim:
            raise RealProjectContractError(
                "calibration report cannot claim workflow superiority"
            )
        object.__setattr__(
            self, "runs", tuple(sorted(runs, key=lambda run: run.workflow.strategy))
        )
        object.__setattr__(self, "limitations", limitations)

    @property
    def equal_configuration_proven(self) -> bool:
        return len({run.workflow.held_constant_digest for run in self.runs}) == 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "banner": self.banner,
            "scenario": self.scenario.to_dict(),
            "runs": [run.to_dict() for run in self.runs],
            "equalConfigurationProven": self.equal_configuration_proven,
            "comparisonClassification": "harness_behavior_only",
            "superiorityClaim": self.superiority_claim,
            "limitations": list(self.limitations),
        }

    def canonical_json(self) -> str:
        return _canonical_json(self.to_dict())
