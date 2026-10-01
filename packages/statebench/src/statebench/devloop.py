"""Privacy-bounded, read-only development-loop collection and evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
from typing import Any, Iterable, Mapping

from .evaluator import HeldConstantConfiguration, MetricObservation, ObservationQuality


DEVLOOP_TRACE_FORMAT = "statebench.devloop-structural-trace/v1"
DEVLOOP_EVALUATION_FORMAT = "statebench.devloop-evaluation/v2"
DEVLOOP_COLLECTOR_VERSION = "v1"
DEVLOOP_EVALUATOR_VERSION = "v2"

_GIT_ID = re.compile(r"^[0-9a-f]{40}$")
_BOUNDED_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MAX_INTERVAL_COMMITS = 10_000
_MAX_CHANGED_PATHS_PER_COMMIT = 100_000


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _require_id(value: object, label: str) -> str:
    if not isinstance(value, str) or not _BOUNDED_ID.fullmatch(value):
        raise ValueError(f"{label} must be a bounded identifier")
    return value


def _require_git_id(value: object, label: str) -> str:
    if not isinstance(value, str) or not _GIT_ID.fullmatch(value):
        raise ValueError(f"{label} must be an exact lowercase Git commit identity")
    return value


class DevLoopCollectionFailure(str, Enum):
    REPOSITORY_INVALID = "repository_invalid"
    HEAD_INVALID = "head_invalid"
    MISSING_HISTORY = "missing_history"
    DIVERGENT_HISTORY = "divergent_history"
    INVALID_STATE_DESCENDANT = "invalid_state_descendant"
    GIT_OBSERVATION_FAILED = "git_observation_failed"


class DevLoopCollectionError(ValueError):
    def __init__(
        self,
        code: DevLoopCollectionFailure,
        detail: str,
        *,
        requires_full_rescan: bool = False,
    ) -> None:
        self.code = code
        self.detail = detail
        self.requires_full_rescan = requires_full_rescan
        super().__init__(f"{code.value}: {detail}")


class PathClassification(str, Enum):
    PRODUCT = "product"
    TESTS = "tests"
    VALIDATION_TOOLING = "validation_tooling"
    POLICY = "policy"
    DOCUMENTATION = "documentation"
    STATE_ONLY = "state_only"


_STATE_PATHS = frozenset(
    {
        "STATUS.md",
        "PROJECT_STATE.yaml",
        "NEXT_ACTIONS.md",
        "WORKLOG.md",
        "docs/EVIDENCE_LOG.md",
    }
)


def classify_path(path: str) -> PathClassification:
    """Classify a Git path without retaining it in the emitted trace."""
    pure = PurePosixPath(path)
    parts = tuple(part.lower() for part in pure.parts)
    name = pure.name.lower()
    lowered = path.lower()

    if path in _STATE_PATHS or lowered.startswith("docs/history/state/"):
        return PathClassification.STATE_ONLY
    if (
        "tests" in parts
        or "test" in parts
        or name.startswith("test_")
        or ".test." in name
        or ".spec." in name
    ):
        return PathClassification.TESTS
    if (
        lowered.startswith(".github/workflows/")
        or lowered.startswith("scripts/validate")
        or lowered.startswith("scripts/check_")
        or lowered.startswith("scripts/test_")
    ):
        return PathClassification.VALIDATION_TOOLING
    if (
        path == "AGENTS.md"
        or lowered.startswith("config/")
        or lowered.startswith("schemas/")
        or lowered.startswith("docs/adr/")
        or lowered.endswith("policy.yaml")
        or lowered.endswith("policy.yml")
    ):
        return PathClassification.POLICY
    if (
        lowered.startswith("docs/")
        or name in {"readme.md", "license", "notice"}
        or pure.suffix.lower() in {".md", ".rst"}
    ):
        return PathClassification.DOCUMENTATION
    return PathClassification.PRODUCT


@dataclass(frozen=True)
class DevLoopCollectionSpec:
    repository_id: str
    base_behavioural_head: str
    current_behavioural_head: str
    base_state_head: str
    current_state_head: str

    def __post_init__(self) -> None:
        _require_id(self.repository_id, "repository id")
        for field in (
            "base_behavioural_head",
            "current_behavioural_head",
            "base_state_head",
            "current_state_head",
        ):
            _require_git_id(getattr(self, field), field)


@dataclass(frozen=True)
class DevLoopCommitFact:
    commit_id: str
    tree_id: str
    parent_ids: tuple[str, ...]
    committed_at_epoch: int
    path_class_counts: tuple[tuple[PathClassification, int], ...]
    state_only: bool
    restores_prior_tree: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "commitId": self.commit_id,
            "treeId": self.tree_id,
            "parentIds": list(self.parent_ids),
            "committedAtEpoch": self.committed_at_epoch,
            "pathClassCounts": {
                classification.value: count
                for classification, count in self.path_class_counts
            },
            "stateOnly": self.state_only,
            "restoresPriorTree": self.restores_prior_tree,
        }


@dataclass(frozen=True)
class DevLoopStructuralTrace:
    repository_id: str
    base_behavioural_head: str
    current_behavioural_head: str
    base_state_head: str
    current_state_head: str
    behavioural_distance: int
    state_distance: int
    state_commits_after_behavioural_head: int
    commits: tuple[DevLoopCommitFact, ...]

    @property
    def trace_digest(self) -> str:
        return _digest(self._payload())

    def _payload(self) -> dict[str, Any]:
        totals = {classification.value: 0 for classification in PathClassification}
        for commit in self.commits:
            for classification, count in commit.path_class_counts:
                totals[classification.value] += count
        return {
            "formatVersion": DEVLOOP_TRACE_FORMAT,
            "collector": {"id": "statebench.devloop-collector", "version": DEVLOOP_COLLECTOR_VERSION},
            "repositoryId": self.repository_id,
            "heads": {
                "behavioural": {"base": self.base_behavioural_head, "current": self.current_behavioural_head},
                "state": {"base": self.base_state_head, "current": self.current_state_head},
            },
            "ancestry": {
                "validated": True,
                "behaviouralDistance": self.behavioural_distance,
                "stateDistance": self.state_distance,
                "stateCommitsAfterBehaviouralHead": self.state_commits_after_behavioural_head,
                "divergenceDetected": False,
                "fullRescanRequired": False,
            },
            "pathClassTotals": totals,
            "commits": [commit.to_dict() for commit in self.commits],
            "privacyBoundary": {
                "containsRawDiffs": False,
                "containsCommitMessages": False,
                "containsAuthorIdentity": False,
                "containsRawPaths": False,
                "containsConversations": False,
                "containsRepositoryLocation": False,
            },
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self._payload()
        payload["traceDigest"] = self.trace_digest
        return payload

    def canonical_json(self) -> str:
        return _canonical_json(self.to_dict())


class DevLoopCollector:
    """Run bounded Git reads and emit a path-free structural trace."""

    def __init__(self, repository: Path) -> None:
        self.repository = repository.resolve()
        if not self.repository.is_dir():
            raise DevLoopCollectionError(
                DevLoopCollectionFailure.REPOSITORY_INVALID,
                "repository is not a directory",
            )
        probe = self._git(("rev-parse", "--is-inside-work-tree"), allow_failure=True)
        if probe.returncode != 0 or probe.stdout.strip() != "true":
            raise DevLoopCollectionError(
                DevLoopCollectionFailure.REPOSITORY_INVALID,
                "repository is not a Git worktree",
            )

    def _git(
        self,
        args: tuple[str, ...],
        *,
        allow_failure: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        try:
            result = subprocess.run(
                ["git", "-C", str(self.repository), *args],
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
                shell=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise DevLoopCollectionError(
                DevLoopCollectionFailure.GIT_OBSERVATION_FAILED,
                "bounded Git observation could not complete",
            ) from exc
        if not allow_failure and result.returncode != 0:
            raise DevLoopCollectionError(
                DevLoopCollectionFailure.GIT_OBSERVATION_FAILED,
                "bounded Git observation failed",
            )
        return result

    def _resolve_commit(self, commit_id: str, label: str, *, base: bool) -> None:
        result = self._git(("cat-file", "-e", f"{commit_id}^{{commit}}"), allow_failure=True)
        if result.returncode != 0:
            raise DevLoopCollectionError(
                DevLoopCollectionFailure.MISSING_HISTORY if base else DevLoopCollectionFailure.HEAD_INVALID,
                f"{label} is not available as an exact commit",
                requires_full_rescan=base,
            )

    def _require_ancestor(self, ancestor: str, descendant: str, relationship: str) -> None:
        result = self._git(("merge-base", "--is-ancestor", ancestor, descendant), allow_failure=True)
        if result.returncode == 1:
            raise DevLoopCollectionError(
                DevLoopCollectionFailure.DIVERGENT_HISTORY,
                f"required ancestry is false: {relationship}",
                requires_full_rescan=True,
            )
        if result.returncode != 0:
            raise DevLoopCollectionError(
                DevLoopCollectionFailure.GIT_OBSERVATION_FAILED,
                f"ancestry could not be established: {relationship}",
                requires_full_rescan=True,
            )

    def _rev_list(self, base: str, current: str) -> tuple[str, ...]:
        if base == current:
            return ()
        output = self._git(
            ("rev-list", "--reverse", "--topo-order", "--ancestry-path", f"{base}..{current}")
        ).stdout.strip()
        commits = tuple(line for line in output.splitlines() if line)
        if len(commits) > _MAX_INTERVAL_COMMITS:
            raise DevLoopCollectionError(
                DevLoopCollectionFailure.GIT_OBSERVATION_FAILED,
                "commit interval exceeds the collector bound",
            )
        return commits

    def _changed_paths(self, commit_id: str, parents: tuple[str, ...]) -> tuple[str, ...]:
        if parents:
            args = ("diff-tree", "--no-commit-id", "--name-only", "-r", "-z", parents[0], commit_id)
        else:
            args = ("diff-tree", "--root", "--no-commit-id", "--name-only", "-r", "-z", commit_id)
        paths = tuple(path for path in self._git(args).stdout.split("\0") if path)
        if len(paths) > _MAX_CHANGED_PATHS_PER_COMMIT:
            raise DevLoopCollectionError(
                DevLoopCollectionFailure.GIT_OBSERVATION_FAILED,
                "changed-path observation exceeds the per-commit bound",
            )
        return paths

    def _commit_fact(self, commit_id: str, prior_trees: set[str]) -> DevLoopCommitFact:
        metadata = self._git(("show", "-s", "--format=%T%x00%P%x00%ct", commit_id)).stdout.strip()
        tree_id, parent_text, epoch_text = metadata.split("\0")
        parents = tuple(parent_text.split()) if parent_text else ()
        counts: dict[PathClassification, int] = {}
        for path in self._changed_paths(commit_id, parents):
            classification = classify_path(path)
            counts[classification] = counts.get(classification, 0) + 1
        ordered_counts = tuple(sorted(counts.items(), key=lambda item: item[0].value))
        return DevLoopCommitFact(
            commit_id=commit_id,
            tree_id=tree_id,
            parent_ids=parents,
            committed_at_epoch=int(epoch_text),
            path_class_counts=ordered_counts,
            state_only=bool(counts) and set(counts) == {PathClassification.STATE_ONLY},
            restores_prior_tree=tree_id in prior_trees,
        )

    def collect(self, spec: DevLoopCollectionSpec) -> DevLoopStructuralTrace:
        for label, commit_id, base in (
            ("base behavioural head", spec.base_behavioural_head, True),
            ("current behavioural head", spec.current_behavioural_head, False),
            ("base state head", spec.base_state_head, True),
            ("current state head", spec.current_state_head, False),
        ):
            self._resolve_commit(commit_id, label, base=base)

        self._require_ancestor(spec.base_behavioural_head, spec.base_state_head, "base behavioural -> base state")
        self._require_ancestor(spec.base_state_head, spec.current_behavioural_head, "base state -> current behavioural")
        self._require_ancestor(spec.current_behavioural_head, spec.current_state_head, "current behavioural -> current state")
        self._require_ancestor(spec.base_behavioural_head, spec.current_behavioural_head, "behavioural cursor")
        self._require_ancestor(spec.base_state_head, spec.current_state_head, "state cursor")

        base_state_tail = self._rev_list(spec.base_behavioural_head, spec.base_state_head)
        current_state_tail = self._rev_list(spec.current_behavioural_head, spec.current_state_head)
        interval = self._rev_list(spec.base_state_head, spec.current_state_head)
        baseline_tree = self._git(("show", "-s", "--format=%T", spec.base_state_head)).stdout.strip()
        prior_trees = {baseline_tree}
        facts: list[DevLoopCommitFact] = []
        for commit_id in interval:
            fact = self._commit_fact(commit_id, prior_trees)
            facts.append(fact)
            prior_trees.add(fact.tree_id)

        fact_by_id = {fact.commit_id: fact for fact in facts}
        for commit_id in base_state_tail:
            fact = self._commit_fact(commit_id, set()) if commit_id not in fact_by_id else fact_by_id[commit_id]
            if not fact.state_only:
                raise DevLoopCollectionError(
                    DevLoopCollectionFailure.INVALID_STATE_DESCENDANT,
                    "base state head contains behaviour after its declared behavioural head",
                    requires_full_rescan=True,
                )
        for commit_id in current_state_tail:
            fact = fact_by_id.get(commit_id) or self._commit_fact(commit_id, set())
            if not fact.state_only:
                raise DevLoopCollectionError(
                    DevLoopCollectionFailure.INVALID_STATE_DESCENDANT,
                    "current state head contains behaviour after its declared behavioural head",
                    requires_full_rescan=True,
                )

        behavioural_distance = len(self._rev_list(spec.base_behavioural_head, spec.current_behavioural_head))
        state_distance = len(interval)
        return DevLoopStructuralTrace(
            repository_id=spec.repository_id,
            base_behavioural_head=spec.base_behavioural_head,
            current_behavioural_head=spec.current_behavioural_head,
            base_state_head=spec.base_state_head,
            current_state_head=spec.current_state_head,
            behavioural_distance=behavioural_distance,
            state_distance=state_distance,
            state_commits_after_behavioural_head=len(current_state_tail),
            commits=tuple(facts),
        )


DEVLOOP_METRIC_UNITS: tuple[tuple[str, str], ...] = (
    ("first_pass_slice_success", "boolean"),
    ("failure_discovery_stage", "stage"),
    ("rework_ratio", "ratio"),
    ("scope_growth", "ratio"),
    ("evidence_lag_seconds", "seconds"),
    ("state_lag_seconds", "seconds"),
    ("branch_divergence_cost", "seconds"),
    ("human_steering_count", "count"),
    ("repeated_correction_rate", "ratio"),
    ("false_closure_count", "count"),
    ("retry_repair_count", "count"),
    ("observed_time_seconds", "seconds"),
    ("observed_token_count", "tokens"),
    ("observed_cost_minor", "cost_minor"),
    ("accepted_value_per_cost", "ratio"),
    ("test_escape_rate", "ratio"),
    ("unrelated_work_preserved", "boolean"),
    ("rollback_success", "boolean"),
    ("worktrees_created", "count"),
    ("worktrees_removed", "count"),
    ("worktrees_leaked", "count"),
    ("branches_created", "count"),
    ("branches_retired", "count"),
    ("peak_registered_worktrees", "count"),
    ("peak_active_writable_worktrees", "count"),
    ("unclassified_workspace_count", "count"),
    ("expired_lease_count", "count"),
    ("cleanup_duration", "seconds"),
    ("cleanup_failures", "count"),
    ("owner_interventions_for_workspace_hygiene", "count"),
    ("wrong_worktree_incidents", "count"),
    ("closure_gate_workspace_failures", "count"),
)

_DISCOVERY_STAGES = frozenset(
    {
        "not_applicable",
        "focused_test",
        "full_suite",
        "browser_journey",
        "agent_journey",
        "human_review",
        "production",
    }
)


@dataclass(frozen=True)
class DevLoopMetricEvidence:
    observation: MetricObservation
    evidence_references: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        references = tuple(_require_id(value, "evidence reference") for value in self.evidence_references)
        if len(set(references)) != len(references):
            raise ValueError("evidence references must be unique")
        if self.observation.quality is ObservationQuality.UNAVAILABLE and references:
            raise ValueError("unavailable observations cannot cite evidence")
        if self.observation.quality is not ObservationQuality.UNAVAILABLE and not references:
            raise ValueError("available observations require at least one evidence reference")
        object.__setattr__(self, "evidence_references", references)

    def to_dict(self) -> dict[str, Any]:
        value = self.observation.to_dict()
        value["evidenceReferences"] = list(self.evidence_references)
        return value


@dataclass(frozen=True)
class DevLoopEvaluationReport:
    report_id: str
    slice_id: str
    trace: DevLoopStructuralTrace
    configuration: HeldConstantConfiguration | None
    metrics: tuple[DevLoopMetricEvidence, ...]

    def _workspace_lifecycle_gate(self) -> dict[str, Any]:
        observations = {item.observation.name: item.observation for item in self.metrics}
        hard_metrics = (
            "worktrees_leaked",
            "unclassified_workspace_count",
            "expired_lease_count",
            "cleanup_failures",
            "closure_gate_workspace_failures",
        )
        blocking = sorted(
            name for name in hard_metrics
            if observations[name].value is not None and observations[name].value > 0
        )
        unavailable = sorted(name for name in hard_metrics if observations[name].value is None)
        status = "failed" if blocking else "not_evaluated" if unavailable else "passed"
        return {
            "status": status,
            "blockingMetrics": blocking,
            "unavailableMetrics": unavailable,
            "processQualityScorePermitted": status == "passed",
        }

    def to_dict(self) -> dict[str, Any]:
        totals = self.trace.to_dict()["pathClassTotals"]
        return {
            "formatVersion": DEVLOOP_EVALUATION_FORMAT,
            "reportId": self.report_id,
            "sliceId": self.slice_id,
            "traceDigest": self.trace.trace_digest,
            "evaluator": {"id": "statebench.devloop-evaluator", "version": DEVLOOP_EVALUATOR_VERSION},
            "configuration": self.configuration.to_dict() if self.configuration else None,
            "configurationQuality": "exact" if self.configuration else "unavailable",
            "structuralFacts": {
                "commitCount": len(self.trace.commits),
                "stateOnlyCommitCount": sum(commit.state_only for commit in self.trace.commits),
                "mergeCommitCount": sum(len(commit.parent_ids) > 1 for commit in self.trace.commits),
                "restoredPriorTreeCount": sum(commit.restores_prior_tree for commit in self.trace.commits),
                "pathClassTotals": totals,
                "branchDivergenceDetected": False,
            },
            "resultVector": [metric.to_dict() for metric in self.metrics],
            "workspaceLifecycleGate": self._workspace_lifecycle_gate(),
            "authoritativePerformanceClaim": False,
            "automaticPolicyMutation": False,
            "promotionDecision": None,
            "limitations": [
                "git_is_identity_and_chronology_not_a_complete_development_trace",
                "missing_observations_remain_unavailable",
                "no_real_project_corpus_or_superiority_evidence",
            ],
        }

    def canonical_json(self) -> str:
        return _canonical_json(self.to_dict())


class DevLoopEvaluator:
    def _validate_metric(self, observation: MetricObservation, expected_unit: str) -> None:
        if observation.unit != expected_unit:
            raise ValueError(f"{observation.name} must use unit {expected_unit}")
        value = observation.value
        if value is None:
            return
        if expected_unit == "boolean" and not isinstance(value, bool):
            raise ValueError(f"{observation.name} must be boolean")
        if expected_unit == "stage" and (not isinstance(value, str) or value not in _DISCOVERY_STAGES):
            raise ValueError("failure_discovery_stage is invalid")
        if expected_unit in {"count", "tokens", "cost_minor"} and (
            isinstance(value, bool) or not isinstance(value, int) or value < 0
        ):
            raise ValueError(f"{observation.name} must be a non-negative integer")
        if expected_unit in {"ratio", "seconds"} and (
            isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0
        ):
            raise ValueError(f"{observation.name} must be a non-negative number")

    def evaluate(
        self,
        *,
        report_id: str,
        slice_id: str,
        trace: DevLoopStructuralTrace,
        observations: Iterable[DevLoopMetricEvidence] = (),
        configuration: HeldConstantConfiguration | None = None,
    ) -> DevLoopEvaluationReport:
        _require_id(report_id, "report id")
        _require_id(slice_id, "slice id")
        supplied: dict[str, DevLoopMetricEvidence] = {}
        expected = dict(DEVLOOP_METRIC_UNITS)
        for metric in observations:
            name = metric.observation.name
            if name not in expected:
                raise ValueError(f"unsupported DevLoop metric: {name}")
            if name in supplied:
                raise ValueError(f"duplicate DevLoop metric: {name}")
            self._validate_metric(metric.observation, expected[name])
            supplied[name] = metric

        vector: list[DevLoopMetricEvidence] = []
        for name, unit in DEVLOOP_METRIC_UNITS:
            vector.append(
                supplied.get(
                    name,
                    DevLoopMetricEvidence(
                        MetricObservation(name, None, ObservationQuality.UNAVAILABLE, unit),
                    ),
                )
            )
        return DevLoopEvaluationReport(
            report_id=report_id,
            slice_id=slice_id,
            trace=trace,
            configuration=configuration,
            metrics=tuple(vector),
        )


def structural_trace_from_dict(value: Mapping[str, Any]) -> DevLoopStructuralTrace:
    """Strictly load a v1 trace emitted by this module without accepting paths."""
    expected_top_level = {
        "formatVersion",
        "collector",
        "repositoryId",
        "heads",
        "ancestry",
        "pathClassTotals",
        "commits",
        "privacyBoundary",
        "traceDigest",
    }
    if set(value) != expected_top_level:
        raise ValueError("DevLoop trace contains missing or unsupported fields")
    if value.get("formatVersion") != DEVLOOP_TRACE_FORMAT:
        raise ValueError("unsupported DevLoop trace format")
    if value.get("collector") != {
        "id": "statebench.devloop-collector",
        "version": DEVLOOP_COLLECTOR_VERSION,
    }:
        raise ValueError("DevLoop trace collector identity is invalid")
    heads = value.get("heads")
    ancestry = value.get("ancestry")
    commits_value = value.get("commits")
    if not isinstance(heads, dict) or not isinstance(ancestry, dict) or not isinstance(commits_value, list):
        raise ValueError("DevLoop trace structure is invalid")
    expected_ancestry_fields = {
        "validated",
        "behaviouralDistance",
        "stateDistance",
        "stateCommitsAfterBehaviouralHead",
        "divergenceDetected",
        "fullRescanRequired",
    }
    if set(ancestry) != expected_ancestry_fields:
        raise ValueError("DevLoop trace ancestry fields are invalid")
    if (
        ancestry.get("validated") is not True
        or ancestry.get("divergenceDetected") is not False
        or ancestry.get("fullRescanRequired") is not False
    ):
        raise ValueError("DevLoop trace does not carry a successful ancestry decision")
    for name in ("behaviouralDistance", "stateDistance", "stateCommitsAfterBehaviouralHead"):
        count = ancestry.get(name)
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("DevLoop trace ancestry counts are invalid")
    commits: list[DevLoopCommitFact] = []
    commit_ids: set[str] = set()
    expected_commit_fields = {
        "commitId",
        "treeId",
        "parentIds",
        "committedAtEpoch",
        "pathClassCounts",
        "stateOnly",
        "restoresPriorTree",
    }
    for item in commits_value:
        if not isinstance(item, dict) or not isinstance(item.get("pathClassCounts"), dict):
            raise ValueError("DevLoop commit fact is invalid")
        if set(item) != expected_commit_fields:
            raise ValueError("DevLoop commit fact contains missing or unsupported fields")
        for count in item["pathClassCounts"].values():
            if isinstance(count, bool) or not isinstance(count, int) or count <= 0:
                raise ValueError("DevLoop path-class count is invalid")
        counts = tuple(
            sorted(
                ((PathClassification(name), int(count)) for name, count in item["pathClassCounts"].items()),
                key=lambda pair: pair[0].value,
            )
        )
        commit_id = _require_git_id(item.get("commitId"), "commit id")
        if commit_id in commit_ids:
            raise ValueError("DevLoop trace contains duplicate commits")
        commit_ids.add(commit_id)
        epoch = item.get("committedAtEpoch")
        if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 0:
            raise ValueError("DevLoop commit epoch is invalid")
        if not isinstance(item.get("parentIds"), list):
            raise ValueError("DevLoop commit parents are invalid")
        if not isinstance(item.get("stateOnly"), bool) or not isinstance(item.get("restoresPriorTree"), bool):
            raise ValueError("DevLoop commit classifications are invalid")
        expected_state_only = bool(counts) and {classification for classification, _ in counts} == {
            PathClassification.STATE_ONLY
        }
        if item["stateOnly"] is not expected_state_only:
            raise ValueError("DevLoop state-only classification contradicts its path classes")
        commits.append(
            DevLoopCommitFact(
                commit_id=commit_id,
                tree_id=_require_git_id(item.get("treeId"), "tree id"),
                parent_ids=tuple(_require_git_id(parent, "parent id") for parent in item["parentIds"]),
                committed_at_epoch=epoch,
                path_class_counts=counts,
                state_only=item["stateOnly"],
                restores_prior_tree=item["restoresPriorTree"],
            )
        )
    behavioural = heads.get("behavioural", {})
    state = heads.get("state", {})
    expected_privacy = {
        "containsRawDiffs": False,
        "containsCommitMessages": False,
        "containsAuthorIdentity": False,
        "containsRawPaths": False,
        "containsConversations": False,
        "containsRepositoryLocation": False,
    }
    if value.get("privacyBoundary") != expected_privacy:
        raise ValueError("DevLoop trace violates the v1 privacy boundary")
    trace = DevLoopStructuralTrace(
        repository_id=_require_id(value.get("repositoryId"), "repository id"),
        base_behavioural_head=_require_git_id(behavioural.get("base"), "base behavioural head"),
        current_behavioural_head=_require_git_id(behavioural.get("current"), "current behavioural head"),
        base_state_head=_require_git_id(state.get("base"), "base state head"),
        current_state_head=_require_git_id(state.get("current"), "current state head"),
        behavioural_distance=int(ancestry.get("behaviouralDistance")),
        state_distance=int(ancestry.get("stateDistance")),
        state_commits_after_behavioural_head=int(ancestry.get("stateCommitsAfterBehaviouralHead")),
        commits=tuple(commits),
    )
    expected_totals = trace.to_dict()["pathClassTotals"]
    if value.get("pathClassTotals") != expected_totals:
        raise ValueError("DevLoop path-class totals contradict commit facts")
    if value.get("traceDigest") != trace.trace_digest:
        raise ValueError("DevLoop trace digest mismatch")
    return trace
