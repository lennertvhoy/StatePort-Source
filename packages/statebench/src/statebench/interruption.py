"""Engine-neutral forced interruption and repository-only continuation.

This module is deliberately a harness contract, not an execution-host loop.
Launchers are supplied by the caller and may use any supported local engine.
The harness only gives Stage A a deterministic interruption control and gives
Stage B a fresh, repository-backed continuation input.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import select
import signal
import stat
import subprocess
import time
from typing import Any, Callable, Literal, Mapping, Protocol, runtime_checkable

from .git_fixtures import (
    FixtureMaterialization,
    GitBundleFixtureMaterializer,
    GitFixtureError,
    RemoteEqualityFacts,
    TemporaryBareRemote,
)


INTERRUPTION_POLICY_FORMAT = "statebench.interruption-policy/v1"
INTERRUPTION_RECORD_FORMAT = "statebench.interruption-record/v1"
_IDENTIFIER = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,127}$")
_EVIDENCE_IDENTIFIER = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$")
_FORBIDDEN_EVIDENCE_TERMS = ("chat", "transcript", "prompt", "session", "provider", "evaluator")
_GIT_IDENTITY = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_STAGE_A_RESULTS = frozenset({"interrupted_partial", "interrupted_checkpoint"})
_STAGE_B_RESULTS = frozenset({"eventual_success", "eventual_failure"})


class ContinuationProtocolError(ValueError):
    """The continuation protocol cannot prove one of its hard boundaries."""


def _identifier(value: str, *, name: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ContinuationProtocolError(f"{name} must be a bounded opaque identifier")
    return value


def _bounded_text(value: str, *, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContinuationProtocolError(f"{name} must be non-empty")
    if len(value) > 16_384:
        raise ContinuationProtocolError(f"{name} exceeds the bounded protocol limit")
    return value


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest(value: object) -> str:
    return f"sha256:{sha256(_canonical_json(value).encode('utf-8')).hexdigest()}"


@dataclass(frozen=True, slots=True)
class InterruptionPolicy:
    """A versioned bounded policy with exactly one deterministic trigger."""

    normalized_event_count: int | None = None
    checkpoint_trigger: str | None = None
    event_budget: int = 1
    tool_budget: int = 0
    allowed_tools: tuple[str, ...] = ()
    format_version: str = INTERRUPTION_POLICY_FORMAT

    def __post_init__(self) -> None:
        if self.format_version != INTERRUPTION_POLICY_FORMAT:
            raise ContinuationProtocolError("unsupported interruption policy version")
        count_set = self.normalized_event_count is not None
        checkpoint_set = self.checkpoint_trigger is not None
        if count_set == checkpoint_set:
            raise ContinuationProtocolError("policy must specify exactly one interruption trigger")
        if not isinstance(self.event_budget, int) or isinstance(self.event_budget, bool) or not 1 <= self.event_budget <= 100_000:
            raise ContinuationProtocolError("event_budget must be a finite positive integer")
        if not isinstance(self.tool_budget, int) or isinstance(self.tool_budget, bool) or not 0 <= self.tool_budget <= 100_000:
            raise ContinuationProtocolError("tool_budget must be a finite non-negative integer")
        if isinstance(self.allowed_tools, str):
            raise ContinuationProtocolError("allowed_tools must be a bounded sequence")
        try:
            tools = tuple(self.allowed_tools)
        except TypeError as exc:
            raise ContinuationProtocolError("allowed_tools must be a bounded sequence") from exc
        if len(tools) > self.tool_budget:
            raise ContinuationProtocolError("allowed_tools may not exceed tool_budget")
        if tuple(sorted(tools)) != tools or len(set(tools)) != len(tools):
            raise ContinuationProtocolError("allowed_tools must be distinct and deterministically sorted")
        for tool in tools:
            _identifier(tool, name="allowed tool")
        object.__setattr__(self, "allowed_tools", tools)
        if count_set:
            count = self.normalized_event_count
            if not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= self.event_budget:
                raise ContinuationProtocolError("normalized_event_count must be within event_budget")
        if checkpoint_set:
            _identifier(self.checkpoint_trigger or "", name="checkpoint_trigger")

    @property
    def trigger(self) -> dict[str, object]:
        if self.normalized_event_count is not None:
            return {"kind": "normalized_event_count", "value": self.normalized_event_count}
        return {"kind": "checkpoint", "value": self.checkpoint_trigger}

    @property
    def budget(self) -> dict[str, int]:
        return {"eventBudget": self.event_budget, "toolBudget": self.tool_budget}

    @property
    def tool_policy(self) -> dict[str, list[str]]:
        return {"allowedTools": list(self.allowed_tools)}

    @property
    def digest(self) -> str:
        return _digest(self.to_dict())

    def to_dict(self) -> dict[str, object]:
        return {
            "formatVersion": self.format_version,
            "trigger": self.trigger,
            "budget": self.budget,
            "toolPolicy": self.tool_policy,
        }


@dataclass(frozen=True, slots=True)
class AttemptIdentity:
    """Opaque, distinct launcher identity for one benchmark attempt."""

    parent_benchmark_run: str
    stage: Literal["A", "B"]
    attempt_id: str
    launcher_identity: str
    launcher_identity_classification: Literal["external_launcher", "ephemeral_local_launcher"]
    ordinal: int

    def __post_init__(self) -> None:
        _identifier(self.parent_benchmark_run, name="parent_benchmark_run")
        if self.stage not in ("A", "B"):
            raise ContinuationProtocolError("attempt stage must be A or B")
        _identifier(self.attempt_id, name="attempt_id")
        _identifier(self.launcher_identity, name="launcher_identity")
        if self.launcher_identity_classification not in ("external_launcher", "ephemeral_local_launcher"):
            raise ContinuationProtocolError("launcher identity classification is unsupported")
        if not isinstance(self.ordinal, int) or isinstance(self.ordinal, bool) or self.ordinal < 1:
            raise ContinuationProtocolError("attempt ordinal must be a positive integer")

    def to_dict(self) -> dict[str, object]:
        return {
            "parentBenchmarkRun": self.parent_benchmark_run,
            "stage": self.stage,
            "attemptId": self.attempt_id,
            "launcherIdentity": self.launcher_identity,
            "launcherIdentityClassification": self.launcher_identity_classification,
            "ordinal": self.ordinal,
        }


@dataclass(frozen=True, slots=True)
class EvidenceReference:
    """A bounded structural reference, never transcript or session content."""

    reference_id: str
    kind: Literal["launcher_outcome", "repository_snapshot"]

    def __post_init__(self) -> None:
        if not isinstance(self.reference_id, str) or not _EVIDENCE_IDENTIFIER.fullmatch(self.reference_id):
            raise ContinuationProtocolError("evidence reference must be a bounded identifier")
        if any(term in self.reference_id.lower() for term in _FORBIDDEN_EVIDENCE_TERMS):
            raise ContinuationProtocolError("evidence references may not identify hidden chat or session material")
        if self.kind not in ("launcher_outcome", "repository_snapshot"):
            raise ContinuationProtocolError("evidence reference kind is unsupported")

    def to_dict(self) -> dict[str, str]:
        return {"referenceId": self.reference_id, "kind": self.kind}


@dataclass(frozen=True, slots=True)
class LauncherStageResult:
    """Small, public-safe result returned by an externally supplied launcher."""

    result: str
    interrupted: bool = False
    evidence_references: tuple[EvidenceReference, ...] = ()

    def __post_init__(self) -> None:
        _identifier(self.result, name="launcher result")
        if not isinstance(self.interrupted, bool):
            raise ContinuationProtocolError("launcher interrupted flag must be boolean")
        refs = tuple(self.evidence_references)
        if len(refs) > 32 or any(type(reference) is not EvidenceReference for reference in refs):
            raise ContinuationProtocolError("launcher evidence must contain only bounded evidence references")
        object.__setattr__(self, "evidence_references", refs)


@dataclass(frozen=True, slots=True)
class RepositorySnapshot:
    """Committed and uncommitted repository identity without file contents."""

    commit: str
    tree: str
    working_tree_digest: str
    clean: bool

    def __post_init__(self) -> None:
        if not _GIT_IDENTITY.fullmatch(self.commit) or not _GIT_IDENTITY.fullmatch(self.tree):
            raise ContinuationProtocolError("repository snapshot Git identities are invalid")
        if not _DIGEST.fullmatch(self.working_tree_digest):
            raise ContinuationProtocolError("repository working-tree digest is invalid")
        if not isinstance(self.clean, bool):
            raise ContinuationProtocolError("repository clean observation must be boolean")

    def to_dict(self) -> dict[str, object]:
        return {
            "commit": self.commit,
            "tree": self.tree,
            "workingTreeDigest": self.working_tree_digest,
            "clean": self.clean,
        }


@dataclass(frozen=True, slots=True)
class InterruptionFact:
    trigger: dict[str, object]
    budget: dict[str, int]
    observed_normalized_events: int
    policy_digest: str

    def to_dict(self) -> dict[str, object]:
        return {
            "trigger": self.trigger,
            "budget": self.budget,
            "observedNormalizedEvents": self.observed_normalized_events,
            "policyDigest": self.policy_digest,
        }


class InterruptionSignal(RuntimeError):
    """Raised into the Stage-A launcher at the exact configured boundary."""


class InterruptionController:
    """The only interruption mechanism exposed to a Stage-A launcher."""

    def __init__(self, policy: InterruptionPolicy) -> None:
        self._policy = policy
        self._events = 0
        self._triggered = False

    def normalized_event(self, event_name: str) -> None:
        _identifier(event_name, name="normalized event")
        if self._triggered:
            raise ContinuationProtocolError("normalized events are forbidden after interruption")
        self._events += 1
        if self._events > self._policy.event_budget:
            raise ContinuationProtocolError("Stage A exceeded its bounded event budget without interruption")
        if self._policy.normalized_event_count == self._events:
            self._triggered = True
            raise InterruptionSignal("normalized event-count trigger reached")

    def checkpoint(self, checkpoint_id: str) -> None:
        _identifier(checkpoint_id, name="checkpoint")
        if self._triggered:
            raise ContinuationProtocolError("checkpoints are forbidden after interruption")
        if self._policy.checkpoint_trigger == checkpoint_id:
            self._triggered = True
            raise InterruptionSignal("explicit checkpoint trigger reached")

    @property
    def fact(self) -> InterruptionFact:
        if not self._triggered:
            raise ContinuationProtocolError("Stage A did not reach the required interruption trigger")
        return InterruptionFact(
            trigger=self._policy.trigger,
            budget=self._policy.budget,
            observed_normalized_events=self._events,
            policy_digest=self._policy.digest,
        )


@dataclass(frozen=True, slots=True)
class StageAInput:
    repository: Path
    durable_statedd_files: tuple[str, ...]
    original_task: str
    policy: InterruptionPolicy
    attempt: AttemptIdentity


@dataclass(frozen=True, slots=True)
class StageBInput:
    """Repository-only continuation input; it has no Stage-A result or session."""

    repository: Path
    durable_statedd_files: tuple[str, ...]
    original_task: str
    policy: InterruptionPolicy
    attempt: AttemptIdentity


@runtime_checkable
class StageALauncher(Protocol):
    def launch_stage_a(self, request: StageAInput, interruption: InterruptionController) -> LauncherStageResult: ...


@runtime_checkable
class StageBLauncher(Protocol):
    def launch_stage_b(self, request: StageBInput) -> LauncherStageResult: ...


@dataclass(frozen=True, slots=True)
class ContinuationAttempt:
    """Separate first-attempt and eventual-result accounting for one run."""

    stage_a: AttemptIdentity
    stage_b: AttemptIdentity
    initial_repository: RepositorySnapshot
    continuation_repository: RepositorySnapshot
    final_repository: RepositorySnapshot
    interruption: InterruptionFact
    first_attempt_result: str
    eventual_result: str
    first_evidence_references: tuple[EvidenceReference, ...]
    eventual_evidence_references: tuple[EvidenceReference, ...]
    initial_remote_facts: RemoteEqualityFacts
    remote_facts: RemoteEqualityFacts
    interruption_record: Path

    def __post_init__(self) -> None:
        if (
            not isinstance(self.stage_a, AttemptIdentity)
            or not isinstance(self.stage_b, AttemptIdentity)
            or self.stage_a.stage != "A" or self.stage_b.stage != "B"
            or self.stage_a.parent_benchmark_run != self.stage_b.parent_benchmark_run
            or self.stage_a.attempt_id == self.stage_b.attempt_id
            or self.stage_a.launcher_identity == self.stage_b.launcher_identity
            or self.stage_a.ordinal >= self.stage_b.ordinal
        ):
            raise ContinuationProtocolError("continuation attempt identities are inconsistent")
        if self.first_attempt_result not in _STAGE_A_RESULTS:
            raise ContinuationProtocolError("first-attempt result is not a closed Stage-A classification")
        if self.eventual_result not in _STAGE_B_RESULTS:
            raise ContinuationProtocolError("eventual result is not a closed Stage-B classification")
        for snapshot in (
            self.initial_repository, self.continuation_repository,
            self.final_repository,
        ):
            if not isinstance(snapshot, RepositorySnapshot):
                raise ContinuationProtocolError("continuation repository identity is untyped")
        if not isinstance(self.interruption, InterruptionFact):
            raise ContinuationProtocolError("continuation interruption fact is untyped")
        for references in (
            self.first_evidence_references, self.eventual_evidence_references,
        ):
            if len(references) > 32 or any(
                not isinstance(item, EvidenceReference) for item in references
            ):
                raise ContinuationProtocolError("continuation evidence references are invalid")
        if not isinstance(self.initial_remote_facts, RemoteEqualityFacts) or not isinstance(
            self.remote_facts, RemoteEqualityFacts
        ):
            raise ContinuationProtocolError("continuation remote facts are untyped")
        record = Path(self.interruption_record)
        if record.is_symlink() or not record.is_file():
            raise ContinuationProtocolError("persisted interruption record is unavailable")
        object.__setattr__(self, "interruption_record", record)

    def to_dict(self) -> dict[str, object]:
        """Public-safe structural report; task text and paths are intentionally absent."""

        return {
            "stageA": self.stage_a.to_dict(),
            "stageB": self.stage_b.to_dict(),
            "initialRepository": self.initial_repository.to_dict(),
            "continuationRepository": self.continuation_repository.to_dict(),
            "finalRepository": self.final_repository.to_dict(),
            "interruption": self.interruption.to_dict(),
            "firstAttemptResult": self.first_attempt_result,
            "eventualResult": self.eventual_result,
            "firstEvidenceReferences": [item.to_dict() for item in self.first_evidence_references],
            "eventualEvidenceReferences": [item.to_dict() for item in self.eventual_evidence_references],
            "initialRemoteFacts": asdict(self.initial_remote_facts),
            "remoteFacts": asdict(self.remote_facts),
            "interruptionRecord": "interruption.json",
        }


class ForcedInterruptionHarness:
    """Materialize, interrupt, release, and continue an isolated local fixture."""

    def __init__(self, *, timeout_seconds: float = 10.0) -> None:
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0:
            raise ContinuationProtocolError("harness timeout must be positive")
        self._materializer = GitBundleFixtureMaterializer(timeout_seconds=timeout_seconds)
        self._timeout_seconds = float(timeout_seconds)

    def run(
        self,
        *,
        bundle: str | Path,
        expected_origin: str,
        run_root: str | Path,
        original_task: str,
        policy: InterruptionPolicy,
        stage_a: StageALauncher,
        stage_a_identity: AttemptIdentity,
        stage_b: StageBLauncher,
        stage_b_identity: AttemptIdentity,
        durable_statedd_files: tuple[str, ...] = (),
    ) -> ContinuationAttempt:
        task = _bounded_text(original_task, name="original_task")
        self._validate_attempts(stage_a_identity, stage_b_identity, stage_a, stage_b)
        root = self._new_run_root(run_root)
        worktree = root / "fixture"
        evidence_dir = root / "evidence"
        evidence_dir.mkdir()
        try:
            materialized = self._materializer.materialize(bundle, worktree, expected_origin=expected_origin)
            if not materialized.clean or self._git_status(worktree):
                raise ContinuationProtocolError("initial fixture must be clean")
            durable = self._durable_files(worktree, durable_statedd_files)
            remote = TemporaryBareRemote.create(root / "remote.git", timeout_seconds=self._timeout_seconds)
            remote.attach_fresh_fixture(worktree)
            branch = f"bench/{stage_a_identity.parent_benchmark_run}"
            remote.create_branch(worktree, branch)
            initial_remote_facts = remote.push_branch(worktree, branch)
            initial = self._snapshot(worktree)
            deadline = time.monotonic() + self._timeout_seconds
            first_result, interruption = self._stage_a(
                stage_a, StageAInput(worktree, durable, task, policy, stage_a_identity),
                deadline,
            )
            if not first_result.interrupted:
                raise ContinuationProtocolError("Stage A must explicitly report interruption")
            continuation_snapshot = self._snapshot(worktree)
            record = evidence_dir / "interruption.json"
            self._persist_interruption(
                record=record, agent_workspace=worktree, materialized=materialized, stage_a=stage_a_identity,
                interruption=interruption, policy=policy, task=task, snapshot=continuation_snapshot,
            )
            self._verify_interruption_record(
                record, materialized, stage_a_identity,
                interruption, policy, task, continuation_snapshot,
            )
            if self._snapshot(worktree) != continuation_snapshot:
                raise ContinuationProtocolError("repository snapshot drifted before Stage B")
            if self._durable_files(worktree, durable) != durable:
                raise ContinuationProtocolError("durable StateDD file set drifted before Stage B")
            if stage_b_identity.parent_benchmark_run != stage_a_identity.parent_benchmark_run or policy.digest != interruption.policy_digest:
                raise ContinuationProtocolError("policy or benchmark identity drifted before Stage B")
            stage_b_input = StageBInput(worktree, durable, task, policy, stage_b_identity)
            eventual_result = self._stage_b(stage_b, stage_b_input, deadline)
            final_snapshot = self._snapshot(worktree)
            remote_facts = remote.push_branch(worktree, branch)
            return ContinuationAttempt(
                stage_a=stage_a_identity, stage_b=stage_b_identity,
                initial_repository=initial, continuation_repository=continuation_snapshot,
                final_repository=final_snapshot, interruption=interruption,
                first_attempt_result=first_result.result, eventual_result=eventual_result.result,
                first_evidence_references=first_result.evidence_references,
                eventual_evidence_references=eventual_result.evidence_references,
                initial_remote_facts=initial_remote_facts, remote_facts=remote_facts,
                interruption_record=record,
            )
        except (GitFixtureError, ContinuationProtocolError):
            raise
        except Exception as exc:
            raise ContinuationProtocolError("launcher failed before a bounded continuation outcome") from exc

    def _validate_attempts(
        self, stage_a_identity: AttemptIdentity, stage_b_identity: AttemptIdentity,
        stage_a: StageALauncher, stage_b: StageBLauncher,
    ) -> None:
        if stage_a_identity.stage != "A" or stage_b_identity.stage != "B":
            raise ContinuationProtocolError("attempt identities must match their stages")
        if stage_a_identity.parent_benchmark_run != stage_b_identity.parent_benchmark_run:
            raise ContinuationProtocolError("attempts must share a parent benchmark run")
        if stage_a_identity.ordinal >= stage_b_identity.ordinal:
            raise ContinuationProtocolError("Stage B ordinal must follow Stage A")
        if stage_a_identity.attempt_id == stage_b_identity.attempt_id:
            raise ContinuationProtocolError("attempt identity reuse is forbidden")
        if stage_a_identity.launcher_identity == stage_b_identity.launcher_identity:
            raise ContinuationProtocolError("launcher/session identity reuse is forbidden")
        if (
            stage_a_identity.launcher_identity_classification != "ephemeral_local_launcher"
            or stage_b_identity.launcher_identity_classification != "ephemeral_local_launcher"
        ):
            raise ContinuationProtocolError(
                "alpha interruption supports only process-isolated synthetic launchers; external launchers require a supervised process-handle contract"
            )
        if stage_a is stage_b:
            raise ContinuationProtocolError("Stage A and Stage B require distinct launcher objects")
        if not isinstance(stage_a, StageALauncher) or not isinstance(stage_b, StageBLauncher):
            raise ContinuationProtocolError("launchers do not implement the required stage protocols")

    @staticmethod
    def _terminate_child_group(pid: int) -> None:
        """Terminate and reap the exact forked launcher session."""

        leader_reaped = False
        for signal_value, timeout in ((signal.SIGTERM, 0.25), (signal.SIGKILL, 1.0)):
            try:
                os.killpg(pid, signal_value)
            except ProcessLookupError:
                try:
                    os.kill(pid, signal_value)
                except ProcessLookupError:
                    pass
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if not leader_reaped:
                    try:
                        waited, _status = os.waitpid(pid, os.WNOHANG)
                    except ChildProcessError:
                        leader_reaped = True
                    else:
                        leader_reaped = waited == pid
                try:
                    os.killpg(pid, 0)
                except ProcessLookupError:
                    if not leader_reaped:
                        try:
                            os.waitpid(pid, 0)
                        except ChildProcessError:
                            pass
                    return
                time.sleep(0.005)
        if not leader_reaped:
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
        try:
            os.killpg(pid, 0)
        except ProcessLookupError:
            return
        raise ContinuationProtocolError(
            "isolated launcher process group could not be reaped"
        )

    def _bounded_process_call(
        self, label: str, callback: Callable[[], Mapping[str, object]],
        deadline: float,
    ) -> dict[str, object]:
        if not hasattr(os, "fork"):
            raise ContinuationProtocolError(
                "alpha launcher isolation requires a POSIX process boundary"
            )
        read_descriptor, write_descriptor = os.pipe()
        pid = os.fork()
        if pid == 0:  # pragma: no cover - parent assertions consume the result
            try:
                os.close(read_descriptor)
                os.setsid()
                try:
                    value = callback()
                    payload: dict[str, object] = {"ok": True, "value": dict(value)}
                except BaseException:  # noqa: BLE001 - never serialize arbitrary exception data
                    payload = {"ok": False, "error": "launcher_callback_failed"}
                encoded = _canonical_json(payload).encode("utf-8")
                if len(encoded) > 65_536:
                    encoded = _canonical_json({"ok": False, "error": "launcher_result_oversized"}).encode("utf-8")
                written = 0
                while written < len(encoded):
                    written += os.write(write_descriptor, encoded[written:])
            finally:
                try:
                    os.close(write_descriptor)
                except OSError:
                    pass
                os._exit(0)
        os.close(write_descriptor)
        received = bytearray()
        timed_out = False
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                ready, _, _ = select.select([read_descriptor], [], [], remaining)
                if not ready:
                    timed_out = True
                    break
                chunk = os.read(read_descriptor, 65_537 - len(received))
                if not chunk:
                    break
                received.extend(chunk)
                if len(received) > 65_536:
                    break
        finally:
            os.close(read_descriptor)
            self._terminate_child_group(pid)
        if timed_out:
            raise ContinuationProtocolError(
                f"{label} exceeded the absolute alpha deadline"
            )
        if len(received) > 65_536:
            raise ContinuationProtocolError(f"{label} returned oversized launcher evidence")
        try:
            payload = json.loads(bytes(received))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ContinuationProtocolError(f"{label} returned malformed launcher evidence") from exc
        if not isinstance(payload, dict) or payload.get("ok") is not True or not isinstance(payload.get("value"), dict):
            raise ContinuationProtocolError(f"{label} failed inside its isolated launcher process")
        return dict(payload["value"])

    @staticmethod
    def _stage_result_payload(result: LauncherStageResult) -> dict[str, object]:
        if type(result) is not LauncherStageResult:
            raise ContinuationProtocolError("launcher must return the bounded LauncherStageResult contract")
        return {
            "result": result.result,
            "interrupted": result.interrupted,
            "evidenceReferences": [item.to_dict() for item in result.evidence_references],
        }

    @staticmethod
    def _stage_result_from_payload(value: object) -> LauncherStageResult:
        if not isinstance(value, dict) or set(value) != {"result", "interrupted", "evidenceReferences"}:
            raise ContinuationProtocolError("isolated launcher result has an invalid shape")
        references = value["evidenceReferences"]
        if not isinstance(references, list):
            raise ContinuationProtocolError("isolated launcher evidence is invalid")
        return LauncherStageResult(
            str(value["result"]),
            value["interrupted"],  # type: ignore[arg-type]
            tuple(EvidenceReference(item["referenceId"], item["kind"]) for item in references),  # type: ignore[index,arg-type]
        )

    def _stage_a(
        self, launcher: StageALauncher, request: StageAInput, deadline: float,
    ) -> tuple[LauncherStageResult, InterruptionFact]:
        def invoke() -> Mapping[str, object]:
            controller = InterruptionController(request.policy)
            result = launcher.launch_stage_a(request, controller)
            return {
                "stageResult": self._stage_result_payload(result),
                "interruption": controller.fact.to_dict(),
            }

        payload = self._bounded_process_call("stage-a", invoke, deadline)
        result = self._stage_result_from_payload(payload.get("stageResult"))
        fact = payload.get("interruption")
        if result.result not in _STAGE_A_RESULTS or not result.interrupted or not isinstance(fact, dict):
            raise ContinuationProtocolError("Stage A returned an incompatible closed outcome")
        interruption = InterruptionFact(
            dict(fact.get("trigger", {})),
            dict(fact.get("budget", {})),
            int(fact.get("observedNormalizedEvents", -1)),
            str(fact.get("policyDigest", "")),
        )
        if interruption.policy_digest != request.policy.digest:
            raise ContinuationProtocolError("Stage A interruption fact is not policy-bound")
        return result, interruption

    def _stage_b(
        self, launcher: StageBLauncher, request: StageBInput, deadline: float,
    ) -> LauncherStageResult:
        payload = self._bounded_process_call(
            "stage-b",
            lambda: {"stageResult": self._stage_result_payload(launcher.launch_stage_b(request))},
            deadline,
        )
        result = self._stage_result_from_payload(payload.get("stageResult"))
        if result.result not in _STAGE_B_RESULTS or result.interrupted:
            raise ContinuationProtocolError("Stage B may not reuse the Stage-A interruption outcome")
        return result

    def _new_run_root(self, value: str | Path) -> Path:
        root = Path(os.path.abspath(os.fspath(value)))
        if ".." in root.parts or root.exists() or root.is_symlink():
            raise ContinuationProtocolError("run_root must be a new non-symlink directory")
        ancestor = root.parent
        while ancestor != ancestor.parent:
            if ancestor.exists() and ancestor.is_symlink():
                raise ContinuationProtocolError("run_root must not traverse a symlink")
            ancestor = ancestor.parent
        root.mkdir(parents=True)
        return root.resolve()

    def _durable_files(self, worktree: Path, values: tuple[str, ...]) -> tuple[str, ...]:
        result: list[str] = []
        for value in values:
            if not isinstance(value, str) or not value or Path(value).is_absolute() or ".." in Path(value).parts:
                raise ContinuationProtocolError("durable StateDD files must be relative repository paths")
            target = worktree / value
            if not target.is_file() or target.is_symlink():
                raise ContinuationProtocolError("durable StateDD file is missing or unsafe")
            result.append(value)
        if len(set(result)) != len(result):
            raise ContinuationProtocolError("durable StateDD files must be distinct")
        return tuple(result)

    def _persist_interruption(
        self, *, record: Path, agent_workspace: Path, materialized: FixtureMaterialization, stage_a: AttemptIdentity,
        interruption: InterruptionFact, policy: InterruptionPolicy, task: str, snapshot: RepositorySnapshot,
    ) -> None:
        try:
            record.relative_to(agent_workspace)
        except ValueError:
            pass
        else:
            raise ContinuationProtocolError("interruption evidence must stay outside the agent workspace")
        payload = {
            "formatVersion": INTERRUPTION_RECORD_FORMAT,
            "stageA": stage_a.to_dict(),
            "fixture": {"commit": materialized.commit, "tree": materialized.tree},
            "policy": policy.to_dict(),
            "interruption": interruption.to_dict(),
            "originalTaskDigest": "sha256:" + sha256(task.encode("utf-8")).hexdigest(),
            "repositorySnapshot": snapshot.to_dict(),
        }
        encoded = (_canonical_json(payload) + "\n").encode("utf-8")
        descriptor = os.open(record, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            os.close(descriptor)

    def _verify_interruption_record(
        self, record: Path, materialized: FixtureMaterialization,
        stage_a: AttemptIdentity, interruption: InterruptionFact,
        policy: InterruptionPolicy, task: str, snapshot: RepositorySnapshot,
    ) -> None:
        if not record.is_file() or record.is_symlink():
            raise ContinuationProtocolError("persisted interruption record is missing")
        try:
            payload = json.loads(record.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ContinuationProtocolError("persisted interruption record is invalid") from exc
        if not isinstance(payload, dict) or set(payload) != {
            "formatVersion", "stageA", "fixture", "policy", "interruption", "originalTaskDigest", "repositorySnapshot",
        }:
            raise ContinuationProtocolError("persisted interruption record has hidden or unsupported fields")
        if payload.get("formatVersion") != INTERRUPTION_RECORD_FORMAT:
            raise ContinuationProtocolError("persisted interruption record version drifted")
        if (
            payload.get("stageA") != stage_a.to_dict()
            or payload.get("fixture") != {
                "commit": materialized.commit, "tree": materialized.tree,
            }
            or payload.get("policy") != policy.to_dict()
            or payload.get("interruption") != interruption.to_dict()
            or payload.get("originalTaskDigest")
            != "sha256:" + sha256(task.encode("utf-8")).hexdigest()
        ):
            raise ContinuationProtocolError("persisted interruption record drifted")
        if payload.get("repositorySnapshot") != snapshot.to_dict():
            raise ContinuationProtocolError("persisted interruption repository snapshot drifted")

    def _snapshot(self, worktree: Path) -> RepositorySnapshot:
        commit = self._git(worktree, ["rev-parse", "HEAD"])
        tree = self._git(worktree, ["rev-parse", "HEAD^{tree}"])
        digest = sha256()
        for path in sorted(worktree.rglob("*"), key=lambda item: item.relative_to(worktree).as_posix()):
            relative = path.relative_to(worktree)
            if relative.parts[0] == ".git":
                continue
            if path.is_symlink():
                raise ContinuationProtocolError("repository snapshots reject symlinks")
            if path.is_dir():
                continue
            if not path.is_file():
                raise ContinuationProtocolError("repository snapshots require regular files")
            digest.update(relative.as_posix().encode("utf-8"))
            digest.update(b"\0")
            mode = stat.S_IMODE(path.stat(follow_symlinks=False).st_mode)
            digest.update(f"{mode:o}".encode("ascii"))
            digest.update(b"\0")
            digest.update(path.read_bytes())
            digest.update(b"\0")
        return RepositorySnapshot(
            commit=commit,
            tree=tree,
            working_tree_digest=f"sha256:{digest.hexdigest()}",
            clean=not bool(self._git_status(worktree)),
        )

    def _git_status(self, worktree: Path) -> str:
        return self._git(worktree, ["status", "--porcelain=v1", "--untracked-files=all"])

    def _git(self, worktree: Path, args: list[str]) -> str:
        completed = subprocess.run(
            ["git", "-C", str(worktree), *args], check=False, capture_output=True, text=True,
            timeout=self._timeout_seconds, shell=False,
        )
        if completed.returncode != 0:
            raise ContinuationProtocolError(f"Git command failed: {completed.stderr.strip()}")
        return completed.stdout.strip()
