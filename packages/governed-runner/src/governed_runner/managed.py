"""Deterministic managed-mode backend over the shared cockpit closure path.

This module adds supervision, not another source of workflow truth.  The fake
backend is test-only, never calls a model, receives only the caller's staging
repository, and retains no canonical provider session contract.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import re
import sys
import tempfile
import threading
from types import MappingProxyType
from typing import Any, Callable, Mapping

from execution_host.contracts import (
    AgentRunSpec,
    BackendCapabilities,
    require_accepted,
    validate_run_result,
)
from execution_host.runtime import (
    AgentBackend,
    BackendEvent,
    BackendHealth,
    BackendOperationResult,
)
from external_engine_runtime import (
    ProcessIdentity,
    ProcessSpec,
    decode_jsonl,
    filtered_environment,
    run_process,
)
from run_bundle import RunBundleWriter
from runtime_contracts import (
    AgentProfile,
    ContextManifest,
    NORMALIZED_AGENT_EVENT_TYPES,
    RunReceipt,
    RuntimeProfile,
    TaskManifest,
    WorkflowDeclaration,
)

from .cockpit import (
    CockpitCoordinator,
    CockpitError,
    CockpitStateError,
    GateReport,
    PreparedCockpitJob,
    _attempt_id,
    _git_sha,
    _git_status,
)
from .evidence import EvidenceStoreError
from .lease import InstanceLease


_CAPABILITY_NAMES = (
    "structuredEvents",
    "nonInteractiveExecution",
    "cancellation",
    "sessionResume",
    "repositoryInstructions",
    "customTools",
    "mcpEquivalent",
    "approvalIntegration",
    "sandboxSupport",
    "changedFileReporting",
    "tokenTelemetry",
    "costTelemetry",
)
_FAKE_STATUSES = frozenset({"completed", "failed", "interrupted"})
_SAFE_INHERITED_ENVIRONMENT = frozenset({"PATH", "LANG", "LC_ALL"})
_CREDENTIAL_ENV = re.compile(
    r"(?:api[_-]?key|authorization|cookie|credential|password|secret|token|private[_-]?key)",
    re.IGNORECASE,
)
_NONTERMINAL_BACKEND_EVENTS = NORMALIZED_AGENT_EVENT_TYPES - {
    "run.started",
    "run.completed",
    "run.failed",
    "run.cancelled",
}


def _safe_relative(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError("fake write path must be a relative POSIX path")
    path = Path(value)
    if path.is_absolute() or any(
        part in {"", ".", "..", ".git"} for part in path.parts
    ):
        raise ValueError("fake write path must remain outside Git metadata")
    return path.as_posix()


def _prepare_safe_write_target(staging_root: Path, relative: str) -> None:
    """Reject symlink/non-directory ancestors before the deterministic write."""

    root = staging_root.resolve(strict=True)
    target = root / relative
    cursor = root
    for part in Path(relative).parts[:-1]:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValueError("fake write path may not traverse a symlink")
        if cursor.exists():
            if not cursor.is_dir():
                raise ValueError("fake write parent must be a directory")
        else:
            cursor.mkdir(mode=0o700)
    if target.is_symlink():
        raise ValueError("fake write target may not be a symlink")
    if target.exists() and not target.is_file():
        raise ValueError("fake write target must be a regular file")
    try:
        target.resolve(strict=False).relative_to(root)
    except ValueError as exc:
        raise ValueError("fake write target escapes the staging workspace") from exc


@dataclass(frozen=True)
class FakeBackendScenario:
    """Strict deterministic behavior injection for public-safe conformance tests."""

    start_status: str = "completed"
    resume_status: str = "completed"
    delay_seconds: float = 0.0
    spawn_child: bool = False
    child_inherits_generation: bool = True
    event_summary: str = "deterministic fake execution"
    event_attributes: Mapping[str, Any] = field(default_factory=dict)
    adapter_metadata: Mapping[str, Any] = field(default_factory=dict)
    write_path: str | None = None
    write_content: str = "deterministic fake output\n"

    def __post_init__(self) -> None:
        if (
            self.start_status not in _FAKE_STATUSES
            or self.resume_status not in _FAKE_STATUSES
        ):
            raise ValueError("fake backend status is invalid")
        if (
            isinstance(self.delay_seconds, bool)
            or not isinstance(self.delay_seconds, (int, float))
            or not math.isfinite(float(self.delay_seconds))
            or not 0 <= float(self.delay_seconds) <= 60
        ):
            raise ValueError(
                "fake backend delay must be between zero and sixty seconds"
            )
        if not isinstance(self.spawn_child, bool):
            raise ValueError("spawn_child must be boolean")
        if not isinstance(self.child_inherits_generation, bool):
            raise ValueError("child_inherits_generation must be boolean")
        if (
            not isinstance(self.event_summary, str)
            or not self.event_summary
            or len(self.event_summary) > 4096
        ):
            raise ValueError("fake event summary must be bounded")
        for name, value in (
            ("event_attributes", self.event_attributes),
            ("adapter_metadata", self.adapter_metadata),
        ):
            if (
                not isinstance(value, Mapping)
                or len(value) > 32
                or any(not isinstance(key, str) for key in value)
            ):
                raise ValueError(f"{name} must be a bounded string-keyed mapping")
            json.dumps(value, allow_nan=False)
            object.__setattr__(self, name, MappingProxyType(dict(value)))
        if self.write_path is not None:
            object.__setattr__(self, "write_path", _safe_relative(self.write_path))
        if (
            not isinstance(self.write_content, str)
            or len(self.write_content.encode("utf-8")) > 64 * 1024
        ):
            raise ValueError("fake write content must be a bounded string")


_FAKE_PROCESS = r"""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

phase, outcome, delay, spawn_child, child_inherits_generation, summary, write_path, write_content = sys.argv[1:]
print(json.dumps({
    "eventType": "message.delta",
    "summary": summary,
    "attributes": {"phase": phase, "environmentKeys": ",".join(sorted(os.environ))},
}, sort_keys=True), flush=True)
if write_path != "-":
    target = Path(write_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(write_content, encoding="utf-8")
    print(json.dumps({
        "eventType": "file.changed", "summary": "fake staging file changed",
        "attributes": {"path": write_path},
    }, sort_keys=True), flush=True)
child = None
if spawn_child == "1":
    child_environment = dict(os.environ)
    if child_inherits_generation != "1":
        child_environment.pop("STATEPORT_PROCESS_GENERATION", None)
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        env=child_environment,
    )
    print(json.dumps({
        "eventType": "command.started", "summary": "fake child started",
        "attributes": {"childPid": child.pid},
    }, sort_keys=True), flush=True)
time.sleep(float(delay))
if child is not None:
    child.terminate()
    child.wait(timeout=5)
print(json.dumps({
    "eventType": "command.completed", "summary": "fake process phase completed",
    "attributes": {"phase": phase, "outcome": outcome},
}, sort_keys=True), flush=True)
print(json.dumps({"stateportFakeOutcome": outcome}, sort_keys=True), flush=True)
raise SystemExit(9 if outcome == "failed" else 0)
"""


class DeterministicFakeBackend:
    """Test-only process backend with explicit start/resume/cancel/health."""

    def __init__(self, scenario: FakeBackendScenario | None = None) -> None:
        self.scenario = scenario or FakeBackendScenario()
        self._lock = threading.Lock()
        self._active: dict[str, threading.Event] = {}
        self._states: dict[str, str] = {}
        self._process_started: Callable[[str, Path, ProcessIdentity], None] | None = None
        self._process_finished: Callable[[str, ProcessIdentity], None] | None = None

    def bind_process_observer(
        self,
        *,
        on_started: Callable[[str, Path, ProcessIdentity], None],
        on_finished: Callable[[str, ProcessIdentity], None],
    ) -> None:
        """Bind the one durable supervisor ledger before any process starts."""

        if not callable(on_started) or not callable(on_finished):
            raise ValueError("managed process observers must be callable")
        with self._lock:
            if self._active:
                raise ValueError("managed process observers cannot change while a run is active")
            self._process_started = on_started
            self._process_finished = on_finished

    def capabilities(self) -> BackendCapabilities:
        capabilities = {name: "unsupported" for name in _CAPABILITY_NAMES}
        capabilities.update(
            {
                "structuredEvents": "supported",
                "nonInteractiveExecution": "supported",
                "cancellation": "supported",
                "sessionResume": "supported",
                "repositoryInstructions": "supported",
                "sandboxSupport": "partial",
                "changedFileReporting": "supported",
                "tokenTelemetry": "unavailable",
                "costTelemetry": "unavailable",
            }
        )
        return BackendCapabilities(
            "managed-fake",
            "deterministic-fake",
            "1.0.0",
            "managed",
            capabilities,
            ("not_applicable",),
            (),
            test_only=True,
            production_eligible=False,
        )

    @staticmethod
    def _validate_environment(
        staging_root: Path, environment: Mapping[str, str]
    ) -> None:
        if not isinstance(environment, Mapping) or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in environment.items()
        ):
            raise ValueError("managed environment must contain string pairs")
        allowed = _SAFE_INHERITED_ENVIRONMENT | {"HOME", "TMPDIR"}
        if set(environment) - allowed or any(
            _CREDENTIAL_ENV.search(key) for key in environment
        ):
            raise ValueError(
                "managed environment is not credential-free and allowlisted"
            )
        for name in ("HOME", "TMPDIR"):
            value = environment.get(name)
            if value is None:
                raise ValueError(
                    "managed fake execution requires isolated HOME and TMPDIR"
                )
            path = Path(value)
            if not path.is_absolute() or path.is_symlink() or not path.is_dir():
                raise ValueError(
                    f"managed {name} must be an existing staging directory"
                )
            try:
                path.resolve().relative_to(staging_root.resolve())
            except ValueError as exc:
                raise ValueError(
                    f"managed {name} must remain inside the staging workspace"
                ) from exc

    def _run_phase(
        self,
        operation: str,
        run_spec: AgentRunSpec,
        staging_root: Path,
        *,
        environment: Mapping[str, str],
        event_sink: Any,
    ) -> BackendOperationResult:
        if not isinstance(staging_root, Path):
            staging_root = Path(staging_root)
        if (
            not staging_root.is_absolute()
            or staging_root.is_symlink()
            or not staging_root.is_dir()
        ):
            raise ValueError(
                "managed staging root must be an existing absolute non-symlink directory"
            )
        self._validate_environment(staging_root, environment)
        if self.scenario.write_path is not None:
            _prepare_safe_write_target(staging_root, self.scenario.write_path)
        desired = (
            self.scenario.start_status
            if operation == "start"
            else self.scenario.resume_status
        )
        cancel_event = threading.Event()
        with self._lock:
            if run_spec.run_id in self._active:
                return BackendOperationResult(
                    operation,
                    run_spec.run_id,
                    "failed",
                    failure_classification="already_running",
                )
            current = self._states.get(run_spec.run_id)
            if operation == "start" and current is not None:
                return BackendOperationResult(
                    operation,
                    run_spec.run_id,
                    "failed",
                    failure_classification="already_started",
                )
            if operation == "resume" and current != "interrupted":
                return BackendOperationResult(
                    operation,
                    run_spec.run_id,
                    "unsupported",
                    failure_classification="resume_state_incompatible",
                )
            self._active[run_spec.run_id] = cancel_event
            self._states[run_spec.run_id] = "running"

        delivered: list[BackendEvent] = []
        start_event = BackendEvent(
            "command.started",
            f"deterministic fake backend {operation}",
            {"operation": operation, "testOnly": True},
            {"backendId": "managed-fake", "testOnly": True},
        )
        try:
            event_sink(start_event)
            delivered.append(start_event)
            command = (
                sys.executable,
                "-c",
                _FAKE_PROCESS,
                operation,
                desired,
                str(float(self.scenario.delay_seconds)),
                "1" if self.scenario.spawn_child else "0",
                "1" if self.scenario.child_inherits_generation else "0",
                self.scenario.event_summary,
                self.scenario.write_path or "-",
                self.scenario.write_content,
            )
            process_result = run_process(
                ProcessSpec(
                    command,
                    staging_root,
                    timeout_seconds=float(run_spec.budgets["timeSeconds"]),
                    max_output_bytes=min(
                        max(run_spec.budgets["steps"], 1) * 256 * 1024, 4 * 1024 * 1024
                    ),
                    environment=environment,
                    on_started=(
                        (lambda identity: self._process_started(
                            run_spec.run_id, staging_root, identity,
                        ))
                        if self._process_started is not None else None
                    ),
                    on_finished=(
                        (lambda identity: self._process_finished(
                            run_spec.run_id, identity,
                        ))
                        if self._process_finished is not None else None
                    ),
                ),
                cancel_event=cancel_event,
            )
            process = {
                "returncode": process_result.returncode,
                "timedOut": process_result.timed_out,
                "cancelled": process_result.cancelled,
                "outputLimited": process_result.output_limited,
                "stdoutRetainedBytes": len(process_result.stdout.encode("utf-8")),
                "stderrRetainedBytes": len(process_result.stderr.encode("utf-8")),
                "durationMs": process_result.duration_ms,
                "cleanup": process_result.cleanup,
            }
            if process_result.cancelled:
                status, failure = "cancelled", "operator_cancelled"
            elif process_result.timed_out:
                status, failure = "timed_out", "timeout"
            elif process_result.output_limited:
                status, failure = "failed", "output_limit"
            else:
                status, failure = desired, None if desired == "completed" else desired

            try:
                native_events = decode_jsonl(process_result.stdout)
                control_status: str | None = None
                for native in native_events:
                    if "stateportFakeOutcome" in native:
                        control_status = native.get("stateportFakeOutcome")
                        continue
                    event_type = native.get("eventType")
                    summary = native.get("summary")
                    attributes = native.get("attributes")
                    if (
                        event_type not in _NONTERMINAL_BACKEND_EVENTS
                        or not isinstance(summary, str)
                        or not isinstance(attributes, Mapping)
                    ):
                        raise ValueError(
                            "fake backend emitted an invalid normalized event"
                        )
                    metadata = (
                        self.scenario.adapter_metadata
                        if event_type == "message.delta"
                        else {}
                    )
                    merged_attributes = dict(attributes)
                    if event_type == "message.delta":
                        merged_attributes.update(self.scenario.event_attributes)
                    event = BackendEvent(
                        event_type, summary, merged_attributes, metadata
                    )
                    event_sink(event)
                    delivered.append(event)
                if (
                    status in {"completed", "failed", "interrupted"}
                    and control_status != desired
                ):
                    status, failure = (
                        "failed",
                        "missing_or_mismatched_structured_outcome",
                    )
            except (ValueError, json.JSONDecodeError):
                if status not in {"cancelled", "timed_out"}:
                    status, failure = "failed", "malformed_structured_output"
            if process_result.returncode not in {0, 9} and status not in {
                "cancelled",
                "timed_out",
            }:
                status, failure = "failed", "process_exit"
            outcome = BackendOperationResult(
                operation,
                run_spec.run_id,
                status,
                tuple(delivered),
                failure_classification=failure,
                process=process,
            )
            with self._lock:
                self._states[run_spec.run_id] = outcome.status
            return outcome
        except Exception:
            with self._lock:
                self._states[run_spec.run_id] = "failed"
            raise
        finally:
            with self._lock:
                self._active.pop(run_spec.run_id, None)

    def start(
        self,
        run_spec: AgentRunSpec,
        staging_root: Path,
        *,
        environment: Mapping[str, str],
        event_sink: Any,
    ) -> BackendOperationResult:
        return self._run_phase(
            "start",
            run_spec,
            Path(staging_root),
            environment=environment,
            event_sink=event_sink,
        )

    def resume(
        self,
        run_spec: AgentRunSpec,
        staging_root: Path,
        *,
        environment: Mapping[str, str],
        event_sink: Any,
    ) -> BackendOperationResult:
        return self._run_phase(
            "resume",
            run_spec,
            Path(staging_root),
            environment=environment,
            event_sink=event_sink,
        )

    def cancel(self, run_id: str) -> BackendOperationResult:
        with self._lock:
            cancel_event = self._active.get(run_id)
            state = self._states.get(run_id)
            if cancel_event is not None:
                cancel_event.set()
                return BackendOperationResult(
                    "cancel", run_id, "cancellation_requested"
                )
            if state == "cancelled":
                return BackendOperationResult("cancel", run_id, "cancelled")
            return BackendOperationResult(
                "cancel",
                run_id,
                "not_running",
                failure_classification="no_active_process",
            )

    def health(self) -> BackendHealth:
        with self._lock:
            active = len(self._active)
        return BackendHealth(
            "managed-fake",
            "healthy",
            active,
            True,
            "deterministic fake backend; no provider or model execution",
        )


class ManagedCockpit(CockpitCoordinator):
    """Managed fake execution through the common lease, verify, and receipt path."""

    def __init__(
        self,
        evidence_store: Any,
        lease_directory: str | Path,
        *,
        backend: AgentBackend | None = None,
        bundle_directory: str | Path | None = None,
        owner: str = "managed-fake",
    ) -> None:
        super().__init__(evidence_store, lease_directory, mode="managed", owner=owner)
        selected = backend or DeterministicFakeBackend()
        capabilities = selected.capabilities()
        if (
            not capabilities.test_only
            or capabilities.production_eligible
            or capabilities.backend_id != "managed-fake"
        ):
            raise CockpitError(
                "this managed slice accepts only the production-ineligible deterministic fake backend"
            )
        self.backend = selected
        if not isinstance(selected, DeterministicFakeBackend):
            raise CockpitError("managed fake backend lacks the bounded process-ledger contract")
        default_bundle_root = Path(evidence_store.path).parent / "managed-run-bundles"
        self.bundle_directory = Path(bundle_directory or default_bundle_root).resolve()
        if self.bundle_directory.exists() and (
            self.bundle_directory.is_symlink() or not self.bundle_directory.is_dir()
        ):
            raise CockpitError("managed RunBundle path must be a non-symlink directory")
        self._outcomes: dict[str, BackendOperationResult] = {}
        self._operation_history: dict[str, list[BackendOperationResult]] = {}
        self._resume_bindings: dict[str, tuple[tuple[str, ...], str]] = {}
        self._operation_lock = threading.RLock()
        self._recovering_runs: set[str] = set()
        self.recovery_observations = tuple(evidence_store.reconcile_supervised_processes())
        self.recovered_attempts = self._recover_abandoned_attempts()
        selected.bind_process_observer(
            on_started=lambda run_id, staging_root, identity: evidence_store.register_supervised_process(
                run_id=run_id,
                attempt_id=_attempt_id(run_id),
                pid=identity.pid,
                process_group_id=identity.process_group_id,
                start_time_ticks=identity.start_time_ticks,
                process_generation=identity.process_generation,
                staging_root=staging_root,
                phase="backend",
            ),
            on_finished=lambda run_id, identity: evidence_store.complete_supervised_process(
                run_id=run_id,
                pid=identity.pid,
                start_time_ticks=identity.start_time_ticks,
            ),
        )

    @staticmethod
    def _recovery_context(job: PreparedCockpitJob) -> dict[str, Any]:
        return {
            "formatVersion": "stateport.managed-recovery-context/v1",
            "workflow": job.workflow.to_dict(),
            "task": job.task.to_dict(),
            "runtime": job.runtime.to_dict(),
            "context": job.context.to_dict(),
            "agent": job.agent.to_dict(),
            "runSpec": job.run_spec.to_dict(),
            "instanceRoot": job.instance_root.as_posix(),
            "stagingRoot": job.staging_root.as_posix(),
        }

    def _create_attempt(self, job: PreparedCockpitJob) -> None:
        """Atomically create the attempt and its restart recovery context."""

        self.evidence_store.create_attempt(
            parent_job_id=job.task.to_dict()["jobId"],
            attempt_id=_attempt_id(job.run_spec.run_id),
            run_id=job.run_spec.run_id,
            managed_recovery_context=self._recovery_context(job),
        )

    def _gate_observers(
        self, job: PreparedCockpitJob, phase: str,
    ) -> tuple[Callable[[ProcessIdentity], None], Callable[[ProcessIdentity], None]]:
        if phase not in {"preflight", "verification"}:
            raise CockpitError("managed gate process phase is unsupported")

        def started(identity: ProcessIdentity) -> None:
            self.evidence_store.register_supervised_process(
                run_id=job.run_spec.run_id,
                attempt_id=_attempt_id(job.run_spec.run_id),
                pid=identity.pid,
                process_group_id=identity.process_group_id,
                start_time_ticks=identity.start_time_ticks,
                process_generation=identity.process_generation,
                staging_root=job.staging_root,
                phase=phase,
            )

        def finished(identity: ProcessIdentity) -> None:
            self.evidence_store.complete_supervised_process(
                run_id=job.run_spec.run_id,
                pid=identity.pid,
                start_time_ticks=identity.start_time_ticks,
            )

        return started, finished

    def _recover_abandoned_attempts(self) -> tuple[dict[str, Any], ...]:
        """Close owner-dead managed attempts only after process reconciliation."""

        recovered: list[dict[str, Any]] = []
        for candidate in self.evidence_store.managed_recovery_candidates():
            data = candidate["context"]
            run_id = candidate["runId"]
            lease: InstanceLease | None = None
            try:
                workflow = WorkflowDeclaration.from_dict(data["workflow"])
                task = TaskManifest.from_dict(data["task"])
                runtime = RuntimeProfile.from_dict(data["runtime"])
                context = ContextManifest.from_dict(data["context"])
                agent = AgentProfile.from_dict(data["agent"])
                run_spec = AgentRunSpec.from_dict(data["runSpec"])
                if run_spec.run_id != run_id or _attempt_id(run_id) != candidate["attemptId"]:
                    raise CockpitError("managed recovery identity drifted")
                instance_root = Path(data["instanceRoot"]).resolve(strict=True)
                staging_root = Path(data["stagingRoot"]).resolve(strict=True)
                lease = InstanceLease(
                    self.lease_directory, instance_root,
                    owner=f"managed-recovery:{run_id}",
                ).acquire()
                if _git_sha(instance_root) != task.to_dict()["baseSha"]:
                    raise CockpitError("managed recovery canonical base SHA drifted")
                job = PreparedCockpitJob(
                    workflow, task, runtime, context, agent, run_spec,
                    instance_root, staging_root, lease,
                )
                journal = self.evidence_store.journal(candidate["attemptId"])
                preflight_passed = any(
                    event.get("eventType") == "command.completed"
                    and event.get("payload", {}).get("summary")
                    == "preflight gate completed"
                    and event.get("payload", {}).get("attributes", {}).get("status")
                    == "passed"
                    for event in journal
                )
                job.preflight = GateReport(
                    (), "passed" if preflight_passed else "failed",
                    0 if preflight_passed else None, False, "",
                    "" if preflight_passed else "supervisor ended before preflight completion was proven",
                    False, False,
                )
                job.verification = GateReport(
                    (), "not_run", None, False, "", "supervisor ended before verification",
                    False, False,
                )
                job.state = "report_and_stop"
                process_pairs = list(zip(
                    candidate["processPhases"], candidate["processStates"], strict=True,
                ))
                interrupted_phase = next(
                    (
                        phase for phase, state in reversed(process_pairs)
                        if state != "reaped"
                    ),
                    None,
                )
                if not preflight_passed:
                    interrupted_phase = "preflight"
                elif interrupted_phase is None and any(
                    phase == "verification" for phase, _state in process_pairs
                ):
                    interrupted_phase = "verification"
                job.report_reason = (
                    "supervisor_lost_during_"
                    + (interrupted_phase or "managed_execution")
                )
                job.terminal_classification = "interrupted"
                job.first_attempt_status = "interrupted"
                job.event_sequence = len(journal)
                if not journal:
                    self._event(
                        job, "run.started",
                        "recovery observed a managed attempt before initial journaling completed",
                    )
                try:
                    self._observe_staging_changes(job)
                except CockpitError:
                    job.changed_paths = ()
                    job.diff_allowed = False
                    job.verified_workspace_digest = None
                    job.report_reason = "unsafe_staging_after_supervisor_loss"
                self._jobs[run_id] = job
                self._recovering_runs.add(run_id)
                outcome = BackendOperationResult(
                    "start", run_id, "interrupted",
                    failure_classification=job.report_reason,
                )
                self._outcomes[run_id] = outcome
                self._operation_history[run_id] = [outcome]
                receipt = self.close_managed(run_id)
                self.evidence_store.finish_managed_recovery_context(
                    run_id=run_id, state="recovered",
                )
                self._recovering_runs.discard(run_id)
                recovered.append({
                    "runId": run_id,
                    "attemptId": candidate["attemptId"],
                    "classification": "interrupted",
                    "receiptDigest": receipt.digest,
                    "processStates": candidate["processStates"],
                    "processPhases": candidate["processPhases"],
                })
                lease = None  # close_managed released the lease.
            except Exception as exc:
                self._recovering_runs.discard(run_id)
                if lease is not None:
                    lease.release()
                raise CockpitError(
                    "managed recovery could not terminalize an abandoned attempt"
                ) from exc
        return tuple(recovered)

    def capabilities(self) -> BackendCapabilities:
        return self.backend.capabilities()

    def health(self) -> BackendHealth:
        return self.backend.health()

    @staticmethod
    def _managed_profile(
        runtime: RuntimeProfile,
        task: TaskManifest,
        run_spec: AgentRunSpec,
        capabilities: BackendCapabilities,
    ) -> None:
        runtime_data = runtime.to_dict()
        task_data = task.to_dict()
        if (run_spec.backend_id, run_spec.adapter_id, run_spec.adapter_version) != (
            capabilities.backend_id,
            capabilities.adapter_id,
            capabilities.adapter_version,
        ):
            raise CockpitError(
                "managed RunSpec does not select the exact fake backend identity"
            )
        if runtime_data["authentication"] != {
            "classification": "not_applicable",
            "owner": "none",
        }:
            raise CockpitError(
                "managed fake authentication must be explicitly not_applicable"
            )
        if run_spec.model_identifier != "deterministic.no-model" or runtime_data[
            "provider"
        ] != {"id": "managed-fake", "model": "deterministic.no-model"}:
            raise CockpitError("managed fake execution cannot select a live model")
        if runtime_data["reasoning"]["classification"] != "deterministic":
            raise CockpitError(
                "managed fake reasoning must be classified deterministic"
            )
        if runtime_data["network"] != {"policy": "unproven", "allowlist": []}:
            raise CockpitError(
                "managed host execution must record network isolation as unproven"
            )
        if runtime_data["sandbox"] != {
            "profile": "staging_copy_only",
            "filesystem": "unproven",
        }:
            raise CockpitError(
                "managed host execution must record staging-copy-only unproven isolation"
            )
        degradations = set(runtime_data["degradations"])
        if not {"container_isolation_unproven", "network_isolation_unproven"}.issubset(
            degradations
        ):
            raise CockpitError("managed runtime omits mandatory isolation degradations")
        environment = set(runtime_data["environmentAllowlist"])
        if not environment.issubset(_SAFE_INHERITED_ENVIRONMENT):
            raise CockpitError(
                "managed runtime environment allowlist is not credential-free"
            )
        if run_spec.budgets["timeSeconds"] <= 0 or run_spec.budgets["costMinor"] != 0:
            raise CockpitError(
                "managed fake execution requires a positive timeout and zero spend budget"
            )
        if runtime_data["resume"]["supported"] and capabilities.capabilities[
            "sessionResume"
        ] not in {"native", "supported"}:
            raise CockpitError("managed runtime requests unsupported resumption")
        if any(
            item["classification"] not in {"none", "filesystem_transaction"}
            or item["automaticRetryAllowed"]
            for item in task_data["sideEffects"]
        ):
            raise CockpitError(
                "managed fake execution rejects external effects and automatic retry"
            )
        if task_data["failure"]["action"] != "report_and_stop":
            raise CockpitError("managed fake failure policy must report and stop")
        if "network" not in runtime_data["toolContract"]["denied"]:
            raise CockpitError("managed fake tool policy must deny network use")
        try:
            require_accepted(run_spec, capabilities)
        except ValueError as exc:
            raise CockpitError(
                f"managed backend capability or authentication negotiation failed: {exc}"
            ) from exc

    def prepare(
        self,
        workflow: WorkflowDeclaration,
        task: TaskManifest,
        runtime: RuntimeProfile,
        context: ContextManifest,
        agent: AgentProfile,
        run_spec: AgentRunSpec,
        *,
        instance_root: str | Path,
        staging_root: str | Path,
        repository_identity: Mapping[str, Any],
        instance_identity: Mapping[str, Any],
    ) -> PreparedCockpitJob:
        self._managed_profile(runtime, task, run_spec, self.backend.capabilities())
        canonical = Path(instance_root).resolve(strict=True)
        staging = Path(staging_root).resolve(strict=True)
        if self.evidence_store.managed_instance_blockers(canonical):
            raise CockpitStateError(
                "managed instance has an unresolved prior attempt and remains quarantined"
            )
        bundle_root = self.bundle_directory.resolve(strict=False)
        for workspace, label in ((canonical, "canonical"), (staging, "staging")):
            try:
                bundle_root.relative_to(workspace)
            except ValueError:
                pass
            else:
                raise CockpitError(
                    f"managed RunBundles may not be written inside the {label} workspace"
                )
        self.bundle_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.bundle_directory.is_symlink() or not self.bundle_directory.is_dir():
            raise CockpitError("managed RunBundle path became unsafe")
        return super().prepare(
            workflow,
            task,
            runtime,
            context,
            agent,
            run_spec,
            instance_root=instance_root,
            staging_root=staging_root,
            repository_identity=repository_identity,
            instance_identity=instance_identity,
        )

    def adopt(self, run_id: str, adopted_run_spec: AgentRunSpec) -> PreparedCockpitJob:
        del run_id, adopted_run_spec
        raise CockpitStateError(
            "managed execution is adopted only by the configured backend start operation"
        )

    def _event_sink(self, job: PreparedCockpitJob, event: BackendEvent) -> None:
        if event.event_type not in _NONTERMINAL_BACKEND_EVENTS:
            raise CockpitError(
                "backend attempted to emit a reserved or non-normalized event type"
            )
        metadata = {
            "backendId": self.backend.capabilities().backend_id,
            "testOnly": True,
        }
        if event.adapter_metadata is not None:
            metadata.update(dict(event.adapter_metadata))
        with self._operation_lock:
            self._event(
                job,
                event.event_type,
                event.summary,
                adapter_metadata=metadata,
                **dict(event.attributes),
            )

    @staticmethod
    def _environment(job: PreparedCockpitJob, runtime_root: Path) -> dict[str, str]:
        home, temporary = runtime_root / "home", runtime_root / "tmp"
        home.mkdir(mode=0o700)
        temporary.mkdir(mode=0o700)
        allow = tuple(job.runtime.to_dict()["environmentAllowlist"]) + (
            "HOME",
            "TMPDIR",
        )
        return filtered_environment(
            source=os.environ,
            allow=allow,
            overrides={"HOME": home.as_posix(), "TMPDIR": temporary.as_posix()},
        )

    def _record_outcome(
        self, job: PreparedCockpitJob, outcome: BackendOperationResult
    ) -> BackendOperationResult:
        with self._operation_lock:
            try:
                self._event(
                    job,
                    "command.completed",
                    f"managed backend {outcome.operation} completed",
                    operation=outcome.operation,
                    status=outcome.status,
                    failureClassification=outcome.failure_classification,
                )
            except EvidenceStoreError:
                outcome = BackendOperationResult(
                    outcome.operation,
                    outcome.run_id,
                    "failed",
                    failure_classification="bounded_journal_rejected_event",
                    process=outcome.process,
                )
            self._outcomes[job.run_spec.run_id] = outcome
            self._operation_history.setdefault(job.run_spec.run_id, []).append(outcome)
            if job.first_attempt_status is None:
                job.first_attempt_status = outcome.status
            if outcome.status == "completed":
                job.state = "adopted"
            elif outcome.status == "interrupted":
                try:
                    self._observe_staging_changes(job)
                except CockpitError:
                    outcome = BackendOperationResult(
                        outcome.operation,
                        outcome.run_id,
                        "failed",
                        failure_classification="unsafe_staging_path",
                        process=outcome.process,
                    )
                    self._outcomes[job.run_spec.run_id] = outcome
                    self._operation_history[job.run_spec.run_id][-1] = outcome
                    job.state = "report_and_stop"
                    job.report_reason = "unsafe_staging_path"
                    job.terminal_classification = "failed"
                    job.verification = GateReport(
                        (), "not_run", None, False, "",
                        "managed interruption left an unsafe staging diff",
                        False, False,
                    )
                else:
                    job.state = "interrupted"
                    assert job.verified_workspace_digest is not None
                    self._resume_bindings[job.run_spec.run_id] = (
                        job.changed_paths, job.verified_workspace_digest,
                    )
            else:
                try:
                    self._observe_staging_changes(job)
                except CockpitError:
                    job.changed_paths, job.diff_allowed = (), False
                    job.verified_workspace_digest = None
                    job.report_reason = "unsafe_staging_path"
                job.state = "report_and_stop"
                if job.report_reason != "unsafe_staging_path":
                    job.report_reason = {
                        "cancelled": "runtime_cancelled",
                        "timed_out": "runtime_timeout",
                        "unsupported": "runtime_capability_unsupported",
                    }.get(
                        outcome.status,
                        outcome.failure_classification or "runtime_failed",
                    )
                job.terminal_classification = {
                    "cancelled": "cancelled",
                    "timed_out": "timed_out",
                }.get(outcome.status, "failed")
                job.verification = GateReport(
                    (),
                    "not_run",
                    None,
                    outcome.status == "timed_out",
                    "",
                    "managed execution did not reach verification",
                    False,
                    False,
                )
        return outcome

    def _operate(self, run_id: str, operation: str) -> BackendOperationResult:
        job = self._jobs.get(run_id)
        required_state = "prepared" if operation == "start" else "interrupted"
        if (
            job is None
            or job.state != required_state
            or job.preflight is None
            or job.preflight.status != "passed"
        ):
            raise CockpitStateError(
                f"managed {operation} requires state {required_state} after passed preflight"
            )
        try:
            self._snapshot(job)
            if operation == "start" and _git_status(job.staging_root):
                raise CockpitError("staging workspace drifted before managed start")
        except CockpitError:
            return self._record_outcome(
                job,
                BackendOperationResult(
                    operation,
                    run_id,
                    "failed",
                    failure_classification=f"snapshot_drift_before_{operation}",
                ),
            )
        if operation == "resume":
            expected = self._resume_bindings.get(run_id)
            try:
                self._observe_staging_changes(job)
                current = (job.changed_paths, job.verified_workspace_digest)
            except CockpitError:
                current = None
            if expected is None or expected != current:
                outcome = BackendOperationResult(
                    "resume",
                    run_id,
                    "failed",
                    failure_classification="snapshot_drift_before_resume",
                )
                return self._record_outcome(job, outcome)
        with self._operation_lock:
            job.state = "managed_running"
        try:
            with tempfile.TemporaryDirectory(
                prefix=".stateport-managed-", dir=job.staging_root
            ) as temporary:
                runtime_root = Path(temporary)
                environment = self._environment(job, runtime_root)
                if operation == "start":
                    outcome = self.backend.start(
                        job.run_spec,
                        job.staging_root,
                        environment=environment,
                        event_sink=lambda event: self._event_sink(job, event),
                    )
                else:
                    outcome = self.backend.resume(
                        job.run_spec,
                        job.staging_root,
                        environment=environment,
                        event_sink=lambda event: self._event_sink(job, event),
                    )
        except Exception:
            outcome = BackendOperationResult(
                operation,
                run_id,
                "failed",
                failure_classification="backend_contract_or_journal_failure",
            )
        return self._record_outcome(job, outcome)

    def start(self, run_id: str) -> BackendOperationResult:
        return self._operate(run_id, "start")

    def resume(self, run_id: str) -> BackendOperationResult:
        return self._operate(run_id, "resume")

    def cancel(self, run_id: str) -> BackendOperationResult:
        job = self._jobs.get(run_id)
        if job is None:
            raise CockpitStateError("managed cancellation requires a prepared run")
        outcome = self.backend.cancel(run_id)
        with self._operation_lock:
            self._operation_history.setdefault(run_id, []).append(outcome)
            self._event(
                job,
                "command.started",
                "managed cancellation requested",
                operation="cancel",
                status=outcome.status,
            )
            if job.state == "interrupted":
                explicit = BackendOperationResult(
                    "cancel",
                    run_id,
                    "cancelled",
                    failure_classification="explicit_cancel_before_resume",
                )
                return self._record_outcome(job, explicit)
        return outcome

    @staticmethod
    def _sandbox_observation() -> dict[str, Any]:
        return {
            "executionBoundary": "staging_copy_only",
            "containerEnforced": False,
            "networkIsolation": "unproven",
            "canonicalAccessIsolation": "unproven",
            "homeIsolation": "isolated_ephemeral_staging_home",
            "environmentPolicy": "credential_free_allowlist",
        }

    @staticmethod
    def _termination_classification(outcome: BackendOperationResult) -> str:
        """Classify process termination independently of the logical outcome."""

        process = outcome.process
        if outcome.status == "timed_out" or (
            process is not None and process.get("timedOut") is True
        ):
            return "timeout"
        if outcome.status == "cancelled" or (
            process is not None and process.get("cancelled") is True
        ):
            return "cancelled"
        if outcome.failure_classification == "output_limit" or (
            process is not None and process.get("outputLimited") is True
        ):
            return "output_limit"
        if process is None:
            return "launch_failure"
        returncode = process.get("returncode")
        if type(returncode) is int and returncode != 0:
            return "worker_nonzero_exit"
        if outcome.failure_classification == "missing_or_mismatched_structured_outcome":
            return "result_artifact_missing"
        if outcome.failure_classification == "malformed_structured_output":
            return "result_artifact_invalid"
        return "success"

    def _run_result(
        self, job: PreparedCockpitJob, outcome: BackendOperationResult
    ) -> dict[str, Any]:
        verification = (
            "not_run"
            if job.verification is None or job.verification.status == "not_run"
            else ("passed" if job.verification.status == "passed" else "failed")
        )
        status = (
            outcome.status
            if outcome.status
            in {"completed", "failed", "cancelled", "timed_out", "interrupted"}
            else "failed"
        )
        failure = outcome.failure_classification or (
            job.report_reason if status != "completed" else None
        )
        result = {
            "formatVersion": "stateport.run-result/v1",
            "runId": job.run_spec.run_id,
            "runSpecDigest": job.run_spec.digest,
            "backend": {
                "id": job.run_spec.backend_id,
                "adapter": {
                    "id": job.run_spec.adapter_id,
                    "version": job.run_spec.adapter_version,
                },
            },
            "model": job.run_spec.model_identifier,
            "authenticationRouteClass": job.run_spec.authentication_route_class,
            "statePack": {
                "reference": job.run_spec.statepack_reference,
                "digest": job.run_spec.statepack_digest,
            },
            "toolPolicy": {
                "permittedCapabilities": list(job.run_spec.permitted_capabilities)
            },
            "sandbox": {
                "profile": job.run_spec.sandbox_profile,
                **self._sandbox_observation(),
            },
            "executionStatus": status,
            "verificationStatus": verification,
            "timestamps": {"startedAt": "unavailable", "finishedAt": "unavailable"},
            "failureClassification": failure,
            "terminationClassification": self._termination_classification(outcome),
            "usage": {
                "token": {"quality": "unavailable", "value": None},
                "cost": {"quality": "unavailable", "value": None},
            },
            "changedFiles": list(job.changed_paths),
            "validationOutcomes": [
                {"id": "declared-verification", "status": verification}
            ],
            "producedArtifacts": [],
            "approvalReference": None,
            "auditReferences": [job.run_spec.run_id],
            "warnings": [
                "deterministic fake backend; no provider or model execution",
                "host staging copy does not prove container or network isolation",
            ],
            "degradations": [
                {"id": "container_isolation", "status": "unproven"},
                {"id": "network_isolation", "status": "unproven"},
            ],
        }
        return validate_run_result(result, job.run_spec)

    def _attempt_chain(
        self, job: PreparedCockpitJob, *, success: bool,
        terminal_classification: str,
    ) -> list[dict[str, Any]]:
        terminal = {"completed", "failed", "cancelled", "interrupted", "timed_out"}
        history = [
            item for item in self._operation_history.get(job.run_spec.run_id, [])
            if item.status in terminal
        ]
        if not history:
            history = [BackendOperationResult(
                "start", job.run_spec.run_id,
                "completed" if success else terminal_classification,
                failure_classification=None if success else (job.report_reason or "managed_failure"),
            )]
        chain: list[dict[str, Any]] = []
        for ordinal, item in enumerate(history, start=1):
            classification = item.status if item.status in terminal else "failed"
            if ordinal == len(history) and not success:
                classification = terminal_classification
            chain.append({
                "attemptId": _attempt_id(job.run_spec.run_id) + f".{ordinal}",
                "ordinal": ordinal,
                "operation": "execution_" + item.operation,
                "classification": classification,
                "result": "passed" if classification == "completed" else "failed",
                "automatic": False,
                "evidence": ["cockpit/" + job.run_spec.run_id],
            })
        return chain

    def _write_bundle(
        self,
        job: PreparedCockpitJob,
        outcome: BackendOperationResult,
        run_result: Mapping[str, Any],
    ) -> dict[str, Any]:
        attempt_id = _attempt_id(job.run_spec.run_id)
        journal = list(self.evidence_store.journal(attempt_id))
        if self.bundle_directory.is_symlink() or not self.bundle_directory.is_dir():
            raise CockpitError("managed RunBundle path became unsafe before closure")
        destination = self.bundle_directory / (
            "managed-" + sha256(job.run_spec.run_id.encode("utf-8")).hexdigest()
        )
        verification = job.verification
        return RunBundleWriter(destination).write(
            manifest={
                "runId": job.run_spec.run_id,
                "mode": "managed",
                "backend": "managed-fake",
                "testOnly": True,
                "baseSha": job.task.to_dict()["baseSha"],
            },
            artifacts={
                "execution/agent-run-spec.json": job.run_spec.to_dict(),
                "execution/capability-negotiation.json": require_accepted(
                    job.run_spec, self.backend.capabilities()
                ),
                "execution/managed-operation.json": outcome.to_dict(),
                "execution/managed-operations.json": [
                    item.to_dict()
                    for item in self._operation_history.get(job.run_spec.run_id, [])
                ],
                "execution/events.jsonl": "".join(
                    json.dumps(event, sort_keys=True) + "\n" for event in journal
                ),
                "execution/run-result.json": dict(run_result),
                "execution/sandbox.json": self._sandbox_observation(),
                "identities/state-before.json": {
                    "baseGit": job.task.to_dict()["baseSha"],
                    "instanceDigest": job.task.to_dict()["instance"]["digest"],
                },
                "validation/preflight.json": {
                    "status": job.preflight.status if job.preflight else "not_run",
                    "timedOut": job.preflight.timed_out if job.preflight else False,
                },
                "validation/verification.json": {
                    "status": verification.status if verification else "not_run",
                    "timedOut": verification.timed_out if verification else False,
                    "changedPaths": list(job.changed_paths),
                    "allowed": job.diff_allowed,
                },
            },
        )

    def close_managed(self, run_id: str) -> RunReceipt:
        job = self._jobs.get(run_id)
        if job is None:
            raise CockpitStateError("managed closure requires a prepared run")
        outcome = self._outcomes.get(run_id)
        if (
            outcome is None
            and job.report_and_stop
            and job.report_reason in {"preflight_failed", "preflight_mutation"}
        ):
            outcome = BackendOperationResult(
                "start",
                run_id,
                "not_running",
                failure_classification=job.report_reason,
            )
            self._outcomes[run_id] = outcome
        if outcome is None:
            raise CockpitStateError(
                "managed closure requires an explicit backend outcome"
            )
        if job.state == "interrupted":
            raise CockpitStateError(
                "interrupted managed work requires explicit resume or cancel"
            )
        try:
            run_result = self._run_result(job, outcome)
            bundle = self._write_bundle(job, outcome, run_result)
            result_id = (
                "managed-result."
                + sha256(job.run_spec.digest.encode("ascii")).hexdigest()
            )
            receipt = super().close(
                run_id,
                run_result=run_result,
                run_result_id=result_id,
                run_bundle=bundle,
            )
            if run_id not in self._recovering_runs:
                self.evidence_store.finish_managed_recovery_context(
                    run_id=run_id, state="closed",
                )
            return receipt
        except Exception:
            # A managed caller cannot repair an immutable failed closure in
            # place. Never strand its exclusive writer lease.
            job.lease.release()
            raise

    def close(
        self,
        run_id: str,
        *,
        run_result: Mapping[str, Any],
        run_result_id: str,
        run_bundle: Mapping[str, Any],
    ) -> RunReceipt:
        del run_id, run_result, run_result_id, run_bundle
        raise CockpitStateError(
            "managed closure must use close_managed and its backend-observed result"
        )


__all__ = [
    "DeterministicFakeBackend",
    "FakeBackendScenario",
    "ManagedCockpit",
]
