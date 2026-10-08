"""Approval-bound execution of durable StatePort container jobs."""

from __future__ import annotations

import hashlib
import json
import math
import shutil
import tempfile
import threading
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from approval_gate import ApprovalGate
from audit_log import AuditLog
from container_runner import (
    ExecutionPlan,
    ExecutorResult,
    is_immutable_image_reference,
)
from governed_runner import (
    CONTAINER_ECHO_COMMAND,
    CONTAINER_JOB_PAYLOAD_FORMAT,
    InstanceLease,
    InstanceLeaseBusy,
    JobQueue,
    RunLedger,
    StateSnapshot,
    diff_snapshots,
    digest_snapshot,
    restore_snapshot,
    snapshot_files,
)
from quota_engine import (
    ReservationConflictError,
    ReservationStateError,
    UsageLedger,
)
from statedd_core import MANIFEST_V2_FORMAT, load_template_manifest, parse_yaml_text


_MAX_RUNNER_OUTPUT_BYTES = 1_048_576


class Executor(Protocol):
    engine: str
    image: str
    timeout_seconds: int

    def execute(
        self,
        plan: ExecutionPlan,
        command: Sequence[str],
        *,
        approval_id: str | None = None,
    ) -> ExecutorResult: ...


class WorkerJobError(ValueError):
    """A queued job failed validation or safe execution."""


class _BoundWorkerJobError(WorkerJobError):
    """A legitimate run/job/approval/usage binding failed a current check."""

    def __init__(
        self,
        message: str,
        *,
        run: dict[str, Any],
        reservation_id: str,
        instance_id: str,
    ) -> None:
        super().__init__(message)
        self.run = run
        self.reservation_id = reservation_id
        self.instance_id = instance_id


class _LeaseOwnershipLost(WorkerJobError):
    """The worker can no longer prove ownership of the claimed queue job."""


class _ExecutionHeartbeat:
    """Keep one queue lease current while a bounded executor call is active."""

    def __init__(
        self,
        queue: JobQueue,
        job_id: str,
        lease_credential: str,
        lease_seconds: float,
    ) -> None:
        self.queue = queue
        self.job_id = job_id
        self.lease_credential = lease_credential
        self.lease_seconds = lease_seconds
        self.interval = max(1.0, min(10.0, lease_seconds / 3.0))
        self.stop_event = threading.Event()
        self.error: Exception | None = None
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self.queue.heartbeat(
            self.job_id,
            self.lease_credential,
            lease_seconds=self.lease_seconds,
        )
        self.thread.start()

    def _run(self) -> None:
        while not self.stop_event.wait(self.interval):
            try:
                self.queue.heartbeat(
                    self.job_id,
                    self.lease_credential,
                    lease_seconds=self.lease_seconds,
                )
            except Exception as exc:  # noqa: BLE001 - surfaced after execution
                self.error = exc
                self.stop_event.set()

    def stop(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=self.interval + 1.0)
        try:
            # A successful final heartbeat proves the lease is still ours even
            # if an earlier refresh hit a transient persistence error.
            self.queue.heartbeat(
                self.job_id,
                self.lease_credential,
                lease_seconds=self.lease_seconds,
            )
        except Exception as exc:  # noqa: BLE001 - normalize worker boundary
            raise _LeaseOwnershipLost("job lease heartbeat failed") from exc


def _canonical_digest(value: Mapping[str, Any]) -> str:
    try:
        encoded = json.dumps(
            dict(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise WorkerJobError("job plan is not canonical JSON") from exc
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _required_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise WorkerJobError(f"{field} must be a non-empty string")
    return value.strip()


class WorkerService:
    """Claim and execute one locally queued job at a time.

    Queue contents are not authority. Every claimed job is rebound to a
    persisted approved request, run record, strict execution plan, confined
    workspace paths, durable usage reservation, and kernel instance lease.
    """

    def __init__(
        self,
        workspace: Path | str,
        *,
        executor: Executor,
        worker_id: str,
        operator_allowed_capabilities: Sequence[str],
        lease_seconds: float | None = None,
    ) -> None:
        self.workspace = Path(workspace).resolve()
        if not self.workspace.is_dir() or self.workspace.is_symlink():
            raise ValueError("worker workspace must be a real directory")
        self.worker_id = _required_string(worker_id, "worker_id")
        if not isinstance(operator_allowed_capabilities, (list, tuple, set, frozenset)) or not all(
            isinstance(item, str) and item.strip()
            for item in operator_allowed_capabilities
        ):
            raise ValueError("operator_allowed_capabilities must be capability strings")
        self.operator_allowed_capabilities = frozenset(
            item.strip() for item in operator_allowed_capabilities
        )
        self.executor = executor
        minimum_lease = float(getattr(executor, "timeout_seconds", 300)) + 30.0
        self.lease_seconds = minimum_lease if lease_seconds is None else float(lease_seconds)
        if self.lease_seconds < minimum_lease:
            raise ValueError("job lease must exceed the executor timeout by at least 30 seconds")
        operational = self.workspace / ".stateport"
        if operational.exists() and (operational.is_symlink() or not operational.is_dir()):
            raise ValueError("worker operational path must be a real directory")
        self.operational = operational
        self.queue = JobQueue(operational / "jobs.sqlite3")
        self.usage = UsageLedger(operational / "usage.sqlite3")
        self.approval_path = operational / "approvals.json"
        self.runs = RunLedger(operational / "runs.json")
        self.audit = AuditLog(operational / "audit.jsonl")

    @staticmethod
    def _yaml_mapping(path: Path, field: str) -> dict[str, Any]:
        try:
            value = parse_yaml_text(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            raise WorkerJobError(f"{field} could not be read") from exc
        if not isinstance(value, dict):
            raise WorkerJobError(f"{field} must contain a mapping")
        return value

    @staticmethod
    def _capability_values(value: Any, field: str) -> list[str]:
        if not isinstance(value, (list, tuple, set, frozenset)) or not all(
            isinstance(item, str) and item.strip() for item in value
        ):
            raise WorkerJobError(f"{field} must contain capability strings")
        return sorted({item.strip() for item in value})

    def _current_execution_policy(
        self,
        template_path: Path,
        instance_path: Path,
        instance_id: str,
    ) -> None:
        manifest = load_template_manifest(template_path)
        instance = self._yaml_mapping(instance_path / "instance.yaml", "instance")
        instance_spec = instance.get("spec")
        metadata = instance.get("metadata")
        if not isinstance(instance_spec, Mapping):
            raise WorkerJobError("instance spec is required")
        if not isinstance(metadata, Mapping) or metadata.get("id") != instance_id:
            raise WorkerJobError("instance identity changed after enqueue")
        if manifest.get("formatVersion") == MANIFEST_V2_FORMAT:
            requested = [
                capability
                for module in manifest.get("modules", [])
                for capability in module.get("capabilities", [])
            ]
        else:
            template = self._yaml_mapping(template_path / "template.yaml", "template")
            template_spec = template.get("spec")
            if not isinstance(template_spec, Mapping):
                raise WorkerJobError("template spec is required")
            requested = template_spec.get(
                "requestedCapabilities", template_spec.get("capabilities")
            )
            if requested is None:
                actions = template_spec.get("allowedActions", ())
                if not isinstance(actions, list):
                    raise WorkerJobError("template allowedActions must be a list")
                requested = [
                    item.get("name")
                    for item in actions
                    if isinstance(item, Mapping)
                    and isinstance(item.get("name"), str)
                    and item.get("name").strip()
                ]
        granted = instance_spec.get(
            "grantedCapabilities",
            instance_spec.get("allowedCapabilities", ()),
        )
        decision = ApprovalGate().capability(
            "execute-run",
            "execute_container",
            self._capability_values(requested, "template capabilities"),
            self._capability_values(granted, "instance capabilities"),
            self.operator_allowed_capabilities,
        )
        if not decision.allowed:
            raise WorkerJobError("current capability intersection denies container execution")

    def _confined_path(self, value: str, field: str) -> Path:
        raw = Path(value)
        candidate = raw if raw.is_absolute() else self.workspace / raw
        try:
            relative = candidate.relative_to(self.workspace)
        except ValueError as exc:
            raise WorkerJobError(f"{field} must stay inside the worker workspace") from exc
        cursor = self.workspace
        for part in relative.parts:
            cursor = cursor / part
            if cursor.is_symlink():
                raise WorkerJobError(f"{field} may not traverse a symlink")
        resolved = candidate.resolve()
        if not resolved.is_relative_to(self.workspace):
            raise WorkerJobError(f"{field} must stay inside the worker workspace")
        return resolved

    @staticmethod
    def _validate_runner_result(result: ExecutorResult) -> dict[str, Any]:
        stdout = result.stdout.encode("utf-8")
        stderr = result.stderr.encode("utf-8")
        evidence: dict[str, Any] = {
            "returncode": result.returncode,
            "stdoutBytes": len(stdout),
            "stdoutSha256": "sha256:" + hashlib.sha256(stdout).hexdigest(),
            "stderrBytes": len(stderr),
            "stderrSha256": "sha256:" + hashlib.sha256(stderr).hexdigest(),
        }
        if len(stdout) > _MAX_RUNNER_OUTPUT_BYTES or len(stderr) > _MAX_RUNNER_OUTPUT_BYTES:
            raise WorkerJobError("runner output exceeded the 1 MiB evidence limit")
        try:
            payload = json.loads(result.stdout)
        except (json.JSONDecodeError, TypeError) as exc:
            raise WorkerJobError("runner output was not valid JSON") from exc
        if not isinstance(payload, Mapping):
            raise WorkerJobError("runner output must be a JSON object")
        if not isinstance(payload.get("ok"), bool):
            raise WorkerJobError("runner output ok must be a boolean")
        status = payload.get("status")
        logs = payload.get("logs")
        errors = payload.get("errors")
        if not isinstance(status, str):
            raise WorkerJobError("runner output status must be a string")
        if not isinstance(logs, list) or not all(isinstance(item, str) for item in logs):
            raise WorkerJobError("runner output logs must be strings")
        if not isinstance(errors, list) or not all(isinstance(item, str) for item in errors):
            raise WorkerJobError("runner output errors must be strings")
        evidence["runner"] = {
            "ok": payload["ok"],
            "status": status,
            "logs": logs,
            "errors": errors,
        }
        return evidence

    def _validate_binding(
        self, job: Mapping[str, Any]
    ) -> tuple[dict[str, Any], dict[str, Any], ExecutionPlan, tuple[str, ...]]:
        payload = job.get("payload")
        if not isinstance(payload, Mapping) or set(payload) != {
            "formatVersion",
            "jobType",
            "runId",
            "approvalId",
            "actor",
            "instanceId",
            "executionPlan",
            "executionPlanDigest",
            "templateDigest",
            "containerEngine",
            "runnerImage",
            "command",
            "usageReservationId",
        }:
            raise WorkerJobError("container job payload has an invalid shape")
        if payload.get("formatVersion") != CONTAINER_JOB_PAYLOAD_FORMAT:
            raise WorkerJobError("container job formatVersion is invalid")
        if payload.get("jobType") != "container_echo":
            raise WorkerJobError("container job type is not supported")
        run_id = _required_string(payload.get("runId"), "runId")
        approval_id = _required_string(payload.get("approvalId"), "approvalId")
        actor = _required_string(payload.get("actor"), "actor")
        instance_id = _required_string(payload.get("instanceId"), "instanceId")
        reservation_id = _required_string(
            payload.get("usageReservationId"), "usageReservationId"
        )
        job_id = _required_string(job.get("jobId"), "jobId")
        if job_id != f"job:{approval_id}" or reservation_id != f"usage:{job_id}":
            raise WorkerJobError("job and usage identities are not approval-bound")
        command_value = payload.get("command")
        if not isinstance(command_value, list) or not all(
            isinstance(item, str) and item for item in command_value
        ):
            raise WorkerJobError("container command must be a list of strings")
        command = tuple(command_value)
        if command != CONTAINER_ECHO_COMMAND:
            raise WorkerJobError("container job command is not the fixed echo runner")
        plan_value = payload.get("executionPlan")
        if not isinstance(plan_value, Mapping):
            raise WorkerJobError("executionPlan must be a mapping")
        plan_digest = _canonical_digest(plan_value)
        if payload.get("executionPlanDigest") != plan_digest:
            raise WorkerJobError("execution plan digest does not match the job")
        template_digest = _required_string(payload.get("templateDigest"), "templateDigest")
        container_engine = _required_string(
            payload.get("containerEngine"), "containerEngine"
        )
        runner_image = _required_string(payload.get("runnerImage"), "runnerImage")
        if container_engine not in {"docker", "podman"}:
            raise WorkerJobError("containerEngine is not supported")
        plan = ExecutionPlan.from_dict(plan_value)
        if plan.lease_id != run_id:
            raise WorkerJobError("execution plan lease is not bound to the run")

        run = self.runs.get(run_id)
        if run is None:
            raise WorkerJobError("bound run was not found")
        if run.get("actor") != actor or run.get("instanceId") != instance_id:
            raise WorkerJobError("job identity does not match the run")
        if run.get("mode") != "container_echo" or tuple(run.get("command", ())) != command:
            raise WorkerJobError("job mode or command does not match the run")
        if (
            run.get("containerEngine") != container_engine
            or run.get("runnerImage") != runner_image
        ):
            raise WorkerJobError("job executor configuration does not match the run")
        run_plan = run.get("executionPlan")
        if not isinstance(run_plan, Mapping) or _canonical_digest(run_plan) != plan_digest:
            raise WorkerJobError("job execution plan does not match the run")
        if run.get("jobId") != job.get("jobId"):
            raise WorkerJobError("run is not bound to the claimed job")

        approval = ApprovalGate(self.approval_path).get(approval_id)
        if approval is None:
            raise WorkerJobError("container execution approval was not found")
        if (
            approval.operation != "execute-run"
            or approval.capability != "execute_container"
            or approval.instance_id != instance_id
            or approval.actor != actor
            or approval.metadata.get("runId") != run_id
            or approval.metadata.get("executionPlanDigest") != plan_digest
            or approval.metadata.get("templateDigest") != template_digest
            or approval.metadata.get("containerEngine") != container_engine
            or approval.metadata.get("runnerImage") != runner_image
            or tuple(approval.metadata.get("command", ())) != command
        ):
            raise WorkerJobError("approval is not bound to the claimed job")
        reservation = self.usage.get(reservation_id)
        run_estimated_cost = run.get("estimatedCost")
        approval_estimated_cost = approval.metadata.get("estimatedCost", 0.0)
        if (
            isinstance(run_estimated_cost, bool)
            or not isinstance(run_estimated_cost, (int, float))
            or not math.isfinite(float(run_estimated_cost))
            or isinstance(approval_estimated_cost, bool)
            or not isinstance(approval_estimated_cost, (int, float))
            or not math.isfinite(float(approval_estimated_cost))
            or float(run_estimated_cost) != float(approval_estimated_cost)
        ):
            raise _BoundWorkerJobError(
                "usage estimate does not match the approved run",
                run=run,
                reservation_id=reservation_id,
                instance_id=instance_id,
            )
        if (
            reservation is None
            or reservation.status not in {"active", "committed"}
            or reservation.subject_id != instance_id
            or reservation.operation != "run"
            or reservation.estimated_cost != float(run_estimated_cost)
            or (
                reservation.status == "committed"
                and reservation.actual_cost != 0.0
            )
        ):
            raise _BoundWorkerJobError(
                "durable usage reservation is not valid for this job",
                run=run,
                reservation_id=reservation_id,
                instance_id=instance_id,
            )

        try:
            if approval.status != "approved":
                raise WorkerJobError("container execution approval is not approved")
            if (
                getattr(self.executor, "engine", None) != container_engine
                or getattr(self.executor, "image", None) != runner_image
                or not is_immutable_image_reference(runner_image)
            ):
                raise WorkerJobError(
                    "worker executor does not match the approved configuration"
                )
            template = self._confined_path(plan.template_path, "template path")
            instance = self._confined_path(plan.instance_path, "instance path")
            runtime = self._confined_path(plan.runtime_path, "runtime path")
            expected_runtime_root = (self.operational / "runtime").resolve()
            if runtime != expected_runtime_root / run_id:
                raise WorkerJobError(
                    "runtime path must be the run-specific .stateport/runtime path"
                )
            if not template.is_dir() or not instance.is_dir():
                raise WorkerJobError(
                    "template and instance paths must be existing directories"
                )
        except (OSError, ValueError, WorkerJobError) as exc:
            raise _BoundWorkerJobError(
                str(exc),
                run=run,
                reservation_id=reservation_id,
                instance_id=instance_id,
            ) from exc
        plan = ExecutionPlan(
            template.as_posix(),
            instance.as_posix(),
            runtime.as_posix(),
            plan.lease_id,
        )
        return dict(payload), run, plan, command

    def _execute(
        self,
        payload: Mapping[str, Any],
        plan: ExecutionPlan,
        command: tuple[str, ...],
        *,
        job_attempt: Any,
    ) -> tuple[bool, dict[str, Any]]:
        before: StateSnapshot
        instance_path = Path(plan.instance_path)
        template_path = Path(plan.template_path)
        staging_path: Path | None = None
        with InstanceLease(
            self.operational / "leases",
            instance_path,
            owner=self.worker_id,
        ):
            try:
                expected_template_digest = _required_string(
                    payload.get("templateDigest"), "templateDigest"
                )
                template_snapshot = snapshot_files(template_path)
                if digest_snapshot(template_snapshot) != expected_template_digest:
                    raise WorkerJobError(
                        "template contents changed after execution approval"
                    )
                instance_id = _required_string(payload.get("instanceId"), "instanceId")
                before = snapshot_files(instance_path)
                baseline_digest = digest_snapshot(before)
                current_run = self.runs.get(str(payload["runId"]))
                if current_run is None or current_run.get("status") not in {
                    "queued",
                    "running",
                }:
                    raise WorkerJobError("bound run is no longer executable")
                previous_baseline = current_run.get("instanceBaselineDigest")
                if (
                    current_run.get("status") == "running"
                    and previous_baseline is not None
                    and previous_baseline != baseline_digest
                ):
                    raise WorkerJobError(
                        "instance changed after an interrupted execution attempt"
                    )

                staging_root = self.operational / "staging"
                if staging_root.exists() and (
                    staging_root.is_symlink() or not staging_root.is_dir()
                ):
                    raise WorkerJobError("worker staging root must be a real directory")
                staging_root.mkdir(parents=True, exist_ok=True)
                if staging_root.is_symlink():
                    raise WorkerJobError("worker staging root may not be a symlink")
                prefix = "job-" + hashlib.sha256(
                    str(payload["runId"]).encode("utf-8")
                ).hexdigest()[:12] + "-"
                staging_path = Path(tempfile.mkdtemp(prefix=prefix, dir=staging_root))
                staged_template = staging_path / "template"
                staged_instance = staging_path / "instance"
                shutil.copytree(template_path, staged_template, symlinks=True)
                shutil.copytree(instance_path, staged_instance, symlinks=True)
                staged_template_snapshot = snapshot_files(staged_template)
                staged_instance_snapshot = snapshot_files(staged_instance)
                if (
                    digest_snapshot(staged_template_snapshot)
                    != expected_template_digest
                    or diff_snapshots(before, staged_instance_snapshot)["filesChanged"]
                ):
                    raise WorkerJobError(
                        "execution inputs changed while creating the isolated snapshot"
                    )
                self._current_execution_policy(
                    staged_template,
                    staged_instance,
                    instance_id,
                )

                self.runs.update(
                    str(payload["runId"]),
                    status="running",
                    workerId=self.worker_id,
                    jobAttempt=job_attempt,
                    instanceBaselineDigest=baseline_digest,
                )
                staged_plan = ExecutionPlan(
                    staged_template.as_posix(),
                    staged_instance.as_posix(),
                    plan.runtime_path,
                    plan.lease_id,
                )
                executor_error: str | None = None
                executor_result: ExecutorResult | None = None
                try:
                    executor_result = self.executor.execute(
                        staged_plan,
                        command,
                        approval_id=str(payload["approvalId"]),
                    )
                except Exception as exc:  # noqa: BLE001 - worker boundary
                    executor_error = str(exc)

                input_snapshot_error: str | None = None
                try:
                    staged_after = snapshot_files(staged_instance)
                    input_diff = diff_snapshots(staged_instance_snapshot, staged_after)
                except ValueError as exc:
                    input_snapshot_error = str(exc)
                    input_diff = {
                        "beforeDigest": digest_snapshot(staged_instance_snapshot),
                        "afterDigest": None,
                        "added": [],
                        "removed": [],
                        "modified": [],
                        "addedDirectories": [],
                        "removedDirectories": [],
                        "filesChanged": ["<unsafe-filesystem-entry>"],
                    }
                durable_snapshot_error: str | None = None
                try:
                    durable_after = snapshot_files(instance_path)
                    state_diff = diff_snapshots(before, durable_after)
                except ValueError as exc:
                    durable_snapshot_error = str(exc)
                    state_diff = {
                        "beforeDigest": baseline_digest,
                        "afterDigest": None,
                        "added": [],
                        "removed": [],
                        "modified": [],
                        "addedDirectories": [],
                        "removedDirectories": [],
                        "filesChanged": ["<unsafe-filesystem-entry>"],
                    }
                state_integrity = (
                    "preserved"
                    if not state_diff["filesChanged"]
                    else "concurrent_external_change_detected"
                )
                input_integrity = (
                    "preserved"
                    if not input_diff["filesChanged"]
                    else "isolated_input_modified"
                )
                files_changed = sorted(
                    set(state_diff["filesChanged"]) | set(input_diff["filesChanged"])
                )
                outcome: dict[str, Any] = {
                    "ok": False,
                    "stateIntegrity": state_integrity,
                    "executionInputIntegrity": input_integrity,
                    "stateDiff": state_diff,
                    "executionInputDiff": input_diff,
                    "restorationDiff": None,
                    "instanceBaselineDigest": baseline_digest,
                    "templateDigest": expected_template_digest,
                    "filesRead": sorted(before),
                    "filesChanged": files_changed,
                }
                if input_snapshot_error is not None:
                    outcome["executionInputSnapshotError"] = input_snapshot_error
                if durable_snapshot_error is not None:
                    outcome["snapshotError"] = durable_snapshot_error
                if executor_error is not None:
                    outcome["error"] = executor_error
                    return False, outcome
                assert executor_result is not None
                try:
                    outcome["executor"] = self._validate_runner_result(executor_result)
                except WorkerJobError as exc:
                    outcome["error"] = str(exc)
                    return False, outcome
                runner = outcome["executor"]["runner"]
                ok = (
                    executor_result.returncode == 0
                    and runner["ok"] is True
                    and not runner["errors"]
                    and state_integrity == "preserved"
                    and input_integrity == "preserved"
                )
                outcome["ok"] = ok
                return ok, outcome
            finally:
                if staging_path is not None:
                    shutil.rmtree(staging_path, ignore_errors=True)

    def _commit_usage(self, reservation_id: str) -> None:
        try:
            self.usage.commit(reservation_id, actual_cost=0.0)
        except (ReservationConflictError, ReservationStateError) as exc:
            # A released/denied reservation is a binding failure, never success.
            raise WorkerJobError("usage reservation could not be committed") from exc

    def _audit_terminal_once(
        self,
        *,
        event_type: str,
        job_id: str,
        run_id: str,
        instance_id: str,
        state_integrity: str,
    ) -> None:
        self.audit.append_once(
            event_type=event_type,
            actor=f"worker:{self.worker_id}",
            subject=instance_id,
            timestamp=self._utc_now(),
            data={
                "jobId": job_id,
                "runId": run_id,
                "stateIntegrity": state_integrity,
            },
            correlation_keys=("jobId", "runId"),
        )

    def run_once(self) -> dict[str, Any] | None:
        job = self.queue.claim(
            worker_id=self.worker_id,
            lease_seconds=self.lease_seconds,
        )
        if job is None:
            return None
        lease = job.get("lease")
        if not isinstance(lease, Mapping):
            raise WorkerJobError("claimed job did not contain a lease")
        lease_credential = _required_string(lease.get("token"), "job lease token")
        job_id = _required_string(job.get("jobId"), "jobId")
        run: dict[str, Any] | None = None
        reservation_id: str | None = None
        instance_id: str | None = None
        heartbeat = _ExecutionHeartbeat(
            self.queue,
            job_id,
            lease_credential,
            self.lease_seconds,
        )
        try:
            try:
                heartbeat.start()
            except Exception as exc:
                raise _LeaseOwnershipLost(
                    "job lease could not be refreshed after claim"
                ) from exc
            payload, bound_run, plan, command = self._validate_binding(job)
            run = bound_run
            reservation_id = str(payload["usageReservationId"])
            instance_id = str(payload["instanceId"])
            if run["status"] == "completed":
                heartbeat.stop()
                self._commit_usage(reservation_id)
                self._audit_terminal_once(
                    event_type="job.completed",
                    job_id=job_id,
                    run_id=str(run["runId"]),
                    instance_id=instance_id,
                    state_integrity=str(
                        (run.get("outcome") or {}).get("stateIntegrity", "unknown")
                    ),
                )
                return self.queue.complete(
                    job_id,
                    lease_credential,
                    result=run.get("outcome") or {"ok": True},
                )
            if run["status"] == "failed":
                heartbeat.stop()
                self._commit_usage(reservation_id)
                self._audit_terminal_once(
                    event_type="job.failed",
                    job_id=job_id,
                    run_id=str(run["runId"]),
                    instance_id=instance_id,
                    state_integrity=str(
                        (run.get("outcome") or {}).get("stateIntegrity", "unknown")
                    ),
                )
                return self.queue.fail(
                    job_id,
                    lease_credential,
                    error={"message": "bound run already failed"},
                )
            if run["status"] not in {"queued", "running"}:
                raise WorkerJobError("bound run is not queue-executable")
            try:
                ok, outcome = self._execute(
                    payload,
                    plan,
                    command,
                    job_attempt=job.get("attemptCount"),
                )
            except InstanceLeaseBusy:
                heartbeat.stop()
                return self.queue.requeue(
                    job_id,
                    lease_credential,
                    reason="instance writer lease is busy",
                )
            heartbeat.stop()
            final_status = "completed" if ok else "failed"
            updated_run = self.runs.update(
                str(payload["runId"]), status=final_status, outcome=outcome
            )
            self._commit_usage(reservation_id)
            self._audit_terminal_once(
                event_type="job.completed" if ok else "job.failed",
                job_id=job_id,
                run_id=str(payload["runId"]),
                instance_id=instance_id,
                state_integrity=str(outcome["stateIntegrity"]),
            )
            if ok:
                return self.queue.complete(
                    job_id,
                    lease_credential,
                    result=updated_run.get("outcome") or {"ok": True},
                )
            return self.queue.fail(
                job_id,
                lease_credential,
                error={"message": "container runner failed", "outcome": outcome},
            )
        except _LeaseOwnershipLost:
            # A stale worker must not mutate run, usage, approval, or audit
            # truth after it can no longer prove ownership of the queue lease.
            raise
        except Exception as exc:  # noqa: BLE001 - terminal fail-closed boundary
            try:
                heartbeat.stop()
            except _LeaseOwnershipLost:
                raise
            if isinstance(exc, _BoundWorkerJobError):
                run = exc.run
                reservation_id = exc.reservation_id
                instance_id = exc.instance_id
            message = str(exc) or type(exc).__name__
            persisted_run = (
                self.runs.get(str(run["runId"])) if run is not None else None
            )
            if persisted_run is not None and persisted_run.get("status") in {
                "completed",
                "failed",
            }:
                try:
                    self.queue.requeue(
                        job_id,
                        lease_credential,
                        reason="terminal run finalization is pending",
                    )
                except Exception:
                    pass
                raise WorkerJobError(
                    "terminal run finalization is pending retry"
                ) from exc
            if persisted_run is not None and persisted_run.get("status") in {
                "queued",
                "running",
            }:
                try:
                    persisted_run = self.runs.update(
                        str(persisted_run["runId"]),
                        status="failed",
                        outcome={
                            "ok": False,
                            "errors": [message],
                            "stateIntegrity": "unknown",
                        },
                    )
                except (KeyError, ValueError):
                    pass
            if reservation_id is not None:
                try:
                    self._commit_usage(reservation_id)
                except WorkerJobError:
                    pass
            if persisted_run is not None and instance_id is not None:
                self._audit_terminal_once(
                    event_type="job.failed",
                    job_id=job_id,
                    run_id=str(persisted_run["runId"]),
                    instance_id=instance_id,
                    state_integrity=str(
                        (persisted_run.get("outcome") or {}).get(
                            "stateIntegrity", "unknown"
                        )
                    ),
                )
            else:
                self.audit.append(
                    event_type="job.rejected",
                    actor=f"worker:{self.worker_id}",
                    subject="unbound",
                    timestamp=self._utc_now(),
                    data={"jobId": job_id, "reason": message},
                )
            try:
                return self.queue.fail(
                    job_id,
                    lease_credential,
                    error={"message": message},
                )
            except Exception:
                raise WorkerJobError(message) from exc

    @staticmethod
    def _utc_now() -> str:
        from datetime import datetime, timezone

        return (
            datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )


__all__ = [
    "CONTAINER_ECHO_COMMAND",
    "CONTAINER_JOB_PAYLOAD_FORMAT",
    "WorkerJobError",
    "WorkerService",
]
