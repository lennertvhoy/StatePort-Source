"""Fail-closed shared cockpit lifecycle.

This is deliberately a coordination layer, not another runner.  An external,
human-controlled agent works only in the caller supplied staging repository;
this module records the immutable handoff, runs the two declared argv gates,
and closes through the existing evidence and lease boundaries.  It never
starts a provider session, examines authentication material, or copies files
into the canonical instance.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import os
from pathlib import Path
import re
import subprocess
from types import MappingProxyType
from typing import Any, Callable, Mapping, Sequence

from execution_host.contracts import AgentRunSpec, validate_run_result
from external_engine_runtime import (
    ProcessIdentity,
    ProcessRuntimeError,
    ProcessSpec,
    run_process,
)
from run_bundle import RunBundleError, verify_bundle
from runtime_contracts import (
    AgentProfile,
    ContextManifest,
    RunReceipt,
    RuntimeProfile,
    TaskManifest,
    WorkflowDeclaration,
    canonical_digest,
)

from .evidence import OperationalEvidenceStore
from .lease import InstanceLease


MAX_GATE_OUTPUT_BYTES = 64 * 1024
MAX_CHANGED_PATHS = 1024
MAX_FINGERPRINT_BYTES = 64 * 1024 * 1024
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_CREDENTIAL_ENV = re.compile(
    r"(?:api[_-]?key|authorization|cookie|credential|password|secret|token|private[_-]?key)",
    re.IGNORECASE,
)


class CockpitError(ValueError):
    """The bounded cockpit cannot safely continue."""


class CockpitStateError(CockpitError):
    """A lifecycle operation was requested out of order."""


@dataclass(frozen=True)
class AssistedHandoff:
    """Bounded portable handoff for a human-controlled external agent.

    This is deliberately an identity-only record.  It contains the exact
    prepared contracts and no host session, conversation, prompt, credential,
    authentication material, credential location, or absolute workspace path.
    """

    run_id: str
    workflow: WorkflowDeclaration
    task_manifest: TaskManifest
    context_manifest: ContextManifest
    agent_profile: AgentProfile
    agent_run_spec: AgentRunSpec
    runtime_profile: RuntimeProfile
    external_agent: Mapping[str, str]

    FORMAT = "stateport.assisted-handoff/v1"

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, str) or not _IDENTIFIER.fullmatch(self.run_id):
            raise CockpitError("assisted handoff has an invalid identity")
        object.__setattr__(
            self,
            "external_agent",
            MappingProxyType(_external_agent_identity(self.external_agent)),
        )

    @property
    def digest(self) -> str:
        return canonical_digest(self._payload())

    def _payload(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "runId": self.run_id,
            "workflowDeclaration": self.workflow.to_dict(),
            "workflowDeclarationDigest": self.workflow.digest,
            "taskManifest": self.task_manifest.to_dict(),
            "taskManifestDigest": self.task_manifest.digest,
            "contextManifest": self.context_manifest.to_dict(),
            "contextManifestDigest": self.context_manifest.digest,
            "agentProfile": self.agent_profile.to_dict(),
            "agentProfileDigest": self.agent_profile.digest,
            "agentRunSpec": self.agent_run_spec.to_dict(),
            "agentRunSpecDigest": self.agent_run_spec.digest,
            "runtimeProfile": self.runtime_profile.to_dict(),
            "runtimeProfileDigest": self.runtime_profile.digest,
            "externalAgent": dict(self.external_agent),
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "digest": self.digest}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AssistedHandoff":
        required = {
            "formatVersion", "runId", "workflowDeclaration", "workflowDeclarationDigest",
            "taskManifest", "taskManifestDigest", "contextManifest", "contextManifestDigest",
            "agentProfile", "agentProfileDigest", "agentRunSpec", "agentRunSpecDigest",
            "runtimeProfile", "runtimeProfileDigest", "externalAgent", "digest",
        }
        if not isinstance(value, Mapping) or set(value) != required:
            raise CockpitError("assisted handoff contains unknown, hidden, or missing fields")
        if value["formatVersion"] != cls.FORMAT or not isinstance(value["runId"], str) or not _IDENTIFIER.fullmatch(value["runId"]):
            raise CockpitError("assisted handoff has an invalid identity")
        try:
            workflow = WorkflowDeclaration.from_dict(value["workflowDeclaration"])
            task = TaskManifest.from_dict(value["taskManifest"])
            context = ContextManifest.from_dict(value["contextManifest"])
            agent = AgentProfile.from_dict(value["agentProfile"])
            spec = AgentRunSpec.from_dict(value["agentRunSpec"])
            runtime = RuntimeProfile.from_dict(value["runtimeProfile"])
        except (TypeError, ValueError) as exc:
            raise CockpitError(f"assisted handoff has invalid prepared contracts: {exc}") from exc
        external_agent = _external_agent_identity(value["externalAgent"])
        handoff = cls(
            value["runId"], workflow, task, context, agent, spec, runtime,
            external_agent,
        )
        if (
            value["workflowDeclarationDigest"] != workflow.digest
            or value["taskManifestDigest"] != task.digest
            or value["contextManifestDigest"] != context.digest
            or value["agentProfileDigest"] != agent.digest
            or value["agentRunSpecDigest"] != spec.digest
            or value["runtimeProfileDigest"] != runtime.digest
            or value["digest"] != handoff.digest
        ):
            raise CockpitError("assisted handoff digest does not bind its exact contracts")
        return handoff


@dataclass(frozen=True)
class GateReport:
    argv: tuple[str, ...]
    status: str
    returncode: int | None
    timed_out: bool
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool


@dataclass(frozen=True)
class PendingProposalReference:
    """A pointer to the existing proposal/apply boundary, never a file patch."""

    run_id: str
    base_sha: str
    changed_paths: tuple[str, ...]
    apply_boundary: str = "stateport.portable_execution.approve_proposal/apply_proposal"

    def to_dict(self) -> dict[str, Any]:
        return {"runId": self.run_id, "baseSha": self.base_sha, "changedPaths": list(self.changed_paths),
                "status": "pending_governed_proposal", "applyBoundary": self.apply_boundary}


@dataclass
class PreparedCockpitJob:
    """In-memory lifecycle state; durable evidence remains in its own store."""

    workflow: WorkflowDeclaration
    task: TaskManifest
    runtime: RuntimeProfile
    context: ContextManifest
    agent: AgentProfile
    run_spec: AgentRunSpec
    instance_root: Path
    staging_root: Path
    lease: InstanceLease
    state: str = "prepared"
    preflight: GateReport | None = None
    verification: GateReport | None = None
    changed_paths: tuple[str, ...] = ()
    diff_allowed: bool = False
    report_reason: str | None = None
    pending_proposal: PendingProposalReference | None = None
    adopted_digest: str | None = None
    assisted_handoff: AssistedHandoff | None = None
    external_agent: Mapping[str, str] | None = None
    verified_workspace_digest: str | None = None
    event_sequence: int = 0
    terminal_classification: str | None = None
    first_attempt_status: str | None = None

    @property
    def report_and_stop(self) -> bool:
        return self.state == "report_and_stop"


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _safe_relative(path: str) -> str:
    if (not isinstance(path, str) or not path or "\\" in path
            or any(ord(character) < 32 for character in path)):
        raise CockpitError("allowed paths must be normalized relative POSIX paths")
    candidate = Path(path)
    if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        raise CockpitError("allowed paths must be normalized relative POSIX paths")
    return candidate.as_posix()


def _inside(root: Path, candidate: Path) -> Path:
    try:
        resolved = candidate.resolve(strict=False)
        resolved.relative_to(root.resolve(strict=True))
    except (OSError, RuntimeError, ValueError) as exc:
        raise CockpitError("path escapes the supplied staging workspace") from exc
    return resolved


def _git(root: Path, *argv: str) -> str:
    completed = subprocess.run(
        ("git", *argv), cwd=root, shell=False, check=False,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, timeout=10, env={"PATH": os.environ.get("PATH", os.defpath), "LC_ALL": "C"},
    )
    if completed.returncode != 0:
        raise CockpitError("required Git snapshot observation failed")
    return completed.stdout.strip()


def _git_sha(root: Path) -> str:
    value = _git(root, "rev-parse", "HEAD")
    if len(value) != 40 or any(char not in "0123456789abcdef" for char in value):
        raise CockpitError("Git snapshot is not an immutable SHA")
    return value


def _git_bytes(root: Path, *argv: str) -> bytes:
    completed = subprocess.run(
        ("git", *argv), cwd=root, shell=False, check=False,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=10, env={"PATH": os.environ.get("PATH", os.defpath), "LC_ALL": "C"},
    )
    if completed.returncode != 0:
        raise CockpitError("required Git workspace observation failed")
    return completed.stdout


def _git_status(root: Path) -> bytes:
    return _git_bytes(root, "status", "--porcelain=v1", "-z", "--untracked-files=all")


def _changed_paths(root: Path, base_sha: str) -> tuple[str, ...]:
    encoded = (
        _git_bytes(root, "diff", "--name-only", "--no-renames", "-z", base_sha)
        + _git_bytes(root, "ls-files", "--others", "--exclude-standard", "-z")
    )
    try:
        paths = {item.decode("utf-8") for item in encoded.split(b"\0") if item}
    except UnicodeDecodeError as exc:
        raise CockpitError("staging paths must be valid UTF-8") from exc
    if len(paths) > MAX_CHANGED_PATHS:
        raise CockpitError("staging diff exceeds the changed-path bound")
    return tuple(sorted(paths))


def _workspace_digest(root: Path, base_sha: str, paths: Sequence[str]) -> str:
    digest = sha256()
    digest.update(_git_sha(root).encode("ascii"))
    digest.update(b"\0")
    digest.update(_git_status(root))
    total = 0
    for value in paths:
        relative = _safe_relative(value)
        target = _inside(root, root / relative)
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        if target.is_symlink():
            raise CockpitError("symlink changes are forbidden in a staging workspace")
        if not target.exists():
            digest.update(b"deleted\0")
            continue
        if not target.is_file():
            raise CockpitError("staging changes must be regular files")
        mode = target.stat(follow_symlinks=False).st_mode & 0o7777
        digest.update(f"{mode:o}".encode("ascii"))
        digest.update(b"\0")
        with target.open("rb") as handle:
            while block := handle.read(64 * 1024):
                total += len(block)
                if total > MAX_FINGERPRINT_BYTES:
                    raise CockpitError("staging diff exceeds the fingerprint byte bound")
                digest.update(block)
        digest.update(b"\0")
    return "sha256:" + digest.hexdigest()


def _bounded_identity(value: Mapping[str, Any], *, name: str) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != {"id", "digest"}:
        raise CockpitError(f"{name} identity observation must contain id and digest")
    identifier, digest = value["id"], value["digest"]
    if not isinstance(identifier, str) or not identifier or len(identifier) > 128:
        raise CockpitError(f"{name} identity observation has an invalid id")
    if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
        raise CockpitError(f"{name} identity observation has an invalid digest")
    return {"id": identifier, "digest": digest}


def _external_agent_identity(value: Mapping[str, Any]) -> dict[str, str]:
    """Accept only a human-controlled agent label, never host/session data."""
    if not isinstance(value, Mapping) or set(value) != {"id", "classification"}:
        raise CockpitError("external agent identity may contain only id and classification")
    identifier, classification = value["id"], value["classification"]
    if not isinstance(identifier, str) or not _IDENTIFIER.fullmatch(identifier):
        raise CockpitError("external agent identity has an invalid id")
    if classification != "human_controlled":
        raise CockpitError("external agent classification must be human_controlled")
    return {"id": identifier, "classification": classification}


def _attempt_id(run_id: str) -> str:
    return "attempt." + sha256(run_id.encode("utf-8")).hexdigest()


def _event_id(run_id: str, sequence: int) -> str:
    return f"event.{sha256(run_id.encode('utf-8')).hexdigest()}.{sequence}"


def _run_gate(
    argv: Sequence[str], cwd: Path, timeout_seconds: int, allowlist: Sequence[str],
    *,
    on_started: Callable[[ProcessIdentity], None] | None = None,
    on_finished: Callable[[ProcessIdentity], None] | None = None,
) -> GateReport:
    """Run one declared argv gate through the shared bounded process runtime.

    Managed callers supply durable observers.  The runtime then holds the
    requested command behind its exec gate until exact process identity has
    committed, and refuses to report completion until group absence has been
    durably recorded.
    """

    environment = {name: os.environ[name] for name in allowlist if name in os.environ}
    registered = False

    def started(identity: ProcessIdentity) -> None:
        nonlocal registered
        if on_started is not None:
            on_started(identity)
            registered = True

    try:
        result = run_process(
            ProcessSpec(
                tuple(argv), cwd, timeout_seconds=float(timeout_seconds),
                max_output_bytes=MAX_GATE_OUTPUT_BYTES, environment=environment,
                on_started=started if on_started is not None else None,
                on_finished=on_finished,
            )
        )
    except ProcessRuntimeError as exc:
        if registered:
            raise CockpitError(
                "gate process supervision could not prove durable cleanup"
            ) from exc
        return GateReport(
            tuple(argv), "failed", None, False, "", str(exc)[:4096],
            False, False,
        )
    status = (
        "passed"
        if result.returncode == 0
        and not result.timed_out
        and not result.cancelled
        and not result.output_limited
        else "failed"
    )
    return GateReport(
        tuple(argv), status, result.returncode, result.timed_out,
        result.stdout, result.stderr, result.output_limited, result.output_limited,
    )


class CockpitCoordinator:
    """One fail-closed lifecycle shared by every cockpit execution mode."""

    def __init__(self, evidence_store: OperationalEvidenceStore, lease_directory: str | Path, *,
                 mode: str, owner: str) -> None:
        if mode not in {"agent_native", "assisted", "managed"}:
            raise CockpitError("cockpit mode is unsupported")
        self.evidence_store = evidence_store
        self.lease_directory = Path(lease_directory)
        self.mode = mode
        self.owner = owner
        self._jobs: dict[str, PreparedCockpitJob] = {}

    def _create_attempt(self, job: PreparedCockpitJob) -> None:
        """Create the semantic attempt before any declared command executes."""

        self.evidence_store.create_attempt(
            parent_job_id=job.task.to_dict()["jobId"],
            attempt_id=_attempt_id(job.run_spec.run_id),
            run_id=job.run_spec.run_id,
        )

    def _gate_observers(
        self, job: PreparedCockpitJob, phase: str,
    ) -> tuple[
        Callable[[ProcessIdentity], None] | None,
        Callable[[ProcessIdentity], None] | None,
    ]:
        """Return durable process observers when the execution mode owns them."""

        del job, phase
        return None, None

    @staticmethod
    def _cross_check(mode: str, workflow: WorkflowDeclaration, task: TaskManifest, runtime: RuntimeProfile,
                     context: ContextManifest, agent: AgentProfile, run_spec: AgentRunSpec) -> None:
        workflow_data, task_data = workflow.to_dict(), task.to_dict()
        runtime_data, context_data, agent_data = runtime.to_dict(), context.to_dict(), agent.to_dict()
        if task_data["requestedMode"] != runtime_data["mode"] or runtime_data["mode"] != mode:
            raise CockpitError(f"mode identity is not {mode} across the prepared contracts")
        if mode not in workflow_data["execution"]["supportedModes"]:
            raise CockpitError(f"workflow does not permit {mode} execution")
        if workflow_data["task"]["kind"] != agent_data["task"]["kind"]:
            raise CockpitError("workflow and agent task kinds do not match")
        if run_spec.objective != workflow_data["task"]["kind"]:
            raise CockpitError("RunSpec objective does not match the workflow task kind")
        if task_data["instance"]["id"] != run_spec.instance_id:
            raise CockpitError("RunSpec instance identity does not match TaskManifest")
        if task_data["baseSha"] != run_spec.source_revision:
            raise CockpitError("RunSpec source revision does not match the exact task base SHA")
        if run_spec.statepack_reference != "context:" + context_data["contextId"] or run_spec.statepack_digest != context.digest:
            raise CockpitError("RunSpec context identity does not match ContextManifest")
        if tuple(workflow_data["preflight"]["command"]) != tuple(task_data["preflight"]["command"]):
            raise CockpitError("workflow and task preflight argv differ")
        if tuple(workflow_data["verify"]["command"]) != tuple(task_data["verification"]["command"]):
            raise CockpitError("workflow and task verification argv differ")
        if tuple(task_data["verification"]["command"]) != run_spec.validation_commands:
            raise CockpitError("RunSpec validation argv does not match the declared verification gate")
        if (
            (run_spec.adapter_id, run_spec.adapter_version)
            != (runtime_data["adapter"]["id"], runtime_data["adapter"]["version"])
            or run_spec.model_identifier != runtime_data["provider"]["model"]
            or run_spec.authentication_route_class != runtime_data["authentication"]["classification"]
            or run_spec.sandbox_profile != runtime_data["sandbox"]["profile"]
            or run_spec.budgets != runtime_data["budgets"]
            or run_spec.benchmark_configuration.get("mode") != runtime_data["mode"]
        ):
            raise CockpitError("RunSpec runtime identity does not match RuntimeProfile")
        output_paths = tuple(item["path"] for item in task_data["outputs"])
        if output_paths != run_spec.required_output_artifacts:
            raise CockpitError("RunSpec required artifacts do not match TaskManifest outputs")
        requested = set(agent_data["permissions"]["requested"])
        allowed_tools = set(runtime_data["toolContract"]["allowed"])
        denied_tools = set(runtime_data["toolContract"]["denied"]) | set(agent_data["permissions"]["prohibited"])
        if requested != set(run_spec.permitted_capabilities) or not requested.issubset(allowed_tools) or requested & denied_tools:
            raise CockpitError("requested permissions do not match the effective capability policy")
        required = {item.name for item in run_spec.required_capabilities}
        if required != set(runtime_data["capabilityRequirements"]):
            raise CockpitError("RunSpec capability requirements do not match RuntimeProfile")
        requests = {item.name: item for item in run_spec.required_capabilities}
        for capability, status in runtime_data["capabilityRequirements"].items():
            if status not in {"native", "supported"} and not (
                status == "partial" and requests[capability].allow_partial
            ):
                raise CockpitError("required capability is unavailable or not accepted as partial")
        if any(_CREDENTIAL_ENV.search(name) for name in runtime_data["environmentAllowlist"]):
            raise CockpitError("credential-like environment variables may not enter cockpit gates")
        allowed_paths = tuple(_safe_relative(item) for item in task_data["allowedPaths"])
        ownership = {_safe_relative(path): owner for path, owner in task_data["ownership"].items()}
        if set(ownership) != set(allowed_paths) or any(not owner for owner in ownership.values()):
            raise CockpitError("ownership scope is outside the allowed paths")
        requirements = set(task_data["execution"]["requirements"])
        if not {"leased_worktree", "base_sha_bound", "staging_only"}.issubset(requirements):
            raise CockpitError("task execution requirements omit a mandatory cockpit boundary")

    @staticmethod
    def _snapshot(job: PreparedCockpitJob) -> None:
        expected = job.task.to_dict()["baseSha"]
        if _git_sha(job.instance_root) != expected or _git_sha(job.staging_root) != expected:
            raise CockpitError("base Git SHA drift detected")
        if _git_status(job.instance_root):
            raise CockpitError("canonical instance changed while its writer lease was held")

    @staticmethod
    def _observe_staging_changes(job: PreparedCockpitJob) -> None:
        """Bind the exact bounded staging diff without following symlinks."""

        changed = _changed_paths(job.staging_root, job.task.to_dict()["baseSha"])
        allowed = set(job.task.to_dict()["allowedPaths"])
        normalized: list[str] = []
        for item in changed:
            relative = _safe_relative(item)
            candidate = job.staging_root / relative
            _inside(job.staging_root, candidate)
            if candidate.is_symlink():
                raise CockpitError("symlink changes are forbidden in a staging workspace")
            normalized.append(relative)
        job.changed_paths = tuple(normalized)
        job.diff_allowed = set(job.changed_paths).issubset(allowed)
        job.verified_workspace_digest = _workspace_digest(
            job.staging_root, job.task.to_dict()["baseSha"], job.changed_paths,
        )

    def _event(self, job: PreparedCockpitJob, event_type: str, summary: str, *,
               adapter_metadata: Mapping[str, Any] | None = None, **attributes: Any) -> None:
        event = {
            "formatVersion": "stateport.agent-event/v1", "eventId": _event_id(job.run_spec.run_id, job.event_sequence),
            "jobId": job.task.to_dict()["jobId"], "attemptId": _attempt_id(job.run_spec.run_id), "runId": job.run_spec.run_id,
            "producer": {"id": "stateport.cockpit", "kind": "lifecycle", "version": "1"},
            "sequence": job.event_sequence, "eventType": event_type, "timestamp": _utc_now(),
            "payload": {"summary": summary, "attributes": attributes},
            "redactionResult": {"status": "not_needed", "categories": []}, "observationQuality": "observed",
        }
        self.evidence_store.append_event(event, adapter_metadata=adapter_metadata)
        job.event_sequence += 1

    def prepare(self, workflow: WorkflowDeclaration, task: TaskManifest, runtime: RuntimeProfile,
                context: ContextManifest, agent: AgentProfile, run_spec: AgentRunSpec, *,
                instance_root: str | Path, staging_root: str | Path,
                repository_identity: Mapping[str, Any],
                instance_identity: Mapping[str, Any]) -> PreparedCockpitJob:
        self._cross_check(self.mode, workflow, task, runtime, context, agent, run_spec)
        if run_spec.run_id in self._jobs:
            raise CockpitStateError("duplicate prepared RunSpec identity")
        canonical = Path(instance_root).resolve(strict=True)
        staging = Path(staging_root).resolve(strict=True)
        if canonical == staging or not canonical.is_dir() or not staging.is_dir():
            raise CockpitError("a distinct caller-supplied staging workspace is required")
        try:
            staging.relative_to(canonical)
        except ValueError:
            pass
        else:
            raise CockpitError("staging workspace may not be nested inside the canonical instance")
        try:
            canonical.relative_to(staging)
        except ValueError:
            pass
        else:
            raise CockpitError("canonical instance may not be nested inside the staging workspace")
        task_data = task.to_dict()
        if _bounded_identity(repository_identity, name="repository") != task_data["repository"]:
            raise CockpitError("observed repository identity does not match TaskManifest")
        if _bounded_identity(instance_identity, name="instance") != task_data["instance"]:
            raise CockpitError("observed instance identity does not match TaskManifest")
        lease = InstanceLease(self.lease_directory, canonical, owner=self.owner).acquire()
        job = PreparedCockpitJob(workflow, task, runtime, context, agent, run_spec, canonical, staging, lease)
        attempt_id = _attempt_id(run_spec.run_id)
        try:
            self._snapshot(job)
            if _git_status(canonical) or _git_status(staging):
                raise CockpitError("prepared canonical and staging repositories must be clean")
            self._create_attempt(job)
            self._event(job, "run.started", f"prepared exact {self.mode} identity")
            command = task.to_dict()["preflight"]
            started, finished = self._gate_observers(job, "preflight")
            report = _run_gate(
                command["command"], staging, command["timeoutSeconds"],
                runtime.to_dict()["environmentAllowlist"],
                on_started=started, on_finished=finished,
            )
            job.preflight = report
            preflight_mutated = bool(_git_status(staging))
            self._event(job, "command.completed", "preflight gate completed", status=report.status,
                        timedOut=report.timed_out, workspaceMutated=preflight_mutated)
            if preflight_mutated:
                job.state, job.report_reason = "report_and_stop", "preflight_mutation"
            elif report.status != "passed":
                job.state, job.report_reason = "report_and_stop", "preflight_failed"
            self._jobs[run_spec.run_id] = job
            return job
        except Exception:
            lease.release()
            raise

    def adopt(self, run_id: str, adopted_run_spec: AgentRunSpec) -> PreparedCockpitJob:
        job = self._jobs.get(run_id)
        if job is None or job.state != "prepared" or job.preflight is None or job.preflight.status != "passed":
            raise CockpitStateError("only a successful prepared job may be adopted")
        if adopted_run_spec.digest != job.run_spec.digest or adopted_run_spec.run_id != run_id:
            raise CockpitError("external agent did not adopt the exact prepared RunSpec")
        try:
            self._snapshot(job)
            if _git_status(job.staging_root):
                raise CockpitError("staging workspace drifted before adoption")
        except CockpitError:
            job.state, job.report_reason = "report_and_stop", "base_sha_drift"
            job.verification = GateReport((), "not_run", None, False, "", "adoption rejected after snapshot drift", False, False)
            self._event(job, "command.completed", "external adoption rejected", status="failed", reason="base_sha_drift")
            return job
        job.adopted_digest, job.state = adopted_run_spec.digest, "adopted"
        self._event(job, "session.created", "external agent adopted exact prepared identity", runSpecDigest=adopted_run_spec.digest)
        return job

    def verify(self, run_id: str) -> PreparedCockpitJob:
        job = self._jobs.get(run_id)
        if job is None or job.state != "adopted":
            raise CockpitStateError("verification requires an adopted job")
        try:
            self._snapshot(job)
        except CockpitError:
            job.state, job.report_reason = "report_and_stop", "base_sha_drift"
            job.verification = GateReport((), "not_run", None, False, "", "verification rejected after snapshot drift", False, False)
            self._event(job, "command.completed", "verification gate not run", status="failed", reason="base_sha_drift")
            return job
        command = job.task.to_dict()["verification"]
        started, finished = self._gate_observers(job, "verification")
        report = _run_gate(
            command["command"], job.staging_root, command["timeoutSeconds"],
            job.runtime.to_dict()["environmentAllowlist"],
            on_started=started, on_finished=finished,
        )
        job.verification = report
        try:
            self._observe_staging_changes(job)
        except CockpitError:
            job.changed_paths, job.diff_allowed, job.verified_workspace_digest = (), False, None
            job.state, job.report_reason = "report_and_stop", "unsafe_staging_path"
        self._event(job, "command.completed", "verification gate completed", status=report.status, timedOut=report.timed_out, changedPathCount=len(job.changed_paths), pathsAllowed=job.diff_allowed)
        if report.status != "passed":
            job.state, job.report_reason = "report_and_stop", "verification_failed"
        elif job.state == "report_and_stop":
            pass
        elif not job.diff_allowed:
            job.state, job.report_reason = "report_and_stop", "forbidden_diff"
        elif job.changed_paths:
            job.state, job.report_reason = "report_and_stop", "pending_governed_proposal"
            job.pending_proposal = PendingProposalReference(
                job.run_spec.run_id, job.task.to_dict()["baseSha"], job.changed_paths,
            )
        else:
            job.state = "verified"
        return job

    @staticmethod
    def _bundle_reference(value: Mapping[str, Any], *, run_id: str) -> dict[str, str]:
        if not isinstance(value, Mapping) or not isinstance(value.get("path"), str):
            raise CockpitError("runBundle must reference an existing bundle path")
        try:
            verified = verify_bundle(value["path"])
        except (OSError, ValueError, RunBundleError) as exc:
            raise CockpitError(f"runBundle verification failed: {exc}") from exc
        if (
            verified.get("runId") != run_id
            or value.get("runId") != run_id
            or verified.get("contentDigest") != value.get("contentDigest")
        ):
            raise CockpitError("runBundle identity or digest does not match the prepared run")
        return {"id": run_id, "digest": verified["contentDigest"]}

    def _receipt_runtime_identity(self, job: PreparedCockpitJob) -> dict[str, Any]:
        runtime = job.runtime.to_dict()
        if self.mode == "assisted":
            harness_classification = "assisted_recommended"
            adapter_classification = "human_controlled"
        elif self.mode == "managed":
            harness_classification = "managed_supervised"
            adapter_classification = "test_only_fake"
        else:
            harness_classification = "agent_native"
            adapter_classification = "external"
        return {
            "harness": {"id": runtime["harness"]["id"], "version": runtime["harness"]["version"], "classification": harness_classification},
            "adapter": {"id": runtime["adapter"]["id"], "version": runtime["adapter"]["version"], "classification": adapter_classification},
            "provider": {"id": runtime["provider"]["id"], "classification": "declared"},
            "model": {"id": runtime["provider"]["model"], "classification": "declared"},
            "authenticationRoute": {"classification": runtime["authentication"]["classification"], "ownerClassification": runtime["authentication"]["owner"]},
        }

    def _attempt_chain(
        self, job: PreparedCockpitJob, *, success: bool,
        terminal_classification: str,
    ) -> list[dict[str, Any]]:
        """Return explicit execution-attempt accounting for the shared receipt."""

        classification = "completed" if success else terminal_classification
        return [{
            "attemptId": _attempt_id(job.run_spec.run_id) + ".1",
            "ordinal": 1,
            "operation": "execution_start",
            "classification": classification,
            "result": "passed" if classification == "completed" else "failed",
            "automatic": False,
            "evidence": ["cockpit/" + job.run_spec.run_id],
        }]

    def close(self, run_id: str, *, run_result: Mapping[str, Any], run_result_id: str,
              run_bundle: Mapping[str, Any]) -> RunReceipt:
        job = self._jobs.get(run_id)
        preflight_failed = bool(
            job and job.preflight
            and (job.preflight.status != "passed" or job.report_reason == "preflight_mutation")
        )
        if job is None or job.state not in {"verified", "report_and_stop"} or (job.verification is None and not preflight_failed):
            raise CockpitStateError("closure requires a completed verification gate, unless preflight failed")
        if not isinstance(run_result_id, str) or not run_result_id:
            raise CockpitError("an existing RunResult identity is required")
        try:
            self._snapshot(job)
        except CockpitError:
            job.state, job.report_reason = "report_and_stop", "base_sha_drift"
        if job.verified_workspace_digest is not None:
            try:
                current_paths = _changed_paths(job.staging_root, job.task.to_dict()["baseSha"])
                current_digest = _workspace_digest(job.staging_root, job.task.to_dict()["baseSha"], current_paths)
                if current_paths != job.changed_paths or current_digest != job.verified_workspace_digest:
                    raise CockpitError("staging workspace drifted after verification")
            except CockpitError:
                job.state, job.report_reason = "report_and_stop", "snapshot_drift_after_verification"
        try:
            validated_result = validate_run_result(run_result, job.run_spec)
        except ValueError as exc:
            raise CockpitError(f"RunResult is not bound to the prepared RunSpec: {exc}") from exc
        if (
            validated_result["model"] != job.run_spec.model_identifier
            or validated_result["authenticationRouteClass"] != job.run_spec.authentication_route_class
            or validated_result["sandbox"]["profile"] != job.run_spec.sandbox_profile
            or tuple(validated_result["toolPolicy"]["permittedCapabilities"])
            != job.run_spec.permitted_capabilities
        ):
            raise CockpitError("RunResult runtime or tool identity does not match the prepared RunSpec")
        result_ref = {"id": run_result_id, "digest": canonical_digest(validated_result)}
        bundle_ref = self._bundle_reference(run_bundle, run_id=run_id)
        clean = not job.changed_paths
        verification_status = (
            "not_run" if job.verification is None or job.verification.status == "not_run"
            else ("passed" if job.verification.status == "passed" else "failed")
        )
        success = job.state == "verified" and clean and job.preflight and job.preflight.status == "passed" and verification_status == "passed"
        closure_status = "closed" if success else "failed"
        reason = "verified_no_canonical_mutation" if success else (job.report_reason or "dirty_worktree")
        journal = list(self.evidence_store.journal(_attempt_id(run_id)))
        attempt_id = _attempt_id(run_id)
        terminal_classification = job.terminal_classification or ("completed" if success else "failed")
        if terminal_classification not in {"completed", "failed", "cancelled", "interrupted", "timed_out"}:
            raise CockpitError("terminal classification is invalid")
        if (terminal_classification == "completed") != success:
            raise CockpitError("terminal classification contradicts cockpit closure")
        terminal_event_type = (
            "run.completed" if terminal_classification == "completed"
            else ("run.cancelled" if terminal_classification == "cancelled" else "run.failed")
        )
        terminal = {
            "formatVersion": "stateport.agent-event/v1", "eventId": _event_id(run_id, job.event_sequence),
            "jobId": job.task.to_dict()["jobId"], "attemptId": attempt_id, "runId": run_id,
            "producer": {"id": "stateport.cockpit", "kind": "lifecycle", "version": "1"},
            "sequence": job.event_sequence, "eventType": terminal_event_type, "timestamp": _utc_now(),
            "payload": {"summary": "cockpit closure" if success else "cockpit report and stop", "attributes": {"reason": reason}},
            "redactionResult": {"status": "not_needed", "categories": []}, "observationQuality": "observed",
        }
        final_events = journal + [terminal]
        event_digest = canonical_digest(final_events)
        outcome = lambda status: {"status": status, "evidence": ["cockpit/" + run_id]}
        requested = list(job.agent.to_dict()["permissions"]["requested"])
        usage = validated_result["usage"]
        token, cost = usage["token"], usage["cost"]
        availability = "unavailable" if token["quality"] == "unavailable" or cost["quality"] == "unavailable" else ("approximate" if "approximate" in {token["quality"], cost["quality"]} else "exact")
        attempt_chain = self._attempt_chain(
            job, success=bool(success), terminal_classification=terminal_classification,
        )
        receipt_data = {
            "formatVersion": "stateport.run-receipt/v1", "runId": run_id, "parentJobId": job.task.to_dict()["jobId"], "attemptId": attempt_id, "taskId": job.task.to_dict()["taskId"],
            "baseGit": job.task.to_dict()["baseSha"], "finalGit": _git_sha(job.staging_root), "mode": self.mode,
            "runtimeIdentity": self._receipt_runtime_identity(job),
            "capabilityNegotiation": {"requested": requested, "effective": requested, "unavailable": [], "acceptedDegradations": [], "observationQuality": "reported"},
            "digests": {"workflowDeclaration": job.workflow.digest, "taskManifest": job.task.digest, "runtimeProfile": job.runtime.digest, "contextManifest": job.context.digest, "agentProfile": job.agent.digest, "agentRunSpec": job.run_spec.digest, "eventJournal": event_digest},
            "references": {"runResult": result_ref, "runBundle": bundle_ref}, "preflight": outcome("passed" if job.preflight.status == "passed" and job.report_reason != "preflight_mutation" else "failed"), "journal": {"eventCount": len(final_events), "digest": event_digest}, "attemptChain": attempt_chain, "first": outcome(attempt_chain[0]["result"]), "eventual": outcome(attempt_chain[-1]["result"]), "verification": outcome(verification_status),
            "fileChanges": {"changedPaths": list(job.changed_paths), "allowed": job.diff_allowed, "digest": canonical_digest(list(job.changed_paths))}, "permissions": {"requested": requested, "effective": requested}, "approvals": {"required": bool(job.task.to_dict()["sideEffects"]), "references": []},
            "usage": {"availability": availability, "token": token["value"] if availability != "unavailable" else None, "costMinor": cost["value"] if availability != "unavailable" else None}, "sideEffects": [{"id": item["id"], "classification": item["classification"], "outcome": "not_attempted"} for item in job.task.to_dict()["sideEffects"]], "rollback": {"required": job.task.to_dict()["failure"]["rollbackRequired"], "status": "not_attempted" if job.task.to_dict()["failure"]["rollbackRequired"] else "not_required"}, "closure": {"status": closure_status, "reason": reason}, "evidence": ["operational-evidence/" + attempt_id],
        }
        receipt = RunReceipt.from_dict(receipt_data)
        self.evidence_store.append_event(terminal, classification=terminal_classification, receipt=receipt.to_dict())
        job.event_sequence += 1
        job.state = "closed" if success else "reported"
        job.lease.release()
        return receipt


class AgentNativeCockpit(CockpitCoordinator):
    """Agent-native entry point retained as the portable baseline."""

    def __init__(self, evidence_store: OperationalEvidenceStore, lease_directory: str | Path, *, owner: str = "agent-native") -> None:
        super().__init__(evidence_store, lease_directory, mode="agent_native", owner=owner)


class AssistedCockpit(CockpitCoordinator):
    """Thin human-handoff entry point over the common lifecycle coordinator."""

    def __init__(self, evidence_store: OperationalEvidenceStore, lease_directory: str | Path, *, owner: str = "assisted") -> None:
        super().__init__(evidence_store, lease_directory, mode="assisted", owner=owner)

    def prepare(self, workflow: WorkflowDeclaration, task: TaskManifest, runtime: RuntimeProfile,
                context: ContextManifest, agent: AgentProfile, run_spec: AgentRunSpec, *,
                instance_root: str | Path, staging_root: str | Path,
                repository_identity: Mapping[str, Any], instance_identity: Mapping[str, Any],
                external_agent: Mapping[str, Any]) -> PreparedCockpitJob:
        external = _external_agent_identity(external_agent)
        job = super().prepare(
            workflow, task, runtime, context, agent, run_spec,
            instance_root=instance_root, staging_root=staging_root,
            repository_identity=repository_identity, instance_identity=instance_identity,
        )
        if job.state != "prepared" or job.preflight is None or job.preflight.status != "passed":
            return job
        handoff = AssistedHandoff(
            run_spec.run_id, workflow, task, context, agent, run_spec, runtime,
            external,
        )
        job.assisted_handoff, job.external_agent = handoff, handoff.external_agent
        self._event(
            job, "session.created", "bounded assisted handoff prepared",
            handoffDigest=handoff.digest, externalAgentId=external["id"],
            externalAgentClassification=external["classification"],
        )
        return job

    def adopt(self, run_id: str, adopted_run_spec: AgentRunSpec, handoff: AssistedHandoff | Mapping[str, Any], *,
              external_agent: Mapping[str, Any]) -> PreparedCockpitJob:
        job = self._jobs.get(run_id)
        if job is None or job.assisted_handoff is None or job.external_agent is None:
            raise CockpitStateError("assisted adoption requires a prepared assisted handoff")
        supplied = handoff if isinstance(handoff, AssistedHandoff) else AssistedHandoff.from_dict(handoff)
        external = _external_agent_identity(external_agent)
        expected = job.assisted_handoff
        if (
            supplied.digest != expected.digest or supplied.run_id != run_id
            or supplied.workflow.digest != job.workflow.digest
            or supplied.task_manifest.digest != job.task.digest
            or supplied.context_manifest.digest != job.context.digest
            or supplied.agent_profile.digest != job.agent.digest
            or supplied.agent_run_spec.digest != job.run_spec.digest
            or supplied.runtime_profile.digest != job.runtime.digest
            or supplied.external_agent != job.external_agent or external != job.external_agent
        ):
            raise CockpitError("assisted adoption does not bind the exact prepared handoff and external agent")
        adopted = super().adopt(run_id, adopted_run_spec)
        self._event(
            adopted, "session.created", "human-controlled external agent adopted exact assisted handoff",
            handoffDigest=expected.digest, externalAgentId=external["id"],
            externalAgentClassification=external["classification"],
        )
        return adopted


__all__ = [
    "AgentNativeCockpit", "AssistedCockpit", "AssistedHandoff", "CockpitCoordinator",
    "CockpitError", "CockpitStateError", "GateReport", "PendingProposalReference", "PreparedCockpitJob",
]
