"""Grant-gated orchestration of one real managed agent run.

``RunEngine`` wires the authority, the execution-host client, the lease-bound
shutdown, and the evidence service into a single, fail-closed run path:

    typed grant -> begin lease -> digest-pinned ephemeral agent container
    (lowered through the execution-host client) -> daemon-observed evidence
    -> shutdown

There is no caller-supplied adapter in the run path: one validated complete
``AgentRunSpecification`` is lowered into one ephemeral container, and the
image, exit, cancellation, and output are observed at the daemon/OS boundary.
A run never launches unless the spec binds a live, non-revoked owner
``RunGrant``.  The client's independently provisioned daemon grant continues
to authorize each execution-host socket request.
While the container executes, a lease monitor watches the authority: if the
grant is revoked mid-run (or the lease lapses) the daemon workload is
cancelled, so the run completes ``cancelled``, never ``succeeded``.  The
final ``RunEvidence`` binds the observed container identity (workload id,
observed image digest, exit code, duration, output digest) and never a
secret, socket, or handle.  Missing observation ends the run ``failed``
with an explicit reason; nothing substitutes an "unobserved" success digest.
A finish whose grant was revoked is certified ``refused`` (never a success).

Shutdown and cancellation are idempotent; a double release or a release after a
revocation is never an error.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import threading
import time
from dataclasses import dataclass
from typing import Any, Mapping

from runtime_contracts import RunEvidence, RunLease

from .agent_run_lifecycle import (
    AgentRunLifecycle,
    RunRefused,
    RunTicket,
)
from . import daemon_contract
from .client import ExecutionHostClient, ExecutionHostRefusal, ExecutionHostTransportError
from .provider_bindings import (
    ProcessIdentity,
    ProviderBindError,
    ProviderBindingManager,
    RunEvidenceService,
)
from .run_authority import RunAuthority
from .run_lease import RunCompletionGate, RunLeaseError


class RunEngineError(RuntimeError):
    """The engine refused to start, run, or finalize a managed run."""


ALLOWED_OUTCOMES = frozenset({"completed", "failed", "cancelled", "refused"})
_TERMINAL_WORKLOAD_STATES = frozenset(
    {"exited", "timed_out", "cancelled", "failed", "interrupted", "removed"}
)


@dataclass(frozen=True)
class RunOutcome:
    """The certified result of one real managed run."""

    evidence: RunEvidence
    outcome: str
    refused: bool
    cancelled: bool


class RunEngine:
    """Grant-gated driver for a single real managed run."""

    def __init__(
        self,
        *,
        authority: RunAuthority,
        evidence_service: RunEvidenceService,
        completion_gate: RunCompletionGate,
        provider_manager: ProviderBindingManager | None = None,
        state_dir: str = "/tmp/stateport-runengine",
        lease_duration_seconds: int = 900,
        monitor_poll_delay: float = 0.02,
    ) -> None:
        if type(authority) is not RunAuthority:
            raise RunEngineError("engine requires a typed RunAuthority")
        if type(evidence_service) is not RunEvidenceService:
            raise RunEngineError("engine requires a concrete RunEvidenceService")
        if type(completion_gate) is not RunCompletionGate:
            raise RunEngineError("engine requires a concrete RunCompletionGate")
        if provider_manager is not None and type(provider_manager) is not ProviderBindingManager:
            raise RunEngineError("engine requires a concrete ProviderBindingManager")
        self._authority = authority
        self._lifecycle = AgentRunLifecycle(
            authority,
            state_dir=state_dir,
            lease_duration_seconds=lease_duration_seconds,
        )
        self._evidence_service = evidence_service
        self._gate = completion_gate
        self._provider = provider_manager if provider_manager is not None else ProviderBindingManager()
        if (
            isinstance(monitor_poll_delay, bool)
            or not isinstance(monitor_poll_delay, (int, float))
            or monitor_poll_delay <= 0
        ):
            raise RunEngineError("monitor_poll_delay must be positive")
        self._monitor_delay = monitor_poll_delay

    @property
    def authority(self) -> RunAuthority:
        return self._authority

    @property
    def lifecycle(self) -> AgentRunLifecycle:
        return self._lifecycle

    def define_provider(
        self,
        config_id: str,
        *,
        provider: str,
        model: str,
        token_env: str,
        process_identity: ProcessIdentity | None = None,
    ) -> str:
        return self._provider.define_config(
            config_id, provider=provider, model=model, token_env=token_env, process_identity=process_identity
        )

    @staticmethod
    def _stamp(moment: datetime) -> str:
        moment = moment.astimezone(timezone.utc)
        return moment.isoformat(timespec="microseconds").replace("+00:00", "Z")

    def _withdrawal_reason(self, ticket: RunTicket) -> str | None:
        try:
            self._lifecycle.assert_live(ticket)
        except RunRefused as exc:
            return "lease-expired" if "lease_expired" in str(exc) else "revoked"
        except Exception:
            return "revoked"
        return None

    @staticmethod
    def _receipt_state(receipt: Mapping[str, Any]) -> str | None:
        result = receipt.get("result")
        if not isinstance(result, Mapping):
            return None
        state = result.get("state")
        return state if isinstance(state, str) else None

    def _monitor(
        self,
        client: ExecutionHostClient,
        workload_id: str,
        ticket: RunTicket,
        activation_lock: threading.Lock,
        ready: threading.Event,
        stop: threading.Event,
        cancelled: dict[str, str],
    ) -> None:
        """Observe withdrawal and retry cancellation until daemon-terminal."""
        while not stop.is_set():
            with activation_lock:
                reason = cancelled.get("reason") or self._withdrawal_reason(ticket)
                if reason is not None:
                    cancelled.setdefault("reason", reason)
                ready.set()
            if reason is None:
                stop.wait(self._monitor_delay)
                continue
            try:
                receipt = client.cancel(workload_id)
                state = self._receipt_state(receipt)
            except Exception:
                try:
                    state = self._receipt_state(client.status(workload_id))
                except Exception:
                    state = None
            if state in _TERMINAL_WORKLOAD_STATES:
                return
            stop.wait(self._monitor_delay)

    def _cleanup_workload(
        self,
        client: ExecutionHostClient,
        workload_id: str,
        *,
        cancellation_required: bool,
    ) -> None:
        """Force removal, retrying cancellation when a workload may still run."""
        while True:
            if cancellation_required:
                try:
                    state = self._receipt_state(client.cancel(workload_id))
                    if state in _TERMINAL_WORKLOAD_STATES:
                        cancellation_required = False
                except ExecutionHostRefusal as exc:
                    if exc.reason == "unknown-workload":
                        return
                except Exception:
                    pass
            try:
                client.remove_workload(workload_id)
                return
            except ExecutionHostRefusal as exc:
                if exc.reason == "unknown-workload":
                    return
            except Exception:
                pass
            time.sleep(self._monitor_delay)

    @staticmethod
    def _validated_lowering(workload: Mapping[str, Any]) -> None:
        """Require the daemon contract to retain every requested resource."""
        try:
            normalized = daemon_contract.validate_workload_spec(workload)
        except ValueError as exc:
            raise RunEngineError(f"lowered agent-run workload is invalid: {exc}") from exc
        if normalized.get("resources") != workload.get("resources"):
            raise RunEngineError(
                "lowered agent-run workload did not retain every requested resource ceiling"
            )

    def run(
        self,
        *,
        specification: Mapping[str, Any],
        client: ExecutionHostClient,
        claimed_image: str,
        host: str,
        config_id: str,
        output_byte_bound: int = 4 * 1024 * 1024,
        clock: datetime | None = None,
        status_poll_seconds: float = 0.05,
    ) -> RunOutcome:
        """Run one validated AgentRunSpecification as a daemon-observed container.

        There is no caller-supplied adapter anywhere in this path: the
        complete validated spec is lowered through the execution-host client
        into one digest-pinned ephemeral agent container, and the pid,
        image, exit, cancellation, and output are observed at the daemon/OS
        boundary.  Missing observation never becomes a success-capable
        digest — an unobserved run ends ``failed`` with an explicit reason.
        """
        from runtime_contracts.alpha4 import AgentRunSpecification  # noqa: PLC0415
        from runtime_contracts import canonical_digest  # noqa: PLC0415

        try:
            spec = AgentRunSpecification.from_dict(dict(specification))
        except ValueError as exc:
            raise RunEngineError(f"agent run specification is invalid: {exc}") from exc
        spec_data = spec.to_dict()
        run_id = spec_data["runId"]
        workspace_id = spec_data["workspaceId"]
        image_digest = spec_data["imageDigest"]
        if not claimed_image.endswith("@" + image_digest):
            raise RunEngineError(
                "claimed image reference does not resolve to the specification image digest"
            )
        if (
            isinstance(status_poll_seconds, bool)
            or not isinstance(status_poll_seconds, (int, float))
            or status_poll_seconds <= 0
        ):
            raise RunEngineError("status_poll_seconds must be positive")
        if type(client) is not ExecutionHostClient:
            raise RunEngineError("run requires the concrete typed ExecutionHostClient boundary")
        if host != self._authority.host:
            raise RunEngineError("run host does not match the owner authority host")
        try:
            provider_config = self._provider.config(config_id)
        except ProviderBindError as exc:
            raise RunEngineError(str(exc)) from exc
        if (spec_data["provider"], spec_data["model"]) != (
            provider_config.provider,
            provider_config.model,
        ):
            raise RunEngineError(
                "agent run provider/model does not match the owner provider configuration"
            )
        if spec_data["networkProfile"]["mode"] == "model-gateway-only":
            raise RunEngineError(
                "requested provider route cannot execute: no configured model gateway is exposed to the workload"
            )
        executor_kind = "execution-host-agent-container"
        budgets = spec_data["budgets"]
        timeout_seconds = max(1, min(int(budgets.get("timeSeconds", 0)) or 900, 86400))

        resources = spec_data["resources"]
        workload = {
            "kind": "agent-run",
            "workloadId": f"run-{run_id}",
            "image": {"reference": claimed_image},
            "parameters": {
                "runSpecDigest": canonical_digest(spec_data),
                "statePackReference": spec_data["stagingPath"],
                "baseRevision": spec_data["baseRevision"],
            },
            "timeoutSeconds": timeout_seconds,
            "outputByteBound": output_byte_bound,
            "resources": dict(resources),
        }
        self._validated_lowering(workload)
        workload_id = str(workload["workloadId"])

        try:
            ticket = self._lifecycle.begin_run(
                {
                    "runId": run_id,
                    "workspaceId": workspace_id,
                    "imageDigest": image_digest,
                    "authorityGrantDigest": spec_data["authorityGrantDigest"],
                },
                executor_kind=executor_kind,
                claimed_image=claimed_image,
                host=host,
                clock=clock,
            )
        except RunRefused as exc:
            raise RunEngineError(str(exc)) from exc
        started_at = ticket.started_at
        started_monotonic = time.monotonic()
        cancelled: dict[str, str] = {}
        stop = threading.Event()
        ready = threading.Event()
        activation_lock = threading.Lock()
        monitor: threading.Thread | None = None
        state = "unknown"
        exit_status: int | None = None
        observed_image: str | None = None
        output_text = ""
        observation: str | None = None
        create_cleanup_required = False
        workload_created = False
        try:
            def create_workload() -> Mapping[str, Any]:
                nonlocal create_cleanup_required
                try:
                    receipt = client.create_workload(workload)
                except ExecutionHostRefusal:
                    raise
                except ExecutionHostTransportError as exc:
                    detail = str(exc)
                    create_cleanup_required = not detail.startswith(
                        ("socket-absent:", "socket-refused:")
                    )
                    raise
                except Exception:
                    create_cleanup_required = True
                    raise
                create_cleanup_required = True
                return receipt

            self._lifecycle.perform_if_live(ticket, effect=create_workload)
            workload_created = True
            monitor = threading.Thread(
                target=self._monitor,
                args=(
                    client,
                    workload_id,
                    ticket,
                    activation_lock,
                    ready,
                    stop,
                    cancelled,
                ),
                daemon=True,
            )
            monitor.start()
            if not ready.wait(timeout=2):
                raise RunEngineError("run authority monitor did not become ready")
            with activation_lock:
                reason = cancelled.get("reason") or self._withdrawal_reason(ticket)
                if reason is not None:
                    cancelled.setdefault("reason", reason)
                    raise RunRefused(f"run activation refused: {reason}")

                self._lifecycle.perform_if_live(
                    ticket,
                    effect=lambda: client.start(workload_id),
                )
            deadline = started_monotonic + timeout_seconds
            while True:
                receipt = client.status(workload_id)
                state = str(receipt["result"]["state"])
                observed_image = receipt.get("observed", {}).get("imageDigest") or observed_image
                if state in _TERMINAL_WORKLOAD_STATES:
                    exit_status = receipt["result"].get("exitStatus")
                    break
                if time.monotonic() > deadline:
                    with activation_lock:
                        cancelled.setdefault("reason", "timed_out")
                stop.wait(status_poll_seconds)
            logs = client.logs(workload_id)
            output_text = str(logs["result"]["output"])
        except Exception as exc:
            observation = f"observation-incomplete:{type(exc).__name__}"
        finally:
            cancellation_required = bool(cancelled) or state not in _TERMINAL_WORKLOAD_STATES
            if create_cleanup_required:
                self._cleanup_workload(
                    client,
                    workload_id,
                    cancellation_required=cancellation_required,
                )
            stop.set()
            if monitor is not None:
                monitor.join(timeout=2)
        ended_at = self._stamp(datetime.now(timezone.utc))
        duration = int(time.monotonic() - started_monotonic)
        output_digest = "sha256:" + hashlib.sha256(output_text.encode("utf-8")).hexdigest()

        lease_id = ticket.lease.to_dict()["leaseId"]
        try:
            revoked = self._authority.is_revoked(ticket.grant_id)
        except Exception:
            # Fail closed: an unverifiable authority is treated as revoked.
            revoked = True

        # A mid-run revocation cancels the workload, so the run ends cancelled,
        # never a success.  A finish that runs to completion while its grant is
        # revoked is a revoked/refused finish.  A timeout or a missing
        # observation is an honest failure, never a substituted success.
        if cancelled.get("reason") == "revoked" or (revoked and state == "cancelled"):
            self._gate.certify_cancelled(lease_id)
            outcome = "cancelled"
        elif revoked:
            outcome = "refused"
        elif (
            observation is not None
            or cancelled.get("reason") in {"timed_out", "lease-expired"}
            or state != "exited"
        ):
            outcome = "failed"
        else:
            outcome = "completed" if exit_status == 0 else "failed"
        if outcome == "completed" and observed_image != image_digest:
            outcome = "failed"
            observation = (
                "observed-image-missing"
                if observed_image is None
                else "observed-image-identity-mismatch"
            )
        if outcome == "completed" and not self._evidence_service.provider_used(run_id, config_id):
            outcome = "refused"
            observation = "provider-effect-unobserved"

        real_process = {
            "executor": executor_kind,
            "pid": None,
            "containerWorkloadId": workload_id,
            "exitCode": exit_status if exit_status is not None else -1,
            "durationSeconds": duration,
            "digestOfOutput": output_digest,
        }
        if observed_image == image_digest:
            real_process["observedImageDigest"] = observed_image

        try:
            if cancelled.get("reason") == "revoked" or revoked:
                self._lifecycle.revoke_run(ticket)
            elif cancelled:
                self._lifecycle.cancel(ticket)
            else:
                self._lifecycle.release(ticket)
        except Exception:
            outcome = "refused"
            observation = "lease-release-failed"
        try:
            terminal_lease = RunLease.from_dict(json.loads(Path(ticket.claim_path).read_text(encoding="utf-8")))
        except (OSError, ValueError):
            outcome = "refused"
            terminal_lease = ticket.lease
        try:
            self._gate.complete(terminal_lease, outcome=outcome)
        except RunLeaseError:
            outcome = "refused"
        else:
            outcome = self._gate.finished_outcome(lease_id) or outcome

        if outcome == "completed":
            exit_reason = "ok"
        elif observation is not None:
            exit_reason = observation
        elif cancelled.get("reason") is not None:
            exit_reason = cancelled["reason"]
        else:
            exit_reason = outcome

        evidence = self._evidence_service.finish_evidence(
            run_id=run_id,
            workspace_id=workspace_id,
            executor_kind=executor_kind,
            image_digest=image_digest,
            lease_id=lease_id,
            started_at=started_at,
            ended_at=ended_at,
            outcome=outcome,
            exit_reason=exit_reason,
            digest_of_output=output_digest,
            config_id=config_id,
            grant_revoked=revoked and outcome != "cancelled",
            provider_use_required=True,
            executed_process=real_process if workload_created else None,
        )
        evidence_data = evidence.to_dict()
        refused = evidence_data["outcome"] == "refused"
        cancelled_outcome = evidence_data["outcome"] == "cancelled"
        return RunOutcome(evidence=evidence, outcome=evidence_data["outcome"], refused=refused, cancelled=cancelled_outcome)


__all__ = ["RunEngine", "RunEngineError", "RunOutcome"]
