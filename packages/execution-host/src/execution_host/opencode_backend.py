from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
import os
import signal
import subprocess
import sys
import threading
import time
from typing import Any, Mapping

from execution_host.runtime import (
    AgentBackend,
    BackendEvent,
    BackendHealth,
    BackendOperationResult,
)
from execution_host.contracts import AgentRunSpec, BackendCapabilities

_source_root = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(_source_root / "packages" / "opencode-adapter" / "src"))
sys.path.insert(0, str(_source_root / "packages" / "container-opencode" / "src"))

from opencode_adapter import OpenCodeAdapter, OpenCodeProbe, opencode_probe
from container_opencode import (
    ContainerOpenCodeEnforcer,
    EnforcerConfig,
    OpenCodeExecutionMode,
    EscapeTestResult,
    verify_container_enforcement,
)


_CTO_EVENT_TYPES = frozenset({
    "run_prepared",
    "container_started",
    "agent_started",
    "progress",
    "tool_activity",
    "file_changed",
    "verification_started",
    "verification_completed",
    "review_required",
    "run_cancelled",
    "run_failed",
    "run_completed",
    "cleanup_completed",
})


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _mode_to_execution_config(mode: str) -> OpenCodeExecutionMode:
    return {
        "faster": OpenCodeExecutionMode.FASTER,
        "balanced": OpenCodeExecutionMode.BALANCED,
        "deeper": OpenCodeExecutionMode.DEEPER,
    }.get(mode, OpenCodeExecutionMode.BALANCED)


def _mode_to_effective_policy(mode: OpenCodeExecutionMode) -> dict[str, Any]:
    return {
        "executionMode": mode.value,
        "timeoutSeconds": mode.timeout_seconds,
        "memoryLimit": mode.memory_limit,
        "cpuLimit": mode.cpu_limit,
        "pidsLimit": mode.pids_limit,
        "maxAttempts": mode.max_attempts,
        "networkPolicy": "none",
        "containerIsolation": "rootless_podman_read_only",
        "writableScope": "staging_only",
        "canonicalAccess": "denied",
    }


@dataclass
class OpenCodeContainerBackend:
    probe: OpenCodeProbe = field(default_factory=opencode_probe)
    _run_lock: threading.Lock = field(default_factory=threading.Lock)
    _active_enforcer: ContainerOpenCodeEnforcer | None = None
    _active_run_id: str | None = None
    _cancel_event: threading.Event = field(default_factory=threading.Event)
    _event_sink: Any = None

    def capabilities(self) -> BackendCapabilities:
        adapter = OpenCodeAdapter(probe=self.probe)
        existing = adapter.capabilities()
        return BackendCapabilities(
            backend_id="opencode",
            adapter_id=existing.adapter_id,
            adapter_version=existing.adapter_version,
            integration_tier="portable",
            capabilities=dict(existing.capabilities),
            authentication_route_classes=getattr(existing, "authentication_route_classes", ()),
            adapter_permissions=getattr(existing, "adapter_permissions", ()),
            test_only=False,
            # The agent itself is confined to a staging-only container, but a
            # separate isolated post-agent validator has not been integrated.
            # Agent-owned staging content must never be executed on the host.
            production_eligible=False,
        )

    def start(
        self,
        run_spec: AgentRunSpec,
        staging_root: Path,
        *,
        environment: Mapping[str, str],
        event_sink: Any,
    ) -> BackendOperationResult:
        with self._run_lock:
            if self._active_run_id is not None:
                return BackendOperationResult(
                    operation="start",
                    run_id=run_spec.run_id,
                    status="failed",
                    failure_classification="concurrent_run_denied",
                )
            self._active_run_id = run_spec.run_id
            self._cancel_event.clear()
            self._event_sink = event_sink

        run_id = run_spec.run_id
        events: list[BackendEvent] = []

        events.append(BackendEvent(
            event_type="run_prepared",
            summary="OpenCode container run prepared",
            attributes={"runId": run_id, "model": run_spec.model_identifier},
        ))

        staging_root.mkdir(parents=True, exist_ok=True)

        try:
            events.append(BackendEvent(
                event_type="container_started",
                summary="Rootless Podman container started",
                attributes={"mode": run_spec.sandbox_profile or "balanced"},
            ))
            if self._event_sink:
                self._event_sink(events[-1])
        except Exception:
            pass

        mode = _mode_to_execution_config(run_spec.sandbox_profile or "balanced")

        config = EnforcerConfig(
            staging_root=staging_root,
            opencode_bin_path=(
                Path(self.probe.executable)
                if self.probe.executable
                else Path.home() / ".opencode" / "bin" / "opencode"
            ),
            mode=mode,
            model=run_spec.model_identifier,
            network_enabled=False,
            allow_home_mount=False,
            allow_socket_mount=False,
            timeout_seconds=mode.timeout_seconds,
        )

        adapter = OpenCodeAdapter(probe=self.probe)
        try:
            command = adapter.build_command(run_spec, staging_root)
        except (ValueError, RuntimeError) as exc:
            self._active_run_id = None
            return BackendOperationResult(
                operation="start",
                run_id=run_id,
                status="failed",
                failure_classification=str(exc),
            )

        enforcer = ContainerOpenCodeEnforcer(config)
        self._active_enforcer = enforcer

        try:
            events.append(BackendEvent(
                event_type="agent_started",
                summary="OpenCode agent started in container",
                attributes={"command": " ".join(str(c) for c in command[:8])},
            ))
            if self._event_sink:
                self._event_sink(events[-1])
        except Exception:
            pass

        events.append(BackendEvent(
            event_type="progress",
            summary="OpenCode run is executing",
            attributes={"runId": run_id, "status": "running"},
        ))
        if self._event_sink:
            self._event_sink(events[-1])

        result = enforcer.execute(command, cancel_event=self._cancel_event)

        if result is None:
            self._active_run_id = None
            self._active_enforcer = None
            events.append(BackendEvent(
                event_type="run_cancelled",
                summary="OpenCode run was cancelled",
                attributes={"runId": run_id},
            ))
            return BackendOperationResult(
                operation="start",
                run_id=run_id,
                status="cancelled",
                events=tuple(events),
            )

        try:
            enforcer.cleanup()
        except Exception:
            pass

        events.append(BackendEvent(
            event_type="cleanup_completed",
            summary="Container cleaned up",
            attributes={"runId": run_id, "returncode": result.returncode},
        ))

        if result.returncode == 0:
            events.append(BackendEvent(
                event_type="run_completed",
                summary="OpenCode run completed successfully",
                attributes={"runId": run_id, "returncode": result.returncode},
            ))
            status = "completed"
            failure = None
        else:
            events.append(BackendEvent(
                event_type="run_failed",
                summary="OpenCode run failed",
                attributes={"runId": run_id, "returncode": result.returncode},
            ))
            status = "failed"
            failure = f"opencode_exit_{result.returncode}"

        self._active_run_id = None
        self._active_enforcer = None

        return BackendOperationResult(
            operation="start",
            run_id=run_id,
            status=status,
            events=tuple(events),
            failure_classification=failure,
            process={
                "returncode": result.returncode,
                "stdoutLength": len(result.stdout or ""),
                "stderrLength": len(result.stderr or ""),
            },
        )

    def resume(
        self,
        run_spec: AgentRunSpec,
        staging_root: Path,
        *,
        environment: Mapping[str, str],
        event_sink: Any,
    ) -> BackendOperationResult:
        return BackendOperationResult(
            operation="resume",
            run_id=run_spec.run_id,
            status="unsupported",
            failure_classification="session_resume_not_implemented",
        )

    def cancel(self, run_id: str) -> BackendOperationResult:
        with self._run_lock:
            if self._active_run_id != run_id:
                return BackendOperationResult(
                    operation="cancel",
                    run_id=run_id,
                    status="not_running",
                )
            self._cancel_event.set()
            enforcer = self._active_enforcer

        if enforcer is not None:
            try:
                enforcer.cleanup()
            except Exception:
                pass

        self._active_run_id = None
        self._active_enforcer = None

        return BackendOperationResult(
            operation="cancel",
            run_id=run_id,
            status="cancelled",
        )

    def health(self) -> BackendHealth:
        if not self.probe.installed:
            return BackendHealth(
                backend_id="opencode",
                status="unavailable",
                active_runs=1 if self._active_run_id else 0,
                test_only=False,
                detail="OpenCode executable not found",
            )
        return BackendHealth(
            backend_id="opencode",
            status="healthy",
            active_runs=1 if self._active_run_id else 0,
            test_only=False,
            detail=f"OpenCode {self.probe.version} ready",
        )

    def container_readiness(self) -> EscapeTestResult | None:
        try:
            with tempfile_tempdir() as tmpdir:
                staging = Path(tmpdir)
                config = EnforcerConfig(
                    staging_root=staging,
                    opencode_bin_path=Path(self.probe.executable or "/usr/bin/opencode"),
                )
                return verify_container_enforcement(config)
        except Exception:
            return None


def tempfile_tempdir():
    import tempfile
    return tempfile.TemporaryDirectory()
