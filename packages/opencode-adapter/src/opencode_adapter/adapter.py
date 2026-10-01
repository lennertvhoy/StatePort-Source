from __future__ import annotations

from dataclasses import dataclass, field
import json
import re
from pathlib import Path
import shlex
import shutil
import subprocess
import threading
from typing import Any, Callable, Mapping

from execution_host.contracts import AgentRunSpec, BackendCapabilities


_VERSION_RE = re.compile(r"(?:opencode\s+)?([0-9]+\.[0-9]+\.[0-9]+)", re.I)
_CAPABILITY_NAMES = (
    "structuredEvents", "nonInteractiveExecution", "cancellation", "sessionResume",
    "repositoryInstructions", "customTools", "mcpEquivalent", "approvalIntegration",
    "sandboxSupport", "changedFileReporting", "tokenTelemetry", "costTelemetry",
)

_OPENCODE_DEEPSEEK_V4_FLASH = "opencode/deepseek-v4-flash"
_OPENCODE_DEEPSEEK_V4_FLASH_FREE = "opencode/deepseek-v4-flash-free"
_DEFAULT_MODEL = _OPENCODE_DEEPSEEK_V4_FLASH_FREE
# Public alias: the shipped default model for managed OpenCode invocations.
DEFAULT_MODEL = _DEFAULT_MODEL
_MODEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,255}$")

_SUPPORTED_RUN_FORMATS = frozenset({"default", "json"})


@dataclass(frozen=True)
class OpenCodeProbe:
    executable: str | None
    version: str
    json_format: bool
    run_command: bool
    model_selection: bool
    auto_approve: bool
    reason: str

    @property
    def installed(self) -> bool:
        return self.executable is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "engineId": "opencode",
            "adapterId": "opencode-cli",
            "executablePresent": self.installed,
            "version": self.version,
            "supportedSurfaces": {
                "jsonFormat": self.json_format,
                "runCommand": self.run_command,
                "modelSelection": self.model_selection,
                "autoApprove": self.auto_approve,
            },
            "authenticationRoute": "operator_authenticated_unverified",
            "reason": self.reason,
        }


def opencode_probe(executable: str = "opencode") -> OpenCodeProbe:
    resolved = shutil.which(executable)
    if resolved is None:
        return OpenCodeProbe(None, "unavailable", False, False, False, False, "opencode executable is not installed")
    try:
        version_result = subprocess.run(
            (resolved, "--version"),
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return OpenCodeProbe(None, "unavailable", False, False, False, False, "opencode --version failed")
    version_match = _VERSION_RE.search(version_result.stdout + "\n" + version_result.stderr)
    version = version_match.group(1) if version_match else "unknown"
    try:
        run_help = subprocess.run(
            (resolved, "run", "--help"),
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return OpenCodeProbe(resolved, version, False, False, False, False, "opencode run --help failed")
    help_text = run_help.stdout + "\n" + run_help.stderr
    return OpenCodeProbe(
        resolved,
        version,
        "--format" in help_text and "json" in help_text,
        "run" in help_text,
        "--model" in help_text,
        "--auto" in help_text,
        "installed; authentication route was not inspected",
    )


@dataclass
class OpenCodeEvent:
    event_type: str
    sequence: int
    summary: str
    attributes: dict[str, Any]
    raw: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "eventType": self.event_type,
            "sequence": self.sequence,
            "summary": self.summary,
            "attributes": dict(self.attributes),
        }


@dataclass
class OpenCodeRunResult:
    success: bool
    returncode: int
    events: list[OpenCodeEvent] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = 0.0
    changed_files: list[str] = field(default_factory=list)
    error: str | None = None
    cancelled: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "returncode": self.returncode,
            "eventCount": len(self.events),
            "durationSeconds": self.duration_seconds,
            "changedFiles": list(self.changed_files),
            "cancelled": self.cancelled,
            "error": self.error,
        }


class OpenCodeAdapter:
    def __init__(self, probe: OpenCodeProbe | None = None):
        self.probe = probe or opencode_probe()

    def capabilities(self) -> BackendCapabilities:
        supported: dict[str, str] = {name: "unsupported" for name in _CAPABILITY_NAMES}
        if self.probe.installed:
            supported.update(
                structuredEvents="supported" if self.probe.json_format else "unsupported",
                nonInteractiveExecution="supported" if self.probe.run_command else "unsupported",
                cancellation="supported",
                sessionResume="unsupported",
                repositoryInstructions="supported",
                customTools="unsupported",
                mcpEquivalent="unsupported",
                approvalIntegration="partial",
                sandboxSupport="supported",
                changedFileReporting="supported",
                tokenTelemetry="unsupported",
                costTelemetry="unsupported",
            )
        return BackendCapabilities(
            "opencode",
            "opencode-cli",
            self.probe.version,
            "managed",
            supported,
            ("operator_authenticated_unverified",),
            ("read_staging", "write_staging"),
            test_only=False,
            production_eligible=False,
        )

    def build_command(
        self,
        spec: AgentRunSpec,
        staging_root: Path,
        *,
        model: str | None = None,
    ) -> tuple[str, ...]:
        if not self.probe.installed:
            raise RuntimeError("opencode executable is unavailable")
        if not staging_root.is_absolute() or not staging_root.is_dir() or staging_root.is_symlink():
            raise ValueError("staging_root must be an existing absolute directory")
        selected_model = spec.model_identifier if model is None else model
        if not isinstance(selected_model, str) or _MODEL.fullmatch(selected_model) is None:
            raise ValueError("OpenCode model identifier is invalid")
        repository_instructions = " ".join(spec.repository_instructions) or "Use only the staging workspace."
        validation_commands = "; ".join(spec.validation_commands) or "No validation command was supplied."
        prompt = (
            f"Execute inside {staging_root}. Never access files outside this directory. "
            f"Run identity: {spec.run_id}. Objective: {spec.objective} "
            f"Repository instructions: {repository_instructions} "
            f"Validation contract: {validation_commands} "
            "Do not modify any canonical checkout, credentials, or host state. "
            "Return structured JSON events. Keep all output bounded."
        )
        args = [
            self.probe.executable,
            "run",
            "--format", "json",
            "--model", selected_model,
            "--dir", staging_root.as_posix(),
            prompt,
        ]
        return tuple(args)

    def execute(
        self,
        spec: AgentRunSpec,
        staging_root: Path,
        *,
        model: str | None = None,
        cancel_event: Any | None = None,
        environment: Mapping[str, str] | None = None,
        on_started: Callable[[ProcessIdentity], None] | None = None,
        on_finished: Callable[[ProcessIdentity], None] | None = None,
        process_generation: str | None = None,
        timeout_seconds: int | None = None,
    ) -> ProcessResult:
        """Run one staging-only OpenCode invocation under the shared supervisor.

        The managed provider path must not invent its own process lifecycle.
        Using the same hardened supervisor as the Codex adapter keeps bounded
        output, process-group termination, cancellation and the generated
        process identity used for restart reconciliation in one place. The raw
        stdout JSONL stream is preserved for event decoding by the caller.
        """
        # Imported here so merely importing the adapter does not require the
        # execution-runtime package on the caller's path.
        from external_engine_runtime import (
            ProcessSpec,
            filtered_environment,
            run_process,
        )

        command = self.build_command(spec, staging_root, model=model)
        budgets = spec.budgets if isinstance(spec.budgets, Mapping) else {}
        configured_timeout = budgets.get("timeSeconds")
        if timeout_seconds is not None:
            timeout = float(timeout_seconds)
        elif (
            isinstance(configured_timeout, int)
            and not isinstance(configured_timeout, bool)
            and configured_timeout > 0
        ):
            timeout = float(configured_timeout)
        else:
            timeout = 300.0
        configured_steps = budgets.get("steps")
        if (
            isinstance(configured_steps, int)
            and not isinstance(configured_steps, bool)
            and configured_steps > 0
        ):
            max_output_bytes = min(configured_steps * 256 * 1024, 4 * 1024 * 1024)
        else:
            max_output_bytes = 1024 * 1024
        return run_process(
            ProcessSpec(
                command,
                staging_root,
                timeout_seconds=timeout,
                max_output_bytes=max_output_bytes,
                environment=(
                    environment
                    if environment is not None
                    else filtered_environment()
                ),
                on_started=on_started,
                on_finished=on_finished,
                process_generation=process_generation,
            ),
            cancel_event=cancel_event,
        )

    @staticmethod
    def _parse_events(text: str) -> list[OpenCodeEvent]:
        events: list[OpenCodeEvent] = []
        seq = 0
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(data, dict):
                continue
            event_type = data.get("type") or data.get("event") or data.get("eventType")
            if not isinstance(event_type, str):
                continue
            seq += 1
            summary = str(data.get("message", data.get("summary", "")))
            attrs = dict(data.get("attributes", data.get("data", {})))
            events.append(OpenCodeEvent(
                event_type=event_type,
                sequence=seq,
                summary=summary[:512],
                attributes=attrs,
                raw=line,
            ))
        return events

    @staticmethod
    def _extract_changed_files(events: list[OpenCodeEvent], stdout: str) -> list[str]:
        changed: list[str] = []
        for ev in events:
            if ev.event_type in ("file.changed", "file.written", "file.created"):
                path = ev.attributes.get("path", ev.attributes.get("file", ""))
                if isinstance(path, str) and path.strip():
                    changed.append(path)
        if not changed:
            for m in re.finditer(r'"(?:file|path)":\s*"([^"]+)"', stdout):
                path = m.group(1)
                if path not in changed:
                    changed.append(path)
        return changed

    @staticmethod
    def command_preview(command: tuple[str, ...]) -> str:
        return shlex.join(command)


def run_opencode_in_container(
    spec: AgentRunSpec,
    staging_root: Path,
    *,
    model: str = _DEFAULT_MODEL,
    container_image: str | None = None,
    cancel_event: threading.Event | None = None,
    timeout_seconds: int = 300,
) -> OpenCodeRunResult:
    """Refuse the retired standalone container path before probing or mutation.

    This helper has no sealed image, operator grant binding, or qualified
    isolation. Keep the callable as an explicit refusal for existing imports;
    managed support must be qualified through the execution host.
    """
    raise RuntimeError(
        "opencode_container_helper_quarantined: managed OpenCode execution "
        "requires a qualified execution-host image, grant and sandbox"
    )
