from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import shlex
from typing import Any, Callable

from execution_host.contracts import AgentRunSpec, BackendCapabilities
from external_engine_runtime import (
    ProcessIdentity,
    ProcessResult,
    ProcessSpec,
    filtered_environment,
    probe_executable,
    run_process,
)


_VERSION = re.compile(r"codex(?:-cli)?\s+([0-9][^\s]*)", re.I)
_CAPABILITY_NAMES = (
    "structuredEvents", "nonInteractiveExecution", "cancellation", "sessionResume",
    "repositoryInstructions", "customTools", "mcpEquivalent", "approvalIntegration",
    "sandboxSupport", "changedFileReporting", "tokenTelemetry", "costTelemetry",
)
_MAX_OBJECTIVE_BYTES = 32 * 1024


@dataclass(frozen=True)
class CodexProbe:
    executable: str | None
    version: str
    exec_json: bool
    ephemeral: bool
    workspace_sandbox: bool
    reason: str

    @property
    def installed(self) -> bool:
        return self.executable is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "engineId": "codex",
            "adapterId": "codex-cli",
            "executablePresent": self.installed,
            "version": self.version,
            "supportedSurfaces": {
                "execJson": self.exec_json,
                "ephemeral": self.ephemeral,
                "workspaceSandbox": self.workspace_sandbox,
            },
            "authenticationRoute": "operator_authenticated_unverified",
            "reason": self.reason,
        }


def _help(executable: str, command: tuple[str, ...]) -> str:
    result = run_process(
        ProcessSpec(
            (executable, *command),
            Path.cwd(),
            timeout_seconds=5,
            max_output_bytes=128 * 1024,
            environment=filtered_environment(),
        )
    )
    if result.returncode not in (0, 2):
        return ""
    return result.stdout + "\n" + result.stderr


def codex_probe(executable: str = "codex") -> CodexProbe:
    resolved = probe_executable(executable)
    if resolved is None:
        return CodexProbe(None, "unavailable", False, False, False, "codex executable is not installed")
    version_result = run_process(
        ProcessSpec(
            (resolved, "--version"),
            Path.cwd(),
            timeout_seconds=5,
            max_output_bytes=16 * 1024,
            environment=filtered_environment(),
        )
    )
    version_match = _VERSION.search(version_result.stdout + "\n" + version_result.stderr)
    version = version_match.group(1) if version_match else "unknown"
    help_text = _help(resolved, ("exec", "--help"))
    sandbox_text = _help(resolved, ("sandbox", "--help"))
    return CodexProbe(
        resolved,
        version,
        "--json" in help_text,
        "--ephemeral" in help_text,
        "workspace-write" in help_text and bool(sandbox_text),
        "installed; authentication route was not inspected",
    )


class CodexAdapter:
    """Translate an exact AgentRunSpec into a staging-only Codex invocation."""

    def __init__(self, probe: CodexProbe | None = None):
        self.probe = probe or codex_probe()

    def capabilities(self) -> BackendCapabilities:
        supported = {name: "unsupported" for name in _CAPABILITY_NAMES}
        if self.probe.installed:
            supported.update(
                structuredEvents="supported" if self.probe.exec_json else "unsupported",
                nonInteractiveExecution="supported",
                cancellation="supported",
                sessionResume="unsupported",
                repositoryInstructions="supported",
                customTools="unsupported",
                mcpEquivalent="unsupported",
                approvalIntegration="unsupported",
                sandboxSupport="environment-gated" if self.probe.workspace_sandbox else "unsupported",
                changedFileReporting="supported",
                tokenTelemetry="unavailable",
                costTelemetry="unavailable",
            )
        return BackendCapabilities(
            "codex",
            "codex-cli",
            self.probe.version,
            "managed",
            supported,
            ("operator_authenticated_unverified",),
            ("read_staging", "write_staging"),
            test_only=False,
            production_eligible=False,
        )

    def prepare_command(self, spec: AgentRunSpec, staging_root: Path) -> tuple[str, ...]:
        if not self.probe.installed:
            raise RuntimeError("codex executable is unavailable")
        if not staging_root.is_absolute() or not staging_root.is_dir() or staging_root.is_symlink():
            raise ValueError("Codex staging root must be an existing absolute non-symlink directory")
        if not self.probe.exec_json or not self.probe.ephemeral:
            raise RuntimeError("installed Codex does not expose the required JSON/ephemeral exec surface")
        objective = spec.objective.strip()
        if len(objective.encode("utf-8")) > _MAX_OBJECTIVE_BYTES:
            raise ValueError("Codex objective exceeds the 32KiB adapter bound")
        instructions = "\n".join(
            f"- {item}" for item in spec.repository_instructions
        ) or "- Follow repository instructions already present in the staging workspace."
        prompt = (
            "Execute only inside the StatePort staging workspace. Never access or modify canonical instance state.\n"
            f"Run identity: {spec.run_id}\n"
            f"Exact AgentRunSpec digest: {spec.digest}\n"
            f"User objective:\n{objective}\n"
            f"Repository instructions:\n{instructions}\n"
            "Return structured JSONL events and keep all output bounded."
        )
        return (
            self.probe.executable,
            "--ask-for-approval",
            "never",
            "exec",
            "--json",
            "--ephemeral",
            "--skip-git-repo-check",
            "--cd",
            staging_root.as_posix(),
            "--sandbox",
            "workspace-write",
            "--model",
            spec.model_identifier,
            prompt,
        )

    def execute(
        self,
        spec: AgentRunSpec,
        staging_root: Path,
        *,
        cancel_event: Any | None = None,
        environment: dict[str, str] | None = None,
        on_started: Callable[[ProcessIdentity], None] | None = None,
        on_finished: Callable[[ProcessIdentity], None] | None = None,
        process_generation: str | None = None,
    ) -> ProcessResult:
        command = self.prepare_command(spec, staging_root)
        return run_process(
            ProcessSpec(
                command,
                staging_root,
                timeout_seconds=float(spec.budgets["timeSeconds"]),
                max_output_bytes=min(spec.budgets["steps"] * 256 * 1024, 4 * 1024 * 1024),
                environment=environment or filtered_environment(),
                on_started=on_started,
                on_finished=on_finished,
                process_generation=process_generation,
            ),
            cancel_event=cancel_event,
        )

    @staticmethod
    def command_preview(command: tuple[str, ...]) -> str:
        return shlex.join(command)
