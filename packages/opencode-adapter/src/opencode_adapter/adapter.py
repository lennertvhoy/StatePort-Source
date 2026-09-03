from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
import re
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from typing import Any

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
        model: str = _DEFAULT_MODEL,
    ) -> tuple[str, ...]:
        if not self.probe.installed:
            raise RuntimeError("opencode executable is unavailable")
        if not staging_root.is_absolute() or not staging_root.is_dir():
            raise ValueError("staging_root must be an existing absolute directory")
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
            "--model", model,
            "--dir", staging_root.as_posix(),
            prompt,
        ]
        return tuple(args)

    def execute(
        self,
        spec: AgentRunSpec,
        staging_root: Path,
        *,
        model: str = _DEFAULT_MODEL,
        cancel_event: threading.Event | None = None,
        timeout_seconds: int = 300,
    ) -> OpenCodeRunResult:
        command = self.build_command(spec, staging_root, model=model)
        start = time.monotonic()
        process: subprocess.Popen | None = None
        cancelled = False
        stdout_chunks: list[str] = []
        stderr_chunks: list[str] = []
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            deadline = start + timeout_seconds
            poll_interval = 0.1
            while process.poll() is None:
                if cancel_event is not None and cancel_event.is_set():
                    process.send_signal(signal.SIGTERM)
                    cancelled = True
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
                    break
                if time.monotonic() >= deadline:
                    process.send_signal(signal.SIGTERM)
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
                    break
                time.sleep(poll_interval)
            stdout_text, stderr_text = process.communicate(timeout=10)
            stdout_chunks.append(stdout_text)
            stderr_chunks.append(stderr_text)
        except (OSError, subprocess.TimeoutExpired) as exc:
            duration = time.monotonic() - start
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            return OpenCodeRunResult(
                success=False, returncode=-1,
                error=str(exc), duration_seconds=duration,
                cancelled=cancelled,
            )
        duration = time.monotonic() - start
        full_stdout = "".join(stdout_chunks)
        full_stderr = "".join(stderr_chunks)
        events = self._parse_events(full_stdout)
        changed_files = self._extract_changed_files(events, full_stdout)
        returncode = process.poll() if process else -1
        return OpenCodeRunResult(
            success=returncode == 0,
            returncode=returncode or 0,
            events=events,
            stdout=full_stdout,
            stderr=full_stderr,
            duration_seconds=duration,
            changed_files=changed_files,
            cancelled=cancelled,
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
    """
    QUARANTINED: This function is not safe for production use.

    The standalone container helper was found to have multiple critical bugs
    during audit (read-only FS writes, broken shell chaining). It is retained
    for reference only. Use ContainerOpenCodeEnforcer from container-opencode
    for any real container execution.
    """
    resolved_image = container_image or "docker.io/python:3.14-slim"
    adapter = OpenCodeAdapter()
    opencode_bin = shutil.which("opencode") or str(Path.home() / ".opencode" / "bin" / "opencode")
    opencode_dir = Path(opencode_bin).resolve().parent.parent
    container_name = "stateport-opencode-" + hashlib.sha256(
        spec.run_id.encode("utf-8")
    ).hexdigest()[:16]
    uid = os.getuid()
    gid = os.getgid()
    shm_dir = Path(tempfile.mkdtemp(prefix="opencode-shm-"))
    setup_script = shm_dir / "setup_and_run.sh"
    script_lines: list[str] = [
        "#!/bin/sh",
        "set -e",
        "mkdir -p /tmp/home /tmp/bin",
        "ln -sf /opencode-bin/bin/opencode /tmp/bin/opencode",
        "export HOME=/tmp/home",
        "export PATH=/tmp/bin:/usr/local/bin:/usr/bin:/bin",
        'exec "$@"',
    ]
    setup_script.write_text("\n".join(script_lines) + "\n")
    os.chmod(setup_script, 0o500)
    run_args = [
        "opencode", "run", "--format", "json", "--model", model,
        "--dir", "/stateport",
        f"Execute inside /stateport. Never access files outside this directory. Run identity: {spec.run_id}.",
    ]
    start = time.monotonic()
    process = None
    cancelled = False
    try:
        podman_args = [
            "podman", "run", "--rm",
            "--read-only",
            "--tmpfs", "/tmp:size=64M",
            "--network=none",
            "--cap-drop=ALL",
            "--security-opt", "no-new-privileges:true",
            "--userns=keep-id",
            "--pids-limit", "128",
            "--memory", "1024m",
            "--cpus", "2",
            "--ulimit", "nofile=1024:1024",
            "--name", container_name,
            "--user", f"{uid}:{gid}",
            "--workdir", "/stateport",
            "--mount", f"type=bind,src={staging_root},dst=/stateport,relabel=private",
            "--mount", f"type=bind,src={opencode_dir},dst=/opencode-bin,readonly,relabel=private",
            "--mount", f"type=bind,src={shm_dir},dst=/shm,readonly,relabel=private",
            resolved_image,
            "sh", "/shm/setup_and_run.sh",
            *run_args,
        ]
        process = subprocess.Popen(
            podman_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        deadline = start + timeout_seconds
        while process.poll() is None:
            if cancel_event is not None and cancel_event.is_set():
                process.send_signal(signal.SIGTERM)
                cancelled = True
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                _cleanup_container(container_name)
                break
            if time.monotonic() >= deadline:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                _cleanup_container(container_name)
                break
            time.sleep(0.1)
        stdout_text, stderr_text = process.communicate(timeout=15)
    except (OSError, subprocess.TimeoutExpired) as exc:
        duration = time.monotonic() - start
        _cleanup_container(container_name)
        if shm_dir.exists():
            shutil.rmtree(shm_dir, ignore_errors=True)
        return OpenCodeRunResult(
            success=False, returncode=-1,
            error=str(exc), duration_seconds=duration,
            cancelled=cancelled,
        )
    duration = time.monotonic() - start
    if shm_dir.exists():
        shutil.rmtree(shm_dir, ignore_errors=True)
    events = adapter._parse_events(stdout_text or "")
    changed_files = adapter._extract_changed_files(events, stdout_text or "")
    returncode = process.poll() if process else -1
    return OpenCodeRunResult(
        success=returncode == 0,
        returncode=returncode or 0,
        events=events,
        stdout=stdout_text or "",
        stderr=stderr_text or "",
        duration_seconds=duration,
        changed_files=changed_files,
        cancelled=cancelled,
    )


def _cleanup_container(name: str) -> None:
    try:
        subprocess.run(
            ("podman", "rm", "--force", name),
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        subprocess.run(
            ("podman", "container", "cleanup", name),
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        pass
