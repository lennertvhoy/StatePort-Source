"""Hardened Docker/Podman command construction with execution disabled by default."""

from __future__ import annotations

import os
import hashlib
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from container_runner.contract import ExecutionPlan


class ExecutorError(ValueError):
    """A fail-closed executor configuration or execution error."""


_IMAGE_DIGEST = re.compile(
    r"(?:sha256:[0-9a-f]{64}|[^\s@]+@sha256:[0-9a-f]{64})\Z"
)


def is_immutable_image_reference(image: object) -> bool:
    """Return whether an image is bound to a full sha256 digest or image ID."""

    return isinstance(image, str) and _IMAGE_DIGEST.fullmatch(image) is not None


@dataclass(frozen=True)
class ExecutorResult:
    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str

    def to_dict(self) -> dict[str, object]:
        return {"command": list(self.command), "returncode": self.returncode, "stdout": self.stdout, "stderr": self.stderr}


class ContainerExecutor:
    """Build and, only when explicitly enabled and approval-correlated, run containers."""

    _ENGINES = {"docker", "podman"}
    _MAX_STREAM_BYTES = 1_048_576
    _FORBIDDEN_COMMAND_FLAGS = {"--privileged", "--network", "--net", "--cap-add", "--cap-drop", "--volume", "-v", "--mount", "--user", "--userns", "--security-opt", "--name", "--cidfile", "--env", "-e", "--pids-limit", "--memory", "--cpus", "--ulimit"}

    def __init__(self, *, engine: str = "podman", image: str = "stateport/runner:local", allow_execution: bool = False, timeout_seconds: int = 300, user: str | None = None):
        if engine not in self._ENGINES:
            raise ExecutorError("engine must be docker or podman")
        if (
            not isinstance(image, str)
            or not image.strip()
            or image.startswith("-")
            or any(char.isspace() for char in image)
        ):
            raise ExecutorError("image must be a single non-empty image reference")
        if allow_execution and not is_immutable_image_reference(image):
            raise ExecutorError(
                "enabled execution requires an immutable sha256 image reference"
            )
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or timeout_seconds <= 0:
            raise ExecutorError("timeout_seconds must be a positive integer")
        resolved_user = user or f"{os.getuid()}:{os.getgid()}"
        parts = resolved_user.split(":")
        if (
            len(parts) != 2
            or not all(part.isdigit() for part in parts)
            or int(parts[0]) <= 0
            or int(parts[1]) <= 0
        ):
            raise ExecutorError("user must be a non-root numeric uid:gid")
        self.engine, self.image, self.allow_execution = engine, image, allow_execution
        self.timeout_seconds, self.user = timeout_seconds, resolved_user

    @staticmethod
    def _host_directory(path: str, label: str, *, must_exist: bool = True) -> Path:
        target = Path(path)
        cursor = Path(target.anchor) if target.is_absolute() else Path.cwd()
        parts = target.parts[1:] if target.is_absolute() else target.parts
        for part in parts:
            cursor = cursor / part
            if cursor.is_symlink():
                raise ExecutorError(f"{label} may not traverse a symlink")
        if must_exist and not target.is_dir():
            raise ExecutorError(f"{label} must be an existing directory")
        if target.exists() and not target.is_dir():
            raise ExecutorError(f"{label} must be a directory")
        return target.resolve()

    @classmethod
    def _command_args(cls, command: Sequence[str]) -> list[str]:
        if not command or not all(isinstance(item, str) and item for item in command):
            raise ExecutorError("container command must be a non-empty sequence of strings")
        for item in command:
            if item in cls._FORBIDDEN_COMMAND_FLAGS or any(item.startswith(flag + "=") for flag in cls._FORBIDDEN_COMMAND_FLAGS):
                raise ExecutorError("container command attempts to override isolation")
        return list(command)

    def build_command(self, plan: ExecutionPlan, command: Sequence[str]) -> tuple[str, ...]:
        plan.validate()
        template = self._host_directory(plan.template_path, "template")
        instance = self._host_directory(plan.instance_path, "instance")
        runtime = self._host_directory(plan.runtime_path, "runtime", must_exist=False)
        args = self._command_args(command)
        engine_identity = ["--userns=keep-id"] if self.engine == "podman" else []
        template_relabel = ",relabel=shared" if self.engine == "podman" else ""
        private_relabel = ",relabel=private" if self.engine == "podman" else ""
        container_name = "stateport-" + hashlib.sha256(
            plan.lease_id.encode("utf-8")
        ).hexdigest()[:24]
        return tuple([
            self.engine, "run", "--rm", "--read-only", "--network=none", "--cap-drop=ALL",
            "--security-opt", "no-new-privileges:true", *engine_identity,
            "--pids-limit", "128", "--memory", "512m", "--cpus", "1",
            "--ulimit", "nofile=1024:1024",
            "--name", container_name, "--user", self.user, "--workdir", "/stateport",
            "--env", "STATEPORT_TEMPLATE_PATH=/stateport/template",
            "--mount", f"type=bind,src={template},dst=/stateport/template,readonly{template_relabel}",
            "--mount", f"type=bind,src={instance},dst=/stateport/instance,readonly{private_relabel}",
            "--mount", f"type=bind,src={runtime},dst=/stateport/runtime{private_relabel}", self.image, *args,
        ])

    def _run_bounded(
        self,
        argv: Sequence[str],
    ) -> subprocess.CompletedProcess[str]:
        """Capture engine output on disk and stop at a hard per-stream limit."""

        with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
            try:
                process = subprocess.Popen(
                    tuple(argv),
                    stdout=stdout_file,
                    stderr=stderr_file,
                    start_new_session=True,
                )
            except OSError as exc:
                raise ExecutorError(f"container engine could not be started: {exc}") from exc
            deadline = time.monotonic() + self.timeout_seconds
            failure: str | None = None
            while process.poll() is None:
                stdout_size = os.fstat(stdout_file.fileno()).st_size
                stderr_size = os.fstat(stderr_file.fileno()).st_size
                if (
                    stdout_size > self._MAX_STREAM_BYTES
                    or stderr_size > self._MAX_STREAM_BYTES
                ):
                    failure = "container output exceeded the 1 MiB per-stream limit"
                    break
                if time.monotonic() >= deadline:
                    failure = "container execution timed out"
                    break
                time.sleep(0.05)
            if failure is not None:
                process.kill()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
                raise ExecutorError(failure)
            returncode = process.wait()
            stdout_file.seek(0)
            stderr_file.seek(0)
            stdout = stdout_file.read(self._MAX_STREAM_BYTES + 1)
            stderr = stderr_file.read(self._MAX_STREAM_BYTES + 1)
            if (
                len(stdout) > self._MAX_STREAM_BYTES
                or len(stderr) > self._MAX_STREAM_BYTES
            ):
                raise ExecutorError(
                    "container output exceeded the 1 MiB per-stream limit"
                )
            return subprocess.CompletedProcess(
                tuple(argv),
                returncode,
                stdout.decode("utf-8", errors="replace"),
                stderr.decode("utf-8", errors="replace"),
            )

    def _container_presence(self, executable: str, container_name: str) -> bool | None:
        """Return True/False when the engine can prove presence/absence."""

        command = (
            (executable, "container", "exists", container_name)
            if self.engine == "podman"
            else (executable, "container", "inspect", container_name)
        )
        try:
            checked = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if checked.returncode == 0:
            return True
        if self.engine == "podman" and checked.returncode == 1:
            return False
        if self.engine == "docker" and "no such" in checked.stderr.lower():
            return False
        return None

    def execute(self, plan: ExecutionPlan, command: Sequence[str], *, approval_id: str | None = None) -> ExecutorResult:
        if not self.allow_execution:
            raise ExecutorError("container execution is disabled by default")
        if not isinstance(approval_id, str) or not approval_id.strip():
            raise ExecutorError("explicit approval_id is required for container execution")
        executable = shutil.which(self.engine)
        if executable is None:
            raise ExecutorError(f"container engine is unavailable: {self.engine}")
        runtime = self._host_directory(plan.runtime_path, "runtime", must_exist=False)
        if runtime.exists():
            raise ExecutorError("runtime must not already exist")
        runtime_created = False
        process_started = False
        container_name = "stateport-" + hashlib.sha256(
            plan.lease_id.encode("utf-8")
        ).hexdigest()[:24]
        try:
            try:
                runtime.mkdir(parents=True, exist_ok=False)
            except FileExistsError as exc:
                raise ExecutorError("runtime must not already exist") from exc
            except OSError as exc:
                raise ExecutorError(f"runtime could not be created: {exc}") from exc
            runtime_created = True
            argv = self.build_command(plan, command)
            try:
                process_started = True
                completed = self._run_bounded((executable, *argv[1:]))
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise ExecutorError(f"container execution failed: {exc}") from exc
        finally:
            cleanup_confirmed = not process_started
            if process_started:
                try:
                    subprocess.run(
                        (executable, "rm", "--force", container_name),
                        capture_output=True,
                        text=True,
                        timeout=15,
                        check=False,
                    )
                except (OSError, subprocess.TimeoutExpired):
                    pass
                cleanup_confirmed = (
                    self._container_presence(executable, container_name) is False
                )
            if runtime_created and cleanup_confirmed:
                shutil.rmtree(runtime, ignore_errors=True)
            if process_started and not cleanup_confirmed:
                raise ExecutorError(
                    "container cleanup could not be confirmed; runtime retained"
                )
        return ExecutorResult(argv, completed.returncode, completed.stdout, completed.stderr)


__all__ = [
    "ContainerExecutor",
    "ExecutorError",
    "ExecutorResult",
    "is_immutable_image_reference",
]
