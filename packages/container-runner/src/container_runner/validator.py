"""Independent read-only validator container command and execution boundary."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from container_runner.executor import ExecutorError, is_immutable_image_reference


@dataclass(frozen=True)
class ValidatorPlan:
    image: str
    staging_path: Path
    command: tuple[str, ...]
    memory_max_bytes: int = 268435456
    cpu_quota_percent: int = 100
    pids_max: int = 128
    timeout_seconds: int = 300
    output_byte_bound: int = 1048576

    def validate(self) -> None:
        if not is_immutable_image_reference(self.image):
            raise ExecutorError("validator requires a digest-pinned image")
        if not self.staging_path.is_absolute() or not self.staging_path.is_dir():
            raise ExecutorError("validator staging path must be an existing directory")
        if self.staging_path.is_symlink():
            raise ExecutorError("validator staging path may not be a symlink")
        if not self.command or any(not isinstance(item, str) or not item or "\x00" in item for item in self.command):
            raise ExecutorError("validator command must be a non-empty argv without NUL bytes")
        if any(item.startswith(flag) for item in self.command for flag in ("--privileged", "--mount", "--volume", "--network", "--userns")):
            raise ExecutorError("validator command may not override container isolation")
        if not 16 * 1024 * 1024 <= self.memory_max_bytes <= 8 * 1024**3:
            raise ExecutorError("validator memory limit is outside the bounded range")
        if not 1 <= self.cpu_quota_percent <= 800 or not 16 <= self.pids_max <= 4096:
            raise ExecutorError("validator resource limits are outside the bounded range")
        if not 1 <= self.timeout_seconds <= 3600 or not 1 <= self.output_byte_bound <= 4 * 1024 * 1024:
            raise ExecutorError("validator time or output limit is outside the bounded range")

    def build_command(self, *, engine: str = "podman") -> tuple[str, ...]:
        self.validate()
        cpu = max(1, self.cpu_quota_percent // 100)
        relabel = ",relabel=private" if engine == "podman" else ""
        return (
            engine,
            "run",
            "--rm",
            "--read-only",
            "--network=none",
            "--cap-drop=ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--userns=keep-id",
            "--pids-limit",
            str(self.pids_max),
            "--memory",
            str(self.memory_max_bytes),
            "--cpus",
            str(cpu),
            "--workdir",
            "/workspace",
            "--mount",
            f"type=bind,src={self.staging_path.resolve()},dst=/workspace,readonly{relabel}",
            self.image,
            *self.command,
        )


class ValidatorExecutor:
    """Compatibility guard: validator execution belongs to the execution host."""

    def __init__(self, **_: Any) -> None:
        pass

    def execute(self, plan: ValidatorPlan) -> None:
        del plan
        raise ExecutorError(
            "direct validator execution is disabled; use execution_host.ValidatorRuntime"
        )


__all__ = ["ValidatorExecutor", "ValidatorPlan"]
