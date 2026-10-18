from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import subprocess
from typing import Iterator, Mapping
import tempfile
from contextlib import contextmanager


class SandboxError(ValueError):
    pass


@dataclass(frozen=True)
class SandboxPolicy:
    """The adapter-visible policy; canonical state is never an execution mount."""

    parent: Path
    network: str = "disabled"
    read_only_inputs: tuple[Path, ...] = ()
    output_limit_bytes: int = 4 * 1024 * 1024
    timeout_seconds: int = 30
    cpu_limit: str = "1"
    memory_limit: str = "512m"
    pids_limit: int = 128
    container_image: str = "stateport/engine-runtime:local"

    def validate(self) -> None:
        if not self.parent.is_absolute() or self.parent.is_symlink() or not self.parent.is_dir():
            raise SandboxError("sandbox parent must be an existing absolute non-symlink directory")
        if self.network not in {"disabled", "destination-scoped"}:
            raise SandboxError("sandbox network policy is invalid")
        if isinstance(self.output_limit_bytes, bool) or self.output_limit_bytes <= 0:
            raise SandboxError("sandbox output limit must be positive")
        if isinstance(self.timeout_seconds, bool) or self.timeout_seconds <= 0:
            raise SandboxError("sandbox timeout must be positive")
        if not self.cpu_limit or not self.memory_limit or isinstance(self.pids_limit, bool) or self.pids_limit <= 0:
            raise SandboxError("sandbox resource limits are invalid")
        for path in self.read_only_inputs:
            if not path.is_absolute() or path.is_symlink() or not path.is_dir():
                raise SandboxError("sandbox inputs must be existing absolute non-symlink directories")
            if path.resolve().is_relative_to(self.parent.resolve()):
                raise SandboxError("sandbox input cannot overlap its staging parent")

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "formatVersion": "stateport.sandbox-policy/v1",
            "network": {"mode": self.network},
            "canonicalStateMount": False,
            "homeMount": False,
            "secretEnvironment": False,
            "readOnlyInputs": [path.as_posix() for path in self.read_only_inputs],
            "writableOutput": "staging-only",
            "timeoutSeconds": self.timeout_seconds,
            "outputLimitBytes": self.output_limit_bytes,
            "cpuLimit": self.cpu_limit,
            "memoryLimit": self.memory_limit,
            "pidsLimit": self.pids_limit,
            "privileged": False,
            "deviceAccess": False,
        }


@dataclass(frozen=True)
class SandboxObservation:
    runtime: str
    available: bool
    rootless: bool
    degradation: str | None
    execution_boundary: str = "staging_copy_only"
    container_enforced: bool = False
    network_isolation: str = "unproven"
    canonical_access_isolation: str = "unproven"

    def to_dict(self) -> dict[str, object]:
        return {
            "formatVersion": "stateport.sandbox-observation/v1",
            "runtime": self.runtime,
            "available": self.available,
            "rootless": self.rootless,
            "degradation": self.degradation,
            "executionBoundary": self.execution_boundary,
            "containerEnforced": self.container_enforced,
            "networkIsolation": self.network_isolation,
            "canonicalAccessIsolation": self.canonical_access_isolation,
        }


class SandboxBoundary:
    def __init__(self, policy: SandboxPolicy):
        policy.validate()
        self.policy = policy

    @staticmethod
    def observe() -> SandboxObservation:
        podman = shutil.which("podman")
        if podman is None:
            return SandboxObservation("rootless-podman", False, False, "rootless_podman_unavailable")
        try:
            result = subprocess.run([podman, "info", "--format", "{{.Host.Security.Rootless}}"], capture_output=True, text=True, timeout=5, env={"PATH": os.environ.get("PATH", ""), "LANG": "C"})
            rootless = result.returncode == 0 and result.stdout.strip().lower() == "true"
            return SandboxObservation("rootless-podman", rootless, rootless, None if rootless else "rootless_podman_not_working")
        except (OSError, subprocess.SubprocessError):
            return SandboxObservation("rootless-podman", False, False, "rootless_podman_probe_failed")

    @staticmethod
    def observe_staging_copy() -> SandboxObservation:
        """Describe the host-process path without borrowing container claims.

        Copying inputs into a temporary directory proves only which paths the
        caller passed to the process.  It does not make other host paths
        inaccessible and it does not disable the host network.
        """

        return SandboxObservation(
            "host-process",
            True,
            False,
            "container_not_invoked",
            execution_boundary="staging_copy_only",
            container_enforced=False,
            network_isolation="unproven",
            canonical_access_isolation="unproven",
        )

    def environment(self, overrides: Mapping[str, str] | None = None) -> dict[str, str]:
        # HOME is intentionally not inherited. Callers may set it to a
        # staging-local directory explicitly when a tool requires one.
        allowed = {"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR"}
        environment = {key: value for key, value in os.environ.items() if key in allowed}
        environment.pop("HOME", None)
        for key, value in (overrides or {}).items():
            if key not in allowed or not isinstance(value, str):
                raise SandboxError("sandbox environment override is not allowlisted")
            if key in {"HOME", "TMPDIR"} and not Path(value).is_absolute():
                raise SandboxError(f"sandbox {key} must be an absolute staging path")
            environment[key] = value
        return environment

    def podman_command(self, command: tuple[str, ...], staging: Path) -> tuple[str, ...]:
        """Build the default-deny rootless Podman invocation without running it."""

        self.policy.validate()
        if not command or any(not isinstance(item, str) or not item for item in command):
            raise SandboxError("sandbox command must contain non-empty strings")
        if not staging.is_absolute() or staging.is_symlink() or not staging.is_dir():
            raise SandboxError("sandbox staging path is invalid")
        staging.resolve().relative_to(self.policy.parent.resolve())
        network = "none" if self.policy.network == "disabled" else "slirp4netns"
        return (
            "podman", "run", "--rm", "--network", network, "--read-only", "--cap-drop=ALL",
            "--security-opt", "no-new-privileges", "--pids-limit", str(self.policy.pids_limit),
            "--memory", self.policy.memory_limit, "--cpus", self.policy.cpu_limit,
            "--userns=keep-id", "--volume", f"{staging.as_posix()}:/workspace:rw",
            "--workdir", "/workspace", self.policy.container_image, *command,
        )

    @contextmanager
    def staging(self) -> Iterator[Path]:
        self.policy.validate()
        temporary = Path(tempfile.mkdtemp(prefix="stateport-sandbox-", dir=self.policy.parent))
        try:
            yield temporary
        finally:
            shutil.rmtree(temporary, ignore_errors=True)
