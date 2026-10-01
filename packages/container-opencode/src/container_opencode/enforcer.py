from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import os
import shlex
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any


class OpenCodeExecutionMode(Enum):
    FASTER = "faster"
    BALANCED = "balanced"
    DEEPER = "deeper"

    @property
    def timeout_seconds(self) -> int:
        return {"faster": 120, "balanced": 300, "deeper": 600}[self.value]

    @property
    def memory_limit(self) -> str:
        return {"faster": "512m", "balanced": "1024m", "deeper": "2048m"}[self.value]

    @property
    def cpu_limit(self) -> str:
        return {"faster": "1", "balanced": "2", "deeper": "4"}[self.value]

    @property
    def max_attempts(self) -> int:
        return {"faster": 1, "balanced": 2, "deeper": 3}[self.value]

    @property
    def pids_limit(self) -> int:
        return {"faster": 64, "balanced": 128, "deeper": 256}[self.value]


@dataclass(frozen=True)
class EnforcerConfig:
    staging_root: Path
    opencode_bin_path: Path
    container_image: str = "docker.io/python:3.14-slim"
    mode: OpenCodeExecutionMode = OpenCodeExecutionMode.BALANCED
    model: str = "opencode/deepseek-v4-flash-free"
    network_enabled: bool = False
    allow_home_mount: bool = False
    allow_socket_mount: bool = False
    allow_ssh_agent: bool = False
    timeout_seconds: int | None = None
    max_output_bytes: int = 4 * 1024 * 1024

    def effective_timeout(self) -> int:
        return self.timeout_seconds or self.mode.timeout_seconds

    def to_dict(self) -> dict[str, Any]:
        return {
            "stagingRoot": str(self.staging_root),
            "containerImage": self.container_image,
            "mode": self.mode.value,
            "model": self.model,
            "networkEnabled": self.network_enabled,
            "allowHomeMount": self.allow_home_mount,
            "allowSocketMount": self.allow_socket_mount,
            "allowSshAgent": self.allow_ssh_agent,
            "timeoutSeconds": self.effective_timeout(),
            "maxOutputBytes": self.max_output_bytes,
        }


@dataclass
class EscapeTestResult:
    outside_write: bool = False
    canonical_checkout_accessible: bool = False
    host_home_accessible: bool = False
    container_socket_accessible: bool = False
    remained_descendants: bool = False
    verification_error: bool = False
    _escaped: bool | None = None
    details: dict[str, str] = field(default_factory=dict)

    @property
    def escaped(self) -> bool:
        return self._escaped if self._escaped is not None else not self.passed()

    @escaped.setter
    def escaped(self, value: bool) -> None:
        self._escaped = value

    def passed(self) -> bool:
        return not (
            self.verification_error
            or self.outside_write
            or self.canonical_checkout_accessible
            or self.host_home_accessible
            or self.container_socket_accessible
            or self.remained_descendants
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "escaped": self.escaped,
            "passed": self.passed(),
            "verificationError": self.verification_error,
            "outsideWrite": self.outside_write,
            "canonicalCheckoutAccessible": self.canonical_checkout_accessible,
            "hostHomeAccessible": self.host_home_accessible,
            "containerSocketAccessible": self.container_socket_accessible,
            "remainedDescendants": self.remained_descendants,
            "details": dict(self.details),
        }


def verify_container_enforcement(
    config: EnforcerConfig,
    canonical_root: Path | None = None,
    *,
    cancel_event: threading.Event | None = None,
) -> EscapeTestResult:
    result = EscapeTestResult()
    shm_dir = Path(tempfile.mkdtemp(prefix="opencode-escape-"))
    uid = os.getuid()
    gid = os.getgid()
    container_name = "stateport-escape-" + hashlib.sha256(
        str(time.monotonic()).encode()
    ).hexdigest()[:16]
    escape_script = shm_dir / "escape_test.sh"
    host_home = shlex.quote(str(Path.home()))
    script_lines = [
        "#!/bin/sh",
        "set -e",
        'echo "ESCAPE_TEST_START"',
        'echo "PWD=$(pwd)"',
        'echo "WHOAMI=$(whoami 2>&1)"',
        'echo "ID=$(id 2>&1)"',
        'echo "LS_ROOT=$(ls -la / 2>&1)"',
        "",
        '# Test 1: write outside staging (host paths must be read-only)',
        'echo "TEST_OUTSIDE_WRITE_START"',
        'if touch /etc/test_escape 2>/dev/null; then echo "ETC_WRITE_POSSIBLE"; else echo "ETC_WRITE_DENIED"; fi',
        'if mkdir /root/test_escape 2>/dev/null; then echo "ROOT_WRITE_POSSIBLE"; else echo "ROOT_WRITE_DENIED"; fi',
        "",
        '# Test 2: host home directory must not be present in container',
        'echo "TEST_HOST_HOME_START"',
        f'if test -d {host_home} && ls {host_home} 2>/dev/null >/dev/null 2>&1; then echo "USER_HOME_READABLE"; else echo "USER_HOME_DENIED"; fi',
        'if ls /home 2>/dev/null; then echo "HOME_DIR_EXISTS"; else echo "HOME_DIR_DENIED"; fi',
        "",
        '# Test 3: cdup escape (mount namespace isolates /; only host paths are escapes)',
        'echo "TEST_CDUP_START"',
        'cd /stateport/../../.. 2>/dev/null || true',
        'echo "CDUP_ENDED_AT=$(pwd)"',
        "",
        '# Test 4: access canonical checkout',
        'echo "TEST_CANONICAL_START"',
    ]
    if canonical_root:
        script_lines.extend([
            f'if test -d {canonical_root} && ls {canonical_root} 2>/dev/null; then echo "CANONICAL_ACCESSIBLE"; else echo "CANONICAL_DENIED"; fi',
        ])
    else:
        script_lines.append('echo "CANONICAL_DENIED (no path)"')
    script_lines.extend([
        "",
        '# Test 5: container socket',
        'echo "TEST_SOCKET_START"',
        'if [ -S /var/run/docker.sock ] || [ -S /run/podman/podman.sock ] || [ -e /var/run/docker.sock ] || [ -e /run/podman/podman.sock ]; then echo "SOCKET_ACCESSIBLE"; else echo "SOCKET_DENIED"; fi',
        "",
        '# Test 6: orphaned process after exit',
        'echo "TEST_ORPHAN_START"',
        '(sleep 5 >/dev/null 2>&1 &) 2>/dev/null',
        'echo "ORPHAN_SPAWNED_DONE"',
        "",
        'echo "ESCAPE_TEST_END"',
    ])
    escape_script.write_text("\n".join(script_lines) + "\n")
    os.chmod(escape_script, 0o500)
    try:
        podman_args = [
            "podman", "run", "--rm",
            "--read-only",
            "--tmpfs", "/tmp:size=4M",
            "--network=none",
            "--cap-drop=ALL",
            "--security-opt", "no-new-privileges:true",
            "--userns=keep-id",
            "--pids-limit", "64",
            "--memory", "256m",
            "--cpus", "0.5",
            "--name", container_name,
            "--env", "HOME=/stateport",
            "--workdir", "/stateport",
            "--mount", f"type=bind,src={config.staging_root},dst=/stateport,relabel=private",
            "--mount", f"type=bind,src={shm_dir},dst=/shm,readonly,relabel=private",
            config.container_image,
            "sh", "/shm/escape_test.sh",
        ]
        process = subprocess.Popen(
            podman_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        deadline = time.monotonic() + 30
        timed_out = False
        while process.poll() is None:
            if cancel_event is not None and cancel_event.is_set():
                process.send_signal(signal.SIGTERM)
                timed_out = True
                process.wait(timeout=10)
                break
            if time.monotonic() >= deadline:
                process.send_signal(signal.SIGTERM)
                timed_out = True
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                break
            time.sleep(0.1)
        if timed_out:
            result.verification_error = True
            result.details["error"] = "escape test container timed out or was cancelled"
        stdout_text, stderr_text = process.communicate(timeout=10)
        output = (stdout_text or "") + "\n" + (stderr_text or "")
        result.details["rawOutput"] = output[:2000]
        if "ETC_WRITE_POSSIBLE" in output:
            result.outside_write = True
            result.details["outsideWriteEtc"] = "touch /etc succeeded"
        if "ROOT_WRITE_POSSIBLE" in output:
            result.outside_write = True
            result.details["outsideWriteRoot"] = "mkdir /root succeeded"
        if "USER_HOME_READABLE" in output:
            result.host_home_accessible = True
            result.details["userHomeRead"] = "configured host home accessible inside container"
        if "CDUP_ENDED_AT=" in output:
            import re as _re
            m = _re.search(r"CDUP_ENDED_AT=(.+)", output)
            if m and m.group(1).strip() not in ("/", "/stateport"):
                result.details["cdup"] = f"cdup ended at unexpected path: {m.group(1)}"
        if "CANONICAL_ACCESSIBLE" in output:
            result.canonical_checkout_accessible = True
        if "SOCKET_ACCESSIBLE" in output:
            result.container_socket_accessible = True
        if "ESCAPE_TEST_END" not in output and not result.verification_error:
            result.verification_error = True
            result.details["error"] = "escape test did not produce end marker"
    except (OSError, subprocess.TimeoutExpired) as exc:
        result.verification_error = True
        result.details["error"] = str(exc)
    finally:
        _cleanup_container(container_name)
        if shm_dir.exists():
            shutil.rmtree(shm_dir, ignore_errors=True)
    # After container exit, check for orphaned descendant processes.
    # A properly isolated container kills all descendants on exit.
    try:
        check = subprocess.run(
            ("pgrep", "-f", "sleep 5"),
            capture_output=True, text=True, timeout=5,
        )
        if check.returncode == 0 and check.stdout.strip():
            result.remained_descendants = True
            result.details["orphanPids"] = check.stdout.strip()[:512]
    except (OSError, subprocess.TimeoutExpired):
        pass
    return result


class ContainerOpenCodeEnforcer:
    def __init__(self, config: EnforcerConfig):
        self.config = config
        self._container_name = "stateport-opencode-" + hashlib.sha256(
            str(time.monotonic_ns()).encode()
        ).hexdigest()[:16]

    @property
    def image(self) -> str:
        return self.config.container_image

    def build_run_command(
        self,
        inner_command: tuple[str, ...],
        opencode_path: Path,
    ) -> tuple[str, ...]:
        cfg = self.config
        uid = os.getuid()
        gid = os.getgid()
        shm_setup = self._prepare_setup_script()
        network_flag = "--network=none" if not cfg.network_enabled else "--network=host"
        home_flag = []
        if cfg.allow_home_mount:
            home_flag = [
                "--mount",
                f"type=bind,src={Path.home()},dst=/stateport-user-home,readonly,relabel=private",
            ]
        socket_flag = []
        if cfg.allow_socket_mount:
            socket_flag = ["--mount", "type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock,readonly"]
        ssh_flag = []
        ssh_socket = os.environ.get("SSH_AUTH_SOCK", "")
        if cfg.allow_ssh_agent and ssh_socket:
            ssh_flag = ["--mount", f"type=bind,src={ssh_socket},dst={ssh_socket}"]
        return tuple([
            "podman", "run", "--rm",
            "--read-only",
            "--tmpfs", "/tmp:size=4M",
            network_flag,
            "--cap-drop=ALL",
            "--security-opt", "no-new-privileges:true",
            "--userns=keep-id",
            "--pids-limit", str(cfg.mode.pids_limit),
            "--memory", cfg.mode.memory_limit,
            "--cpus", cfg.mode.cpu_limit,
            "--ulimit", "nofile=1024:1024",
            "--name", self._container_name,
            "--env", "HOME=/stateport",
            "--workdir", "/stateport",
            "--mount", f"type=bind,src={cfg.staging_root},dst=/stateport,relabel=private",
            "--mount", f"type=bind,src={opencode_path},dst=/usr/local/bin/opencode,readonly,relabel=private",
            *home_flag,
            *socket_flag,
            *ssh_flag,
            "--mount", f"type=bind,src={shm_setup},dst=/shm,readonly,relabel=private",
            cfg.container_image,
            "sh", "/shm/setup_and_run.sh",
            *inner_command,
        ])

    def _prepare_setup_script(self) -> Path:
        shm_dir = Path(tempfile.mkdtemp(prefix="opencode-shm-"))
        script = shm_dir / "setup_and_run.sh"
        script_lines = [
            "#!/bin/sh",
            "set -e",
            "HOME=/stateport",
            "export HOME",
            "mkdir -p /stateport/.opencode /tmp/bin",
            "ln -sf /usr/local/bin/opencode /tmp/bin/opencode 2>/dev/null || true",
            'export PATH="/tmp/bin:${PATH}"',
            "exec \"$@\"",
        ]
        script.write_text("\n".join(script_lines) + "\n")
        os.chmod(script, 0o500)
        return shm_dir

    def execute(
        self,
        command: tuple[str, ...],
        *,
        cancel_event: threading.Event | None = None,
    ) -> subprocess.CompletedProcess[str] | None:
        cfg = self.config
        opencode_bin_path = cfg.opencode_bin_path
        if not opencode_bin_path.is_file():
            raise RuntimeError("configured OpenCode executable is unavailable")
        opencode_source = opencode_bin_path.resolve(strict=True)
        # Translate host opencode path to container path
        container_command = tuple(
            arg.replace(str(opencode_bin_path), "/usr/local/bin/opencode")
            for arg in command
        )
        full_command = self.build_run_command(container_command, opencode_source)
        try:
            process = subprocess.Popen(
                full_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
        except OSError as exc:
            raise RuntimeError(f"container could not be started: {exc}") from exc
        deadline = time.monotonic() + cfg.effective_timeout()
        while process.poll() is None:
            if cancel_event is not None and cancel_event.is_set():
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                _cleanup_container(self._container_name)
                return None
            if time.monotonic() >= deadline:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                _cleanup_container(self._container_name)
                return None
            time.sleep(0.1)
        stdout_text, stderr_text = process.communicate(timeout=15)
        return subprocess.CompletedProcess(
            full_command,
            process.poll() or 0,
            stdout_text,
            stderr_text,
        )

    def cleanup(self) -> None:
        _cleanup_container(self._container_name)


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
