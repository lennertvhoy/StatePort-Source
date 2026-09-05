"""Rootless Podman CLI engine adapter for the execution-host daemon.

The daemon owns every container argument: argv is built only from fixed
templates plus typed, validated spec fields, then re-asserted against an
allowlist before execution (hardening rules reused from
``packages/container-runner``: digest-pinned images, no privilege, no host
namespaces, no mounts, bounded resources).  The single exception is the
sealed ``validator-run`` kind, whose argv carries exactly one read-only
bind of the immutable staging tree at ``/validator`` and is re-asserted
against that exact shape.  The engine never touches a control-plane
socket; only the execution user's own rootless socket (or the default
rootless CLI) is used.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import pty
import re
import selectors
import signal
import struct
import subprocess
import termios
import time
from typing import Any, Mapping, Sequence

from .daemon_contract import MAX_OUTPUT_BYTES, MAX_REQUEST_TIMEOUT_SECONDS


MANAGED_LABEL_KEY = "io.stateport.execution.managed"
MANAGED_LABEL = f"{MANAGED_LABEL_KEY}=true"
WORKLOAD_LABEL = "io.stateport.execution.workload"
KIND_LABEL = "io.stateport.execution.kind"
VOLUME_MANAGED_LABEL = "io.stateport.execution.volume.managed"
VOLUME_KIND_LABEL = "io.stateport.execution.volume.kind"
VOLUME_WORKSPACE_LABEL = "io.stateport.execution.volume.workspace"
VOLUME_ID_LABEL = "io.stateport.execution.volume.id"
VOLUME_DISK_LIMIT_LABEL = "io.stateport.execution.volume.disk-limit"

# Sockets that belong to the control plane or a system engine.  The execution
# host owns its own rootless socket and must never observe these.
CONTROL_PLANE_SOCKETS = frozenset(
    {
        "/run/podman/podman.sock",
        "/var/run/podman/podman.sock",
        "/var/run/docker.sock",
        "/run/docker.sock",
    }
)

# Daemon-owned volume naming.  The workspace data volume and cache volumes
# only ever exist under these prefixes; host paths are not representable.
WORKSPACE_VOLUME_PREFIX = "stateport-workspace-"
CACHE_VOLUME_PREFIX = "stateport-cache-"
_VOLUME_NAME = r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}"
_WORKSPACE_VOLUME_ARG = re.compile(
    rf"{WORKSPACE_VOLUME_PREFIX}{_VOLUME_NAME}:/workspace:rw"
)
_CACHE_VOLUME_ARG = re.compile(
    rf"{CACHE_VOLUME_PREFIX}[0-9a-f]{{64}}:/workspace/[A-Za-z0-9._-][A-Za-z0-9._/-]{{0,255}}:(?:ro|rw)"
)

# Daemon-owned workload supervisor entrypoint.  Every value it consumes
# arrives as a validated typed environment variable; no client-controlled
# string is ever spliced into a command line.
_WORKLOAD_TEMPLATE = (
    "set -eu; "
    'if [ "$STATEPORT_WORKLOAD_KIND" = "workspace" ]; then '
    "while :; do sleep 3600; done; "
    "fi; "
    'echo "stateport-workload-start kind=$STATEPORT_WORKLOAD_KIND id=$STATEPORT_WORKLOAD_ID"; '
    'if [ "$STATEPORT_PARAM_EMIT_BYTES" -gt 0 ]; then '
    'head -c "$STATEPORT_PARAM_EMIT_BYTES" /dev/zero | tr "\\0" "s"; echo; fi; '
    'sleep "$STATEPORT_PARAM_WORK_SECONDS"; '
    'echo "stateport-workload-complete id=$STATEPORT_WORKLOAD_ID"'
)

# Fixed allowlist for the constructed create argv (flag position 0 is the
# podman binary itself).  Anything outside this set fails closed.
_ALLOWED_CREATE_FLAGS = frozenset(
    {
        "create",
        "--name",
        "--label",
        "--network",
        "--read-only",
        "--cap-drop",
        "--security-opt",
        "--pids-limit",
        "--memory",
        "--cpus",
        "--tmpfs",
        "--env",
        "--entrypoint",
        "--stop-signal",
        "--stop-timeout",
        "--pull",
        "--quiet",
        "--workdir",
        "--volume",
        # --mount is only ever produced by the sealed validator argv, which
        # re-asserts it against the exact read-only staging shape; the generic
        # hardening below keeps forbidding it for every other kind.
        "--mount",
    }
)


class EngineError(RuntimeError):
    """A typed engine failure; the daemon converts it into a refusal receipt."""


def container_name(workload_id: str) -> str:
    return f"stateport-exec-{workload_id}"


def cache_volume_name(workspace_id: str, volume_id: str) -> str:
    """Return a cache volume identity private to one workspace."""
    identity = f"{workspace_id}\x00{volume_id}".encode("utf-8")
    return CACHE_VOLUME_PREFIX + hashlib.sha256(identity).hexdigest()


def build_create_argv(spec: Mapping[str, Any]) -> list[str]:
    """Build the hardened create argv from a validated sealed spec."""

    if spec["kind"] == "validator-run":
        return build_validator_create_argv(spec)
    name = container_name(spec["workloadId"])
    parameters = spec["parameters"]
    is_workspace = spec["kind"] == "workspace"
    is_agent_run = spec["kind"] == "agent-run"
    env = {
        "STATEPORT_WORKLOAD_ID": spec["workloadId"],
        "STATEPORT_WORKLOAD_KIND": spec["kind"],
        "STATEPORT_PARAM_WORK_SECONDS": str(parameters["workSeconds"]),
        "STATEPORT_PARAM_EMIT_BYTES": str(parameters["emitBytes"]),
    }
    for field, raw in parameters.items():
        if field in {"workSeconds", "emitBytes"} or not isinstance(raw, str):
            continue
        # Identity fields are validated typed strings (ids, digests, references).
        env["STATEPORT_PARAM_" + field.upper()] = str(raw)
    argv = [
        "create",
        "--name",
        name,
        "--label",
        MANAGED_LABEL,
        "--label",
        f"{WORKLOAD_LABEL}={spec['workloadId']}",
        "--label",
        f"{KIND_LABEL}={spec['kind']}",
    ]
    if not is_workspace or parameters["networkMode"] == "none":
        argv.extend(["--network", "none"])
    argv.extend(
        [
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            str(spec["resources"]["pidsMax"]),
            "--memory",
            str(spec["resources"]["memoryMaxBytes"]),
        ]
    )
    if is_workspace:
        argv.extend(["--cpus", str(parameters["cpuQuotaPercent"] / 100)])
        # The persistent named volume has no portable rootless Podman quota.
        # Its unsupported status is recorded separately; /tmp remains tightly
        # and independently bounded rather than masquerading as that quota.
        tmpfs_size = 16 * 1024 * 1024
        volume_name = parameters["volumeName"]
        if _WORKSPACE_VOLUME_ARG.fullmatch(f"{volume_name}:/workspace:rw") is None:
            raise EngineError("workspace volume name is not daemon-owned")
        argv.extend(["--volume", f"{volume_name}:/workspace:rw"])
        for cache in parameters["cacheVolumes"]:
            cache_arg = (
                f"{cache_volume_name(parameters['workspaceId'], cache['volumeId'])}:"
                f"{cache['mountPath']}"
                f":{'ro' if cache['readOnly'] else 'rw'}"
            )
            if _CACHE_VOLUME_ARG.fullmatch(cache_arg) is None:
                raise EngineError("cache volume mount is not daemon-owned")
            argv.extend(["--volume", cache_arg])
        argv.extend(["--workdir", "/workspace"])
    elif is_agent_run:
        argv.extend(["--cpus", str(spec["resources"]["cpuQuotaPercent"] / 100)])
        # The read-only ephemeral workload has no other writable filesystem,
        # so its exact requested disk ceiling is enforced by /tmp.
        tmpfs_size = spec["resources"]["diskMaxBytes"]
    else:
        # Capsule, browser, and terminal workloads retain their fixed limits;
        # validators carry explicit values through their dedicated path.
        argv.extend(["--cpus", "1.0"])
        tmpfs_size = 16 * 1024 * 1024
    argv.extend(
        [
            "--tmpfs",
            f"/tmp:rw,noexec,nosuid,nodev,size={tmpfs_size}",
            "--pull",
            "never",
            "--stop-signal",
            "SIGKILL",
            "--stop-timeout",
            "2",
            "--entrypoint",
            "/bin/sh",
            "--quiet",
        ]
    )
    for key in sorted(env):
        argv.extend(["--env", f"{key}={env[key]}"])
    argv.extend([spec["image"]["reference"], "-c", _WORKLOAD_TEMPLATE])
    assert_create_argv_hardened(argv)
    return argv


def assert_create_argv_hardened(argv: Sequence[str]) -> None:
    """Re-assert the constructed argv against the fixed flag allowlist."""

    flags = {item for item in argv if item.startswith("--")}
    unknown = flags - _ALLOWED_CREATE_FLAGS
    if unknown:
        raise EngineError(f"constructed argv carries unapproved flags: {sorted(unknown)}")
    text = list(argv)
    for forbidden in ("--privileged", "--device", "--mount", "--cap-add", "--userns"):
        if forbidden in text:
            raise EngineError(f"constructed argv carries a forbidden flag: {forbidden}")
    volumes = [text[index + 1] for index, item in enumerate(text) if item == "--volume" and index + 1 < len(text)]
    if len(volumes) != text.count("--volume"):
        raise EngineError("a volume flag is malformed")
    workspace_volumes = [item for item in volumes if _WORKSPACE_VOLUME_ARG.fullmatch(item)]
    if volumes:
        if len(workspace_volumes) != 1:
            raise EngineError("exactly one daemon-owned workspace volume at /workspace is required")
        if any(
            _CACHE_VOLUME_ARG.fullmatch(item) is None and item not in workspace_volumes
            for item in volumes
        ):
            raise EngineError("volumes must be daemon-owned named volumes below /workspace")
        if any(".." in item or "," in item for item in volumes):
            raise EngineError("volume arguments are unsafe")
    if "--network" in text:
        position = text.index("--network")
        if position + 1 >= len(text) or text[position + 1] != "none":
            raise EngineError("constructed argv carries an unapproved network mode")
    if any(value in {"host", "container", "ns"} for value in text):
        raise EngineError("constructed argv references a host or shared namespace")
    if any(CONTROL_PLANE_SOCKETS & {item} for item in text):
        raise EngineError("constructed argv references a control-plane socket")


def build_validator_create_argv(spec: Mapping[str, Any]) -> list[str]:
    """Build the sealed validator-run create argv.

    Tighter than any other workload: no environment, no named volumes, no
    network, read-only root, one read-only bind of the immutable staging tree
    at /validator, and the digest-bound command as the entrypoint.
    """

    parameters = spec["parameters"]
    staging = parameters["stagingPath"]
    command = list(parameters["command"])
    mount = f"type=bind,src={staging},dst=/validator,readonly,relabel=private"
    argv = [
        "create",
        "--name",
        container_name(spec["workloadId"]),
        "--label",
        MANAGED_LABEL,
        "--label",
        f"{WORKLOAD_LABEL}={spec['workloadId']}",
        "--label",
        f"{KIND_LABEL}={spec['kind']}",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        str(spec["resources"]["pidsMax"]),
        "--memory",
        str(spec["resources"]["memoryMaxBytes"]),
        "--cpus",
        str(spec["resources"]["cpuQuotaPercent"] / 100),
        "--mount",
        mount,
        "--tmpfs",
        f"/tmp:rw,noexec,nosuid,nodev,size={min(spec['resources']['diskMaxBytes'], 1024**3)}",
        "--pull",
        "never",
        "--stop-signal",
        "SIGKILL",
        "--stop-timeout",
        "2",
        "--workdir",
        "/validator",
        "--entrypoint",
        command[0],
        "--quiet",
        spec["image"]["reference"],
        *command[1:],
    ]
    assert_validator_argv_hardened(argv, staging=staging)
    return argv


def assert_validator_argv_hardened(argv: Sequence[str], *, staging: str) -> None:
    """Fail-closed re-assertion of the sealed validator argv."""

    flags = {item for item in argv if item.startswith("--")}
    unknown = flags - _ALLOWED_CREATE_FLAGS
    if unknown:
        raise EngineError(f"constructed validator argv carries unapproved flags: {sorted(unknown)}")
    text = list(argv)
    for forbidden in ("--privileged", "--device", "--cap-add", "--userns", "--env", "--volume"):
        if forbidden in text:
            raise EngineError(f"constructed validator argv carries a forbidden flag: {forbidden}")
    mounts = [text[index + 1] for index, item in enumerate(text) if item == "--mount" and index + 1 < len(text)]
    expected = f"type=bind,src={staging},dst=/validator,readonly,relabel=private"
    if mounts != [expected]:
        raise EngineError("validator argv must carry exactly the sealed read-only staging mount")
    position = text.index("--network")
    if text[position + 1] != "none":
        raise EngineError("validator argv must disable the network")
    if any(value in {"host", "container", "ns"} for value in text):
        raise EngineError("constructed validator argv references a host or shared namespace")
    if any(CONTROL_PLANE_SOCKETS & {item} for item in text):
        raise EngineError("constructed validator argv references a control-plane socket")


class PodmanCliEngine:
    """Rootless Podman over the CLI, optionally against the owned socket."""

    def __init__(
        self,
        *,
        binary: str = "podman",
        socket_path: str | None = None,
        runner: Any = subprocess.run,
    ) -> None:
        if socket_path is not None:
            normalized = os.path.normpath(socket_path)
            if normalized in CONTROL_PLANE_SOCKETS or not normalized.startswith("/"):
                raise EngineError(
                    f"engine socket {socket_path!r} is a control-plane or relative path; refused"
                )
            socket_path = normalized
        self._binary = binary
        self._socket_path = socket_path
        self._runner = runner

    @property
    def identity(self) -> dict[str, str]:
        return {
            "engine": f"{self._binary}-cli",
            "socket": self._socket_path or "default-rootless",
        }

    def _env(self) -> dict[str, str]:
        env = dict(os.environ)
        env.pop("DOCKER_HOST", None)
        if self._socket_path is not None:
            env["CONTAINER_HOST"] = f"unix://{self._socket_path}"
        else:
            env.pop("CONTAINER_HOST", None)
        return env

    def _run(self, args: Sequence[str], *, timeout: int = MAX_REQUEST_TIMEOUT_SECONDS) -> subprocess.CompletedProcess[str]:
        if any(item in CONTROL_PLANE_SOCKETS for item in args):
            raise EngineError("engine invocation references a control-plane socket")
        try:
            completed = self._runner(
                [self._binary, *args],
                capture_output=True,
                text=True,
                timeout=timeout,
                env=self._env(),
                stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired as exc:
            raise EngineError(f"engine call timed out: {args[0]}") from exc
        except FileNotFoundError as exc:
            raise EngineError(f"engine binary is unavailable: {self._binary}") from exc
        return completed

    def _require_ok(self, completed: subprocess.CompletedProcess[str], action: str) -> str:
        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip()
            raise EngineError(f"{action} failed: {detail[:300]}")
        return completed.stdout.strip()

    def version(self) -> dict[str, str]:
        out = self._require_ok(self._run(["version", "--format", "json"], timeout=30), "podman version")
        try:
            parsed = json.loads(out)
            return {"engine": "podman", "engineVersion": str(parsed.get("Client", {}).get("Version", "unknown"))}
        except (ValueError, AttributeError):
            return {"engine": "podman", "engineVersion": "unknown"}

    def _inspect_volume(self, name: str) -> dict[str, Any] | None:
        completed = self._run(
            ["volume", "inspect", "--format", "{{json .}}", name], timeout=60
        )
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).lower()
            if "no such volume" in detail or "not found" in detail:
                return None
            observed = completed.stderr.strip() or completed.stdout.strip()
            raise EngineError(f"volume inspect failed: {observed[:300]}")
        try:
            value = json.loads(completed.stdout)
        except ValueError as exc:
            raise EngineError("volume inspect returned malformed JSON") from exc
        if not isinstance(value, Mapping):
            raise EngineError("volume inspect returned an invalid shape")
        return dict(value)

    def _assert_volume(self, name: str, labels: Mapping[str, str]) -> None:
        info = self._inspect_volume(name)
        if info is None:
            raise EngineError(f"daemon-owned volume {name} is absent")
        observed_labels = info.get("Labels") or {}
        if not isinstance(observed_labels, Mapping) or any(
            observed_labels.get(key) != value for key, value in labels.items()
        ):
            raise EngineError(
                f"volume {name} exists without the exact daemon ownership labels"
            )

    def _ensure_volume(self, name: str, labels: Mapping[str, str]) -> None:
        args = ["volume", "create"]
        for key in sorted(labels):
            args.extend(["--label", f"{key}={labels[key]}"])
        args.append(name)
        completed = self._run(args, timeout=60)
        if completed.returncode != 0 and "already exists" not in completed.stderr.lower():
            detail = completed.stderr.strip() or completed.stdout.strip()
            raise EngineError(f"volume create failed: {detail[:300]}")
        # Creating an existing volume does not replace its labels. Exact
        # post-create inspection closes foreign pre-creation and name races.
        self._assert_volume(name, labels)

    @staticmethod
    def _workspace_volume_claims(
        spec: Mapping[str, Any],
    ) -> list[tuple[str, dict[str, str]]]:
        parameters = spec["parameters"]
        workspace_id = parameters["workspaceId"]
        claims = [
            (
                parameters["volumeName"],
                {
                    VOLUME_MANAGED_LABEL: "true",
                    VOLUME_KIND_LABEL: "workspace",
                    VOLUME_WORKSPACE_LABEL: workspace_id,
                    VOLUME_ID_LABEL: workspace_id,
                    VOLUME_DISK_LIMIT_LABEL: "unsupported",
                },
            )
        ]
        for cache in parameters["cacheVolumes"]:
            claims.append(
                (
                    cache_volume_name(workspace_id, cache["volumeId"]),
                    {
                        VOLUME_MANAGED_LABEL: "true",
                        VOLUME_KIND_LABEL: "cache",
                        VOLUME_WORKSPACE_LABEL: workspace_id,
                        VOLUME_ID_LABEL: cache["volumeId"],
                        VOLUME_DISK_LIMIT_LABEL: "unsupported",
                    },
                )
            )
        return claims

    def verify_workspace_volumes(self, spec: Mapping[str, Any]) -> None:
        for name, labels in self._workspace_volume_claims(spec):
            self._assert_volume(name, labels)

    @staticmethod
    def resource_enforcement(spec: Mapping[str, Any]) -> dict[str, Any]:
        if spec["kind"] != "workspace":
            return {}
        return {
            "persistentVolumeDiskMaxBytes": {
                "status": "unsupported",
                "requestedBytes": spec["parameters"]["diskMaxBytes"],
                "detail": (
                    "portable rootless Podman named volumes do not expose an "
                    "enforceable per-volume byte quota"
                ),
            }
        }

    def create(self, spec: Mapping[str, Any], *, timeout: int | None = None) -> str:
        if spec["kind"] == "workspace":
            for name, labels in self._workspace_volume_claims(spec):
                self._ensure_volume(name, labels)
        argv = build_create_argv(spec)
        return self._require_ok(
            self._run(argv, timeout=timeout or MAX_REQUEST_TIMEOUT_SECONDS), "workload create"
        )

    def start(self, workload_id: str, *, timeout: int | None = None) -> None:
        self._require_ok(
            self._run(
                ["start", container_name(workload_id)],
                timeout=timeout or MAX_REQUEST_TIMEOUT_SECONDS,
            ),
            "workload start",
        )

    def stop(self, workload_id: str, *, timeout: int = 2) -> None:
        completed = self._run(["stop", "--time", str(timeout), container_name(workload_id)])
        if completed.returncode != 0 and "no such container" not in completed.stderr.lower():
            raise EngineError(f"workload stop failed: {completed.stderr.strip()[:300]}")

    def kill(self, workload_id: str) -> None:
        completed = self._run(["kill", container_name(workload_id)])
        if completed.returncode != 0 and "no such container" not in completed.stderr.lower():
            raise EngineError(f"workload kill failed: {completed.stderr.strip()[:300]}")

    def open_terminal(
        self,
        workload_id: str,
        *,
        columns: int,
        rows: int,
        shell: Sequence[str] = ("/bin/sh",),
    ) -> tuple[subprocess.Popen[bytes], int]:
        """Attach the sealed workspace shell to a running container via a PTY.

        There is deliberately no free-form command argument: the shell argv
        comes from the sealed workspace spec, is passed as exact exec argv
        (never shell-joined), and can only enter the workspace container.
        """

        if isinstance(columns, bool) or not isinstance(columns, int) or not 1 <= columns <= 1000:
            raise EngineError("terminal columns are outside policy")
        if isinstance(rows, bool) or not isinstance(rows, int) or not 1 <= rows <= 1000:
            raise EngineError("terminal rows are outside policy")
        if not shell or len(shell) > 32 or any(not isinstance(item, str) or "\x00" in item for item in shell):
            raise EngineError("terminal shell argv is outside policy")
        master_fd, slave_fd = pty.openpty()
        try:
            termios.tcsetattr(slave_fd, termios.TCSANOW, termios.tcgetattr(slave_fd))
            fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))
            process = subprocess.Popen(
                [
                    self._binary,
                    "exec",
                    "--interactive",
                    "--tty",
                    "--env",
                    "TERM=xterm-256color",
                    container_name(workload_id),
                    *shell,
                ],
                env=self._env(),
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                start_new_session=True,
                close_fds=True,
            )
        except Exception as exc:
            os.close(slave_fd)
            os.close(master_fd)
            raise EngineError(f"terminal attach failed: {exc}") from exc
        os.close(slave_fd)
        os.set_blocking(master_fd, False)
        return process, master_fd

    @staticmethod
    def resize_terminal(master_fd: int, *, columns: int, rows: int) -> None:
        if isinstance(columns, bool) or not isinstance(columns, int) or not 1 <= columns <= 1000:
            raise EngineError("terminal columns are outside policy")
        if isinstance(rows, bool) or not isinstance(rows, int) or not 1 <= rows <= 1000:
            raise EngineError("terminal rows are outside policy")
        try:
            fcntl.ioctl(master_fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))
        except OSError as exc:
            raise EngineError(f"terminal resize failed: {exc}") from exc

    def exec_workload(
        self,
        workload_id: str,
        argv: Sequence[str],
        *,
        timeout: int,
        max_bytes: int,
    ) -> dict[str, Any]:
        """Run one typed argv inside a running workspace; no shell joining."""

        if not argv or len(argv) > 32 or any(not isinstance(item, str) or "\x00" in item for item in argv):
            raise EngineError("exec argv is outside policy")
        completed = self._run(
            ["exec", container_name(workload_id), *argv],
            timeout=timeout,
        )
        data = (completed.stdout + completed.stderr).encode("utf-8", "replace")
        # The receipt contract bounds exitStatus to [-1, 255]; a signal-killed
        # command (negative returncode) is reported as -1, never fabricated.
        exit_status = max(-1, min(255, completed.returncode))
        return {
            "exitStatus": exit_status,
            "output": data[:max_bytes].decode("utf-8", "replace"),
            "byteCount": min(len(data), max_bytes),
            "truncated": len(data) > max_bytes,
        }

    def remove(self, workload_id: str, *, force: bool = True) -> None:
        args = ["rm"]
        if force:
            args.append("--force")
        args.append(container_name(workload_id))
        completed = self._run(args)
        if completed.returncode != 0 and "no such container" not in completed.stderr.lower():
            raise EngineError(f"workload remove failed: {completed.stderr.strip()[:300]}")

    def inspect(self, workload_id: str) -> dict[str, Any]:
        out = self._run(
            [
                "inspect",
                "--format",
                "{{json .}}",
                container_name(workload_id),
            ]
        )
        if out.returncode != 0:
            return {"present": False}
        try:
            raw = json.loads(out.stdout)
        except ValueError as exc:
            raise EngineError("engine inspect returned malformed JSON") from exc
        state = raw.get("State", {}) if isinstance(raw, Mapping) else {}
        config = raw.get("Config", {}) if isinstance(raw, Mapping) else {}
        return {
            "present": True,
            "status": str(state.get("Status", "unknown")),
            "running": bool(state.get("Running", False)),
            "exitStatus": state.get("ExitCode") if "ExitCode" in state else None,
            "startedAt": state.get("StartedAt") or None,
            "finishedAt": state.get("FinishedAt") or None,
            "imageDigest": raw.get("ImageDigest") or None,
            "imageReference": config.get("Image") or raw.get("ImageName") or None,
            "labels": dict(config.get("Labels") or {}),
        }

    def logs(self, workload_id: str, *, max_bytes: int) -> dict[str, Any]:
        """Drain CLI pipes with a bounded prefix, never capture the whole log.

        Continue draining without retaining overflow so a natural nonzero exit
        remains an error. Stderr is discarded, not copied to public diagnostics.
        The fixed timeout also bounds an endless or stalled log producer.
        """
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 1 <= max_bytes <= MAX_OUTPUT_BYTES:
            raise EngineError("log byte bound is outside policy")
        deadline = time.monotonic() + min(30, MAX_REQUEST_TIMEOUT_SECONDS)
        try:
            process = subprocess.Popen(
                [self._binary, "logs", container_name(workload_id)],
                env=self._env(), stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except OSError:
            raise EngineError("workload logs could not start; check the execution engine") from None
        retained = bytearray()
        truncated = False
        selector = selectors.DefaultSelector()
        assert process.stdout is not None and process.stderr is not None
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        try:
            while selector.get_map():
                remaining_time = deadline - time.monotonic()
                if remaining_time <= 0:
                    raise EngineError("workload logs timed out; retry after checking the execution engine")
                for key, _ in selector.select(timeout=min(0.05, remaining_time)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                    elif key.data == "stdout":
                        remaining_bytes = max_bytes - len(retained)
                        retained.extend(chunk[:remaining_bytes])
                        truncated = truncated or len(chunk) > remaining_bytes
            try:
                returncode = process.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                raise EngineError("workload logs timed out; retry after checking the execution engine") from None
            if returncode != 0:
                raise EngineError("workload logs failed; check workload state and the execution engine")
        except OSError:
            raise EngineError("workload logs could not be read; check the execution engine") from None
        finally:
            selector.close()
            process.stdout.close()
            process.stderr.close()
            # Kill only this newly-created CLI process group, including a child
            # that retained a pipe after its leader exited. Never signal a
            # workload container or a shared engine process.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                raise EngineError("workload log reader cleanup did not complete") from None
        decoded = retained.decode("utf-8", "replace").encode("utf-8")
        if len(decoded) > max_bytes:
            truncated = True
        output = decoded[:max_bytes].decode("utf-8", "ignore")
        return {"bytes": output, "byteCount": len(output.encode("utf-8")), "truncated": truncated}

    def list_managed(self) -> list[dict[str, Any]]:
        completed = self._run(
            ["ps", "--all", "--filter", f"label={MANAGED_LABEL}", "--format", "json"]
        )
        if completed.returncode != 0:
            raise EngineError(f"managed enumeration failed: {completed.stderr.strip()[:300]}")
        try:
            entries = json.loads(completed.stdout or "[]")
        except ValueError as exc:
            raise EngineError("managed enumeration returned malformed JSON") from exc
        managed: list[dict[str, Any]] = []
        for entry in entries:
            labels = entry.get("Labels") or {}
            if isinstance(labels, str):
                labels = dict(
                    item.split("=", 1) for item in labels.split(",") if "=" in item
                )
            workload = labels.get(WORKLOAD_LABEL)
            managed.append(
                {
                    "workloadId": workload,
                    "state": str(entry.get("State", "unknown")),
                    "labels": labels,
                }
            )
        return managed
