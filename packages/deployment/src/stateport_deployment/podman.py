"""Rootless local Podman execution adapter.

The adapter owns only low-level effects and observations.  It never decides
authority or accepted deployment state.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import signal
import shutil
import socket
import stat
import subprocess
import tempfile
import tarfile
import time
from typing import Any, Mapping, Sequence

from .contracts import ARCHITECTURE, TARGET_ADAPTER
from .errors import AdapterError, DeploymentRefusal
from .inspection import sanitized_git_command, sanitized_git_environment
from .util import DIGEST, confined, digest_value, ensure_private_directory, relative_posix, safe_id, timestamp


MAX_OUTPUT_BYTES = 1_048_576
MAX_BUILD_CONTEXT_BYTES = 512 * 1024 * 1024
MAX_BACKUP_ARCHIVE_BYTES = 1024 * 1024 * 1024
MAX_BACKUP_ARCHIVE_MEMBERS = 100_000
LABEL_MANAGED = "io.stateport.deployment.managed"
LABEL_DEPLOYMENT = "io.stateport.deployment.id"
LABEL_SERVICE = "io.stateport.deployment.service"
LABEL_PLAN = "io.stateport.deployment.plan"
LABEL_SOURCE = "io.stateport.deployment.source"
LABEL_REVISION = "io.stateport.deployment.revision"
LABEL_STORAGE = "io.stateport.deployment.storage"
LABEL_NETWORK = "io.stateport.deployment.network"
_SECRET = re.compile(
    r"(?:-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |OPENSSH |EC )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,}|AKIA[A-Z0-9]{16}|STATEPORT_TEST_SECRET_[A-Za-z0-9_-]+)"
)


def _redact(text: str) -> str:
    return _SECRET.sub("[REDACTED]", text)


def _bounded(raw: bytes) -> str:
    if len(raw) > MAX_OUTPUT_BYTES:
        raw = raw[:MAX_OUTPUT_BYTES] + b"\n[truncated]"
    return _redact(raw.decode("utf-8", errors="replace"))


def _bounded_stream(raw: bytearray, truncated: bool) -> str:
    value = bytes(raw)
    if truncated:
        value += b"\n[truncated]"
    return _redact(value.decode("utf-8", errors="replace"))


def _image_identity(value: object) -> str | None:
    if isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        return value
    if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value):
        return f"sha256:{value}"
    return None


def _file_digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return f"sha256:{hasher.hexdigest()}"


def _memory_bytes(value: str) -> int:
    match = re.fullmatch(r"([1-9][0-9]*)([kKmMgG]?)", value)
    if match is None:
        raise AdapterError("invalid_contract", "memory limit is invalid")
    scale = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3}
    return int(match.group(1)) * scale[match.group(2).lower()]


def _environment_mapping(value: object) -> dict[str, str] | None:
    if not isinstance(value, list):
        return None
    parsed: dict[str, str] = {}
    for item in value:
        if not isinstance(item, str) or "=" not in item:
            return None
        key, content = item.split("=", 1)
        if not key or key in parsed:
            return None
        parsed[key] = content
    return parsed


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "argv": list(self.argv),
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
        }


class RootlessPodmanAdapter:
    """A strict, label-bound local Podman adapter for Linux AMD64."""

    def __init__(
        self,
        *,
        executable: str = "podman",
        timeout_seconds: int = 300,
        engine_socket: str | None = None,
        backup_root: Path | str | None = None,
    ) -> None:
        if not isinstance(executable, str) or not executable or Path(executable).name != executable:
            raise DeploymentRefusal("invalid_adapter", "Podman executable must be a bare command name")
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or timeout_seconds <= 0:
            raise DeploymentRefusal("invalid_adapter", "adapter timeout must be positive")
        resolved = shutil.which(executable)
        if resolved is None:
            raise AdapterError("podman_unavailable", "rootless Podman is not installed or not on PATH")
        if engine_socket is not None:
            normalized_socket = os.path.normpath(engine_socket)
            if (
                not os.path.isabs(normalized_socket)
                or normalized_socket
                in {
                    "/run/podman/podman.sock",
                    "/var/run/podman/podman.sock",
                    "/run/docker.sock",
                    "/var/run/docker.sock",
                }
            ):
                raise DeploymentRefusal(
                    "invalid_adapter",
                    "deployment engine socket must be the confined execution user's rootless socket",
                )
            engine_socket = normalized_socket
        self.executable = resolved
        self.timeout_seconds = timeout_seconds
        self.engine_socket = engine_socket
        if backup_root is not None:
            backup_root = Path(backup_root)
            if not backup_root.is_absolute():
                raise DeploymentRefusal(
                    "invalid_adapter", "deployment backup root must be absolute"
                )
        self.backup_root = backup_root
        allowed_environment = {
            "HOME",
            "PATH",
            "LANG",
            "LC_ALL",
            "TMPDIR",
            "XDG_RUNTIME_DIR",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "XDG_CACHE_HOME",
            "DBUS_SESSION_BUS_ADDRESS",
        }
        self.environment = {
            key: value
            for key, value in os.environ.items()
            if key in allowed_environment and value
        }
        if engine_socket is not None:
            self.environment["CONTAINER_HOST"] = f"unix://{engine_socket}"

    def _run(
        self,
        argv: Sequence[str],
        *,
        timeout: int | None = None,
        input_bytes: bytes | None = None,
        check: bool = True,
    ) -> CommandResult:
        if not argv or any(not isinstance(item, str) or not item or "\x00" in item for item in argv):
            raise AdapterError("invalid_command", "adapter command must be a bounded argv vector")
        if input_bytes is not None and len(input_bytes) > MAX_OUTPUT_BYTES:
            raise AdapterError("invalid_command", "adapter stdin exceeds the bounded input limit")
        effective_timeout = self.timeout_seconds if timeout is None else timeout
        if (
            isinstance(effective_timeout, bool)
            or not isinstance(effective_timeout, int)
            or effective_timeout <= 0
        ):
            raise AdapterError("invalid_command", "adapter timeout must be positive")
        command = (self.executable, *argv)
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self.environment,
                shell=False,
                start_new_session=True,
            )
        except OSError as exc:
            raise AdapterError("podman_unavailable", "Podman could not be started") from exc

        if input_bytes is not None:
            assert process.stdin is not None
            try:
                process.stdin.write(input_bytes)
                process.stdin.close()
            except BrokenPipeError:
                pass

        stdout_stream = process.stdout
        stderr_stream = process.stderr
        streams = {stdout_stream: bytearray(), stderr_stream: bytearray()}
        truncated = {process.stdout: False, process.stderr: False}
        selector = selectors.DefaultSelector()
        for stream in streams:
            assert stream is not None
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        deadline = time.monotonic() + effective_timeout
        timed_out = False
        termination_started: float | None = None
        drain_deadline: float | None = None
        captured_bytes = 0

        def signal_group(value: signal.Signals) -> None:
            try:
                os.killpg(process.pid, value)
            except ProcessLookupError:
                return
            except OSError as exc:
                raise AdapterError(
                    "podman_unavailable",
                    "Podman process group could not be terminated safely",
                ) from exc

        try:
            while selector.get_map():
                now = time.monotonic()
                remaining = deadline - now
                if not timed_out and remaining <= 0:
                    timed_out = True
                    termination_started = now
                    signal_group(signal.SIGTERM)
                if (
                    timed_out
                    and termination_started is not None
                    and process.poll() is None
                    and now - termination_started >= 1.0
                ):
                    signal_group(signal.SIGKILL)
                if process.poll() is not None and drain_deadline is None:
                    drain_deadline = now + 1.0
                if drain_deadline is not None and now >= drain_deadline:
                    # A descendant inherited a pipe after the command exited.
                    # Bound the drain and terminate the isolated process group
                    # so no hidden helper can outlive the recorded operation.
                    signal_group(signal.SIGKILL)
                    for key in list(selector.get_map().values()):
                        selector.unregister(key.fileobj)
                    break
                wait_for = 0.1
                if not timed_out:
                    wait_for = min(wait_for, max(0.0, remaining))
                if drain_deadline is not None:
                    wait_for = min(
                        wait_for, max(0.0, drain_deadline - now)
                    )
                events = selector.select(wait_for)
                for key, _mask in events:
                    stream = key.fileobj
                    chunk = os.read(stream.fileno(), 65_536)
                    if not chunk:
                        selector.unregister(stream)
                        continue
                    available = max(0, MAX_OUTPUT_BYTES - captured_bytes)
                    streams[stream].extend(chunk[:available])
                    captured_bytes += min(len(chunk), available)
                    if len(chunk) > available:
                        truncated[stream] = True
            if process.poll() is None:
                signal_group(signal.SIGKILL)
            returncode = process.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired) as exc:
            signal_group(signal.SIGKILL)
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired as wait_exc:
                raise AdapterError(
                    "podman_unavailable",
                    "Podman process group did not terminate",
                ) from wait_exc
            if isinstance(exc, subprocess.TimeoutExpired):
                timed_out = True
            else:
                raise AdapterError("podman_unavailable", "Podman output could not be read") from exc
            returncode = process.returncode
        finally:
            selector.close()
            for stream in streams:
                if stream is not None:
                    stream.close()
        if timed_out:
            raise AdapterError(
                "adapter_timeout",
                f"Podman operation timed out: {argv[0]}",
                details={"operation": argv[0], "processId": process.pid},
            )
        stdout = _bounded_stream(streams[stdout_stream], truncated[stdout_stream])
        stderr = _bounded_stream(streams[stderr_stream], truncated[stderr_stream])
        result = CommandResult(tuple(command), returncode, stdout, stderr)
        if check and result.returncode != 0:
            raise AdapterError(
                "podman_command_failed",
                f"Podman operation failed: {argv[0]}",
                details={"operation": argv[0], "returncode": result.returncode, "stderr": result.stderr[-4000:]},
            )
        return result

    def probe(self) -> dict[str, Any]:
        result = self._run(("info", "--format", "json"), timeout=30)
        try:
            value = json.loads(result.stdout)
            host = value["host"]
            store = value["store"]
            rootless = host["security"]["rootless"]
            arch = host["arch"]
            operating_system = host["os"]
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise AdapterError("target_probe_invalid", "Podman returned an invalid target probe") from exc
        if rootless is not True:
            raise AdapterError("rootless_required", "StatePort alpha deployments require rootless Podman")
        service_is_remote = host.get("serviceIsRemote")
        if self.engine_socket is None and service_is_remote is not False:
            raise AdapterError("local_target_required", "local deployment refuses a remote Podman service")
        if self.engine_socket is not None:
            try:
                socket_identity = os.lstat(self.engine_socket)
            except OSError as exc:
                raise AdapterError(
                    "podman_unavailable", "the confined execution engine socket is unavailable"
                ) from exc
            if (
                service_is_remote is not True
                or stat.S_ISLNK(socket_identity.st_mode)
                or not stat.S_ISSOCK(socket_identity.st_mode)
                or socket_identity.st_uid != os.geteuid()
            ):
                raise AdapterError(
                    "local_target_required",
                    "the deployment client is not bound to the local execution user's rootless service",
                )
        if arch not in {"amd64", "x86_64"} or operating_system != "linux":
            raise AdapterError("unsupported_target", "StatePort alpha supports Linux AMD64 only")
        version = self._run(("version", "--format", "json"), timeout=30)
        try:
            version_value = json.loads(version.stdout)
        except json.JSONDecodeError as exc:
            raise AdapterError("target_probe_invalid", "Podman returned invalid version data") from exc
        observed = {
            "adapter": TARGET_ADAPTER,
            "targetId": "local",
            "architecture": ARCHITECTURE,
            "rootless": True,
            "uid": os.getuid(),
            "podmanVersion": version_value.get("Client", {}).get("Version") or version_value.get("Version"),
            "operatingSystem": operating_system,
            "serviceIsRemote": False,
            "networkBackend": host.get("networkBackend"),
            "rootlessNetworkCommand": host.get("rootlessNetworkCmd"),
            "graphRoot": store.get("graphRoot"),
            "runRoot": store.get("runRoot"),
            "volumePath": store.get("volumePath"),
        }
        if self.engine_socket is not None:
            # Podman calls this a remote client, but the target remains the
            # local execution user's engine on the same host. Bind that
            # confined transport into target identity without relabelling the
            # deployment as a remote target.
            observed["executionTransport"] = "confined-local-rootless-socket"
        return {**observed, "identityDigest": digest_value(observed)}

    def _assert_target_identity(self, spec: Mapping[str, Any]) -> dict[str, Any]:
        observed = self.probe()
        if observed["identityDigest"] != spec["target"]["identityDigest"]:
            raise AdapterError(
                "target_identity_changed",
                "local Podman target identity changed after planning",
            )
        return observed

    @staticmethod
    def _slug(deployment_id: str) -> str:
        safe_id(deployment_id, "deployment id")
        normalized = re.sub(r"[^a-z0-9]+", "-", deployment_id.lower()).strip("-")[:28] or "deployment"
        return f"sp-{normalized}-{digest_value(deployment_id)[7:15]}"

    @classmethod
    def resource_names(cls, spec: Mapping[str, Any]) -> dict[str, Any]:
        deployment_id = spec["metadata"]["deploymentId"]
        slug = cls._slug(deployment_id)
        return {
            "slug": slug,
            "containers": {service["id"]: f"{slug}-{service['id']}" for service in spec["services"]},
            "images": {service["id"]: f"localhost/{slug}-{service['id']}" for service in spec["services"]},
            "networks": {network["id"]: f"{slug}-net-{network['id']}" for network in spec["networks"]},
            "volumes": {
                storage["id"]: f"{slug}-vol-{storage['id']}"
                for service in spec["services"]
                for storage in service["storage"]
                if storage["persistence"] != "externally_managed"
            },
        }

    def _backup_directory(
        self, spec: Mapping[str, Any], backup_id: str
    ) -> Path:
        if self.backup_root is None:
            raise AdapterError(
                "backup_unavailable",
                "deployment backup storage is not configured on the execution host",
            )
        safe_id(backup_id, "backup id")
        deployment_root = self.backup_root / self._slug(
            spec["metadata"]["deploymentId"]
        )
        ensure_private_directory(self.backup_root)
        ensure_private_directory(deployment_root)
        return confined(
            deployment_root,
            backup_id,
            "deployment backup",
            must_exist=False,
        )

    @staticmethod
    def _archive_evidence(path: Path) -> dict[str, Any]:
        if path.is_symlink() or not path.is_file():
            raise AdapterError(
                "backup_verification_failed", "deployment backup archive is unsafe"
            )
        size = path.stat().st_size
        if size > MAX_BACKUP_ARCHIVE_BYTES:
            raise AdapterError(
                "backup_size_exceeded", "deployment backup archive exceeds its bound"
            )
        file_count = 0
        try:
            with tarfile.open(path, mode="r:*") as archive:
                members = archive.getmembers()
                if len(members) > MAX_BACKUP_ARCHIVE_MEMBERS:
                    raise AdapterError(
                        "backup_size_exceeded",
                        "deployment backup archive contains too many entries",
                    )
                for member in members:
                    normalized = PurePosixPath(member.name)
                    if (
                        normalized.is_absolute()
                        or ".." in normalized.parts
                        or member.isdev()
                    ):
                        raise AdapterError(
                            "backup_verification_failed",
                            "deployment backup archive contains an unsafe entry",
                        )
                    if member.isfile():
                        file_count += 1
        except (tarfile.TarError, OSError) as exc:
            raise AdapterError(
                "backup_verification_failed", "deployment backup archive is malformed"
            ) from exc
        return {
            "contentDigest": _file_digest(path),
            "fileCount": file_count,
            "bytes": size,
        }

    def _export_volume(self, volume_name: str, destination: Path) -> dict[str, Any]:
        if destination.exists() or destination.is_symlink():
            raise AdapterError(
                "backup_conflict", "deployment backup archive already exists"
            )
        self._run(
            (
                "volume",
                "export",
                "--output",
                str(destination),
                volume_name,
            ),
            timeout=900,
        )
        try:
            destination.chmod(0o600)
        except OSError as exc:
            raise AdapterError(
                "backup_verification_failed",
                "deployment backup archive permissions could not be secured",
            ) from exc
        return self._archive_evidence(destination)

    def _import_volume(self, volume_name: str, source: Path) -> None:
        self._run(
            ("volume", "import", volume_name, str(source)), timeout=900
        )

    def _inspect(self, kind: str, name: str) -> dict[str, Any] | None:
        result = self._run((kind, "inspect", name), timeout=20, check=False)
        if result.returncode != 0:
            lowered = (result.stderr + result.stdout).lower()
            if (
                "no such" in lowered
                or "not found" in lowered
                or "does not exist" in lowered
                or "image not known" in lowered
            ):
                return None
            raise AdapterError("runtime_observation_failed", f"could not inspect Podman {kind}: {name}")
        try:
            parsed = json.loads(result.stdout)
            if isinstance(parsed, list):
                parsed = parsed[0]
            if not isinstance(parsed, dict):
                raise ValueError
            return parsed
        except (json.JSONDecodeError, ValueError, IndexError) as exc:
            raise AdapterError("runtime_observation_failed", f"Podman {kind} inspection was malformed") from exc

    @staticmethod
    def _labels(value: Mapping[str, Any] | None) -> Mapping[str, str]:
        if not value:
            return {}
        labels = value.get("Labels") or value.get("labels") or value.get("Config", {}).get("Labels")
        return labels if isinstance(labels, Mapping) else {}

    def _assert_owned(self, kind: str, name: str, deployment_id: str) -> dict[str, Any] | None:
        observed = self._inspect(kind, name)
        if observed is None:
            return None
        labels = self._labels(observed)
        if labels.get(LABEL_MANAGED) != "true" or labels.get(LABEL_DEPLOYMENT) != deployment_id:
            raise AdapterError("unknown_runtime_residue", f"Podman {kind} name collides with an unmanaged resource: {name}")
        return observed

    def _assert_exact_container(
        self,
        name: str,
        *,
        deployment_id: str,
        service_id: str,
        source_commit: str,
        expected_revision: str | None,
    ) -> dict[str, Any] | None:
        observed = self._assert_owned("container", name, deployment_id)
        if observed is None:
            return None
        labels = self._labels(observed)
        if (
            labels.get(LABEL_SERVICE) != service_id
            or labels.get(LABEL_SOURCE) != source_commit
            or (
                expected_revision is not None
                and (
                    labels.get(LABEL_REVISION) != expected_revision
                    or labels.get(LABEL_PLAN) != expected_revision
                )
            )
        ):
            raise AdapterError(
                "runtime_identity_mismatch",
                f"deployment service identity differs: {service_id}",
            )
        return observed

    def _managed_names(self, kind: str, deployment_id: str) -> set[str]:
        commands = {
            "container": ("ps", "--all"),
            "network": ("network", "ls"),
            "volume": ("volume", "ls"),
            "image": ("images",),
        }
        prefix = commands.get(kind)
        if prefix is None:
            raise AdapterError("runtime_observation_failed", "unsupported managed-resource query")
        result = self._run(
            (
                *prefix,
                "--filter",
                f"label={LABEL_DEPLOYMENT}={deployment_id}",
                "--format",
                "json",
            ),
            timeout=30,
        )
        try:
            values = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise AdapterError("runtime_observation_failed", "managed resource inventory was malformed") from exc
        if not isinstance(values, list):
            raise AdapterError("runtime_observation_failed", "managed resource inventory was malformed")
        names: set[str] = set()
        for value in values:
            if not isinstance(value, Mapping):
                raise AdapterError("runtime_observation_failed", "managed resource inventory was malformed")
            candidate = (
                value.get("Names")
                or value.get("Name")
                or value.get("names")
                or value.get("name")
            )
            if kind == "image" and not candidate:
                candidate = (
                    value.get("Id")
                    or value.get("ID")
                    or value.get("id")
                )
            if isinstance(candidate, list):
                names.update(item for item in candidate if isinstance(item, str))
            elif isinstance(candidate, str):
                names.add(candidate)
        return names

    @staticmethod
    def _label_args(labels: Mapping[str, str]) -> list[str]:
        args: list[str] = []
        for key, value in sorted(labels.items()):
            if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,127}", key) or not isinstance(value, str) or len(value) > 512 or "\x00" in value:
                raise AdapterError("invalid_label", "deployment resource label is invalid")
            args.extend(("--label", f"{key}={value}"))
        return args

    def materialize_context(self, plan: Mapping[str, Any], destination: Path) -> dict[str, Any]:
        if destination.is_symlink() or destination.exists():
            raise AdapterError("build_context_conflict", "exact build context destination must not already exist")
        ensure_private_directory(destination)
        source = plan["spec"]["source"]
        repository = Path(source["repositoryRoot"])
        if repository.is_symlink() or not repository.is_dir():
            raise AdapterError("source_identity_mismatch", "source repository is missing or unsafe")
        try:
            current = subprocess.run(
                sanitized_git_command(
                    repository, "rev-parse", "--verify", source["commit"]
                ),
                capture_output=True,
                text=True,
                env=sanitized_git_environment(),
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AdapterError("source_identity_mismatch", "exact source commit could not be resolved") from exc
        if current.returncode != 0 or current.stdout.strip() != source["commit"]:
            raise AdapterError("source_identity_mismatch", "exact source commit is unavailable")
        total = 0
        written: list[dict[str, Any]] = []
        for item in plan["sourceInventory"]:
            path = destination / item["path"]
            ensure_private_directory(path.parent)
            if path.exists() or path.is_symlink():
                raise AdapterError("build_context_conflict", "source inventory contains a duplicate or unsafe path")
            size_result = subprocess.run(
                sanitized_git_command(
                    repository, "cat-file", "-s", item["objectId"]
                ),
                capture_output=True,
                text=True,
                env=sanitized_git_environment(),
                timeout=20,
                check=False,
            )
            if size_result.returncode != 0:
                raise AdapterError(
                    "source_identity_mismatch",
                    "tracked source blob size is unavailable",
                )
            try:
                size = int(size_result.stdout.strip())
            except ValueError as exc:
                raise AdapterError("source_identity_mismatch", "tracked source blob size is unavailable") from exc
            total += size
            if total > MAX_BUILD_CONTEXT_BYTES:
                raise AdapterError("build_context_too_large", "exact build context exceeds the alpha size limit")
            with path.open("xb") as handle:
                process = subprocess.run(
                    sanitized_git_command(
                        repository, "cat-file", "blob", item["objectId"]
                    ),
                    stdout=handle,
                    stderr=subprocess.PIPE,
                    env=sanitized_git_environment(),
                    timeout=60,
                    check=False,
                )
                handle.flush()
                os.fsync(handle.fileno())
            observed_digest = _file_digest(path)
            if (
                process.returncode != 0
                or path.stat().st_size != size
                or observed_digest != item["contentDigest"]
            ):
                path.unlink(missing_ok=True)
                raise AdapterError("source_identity_mismatch", "tracked source blob could not be materialized exactly")
            path.chmod(0o755 if item["mode"] == "100755" else 0o644)
            written.append(
                {
                    "path": item["path"],
                    "mode": item["mode"],
                    "size": size,
                    "sha256": observed_digest,
                }
            )
        context_digest = digest_value(written)
        return {"path": str(destination), "files": written, "bytes": total, "contextDigest": context_digest}

    def _create_networks_and_volumes(
        self,
        spec: Mapping[str, Any],
        plan_digest: str,
        names: Mapping[str, Any],
    ) -> tuple[dict[str, str], dict[str, str]]:
        deployment_id = spec["metadata"]["deploymentId"]
        base_labels = {
            LABEL_MANAGED: "true",
            LABEL_DEPLOYMENT: deployment_id,
            LABEL_PLAN: plan_digest,
            LABEL_SOURCE: spec["source"]["commit"],
            LABEL_REVISION: plan_digest,
        }
        networks: dict[str, str] = {}
        for network_id, name in names["networks"].items():
            if self._assert_owned("network", name, deployment_id) is not None:
                raise AdapterError("duplicate_deployment", f"deployment network already exists: {name}")
            self._run(
                (
                    "network",
                    "create",
                    "--internal",
                    *self._label_args({**base_labels, LABEL_NETWORK: network_id}),
                    name,
                ),
                timeout=30,
            )
            networks[network_id] = name
        volumes: dict[str, str] = {}
        for storage_id, name in names["volumes"].items():
            observed = self._assert_owned("volume", name, deployment_id)
            if observed is not None:
                raise AdapterError(
                    "duplicate_deployment",
                    f"deployment volume already exists and requires reconciliation: {name}",
                )
            labels = {**base_labels, LABEL_STORAGE: storage_id}
            self._run(("volume", "create", *self._label_args(labels), name), timeout=30)
            volumes[storage_id] = name
        return networks, volumes

    def _build_images(
        self,
        plan: Mapping[str, Any],
        context_root: Path,
        overlay_root: Path,
        names: Mapping[str, Any],
    ) -> tuple[dict[str, str], dict[str, dict[str, str]]]:
        spec = plan["spec"]
        deployment_id = spec["metadata"]["deploymentId"]
        images: dict[str, str] = {}
        materials: dict[str, dict[str, str]] = {}
        for service in spec["services"]:
            service_id = service["id"]
            if service["build"]["mode"] == "image":
                reference = service["image"]["reference"]
                material = self._pull_exact_image(reference)
                images[service_id] = material["imageDigest"]
                materials[service_id] = material
                continue
            build_context = confined(context_root, service["build"]["context"], "build context")
            if service["build"]["generated"]:
                containerfile = confined(overlay_root, service["build"]["containerfile"], "generated Containerfile")
                ignorefile = overlay_root / f"{service_id}.containerignore"
                if ignorefile.is_symlink() or not ignorefile.is_file():
                    raise AdapterError("overlay_missing", "generated build ignore file is missing")
            else:
                containerfile = confined(build_context, service["build"]["containerfile"], "Containerfile")
                ignorefile = None
            try:
                containerfile_text = containerfile.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as exc:
                raise AdapterError(
                    "containerfile_unavailable",
                    "approved Containerfile could not be read exactly",
                ) from exc
            base_matches = re.findall(
                r"(?mi)^\s*FROM\s+([^\s]+)\s*$", containerfile_text
            )
            if len(base_matches) != 1 or "@sha256:" not in base_matches[0]:
                raise AdapterError(
                    "mutable_base_image",
                    "approved Containerfile must bind one exact base image",
                )
            materials[service_id] = self._pull_exact_image(base_matches[0])
            tag = f"{names['images'][service_id]}:{plan['planDigest'][7:19]}"
            labels = {
                LABEL_MANAGED: "true",
                LABEL_DEPLOYMENT: deployment_id,
                LABEL_SERVICE: service_id,
                LABEL_PLAN: plan["planDigest"],
                LABEL_SOURCE: spec["source"]["commit"],
                LABEL_REVISION: plan["planDigest"],
            }
            existing = self._assert_owned("image", tag, deployment_id)
            if existing is not None:
                raise AdapterError(
                    "duplicate_deployment",
                    f"deployment image already exists and requires reconciliation: {service_id}",
                )
            argv = [
                "build",
                "--pull=never",
                "--layers=false",
                "--format=docker",
                "--network=none",
                "--http-proxy=false",
                "--file",
                str(containerfile),
                "--tag",
                tag,
                *self._label_args(labels),
            ]
            if ignorefile is not None:
                argv.extend(("--ignorefile", str(ignorefile)))
            argv.append(str(build_context))
            self._run(tuple(argv), timeout=900)
            observed = self._inspect("image", tag)
            image_id = _image_identity((observed or {}).get("Id") or (observed or {}).get("ID"))
            observed_labels = self._labels(observed or {})
            if (
                image_id is None
                or observed_labels.get(LABEL_PLAN) != plan["planDigest"]
                or observed_labels.get(LABEL_SERVICE) != service_id
                or observed_labels.get(LABEL_SOURCE) != spec["source"]["commit"]
                or observed_labels.get(LABEL_REVISION) != plan["planDigest"]
            ):
                raise AdapterError("image_identity_missing", "built image lacks an exact sha256 identity")
            images[service_id] = image_id
        return images, materials

    def _pull_exact_image(self, reference: str) -> dict[str, str]:
        if not isinstance(reference, str) or not re.fullmatch(
            r"[^\s@]+@sha256:[0-9a-f]{64}", reference
        ):
            raise AdapterError(
                "mutable_image", "image pull requires one immutable digest reference"
            )
        requested_digest = reference.rsplit("@", 1)[1]
        self._run(
            ("pull", "--platform", "linux/amd64", reference),
            timeout=900,
        )
        observed = self._inspect("image", reference)
        repo_digests = (
            observed.get("RepoDigests") if isinstance(observed, Mapping) else None
        )
        image_id = _image_identity(
            (observed or {}).get("Id") or (observed or {}).get("ID")
        )
        if (
            image_id is None
            or not isinstance(repo_digests, list)
            or not any(
                isinstance(item, str) and item.endswith("@" + requested_digest)
                for item in repo_digests
            )
        ):
            raise AdapterError(
                "image_digest_mismatch",
                "pulled image does not resolve the exact approved manifest digest",
            )
        return {
            "reference": reference,
            "manifestDigest": requested_digest,
            "imageDigest": image_id,
            "platform": "linux/amd64",
        }

    def _run_services(
        self,
        plan: Mapping[str, Any],
        names: Mapping[str, Any],
        images: Mapping[str, str],
        networks: Mapping[str, str],
        volumes: Mapping[str, str],
        *,
        failpoint: str | None = None,
    ) -> dict[str, Any]:
        spec = plan["spec"]
        deployment_id = spec["metadata"]["deploymentId"]
        result: dict[str, Any] = {}
        for service in spec["services"]:
            service_id = service["id"]
            name = names["containers"][service_id]
            if self._assert_owned("container", name, deployment_id) is not None:
                raise AdapterError("duplicate_deployment", f"deployment container already exists: {name}")
            user = service["runtime"]["user"]
            labels = {
                LABEL_MANAGED: "true",
                LABEL_DEPLOYMENT: deployment_id,
                LABEL_SERVICE: service_id,
                LABEL_PLAN: plan["planDigest"],
                LABEL_SOURCE: spec["source"]["commit"],
                LABEL_REVISION: plan["planDigest"],
            }
            argv = [
                "run",
                "--detach",
                "--name",
                name,
                *self._label_args(labels),
                "--entrypoint=[]",
                "--unsetenv-all",
                "--image-volume=ignore",
                "--userns",
                f"keep-id:uid={user['uid']},gid={user['gid']}",
                "--user",
                f"{user['uid']}:{user['gid']}",
                "--read-only",
                "--read-only-tmpfs=false",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=64m",
                "--cap-drop=all",
                "--security-opt=no-new-privileges",
                "--ipc=private",
                "--pid=private",
                "--uts=private",
                "--pids-limit",
                str(service["resources"]["pidsLimit"]),
                "--memory",
                service["resources"]["memoryLimit"],
                "--cpus",
                str(service["resources"]["cpuLimit"]),
                "--init",
                "--stop-timeout",
                "10",
                "--log-opt",
                "max-size=1m",
                "--log-driver",
                "k8s-file",
                "--workdir",
                service["runtime"]["workdir"],
                "--network",
                networks[service["networks"][0]],
                "--network-alias",
                service_id,
            ]
            for key, value in sorted(service["environment"].items()):
                argv.extend(("--env", f"{key}={value}"))
            for port in service["ports"]:
                if port["hostPort"]:
                    try:
                        with socket.socket(
                            socket.AF_INET6 if ":" in port["hostAddress"] else socket.AF_INET,
                            socket.SOCK_STREAM,
                        ) as probe:
                            probe.bind((port["hostAddress"], port["hostPort"]))
                    except OSError as exc:
                        raise AdapterError(
                            "port_unavailable", f"host port is unavailable: {port['hostPort']}"
                        ) from exc
                host_port = "" if port["hostPort"] == 0 else str(port["hostPort"])
                host_address = (
                    f"[{port['hostAddress']}]"
                    if ":" in port["hostAddress"]
                    else port["hostAddress"]
                )
                argv.extend(("--publish", f"{host_address}:{host_port}:{port['containerPort']}/tcp"))
            for storage in service["storage"]:
                if storage["persistence"] == "externally_managed":
                    raise AdapterError("external_storage_unsupported", "Slice A does not bind externally managed storage")
                volume = volumes[storage["id"]]
                argv.extend(
                    (
                        "--volume",
                        f"{volume}:{storage['mountPath']}:rw,nodev,nosuid,noexec",
                    )
                )
            argv.append(images[service_id])
            argv.extend(service["runtime"]["command"])
            started = self._run(tuple(argv), timeout=120)
            container_id = started.stdout.strip().splitlines()[-1] if started.stdout.strip() else ""
            if not re.fullmatch(r"[0-9a-f]{12,64}", container_id):
                raise AdapterError("container_identity_missing", f"service {service_id} did not return a container id")
            for network_id in service["networks"][1:]:
                self._run(("network", "connect", networks[network_id], name), timeout=30)
            result[service_id] = {"name": name, "containerId": container_id, "imageDigest": images[service_id]}
            if failpoint == "after_first_service_creation":
                raise AdapterError(
                    "injected_interruption",
                    "injected interruption after first service creation",
                )
        return result

    def _service_health(self, service: Mapping[str, Any], container_name: str) -> tuple[bool, dict[str, Any]]:
        health = service["health"]
        if health["type"] == "command":
            check = self._run(
                ("exec", container_name, *health["command"]),
                timeout=health["timeoutSeconds"],
                check=False,
            )
            return check.returncode == 0, {
                "type": "command",
                "checkedAt": timestamp(),
                "returncode": check.returncode,
                "status": "healthy" if check.returncode == 0 else "unhealthy",
            }
        port = next(
            (
                item
                for item in service["ports"]
                if item["name"] == health["portName"]
            ),
            None,
        )
        if port is None:
            raise AdapterError(
                "health_observation_failed",
                "declared HTTP health port is unavailable",
            )
        observed = self._inspect("container", container_name)
        network = (
            observed.get("NetworkSettings")
            if isinstance(observed, Mapping)
            else None
        )
        bindings = (
            network.get("Ports", {}).get(f"{port['containerPort']}/tcp")
            if isinstance(network, Mapping)
            and isinstance(network.get("Ports"), Mapping)
            else None
        )
        if (
            not isinstance(bindings, list)
            or len(bindings) != 1
            or not isinstance(bindings[0], Mapping)
            or bindings[0].get("HostIp") != port["hostAddress"]
        ):
            raise AdapterError(
                "health_observation_failed",
                "declared HTTP health binding differs from runtime",
            )
        try:
            host_port = int(bindings[0].get("HostPort"))
        except (TypeError, ValueError) as exc:
            raise AdapterError(
                "health_observation_failed",
                "declared HTTP health port is invalid",
            ) from exc
        connection = http.client.HTTPConnection(
            port["hostAddress"],
            host_port,
            timeout=health["timeoutSeconds"],
        )
        try:
            connection.request("GET", health["path"])
            response = connection.getresponse()
            response.read(64 * 1024)
            status_code = response.status
        except (OSError, http.client.HTTPException) as exc:
            return False, {
                "type": "http",
                "checkedAt": timestamp(),
                "path": health["path"],
                "portName": health["portName"],
                "statusCode": None,
                "failure": type(exc).__name__,
                "status": "unhealthy",
            }
        finally:
            connection.close()
        healthy = 200 <= status_code < 300
        return healthy, {
            "type": "http",
            "checkedAt": timestamp(),
            "path": health["path"],
            "portName": health["portName"],
            "statusCode": status_code,
            "status": "healthy" if healthy else "unhealthy",
        }

    def _runtime_capabilities(
        self, container_name: str
    ) -> tuple[bool, dict[str, Any]]:
        observed = self._run(
            ("top", container_name, "capeff,capbnd"),
            timeout=30,
            check=False,
        )
        lines = [line.split() for line in observed.stdout.splitlines() if line.strip()]
        values = lines[1:] if lines else []
        exact = (
            observed.returncode == 0
            and bool(values)
            and all(
                len(item) == 2
                and item[0].lower() == "none"
                and item[1].lower() == "none"
                for item in values
            )
        )
        return exact, {
            "status": "none" if exact else "unknown_or_present",
            "processesObserved": len(values),
            "returncode": observed.returncode,
        }

    def _runtime_user_mapping(
        self,
        container_name: str,
        *,
        expected_uid: int,
    ) -> tuple[bool, dict[str, Any]]:
        observed = self._run(
            # Podman resolves `user`/`huser` through the image's passwd file.
            # That made an exact uid mapping appear different when an image
            # happened to name the host uid (for example Node's uid 1000
            # account).  Numeric descriptors are stable across image content.
            ("top", container_name, "uid,huid"),
            timeout=30,
            check=False,
        )
        lines = [line.split() for line in observed.stdout.splitlines() if line.strip()]
        values = lines[1:] if lines else []
        exact = (
            observed.returncode == 0
            and bool(values)
            and all(
                len(item) == 2
                and item[0] == str(expected_uid)
                and item[1] == str(os.geteuid())
                for item in values
            )
        )
        return exact, {
            "status": "keep_id_exact" if exact else "unknown_or_changed",
            "processesObserved": len(values),
            "hostUid": os.geteuid(),
            "containerUid": expected_uid,
            "returncode": observed.returncode,
        }

    def verify_health(self, spec: Mapping[str, Any], names: Mapping[str, Any]) -> dict[str, Any]:
        health: dict[str, Any] = {}
        deadline = time.monotonic() + max(
            service["health"]["startPeriodSeconds"] + 60 for service in spec["services"]
        )
        pending = {service["id"]: service for service in spec["services"]}
        while pending and time.monotonic() < deadline:
            for service_id, service in list(pending.items()):
                observed = self._inspect("container", names["containers"][service_id])
                running = bool((observed or {}).get("State", {}).get("Running"))
                if not running:
                    health[service_id] = {"status": "exited", "checkedAt": timestamp()}
                    pending.pop(service_id)
                    continue
                ok, evidence = self._service_health(service, names["containers"][service_id])
                health[service_id] = evidence
                if ok:
                    pending.pop(service_id)
            if pending:
                time.sleep(min(service["health"]["intervalSeconds"] for service in pending.values()))
        if pending or any(item.get("status") != "healthy" for item in health.values()):
            raise AdapterError("health_verification_failed", "one or more deployment services did not become healthy", details={"health": health})
        return health

    def _cleanup_partial(self, plan: Mapping[str, Any], names: Mapping[str, Any]) -> dict[str, Any]:
        spec = plan["spec"]
        deployment_id = spec["metadata"]["deploymentId"]
        removed: dict[str, list[str]] = {
            "containers": [],
            "networks": [],
            "volumes": [],
            "images": [],
        }
        uncertain: list[str] = []
        runtime_effect_possible = False
        service_ids_by_name = {
            name: service_id for service_id, name in names["containers"].items()
        }
        for name in reversed(list(names["containers"].values())):
            try:
                observed = self._assert_owned("container", name, deployment_id)
                if observed is not None:
                    runtime_effect_possible = True
                    labels = self._labels(observed)
                    if (
                        labels.get(LABEL_PLAN) != plan["planDigest"]
                        or labels.get(LABEL_SOURCE) != spec["source"]["commit"]
                        or labels.get(LABEL_REVISION) != plan["planDigest"]
                        or labels.get(LABEL_SERVICE) != service_ids_by_name[name]
                    ):
                        uncertain.append(name)
                    else:
                        self._run(("rm", "--force", name), timeout=30)
                        removed["containers"].append(name)
            except AdapterError:
                runtime_effect_possible = True
                uncertain.append(name)
        network_ids_by_name = {
            name: network_id for network_id, name in names["networks"].items()
        }
        for name in reversed(list(names["networks"].values())):
            try:
                observed = self._assert_owned("network", name, deployment_id)
                if observed is not None:
                    labels = self._labels(observed)
                    if (
                        labels.get(LABEL_PLAN) != plan["planDigest"]
                        or labels.get(LABEL_SOURCE) != spec["source"]["commit"]
                        or labels.get(LABEL_REVISION) != plan["planDigest"]
                        or labels.get(LABEL_NETWORK) != network_ids_by_name[name]
                    ):
                        uncertain.append(name)
                    else:
                        self._run(("network", "rm", name), timeout=30)
                        removed["networks"].append(name)
            except AdapterError:
                uncertain.append(name)
        persistence = {
            storage["id"]: storage["persistence"]
            for service in spec["services"]
            for storage in service["storage"]
        }
        retained_volumes: dict[str, str] = {}
        for storage_id, name in reversed(list(names["volumes"].items())):
            try:
                observed = self._assert_owned("volume", name, deployment_id)
                if observed is not None:
                    labels = self._labels(observed)
                    if (
                        labels.get(LABEL_STORAGE) != storage_id
                        or labels.get(LABEL_PLAN) != plan["planDigest"]
                        or labels.get(LABEL_SOURCE) != spec["source"]["commit"]
                        or labels.get(LABEL_REVISION) != plan["planDigest"]
                    ):
                        uncertain.append(name)
                    elif (
                        runtime_effect_possible
                        and persistence[storage_id] != "ephemeral"
                    ):
                        retained_volumes[storage_id] = name
                    else:
                        self._run(("volume", "rm", name), timeout=30)
                        removed["volumes"].append(name)
            except AdapterError:
                uncertain.append(name)
        source_image_names = [
            (
                service["id"],
                f"{names['images'][service['id']]}:{plan['planDigest'][7:19]}",
            )
            for service in spec["services"]
            if service["build"]["mode"] == "source"
        ]
        for service_id, name in reversed(source_image_names):
            try:
                observed = self._assert_owned("image", name, deployment_id)
                if observed is not None:
                    labels = self._labels(observed)
                    if (
                        labels.get(LABEL_PLAN) != plan["planDigest"]
                        or labels.get(LABEL_SOURCE) != spec["source"]["commit"]
                        or labels.get(LABEL_REVISION) != plan["planDigest"]
                        or labels.get(LABEL_SERVICE) != service_id
                    ):
                        uncertain.append(name)
                    else:
                        self._run(("image", "rm", "--force", name), timeout=60)
                        removed["images"].append(name)
            except AdapterError:
                uncertain.append(name)
        expected_after = {
            "container": set(),
            "network": set(),
            "volume": set(retained_volumes.values()),
            "image": set(),
        }
        for kind, expected in expected_after.items():
            try:
                unexpected = self._managed_names(kind, deployment_id) - expected
            except AdapterError:
                uncertain.append(f"{kind}:inventory_unavailable")
            else:
                uncertain.extend(
                    f"{kind}:{name}" for name in sorted(unexpected)
                )
        return {
            "removed": removed,
            "uncertain": sorted(set(uncertain)),
            "volumesRetained": sorted(retained_volumes.values()),
            "retainedStorageIdentities": dict(sorted(retained_volumes.items())),
            "runtimeEffectPossible": runtime_effect_possible,
            "verified": not uncertain,
        }

    def apply(
        self,
        plan: Mapping[str, Any],
        *,
        context_root: Path,
        overlay_root: Path,
        failpoint: str | None = None,
    ) -> dict[str, Any]:
        spec = plan["spec"]
        probe = self._assert_target_identity(spec)
        if any(service["secrets"] for service in spec["services"]):
            raise AdapterError("secret_binding_unavailable", "Slice A requires an explicit configured secret broker before applying secrets")
        names = self.resource_names(spec)
        networks: dict[str, str] = {}
        volumes: dict[str, str] = {}
        images: dict[str, str] = {}
        services: dict[str, Any] = {}
        checkpoints: list[str] = []
        try:
            networks, volumes = self._create_networks_and_volumes(spec, plan["planDigest"], names)
            checkpoints.append("resources_created")
            if failpoint == "after_volume_creation":
                raise AdapterError("injected_interruption", "injected interruption after volume creation")
            images, image_materials = self._build_images(
                plan, context_root, overlay_root, names
            )
            checkpoints.append("images_ready")
            if failpoint == "after_image_build":
                raise AdapterError("injected_interruption", "injected interruption after image build")
            services = self._run_services(
                plan,
                names,
                images,
                networks,
                volumes,
                failpoint=failpoint,
            )
            checkpoints.append("services_started")
            health = self.verify_health(spec, names)
            checkpoints.append("health_verified")
            observation = self.observe(
                spec,
                expected_revision=plan["planDigest"],
                expected_images=images,
                verify_health=True,
            )
            checkpoints.append("runtime_observed")
        except AdapterError as exc:
            cleanup = self._cleanup_partial(plan, names)
            details = {
                **exc.details,
                "checkpoints": checkpoints,
                "cleanup": cleanup,
                "createdImages": dict(images),
                "resourceNames": names,
            }
            raise AdapterError(exc.code, str(exc), details=details) from exc
        return {
            "adapter": TARGET_ADAPTER,
            "target": probe,
            "names": names,
            "networks": networks,
            "volumes": volumes,
            "images": images,
            "imageMaterials": image_materials,
            "services": services,
            "health": health,
            "observation": observation,
            "checkpoints": checkpoints,
        }

    def _ensure_update_infrastructure(
        self,
        plan: Mapping[str, Any],
        infrastructure: Mapping[str, Any] | None,
        names: Mapping[str, Any],
    ) -> tuple[dict[str, str], dict[str, str], dict[str, Any], dict[str, list[str]]]:
        """Reuse exact shared networks/volumes and create only newly declared ones.

        Networks and volumes cannot be relabelled by Podman, so an update
        keeps the exact labels of the revision that created each shared
        resource.  Removing a declared network or storage identity through an
        update is refused: volume removal destroys data and must go through
        the separately approved remove/purge flow.
        """

        spec = plan["spec"]
        deployment_id = spec["metadata"]["deploymentId"]
        prior = infrastructure if isinstance(infrastructure, Mapping) else {}
        prior_networks = prior.get("networks") if isinstance(prior.get("networks"), Mapping) else {}
        prior_volumes = prior.get("volumes") if isinstance(prior.get("volumes"), Mapping) else {}
        created = {"networks": [], "volumes": []}
        effective: dict[str, Any] = {"networks": {}, "volumes": {}}

        def verify_labels(
            kind: str,
            resource_id: str,
            observed: Mapping[str, Any],
            entry: object,
        ) -> dict[str, str]:
            if (
                not isinstance(entry, Mapping)
                or DIGEST.fullmatch(str(entry.get("revision"))) is None
                or not isinstance(entry.get("sourceCommit"), str)
            ):
                raise AdapterError(
                    "runtime_identity_mismatch",
                    f"deployment {kind} lacks an exact infrastructure identity: {resource_id}",
                )
            labels = self._labels(observed)
            extra = LABEL_NETWORK if kind == "network" else LABEL_STORAGE
            if (
                labels.get(extra) != resource_id
                or labels.get(LABEL_PLAN) != entry["revision"]
                or labels.get(LABEL_REVISION) != entry["revision"]
                or labels.get(LABEL_SOURCE) != entry["sourceCommit"]
            ):
                raise AdapterError(
                    "runtime_identity_mismatch",
                    f"deployment {kind} identity differs from accepted state: {resource_id}",
                )
            return {"revision": entry["revision"], "sourceCommit": entry["sourceCommit"]}

        base_labels = {
            LABEL_MANAGED: "true",
            LABEL_DEPLOYMENT: deployment_id,
            LABEL_PLAN: plan["planDigest"],
            LABEL_SOURCE: spec["source"]["commit"],
            LABEL_REVISION: plan["planDigest"],
        }
        networks: dict[str, str] = {}
        for network_id, name in names["networks"].items():
            observed = self._assert_owned("network", name, deployment_id)
            if observed is None:
                self._run(
                    (
                        "network",
                        "create",
                        "--internal",
                        *self._label_args({**base_labels, LABEL_NETWORK: network_id}),
                        name,
                    ),
                    timeout=30,
                )
                created["networks"].append(network_id)
                effective["networks"][network_id] = {
                    "revision": plan["planDigest"],
                    "sourceCommit": spec["source"]["commit"],
                }
            else:
                if not bool(observed.get("Internal") or observed.get("internal")):
                    raise AdapterError(
                        "runtime_identity_mismatch",
                        f"deployment network is not internal: {network_id}",
                    )
                effective["networks"][network_id] = verify_labels(
                    "network", network_id, observed, prior_networks.get(network_id)
                )
            networks[network_id] = name
        volumes: dict[str, str] = {}
        for storage_id, name in names["volumes"].items():
            observed = self._assert_owned("volume", name, deployment_id)
            if observed is None:
                if storage_id in prior_volumes:
                    raise AdapterError(
                        "runtime_identity_mismatch",
                        f"accepted deployment storage is missing: {storage_id}",
                    )
                self._run(
                    (
                        "volume",
                        "create",
                        *self._label_args({**base_labels, LABEL_STORAGE: storage_id}),
                        name,
                    ),
                    timeout=30,
                )
                created["volumes"].append(storage_id)
                effective["volumes"][storage_id] = {
                    "revision": plan["planDigest"],
                    "sourceCommit": spec["source"]["commit"],
                }
            else:
                effective["volumes"][storage_id] = verify_labels(
                    "volume", storage_id, observed, prior_volumes.get(storage_id)
                )
            volumes[storage_id] = name
        removed_networks = sorted(set(prior_networks) - set(effective["networks"]))
        removed_volumes = sorted(set(prior_volumes) - set(effective["volumes"]))
        if removed_networks or removed_volumes:
            raise AdapterError(
                "update_topology_changed",
                "an update may not remove networks or storage; use the separately approved remove and purge flow",
                details={
                    "removedNetworks": removed_networks,
                    "removedStorage": removed_volumes,
                },
            )
        return networks, volumes, effective, created

    def _stop_swap_predecessor(
        self,
        predecessor_plan: Mapping[str, Any],
        names: Mapping[str, Any],
    ) -> None:
        """Stop and remove the exact accepted containers after verifying all."""

        spec = predecessor_plan["spec"]
        deployment_id = spec["metadata"]["deploymentId"]
        for service in spec["services"]:
            name = names["containers"][service["id"]]
            if (
                self._assert_exact_container(
                    name,
                    deployment_id=deployment_id,
                    service_id=service["id"],
                    source_commit=spec["source"]["commit"],
                    expected_revision=predecessor_plan["planDigest"],
                )
                is None
            ):
                raise AdapterError(
                    "runtime_identity_mismatch",
                    f"accepted deployment service is missing: {service['id']}",
                )
        for service in spec["services"]:
            name = names["containers"][service["id"]]
            self._run(("stop", "--time", "10", name), timeout=30)
            self._run(("rm", name), timeout=30)

    def _restore_predecessor(
        self,
        plan: Mapping[str, Any],
        predecessor_plan: Mapping[str, Any],
        names: Mapping[str, Any],
        predecessor_images: Mapping[str, str],
        networks: Mapping[str, str],
        volumes: Mapping[str, str],
        infrastructure: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        """Re-apply the exact predecessor runtime after a failed update."""

        spec = plan["spec"]
        deployment_id = spec["metadata"]["deploymentId"]
        for service in spec["services"]:
            name = names["containers"][service["id"]]
            if self._assert_owned("container", name, deployment_id) is not None:
                self._run(("rm", "--force", name), timeout=30)
        predecessor_spec = predecessor_plan["spec"]
        expected_images = {
            service["id"]: predecessor_images.get(service["id"])
            for service in predecessor_spec["services"]
        }
        if any(not isinstance(value, str) or DIGEST.fullmatch(value) is None for value in expected_images.values()):
            return {
                "status": "failed",
                "failureCode": "runtime_identity_mismatch",
                "details": {"reason": "accepted image identities are incomplete"},
            }
        try:
            services = self._run_services(
                predecessor_plan,
                names,
                expected_images,
                dict(networks),
                dict(volumes),
            )
            health = self.verify_health(predecessor_spec, names)
            observation = self.observe(
                predecessor_spec,
                expected_revision=predecessor_plan["planDigest"],
                expected_images=expected_images,
                verify_health=True,
                infrastructure=infrastructure,
            )
        except AdapterError as exc:
            return {
                "status": "failed",
                "failureCode": exc.code,
                "details": dict(exc.details),
            }
        if observation["drift"]:
            return {
                "status": "failed",
                "failureCode": "runtime_identity_mismatch",
                "details": {"observation": observation},
            }
        return {
            "status": "restored",
            "revision": predecessor_plan["planDigest"],
            "services": services,
            "health": health,
            "observation": observation,
        }

    def _prune_revision_images(
        self,
        plan: Mapping[str, Any],
        names: Mapping[str, Any],
    ) -> list[str]:
        """Remove one revision's source-built image tags after it is superseded."""

        pruned: list[str] = []
        for service in plan["spec"]["services"]:
            if service["build"]["mode"] != "source":
                continue
            tag = f"{names['images'][service['id']]}:{plan['planDigest'][7:19]}"
            self._run(("image", "rm", tag), timeout=60, check=False)
            if self._inspect("image", tag) is None:
                pruned.append(tag)
        return pruned

    def _discard_update_residue(
        self,
        plan: Mapping[str, Any],
        names: Mapping[str, Any],
        created: Mapping[str, list[str]],
    ) -> dict[str, Any]:
        """Discard resources that only the failed update revision created."""

        removed: dict[str, list[str]] = {"images": [], "networks": [], "volumes": []}
        uncertain: list[str] = []
        for service in plan["spec"]["services"]:
            if service["build"]["mode"] != "source":
                continue
            tag = f"{names['images'][service['id']]}:{plan['planDigest'][7:19]}"
            self._run(("image", "rm", tag), timeout=60, check=False)
            if self._inspect("image", tag) is None:
                removed["images"].append(tag)
            else:
                uncertain.append(f"image:{tag}")
        for network_id in created.get("networks", []):
            name = names["networks"][network_id]
            self._run(("network", "rm", name), timeout=30, check=False)
            if self._inspect("network", name) is None:
                removed["networks"].append(name)
            else:
                uncertain.append(f"network:{name}")
        for storage_id in created.get("volumes", []):
            name = names["volumes"][storage_id]
            self._run(("volume", "rm", name), timeout=30, check=False)
            if self._inspect("volume", name) is None:
                removed["volumes"].append(name)
            else:
                uncertain.append(f"volume:{name}")
        return {"removed": removed, "uncertain": uncertain, "verified": not uncertain}

    def apply_update(
        self,
        plan: Mapping[str, Any],
        *,
        predecessor_plan: Mapping[str, Any],
        predecessor_images: Mapping[str, str],
        infrastructure: Mapping[str, Any] | None,
        context_root: Path,
        overlay_root: Path,
        failpoint: str | None = None,
    ) -> dict[str, Any]:
        """Stop-swap the accepted runtime to a new approved revision.

        Container names and host ports are stable per deployment, so a
        concurrent blue/green pair is impossible and the strategy is an exact
        stop-swap: new revision images are built before any runtime change,
        the verified predecessor containers are then stopped and replaced,
        and the new revision is health-gated with the same bounded polling as
        a first apply.  A failure after the swap automatically re-applies the
        exact predecessor runtime before the failure is reported.
        """

        spec = plan["spec"]
        probe = self._assert_target_identity(spec)
        if any(service["secrets"] for service in spec["services"]):
            raise AdapterError("secret_binding_unavailable", "a secret broker is required before applying secrets")
        names = self.resource_names(spec)
        if names != self.resource_names(predecessor_plan["spec"]):
            raise AdapterError(
                "update_topology_changed",
                "an update must preserve exact runtime resource names",
            )
        checkpoints: list[str] = []
        created: dict[str, list[str]] = {"networks": [], "volumes": []}
        images: dict[str, str] = {}
        swapped = False
        networks: dict[str, str] = {}
        volumes: dict[str, str] = {}
        effective_infra: dict[str, Any] = infrastructure if isinstance(infrastructure, Mapping) else {"networks": {}, "volumes": {}}
        try:
            networks, volumes, effective_infra, created = self._ensure_update_infrastructure(
                plan, infrastructure, names
            )
            checkpoints.append("infrastructure_ready")
            images, image_materials = self._build_images(
                plan, context_root, overlay_root, names
            )
            checkpoints.append("images_ready")
            if failpoint == "after_image_build":
                raise AdapterError("injected_interruption", "injected interruption after image build")
            self._stop_swap_predecessor(predecessor_plan, names)
            swapped = True
            checkpoints.append("predecessor_stopped")
            if failpoint == "after_predecessor_stopped":
                raise AdapterError("injected_interruption", "injected interruption after predecessor stop")
            services = self._run_services(
                plan,
                names,
                images,
                networks,
                volumes,
                failpoint=failpoint,
            )
            checkpoints.append("services_started")
            health = self.verify_health(spec, names)
            checkpoints.append("health_verified")
            observation = self.observe(
                spec,
                expected_revision=plan["planDigest"],
                expected_images=images,
                verify_health=True,
                infrastructure=effective_infra,
            )
            checkpoints.append("runtime_observed")
        except AdapterError as exc:
            if swapped:
                rollback = self._restore_predecessor(
                    plan,
                    predecessor_plan,
                    names,
                    predecessor_images,
                    networks,
                    volumes,
                    infrastructure,
                )
            else:
                rollback = {
                    "status": "not_required",
                    "revision": predecessor_plan["planDigest"],
                    "reason": "update failed before the accepted runtime was stopped",
                }
            residue = self._discard_update_residue(plan, names, created)
            details = {
                **exc.details,
                "checkpoints": checkpoints,
                "rollback": rollback,
                "residue": residue,
                "resourceNames": names,
            }
            raise AdapterError(exc.code, str(exc), details=details) from exc
        pruned = self._prune_revision_images(predecessor_plan, names)
        return {
            "adapter": TARGET_ADAPTER,
            "target": probe,
            "names": names,
            "networks": networks,
            "volumes": volumes,
            "images": images,
            "imageMaterials": image_materials,
            "services": services,
            "health": health,
            "observation": observation,
            "infrastructure": effective_infra,
            "prunedImages": pruned,
            "checkpoints": checkpoints,
        }

    def observe(
        self,
        spec: Mapping[str, Any],
        *,
        expected_revision: str | None = None,
        expected_images: Mapping[str, str] | None = None,
        verify_health: bool = False,
        infrastructure: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        target = self._assert_target_identity(spec)
        names = self.resource_names(spec)
        deployment_id = spec["metadata"]["deploymentId"]
        services: dict[str, Any] = {}
        revisions: set[str] = set()
        drift: list[str] = []
        health: dict[str, Any] = {}
        for service in spec["services"]:
            service_id = service["id"]
            name = names["containers"][service_id]
            observed = self._assert_owned("container", name, deployment_id)
            if observed is None:
                services[service_id] = {"name": name, "present": False, "running": False}
                drift.append(f"container_missing:{service_id}")
                continue
            labels = self._labels(observed)
            revision = labels.get(LABEL_REVISION)
            if revision:
                revisions.add(revision)
            running = bool(observed.get("State", {}).get("Running"))
            if not running:
                drift.append(f"container_stopped:{service_id}")
            image = _image_identity(observed.get("Image"))
            if labels.get(LABEL_SERVICE) != service_id:
                drift.append(f"service_label_changed:{service_id}")
            if labels.get(LABEL_SOURCE) != spec["source"]["commit"]:
                drift.append(f"source_changed:{service_id}")
            if expected_revision is not None and (
                revision != expected_revision or labels.get(LABEL_PLAN) != expected_revision
            ):
                drift.append(f"revision_changed:{service_id}")
            expected_image = (expected_images or {}).get(service_id)
            if expected_image is not None and image != expected_image:
                drift.append(f"image_changed:{service_id}")
            config = observed.get("Config") if isinstance(observed.get("Config"), Mapping) else {}
            host_config = observed.get("HostConfig") if isinstance(observed.get("HostConfig"), Mapping) else {}
            expected_user = service["runtime"]["user"]
            if config.get("User") != f"{expected_user['uid']}:{expected_user['gid']}":
                drift.append(f"user_changed:{service_id}")
            if config.get("WorkingDir") != service["runtime"]["workdir"]:
                drift.append(f"workdir_changed:{service_id}")
            observed_command = config.get("Cmd")
            if observed_command != service["runtime"]["command"]:
                drift.append(f"command_changed:{service_id}")
            if config.get("Entrypoint") not in (None, "", [], [""]):
                drift.append(f"entrypoint_changed:{service_id}")
            observed_environment = _environment_mapping(config.get("Env"))
            if isinstance(observed_environment, Mapping):
                runtime_hostname = observed_environment.pop("HOSTNAME", None)
            else:
                runtime_hostname = None
            container_id = observed.get("Id")
            if (
                observed_environment != service["environment"]
                or not isinstance(container_id, str)
                or runtime_hostname != container_id[:12]
            ):
                drift.append(f"environment_changed:{service_id}")
            if host_config.get("ReadonlyRootfs") is not True:
                drift.append(f"read_only_root_changed:{service_id}")
            if host_config.get("Privileged") is True:
                drift.append(f"privileged_runtime:{service_id}")
            try:
                no_capabilities, capability_evidence = self._runtime_capabilities(
                    name
                )
            except AdapterError as exc:
                no_capabilities = False
                capability_evidence = {
                    "status": "unknown",
                    "failureCode": exc.code,
                }
            if not no_capabilities:
                drift.append(f"capabilities_changed:{service_id}")
            security_options = host_config.get("SecurityOpt")
            if not isinstance(security_options, list) or not any(
                "no-new-privileges" in str(item)
                for item in security_options
            ) or any(
                "unconfined" in str(item).lower()
                or str(item).lower() in {
                    "no-new-privileges=false",
                    "no-new-privileges=0",
                }
                for item in (security_options or [])
            ):
                drift.append(f"security_options_changed:{service_id}")
            if host_config.get("PidsLimit") != service["resources"]["pidsLimit"]:
                drift.append(f"pids_limit_changed:{service_id}")
            if host_config.get("Memory") != _memory_bytes(
                service["resources"]["memoryLimit"]
            ):
                drift.append(f"memory_limit_changed:{service_id}")
            expected_nano_cpus = int(service["resources"]["cpuLimit"] * 1_000_000_000)
            if host_config.get("NanoCpus") != expected_nano_cpus:
                drift.append(f"cpu_limit_changed:{service_id}")
            if host_config.get("Init") is not True:
                drift.append(f"init_changed:{service_id}")
            annotations = config.get("Annotations")
            annotations = annotations if isinstance(annotations, Mapping) else {}
            expected_userns = (
                f"keep-id:uid={expected_user['uid']},gid={expected_user['gid']}"
            )
            if (
                host_config.get("UsernsMode") != "private"
                or annotations.get("io.podman.annotations.userns")
                != expected_userns
            ):
                drift.append(f"user_namespace_changed:{service_id}")
            try:
                mapping_exact, mapping_evidence = self._runtime_user_mapping(
                    name, expected_uid=expected_user["uid"]
                )
            except AdapterError as exc:
                mapping_exact = False
                mapping_evidence = {
                    "status": "unknown",
                    "failureCode": exc.code,
                }
            if not mapping_exact:
                drift.append(f"user_mapping_changed:{service_id}")
            if host_config.get("NetworkMode") == "host":
                drift.append(f"host_network_runtime:{service_id}")
            if host_config.get("PidMode") not in {None, "", "private"} or host_config.get(
                "IpcMode"
            ) not in {None, "", "private"} or host_config.get("UTSMode") not in {
                None,
                "",
                "private",
            }:
                drift.append(f"host_namespace_runtime:{service_id}")
            if host_config.get("Devices"):
                drift.append(f"devices_changed:{service_id}")
            tmpfs = host_config.get("Tmpfs")
            tmpfs_options = tmpfs.get("/tmp") if isinstance(tmpfs, Mapping) else None
            if (
                not isinstance(tmpfs, Mapping)
                or set(tmpfs) != {"/tmp"}
                or not isinstance(tmpfs_options, str)
                or not {"rw", "noexec", "nosuid", "nodev", "size=64m"}.issubset(
                    set(tmpfs_options.split(","))
                )
            ):
                drift.append(f"tmpfs_changed:{service_id}")
            log_config = host_config.get("LogConfig")
            log_options = (
                log_config.get("Config")
                if isinstance(log_config, Mapping)
                and isinstance(log_config.get("Config"), Mapping)
                else {}
            )
            observed_log_limit = (
                log_options.get("max-size")
                if isinstance(log_options, Mapping)
                else None
            ) or (
                log_config.get("Size")
                if isinstance(log_config, Mapping)
                else None
            )
            if (
                not isinstance(log_config, Mapping)
                or log_config.get("Type") != "k8s-file"
                or observed_log_limit not in {"1m", "1MB"}
            ):
                drift.append(f"log_policy_changed:{service_id}")
            network_settings = observed.get("NetworkSettings") if isinstance(observed.get("NetworkSettings"), Mapping) else {}
            observed_networks_raw = network_settings.get("Networks")
            observed_networks = set(observed_networks_raw) if isinstance(observed_networks_raw, Mapping) else set()
            expected_networks = {names["networks"][item] for item in service["networks"]}
            if observed_networks != expected_networks:
                drift.append(f"networks_changed:{service_id}")
            elif isinstance(observed_networks_raw, Mapping):
                for network_id in service["networks"]:
                    network_name = names["networks"][network_id]
                    network_value = observed_networks_raw.get(network_name)
                    aliases = (
                        network_value.get("Aliases")
                        if isinstance(network_value, Mapping)
                        else None
                    )
                    if service_id not in (aliases or []):
                        drift.append(f"network_alias_changed:{service_id}:{network_id}")
            observed_volumes = {
                (item.get("Name"), item.get("Destination"))
                for item in observed.get("Mounts", [])
                if isinstance(item, Mapping) and item.get("Type") == "volume"
            }
            expected_volumes = {
                (names["volumes"][item["id"]], item["mountPath"])
                for item in service["storage"]
                if item["persistence"] != "externally_managed"
            }
            if observed_volumes != expected_volumes:
                drift.append(f"storage_changed:{service_id}")
            for mount in observed.get("Mounts", []):
                if not isinstance(mount, Mapping):
                    drift.append(f"unsupported_mount_changed:{service_id}")
                    continue
                if mount.get("Type") != "volume":
                    # Slice A never authorizes host binds, engine sockets, or
                    # other non-volume mounts.  They must remain visible as
                    # drift even when every declared volume is also present.
                    drift.append(f"unsupported_mount_changed:{service_id}")
                    continue
                options = mount.get("Options")
                if (
                    mount.get("RW") is not True
                    or not isinstance(options, list)
                    or not {"nodev", "nosuid", "noexec"}.issubset(set(options))
                ):
                    drift.append(f"storage_options_changed:{service_id}")
            port_evidence: list[dict[str, Any]] = []
            observed_ports = network_settings.get("Ports")
            observed_ports = observed_ports if isinstance(observed_ports, Mapping) else {}
            for port in service["ports"]:
                bindings = observed_ports.get(f"{port['containerPort']}/tcp")
                if not isinstance(bindings, list) or len(bindings) != 1 or not isinstance(bindings[0], Mapping):
                    drift.append(f"port_missing:{service_id}:{port['name']}")
                    continue
                binding = bindings[0]
                try:
                    host_port = int(binding.get("HostPort"))
                except (TypeError, ValueError):
                    drift.append(f"port_invalid:{service_id}:{port['name']}")
                    continue
                host_address = binding.get("HostIp")
                if host_address != port["hostAddress"] or (
                    port["hostPort"] and host_port != port["hostPort"]
                ):
                    drift.append(f"port_changed:{service_id}:{port['name']}")
                port_evidence.append(
                    {
                        "name": port["name"],
                        "containerPort": port["containerPort"],
                        "hostAddress": host_address,
                        "hostPort": host_port,
                    }
                )
            if verify_health and running:
                try:
                    healthy, evidence = self._service_health(service, name)
                except AdapterError as exc:
                    healthy = False
                    evidence = {"status": "unknown", "failureCode": exc.code, "checkedAt": timestamp()}
                health[service_id] = evidence
                if not healthy:
                    drift.append(f"health_unhealthy:{service_id}")
            elif verify_health:
                health[service_id] = {"status": "absent", "checkedAt": timestamp()}
            services[service_id] = {
                "name": name,
                "present": True,
                "running": running,
                "containerId": observed.get("Id"),
                "imageDigest": image,
                "revision": revision,
                "sourceCommit": labels.get(LABEL_SOURCE),
                "ports": port_evidence,
                "capabilities": capability_evidence,
                "userMapping": mapping_evidence,
            }
        observed_revision = next(iter(revisions)) if len(revisions) == 1 else None
        if len(revisions) > 1:
            drift.append("mixed_runtime_revisions")
        # Networks and volumes are created once and cannot be relabelled by
        # Podman, so an updated deployment validates their labels against the
        # exact revision that created them rather than the running revision.
        infra = infrastructure if isinstance(infrastructure, Mapping) else {}
        infra_networks = infra.get("networks") if isinstance(infra.get("networks"), Mapping) else {}
        infra_volumes = infra.get("volumes") if isinstance(infra.get("volumes"), Mapping) else {}

        def infra_expectation(entry: object) -> tuple[str | None, str]:
            if isinstance(entry, Mapping):
                return (
                    entry.get("revision") if isinstance(entry.get("revision"), str) else None,
                    entry.get("sourceCommit") if isinstance(entry.get("sourceCommit"), str) else spec["source"]["commit"],
                )
            return expected_revision, spec["source"]["commit"]

        networks: dict[str, Any] = {}
        for network_id, name in names["networks"].items():
            observed = self._assert_owned("network", name, deployment_id)
            present = observed is not None
            labels = self._labels(observed or {})
            internal = bool(
                (observed or {}).get("Internal") or (observed or {}).get("internal")
            )
            expected_label_revision, expected_label_source = infra_expectation(
                infra_networks.get(network_id)
            )
            if not present:
                drift.append(f"network_missing:{network_id}")
            elif not internal:
                drift.append(f"network_not_internal:{network_id}")
            elif (
                labels.get(LABEL_SOURCE) != expected_label_source
                or labels.get(LABEL_NETWORK) != network_id
                or labels.get(LABEL_PLAN) != labels.get(LABEL_REVISION)
                or (
                    expected_label_revision is not None
                    and labels.get(LABEL_PLAN) != expected_label_revision
                )
            ):
                drift.append(f"network_identity_changed:{network_id}")
            networks[network_id] = {
                "name": name,
                "present": present,
                "internal": internal,
                "planDigest": labels.get(LABEL_PLAN),
                "sourceCommit": labels.get(LABEL_SOURCE),
                "revision": labels.get(LABEL_REVISION),
            }
        volumes: dict[str, Any] = {}
        storage_by_id = {
            item["id"]: item
            for service in spec["services"]
            for item in service["storage"]
            if item["persistence"] != "externally_managed"
        }
        for storage_id, name in names["volumes"].items():
            observed = self._assert_owned("volume", name, deployment_id)
            present = observed is not None
            labels = self._labels(observed or {})
            expected_label_revision, expected_label_source = infra_expectation(
                infra_volumes.get(storage_id)
            )
            if not present:
                drift.append(f"volume_missing:{storage_id}")
            elif (
                labels.get(LABEL_STORAGE) != storage_id
                or labels.get(LABEL_SOURCE) != expected_label_source
                or labels.get(LABEL_PLAN) != labels.get(LABEL_REVISION)
                or (
                    expected_label_revision is not None
                    and labels.get(LABEL_PLAN) != expected_label_revision
                )
            ):
                drift.append(f"volume_identity_changed:{storage_id}")
            volumes[storage_id] = {
                "name": name,
                "present": present,
                "persistence": storage_by_id[storage_id]["persistence"],
                "planDigest": labels.get(LABEL_PLAN),
                "sourceCommit": labels.get(LABEL_SOURCE),
                "revision": labels.get(LABEL_REVISION),
            }
        images: dict[str, Any] = {}
        expected_image_names: set[str] = set()
        if expected_revision is not None:
            for service in spec["services"]:
                if service["build"]["mode"] != "source":
                    continue
                service_id = service["id"]
                image_name = (
                    f"{names['images'][service_id]}:{expected_revision[7:19]}"
                )
                expected_image_names.add(image_name)
                observed = self._assert_owned("image", image_name, deployment_id)
                present = observed is not None
                labels = self._labels(observed or {})
                image_id = _image_identity(
                    (observed or {}).get("Id") or (observed or {}).get("ID")
                )
                if not present:
                    drift.append(f"image_missing:{service_id}")
                elif (
                    labels.get(LABEL_SERVICE) != service_id
                    or labels.get(LABEL_PLAN) != expected_revision
                    or labels.get(LABEL_SOURCE) != spec["source"]["commit"]
                    or labels.get(LABEL_REVISION) != expected_revision
                    or image_id is None
                    or (
                        isinstance((expected_images or {}).get(service_id), str)
                        and image_id != (expected_images or {})[service_id]
                    )
                ):
                    drift.append(f"image_identity_changed:{service_id}")
                images[service_id] = {
                    "name": image_name,
                    "present": present,
                    "imageDigest": image_id,
                }
        unexpected: dict[str, list[str]] = {}
        for kind, expected in (
            ("container", set(names["containers"].values())),
            ("network", set(names["networks"].values())),
            ("volume", set(names["volumes"].values())),
            ("image", expected_image_names),
        ):
            extra = sorted(self._managed_names(kind, deployment_id) - expected)
            unexpected[f"{kind}s"] = extra
            if extra:
                drift.append(f"unexpected_{kind}_resources")
        target_identity = target["identityDigest"]
        if target_identity != spec["target"]["identityDigest"]:
            drift.append("target_identity_changed")
        return {
            "observedAt": timestamp(),
            "targetIdentity": target_identity,
            "observedRevision": observed_revision,
            "services": services,
            "health": health,
            "networks": networks,
            "volumes": volumes,
            "images": images,
            "unexpectedResources": unexpected,
            "drift": sorted(set(drift)),
            "status": "in_sync" if not drift else "drifted",
        }

    def logs(
        self,
        spec: Mapping[str, Any],
        *,
        service_id: str | None = None,
        tail: int = 200,
        expected_revision: str | None = None,
    ) -> dict[str, Any]:
        self._assert_target_identity(spec)
        if isinstance(tail, bool) or not isinstance(tail, int) or not 1 <= tail <= 1000:
            raise DeploymentRefusal("invalid_log_request", "log tail must be between 1 and 1000")
        names = self.resource_names(spec)
        selected = [service_id] if service_id else [item["id"] for item in spec["services"]]
        known = {item["id"] for item in spec["services"]}
        if any(item not in known for item in selected):
            raise DeploymentRefusal("service_not_found", "deployment service does not exist")
        logs: dict[str, str] = {}
        for item in selected:
            name = names["containers"][item]
            if self._assert_exact_container(
                name,
                deployment_id=spec["metadata"]["deploymentId"],
                service_id=item,
                source_commit=spec["source"]["commit"],
                expected_revision=expected_revision,
            ) is None:
                raise AdapterError("runtime_missing", f"deployment service is missing: {item}")
            result = self._run(("logs", "--tail", str(tail), name), timeout=30, check=False)
            if result.returncode != 0:
                raise AdapterError("logs_unavailable", f"logs are unavailable for service {item}")
            logs[item] = _redact(result.stdout + result.stderr)
        return {"deploymentId": spec["metadata"]["deploymentId"], "logs": logs, "redacted": True, "bounded": True}

    def restart(
        self,
        spec: Mapping[str, Any],
        *,
        expected_revision: str | None = None,
        expected_images: Mapping[str, str] | None = None,
        infrastructure: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._assert_target_identity(spec)
        names = self.resource_names(spec)
        deployment_id = spec["metadata"]["deploymentId"]
        for service in spec["services"]:
            name = names["containers"][service["id"]]
            if self._assert_exact_container(
                name,
                deployment_id=deployment_id,
                service_id=service["id"],
                source_commit=spec["source"]["commit"],
                expected_revision=expected_revision,
            ) is None:
                raise AdapterError("runtime_missing", f"deployment service is missing: {service['id']}")
            self._run(("restart", "--time", "10", name), timeout=60)
        health = self.verify_health(spec, names)
        return {
            "health": health,
            "observation": self.observe(
                spec,
                expected_revision=expected_revision,
                expected_images=expected_images,
                verify_health=True,
                infrastructure=infrastructure,
            ),
        }

    def _assert_data_operation_identity(
        self,
        spec: Mapping[str, Any],
        *,
        expected_volumes: Mapping[str, str],
        expected_revision: str,
        expected_images: Mapping[str, str],
        infrastructure: Mapping[str, Any] | None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        if DIGEST.fullmatch(expected_revision) is None:
            raise AdapterError(
                "runtime_identity_mismatch",
                "deployment data operation requires an exact accepted revision",
            )
        names = self.resource_names(spec)
        retained_ids = {
            item["id"]
            for service in spec["services"]
            for item in service["storage"]
            if item["persistence"] == "retained"
        }
        if (
            not retained_ids
            or set(expected_volumes) != retained_ids
            or any(
                expected_volumes[storage_id] != names["volumes"].get(storage_id)
                for storage_id in retained_ids
            )
        ):
            raise AdapterError(
                "backup_identity_mismatch",
                "deployment retained-volume identity differs from accepted state",
            )
        observation = self.observe(
            spec,
            expected_revision=expected_revision,
            expected_images=expected_images,
            verify_health=True,
            infrastructure=infrastructure,
        )
        if observation["status"] != "in_sync" or observation["drift"]:
            raise AdapterError(
                "runtime_identity_mismatch",
                "deployment runtime must be healthy and exact before a data operation",
                details={"observation": observation},
            )
        return names, observation

    def backup_data(
        self,
        spec: Mapping[str, Any],
        *,
        backup_id: str,
        plan_digest: str,
        expected_volumes: Mapping[str, str],
        expected_revision: str,
        expected_images: Mapping[str, str],
        infrastructure: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        safe_id(backup_id, "backup id")
        if DIGEST.fullmatch(plan_digest) is None:
            raise AdapterError(
                "backup_identity_mismatch", "deployment backup plan digest is invalid"
            )
        names, _before = self._assert_data_operation_identity(
            spec,
            expected_volumes=expected_volumes,
            expected_revision=expected_revision,
            expected_images=expected_images,
            infrastructure=infrastructure,
        )
        final_directory = self._backup_directory(spec, backup_id)
        if final_directory.exists() or final_directory.is_symlink():
            raise AdapterError(
                "backup_conflict", "an exact deployment backup already exists"
            )
        staging = Path(
            tempfile.mkdtemp(
                prefix=f".{backup_id}.staging-", dir=final_directory.parent
            )
        )
        staging.chmod(0o700)
        stopped: list[str] = []
        storage: dict[str, Any] = {}
        primary_error: AdapterError | None = None
        try:
            for service in spec["services"]:
                container_name = names["containers"][service["id"]]
                self._run(("stop", "--time", "10", container_name), timeout=30)
                stopped.append(container_name)
            for storage_id, volume_name in sorted(expected_volumes.items()):
                archive = staging / f"{storage_id}.tar"
                evidence = self._export_volume(volume_name, archive)
                storage[storage_id] = {
                    "artifactId": f"{backup_id}/{storage_id}.tar",
                    **evidence,
                }
        except AdapterError as exc:
            primary_error = exc
        recovery_error: AdapterError | None = None
        try:
            for container_name in stopped:
                self._run(("start", container_name), timeout=60)
            if stopped:
                health = self.verify_health(spec, names)
                observation = self.observe(
                    spec,
                    expected_revision=expected_revision,
                    expected_images=expected_images,
                    verify_health=True,
                    infrastructure=infrastructure,
                )
                if observation["status"] != "in_sync" or observation["drift"]:
                    raise AdapterError(
                        "runtime_identity_mismatch",
                        "deployment runtime changed while creating its backup",
                        details={"observation": observation},
                    )
            else:
                health = {}
                observation = _before
        except AdapterError as exc:
            recovery_error = exc
        if primary_error is not None or recovery_error is not None:
            shutil.rmtree(staging, ignore_errors=True)
            if recovery_error is not None:
                raise AdapterError(
                    "backup_runtime_recovery_failed",
                    "deployment runtime could not be recovered after backup",
                    details={
                        "backupFailureCode": (
                            primary_error.code if primary_error is not None else None
                        ),
                        "recoveryFailureCode": recovery_error.code,
                    },
                ) from recovery_error
            assert primary_error is not None
            raise primary_error
        try:
            staging.rename(final_directory)
        except OSError as exc:
            shutil.rmtree(staging, ignore_errors=True)
            raise AdapterError(
                "backup_publication_failed",
                "deployment backup could not be published atomically",
            ) from exc
        return {
            "backupId": backup_id,
            "sourceRevision": expected_revision,
            "createdAt": timestamp(),
            "storage": storage,
            "health": health,
            "observation": observation,
        }

    def restore_data(
        self,
        spec: Mapping[str, Any],
        *,
        backup: Mapping[str, Any],
        plan_digest: str,
        expected_volumes: Mapping[str, str],
        expected_revision: str,
        expected_images: Mapping[str, str],
        infrastructure: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        backup_id = safe_id(backup.get("backupId"), "backup id")
        backup_digest = backup.get("backupDigest")
        if (
            DIGEST.fullmatch(plan_digest) is None
            or not isinstance(backup_digest, str)
            or DIGEST.fullmatch(backup_digest) is None
            or backup.get("sourceRevision") is None
            or backup.get("status") != "available"
        ):
            raise AdapterError(
                "backup_identity_mismatch", "deployment restore backup is invalid"
            )
        names, _before = self._assert_data_operation_identity(
            spec,
            expected_volumes=expected_volumes,
            expected_revision=expected_revision,
            expected_images=expected_images,
            infrastructure=infrastructure,
        )
        backup_directory = self._backup_directory(spec, backup_id)
        if backup_directory.is_symlink() or not backup_directory.is_dir():
            raise AdapterError(
                "backup_not_found", "exact deployment backup artifacts are absent"
            )
        storage = backup.get("storage")
        if not isinstance(storage, Mapping) or set(storage) != set(expected_volumes):
            raise AdapterError(
                "backup_identity_mismatch", "deployment backup storage set differs"
            )
        backup_archives: dict[str, Path] = {}
        for storage_id, evidence in sorted(storage.items()):
            archive = confined(
                backup_directory,
                f"{storage_id}.tar",
                "deployment backup artifact",
            )
            observed = self._archive_evidence(archive)
            if (
                not isinstance(evidence, Mapping)
                or evidence.get("artifactId")
                != f"{backup_id}/{storage_id}.tar"
                or observed
                != {
                    "contentDigest": evidence.get("contentDigest"),
                    "fileCount": evidence.get("fileCount"),
                    "bytes": evidence.get("bytes"),
                }
            ):
                raise AdapterError(
                    "backup_identity_mismatch",
                    "deployment backup artifact differs from durable identity",
                )
            backup_archives[storage_id] = archive
        expected_files = {f"{storage_id}.tar" for storage_id in storage}
        if {
            item.name for item in backup_directory.iterdir()
        } != expected_files:
            raise AdapterError(
                "backup_identity_mismatch",
                "deployment backup contains unexpected artifacts",
            )

        volume_labels: dict[str, dict[str, str]] = {}
        for storage_id, volume_name in expected_volumes.items():
            observed_volume = self._assert_owned(
                "volume", volume_name, spec["metadata"]["deploymentId"]
            )
            labels = dict(self._labels(observed_volume))
            if (
                observed_volume is None
                or labels.get(LABEL_STORAGE) != storage_id
            ):
                raise AdapterError(
                    "runtime_identity_mismatch",
                    "accepted deployment volume identity differs before restore",
                )
            volume_labels[storage_id] = labels

        rollback_directory = Path(
            tempfile.mkdtemp(
                prefix=f".{backup_id}.rollback-", dir=backup_directory.parent
            )
        )
        rollback_directory.chmod(0o700)
        runtime_plan = {"spec": spec, "planDigest": expected_revision}
        networks = dict(names["networks"])
        volumes = dict(names["volumes"])
        swapped = False
        try:
            for storage_id, volume_name in sorted(expected_volumes.items()):
                self._export_volume(
                    volume_name, rollback_directory / f"{storage_id}.tar"
                )
            swapped = True
            self._stop_swap_predecessor(runtime_plan, names)
            for storage_id, volume_name in sorted(expected_volumes.items()):
                self._run(("volume", "rm", volume_name), timeout=30)
                self._run(
                    (
                        "volume",
                        "create",
                        *self._label_args(volume_labels[storage_id]),
                        volume_name,
                    ),
                    timeout=30,
                )
                self._import_volume(volume_name, backup_archives[storage_id])
            services = self._run_services(
                runtime_plan,
                names,
                dict(expected_images),
                networks,
                volumes,
            )
            health = self.verify_health(spec, names)
            observation = self.observe(
                spec,
                expected_revision=expected_revision,
                expected_images=expected_images,
                verify_health=True,
                infrastructure=infrastructure,
            )
            if observation["status"] != "in_sync" or observation["drift"]:
                raise AdapterError(
                    "restore_verification_failed",
                    "restored deployment runtime does not match accepted identity",
                    details={"observation": observation},
                )
        except AdapterError as exc:
            rollback: dict[str, Any]
            if not swapped:
                rollback = {
                    "status": "not_required",
                    "revision": expected_revision,
                }
            else:
                try:
                    for service in spec["services"]:
                        container_name = names["containers"][service["id"]]
                        if (
                            self._assert_owned(
                                "container",
                                container_name,
                                spec["metadata"]["deploymentId"],
                            )
                            is not None
                        ):
                            self._run(
                                ("rm", "--force", container_name), timeout=30
                            )
                    for storage_id, volume_name in sorted(expected_volumes.items()):
                        if self._inspect("volume", volume_name) is not None:
                            self._run(("volume", "rm", volume_name), timeout=30)
                        self._run(
                            (
                                "volume",
                                "create",
                                *self._label_args(volume_labels[storage_id]),
                                volume_name,
                            ),
                            timeout=30,
                        )
                        self._import_volume(
                            volume_name,
                            rollback_directory / f"{storage_id}.tar",
                        )
                    self._run_services(
                        runtime_plan,
                        names,
                        dict(expected_images),
                        networks,
                        volumes,
                    )
                    rollback_health = self.verify_health(spec, names)
                    rollback_observation = self.observe(
                        spec,
                        expected_revision=expected_revision,
                        expected_images=expected_images,
                        verify_health=True,
                        infrastructure=infrastructure,
                    )
                    if (
                        rollback_observation["status"] != "in_sync"
                        or rollback_observation["drift"]
                    ):
                        raise AdapterError(
                            "restore_rollback_failed",
                            "pre-restore runtime could not be verified",
                        )
                    rollback = {
                        "status": "restored",
                        "revision": expected_revision,
                        "health": rollback_health,
                    }
                except AdapterError as rollback_exc:
                    rollback = {
                        "status": "failed",
                        "failureCode": rollback_exc.code,
                        "details": dict(rollback_exc.details),
                    }
            shutil.rmtree(rollback_directory, ignore_errors=True)
            raise AdapterError(
                exc.code,
                str(exc),
                details={**exc.details, "rollback": rollback},
            ) from exc
        try:
            shutil.rmtree(rollback_directory)
        except OSError as exc:
            raise AdapterError(
                "restore_cleanup_failed",
                "verified restore rollback artifacts could not be removed",
            ) from exc
        if backup_directory.is_symlink():
            raise AdapterError(
                "backup_identity_mismatch",
                "deployment backup became unsafe before consumption",
            )
        try:
            shutil.rmtree(backup_directory)
        except OSError as exc:
            raise AdapterError(
                "restore_cleanup_failed",
                "verified restore backup artifacts could not be consumed",
            ) from exc
        try:
            backup_directory.parent.rmdir()
        except OSError:
            pass
        return {
            "backupId": backup_id,
            "backupDigest": backup_digest,
            "backupConsumed": True,
            "restoredAt": timestamp(),
            "services": services,
            "health": health,
            "observation": observation,
        }

    def remove_runtime(
        self,
        spec: Mapping[str, Any],
        *,
        expected_revision: str | None = None,
        recovery_operation: str | None = None,
    ) -> dict[str, Any]:
        self._assert_target_identity(spec)
        if not isinstance(expected_revision, str):
            raise AdapterError(
                "runtime_identity_mismatch",
                "ordinary runtime removal requires an exact accepted revision",
            )
        names = self.resource_names(spec)
        deployment_id = spec["metadata"]["deploymentId"]
        if recovery_operation not in {None, "apply", "remove"}:
            raise AdapterError(
                "invalid_recovery_contract",
                "runtime removal recovery operation is unsupported",
            )
        persistence = {
            item["id"]: item["persistence"]
            for service in spec["services"]
            for item in service["storage"]
            if item["persistence"] != "externally_managed"
        }
        expected_images = {
            f"{names['images'][service['id']]}:{expected_revision[7:19]}"
            for service in spec["services"]
            if expected_revision is not None and service["build"]["mode"] == "source"
        }
        expected_before = {
            "container": set(names["containers"].values()),
            "network": set(names["networks"].values()),
            "volume": set(names["volumes"].values()),
            "image": expected_images,
        }
        observed_before = {
            kind: self._managed_names(kind, deployment_id)
            for kind in expected_before
        }
        inventory_differences = {
            kind: {
                "missing": sorted(expected - observed_before[kind]),
                "unexpected": sorted(observed_before[kind] - expected),
            }
            for kind, expected in expected_before.items()
        }
        allowed_missing = {
            "container": set(),
            "network": set(),
            "volume": set(),
            "image": set(),
        }
        if recovery_operation == "apply":
            allowed_missing = {
                kind: set(expected) for kind, expected in expected_before.items()
            }
        elif recovery_operation == "remove":
            allowed_missing["container"] = set(expected_before["container"])
            allowed_missing["network"] = set(expected_before["network"])
            allowed_missing["image"] = set(expected_before["image"])
            allowed_missing["volume"] = {
                names["volumes"][storage_id]
                for storage_id, policy in persistence.items()
                if policy == "ephemeral"
            }
        if any(
            difference["unexpected"]
            or set(difference["missing"]) - allowed_missing[kind]
            for kind, difference in inventory_differences.items()
        ):
            raise AdapterError(
                "unknown_runtime_residue",
                "deployment resources differ before ordinary removal",
                details={"inventoryDifferences": inventory_differences},
            )
        for service in spec["services"]:
            container_name = names["containers"][service["id"]]
            if container_name not in observed_before["container"]:
                continue
            if self._assert_exact_container(
                container_name,
                deployment_id=deployment_id,
                service_id=service["id"],
                source_commit=spec["source"]["commit"],
                expected_revision=expected_revision,
            ) is None:
                raise AdapterError(
                    "runtime_identity_mismatch",
                    f"deployment service is missing before removal: {service['id']}",
                )
        for network_id, name in names["networks"].items():
            if name not in observed_before["network"]:
                continue
            observed_network = self._assert_owned("network", name, deployment_id)
            labels = self._labels(observed_network or {})
            if (
                observed_network is None
                or labels.get(LABEL_NETWORK) != network_id
                or labels.get(LABEL_PLAN) != expected_revision
                or labels.get(LABEL_REVISION) != expected_revision
                or labels.get(LABEL_SOURCE) != spec["source"]["commit"]
            ):
                raise AdapterError(
                    "runtime_identity_mismatch",
                    f"deployment network identity differs before removal: {network_id}",
                )
        retained: list[str] = []
        retained_storage: dict[str, str] = {}
        for storage_id, name in names["volumes"].items():
            if name not in observed_before["volume"]:
                continue
            observed = self._assert_owned("volume", name, deployment_id)
            labels = self._labels(observed or {})
            if (
                observed is None
                or labels.get(LABEL_STORAGE) != storage_id
                or labels.get(LABEL_PLAN) != expected_revision
                or labels.get(LABEL_REVISION) != expected_revision
                or labels.get(LABEL_SOURCE) != spec["source"]["commit"]
            ):
                raise AdapterError(
                    "runtime_identity_mismatch",
                    f"deployment storage identity differs before removal: {storage_id}",
                )
            if persistence[storage_id] != "ephemeral":
                retained.append(name)
                retained_storage[storage_id] = name
        source_images: list[str] = []
        for service in spec["services"]:
            if service["build"]["mode"] != "source":
                continue
            image_name = f"{names['images'][service['id']]}:{expected_revision[7:19]}"
            if image_name not in observed_before["image"]:
                continue
            observed_image = self._assert_owned("image", image_name, deployment_id)
            labels = self._labels(observed_image or {})
            if (
                observed_image is None
                or labels.get(LABEL_PLAN) != expected_revision
                or labels.get(LABEL_REVISION) != expected_revision
                or labels.get(LABEL_SERVICE) != service["id"]
                or labels.get(LABEL_SOURCE) != spec["source"]["commit"]
            ):
                raise AdapterError(
                    "image_identity_mismatch",
                    f"deployment image differs before removal: {service['id']}",
                )
            source_images.append(image_name)

        removed: dict[str, list[str]] = {"containers": [], "networks": []}
        for name in reversed(list(names["containers"].values())):
            if name not in observed_before["container"]:
                continue
            self._run(("rm", "--force", "--time", "10", name), timeout=60)
            removed["containers"].append(name)
        for name in reversed(list(names["networks"].values())):
            if name not in observed_before["network"]:
                continue
            self._run(("network", "rm", name), timeout=30)
            removed["networks"].append(name)
        ephemeral_removed: list[str] = []
        for storage_id, name in names["volumes"].items():
            if (
                name in observed_before["volume"]
                and persistence[storage_id] == "ephemeral"
            ):
                self._run(("volume", "rm", name), timeout=30)
                ephemeral_removed.append(name)
        removed_images: list[str] = []
        for image_name in source_images:
            self._run(("image", "rm", image_name), timeout=60)
            removed_images.append(image_name)
        expected_after = {
            "container": set(),
            "network": set(),
            "volume": set(retained),
            "image": set(),
        }
        observed_after = {
            kind: self._managed_names(kind, deployment_id)
            for kind in expected_after
        }
        inventory_after = {
            kind: {
                "missing": sorted(expected - observed_after[kind]),
                "unexpected": sorted(observed_after[kind] - expected),
            }
            for kind, expected in expected_after.items()
        }
        if any(
            difference["missing"] or difference["unexpected"]
            for difference in inventory_after.values()
        ):
            raise AdapterError(
                "removal_verification_failed",
                "deployment resources differ after ordinary removal",
                details={"inventoryDifferences": inventory_after},
            )
        for storage_id, name in retained_storage.items():
            observed = self._assert_owned("volume", name, deployment_id)
            labels = self._labels(observed or {})
            if (
                observed is None
                or labels.get(LABEL_STORAGE) != storage_id
                or labels.get(LABEL_PLAN) != expected_revision
                or labels.get(LABEL_REVISION) != expected_revision
                or labels.get(LABEL_SOURCE) != spec["source"]["commit"]
            ):
                raise AdapterError(
                    "removal_verification_failed",
                    "retained deployment storage identity changed during removal",
                )
        return {
            "removed": removed,
            "retainedVolumes": retained,
            "retainedStorageIdentities": dict(sorted(retained_storage.items())),
            "ephemeralVolumesRemoved": ephemeral_removed,
            "removedImages": removed_images,
            "ordinaryRemovalPreservedData": True,
            "verifiedRuntimeAbsent": True,
            "partialRecovery": recovery_operation is not None,
            "recoveryOperation": recovery_operation,
        }

    def purge_data(
        self,
        spec: Mapping[str, Any],
        *,
        expected_volumes: Mapping[str, str],
        expected_revision: str,
        recover_interrupted: bool = False,
    ) -> dict[str, Any]:
        self._assert_target_identity(spec)
        names = self.resource_names(spec)
        deployment_id = spec["metadata"]["deploymentId"]
        persistent_ids = {
            item["id"]
            for service in spec["services"]
            for item in service["storage"]
            if item["persistence"] != "ephemeral"
        }
        if (
            not expected_volumes
            or set(expected_volumes) != persistent_ids
            or any(
                names["volumes"].get(storage_id) != volume_name
                for storage_id, volume_name in expected_volumes.items()
            )
        ):
            raise AdapterError(
                "purge_identity_mismatch",
                "purge request does not match exact retained volume identities",
            )
        expected_volume_names = set(expected_volumes.values())
        expected_before = {
            "container": set(),
            "network": set(),
            "volume": expected_volume_names,
            "image": set(),
        }
        observed_before = {
            kind: self._managed_names(kind, deployment_id)
            for kind in expected_before
        }
        inventory_differences = {
            kind: {
                "missing": sorted(expected - observed_before[kind]),
                "unexpected": sorted(observed_before[kind] - expected),
            }
            for kind, expected in expected_before.items()
        }
        if any(
            difference["unexpected"]
            or (
                difference["missing"]
                and (kind != "volume" or not recover_interrupted)
            )
            for kind, difference in inventory_differences.items()
        ):
            raise AdapterError(
                "purge_identity_mismatch",
                "deployment data purge requires the exact retained resource inventory",
                details={"inventoryDifferences": inventory_differences},
            )
        for kind, resources in (
            ("container", names["containers"].values()),
            ("network", names["networks"].values()),
        ):
            for name in resources:
                if self._assert_owned(kind, name, deployment_id) is not None:
                    raise AdapterError(
                        "runtime_present",
                        "runtime must be absent before persistent data can be purged",
                    )
        for service in spec["services"]:
            if service["build"]["mode"] != "source":
                continue
            image_name = (
                f"{names['images'][service['id']]}:{expected_revision[7:19]}"
            )
            if self._assert_owned("image", image_name, deployment_id) is not None:
                raise AdapterError(
                    "runtime_present",
                    "deployment images must be absent before persistent data can be purged",
                )
        storage_ids_by_name = {
            name: storage_id for storage_id, name in expected_volumes.items()
        }
        validated_volumes: list[str] = []
        for name in expected_volume_names:
            if name not in observed_before["volume"]:
                continue
            observed = self._assert_owned("volume", name, deployment_id)
            labels = self._labels(observed or {})
            if (
                observed is None
                or labels.get(LABEL_STORAGE) != storage_ids_by_name[name]
                or labels.get(LABEL_PLAN) != expected_revision
                or labels.get(LABEL_REVISION) != expected_revision
                or labels.get(LABEL_SOURCE) != spec["source"]["commit"]
            ):
                raise AdapterError(
                    "purge_identity_mismatch",
                    "purge request does not match exact retained volume labels",
                )
            validated_volumes.append(name)
        removed: list[str] = []
        for name in validated_volumes:
            self._run(("volume", "rm", name), timeout=30)
            removed.append(name)
        remaining = [
            name
            for name in expected_volume_names
            if self._assert_owned("volume", name, deployment_id) is not None
        ]
        if remaining:
            raise AdapterError(
                "purge_verification_failed",
                "one or more deployment volumes remain after purge",
                details={"remainingVolumes": remaining, "purgedVolumes": removed},
            )
        unexpected_after = {
            kind: sorted(self._managed_names(kind, deployment_id))
            for kind in ("container", "network", "volume", "image")
        }
        if any(unexpected_after.values()):
            raise AdapterError(
                "purge_verification_failed",
                "deployment resources remain after data purge",
                details={"unexpectedResources": unexpected_after},
            )
        return {
            "purgedVolumes": removed,
            "alreadyAbsentVolumes": sorted(
                expected_volume_names - observed_before["volume"]
            ),
            "irreversible": True,
            "verifiedAbsent": True,
            "interruptedRecovery": recover_interrupted,
        }


__all__ = [
    "LABEL_DEPLOYMENT",
    "LABEL_MANAGED",
    "RootlessPodmanAdapter",
]
