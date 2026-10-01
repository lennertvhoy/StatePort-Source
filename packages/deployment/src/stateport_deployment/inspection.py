"""Read-only project discovery and exact Git source identity."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import subprocess
import time
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit, urlunsplit

from .contracts import DEPLOYMENT_SCHEMA, INSPECTION_SCHEMA, validate_deployment_spec
from .errors import DeploymentRefusal
from .util import (
    digest_bytes,
    digest_value,
    relative_posix,
    safe_id,
    strict_mapping_document,
)


DESCRIPTORS = (
    "stateport.deployment.yaml",
    "stateport.deployment.yml",
    "stateport.deployment.json",
)
COMPOSE_FILES = ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml")
CONTAINERFILES = ("Containerfile", "Dockerfile")
PYTHON_MARKERS = ("pyproject.toml", "requirements.txt", "requirements.lock", "Pipfile")
NODE_MARKERS = ("package.json",)
STATIC_DIRS = ("dist", "build", "public")
MAX_SOURCE_BYTES = 512 * 1024 * 1024


def assisted_runtime_contract(candidate: Mapping[str, Any]) -> dict[str, Any]:
    """Return the exact generated runtime fields shared by inspect and plan."""

    source = candidate.get("source")
    if source == "assisted_python":
        command = ["python3", "app.py"]
        context = "."
        health_path = "/health"
        health_command = [
            "python3",
            "-c",
            "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2).read()",
        ]
    elif source == "assisted_node":
        command = ["node", "server.js"]
        context = "."
        health_path = "/health"
        health_command = [
            "node",
            "-e",
            "fetch('http://127.0.0.1:8080/health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))",
        ]
    elif source == "assisted_static":
        command = [
            "python3",
            "-m",
            "http.server",
            "8080",
            "--bind",
            "0.0.0.0",
            "--directory",
            "/app",
        ]
        context = relative_posix(candidate.get("staticRoot"), "static root")
        health_path = "/"
        health_command = [
            "python3",
            "-c",
            "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/', timeout=2).read()",
        ]
    else:
        raise DeploymentRefusal(
            "assisted_profile_unsupported",
            "assisted inspection candidate is not a supported exact profile",
        )
    return {
        "sourcePath": context,
        "command": command,
        "health": {
            "type": "http",
            "path": health_path,
            "portName": "http",
            "command": health_command,
            "intervalSeconds": 2,
            "timeoutSeconds": 3,
            "startPeriodSeconds": 5,
        },
    }


def sanitized_git_environment() -> dict[str, str]:
    """Return the complete, intentionally tiny environment for exact Git reads."""

    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_COUNT": "2",
        "GIT_CONFIG_KEY_0": "core.fsmonitor",
        "GIT_CONFIG_VALUE_0": "false",
        "GIT_CONFIG_KEY_1": "core.hooksPath",
        "GIT_CONFIG_VALUE_1": "/dev/null",
    }


def sanitized_git_command(root: Path, *args: str) -> tuple[str, ...]:
    return ("git", "--no-replace-objects", "-C", str(root), *args)


def _run_git(root: Path, *args: str, check: bool = True, binary: bool = False) -> str | bytes:
    try:
        completed = subprocess.run(
            sanitized_git_command(root, *args),
            capture_output=True,
            text=not binary,
            env=sanitized_git_environment(),
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DeploymentRefusal("source_identity_unavailable", "Git source identity could not be observed") from exc
    if check and completed.returncode != 0:
        raise DeploymentRefusal(
            "source_identity_unavailable",
            "project is not inside a readable Git repository",
            details={"gitOperation": args[0] if args else "unknown"},
        )
    return completed.stdout


def _git_blob_content_digest(
    repository: Path, object_id: str, expected_size: int
) -> str:
    """Stream one replacement-disabled Git blob into a SHA-256 digest."""

    try:
        process = subprocess.Popen(
            sanitized_git_command(repository, "cat-file", "blob", object_id),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=sanitized_git_environment(),
        )
    except OSError as exc:
        raise DeploymentRefusal(
            "source_identity_unavailable", "tracked source blob could not be read"
        ) from exc
    assert process.stdout is not None
    assert process.stderr is not None
    hasher = hashlib.sha256()
    observed_size = 0
    stderr = bytearray()
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    deadline = time.monotonic() + 30
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                process.kill()
                process.wait(timeout=5)
                raise DeploymentRefusal(
                    "source_identity_unavailable", "tracked source blob read timed out"
                )
            events = selector.select(timeout=min(remaining, 0.5))
            if not events and process.poll() is not None:
                events = [
                    (key, selectors.EVENT_READ)
                    for key in tuple(selector.get_map().values())
                ]
            for key, _mask in events:
                chunk = os.read(key.fileobj.fileno(), 1024 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.data == "stdout":
                    observed_size += len(chunk)
                    if (
                        observed_size > expected_size
                        or observed_size > MAX_SOURCE_BYTES
                    ):
                        process.kill()
                        process.wait(timeout=5)
                        raise DeploymentRefusal(
                            "source_inventory_invalid",
                            "tracked source blob size changed while reading",
                        )
                    hasher.update(chunk)
                elif len(stderr) < 16 * 1024:
                    stderr.extend(chunk[: 16 * 1024 - len(stderr)])
    finally:
        selector.close()
    returncode = process.wait(timeout=5)
    if returncode != 0 or observed_size != expected_size:
        raise DeploymentRefusal(
            "source_identity_unavailable",
            "tracked source blob could not be read exactly",
            details={"gitError": stderr.decode("utf-8", errors="replace")[:1024]},
        )
    return f"sha256:{hasher.hexdigest()}"


def _public_origin(value: str | None) -> str | None:
    if not value:
        return None
    if "://" in value:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        if not hostname:
            return None
        netloc = hostname + (f":{parsed.port}" if parsed.port is not None else "")
        return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))
    if re.match(r"^[^/@:]+@[^/:]+:", value):
        return value.split("@", 1)[1]
    return None


def _safe_project(path: Path | str) -> Path:
    source = Path(path).expanduser()
    if source.is_symlink() or not source.is_dir():
        raise DeploymentRefusal("project_not_found", "project path is missing or unsafe")
    try:
        resolved = source.resolve(strict=True)
    except OSError as exc:
        raise DeploymentRefusal("project_not_found", "project path could not be resolved") from exc
    if resolved.is_symlink():
        raise DeploymentRefusal("project_not_found", "project path may not be a symlink")
    return resolved


def _parse_z_records(raw: bytes) -> list[bytes]:
    records = raw.split(b"\0")
    if records and records[-1] == b"":
        records.pop()
    return records


@dataclass(frozen=True)
class SourceIdentity:
    repository_identity: str
    repository_root: str
    project_path: str
    commit: str
    tree_digest: str
    dirty: bool
    dirty_digest: str
    descriptor_digest: str
    origin: str | None
    inventory: tuple[dict[str, Any], ...]

    def to_spec(self) -> dict[str, Any]:
        return {
            "repositoryIdentity": self.repository_identity,
            "repositoryRoot": self.repository_root,
            "projectPath": self.project_path,
            "commit": self.commit,
            "treeDigest": self.tree_digest,
            "dirty": self.dirty,
            "dirtyDigest": self.dirty_digest,
            "dirtyPolicy": "refuse",
            "descriptorDigest": self.descriptor_digest,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.to_spec(),
            "origin": self.origin,
            "inventory": list(self.inventory),
        }


def git_source_identity(project: Path | str, *, descriptor_digest: str) -> SourceIdentity:
    project_root = _safe_project(project)
    repository_text = _run_git(project_root, "rev-parse", "--show-toplevel")
    assert isinstance(repository_text, str)
    repository = Path(repository_text.strip())
    if repository.is_symlink() or not repository.is_dir():
        raise DeploymentRefusal("source_identity_unavailable", "Git repository root is unsafe")
    try:
        relative = project_root.relative_to(repository).as_posix() or "."
    except ValueError as exc:
        raise DeploymentRefusal("source_identity_unavailable", "project escaped its Git repository") from exc
    relative = relative_posix(relative, "project path")
    commit_text = _run_git(repository, "rev-parse", "--verify", "HEAD")
    assert isinstance(commit_text, str)
    commit = commit_text.strip()
    origin_text = _run_git(repository, "remote", "get-url", "origin", check=False)
    assert isinstance(origin_text, str)
    origin = _public_origin(origin_text.strip() or None)
    identity_material = {"origin": origin, "repositoryRoot": str(repository.resolve())}
    repository_identity = digest_value(identity_material)

    pathspec = "." if relative == "." else relative
    status_text = _run_git(
        repository,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--",
        pathspec,
    )
    assert isinstance(status_text, str)
    status_lines = sorted(line for line in status_text.splitlines() if line)
    dirty_digest = digest_value(status_lines)

    raw = _run_git(repository, "ls-tree", "-r", "-z", commit, "--", pathspec, binary=True)
    assert isinstance(raw, bytes)
    prefix = "" if relative == "." else relative.rstrip("/") + "/"
    inventory: list[dict[str, Any]] = []
    total_source_bytes = 0
    for record in _parse_z_records(raw):
        try:
            metadata, encoded_path = record.split(b"\t", 1)
            mode, kind, object_id = metadata.decode("ascii").split(" ")
            tracked_path = encoded_path.decode("utf-8")
        except (ValueError, UnicodeError) as exc:
            raise DeploymentRefusal("source_inventory_invalid", "Git source inventory is malformed") from exc
        if kind != "blob" or mode == "160000":
            raise DeploymentRefusal("unsupported_source_entry", "submodules and non-file source entries are unsupported")
        local_path = tracked_path.removeprefix(prefix)
        local_path = relative_posix(local_path, "tracked source path", allow_dot=False)
        if mode == "120000":
            raise DeploymentRefusal("symlink_escape", f"tracked source symlink is unsupported: {local_path}")
        size_text = _run_git(repository, "cat-file", "-s", object_id)
        assert isinstance(size_text, str)
        try:
            size = int(size_text.strip())
        except ValueError as exc:
            raise DeploymentRefusal(
                "source_inventory_invalid", "tracked source blob size is invalid"
            ) from exc
        if size < 0:
            raise DeploymentRefusal(
                "source_inventory_invalid", "tracked source blob size is invalid"
            )
        total_source_bytes += size
        if total_source_bytes > MAX_SOURCE_BYTES:
            raise DeploymentRefusal(
                "source_too_large", "tracked source exceeds the alpha size limit"
            )
        inventory.append(
            {
                "path": local_path,
                "mode": mode,
                "objectId": object_id,
                "contentDigest": _git_blob_content_digest(
                    repository, object_id, size
                ),
            }
        )
    inventory.sort(key=lambda item: item["path"])
    if not inventory:
        raise DeploymentRefusal("empty_source", "project contains no tracked source files")
    return SourceIdentity(
        repository_identity=repository_identity,
        repository_root=str(repository.resolve()),
        project_path=relative,
        commit=commit,
        tree_digest=digest_value(inventory),
        dirty=bool(status_lines),
        dirty_digest=dirty_digest,
        descriptor_digest=descriptor_digest,
        origin=origin,
        inventory=tuple(inventory),
    )


def read_exact_source_file(
    source: Mapping[str, Any],
    inventory: Sequence[Mapping[str, Any]],
    relative: str,
    *,
    maximum_bytes: int = 2 * 1024 * 1024,
) -> bytes:
    """Read one approved tracked blob without consulting mutable worktree bytes."""

    relative = relative_posix(relative, "tracked source file", allow_dot=False)
    matches = [item for item in inventory if item.get("path") == relative]
    if len(matches) != 1:
        raise DeploymentRefusal("source_identity_mismatch", "tracked source file is missing or ambiguous")
    object_id = matches[0].get("objectId")
    content_digest = matches[0].get("contentDigest")
    if not isinstance(object_id, str) or re.fullmatch(r"[0-9a-f]{40,64}", object_id) is None:
        raise DeploymentRefusal("source_identity_mismatch", "tracked source object identity is invalid")
    if not isinstance(content_digest, str) or re.fullmatch(
        r"sha256:[0-9a-f]{64}", content_digest
    ) is None:
        raise DeploymentRefusal(
            "source_identity_mismatch", "tracked source content identity is invalid"
        )
    repository = Path(str(source.get("repositoryRoot", "")))
    raw = _run_git(repository, "cat-file", "blob", object_id, binary=True)
    assert isinstance(raw, bytes)
    if len(raw) > maximum_bytes:
        raise DeploymentRefusal("descriptor_too_large", "deployment input exceeds the alpha size limit")
    if digest_bytes(raw) != content_digest:
        raise DeploymentRefusal(
            "source_identity_mismatch", "tracked source content differs from its inventory"
        )
    return raw


def _load_structured(path: Path) -> Mapping[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise DeploymentRefusal("descriptor_invalid", f"could not parse {path.name}") from exc
    return strict_mapping_document(
        text,
        format_name="json" if path.suffix == ".json" else "yaml",
        label=path.name,
    )


def _regular_file(root: Path, relative: str) -> Path | None:
    candidate = root / relative
    if candidate.is_symlink():
        raise DeploymentRefusal("symlink_escape", f"project marker may not be a symlink: {relative}")
    return candidate if candidate.is_file() else None


def _container_duration(value: str) -> int:
    match = re.fullmatch(r"([1-9][0-9]*)(s|m)", value)
    if match is None:
        raise DeploymentRefusal(
            "containerfile_unsupported",
            "Containerfile health durations must be bounded seconds or minutes",
        )
    seconds = int(match.group(1)) * (60 if match.group(2) == "m" else 1)
    if seconds > 3600:
        raise DeploymentRefusal(
            "containerfile_unsupported",
            "Containerfile health duration exceeds the alpha limit",
        )
    return seconds


def _json_argv(value: str, label: str) -> list[str]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise DeploymentRefusal(
            "containerfile_unsupported", f"{label} must use JSON argv form"
        ) from exc
    if (
        not isinstance(parsed, list)
        or not parsed
        or any(not isinstance(item, str) or not item or "\x00" in item for item in parsed)
    ):
        raise DeploymentRefusal(
            "containerfile_unsupported", f"{label} must be a non-empty argv vector"
        )
    return parsed


def parse_containerfile_contract(
    text: str, *, require_runtime: bool = True
) -> dict[str, Any]:
    """Parse the deliberately small, offline-safe declared alpha subset."""

    if not isinstance(text, str) or len(text.encode("utf-8")) > 2 * 1024 * 1024:
        raise DeploymentRefusal(
            "containerfile_unsupported", "Containerfile exceeds the alpha size limit"
        )
    instructions: list[tuple[str, str]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("\\") or "<<" in line:
            raise DeploymentRefusal(
                "containerfile_unsupported",
                "Containerfile continuations and heredocs require a StatePort descriptor",
            )
        match = re.fullmatch(r"([A-Za-z]+)\s+(.+)", line)
        if match is None:
            raise DeploymentRefusal(
                "containerfile_unsupported", "Containerfile instruction is malformed"
            )
        instruction, body = match.group(1).upper(), match.group(2).strip()
        if instruction not in {
            "FROM",
            "WORKDIR",
            "COPY",
            "RUN",
            "USER",
            "EXPOSE",
            "HEALTHCHECK",
            "CMD",
            "LABEL",
        }:
            raise DeploymentRefusal(
                "containerfile_unsupported",
                f"Containerfile instruction requires a StatePort descriptor: {instruction}",
            )
        instructions.append((instruction, body))
    if not instructions:
        raise DeploymentRefusal("containerfile_unsupported", "Containerfile is empty")

    from_values = [body for instruction, body in instructions if instruction == "FROM"]
    if len(from_values) != 1:
        raise DeploymentRefusal(
            "containerfile_unsupported", "declared alpha Containerfiles require one build stage"
        )
    base_parts = from_values[0].split()
    if (
        len(base_parts) != 1
        or re.fullmatch(r"[^\s@$]+(?:/[^\s@$]+)*@sha256:[0-9a-f]{64}", base_parts[0])
        is None
    ):
        raise DeploymentRefusal(
            "mutable_base_image", "Containerfile base image must bind one exact digest"
        )

    workdir = "/"
    user: tuple[int, int] | None = None
    ports: list[int] = []
    command: list[str] | None = None
    health: dict[str, Any] | None = None
    for instruction, body in instructions:
        if instruction == "WORKDIR":
            if not body.startswith("/") or ".." in body.split("/") or any(
                token in body for token in ("$", "`", "\x00")
            ):
                raise DeploymentRefusal(
                    "unsafe_path", "Containerfile WORKDIR must be an exact absolute path"
                )
            workdir = body
        elif instruction == "COPY":
            try:
                parts = shlex.split(body)
            except ValueError as exc:
                raise DeploymentRefusal(
                    "containerfile_unsupported", "Containerfile COPY is malformed"
                ) from exc
            while parts and parts[0].startswith("--"):
                flag = parts.pop(0)
                if re.fullmatch(r"--chown=[1-9][0-9]*:[1-9][0-9]*", flag) is None:
                    raise DeploymentRefusal(
                        "containerfile_unsupported",
                        "Containerfile COPY supports only numeric --chown",
                    )
            if len(parts) < 2:
                raise DeploymentRefusal(
                    "containerfile_unsupported", "Containerfile COPY requires source and destination"
                )
            for source in parts[:-1]:
                relative_posix(source, "Containerfile COPY source")
        elif instruction == "RUN":
            if re.search(r"(?:^|\s)--(?:mount|network|security)(?:=|\s)", body):
                raise DeploymentRefusal(
                    "containerfile_unsupported",
                    "Containerfile RUN may not request host-sensitive build extensions",
                )
        elif instruction == "USER":
            match = re.fullmatch(r"([1-9][0-9]*)(?::([1-9][0-9]*))?", body)
            if match is None:
                raise DeploymentRefusal(
                    "root_runtime", "Containerfile must end with a numeric non-root USER"
                )
            uid = int(match.group(1))
            user = (uid, int(match.group(2) or uid))
        elif instruction == "EXPOSE":
            for item in body.split():
                match = re.fullmatch(r"([1-9][0-9]{0,4})(?:/tcp)?", item)
                if match is None or not 1 <= int(match.group(1)) <= 65535:
                    raise DeploymentRefusal(
                        "containerfile_unsupported", "Containerfile EXPOSE must use TCP ports"
                    )
                ports.append(int(match.group(1)))
        elif instruction == "CMD":
            if command is not None:
                raise DeploymentRefusal(
                    "containerfile_unsupported", "Containerfile may declare one exact CMD"
                )
            command = _json_argv(body, "Containerfile CMD")
        elif instruction == "HEALTHCHECK":
            if health is not None or body == "NONE":
                raise DeploymentRefusal(
                    "missing_health", "Containerfile requires one executable health check"
                )
            tokens = body.split()
            options = {
                "intervalSeconds": 5,
                "timeoutSeconds": 3,
                "startPeriodSeconds": 20,
            }
            while tokens and tokens[0].startswith("--"):
                key, separator, raw_value = tokens.pop(0)[2:].partition("=")
                mapping = {
                    "interval": "intervalSeconds",
                    "timeout": "timeoutSeconds",
                    "start-period": "startPeriodSeconds",
                }
                if not separator or key not in mapping:
                    raise DeploymentRefusal(
                        "containerfile_unsupported", "Containerfile health option is unsupported"
                    )
                options[mapping[key]] = _container_duration(raw_value)
            remainder = " ".join(tokens)
            if not remainder.startswith("CMD "):
                raise DeploymentRefusal(
                    "containerfile_unsupported", "Containerfile health must use CMD JSON form"
                )
            health = {
                "type": "command",
                "path": None,
                "portName": None,
                "command": _json_argv(remainder[4:].strip(), "Containerfile HEALTHCHECK"),
                **options,
            }
    if require_runtime and user is None:
        raise DeploymentRefusal(
            "missing_nonroot_user", "Containerfile requires a numeric non-root USER"
        )
    if require_runtime and command is None:
        raise DeploymentRefusal(
            "containerfile_unsupported", "Containerfile requires an exact JSON CMD"
        )
    if require_runtime and health is None:
        raise DeploymentRefusal(
            "missing_health", "Containerfile requires an exact command health check"
        )
    return {
        "baseImage": base_parts[0],
        "workdir": workdir,
        "uid": user[0] if user is not None else None,
        "gid": user[1] if user is not None else None,
        "ports": sorted(set(ports)),
        "command": command,
        "health": health,
    }


def validate_project_declared_builds(
    spec: Mapping[str, Any],
    source: Mapping[str, Any],
    inventory: Sequence[Mapping[str, Any]],
) -> None:
    """Validate project-owned build files without trusting overlay provenance."""

    for service in spec["services"]:
        build = service["build"]
        if build["generated"] is True:
            raise DeploymentRefusal(
                "generated_build_forbidden",
                "project descriptors may not claim StatePort-generated build files",
            )
        if build["mode"] != "source":
            continue
        context = relative_posix(build["context"], "build context")
        containerfile = relative_posix(
            build["containerfile"], "Containerfile", allow_dot=False
        )
        declared_path = (
            containerfile if context == "." else f"{context}/{containerfile}"
        )
        declared_path = relative_posix(
            declared_path, "declared Containerfile", allow_dot=False
        )
        try:
            text = read_exact_source_file(
                source, inventory, declared_path
            ).decode("utf-8")
        except UnicodeError as exc:
            raise DeploymentRefusal(
                "containerfile_unsupported", "Containerfile must be UTF-8 text"
            ) from exc
        parse_containerfile_contract(text, require_runtime=False)


def _containerfile_findings(
    path: Path,
) -> tuple[list[str], list[str], dict[str, Any] | None]:
    try:
        contract = parse_containerfile_contract(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as exc:
        raise DeploymentRefusal("descriptor_invalid", f"could not read {path.name}") from exc
    except DeploymentRefusal as exc:
        return [f"containerfile:{exc.code}"], [str(exc)], None
    return [], [], contract


def _containerfile_review_projection(
    contract: Mapping[str, Any], *, containerfile: str
) -> dict[str, Any]:
    return {
        "id": "app",
        "source": "containerfile",
        "sourcePath": ".",
        "build": {
            "mode": "source",
            "context": ".",
            "containerfile": containerfile,
            "generated": False,
        },
        "image": {"reference": None, "acceptedDigest": None},
        "command": list(contract["command"]),
        "runtimeUser": {
            "mode": "nonroot",
            "uid": contract["uid"],
            "gid": contract["gid"],
        },
        "ports": [
            {
                "name": "http" if index == 1 else f"port-{index}",
                "containerPort": port,
                "hostAddress": "127.0.0.1",
                "hostPort": 0,
            }
            for index, port in enumerate(contract["ports"], 1)
        ],
        "storage": [],
        "health": deepcopy(dict(contract["health"])),
        "secretReferences": [],
        "networks": ["internal"],
    }


def _compose_duration(value: object, default: int) -> int:
    if value is None:
        return default
    if not isinstance(value, str):
        raise DeploymentRefusal(
            "compose_unsupported", "Compose health durations must be strings"
        )
    match = re.fullmatch(r"([1-9][0-9]*)(s|m)", value)
    if match is None:
        raise DeploymentRefusal(
            "compose_unsupported", "Compose health duration is unsupported"
        )
    seconds = int(match.group(1)) * (60 if match.group(2) == "m" else 1)
    if seconds > 3600:
        raise DeploymentRefusal(
            "compose_unsupported", "Compose health duration exceeds the alpha limit"
        )
    return seconds


def parse_compose_contract(
    value: Mapping[str, Any],
    *,
    source: Mapping[str, Any],
    inventory: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Normalize the one strict Compose subset shared by inspect and plan."""

    def contains_interpolation(candidate: object) -> bool:
        if isinstance(candidate, str):
            return "${" in candidate
        if isinstance(candidate, Mapping):
            return any(
                contains_interpolation(key) or contains_interpolation(item)
                for key, item in candidate.items()
            )
        if isinstance(candidate, (list, tuple)):
            return any(contains_interpolation(item) for item in candidate)
        return False

    compose = deepcopy(dict(value))
    if contains_interpolation(compose):
        raise DeploymentRefusal(
            "compose_unsupported",
            "Compose interpolation requires an explicit StatePort descriptor",
        )
    allowed_top = {"name", "services", "networks", "volumes"}
    unknown_top = set(compose) - allowed_top
    if unknown_top:
        raise DeploymentRefusal(
            "compose_unsupported",
            f"unsupported Compose fields: {sorted(unknown_top)}",
        )
    raw_services = compose.get("services")
    if not isinstance(raw_services, Mapping) or not raw_services:
        raise DeploymentRefusal(
            "compose_unsupported", "Compose services are missing"
        )
    raw_networks = compose.get("networks", {"internal": {}})
    if not isinstance(raw_networks, Mapping) or not raw_networks:
        raise DeploymentRefusal(
            "compose_unsupported", "Compose networks are invalid"
        )
    if any(item not in (None, {}) for item in raw_networks.values()):
        raise DeploymentRefusal(
            "compose_unsupported",
            "Compose network options require an explicit StatePort descriptor",
        )
    raw_volumes = compose.get("volumes", {})
    if not isinstance(raw_volumes, Mapping) or any(
        item not in (None, {}) for item in raw_volumes.values()
    ):
        raise DeploymentRefusal(
            "compose_unsupported",
            "Compose volume options require an explicit StatePort descriptor",
        )
    declared_volumes = {safe_id(name, "storage id") for name in raw_volumes}
    networks = [
        {"id": safe_id(name, "network id"), "public": False}
        for name in sorted(raw_networks)
    ]
    network_ids = [item["id"] for item in networks]
    services: list[dict[str, Any]] = []
    for raw_service_id, raw_value in sorted(raw_services.items()):
        service_id = safe_id(raw_service_id, "service id")
        if not isinstance(raw_value, Mapping):
            raise DeploymentRefusal(
                "compose_unsupported", "Compose service is invalid"
            )
        raw = dict(raw_value)
        if raw.get("privileged") is True:
            raise DeploymentRefusal(
                "privileged_container", "Compose privileged services are forbidden"
            )
        if any(raw.get(name) == "host" for name in ("network_mode", "pid", "ipc")):
            raise DeploymentRefusal(
                "host_namespace", "Compose host namespaces are forbidden"
            )
        allowed = {
            "build",
            "image",
            "command",
            "working_dir",
            "user",
            "ports",
            "volumes",
            "networks",
            "healthcheck",
            "environment",
        }
        unknown = set(raw) - allowed
        if unknown:
            raise DeploymentRefusal(
                "compose_unsupported",
                f"unsupported Compose service fields for {service_id}: {sorted(unknown)}",
            )
        user = str(raw.get("user", ""))
        if re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", user) is None:
            raise DeploymentRefusal(
                "root_runtime",
                f"Compose service {service_id} requires numeric non-root uid:gid",
            )
        uid, gid = (int(part) for part in user.split(":"))
        command = raw.get("command")
        if (
            not isinstance(command, list)
            or not command
            or any(not isinstance(item, str) or not item for item in command)
        ):
            raise DeploymentRefusal(
                "compose_unsupported",
                f"Compose service {service_id} command must be an argv list",
            )
        build_raw = raw.get("build")
        image_raw = raw.get("image")
        if build_raw is not None and image_raw is not None:
            raise DeploymentRefusal(
                "compose_unsupported",
                "Compose service may not mix build and image modes",
            )
        if build_raw is not None:
            if isinstance(build_raw, str):
                context, containerfile = build_raw, "Containerfile"
            elif isinstance(build_raw, Mapping) and set(build_raw) <= {
                "context",
                "dockerfile",
            }:
                context = build_raw.get("context", ".")
                containerfile = build_raw.get("dockerfile", "Containerfile")
            else:
                raise DeploymentRefusal(
                    "compose_unsupported",
                    f"Compose build for {service_id} is unsupported",
                )
            build = {
                "mode": "source",
                "context": relative_posix(context, "build context"),
                "containerfile": relative_posix(
                    containerfile, "containerfile", allow_dot=False
                ),
                "generated": False,
            }
            exact_containerfile = relative_posix(
                build["containerfile"]
                if build["context"] == "."
                else f"{build['context']}/{build['containerfile']}",
                "exact Compose Containerfile",
                allow_dot=False,
            )
            try:
                containerfile_text = read_exact_source_file(
                    source, inventory, exact_containerfile
                ).decode("utf-8")
            except UnicodeError as exc:
                raise DeploymentRefusal(
                    "containerfile_unsupported",
                    "Compose Containerfile must be UTF-8 text",
                ) from exc
            parse_containerfile_contract(
                containerfile_text, require_runtime=False
            )
            image = {"reference": None, "acceptedDigest": None}
        else:
            if not isinstance(image_raw, str) or "@sha256:" not in image_raw:
                raise DeploymentRefusal(
                    "mutable_image",
                    f"Compose image for {service_id} must be digest-pinned",
                )
            build = {
                "mode": "image",
                "context": ".",
                "containerfile": "Containerfile",
                "generated": False,
            }
            image = {"reference": image_raw, "acceptedDigest": None}
        ports: list[dict[str, Any]] = []
        for index, raw_port_value in enumerate(raw.get("ports", []), 1):
            if not isinstance(raw_port_value, str) or "${" in raw_port_value:
                raise DeploymentRefusal(
                    "compose_unsupported", "Compose port interpolation is unsupported"
                )
            raw_port = raw_port_value
            protocol = "tcp"
            if "/" in raw_port:
                raw_port, protocol = raw_port.rsplit("/", 1)
            if protocol != "tcp":
                raise DeploymentRefusal(
                    "compose_unsupported", "Slice A supports TCP Compose ports only"
                )
            parts = raw_port.rsplit(":", 2)
            if len(parts) == 2:
                address, host, container = "127.0.0.1", parts[0], parts[1]
            elif len(parts) == 3:
                address, host, container = parts
            else:
                raise DeploymentRefusal(
                    "compose_unsupported", "Compose port form is unsupported"
                )
            try:
                host_port = int(host)
                container_port = int(container)
            except ValueError as exc:
                raise DeploymentRefusal(
                    "compose_unsupported", "Compose ports must be numeric"
                ) from exc
            ports.append(
                {
                    "name": "http" if index == 1 else f"port-{index}",
                    "containerPort": container_port,
                    "hostAddress": address,
                    "hostPort": host_port,
                }
            )
        storage: list[dict[str, Any]] = []
        raw_storage = raw.get("volumes", [])
        if not isinstance(raw_storage, list):
            raise DeploymentRefusal(
                "compose_unsupported", "Compose volumes must be a list"
            )
        for raw_volume in raw_storage:
            if not isinstance(raw_volume, str) or raw_volume.count(":") != 1:
                raise DeploymentRefusal(
                    "compose_unsupported", "Compose volume form is unsupported"
                )
            volume_source, mount = raw_volume.split(":")
            if volume_source.startswith(("/", ".", "~")) or "/" in volume_source:
                raise DeploymentRefusal(
                    "unsafe_mount", "Compose host bind mounts are forbidden"
                )
            if volume_source not in declared_volumes:
                raise DeploymentRefusal(
                    "compose_unsupported",
                    "Compose named volumes must be explicitly declared",
                )
            storage.append(
                {
                    "id": safe_id(volume_source, "storage id"),
                    "mountPath": mount,
                    "persistence": "retained",
                }
            )
        health_raw = raw.get("healthcheck")
        if not isinstance(health_raw, Mapping) or set(health_raw) - {
            "test",
            "interval",
            "timeout",
            "start_period",
        }:
            raise DeploymentRefusal(
                "missing_health",
                f"Compose service {service_id} requires a supported healthcheck",
            )
        health_test = health_raw.get("test")
        if (
            not isinstance(health_test, list)
            or len(health_test) < 2
            or health_test[0] != "CMD"
            or any(not isinstance(item, str) or not item for item in health_test[1:])
        ):
            raise DeploymentRefusal(
                "compose_unsupported",
                "Compose healthcheck must use an exact CMD argv list",
            )
        service_networks_raw = raw.get("networks", network_ids)
        if isinstance(service_networks_raw, (list, tuple)):
            service_networks = list(service_networks_raw)
        elif isinstance(service_networks_raw, Mapping) and all(
            item in (None, {}) for item in service_networks_raw.values()
        ):
            service_networks = list(service_networks_raw)
        else:
            raise DeploymentRefusal(
                "compose_unsupported",
                "Compose per-service network options require a StatePort descriptor",
            )
        environment = raw.get("environment", {})
        if not isinstance(environment, Mapping):
            raise DeploymentRefusal(
                "compose_unsupported", "Compose environment must be an object"
            )
        services.append(
            {
                "id": service_id,
                "sourcePath": ".",
                "build": build,
                "image": image,
                "runtime": {
                    "command": command,
                    "workdir": raw.get("working_dir", "/app"),
                    "user": {"mode": "nonroot", "uid": uid, "gid": gid},
                    "readOnlyRoot": True,
                },
                "ports": ports,
                "health": {
                    "type": "command",
                    "path": None,
                    "portName": None,
                    "command": health_test[1:],
                    "intervalSeconds": _compose_duration(
                        health_raw.get("interval"), 2
                    ),
                    "timeoutSeconds": _compose_duration(
                        health_raw.get("timeout"), 3
                    ),
                    "startPeriodSeconds": _compose_duration(
                        health_raw.get("start_period"), 5
                    ),
                },
                "resources": {
                    "memoryLimit": "256m",
                    "cpuLimit": 1.0,
                    "pidsLimit": 128,
                },
                "storage": storage,
                "secrets": [],
                "environment": dict(environment),
                "networks": service_networks,
            }
        )
    source_fields = {
        key: source[key]
        for key in (
            "repositoryIdentity",
            "repositoryRoot",
            "projectPath",
            "commit",
            "treeDigest",
            "dirty",
            "dirtyDigest",
            "dirtyPolicy",
            "descriptorDigest",
        )
    }
    normalized = validate_deployment_spec(
        {
            "schema": DEPLOYMENT_SCHEMA,
            "metadata": {
                "deploymentId": "compose-inspection",
                "applicationId": "compose-inspection",
                "name": str(compose.get("name") or "Compose application"),
            },
            "source": source_fields,
            "target": {
                "adapter": "rootless-podman-local",
                "targetId": "local",
                "architecture": "linux-amd64",
                "identityDigest": None,
            },
            "services": services,
            "networks": networks,
            "authority": {
                "grantId": None,
                "requireApproval": ["first_apply"],
                "automaticWithReceipt": [
                    "health_check",
                    "restart",
                    "log_collection",
                    "observe",
                    "remove_runtime_preserve_data",
                ],
            },
            "policy": {
                "ordinaryRemovePreservesData": True,
                "rollbackOnFailedHealth": True,
            },
        },
        materialized=False,
    )
    return {
        "name": normalized["metadata"]["name"],
        "services": normalized["services"],
        "networks": normalized["networks"],
    }


def _service_review_projection(
    service: Mapping[str, Any], *, source: str
) -> dict[str, Any]:
    return {
        "id": service["id"],
        "source": source,
        "sourcePath": service["sourcePath"],
        "build": deepcopy(dict(service["build"])),
        "image": deepcopy(dict(service["image"])),
        "command": list(service["runtime"]["command"]),
        "runtimeUser": deepcopy(dict(service["runtime"]["user"])),
        "ports": deepcopy(list(service["ports"])),
        "storage": deepcopy(list(service["storage"])),
        "health": deepcopy(dict(service["health"])),
        "secretReferences": [
            secret["binding"] for secret in service["secrets"]
        ],
        "networks": list(service["networks"]),
    }


def _assisted_review_projection(candidate: Mapping[str, Any]) -> dict[str, Any]:
    source = candidate.get("source")
    runtime = assisted_runtime_contract(candidate)
    context = runtime["sourcePath"]
    return {
        "id": "web",
        "source": source,
        "sourcePath": context,
        "build": {
            "mode": "source",
            "context": context,
            "containerfile": "web.Containerfile",
            "generated": True,
        },
        "image": {"reference": None, "acceptedDigest": None},
        "command": runtime["command"],
        "runtimeUser": {"mode": "nonroot", "uid": 10001, "gid": 10001},
        "ports": [
            {
                "name": "http",
                "containerPort": 8080,
                "hostAddress": "127.0.0.1",
                "hostPort": 0,
            }
        ],
        "storage": [],
        "health": runtime["health"],
        "secretReferences": [],
        "networks": ["internal"],
    }


def _compose_findings(
    path: Path,
    *,
    source: Mapping[str, Any],
    inventory: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    try:
        normalized = parse_compose_contract(
            _load_structured(path), source=source, inventory=inventory
        )
    except DeploymentRefusal as exc:
        return [], [f"compose:{exc.code}"], [str(exc)]
    return (
        [
            _service_review_projection(service, source="compose")
            for service in normalized["services"]
        ],
        [],
        [],
    )


def _node_metadata(path: Path) -> tuple[str | None, list[str]]:
    value = _load_structured(path)
    scripts = value.get("scripts", {})
    if not isinstance(scripts, Mapping):
        return None, ["package_scripts_invalid"]
    for name in ("start", "serve"):
        command = scripts.get(name)
        if isinstance(command, str) and command.strip():
            return f"npm run {name}", []
    if (path.parent / "server.js").is_file():
        return "node server.js", []
    return None, ["node_runtime_command_unknown"]


def resolve_assisted_profile(
    source: Mapping[str, Any], inventory: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    """Resolve one exact dependency-free assisted profile from tracked bytes."""

    tracked = {str(item.get("path")) for item in inventory}
    blockers: list[str] = []
    candidates: list[dict[str, Any]] = []

    python_detected = bool(set(PYTHON_MARKERS) & tracked) or "app.py" in tracked
    if python_detected:
        python_blocker: str | None = None
        if "app.py" not in tracked:
            python_blocker = "python_runtime_command_unknown"
        for name in ("requirements.txt", "requirements.lock"):
            if python_blocker is not None or name not in tracked:
                continue
            try:
                text = read_exact_source_file(source, inventory, name).decode(
                    "utf-8"
                )
            except UnicodeError:
                python_blocker = "descriptor_invalid"
                break
            if any(
                line.strip() and not line.lstrip().startswith("#")
                for line in text.splitlines()
            ):
                python_blocker = "assisted_dependencies_unsupported"
        if python_blocker is None and "Pipfile" in tracked:
            python_blocker = "assisted_dependencies_unsupported"
        if python_blocker is None and "pyproject.toml" in tracked:
            try:
                import tomllib

                pyproject = tomllib.loads(
                    read_exact_source_file(
                        source, inventory, "pyproject.toml"
                    ).decode("utf-8")
                )
                project = pyproject.get("project", {})
            except (UnicodeError, ValueError):
                python_blocker = "descriptor_invalid"
            else:
                if (
                    not isinstance(project, Mapping)
                    or project.get("dependencies") not in (None, [])
                    or project.get("optional-dependencies") not in (None, {})
                ):
                    python_blocker = "assisted_dependencies_unsupported"
        if python_blocker is None:
            candidates.append(
                {
                    "profile": "python",
                    "service": {
                        "id": "web",
                        "source": "assisted_python",
                        "command": "python3 app.py",
                    },
                }
            )
        else:
            blockers.append(f"python:{python_blocker}")

    if "package.json" in tracked:
        node_blocker: str | None = None
        try:
            package = strict_mapping_document(
                read_exact_source_file(source, inventory, "package.json").decode(
                    "utf-8"
                ),
                format_name="json",
                label="package.json",
            )
        except (UnicodeError, DeploymentRefusal):
            package = {}
            node_blocker = "descriptor_invalid"
        if node_blocker is None and "server.js" not in tracked:
            node_blocker = "node_runtime_command_unknown"
        if node_blocker is None:
            for key in (
                "dependencies",
                "devDependencies",
                "optionalDependencies",
                "peerDependencies",
            ):
                if package.get(key) not in (None, {}):
                    node_blocker = "assisted_dependencies_unsupported"
                    break
        scripts = package.get("scripts", {})
        if node_blocker is None and (
            not isinstance(scripts, Mapping)
            or scripts.get("start") not in (None, "node server.js")
        ):
            node_blocker = "assisted_command_unsupported"
        if node_blocker is None:
            candidates.append(
                {
                    "profile": "node",
                    "service": {
                        "id": "web",
                        "source": "assisted_node",
                        "command": "node server.js",
                    },
                }
            )
        else:
            blockers.append(f"node:{node_blocker}")

    static_root: str | None = None
    if "index.html" in tracked:
        static_root = "."
    else:
        static_root = next(
            (
                name
                for name in STATIC_DIRS
                if f"{name}/index.html" in tracked
            ),
            None,
        )
    if static_root is not None:
        static_blocker: str | None = None
        if static_root == ".":
            static_suffixes = {
                ".html",
                ".htm",
                ".css",
                ".js",
                ".mjs",
                ".json",
                ".svg",
                ".png",
                ".jpg",
                ".jpeg",
                ".gif",
                ".webp",
                ".ico",
                ".woff",
                ".woff2",
                ".txt",
                ".xml",
                ".webmanifest",
            }
            if any(
                Path(path).suffix.lower() not in static_suffixes
                or any(part.startswith(".") for part in Path(path).parts)
                for path in tracked
            ):
                static_blocker = "static_source_scope_ambiguous"
        if static_blocker is None:
            candidates.append(
                {
                    "profile": "static",
                    "staticRoot": static_root,
                    "service": {
                        "id": "web",
                        "source": "assisted_static",
                        "staticRoot": static_root,
                    },
                }
            )
        else:
            blockers.append(f"static:{static_blocker}")

    selected = candidates[0] if len(candidates) == 1 else None
    if len(candidates) > 1:
        blockers.append("assisted_profile_ambiguous")
    elif not candidates and not blockers:
        blockers.append("assisted_profile_unsupported")
    return {
        "profile": selected["profile"] if selected else None,
        "staticRoot": selected.get("staticRoot") if selected else None,
        "candidates": [dict(item["service"]) for item in candidates],
        "blockers": sorted(set(blockers)),
    }


def inspect_project(path: Path | str) -> dict[str, Any]:
    """Inspect a project without writing, building, reserving, or deploying."""

    root = _safe_project(path)
    descriptor_path = next((candidate for name in DESCRIPTORS if (candidate := _regular_file(root, name))), None)
    compose_path = next((candidate for name in COMPOSE_FILES if (candidate := _regular_file(root, name))), None)
    containerfile_path = next((candidate for name in CONTAINERFILES if (candidate := _regular_file(root, name))), None)
    descriptor_digest = digest_bytes(descriptor_path.read_bytes()) if descriptor_path else digest_value({"descriptor": None})
    source = git_source_identity(root, descriptor_digest=descriptor_digest)

    detected: list[str] = []
    services: list[dict[str, Any]] = []
    unsafe: list[str] = []
    unknowns: list[str] = []
    descriptor: Mapping[str, Any] | None = None
    if descriptor_path is not None:
        detected.append("stateport_descriptor")
        descriptor = _load_structured(descriptor_path)
        if descriptor.get("schema") != DEPLOYMENT_SCHEMA:
            unsafe.append("unsupported_stateport_descriptor")
        else:
            try:
                normalized = validate_deployment_spec(
                    descriptor, materialized=False
                )
                validate_project_declared_builds(
                    normalized, source.to_dict(), source.inventory
                )
            except DeploymentRefusal as exc:
                unsafe.append(f"descriptor:{exc.code}")
            else:
                services.extend(
                    _service_review_projection(
                        item, source="stateport_descriptor"
                    )
                    for item in normalized["services"]
                )
    if compose_path is not None:
        detected.append("compose")
        compose_services, compose_unsafe, compose_unknowns = _compose_findings(
            compose_path,
            source=source.to_dict(),
            inventory=source.inventory,
        )
        services.extend({**item, "source": "compose"} for item in compose_services)
        unsafe.extend(compose_unsafe)
        unknowns.extend(compose_unknowns)
    if containerfile_path is not None:
        detected.append("containerfile")
        if descriptor_path is None and compose_path is None:
            findings, container_unknowns, contract = _containerfile_findings(
                containerfile_path
            )
            unsafe.extend(findings)
            unknowns.extend(container_unknowns)
            if contract is not None and not services:
                services.append(
                    _containerfile_review_projection(
                        contract, containerfile=containerfile_path.name
                    )
                )

    python_marker = next((candidate for name in PYTHON_MARKERS if (candidate := _regular_file(root, name))), None)
    if python_marker is not None or (root / "app.py").is_file():
        detected.append("python")
        if not (root / "app.py").is_file():
            unknowns.append("python_runtime_command_unknown")
    node_marker = _regular_file(root, "package.json")
    if node_marker is not None:
        detected.append("node")
        _command, node_unknowns = _node_metadata(node_marker)
        unknowns.extend(node_unknowns)
    static_root: str | None = None
    if (root / "index.html").is_file():
        static_root = "."
    else:
        for name in STATIC_DIRS:
            candidate = root / name
            if candidate.is_dir() and not candidate.is_symlink() and (candidate / "index.html").is_file():
                static_root = name
                break
    if static_root is not None:
        detected.append("static_web")

    declared = any(
        item is not None
        for item in (descriptor_path, compose_path, containerfile_path)
    )
    if declared:
        supported = not unsafe and bool(services)
    else:
        resolution = resolve_assisted_profile(
            source.to_dict(), source.inventory
        )
        services = [
            _assisted_review_projection(item)
            for item in resolution["candidates"]
        ]
        unknowns.extend(resolution["blockers"])
        supported = not unsafe and resolution["profile"] is not None
    if not detected:
        unknowns.append("project_type_unknown")
    build_contexts = sorted(
        {
            str(build["context"])
            for item in services
            if isinstance((build := item.get("build")), Mapping)
            and isinstance(build.get("context"), str)
        }
    )
    commands = sorted(
        {
            (
                shlex.join(command)
                if isinstance(command, list)
                and all(isinstance(part, str) for part in command)
                else str(command)
            )
            for item in services
            if (command := item.get("command"))
        }
    )
    ports = sorted(
        {
            port["containerPort"] if isinstance(port, Mapping) else port
            for item in services
            for port in item.get("ports", [])
            if (
                isinstance(port, int)
                or (
                    isinstance(port, Mapping)
                    and isinstance(port.get("containerPort"), int)
                )
            )
        }
    )
    persistent_paths = sorted(
        {
            storage["mountPath"]
            for item in services
            for storage in item.get("storage", [])
            if isinstance(storage, Mapping)
            and storage.get("persistence") != "ephemeral"
            and isinstance(storage.get("mountPath"), str)
        }
    )
    health_signals = sorted(
        {
            json.dumps(item["health"], sort_keys=True, separators=(",", ":"))
            for item in services
            if isinstance(item.get("health"), Mapping)
        }
    )
    secret_references = sorted(
        {
            reference
            for item in services
            for reference in item.get("secretReferences", [])
            if isinstance(reference, str)
        }
    )
    result = {
        "schema": INSPECTION_SCHEMA,
        "project": str(root),
        "source": source.to_dict(),
        "dirty": source.dirty,
        "detectedProjectTypes": sorted(set(detected)),
        "candidateServices": services,
        "buildContexts": build_contexts,
        "commands": commands,
        "ports": ports,
        "persistentPaths": persistent_paths,
        "healthSignals": health_signals,
        "secretReferences": secret_references,
        "unsafeConstructs": sorted(set(unsafe)),
        "unknowns": sorted(set(unknowns)),
        "deterministicAssistedPlanningSupported": supported,
        "sideEffects": [],
    }
    return result


def authority_source_identity(value: Mapping[str, Any]) -> dict[str, Any]:
    """Project the exact, non-secret source fields bound into authority."""

    source = value.get("source", value)
    if not isinstance(source, Mapping):
        raise DeploymentRefusal(
            "source_identity_missing", "deployment source identity is missing"
        )
    fields = (
        "repositoryIdentity",
        "projectPath",
        "commit",
        "treeDigest",
        "dirty",
        "dirtyDigest",
        "descriptorDigest",
    )
    if any(field not in source for field in fields):
        raise DeploymentRefusal(
            "source_identity_missing", "deployment source identity is incomplete"
        )
    return {field: source[field] for field in fields}


__all__ = [
    "SourceIdentity",
    "assisted_runtime_contract",
    "authority_source_identity",
    "git_source_identity",
    "inspect_project",
    "parse_containerfile_contract",
    "read_exact_source_file",
    "resolve_assisted_profile",
    "sanitized_git_command",
    "sanitized_git_environment",
    "validate_project_declared_builds",
]
