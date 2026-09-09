from __future__ import annotations

"""Governed repository discovery and non-mutating inspection.

Repository contents are untrusted data.  This module has no repository-code execution API. It discovers local sources,
acquires bounded public HTTPS sources at exact commits, and inspects Git
metadata without executing repository code. The existing plan and transaction
flow binds the resulting immutable identity before managed materialization.
"""

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import shutil
import signal
import stat
import sys
import tempfile
import subprocess
from time import monotonic
from typing import Any, Iterable
from urllib.parse import urlsplit, urlunsplit

import yaml

from stateport_persistent_app.repository_content import (
    RepositoryContentError,
    repository_content_snapshot,
)
from stateport_persistent_app.template_adapters import (
    TemplateAdapterError,
    TemplateAdapterRegistry,
)


class RepositoryImportError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True)
class RepositoryResourceLimits:
    inspection_timeout_seconds: float = 8.0
    maximum_file_count: int = 50_000
    maximum_materialized_bytes: int = 512 * 1024 * 1024
    maximum_path_length: int = 512
    maximum_redirects: int = 3
    maximum_local_depth: int = 4

    def to_dict(self) -> dict[str, object]:
        return {
            "inspectionTimeoutSeconds": self.inspection_timeout_seconds,
            "maximumFileCount": self.maximum_file_count,
            "maximumMaterializedBytes": self.maximum_materialized_bytes,
            "maximumPathLength": self.maximum_path_length,
            "maximumRedirects": self.maximum_redirects,
            "maximumLocalDepth": self.maximum_local_depth,
            "publicFetchTimeoutSeconds": 60,
            "maximumPublicDownloadBytes": 128 * 1024 * 1024,
            "maximumPublicCacheBytes": 1024 * 1024 * 1024,
            "maximumPublicCacheEntries": 100_000,
        }

def _digest(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _safe_display_path(path: Path, roots: Iterable[Path]) -> str:
    for root in roots:
        try:
            return path.resolve(strict=True).relative_to(root.resolve(strict=True)).as_posix()
        except ValueError:
            continue
        except OSError:
            break
    return path.name


def _is_denied_ip(address: str) -> bool:
    try:
        value = ipaddress.ip_address(address)
    except ValueError:
        return True
    return not value.is_global or value.is_multicast or value.is_reserved


def validate_public_https_url(value: object, *, resolve: bool = True) -> str:
    if not isinstance(value, str) or len(value) > 2048 or "\x00" in value:
        raise RepositoryImportError("repository_url_invalid", "repository URL is invalid")
    if any(ord(char) <= 32 or ord(char) == 127 for char in value) or "\\" in value:
        raise RepositoryImportError("repository_url_invalid", "repository URL is invalid")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise RepositoryImportError("repository_url_invalid", "repository URL is invalid") from exc
    if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.fragment or parsed.query:
        raise RepositoryImportError("repository_url_refused", "only public HTTPS repository URLs without credentials are supported")
    if port not in (None, 443):
        raise RepositoryImportError("repository_url_refused", "repository URL must use HTTPS port 443")
    try:
        hostname = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise RepositoryImportError("repository_url_invalid", "repository hostname is invalid") from exc
    if "%" in hostname or not re.fullmatch(r"[a-z0-9.:-]+", hostname):
        raise RepositoryImportError("repository_url_invalid", "repository hostname is invalid")
    if hostname in {"localhost", "localhost.localdomain"} or hostname.endswith(".local"):
        raise RepositoryImportError("repository_url_refused", "private or local repository hosts are not allowed")
    if resolve:
        try:
            addresses = {item[4][0] for item in socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)}
        except OSError as exc:
            raise RepositoryImportError("repository_url_unresolved", "repository host could not be resolved") from exc
        if not addresses or any(_is_denied_ip(address) for address in addresses):
            raise RepositoryImportError("repository_url_private_target", "repository URL resolves to a private or reserved network")
    return urlunsplit(("https", "[" + hostname + "]" if ":" in hostname else hostname, parsed.path or "/", "", ""))


class RepositorySourcePolicy:
    """Resolve the only source roots and managed destination StatePort may use."""

    def __init__(self, layout: Any, *, limits: RepositoryResourceLimits | None = None) -> None:
        self.layout = layout
        self.limits = limits or RepositoryResourceLimits()
        configured = os.environ.get("STATEPORT_REPOSITORY_ROOTS", "")
        self.allowlisted_roots = tuple(
            path.resolve()
            for path in (Path(item).expanduser() for item in configured.split(os.pathsep) if item.strip())
            if path.exists() and path.is_dir() and not path.is_symlink()
        )
        self.managed_root = (layout.data_root / "managed-projects").resolve()

    def to_dict(self) -> dict[str, object]:
        return {
            "allowlistedRoots": [root.name for root in self.allowlisted_roots],
            "managedDestination": "StatePort managed project storage",
            "limits": self.limits.to_dict(),
        }

    def resolve_candidate(self, candidate_id: object) -> Path:
        if not isinstance(candidate_id, str) or not re.fullmatch(r"repo-[0-9a-f]{32}", candidate_id):
            raise RepositoryImportError("repository_candidate_invalid", "repository candidate identity is invalid")
        remote = _remote_marker(self, candidate_id)
        if remote is not None:
            return remote[0]
        for root in self.allowlisted_roots:
            for candidate in _discover_repositories(root, self.limits):
                if _candidate_id(candidate, root) == candidate_id:
                    return _safe_repository(candidate, root)
        raise RepositoryImportError("repository_candidate_stale", "repository candidate is no longer available")


def _safe_repository(path: Path, root: Path) -> Path:
    if path.is_symlink() or root.is_symlink():
        raise RepositoryImportError("repository_path_refused", "repository path or allowlisted root is a symlink")
    try:
        resolved_root = root.resolve(strict=True)
        resolved = path.resolve(strict=True)
        resolved.relative_to(resolved_root)
    except (OSError, ValueError) as exc:
        raise RepositoryImportError("repository_path_refused", "repository is outside the configured allowlist") from exc
    if not resolved.is_dir() or not ((resolved / ".git").is_dir() or (resolved / ".git").is_file()):
        raise RepositoryImportError("repository_invalid", "candidate is not a Git repository")
    return resolved


def _discover_repositories(root: Path, limits: RepositoryResourceLimits) -> list[Path]:
    found: list[Path] = []
    root = root.resolve(strict=True)
    for current, directories, _files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        depth = len(current_path.relative_to(root).parts)
        directories[:] = [item for item in directories if not (current_path / item).is_symlink() and item != ".git"]
        if depth > limits.maximum_local_depth:
            directories[:] = []
            continue
        git = current_path / ".git"
        if git.is_dir() or git.is_file():
            found.append(current_path)
            directories[:] = []
    return sorted(found, key=lambda item: item.as_posix())


def _candidate_id(path: Path, root: Path) -> str:
    return "repo-" + hashlib.sha256(f"{root.resolve()}\0{path.resolve()}".encode("utf-8")).hexdigest()[:32]


def _run_git(root: Path, args: list[str], *, timeout: float) -> str:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": "/nonexistent",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/false",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_LFS_SKIP_SMUDGE": "1",
    }
    try:
        result = subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never", *args],
            cwd=root,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RepositoryImportError("repository_inspection_timeout", "Git inspection exceeded the configured limit") from exc
    if result.returncode != 0:
        raise RepositoryImportError("repository_inspection_refused", "Git repository inspection was refused")
    return result.stdout.strip()


def _classify_statespec(root: Path) -> dict[str, object]:
    instance = root / "instance.yaml"
    lock = root / ".statedd" / "lock.yaml"
    project = root / "PROJECT.md"
    state = root / "STATE.yaml"
    project_state = root / "PROJECT_STATE.yaml"
    project_dna = root / "PROJECT_DNA.yaml"
    if instance.exists() or lock.exists():
        if instance.is_file() and lock.is_file():
            try:
                instance_data = yaml.safe_load(instance.read_text(encoding="utf-8"))
                lock_data = yaml.safe_load(lock.read_text(encoding="utf-8"))
                if isinstance(instance_data, dict) and isinstance(lock_data, dict):
                    return {"classification": "valid_current", "label": "Valid current StateSpec", "files": ["instance.yaml", ".statedd/lock.yaml"], "issues": []}
            except (OSError, UnicodeError, yaml.YAMLError):
                pass
        return {"classification": "invalid", "label": "Invalid StateSpec", "files": ["instance.yaml", ".statedd/lock.yaml"], "issues": ["StateSpec files are incomplete or invalid"]}
    if project.exists() or state.exists():
        files = [
            name
            for name, path in (("PROJECT.md", project), ("STATE.yaml", state))
            if path.is_file()
        ]
        if len(files) == 2:
            try:
                state_data = yaml.safe_load(state.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, yaml.YAMLError):
                state_data = None
            if isinstance(state_data, dict) and state_data.get("version") == "projectstate-template-v6":
                return {
                    "classification": "valid_projectstate_v6",
                    "label": "Valid ProjectState v6",
                    "files": files,
                    "issues": [],
                }
        return {
            "classification": "invalid",
            "label": "Invalid ProjectState v6",
            "files": files,
            "issues": ["ProjectState v6 files are incomplete or invalid"],
        }
    if project_state.exists() or project_dna.exists():
        files = [name for name, path in (("PROJECT_STATE.yaml", project_state), ("PROJECT_DNA.yaml", project_dna)) if path.is_file()]
        classification = "partial" if len(files) < 2 else "legacy_supported"
        label = "Partial StateSpec" if classification == "partial" else "Supported legacy StateSpec"
        return {"classification": classification, "label": label, "files": files, "issues": []}
    return {"classification": "none", "label": "No StateSpec", "files": [], "issues": []}


class RepositoryInspector:
    def __init__(
        self,
        policy: RepositorySourcePolicy,
        *,
        template_adapters: TemplateAdapterRegistry | None = None,
    ) -> None:
        self.policy = policy
        self.template_adapters = template_adapters or TemplateAdapterRegistry()

    def local_candidates(self) -> list[dict[str, object]]:
        result: list[dict[str, object]] = []
        for root in self.policy.allowlisted_roots:
            for path in _discover_repositories(root, self.policy.limits):
                try:
                    inspected = self.inspect_local(path, root=root)
                except RepositoryImportError:
                    continue
                result.append({
                    "candidateId": _candidate_id(path, root),
                    "displayName": path.name,
                    "relativeLocation": _safe_display_path(path, (root,)),
                    "inspection": inspected,
                })
        return result

    def inspect_candidate(self, candidate_id: object) -> dict[str, object]:
        if isinstance(candidate_id, str) and re.fullmatch(r"repo-[0-9a-f]{32}", candidate_id):
            remote = _remote_marker(self.policy, candidate_id)
            if remote is not None:
                path, source = remote
                result = self._inspect(path, source_kind="public_https", source_display=source["url"], source_url=source["url"])
                if result["sourceIdentity"]["headCommit"] != source["revision"] or result["sourceIdentity"]["dirty"]:
                    raise RepositoryImportError("repository_inspection_stale", "public repository snapshot changed; inspect the exact source again")
                return result | {"candidateId": candidate_id}
        path = self.policy.resolve_candidate(candidate_id)
        root = next(root for root in self.policy.allowlisted_roots if path.is_relative_to(root.resolve()))
        return self.inspect_local(path, root=root) | {"candidateId": candidate_id}

    def inspect_local(self, path: Path, *, root: Path) -> dict[str, object]:
        source = _safe_repository(path, root)
        return self._inspect(source, source_kind="local", source_display=_safe_display_path(source, (root,)), source_url=None)

    def inspect_public_url(self, value: object, revision: object = None) -> dict[str, object]:
        return _fetch_public_repository(self, value, revision)

    def _inspect(self, root: Path, *, source_kind: str, source_display: str, source_url: str | None) -> dict[str, object]:
        started = monotonic()
        try:
            content = repository_content_snapshot(
                root,
                maximum_file_count=self.policy.limits.maximum_file_count,
                maximum_total_bytes=self.policy.limits.maximum_materialized_bytes,
                maximum_path_length=self.policy.limits.maximum_path_length,
                timeout_seconds=self.policy.limits.inspection_timeout_seconds,
            )
        except RepositoryContentError as exc:
            raise RepositoryImportError(exc.code, str(exc)) from exc
        head = _run_git(root, ["rev-parse", "HEAD"], timeout=self.policy.limits.inspection_timeout_seconds)
        tree = _run_git(root, ["rev-parse", "HEAD^{tree}"], timeout=self.policy.limits.inspection_timeout_seconds)
        branch = _run_git(root, ["branch", "--show-current"], timeout=self.policy.limits.inspection_timeout_seconds) or "HEAD"
        status = _run_git(root, ["status", "--porcelain=v1", "--untracked-files=normal"], timeout=self.policy.limits.inspection_timeout_seconds)
        remote = ""
        try:
            remote = _run_git(root, ["remote", "get-url", "origin"], timeout=self.policy.limits.inspection_timeout_seconds)
        except RepositoryImportError:
            remote = ""
        content_identity = content.identity
        file_count = int(content_identity["fileCount"])
        total_bytes = int(content_identity["totalBytes"])
        lfs_pointers = content.lfs_pointers_detected
        submodules = (root / ".gitmodules").is_file()
        state_spec = _classify_statespec(root)
        try:
            template = self.template_adapters.inspect(root)
        except TemplateAdapterError as exc:
            template = {
                "formatVersion": "stateport.template-adapter-match/v1",
                "validation": {
                    "status": "failed",
                    "issues": [{"code": exc.code, "message": str(exc)}],
                },
                "repositoryCommandsExecuted": False,
            }
        identity = {
            "sourceKind": source_kind,
            "source": source_url or source_display,
            "remote": remote if remote.startswith("https://") else ("present" if remote else None),
            "headCommit": head,
            "headTree": tree,
            "branch": branch,
            "dirty": bool(status),
            "submodulesDeclared": submodules,
            "lfsPointersDetected": lfs_pointers,
            "fileCount": file_count,
            "estimatedBytes": total_bytes,
            "contentIdentity": content_identity,
        }
        findings: list[dict[str, str]] = []
        if submodules:
            findings.append({"code": "submodules_disabled", "severity": "warning", "message": "Submodules are declared but will not be initialized."})
        if lfs_pointers:
            findings.append({"code": "lfs_pointers_present", "severity": "warning", "message": "Git LFS pointers are present; LFS content is not downloaded."})
        return {
            "formatVersion": "stateport.repository-inspection/v1",
            "sourceKind": source_kind,
            "source": source_display,
            "sourceIdentity": identity,
            "stateSpec": state_spec,
            "template": template,
            "safetyFindings": findings,
            "resourceFindings": [],
            "inspectionPolicy": self.policy.limits.to_dict(),
            "inspectionDurationMs": round((monotonic() - started) * 1000),
            "mutated": False,
            "inspectionDigest": _digest({"identity": identity, "stateSpec": state_spec, "template": template, "findings": findings}),
        }


def _public_target(value: object) -> tuple[str, str]:
    """Resolve once; the selected address is subsequently pinned in libcurl."""
    url = validate_public_https_url(value, resolve=False)
    host = urlsplit(url).hostname
    # Resolve in a disposable process so an unavailable resolver cannot occupy
    # a service request indefinitely. Revalidate every returned address.
    try:
        result = subprocess.run(
            [sys.executable, "-I", "-c", "import json,socket,sys; print(json.dumps(sorted({x[4][0] for x in socket.getaddrinfo(sys.argv[1],443,type=socket.SOCK_STREAM)})))", str(host)],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=8, check=True,
        )
        addresses = json.loads(result.stdout)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        raise RepositoryImportError("repository_url_unresolved", "repository host could not be resolved within the limit") from exc
    if not addresses or any(not isinstance(item, str) or _is_denied_ip(item) for item in addresses):
        raise RepositoryImportError("repository_url_private_target", "repository URL resolves to a private or reserved network")
    return url, sorted(addresses, key=lambda item: (":" in item, item))[0]


def _private_repository_cache(policy: RepositorySourcePolicy) -> Path:
    root = policy.layout.data_root / "public-repositories"
    if root.resolve() != root.absolute():
        raise RepositoryImportError("repository_cache_unsafe", "public repository cache path is unsafe")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = root.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise RepositoryImportError("repository_cache_unsafe", "public repository cache must be owner-private")
    return root


def _cache_size(root: Path) -> int:
    size = 0
    entries = 0
    for current, directories, files in os.walk(root, followlinks=False):
        for name in directories + files:
            entries += 1
            if entries > 100_000:
                raise RepositoryImportError("repository_cache_full", "public repository cache exceeds its entry limit")
            path = Path(current) / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
                raise RepositoryImportError("repository_cache_unsafe", "public repository cache contains an unsafe entry")
            size += max(info.st_size, info.st_blocks * 512)
    return size


@contextmanager
def _restricted_git_helpers():
    """Remove secondary network helpers instead of trusting server negotiation."""
    git = Path("/usr/bin/git").resolve(strict=True)
    environment = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}
    def trusted(path: Path) -> tuple[int, int, int, int]:
        info = path.stat()
        for parent in path.parents:
            parent_info = parent.stat()
            if parent_info.st_uid != 0 or parent_info.st_mode & 0o022:
                raise RepositoryImportError("repository_git_unsupported", "system Git executable directories must be trusted")
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RepositoryImportError("repository_git_unsupported", "public acquisition requires trusted system Git executables")
        return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns
    identity = trusted(git)
    try:
        builtins = subprocess.run([str(git), "--list-cmds=builtins"], env=environment, capture_output=True, text=True, timeout=5, check=True).stdout.splitlines()
        configuration = subprocess.run([str(git), "help", "--config"], env=environment, capture_output=True, text=True, timeout=5, check=True).stdout.splitlines()
        exec_path = subprocess.run([str(git), "--exec-path"], env=environment, capture_output=True, text=True, timeout=5, check=True).stdout.strip()
        https = (Path(exec_path) / "git-remote-https").resolve(strict=True)
        helper_identity = trusted(https)
    except (OSError, subprocess.SubprocessError) as exc:
        raise RepositoryImportError("repository_git_unsupported", "system Git capabilities could not be verified") from exc
    if "http-fetch" in builtins or "fetch-pack" not in builtins or "index-pack" not in builtins or "http.curloptResolve" not in configuration:
        raise RepositoryImportError("repository_git_unsupported", "this Git build cannot exclude secondary network fetch helpers")
    # Both exec-path and PATH are replaced. No system helper fallback exists.
    # Protocol v2 packfile URI handling must fail to execute git-http-fetch.
    with tempfile.TemporaryDirectory(prefix="stateport-git-helpers-") as directory:
        root = Path(directory)
        (root / "git").symlink_to(git)
        (root / "git-remote-https").symlink_to(https)
        root.chmod(0o500)
        try:
            if trusted(git) != identity or trusted(https) != helper_identity:
                raise RepositoryImportError("repository_git_unsupported", "system Git identity changed during capability verification")
            yield root
        finally:
            root.chmod(0o700)


def _remote_git(root: Path, args: list[str], *, deadline: float, limit: int, resolve: str | None = None) -> bytes:
    """No inherited configuration, credentials, helpers, or unbounded pipes."""
    environment = {
        "PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull, "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/false", "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_ALLOW_PROTOCOL": "https", "GIT_ATTR_NOSYSTEM": "1",
    }
    options = [
        "core.hooksPath=/dev/null", "credential.helper=", "protocol.allow=never",
        "protocol.https.allow=always", "http.proxy=", "http.followRedirects=false",
        "http.sslVerify=true", "http.lowSpeedLimit=1024", "http.lowSpeedTime=10",
        "fetch.unpackLimit=0", "transfer.unpackLimit=0", "fetch.fsckObjects=true",
        "transfer.fsckObjects=true", "maintenance.auto=false", "gc.auto=0",
        "submodule.recurse=false", "core.attributesFile=/dev/null",
        # Prefer v0; this is NOT a boundary against unsolicited v2. The
        # restricted helper directory below prevents secondary URI acquisition.
        "protocol.version=0", "fetch.uriprotocols=", "transfer.bundleURI=false",
    ]
    if resolve:
        options.append("http.curloptResolve=" + resolve)
    command = ["git", *[part for option in options for part in ("-c", option)], *args]
    # Limits are applied in a fresh interpreter, never preexec_fn in this
    # multithreaded service. Descendant Git processes inherit them.
    bootstrap = "import os,resource,sys; n=int(sys.argv[1]); resource.setrlimit(resource.RLIMIT_FSIZE,(n,n)); resource.setrlimit(resource.RLIMIT_AS,(1073741824,1073741824)); resource.setrlimit(resource.RLIMIT_CPU,(60,60)); resource.setrlimit(resource.RLIMIT_NOFILE,(64,64)); os.execvpe(sys.argv[2],sys.argv[2:],os.environ)"
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise RepositoryImportError("repository_fetch_timeout", "public repository acquisition exceeded its time limit")
    with _restricted_git_helpers() as helpers, tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        environment["PATH"] = str(helpers)
        environment["GIT_EXEC_PATH"] = str(helpers)
        environment["HOME"] = str(helpers)
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise RepositoryImportError("repository_fetch_timeout", "public repository acquisition exceeded its time limit")
        process = subprocess.Popen([sys.executable, "-I", "-c", bootstrap, str(limit), *command], cwd=root, env=environment, stdin=subprocess.DEVNULL, stdout=output, stderr=errors, start_new_session=True)
        try:
            try:
                process.wait(timeout=remaining)
            except subprocess.TimeoutExpired as exc:
                raise RepositoryImportError("repository_fetch_timeout", "public repository acquisition exceeded its time limit") from exc
            if process.returncode:
                raise RepositoryImportError("repository_fetch_refused", "public Git acquisition was refused or exceeded a resource limit; verify the URL and exact public commit")
            output.seek(0)
            result = output.read(limit + 1)
            if len(result) > limit:
                raise RepositoryImportError("repository_fetch_limit", "public Git output exceeded its resource limit")
            return result
        finally:
            # A failed/resource-limited parent can leave a network helper alive.
            # Terminate the entire acquisition group on every outcome, not only
            # when waiting for the parent timed out.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired as exc:
                raise RepositoryImportError("repository_fetch_cleanup_failed", "public Git process cleanup could not be confirmed") from exc


def _remote_marker(policy: RepositorySourcePolicy, candidate_id: str) -> tuple[Path, dict[str, str]] | None:
    if not (policy.layout.data_root / "public-repositories").exists():
        return None
    root = _private_repository_cache(policy)
    entry = root / candidate_id
    if not entry.exists() and not entry.is_symlink():
        return None
    if entry.is_symlink() or not entry.is_dir():
        raise RepositoryImportError("repository_cache_unsafe", "public repository candidate is unsafe")
    marker = entry / "source.json"
    try:
        descriptor = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 4096:
                raise ValueError("unsafe marker")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                source = json.loads(stream.read(4097))
        finally:
            os.close(descriptor)
        if set(source) != {"url", "revision", "candidateId"} or source["candidateId"] != candidate_id or not re.fullmatch(r"[0-9a-f]{40}", source["revision"]):
            raise ValueError("identity")
        if candidate_id != "repo-" + hashlib.sha256(f"{source['url']}\0{source['revision']}".encode()).hexdigest()[:32]:
            raise ValueError("binding")
    except (OSError, ValueError, TypeError) as exc:
        raise RepositoryImportError("repository_cache_unsafe", "public repository candidate identity is invalid") from exc
    return _safe_repository(entry / "repository", entry), source


def _fetch_public_repository(inspector: RepositoryInspector, value: object, revision: object) -> dict[str, object]:
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise RepositoryImportError("repository_revision_invalid", "use the full lowercase 40-character Git commit identity")
    url, address = _public_target(value)
    policy = inspector.policy
    cache = _private_repository_cache(policy)
    candidate_id = "repo-" + hashlib.sha256(f"{url}\0{revision}".encode()).hexdigest()[:32]
    descriptor = os.open(cache / ".acquisition.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RepositoryImportError("repository_fetch_busy", "another public repository is being inspected; retry after it finishes") from exc
        for abandoned in cache.glob(".acquiring-*"):
            if abandoned.is_symlink() or not abandoned.is_dir():
                raise RepositoryImportError("repository_cache_unsafe", "abandoned public acquisition is unsafe")
            shutil.rmtree(abandoned)
        cached = _remote_marker(policy, candidate_id)
        if cached is not None:
            # A completed candidate may now contain unique local changes.
            # Refuse changed identity and preserve it for explicit inspection;
            # a retry never silently deletes completed source data.
            return inspector.inspect_candidate(candidate_id)
        # Cache growth is finite, including completed snapshots. Never evict a
        # candidate referenced by an outstanding approval to admit another one.
        budget = 1024 * 1024 * 1024 - _cache_size(cache)
        if budget < 4 * 1024 * 1024:
            raise RepositoryImportError("repository_cache_full", "public repository cache is full; operator cleanup is required")
        limit = min(128 * 1024 * 1024, budget // 4)
        deadline = monotonic() + 60
        stage = Path(tempfile.mkdtemp(prefix=".acquiring-", dir=cache))
        try:
            repository = stage / "repository"
            repository.mkdir(mode=0o700)
            _remote_git(repository, ["init", "--quiet", "--template=", "--initial-branch=main"], deadline=deadline, limit=limit)
            host = urlsplit(url).hostname
            try:
                ipaddress.ip_address(str(host))
                pinned = None  # A validated literal IP already fixes the target.
            except ValueError:
                pinned = f"{host}:443:{'[' + address + ']' if ':' in address else address}"
            # depth is a security boundary: Git refuses dumb HTTP before its
            # object walker can follow server-supplied alternate URLs.
            _remote_git(repository, ["fetch", "--quiet", "--depth=1", "--no-tags", "--no-recurse-submodules", url, revision], deadline=deadline, limit=limit, resolve=pinned)
            actual = _remote_git(repository, ["rev-parse", "FETCH_HEAD^{commit}"], deadline=deadline, limit=limit).decode().strip()
            if actual != revision:
                raise RepositoryImportError("repository_revision_mismatch", "fetched Git commit does not match the requested identity")
            inventory = _remote_git(repository, ["ls-tree", "-rlz", revision], deadline=deadline, limit=limit)
            entries = inventory.rstrip(b"\0").split(b"\0")
            total = 0
            if len(entries) > policy.limits.maximum_file_count:
                raise RepositoryImportError("repository_tree_refused", "public Git tree exceeds the file-count limit")
            for entry in entries:
                try:
                    header, raw_path = entry.split(b"\t", 1)
                    mode, kind, oid, size = header.split()
                    path = raw_path.decode("utf-8")
                    parts = path.split("/")
                    if mode not in (b"100644", b"100755") or kind != b"blob" or any(part.casefold() in {"", ".", "..", ".git"} for part in parts) or "\\" in path or any(ord(char) < 32 for char in path) or len(path) > policy.limits.maximum_path_length:
                        raise ValueError("unsafe tree")
                    total += int(size)
                except (ValueError, UnicodeError) as exc:
                    raise RepositoryImportError("repository_tree_refused", "public Git tree must contain bounded regular files only; symlinks and submodules are refused") from exc
            if total > policy.limits.maximum_materialized_bytes or total + _cache_size(cache) > 1024 * 1024 * 1024:
                raise RepositoryImportError("repository_tree_refused", "public Git tree exceeds the materialization or cache limit")
            _remote_git(repository, ["checkout", "--quiet", "--detach", revision], deadline=deadline, limit=limit)
            _remote_git(repository, ["remote", "add", "origin", url], deadline=deadline, limit=limit)
            if _cache_size(cache) > 1024 * 1024 * 1024:
                raise RepositoryImportError("repository_cache_full", "public repository cache exceeds its disk limit")
            inspection = inspector._inspect(repository, source_kind="public_https", source_display=url, source_url=url)
            template = inspection.get("template")
            if not isinstance(template, dict) or template.get("validation", {}).get("status") != "passed":
                raise RepositoryImportError("template_contract_invalid", "public repository does not contain a valid supported template contract")
            (stage / "source.json").write_text(json.dumps({"url": url, "revision": revision, "candidateId": candidate_id}), encoding="utf-8")
            os.rename(stage, cache / candidate_id)
            return inspector.inspect_candidate(candidate_id)
        finally:
            if stage.exists():
                shutil.rmtree(stage)
