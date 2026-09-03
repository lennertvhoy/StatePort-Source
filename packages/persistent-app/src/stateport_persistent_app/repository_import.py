from __future__ import annotations

"""Governed repository discovery and non-mutating inspection.

Repository contents are untrusted data.  This module deliberately has no
materialization or execution API: it only discovers configured local sources,
validates public HTTPS source identifiers, and inspects Git metadata with a
sanitized environment.  Proposal and transaction code can bind to the
resulting immutable identity in a later slice.
"""

from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
from time import monotonic
from typing import Any, Iterable
from urllib.parse import urlsplit, urlunsplit

import yaml

from stateport_persistent_app.repository_content import (
    RepositoryContentError,
    repository_content_snapshot,
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
    return value.is_loopback or value.is_private or value.is_link_local or value.is_reserved or value.is_multicast or value.is_unspecified


def validate_public_https_url(value: object) -> str:
    if not isinstance(value, str) or len(value) > 2048 or "\x00" in value:
        raise RepositoryImportError("repository_url_invalid", "repository URL is invalid")
    parsed = urlsplit(value)
    if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise RepositoryImportError("repository_url_refused", "only public HTTPS repository URLs without credentials are supported")
    if parsed.port not in (None, 443):
        raise RepositoryImportError("repository_url_refused", "repository URL must use HTTPS port 443")
    hostname = parsed.hostname.rstrip(".").lower()
    if hostname in {"localhost", "localhost.localdomain"} or hostname.endswith(".local"):
        raise RepositoryImportError("repository_url_refused", "private or local repository hosts are not allowed")
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)}
    except OSError as exc:
        raise RepositoryImportError("repository_url_unresolved", "repository host could not be resolved") from exc
    if not addresses or any(_is_denied_ip(address) for address in addresses):
        raise RepositoryImportError("repository_url_private_target", "repository URL resolves to a private or reserved network")
    return urlunsplit(("https", hostname, parsed.path or "/", parsed.query, ""))


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
    if project_state.exists() or project_dna.exists():
        files = [name for name, path in (("PROJECT_STATE.yaml", project_state), ("PROJECT_DNA.yaml", project_dna)) if path.is_file()]
        classification = "partial" if len(files) < 2 else "legacy_supported"
        label = "Partial StateSpec" if classification == "partial" else "Supported legacy StateSpec"
        return {"classification": classification, "label": label, "files": files, "issues": []}
    return {"classification": "none", "label": "No StateSpec", "files": [], "issues": []}


class RepositoryInspector:
    def __init__(self, policy: RepositorySourcePolicy) -> None:
        self.policy = policy

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
        path = self.policy.resolve_candidate(candidate_id)
        root = next(root for root in self.policy.allowlisted_roots if path.is_relative_to(root.resolve()))
        return self.inspect_local(path, root=root) | {"candidateId": candidate_id}

    def inspect_local(self, path: Path, *, root: Path) -> dict[str, object]:
        source = _safe_repository(path, root)
        return self._inspect(source, source_kind="local", source_display=_safe_display_path(source, (root,)), source_url=None)

    def inspect_public_url(self, value: object) -> dict[str, object]:
        url = validate_public_https_url(value)
        # URL metadata validation is non-mutating. Clone/materialization is a
        # separate transaction and must revalidate every network hop.
        return {
            "formatVersion": "stateport.repository-inspection/v1",
            "sourceKind": "public_https",
            "source": url,
            "sourceIdentity": {"kind": "public_https", "url": url},
            "stateSpec": {"classification": "unknown", "label": "Inspection required", "files": [], "issues": ["Remote contents are not fetched until a bounded inspection transaction is started"]},
            "safetyFindings": [],
            "resourceFindings": [],
            "inspectionPolicy": self.policy.limits.to_dict(),
            "mutated": False,
        }

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
            "safetyFindings": findings,
            "resourceFindings": [],
            "inspectionPolicy": self.policy.limits.to_dict(),
            "inspectionDurationMs": round((monotonic() - started) * 1000),
            "mutated": False,
            "inspectionDigest": _digest({"identity": identity, "stateSpec": state_spec, "findings": findings}),
        }
