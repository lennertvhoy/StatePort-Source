"""Small immutable contracts for local historical candidate evaluation."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Callable, Any


FORMAT_VERSION = "stateport.historical-benchmark/v1"
_HEX40 = re.compile(r"^[0-9a-f]{40}$")


def _required(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _safe_relative_path(value: Any, name: str) -> str:
    value = _required(value, name).replace("\\", "/")
    path = Path(value)
    if path.is_absolute() or value.startswith("/") or ".." in path.parts:
        raise ValueError(f"{name} must be a repository-relative path")
    return value


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True)
class HistoricalCandidate:
    """A commit and its tree, resolved from a local Git repository."""

    repository: str
    commit: str
    tree: str
    ref: str
    subject: str = ""
    local_repository: str = ""

    def __post_init__(self) -> None:
        _required(self.repository, "repository")
        for name in ("commit", "tree"):
            value = _required(getattr(self, name), name)
            if not _HEX40.fullmatch(value):
                raise ValueError(f"{name} must be a full lowercase Git object id")
        _required(self.ref, "ref")
        object.__setattr__(self, "local_repository", self.local_repository or self.repository)
        _required(self.local_repository, "local_repository")

    def to_dict(self) -> dict[str, str]:
        return {
            "repository": self.repository,
            "commit": self.commit,
            "tree": self.tree,
            "ref": self.ref,
            "subject": self.subject,
        }

    @property
    def candidate_id(self) -> str:
        """Stable ID for the resolved source, independent of its display subject."""

        identity = {"repository": self.repository, "commit": self.commit, "tree": self.tree}
        return hashlib.sha256(_canonical(identity).encode("utf-8")).hexdigest()[:24]

    def read_file(self, path: str) -> bytes:
        """Read one file from this exact commit; no checkout or remote access occurs."""

        path = _safe_relative_path(path, "path")
        completed = subprocess.run(
            ["git", "show", f"{self.commit}:{path}"],
            cwd=self.local_repository,
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0:
            raise FileNotFoundError(f"{path} is not present in candidate {self.commit}")
        return completed.stdout


@dataclass(frozen=True)
class BenchmarkTask:
    """A public synthetic task that maps one candidate file to one artifact."""

    task_id: str
    source_path: str
    artifact_path: str
    validator_id: str

    def __post_init__(self) -> None:
        _required(self.task_id, "task_id")
        _safe_relative_path(self.source_path, "source_path")
        _safe_relative_path(self.artifact_path, "artifact_path")
        _required(self.validator_id, "validator_id")


@dataclass(frozen=True)
class ValidationResult:
    valid: bool
    details: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.valid, bool):
            raise TypeError("valid must be a bool")


ValidatorFunction = Callable[[Path, BenchmarkTask], ValidationResult]


@dataclass(frozen=True)
class Validator:
    """Named deterministic validator supplied by the local benchmark caller."""

    validator_id: str
    function: ValidatorFunction

    def __post_init__(self) -> None:
        _required(self.validator_id, "validator_id")
        if not callable(self.function):
            raise TypeError("function must be callable")

    def validate(self, output_root: Path, task: BenchmarkTask) -> ValidationResult:
        result = self.function(output_root, task)
        if not isinstance(result, ValidationResult):
            raise TypeError("validator function must return ValidationResult")
        return result


@dataclass(frozen=True)
class ConfigurationIdentity:
    """All dimensions that must match before two historical runs are compared."""

    repository: str
    commit: str
    tree: str
    adapter: str
    context_policy: str
    task_set: tuple[str, ...]
    validator: str
    configuration_id: str = ""

    def __post_init__(self) -> None:
        _required(self.repository, "repository")
        for name in ("commit", "tree"):
            value = _required(getattr(self, name), name)
            if not _HEX40.fullmatch(value):
                raise ValueError(f"{name} must be a full lowercase Git object id")
        for name in ("adapter", "context_policy", "validator"):
            _required(getattr(self, name), name)
        task_set = tuple(sorted(self.task_set))
        if not task_set or any(not isinstance(item, str) or not item.strip() for item in task_set):
            raise ValueError("task_set must contain non-empty task IDs")
        if len(task_set) != len(set(task_set)):
            raise ValueError("task_set must not contain duplicates")
        object.__setattr__(self, "task_set", task_set)
        if not self.configuration_id:
            object.__setattr__(self, "configuration_id", self._digest())
        else:
            _required(self.configuration_id, "configuration_id")

    def to_dict(self, *, include_identity: bool = True) -> dict[str, Any]:
        value: dict[str, Any] = {
            "formatVersion": FORMAT_VERSION,
            "repository": self.repository,
            "commit": self.commit,
            "tree": self.tree,
            "adapter": self.adapter,
            "contextPolicy": self.context_policy,
            "taskSet": list(self.task_set),
            "validator": self.validator,
        }
        if include_identity:
            value["configurationId"] = self.configuration_id
        return value

    def _digest(self) -> str:
        return hashlib.sha256(_canonical(self.to_dict(include_identity=False)).encode("utf-8")).hexdigest()[:24]

    def canonical_json(self) -> str:
        return _canonical(self.to_dict())
