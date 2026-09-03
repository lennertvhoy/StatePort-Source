"""Deterministic local fake runner for synthetic artifact tasks."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import shutil

from .contracts import (
    BenchmarkTask,
    ConfigurationIdentity,
    HistoricalCandidate,
    ValidationResult,
    Validator,
)


def _artifact_digest(root: Path) -> tuple[str, int, int]:
    digest = hashlib.sha256()
    file_count = 0
    byte_count = 0
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        content = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
        file_count += 1
        byte_count += len(content)
    return digest.hexdigest(), file_count, byte_count


@dataclass(frozen=True)
class FakeRunResult:
    run_id: str
    task_id: str
    repetition: int
    valid: bool
    deterministic_artifact_digest: str
    artifact_present: bool
    artifact_file_count: int
    artifact_bytes: int
    validation_details: str = ""


class DeterministicFakeRunner:
    """Copy-only runner; it never starts a model, host, or network client."""

    def __init__(self, adapter: str = "fake-local/v1") -> None:
        if not isinstance(adapter, str) or not adapter.strip():
            raise ValueError("adapter must be a non-empty string")
        self.adapter = adapter

    def run(
        self,
        candidate: HistoricalCandidate,
        configuration: ConfigurationIdentity,
        task: BenchmarkTask,
        validator: Validator,
        *,
        repetition: int,
        output_root: Path,
    ) -> FakeRunResult:
        if validator.validator_id != configuration.validator or validator.validator_id != task.validator_id:
            raise ValueError("validator does not match the configuration and task")
        if isinstance(repetition, bool) or not isinstance(repetition, int) or repetition < 0:
            raise ValueError("repetition must be a non-negative integer")
        output_root.mkdir(parents=True, exist_ok=True)
        artifact_path = output_root / task.artifact_path
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        validation_details = ""
        try:
            artifact_path.write_bytes(candidate.read_file(task.source_path))
        except (FileNotFoundError, OSError) as exc:
            validation_details = str(exc)
        try:
            validation: ValidationResult = validator.validate(output_root, task)
        except Exception as exc:  # a failing validator is a failed local run
            validation = ValidationResult(False, f"validator error: {exc}")
        digest, file_count, byte_count = _artifact_digest(output_root)
        return FakeRunResult(
            run_id=hashlib.sha256(
                f"{configuration.configuration_id}:{task.task_id}:{repetition}".encode("utf-8")
            ).hexdigest()[:24],
            task_id=task.task_id,
            repetition=repetition,
            valid=validation.valid,
            deterministic_artifact_digest=digest,
            artifact_present=artifact_path.is_file(),
            artifact_file_count=file_count,
            artifact_bytes=byte_count,
            validation_details=validation_details or validation.details,
        )


__all__ = ["DeterministicFakeRunner", "FakeRunResult"]
