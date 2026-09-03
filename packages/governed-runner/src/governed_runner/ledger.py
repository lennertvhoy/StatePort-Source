"""Small persistent run-plan ledger with fail-closed record validation."""

from __future__ import annotations

import json
import os
import secrets
from contextlib import contextmanager
import fcntl
from pathlib import Path
from typing import Any, Mapping


RUN_FORMAT = "stateport.governed-run/v1"
_STATUSES = {"planned", "queued", "running", "completed", "failed"}
_TRANSITIONS = {
    "planned": {"queued", "running", "failed"},
    "queued": {"running", "failed"},
    "running": {"running", "completed", "failed"},
    "completed": set(),
    "failed": set(),
}


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class RunLedger:
    """Persist run plans and outcomes as operational metadata, never state truth."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.lock_path = self.path.with_name(f".{self.path.name}.lock")
        self._records: dict[str, dict[str, Any]] = {}
        if self.path.is_symlink() or self.lock_path.is_symlink():
            raise ValueError("run ledger paths may not be symlinks")
        if self.path.exists():
            self._load()

    def _load(self) -> None:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(raw, list):
                raise ValueError("run ledger must contain a list")
            records: dict[str, dict[str, Any]] = {}
            for record in raw:
                if not isinstance(record, Mapping):
                    raise ValueError("run ledger contains an invalid record")
                item = dict(record)
                if item.get("formatVersion") != RUN_FORMAT:
                    raise ValueError("run ledger record has an invalid formatVersion")
                run_id = item.get("runId")
                if not isinstance(run_id, str) or not run_id.strip():
                    raise ValueError("run ledger record has an invalid runId")
                if item.get("status") not in _STATUSES:
                    raise ValueError("run ledger record has an invalid status")
                if run_id in records:
                    raise ValueError("run ledger contains a duplicate runId")
                records[run_id] = item
            self._records = records
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise ValueError(f"run ledger could not be loaded: {exc}") from exc

    @contextmanager
    def _write_lock(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.parent.is_symlink() or self.lock_path.is_symlink():
            raise ValueError("run ledger paths may not be symlinks")
        with self.lock_path.open("a+b") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _refresh(self) -> None:
        if self.path.exists():
            if self.path.is_symlink():
                raise ValueError("run ledger path may not be a symlink")
            self._load()
        else:
            self._records = {}

    def _persist(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f".{self.path.name}.{secrets.token_hex(6)}.tmp")
        try:
            # fsync the staged file, atomically replace, then fsync the
            # directory so run-truth survives power loss, not just tearing.
            with temporary.open("w", encoding="utf-8") as handle:
                handle.write(
                    json.dumps([self._records[key] for key in sorted(self._records)], sort_keys=True) + "\n"
                )
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            _fsync_directory(self.path.parent)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise

    def create(self, *, actor: str, instance_id: str, instance_path: str, template_path: str, capability: str, policy: dict[str, Any], quota: dict[str, Any], execution_plan: dict[str, Any], estimated_cost: float = 0.0, run_id: str | None = None, mode: str = "echo", command: list[str] | None = None, container_engine: str | None = None, runner_image: str | None = None) -> dict[str, Any]:
        run_id = run_id or "run:" + secrets.token_hex(12)
        if not isinstance(mode, str) or not mode.strip():
            raise ValueError("run mode is required")
        if command is not None and (
            not isinstance(command, list)
            or not command
            or not all(isinstance(item, str) and item for item in command)
        ):
            raise ValueError("run command must be a non-empty list of strings")
        if container_engine is not None and container_engine not in {"docker", "podman"}:
            raise ValueError("container engine must be docker or podman")
        if runner_image is not None and (
            not isinstance(runner_image, str)
            or not runner_image.strip()
            or runner_image.startswith("-")
            or any(char.isspace() for char in runner_image)
        ):
            raise ValueError("runner image must be a single non-empty image reference")
        record = {
            "formatVersion": RUN_FORMAT,
            "runId": run_id,
            "status": "planned",
            "actor": actor,
            "instanceId": instance_id,
            "instancePath": instance_path,
            "templatePath": template_path,
            "capability": capability,
            "policy": policy,
            "quota": quota,
            "estimatedCost": estimated_cost,
            "executionPlan": execution_plan,
            "mode": mode,
            "command": list(command or []),
            "containerEngine": container_engine,
            "runnerImage": runner_image,
        }
        with self._write_lock():
            self._refresh()
            if run_id in self._records:
                raise ValueError("runId already exists")
            self._records[run_id] = record
            self._persist()
        return dict(record)

    def get(self, run_id: Any) -> dict[str, Any] | None:
        if not isinstance(run_id, str):
            return None
        self._refresh()
        record = self._records.get(run_id)
        return dict(record) if record is not None else None

    def update(self, run_id: str, *, status: str, **fields: Any) -> dict[str, Any]:
        if status not in _STATUSES:
            raise ValueError("invalid run status")
        if {"runId", "formatVersion", "actor", "instanceId"} & set(fields):
            raise ValueError("immutable run identity fields may not be updated")
        with self._write_lock():
            self._refresh()
            current = self._records.get(run_id)
            if current is None:
                raise KeyError("unknown run")
            if status not in _TRANSITIONS[current["status"]]:
                raise ValueError("invalid run status transition")
            updated = current.copy()
            updated.update(fields)
            updated["status"] = status
            self._records[run_id] = updated
            self._persist()
        return dict(updated)

    def all(self) -> tuple[dict[str, Any], ...]:
        self._refresh()
        return tuple(dict(self._records[key]) for key in sorted(self._records))


__all__ = ["RUN_FORMAT", "RunLedger"]
