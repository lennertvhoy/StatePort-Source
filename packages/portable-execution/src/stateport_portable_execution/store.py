from __future__ import annotations

import json
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import fcntl

from .contracts import LIFECYCLE_STATES, RUN_FORMAT, allowed_lifecycle_transition, allowed_transition, lifecycle_for_status


class RunStore:
    def __init__(self, path: Path):
        self.path = path

    @contextmanager
    def _lock(self, *, exclusive: bool) -> Any:
        lock_path = self.path.with_name(self.path.name + ".lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with lock_path.open("a+", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _load(self) -> dict[str, Any]:
        if not self.path.is_file():
            return {"formatVersion": "stateport.governed-action-run-store/v1", "runs": []}
        value = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or not isinstance(value.get("runs"), list):
            raise ValueError("portable run store is invalid")
        return value

    def _save(self, value: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = self.path.with_name(f".{self.path.name}.tmp")
        payload = (
            json.dumps(
                value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
            )
            + "\n"
        ).encode("utf-8")
        descriptor: int | None = None
        try:
            descriptor = os.open(
                tmp,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_TRUNC
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            written = 0
            while written < len(payload):
                written += os.write(descriptor, payload[written:])
            os.fsync(descriptor)
        finally:
            if descriptor is not None:
                os.close(descriptor)
        os.replace(tmp, self.path)
        directory = os.open(
            self.path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def create(self, record: dict[str, Any]) -> dict[str, Any]:
        with self._lock(exclusive=True):
            record = dict(record)
            record["revision"] = 0
            record.setdefault("lifecycleState", lifecycle_for_status(record.get("status")))
            record.setdefault("lifecycleVersion", "stateport.run-lifecycle/v1")
            value = self._load()
            if any(item.get("runId") == record.get("runId") for item in value["runs"]):
                raise ValueError("run already exists")
            value["runs"].append(record)
            self._save(value)
            return dict(record)

    def get(self, run_id: str) -> dict[str, Any] | None:
        with self._lock(exclusive=False):
            return next((dict(item) for item in self._load()["runs"] if item.get("runId") == run_id), None)

    def all(self, instance_id: str | None = None) -> list[dict[str, Any]]:
        with self._lock(exclusive=False):
            runs = self._load()["runs"]
            if instance_id is not None:
                runs = [item for item in runs if item.get("instanceId") == instance_id]
            return [dict(item) for item in runs]

    @staticmethod
    def _require_binding(
        item: dict[str, Any], *, expected_instance_id: str | None,
        expected_revision: int | None,
    ) -> None:
        if expected_instance_id is not None and item.get("instanceId") != expected_instance_id:
            raise ValueError("run instance identity does not match the expected instance")
        if expected_revision is not None and item.get("revision", 0) != expected_revision:
            raise ValueError("run revision is stale")

    def require_binding(
        self, run_id: str, *, expected_instance_id: str | None,
        expected_revision: int | None,
    ) -> dict[str, Any]:
        with self._lock(exclusive=False):
            item = next((item for item in self._load()["runs"] if item.get("runId") == run_id), None)
            if item is None:
                raise KeyError(run_id)
            self._require_binding(
                item, expected_instance_id=expected_instance_id,
                expected_revision=expected_revision,
            )
            return dict(item)

    def update(
        self, run_id: str, *, expected_instance_id: str | None = None,
        expected_revision: int | None = None, **fields: Any,
    ) -> dict[str, Any]:
        with self._lock(exclusive=True):
            value = self._load()
            for item in value["runs"]:
                if item.get("runId") == run_id:
                    self._require_binding(
                        item, expected_instance_id=expected_instance_id,
                        expected_revision=expected_revision,
                    )
                    if "status" in fields and "lifecycleState" not in fields:
                        fields["lifecycleState"] = lifecycle_for_status(fields["status"])
                    if "lifecycleState" in fields:
                        current_lifecycle = item.get("lifecycleState") or lifecycle_for_status(item.get("status"))
                        target_lifecycle = fields["lifecycleState"]
                        if not allowed_lifecycle_transition(current_lifecycle, target_lifecycle):
                            raise ValueError(f"invalid lifecycle transition: {current_lifecycle} -> {target_lifecycle}")
                        if current_lifecycle != target_lifecycle:
                            item.setdefault("events", []).append({
                                "type": "lifecycle_transition",
                                "fromLifecycle": current_lifecycle,
                                "toLifecycle": target_lifecycle,
                                "actor": fields.pop("lifecycleActor", "stateport"),
                                "reason": fields.pop("lifecycleReason", None),
                                "at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                            })
                    item.update(fields)
                    item["revision"] = int(item.get("revision", 0)) + 1
                    item.setdefault("lifecycleVersion", "stateport.run-lifecycle/v1")
                    self._save(value)
                    return dict(item)
            raise KeyError(run_id)

    def lifecycle_transition(self, run_id: str, target: str, *, actor: str = "stateport", reason: str | None = None, **fields: Any) -> dict[str, Any]:
        """Advance the explicit lifecycle without changing the legacy status projection."""

        return self.update(run_id, lifecycleState=target, lifecycleActor=actor, lifecycleReason=reason, **fields)

    def transition(
        self, run_id: str, target: str, *, actor: str = "stateport",
        reason: str | None = None, expected_instance_id: str | None = None,
        expected_revision: int | None = None, **fields: Any,
    ) -> dict[str, Any]:
        with self._lock(exclusive=True):
            value = self._load()
            for item in value["runs"]:
                if item.get("runId") == run_id:
                    self._require_binding(
                        item, expected_instance_id=expected_instance_id,
                        expected_revision=expected_revision,
                    )
                    current = item.get("status")
                    if not allowed_transition(current, target):
                        raise ValueError(f"invalid run transition: {current} -> {target}")
                    current_lifecycle = item.get("lifecycleState") or lifecycle_for_status(current)
                    requested_lifecycle = fields.pop("lifecycleState", None)
                    target_lifecycle = requested_lifecycle or lifecycle_for_status(target)
                    if not isinstance(target_lifecycle, str) or target_lifecycle not in LIFECYCLE_STATES:
                        raise ValueError(f"invalid lifecycle state: {target_lifecycle}")
                    if not allowed_lifecycle_transition(current_lifecycle, target_lifecycle):
                        raise ValueError(f"invalid lifecycle transition: {current_lifecycle} -> {target_lifecycle}")
                    item.update(fields)
                    item["status"] = target
                    item["lifecycleState"] = target_lifecycle
                    item["lifecycleVersion"] = "stateport.run-lifecycle/v1"
                    item["revision"] = int(item.get("revision", 0)) + 1
                    item.setdefault("attempts", 1)
                    item.setdefault("events", []).append({
                        "type": "state_transition",
                        "from": current,
                        "to": target,
                        "actor": actor,
                        "reason": reason or fields.get("diagnostic"),
                        "at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                    })
                    self._save(value)
                    return dict(item)
            raise KeyError(run_id)

    def recover_orphans(self, active_run_ids: set[str] | None = None) -> list[dict[str, Any]]:
        """Mark persisted in-flight runs interrupted after a service restart."""

        active_run_ids = active_run_ids or set()
        recovered: list[dict[str, Any]] = []
        with self._lock(exclusive=True):
            value = self._load()
            for item in value["runs"]:
                if item.get("runId") in active_run_ids:
                    continue
                if item.get("status") in {"preparing", "prepared", "running", "cancelling", "applying"}:
                    current = item.get("status")
                    target = "interrupted"
                    current_lifecycle = item.get("lifecycleState") or lifecycle_for_status(current)
                    target_lifecycle = "INTERRUPTED"
                    if not allowed_lifecycle_transition(current_lifecycle, target_lifecycle):
                        # A legacy record may have been persisted without the
                        # new field; recovery is allowed to establish the
                        # explicit terminal safety state in that case.
                        current_lifecycle = "STARTING" if current in {"preparing", "prepared"} else current_lifecycle
                    item["status"] = target
                    item["lifecycleState"] = target_lifecycle
                    item["lifecycleVersion"] = "stateport.run-lifecycle/v1"
                    item.setdefault("events", []).append({
                        "type": "state_transition", "from": current, "to": target,
                        "fromLifecycle": current_lifecycle, "toLifecycle": target_lifecycle,
                        "actor": "stateport-recovery",
                        "reason": (
                            "service restart interrupted an apply; rollback is unproven and operator inspection is required"
                            if current == "applying"
                            else "service restart found no live process"
                        ),
                        "at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                    })
                    if current == "applying":
                        item["rollback"] = {
                            "status": "unknown",
                            "byteIdentical": False,
                            "operatorInspectionRequired": True,
                        }
                    item["revision"] = int(item.get("revision", 0)) + 1
                    recovered.append(dict(item))
            if recovered:
                self._save(value)
        return recovered
