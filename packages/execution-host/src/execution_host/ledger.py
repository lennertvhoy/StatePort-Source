"""Durable operation ledger for the execution-host daemon.

One atomic JSON document per workload plus a recovery journal.  On boot the
daemon reconciles the ledger against the engine's ``io.stateport.execution.managed``
enumeration *before* accepting new work: a workload the previous epoch left
non-terminal is marked ``interrupted``, its container is stopped and removed,
and the cleanup outcome is receipted.  Orphan managed containers with no
ledger entry are removed and receipted as well.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import threading
from typing import Any, Mapping

from .daemon_contract import TERMINAL_STATES, canonical_digest
from .engine import KIND_LABEL, MANAGED_LABEL_KEY, WORKLOAD_LABEL


class LedgerError(RuntimeError):
    pass


def _container_identity_error(
    entry: Mapping[str, Any], info: Mapping[str, Any]
) -> str | None:
    workload_id = str(entry["workloadId"])
    kind = str(entry.get("spec", {}).get("kind", ""))
    labels = info.get("labels")
    if not isinstance(labels, Mapping):
        return "container has no label mapping"
    if labels.get(MANAGED_LABEL_KEY) != "true":
        return "container lacks the managed label"
    if labels.get(WORKLOAD_LABEL) != workload_id:
        return "container workload label does not match"
    if labels.get(KIND_LABEL) != kind:
        return "container kind label does not match"
    try:
        expected_image_digest = entry["spec"]["image"]["reference"].rsplit("@", 1)[1]
    except (KeyError, AttributeError, IndexError):
        return "ledger entry has no sealed image identity"
    if info.get("imageDigest") != expected_image_digest:
        return "container image digest does not match the sealed spec"
    return None


def _atomic_write(path: Path, payload: Mapping[str, Any]) -> None:
    # Unique temporary name in the same directory: concurrent writers never
    # collide on a shared fixed ".tmp" path.
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=path.name + ".", suffix=".tmp"
    )
    data = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    directory_fd = os.open(str(path.parent), os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


class OperationLedger:
    def __init__(self, state_dir: Path) -> None:
        self._state_dir = Path(state_dir)
        self._workloads_dir = self._state_dir / "workloads"
        self._recovery_dir = self._state_dir / "recovery"
        self._deployment_operations_dir = self._state_dir / "deployment-operations"
        # One lock serializes every ledger read-modify-write: the supervisor
        # thread and connection threads can never interleave transitions.
        self._lock = threading.Lock()
        for directory in (
            self._workloads_dir,
            self._recovery_dir,
            self._deployment_operations_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)
            os.chmod(directory, 0o700)

    @property
    def state_dir(self) -> Path:
        return self._state_dir

    def _path(self, workload_id: str) -> Path:
        return self._workloads_dir / f"{workload_id}.json"

    def _deployment_operation_path(self, operation_id: str) -> Path:
        return self._deployment_operations_dir / f"{operation_id}.json"

    def _read_deployment_operation(
        self, operation_id: str
    ) -> dict[str, Any] | None:
        path = self._deployment_operation_path(operation_id)
        if not path.is_file():
            return None
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            raise LedgerError(
                f"deployment operation {operation_id} is unreadable: {exc}"
            ) from exc
        if not isinstance(value, dict):
            raise LedgerError(
                f"deployment operation {operation_id} is not an object"
            )
        return value

    def admit_deployment_operation(
        self,
        request: Mapping[str, Any],
        *,
        request_digest: str,
        requester: Mapping[str, Any],
        payload: Mapping[str, Any] | None = None,
        at: str,
    ) -> dict[str, Any]:
        """Durably admit one exact host-side deployment operation.

        A completed or interrupted operation replays its exact receipt. An
        in-flight duplicate is reported without re-entering the adapter, and
        reusing an operation identity for different bytes is always refused.
        """

        operation_id = str(request["operationId"])
        with self._lock:
            existing = self._read_deployment_operation(operation_id)
            if existing is not None:
                if existing.get("requestDigest") != request_digest:
                    raise LedgerError(
                        f"deployment operation {operation_id} was reused for a different request"
                    )
                receipt = existing.get("receipt")
                if existing.get("state") in {"completed", "interrupted"} and isinstance(
                    receipt, Mapping
                ):
                    return {"status": "replay", "receipt": dict(receipt)}
                return {"status": "in-progress", "receipt": None}
            deployment_id = (
                payload.get("deploymentId") if isinstance(payload, Mapping) else None
            )
            entry = {
                "operationId": operation_id,
                "requestDigest": request_digest,
                "operation": str(request["operation"]),
                "deploymentId": deployment_id,
                "requester": dict(requester),
                "state": "admitted",
                "receivedAt": at,
                "updatedAt": at,
                "receipt": None,
            }
            _atomic_write(self._deployment_operation_path(operation_id), entry)
            return {"status": "admitted", "receipt": None}

    def complete_deployment_operation(
        self,
        operation_id: str,
        *,
        request_digest: str,
        receipt: Mapping[str, Any],
        at: str,
    ) -> dict[str, Any]:
        with self._lock:
            entry = self._read_deployment_operation(operation_id)
            if entry is None:
                raise LedgerError(
                    f"deployment operation {operation_id} was not admitted"
                )
            if entry.get("requestDigest") != request_digest:
                raise LedgerError(
                    f"deployment operation {operation_id} request digest changed"
                )
            if entry.get("state") != "admitted":
                existing_receipt = entry.get("receipt")
                if existing_receipt == dict(receipt):
                    return entry
                raise LedgerError(
                    f"deployment operation {operation_id} is already {entry.get('state')}"
                )
            entry.update(
                state="completed",
                updatedAt=at,
                receipt=dict(receipt),
            )
            _atomic_write(self._deployment_operation_path(operation_id), entry)
            return entry

    def interrupt_deployment_operations(self, *, at: str) -> list[str]:
        """Fail closed for effects whose daemon process ended without a receipt."""

        interrupted: list[str] = []
        with self._lock:
            for path in sorted(self._deployment_operations_dir.glob("*.json")):
                try:
                    entry = json.loads(path.read_text(encoding="utf-8"))
                except (ValueError, OSError) as exc:
                    raise LedgerError(
                        f"deployment operation entry {path.name} is unreadable: {exc}"
                    ) from exc
                if not isinstance(entry, dict) or entry.get("state") != "admitted":
                    continue
                operation_id = str(entry.get("operationId"))
                operation = str(entry.get("operation"))
                receipt = {
                    "formatVersion": "stateport.execution-host-receipt/v1",
                    "operationId": operation_id,
                    "requestDigest": entry.get("requestDigest"),
                    "accepted": True,
                    "refusal": None,
                    "requester": dict(entry.get("requester") or {}),
                    "result": {
                        "outcome": "failed",
                        "operation": operation,
                        "value": None,
                        "failure": {
                            "code": "operation-interrupted",
                            "message": (
                                "the execution-host process ended before the deployment "
                                "effect produced a durable receipt"
                            ),
                            "details": {
                                "runtimeEffectUncertain": True,
                                "automaticReplay": False,
                            },
                        },
                    },
                    "observed": {
                        "engine": None,
                        "engineVersion": None,
                        "imageDigest": None,
                        "exitStatus": None,
                        "startedAt": None,
                        "finishedAt": None,
                    },
                    "cleanup": {
                        "outcome": "not-required",
                        "detail": (
                            "daemon-owned transfer snapshots are reconciled separately; "
                            "runtime effects require a new governed reconciliation operation"
                        ),
                    },
                    "timestamps": {
                        "receivedAt": str(entry.get("receivedAt") or at),
                        "completedAt": at,
                    },
                }
                entry.update(
                    state="interrupted",
                    updatedAt=at,
                    receipt=receipt,
                )
                _atomic_write(path, entry)
                interrupted.append(operation_id)
        return interrupted

    def _read(self, workload_id: str) -> dict[str, Any] | None:
        path = self._path(workload_id)
        if not path.is_file():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            raise LedgerError(f"ledger entry for {workload_id} is unreadable: {exc}") from exc

    def get(self, workload_id: str) -> dict[str, Any] | None:
        with self._lock:
            return self._read(workload_id)

    def all(self) -> list[dict[str, Any]]:
        with self._lock:
            return self._read_all_unlocked()

    def record_created(
        self,
        spec: Mapping[str, Any],
        *,
        at: str,
        container_id: str,
        grant_id: str = "unbound",
        grant_epoch: int = 0,
    ) -> dict[str, Any]:
        with self._lock:
            workload_id = str(spec["workloadId"])
            if self._path(workload_id).exists():
                raise LedgerError(f"workload {workload_id} already has a ledger entry")
            entry = {
                "workloadId": workload_id,
                "specDigest": canonical_digest(spec),
                "spec": dict(spec),
                "containerId": container_id,
                "grantId": grant_id,
                "grantEpoch": grant_epoch,
                "state": "created",
                "version": 1,
                "createdAt": at,
                "updatedAt": at,
                "startedAt": None,
                "finishedAt": None,
                "exitStatus": None,
                "receipts": [],
            }
            _atomic_write(self._path(workload_id), entry)
            return entry

    def reserve(
        self,
        spec: Mapping[str, Any],
        *,
        at: str,
        grant_id: str,
        grant_epoch: int,
        max_active: int,
        max_per_grant: int,
        grant_digest: str | None = None,
    ) -> dict[str, Any]:
        """Atomically reserve capacity for a new workload.

        Under the ledger lock: reject duplicates and exhausted capacity
        (daemon-wide and per-grant) and insert a ``reserved`` placeholder.
        The engine container is created AFTER the reservation, outside the
        lock, so a slow engine never serializes transitions; the placeholder
        already counts against every capacity check, so the capacity
        reservation and the workload creation cannot interleave.
        """
        with self._lock:
            workload_id = str(spec["workloadId"])
            if self._path(workload_id).exists():
                raise LedgerError(f"workload {workload_id} already has a ledger entry")
            active = [
                entry
                for entry in self._read_all_unlocked()
                if entry["state"] not in TERMINAL_STATES
            ]
            if len(active) >= max_active:
                raise LedgerError("daemon workload capacity is exhausted")
            if sum(1 for entry in active if entry.get("grantId") == grant_id) >= max_per_grant:
                raise LedgerError("the grant's active workload budget is exhausted")
            entry = {
                "workloadId": workload_id,
                "specDigest": canonical_digest(spec),
                "spec": dict(spec),
                "containerId": None,
                "grantId": grant_id,
                "grantDigest": grant_digest,
                "grantEpoch": grant_epoch,
                "state": "reserved",
                "version": 1,
                "createdAt": at,
                "updatedAt": at,
                "startedAt": None,
                "finishedAt": None,
                "exitStatus": None,
                "receipts": [],
            }
            _atomic_write(self._path(workload_id), entry)
            return entry

    def finalize_reserved(
        self,
        workload_id: str,
        *,
        at: str,
        container_id: str,
        expect_version: int | None = None,
        extra: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Complete a reservation after the engine container exists."""
        return self.transition(
            workload_id,
            "created",
            at=at,
            expect_states={"reserved"},
            expect_version=expect_version,
            extra={**dict(extra or {}), "containerId": container_id},
        )

    def abort_reserved(
        self, workload_id: str, *, at: str, receipt: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Fail a reservation whose engine creation failed (terminal)."""
        return self.transition(
            workload_id,
            "failed",
            at=at,
            expect_states={"reserved"},
            finished_at=at,
            receipt=receipt,
        )

    def _read_all_unlocked(self) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        for path in sorted(self._workloads_dir.glob("*.json")):
            try:
                entries.append(json.loads(path.read_text(encoding="utf-8")))
            except (ValueError, OSError) as exc:
                raise LedgerError(f"ledger entry {path.name} is unreadable: {exc}") from exc
        return entries

    def transition(
        self,
        workload_id: str,
        state: str,
        *,
        at: str,
        receipt: Mapping[str, Any] | None = None,
        exit_status: int | None = None,
        started_at: str | None = None,
        finished_at: str | None = None,
        extra: Mapping[str, Any] | None = None,
        expect_states: set[str] | None = None,
        expect_version: int | None = None,
    ) -> dict[str, Any]:
        """Versioned CAS transition: every write increments ``version`` and
        optionally refuses unless the current state and version match."""
        with self._lock:
            entry = self._read(workload_id)
            if entry is None:
                raise LedgerError(f"workload {workload_id} has no ledger entry")
            if expect_states is not None and entry["state"] not in expect_states:
                raise LedgerError(
                    f"workload {workload_id} is {entry['state']}; "
                    f"expected one of {sorted(expect_states)}"
                )
            if expect_version is not None and int(entry.get("version", 0)) != expect_version:
                raise LedgerError(
                    f"workload {workload_id} is version {entry.get('version', 0)}; "
                    f"expected version {expect_version}"
                )
            entry["state"] = state
            entry["version"] = int(entry.get("version", 0)) + 1
            entry["updatedAt"] = at
            if exit_status is not None:
                entry["exitStatus"] = exit_status
            if started_at is not None:
                entry["startedAt"] = started_at
            if finished_at is not None:
                entry["finishedAt"] = finished_at
            if receipt is not None:
                entry["receipts"].append(dict(receipt))
            if extra:
                entry.update(dict(extra))
            _atomic_write(self._path(workload_id), entry)
            return entry

    def record_recovery(self, report: Mapping[str, Any], *, at: str) -> Path:
        name = f"recovery-{at.replace(':', '').replace('-', '')}.json"
        path = self._recovery_dir / name
        _atomic_write(path, {"recordedAt": at, "report": dict(report)})
        return path

    def active_workload_ids(self, grant_id: str | None = None) -> set[str]:
        return {
            str(entry["workloadId"])
            for entry in self.all()
            if entry["state"] not in TERMINAL_STATES
            and (grant_id is None or entry.get("grantId") == grant_id)
        }


def reconcile_on_boot(ledger: OperationLedger, engine: Any, *, at: str) -> dict[str, Any]:
    """Reconcile durable ledger state against managed engine containers.

    Returns the recovery report; every reconciliation action is recorded.
    The daemon must run this before accepting new work.

    Ephemeral (non-workspace) workloads are terminated and receipted across a
    restart.  Persistent workspaces are deliberately ADOPTED: a surviving
    workspace container is reattached in its observed state (running stays
    running, anything else becomes stopped) and its daemon-owned volume is
    never touched by reconciliation.
    """

    report: dict[str, Any] = {"interrupted": [], "adopted": [], "orphansRemoved": [], "failures": []}
    managed = engine.list_managed()
    managed_by_id: dict[str, Mapping[str, Any]] = {}
    for item in managed:
        labels = item.get("labels")
        if not isinstance(labels, Mapping):
            report["failures"].append(
                {"workloadId": None, "error": "managed container has no label mapping"}
            )
            continue
        workload_id = labels.get(WORKLOAD_LABEL)
        kind = labels.get(KIND_LABEL)
        if (
            labels.get(MANAGED_LABEL_KEY) != "true"
            or not isinstance(workload_id, str)
            or not workload_id
            or not isinstance(kind, str)
            or not kind
            or item.get("workloadId") != workload_id
        ):
            report["failures"].append(
                {
                    "workloadId": workload_id,
                    "error": "container enumeration lacks exact managed workload/kind labels",
                }
            )
            continue
        if workload_id in managed_by_id:
            report["failures"].append(
                {"workloadId": workload_id, "error": "duplicate managed workload identity"}
            )
            continue
        managed_by_id[workload_id] = item

    for entry in ledger.all():
        workload_id = str(entry["workloadId"])
        is_workspace = entry.get("spec", {}).get("kind") == "workspace"
        if entry["state"] in TERMINAL_STATES:
            if entry["state"] != "removed":
                # Terminal in the ledger but still present in the engine:
                # finish the cleanup the previous epoch did not complete.
                try:
                    info = engine.inspect(workload_id)
                    if info.get("present"):
                        identity_error = _container_identity_error(entry, info)
                        if identity_error is not None:
                            report["failures"].append(
                                {"workloadId": workload_id, "error": identity_error}
                            )
                        else:
                            engine.remove(workload_id, force=True)
                            report["orphansRemoved"].append(workload_id)
                except Exception as exc:  # reconciliation records, never hides
                    report["failures"].append({"workloadId": workload_id, "error": str(exc)[:300]})
            continue
        if is_workspace:
            # Adopt-and-reattach: the workspace container and volume survive
            # a daemon restart by design; never terminate-and-receipt them.
            try:
                info = engine.inspect(workload_id)
            except Exception as exc:
                report["failures"].append({"workloadId": workload_id, "error": str(exc)[:300]})
                continue
            if info.get("present"):
                identity_error = _container_identity_error(entry, info)
                if identity_error is not None:
                    # A foreign name claim is not daemon-owned and is never
                    # adopted or destructively removed. Boot fails closed.
                    report["failures"].append(
                        {"workloadId": workload_id, "error": identity_error}
                    )
                    continue
                verifier = getattr(engine, "verify_workspace_volumes", None)
                if not callable(verifier):
                    report["failures"].append(
                        {
                            "workloadId": workload_id,
                            "error": "engine cannot verify daemon-owned workspace volume claims",
                        }
                    )
                    continue
                try:
                    verifier(entry["spec"])
                except Exception as exc:
                    report["failures"].append(
                        {
                            "workloadId": workload_id,
                            "error": f"workspace volume identity mismatch: {str(exc)[:240]}",
                        }
                    )
                    continue
                observed_state = "running" if info.get("running") else "stopped"
                # Boot reconciliation is single-threaded and runs before the
                # supervisor or socket server exists, so no runtime CAS is
                # needed for these adoption-only transitions.
                ledger.transition(
                    workload_id,
                    observed_state,
                    at=at,
                    started_at=entry.get("startedAt") if observed_state == "running" else None,
                    receipt={
                        "kind": "restart-adopt",
                        "detail": (
                            f"daemon restart reattached the persistent workspace; "
                            f"observed engine state is {info.get('status', 'unknown')}"
                        ),
                        "cleanup": "not-required",
                    },
                )
                report["adopted"].append(workload_id)
            else:
                ledger.transition(
                    workload_id,
                    "interrupted",
                    at=at,
                    receipt={
                        "kind": "restart-recovery",
                        "detail": (
                            "workspace container is absent across the daemon restart; "
                            "the daemon-owned data volume is preserved"
                        ),
                        "cleanup": "not-required",
                    },
                )
                report["interrupted"].append(workload_id)
            continue
        # Non-terminal across a daemon restart: supervision is lost, so the
        # alpha policy is terminate-and-receipt, never adopt.
        try:
            info = engine.inspect(workload_id)
            if info.get("present"):
                identity_error = _container_identity_error(entry, info)
                if identity_error is not None:
                    report["failures"].append(
                        {"workloadId": workload_id, "error": identity_error}
                    )
                    continue
                engine.stop(workload_id, timeout=2)
                engine.remove(workload_id, force=True)
            ledger.transition(
                workload_id,
                "interrupted",
                at=at,
                receipt={
                    "kind": "restart-recovery",
                    "detail": "daemon restart interrupted a non-terminal workload; container stopped and removed",
                    "cleanup": "performed" if info.get("present") else "not-required",
                },
            )
            report["interrupted"].append(workload_id)
        except Exception as exc:
            report["failures"].append({"workloadId": workload_id, "error": str(exc)[:300]})

    ledger_ids = {str(entry["workloadId"]) for entry in ledger.all()}
    for workload_id in sorted(set(managed_by_id) - ledger_ids):
        try:
            engine.stop(workload_id, timeout=2)
            engine.remove(workload_id, force=True)
            report["orphansRemoved"].append(workload_id)
        except Exception as exc:
            report["failures"].append({"workloadId": workload_id, "error": str(exc)[:300]})

    ledger.record_recovery(report, at=at)
    return report
