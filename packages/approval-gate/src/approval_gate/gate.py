from __future__ import annotations

import json
import os
import secrets
from contextlib import contextmanager
from dataclasses import dataclass, field
import fcntl
from pathlib import Path
from typing import Any, Iterable

from approval_gate.capabilities import parse_capabilities


_MUTABLE_METADATA_KEYS = frozenset({"decision", "execution"})


def _request_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in metadata.items()
        if key not in _MUTABLE_METADATA_KEYS
    }


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def intersect_capabilities(template_requested: Iterable[str], instance_granted: Iterable[str], operator_allowed: Iterable[str]) -> frozenset[str]:
    template, template_error = parse_capabilities(template_requested, "template")
    instance, instance_error = parse_capabilities(instance_granted, "instance")
    operator, operator_error = parse_capabilities(operator_allowed, "operator")
    if template_error or instance_error or operator_error:
        return frozenset()
    return template & instance & operator


@dataclass(frozen=True)
class CapabilityDecision:
    operation: str
    allowed: bool
    effective_capabilities: frozenset[str]
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {"operation": self.operation, "allowed": self.allowed,
                "effectiveCapabilities": sorted(self.effective_capabilities), "reason": self.reason}


@dataclass(frozen=True)
class ApprovalRequest:
    id: str
    operation: str
    capability: str
    instance_id: str
    status: str = "pending"
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    actor: str = ""
    instance_path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "operation": self.operation, "capability": self.capability,
                "instanceId": self.instance_id, "status": self.status, "reason": self.reason,
                "metadata": self.metadata.copy(), "actor": self.actor,
                "instancePath": self.instance_path}


class ApprovalGate:
    def __init__(self, path: Path | str | None = None) -> None:
        self._requests: dict[str, ApprovalRequest] = {}
        self.path = Path(path) if path is not None else None
        self.lock_path = (
            self.path.with_name(f".{self.path.name}.lock")
            if self.path is not None
            else None
        )
        if self.path is not None and (
            self.path.is_symlink()
            or (self.lock_path is not None and self.lock_path.is_symlink())
        ):
            raise ValueError("approval store paths may not be symlinks")
        if self.path and self.path.exists():
            self._load()

    @contextmanager
    def _write_lock(self):
        if self.path is None or self.lock_path is None:
            yield
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.parent.is_symlink() or self.lock_path.is_symlink():
            raise ValueError("approval store paths may not be symlinks")
        with self.lock_path.open("a+b") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _refresh(self) -> None:
        if self.path is not None and self.path.exists():
            if self.path.is_symlink():
                raise ValueError("approval store path may not be a symlink")
            self._load()
        elif self.path is not None:
            self._requests = {}

    def _persist(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f".{self.path.name}.{secrets.token_hex(6)}.tmp")
        try:
            # Authorization-relevant state must be durable, not merely
            # tear-safe: fsync the staged file, atomically replace, then
            # fsync the directory so the rename survives power loss.
            with temporary.open("w", encoding="utf-8") as handle:
                handle.write(
                    json.dumps([request.to_dict() for request in self._requests.values()], sort_keys=True) + "\n"
                )
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            _fsync_directory(self.path.parent)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise

    def _load(self) -> None:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))  # type: ignore[union-attr]
            if not isinstance(raw, list):
                raise ValueError("approval store must contain a list")
            requests: dict[str, ApprovalRequest] = {}
            for item in raw:
                if not isinstance(item, dict):
                    raise ValueError("approval store contains an invalid request")
                request = ApprovalRequest(
                    id=str(item["id"]), operation=str(item["operation"]),
                    capability=str(item["capability"]), instance_id=str(item["instanceId"]),
                    status=str(item.get("status", "pending")), reason=str(item.get("reason", "")),
                    metadata=dict(item.get("metadata", {})), actor=str(item.get("actor", "")),
                    instance_path=str(item.get("instancePath", "")),
                )
                if request.status not in {"pending", "approved", "rejected", "cancelled"}:
                    raise ValueError("approval store contains an invalid status")
                if request.id in requests:
                    raise ValueError("approval store contains a duplicate request id")
                requests[request.id] = request
            self._requests = requests
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"approval store could not be loaded: {exc}") from exc

    def capability(self, operation: str, capability: str, template: Iterable[str], instance: Iterable[str], operator: Iterable[str]) -> CapabilityDecision:
        parsed = parse_capabilities(template, "template")
        parsed_instance = parse_capabilities(instance, "instance")
        parsed_operator = parse_capabilities(operator, "operator")
        errors = [error for _, error in (parsed, parsed_instance, parsed_operator) if error]
        effective = parsed[0] & parsed_instance[0] & parsed_operator[0] if not errors else frozenset()
        allowed = capability in effective
        reason = "; ".join(errors) if errors else ("capability intersection permits operation" if allowed else "capability intersection denies operation")
        return CapabilityDecision(operation, allowed, effective, reason)

    def request(self, *, operation: str, capability: str, instance_id: str, reason: str = "", metadata: dict[str, Any] | None = None, actor: str = "", instance_path: str = "") -> ApprovalRequest:
        if not operation.strip() or not capability.strip() or not instance_id.strip():
            raise ValueError("operation, capability, and instance_id are required")
        request = ApprovalRequest(secrets.token_hex(12), operation, capability, instance_id, reason=reason, metadata=metadata or {}, actor=actor, instance_path=instance_path)
        with self._write_lock():
            self._refresh()
            self._requests[request.id] = request
            self._persist()
        return request

    def request_once(self, request_id: str, *, operation: str, capability: str, instance_id: str, reason: str = "", metadata: dict[str, Any] | None = None, actor: str = "", instance_path: str = "") -> tuple[ApprovalRequest, bool]:
        """Atomically create one immutable request or return its exact match."""

        if not isinstance(request_id, str) or not request_id.strip():
            raise ValueError("request_id is required")
        if not operation.strip() or not capability.strip() or not instance_id.strip():
            raise ValueError("operation, capability, and instance_id are required")
        requested_metadata = dict(metadata or {})
        if _MUTABLE_METADATA_KEYS.intersection(requested_metadata):
            raise ValueError("approval request metadata uses a reserved lifecycle key")
        candidate = ApprovalRequest(
            request_id.strip(),
            operation,
            capability,
            instance_id,
            reason=reason,
            metadata=requested_metadata,
            actor=actor,
            instance_path=instance_path,
        )
        with self._write_lock():
            self._refresh()
            current = self._requests.get(candidate.id)
            if current is not None:
                immutable_current = (
                    current.operation,
                    current.capability,
                    current.instance_id,
                    current.actor,
                    current.instance_path,
                    _request_metadata(current.metadata),
                )
                immutable_candidate = (
                    candidate.operation,
                    candidate.capability,
                    candidate.instance_id,
                    candidate.actor,
                    candidate.instance_path,
                    _request_metadata(candidate.metadata),
                )
                if immutable_current != immutable_candidate:
                    raise ValueError(
                        "approval request id is bound to different immutable inputs"
                    )
                return current, True
            self._requests[candidate.id] = candidate
            self._persist()
        return candidate, False

    def transition(
        self,
        request_id: str,
        status: str,
        reason: str = "",
        *,
        decided_by: str = "",
        decided_at: str = "",
    ) -> ApprovalRequest:
        if status not in {"approved", "rejected", "cancelled"}:
            raise ValueError("invalid approval status")
        with self._write_lock():
            self._refresh()
            current = self._requests.get(request_id)
            if current is None:
                raise KeyError("unknown approval request")
            if current.status != "pending":
                raise ValueError("only pending approvals can transition")
            metadata = current.metadata.copy()
            if decided_by:
                metadata["decision"] = {
                    "actor": decided_by,
                    "status": status,
                    **({"at": decided_at} if decided_at else {}),
                }
            updated = ApprovalRequest(current.id, current.operation, current.capability, current.instance_id, status, reason, metadata, current.actor, current.instance_path)
            self._requests[request_id] = updated
            self._persist()
        return updated

    def mark_executed(self, request_id: str, *, metadata: dict[str, Any]) -> ApprovalRequest:
        with self._write_lock():
            self._refresh()
            current = self._requests.get(request_id)
            if current is None:
                raise KeyError("unknown approval request")
            if current.status != "approved":
                raise ValueError("only approved requests can be executed")
            merged = current.metadata.copy()
            merged.update(metadata)
            updated = ApprovalRequest(current.id, current.operation, current.capability, current.instance_id, current.status, current.reason, merged, current.actor, current.instance_path)
            self._requests[request_id] = updated
            self._persist()
        return updated

    def get(self, request_id: str) -> ApprovalRequest | None:
        self._refresh()
        return self._requests.get(request_id)

    def all(self) -> tuple[ApprovalRequest, ...]:
        self._refresh()
        return tuple(self._requests[key] for key in sorted(self._requests))
