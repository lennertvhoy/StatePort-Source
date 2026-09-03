"""Safe file executor with receipt-last commit and failure rollback."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .contract import (
    MigrationContract,
    MigrationError,
    MigrationOperation,
    OperationKind,
    RECEIPT_FORMAT,
    safe_relative_path,
)
from .registry import MigrationRegistry, RegistryError


def _hash_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


class SafeOwnedWorkspace:
    """Resolve only exact declared files under a non-symlinked instance root."""

    def __init__(self, root: Path | str, contract: MigrationContract) -> None:
        candidate = Path(root)
        if candidate.is_symlink() or not candidate.is_dir():
            raise MigrationError("migration root must be an existing regular directory")
        self.root = candidate.resolve()
        self._owned = {item.path for item in contract.owned_paths}

    def path(self, relative: str, *, declared: str) -> Path:
        value = safe_relative_path(relative, "migration path")
        if value not in self._owned:
            raise MigrationError(f"{declared} path is not declared as owned: {value}")
        current = self.root
        for part in Path(value).parts:
            current = current / part
            if current.is_symlink():
                raise MigrationError(f"owned path traverses a symlink: {value}")
        resolved = current.resolve(strict=False)
        if not resolved.is_relative_to(self.root):
            raise MigrationError(f"owned path escapes migration root: {value}")
        return current

    def read(self, relative: str) -> bytes | None:
        target = self.path(relative, declared="read")
        if not target.exists():
            return None
        if not target.is_file():
            raise MigrationError(f"owned path is not a regular file: {relative}")
        return target.read_bytes()

    def write(self, relative: str, value: bytes, *, replace: bool = False) -> None:
        target = self.path(relative, declared="write")
        if target.exists() and target.is_symlink():
            raise MigrationError(f"write target is a symlink: {relative}")
        if target.exists() and not target.is_file():
            raise MigrationError(f"write target is not a regular file: {relative}")
        if target.exists() and not replace:
            raise MigrationError(f"write target already exists: {relative}")
        target.parent.mkdir(parents=True, exist_ok=True)
        # Re-check parent components after mkdir before the atomic replacement.
        self.path(relative, declared="write")
        temporary = target.parent / f".{target.name}.stateport-migration.tmp"
        if temporary.exists() or temporary.is_symlink():
            raise MigrationError(f"temporary write path already exists: {relative}")
        try:
            with temporary.open("xb") as handle:
                handle.write(value)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
        finally:
            if temporary.exists():
                temporary.unlink()

    def delete(self, relative: str) -> None:
        target = self.path(relative, declared="write")
        if not target.exists():
            return
        if target.is_symlink() or not target.is_file():
            raise MigrationError(f"delete target is not a regular file: {relative}")
        target.unlink()


@dataclass(frozen=True)
class ApplyResult:
    """Typed durable receipt returned by a migration application."""

    receipt: dict[str, Any]
    idempotent: bool = False

    def to_dict(self) -> dict[str, Any]:
        value = dict(self.receipt)
        value["idempotent"] = self.idempotent
        return value

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]


@dataclass
class _Snapshot:
    path: str
    value: bytes | None


class MigrationTransaction:
    """In-process rollback journal for the declared paths of one migration."""

    def __init__(self, workspace: SafeOwnedWorkspace) -> None:
        self.workspace = workspace
        self.snapshots: dict[str, _Snapshot] = {}

    def capture(self, path: str) -> None:
        safe_relative_path(path, "transaction path")
        if path not in self.snapshots:
            self.snapshots[path] = _Snapshot(path, self.workspace.read(path))

    def rollback(self) -> None:
        for snapshot in reversed(tuple(self.snapshots.values())):
            current = self.workspace.read(snapshot.path)
            if snapshot.value is None:
                if current is not None:
                    self.workspace.delete(snapshot.path)
            else:
                self.workspace.write(snapshot.path, snapshot.value, replace=current is not None)


def _receipt_directory(root: Path) -> Path:
    stateport = root / ".stateport"
    if stateport.is_symlink():
        raise MigrationError("StatePort receipt directory is a symlink")
    receipts = stateport / "migrations" / "receipts"
    for parent in (stateport, stateport / "migrations", receipts):
        if parent.exists() and parent.is_symlink():
            raise MigrationError("StatePort receipt path contains a symlink")
    receipts.mkdir(parents=True, exist_ok=True)
    return receipts


def _receipt_path(root: Path, migration_id: str) -> Path:
    # Contract IDs are validated before this function is called.
    return _receipt_directory(root) / f"{migration_id}.json"


def _read_receipt(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file():
        raise MigrationError("migration receipt is not a regular file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MigrationError(f"could not read migration receipt: {exc}") from exc
    if not isinstance(value, dict) or value.get("formatVersion") != RECEIPT_FORMAT:
        raise MigrationError("migration receipt format is unsupported")
    return value


def _write_receipt(path: Path, value: dict[str, Any]) -> None:
    temporary = path.parent / f".{path.name}.tmp"
    if temporary.exists() or temporary.is_symlink():
        raise MigrationError("migration receipt temporary path already exists")
    try:
        with temporary.open("xb") as handle:
            handle.write(_canonical_json(value) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _hashes(workspace: SafeOwnedWorkspace, paths: tuple[str, ...]) -> dict[str, str | None]:
    return {path: (_hash_bytes(value) if (value := workspace.read(path)) is not None else None) for path in paths}


def _check_expected(operation: MigrationOperation, value: bytes | None) -> None:
    if operation.expected_hash is not None and operation.expected_hash != (
        _hash_bytes(value) if value is not None else None
    ):
        raise MigrationError(f"expected hash does not match {operation.target}")


def _apply_operation(workspace: SafeOwnedWorkspace, operation: MigrationOperation, transaction: MigrationTransaction) -> None:
    source_value = workspace.read(operation.source) if operation.source is not None else workspace.read(operation.target)
    _check_expected(operation, source_value)
    transaction.capture(operation.target)
    if operation.source is not None:
        transaction.capture(operation.source)
    if operation.kind is OperationKind.COPY:
        if source_value is None:
            raise MigrationError(f"copy source is missing: {operation.source}")
        workspace.write(operation.target, source_value)
    elif operation.kind is OperationKind.MOVE:
        if source_value is None:
            raise MigrationError(f"move source is missing: {operation.source}")
        workspace.write(operation.target, source_value)
        workspace.delete(operation.source)  # type: ignore[arg-type]
    elif operation.kind is OperationKind.DELETE:
        workspace.delete(operation.target)
    elif operation.kind is OperationKind.WRITE_TEXT:
        workspace.write(operation.target, operation.content.encode("utf-8"))  # type: ignore[union-attr]
    elif operation.kind is OperationKind.REPLACE_TEXT:
        if source_value is None:
            raise MigrationError(f"replace_text target is missing: {operation.target}")
        try:
            current = source_value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise MigrationError(f"replace_text target is not UTF-8: {operation.target}") from exc
        if current.count(operation.old) != 1:  # type: ignore[arg-type]
            raise MigrationError(f"replace_text requires exactly one old value: {operation.target}")
        workspace.write(operation.target, current.replace(operation.old, operation.new, 1).encode("utf-8"), replace=True)  # type: ignore[arg-type]
    else:  # pragma: no cover - enum validation makes this unreachable
        raise MigrationError(f"unsupported operation: {operation.kind}")


class MigrationExecutor:
    """Apply only registered, typed contracts to one instance root."""

    def __init__(self, registry: MigrationRegistry | None = None, *, applied_at: str | None = None) -> None:
        self.registry = registry
        self.applied_at = applied_at

    def apply(self, root: Path | str, migration: MigrationContract | str) -> ApplyResult:
        if self.registry is not None:
            if isinstance(migration, str):
                contract = self.registry.get(migration)
            else:
                contract = self.registry.get(migration.migration_id)
                if contract.digest != migration.digest:
                    raise RegistryError("supplied migration differs from the registered contract")
        elif isinstance(migration, MigrationContract):
            contract = migration
        else:
            raise MigrationError("an unregistered migration requires a MigrationContract")
        contract.__post_init__()
        workspace = SafeOwnedWorkspace(root, contract)
        receipt_path = _receipt_path(workspace.root, contract.migration_id)
        existing = _read_receipt(receipt_path)
        if existing is not None:
            if existing.get("migrationId") != contract.migration_id or existing.get("contractDigest") != contract.digest:
                raise MigrationError("existing receipt does not match the migration contract")
            expected = existing.get("afterHashes")
            if expected != _hashes(workspace, contract.write_paths):
                raise MigrationError("existing migration receipt is stale or output was modified")
            return ApplyResult(existing, idempotent=True)

        before_reads = _hashes(workspace, contract.read_paths)
        transaction = MigrationTransaction(workspace)
        try:
            for operation in contract.operations:
                _apply_operation(workspace, operation, transaction)
            after_hashes = _hashes(workspace, contract.write_paths)
            receipt: dict[str, Any] = {
                "formatVersion": RECEIPT_FORMAT,
                "status": "applied",
                "migrationId": contract.migration_id,
                "contractDigest": contract.digest,
                "fromVersion": contract.from_version,
                "toVersion": contract.to_version,
                "appliedAt": self.applied_at or datetime.now(timezone.utc).isoformat(),
                "beforeHashes": before_reads,
                "afterHashes": after_hashes,
                "operations": [operation.to_dict() for operation in contract.operations],
                "rollback": {"supported": True, "onFailure": "restore-before-state"},
            }
            # The receipt is written only after all declared operations succeed.
            _write_receipt(receipt_path, receipt)
            return ApplyResult(receipt, idempotent=False)
        except Exception:
            try:
                transaction.rollback()
            except Exception as rollback_error:
                raise MigrationError(f"migration failed and rollback failed: {rollback_error}") from rollback_error
            raise


def apply_migration(
    root: Path | str,
    migration: MigrationContract | str,
    *,
    registry: MigrationRegistry | None = None,
    applied_at: str | None = None,
) -> ApplyResult:
    """Convenience wrapper for the registry-bound executor."""

    return MigrationExecutor(registry, applied_at=applied_at).apply(root, migration)
