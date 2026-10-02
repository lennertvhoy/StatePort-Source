#!/usr/bin/env python3
"""Focused tests for the StatePort-owned declarative migration boundary."""

from __future__ import annotations

import json
import hashlib
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "lifecycle-migrations" / "src"))

from lifecycle_migrations import (  # noqa: E402
    MigrationContract,
    MigrationError,
    MigrationOperation,
    MigrationRegistry,
    OperationKind,
    OwnedPath,
    PathOwner,
    RegistryError,
    apply_migration,
)


def _contract(*, migration_id: str = "stateport.fixture.rename", operations=None, reads=None, writes=None, owned=None) -> MigrationContract:
    operations = tuple(operations or (MigrationOperation(OperationKind.MOVE, source="state/settings.txt", target="state/preferences.txt"),))
    reads = tuple(sorted(reads or {"state/settings.txt"}))
    writes = tuple(sorted(writes or {"state/preferences.txt"}))
    owned = tuple(OwnedPath(path, PathOwner.INSTANCE) for path in sorted(owned or set(reads) | set(writes)))
    return MigrationContract(
        migration_id=migration_id,
        from_version="1.0.0",
        to_version="1.1.0",
        read_paths=reads,
        write_paths=writes,
        owned_paths=owned,
        operations=operations,
        description="fixture migration",
    )


def test_contract_and_registry_are_typed_and_digest_deterministic() -> None:
    contract = _contract()
    restored = MigrationContract.from_dict(contract.to_dict())
    assert restored == contract
    assert restored.digest == contract.digest
    registry = MigrationRegistry.from_contracts([contract])
    assert MigrationRegistry.from_dict(registry.to_dict()).digest == registry.digest
    assert registry.path("1.0.0", "1.1.0") == (contract,)


def test_registry_rejects_duplicates_and_unsafe_contract_fields() -> None:
    contract = _contract()
    try:
        MigrationRegistry((contract, contract))
    except RegistryError as exc:
        assert "duplicate migration id" in str(exc)
    else:
        raise AssertionError("duplicate migration was accepted")
    try:
        MigrationContract.from_dict({**contract.to_dict(), "operations": [{"kind": "python", "target": "state/x"}]})
    except MigrationError as exc:
        assert "unsupported" in str(exc)
    else:
        raise AssertionError("arbitrary operation was accepted")
    try:
        MigrationContract(
            migration_id="stateport.fixture.invalid",
            from_version="1",
            to_version="2",
            read_paths=(),
            write_paths=("state/settings.txt",),
            owned_paths=(OwnedPath("state/settings.txt"),),
            operations=(MigrationOperation(OperationKind.REPLACE_TEXT, target="state/settings.txt", old="a", new="b"),),
        )
    except MigrationError as exc:
        assert "read path" in str(exc)
    else:
        raise AssertionError("invalid delete contract was accepted")


def test_apply_uses_owned_paths_receipt_last_and_is_idempotent() -> None:
    with tempfile.TemporaryDirectory(prefix="stateport-migration-") as raw:
        root = Path(raw)
        (root / "state").mkdir()
        (root / "state/settings.txt").write_text("legacy\n", encoding="utf-8")
        contract = _contract()
        registry = MigrationRegistry.from_contracts([contract])
        first = apply_migration(root, contract.migration_id, registry=registry, applied_at="2026-01-01T00:00:00+00:00")
        assert first["status"] == "applied"
        assert first.idempotent is False
        assert (root / "state/preferences.txt").read_text(encoding="utf-8") == "legacy\n"
        assert not (root / "state/settings.txt").exists()
        receipt = root / ".stateport/migrations/receipts/stateport.fixture.rename.json"
        assert json.loads(receipt.read_text(encoding="utf-8"))["contractDigest"] == contract.digest
        second = apply_migration(root, contract.migration_id, registry=registry)
        assert second.idempotent is True
        assert second["toVersion"] == "1.1.0"


def test_receipt_write_failure_rolls_back_after_operations() -> None:
    import lifecycle_migrations.executor as executor

    with tempfile.TemporaryDirectory(prefix="stateport-migration-receipt-") as raw:
        root = Path(raw)
        (root / "state").mkdir()
        (root / "state/settings.txt").write_text("legacy\n", encoding="utf-8")
        contract = _contract(migration_id="stateport.fixture.receipt-failure")
        original = executor._write_receipt
        executor._write_receipt = lambda path, value: (_ for _ in ()).throw(OSError("disk full"))
        try:
            try:
                apply_migration(root, contract)
            except OSError as exc:
                assert "disk full" in str(exc)
            else:
                raise AssertionError("receipt write failure was swallowed")
        finally:
            executor._write_receipt = original
        assert (root / "state/settings.txt").read_text(encoding="utf-8") == "legacy\n"
        assert not (root / "state/preferences.txt").exists()
        assert not (root / ".stateport/migrations/receipts/stateport.fixture.receipt-failure.json").exists()


def test_failure_rolls_back_all_owned_files_and_writes_no_receipt() -> None:
    with tempfile.TemporaryDirectory(prefix="stateport-migration-rollback-") as raw:
        root = Path(raw)
        (root / "state").mkdir()
        (root / "state/a.txt").write_text("a\n", encoding="utf-8")
        (root / "state/b.txt").write_text("b\n", encoding="utf-8")
        contract = _contract(
            migration_id="stateport.fixture.rollback",
            operations=(
                MigrationOperation(OperationKind.MOVE, source="state/a.txt", target="state/c.txt"),
                MigrationOperation(OperationKind.REPLACE_TEXT, target="state/b.txt", old="missing", new="never"),
            ),
            reads={"state/a.txt", "state/b.txt"},
            writes={"state/a.txt", "state/b.txt", "state/c.txt"},
            owned={"state/a.txt", "state/b.txt", "state/c.txt"},
        )
        try:
            apply_migration(root, contract)
        except MigrationError as exc:
            assert "exactly one" in str(exc)
        else:
            raise AssertionError("failed migration was accepted")
        assert (root / "state/a.txt").read_text(encoding="utf-8") == "a\n"
        assert (root / "state/b.txt").read_text(encoding="utf-8") == "b\n"
        assert not (root / "state/c.txt").exists()
        assert not (root / ".stateport/migrations/receipts/stateport.fixture.rollback.json").exists()


def test_paths_and_symlinks_are_rejected_before_mutation() -> None:
    with tempfile.TemporaryDirectory(prefix="stateport-migration-safety-") as raw:
        root = Path(raw)
        (root / "state").mkdir()
        (root / "outside.txt").write_text("secret\n", encoding="utf-8")
        (root / "state/link.txt").symlink_to(root / "outside.txt")
        try:
            contract = _contract(
                operations=(MigrationOperation(OperationKind.MOVE, source="state/link.txt", target="state/new.txt"),),
                reads={"state/link.txt"},
                writes={"state/new.txt"},
                owned={"state/link.txt", "state/new.txt"},
            )
            apply_migration(root, contract)
        except MigrationError as exc:
            assert "symlink" in str(exc)
        else:
            raise AssertionError("symlinked source was accepted")
        assert (root / "outside.txt").read_text(encoding="utf-8") == "secret\n"
        try:
            MigrationContract.from_dict({**_contract().to_dict(), "writePaths": [".statedd/lock.yaml"]})
        except MigrationError as exc:
            assert "reserved" in str(exc)
        else:
            raise AssertionError("reserved control path was accepted")


def test_migration_expected_hash_binds_source_before_any_write() -> None:
    with tempfile.TemporaryDirectory(prefix="stateport-migration-stale-") as raw:
        root = Path(raw)
        (root / "state").mkdir()
        source = root / "state/settings.txt"
        source.write_text("unexpected\n", encoding="utf-8")
        expected = "sha256:" + hashlib.sha256(b"legacy\n").hexdigest()
        contract = _contract(
            migration_id="stateport.fixture.stale-source",
            operations=(
                MigrationOperation(
                    OperationKind.MOVE,
                    source="state/settings.txt",
                    target="state/preferences.txt",
                    expected_hash=expected,
                ),
            ),
        )
        try:
            apply_migration(root, contract)
        except MigrationError as exc:
            assert "expected hash" in str(exc)
        else:
            raise AssertionError("stale migration source was accepted")
        assert source.read_text(encoding="utf-8") == "unexpected\n"
        assert not (root / "state/preferences.txt").exists()


def main() -> int:
    tests = [value for name, value in globals().items() if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
    print(f"{len(tests)} lifecycle migration tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
