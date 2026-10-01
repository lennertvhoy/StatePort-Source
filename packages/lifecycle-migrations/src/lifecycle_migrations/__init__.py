"""Typed, declarative StatePort-owned instance migrations.

This package intentionally has no extension point for Python callbacks, shell
commands, or template-provided code.  A migration is a validated data
contract and the executor implements the small set of file operations itself.
"""

from .contract import (
    CONTRACT_FORMAT,
    REGISTRY_FORMAT,
    RECEIPT_FORMAT,
    MigrationContract,
    MigrationError,
    MigrationOperation,
    OperationKind,
    OwnedPath,
    PathOwner,
)
from .executor import ApplyResult, MigrationExecutor, apply_migration
from .registry import MigrationRegistry, RegistryError

__all__ = [
    "ApplyResult",
    "CONTRACT_FORMAT",
    "MigrationContract",
    "MigrationError",
    "MigrationExecutor",
    "MigrationOperation",
    "MigrationRegistry",
    "OperationKind",
    "OwnedPath",
    "PathOwner",
    "RECEIPT_FORMAT",
    "REGISTRY_FORMAT",
    "RegistryError",
    "apply_migration",
]
