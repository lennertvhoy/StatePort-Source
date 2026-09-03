"""Validated in-process registry for StatePort-owned migrations."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .contract import CONTRACT_FORMAT, REGISTRY_FORMAT, MigrationContract, MigrationError


class RegistryError(MigrationError):
    """Raised when a registry is duplicate, ambiguous, or malformed."""


@dataclass(frozen=True)
class MigrationRegistry:
    """An immutable, deterministically ordered migration registry."""

    migrations: tuple[MigrationContract, ...] = ()

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        ids: set[str] = set()
        edges: set[tuple[str, str]] = set()
        for migration in self.migrations:
            if not isinstance(migration, MigrationContract):
                raise RegistryError("registry entries must be MigrationContract values")
            if migration.migration_id in ids:
                raise RegistryError(f"duplicate migration id: {migration.migration_id}")
            ids.add(migration.migration_id)
            edge = (migration.from_version, migration.to_version)
            if edge in edges:
                raise RegistryError(f"duplicate migration edge: {edge[0]} -> {edge[1]}")
            edges.add(edge)
        ordered = tuple(sorted(self.migrations, key=lambda item: item.migration_id))
        if ordered != self.migrations:
            raise RegistryError("registry entries must be sorted by migration id")

    @classmethod
    def from_contracts(cls, contracts: Iterable[MigrationContract]) -> "MigrationRegistry":
        return cls(tuple(sorted(tuple(contracts), key=lambda item: item.migration_id)))

    @classmethod
    def from_dict(cls, value: Any) -> "MigrationRegistry":
        if not isinstance(value, Mapping):
            raise RegistryError("registry must be a mapping")
        if set(value) - {"formatVersion", "owner", "migrations", "registryDigest"}:
            unknown = set(value) - {"formatVersion", "owner", "migrations", "registryDigest"}
            raise RegistryError(f"registry contains unknown fields: {sorted(unknown)}")
        if value.get("formatVersion") != REGISTRY_FORMAT or value.get("owner") != "stateport":
            raise RegistryError("registry must be StatePort-owned and use the migration format")
        raw = value.get("migrations")
        if not isinstance(raw, list):
            raise RegistryError("registry.migrations must be a list")
        registry = cls.from_contracts(MigrationContract.from_dict(item) for item in raw)
        supplied = value.get("registryDigest")
        if supplied is not None and supplied != registry.digest:
            raise RegistryError("registryDigest does not match canonical registry")
        return registry

    @property
    def digest(self) -> str:
        payload = self.to_dict(include_digest=False)
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        return "sha256:" + hashlib.sha256(encoded).hexdigest()

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        value: dict[str, Any] = {
            "formatVersion": REGISTRY_FORMAT,
            "owner": "stateport",
            "migrations": [item.to_dict() for item in self.migrations],
        }
        if include_digest:
            value["registryDigest"] = self.digest
        return value

    def get(self, migration_id: str) -> MigrationContract:
        for migration in self.migrations:
            if migration.migration_id == migration_id:
                return migration
        raise RegistryError(f"migration is not registered: {migration_id}")

    def path(self, from_version: str, to_version: str) -> tuple[MigrationContract, ...]:
        """Return one deterministic shortest migration path, if available."""

        if from_version == to_version:
            return ()
        frontier: list[tuple[str, tuple[MigrationContract, ...]]] = [(from_version, ())]
        visited = {from_version}
        while frontier:
            version, route = frontier.pop(0)
            next_edges = [item for item in self.migrations if item.from_version == version]
            for migration in next_edges:
                candidate = route + (migration,)
                if migration.to_version == to_version:
                    return candidate
                if migration.to_version not in visited:
                    visited.add(migration.to_version)
                    frontier.append((migration.to_version, candidate))
        raise RegistryError(f"no migration path from {from_version} to {to_version}")
