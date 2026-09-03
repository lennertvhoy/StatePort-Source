"""Explicit local identity and instance-scope contracts.

This is an authorization input, not an authentication system.  The loopback
adapter has no trusted identity provider; callers must configure the local
identity directory and transport authentication separately before exposure.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class Identity:
    id: str
    roles: frozenset[str]
    instances: frozenset[str]

    @classmethod
    def from_value(cls, identity_id: str, value: Any) -> "Identity":
        if isinstance(value, Identity):
            return value
        if not isinstance(identity_id, str) or not identity_id.strip():
            raise ValueError("identity id must be a non-empty string")
        if not isinstance(value, Mapping):
            raise ValueError("identity configuration must be a mapping")
        roles = value.get("roles", ())
        instances = value.get("instances", value.get("instanceIds", ()))
        if not isinstance(roles, (list, tuple, set, frozenset)) or not all(
            isinstance(item, str) and item.strip() for item in roles
        ):
            raise ValueError("identity roles must be a collection of strings")
        if not isinstance(instances, (list, tuple, set, frozenset)) or not all(
            isinstance(item, str) and item.strip() for item in instances
        ):
            raise ValueError("identity instances must be a collection of strings")
        return cls(identity_id.strip(), frozenset(item.strip() for item in roles), frozenset(item.strip() for item in instances))

    def can_access(self, instance_id: str) -> bool:
        return "*" in self.instances or instance_id in self.instances

    def is_approver(self) -> bool:
        return bool(self.roles & {"approver", "operator", "admin"})

    def is_operator(self) -> bool:
        return bool(self.roles & {"operator", "admin"})

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "roles": sorted(self.roles),
            "instances": sorted(self.instances),
        }


class IdentityDirectory:
    def __init__(self, identities: Mapping[str, Any] | None = None):
        self._identities: dict[str, Identity] = {}
        for identity_id, value in (identities or {}).items():
            identity = Identity.from_value(identity_id, value)
            self._identities[identity.id] = identity

    def get(self, identity_id: Any) -> Identity | None:
        if not isinstance(identity_id, str):
            return None
        return self._identities.get(identity_id.strip())

    def all(self) -> tuple[Identity, ...]:
        return tuple(self._identities[key] for key in sorted(self._identities))
