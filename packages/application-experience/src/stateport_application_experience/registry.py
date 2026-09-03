"""Load reviewed application-experience descriptors from the StatePort tree."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

import yaml

from .contracts import ApplicationExperienceDescriptor, ExperienceContractError
from .resolver import resolve_experience


def load_experience_descriptors(repo_root: Path) -> tuple[ApplicationExperienceDescriptor, ...]:
    root = repo_root.resolve() / "fixtures" / "application-experiences"
    descriptors: list[ApplicationExperienceDescriptor] = []
    if not root.is_dir() or root.is_symlink():
        raise ExperienceContractError("trusted application-experience registry is unavailable")
    for path in sorted(root.glob("*.yaml")):
        if path.is_symlink() or path.parent.resolve() != root:
            raise ExperienceContractError("application-experience descriptor path is unsafe")
        try:
            value = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
            raise ExperienceContractError(f"could not parse trusted experience descriptor: {path.name}") from exc
        descriptors.append(ApplicationExperienceDescriptor.from_mapping(value))
    ids = [item.application_id for item in descriptors]
    aliases = [alias for item in descriptors for alias in item.legacy_aliases]
    if not descriptors or len(ids) != len(set(ids)) or set(ids) & set(aliases) or len(aliases) != len(set(aliases)):
        raise ExperienceContractError("application-experience registry identities are ambiguous")
    return tuple(descriptors)


class ExperienceRegistry:
    def __init__(self, repo_root: Path):
        self._descriptors = load_experience_descriptors(repo_root)
        self._by_identity: dict[str, ApplicationExperienceDescriptor] = {}
        for descriptor in self._descriptors:
            self._by_identity[descriptor.application_id] = descriptor
            for alias in descriptor.legacy_aliases:
                self._by_identity[alias] = descriptor

    def list(self) -> list[dict[str, Any]]:
        return [item.to_dict() for item in self._descriptors]

    def get(self, application_id: str) -> ApplicationExperienceDescriptor | None:
        return self._by_identity.get(application_id)

    def resolve(
        self,
        application_id: str,
        *,
        instance_grants: set[str] | frozenset[str],
        operator_permits: set[str] | frozenset[str],
        runtime_capabilities: Mapping[str, str | Mapping[str, str]],
        actor_permissions: set[str] | frozenset[str],
    ) -> dict[str, Any] | None:
        descriptor = self.get(application_id)
        if descriptor is None:
            return None
        return resolve_experience(
            descriptor,
            instance_grants=instance_grants,
            operator_permits=operator_permits,
            runtime_capabilities=runtime_capabilities,
            actor_permissions=actor_permissions,
        )
