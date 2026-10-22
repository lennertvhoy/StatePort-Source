"""StatePort-owned policy inputs for application-experience resolution."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any, Mapping

import yaml

from .contracts import ApplicationCapability, ExperienceContractError


_APPLICATION_ID = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$")
_PERMISSION = re.compile(r"^[a-z][a-z0-9._-]{1,127}$")
_RUNTIME_STATES = frozenset({"available", "degraded", "environment_gated", "unavailable"})


def _capabilities(value: object, label: str) -> frozenset[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ExperienceContractError(f"{label} must be an array of capabilities")
    known = {item.value for item in ApplicationCapability}
    unknown = sorted(set(value) - known)
    if unknown or len(value) != len(set(value)):
        raise ExperienceContractError(f"{label} contains unknown or duplicate capabilities")
    return frozenset(value)


@dataclass(frozen=True)
class ApplicationExperiencePolicy:
    operator_permits: frozenset[str]
    application_grants: Mapping[str, frozenset[str]]
    runtime_capabilities: Mapping[str, Mapping[str, str]]
    actor_permissions: Mapping[str, frozenset[str]]

    def grants_for(self, application_id: str) -> frozenset[str]:
        return self.application_grants.get(application_id, frozenset())

    def permissions_for(self, actor_role: str) -> frozenset[str]:
        return self.actor_permissions.get(actor_role, frozenset())


def load_experience_policy(path: Path) -> ApplicationExperiencePolicy:
    if path.is_symlink() or not path.is_file():
        raise ExperienceContractError("application-experience policy is unavailable")
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ExperienceContractError("application-experience policy could not be parsed") from exc
    if not isinstance(value, dict):
        raise ExperienceContractError("application-experience policy must be an object")
    required = {"formatVersion", "operatorPermits", "applicationGrants", "runtimeCapabilities", "actorPermissions"}
    if set(value) != required or value["formatVersion"] != "stateport.application-experience-policy/v1":
        raise ExperienceContractError("application-experience policy shape or format is unsupported")
    operator_permits = _capabilities(value["operatorPermits"], "operator permits")
    grants_source = value["applicationGrants"]
    if not isinstance(grants_source, dict):
        raise ExperienceContractError("application grants must be an object")
    grants: dict[str, frozenset[str]] = {}
    for application_id, capabilities in grants_source.items():
        if not isinstance(application_id, str) or not _APPLICATION_ID.fullmatch(application_id):
            raise ExperienceContractError("application grant identity is unsafe")
        grants[application_id] = _capabilities(capabilities, f"application grants for {application_id}")

    runtime_source = value["runtimeCapabilities"]
    if not isinstance(runtime_source, dict) or set(runtime_source) != {item.value for item in ApplicationCapability}:
        raise ExperienceContractError("runtime policy must classify every known application capability exactly once")
    runtime: dict[str, Mapping[str, str]] = {}
    for capability, status_value in runtime_source.items():
        if not isinstance(status_value, dict) or set(status_value) - {"status", "reason"} or "status" not in status_value:
            raise ExperienceContractError(f"runtime capability {capability} has an invalid status object")
        if status_value["status"] not in _RUNTIME_STATES:
            raise ExperienceContractError(f"runtime capability {capability} has an invalid status")
        reason = status_value.get("reason")
        if reason is not None and (not isinstance(reason, str) or not _APPLICATION_ID.fullmatch(reason)):
            raise ExperienceContractError(f"runtime capability {capability} has an unsafe reason")
        if status_value["status"] != "available" and not reason:
            raise ExperienceContractError(f"runtime capability {capability} requires a bounded reason")
        runtime[capability] = dict(status_value)

    permissions_source = value["actorPermissions"]
    if not isinstance(permissions_source, dict):
        raise ExperienceContractError("actor permissions must be an object")
    actor_permissions: dict[str, frozenset[str]] = {}
    for role, permissions in permissions_source.items():
        if not isinstance(role, str) or not _APPLICATION_ID.fullmatch(role) or not isinstance(permissions, list):
            raise ExperienceContractError("actor permission role is invalid")
        if any(not isinstance(item, str) or not _PERMISSION.fullmatch(item) for item in permissions) or len(permissions) != len(set(permissions)):
            raise ExperienceContractError(f"actor permissions for {role} are invalid")
        actor_permissions[role] = frozenset(permissions)
    return ApplicationExperiencePolicy(operator_permits, grants, runtime, actor_permissions)
