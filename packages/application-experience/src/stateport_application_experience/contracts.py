"""Strict v1 contracts for trusted, capability-driven application UI."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import re
from typing import Any, Mapping


APPLICATION_EXPERIENCE_FORMAT = "stateport.application-experience/v1"
_ID = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$")
_ROUTE = re.compile(r"^/(?:application|conversation|advanced|workbench)(?:/[a-z0-9][a-z0-9._-]{0,126})?$")
_PERMISSION = re.compile(r"^[a-z][a-z0-9._-]{1,127}$")


class ExperienceContractError(ValueError):
    """Raised when an untrusted package descriptor crosses the UI boundary."""


class ApplicationCapability(str, Enum):
    CONVERSATION = "conversation"
    PROGRESS_DASHBOARD = "progress_dashboard"
    GOAL_EXECUTION = "goal_execution"
    PROACTIVE_NOTIFICATIONS = "proactive_notifications"
    FILE_VIEWER = "file_viewer"
    WORKBENCH = "workbench"
    TERMINAL = "terminal"
    EDITOR = "editor"
    CTO_ORCHESTRATION = "cto_orchestration"
    BENCHMARK_EVIDENCE = "benchmark_evidence"
    BACKUP = "backup"
    CALENDAR = "calendar"
    WEB_RESEARCH = "web_research"


# Packages refer only to these StatePort-owned renderers.  The list is kept
# deliberately small; extending it requires StatePort code and review.
TRUSTED_COMPONENTS = frozenset(
    {
        "activity_history",
        "application_home",
        "backup_manager",
        "benchmark_evidence",
        "context_summary",
        "conversation_thread",
        "cost_summary",
        "cto_orchestration",
        "development_workbench",
        "editor_surface",
        "file_viewer",
        "goal_actions",
        "notification_feed",
        "permission_summary",
        "progress_overview",
        "receipt_list",
        "run_history",
        "state_summary",
        "terminal_surface",
        "update_manager",
    }
)


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ExperienceContractError(f"{label} must be an object")
    return value


def _strict_keys(value: Mapping[str, Any], label: str, required: set[str], optional: set[str] | None = None) -> None:
    optional = optional or set()
    missing = sorted(required - set(value))
    unknown = sorted(set(value) - required - optional)
    if missing:
        raise ExperienceContractError(f"{label} is missing: {', '.join(missing)}")
    if unknown:
        raise ExperienceContractError(f"{label} contains unknown fields: {', '.join(unknown)}")


def _text(value: object, label: str, *, maximum: int = 240) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ExperienceContractError(f"{label} must be a non-empty string of at most {maximum} characters")
    if any(ord(char) < 32 for char in value):
        raise ExperienceContractError(f"{label} contains control characters")
    lowered = value.lower()
    unsafe_scheme = re.search(r"(?:^|[\s\"'=(])(?:javascript|vbscript|data|https?):", lowered)
    if "<" in value or ">" in value or unsafe_scheme or "url(" in lowered or "@import" in lowered:
        raise ExperienceContractError(f"{label} contains unsafe markup or URL content")
    return value


def _identifier(value: object, label: str) -> str:
    text = _text(value, label, maximum=128)
    if not _ID.fullmatch(text):
        raise ExperienceContractError(f"{label} is not a safe identifier")
    return text


def _capability(value: object, label: str) -> ApplicationCapability:
    try:
        return ApplicationCapability(value)
    except (TypeError, ValueError) as exc:
        raise ExperienceContractError(f"{label} is not a supported application capability") from exc


def _component(value: object, label: str) -> str:
    component = _text(value, label, maximum=64)
    if component not in TRUSTED_COMPONENTS:
        raise ExperienceContractError(f"{label} is not a trusted StatePort component")
    return component


def _route(value: object, label: str) -> str:
    route = _text(value, label, maximum=160)
    if not _ROUTE.fullmatch(route) or ".." in route or "//" in route:
        raise ExperienceContractError(f"{label} is not a safe application-relative route")
    return route


def _sequence(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise ExperienceContractError(f"{label} must be an array")
    return value


@dataclass(frozen=True)
class ApplicationView:
    view_id: str
    label: str
    component: str
    route: str
    capability: ApplicationCapability

    @classmethod
    def from_mapping(cls, source: object) -> "ApplicationView":
        value = _mapping(source, "application view")
        _strict_keys(value, "application view", {"viewId", "label", "component", "route", "capability"})
        return cls(
            view_id=_identifier(value["viewId"], "application view id"),
            label=_text(value["label"], "application view label", maximum=80),
            component=_component(value["component"], "application view component"),
            route=_route(value["route"], "application view route"),
            capability=_capability(value["capability"], "application view capability"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {"viewId": self.view_id, "label": self.label, "component": self.component, "route": self.route, "capability": self.capability.value}


@dataclass(frozen=True)
class NavigationContribution:
    contribution_id: str
    label: str
    view_id: str
    placement: str
    order: int

    @classmethod
    def from_mapping(cls, source: object) -> "NavigationContribution":
        value = _mapping(source, "navigation contribution")
        _strict_keys(value, "navigation contribution", {"contributionId", "label", "viewId", "placement", "order"})
        placement = value["placement"]
        if placement not in {"application", "conversation", "advanced"}:
            raise ExperienceContractError("navigation placement is unsupported")
        order = value["order"]
        if isinstance(order, bool) or not isinstance(order, int) or not 0 <= order <= 1000:
            raise ExperienceContractError("navigation order must be an integer from 0 through 1000")
        return cls(
            contribution_id=_identifier(value["contributionId"], "navigation contribution id"),
            label=_text(value["label"], "navigation label", maximum=80),
            view_id=_identifier(value["viewId"], "navigation view id"),
            placement=placement,
            order=order,
        )

    def to_dict(self) -> dict[str, Any]:
        return {"contributionId": self.contribution_id, "label": self.label, "viewId": self.view_id, "placement": self.placement, "order": self.order}


@dataclass(frozen=True)
class ConversationPresentation:
    enabled: bool
    mode: str
    component: str
    title: str
    empty_state: str

    @classmethod
    def from_mapping(cls, source: object) -> "ConversationPresentation":
        value = _mapping(source, "conversation presentation")
        _strict_keys(value, "conversation presentation", {"enabled", "mode", "component", "title", "emptyState"})
        if not isinstance(value["enabled"], bool):
            raise ExperienceContractError("conversation enabled must be boolean")
        if value["mode"] != "application_attached":
            raise ExperienceContractError("conversation mode must be application_attached")
        return cls(
            enabled=value["enabled"],
            mode="application_attached",
            component=_component(value["component"], "conversation component"),
            title=_text(value["title"], "conversation title", maximum=80),
            empty_state=_text(value["emptyState"], "conversation empty state", maximum=240),
        )

    def to_dict(self) -> dict[str, Any]:
        return {"enabled": self.enabled, "mode": self.mode, "component": self.component, "title": self.title, "emptyState": self.empty_state}


@dataclass(frozen=True)
class AdvancedControlContribution:
    control_id: str
    label: str
    component: str
    capability: ApplicationCapability
    order: int

    @classmethod
    def from_mapping(cls, source: object) -> "AdvancedControlContribution":
        value = _mapping(source, "advanced control contribution")
        _strict_keys(value, "advanced control contribution", {"controlId", "label", "component", "capability", "order"})
        order = value["order"]
        if isinstance(order, bool) or not isinstance(order, int) or not 0 <= order <= 1000:
            raise ExperienceContractError("advanced control order must be an integer from 0 through 1000")
        return cls(
            control_id=_identifier(value["controlId"], "advanced control id"),
            label=_text(value["label"], "advanced control label", maximum=80),
            component=_component(value["component"], "advanced control component"),
            capability=_capability(value["capability"], "advanced control capability"),
            order=order,
        )

    def to_dict(self) -> dict[str, Any]:
        return {"controlId": self.control_id, "label": self.label, "component": self.component, "capability": self.capability.value, "order": self.order}


@dataclass(frozen=True)
class PlatformOperationPermission:
    operation_id: str
    label: str
    component: str
    capability: ApplicationCapability
    required_actor_permissions: tuple[str, ...]

    @classmethod
    def from_mapping(cls, source: object) -> "PlatformOperationPermission":
        value = _mapping(source, "platform operation permission")
        _strict_keys(value, "platform operation permission", {"operationId", "label", "component", "capability", "requiredActorPermissions"})
        permissions: list[str] = []
        for item in _sequence(value["requiredActorPermissions"], "required actor permissions"):
            permission = _text(item, "actor permission", maximum=128)
            if not _PERMISSION.fullmatch(permission):
                raise ExperienceContractError("actor permission is not a safe permission identifier")
            permissions.append(permission)
        if not permissions or len(set(permissions)) != len(permissions):
            raise ExperienceContractError("platform operation permissions must be non-empty and unique")
        return cls(
            operation_id=_identifier(value["operationId"], "platform operation id"),
            label=_text(value["label"], "platform operation label", maximum=80),
            component=_component(value["component"], "platform operation component"),
            capability=_capability(value["capability"], "platform operation capability"),
            required_actor_permissions=tuple(permissions),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "operationId": self.operation_id,
            "label": self.label,
            "component": self.component,
            "capability": self.capability.value,
            "requiredActorPermissions": list(self.required_actor_permissions),
        }


@dataclass(frozen=True)
class ApplicationExperienceDescriptor:
    application_id: str
    display_name: str
    description: str
    capabilities: tuple[ApplicationCapability, ...]
    views: tuple[ApplicationView, ...]
    navigation: tuple[NavigationContribution, ...]
    conversation: ConversationPresentation
    advanced_controls: tuple[AdvancedControlContribution, ...]
    platform_operations: tuple[PlatformOperationPermission, ...]
    legacy_aliases: tuple[str, ...]

    @classmethod
    def from_mapping(cls, source: object) -> "ApplicationExperienceDescriptor":
        value = _mapping(source, "application experience descriptor")
        required = {
            "formatVersion",
            "applicationId",
            "displayName",
            "description",
            "capabilities",
            "views",
            "navigation",
            "conversation",
            "advancedControls",
            "platformOperations",
            "legacyAliases",
        }
        _strict_keys(value, "application experience descriptor", required)
        if value["formatVersion"] != APPLICATION_EXPERIENCE_FORMAT:
            raise ExperienceContractError("unsupported application experience format")

        capabilities = tuple(_capability(item, "application capability") for item in _sequence(value["capabilities"], "application capabilities"))
        if not capabilities or len(set(capabilities)) != len(capabilities):
            raise ExperienceContractError("application capabilities must be non-empty and unique")
        views = tuple(ApplicationView.from_mapping(item) for item in _sequence(value["views"], "application views"))
        navigation = tuple(NavigationContribution.from_mapping(item) for item in _sequence(value["navigation"], "navigation contributions"))
        conversation = ConversationPresentation.from_mapping(value["conversation"])
        advanced = tuple(AdvancedControlContribution.from_mapping(item) for item in _sequence(value["advancedControls"], "advanced controls"))
        platform = tuple(PlatformOperationPermission.from_mapping(item) for item in _sequence(value["platformOperations"], "platform operations"))
        aliases = tuple(_identifier(item, "legacy alias") for item in _sequence(value["legacyAliases"], "legacy aliases"))

        capability_set = set(capabilities)
        if conversation.enabled and ApplicationCapability.CONVERSATION not in capability_set:
            raise ExperienceContractError("enabled conversation must request the conversation capability")
        if any(item.capability not in capability_set for item in (*views, *advanced, *platform)):
            raise ExperienceContractError("views and contributions may reference only requested capabilities")
        view_ids = [item.view_id for item in views]
        if not view_ids or len(set(view_ids)) != len(view_ids):
            raise ExperienceContractError("application view ids must be non-empty and unique")
        if any(item.view_id not in set(view_ids) for item in navigation):
            raise ExperienceContractError("navigation must reference a declared application view")
        for label, identifiers in (
            ("navigation contribution", [item.contribution_id for item in navigation]),
            ("advanced control", [item.control_id for item in advanced]),
            ("platform operation", [item.operation_id for item in platform]),
        ):
            if len(set(identifiers)) != len(identifiers):
                raise ExperienceContractError(f"{label} ids must be unique")
        if len(set(aliases)) != len(aliases):
            raise ExperienceContractError("legacy aliases must be unique")

        return cls(
            application_id=_identifier(value["applicationId"], "application id"),
            display_name=_text(value["displayName"], "application display name", maximum=80),
            description=_text(value["description"], "application description", maximum=240),
            capabilities=capabilities,
            views=views,
            navigation=navigation,
            conversation=conversation,
            advanced_controls=advanced,
            platform_operations=platform,
            legacy_aliases=aliases,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": APPLICATION_EXPERIENCE_FORMAT,
            "applicationId": self.application_id,
            "displayName": self.display_name,
            "description": self.description,
            "capabilities": [item.value for item in self.capabilities],
            "views": [item.to_dict() for item in self.views],
            "navigation": [item.to_dict() for item in self.navigation],
            "conversation": self.conversation.to_dict(),
            "advancedControls": [item.to_dict() for item in self.advanced_controls],
            "platformOperations": [item.to_dict() for item in self.platform_operations],
            "legacyAliases": list(self.legacy_aliases),
        }

    def descriptor_digest(self) -> str:
        canonical = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return "sha256:" + hashlib.sha256(canonical).hexdigest()

    def identity(self) -> dict[str, str]:
        return {"applicationId": self.application_id, "formatVersion": APPLICATION_EXPERIENCE_FORMAT, "descriptorDigest": self.descriptor_digest()}
