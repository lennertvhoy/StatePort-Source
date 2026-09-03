"""Most-restrictive effective application-experience calculation."""

from __future__ import annotations

from typing import Any, Mapping

from .contracts import ApplicationCapability, ApplicationExperienceDescriptor, ExperienceContractError


_RUNTIME_STATES = frozenset({"available", "degraded", "environment_gated", "unavailable"})


def _known_capabilities(values: set[str] | frozenset[str], label: str) -> set[str]:
    known = {item.value for item in ApplicationCapability}
    unknown = sorted(set(values) - known)
    if unknown:
        raise ExperienceContractError(f"{label} contains unknown capabilities: {', '.join(unknown)}")
    return set(values)


def resolve_experience(
    descriptor: ApplicationExperienceDescriptor,
    *,
    instance_grants: set[str] | frozenset[str],
    operator_permits: set[str] | frozenset[str],
    runtime_capabilities: Mapping[str, str | Mapping[str, str]],
    actor_permissions: set[str] | frozenset[str],
) -> dict[str, Any]:
    """Resolve an experience without allowing the descriptor to self-authorize.

    A requested capability is effective only when the independently supplied
    instance grant, operator policy, and runtime feature all permit it.  A
    descriptor may request a platform operation but actor permissions remain
    a separate final gate.
    """

    grants = _known_capabilities(instance_grants, "instance grants")
    permits = _known_capabilities(operator_permits, "operator permits")
    requested = {item.value for item in descriptor.capabilities}
    unknown_runtime = sorted(set(runtime_capabilities) - {item.value for item in ApplicationCapability})
    if unknown_runtime:
        raise ExperienceContractError(f"runtime capabilities contain unknown entries: {', '.join(unknown_runtime)}")

    resolved: dict[str, dict[str, Any]] = {}
    for capability in descriptor.capabilities:
        name = capability.value
        reasons: list[str] = []
        if name not in grants:
            reasons.append("not_granted_by_instance")
        if name not in permits:
            reasons.append("denied_by_operator_policy")
        runtime = runtime_capabilities.get(name, "unavailable")
        if isinstance(runtime, Mapping):
            if set(runtime) - {"status", "reason"} or "status" not in runtime:
                raise ExperienceContractError(f"runtime capability {name} has an invalid status object")
            runtime_status = runtime["status"]
            runtime_reason = runtime.get("reason")
        else:
            runtime_status = runtime
            runtime_reason = None
        if runtime_status not in _RUNTIME_STATES:
            raise ExperienceContractError(f"runtime capability {name} has an unsupported status")
        if runtime_status != "available":
            reasons.append(str(runtime_reason or f"runtime_{runtime_status}"))
        status = "available"
        if "not_granted_by_instance" in reasons or "denied_by_operator_policy" in reasons:
            status = "denied"
        elif runtime_status == "unavailable":
            status = "unavailable"
        elif runtime_status == "environment_gated":
            status = "environment_gated"
        elif runtime_status == "degraded":
            status = "degraded"
        resolved[name] = {"id": name, "status": status, "reasons": reasons}

    def capability_status(name: str) -> dict[str, Any]:
        return resolved.get(name, {"id": name, "status": "unavailable", "reasons": ["not_requested_by_application"]})

    views = []
    for item in descriptor.views:
        resolution = capability_status(item.capability.value)
        views.append({**item.to_dict(), "status": resolution["status"], "reasons": list(resolution["reasons"]), "visible": resolution["status"] in {"available", "degraded"}})
    visible_views = {item["viewId"] for item in views if item["visible"]}
    navigation = [{**item.to_dict(), "visible": item.view_id in visible_views} for item in sorted(descriptor.navigation, key=lambda value: (value.order, value.contribution_id))]

    conversation_capability = capability_status(ApplicationCapability.CONVERSATION.value)
    conversation = {
        **descriptor.conversation.to_dict(),
        "enabled": descriptor.conversation.enabled and conversation_capability["status"] in {"available", "degraded"},
        "status": conversation_capability["status"],
        "reasons": list(conversation_capability["reasons"]),
    }
    advanced_controls = []
    for item in sorted(descriptor.advanced_controls, key=lambda value: (value.order, value.control_id)):
        resolution = capability_status(item.capability.value)
        advanced_controls.append({**item.to_dict(), "status": resolution["status"], "reasons": list(resolution["reasons"]), "visible": resolution["status"] in {"available", "degraded"}})

    platform_operations = []
    for item in descriptor.platform_operations:
        resolution = capability_status(item.capability.value)
        missing = sorted(set(item.required_actor_permissions) - set(actor_permissions))
        reasons = list(resolution["reasons"])
        if missing:
            reasons.extend(f"missing_actor_permission:{permission}" for permission in missing)
        status = resolution["status"] if not missing else "denied"
        platform_operations.append({**item.to_dict(), "status": status, "reasons": reasons, "visible": status in {"available", "degraded"}})

    return {
        "formatVersion": "stateport.application-experience-resolution/v1",
        "applicationId": descriptor.application_id,
        "descriptorIdentity": descriptor.identity(),
        "installProjection": {
            "formatVersion": "stateport.application-experience-install-projection/v1",
            "applicationId": descriptor.application_id,
            "descriptorDigest": descriptor.descriptor_digest(),
            "requestedCapabilities": sorted(requested),
            "grantsCapabilities": False,
        },
        "descriptor": descriptor.to_dict(),
        "capabilities": [resolved[name] for name in sorted(requested)],
        "views": views,
        "navigation": navigation,
        "conversation": conversation,
        "advancedControls": advanced_controls,
        "platformOperations": platform_operations,
        "actor": {"platformOperationsAllowed": any(item["status"] in {"available", "degraded"} for item in platform_operations)},
    }
