"""Capability intersection with no implicit grants."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from typing import Any


def _capability_set(value: Any, name: str) -> tuple[set[str], str | None]:
    if not isinstance(value, (list, tuple, set, frozenset)):
        return set(), f"{name} must be a collection of capability strings"
    result: set[str] = set()
    for item in value:
        if not isinstance(item, str) or not item.strip():
            return set(), f"{name} contains an invalid capability"
        result.add(item.strip())
    return result, None


def parse_capabilities(value: Any, name: str = "capabilities") -> tuple[frozenset[str], str | None]:
    """Parse a capability collection without ever treating malformed input as a grant."""

    items, error = _capability_set(value, name)
    return frozenset(items), error


@dataclass(frozen=True)
class CapabilityIntersection:
    """The effective capability set and the inputs used to derive it."""

    template_requested: list[str]
    instance_granted: list[str]
    operator_allowed: list[str]
    effective: list[str]
    denied: list[str]
    valid: bool
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def intersect_capabilities(
    template_requested: Any,
    instance_granted: Any,
    operator_allowed: Any,
) -> CapabilityIntersection:
    """Compute ``template ∩ instance ∩ operator`` deterministically.

    Any malformed or missing policy input produces an empty effective set.
    Template requests never grant a capability by themselves.
    """

    raw_values = (
        (template_requested, "template_requested"),
        (instance_granted, "instance_granted"),
        (operator_allowed, "operator_allowed"),
    )
    parsed: list[set[str]] = []
    errors: list[str] = []
    for value, name in raw_values:
        items, error = _capability_set(value, name)
        parsed.append(items)
        if error:
            errors.append(error)
    requested, granted, allowed = parsed
    effective = requested & granted & allowed if not errors else set()
    denied = requested - effective
    reason = "; ".join(errors) if errors else "effective capabilities are the policy intersection"
    return CapabilityIntersection(
        template_requested=sorted(requested),
        instance_granted=sorted(granted),
        operator_allowed=sorted(allowed),
        effective=sorted(effective),
        denied=sorted(denied),
        valid=not errors,
        reason=reason,
    )


def effective_capabilities(
    template_requested: Any,
    instance_granted: Any,
    operator_allowed: Any,
) -> list[str]:
    """Return only the effective sorted capabilities."""

    return intersect_capabilities(
        template_requested,
        instance_granted,
        operator_allowed,
    ).effective
