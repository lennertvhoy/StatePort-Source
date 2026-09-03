"""Typed, value-free contracts for the sensitive-data boundary."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


CONFIDENCE = frozenset(
    {"confirmed_sensitive", "high_confidence", "possible_sensitive", "user_allowlisted"}
)
ACTIONS = frozenset({"block", "redact", "review", "allow"})
DELIVERY_MODES = frozenset(
    {"brokered_capability", "restricted_process_injection", "development_environment_injection"}
)


def _required(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 512 or "\x00" in value:
        raise ValueError(f"{label} must be a non-empty bounded string")
    return value


@dataclass(frozen=True)
class SensitiveFinding:
    """Metadata about a finding. Matched and surrounding text are forbidden."""

    finding_id: str
    detector: str
    category: str
    confidence: str
    source_kind: str
    start: int
    end: int
    action: str
    scanner_version: str
    policy_id: str

    def __post_init__(self) -> None:
        for label in ("finding_id", "detector", "category", "source_kind", "scanner_version", "policy_id"):
            _required(getattr(self, label), label)
        if self.confidence not in CONFIDENCE:
            raise ValueError("unsupported finding confidence")
        if self.action not in ACTIONS:
            raise ValueError("unsupported finding action")
        if self.start < 0 or self.end <= self.start:
            raise ValueError("finding offsets are invalid")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SensitiveDataPolicy:
    policy_id: str = "policy.strict-local-v1"
    strict: bool = True
    possible_person_action: str = "review"
    email_action: str = "redact"

    def __post_init__(self) -> None:
        _required(self.policy_id, "policy_id")
        if self.possible_person_action not in {"review", "redact", "allow"}:
            raise ValueError("invalid possible-person action")
        if self.email_action not in {"review", "redact", "allow"}:
            raise ValueError("invalid email action")


@dataclass(frozen=True)
class RedactionDecision:
    sanitized_text: str
    findings: tuple[SensitiveFinding, ...]
    placeholders: tuple[str, ...]
    blocked: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "sanitizedText": self.sanitized_text,
            "findings": [item.to_dict() for item in self.findings],
            "placeholders": list(self.placeholders),
            "blocked": self.blocked,
        }


@dataclass(frozen=True)
class SanitizedContextReceipt:
    receipt_id: str
    boundary: str
    source_kinds: tuple[str, ...]
    input_digest: str
    output_digest: str | None
    finding_ids: tuple[str, ...]
    outcome: str
    scanner_version: str
    policy_id: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SecretRequirement:
    requirement_id: str
    display_name: str
    purpose: str
    expected_interface: str
    capability: str
    scope: str
    optional: bool = False
    approval_policy: str = "ask_every_time"
    preferred_delivery: str = "brokered_capability"

    def __post_init__(self) -> None:
        for label in (
            "requirement_id", "display_name", "purpose", "expected_interface", "capability", "scope",
        ):
            _required(getattr(self, label), label)
        if self.preferred_delivery not in DELIVERY_MODES:
            raise ValueError("unsupported secret delivery mode")
        if self.approval_policy != "ask_every_time":
            raise ValueError("the first slice supports ask-every-time approval only")


@dataclass(frozen=True)
class SecretMetadata:
    secret_id: str
    requirement_id: str
    display_name: str
    capability: str
    scope: str
    status: str
    created_at: str
    rotated_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SecretReference:
    reference_id: str
    secret_id: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CapabilityRequest:
    request_id: str
    reference_id: str
    run_id: str
    operation: str
    capability: str
    scope: str
    status: str
    requested_at: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SecretUseGrant:
    grant_id: str
    request_id: str
    reference_id: str
    run_id: str
    operation: str
    capability: str
    scope: str
    expires_at: str
    status: str = "available"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SecretUseReceipt:
    receipt_id: str
    grant_id: str
    request_id: str
    reference_id: str
    run_id: str
    operation: str
    capability: str
    scope: str
    outcome: str
    output_digest: str | None
    finding_ids: tuple[str, ...]
    completed_at: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
