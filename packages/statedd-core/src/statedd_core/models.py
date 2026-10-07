"""Canonical dataclasses for StateDD templates and instances."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


APPROVAL_POLICY_LEVELS = ("L2", "L3", "L4", "L5")
APPROVAL_POLICY_DECISIONS = frozenset({"require_explicit_approval"})


def _to_bool(value: Any) -> bool:
    """Coerce a YAML scalar to a boolean, recognising string forms.

    ``True``/``False`` are returned as-is, ``"true"``/``"false"`` (case
    insensitive) are parsed, ``None`` defaults to ``False``, and any other
    value falls back to Python truthiness.
    """
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
    return bool(value)


def _require_non_empty(value: Any, field_name: str) -> str:
    """Return ``value`` as a string, raising if it is missing or empty."""
    if not isinstance(value, str) or value.strip() == "":
        raise ValueError(f"{field_name} is required and must be a non-empty string")
    return value


def _require_int_or_none(value: Any, field_name: str) -> int | None:
    """Return ``value`` as an int or None, rejecting other types."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer or null")
    return value


@dataclass(frozen=True)
class TemplateMetadata:
    id: str
    name: str
    version: str
    description: str = ""


@dataclass(frozen=True)
class ActionDef:
    name: str
    level: str
    description: str = ""

    def __post_init__(self) -> None:
        _require_non_empty(self.name, "ActionDef.name")
        allowed_levels = {f"L{i}" for i in range(6)}
        if self.level not in allowed_levels:
            raise ValueError(
                f"ActionDef.level must be one of {sorted(allowed_levels)}, got {self.level!r}"
            )


@dataclass(frozen=True)
class Inbox:
    format: str
    allowed_extensions: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Quota:
    runs_per_day: int | None = None
    messages_per_day: int | None = None
    monthly_euro_estimate: int | None = None


@dataclass(frozen=True)
class AgentContract:
    role: str
    responsibilities: list[str] = field(default_factory=list)
    forbidden_actions: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class TemplateSpec:
    domain: str
    lifecycle: list[str]
    allowed_actions: list[ActionDef]
    schemas: list[str]
    agent_contract: AgentContract
    review_cadence: str = ""
    inbox: Inbox | None = None
    quotas: Quota | None = None


@dataclass(frozen=True)
class Template:
    api_version: str
    kind: str
    metadata: TemplateMetadata
    spec: TemplateSpec

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Template":
        if not isinstance(data, dict):
            raise ValueError("template must be a mapping")
        metadata = data.get("metadata", {}) or {}
        spec = data.get("spec", {}) or {}
        allowed_actions: list[ActionDef] = []
        for index, a in enumerate(spec.get("allowedActions", []) or []):
            if not isinstance(a, dict):
                raise ValueError(f"spec.allowedActions[{index}] must be a mapping")
            allowed_actions.append(
                ActionDef(
                    name=a.get("name", ""),
                    level=str(a.get("level", "")),
                    description=a.get("description", ""),
                )
            )
        action_names = [action.name for action in allowed_actions]
        if len(action_names) != len(set(action_names)):
            raise ValueError("spec.allowedActions contains duplicate action names")
        return cls(
            api_version=data.get("apiVersion", ""),
            kind=data.get("kind", ""),
            metadata=TemplateMetadata(
                id=_require_non_empty(metadata.get("id"), "metadata.id"),
                name=_require_non_empty(metadata.get("name"), "metadata.name"),
                version=_require_non_empty(metadata.get("version"), "metadata.version"),
                description=metadata.get("description", ""),
            ),
            spec=TemplateSpec(
                domain=_require_non_empty(spec.get("domain"), "spec.domain"),
                lifecycle=list(spec.get("lifecycle", []) or []),
                allowed_actions=allowed_actions,
                schemas=list(spec.get("schemas", []) or []),
                agent_contract=AgentContract(
                    role=_require_non_empty(
                        (spec.get("agentContract", {}) or {}).get("role"),
                        "spec.agentContract.role",
                    ),
                    responsibilities=list(
                        (spec.get("agentContract", {}) or {}).get("responsibilities", []) or []
                    ),
                    forbidden_actions=list(
                        (spec.get("agentContract", {}) or {}).get("forbiddenActions", []) or []
                    ),
                ),
                review_cadence=spec.get("reviewCadence", ""),
                inbox=_parse_inbox(spec.get("inbox")),
                quotas=_parse_quota(spec.get("quotas")),
            ),
        )


def _parse_inbox(data: Any) -> Inbox | None:
    if not isinstance(data, dict):
        return None
    return Inbox(
        format=data.get("format", ""),
        allowed_extensions=list(data.get("allowedExtensions", []) or []),
    )


def _parse_quota(data: Any) -> Quota | None:
    if not isinstance(data, dict):
        return None
    return Quota(
        runs_per_day=_require_int_or_none(data.get("runsPerDay"), "spec.quotas.runsPerDay"),
        messages_per_day=_require_int_or_none(data.get("messagesPerDay"), "spec.quotas.messagesPerDay"),
        monthly_euro_estimate=_require_int_or_none(data.get("monthlyEuroEstimate"), "spec.quotas.monthlyEuroEstimate"),
    )


@dataclass(frozen=True)
class TemplateRef:
    id: str
    path: str


@dataclass(frozen=True)
class InstanceMetadata:
    id: str
    name: str
    created_at: str = ""


@dataclass(frozen=True)
class Owner:
    name: str
    handle: str


@dataclass(frozen=True)
class ApprovalPolicy:
    # Missing policy must never widen authority.  Explicit approval is the
    # fail-closed default for every write, external side effect, or security
    # boundary above observation-only L1.
    L2: str = "require_explicit_approval"
    L3: str = "require_explicit_approval"
    L4: str = "require_explicit_approval"
    L5: str = "require_explicit_approval"

    def __post_init__(self) -> None:
        for level in APPROVAL_POLICY_LEVELS:
            decision = getattr(self, level)
            if decision not in APPROVAL_POLICY_DECISIONS:
                raise ValueError(
                    f"spec.approvalPolicy.{level} must be require_explicit_approval"
                )


@dataclass(frozen=True)
class GdprInfo:
    data_subject_category: str = ""
    pseudonymised: bool = False
    dpia_required: bool = False


@dataclass(frozen=True)
class InstanceSpec:
    template_ref: TemplateRef
    status: str
    owner: Owner
    retention_days: int | None = None
    quotas: Quota | None = None
    approval_policy: ApprovalPolicy = field(default_factory=ApprovalPolicy)
    gdpr: GdprInfo = field(default_factory=GdprInfo)


@dataclass(frozen=True)
class Instance:
    api_version: str
    kind: str
    metadata: InstanceMetadata
    spec: InstanceSpec

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Instance":
        if not isinstance(data, dict):
            raise ValueError("instance must be a mapping")
        metadata = data.get("metadata", {}) or {}
        spec = data.get("spec", {}) or {}
        if not isinstance(metadata, dict):
            raise ValueError("metadata must be a mapping")
        if not isinstance(spec, dict):
            raise ValueError("spec must be a mapping")
        template_ref = spec.get("templateRef", {}) or {}
        owner = spec.get("owner", {}) or {}
        if not isinstance(template_ref, dict):
            raise ValueError("spec.templateRef must be a mapping")
        if not isinstance(owner, dict):
            raise ValueError("spec.owner must be a mapping")
        raw_approval_policy = spec.get("approvalPolicy")
        if raw_approval_policy is None:
            approval_policy: dict[str, Any] = {}
        elif not isinstance(raw_approval_policy, dict):
            raise ValueError("spec.approvalPolicy must be a mapping")
        else:
            approval_policy = raw_approval_policy
        unknown_policy_levels = set(approval_policy) - set(APPROVAL_POLICY_LEVELS)
        if unknown_policy_levels:
            raise ValueError(
                "spec.approvalPolicy contains unsupported levels: "
                + ", ".join(sorted(unknown_policy_levels))
            )
        gdpr = spec.get("gdpr", {}) or {}
        if not isinstance(gdpr, dict):
            raise ValueError("spec.gdpr must be a mapping")
        return cls(
            api_version=data.get("apiVersion", ""),
            kind=data.get("kind", ""),
            metadata=InstanceMetadata(
                id=_require_non_empty(metadata.get("id"), "metadata.id"),
                name=_require_non_empty(metadata.get("name"), "metadata.name"),
                created_at=metadata.get("createdAt", ""),
            ),
            spec=InstanceSpec(
                template_ref=TemplateRef(
                    id=_require_non_empty(template_ref.get("id"), "spec.templateRef.id"),
                    path=_require_non_empty(
                        template_ref.get("path"), "spec.templateRef.path"
                    ),
                ),
                status=_require_non_empty(spec.get("status"), "spec.status"),
                owner=Owner(
                    name=_require_non_empty(owner.get("name"), "spec.owner.name"),
                    handle=_require_non_empty(owner.get("handle"), "spec.owner.handle"),
                ),
                retention_days=_require_int_or_none(spec.get("retentionDays"), "spec.retentionDays"),
                quotas=_parse_quota(spec.get("quotas")),
                approval_policy=ApprovalPolicy(
                    L2=approval_policy.get("L2", "require_explicit_approval"),
                    L3=approval_policy.get("L3", "require_explicit_approval"),
                    L4=approval_policy.get("L4", "require_explicit_approval"),
                    L5=approval_policy.get("L5", "require_explicit_approval"),
                ),
                gdpr=GdprInfo(
                    data_subject_category=gdpr.get("dataSubjectCategory", ""),
                    pseudonymised=_to_bool(gdpr.get("pseudonymised", False)),
                    dpia_required=_to_bool(gdpr.get("dpiaRequired", False)),
                ),
            ),
        )
