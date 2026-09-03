from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class QuotaPolicy:
    runs_per_day: int | None = None
    messages_per_day: int | None = None
    monthly_euro_estimate: float | None = None

    def __post_init__(self) -> None:
        for name in ("runs_per_day", "messages_per_day"):
            value = getattr(self, name)
            if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
                raise ValueError(f"{name} must be a non-negative integer or null")
        if self.monthly_euro_estimate is not None and (
            isinstance(self.monthly_euro_estimate, bool)
            or not isinstance(self.monthly_euro_estimate, (int, float))
            or not math.isfinite(float(self.monthly_euro_estimate))
            or self.monthly_euro_estimate < 0
        ):
            raise ValueError("monthly_euro_estimate must be non-negative or null")


@dataclass(frozen=True)
class UsageSnapshot:
    runs_today: int = 0
    messages_today: int = 0
    monthly_euro_estimate: float = 0.0

    def __post_init__(self) -> None:
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in (self.runs_today, self.messages_today)
        ) or (
            isinstance(self.monthly_euro_estimate, bool)
            or not isinstance(self.monthly_euro_estimate, (int, float))
            or not math.isfinite(float(self.monthly_euro_estimate))
            or self.monthly_euro_estimate < 0
        ):
            raise ValueError("usage values must be finite and non-negative")


@dataclass(frozen=True)
class QuotaDecision:
    allowed: bool
    code: str
    reason: str
    usage: UsageSnapshot
    limits: QuotaPolicy

    def to_dict(self) -> dict[str, Any]:
        return {"allowed": self.allowed, "code": self.code, "reason": self.reason,
                "usage": self.usage.__dict__.copy(), "limits": self.limits.__dict__.copy()}


class QuotaEngine:
    """Evaluate quotas before an operation is admitted; missing limits do not grant access."""

    def __init__(self, policy: QuotaPolicy):
        self.policy = policy

    def evaluate(self, usage: UsageSnapshot, *, operation: str = "run", estimated_cost: float = 0.0) -> QuotaDecision:
        if not isinstance(operation, str) or not operation.strip():
            return QuotaDecision(False, "invalid_operation", "operation is required", usage, self.policy)
        if (
            not isinstance(estimated_cost, (int, float))
            or isinstance(estimated_cost, bool)
            or not math.isfinite(float(estimated_cost))
            or estimated_cost < 0
        ):
            return QuotaDecision(False, "invalid_cost", "estimated cost must be non-negative", usage, self.policy)
        checks = (("runs_per_day", usage.runs_today, "runs"), ("messages_per_day", usage.messages_today, "messages"))
        for field, current, label in checks:
            limit = getattr(self.policy, field)
            if limit is not None and current >= limit:
                return QuotaDecision(False, "quota_exceeded", f"{label} quota exhausted", usage, self.policy)
        if self.policy.monthly_euro_estimate is not None and usage.monthly_euro_estimate + estimated_cost > self.policy.monthly_euro_estimate:
            return QuotaDecision(False, "quota_exceeded", "monthly cost quota would be exceeded", usage, self.policy)
        return QuotaDecision(True, "allowed", "quota available", usage, self.policy)
