"""A run-bound provider route for managed execution.

The provider adapter owns credential use outside the agent container.  This
module only authorizes an exact route, enforces local budgets, and emits
metadata.  It never stores prompts, source code, or third-party credentials.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import hmac
import secrets
import threading
import time
from typing import Any, Callable, Mapping


class ModelGatewayError(RuntimeError):
    """A fail-closed route, token, budget, or provider-adapter refusal."""


@dataclass(frozen=True)
class ModelRoute:
    run_id: str
    provider: str
    model: str
    max_requests: int = 32
    max_tokens: int = 10000
    max_cost_minor: int = 0
    expires_after_seconds: int = 3600

    def validate(self) -> None:
        if not all(isinstance(value, str) and value.strip() for value in (self.run_id, self.provider, self.model)):
            raise ModelGatewayError("run, provider, and model are required")
        positive_limits = (self.max_requests, self.max_tokens, self.expires_after_seconds)
        if any(isinstance(value, bool) or not isinstance(value, int) or value <= 0 for value in positive_limits):
            raise ModelGatewayError("model route limits must be positive")
        if isinstance(self.max_cost_minor, bool) or not isinstance(self.max_cost_minor, int) or self.max_cost_minor < 0:
            raise ModelGatewayError("model route cost limit must be non-negative")


class ModelGateway:
    """In-memory, single-run gateway around one already configured adapter.

    Authorization and budget reservation are one atomic admission decision.
    Admission consumes the request slot before the provider effect and keeps
    token/cost estimates reserved until settlement. Provider exceptions and
    malformed/unknown usage consume the remaining route budget and lock the
    route because an external effect may already have happened. Actual usage
    is always charged, even when it exceeds an estimate or route maximum; an
    overrun is recorded and locks out all later admissions.

    Revocation blocks token issuance and new admissions immediately. Requests
    already admitted are in flight: they may return, and their usage is still
    settled after revocation so concurrent accounting is never discarded.
    """

    def __init__(self, route: ModelRoute, adapter: Callable[[str, str, Mapping[str, Any]], Mapping[str, Any]] | None = None) -> None:
        route.validate()
        if adapter is not None and not callable(adapter):
            raise ModelGatewayError("provider adapter must be callable")
        self._route = route
        self._adapter = adapter
        self._token_digest: str | None = None
        self._issued_at: float | None = None
        self._requests = 0
        self._tokens = 0
        self._cost_minor = 0
        self._reserved_requests = 0
        self._reserved_tokens = 0
        self._reserved_cost_minor = 0
        self._revoked = False
        self._locked_reason: str | None = None
        self._unknown_effects = 0
        self._overruns = 0
        self._lock = threading.Lock()

    @property
    def route(self) -> ModelRoute:
        return self._route

    def issue_token(self) -> str:
        with self._lock:
            if self._revoked:
                raise ModelGatewayError("model route is revoked")
            if self._locked_reason is not None:
                raise ModelGatewayError(f"model route is locked: {self._locked_reason}")
            token = secrets.token_urlsafe(32)
            self._token_digest = sha256(token.encode("ascii")).hexdigest()
            self._issued_at = time.monotonic()
            return token

    @staticmethod
    def _estimate(value: Any, name: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ModelGatewayError(f"{name} estimate must be a non-negative integer")
        return value

    def _authorize_and_reserve(
        self,
        token: str,
        provider: str,
        model: str,
        *,
        tokens: int,
        cost_minor: int,
    ) -> Callable[[str, str, Mapping[str, Any]], Mapping[str, Any]]:
        """Atomically authorize and admit one provider-effect attempt."""
        if not isinstance(token, str):
            raise ModelGatewayError("run-bound model token refused")
        try:
            presented_digest = sha256(token.encode("ascii")).hexdigest()
        except UnicodeEncodeError:
            raise ModelGatewayError("run-bound model token refused") from None
        with self._lock:
            if self._locked_reason is not None:
                raise ModelGatewayError(f"model route is locked: {self._locked_reason}")
            if self._revoked or self._token_digest is None or self._issued_at is None:
                raise ModelGatewayError("model route is unavailable")
            if not hmac.compare_digest(self._token_digest, presented_digest):
                raise ModelGatewayError("run-bound model token refused")
            if time.monotonic() - self._issued_at > self._route.expires_after_seconds:
                raise ModelGatewayError("run-bound model token expired")
            if provider != self._route.provider or model != self._route.model:
                raise ModelGatewayError("provider or model is outside the approved route")
            if self._adapter is None:
                raise ModelGatewayError("no configured provider adapter is available")
            if self._requests + 1 > self._route.max_requests:
                raise ModelGatewayError("model request budget exhausted")
            if self._tokens + self._reserved_tokens + tokens > self._route.max_tokens:
                raise ModelGatewayError("model token budget exhausted by reserved estimate")
            if self._cost_minor + self._reserved_cost_minor + cost_minor > self._route.max_cost_minor:
                raise ModelGatewayError("model cost budget exhausted by reserved estimate")
            self._requests += 1
            self._reserved_requests += 1
            self._reserved_tokens += tokens
            self._reserved_cost_minor += cost_minor
            return self._adapter

    def _release_reservation(self, *, tokens: int, cost_minor: int) -> None:
        self._reserved_requests -= 1
        self._reserved_tokens -= tokens
        self._reserved_cost_minor -= cost_minor
        if min(self._reserved_requests, self._reserved_tokens, self._reserved_cost_minor) < 0:
            self._locked_reason = "gateway-accounting-invariant-violated"
            self._token_digest = None
            raise ModelGatewayError("model gateway accounting invariant violated")

    def _settle_known(
        self,
        *,
        estimated_tokens: int,
        estimated_cost_minor: int,
        tokens: int,
        cost_minor: int,
    ) -> None:
        """Charge exact observed usage, retaining every over-budget effect."""
        with self._lock:
            self._release_reservation(tokens=estimated_tokens, cost_minor=estimated_cost_minor)
            self._tokens += tokens
            self._cost_minor += cost_minor
            overrun = (
                tokens > estimated_tokens
                or cost_minor > estimated_cost_minor
                or self._tokens > self._route.max_tokens
                or self._cost_minor > self._route.max_cost_minor
            )
            if overrun:
                self._overruns += 1
                if self._locked_reason is None:
                    self._locked_reason = "provider-usage-exceeded-reservation"
                self._token_digest = None
                raise ModelGatewayError("provider usage exceeded its reserved budget")

    def _settle_unknown(self, *, estimated_tokens: int, estimated_cost_minor: int) -> None:
        """Conservatively exhaust and lock a route after an unknown effect."""
        with self._lock:
            self._release_reservation(tokens=estimated_tokens, cost_minor=estimated_cost_minor)
            self._tokens = max(self._tokens + estimated_tokens, self._route.max_tokens)
            self._cost_minor = max(
                self._cost_minor + estimated_cost_minor,
                self._route.max_cost_minor,
            )
            self._unknown_effects += 1
            if self._locked_reason is None:
                self._locked_reason = "provider-effect-usage-unknown"
            self._token_digest = None

    @staticmethod
    def _usage(result: Mapping[str, Any]) -> tuple[int, int]:
        usage = result.get("usage")
        if not isinstance(usage, Mapping):
            raise ModelGatewayError("provider adapter usage is malformed")
        tokens = usage.get("tokens")
        cost_minor = usage.get("costMinor")
        if isinstance(tokens, bool) or not isinstance(tokens, int) or tokens < 0:
            raise ModelGatewayError("provider token usage is malformed")
        if isinstance(cost_minor, bool) or not isinstance(cost_minor, int) or cost_minor < 0:
            raise ModelGatewayError("provider cost usage is malformed")
        return tokens, cost_minor

    def request(
        self,
        token: str,
        *,
        provider: str,
        model: str,
        request: Mapping[str, Any],
        estimated_tokens: int = 0,
        estimated_cost_minor: int = 0,
    ) -> Mapping[str, Any]:
        estimated_tokens = self._estimate(estimated_tokens, "token")
        estimated_cost_minor = self._estimate(estimated_cost_minor, "cost")
        adapter = self._authorize_and_reserve(
            token,
            provider,
            model,
            tokens=estimated_tokens,
            cost_minor=estimated_cost_minor,
        )
        started = time.monotonic()
        try:
            result = adapter(provider, model, request)
        except BaseException:
            self._settle_unknown(
                estimated_tokens=estimated_tokens,
                estimated_cost_minor=estimated_cost_minor,
            )
            raise
        if not isinstance(result, Mapping):
            self._settle_unknown(
                estimated_tokens=estimated_tokens,
                estimated_cost_minor=estimated_cost_minor,
            )
            raise ModelGatewayError("provider adapter returned a non-object result")
        try:
            tokens, cost_minor = self._usage(result)
        except BaseException:
            self._settle_unknown(
                estimated_tokens=estimated_tokens,
                estimated_cost_minor=estimated_cost_minor,
            )
            raise
        self._settle_known(
            estimated_tokens=estimated_tokens,
            estimated_cost_minor=estimated_cost_minor,
            tokens=tokens,
            cost_minor=cost_minor,
        )
        return {
            "provider": provider,
            "model": model,
            "outcome": "completed",
            "usage": {"tokens": tokens, "costMinor": cost_minor},
            "timing": {"durationMilliseconds": int((time.monotonic() - started) * 1000)},
            "response": dict(result),
        }

    def revoke(self) -> None:
        with self._lock:
            self._revoked = True
            self._token_digest = None

    def usage(self) -> dict[str, Any]:
        with self._lock:
            return {
                "provider": self._route.provider,
                "model": self._route.model,
                "requests": self._requests,
                "tokens": self._tokens,
                "costMinor": self._cost_minor,
                "reserved": {
                    "requests": self._reserved_requests,
                    "tokens": self._reserved_tokens,
                    "costMinor": self._reserved_cost_minor,
                },
                "revoked": self._revoked,
                "lockedReason": self._locked_reason,
                "unknownEffects": self._unknown_effects,
                "overruns": self._overruns,
            }


__all__ = ["ModelGateway", "ModelGatewayError", "ModelRoute"]
