"""Mock secret store and one-use capability broker for public-safe proofs."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from hashlib import sha256
import secrets
from typing import Callable, Protocol

from .contracts import (
    CapabilityRequest,
    SecretMetadata,
    SecretReference,
    SecretRequirement,
    SecretUseGrant,
    SecretUseReceipt,
)
from .gateway import GatewayBlocked, SensitiveDataGateway


class BrokerRefusal(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class SecretStore(Protocol):
    def create(self, requirement: SecretRequirement, value: str) -> SecretReference: ...
    def metadata(self, reference_id: str) -> SecretMetadata: ...
    def revoke(self, reference_id: str) -> SecretMetadata: ...
    def exact_matches(self, text: str) -> tuple[tuple[int, int, str], ...]: ...


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _timestamp(value: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise BrokerRefusal("invalid_grant_expiry")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise BrokerRefusal("invalid_grant_expiry") from exc
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise BrokerRefusal("invalid_grant_expiry")
    return parsed


class InMemorySecretStore:
    """Fictional mock. The public API deliberately has no reveal method."""

    def __init__(self, *, clock: Callable[[], str] = _now, token: Callable[[int], str] = secrets.token_hex) -> None:
        self._clock = clock
        self._token = token
        self._material: dict[str, str] = {}
        self._metadata: dict[str, SecretMetadata] = {}
        self._references: dict[str, str] = {}

    def create(self, requirement: SecretRequirement, value: str) -> SecretReference:
        if not isinstance(value, str) or len(value) < 16 or "\x00" in value:
            raise ValueError("secret material must be a bounded non-empty value")
        secret_id = "secret." + self._token(12)
        reference_id = "secretref." + self._token(16)
        self._material[secret_id] = value
        self._references[reference_id] = secret_id
        self._metadata[secret_id] = SecretMetadata(
            secret_id, requirement.requirement_id, requirement.display_name,
            requirement.capability, requirement.scope, "active", self._clock(),
        )
        return SecretReference(reference_id, secret_id)

    def metadata(self, reference_id: str) -> SecretMetadata:
        secret_id = self._references.get(reference_id)
        if secret_id is None:
            raise BrokerRefusal("unknown_secret_reference")
        return self._metadata[secret_id]

    def revoke(self, reference_id: str) -> SecretMetadata:
        current = self.metadata(reference_id)
        updated = replace(current, status="revoked")
        self._metadata[current.secret_id] = updated
        return updated

    def exact_matches(self, text: str) -> tuple[tuple[int, int, str], ...]:
        result: list[tuple[int, int, str]] = []
        for secret_id, value in self._material.items():
            start = 0
            while True:
                start = text.find(value, start)
                if start < 0:
                    break
                result.append((start, start + len(value), secret_id))
                start += len(value)
        return tuple(sorted(result))

    def _resolve_for_broker(self, reference_id: str) -> str:
        metadata = self.metadata(reference_id)
        if metadata.status != "active":
            raise BrokerRefusal("secret_revoked")
        return self._material[metadata.secret_id]


class CapabilityBroker:
    """Approve and consume exact, scoped grants without exposing material."""

    def __init__(
        self,
        store: InMemorySecretStore,
        gateway: SensitiveDataGateway,
        *,
        clock: Callable[[], str] = _now,
        token: Callable[[int], str] = secrets.token_hex,
    ) -> None:
        self.store = store
        self.gateway = gateway
        self._clock = clock
        self._token = token
        self._requests: dict[str, CapabilityRequest] = {}
        self._grants: dict[str, SecretUseGrant] = {}

    def request(self, reference: SecretReference, *, run_id: str, operation: str, capability: str, scope: str) -> CapabilityRequest:
        metadata = self.store.metadata(reference.reference_id)
        if metadata.status != "active":
            raise BrokerRefusal("secret_revoked")
        if (metadata.capability, metadata.scope) != (capability, scope):
            raise BrokerRefusal("capability_scope_mismatch")
        request = CapabilityRequest(
            "capreq." + self._token(12), reference.reference_id, run_id, operation,
            capability, scope, "pending", self._clock(),
        )
        self._requests[request.request_id] = request
        return request

    def approve(self, request_id: str, *, expires_at: str) -> SecretUseGrant:
        request = self._requests.get(request_id)
        if request is None:
            raise BrokerRefusal("unknown_capability_request")
        if request.status != "pending":
            raise BrokerRefusal("capability_request_already_decided")
        metadata = self.store.metadata(request.reference_id)
        if metadata.status != "active":
            raise BrokerRefusal("secret_revoked")
        if _timestamp(expires_at) <= _timestamp(self._clock()):
            raise BrokerRefusal("grant_expiry_not_future")
        approved = replace(request, status="approved")
        self._requests[request_id] = approved
        grant = SecretUseGrant(
            "grant." + self._token(12), request_id, request.reference_id, request.run_id,
            request.operation, request.capability, request.scope, expires_at,
        )
        self._grants[grant.grant_id] = grant
        return grant

    def execute(
        self,
        grant_id: str,
        *,
        run_id: str,
        operation: str,
        capability: str,
        scope: str,
        handler: Callable[[str], str],
    ) -> tuple[str, SecretUseReceipt]:
        grant = self._grants.get(grant_id)
        if grant is None:
            raise BrokerRefusal("unknown_grant")
        if grant.status != "available":
            raise BrokerRefusal("grant_already_consumed")
        if (grant.run_id, grant.operation, grant.capability, grant.scope) != (run_id, operation, capability, scope):
            raise BrokerRefusal("grant_binding_mismatch")
        if _timestamp(self._clock()) >= _timestamp(grant.expires_at):
            self._grants[grant_id] = replace(grant, status="expired")
            raise BrokerRefusal("grant_expired")

        # Consumption happens before resolution/execution. Failures cannot silently retry.
        self._grants[grant_id] = replace(grant, status="consumed")
        try:
            value = self.store._resolve_for_broker(grant.reference_id)
            raw_output = handler(value)
            output, scan_receipt = self.gateway.sanitize_model_return(raw_output, source_kind="broker_tool_output")
        except GatewayBlocked as exc:
            raise BrokerRefusal("sensitive_output_withheld") from exc
        except BrokerRefusal:
            raise
        except Exception as exc:
            raise BrokerRefusal("capability_failed_no_retry") from exc
        digest = "sha256:" + sha256(output.encode("utf-8")).hexdigest()
        receipt = SecretUseReceipt(
            "secretuse." + self._token(12), grant.grant_id, grant.request_id,
            grant.reference_id, run_id, operation, capability, scope, "completed",
            digest, scan_receipt.finding_ids, self._clock(),
        )
        return output, receipt
