"""Exact adapter from updater plans to StatePort's canonical authority store."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import re
from typing import Any, Callable, Mapping, Sequence, TypeVar


T = TypeVar("T")
AUTHORITY_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
AUTHORITY_REQUEST = re.compile(r"authority_request_[0-9a-f]{32}\Z")
AUTHORITY_RESERVATION = re.compile(r"authority_reservation_[0-9a-f]{32}\Z")
AUTHORITY_CLAIM = re.compile(r"authority_claim_[0-9a-f]{32}\Z")
AUTHORITY_RECEIPT = re.compile(r"authority_receipt_[0-9a-f]{32}\Z")
BOUNDARY_CODE = re.compile(r"[a-z][a-z0-9_]{0,127}\Z")


def _authority_digest(value: Mapping[str, Any]) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _normalized_manager_error(exc: Exception) -> "UpdateAuthorityError":
    """Normalize only typed canonical manager failures without importing Git runtime code.

    The installed updater receives a manager/subject adapter by injection.  Its
    wheel must remain usable for read-only health and status on a clean host;
    importing repository-backed authority is therefore not a package import
    side effect.  Unexpected exceptions retain a stable boundary code without
    exposing private details.
    """

    code = getattr(exc, "code", None)
    if not isinstance(code, str) or BOUNDARY_CODE.fullmatch(code) is None:
        code = "authority_adapter_failed"
    receipt = getattr(exc, "receipt", None)
    canonical_receipt = None
    if isinstance(receipt, Mapping):
        try:
            canonical_receipt = _validate_receipt(receipt)
        except UpdateAuthorityError:
            canonical_receipt = None
    return UpdateAuthorityError(
        code,
        "canonical authority adapter failed",
        receipt=canonical_receipt,
    )


def _validate_decision(decision: object) -> dict[str, Any]:
    expected = {
        "schema",
        "requestId",
        "action",
        "actorId",
        "authorizedBy",
        "scope",
        "profile",
        "configuredPolicy",
        "policy",
        "decision",
        "reason",
        "missingAssurances",
        "estimatedCostUsd",
        "estimatedDurationSeconds",
        "requestedCapabilities",
        "decidedAt",
        "decisionDigest",
    }
    if (
        not isinstance(decision, Mapping)
        or set(decision) != expected
        or decision.get("schema") != "stateport.authority-decision/v1"
        or AUTHORITY_REQUEST.fullmatch(str(decision.get("requestId", ""))) is None
    ):
        raise UpdateAuthorityError("authority_contract_invalid", "authority decision is malformed")
    value = dict(decision)
    body = {key: item for key, item in value.items() if key != "decisionDigest"}
    if value.get("decisionDigest") != _authority_digest(body):
        raise UpdateAuthorityError(
            "authority_contract_invalid", "authority decision digest is invalid"
        )
    if (
        value.get("decision") not in {"authorized", "approval_required", "denied"}
        or not isinstance(value.get("scope"), Mapping)
        or not isinstance(value.get("authorizedBy"), Mapping)
        or not isinstance(value.get("requestedCapabilities"), Mapping)
        or set(value["requestedCapabilities"])
        != {"domains", "provider", "secretCapabilities", "assurances", "sourceIdentity"}
    ):
        raise UpdateAuthorityError(
            "authority_contract_invalid", "authority decision fields are invalid"
        )
    return value


def _validate_reservation(reservation: object) -> dict[str, Any]:
    if (
        not isinstance(reservation, Mapping)
        or set(reservation)
        != {
            "schema",
            "reservationId",
            "requestId",
            "decision",
            "reservedAt",
            "reservationDigest",
        }
        or reservation.get("schema") != "stateport.authority-action-reservation/v1"
        or AUTHORITY_RESERVATION.fullmatch(str(reservation.get("reservationId", ""))) is None
    ):
        raise UpdateAuthorityError(
            "authority_contract_invalid", "authority reservation is malformed"
        )
    value = dict(reservation)
    decision = _validate_decision(value["decision"])
    body = {key: item for key, item in value.items() if key != "reservationDigest"}
    if (
        value.get("reservationDigest") != _authority_digest(body)
        or value.get("requestId") != decision["requestId"]
    ):
        raise UpdateAuthorityError(
            "authority_contract_invalid", "authority reservation digest is invalid"
        )
    return value


def _validate_claim(claim: object) -> dict[str, Any]:
    if (
        not isinstance(claim, Mapping)
        or set(claim)
        != {
            "schema",
            "claimId",
            "requestId",
            "reservationId",
            "reservationDigest",
            "decisionDigest",
            "claimedAt",
            "claimDigest",
        }
        or claim.get("schema") != "stateport.authority-action-claim/v1"
        or AUTHORITY_CLAIM.fullmatch(str(claim.get("claimId", ""))) is None
    ):
        raise UpdateAuthorityError("authority_contract_invalid", "authority claim is malformed")
    value = dict(claim)
    body = {key: item for key, item in value.items() if key != "claimDigest"}
    if value.get("claimDigest") != _authority_digest(body):
        raise UpdateAuthorityError(
            "authority_contract_invalid", "authority claim digest is invalid"
        )
    return value


def _validate_receipt(receipt: object) -> dict[str, Any]:
    expected = {
        "schema",
        "receiptId",
        "requestId",
        "action",
        "actorId",
        "authorizedBy",
        "scope",
        "profile",
        "configuredPolicy",
        "policy",
        "decision",
        "result",
        "startedAt",
        "completedAt",
        "estimatedCostUsd",
        "actualCostUsd",
        "decisionDigest",
        "reservation",
        "claim",
        "receiptDigest",
    }
    if (
        not isinstance(receipt, Mapping)
        or set(receipt) != expected
        or receipt.get("schema") != "stateport.authority-action-receipt/v1"
        or AUTHORITY_RECEIPT.fullmatch(str(receipt.get("receiptId", ""))) is None
        or AUTHORITY_REQUEST.fullmatch(str(receipt.get("requestId", ""))) is None
    ):
        raise UpdateAuthorityError("authority_contract_invalid", "authority receipt is malformed")
    value = dict(receipt)
    body = {key: item for key, item in value.items() if key != "receiptDigest"}
    result = value.get("result")
    if (
        value.get("receiptDigest") != _authority_digest(body)
        or not isinstance(result, Mapping)
        or set(result) != {"status", "code", "summary", "resource"}
        or result.get("status") not in {"succeeded", "failed", "refused", "not_executed"}
        or not isinstance(result.get("resource"), Mapping)
    ):
        raise UpdateAuthorityError(
            "authority_contract_invalid", "authority receipt digest is invalid"
        )
    reservation = value.get("reservation")
    claim = value.get("claim")
    if reservation is not None and (
        not isinstance(reservation, Mapping)
        or set(reservation) != {"reservationId", "reservationDigest"}
        or AUTHORITY_RESERVATION.fullmatch(str(reservation.get("reservationId", ""))) is None
        or AUTHORITY_DIGEST.fullmatch(str(reservation.get("reservationDigest", ""))) is None
    ):
        raise UpdateAuthorityError(
            "authority_contract_invalid", "authority receipt reservation is invalid"
        )
    if claim is not None and (
        not isinstance(claim, Mapping)
        or set(claim) != {"claimId", "claimDigest"}
        or AUTHORITY_CLAIM.fullmatch(str(claim.get("claimId", ""))) is None
        or AUTHORITY_DIGEST.fullmatch(str(claim.get("claimDigest", ""))) is None
    ):
        raise UpdateAuthorityError(
            "authority_contract_invalid", "authority receipt claim is invalid"
        )
    return value


class UpdateAuthorityError(ValueError):
    """Canonical authority refused, changed, or requires reconciliation."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        receipt: Mapping[str, Any] | None = None,
    ) -> None:
        if not isinstance(code, str) or BOUNDARY_CODE.fullmatch(code) is None:
            code = "authority_error"
        super().__init__(message)
        self.code = code
        self.receipt = None if receipt is None else dict(receipt)


@dataclass(frozen=True)
class AuthorityScope:
    actor_id: str
    grant_id: str
    branch: str
    slice_id: str | None
    application_id: str | None
    paths: tuple[str, ...]


class AuthorityManagerAdapter:
    """Development adapter for repository authority v1.

    Installed mutation uses a separate typed installation-subject manager.  It
    must be injected by the installed control plane; this adapter never creates
    a fake Git repository, branch, or path scope on a clean host.
    """

    authority_subject = "repository-development-v1"

    def __init__(self, manager: Any, scope: AuthorityScope) -> None:
        self.manager = manager
        self.scope = scope

    @staticmethod
    def _action(plan: Mapping[str, Any]) -> str:
        operation = plan.get("operation")
        if operation == "update":
            return "apply_update"
        if operation == "rollback":
            return "rollback_update"
        raise UpdateAuthorityError("plan_invalid", "update plan operation is invalid")

    def _validate_repository_scope(
        self,
        decision: Mapping[str, Any],
        *,
        action: str,
        run_id: str,
    ) -> None:
        scope = decision.get("scope")
        authorized_by = decision.get("authorizedBy")
        if (
            decision.get("action") != action
            or decision.get("actorId") != self.scope.actor_id
            or not isinstance(authorized_by, Mapping)
            or authorized_by.get("type") != "grant"
            or authorized_by.get("id") != self.scope.grant_id
            or not isinstance(scope, Mapping)
            or scope.get("branch") != self.scope.branch
            or scope.get("sliceId") != self.scope.slice_id
            or scope.get("applicationId") != self.scope.application_id
            or scope.get("runId") != run_id
            or scope.get("paths") != list(self.scope.paths)
            or not isinstance(scope.get("repository"), Mapping)
        ):
            raise UpdateAuthorityError(
                "authority_scope_mismatch",
                "repository development authority does not bind the exact updater scope",
            )

    def reserve(self, plan: Mapping[str, Any]) -> dict[str, Any]:
        """Reserve the canonical action; refusals are terminally receipted."""

        action = self._action(plan)
        digest = plan.get("planDigest")
        if not isinstance(digest, str) or plan.get("authority", {}).get("runId") != digest:
            raise UpdateAuthorityError(
                "authority_scope_mismatch", "plan does not bind its exact authority run"
            )
        try:
            decision, reservation = self.manager.reserve_action(
                action,
                actor_id=self.scope.actor_id,
                grant_id=self.scope.grant_id,
                branch=self.scope.branch,
                slice_id=self.scope.slice_id,
                application_id=self.scope.application_id,
                run_id=digest,
                paths=self.scope.paths,
                estimated_duration_seconds=3600,
            )
        except Exception as exc:
            raise _normalized_manager_error(exc) from exc
        decision = _validate_decision(decision)
        self._validate_repository_scope(decision, action=action, run_id=str(digest))
        if reservation is not None:
            reservation = _validate_reservation(reservation)
            if reservation["decision"] != decision:
                raise UpdateAuthorityError(
                    "authority_reservation_mismatch",
                    "canonical reservation does not contain the exact decision",
                )
        if decision.get("decision") != "authorized" or reservation is None:
            try:
                receipt = self.manager.record_action(
                    decision,
                    result_status="not_executed",
                    code=str(decision.get("reason", "authority_refused")),
                    summary="StatePort update was not executed because authority was refused",
                )
            except Exception as exc:
                raise _normalized_manager_error(exc) from exc
            receipt = _validate_receipt(receipt)
            raise UpdateAuthorityError(
                str(decision.get("reason", "authority_refused")),
                "update action is outside effective standing authority",
                receipt=receipt,
            )
        return {"decision": decision, "reservation": reservation}

    def validate_reservation(
        self,
        plan: Mapping[str, Any],
        authorization: Mapping[str, Any],
    ) -> dict[str, Any]:
        if not isinstance(authorization, Mapping) or set(authorization) != {
            "decision",
            "reservation",
        }:
            raise UpdateAuthorityError(
                "authority_reservation_invalid", "update authorization is malformed"
            )
        decision = _validate_decision(authorization.get("decision"))
        reservation = _validate_reservation(authorization.get("reservation"))
        action = self._action(plan)
        digest = plan.get("planDigest")
        self._validate_repository_scope(decision, action=action, run_id=str(digest))
        if (
            decision.get("action") != action
            or decision.get("decision") != "authorized"
            or decision.get("scope", {}).get("runId") != digest
            or reservation.get("requestId") != decision.get("requestId")
            or reservation.get("decision") != dict(decision)
        ):
            raise UpdateAuthorityError(
                "authority_reservation_mismatch",
                "canonical reservation does not bind the exact update plan",
            )
        return {"decision": decision, "reservation": reservation}

    def claim(self, binding: Mapping[str, Any]) -> dict[str, Any]:
        decision = binding.get("decision")
        if not isinstance(decision, Mapping):
            raise UpdateAuthorityError("authority_claim_invalid", "authority decision is missing")
        try:
            claimed = self.manager.claim_reserved_decision(decision)
        except Exception as exc:
            raise _normalized_manager_error(exc) from exc
        if not isinstance(claimed, Mapping) or set(claimed) != {
            "schema",
            "reservationId",
            "requestId",
            "decision",
            "reservedAt",
            "reservationDigest",
            "claim",
        }:
            raise UpdateAuthorityError(
                "authority_contract_invalid",
                "claimed reservation has an invalid shape",
            )
        canonical_reservation = _validate_reservation(
            {key: value for key, value in claimed.items() if key != "claim"}
        )
        if canonical_reservation != dict(binding["reservation"]):
            raise UpdateAuthorityError(
                "authority_claim_mismatch",
                "claimed authority reservation differs from its exact binding",
            )
        if claimed.get("reservationId") != binding.get("reservation", {}).get("reservationId"):
            raise UpdateAuthorityError(
                "authority_claim_mismatch", "claimed authority reservation changed"
            )
        claim = _validate_claim(claimed.get("claim"))
        if (
            claim["requestId"] != decision["requestId"]
            or claim["reservationId"] != canonical_reservation["reservationId"]
            or claim["reservationDigest"] != canonical_reservation["reservationDigest"]
            or claim["decisionDigest"] != decision["decisionDigest"]
        ):
            raise UpdateAuthorityError(
                "authority_claim_mismatch",
                "canonical claim does not bind the exact decision and reservation",
            )
        return claim

    def recover_claim(self, request_id: str) -> dict[str, Any] | None:
        try:
            if not self.manager.has_claim(request_id):
                return None
            claim = self.manager.get_claim(request_id)
        except Exception as exc:
            raise _normalized_manager_error(exc) from exc
        return _validate_claim(claim)

    def terminal_receipt(self, request_id: str) -> dict[str, Any] | None:
        try:
            receipt = self.manager.get_receipt_for_request(request_id)
        except Exception as exc:
            raise _normalized_manager_error(exc) from exc
        return None if receipt is None else _validate_receipt(receipt)

    @staticmethod
    def _validate_terminal_receipt(
        binding: Mapping[str, Any],
        receipt: Mapping[str, Any],
        *,
        result_status: str,
        code: str | None,
        summary: str,
        resource: Mapping[str, Any],
    ) -> dict[str, Any]:
        receipt = _validate_receipt(receipt)
        decision = binding["decision"]
        reservation = binding["reservation"]
        claim = binding["claim"]
        expected = {
            "requestId": decision["requestId"],
            "action": decision["action"],
            "actorId": decision["actorId"],
            "authorizedBy": dict(decision["authorizedBy"]),
            "scope": dict(decision["scope"]),
            "profile": decision["profile"],
            "configuredPolicy": decision["configuredPolicy"],
            "policy": decision["policy"],
            "decision": decision["decision"],
            "decisionDigest": decision["decisionDigest"],
            "reservation": {
                "reservationId": reservation["reservationId"],
                "reservationDigest": reservation["reservationDigest"],
            },
            "claim": {
                "claimId": claim["claimId"],
                "claimDigest": claim["claimDigest"],
            },
            "result": {
                "status": result_status,
                "code": code,
                "summary": summary.strip(),
                "resource": dict(resource),
            },
        }
        if any(receipt.get(key) != value for key, value in expected.items()):
            raise UpdateAuthorityError(
                "authority_terminal_conflict",
                "existing canonical authority receipt conflicts with the exact update outcome",
            )
        return dict(receipt)

    def finalize(
        self,
        binding: Mapping[str, Any],
        *,
        result_status: str,
        code: str | None,
        summary: str,
        resource: Mapping[str, Any],
        started_at: datetime,
    ) -> dict[str, Any]:
        decision = binding.get("decision")
        reservation = binding.get("reservation")
        claim = binding.get("claim")
        if not all(isinstance(item, Mapping) for item in (decision, reservation, claim)):
            raise UpdateAuthorityError(
                "authority_claim_invalid", "canonical authority binding is incomplete"
            )
        request_id = str(decision["requestId"])
        existing = self.terminal_receipt(request_id)
        if existing is not None:
            return self._validate_terminal_receipt(
                binding,
                existing,
                result_status=result_status,
                code=code,
                summary=summary,
                resource=resource,
            )
        try:
            recorded = self.manager.record_action(
                decision,
                result_status=result_status,
                code=code,
                summary=summary,
                resource=resource,
                started_at=started_at,
                reservation=reservation,
                claim=claim,
            )
            return self._validate_terminal_receipt(
                binding,
                _validate_receipt(recorded),
                result_status=result_status,
                code=code,
                summary=summary,
                resource=resource,
            )
        except Exception as exc:
            # A retry can race only with its own create-only terminal record.
            if getattr(exc, "code", None) == "duplicate_record":
                recovered = self.terminal_receipt(request_id)
                if recovered is not None:
                    return self._validate_terminal_receipt(
                        binding,
                        recovered,
                        result_status=result_status,
                        code=code,
                        summary=summary,
                        resource=resource,
                    )
            raise _normalized_manager_error(exc) from exc

    def execute_scoped(
        self,
        action: str,
        *,
        run_id: str,
        operation: Callable[[], T],
        resource_from_result: Callable[[T], Mapping[str, Any]] | None = None,
    ) -> tuple[T, dict[str, Any]]:
        """Use the canonical engine for observe/plan/policy operations."""

        try:
            result, receipt = self.manager.execute(
                action,
                operation,
                actor_id=self.scope.actor_id,
                grant_id=self.scope.grant_id,
                branch=self.scope.branch,
                slice_id=self.scope.slice_id,
                application_id=self.scope.application_id,
                run_id=run_id,
                paths=self.scope.paths,
                estimated_duration_seconds=300,
                resource_from_result=resource_from_result,
            )
        except Exception as exc:
            attached = getattr(exc, "authority_receipt", None)
            if isinstance(attached, Mapping) and getattr(exc, "receipt", None) is None:
                try:
                    setattr(exc, "receipt", _validate_receipt(attached))
                except (AttributeError, UpdateAuthorityError):
                    pass
            raise _normalized_manager_error(exc) from exc
        canonical = _validate_receipt(receipt)
        if (
            canonical["action"] != action
            or canonical["actorId"] != self.scope.actor_id
            or canonical["result"]["status"] != "succeeded"
        ):
            raise UpdateAuthorityError(
                "authority_receipt_mismatch",
                "canonical scoped execution receipt does not bind the exact operation",
            )
        self._validate_repository_scope(canonical, action=action, run_id=run_id)
        return result, canonical


def authority_reference(
    binding: Mapping[str, Any],
    *,
    plan_digest: str,
) -> dict[str, Any]:
    """Project exact decision/reservation/claim identity into update contracts."""

    decision = binding["decision"]
    reservation = binding["reservation"]
    claim = binding["claim"]
    authorized_by = decision["authorizedBy"]
    if authorized_by.get("type") != "grant":
        raise UpdateAuthorityError(
            "standing_grant_required", "update effects require an exact standing grant"
        )
    return {
        "action": decision["action"],
        "actorId": decision["actorId"],
        "grantId": authorized_by["id"],
        "grantDigest": authorized_by["digest"],
        "profile": decision["profile"],
        "configuredPolicy": decision["configuredPolicy"],
        "effectivePolicy": decision["policy"],
        "scope": dict(decision["scope"]),
        "runId": plan_digest,
        "planDigest": plan_digest,
        "requestId": decision["requestId"],
        "decisionDigest": decision["decisionDigest"],
        "reservationId": reservation["reservationId"],
        "reservationDigest": reservation["reservationDigest"],
        "claimId": claim["claimId"],
        "claimDigest": claim["claimDigest"],
    }


def finalized_authority_reference(
    binding: Mapping[str, Any],
    receipt: Mapping[str, Any],
    *,
    plan_digest: str,
) -> dict[str, Any]:
    reference = authority_reference(binding, plan_digest=plan_digest)
    return {
        **reference,
        "receiptId": receipt["receiptId"],
        "receiptDigest": receipt["receiptDigest"],
    }
