"""Narrow validation bridge to StatePort's canonical authority decisions."""

from __future__ import annotations

from copy import deepcopy
import re
from typing import Any, Mapping

from .errors import DeploymentRefusal
from .inspection import authority_source_identity
from .util import digest_value


DECISION_SCHEMA = "stateport.authority-decision/v1"
RECEIPT_SCHEMA = "stateport.authority-action-receipt/v1"
_RECEIPT_ID = re.compile(r"^authority_receipt_[0-9a-f]{32}$")
_REQUEST_ID = re.compile(r"^authority_request_[0-9a-f]{32}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def authority_result_resource(
    deployment_id: str, value: Mapping[str, Any]
) -> dict[str, Any]:
    """Project one exact, non-secret deployment result for canonical receipts."""

    state = value.get("state") if isinstance(value.get("state"), Mapping) else None
    resource: dict[str, Any] = {
        "deploymentId": deployment_id,
        "lifecycleState": state.get("lifecycleState") if state is not None else None,
    }
    if state is not None:
        resource.update(
            acceptedRevision=state.get("acceptedRevision"),
            desiredRevision=state.get("desiredRevision"),
            observedRevision=state.get("observedRevision"),
            sourceIdentity=deepcopy(state.get("sourceIdentity")),
            targetIdentity=deepcopy(state.get("targetIdentity")),
            imageDigests=deepcopy(dict(state.get("imageDigests", {}))),
            storageIdentities=deepcopy(dict(state.get("storageIdentities", {}))),
            retainedDataState=state.get("retainedDataState"),
            driftStatus=state.get("driftStatus"),
        )
    if isinstance(value.get("planDigest"), str):
        spec = value.get("spec")
        if not isinstance(spec, Mapping):
            raise DeploymentRefusal(
                "invalid_operation_result",
                "deployment plan result lacks an exact specification",
            )
        resource.update(
            planId=value.get("planId"),
            planDigest=value["planDigest"],
            operation=value.get("operation"),
            sourceIdentity=authority_source_identity(spec),
            targetIdentity=deepcopy(dict(spec["target"])),
        )
    supplemental = value.get("authorityResource")
    if supplemental is not None:
        if not isinstance(supplemental, Mapping):
            raise DeploymentRefusal(
                "invalid_operation_result",
                "deployment authority resource must be an object",
            )
        protected = {"deploymentId", "lifecycleState"}
        if protected & set(supplemental):
            raise DeploymentRefusal(
                "invalid_operation_result",
                "deployment authority resource may not override canonical state identity",
            )
        resource.update(deepcopy(dict(supplemental)))
    return resource


def terminal_authority_data(
    authority_reference: Mapping[str, Any],
    *,
    deployment_id: str,
    result: Mapping[str, Any],
    status: str,
    code: str | None,
    summary: str,
) -> dict[str, Any]:
    if status not in {"succeeded", "failed"}:
        raise DeploymentRefusal(
            "authority_receipt_unbound", "terminal authority outcome is invalid"
        )
    return {
        "authorityDecision": deepcopy(dict(authority_reference)),
        "authorityOutcome": {
            "status": status,
            "code": code,
            "summary": summary,
            "resource": authority_result_resource(deployment_id, result),
        },
    }


def validate_authority_decision(
    value: Mapping[str, Any] | None,
    *,
    action: str,
    actor: str,
    deployment_id: str,
    grant_id: str | None = None,
    run_id: str | None = None,
    source_identity: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or value.get("schema") != DECISION_SCHEMA:
        raise DeploymentRefusal("authority_required", "a canonical authority decision is required")
    body = {key: item for key, item in value.items() if key != "decisionDigest"}
    if value.get("decisionDigest") != digest_value(body):
        raise DeploymentRefusal("authority_invalid", "authority decision integrity check failed")
    scope = value.get("scope")
    authorized_by = value.get("authorizedBy")
    request_id = value.get("requestId")
    requested = value.get("requestedCapabilities")
    if (
        not isinstance(request_id, str)
        or value.get("decision") != "authorized"
        or value.get("action") != action
        or value.get("actorId") != actor
        or not isinstance(scope, Mapping)
        or scope.get("applicationId") != deployment_id
        or scope.get("runId") != run_id
        or not isinstance(authorized_by, Mapping)
        or authorized_by.get("type") != "grant"
        or (grant_id is not None and authorized_by.get("id") != grant_id)
        or not isinstance(requested, Mapping)
        or requested.get("sourceIdentity")
        != (dict(source_identity) if source_identity is not None else None)
    ):
        raise DeploymentRefusal(
            "authority_scope_mismatch",
            "authority decision does not bind this actor, deployment, action, and grant",
        )
    return {
        "requestId": request_id,
        "decisionDigest": value["decisionDigest"],
        "action": action,
        "actorId": actor,
        "grantId": authorized_by.get("id"),
        "grantDigest": authorized_by.get("digest"),
        "runId": run_id,
        "profile": value.get("profile"),
        "policy": value.get("policy"),
        "scope": deepcopy(dict(scope)),
        "decision": deepcopy(dict(value)),
        "sourceIdentity": deepcopy(
            dict(source_identity) if source_identity is not None else None
        ),
    }


def validate_authority_receipt(
    value: Mapping[str, Any],
    *,
    deployment_id: str,
    grant_id: str | None = None,
    actor: str,
    action: str | None = None,
) -> dict[str, Any]:
    if value.get("schema") != RECEIPT_SCHEMA:
        raise DeploymentRefusal("authority_receipt_invalid", "authority receipt schema is invalid")
    body = {key: item for key, item in value.items() if key != "receiptDigest"}
    if value.get("receiptDigest") != digest_value(body):
        raise DeploymentRefusal("authority_receipt_invalid", "authority receipt integrity check failed")
    scope = value.get("scope")
    authorized_by = value.get("authorizedBy")
    result = value.get("result")
    receipt_id = value.get("receiptId")
    receipt_digest = value.get("receiptDigest")
    request_id = value.get("requestId")
    receipt_action = value.get("action")
    reservation = value.get("reservation")
    claim = value.get("claim")
    if (
        not isinstance(receipt_id, str)
        or _RECEIPT_ID.fullmatch(receipt_id) is None
        or not isinstance(receipt_digest, str)
        or _DIGEST.fullmatch(receipt_digest) is None
        or not isinstance(request_id, str)
        or _REQUEST_ID.fullmatch(request_id) is None
        or not isinstance(receipt_action, str)
        or (action is not None and receipt_action != action)
        or not isinstance(scope, Mapping)
        or scope.get("applicationId") != deployment_id
        or value.get("actorId") != actor
        or not isinstance(authorized_by, Mapping)
        or authorized_by.get("type") != "grant"
        or (grant_id is not None and authorized_by.get("id") != grant_id)
        or not isinstance(authorized_by.get("id"), str)
        or not isinstance(authorized_by.get("digest"), str)
        or _DIGEST.fullmatch(authorized_by["digest"]) is None
        or value.get("decision") != "authorized"
        or not isinstance(value.get("decisionDigest"), str)
        or _DIGEST.fullmatch(value["decisionDigest"]) is None
        or not isinstance(result, Mapping)
        or result.get("status") not in {"succeeded", "failed", "not_executed"}
        or not isinstance(result.get("resource"), Mapping)
        or not isinstance(reservation, Mapping)
        or not isinstance(reservation.get("reservationId"), str)
        or not isinstance(reservation.get("reservationDigest"), str)
        or _DIGEST.fullmatch(reservation["reservationDigest"]) is None
        or not isinstance(claim, Mapping)
        or not isinstance(claim.get("claimId"), str)
        or not isinstance(claim.get("claimDigest"), str)
        or _DIGEST.fullmatch(claim["claimDigest"]) is None
    ):
        raise DeploymentRefusal("authority_receipt_invalid", "authority receipt scope or outcome is invalid")
    return {
        "receiptId": receipt_id,
        "receiptDigest": receipt_digest,
        "requestId": request_id,
        "action": receipt_action,
        "resultStatus": result["status"],
        "grantId": authorized_by.get("id"),
        "decisionDigest": value.get("decisionDigest"),
        "reservationId": reservation["reservationId"],
        "reservationDigest": reservation["reservationDigest"],
        "claimId": claim["claimId"],
        "claimDigest": claim["claimDigest"],
    }


__all__ = [
    "authority_result_resource",
    "terminal_authority_data",
    "validate_authority_decision",
    "validate_authority_receipt",
]
