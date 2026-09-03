"""Shared governed execution for deployment authority actions.

The admin CLI and the web AppServer both drive ``DeploymentService`` through
the same canonical authority boundary: reserve one exact decision, run the
operation, and finalize one durable authority receipt — including the
response-loss, preflight-failure, unfinalized-effect, and link-pending edge
cases.  This module is the single implementation of that flow; callers supply
identity parameters explicitly instead of a CLI argument namespace.
"""

from __future__ import annotations

import subprocess
from typing import Any, Callable, Mapping

from governed_runner.authority import AuthorityError, AuthorityManager

from .errors import DeploymentError
from .service import DeploymentService


def checked_out_branch(manager: AuthorityManager) -> str:
    """Return the exact checked-out branch the authority decision binds to."""

    completed = subprocess.run(
        (
            "git",
            "--no-replace-objects",
            "-c",
            "core.hooksPath=/dev/null",
            "-C",
            str(manager.checkout),
            "branch",
            "--show-current",
        ),
        check=True,
        capture_output=True,
        text=True,
        shell=False,
        timeout=30,
    )
    branch = completed.stdout.strip()
    if not branch:
        raise ValueError("deployment authority requires an exact checked-out branch")
    return branch


def attach_authority(
    result: Mapping[str, Any],
    authority_receipt: Mapping[str, Any],
    link: Mapping[str, Any] | None,
) -> dict[str, Any]:
    attached = {**dict(result), "authorityReceipt": dict(authority_receipt)}
    if link is not None:
        attached["authorityLink"] = dict(link)
    return attached


def record_or_reuse_action(
    manager: AuthorityManager,
    decision: Mapping[str, Any],
    *,
    result_status: str,
    summary: str,
    code: str | None,
    resource: Mapping[str, Any] | None = None,
    reservation: Mapping[str, Any] | None = None,
    claim: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Finalize once, reusing only an exact canonical response-loss result."""

    expected_result = {
        "status": result_status,
        "code": code,
        "summary": summary,
        "resource": dict(resource or {}),
    }
    try:
        return manager.record_action(
            decision,
            result_status=result_status,
            summary=summary,
            code=code,
            resource=resource,
            reservation=reservation,
            claim=claim,
        )
    except AuthorityError:
        existing = manager.get_receipt_for_request(str(decision["requestId"]))
        if (
            existing is None
            or existing.get("decisionDigest") != decision.get("decisionDigest")
            or existing.get("result") != expected_result
        ):
            raise
        return existing


def unknown_effect_outcome(
    deployment_id: str, *, code: str | None
) -> dict[str, Any]:
    return {
        "status": "failed",
        "code": "authority_effect_outcome_unknown",
        "summary": "Claimed deployment effect completed without readable exact outcome evidence and requires reconciliation",
        "resource": {
            "deploymentId": deployment_id,
            "effectDisposition": "unknown",
            "reconciliationRequired": True,
            "outcomeReadCode": code,
        },
    }


def finalization_pending(
    exc: AuthorityError,
    *,
    decision: Mapping[str, Any],
    durable_outcome: Mapping[str, Any] | None,
) -> DeploymentError:
    """Classify a post-claim canonical receipt failure without replaying effects."""

    pending = DeploymentError(
        "authority_finalization_pending",
        "deployment effect outcome is durable but canonical authority finalization requires reconciliation",
        details={
            "requestId": decision.get("requestId"),
            "authorityCode": exc.code,
            "effectDisposition": (
                "durably_recorded" if durable_outcome is not None else "unknown"
            ),
            "reconciliationRequired": True,
        },
    )
    existing = getattr(exc, "receipt", None) or getattr(
        exc, "authority_receipt", None
    )
    if isinstance(existing, Mapping):
        setattr(pending, "authority_receipt", dict(existing))
    return pending


def run_governed(
    *,
    manager: AuthorityManager,
    service: DeploymentService,
    actor_id: str,
    grant_id: str | None,
    branch: str,
    action: str,
    deployment_id: str,
    operation: Callable[[Mapping[str, Any]], Mapping[str, Any]],
    slice_id: str | None = None,
    run_id: str | None = None,
    run_id_resolver: Callable[[], str] | None = None,
    source_identity: Mapping[str, Any] | None = None,
    preflight: Callable[[], None] | None = None,
    link: bool = True,
) -> dict[str, Any]:
    """Reserve, execute, and finalize one governed deployment action.

    Every path either returns the operation result with its canonical
    authority receipt (and link) attached, or raises a ``DeploymentError``
    carrying the durable receipt on ``authority_receipt``.  A refused or
    failed action is still receipted as ``not_executed``/``failed``; a
    completed effect whose receipt cannot be finalized raises
    ``authority_finalization_pending`` instead of replaying anything.
    """

    if run_id_resolver is not None:
        if run_id is not None:
            raise ValueError("run_id and run_id_resolver are mutually exclusive")
        try:
            run_id = run_id_resolver()
        except DeploymentError as exc:
            decision, reservation = manager.reserve_action(
                action,
                actor_id=actor_id,
                grant_id=grant_id,
                branch=branch,
                slice_id=slice_id,
                application_id=deployment_id,
                run_id=None,
                paths=(".",),
                estimated_duration_seconds=300,
                assurances=("preflight_only",),
            )
            receipt = record_or_reuse_action(
                manager,
                decision,
                result_status="not_executed",
                summary=f"Deployment action preflight failed before any effect: {exc.code}",
                code=exc.code,
                reservation=reservation,
            )
            setattr(exc, "authority_receipt", receipt)
            raise

    decision, reservation = manager.reserve_action(
        action,
        actor_id=actor_id,
        grant_id=grant_id,
        branch=branch,
        slice_id=slice_id,
        application_id=deployment_id,
        run_id=run_id,
        paths=(".",),
        estimated_duration_seconds=(
            3600 if action in {"plan_deployment", "apply_deployment"} else 300
        ),
        source_identity=source_identity,
    )
    if decision["decision"] != "authorized":
        receipt = record_or_reuse_action(
            manager,
            decision,
            result_status="not_executed",
            summary=f"Deployment action was not executed: {decision['reason']}",
            code=decision["reason"],
        )
        error = DeploymentError(
            "authority_refused",
            "deployment action is outside effective standing authority",
            details={"authorityReceipt": receipt},
        )
        setattr(error, "authority_receipt", receipt)
        raise error

    if preflight is not None:
        try:
            preflight()
        except DeploymentError as exc:
            receipt = record_or_reuse_action(
                manager,
                decision,
                result_status="not_executed",
                summary=(
                    "Deployment action preflight failed before any effect: "
                    f"{exc.code}"
                ),
                code=exc.code,
                reservation=reservation,
            )
            setattr(exc, "authority_receipt", receipt)
            raise

    # A prior process may have completed and finalized an exact action before
    # losing the deployment-side link. Reserve the current request first, then
    # repair that evidence boundary without implicitly replaying the old claim.
    pending_reconciliation: Mapping[str, Any] | None = None
    prior_reconciliation: Mapping[str, Any] | None = None
    try:
        reconciliation = service.reconcile_authority_receipts(deployment_id)
    except DeploymentError as exc:
        unresolved = (
            exc.details.get("unresolved")
            if isinstance(exc.details, Mapping)
            else None
        )
        recoverable_claimed_effect = (
            action
            in {
                "observe_deployment",
                "remove_deployment_runtime",
                "purge_deployment_data",
            }
            and exc.code == "authority_effect_unfinalized"
            and isinstance(unresolved, list)
            and bool(unresolved)
            and all(
                isinstance(item, Mapping)
                and item.get("classification") == "authority_effect_unfinalized"
                and item.get("claimExists") is True
                for item in unresolved
            )
        )
        if recoverable_claimed_effect:
            pending_reconciliation = dict(exc.details)
        elif exc.code == "deployment_not_found":
            pass
        else:
            receipt = record_or_reuse_action(
                manager,
                decision,
                result_status="not_executed",
                summary=f"Deployment action was blocked before effect by authority reconciliation: {exc.code}",
                code=exc.code,
                reservation=reservation,
            )
            setattr(exc, "authority_receipt", receipt)
            raise
    else:
        if reconciliation["links"]:
            prior_reconciliation = reconciliation
    try:
        result = operation(decision)
        if not isinstance(result, Mapping):
            raise DeploymentError(
                "invalid_operation_result",
                "governed deployment operation returned a non-object result",
            )
        result = dict(result)
        if prior_reconciliation is not None:
            result["priorAuthorityReconciliation"] = dict(
                prior_reconciliation
            )
        reconciliation_receipt = result.get("reconciliationReceipt")
        if action == "observe_deployment" and isinstance(
            reconciliation_receipt, Mapping
        ):
            reconciliation_data = reconciliation_receipt.get("data")
            reconciled_request_id = (
                reconciliation_data.get("reconciledAuthorityRequestId")
                if isinstance(reconciliation_data, Mapping)
                else None
            )
            if not isinstance(reconciled_request_id, str):
                raise DeploymentError(
                    "authority_receipt_unbound",
                    "runtime reconciliation did not bind the interrupted authority request",
                )
            result["authorityReconciliation"] = (
                service.reconcile_authority_receipts(
                    deployment_id, request_id=reconciled_request_id
                )
            )
            pending_reconciliation = None
        elif pending_reconciliation is not None:
            if action in {
                "remove_deployment_runtime",
                "purge_deployment_data",
            }:
                reconciled: list[dict[str, Any]] = []
                for unresolved in pending_reconciliation.get("unresolved", []):
                    reconciled.append(
                        service.reconcile_authority_receipts(
                            deployment_id,
                            request_id=unresolved["requestId"],
                        )
                    )
                result["authorityReconciliation"] = {
                    "deploymentId": deployment_id,
                    "reconciled": reconciled,
                }
            else:
                result["authorityEffectPending"] = dict(pending_reconciliation)
    except Exception as exc:
        code = getattr(exc, "code", "operation_failed")
        if not isinstance(code, str):
            code = "operation_failed"
        claimed = manager.has_claim(decision["requestId"])
        durable_outcome: Mapping[str, Any] | None = None
        outcome_read_code: str | None = None
        if claimed:
            try:
                durable_outcome = service.store.authority_effect_outcome(
                    deployment_id, decision["requestId"]
                )
            except DeploymentError as outcome_exc:
                outcome_read_code = outcome_exc.code
        if claimed and durable_outcome is None:
            durable_outcome = unknown_effect_outcome(
                deployment_id,
                code=outcome_read_code or "authority_effect_outcome_missing",
            )
            if isinstance(getattr(exc, "details", None), dict):
                exc.details["authorityEffectDisposition"] = dict(durable_outcome)
        result_status = (
            durable_outcome["status"]
            if durable_outcome is not None
            else "not_executed"
        )
        claim = manager.get_claim(decision["requestId"]) if claimed else None
        try:
            receipt = record_or_reuse_action(
                manager,
                decision,
                result_status=result_status,
                summary=(
                    durable_outcome["summary"]
                    if durable_outcome is not None
                    else f"Authorized deployment action failed with {type(exc).__name__}"
                ),
                code=(
                    durable_outcome["code"] if durable_outcome is not None else code
                ),
                resource=(
                    durable_outcome["resource"]
                    if durable_outcome is not None
                    else None
                ),
                reservation=reservation,
                claim=claim,
            )
        except AuthorityError as finalization_exc:
            if claimed:
                raise finalization_pending(
                    finalization_exc,
                    decision=decision,
                    durable_outcome=durable_outcome,
                ) from finalization_exc
            raise
        if link and claimed:
            try:
                link_result = service.link_authority_receipt(deployment_id, receipt)
                setattr(exc, "authority_link", link_result)
            except DeploymentError as link_exc:
                link_pending = {
                    "receiptId": receipt["receiptId"],
                    "requestId": receipt["requestId"],
                    "code": link_exc.code,
                    "detail": str(link_exc),
                }
                if isinstance(getattr(exc, "details", None), dict):
                    exc.details["authorityLinkPending"] = link_pending
                try:
                    setattr(exc, "authority_link_pending", link_pending)
                except Exception:
                    pass
        try:
            setattr(exc, "authority_receipt", receipt)
        except Exception:
            pass
        raise
    outcome_error: DeploymentError | None = None
    try:
        durable_outcome = service.store.authority_effect_outcome(
            deployment_id, decision["requestId"]
        )
    except DeploymentError as exc:
        durable_outcome = unknown_effect_outcome(
            deployment_id, code=exc.code
        )
        outcome_error = DeploymentError(
            "authority_effect_outcome_unknown",
            "deployment action returned but its exact durable authority outcome could not be read",
            details={"requestId": decision["requestId"], "outcomeCode": exc.code},
        )
    if durable_outcome is None:
        durable_outcome = unknown_effect_outcome(
            deployment_id, code="authority_effect_outcome_missing"
        )
        outcome_error = DeploymentError(
            "authority_effect_unfinalized",
            "deployment action returned without one exact durable successful authority outcome",
            details={"requestId": decision["requestId"]},
        )
    elif durable_outcome["status"] != "succeeded" and outcome_error is None:
        outcome_error = DeploymentError(
            "authority_effect_unfinalized",
            "deployment action returned with a non-success terminal authority outcome",
            details={"requestId": decision["requestId"]},
        )
    try:
        receipt = record_or_reuse_action(
            manager,
            decision,
            result_status=durable_outcome["status"],
            summary=durable_outcome["summary"],
            code=durable_outcome["code"],
            resource=durable_outcome["resource"],
            reservation=reservation,
            claim=manager.get_claim(decision["requestId"]),
        )
    except AuthorityError as exc:
        raise finalization_pending(
            exc,
            decision=decision,
            durable_outcome=durable_outcome,
        ) from exc
    if link:
        try:
            link_result = service.link_authority_receipt(deployment_id, receipt)
        except DeploymentError as exc:
            pending = DeploymentError(
                "authority_link_pending",
                "deployment action completed but its canonical receipt link requires reconciliation",
                details={
                    "authorityReceipt": receipt,
                    "linkCode": exc.code,
                    "linkDetail": str(exc),
                },
            )
            setattr(pending, "authority_receipt", receipt)
            raise pending from exc
    else:
        link_result = None
    if outcome_error is not None:
        setattr(outcome_error, "authority_receipt", receipt)
        if link_result is not None:
            setattr(outcome_error, "authority_link", link_result)
        raise outcome_error
    return attach_authority(result, receipt, link_result)


__all__ = [
    "attach_authority",
    "checked_out_branch",
    "finalization_pending",
    "record_or_reuse_action",
    "run_governed",
    "unknown_effect_outcome",
]
