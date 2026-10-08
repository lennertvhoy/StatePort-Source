"""Deployment, standing-authority, and updater surfaces for the web AppServer.

The web service exposes the same governed deployment lifecycle the admin CLI
drives, the operator's standing-authority policy/grant state, and the
installed updater's durable status as session-gated, CSRF-guarded HTTP
routes.  Every deployment effect crosses the canonical authority boundary
through :func:`stateport_deployment.governed.run_governed` — the exact
single implementation shared with the CLI — so receipts, reservations, and
refusals are identical no matter which surface the operator uses, then crosses
the confined execution-host socket rather than a control-plane engine socket.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
from typing import Any, Callable, Mapping

from governed_runner.authority import AuthorityError, AuthorityManager
from stateport_deployment import DeploymentError, DeploymentService
from stateport_deployment.governed import checked_out_branch, run_governed
from stateport_deployment.inspection import authority_source_identity
from stateport_deployment.store import DeploymentStore
from stateport_deployment.util import default_state_root
from stateport_release import (
    canonical_digest,
    update_policy_digest,
    validate_update_status,
)
from stateport_updater import control_plane
from stateport_updater.authority import UpdateAuthorityError
from stateport_updater.engine import (
    TARGET_ID,
    UpdateEngine,
    UpdateError,
    historic_verification_policy,
)
from stateport_updater.installed import InstalledAuthorityAdapter
from stateport_updater.models import ContractError, UpdatePolicy
from stateport_updater.service import UpdaterServiceError
from stateport_updater.store import StoreError, UpdateStore, project_update_status


_PUBLIC_CODE = re.compile(r"[a-z][a-z0-9_]{0,127}\Z")
_DEPLOYMENT_ID = re.compile(r"[a-z0-9][a-z0-9._-]{1,127}\Z")
_GRANT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{1,127}\Z")
_OWNER_DIRECTIVE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}\Z")
_SHA256_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_REASON = 1024


class PlatformSurfaceError(ValueError):
    """Typed refusal for the platform service surface."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def public_error_code(exc: Exception, fallback: str = "operation_refused") -> str:
    """Expose only bounded typed codes from platform service failures."""

    code = getattr(exc, "code", None)
    if isinstance(code, str) and _PUBLIC_CODE.fullmatch(code):
        return code
    return fallback


def deployment_id(value: object) -> str:
    if not isinstance(value, str) or _DEPLOYMENT_ID.fullmatch(value) is None:
        raise PlatformSurfaceError("invalid_identity", "deployment identity is invalid")
    return value


def grant_id(value: object) -> str:
    if not isinstance(value, str) or _GRANT_ID.fullmatch(value) is None:
        raise PlatformSurfaceError("invalid_identity", "authority grant identity is invalid")
    return value


def optional_slice_id(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or _GRANT_ID.fullmatch(value) is None:
        raise PlatformSurfaceError("invalid_identity", "authority slice identity is invalid")
    return value


def bounded_text(value: object, label: str, *, maximum: int = 4096) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or "\x00" in value
    ):
        raise PlatformSurfaceError("invalid_contract", f"{label} is invalid")
    return value


def deployment_project_path(value: object) -> str:
    """Bind browser-submitted deployment sources to the owned project inbox."""

    text = bounded_text(value, "deployment project path")
    root = Path(
        os.environ.get(
            "STATEPORT_DEPLOYMENT_PROJECT_ROOT", "/var/lib/stateport/deployments"
        )
    )
    candidate = Path(text)
    if (
        not root.is_absolute()
        or not candidate.is_absolute()
        or root.is_symlink()
        or candidate.is_symlink()
    ):
        raise PlatformSurfaceError(
            "unsafe_path", "deployment project path is outside the owned project inbox"
        )
    try:
        root = root.resolve(strict=True)
        candidate = candidate.resolve(strict=True)
        candidate.relative_to(root)
    except (OSError, ValueError) as exc:
        raise PlatformSurfaceError(
            "unsafe_path", "deployment project path is outside the owned project inbox"
        ) from exc
    return str(candidate)


def digest_text(value: object, label: str) -> str:
    digest = bounded_text(value, label, maximum=71)
    if _SHA256_DIGEST.fullmatch(digest) is None:
        raise PlatformSurfaceError("invalid_contract", f"{label} must be sha256:<64hex>")
    return digest


def _successful_authority_receipt(
    receipt: object,
    *,
    actor_id: str,
    resource: Mapping[str, object],
) -> Mapping[str, object]:
    if not isinstance(receipt, Mapping):
        raise PlatformSurfaceError("authority_receipt_invalid", "authority mutation returned no receipt")
    authorized_by = receipt.get("authorizedBy")
    result = receipt.get("result")
    actual_resource = result.get("resource") if isinstance(result, Mapping) else None
    if (
        receipt.get("schema") != "stateport.authority-action-receipt/v1"
        or receipt.get("actorId") != actor_id
        or receipt.get("action") != "modify_authority_policy"
        or receipt.get("decision") != "authorized"
        or not isinstance(receipt.get("receiptDigest"), str)
        or not _SHA256_DIGEST.fullmatch(receipt["receiptDigest"])
        or not isinstance(receipt.get("decisionDigest"), str)
        or not _SHA256_DIGEST.fullmatch(receipt["decisionDigest"])
        or not isinstance(authorized_by, Mapping)
        or authorized_by.get("type") != "owner_directive"
        or not isinstance(result, Mapping)
        or result.get("status") != "succeeded"
        or not isinstance(actual_resource, Mapping)
        or any(actual_resource.get(key) != value for key, value in resource.items())
    ):
        raise PlatformSurfaceError(
            "authority_receipt_invalid",
            "authority mutation receipt is not a successful bound receipt",
        )
    return receipt


def require_digest_approval(
    server: Any,
    body: Mapping[str, object],
    expected_digest: str,
) -> None:
    """Bind one mutation to the exact artifact digest the operator approved."""

    expected = digest_text(expected_digest, "reviewed digest")
    approval = body.get("approval")
    if (
        not isinstance(approval, dict)
        or set(approval) != {"decision", "actorId", "proposalDigest"}
        or approval.get("decision") != "approve"
        or approval.get("actorId") != server.actor_id
    ):
        raise PlatformSurfaceError(
            "approval_required",
            "an exact local-operator approval is required",
        )
    proposal_digest = digest_text(approval.get("proposalDigest"), "proposal digest")
    if proposal_digest != expected:
        raise PlatformSurfaceError(
            "approval_digest_mismatch",
            "approval does not match the exact artifact digest",
        )


# ---------------------------------------------------------------------------
# Lazy service wiring on the AppServer
# ---------------------------------------------------------------------------


def authority_manager(server: Any) -> AuthorityManager:
    """Resolve the canonical standing-authority manager for this checkout."""

    manager = getattr(server, "_authority_manager", None)
    if manager is None:
        manager = AuthorityManager(server.product_root)
        server._authority_manager = manager
    return manager


def deployment_service(server: Any) -> DeploymentService:
    """Resolve the governed deployment service bound to canonical authority."""

    service = getattr(server, "_deployment_service", None)
    if service is None:
        service = DeploymentService(
            state_root=None,
            adapter=server.execution_host.deployment_adapter(),
            authority_manager=authority_manager(server),
            actor=server.actor_id,
        )
        server._deployment_service = service
    return service


def deployment_store(server: Any, *, create: bool = False) -> DeploymentStore:
    root = default_state_root()
    if not create and not (root / "records").is_dir():
        raise PlatformSurfaceError(
            "deployment_state_unavailable",
            "no durable deployment state exists on this host",
        )
    return DeploymentStore(root, create=create)


def updater_state_root(server: Any) -> Path:
    """Resolve the installed updater state root without ever creating it."""

    import os

    override = os.environ.get("STATEPORT_UPDATER_STATE_ROOT", "").strip()
    root = Path(override) if override else server.layout.state_root / "updater"
    if not root.is_absolute():
        raise PlatformSurfaceError(
            "updater_state_unavailable", "updater state root must be absolute"
        )
    return root


def updater_store(server: Any) -> UpdateStore:
    root = updater_state_root(server)
    if not (root / "status.json").is_file() or (root / "status.json").is_symlink():
        raise PlatformSurfaceError(
            "updater_state_unavailable",
            "no installed updater state exists on this host",
        )
    try:
        return UpdateStore.open_existing(root)
    except StoreError as exc:
        raise PlatformSurfaceError(
            "updater_state_unavailable", "installed updater state is unreadable"
        ) from exc


# ---------------------------------------------------------------------------
# Deployment projections and governed mutations
# ---------------------------------------------------------------------------


def _deployment_summary(state: Mapping[str, Any]) -> dict[str, Any]:
    transition = state.get("currentTransition")
    return {
        "deploymentId": state["deploymentId"],
        "lifecycleState": state["lifecycleState"],
        "driftStatus": state.get("driftStatus"),
        "desiredRevision": state.get("desiredRevision"),
        "approvedPlanDigest": state.get("approvedPlanDigest"),
        "acceptedRevision": state.get("acceptedRevision"),
        "observedRevision": state.get("observedRevision"),
        "rollback": state.get("rollback"),
        "retainedDataState": state.get("retainedDataState"),
        "currentOperation": (
            transition.get("operation") if isinstance(transition, Mapping) else None
        ),
        "serviceHealth": state.get("serviceHealth"),
    }


def deployments_index(server: Any) -> dict[str, object]:
    try:
        store = deployment_store(server)
    except PlatformSurfaceError as exc:
        if exc.code == "deployment_state_unavailable":
            return {
                "formatVersion": "stateport.deployment-index/v1",
                "deployments": [],
            }
        raise
    states = store.list_states()
    return {
        "formatVersion": "stateport.deployment-index/v1",
        "deployments": [_deployment_summary(state) for state in states],
    }


def deployment_detail(server: Any, identity: str) -> dict[str, object]:
    selected = deployment_id(identity)
    try:
        store = deployment_store(server)
    except PlatformSurfaceError as exc:
        if exc.code == "deployment_state_unavailable":
            raise PlatformSurfaceError(
                "deployment_not_found", f"deployment does not exist: {selected}"
            ) from exc
        raise
    return {"state": store.load_state(selected)}


def _governed(
    server: Any,
    *,
    action: str,
    identity: str,
    grant: object,
    slice_identity: object = None,
    operation: Callable[[Mapping[str, Any]], Mapping[str, Any]],
    run_id: str | None = None,
    run_id_resolver: Callable[[], str] | None = None,
    source_identity: Mapping[str, Any] | None = None,
    preflight: Callable[[], None] | None = None,
) -> dict[str, Any]:
    manager = authority_manager(server)
    try:
        branch = checked_out_branch(manager)
    except (ValueError, OSError) as exc:
        raise PlatformSurfaceError(
            "repository_identity_uncertain",
            "deployment authority requires an exact checked-out branch",
        ) from exc
    return run_governed(
        manager=manager,
        service=deployment_service(server),
        actor_id=server.actor_id,
        grant_id=grant_id(grant),
        branch=branch,
        action=action,
        deployment_id=deployment_id(identity),
        operation=operation,
        slice_id=optional_slice_id(slice_identity),
        run_id=run_id,
        run_id_resolver=run_id_resolver,
        source_identity=source_identity,
        preflight=preflight,
    )


def plan_deployment(
    server: Any,
    *,
    project: object,
    identity: object,
    grant: object,
    slice_identity: object = None,
    rollback_of: object = None,
) -> dict[str, Any]:
    """Plan an exact apply, update, or rollback from one inspected project."""

    project_path = deployment_project_path(project)
    if rollback_of is not None:
        rollback_of = digest_text(rollback_of, "rollback revision digest")
    manager = authority_manager(server)
    service = deployment_service(server)
    try:
        state = service.store.load_state(deployment_id(identity))
    except DeploymentError as exc:
        if public_error_code(exc) != "deployment_not_found":
            raise
        state = None
    # A healthy or degraded accepted revision updates through the exact
    # revision-update contract; anything else plans a fresh apply.
    updating = state is not None and state.get("lifecycleState") in {
        "healthy",
        "degraded",
    }
    inspected, inspection_receipt = manager.execute(
        "inspect_repository",
        lambda: service.inspect(project_path),
        actor_id=server.actor_id,
        grant_id=grant_id(grant),
        branch=checked_out_branch(manager),
        slice_id=optional_slice_id(slice_identity),
        application_id=deployment_id(identity),
        resource_from_result=lambda value: {
            "sourceIdentity": authority_source_identity(value),
            "sideEffects": value["sideEffects"],
        },
    )
    source_identity = authority_source_identity(inspected)
    result = _governed(
        server,
        action="plan_deployment",
        identity=identity,
        grant=grant,
        slice_identity=slice_identity,
        source_identity=source_identity,
        preflight=lambda: service.assert_state_root_separate(inspected),
        operation=lambda decision: (
            service.plan_update(
                project_path,
                deployment_id=deployment_id(identity),
                grant_id=decision["authorizedBy"]["id"],
                authority_decision=decision,
                rollback_of=rollback_of,
            )
            if rollback_of is not None or updating
            else service.plan(
                project_path,
                deployment_id=deployment_id(identity),
                grant_id=decision["authorizedBy"]["id"],
                authority_decision=decision,
            )
        ),
    )
    result["inspectionAuthorityReceipt"] = inspection_receipt
    return result


def apply_plan(
    server: Any,
    *,
    identity: object,
    accept_plan_digest: object,
    grant: object,
    slice_identity: object = None,
) -> dict[str, Any]:
    """Approve and apply one exact plan, dispatching on its operation."""

    digest = digest_text(accept_plan_digest, "accepted plan digest")
    service = deployment_service(server)
    plan = service.store.load_plan(
        deployment_id(identity), digest, require_unexpired=False
    )
    operation_name = plan.get("operation")
    if operation_name == "apply":
        action, operation = "apply_deployment", lambda decision: service.apply(
            deployment_id(identity),
            accept_plan_digest=digest,
            authority_decision=decision,
        )
    elif operation_name in {"update", "rollback"}:
        action, operation = "apply_deployment", lambda decision: service.apply_update(
            deployment_id(identity),
            accept_plan_digest=digest,
            authority_decision=decision,
        )
    elif operation_name in {"backup_data", "restore_data"}:
        action = (
            "backup_deployment_data"
            if operation_name == "backup_data"
            else "restore_deployment_data"
        )
        operation = lambda decision: service.apply_data_plan(
            deployment_id(identity),
            accept_plan_digest=digest,
            authority_decision=decision,
        )
    elif operation_name == "purge_data":
        action, operation = "purge_deployment_data", lambda decision: service.purge_data(
            deployment_id(identity),
            accept_plan_digest=digest,
            authority_decision=decision,
        )
    else:
        raise PlatformSurfaceError(
            "invalid_contract", "the bound plan operation is unsupported"
        )
    return _governed(
        server,
        action=action,
        identity=identity,
        grant=grant,
        slice_identity=slice_identity,
        run_id=digest,
        operation=operation,
    )


def reject_plan(
    server: Any,
    *,
    identity: object,
    plan_digest: object,
    grant: object,
    slice_identity: object = None,
) -> dict[str, Any]:
    """Reject one exact pending revision proposal without a runtime effect."""

    digest = digest_text(plan_digest, "rejected plan digest")
    service = deployment_service(server)
    return _governed(
        server,
        action="plan_deployment",
        identity=identity,
        grant=grant,
        slice_identity=slice_identity,
        run_id=digest,
        operation=lambda decision: service.reject_plan(
            deployment_id(identity),
            plan_digest=digest,
            authority_decision=decision,
        ),
    )


def observe_deployment(
    server: Any, *, identity: object, grant: object, slice_identity: object = None
) -> dict[str, Any]:
    service = deployment_service(server)
    return _governed(
        server,
        action="observe_deployment",
        identity=identity,
        grant=grant,
        slice_identity=slice_identity,
        run_id_resolver=lambda: service.peek_authority_run_id(
            deployment_id(identity), "observe_deployment"
        ),
        operation=lambda decision: service.status(
            deployment_id(identity), authority_decision=decision
        ),
    )


def deployment_logs(
    server: Any,
    *,
    identity: object,
    grant: object,
    slice_identity: object = None,
    service_id: object = None,
    tail: object = None,
) -> dict[str, Any]:
    service = deployment_service(server)
    if service_id is not None:
        service_id = bounded_text(service_id, "deployment service identity", maximum=128)
    if tail is None:
        tail_lines = 200
    elif isinstance(tail, bool) or not isinstance(tail, int) or not 1 <= tail <= 5000:
        raise PlatformSurfaceError("invalid_contract", "log tail bound is invalid")
    else:
        tail_lines = tail
    return _governed(
        server,
        action="collect_deployment_logs",
        identity=identity,
        grant=grant,
        slice_identity=slice_identity,
        run_id_resolver=lambda: service.peek_authority_run_id(
            deployment_id(identity), "collect_deployment_logs"
        ),
        operation=lambda decision: service.logs(
            deployment_id(identity),
            authority_decision=decision,
            service_id=service_id,
            tail=tail_lines,
        ),
    )


def restart_deployment(
    server: Any, *, identity: object, grant: object, slice_identity: object = None
) -> dict[str, Any]:
    service = deployment_service(server)
    return _governed(
        server,
        action="restart_deployment",
        identity=identity,
        grant=grant,
        slice_identity=slice_identity,
        run_id_resolver=lambda: service.peek_authority_run_id(
            deployment_id(identity), "restart_deployment"
        ),
        operation=lambda decision: service.restart(
            deployment_id(identity), authority_decision=decision
        ),
    )


def remove_deployment(
    server: Any, *, identity: object, grant: object, slice_identity: object = None
) -> dict[str, Any]:
    service = deployment_service(server)
    return _governed(
        server,
        action="remove_deployment_runtime",
        identity=identity,
        grant=grant,
        slice_identity=slice_identity,
        run_id_resolver=lambda: service.peek_authority_run_id(
            deployment_id(identity), "remove_deployment_runtime"
        ),
        operation=lambda decision: service.remove(
            deployment_id(identity), authority_decision=decision
        ),
    )


def plan_purge(server: Any, *, identity: object, grant: object, slice_identity: object = None) -> dict[str, Any]:
    service = deployment_service(server)
    return _governed(
        server,
        action="plan_deployment",
        identity=identity,
        grant=grant,
        slice_identity=slice_identity,
        run_id_resolver=lambda: service.peek_authority_run_id(
            deployment_id(identity), "plan_deployment"
        ),
        operation=lambda decision: service.plan_purge(
            deployment_id(identity), authority_decision=decision
        ),
    )


def plan_backup(
    server: Any,
    *,
    identity: object,
    grant: object,
    slice_identity: object = None,
) -> dict[str, Any]:
    service = deployment_service(server)
    return _governed(
        server,
        action="plan_deployment",
        identity=identity,
        grant=grant,
        slice_identity=slice_identity,
        run_id_resolver=lambda: service.peek_authority_run_id(
            deployment_id(identity), "plan_deployment"
        ),
        operation=lambda decision: service.plan_backup(
            deployment_id(identity), authority_decision=decision
        ),
    )


def plan_restore(
    server: Any,
    *,
    identity: object,
    backup: object,
    grant: object,
    slice_identity: object = None,
) -> dict[str, Any]:
    service = deployment_service(server)
    backup_id = bounded_text(backup, "deployment backup identity", maximum=128)
    return _governed(
        server,
        action="plan_deployment",
        identity=identity,
        grant=grant,
        slice_identity=slice_identity,
        run_id_resolver=lambda: service.peek_authority_run_id(
            deployment_id(identity), "plan_deployment"
        ),
        operation=lambda decision: service.plan_restore(
            deployment_id(identity),
            backup_id=backup_id,
            authority_decision=decision,
        ),
    )


# ---------------------------------------------------------------------------
# Standing-authority projections and mutations
# ---------------------------------------------------------------------------


def authority_profiles(server: Any) -> dict[str, object]:
    policy = authority_manager(server).policy
    return {
        "formatVersion": "stateport.authority-profile-index/v1",
        "schema": "stateport.authority-policy/v1",
        "defaultProfile": policy.default_profile,
        "policyDigest": policy.policy_digest,
        "actionPolicies": {key: dict(value) for key, value in policy.actions.items()},
        "profiles": {key: dict(value) for key, value in policy.profiles.items()},
        "hardDeny": sorted(policy.hard_deny),
        "mergeRequirements": sorted(policy.merge_requirements),
        "subagentDefaultDeny": sorted(policy.subagent_default_deny),
        "escalationConditions": list(policy.escalation_conditions),
    }


def authority_grants(server: Any) -> dict[str, object]:
    """Project grants, pause control, and recent receipted authority actions."""

    projection = authority_manager(server).inspect()
    control = projection.get("control")
    return {**projection, "paused": bool(control.get("paused")) if isinstance(control, Mapping) else False}


def authority_index(server: Any) -> dict[str, object]:
    """Project the one canonical authority snapshot used for operator review."""

    require_platform_operator(server)
    return authority_manager(server).authority_index()


def require_platform_operator(server: Any) -> None:
    """Keep the standing-authority control plane out of local-user sessions."""

    if getattr(server, "actor_role", None) != "platform_operator":
        raise PermissionError("platform operator role is required")


def require_platform_operator_for_path(server: Any, path: str) -> None:
    """Guard every HTTP projection backed by local platform host state."""

    if path in {"/v1/deployments", "/v1/authority", "/v1/updater", "/v1/preview-routes"} or path.startswith(
        ("/v1/deployments/", "/v1/authority/", "/v1/updater/", "/v1/preview-routes/", "/v1/platform/")
    ):
        require_platform_operator(server)


def authority_grant_detail(server: Any, identity: object) -> dict[str, object]:
    manager = authority_manager(server)
    selected = grant_id(identity)
    index = manager.list_grants()
    for grant in index["grants"]:
        if grant.get("grantId") == selected:
            return {
                "grant": grant,
                "paused": index["paused"],
                "repository": index["repository"],
            }
    raise PlatformSurfaceError(
        "grant_not_found", "authority grant does not exist on this host"
    )


def revoke_grant(
    server: Any,
    *,
    identity: object,
    owner_directive_id: object,
    reason: object,
    expected_grant_digest: object,
) -> dict[str, object]:
    require_platform_operator(server)
    manager = authority_manager(server)
    detail = authority_grant_detail(server, identity)
    digest = detail["grant"].get("grantDigest")
    if not isinstance(digest, str):
        raise PlatformSurfaceError(
            "invalid_authority_state", "authority grant digest is unavailable"
        )
    directive = bounded_text(owner_directive_id, "owner directive identity", maximum=128)
    if _OWNER_DIRECTIVE_ID.fullmatch(directive) is None:
        raise PlatformSurfaceError(
            "invalid_contract", "owner directive identity is invalid"
        )
    text = bounded_text(reason, "revocation reason", maximum=_MAX_REASON)
    reviewed_digest = digest_text(expected_grant_digest, "authority grant digest")
    result = manager.revoke_grant(
        grant_id(identity),
        actor_id=server.actor_id,
        owner_directive_id=directive,
        reason=text,
        expected_grant_digest=reviewed_digest,
    )
    receipt = _successful_authority_receipt(
        result.get("receipt"),
        actor_id=server.actor_id,
        resource={
            "grantId": grant_id(identity),
            "revocationDigest": result["revocation"]["revocationDigest"],
        },
    )
    return {
        "revocation": result["revocation"],
        "revokedGrantDigest": reviewed_digest,
        "receipt": receipt,
        "receiptId": receipt.get("receiptId") if isinstance(receipt, Mapping) else None,
        "receiptDigest": receipt.get("receiptDigest") if isinstance(receipt, Mapping) else None,
    }


def set_authority_paused(
    server: Any,
    *,
    paused: object,
    owner_directive_id: object,
    reason: object,
    expected_control_digest: object,
) -> dict[str, object]:
    require_platform_operator(server)
    if not isinstance(paused, bool):
        raise PlatformSurfaceError("invalid_contract", "pause state must be boolean")
    directive = bounded_text(owner_directive_id, "owner directive identity", maximum=128)
    if _OWNER_DIRECTIVE_ID.fullmatch(directive) is None:
        raise PlatformSurfaceError(
            "invalid_contract", "owner directive identity is invalid"
        )
    text = bounded_text(reason, "pause reason", maximum=_MAX_REASON)
    reviewed_digest = digest_text(expected_control_digest, "authority control digest")
    result = authority_manager(server).set_paused(
        paused=paused,
        actor_id=server.actor_id,
        owner_directive_id=directive,
        reason=text,
        expected_control_digest=reviewed_digest,
    )
    receipt = _successful_authority_receipt(
        result.get("receipt"),
        actor_id=server.actor_id,
        resource={"paused": paused, "controlDigest": result["control"]["controlDigest"]},
    )
    return {
        "control": result["control"],
        "receipt": receipt,
        "receiptId": receipt.get("receiptId") if isinstance(receipt, Mapping) else None,
        "receiptDigest": receipt.get("receiptDigest") if isinstance(receipt, Mapping) else None,
    }


# ---------------------------------------------------------------------------
# Installed updater projections and gated mutations
# ---------------------------------------------------------------------------


def _updater_snapshot(server: Any) -> tuple[dict[str, Any], dict[str, Any] | None]:
    try:
        return updater_store(server).snapshot()
    except StoreError as exc:
        raise PlatformSurfaceError(
            public_error_code(exc, "updater_state_unavailable"),
            "installed updater state is unavailable",
        ) from exc


def updater_status(server: Any) -> dict[str, object]:
    status, pending = _updater_snapshot(server)
    try:
        validated = validate_update_status(project_update_status(status, pending))
    except ValueError as exc:
        raise PlatformSurfaceError(
            "updater_state_invalid", "installed updater status is invalid"
        ) from exc
    return validated.as_dict()


def updater_policy(server: Any) -> dict[str, object]:
    status, _pending = _updater_snapshot(server)
    return {
        "formatVersion": "stateport.updater-policy/v1",
        "policy": status["policy"],
        "statusDigest": canonical_digest(status),
    }


def updater_rollback(server: Any) -> dict[str, object]:
    status, pending = _updater_snapshot(server)
    projected = project_update_status(status, pending)
    retained = status.get("retainedPredecessor")
    return {
        "formatVersion": "stateport.updater-rollback/v1",
        "phase": projected["phase"],
        "pendingPhase": None if pending is None else str(pending["phase"]),
        "retainedPredecessor": dict(retained) if isinstance(retained, Mapping) else None,
        "rollbackAvailable": isinstance(retained, Mapping) and pending is None,
        "statusDigest": canonical_digest(status),
    }


def set_updater_policy(
    server: Any,
    *,
    policy: object,
    expected_status_digest: object,
) -> dict[str, object]:
    """Modify the installed update policy through canonical installed authority."""

    digest = digest_text(expected_status_digest, "expected status digest")
    if not isinstance(policy, Mapping):
        raise PlatformSurfaceError("policy_invalid", "update policy must be an object")
    # The operator reviews mode/channel/schedule/retention; the service binds
    # the exact policy digest so a client never has to compute it.
    candidate = {key: value for key, value in policy.items() if key != "policyDigest"}
    candidate["policyDigest"] = update_policy_digest(candidate)
    try:
        selected = UpdatePolicy.from_mapping(candidate)
    except ContractError as exc:
        raise PlatformSurfaceError(
            public_error_code(exc, "policy_invalid"), str(exc)[:512]
        ) from exc
    store = updater_store(server)
    adapter = InstalledAuthorityAdapter(store)
    # Policy mutation never touches the host or signature verifier; the CLI
    # constructs the engine the same way for `policy set`.
    engine = UpdateEngine(
        store,
        object(),
        adapter,
        verification_policy=historic_verification_policy(store),
        signature_verifier=object(),
    )
    try:
        changed = engine.set_policy(
            selected,
            expected_status_digest=digest,
            mutate=adapter.execute_scoped,
        )
        return changed
    except (UpdateError, StoreError) as exc:
        raise PlatformSurfaceError(
            public_error_code(exc, "updater_error"), str(exc)[:512]
        ) from exc


def updater_control_plane(server: Any) -> Any:
    """Resolve the validated installed control-plane binding for this host.

    Rollback planning re-verifies historic release signatures, so it requires
    the same pinned-trust binding the installed updater CLI uses.  Without a
    durable trust root the surface refuses typed instead of degrading trust.
    """

    binding = getattr(server, "_updater_control_plane", None)
    if binding is None:
        try:
            binding = control_plane.build(updater_state_root(server)).validated(
                expected_target=TARGET_ID
            )
        except UpdateAuthorityError as exc:
            raise PlatformSurfaceError(
                public_error_code(exc, "installed_authority_adapter_required"),
                "the installed updater control plane is unavailable on this host",
            ) from exc
        server._updater_control_plane = binding
    return binding


def plan_updater_rollback(
    server: Any, *, expected_status_digest: object
) -> dict[str, object]:
    """Plan the exact retained-predecessor rollback for the observed status."""

    digest = digest_text(expected_status_digest, "expected status digest")
    status, pending = _updater_snapshot(server)
    if canonical_digest(status) != digest:
        raise PlatformSurfaceError(
            "approval_digest_mismatch",
            "updater status changed; observe it again before planning a rollback",
        )
    if pending is not None:
        raise PlatformSurfaceError(
            "interrupted_update_requires_reconciliation",
            "a pending update must be reconciled before a rollback can be planned",
        )
    binding = updater_control_plane(server)
    store = updater_store(server)
    adapter = InstalledAuthorityAdapter(store, clock=binding.clock)
    engine = UpdateEngine(
        store,
        binding.host,
        adapter,
        verification_policy=binding.verification_policy,
        signature_verifier=binding.signature_verifier,
        clock=binding.clock,
    )
    try:
        plan = engine.plan(operation="rollback")
    except (UpdateError, StoreError) as exc:
        raise PlatformSurfaceError(
            public_error_code(exc, "updater_error"), str(exc)[:512]
        ) from exc
    return {
        "plan": plan,
        "applyBoundary": "installed-authority-cli",
        "note": (
            "applying the rollback plan remains reserved to the installed "
            "updater authority boundary (stateport-updater apply/rollback)"
        ),
    }


__all__ = [
    "PlatformSurfaceError",
    "apply_plan",
    "authority_grant_detail",
    "authority_grants",
    "authority_manager",
    "authority_profiles",
    "deployment_detail",
    "deployment_logs",
    "deployment_project_path",
    "deployment_service",
    "digest_text",
    "deployments_index",
    "observe_deployment",
    "plan_deployment",
    "plan_purge",
    "plan_updater_rollback",
    "public_error_code",
    "require_platform_operator",
    "require_platform_operator_for_path",
    "remove_deployment",
    "require_digest_approval",
    "restart_deployment",
    "revoke_grant",
    "set_authority_paused",
    "set_updater_policy",
    "updater_policy",
    "updater_rollback",
    "updater_status",
    "updater_store",
]
