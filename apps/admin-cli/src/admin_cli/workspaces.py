"""CLI adapter for the canonical governed workspace lifecycle manager."""

from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
import sys
from typing import Any, Mapping

from governed_runner.authority import AuthorityError, AuthorityManager
from governed_runner.workspaces import WorkspaceLifecycleError, WorkspaceLifecycleManager


def _timestamp(value: str | None) -> datetime | None:
    if value is None:
        return None
    if not value.endswith("Z"):
        raise ValueError("timestamps must be UTC values ending in Z")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return parsed


def workspace_cmd(args: Any) -> int:
    """Run one workspace lifecycle command and emit a typed JSON result."""

    try:
        manager = WorkspaceLifecycleManager(
            Path(args.repository),
            state_root=Path(args.state_root) if args.state_root else None,
        )
        authority = AuthorityManager(
            Path(args.repository),
            state_root=Path(args.authority_state_root) if args.authority_state_root else None,
            policy_path=Path(args.authority_policy) if args.authority_policy else None,
        )
        command = args.workspace_command
        actor_id = args.actor_id or getattr(args, "owner_agent_id", None) or "local-operator"

        def attach(result: Any, receipt: Mapping[str, Any]) -> dict[str, Any]:
            if isinstance(result, Mapping):
                return {**dict(result), "authorityReceipt": dict(receipt)}
            return {"result": result, "authorityReceipt": dict(receipt)}

        if command == "inventory":
            operation, receipt = authority.execute(
                "inspect_repository",
                lambda: manager.audit(slice_id=args.slice_id, record=args.record),
                actor_id=actor_id,
                grant_id=args.grant_id,
                slice_id=args.slice_id,
                resource_from_result=lambda value: {"auditSchema": value["schema"], "ok": value["ok"]},
            )
            result = attach(operation, receipt)
        elif command == "classify":
            operation, receipt = authority.execute(
                "classify_workspace",
                lambda: manager.classify_workspace(
                    args.worktree,
                    classification=args.classification,
                    reason=args.reason,
                    head_policy=args.head_policy,
                    expires_at=_timestamp(args.expires_at),
                ),
                actor_id=actor_id,
                grant_id=args.grant_id,
                resource_from_result=lambda value: {
                    "classification": value["classification"],
                    "worktreeStateDigest": value["stateDigest"],
                },
            )
            result = attach(operation, receipt)
        elif command == "create":
            operation, receipt = authority.execute(
                "create_managed_worktree",
                lambda: manager.create_workspace(
                    slice_id=args.slice_id,
                    owner_agent_id=args.owner_agent_id,
                    branch=args.branch,
                    workspace_name=args.workspace_name,
                    purpose=args.purpose,
                    base_ref=args.base_ref,
                    duration_seconds=args.duration_seconds,
                ),
                actor_id=actor_id,
                grant_id=args.grant_id,
                branch=args.branch,
                slice_id=args.slice_id,
                estimated_duration_seconds=args.duration_seconds or manager.budget.default_duration_seconds,
                resource_from_result=lambda value: {
                    "leaseId": value["leaseId"],
                    "branch": value["branch"],
                    "creationReceipt": value["creationReceipt"],
                },
            )
            result = attach(operation, receipt)
        elif command == "lease":
            lease = manager.get_lease(args.lease_id)
            operation, receipt = authority.execute(
                "inspect_repository",
                lambda: lease,
                actor_id=actor_id,
                grant_id=args.grant_id,
                branch=lease["branch"],
                slice_id=lease["sliceId"],
                resource_from_result=lambda value: {"leaseId": value["leaseId"], "status": value["status"]},
            )
            result = attach(operation, receipt)
        elif command == "export-evidence":
            lease = manager.get_lease(args.lease_id)
            artifacts = {
                "testReceipts": args.test_receipt,
                "browserJourneyEvidence": args.browser_evidence,
                "generatedArtifacts": args.generated_artifact,
                "stateBenchTrace": args.statebench_trace,
                "subagentResult": args.subagent_result,
            }
            operation, receipt = authority.execute(
                "export_workspace_evidence",
                lambda: manager.export_evidence(args.lease_id, artifacts=artifacts),
                actor_id=actor_id,
                grant_id=args.grant_id,
                branch=lease["branch"],
                slice_id=lease["sliceId"],
                resource_from_result=lambda value: {
                    "leaseId": value["leaseId"],
                    "manifestDigest": value["manifestDigest"],
                },
            )
            result = attach(operation, receipt)
        elif command == "close":
            lease = manager.get_lease(args.lease_id)
            operation, receipt = authority.execute(
                "retire_owned_worktree",
                lambda: manager.close_workspace(
                    args.lease_id,
                    disposition=args.disposition,
                    integration_ref=args.integration_ref,
                    exception_reason=args.exception_reason,
                    exception_expires_at=_timestamp(args.exception_expires_at),
                ),
                actor_id=actor_id,
                grant_id=args.grant_id,
                branch=lease["branch"],
                slice_id=lease["sliceId"],
                resource_from_result=lambda value: {
                    "leaseId": value["leaseId"],
                    "status": value["status"],
                    "workspaceReceiptDigest": value["receiptDigest"],
                },
            )
            result = attach(operation, receipt)
            if args.close_slice:
                closure, closure_receipt = authority.execute(
                    "close_authority_scope",
                    lambda: {
                        "sliceClosure": manager.assert_slice_closed(lease["sliceId"]),
                        "authorityScopeClosure": authority.close_scope(
                            kind="slice",
                            scope_id=lease["sliceId"],
                            actor_id=actor_id,
                        ),
                    },
                    actor_id=actor_id,
                    grant_id=args.grant_id,
                    slice_id=lease["sliceId"],
                    resource_from_result=lambda value: {
                        "sliceId": value["sliceClosure"]["sliceId"],
                        "ok": value["sliceClosure"]["ok"],
                        "closureDigest": value["authorityScopeClosure"]["closureDigest"],
                    },
                )
                result.update(closure)
                result["sliceClosureAuthorityReceipt"] = closure_receipt
        elif command == "reconcile-missing-integrated":
            lease = manager.get_lease(args.lease_id)
            operation, receipt = authority.execute(
                "routine_cleanup",
                lambda: manager.reconcile_missing_integrated_workspace(
                    args.lease_id,
                    recovered_ref=args.recovered_ref,
                    integration_ref=args.integration_ref,
                ),
                actor_id=actor_id,
                grant_id=args.grant_id,
                branch=lease["branch"],
                slice_id=lease["sliceId"],
                resource_from_result=lambda value: {
                    "leaseId": value["leaseId"],
                    "status": value["status"],
                    "workspaceReceiptDigest": value["receiptDigest"],
                    "classifications": value["classifications"],
                },
            )
            result = attach(operation, receipt)
        elif command == "assert-slice-closed":
            operation, receipt = authority.execute(
                "close_authority_scope",
                lambda: {
                    "sliceClosure": manager.assert_slice_closed(args.slice_id),
                    "authorityScopeClosure": authority.close_scope(
                        kind="slice",
                        scope_id=args.slice_id,
                        actor_id=actor_id,
                    ),
                },
                actor_id=actor_id,
                grant_id=args.grant_id,
                slice_id=args.slice_id,
                resource_from_result=lambda value: {
                    "sliceId": value["sliceClosure"]["sliceId"],
                    "ok": value["sliceClosure"]["ok"],
                    "closureDigest": value["authorityScopeClosure"]["closureDigest"],
                },
            )
            result = attach(operation, receipt)
        elif command == "assert-repository-closed":
            operation, receipt = authority.execute(
                "inspect_repository",
                manager.assert_repository_closed,
                actor_id=actor_id,
                grant_id=args.grant_id,
                resource_from_result=lambda value: {"closureSchema": value["schema"], "ok": value["ok"]},
            )
            result = attach(operation, receipt)
        else:  # pragma: no cover - argparse owns this boundary
            raise ValueError(f"unsupported workspace command: {command}")
    except (OSError, ValueError, AuthorityError, WorkspaceLifecycleError) as exc:
        code = exc.code if isinstance(exc, (AuthorityError, WorkspaceLifecycleError)) else "invalid_contract"
        payload: dict[str, Any] = {"ok": False, "code": code, "detail": str(exc)}
        receipt = getattr(exc, "receipt", None) or getattr(exc, "authority_receipt", None)
        if isinstance(receipt, Mapping):
            payload["authorityReceipt"] = dict(receipt)
        print(json.dumps(payload, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0
