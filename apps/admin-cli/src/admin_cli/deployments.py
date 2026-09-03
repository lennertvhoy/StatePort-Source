"""CLI boundary for governed StatePort deployments."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
from typing import Any, Callable, Mapping

from governed_runner.authority import AuthorityError, AuthorityManager
from stateport_deployment import DeploymentError, DeploymentService
from stateport_deployment.execution_host import ExecutionHostDeploymentAdapter
from stateport_deployment.governed import (
    attach_authority,
    checked_out_branch,
    run_governed,
)
from stateport_deployment.inspection import authority_source_identity
from stateport_deployment.util import digest_value


def _branch(manager: AuthorityManager) -> str:
    return checked_out_branch(manager)


def _service(args: Any, authority_manager: AuthorityManager) -> DeploymentService:
    adapter = ExecutionHostDeploymentAdapter.configured(
        socket_path=str(getattr(args, "execution_host_socket", None) or ""),
        grant_id=str(getattr(args, "execution_host_grant_id", None) or ""),
        authority_grant_digest=str(
            getattr(args, "execution_host_grant_digest", None) or ""
        ),
        timeout_seconds=getattr(args, "execution_host_timeout_seconds", 1200),
    )
    return DeploymentService(
        state_root=Path(args.deployment_state_root) if args.deployment_state_root else None,
        adapter=adapter,
        authority_manager=authority_manager,
        actor=args.actor_id,
    )


def _authority(args: Any) -> AuthorityManager:
    return AuthorityManager(
        Path(args.repository),
        state_root=Path(args.authority_state_root)
        if args.authority_state_root
        else None,
        policy_path=Path(args.authority_policy) if args.authority_policy else None,
    )


def _attach_authority(
    result: Mapping[str, Any],
    authority_receipt: Mapping[str, Any],
    link: Mapping[str, Any] | None,
) -> dict[str, Any]:
    return attach_authority(result, authority_receipt, link)


def _run_governed(
    *,
    manager: AuthorityManager,
    service: DeploymentService,
    args: Any,
    action: str,
    deployment_id: str,
    operation: Any,
    run_id: str | None = None,
    run_id_resolver: Callable[[], str] | None = None,
    source_identity: Mapping[str, Any] | None = None,
    preflight: Callable[[], None] | None = None,
    link: bool = True,
) -> dict[str, Any]:
    """Adapt CLI arguments to the shared governed execution flow."""

    return run_governed(
        manager=manager,
        service=service,
        actor_id=args.actor_id,
        grant_id=args.grant_id,
        branch=_branch(manager),
        action=action,
        deployment_id=deployment_id,
        operation=operation,
        slice_id=args.slice_id,
        run_id=run_id,
        run_id_resolver=run_id_resolver,
        source_identity=source_identity,
        preflight=preflight,
        link=link,
    )


def _append_receipt_identities(
    lines: list[str], value: Mapping[str, Any]
) -> None:
    seen: set[tuple[str, str]] = set()

    def append(label: str, candidate: Any) -> None:
        if not isinstance(candidate, Mapping):
            return
        receipt_id = candidate.get("receiptId")
        receipt_digest = candidate.get("receiptDigest")
        if not isinstance(receipt_id, str) or not isinstance(receipt_digest, str):
            return
        identity = (receipt_id, receipt_digest)
        if identity in seen:
            return
        seen.add(identity)
        lines.append(f"{label}: {receipt_id} ({receipt_digest})")

    deployment_receipt = value.get("receipt")
    append("Deployment receipt", deployment_receipt)
    authority_receipt = value.get("authorityReceipt")
    append("Authority receipt", authority_receipt)
    append("Inspection authority receipt", value.get("inspectionAuthorityReceipt"))
    for index, receipt in enumerate(value.get("approvalReceipts", []), 1):
        append(f"Approval receipt {index}", receipt)
    append("Reconciliation receipt", value.get("reconciliationReceipt"))
    authority_link = value.get("authorityLink")
    if isinstance(authority_link, Mapping):
        append("Authority-link receipt", authority_link.get("receipt"))
    for key in (
        "priorAuthorityReconciliation",
        "authorityReconciliation",
    ):
        reconciliation = value.get(key)
        if not isinstance(reconciliation, Mapping):
            continue
        for index, link in enumerate(reconciliation.get("links", []), 1):
            if isinstance(link, Mapping):
                append(f"Reconciled authority receipt {index}", link.get("authorityReceipt"))
                append(f"Reconciliation link receipt {index}", link.get("receipt"))
        for group in reconciliation.get("reconciled", []):
            if not isinstance(group, Mapping):
                continue
            for index, link in enumerate(group.get("links", []), 1):
                if isinstance(link, Mapping):
                    append(
                        f"Reconciled authority receipt {index}",
                        link.get("authorityReceipt"),
                    )
                    append(
                        f"Reconciliation link receipt {index}", link.get("receipt")
                    )


def _human_summary(command: str, value: Mapping[str, Any]) -> str:
    if command == "inspect":
        source = value["source"]
        lines = [
            f"Project: {value['project']}",
            f"Source: {source['commit']} ({source['treeDigest']})",
            f"Dirty: {'yes' if value['dirty'] else 'no'}",
            f"Detected: {', '.join(value['detectedProjectTypes']) or 'unknown'}",
            f"Planning: {'supported' if value['deterministicAssistedPlanningSupported'] else 'refused'}",
            f"Candidate services: {', '.join(item['id'] for item in value['candidateServices']) or 'none'}",
            f"Build contexts: {json.dumps(value['buildContexts'], sort_keys=True)}",
            f"Commands: {json.dumps(value['commands'], sort_keys=True)}",
            f"Ports: {', '.join(str(item) for item in value['ports']) or 'none'}",
            f"Persistent paths: {', '.join(value['persistentPaths']) or 'none'}",
            f"Health signals: {json.dumps(value['healthSignals'], sort_keys=True)}",
            f"Secret identifiers: {', '.join(value['secretReferences']) or 'none'}",
            f"Unknowns: {', '.join(value['unknowns']) or 'none'}",
            f"Unsafe findings: {', '.join(value['unsafeConstructs']) or 'none'}",
            "Side effects: none (read-only inspection)",
        ]
        _append_receipt_identities(lines, value)
        return "\n".join(lines)
    if command in {"plan", "plan-purge"}:
        lines = [
            f"Deployment: {value['spec']['metadata']['deploymentId']}",
            f"Operation: {value['operation']}",
            f"Plan: {value['planDigest']}",
            f"Source: {value['spec']['source']['commit']} ({value['spec']['source']['treeDigest']})",
            f"Target: {value['spec']['target']['targetId']} ({value['spec']['target']['identityDigest']})",
            "Changes:",
        ]
        for change in value["changes"]:
            kind = change["kind"]
            if kind == "network":
                detail = f"create private network {change['id']}"
            elif kind == "service":
                detail = (
                    f"create service {change['id']} via {change['buildMode']} "
                    f"on {', '.join(change['networks'])}"
                )
            elif kind == "image":
                identity = change.get("reference") or "exact source build"
                detail = f"{change['action']} image for {change['serviceId']}: {identity}"
            elif kind == "source":
                detail = (
                    "update exact source "
                    f"{change['fromCommit']} -> {change['toCommit']}"
                )
            elif kind == "port":
                requested = change["hostPort"] or "allocated"
                detail = (
                    f"bind {change['serviceId']}/{change['name']} "
                    f"{change['hostAddress']}:{requested} -> {change['containerPort']}"
                )
            elif kind == "storage" and change["action"] == "mount":
                detail = (
                    f"mount {change['storageId']} at {change['serviceId']}:{change['mountPath']} "
                    f"({change['persistence']})"
                )
            elif kind == "secret_binding":
                detail = (
                    f"bind secret identifier {change['secretId']} to {change['serviceId']} "
                    f"via {change['binding']}"
                )
            elif kind == "storage" and change["action"] == "purge":
                detail = f"irreversibly purge retained storage {change['id']}"
            else:  # validated plans make this unreachable
                detail = json.dumps(change, sort_keys=True)
            lines.append(f"  - {detail}")
        lines.append("Service contracts:")
        for service in value["spec"]["services"]:
            build = service["build"]
            runtime = service["runtime"]
            health = service["health"]
            resources = service["resources"]
            lines.extend(
                (
                    f"  - {service['id']}:",
                    f"      build: {build['mode']} context={build.get('context')} containerfile={build.get('containerfile')}",
                    f"      command: {json.dumps(runtime['command'])}",
                    f"      workdir: {runtime['workdir']}",
                    f"      user: {runtime['user']['mode']} uid={runtime['user'].get('uid')}",
                    f"      health: {health['type']} path={health.get('path')} port={health.get('port')}",
                    f"      resources: {json.dumps(resources, sort_keys=True)}",
                )
            )
        lines.append(f"Overlay digest: {digest_value(value['overlay'])}")
        destructive = value["destructiveEffects"]
        retention = value["dataRetentionEffects"]
        lines.extend(
            (
                f"Risks: {', '.join(value['risks']) or 'none'}",
                "Destructive effects: "
                + (
                    "; ".join(
                        f"{item.get('kind')} {item.get('name')} irreversible={str(item.get('irreversible')).lower()}"
                        for item in destructive
                    )
                    if destructive
                    else "none"
                ),
                "Data-retention effects: "
                + (
                    "; ".join(
                        f"{item.get('from')} → {item.get('to')}" for item in retention
                    )
                    if retention
                    else "none"
                ),
                f"Approval required: {', '.join(value['authorityDecision']['required'])}",
                f"Expires: {value['expiresAt']}",
                f"Evidence: {value['evidencePath']}",
            )
        )
        _append_receipt_identities(lines, value)
        return "\n".join(lines)
    state = value.get("state") if isinstance(value.get("state"), Mapping) else value
    if isinstance(state, Mapping) and "lifecycleState" in state:
        lines = [
            f"Deployment: {state['deploymentId']}",
            f"Lifecycle: {state['lifecycleState']}",
            f"Source: {state['sourceIdentity']['commit']} ({state['sourceIdentity']['treeDigest']})",
            f"Target: {state['targetIdentity']['targetId']} ({state['targetIdentity']['identityDigest']})",
            f"Accepted: {state.get('acceptedRevision') or 'none'}",
            f"Desired: {state.get('desiredRevision') or 'none'}",
            f"Observed: {state.get('observedRevision') or 'none'}",
            f"Drift: {state.get('driftStatus')}",
            f"Images: {json.dumps(state.get('imageDigests', {}), sort_keys=True)}",
            f"Service health: {json.dumps(state.get('serviceHealth', {}), sort_keys=True)}",
            f"Storage: {json.dumps(state.get('storageIdentities', {}), sort_keys=True)}",
            f"Secret bindings: {', '.join(state.get('secretBindingIdentifiers', [])) or 'none'}",
            f"Removal state: {state.get('removalState')}",
            f"Retained data: {state.get('retainedDataState')}",
        ]
        observation = value.get("observation")
        if not isinstance(observation, Mapping):
            observation = state.get("lastSuccessfulObservation")
        if isinstance(observation, Mapping):
            ports = {
                service_id: item.get("ports", [])
                for service_id, item in observation.get("services", {}).items()
                if isinstance(item, Mapping)
            }
            lines.append(f"Observed ports: {json.dumps(ports, sort_keys=True)}")
        _append_receipt_identities(lines, value)
        linked = state.get("authorityReceipts", [])
        lines.append(
            "Linked authority receipts: "
            + (
                ", ".join(item["receiptId"] for item in linked)
                if linked
                else "none"
            )
        )
        return "\n".join(lines)
    if command == "logs":
        lines = [f"Deployment: {value['deploymentId']}"]
        for service_id, log in value["logs"].items():
            lines.extend((f"[{service_id}]", log.rstrip()))
        _append_receipt_identities(lines, value)
        return "\n".join(lines)
    return json.dumps(value, indent=2, sort_keys=True)


def deployment_cmd(args: Any) -> int:
    """Execute one deployment command with typed, non-traceback refusals."""

    command = args.deploy_command
    try:
        manager = _authority(args)
        service = _service(args, manager)
        if command == "inspect":
            inspected, receipt = manager.execute(
                "inspect_repository",
                lambda: service.inspect(args.project),
                actor_id=args.actor_id,
                grant_id=args.grant_id,
                branch=_branch(manager),
                slice_id=args.slice_id,
                resource_from_result=lambda value: {
                    "sourceCommit": value["source"]["commit"],
                    "sideEffects": value["sideEffects"],
                },
            )
            result = _attach_authority(inspected, receipt, None)
        elif command == "plan":
            if args.target != "local":
                raise ValueError("Slice A supports only --target local")
            inspected, inspection_receipt = manager.execute(
                "inspect_repository",
                lambda: service.inspect(args.project),
                actor_id=args.actor_id,
                grant_id=args.grant_id,
                branch=_branch(manager),
                slice_id=args.slice_id,
                application_id=args.deployment_id,
                resource_from_result=lambda value: {
                    "sourceIdentity": authority_source_identity(value),
                    "sideEffects": value["sideEffects"],
                },
            )
            source_identity = authority_source_identity(inspected)
            result = _run_governed(
                manager=manager,
                service=service,
                args=args,
                action="plan_deployment",
                deployment_id=args.deployment_id,
                source_identity=source_identity,
                preflight=lambda: service.assert_state_root_separate(inspected),
                operation=lambda decision: service.plan(
                    args.project,
                    deployment_id=args.deployment_id,
                    grant_id=decision["authorizedBy"]["id"],
                    authority_decision=decision,
                ),
            )
            result["inspectionAuthorityReceipt"] = inspection_receipt
        elif command == "apply":
            result = _run_governed(
                manager=manager,
                service=service,
                args=args,
                action="apply_deployment",
                deployment_id=args.deployment,
                run_id=args.accept_plan_digest,
                operation=lambda decision: service.apply(
                    args.deployment,
                    accept_plan_digest=args.accept_plan_digest,
                    authority_decision=decision,
                ),
            )
        elif command == "status":
            result = _run_governed(
                manager=manager,
                service=service,
                args=args,
                action="observe_deployment",
                deployment_id=args.deployment,
                run_id_resolver=lambda: service.peek_authority_run_id(
                    args.deployment, "observe_deployment"
                ),
                operation=lambda decision: service.status(
                    args.deployment, authority_decision=decision
                ),
            )
        elif command == "logs":
            result = _run_governed(
                manager=manager,
                service=service,
                args=args,
                action="collect_deployment_logs",
                deployment_id=args.deployment,
                run_id_resolver=lambda: service.peek_authority_run_id(
                    args.deployment, "collect_deployment_logs"
                ),
                operation=lambda decision: service.logs(
                    args.deployment,
                    authority_decision=decision,
                    service_id=args.service,
                    tail=args.tail,
                ),
            )
        elif command == "restart":
            result = _run_governed(
                manager=manager,
                service=service,
                args=args,
                action="restart_deployment",
                deployment_id=args.deployment,
                run_id_resolver=lambda: service.peek_authority_run_id(
                    args.deployment, "restart_deployment"
                ),
                operation=lambda decision: service.restart(
                    args.deployment, authority_decision=decision
                ),
            )
        elif command == "remove":
            result = _run_governed(
                manager=manager,
                service=service,
                args=args,
                action="remove_deployment_runtime",
                deployment_id=args.deployment,
                run_id_resolver=lambda: service.peek_authority_run_id(
                    args.deployment, "remove_deployment_runtime"
                ),
                operation=lambda decision: service.remove(
                    args.deployment, authority_decision=decision
                ),
            )
        elif command == "plan-purge":
            result = _run_governed(
                manager=manager,
                service=service,
                args=args,
                action="plan_deployment",
                deployment_id=args.deployment,
                run_id_resolver=lambda: service.peek_authority_run_id(
                    args.deployment, "plan_deployment"
                ),
                operation=lambda decision: service.plan_purge(
                    args.deployment, authority_decision=decision
                ),
            )
        elif command == "purge-data":
            result = _run_governed(
                manager=manager,
                service=service,
                args=args,
                action="purge_deployment_data",
                deployment_id=args.deployment,
                run_id=args.accept_plan_digest,
                operation=lambda decision: service.purge_data(
                    args.deployment,
                    accept_plan_digest=args.accept_plan_digest,
                    authority_decision=decision,
                ),
            )
        else:  # pragma: no cover - argparse owns this boundary
            raise ValueError(f"unsupported deployment command: {command}")
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(_human_summary(command, result))
        return 0
    except DeploymentError as exc:
        details = dict(exc.details)
        authority_receipt = getattr(exc, "authority_receipt", None)
        authority_link = getattr(exc, "authority_link", None)
        authority_link_pending = getattr(exc, "authority_link_pending", None)
        if isinstance(authority_receipt, Mapping):
            details["authorityReceipt"] = dict(authority_receipt)
        if isinstance(authority_link, Mapping):
            details["authorityLink"] = dict(authority_link)
        if isinstance(authority_link_pending, Mapping):
            details["authorityLinkPending"] = dict(authority_link_pending)
        payload = {
            "ok": False,
            "code": exc.code,
            "detail": str(exc),
            "details": details,
        }
        if args.json:
            print(json.dumps(payload, sort_keys=True), file=sys.stderr)
        else:
            category = {
                2: "refused",
                3: "runtime failed",
                4: "reconciliation required",
                70: "internal error",
            }.get(exc.exit_code, "failed")
            lines = [f"{category} [{exc.code}]: {exc}"]
            _append_receipt_identities(lines, details)
            print("\n".join(lines), file=sys.stderr)
        return exc.exit_code
    except AuthorityError as exc:
        authority_receipt = getattr(exc, "receipt", None) or getattr(
            exc, "authority_receipt", None
        )
        payload = {
            "ok": False,
            "code": exc.code,
            "detail": str(exc),
            "details": {
                "authorityReceipt": dict(authority_receipt)
                if isinstance(authority_receipt, Mapping)
                else None
            },
        }
        if args.json:
            print(json.dumps(payload, sort_keys=True), file=sys.stderr)
        else:
            lines = [f"refused [{exc.code}]: {exc}"]
            _append_receipt_identities(lines, payload["details"])
            print("\n".join(lines), file=sys.stderr)
        return 2
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        payload = {"ok": False, "code": "invalid_request", "detail": str(exc)}
        if args.json:
            print(json.dumps(payload, sort_keys=True), file=sys.stderr)
        else:
            print(f"refused [invalid_request]: {exc}", file=sys.stderr)
        return 2
    except (KeyError, TypeError) as exc:
        payload = {
            "ok": False,
            "code": "operation_contract_error",
            "detail": "deployment operation returned an invalid internal shape",
            "details": {"exception": type(exc).__name__},
        }
        if args.json:
            print(json.dumps(payload, sort_keys=True), file=sys.stderr)
        else:
            print(
                "failed [operation_contract_error]: deployment operation returned an invalid internal shape",
                file=sys.stderr,
            )
        return 70


__all__ = ["deployment_cmd"]
