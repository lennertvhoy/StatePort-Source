#!/usr/bin/env python3
"""Deterministic tests for deployment update, rollback, and drift lifecycle (Stream B2 MS1)."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime
import json
from pathlib import Path
import sys
from typing import Any, Mapping

import jsonschema
import pytest
from referencing import Registry, Resource


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = Path(__file__).resolve().parent
DEPLOYMENT_SRC = ROOT / "packages" / "deployment" / "src"
ADMIN_SRC = ROOT / "apps" / "admin-cli" / "src"
GOVERNED_SRC = ROOT / "packages" / "governed-runner" / "src"
for candidate in (SCRIPTS, DEPLOYMENT_SRC, ADMIN_SRC, GOVERNED_SRC):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from stateport_deployment.contracts import (  # noqa: E402
    deployment_update_changes,
    plan_digest,
    validate_plan,
    validate_transition,
)
from stateport_deployment.errors import AdapterError, DeploymentRefusal  # noqa: E402
from stateport_deployment.inspection import authority_source_identity  # noqa: E402
from stateport_deployment.store import DeploymentStore  # noqa: E402
from stateport_deployment.util import digest_value  # noqa: E402

from test_container_deployment import (  # noqa: E402
    ACTOR,
    FakeAdapter,
    SimulatedStoreCrash,
    _format_checker,
    _git,
    apply_authorized,
    authority_harness,
    committed_fixture,
    governed_call,
    plan_authorized,
    planned_service,
    reserve_for,
)
from stateport_deployment.service import DeploymentService  # noqa: E402


class FakeUpdateAdapter(FakeAdapter):
    """Fake adapter with stop-swap update semantics and injectable failures."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.update_failure: str | None = None

    def _effective_infrastructure(
        self,
        plan: Mapping[str, Any],
        infrastructure: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        prior = infrastructure if isinstance(infrastructure, Mapping) else {}
        prior_networks = prior.get("networks", {})
        prior_volumes = prior.get("volumes", {})

        def entry(prior_entries: Mapping[str, Any], resource_id: str) -> dict[str, str]:
            existing = prior_entries.get(resource_id)
            if isinstance(existing, Mapping):
                return dict(existing)
            return {
                "revision": plan["planDigest"],
                "sourceCommit": plan["spec"]["source"]["commit"],
            }

        return {
            "networks": {
                network["id"]: entry(prior_networks, network["id"])
                for network in plan["spec"]["networks"]
            },
            "volumes": {
                item["id"]: entry(prior_volumes, item["id"])
                for service in plan["spec"]["services"]
                for item in service["storage"]
                if item["persistence"] != "externally_managed"
            },
        }

    def observe(self, spec: Mapping[str, Any], **kwargs: Any) -> dict[str, Any]:
        observation = super().observe(spec, **kwargs)
        for item in observation["networks"].values():
            item["planDigest"] = self.plan["planDigest"] if self.plan else None
            item["revision"] = self.plan["planDigest"] if self.plan else None
            item["sourceCommit"] = (
                self.plan["spec"]["source"]["commit"] if self.plan else None
            )
        return observation

    def apply_update(
        self,
        plan: Mapping[str, Any],
        *,
        predecessor_plan: Mapping[str, Any],
        predecessor_images: Mapping[str, str],
        infrastructure: Mapping[str, Any] | None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        self.calls.append("apply_update")
        effective = self._effective_infrastructure(plan, infrastructure)
        if self.update_failure == "pre_swap":
            raise AdapterError(
                "mutable_base_image",
                "simulated pre-swap update failure",
                details={
                    "checkpoints": ["infrastructure_ready"],
                    "rollback": {
                        "status": "not_required",
                        "revision": predecessor_plan["planDigest"],
                        "reason": "update failed before the accepted runtime was stopped",
                    },
                    "residue": {"removed": {}, "uncertain": [], "verified": True},
                },
            )
        if self.update_failure in {"health", "health_restore_failed", "health_gone"}:
            restored = self.update_failure == "health"
            if self.update_failure == "health_gone":
                self.present = False
                self.plan = None
            else:
                # The runtime is in fact back at the predecessor, whether or
                # not the adapter could prove its own restoration.
                self.present = True
                self.plan = predecessor_plan
                self.images = dict(predecessor_images)
            raise AdapterError(
                "health_verification_failed",
                "simulated unhealthy update",
                details={
                    "health": {
                        service["id"]: {"status": "unhealthy"}
                        for service in plan["spec"]["services"]
                    },
                    "checkpoints": [
                        "infrastructure_ready",
                        "images_ready",
                        "predecessor_stopped",
                        "services_started",
                    ],
                    "rollback": (
                        {
                            "status": "restored",
                            "revision": predecessor_plan["planDigest"],
                            "health": {
                                service["id"]: {"status": "healthy"}
                                for service in predecessor_plan["spec"]["services"]
                            },
                        }
                        if restored
                        else {
                            "status": "failed",
                            "failureCode": "health_verification_failed",
                            "details": {},
                        }
                    ),
                    "residue": {"removed": {}, "uncertain": [], "verified": True},
                },
            )
        result = FakeAdapter.apply(self, plan)
        result["infrastructure"] = effective
        result["prunedImages"] = [
            f"fake-image-{service['id']}:{predecessor_plan['planDigest'][7:19]}"
            for service in plan["spec"]["services"]
            if service["build"]["mode"] == "source"
        ]
        return result


def update_planned_service(
    tmp_path: Path, fixture: str = "python-http"
) -> tuple[DeploymentService, FakeUpdateAdapter, Path, dict[str, Any], dict[str, Any]]:
    """Return a healthy first revision and its project, ready for an update commit."""

    project = committed_fixture(tmp_path, fixture)
    adapter = FakeUpdateAdapter()
    deployment_id = f"deployment-{fixture}"
    manager, grant_id = authority_harness(tmp_path, deployment_id, project=project)
    service = DeploymentService(
        state_root=tmp_path / "state",
        adapter=adapter,
        authority_manager=manager,
        actor=ACTOR,
    )
    assert grant_id
    plan = plan_authorized(service, project, deployment_id)
    apply_authorized(service, deployment_id, plan["planDigest"])
    state = service.store.load_state(deployment_id)
    assert state["lifecycleState"] == "healthy"
    assert state["acceptedRevision"] == plan["planDigest"]
    return service, adapter, project, plan, state


def commit_update(project: Path, files: Mapping[str, str]) -> str:
    for relative, content in files.items():
        target = project / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    _git("add", ".", cwd=project)
    _git("commit", "-m", "update", cwd=project)
    return _git("rev-parse", "HEAD", cwd=project)


def plan_update_authorized(
    service: DeploymentService,
    project: Path,
    deployment_id: str,
    *,
    rollback_of: str | None = None,
) -> dict[str, Any]:
    source_identity = authority_source_identity(service.inspect(project))
    return governed_call(
        service,
        "plan_deployment",
        deployment_id,
        lambda decision: service.plan_update(
            project,
            deployment_id=deployment_id,
            grant_id=decision["authorizedBy"]["id"],
            authority_decision=decision,
            rollback_of=rollback_of,
        ),
        source_identity=source_identity,
    )


def apply_update_authorized(
    service: DeploymentService, deployment_id: str, plan_digest: str
) -> dict[str, Any]:
    return governed_call(
        service,
        "apply_deployment",
        deployment_id,
        lambda decision: service.apply_update(
            deployment_id,
            accept_plan_digest=plan_digest,
            authority_decision=decision,
        ),
        run_id=plan_digest,
    )


def reject_update_authorized(
    service: DeploymentService, deployment_id: str, plan_digest: str
) -> dict[str, Any]:
    return governed_call(
        service,
        "plan_deployment",
        deployment_id,
        lambda decision: service.reject_plan(
            deployment_id,
            plan_digest=plan_digest,
            authority_decision=decision,
        ),
        run_id=plan_digest,
    )


def plan_backup_authorized(
    service: DeploymentService, deployment_id: str
) -> dict[str, Any]:
    accepted = service.store.peek_authority_run_id(
        deployment_id, "plan_deployment"
    )
    return governed_call(
        service,
        "plan_deployment",
        deployment_id,
        lambda decision: service.plan_backup(
            deployment_id, authority_decision=decision
        ),
        run_id=accepted,
    )


def plan_restore_authorized(
    service: DeploymentService, deployment_id: str, backup_id: str
) -> dict[str, Any]:
    accepted = service.store.peek_authority_run_id(
        deployment_id, "plan_deployment"
    )
    return governed_call(
        service,
        "plan_deployment",
        deployment_id,
        lambda decision: service.plan_restore(
            deployment_id,
            backup_id=backup_id,
            authority_decision=decision,
        ),
        run_id=accepted,
    )


def apply_data_authorized(
    service: DeploymentService,
    deployment_id: str,
    plan: Mapping[str, Any],
) -> dict[str, Any]:
    action = (
        "backup_deployment_data"
        if plan["operation"] == "backup_data"
        else "restore_deployment_data"
    )
    return governed_call(
        service,
        action,
        deployment_id,
        lambda decision: service.apply_data_plan(
            deployment_id,
            accept_plan_digest=plan["planDigest"],
            authority_decision=decision,
        ),
        run_id=plan["planDigest"],
    )


def observe_authorized(
    service: DeploymentService, deployment_id: str, run_id: str
) -> dict[str, Any]:
    return governed_call(
        service,
        "observe_deployment",
        deployment_id,
        lambda decision: service.status(
            deployment_id, authority_decision=decision
        ),
        run_id=run_id,
    )


PYTHON_APP_V2 = '''"""Dependency-free public-safe Python deployment fixture, revision two."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
        if self.path == "/health":
            payload = {"ok": True, "fixture": "python-http", "revision": 2}
            encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
            return
        self.send_response(404)
        self.end_headers()


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
'''


def test_healthy_update_supersedes_the_accepted_revision(tmp_path: Path) -> None:
    service, adapter, project, plan, accepted = update_planned_service(tmp_path)
    deployment_id = "deployment-python-http"
    assert accepted["infrastructureIdentity"] == {
        "networks": {
            "internal": {
                "revision": plan["planDigest"],
                "sourceCommit": plan["spec"]["source"]["commit"],
            }
        },
        "volumes": {},
    }
    commit_update(project, {"app.py": PYTHON_APP_V2})
    update = plan_update_authorized(service, project, deployment_id)
    assert update["operation"] == "update"
    assert update["revisionId"] == update["planDigest"]
    assert update["supersedes"] == plan["planDigest"]
    assert update["predecessorRevision"] == plan["planDigest"]
    assert update["rollbackOf"] is None
    assert update["changes"] == deployment_update_changes(
        plan["spec"], update["spec"]
    )
    assert update["changes"][0] == {
        "kind": "source",
        "action": "update",
        "id": "source",
        "fromCommit": plan["spec"]["source"]["commit"],
        "toCommit": update["spec"]["source"]["commit"],
        "fromTreeDigest": plan["spec"]["source"]["treeDigest"],
        "toTreeDigest": update["spec"]["source"]["treeDigest"],
        "fromDirtyDigest": plan["spec"]["source"]["dirtyDigest"],
        "toDirtyDigest": update["spec"]["source"]["dirtyDigest"],
        "fromDescriptorDigest": plan["spec"]["source"]["descriptorDigest"],
        "toDescriptorDigest": update["spec"]["source"]["descriptorDigest"],
    }
    planned = service.store.load_state(deployment_id)
    assert planned["lifecycleState"] == "awaiting_approval"
    assert planned["desiredRevision"] == update["planDigest"]
    assert planned["acceptedRevision"] == plan["planDigest"]
    assert adapter.calls.count("apply_update") == 0

    result = apply_update_authorized(service, deployment_id, update["planDigest"])
    state = result["state"]
    assert state["lifecycleState"] == "healthy"
    assert state["acceptedRevision"] == update["planDigest"]
    assert state["desiredRevision"] == update["planDigest"]
    assert state["observedRevision"] == update["planDigest"]
    assert state["rollbackPredecessor"] == plan["planDigest"]
    assert state["driftStatus"] == "in_sync"
    assert state["infrastructureIdentity"]["networks"]["internal"]["revision"] == plan["planDigest"]
    events = [
        json.loads(path.read_text(encoding="utf-8"))["event"]
        for path in sorted(
            (service.store._deployment_root(deployment_id) / "receipts").glob("*.json")
        )
    ]
    assert "update_plan_created" in events
    assert "update_runtime_started" in events
    last_accepted = len(events) - 1 - events[::-1].index("revision_accepted")
    assert last_accepted > events.index("update_runtime_started")
    assert events.count("revision_accepted") == 2

    observed = observe_authorized(service, deployment_id, update["planDigest"])
    assert observed["state"]["lifecycleState"] == "healthy"
    assert observed["state"]["driftStatus"] == "in_sync"
    restarted = governed_call(
        service,
        "restart_deployment",
        deployment_id,
        lambda decision: service.restart(
            deployment_id, authority_decision=decision
        ),
        run_id=update["planDigest"],
    )
    assert restarted["state"]["lifecycleState"] == "healthy"


def test_exact_update_proposal_can_be_rejected_without_runtime_mutation(
    tmp_path: Path,
) -> None:
    service, adapter, project, accepted_plan, accepted = update_planned_service(
        tmp_path
    )
    deployment_id = "deployment-python-http"
    commit_update(project, {"app.py": PYTHON_APP_V2})
    proposal = plan_update_authorized(service, project, deployment_id)
    calls_before = list(adapter.calls)

    result = reject_update_authorized(
        service, deployment_id, proposal["planDigest"]
    )

    state = result["state"]
    assert state["lifecycleState"] == "healthy"
    assert state["acceptedRevision"] == accepted_plan["planDigest"]
    assert state["desiredRevision"] == accepted_plan["planDigest"]
    assert state["approvedPlanDigest"] == accepted_plan["planDigest"]
    assert state["observedRevision"] == accepted_plan["planDigest"]
    assert state["sourceIdentity"] == accepted["sourceIdentity"]
    assert adapter.calls == calls_before
    assert result["receipt"]["event"] == "proposal_rejected"
    assert result["receipt"]["data"]["runtimeMutation"] is False

    with pytest.raises(DeploymentRefusal, match="not awaiting this exact proposal"):
        reject_update_authorized(service, deployment_id, proposal["planDigest"])


def test_exact_backup_restore_consumes_snapshot_after_verified_restore(
    tmp_path: Path,
) -> None:
    service, adapter, _project, accepted_plan, _accepted = (
        update_planned_service(tmp_path, "persistent-multi")
    )
    deployment_id = "deployment-persistent-multi"
    adapter.volume_data["app-data"] = "canonical-before-backup"

    backup_plan = plan_backup_authorized(service, deployment_id)
    assert backup_plan["operation"] == "backup_data"
    assert backup_plan["predecessorRevision"] == accepted_plan["planDigest"]
    assert backup_plan["changes"] == [
        {
            "kind": "storage",
            "action": "backup",
            "id": "app-data",
            "backupId": backup_plan["backupId"],
        }
    ]
    assert backup_plan["destructiveEffects"] == []

    backed_up = apply_data_authorized(
        service, deployment_id, backup_plan
    )
    backup = backed_up["backup"]
    assert backup["status"] == "available"
    assert backup["storage"]["app-data"]["artifactId"] == (
        f"{backup['backupId']}/app-data.tar"
    )
    assert backed_up["state"]["acceptedRevision"] == accepted_plan["planDigest"]
    assert backed_up["state"]["dataBackups"] == {backup["backupId"]: backup}

    adapter.volume_data["app-data"] = "changed-after-backup"
    restore_plan = plan_restore_authorized(
        service, deployment_id, backup["backupId"]
    )
    assert restore_plan["operation"] == "restore_data"
    assert restore_plan["backupDigest"] == backup["backupDigest"]
    assert restore_plan["destructiveEffects"] == [
        {
            "kind": "volume",
            "name": backed_up["state"]["storageIdentities"]["app-data"],
            "irreversible": True,
        }
    ]

    restored = apply_data_authorized(
        service, deployment_id, restore_plan
    )
    assert adapter.volume_data["app-data"] == "canonical-before-backup"
    assert backup["backupId"] not in adapter.backups
    assert restored["state"]["lifecycleState"] == "healthy"
    assert restored["state"]["acceptedRevision"] == accepted_plan["planDigest"]
    assert restored["state"]["desiredRevision"] == accepted_plan["planDigest"]
    assert restored["backup"]["status"] == "restored_consumed"
    assert restored["backup"]["restoredAt"] == "2026-07-30T00:01:00Z"

    deployment_schema = json.loads(
        (ROOT / "schemas" / "deployment.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    plan_schema = json.loads(
        (ROOT / "schemas" / "deployment-plan.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    plan_validator = jsonschema.Draft202012Validator(
        plan_schema,
        registry=Registry().with_resource(
            deployment_schema["$id"], Resource.from_contents(deployment_schema)
        ),
        format_checker=_format_checker(),
    )
    plan_validator.validate(backup_plan)
    plan_validator.validate(restore_plan)
    state_schema = json.loads(
        (ROOT / "schemas" / "deployment-state.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.Draft202012Validator(
        state_schema, format_checker=_format_checker()
    ).validate(restored["state"])


def test_exact_backup_proposal_can_be_rejected_without_runtime_mutation(
    tmp_path: Path,
) -> None:
    service, adapter, _project, accepted_plan, _accepted = (
        update_planned_service(tmp_path, "persistent-multi")
    )
    deployment_id = "deployment-persistent-multi"
    proposal = plan_backup_authorized(service, deployment_id)
    calls_before = list(adapter.calls)

    result = reject_update_authorized(
        service, deployment_id, proposal["planDigest"]
    )

    assert result["state"]["lifecycleState"] == "healthy"
    assert result["state"]["acceptedRevision"] == accepted_plan["planDigest"]
    assert result["state"]["dataBackups"] == {}
    assert result["receipt"]["event"] == "proposal_rejected"
    assert adapter.calls == calls_before


def test_legacy_v1_state_projects_empty_backups_until_next_receipted_write(
    tmp_path: Path,
) -> None:
    service, _adapter, _project, _plan, _accepted = update_planned_service(
        tmp_path, "persistent-multi"
    )
    deployment_id = "deployment-persistent-multi"
    state_path = service.store._state_path(deployment_id)
    legacy = json.loads(state_path.read_text(encoding="utf-8"))
    legacy.pop("dataBackups")
    legacy.pop("stateDigest")
    legacy["stateDigest"] = digest_value(legacy)
    state_path.write_text(
        json.dumps(legacy, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    projected = service.store.load_state(deployment_id)
    assert projected["dataBackups"] == {}
    projected_unsigned = dict(projected)
    projected_digest = projected_unsigned.pop("stateDigest")
    assert projected_digest == digest_value(projected_unsigned)
    assert "dataBackups" not in json.loads(state_path.read_text(encoding="utf-8"))

    plan_backup_authorized(service, deployment_id)
    persisted = json.loads(state_path.read_text(encoding="utf-8"))
    assert persisted["dataBackups"] == {}


def test_unhealthy_update_rolls_back_to_the_accepted_revision(tmp_path: Path) -> None:
    service, adapter, project, plan, _accepted = update_planned_service(tmp_path)
    deployment_id = "deployment-python-http"
    commit_update(project, {"app.py": PYTHON_APP_V2})
    update = plan_update_authorized(service, project, deployment_id)
    adapter.update_failure = "health"
    with pytest.raises(AdapterError, match="simulated unhealthy update"):
        apply_update_authorized(service, deployment_id, update["planDigest"])
    state = service.store.load_state(deployment_id)
    assert state["lifecycleState"] == "healthy"
    assert state["acceptedRevision"] == plan["planDigest"]
    assert state["desiredRevision"] == plan["planDigest"]
    assert state["approvedPlanDigest"] == plan["planDigest"]
    assert state["observedRevision"] == plan["planDigest"]
    assert state["rollbackPredecessor"] == update["planDigest"]
    assert state["driftStatus"] == "in_sync"
    assert state["currentTransition"] is None
    receipts = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(
            (service.store._deployment_root(deployment_id) / "receipts").glob("*.json")
        )
    ]
    events = [receipt["event"] for receipt in receipts]
    failed_at = events.index("update_failed")
    assert events[failed_at + 1 : failed_at + 3] == [
        "automatic_rollback_started",
        "automatic_rollback_completed",
    ]
    failure = receipts[failed_at]
    assert failure["data"]["authorityOutcome"]["status"] == "failed"
    assert failure["data"]["rollback"]["status"] == "restored"


def test_update_failure_before_the_swap_keeps_the_accepted_revision(
    tmp_path: Path,
) -> None:
    service, adapter, project, plan, _accepted = update_planned_service(tmp_path)
    deployment_id = "deployment-python-http"
    commit_update(project, {"app.py": PYTHON_APP_V2})
    update = plan_update_authorized(service, project, deployment_id)
    adapter.update_failure = "pre_swap"
    with pytest.raises(AdapterError, match="pre-swap"):
        apply_update_authorized(service, deployment_id, update["planDigest"])
    state = service.store.load_state(deployment_id)
    assert state["lifecycleState"] == "healthy"
    assert state["acceptedRevision"] == plan["planDigest"]
    assert state["rollbackPredecessor"] == update["planDigest"]


@pytest.mark.parametrize(
    ("failure", "expected_state", "expected_revision"),
    (
        ("health_restore_failed", "healthy", "predecessor"),
        ("health_gone", "reconciliation_required", "predecessor"),
    ),
)
def test_uncertain_update_rollback_requires_observed_reconciliation(
    tmp_path: Path, failure: str, expected_state: str, expected_revision: str
) -> None:
    service, adapter, project, plan, _accepted = update_planned_service(tmp_path)
    deployment_id = "deployment-python-http"
    commit_update(project, {"app.py": PYTHON_APP_V2})
    update = plan_update_authorized(service, project, deployment_id)
    adapter.update_failure = failure
    with pytest.raises(AdapterError, match="simulated unhealthy update"):
        apply_update_authorized(service, deployment_id, update["planDigest"])
    state = service.store.load_state(deployment_id)
    assert state["lifecycleState"] == "reconciliation_required"
    assert state["currentTransition"]["operation"] == "update"
    assert state["currentTransition"]["planDigest"] == update["planDigest"]
    observed = observe_authorized(service, deployment_id, update["planDigest"])
    assert observed["state"]["lifecycleState"] == expected_state
    if expected_state == "healthy":
        assert observed["state"]["acceptedRevision"] == plan["planDigest"]
        assert observed["state"]["rollbackPredecessor"] == update["planDigest"]
        assert observed["state"]["driftStatus"] == "in_sync"
    else:
        assert observed["state"]["lifecycleState"] == "reconciliation_required"


def test_rollback_plan_restores_the_exact_named_revision(tmp_path: Path) -> None:
    service, adapter, project, plan, _accepted = update_planned_service(tmp_path)
    deployment_id = "deployment-python-http"
    v1_commit = plan["spec"]["source"]["commit"]
    commit_update(project, {"app.py": PYTHON_APP_V2})
    update = plan_update_authorized(service, project, deployment_id)
    apply_update_authorized(service, deployment_id, update["planDigest"])
    assert service.store.load_state(deployment_id)["acceptedRevision"] == update["planDigest"]

    # A rollback cannot be planned against a source that does not match the
    # revision it names.
    with pytest.raises(DeploymentRefusal, match="exact specification"):
        plan_update_authorized(
            service, project, deployment_id, rollback_of=plan["planDigest"]
        )
    with pytest.raises(DeploymentRefusal, match="different revision"):
        plan_update_authorized(
            service, project, deployment_id, rollback_of=update["planDigest"]
        )

    _git("checkout", v1_commit, cwd=project)
    rollback = plan_update_authorized(
        service, project, deployment_id, rollback_of=plan["planDigest"]
    )
    assert rollback["operation"] == "rollback"
    assert rollback["rollbackOf"] == plan["planDigest"]
    assert rollback["supersedes"] == update["planDigest"]
    assert rollback["spec"] == plan["spec"]
    assert rollback["changes"] == deployment_update_changes(
        update["spec"], rollback["spec"]
    )
    result = apply_update_authorized(service, deployment_id, rollback["planDigest"])
    assert result["state"]["lifecycleState"] == "healthy"
    assert result["state"]["acceptedRevision"] == rollback["planDigest"]
    assert result["state"]["rollbackPredecessor"] == update["planDigest"]
    assert result["state"]["observedRevision"] == rollback["planDigest"]


def test_update_plan_requires_a_healthy_accepted_revision(tmp_path: Path) -> None:
    service, _adapter, project, plan = planned_service(tmp_path, "python-http")
    deployment_id = "deployment-python-http"
    with pytest.raises(DeploymentRefusal, match="healthy or degraded"):
        plan_update_authorized(service, project, deployment_id)
    assert service.store.load_state(deployment_id)["lifecycleState"] == "awaiting_approval"


def test_update_refuses_storage_removal_before_any_approval(tmp_path: Path) -> None:
    service, adapter, project, plan, _accepted = update_planned_service(
        tmp_path, "persistent-multi"
    )
    deployment_id = "deployment-persistent-multi"
    descriptor = project / "stateport.deployment.yaml"
    text = descriptor.read_text(encoding="utf-8")
    updated = text.replace(
        "    storage:\n      - {id: app-data, mountPath: /data, persistence: retained}\n",
        "    storage: []\n",
    )
    assert updated != text
    commit_update(project, {"stateport.deployment.yaml": updated})
    with pytest.raises(DeploymentRefusal, match="repurpose retained storage"):
        plan_update_authorized(service, project, deployment_id)
    state = service.store.load_state(deployment_id)
    assert state["lifecycleState"] == "healthy"
    assert adapter.calls.count("apply_update") == 0


def test_drift_observation_degrades_and_recovers(tmp_path: Path) -> None:
    service, adapter, project, plan, _accepted = update_planned_service(tmp_path)
    deployment_id = "deployment-python-http"
    commit_update(project, {"app.py": PYTHON_APP_V2})
    update = plan_update_authorized(service, project, deployment_id)
    apply_update_authorized(service, deployment_id, update["planDigest"])

    original_observe = adapter.observe

    def drifting(spec: Mapping[str, Any], **options: Any) -> dict[str, Any]:
        observation = original_observe(spec, **options)
        observation["drift"] = ["image_changed:app"]
        observation["status"] = "drifted"
        return observation

    adapter.observe = drifting  # type: ignore[method-assign]
    observed = observe_authorized(service, deployment_id, update["planDigest"])
    assert observed["state"]["lifecycleState"] == "degraded"
    assert observed["state"]["driftStatus"] == "drifted"

    adapter.observe = original_observe  # type: ignore[method-assign]
    recovered = observe_authorized(service, deployment_id, update["planDigest"])
    assert recovered["state"]["lifecycleState"] == "healthy"
    assert recovered["state"]["driftStatus"] == "in_sync"


def _interrupt_update_after_claim(
    service: DeploymentService,
    deployment_id: str,
    update: Mapping[str, Any],
) -> dict[str, Any]:
    decision, _reservation = reserve_for(
        service,
        "apply_deployment",
        deployment_id,
        run_id=update["planDigest"],
    )
    reference = service._verify_authority(
        decision,
        action="apply_deployment",
        deployment_id=deployment_id,
        run_id=update["planDigest"],
    )
    service.store.approve_and_reserve(
        deployment_id,
        update,
        actor=ACTOR,
        authority_reference=reference,
    )
    return decision


@pytest.mark.parametrize("runtime", ("new_revision", "predecessor"))
def test_interrupted_update_reconciles_without_replay(
    tmp_path: Path, runtime: str
) -> None:
    service, adapter, project, plan, _accepted = update_planned_service(tmp_path)
    deployment_id = "deployment-python-http"
    commit_update(project, {"app.py": PYTHON_APP_V2})
    update = plan_update_authorized(service, project, deployment_id)
    _interrupt_update_after_claim(service, deployment_id, update)
    state = service.store.load_state(deployment_id)
    assert state["lifecycleState"] == "updating"
    assert state["currentTransition"]["operation"] == "update"
    assert state["approvedPlanDigest"] == update["planDigest"]

    if runtime == "new_revision":
        adapter.plan = update
        adapter.present = True
        adapter.images = {
            service_spec["id"]: "sha256:" + format(index + 7, "064x")
            for index, service_spec in enumerate(update["spec"]["services"])
        }
    else:
        adapter.plan = plan
        adapter.present = True
    result = observe_authorized(service, deployment_id, update["planDigest"])
    assert result["state"]["lifecycleState"] == "healthy"
    assert "apply_update" not in adapter.calls
    if runtime == "new_revision":
        assert result["state"]["acceptedRevision"] == update["planDigest"]
        assert result["state"]["rollbackPredecessor"] == plan["planDigest"]
    else:
        assert result["state"]["acceptedRevision"] == plan["planDigest"]
        assert result["state"]["rollbackPredecessor"] == update["planDigest"]
    assert result["state"]["driftStatus"] == "in_sync"


@pytest.mark.parametrize(
    "boundary",
    (
        "after_journal",
        "after_receipt_1",
        "after_receipt_2",
        "before_state",
        "after_state",
        "before_journal_cleanup",
    ),
)
def test_update_approval_recovers_every_commit_boundary(
    tmp_path: Path, boundary: str
) -> None:
    service, _adapter, project, plan, _accepted = update_planned_service(tmp_path)
    deployment_id = "deployment-python-http"
    commit_update(project, {"app.py": PYTHON_APP_V2})
    update = plan_update_authorized(service, project, deployment_id)
    decision, _reservation = reserve_for(
        service,
        "apply_deployment",
        deployment_id,
        run_id=update["planDigest"],
    )
    reference = service._verify_authority(
        decision,
        action="apply_deployment",
        deployment_id=deployment_id,
        run_id=update["planDigest"],
    )
    root = service.store.root
    before = service.store.load_state(deployment_id)

    def failpoint(name: str) -> None:
        if name == boundary:
            raise SimulatedStoreCrash(name)

    crashing = DeploymentStore(root, failpoint=failpoint)
    with pytest.raises(SimulatedStoreCrash):
        crashing.approve_and_reserve(
            deployment_id,
            update,
            actor=ACTOR,
            authority_reference=reference,
        )
    recovered = DeploymentStore(root)
    state = recovered.load_state(deployment_id)
    assert state["lifecycleState"] == "updating"
    assert state["currentTransition"]["operation"] == "update"
    assert state["approvedPlanDigest"] == update["planDigest"]
    assert state["acceptedRevision"] == plan["planDigest"]
    events = [
        json.loads(path.read_text(encoding="utf-8"))["event"]
        for path in (root / "records" / deployment_id / "receipts").glob("*.json")
    ]
    assert len(events) == len(before["receipts"]) + 2
    assert events.count("plan_approved") == 2
    assert events.count("update_reserved") == 1
    assert recovered.load_state(deployment_id) == state


def test_update_lifecycle_state_machine_boundaries() -> None:
    allowed = (
        ("healthy", "update_planned"),
        ("degraded", "update_planned"),
        ("update_planned", "awaiting_approval"),
        ("awaiting_approval", "approved"),
        ("approved", "updating"),
        ("updating", "verifying"),
        ("verifying", "healthy"),
        ("updating", "rollback_required"),
        ("rollback_required", "rolling_back"),
        ("rolling_back", "healthy"),
        ("updating", "reconciliation_required"),
        ("reconciliation_required", "healthy"),
    )
    for current, target in allowed:
        validate_transition(current, target)
    refused = (
        ("healthy", "updating"),
        ("healthy", "rolling_back"),
        ("applying", "updating"),
        ("update_planned", "healthy"),
        ("approved", "applying_and_skipping"),
        ("rolling_back", "update_planned"),
        ("planned", "updating"),
    )
    for current, target in refused:
        with pytest.raises(DeploymentRefusal):
            validate_transition(current, target)


def test_update_change_diff_is_exact(tmp_path: Path) -> None:
    _service, _adapter, _project, plan = planned_service(tmp_path, "python-http")
    changed = deepcopy(plan["spec"])
    changed["services"][0]["ports"][0]["hostPort"] = 8080
    diff = deployment_update_changes(plan["spec"], changed)
    assert [(item["kind"], item["id"], item["action"]) for item in diff] == [
        ("port", "web.http", "update")
    ]
    unchanged = deployment_update_changes(plan["spec"], plan["spec"])
    assert unchanged == []
    removed = deepcopy(plan["spec"])
    removed["networks"] = []
    diff = deployment_update_changes(plan["spec"], removed)
    assert {(item["kind"], item["action"]) for item in diff} == {
        ("network", "remove"),
    }


def test_update_plan_lineage_is_exact(tmp_path: Path) -> None:
    service, _adapter, project, plan, _accepted = update_planned_service(tmp_path)
    deployment_id = "deployment-python-http"
    commit_update(project, {"app.py": PYTHON_APP_V2})
    update = plan_update_authorized(service, project, deployment_id)

    broken_revision = deepcopy(update)
    broken_revision["revisionId"] = plan["planDigest"]
    with pytest.raises(DeploymentRefusal, match="lineage"):
        validate_plan(broken_revision)

    broken_supersedes = deepcopy(update)
    broken_supersedes["supersedes"] = update["planDigest"]
    with pytest.raises(DeploymentRefusal, match="lineage"):
        validate_plan(broken_supersedes)

    broken_rollback_of = deepcopy(update)
    broken_rollback_of["rollbackOf"] = plan["planDigest"]
    with pytest.raises(DeploymentRefusal, match="lineage"):
        validate_plan(broken_rollback_of)

    recomputed = deepcopy(update)
    recomputed.pop("planDigest")
    recomputed.pop("revisionId")
    assert plan_digest(recomputed) == update["planDigest"]


def test_update_documents_validate_against_json_schemas(tmp_path: Path) -> None:
    service, _adapter, project, plan, _accepted = update_planned_service(tmp_path)
    deployment_id = "deployment-python-http"
    commit_update(project, {"app.py": PYTHON_APP_V2})
    update = plan_update_authorized(service, project, deployment_id)
    apply_update_authorized(service, deployment_id, update["planDigest"])
    schemas = {
        name: json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
        for name in (
            "deployment.v1.schema.json",
            "deployment-plan.v1.schema.json",
            "deployment-state.v1.schema.json",
        )
    }
    for schema in schemas.values():
        jsonschema.Draft202012Validator.check_schema(schema)
        assert schema["additionalProperties"] is False
    format_checker = _format_checker()
    registry = Registry().with_resource(
        schemas["deployment.v1.schema.json"]["$id"],
        Resource.from_contents(schemas["deployment.v1.schema.json"]),
    )
    validator = jsonschema.Draft202012Validator(
        schemas["deployment-plan.v1.schema.json"],
        registry=registry,
        format_checker=format_checker,
    )
    validator.validate(plan)
    validator.validate(update)
    state = service.store.load_state(deployment_id)
    jsonschema.Draft202012Validator(
        schemas["deployment-state.v1.schema.json"],
        format_checker=format_checker,
    ).validate(state)
    assert state["acceptedRevision"] == update["planDigest"]
