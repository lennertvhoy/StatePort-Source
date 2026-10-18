#!/usr/bin/env python3
"""Acceptance tests for the identity and approval-backed mutation boundary."""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for relative in (
    "packages/governed-api/src",
    "packages/statedd-core/src",
    "packages/template-validator/src",
    "packages/approval-gate/src",
    "packages/quota-engine/src",
    "packages/audit-log/src",
    "packages/governed-runner/src",
    "packages/container-runner/src",
    "apps/runner/src",
):
    sys.path.insert(0, str(ROOT / relative))

from governed_api import GovernedAPI
from governed_runner import InstanceLease
from statedd_core import create_instance


CLASSDD = ROOT / "templates" / "classdd"


def _fixture(workspace: Path) -> tuple[GovernedAPI, Path, Path]:
    template = workspace / "template"
    shutil.copytree(CLASSDD, template)
    instance = workspace / "instance"
    create_instance(template, instance, instance_id="mutation-demo", name="Mutation demo", owner_name="Tester", owner_handle="@tester")
    instance_yaml = instance / "instance.yaml"
    instance_yaml.write_text(
        instance_yaml.read_text(encoding="utf-8").replace(
            "  status: \"draft\"\n", "  status: \"draft\"\n  grantedCapabilities:\n    - \"write_state\"\n"
        ),
        encoding="utf-8",
    )
    (instance / ".statedd" / "lock.yaml").unlink()
    api = GovernedAPI(
        workspace,
        identities={
            "requester": {"roles": ["user"], "instances": ["mutation-demo"]},
            "reviewer": {"roles": ["approver"], "instances": ["mutation-demo"]},
            "operator": {"roles": ["operator"], "instances": ["mutation-demo"]},
        },
        operator_allowed_capabilities=["write_state"],
    )
    return api, template, instance


def test_mutation_requires_identity_and_capability_intersection() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        api, template, instance = _fixture(Path(tmpdir))
        api = GovernedAPI(
            Path(tmpdir),
            identities={"requester": {"roles": ["user"], "instances": ["mutation-demo"]}},
        )
        no_identity = api.dispatch("POST", "/v1/mutations/request", {"operation": "materialize-instance", "instancePath": "instance", "templatePath": "template"})
        assert no_identity.status == 401
        denied = api.dispatch("POST", "/v1/mutations/request", {"actor": "requester", "operation": "materialize-instance", "instancePath": "instance", "templatePath": "template"})
        assert denied.status == 403 and denied.body["error"]["code"] == "capability_denied"
        assert not (instance / ".statedd" / "lock.yaml").exists()


def test_approved_mutation_is_persisted_audited_and_idempotent() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        api, _, instance = _fixture(workspace)
        requested = api.dispatch("POST", "/v1/mutations/request", {"actor": "requester", "operation": "materialize-instance", "instancePath": "instance", "templatePath": "template", "reason": "initialise the instance"})
        assert requested.status == 200
        approval_id = requested.body["result"]["approval"]["id"]
        assert requested.body["result"]["approval"]["status"] == "pending"
        assert not (instance / ".statedd" / "lock.yaml").exists()
        self_approval = api.dispatch("POST", "/v1/approvals/decide", {"actor": "requester", "approvalId": approval_id, "status": "approved"})
        assert self_approval.status == 403
        approved = api.dispatch("POST", "/v1/approvals/decide", {"actor": "reviewer", "approvalId": approval_id, "status": "approved"})
        assert approved.body["result"]["approval"]["status"] == "approved"
        applied = api.dispatch("POST", "/v1/mutations/apply", {"actor": "operator", "approvalId": approval_id})
        assert applied.status == 200 and applied.body["result"]["applied"] is True
        assert (instance / ".statedd" / "lock.yaml").exists()
        repeated = api.dispatch("POST", "/v1/mutations/apply", {"actor": "operator", "approvalId": approval_id})
        assert repeated.body["result"]["idempotent"] is True
        reloaded = GovernedAPI(workspace, identities={"reviewer": {"roles": ["approver"], "instances": ["mutation-demo"]}}, operator_allowed_capabilities=["write_state"])
        listed = reloaded.dispatch("POST", "/v1/approvals/list", {"actor": "reviewer"})
        assert listed.status == 200 and listed.body["result"]["approvals"][0]["id"] == approval_id
        audit = (workspace / ".stateport" / "audit.jsonl").read_text(encoding="utf-8")
        assert "mutation.requested" in audit and "mutation.applied" in audit


def test_mutation_defers_while_worker_writer_lease_is_held() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        api, _, instance = _fixture(workspace)
        requested = api.dispatch(
            "POST",
            "/v1/mutations/request",
            {
                "actor": "requester",
                "operation": "materialize-instance",
                "instancePath": "instance",
                "templatePath": "template",
            },
        )
        approval_id = requested.body["result"]["approval"]["id"]
        assert api.dispatch(
            "POST",
            "/v1/approvals/decide",
            {"actor": "reviewer", "approvalId": approval_id, "status": "approved"},
        ).status == 200
        with InstanceLease(
            workspace / ".stateport" / "leases",
            instance,
            owner="active-worker",
        ):
            busy = api.dispatch(
                "POST",
                "/v1/mutations/apply",
                {"actor": "operator", "approvalId": approval_id},
            )
        assert busy.status == 409
        assert busy.body["error"]["code"] == "instance_busy"
        assert not (instance / ".statedd" / "lock.yaml").exists()
        applied = api.dispatch(
            "POST",
            "/v1/mutations/apply",
            {"actor": "operator", "approvalId": approval_id},
        )
        assert applied.status == 200


if __name__ == "__main__":
    test_mutation_requires_identity_and_capability_intersection()
    test_approved_mutation_is_persisted_audited_and_idempotent()
    test_mutation_defers_while_worker_writer_lease_is_held()
    print("PASS")
