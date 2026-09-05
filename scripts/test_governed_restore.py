#!/usr/bin/env python3
"""Focused tests for the exact-plan managed recovery transaction."""

from __future__ import annotations

import hashlib
from datetime import datetime as real_datetime
from argparse import Namespace
import json
import os
from pathlib import Path
import socket
import sys
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
for relative in (
    "packages/statedd-core/src",
    "packages/template-validator/src",
    "packages/persistent-app/src",
    "packages/instance-backup/src",
    "packages/instance-catalog/src",
    "packages/diagnostics/src",
    "packages/portable-execution/src",
    "packages/application-experience/src",
    "packages/conversation-service/src",
    "packages/governed-runner/src",
    "packages/deployment/src",
    "packages/execution-host/src",
    "packages/external-engine-runtime/src",
    "packages/codex-adapter/src",
    "packages/run-bundle/src",
    "apps/runner/src",
    "apps/admin-cli/src",
):
    sys.path.insert(0, str(ROOT / relative))

import instance_backup  # noqa: E402
import stateport_persistent_app.app as persistent_app_module  # noqa: E402
from stateport_persistent_app import LocalLayout, PersistentApp  # noqa: E402
from stateport_persistent_app.app import ApprovalError, AppError  # noqa: E402
from statedd_core import materialize_instance  # noqa: E402
from statedd_validate_schema import load_schema, validate_json_schema  # noqa: E402
from service_test_product import service_product_fixture  # noqa: E402
from admin_cli.local_alpha import backup_cmd  # noqa: E402


class _IndentedDumper(yaml.SafeDumper):
    def increase_indent(self, flow: bool = False, indentless: bool = False) -> None:
        return super().increase_indent(flow, False)


def _digest_tree(root: Path) -> str:
    value = [
        (path.relative_to(root).as_posix(), hashlib.sha256(path.read_bytes()).hexdigest())
        for path in sorted(root.rglob("*"))
        if path.is_file() and not path.is_symlink() and ".git" not in path.parts
    ]
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def _app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> PersistentApp:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    return app


def _operator_boundary_fixture(app: PersistentApp) -> Path:
    boundary = app.layout.config_root / "platform-operator-authority"
    boundary.write_text("test operator boundary\n", encoding="utf-8")
    boundary.chmod(0o600)
    return boundary


def _instance(app: PersistentApp, instance_id: str = "restore-source") -> Path:
    root = app.layout.instances_root / instance_id
    (root / ".statedd").mkdir(parents=True)
    (root / "state").mkdir()
    (root / "template").mkdir()
    (root / "template" / ".statedd").mkdir()
    (root / "instance.yaml").write_text(
        "apiVersion: statedd.stateport.io/v1alpha1\n"
        "kind: Instance\n"
        "metadata:\n"
        f"  id: {instance_id}\n"
        "  name: Governed restore fixture\n"
        "spec:\n"
        "  templateRef:\n"
        "    id: stateport.fixture.governed-restore\n"
        "    path: template\n"
        "  status: active\n"
        "  owner:\n"
        "    name: Synthetic Owner\n"
        "    handle: synthetic-owner\n",
        encoding="utf-8",
    )
    lock = {
        "formatVersion": "statedd.lock/v1",
        "instanceId": instance_id,
        "template": {
            "id": "stateport.fixture.governed-restore",
            "version": "1.0.0",
            "sourcePath": "template",
            "sourceRevision": "sha256:" + "2" * 64,
            "instanceSchemaVersion": "statedd.stateport.io/instance/v1alpha1",
            "source": {
                "formatVersion": "statedd.source/v1",
                "kind": "local",
                "path": "template",
                "identity": "sha256:" + "2" * 64,
            },
        },
        "files": [
            {
                "path": "README.md",
                "owner": "instance",
                "merge": "preserve",
                "required": True,
                "sensitivity": "public",
            },
            {
                "path": "instance.yaml",
                "owner": "instance",
                "merge": "preserve",
                "required": True,
                "sensitivity": "private",
            },
            {
                "path": ".statedd/lock.yaml",
                "owner": "generated",
                "merge": "replace",
                "required": True,
                "sensitivity": "internal",
            },
            {
                "path": "state/notes.md",
                "owner": "instance",
                "merge": "preserve",
                "required": True,
                "sensitivity": "private",
            },
            {
                "path": "template/README.md",
                "owner": "template",
                "merge": "replace",
                "required": True,
                "sensitivity": "public",
            },
            {
                "path": "template/template.yaml",
                "owner": "template",
                "merge": "replace",
                "required": True,
                "sensitivity": "public",
            },
            {
                "path": "template/.statedd/contract.md",
                "owner": "template",
                "merge": "replace",
                "required": True,
                "sensitivity": "public",
            },
            {
                "path": "template/.statedd/manifest.yaml",
                "owner": "template",
                "merge": "replace",
                "required": True,
                "sensitivity": "public",
            },
        ],
    }
    (root / ".statedd" / "lock.yaml").write_text(
        yaml.dump(lock, Dumper=_IndentedDumper, sort_keys=False), encoding="utf-8"
    )
    (root / "README.md").write_text("# Template fixture\n", encoding="utf-8")
    (root / "template" / "README.md").write_text("# Template fixture\n", encoding="utf-8")
    (root / "template" / "template.yaml").write_text(
        "apiVersion: statedd.stateport.io/v1alpha1\n"
        "kind: Template\n"
        "metadata:\n"
        "  id: stateport.fixture.governed-restore\n"
        "  name: Synthetic template\n"
        "  version: 1.0.0\n"
        "spec:\n"
        "  domain: synthetic\n"
        "  lifecycle:\n"
        "    - active\n"
        "  allowedActions:\n"
        "    - name: read_state\n"
        "      level: L0\n"
        "      description: Read synthetic state\n"
        "  schemas: []\n"
        "  agentContract:\n"
        "    role: assistant\n"
        "    responsibilities:\n"
        "      - Preserve synthetic state\n"
        "    forbiddenActions:\n"
        "      - Contact external systems\n",
        encoding="utf-8",
    )
    (root / "template" / ".statedd" / "contract.md").write_text(
        "# Synthetic StateSpec contract\n", encoding="utf-8"
    )
    (root / "template" / ".statedd" / "manifest.yaml").write_text(
        "formatVersion: statedd.template-manifest/v2\n"
        "template:\n"
        "  id: stateport.fixture.governed-restore\n"
        "  releaseVersion: 1.0.0\n"
        "  stateddSpecVersion: statedd.stateport.io/v1alpha1\n"
        "  instanceSchemaVersion: statedd.stateport.io/instance/v1alpha1\n"
        "source:\n"
        "  class: synthetic_fixture\n"
        "  productionEligible: false\n"
        "modules:\n"
        "  - id: core\n"
        "    contractVersion: \"1.0\"\n"
        "    dependencies: []\n"
        "    conflicts: []\n"
        "    capabilities:\n"
        "      - read_state\n"
        "    assets:\n"
        "      - guide\n"
        "      - instance-definition\n"
        "      - durable-state\n"
        "      - lifecycle-lock\n"
        "    selfTests:\n"
        "      - id: governed-restore-contract\n"
        "    order: 10\n"
        "selectedModules:\n"
        "  - core\n"
        "assets:\n"
        "  - id: guide\n"
        "    path: README.md\n"
        "    kind: file\n"
        "    owner: template\n"
        "    role: operator_guide\n"
        "    provisionPolicy: copy_from_template\n"
        "    updatePolicy: replace_if_unmodified\n"
        "    required: true\n"
        "    schema: null\n"
        "    sensitivity: public\n"
        "    source: README.md\n"
        "    selectingModules:\n"
        "      - core\n"
        "  - id: durable-state\n"
        "    path: state\n"
        "    kind: tree\n"
        "    owner: instance\n"
        "    role: durable_state\n"
        "    provisionPolicy: create_if_missing\n"
        "    updatePolicy: preserve\n"
        "    required: true\n"
        "    schema: null\n"
        "    sensitivity: private\n"
        "    selectingModules:\n"
        "      - core\n"
        "  - id: instance-definition\n"
        "    path: instance.yaml\n"
        "    kind: file\n"
        "    owner: instance\n"
        "    role: instance_definition\n"
        "    provisionPolicy: create_if_missing\n"
        "    updatePolicy: preserve\n"
        "    required: true\n"
        "    schema: statedd.stateport.io/instance/v1alpha1\n"
        "    sensitivity: private\n"
        "    selectingModules:\n"
        "      - core\n"
        "  - id: lifecycle-lock\n"
        "    path: .statedd/lock.yaml\n"
        "    kind: file\n"
        "    owner: generated\n"
        "    role: lifecycle_lock\n"
        "    provisionPolicy: generated_output\n"
        "    updatePolicy: generated\n"
        "    required: true\n"
        "    schema: statedd.stateport.io/lock/v1\n"
        "    sensitivity: internal\n"
        "    generator: materializer\n"
        "    selectingModules:\n"
        "      - core\n",
        encoding="utf-8",
    )
    (root / "state" / "notes.md").write_text(
        "durable synthetic recovery state\n", encoding="utf-8"
    )
    (root / ".statedd" / "lock.yaml").unlink()
    lock = materialize_instance(root / "template", root, allow_fixture=True)
    lock["template"]["sourcePath"] = "template"
    lock["template"]["source"]["checkoutLocation"] = "template"
    (root / ".statedd" / "lock.yaml").write_text(
        yaml.dump(lock, Dumper=_IndentedDumper, sort_keys=False), encoding="utf-8"
    )
    app.catalog.register(
        root,
        instance_id=instance_id,
        name="Governed restore fixture",
        source={
            "templateId": "stateport.fixture.governed-restore",
            **lock["template"]["source"],
        },
    )
    return root


def _planned(app: PersistentApp, source_id: str = "restore-source") -> tuple[dict, dict]:
    backup = app.backup(source_id)
    plan = app.restore_plan(
        source_id,
        backup_receipt_id=backup["backupReceipt"]["receiptId"],
        destination_instance_id="restore-result",
        destination_name="Recovered fixture",
    )
    approval = app.approve_restore(
        source_id,
        plan_digest=plan["planDigest"],
        actor_id="test-operator",
        actor_role="local_operator",
    )
    return plan, approval


def test_same_second_backups_keep_distinct_verified_recovery_points(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _app(tmp_path, monkeypatch)
    root = _instance(app)
    before = _digest_tree(root)

    class FixedClock(real_datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 9, 5, 12, 0, 0, tzinfo=tz)

    monkeypatch.setattr(persistent_app_module, "datetime", FixedClock)
    first = app.backup("restore-source")
    second = app.backup("restore-source")
    assert first["archive"] != second["archive"]
    assert first["backupReceipt"]["receiptId"] != second["backupReceipt"]["receiptId"]
    for backup in (first, second):
        assert Path(backup["archive"]).is_file()
        plan = app.restore_plan(
            "restore-source", backup_receipt_id=backup["backupReceipt"]["receiptId"],
            destination_instance_id="restored-backup", destination_name="Restored backup",
        )
        assert plan["planDigest"]
    assert _digest_tree(root) == before


def test_governed_restore_is_path_free_new_identity_and_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _app(tmp_path, monkeypatch)
    source = _instance(app)
    source_digest = _digest_tree(source)
    plan, approval = _planned(app)

    encoded_plan = json.dumps(plan, sort_keys=True)
    assert tmp_path.as_posix() not in encoded_plan
    assert plan["identityPolicy"] == "reidentify"
    assert plan["effects"] == {
        "sourceCanonicalState": "unchanged",
        "destinationCanonicalState": "new_instance_created",
        "externalEffectsRestored": False,
        "overwriteAllowed": False,
        "sourceAccess": {"disposition": "not_propagated"},
    }

    receipt = app.apply_restore(
        "restore-source",
        plan_digest=plan["planDigest"],
        approval_digest=approval["approvalDigest"],
    )
    assert receipt["status"] == "validated"
    for value, schema_name in (
        (plan, "restore-plan.v1.schema.json"),
        (approval, "restore-approval.v1.schema.json"),
        (receipt, "restore-receipt.v1.schema.json"),
    ):
        assert validate_json_schema(value, load_schema(ROOT / "schemas" / schema_name)) == []
    assert receipt["result"]["instanceId"] == "restore-result"
    assert receipt["effects"]["externalEffectsRestored"] is False
    assert tmp_path.as_posix() not in json.dumps(receipt, sort_keys=True)
    assert _digest_tree(source) == source_digest

    destination = app.layout.instances_root / "restore-result"
    assert destination.is_dir()
    assert (destination / ".git").is_dir()
    assert 'id: "restore-result"' in (destination / "instance.yaml").read_text()
    restored_lock = yaml.safe_load((destination / ".statedd/lock.yaml").read_text())
    assert restored_lock["instanceId"] == "restore-result"
    assert app.catalog.get("restore-result")["pathState"] == "present"

    repeated = app.apply_restore(
        "restore-source",
        plan_digest=plan["planDigest"],
        approval_digest=approval["approvalDigest"],
    )
    assert repeated == receipt
    status = app.recovery_status("restore-source")
    assert status["formatVersion"] == "stateport.recovery-status/v1"
    assert status["restore"]["status"] == "validated"
    assert validate_json_schema(
        status, load_schema(ROOT / "schemas" / "recovery-status.v1.schema.json")
    ) == []
    assert "archive" not in status["latest"]


def test_restore_refuses_destination_and_backup_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _app(tmp_path, monkeypatch)
    _instance(app)
    plan, approval = _planned(app)
    destination = app.layout.instances_root / "restore-result"
    destination.mkdir()
    (destination / "owner.txt").write_text("unrelated\n", encoding="utf-8")
    with pytest.raises(AppError, match="destination already exists"):
        app.apply_restore(
            "restore-source",
            plan_digest=plan["planDigest"],
            approval_digest=approval["approvalDigest"],
        )
    assert (destination / "owner.txt").read_text() == "unrelated\n"
    destination.rename(app.layout.instances_root / "owner-preserved")

    archive = next((app.layout.backups_root / "restore-source").glob("*.tar"))
    archive.write_bytes(archive.read_bytes() + b"tampered")
    with pytest.raises(AppError, match="backup"):
        app.apply_restore(
            "restore-source",
            plan_digest=plan["planDigest"],
            approval_digest=approval["approvalDigest"],
        )


def test_failed_restore_surfaces_retained_staging_without_host_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _app(tmp_path, monkeypatch)
    _instance(app)
    plan, approval = _planned(app)

    monkeypatch.setattr(
        instance_backup,
        "_atomic_promote_new_directory",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("interrupted promotion")),
    )
    with pytest.raises(AppError, match="restore transaction failed"):
        app.apply_restore(
            "restore-source",
            plan_digest=plan["planDigest"],
            approval_digest=approval["approvalDigest"],
        )

    status = app.recovery_status("restore-source")
    assert status["restore"] == {
        "status": "failed",
        "latestPlanDigest": plan["planDigest"],
        "latestApprovalDigest": approval["approvalDigest"],
        "latestReceiptId": None,
        "operatorInspectionRequired": True,
        "stagingRetained": True,
        "destinationInstanceId": "restore-result",
        "expiresAt": plan["expiresAt"],
        "failureReasonCode": "restore_apply_failed",
    }
    assert tmp_path.as_posix() not in json.dumps(status, sort_keys=True)
    assert validate_json_schema(
        status, load_schema(ROOT / "schemas" / "recovery-status.v1.schema.json")
    ) == []


def test_restore_approval_and_direct_mutation_boundaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _app(tmp_path, monkeypatch)
    _instance(app)
    backup = app.backup("restore-source")
    plan = app.restore_plan(
        "restore-source",
        backup_receipt_id=backup["backupReceipt"]["receiptId"],
        destination_instance_id="restore-result",
    )
    with pytest.raises(ApprovalError, match="operator role"):
        app.approve_restore(
            "restore-source",
            plan_digest=plan["planDigest"],
            actor_id="browser-user",
            actor_role="local_user",
        )
    with pytest.raises(ApprovalError):
        app.apply_restore(
            "restore-source",
            plan_digest=plan["planDigest"],
            approval_digest="sha256:" + "0" * 64,
        )
    assert not (app.layout.instances_root / "restore-result").exists()
    with pytest.raises(ValueError, match="direct backup restore is dry-run only"):
        backup_cmd(
            Namespace(
                backup_command="restore",
                archive_path=str(next((app.layout.backups_root / "restore-source").glob("*.tar"))),
                target_path=str(app.layout.instances_root / "direct-bypass"),
                dry_run=False,
                identity_policy="reidentify",
                new_instance_id="direct-bypass",
                json=True,
            )
        )


def test_restore_plan_rejects_same_identity_and_public_status_redacts_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _app(tmp_path, monkeypatch)
    _instance(app)
    backup = app.backup("restore-source")
    with pytest.raises(AppError, match="different instance identity"):
        app.restore_plan(
            "restore-source",
            backup_receipt_id=backup["backupReceipt"]["receiptId"],
            destination_instance_id="restore-source",
        )
    status = app.recovery_status("restore-source")
    assert tmp_path.as_posix() not in json.dumps(status, sort_keys=True)
    assert status["limitations"]["externalEffectsRestored"] is False


def test_recovery_status_revalidates_persisted_plan_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _app(tmp_path, monkeypatch)
    _instance(app)
    plan, _approval = _planned(app)
    path = app._restore_artifact_path("plans", plan["planDigest"])
    tampered = json.loads(path.read_text(encoding="utf-8"))
    tampered["destinationName"] = "Tampered status projection"
    path.write_text(json.dumps(tampered), encoding="utf-8")

    with pytest.raises(ApprovalError, match="restore plan digest is invalid"):
        app.recovery_status("restore-source")


def test_recovery_status_revalidates_persisted_receipt_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _app(tmp_path, monkeypatch)
    _instance(app)
    plan, approval = _planned(app)
    app.apply_restore(
        "restore-source",
        plan_digest=plan["planDigest"],
        approval_digest=approval["approvalDigest"],
    )
    path = app._restore_artifact_path("receipts", plan["planDigest"])
    tampered = json.loads(path.read_text(encoding="utf-8"))
    tampered["status"] = "failed"
    path.write_text(json.dumps(tampered), encoding="utf-8")

    with pytest.raises(ApprovalError, match="restore receipt digest is invalid"):
        app.recovery_status("restore-source")


@pytest.mark.parametrize("kind", ("plans", "approvals", "failures"))
def test_recovery_status_refuses_symlinked_operation_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    app = _app(tmp_path, monkeypatch)
    _instance(app)
    _planned(app)
    root = app._restore_operations_root / kind
    root.mkdir(parents=True, exist_ok=True)
    (root / f"{'0' * 64}.json").symlink_to(tmp_path / "missing-artifact.json")

    with pytest.raises(ApprovalError, match=f"restore {kind} inventory contains"):
        app.recovery_status("restore-source")


def test_recovery_status_refuses_a_symlinked_expected_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _app(tmp_path, monkeypatch)
    _instance(app)
    plan, approval = _planned(app)
    app.apply_restore(
        "restore-source",
        plan_digest=plan["planDigest"],
        approval_digest=approval["approvalDigest"],
    )
    path = app._restore_artifact_path("receipts", plan["planDigest"])
    path.unlink()
    path.symlink_to(tmp_path / "missing-receipt.json")

    with pytest.raises(ApprovalError, match="receipts inventory contains an unsafe"):
        app.recovery_status("restore-source")


def test_recovery_status_refuses_to_truncate_operation_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _app(tmp_path, monkeypatch)
    _instance(app)
    _planned(app)
    monkeypatch.setattr(persistent_app_module, "_RESTORE_STATUS_ARTIFACT_LIMIT", 0)

    with pytest.raises(ApprovalError, match="inventory exceeds the safe review limit"):
        app.recovery_status("restore-source")


def test_recovery_status_refuses_a_symlinked_restore_ancestor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _app(tmp_path, monkeypatch)
    _instance(app)
    external = tmp_path / "external-restores"
    external.mkdir()
    app._restore_operations_root.symlink_to(external, target_is_directory=True)

    with pytest.raises(ApprovalError, match="plans inventory is unsafe"):
        app.recovery_status("restore-source")


def test_recovery_status_refuses_a_symlinked_receipts_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _app(tmp_path, monkeypatch)
    _instance(app)
    _planned(app)
    external = tmp_path / "external-receipts"
    external.mkdir()
    (app._restore_operations_root / "receipts").symlink_to(
        external, target_is_directory=True
    )

    with pytest.raises(ApprovalError, match="receipts inventory is unsafe"):
        app.recovery_status("restore-source")


def test_recovery_status_refuses_nonconforming_inventory_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _app(tmp_path, monkeypatch)
    _instance(app)
    _planned(app)
    (app._restore_operations_root / "plans" / "hidden.json.bak").write_text(
        "{}\n", encoding="utf-8"
    )

    with pytest.raises(ApprovalError, match="plans inventory contains an unexpected"):
        app.recovery_status("restore-source")


def test_restore_artifact_publication_refuses_a_symlinked_ancestor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _app(tmp_path, monkeypatch)
    _instance(app)
    backup = app.backup("restore-source")
    external = tmp_path / "external-operation-store"
    external.mkdir()
    app._restore_operations_root.symlink_to(external, target_is_directory=True)

    with pytest.raises(ApprovalError, match="plans inventory is unsafe"):
        app.restore_plan(
            "restore-source",
            backup_receipt_id=backup["backupReceipt"]["receiptId"],
            destination_instance_id="restore-result",
        )
    assert list(external.iterdir()) == []


def test_restore_lock_refuses_a_symlinked_lock_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _app(tmp_path, monkeypatch)
    _instance(app)
    plan, approval = _planned(app)
    external = tmp_path / "external-lock-store"
    external.mkdir()
    (app._restore_operations_root / "locks").symlink_to(
        external, target_is_directory=True
    )

    with pytest.raises(ApprovalError, match="locks inventory is unsafe"):
        app.apply_restore(
            "restore-source",
            plan_digest=plan["planDigest"],
            approval_digest=approval["approvalDigest"],
        )
    assert list(external.iterdir()) == []
    assert not (app.layout.instances_root / "restore-result").exists()


def test_restore_artifact_cleanup_never_unlinks_a_racing_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _app(tmp_path, monkeypatch)
    digest = "sha256:" + "1" * 64
    target = app._restore_artifact_path("plans", digest)
    real_fchmod = os.fchmod
    replaced = False

    def replace_after_creation(descriptor: int, mode: int) -> None:
        nonlocal replaced
        real_fchmod(descriptor, mode)
        if not replaced:
            replaced = True
            target.unlink()
            target.write_text("foreign replacement\n", encoding="utf-8")

    monkeypatch.setattr(os, "fchmod", replace_after_creation)
    with pytest.raises(AppError, match="artifact ownership changed"):
        app._write_restore_artifact_new(
            "plans", digest, {"formatVersion": "fixture"}
        )

    assert target.read_text(encoding="utf-8") == "foreign replacement\n"


def test_operator_http_restore_uses_same_plan_approval_and_receipt_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _app(tmp_path, monkeypatch)
    _instance(app)
    backup = app.backup("restore-source")
    product_root = service_product_fixture(tmp_path, ROOT)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = int(probe.getsockname()[1])
    base = f"http://127.0.0.1:{port}"

    def start(role: str) -> tuple[str, str]:
        app.service_start(port=port, repo_root=product_root, actor_role=role)
        with urlopen(f"{base}/session") as response:
            result = json.loads(response.read())["result"]
            return response.headers["Set-Cookie"].split(";", 1)[0], result["csrfToken"]

    def post(path: str, cookie: str, csrf: str, body: dict) -> dict:
        with urlopen(
            Request(
                f"{base}{path}",
                data=json.dumps(body).encode(),
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "Cookie": cookie,
                    "Origin": base,
                    "X-StatePort-CSRF": csrf,
                },
            )
        ) as response:
            return json.loads(response.read())["result"]

    try:
        cookie, csrf = start("local_user")
        with pytest.raises(HTTPError) as denied:
            post(
                "/v1/instances/restore-source/recovery/restore/plan",
                cookie,
                csrf,
                {
                    "backupReceiptId": backup["backupReceipt"]["receiptId"],
                    "destinationInstanceId": "restore-http",
                    "destinationName": "HTTP restore",
                },
            )
        assert denied.value.code == 403
        app.service_stop()

        _operator_boundary_fixture(app)
        cookie, csrf = start("platform_operator")
        plan = post(
            "/v1/instances/restore-source/recovery/restore/plan",
            cookie,
            csrf,
            {
                "backupReceiptId": backup["backupReceipt"]["receiptId"],
                "destinationInstanceId": "restore-http",
                "destinationName": "HTTP restore",
            },
        )
        approval = post(
            "/v1/instances/restore-source/recovery/restore/approve",
            cookie,
            csrf,
            {"planDigest": plan["planDigest"]},
        )
        receipt = post(
            "/v1/instances/restore-source/recovery/restore/apply",
            cookie,
            csrf,
            {
                "planDigest": plan["planDigest"],
                "approvalDigest": approval["approvalDigest"],
            },
        )
        assert receipt["status"] == "validated"
        assert receipt["destinationInstanceId"] == "restore-http"
        with urlopen(
            Request(
                f"{base}/v1/instances/restore-source/recovery",
                headers={"Cookie": cookie},
            )
        ) as response:
            status = json.loads(response.read())["result"]
        assert status["restore"]["latestReceiptId"] == receipt["receiptId"]
        assert tmp_path.as_posix() not in json.dumps(status, sort_keys=True)
    finally:
        app.service_stop()
