"""Focused persistent StudyDD application journey without private data."""

from __future__ import annotations

import os
import json
from pathlib import Path
import shutil
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
    "apps/runner/src",
    "apps/admin-cli/src",
):
    path = ROOT / relative
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from stateport_persistent_app import AppError, LocalLayout, PersistentApp  # noqa: E402
import stateport_persistent_app.app as app_module  # noqa: E402
from template_validator.validator import validate_instance  # noqa: E402
from admin_cli.main import main as cli_main  # noqa: E402
from service_test_product import service_product_fixture  # noqa: E402


def test_bootstrap_rejects_rendered_destination_collisions_before_writes(
    tmp_path: Path,
) -> None:
    root = tmp_path / "instance"
    root.mkdir()
    contract = {
        "formatVersion": "synthetic.bootstrap/v1",
        "fields": [
            {"id": "first_id", "type": "identifier", "required": True},
            {"id": "second_id", "type": "identifier", "required": True},
        ],
        "writes": [
            {
                "path": "targets/{first_id}/TARGET.yaml",
                "format": "text",
                "template": "first\n",
            },
            {
                "path": "targets/{second_id}/TARGET.yaml",
                "format": "text",
                "template": "second\n",
            },
        ],
    }

    with pytest.raises(app_module.BootstrapError, match="conflicts"):
        app_module.apply_bootstrap(
            contract,
            root,
            {"first_id": "same-id", "second_id": "same-id"},
        )

    assert list(root.iterdir()) == []


@pytest.mark.skipif(not os.environ.get("STATEPORT_STUDYDD_MIRROR"), reason="set STATEPORT_STUDYDD_MIRROR to run the cross-repository journey")
def test_persistent_create_inspect_run_backup_restore_and_metadata_reimport(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    destination = app.layout.instances_root / "StudyDD-AI103"
    plan = app.plan_create(
        source_profile="builtin:studydd-local-alpha",
        destination=str(destination),
            instance_id="studydd-ai103",
            name="AI-103 Study",
            owner_name="Synthetic Owner",
            owner_handle="synthetic-owner",
            target_id="ai-103",
        target_title="AI-103",
        allow_development_candidate=True,
    )
    created = app.create(plan, app.approve(plan))
    assert created["ok"] is True
    assert app.inspect("studydd-ai103")["source"]["resolvedCommit"] == plan["source"]["resolvedCommit"]
    run = app.synthetic_run("studydd-ai103")
    assert run["status"] == "passed"
    backup = app.backup("studydd-ai103")
    assert backup["validation"] == "verified"
    restore_plan = app.restore_plan(
        "studydd-ai103",
        backup_receipt_id=backup["backupReceipt"]["receiptId"],
        destination_instance_id="studydd-ai103-restored",
    )
    restore_approval = app.approve_restore(
        "studydd-ai103",
        plan_digest=restore_plan["planDigest"],
        actor_id="test-operator",
        actor_role="local_operator",
    )
    restored = app.apply_restore(
        "studydd-ai103",
        plan_digest=restore_plan["planDigest"],
        approval_digest=restore_approval["approvalDigest"],
    )
    assert restore_plan["effects"]["sourceAccess"] == {
        "disposition": "propagate_exact_receipt",
        "sourceAccessClass": "development_candidate",
        "productionInstallAllowed": False,
        "sourceReceiptDigest": app.source_access_authorization("studydd-ai103")[
            "receiptDigest"
        ],
    }
    assert restored["effects"]["sourceAccess"]["disposition"] == "propagated"
    assert restored["effects"]["sourceAccess"]["destinationReceiptDigest"] == (
        app.source_access_authorization("studydd-ai103-restored")["receiptDigest"]
    )
    assert app.development_candidate_testing_allowed("studydd-ai103-restored") is True
    assert app.inspect("studydd-ai103-restored")["source"]["productionInstallAllowed"] is False
    app.setup_uninstall()
    assert destination.is_dir()
    app.setup_init()
    imported = app.import_instance(str(destination))
    assert imported["ok"] is True
    assert app.inspect("studydd-ai103")["recovery"]["status"] == "verified"
    assert app.development_candidate_testing_allowed("studydd-ai103") is False
    assert "sourceAccessClass" not in app.inspect("studydd-ai103")["source"]


@pytest.mark.skipif(not os.environ.get("STATEPORT_STUDYDD_MIRROR"), reason="set STATEPORT_STUDYDD_MIRROR to run the cross-repository journey")
def test_explicit_development_candidate_consent_reaches_service_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    mirror = Path(os.environ["STATEPORT_STUDYDD_MIRROR"])
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    assert cli_main(["setup", "--source-mirror", str(mirror), "init", "--json"]) == 0
    capsys.readouterr()
    arguments = [
        "instance", "plan-create",
        "--source-profile", "builtin:studydd-local-alpha",
        "--instance-id", "candidate-service-study",
        "--name", "Candidate service study",
        "--owner-name", "Synthetic Owner",
        "--target-id", "service-test",
        "--seed-mode", "synthetic-demo",
        "--json",
    ]
    with pytest.raises(AppError, match="awaiting a verified release"):
        cli_main(arguments)
    capsys.readouterr()
    assert cli_main([*arguments[:-1], "--allow-development-candidate", "--json"]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["sourceAccessClass"] == "development_candidate"
    assert plan["productionInstallAllowed"] is False

    app = PersistentApp(LocalLayout.from_environment())
    created = app.create(plan, app.approve(plan))
    assert created["sourceAccessClass"] == "development_candidate"
    assert app.development_candidate_testing_allowed("candidate-service-study") is True
    inspected = app.inspect("candidate-service-study")
    assert inspected["source"]["sourceAccessClass"] == "development_candidate"
    assert inspected["source"]["productionInstallAllowed"] is False

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = int(probe.getsockname()[1])
    app.service_start(port=port, repo_root=service_product_fixture(tmp_path, ROOT))
    base = f"http://127.0.0.1:{port}"
    try:
        with urlopen(f"{base}/session") as response:
            session = json.loads(response.read())["result"]
            cookie = response.headers["Set-Cookie"].split(";", 1)[0]
        with urlopen(Request(f"{base}/v1/instances/candidate-service-study/actions", headers={"Cookie": cookie})) as response:
            actions = json.loads(response.read())["result"]["actions"]
        assert "studydd.plan-next-session/v1" in {item["actionId"] for item in actions}
        body = {
            "expectedInstanceId": "candidate-service-study",
            "actionId": "studydd.plan-next-session/v1",
            "engineId": "synthetic",
            "inputs": {"timeAvailableMinutes": 20, "includeFastDrillProposal": True},
        }
        request = Request(
            f"{base}/v1/instances/candidate-service-study/execution/prepare",
            data=json.dumps(body).encode(),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Cookie": cookie,
                "Origin": base,
                "X-StatePort-CSRF": session["csrfToken"],
            },
        )
        with urlopen(request) as response:
            prepared = json.loads(response.read())["result"]
        assert prepared["run"]["status"] == "awaiting_approval"
        assert prepared["run"]["sourceAccessClass"] == "development_candidate"
        assert prepared["run"]["sourceAccessReceiptDigest"] == (
            app.source_access_authorization("candidate-service-study")["receiptDigest"]
        )
    finally:
        app.service_stop()


def test_catalog_source_access_fields_without_a_durable_receipt_do_not_grant_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    instance = app.layout.instances_root / "untrusted-access"
    (instance / ".statedd").mkdir(parents=True)
    source = {
        "formatVersion": "statedd.source/v2",
        "kind": "git",
        "sourceClass": "canonical_source",
        "productionEligible": True,
        "repository": "https://example.invalid/study-state.git",
        "resolvedCommit": "a" * 40,
        "resolvedTree": "b" * 40,
        "manifestDigest": "sha256:" + "c" * 64,
        "sourceDigest": "sha256:" + "d" * 64,
    }
    (instance / ".statedd" / "lock.yaml").write_text(
        json.dumps(
            {
                "formatVersion": "statedd.lock/v1",
                "instanceId": "untrusted-access",
                "template": {"id": "studydd", "source": source},
            }
        ),
        encoding="utf-8",
    )
    app.catalog.register(
        instance,
        instance_id="untrusted-access",
        name="Untrusted access",
        source={
            "templateId": "studydd",
            **source,
            "sourceAccessClass": "development_candidate",
            "productionInstallAllowed": False,
        },
    )

    assert app.development_candidate_testing_allowed("untrusted-access") is False
    inspected = app.inspect("untrusted-access")
    assert "sourceAccessClass" not in inspected["source"]
    assert "productionInstallAllowed" not in inspected["source"]
    public_entry = next(
        item
        for item in app.instance_list_public()
        if item["instanceId"] == "untrusted-access"
    )
    assert "sourceAccessClass" not in public_entry["observedSource"]
    assert "productionInstallAllowed" not in public_entry["observedSource"]


@pytest.mark.skipif(not os.environ.get("STATEPORT_STUDYDD_MIRROR"), reason="set STATEPORT_STUDYDD_MIRROR to run the cross-repository journey")
def test_source_access_receipt_does_not_follow_reincarnated_instance_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    plan = app.plan_create(
        source_profile="builtin:studydd-local-alpha",
        instance_id="receipt-reincarnation",
        name="Receipt reincarnation",
        owner_name="Synthetic Owner",
        owner_handle="synthetic-owner",
        target_id="receipt-test",
        allow_development_candidate=True,
    )
    app.create(plan, app.approve(plan))
    original = app.layout.instances_root / "receipt-reincarnation"
    retained = app.layout.instances_root / "receipt-reincarnation-original"
    original_identity = os.lstat(original).st_ino
    app.catalog.forget("receipt-reincarnation")
    os.replace(original, retained)
    shutil.copytree(retained, original)
    assert os.lstat(original).st_ino != original_identity

    app.import_instance(str(original))

    assert app.development_candidate_testing_allowed("receipt-reincarnation") is False
    inspected = app.inspect("receipt-reincarnation")
    assert "sourceAccessClass" not in inspected["source"]
    assert "productionInstallAllowed" not in inspected["source"]


@pytest.mark.skipif(not os.environ.get("STATEPORT_STUDYDD_MIRROR"), reason="set STATEPORT_STUDYDD_MIRROR to run the cross-repository journey")
def test_development_access_requires_the_current_development_only_trust_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    catalog_path = tmp_path / "studydd.yaml"
    catalog_path.write_bytes((ROOT / "sources/canonical/studydd.yaml").read_bytes())
    app = PersistentApp(
        LocalLayout.from_environment(), canonical_source_catalog=catalog_path
    )
    app.setup_init()
    plan = app.plan_create(
        source_profile="builtin:studydd-local-alpha",
        instance_id="revoked-trust-state",
        name="Revoked trust state",
        owner_name="Synthetic Owner",
        owner_handle="synthetic-owner",
        target_id="trust-test",
        allow_development_candidate=True,
    )
    app.create(plan, app.approve(plan))
    assert app.development_candidate_testing_allowed("revoked-trust-state") is True

    catalog = yaml.safe_load(catalog_path.read_text(encoding="utf-8"))
    catalog["trust"]["state"] = "unverified"
    _write = yaml.safe_dump(catalog, sort_keys=False)
    catalog_path.write_text(_write, encoding="utf-8")

    assert app.source_access_authorization("revoked-trust-state") is None
    assert app.development_candidate_testing_allowed("revoked-trust-state") is False


@pytest.mark.skipif(not os.environ.get("STATEPORT_STUDYDD_MIRROR"), reason="set STATEPORT_STUDYDD_MIRROR to run the cross-repository journey")
def test_existing_empty_destination_identity_and_metadata_survive_create_rollback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()

    successful = app.layout.instances_root / "existing-success"
    successful.mkdir()
    successful.chmod(0o750)
    success_identity = (os.lstat(successful).st_dev, os.lstat(successful).st_ino)
    success_plan = app.plan_create(
        source_profile="builtin:studydd-local-alpha",
        destination=str(successful),
        instance_id="existing-success",
        name="Existing success",
        owner_name="Synthetic Owner",
        owner_handle="synthetic-owner",
        target_id="existing-success",
        allow_development_candidate=True,
    )
    app.create(success_plan, app.approve(success_plan))
    assert (os.lstat(successful).st_dev, os.lstat(successful).st_ino) == success_identity
    assert os.lstat(successful).st_mode & 0o777 == 0o750

    rolled_back = app.layout.instances_root / "existing-rollback"
    rolled_back.mkdir()
    rolled_back.chmod(0o710)
    rollback_plan = app.plan_create(
        source_profile="builtin:studydd-local-alpha",
        destination=str(rolled_back),
        instance_id="existing-rollback",
        name="Existing rollback",
        owner_name="Synthetic Owner",
        owner_handle="synthetic-owner",
        target_id="existing-rollback",
        allow_development_candidate=True,
    )
    timestamp = 1_700_000_000_123_456_789
    os.utime(rolled_back, ns=(timestamp, timestamp))
    before = os.lstat(rolled_back)

    def fail_catalog_registration(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("synthetic post-promotion failure")

    monkeypatch.setattr(app.catalog, "register", fail_catalog_registration)
    with pytest.raises(RuntimeError, match="post-promotion"):
        app.create(rollback_plan, app.approve(rollback_plan))

    after = os.lstat(rolled_back)
    assert (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino)
    assert after.st_mode & 0o777 == before.st_mode & 0o777
    assert after.st_atime_ns == before.st_atime_ns
    assert after.st_mtime_ns == before.st_mtime_ns
    assert not any(rolled_back.iterdir())
    assert not app._source_access_path("existing-rollback").exists()


@pytest.mark.skipif(not os.environ.get("STATEPORT_STUDYDD_MIRROR"), reason="set STATEPORT_STUDYDD_MIRROR to run the cross-repository journey")
def test_create_never_replaces_a_destination_that_appears_during_promotion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    destination = app.layout.instances_root / "racing-destination"
    plan = app.plan_create(
        source_profile="builtin:studydd-local-alpha",
        destination=str(destination),
        instance_id="racing-destination",
        name="Racing destination",
        owner_name="Synthetic Owner",
        owner_handle="synthetic-owner",
        target_id="promotion-race",
        allow_development_candidate=True,
    )
    real_rename = app_module._rename_no_replace
    race_injected = False

    def inject_destination(
        source_parent: int,
        source_name: str,
        destination_parent: int,
        destination_name: str,
    ) -> None:
        nonlocal race_injected
        if not race_injected and destination_name == destination.name:
            race_injected = True
            destination.mkdir()
            (destination / "foreign.txt").write_text(
                "foreign state\n",
                encoding="utf-8",
            )
        real_rename(
            source_parent,
            source_name,
            destination_parent,
            destination_name,
        )

    monkeypatch.setattr(app_module, "_rename_no_replace", inject_destination)

    with pytest.raises(AppError, match="destination appeared during promotion"):
        app.create(plan, app.approve(plan))

    assert race_injected is True
    assert (destination / "foreign.txt").read_text(encoding="utf-8") == "foreign state\n"
    assert not app._source_access_path("racing-destination").exists()
    with pytest.raises(AppError):
        app.catalog.get("racing-destination")


@pytest.mark.skipif(not os.environ.get("STATEPORT_STUDYDD_MIRROR"), reason="set STATEPORT_STUDYDD_MIRROR to run the cross-repository journey")
def test_restore_rechecks_source_receipt_inside_destination_receipt_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    plan = app.plan_create(
        source_profile="builtin:studydd-local-alpha",
        instance_id="restore-race-source",
        name="Restore race source",
        owner_name="Synthetic Owner",
        owner_handle="synthetic-owner",
        target_id="restore-race",
        allow_development_candidate=True,
    )
    app.create(plan, app.approve(plan))
    backup = app.backup("restore-race-source")
    restore_plan = app.restore_plan(
        "restore-race-source",
        backup_receipt_id=backup["backupReceipt"]["receiptId"],
        destination_instance_id="restore-race-result",
    )
    approval = app.approve_restore(
        "restore-race-source",
        plan_digest=restore_plan["planDigest"],
        actor_id="test-operator",
        actor_role="local_operator",
    )
    source_receipt = app._source_access_path("restore-race-source")
    original_record = app._record_source_access_receipt

    def revoke_then_record(*args: object, **kwargs: object) -> dict[str, object]:
        source_receipt.unlink()
        return original_record(*args, **kwargs)

    monkeypatch.setattr(app, "_record_source_access_receipt", revoke_then_record)
    with pytest.raises(AppError, match="source access changed before effect"):
        app.apply_restore(
            "restore-race-source",
            plan_digest=restore_plan["planDigest"],
            approval_digest=approval["approvalDigest"],
        )

    assert not app._source_access_path("restore-race-result").exists()
    assert app.development_candidate_testing_allowed("restore-race-result") is False
    with pytest.raises(AppError):
        app.catalog.get("restore-race-result")


@pytest.mark.skipif(not os.environ.get("STATEPORT_STUDYDD_MIRROR"), reason="set STATEPORT_STUDYDD_MIRROR to run the cross-repository journey")
def test_create_failure_before_promotion_preserves_existing_empty_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    destination = app.layout.instances_root / "preserved-empty"
    destination.mkdir()
    identity = (os.lstat(destination).st_dev, os.lstat(destination).st_ino)
    plan = app.plan_create(
        source_profile="builtin:studydd-local-alpha",
        destination=str(destination),
        instance_id="preserved-empty",
        name="Preserved empty destination",
        owner_name="Synthetic Owner",
        owner_handle="synthetic-owner",
        target_id="rollback-test",
        allow_development_candidate=True,
    )

    def fail_before_promotion(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("synthetic pre-promotion failure")

    monkeypatch.setattr(app_module, "create_instance", fail_before_promotion)
    with pytest.raises(RuntimeError, match="pre-promotion"):
        app.create(plan, app.approve(plan))

    assert destination.is_dir()
    assert not any(destination.iterdir())
    assert (os.lstat(destination).st_dev, os.lstat(destination).st_ino) == identity


@pytest.mark.skipif(not os.environ.get("STATEPORT_STUDYDD_MIRROR"), reason="set STATEPORT_STUDYDD_MIRROR to run the cross-repository journey")
def test_studydd_external_descriptor_rejects_malformed_domain_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    plan = app.plan_create(
        source_profile="builtin:studydd-local-alpha",
        instance_id="malformed-domain-target",
        name="Malformed domain target",
        owner_name="Synthetic Owner",
        owner_handle="synthetic-owner",
        target_id="domain-target",
        allow_development_candidate=True,
    )
    app.create(plan, app.approve(plan))
    instance = app.layout.instances_root / "malformed-domain-target"
    descriptor_path = instance / "instance.yaml"
    descriptor = yaml.safe_load(descriptor_path.read_text(encoding="utf-8"))
    descriptor["spec"]["target"] = "not-a-domain-target"
    descriptor_path.write_text(
        yaml.safe_dump(descriptor, sort_keys=False), encoding="utf-8"
    )

    result = validate_instance(instance)

    assert not result.ok
    assert any(
        issue.path == "instance.yaml.spec.target"
        and "descriptor value must be a mapping" in issue.message
        for issue in result.issues
    )


def test_service_stop_waits_for_listener_before_restart(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = int(probe.getsockname()[1])
    product_root = service_product_fixture(tmp_path, ROOT)
    first = app.service_start(port=port, repo_root=product_root)
    assert first["status"] == "running"
    first_pid = first["pid"]
    held_connection = socket.create_connection(("127.0.0.1", port), timeout=1)
    try:
        assert app.service_stop()["status"] == "stopped"
        assert app.service_status()["status"] == "stopped"
        with pytest.raises(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=0.2)
        with socket.socket() as rebound:
            rebound.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            rebound.bind(("127.0.0.1", port))
        second = app.service_start(port=port, repo_root=product_root)
        assert second["status"] == "running" and second["pid"] != first_pid
    finally:
        held_connection.close()
        app.service_stop()


def test_recovery_revalidates_backup_archive_and_emits_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    instance = app.layout.instances_root / "backup-fixture"
    (instance / ".statedd").mkdir(parents=True)
    (instance / "state").mkdir()
    (instance / "instance.yaml").write_text(
        "metadata:\n  id: backup-fixture\n  name: Backup fixture\n",
        encoding="utf-8",
    )
    (instance / ".statedd" / "lock.yaml").write_text(
        json.dumps({
            "formatVersion": "statedd.lock/v1",
            "instanceId": "backup-fixture",
            "template": {"id": "synthetic-template", "source": {"sourceDigest": "sha256:" + "1" * 64}},
            "files": [
                {"path": "instance.yaml", "owner": "instance", "sensitivity": "private"},
                {"path": ".statedd/lock.yaml", "owner": "generated", "sensitivity": "internal"},
                {"path": "state/notes.md", "owner": "instance", "sensitivity": "private"},
            ],
        }),
        encoding="utf-8",
    )
    (instance / "state" / "notes.md").write_text("durable backup fixture\n", encoding="utf-8")
    app.catalog.register(instance, instance_id="backup-fixture", name="Backup fixture", source={"templateId": "synthetic-template"})

    summary = app.backup("backup-fixture")
    assert summary["backupReceipt"]["formatVersion"] == "stateport.backup-receipt/v1"
    assert app.inspect("backup-fixture")["recovery"]["status"] == "verified"

    archive = Path(str(summary["archive"]))
    archive.write_bytes(archive.read_bytes() + b"tampered")
    recovery = app.inspect("backup-fixture")["recovery"]
    assert recovery["status"] == "degraded"
    assert recovery["operatorInspectionRequired"] is True
    assert recovery["verificationIssues"]


def test_service_exposes_typed_global_and_application_settings_with_receipts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    instance = app.layout.instances_root / "settings-fixture"
    instance.mkdir(parents=True)
    app.catalog.register(instance, instance_id="settings-fixture", name="Settings fixture", source={"templateId": "stateport.development-reference"})
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = int(probe.getsockname()[1])
    app.service_start(port=port)
    base = f"http://127.0.0.1:{port}"

    def session() -> tuple[str, str]:
        with urlopen(f"{base}/session") as response:
            payload = json.loads(response.read())["result"]
            return response.headers["Set-Cookie"].split(";", 1)[0], payload["csrfToken"]

    def request(path: str, cookie: str, csrf: str, method: str = "GET", body: dict[str, object] | None = None) -> dict[str, object]:
        headers = {"Cookie": cookie}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers.update({"Content-Type": "application/json", "Origin": base, "X-StatePort-CSRF": csrf})
        with urlopen(Request(f"{base}{path}", data=data, method=method, headers=headers)) as response:
            return json.loads(response.read())["result"]

    try:
        cookie, csrf = session()
        global_settings = request("/v1/settings", cookie, csrf)
        assert global_settings["formatVersion"] == "stateport.settings-projection/v1"
        application_settings = request("/v1/instances/settings-fixture/settings", cookie, csrf)
        assert application_settings["scope"] == "application"
        application_keys = {
            field["key"]
            for section in application_settings["sections"]
            for field in section["fields"]
        }
        assert "general.appearance" not in application_keys
        with pytest.raises(HTTPError) as application_scope_error:
            request(
                "/v1/instances/settings-fixture/settings",
                cookie,
                csrf,
                "POST",
                {"expectedRevision": 0, "changes": {"general.appearance": "dark"}},
            )
        # The service classifies a scope/authority mismatch as a conflict so
        # clients know to reload the effective projection rather than retrying
        # the same inert field.
        assert application_scope_error.value.code == 409
        changed = request("/v1/settings", cookie, csrf, "POST", {"expectedRevision": 0, "changes": {"general.defaultLandingView": "catalog"}})
        assert changed["receipt"]["formatVersion"] == "stateport.settings-mutation-receipt/v1"
        assert changed["projection"]["revision"] == 1
        with pytest.raises(HTTPError) as stale:
            request("/v1/settings", cookie, csrf, "POST", {"expectedRevision": 0, "changes": {"context.mode": "deeper"}})
        assert stale.value.code == 409
    finally:
        app.service_stop()
    second = app.service_start(port=port)
    assert second["status"] == "running"
    assert app.service_stop()["status"] == "stopped"


def test_inspect_describes_registered_fixture_without_instance_materialization(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A registered development fixture (application.yaml only) must inspect honestly.

    Regression for the ProjectState CTO pilot P1: the instance was registered as a
    raw fixture and bypassed the install-time instance.yaml/.statedd/lock.yaml
    materialization, which previously crashed inspect() with operation_failed and
    made the application impossible to open from the browser.
    """
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()

    fixture = app.layout.instances_root / "dev-raw-fixture"
    fixture.mkdir(parents=True)
    (fixture / "application.yaml").write_text(
        "formatVersion: stateport.application/v1\n"
        "applicationId: stateport.development-reference\n"
        "displayName: ProjectState\n"
        "description: A public-safe development application.\n"
        "sourceProfile: fixture:development-reference\n"
        "productionEligible: false\n",
        encoding="utf-8",
    )
    (fixture / "actions.yaml").write_text(
        "formatVersion: stateport.application-action/v1\n"
        "applicationId: stateport.development-reference\n"
        "actions: []\n",
        encoding="utf-8",
    )
    app.catalog.register(
        fixture,
        instance_id="dev-raw-fixture",
        name="Development raw fixture",
        source={"templateId": "stateport.development-reference"},
    )

    result = app.inspect("dev-raw-fixture")

    assert result["instance"]["id"] == "dev-raw-fixture"
    assert result["instance"]["pathState"] == "present"
    assert result["instance"]["descriptor"]["kind"] == "Application"
    assert result["source"]["templateId"] == "stateport.development-reference"
    assert result["ownership"]["counts"]["instance"] == 2
    assert "application.yaml" in result["ownership"]["paths"]["instance"]
    assert result["health"] == "valid"


def test_inspect_uses_lock_manifest_when_present(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The StateSpec-style lock path stays authoritative when materialized."""

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()

    fixture = app.layout.instances_root / "lock-backed"
    fixture.mkdir(parents=True)
    (fixture / "instance.yaml").write_text("kind: Instance\nspec:\n  mode: guided\n", encoding="utf-8")
    (fixture / ".statedd").mkdir()
    (fixture / ".statedd" / "lock.yaml").write_text(
        "formatVersion: stateport.application-lock/v1\n"
        "template:\n"
        "  id: studydd\n"
        "  version: '1.2.3'\n"
        "  source:\n"
        "    repository: https://example.org/study.git\n"
        "    resolvedCommit: abcdef\n"
        "    profile: builtin\n"
        "    checkoutLocation: src\n"
        "files:\n"
        "  - {owner: template, path: AGENTS.md}\n"
        "  - {owner: instance, path: state/STUDY_STATE.yaml}\n",
        encoding="utf-8",
    )
    app.catalog.register(fixture, instance_id="lock-backed", name="Lock backed", source={"templateId": "studydd"})

    result = app.inspect("lock-backed")

    assert result["instance"]["descriptor"] == {"kind": "Instance", "mode": "guided"}
    assert result["version"] == "1.2.3"
    assert result["source"]["repository"] == "https://example.org/study.git"
    assert result["source"]["resolvedCommit"] == "abcdef"
    assert "profile" not in result["source"]
    assert "checkoutLocation" not in result["source"]
    assert result["ownership"]["counts"] == {"template": 1, "instance": 1, "generated": 0, "override": 0}
    assert result["ownership"]["paths"]["template"] == ["AGENTS.md"]


def test_product_status_reports_execution_runtime_truthfully(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The status payload must tell the browser the execution-host socket truth.

    Fail-old: ``product_status()`` omitted any execution runtime field, so the
    GUI could only render a generic "connected" service chip even when the
    mounted execution-host control socket was unreadable. Pass-new: the payload
    carries a bounded ``runtime`` object derived from the same environment the
    quadlet units express, never a synthetic "available".
    """

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()

    # The installed reality this regression documents: the socket env is
    # declared by the unit files, but the web container user cannot read the
    # group-confined directory, so .exists() is False from inside the service.
    monkeypatch.setenv("STATEPORT_EXECUTION_SOCKET", str(tmp_path / "absent" / "control.sock"))
    monkeypatch.setenv("STATEPORT_EXECUTION_PEER_POLICY", "unix-peer-credentials-required")
    monkeypatch.delenv("STATEPORT_WORKER_EXECUTION_ENABLED", raising=False)

    status = app.product_status()
    runtime = status["runtime"]
    assert runtime["status"] == "unavailable"
    assert runtime["reason"] == "execution_socket_unreachable"
    assert runtime["socketPresent"] is False
    assert runtime["socketPath"] == str(tmp_path / "absent" / "control.sock")
    assert runtime["peerPolicy"] == "unix-peer-credentials-required"
    assert runtime["workerExecutionEnabled"] is False
    assert "cannot start" in runtime["detail"]

    # A genuinely reachable socket must flip to available and stay honest.
    socket_dir = tmp_path / "execution-control"
    socket_dir.mkdir()
    socket_path = socket_dir / "control.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(socket_path))
    try:
        monkeypatch.setenv("STATEPORT_EXECUTION_SOCKET", str(socket_path))
        monkeypatch.setenv("STATEPORT_WORKER_EXECUTION_ENABLED", "true")
        status = app.product_status()
        runtime = status["runtime"]
        assert runtime["status"] == "available"
        assert runtime["socketPresent"] is True
        assert runtime["workerExecutionEnabled"] is True
        assert "reachable" in runtime["detail"]
    finally:
        server.close()

    # An absent socket env must be reported as not configured, not invented.
    monkeypatch.delenv("STATEPORT_EXECUTION_SOCKET")
    runtime = app.product_status()["runtime"]
    assert runtime["status"] == "unavailable"
    assert runtime["reason"] == "execution_socket_not_configured"
