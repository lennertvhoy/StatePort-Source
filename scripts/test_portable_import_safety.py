from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import socket
import sys
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

ROOT = Path(__file__).resolve().parents[1]
for relative in (
    "packages/persistent-app/src",
    "packages/context-lifecycle/src",
    "packages/portable-execution/src",
    "packages/execution-host/src",
    "packages/external-engine-runtime/src",
    "packages/codex-adapter/src",
    "packages/run-bundle/src",
    "packages/statedd-core/src",
    "packages/template-validator/src",
    "packages/instance-backup/src",
    "packages/instance-catalog/src",
    "packages/diagnostics/src",
):
    sys.path.insert(0, str(ROOT / relative))

from stateport_persistent_app.service_process import Handler  # noqa: E402
from stateport_persistent_app import AppError, LocalLayout, PersistentApp  # noqa: E402
from stateport_portable_execution import PortableExecutionError, PortableExecutionService  # noqa: E402
from stateport_portable_execution.contracts import digest  # noqa: E402
from stateport_portable_execution.runtime import PortableImportError  # noqa: E402
from service_test_product import service_product_fixture  # noqa: E402


def test_http_import_paths_reject_traversal_and_symlink_escape(tmp_path: Path) -> None:
    root = tmp_path / "portable"
    root.mkdir()
    with pytest.raises(ValueError, match="traversal"):
        Handler._local_child((root / ".." / "outside.zip").as_posix(), root, "archivePath")
    outside = tmp_path / "outside"
    outside.mkdir()
    link = root / "link"
    link.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError):
        Handler._local_child((link / "archive.zip").as_posix(), root, "archivePath")


def test_persistent_catalog_import_adopts_without_mutating_instance(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    instance = app.layout.instances_root / "imported"
    instance.mkdir()
    (instance / "canonical.txt").write_text("preserve", encoding="utf-8")
    imported = app.catalog.import_instance(instance, instance_id="imported")
    assert imported["instanceId"] == "imported"
    assert (instance / "canonical.txt").read_text(encoding="utf-8") == "preserve"


def _port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _post(origin: str, path: str, body: dict[str, object], *, cookie: str | None = None, csrf: str | None = None) -> tuple[int, dict[str, object]]:
    headers = {"Content-Type": "application/json", "Origin": origin}
    if cookie is not None:
        headers["Cookie"] = cookie
    if csrf is not None:
        headers["X-StatePort-CSRF"] = csrf
    request = Request(f"{origin}{path}", data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
    try:
        with urlopen(request) as response:
            return response.status, json.loads(response.read())
    except HTTPError as error:
        return error.code, json.loads(error.read())


def test_portable_import_is_preview_bound_authenticated_and_replay_safe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    execution = PortableExecutionService(app, ROOT)
    execution.install_fixture_instance("checklistdd", "source-import")
    exported = execution.export_instance("source-import")
    archive = {
        "path": exported["archive"],
        "archiveDigest": exported["archiveDigest"],
        "archiveFileDigest": exported["archiveFileDigest"],
    }
    destination = {"path": (app.layout.instances_root / "restored-import").as_posix(), "instanceId": "restored-import"}
    preview_body = {"archive": archive, "destination": destination, "identityPolicy": "reidentify"}
    port = _port()
    origin = f"http://127.0.0.1:{port}"
    app.service_start(
        port=port,
        repo_root=service_product_fixture(tmp_path, ROOT),
    )
    try:
        status, denied = _post(origin, "/v1/portable-import/preview", preview_body)
        assert status == 401 and denied["error"]["code"] == "session_required"
        with urlopen(f"{origin}/session") as response:
            session = json.loads(response.read())["result"]
            cookie = response.headers["Set-Cookie"].split(";", 1)[0]
        status, denied = _post(origin, "/v1/portable-import/preview", preview_body, cookie=cookie)
        assert status == 403 and denied["error"]["code"] == "portable_import_denied"
        status, malformed = _post(origin, "/v1/portable-import/preview", {**preview_body, "dryRun": True}, cookie=cookie, csrf=session["csrfToken"])
        assert status == 409 and malformed["error"]["code"] == "portable_import_request_invalid"
        stale_archive = {**archive, "archiveFileDigest": "sha256:" + "0" * 64}
        status, stale = _post(origin, "/v1/portable-import/preview", {**preview_body, "archive": stale_archive}, cookie=cookie, csrf=session["csrfToken"])
        assert status == 409 and stale["error"]["code"] == "portable_import_stale"
        mismatched_destination = {"path": (app.layout.instances_root / "nested" / "restored-import").as_posix(), "instanceId": "restored-import"}
        status, refused = _post(origin, "/v1/portable-import/preview", {**preview_body, "destination": mismatched_destination}, cookie=cookie, csrf=session["csrfToken"])
        assert status == 409 and refused["error"]["code"] == "portable_import_destination_refused"
        status, preview_response = _post(origin, "/v1/portable-import/preview", preview_body, cookie=cookie, csrf=session["csrfToken"])
        assert status == 200
        preview = preview_response["result"]
        assert preview["dryRun"] is True and preview["destinationMutated"] is False
        assert not (app.layout.instances_root / "restored-import").exists()
        assert preview["archiveFileDigest"] == exported["archiveFileDigest"]
        wrong_approval = {
            "archive": archive, "destination": destination, "identityPolicy": "reidentify",
            "expectedPlanDigest": preview["planDigest"],
            "approval": {"decision": "approve", "actorId": "other-user", "actorRole": "local_user"},
        }
        status, denied = _post(origin, "/v1/portable-import/apply", wrong_approval, cookie=cookie, csrf=session["csrfToken"])
        assert status == 403 and denied["error"]["code"] == "portable_import_denied"
        apply_body = {
            "archive": archive, "destination": destination, "identityPolicy": "reidentify",
            "expectedPlanDigest": preview["planDigest"],
            "approval": {"decision": "approve", "actorId": "local-user", "actorRole": "local_user"},
        }
        status, applied_response = _post(origin, "/v1/portable-import/apply", apply_body, cookie=cookie, csrf=session["csrfToken"])
        assert status == 200
        applied = applied_response["result"]
        assert applied["destinationMutated"] is True and applied["idempotentReplay"] is False
        receipt = applied["receipt"]
        assert receipt["approval"] == apply_body["approval"]
        assert receipt["approvalDigest"].startswith("sha256:")
        assert receipt["targetIdentity"] == receipt["catalogEntry"]["filesystem"]
        assert receipt["archiveDigest"] == exported["archiveDigest"]
        assert (app.layout.instances_root / "restored-import" / "instance.yaml").is_file()
        receipt_path = app.layout.operations_root / "portable-imports" / f"restored-import-{preview['planDigest'][7:]}.json"
        assert receipt_path.is_file()
        tampered_receipt = dict(receipt)
        tampered_receipt["receiptDigest"] = "sha256:" + "0" * 64
        receipt_path.write_text(json.dumps(tampered_receipt), encoding="utf-8")
        status, refused_receipt = _post(origin, "/v1/portable-import/apply", apply_body, cookie=cookie, csrf=session["csrfToken"])
        assert status == 409 and refused_receipt["error"]["code"] == "portable_import_receipt_refused"
        receipt_path.write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        status, replay_response = _post(origin, "/v1/portable-import/apply", apply_body, cookie=cookie, csrf=session["csrfToken"])
        assert status == 200, replay_response
        replay = replay_response["result"]
        assert replay["idempotentReplay"] is True and replay["destinationMutated"] is False
        assert replay["receipt"] == receipt
        status, old_route = _post(origin, "/v1/portable-import", {"archivePath": archive["path"], "destination": destination["path"]}, cookie=cookie, csrf=session["csrfToken"])
        assert status == 404 and old_route["error"]["code"] == "not_found"
    finally:
        app.service_stop()


def test_portable_import_rejects_stale_identity_and_rolls_back_registration_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    service = PortableExecutionService(app, ROOT)
    service.install_fixture_instance("checklistdd", "import-source")
    exported = service.export_instance("import-source")
    archive = Path(exported["archive"])
    destination = app.layout.instances_root / "rollback-target"
    preview = service.preview_portable_import(
        archive, destination,
        expected_archive_digest=exported["archiveDigest"], expected_archive_file_digest=exported["archiveFileDigest"],
        destination_instance_id="rollback-target", identity_policy="reidentify",
    )
    with pytest.raises(PortableExecutionError, match="preview changed"):
        service.apply_portable_import(
            archive, destination,
            expected_archive_digest=exported["archiveDigest"], expected_archive_file_digest=exported["archiveFileDigest"],
            destination_instance_id="rollback-target", identity_policy="reidentify",
            expected_plan_digest="sha256:" + "0" * 64,
            approval={"decision": "approve", "actorId": "local-user", "actorRole": "local_user"},
        )
    assert not destination.exists()

    def reject_registration(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise RuntimeError("catalog write refused")

    monkeypatch.setattr(app, "register_portable_import", reject_registration)
    with pytest.raises(PortableExecutionError, match="destination was unchanged"):
        service.apply_portable_import(
            archive, destination,
            expected_archive_digest=exported["archiveDigest"], expected_archive_file_digest=exported["archiveFileDigest"],
            destination_instance_id="rollback-target", identity_policy="reidentify",
            expected_plan_digest=preview["planDigest"],
            approval={"decision": "approve", "actorId": "local-user", "actorRole": "local_user"},
        )
    assert not destination.exists()


def test_portable_import_preserves_replacement_during_inode_bound_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    service = PortableExecutionService(app, ROOT)
    service.install_fixture_instance("checklistdd", "import-source")
    exported = service.export_instance("import-source")
    archive = Path(exported["archive"])
    destination = app.layout.instances_root / "rollback-target"
    preview = service.preview_portable_import(
        archive,
        destination,
        expected_archive_digest=exported["archiveDigest"],
        expected_archive_file_digest=exported["archiveFileDigest"],
        destination_instance_id="rollback-target",
        identity_policy="reidentify",
    )

    def replace_then_reject(*_args: object, **_kwargs: object) -> dict[str, object]:
        saved = destination.with_name("rollback-original")
        destination.rename(saved)
        destination.mkdir()
        (destination / "operator-owned.txt").write_text("preserve\n", encoding="utf-8")
        raise RuntimeError("catalog write refused")

    monkeypatch.setattr(app, "register_portable_import", replace_then_reject)
    with pytest.raises(PortableImportError, match="operator inspection"):
        service.apply_portable_import(
            archive,
            destination,
            expected_archive_digest=exported["archiveDigest"],
            expected_archive_file_digest=exported["archiveFileDigest"],
            destination_instance_id="rollback-target",
            identity_policy="reidentify",
            expected_plan_digest=preview["planDigest"],
            approval={"decision": "approve", "actorId": "local-user", "actorRole": "local_user"},
        )
    assert (destination / "operator-owned.txt").read_text(encoding="utf-8") == "preserve\n"


def test_portable_import_manifest_rejection_cleans_materialized_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    service = PortableExecutionService(app, ROOT)
    service.install_fixture_instance("checklistdd", "import-source")
    exported = service.export_instance("import-source")
    archive = Path(exported["archive"])
    destination = app.layout.instances_root / "manifest-rejection"
    preview = service.preview_portable_import(
        archive,
        destination,
        expected_archive_digest=exported["archiveDigest"],
        expected_archive_file_digest=exported["archiveFileDigest"],
        destination_instance_id="manifest-rejection",
        identity_policy="reidentify",
    )
    real_import = service.import_instance_archive

    def reject_manifest(*args: object, **kwargs: object) -> dict[str, object]:
        result = real_import(*args, **kwargs)
        manifest = dict(result["manifest"])
        manifest["archiveFileDigest"] = "sha256:" + "0" * 64
        return {**result, "manifest": manifest}

    monkeypatch.setattr(service, "import_instance_archive", reject_manifest)
    with pytest.raises(PortableImportError, match="archive changed"):
        service.apply_portable_import(
            archive,
            destination,
            expected_archive_digest=exported["archiveDigest"],
            expected_archive_file_digest=exported["archiveFileDigest"],
            destination_instance_id="manifest-rejection",
            identity_policy="reidentify",
            expected_plan_digest=preview["planDigest"],
            approval={"decision": "approve", "actorId": "local-user", "actorRole": "local_user"},
        )
    assert not destination.exists()
    with pytest.raises(AppError):
        app.catalog.get("manifest-rejection")


def test_portable_replay_rejects_replaced_destination_inode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    service = PortableExecutionService(app, ROOT)
    service.install_fixture_instance("checklistdd", "import-source")
    exported = service.export_instance("import-source")
    archive = Path(exported["archive"])
    destination = app.layout.instances_root / "replay-target"
    preview = service.preview_portable_import(
        archive,
        destination,
        expected_archive_digest=exported["archiveDigest"],
        expected_archive_file_digest=exported["archiveFileDigest"],
        destination_instance_id="replay-target",
        identity_policy="reidentify",
    )
    approval = {"decision": "approve", "actorId": "local-user", "actorRole": "local_user"}
    service.apply_portable_import(
        archive,
        destination,
        expected_archive_digest=exported["archiveDigest"],
        expected_archive_file_digest=exported["archiveFileDigest"],
        destination_instance_id="replay-target",
        identity_policy="reidentify",
        expected_plan_digest=preview["planDigest"],
        approval=approval,
    )
    with pytest.raises(PortableImportError, match="approval"):
        service.apply_portable_import(
            archive,
            destination,
            expected_archive_digest=exported["archiveDigest"],
            expected_archive_file_digest=exported["archiveFileDigest"],
            destination_instance_id="replay-target",
            identity_policy="reidentify",
            expected_plan_digest=preview["planDigest"],
            approval={**approval, "actorId": "other-user"},
        )
    target = destination
    target.rename(target.with_name("replay-original"))
    target.mkdir()
    (target / "operator-owned.txt").write_text("preserve\n", encoding="utf-8")

    with pytest.raises(PortableImportError, match="(?:path|inode)"):
        service.apply_portable_import(
            archive,
            target,
            expected_archive_digest=exported["archiveDigest"],
            expected_archive_file_digest=exported["archiveFileDigest"],
            destination_instance_id="replay-target",
            identity_policy="reidentify",
            expected_plan_digest=preview["planDigest"],
            approval=approval,
        )
    assert (target / "operator-owned.txt").read_text(encoding="utf-8") == "preserve\n"


def test_portable_replay_rejects_same_inode_tree_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    service = PortableExecutionService(app, ROOT)
    service.install_fixture_instance("checklistdd", "import-source")
    exported = service.export_instance("import-source")
    archive = Path(exported["archive"])
    target = app.layout.instances_root / "replay-tree"
    preview = service.preview_portable_import(
        archive, target,
        expected_archive_digest=exported["archiveDigest"],
        expected_archive_file_digest=exported["archiveFileDigest"],
        destination_instance_id="replay-tree", identity_policy="reidentify",
    )
    approval = {"decision": "approve", "actorId": "local-user", "actorRole": "local_user"}
    service.apply_portable_import(
        archive, target,
        expected_archive_digest=exported["archiveDigest"],
        expected_archive_file_digest=exported["archiveFileDigest"],
        destination_instance_id="replay-tree", identity_policy="reidentify",
        expected_plan_digest=preview["planDigest"], approval=approval,
    )
    receipt_path = app.layout.operations_root / "portable-imports" / f"replay-tree-{preview['planDigest'][7:]}.json"
    original_receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    for field, replacement in (
        ("archiveDigest", "sha256:" + "0" * 64),
        ("archiveFileDigest", "sha256:" + "1" * 64),
        ("sourceInstanceId", "other-source"),
        ("sourceIdentity", {}),
        ("destinationInstanceId", "other-target"),
        ("identityPolicy", "preserve"),
        ("fileCount", original_receipt["fileCount"] + 1),
    ):
        tampered = deepcopy(original_receipt)
        tampered[field] = replacement
        unsigned = dict(tampered)
        unsigned.pop("receiptDigest")
        tampered["receiptDigest"] = digest(unsigned)
        receipt_path.write_text(json.dumps(tampered, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        with pytest.raises(PortableImportError, match="different|identity changed|archive"):
            service.apply_portable_import(
                archive, target,
                expected_archive_digest=exported["archiveDigest"],
                expected_archive_file_digest=exported["archiveFileDigest"],
                destination_instance_id="replay-tree", identity_policy="reidentify",
                expected_plan_digest=preview["planDigest"], approval=approval,
            )
        receipt_path.write_text(json.dumps(original_receipt, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    mutable = next(path for path in target.rglob("*") if path.is_file() and path.name != "instance.yaml")
    mutable.write_bytes(mutable.read_bytes() + b"mutation")
    with pytest.raises(PortableImportError, match="tree changed"):
        service.apply_portable_import(
            archive, target,
            expected_archive_digest=exported["archiveDigest"],
            expected_archive_file_digest=exported["archiveFileDigest"],
            destination_instance_id="replay-tree", identity_policy="reidentify",
            expected_plan_digest=preview["planDigest"], approval=approval,
        )


def test_portable_import_rollback_failure_preserves_operator_inspection_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    service = PortableExecutionService(app, ROOT)
    service.install_fixture_instance("checklistdd", "import-source")
    exported = service.export_instance("import-source")
    destination = app.layout.instances_root / "rollback-error"

    def reject_registration(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise RuntimeError("catalog write refused")

    def refuse_rollback(*_args: object, **_kwargs: object) -> None:
        raise PortableImportError("portable_import_rollback_failed", "operator inspection is required")

    monkeypatch.setattr(app, "register_portable_import", reject_registration)
    monkeypatch.setattr(service, "_rollback_portable_import_destination", refuse_rollback)
    with pytest.raises(PortableImportError, match="operator inspection"):
        service.import_instance_archive(exported["archive"], destination, new_instance_id="rollback-error")
