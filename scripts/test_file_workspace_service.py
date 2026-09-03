#!/usr/bin/env python3
"""Real loopback-service proof for the scoped browser file workflow."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

import pytest


ROOT = Path(__file__).resolve().parents[1]
for relative in (
    "packages/persistent-app/src",
    "packages/portable-execution/src",
    "packages/application-experience/src",
    "packages/conversation-service/src",
    "packages/context-lifecycle/src",
    "packages/goal-execution/src",
    "packages/file-workspace-broker/src",
    "packages/terminal-broker/src",
    "packages/governed-runner/src",
    "packages/execution-host/src",
    "packages/external-engine-runtime/src",
    "packages/codex-adapter/src",
    "packages/run-bundle/src",
    "packages/sandbox-runtime/src",
    "packages/statebench/src",
    "packages/instance-backup/src",
    "packages/instance-catalog/src",
    "packages/diagnostics/src",
    "packages/statedd-core/src",
    "packages/template-validator/src",
    "packages/opencode-adapter/src",
    "packages/container-opencode/src",
    "apps/runner/src",
):
    sys.path.insert(0, str(ROOT / relative))

from stateport_persistent_app import LocalLayout, PersistentApp  # noqa: E402
from stateport_persistent_app.activity_receipts import ActivityReceiptError  # noqa: E402
from stateport_persistent_app.service_process import AppServer  # noqa: E402
from service_test_product import service_product_fixture  # noqa: E402


APP = "stateport.development-reference"


def _git(project: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(project), *args], check=True, text=True,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ).stdout.strip()


def _digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _fixture(project: Path) -> str:
    (project / "src").mkdir(parents=True)
    (project / "src" / "main.py").write_text("answer = 41\n", encoding="utf-8")
    (project / "README.md").write_text("# Development fixture\n", encoding="utf-8")
    (project / "PROJECT_STATE.yaml").write_text("project:\n  mode: fixture\n", encoding="utf-8")
    _git(project, "init", "-q", "-b", "main")
    _git(project, "config", "user.email", "stateport-service@example.invalid")
    _git(project, "config", "user.name", "StatePort Service Fixture")
    _git(project, "add", ".")
    _git(project, "commit", "-q", "-m", "fixture")
    return _git(project, "rev-parse", "HEAD")


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("formatVersion", None),
        ("operation", "createFile"),
        ("actorId", "different-actor"),
        ("applicationId", "stateport.other"),
        ("instanceId", "different-instance"),
        ("destinationPath", "unexpected.py"),
        ("baseSha", "not-a-git-sha"),
        ("preHash", None),
        ("postHash", None),
        ("diffDigest", "not-a-digest"),
        ("validation", "failed"),
        ("contentRetained", True),
    ),
)
def test_file_receipt_index_rejects_malformed_or_mismatched_commit_evidence(
    tmp_path: Path,
    monkeypatch,
    field: str,
    value: object,
) -> None:
    """The receipt projection cannot bless incomplete broker evidence."""

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    web_root = service_product_fixture(tmp_path, ROOT) / "apps" / "web"
    server = AppServer(("127.0.0.1", 0), app.layout, web_root)
    receipt: dict[str, object] = {
        "formatVersion": "stateport.file-workspace/v1",
        "operation": "commitWrite",
        "receiptId": "file-receipt-regression",
        "actorId": server.actor_id,
        "applicationId": APP,
        "instanceId": "dev-one",
        "sourcePath": "src/main.py",
        "destinationPath": None,
        "baseSha": "a" * 40,
        "preHash": "sha256:" + "b" * 64,
        "postHash": "sha256:" + "c" * 64,
        "ownershipClass": "application_owned",
        "diffDigest": "sha256:" + "d" * 64,
        "validation": "passed",
        "completedAt": "2026-07-19T09:00:00Z",
        "contentRetained": False,
    }
    if value is None and field == "formatVersion":
        receipt.pop(field)
    else:
        receipt[field] = value
    try:
        with pytest.raises(ActivityReceiptError):
            server.record_file_workspace_receipt(
                instance_id="dev-one",
                application_id=APP,
                expected_operation="commitWrite",
                receipt=receipt,
            )
        assert server.activity_receipts.receipt_index("dev-one")["receipts"] == []
    finally:
        server.server_close()


def test_a12_real_service_refuses_unclassified_canonical_and_replaced_catalog_paths(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    layout = LocalLayout.from_environment()
    app = PersistentApp(layout)
    app.setup_init()
    project = layout.instances_root / "dev-one"
    head = _fixture(project)
    app.catalog.register(
        project,
        instance_id="dev-one",
        name="Development One",
        source={"templateId": APP, "resolvedCommit": head, "resolvedTree": "fixture-tree", "manifestDigest": "sha256:" + "0" * 64},
    )
    study = layout.instances_root / "study-one"
    _fixture(study)
    app.catalog.register(
        study,
        instance_id="study-one",
        name="StudyState One",
        source={"templateId": "studydd", "resolvedCommit": _git(study, "rev-parse", "HEAD"), "resolvedTree": "fixture-tree", "manifestDigest": "sha256:" + "1" * 64},
    )
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = int(probe.getsockname()[1])
    origin = f"http://127.0.0.1:{port}"
    app.service_start(
        port=port,
        repo_root=service_product_fixture(tmp_path, ROOT),
    )
    try:
        with urlopen(f"{origin}/session") as response:
            session = json.loads(response.read())["result"]
            cookie = response.headers["Set-Cookie"].split(";", 1)[0]
        assert len(session["csrfToken"]) >= 32

        def get(instance: str, operation: str, path: str) -> dict[str, object]:
            request = Request(
                f"{origin}/v1/instances/{instance}/file-workspace/{operation}?path={quote(path, safe='')}",
                headers={"Cookie": cookie},
            )
            with urlopen(request) as response:
                return json.loads(response.read())["result"]

        def get_api(path: str) -> dict[str, object]:
            request = Request(f"{origin}{path}", headers={"Cookie": cookie})
            with urlopen(request) as response:
                return json.loads(response.read())["result"]

        def post(operation: str, payload: dict[str, object], *, token: str | None = session["csrfToken"], request_origin: str | None = origin) -> tuple[int, dict[str, object]]:
            headers = {"Cookie": cookie, "Content-Type": "application/json"}
            if token is not None:
                headers["X-StatePort-CSRF"] = token
            if request_origin is not None:
                headers["Origin"] = request_origin
            request = Request(
                f"{origin}/v1/instances/dev-one/file-workspace/{operation}",
                data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST",
            )
            try:
                with urlopen(request) as response:
                    return response.status, json.loads(response.read())
            except HTTPError as error:
                return error.code, json.loads(error.read())

        listing = get("dev-one", "listDirectory", "")
        assert listing["operation"] == "listDirectory"
        assert {item["name"] for item in listing["entries"]} >= {"src", "README.md"}
        assert str(project) not in repr(listing)
        opened = get("dev-one", "readFile", "src/main.py")
        assert opened["content"] == "answer = 41\n"
        assert opened["metadata"]["baseSha"] == head

        canonical = get("dev-one", "readFileMetadata", "PROJECT_STATE.yaml")
        assert canonical["ownershipClass"] == "canonical" and canonical["readOnly"] is True
        canonical_status, canonical_refusal = post(
            "prepareWrite",
            {
                "path": "PROJECT_STATE.yaml",
                "content": "project:\n  mode: changed\n",
                "expectedContentHash": canonical["contentHash"],
                "expectedBaseSha": head,
            },
        )
        assert canonical_status == 409 and canonical_refusal["error"]["code"] == "file_workspace_refused"

        (project / "private").mkdir()
        (project / "private" / "notes.txt").write_text("not classified\n", encoding="utf-8")
        refreshed_listing = get("dev-one", "listDirectory", "")
        assert "private" not in {item["name"] for item in refreshed_listing["entries"]}
        try:
            get("dev-one", "readFile", "private/notes.txt")
        except HTTPError as error:
            assert error.code == 409
            assert json.loads(error.read())["error"]["code"] == "file_workspace_refused"
        else:
            raise AssertionError("unclassified path unexpectedly fell through to application ownership")

        denied_status, denied = post(
            "prepareWrite",
            {"path": "src/main.py", "content": "answer = 42\n", "expectedContentHash": opened["metadata"]["contentHash"], "expectedBaseSha": head},
            token=None,
        )
        assert denied_status == 403 and denied["error"]["code"] == "file_workspace_access_denied"
        wrong_origin_status, _ = post(
            "prepareWrite",
            {"path": "src/main.py", "content": "answer = 42\n", "expectedContentHash": opened["metadata"]["contentHash"], "expectedBaseSha": head},
            request_origin="http://example.invalid",
        )
        assert wrong_origin_status == 403

        status, prepared_payload = post(
            "prepareWrite",
            {"path": "src/main.py", "content": "answer = 42\n", "expectedContentHash": opened["metadata"]["contentHash"], "expectedBaseSha": head},
        )
        assert status == 200
        prepared = prepared_payload["result"]
        status, preview_payload = post("previewDiff", {"preparedWriteId": prepared["preparedWriteId"]})
        assert status == 200 and "+answer = 42" in preview_payload["result"]["diff"]
        preview = preview_payload["result"]
        status, committed_payload = post("commitWrite", {"preparedWriteId": prepared["preparedWriteId"], "confirmedDiffDigest": preview["diffDigest"]})
        assert status == 200
        receipt = committed_payload["result"]
        assert receipt["operation"] == "commitWrite" and receipt["contentRetained"] is False
        assert (project / "src" / "main.py").read_text(encoding="utf-8") == "answer = 42\n"

        status, create_prepared_payload = post(
            "createFile",
            {
                "path": "src/created.py",
                "content": "created = True\n",
                "expectedBaseSha": head,
            },
        )
        assert status == 200
        create_prepared = create_prepared_payload["result"]
        status, create_preview_payload = post(
            "previewDiff",
            {"preparedWriteId": create_prepared["preparedWriteId"]},
        )
        assert status == 200
        status, created_payload = post(
            "commitWrite",
            {
                "preparedWriteId": create_prepared["preparedWriteId"],
                "confirmedDiffDigest": create_preview_payload["result"]["diffDigest"],
            },
        )
        assert status == 200
        created_receipt = created_payload["result"]
        assert created_receipt["operation"] == "createFile"
        created_metadata = get("dev-one", "readFileMetadata", "src/created.py")

        status, renamed_payload = post(
            "renamePath",
            {
                "sourcePath": "src/created.py",
                "destinationPath": "src/renamed.py",
                "expectedContentHash": created_metadata["contentHash"],
                "expectedBaseSha": head,
            },
        )
        assert status == 200
        renamed_receipt = renamed_payload["result"]
        assert renamed_receipt["operation"] == "renamePath"
        renamed_metadata = get("dev-one", "readFileMetadata", "src/renamed.py")

        status, deleted_payload = post(
            "deletePath",
            {
                "path": "src/renamed.py",
                "expectedContentHash": renamed_metadata["contentHash"],
                "expectedBaseSha": head,
            },
        )
        assert status == 200
        deleted_receipt = deleted_payload["result"]
        assert deleted_receipt["operation"] == "deletePath"
        authority_receipts = (
            receipt,
            created_receipt,
            renamed_receipt,
            deleted_receipt,
        )
        receipt_index = get_api("/v1/instances/dev-one/receipts")
        indexed_ids = {item["receiptId"] for item in receipt_index["receipts"]}
        assert {item["receiptId"] for item in authority_receipts} <= indexed_ids
        for authority_receipt in authority_receipts:
            detail = get_api(
                f"/v1/instances/dev-one/receipts/{authority_receipt['receiptId']}"
            )["receipt"]
            assert detail["status"] == "applied"
            assert detail["action"] == f"file_workspace.{authority_receipt['operation']}"
            assert detail["payload"]["fileMutationReceipt"] == authority_receipt
            assert detail["payload"]["instanceId"] == "dev-one"
            assert detail["payload"]["applicationId"] == APP

        refreshed = get("dev-one", "readFile", "src/main.py")
        status, stale_prepared_payload = post(
            "prepareWrite",
            {"path": "src/main.py", "content": "answer = 43\n", "expectedContentHash": refreshed["metadata"]["contentHash"], "expectedBaseSha": head},
        )
        assert status == 200
        stale_prepared = stale_prepared_payload["result"]
        _, stale_preview_payload = post("previewDiff", {"preparedWriteId": stale_prepared["preparedWriteId"]})
        (project / "src" / "main.py").write_text("answer = 99\n", encoding="utf-8")
        status, refused = post("commitWrite", {"preparedWriteId": stale_prepared["preparedWriteId"], "confirmedDiffDigest": stale_preview_payload["result"]["diffDigest"]})
        assert status == 409 and refused["error"]["code"] == "file_workspace_refused"
        assert (project / "src" / "main.py").read_text(encoding="utf-8") == "answer = 99\n"
        after_refusal = get_api("/v1/instances/dev-one/receipts")
        assert {item["receiptId"] for item in after_refusal["receipts"]} == indexed_ids
        post("discardWrite", {"preparedWriteId": stale_prepared["preparedWriteId"]})

        try:
            get("study-one", "listDirectory", "")
        except HTTPError as error:
            assert error.code == 403
            assert json.loads(error.read())["error"]["code"] == "file_workspace_access_denied"
        else:
            raise AssertionError("StudyState unexpectedly received a file Workbench")

        displaced = tmp_path / "displaced-dev-one"
        project.rename(displaced)
        _fixture(project)
        try:
            get("dev-one", "listDirectory", "")
        except HTTPError as error:
            assert error.code == 403
            assert json.loads(error.read())["error"]["code"] == "file_workspace_access_denied"
        else:
            raise AssertionError("replacement directory unexpectedly reused the cataloged file capability")
        assert PersistentApp(layout).catalog.get("dev-one")["pathState"] == "stale"
        assert (project / "src" / "main.py").read_text(encoding="utf-8") == "answer = 41\n"
    finally:
        app.service_stop()


if __name__ == "__main__":
    raise SystemExit(__import__("pytest").main([__file__]))
