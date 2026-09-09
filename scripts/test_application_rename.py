"""Real catalog rename transactions; no template, container, or provider effects."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import socket
import shutil
import sys
import threading
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

ROOT = Path(__file__).resolve().parents[1]
for source in (ROOT / "packages").glob("*/src"):
    sys.path.insert(0, str(source))

from stateport_persistent_app import LocalLayout, PersistentApp  # noqa: E402
from stateport_persistent_app.app import ApplicationRenameError  # noqa: E402
from stateport_persistent_app.activity_receipts import ActivityReceiptError, ActivityReceiptStore  # noqa: E402
from test_nix_project_registration import _repo  # noqa: E402
from service_test_product import service_product_fixture  # noqa: E402


def setup(tmp_path: Path, external: bool = False):
    layout = LocalLayout(tmp_path / "config", tmp_path / "data", tmp_path / "state")
    layout.initialize()
    app = PersistentApp(layout)
    if external:
        directory = _repo(tmp_path / "external")
        app.catalog.register_external(directory, instance_id="first-app", name="First",
                                      application_id="nixos-infrastructure", source={"sourceKind": "local"})
    else:
        directory = layout.instances_root / "first-app"
        directory.mkdir()
        (directory / "owner-file.txt").write_text("preserve owner contents\n")
        app.catalog.register(directory, instance_id="first-app", name="First", source={})
    return app, directory


def rename(app, name="Renamed", expected="First"):
    return app.rename_instance("first-app", name=name, expected_name=expected,
                               actor_id="local-user", actor_role="local_user")


@pytest.mark.parametrize("external", [False, True])
def test_rename_persists_receipt_and_exact_retry_without_source_changes(tmp_path, external):
    app, directory = setup(tmp_path, external)
    original = app.catalog.get("first-app")
    files = {str(path.relative_to(directory)): path.read_bytes() for path in directory.rglob("*") if path.is_file()}
    result = rename(app)
    assert result["receipt"]["oldName"] == "First"
    assert result["receipt"]["newName"] == "Renamed"
    assert result["receipt"]["actorId"] == "local-user"
    catalog_file = app.layout.external_catalog_file if external else app.layout.catalog_file
    saved = catalog_file.read_bytes()
    retried = rename(PersistentApp(app.layout))
    assert retried == {**result, "replayed": True}
    assert catalog_file.read_bytes() == saved
    reopened = PersistentApp(app.layout).catalog.get("first-app")
    assert reopened["name"] == "Renamed"
    assert reopened["path"] == original["path"]
    assert reopened["observedSource"] == original["observedSource"]
    assert reopened["metadata"]["displayNameChanges"] == [result["receipt"]]
    assert {str(path.relative_to(directory)): path.read_bytes() for path in directory.rglob("*") if path.is_file()} == files


@pytest.mark.parametrize("external", [False, True])
def test_concurrent_rename_has_one_winner_and_one_stale_refusal(tmp_path, external):
    app, _ = setup(tmp_path, external)
    barrier = threading.Barrier(2)
    def attempt(name):
        barrier.wait(timeout=3)
        try:
            return rename(PersistentApp(app.layout), name)
        except ApplicationRenameError as error:
            return error.code
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, ["Name A", "Name B"]))
    assert results.count("rename_conflict") == 1
    changed = next(result for result in results if isinstance(result, dict))
    reopened = app.catalog.get("first-app")
    assert reopened["name"] == changed["name"]
    assert reopened["metadata"]["displayNameChanges"] == [changed["receipt"]]


def test_external_rename_serializes_with_import_rebind_and_metadata_update(tmp_path, monkeypatch):
    app, _ = setup(tmp_path, True)
    original = app.catalog.get("first-app")
    second = _repo(tmp_path / "second")
    reached_write = threading.Event()
    release_write = threading.Event()
    original_write = app.catalog._external_write
    def held_write(entries):
        reached_write.set()
        assert release_write.wait(timeout=5)
        original_write(entries)
    monkeypatch.setattr(app.catalog, "_external_write", held_write)
    with ThreadPoolExecutor(max_workers=4) as pool:
        renaming = pool.submit(rename, app)
        assert reached_write.wait(timeout=3)
        other = PersistentApp(app.layout).catalog
        importing = pool.submit(other.register_external, second, instance_id="second-app", name="Second",
                                application_id="nixos-infrastructure", source={"sourceKind": "local"})
        metadata = pool.submit(other.update, "first-app", testMarker="retained")
        rebinding = pool.submit(other.rebind_external_content, "first-app",
                                expected_content_identity=original["contentIdentity"])
        release_write.set()
        result = renaming.result(timeout=5)
        importing.result(timeout=5)
        metadata.result(timeout=5)
        rebinding.result(timeout=5)
    reopened = PersistentApp(app.layout).catalog
    assert {entry["instanceId"] for entry in reopened.list()} == {"first-app", "second-app"}
    first = reopened.get("first-app")
    assert first["name"] == "Renamed"
    assert first["metadata"]["testMarker"] == "retained"
    assert first["metadata"]["displayNameChanges"] == [result["receipt"]]
    assert first["contentIdentity"] == original["contentIdentity"]


@pytest.mark.parametrize("name", ["", " padded ", "line\nbreak", "x" * 121, 7])
def test_invalid_rename_keeps_catalog_unchanged(tmp_path, name):
    app, _ = setup(tmp_path)
    before = app.layout.catalog_file.read_bytes()
    with pytest.raises(ApplicationRenameError):
        rename(app, name)
    assert app.layout.catalog_file.read_bytes() == before


def test_real_http_rename_csrf_stale_refusal_receipt_and_restart(tmp_path, monkeypatch):
    for variable, child in (("XDG_CONFIG_HOME", "config"), ("XDG_DATA_HOME", "data"), ("XDG_STATE_HOME", "state")):
        monkeypatch.setenv(variable, str(tmp_path / child))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    directory = app.layout.instances_root / "first-app"
    shutil.copytree(ROOT / "fixtures/apps/development-reference", directory)
    marker = directory / "owner-file.txt"
    marker.write_text("preserved\n")
    app.catalog.register(directory, instance_id="first-app", name="First", source={"templateId": "stateport.development-reference"})
    product = service_product_fixture(tmp_path, ROOT)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    base = f"http://127.0.0.1:{port}"

    def session():
        with urlopen(base + "/session", timeout=5) as response:
            return response.headers["Set-Cookie"].split(";", 1)[0], json.loads(response.read())["result"]["csrfToken"]

    def request(path, cookie, csrf, body=None):
        headers = {"Cookie": cookie}
        if body is not None:
            headers.update({"Content-Type": "application/json", "Origin": base, "X-StatePort-CSRF": csrf})
        data = None if body is None else json.dumps(body).encode()
        with urlopen(Request(base + path, data=data, headers=headers), timeout=5) as response:
            return json.loads(response.read())["result"]

    app.service_start(port=port, repo_root=product)
    try:
        cookie, csrf = session()
        body = {"name": "Renamed", "expectedName": "First"}
        with pytest.raises(HTTPError) as refused:
            request("/v1/instances/first-app/rename", cookie, "invalid", body)
        assert refused.value.code == 403
        assert app.catalog.get("first-app")["name"] == "First"
        result = request("/v1/instances/first-app/rename", cookie, csrf, body)
        assert result["receipt"]["actorId"] == "local-user"
        assert result["receipt"]["actorRole"] == "local_user"
        assert request("/v1/instances/first-app/rename", cookie, csrf, body) == {**result, "replayed": True}
        with pytest.raises(HTTPError) as stale:
            request("/v1/instances/first-app/rename", cookie, csrf, {"name": "Other", "expectedName": "First"})
        assert stale.value.code == 409
        public = request("/v1/instances", cookie, csrf)["instances"]
        assert next(item for item in public if item["instanceId"] == "first-app")["name"] == "Renamed"
        assert "displayNameChanges" not in json.dumps(public)
        index = request("/v1/instances/first-app/receipts", cookie, csrf)
        projected = next(item for item in index["receipts"] if item["receiptId"] == result["receipt"]["receiptId"])
        assert projected["action"] == "application.rename"
        detail = request(f'/v1/instances/first-app/receipts/{result["receipt"]["receiptId"]}', cookie, csrf)
        assert detail["receipt"]["payload"] == result["receipt"]
    finally:
        app.service_stop()
    app.service_start(port=port, repo_root=product)
    try:
        cookie, csrf = session()
        public = request("/v1/instances", cookie, csrf)["instances"]
        assert next(item for item in public if item["instanceId"] == "first-app")["name"] == "Renamed"
        assert app.catalog.get("first-app")["metadata"]["displayNameChanges"] == [result["receipt"]]
        assert request(f'/v1/instances/first-app/receipts/{result["receipt"]["receiptId"]}', cookie, csrf)["receipt"]["payload"] == result["receipt"]
        assert marker.read_text() == "preserved\n"
    finally:
        app.service_stop()


def test_rename_receipt_index_rebuilds_from_catalog_after_missing_projection(tmp_path):
    app, _ = setup(tmp_path)
    result = rename(app)
    store = ActivityReceiptStore(tmp_path / "recreated-index.sqlite3")
    assert store.receipt_index("first-app")["receipts"] == []
    for _ in range(2):
        store.refresh(instance_id="first-app", inspection={}, settings_receipts=[],
                      application_rename_receipts=app.application_rename_receipts("first-app"))
    assert len(store.receipt_index("first-app")["receipts"]) == 1
    assert store.receipt_detail("first-app", result["receipt"]["receiptId"])["receipt"]["payload"] == result["receipt"]
    with pytest.raises(ActivityReceiptError, match="identity is invalid"):
        store.refresh(instance_id="another-app", inspection={}, settings_receipts=[],
                      application_rename_receipts=app.application_rename_receipts("first-app"))
    assert store.receipt_index("another-app")["receipts"] == []
