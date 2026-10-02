"""A refused instance writer lease says why: busy, full disk, or not writable.

Found by the durability e2e rows: portable export on a full disk answered
"instance writer lease is unavailable" (hiding the disk), and the loser of a
concurrent apply got the internal sentence "instance already has an active writer
lease". Lease semantics are unchanged; only the refusal is now specific.
"""
from __future__ import annotations

import errno
import json
import sys
import threading
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

ROOT = Path(__file__).resolve().parents[1]
for source_root in sorted((ROOT / "packages").glob("*/src")):
    sys.path.insert(0, str(source_root))
for source_root in sorted((ROOT / "apps").glob("*/src")):
    sys.path.insert(0, str(source_root))

import governed_runner.lease as lease_module  # noqa: E402
from governed_runner import InstanceLease, snapshot_files  # noqa: E402
from stateport_persistent_app import LocalLayout, PersistentApp  # noqa: E402
from stateport_persistent_app.service_process import AppServer  # noqa: E402
from stateport_portable_execution.runtime import (  # noqa: E402
    InstanceLeaseRefusedError,
    PortableExecutionError,
    PortableExecutionService,
)


def _service(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    service = PortableExecutionService(app, ROOT)
    service.install_fixture_instance("checklistdd", "lease-refusals")
    _, instance_root = app._entry("lease-refusals")
    return service, app, instance_root


def _approved(service: PortableExecutionService) -> str:
    prepared = service.prepare("lease-refusals", "checklistdd.complete-item/v1", "synthetic", {"itemId": "first-item"})
    run_id = prepared["run"]["runId"]
    service.approve_run(run_id)
    service.execute(run_id)
    service.approve_proposal(run_id)
    return run_id


def _fail_lease_write(monkeypatch: pytest.MonkeyPatch, code: int) -> None:
    def broken(*_args: object, **_kwargs: object) -> None:
        raise OSError(code, "injected")

    monkeypatch.setattr(lease_module.os, "ftruncate", broken)


def test_export_on_a_full_disk_says_the_disk_is_full_not_lease_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _app, _root = _service(tmp_path, monkeypatch)
    _fail_lease_write(monkeypatch, errno.ENOSPC)
    with pytest.raises(InstanceLeaseRefusedError) as raised:
        service.export_instance("lease-refusals")
    assert raised.value.code == "disk_full"
    message = str(raised.value)
    assert "disk" in message and "full" in message and "not exported" in message
    assert "lease" not in message.lower()


def test_export_in_a_read_only_data_folder_says_it_is_not_writable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _app, _root = _service(tmp_path, monkeypatch)
    _fail_lease_write(monkeypatch, errno.EROFS)
    with pytest.raises(InstanceLeaseRefusedError) as raised:
        service.export_instance("lease-refusals")
    assert raised.value.code == "data_not_writable"
    assert "cannot write" in str(raised.value) and "lease" not in str(raised.value).lower()


def test_export_with_a_genuinely_held_lease_says_busy_and_keeps_the_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, app, root = _service(tmp_path, monkeypatch)
    with InstanceLease(app.layout.operations_root / "leases", root, owner="competing-writer"):
        with pytest.raises(InstanceLeaseRefusedError) as raised:
            service.export_instance("lease-refusals")
    assert raised.value.code == "instance_busy"
    assert "Another operation is using this instance" in str(raised.value)
    assert "lease" not in str(raised.value).lower()
    # the lease is released again: a later export works
    assert service.export_instance("lease-refusals")["archive"]


def test_apply_loser_is_told_another_change_is_being_applied_and_nothing_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, app, root = _service(tmp_path, monkeypatch)
    run_id = _approved(service)
    before = snapshot_files(root)
    with InstanceLease(app.layout.operations_root / "leases", root, owner="competing-writer"):
        with pytest.raises(InstanceLeaseRefusedError) as raised:
            service.apply_proposal(run_id)
    assert raised.value.code == "instance_busy"
    assert str(raised.value) == (
        "Another change is being applied to this instance right now, so this one was not applied. "
        "Wait for it to finish, then try again."
    )
    assert snapshot_files(root) == before
    assert service.inspect(run_id)["run"]["status"] == "state_change_approved"  # outcome semantics unchanged
    assert service.apply_proposal(run_id)["run"]["status"] == "applied"  # retry after the winner finished


def test_apply_on_a_full_disk_is_not_reported_as_a_busy_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _app, root = _service(tmp_path, monkeypatch)
    run_id = _approved(service)
    before = snapshot_files(root)
    _fail_lease_write(monkeypatch, errno.ENOSPC)
    with pytest.raises(InstanceLeaseRefusedError) as raised:
        service.apply_proposal(run_id)
    assert raised.value.code == "disk_full" and "not applied" in str(raised.value)
    monkeypatch.undo()
    assert snapshot_files(root) == before


def test_the_refusal_is_a_portable_execution_error_for_existing_callers() -> None:
    assert issubclass(InstanceLeaseRefusedError, PortableExecutionError)


def test_http_boundary_answers_409_with_the_specific_code_and_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    layout = LocalLayout.from_environment()
    layout.initialize()
    server = AppServer(("127.0.0.1", 0), layout, ROOT / "apps" / "_lease-refusal-test-web")
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    port = int(server.server_address[1])
    origin = f"http://127.0.0.1:{port}"
    try:
        with urlopen(f"{origin}/session") as response:
            csrf = str(json.loads(response.read())["result"]["csrfToken"])
            cookie = response.headers["Set-Cookie"].split(";", 1)[0]
        server.execution.install_fixture_instance("checklistdd", "http-lease")
        _, root = server.source_app()._entry("http-lease")

        def export() -> tuple[int, dict]:
            request = Request(
                f"{origin}/v1/instances/http-lease/portable-export", data=b"{}", method="POST",
                headers={"Cookie": cookie, "Origin": origin, "X-StatePort-CSRF": csrf, "Content-Type": "application/json"},
            )
            try:
                with urlopen(request) as response:
                    return response.status, json.loads(response.read())
            except HTTPError as error:
                return error.code, json.loads(error.read())

        with InstanceLease(layout.operations_root / "leases", root, owner="competing-writer"):
            status, document = export()
        assert status == 409
        assert document["error"]["code"] == "instance_busy"
        assert document["error"]["causeCode"] == "instance_busy"
        assert "Another operation is using this instance" in document["error"]["message"]

        real = lease_module.os.ftruncate
        lease_module.os.ftruncate = lambda *a, **k: (_ for _ in ()).throw(OSError(errno.ENOSPC, "injected"))
        try:
            status, document = export()
        finally:
            lease_module.os.ftruncate = real
        assert status == 409
        assert document["error"]["code"] == "disk_full"
        assert "disk holding StatePort data is full" in document["error"]["message"]
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
