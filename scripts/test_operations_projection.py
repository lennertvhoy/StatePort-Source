"""Source API operations polling: durable catalog/run store, no runtime execution."""
import json
from pathlib import Path
import socket
import sys
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

ROOT = Path(__file__).resolve().parents[1]
for source in (ROOT / "packages").glob("*/src"):
    sys.path.insert(0, str(source))

from stateport_persistent_app import LocalLayout, PersistentApp  # noqa: E402
from stateport_persistent_app.operations import operation_projection  # noqa: E402
from stateport_portable_execution import PortableExecutionError, PortableExecutionService  # noqa: E402
from stateport_portable_execution.store import RunStore  # noqa: E402
from service_test_product import service_product_fixture  # noqa: E402
from test_nix_project_registration import _repo  # noqa: E402


def register(app, instance_id):
    directory = app.layout.instances_root / instance_id
    directory.mkdir()
    return app.catalog.register(directory, instance_id=instance_id, name=instance_id, source={})


def run(entry, run_id="run-one", **extra):
    return {"runId": run_id, "instanceId": entry["instanceId"], "applicationId": entry["applicationId"],
            "actionId": "validate", "engineId": "local", "status": "running",
            "requestedAt": "2026-09-05T21:00:00Z", "inputs": {"private": "do not expose"},
            "runSpec": {"path": "/private/source"}, **extra}


def test_projection_fresh_ownership_private_payloads_and_no_source_probes(tmp_path, monkeypatch):
    app = PersistentApp(LocalLayout(tmp_path / "config", tmp_path / "data", tmp_path / "state"))
    app.layout.initialize()
    entry = register(app, "first")
    store = RunStore(app.layout.operations_root / "portable-runs.json")
    execution = SimpleNamespace(store=store, _validate_run_closure_receipt=PortableExecutionService._validate_run_closure_receipt)
    monkeypatch.setattr(app, "instance_list_public", lambda: pytest.fail("full inventory is forbidden"))
    monkeypatch.setattr(app, "locked_source", lambda *_a, **_k: pytest.fail("source lock is forbidden"))
    assert operation_projection(app, execution)["runs"] == []
    store.create(run(entry))
    assert operation_projection(app, execution)["runs"][0]["runId"] == "run-one"
    second = register(app, "second")
    store.create(run(second, "run-two"))
    store.create(run(second, "foreign", applicationId="foreign-owner"))
    external = _repo(tmp_path / "external")
    app.catalog.register_external(external, instance_id="infra-app", name="Infra",
                                  application_id="nixos-infrastructure", source={"sourceKind": "local"})
    monkeypatch.setattr(app.catalog, "list", lambda: pytest.fail("full catalog is forbidden"))
    monkeypatch.setattr(app.catalog._canonical(), "_revalidate", lambda *_a: pytest.fail("catalog path refresh is forbidden"))
    monkeypatch.setattr(app.catalog, "_entry", lambda *_a: pytest.fail("managed source inspection is forbidden"))
    monkeypatch.setattr(app.catalog, "_external_entry", lambda *_a: pytest.fail("external content hashing is forbidden"))
    projected = operation_projection(app, execution)
    assert {row["runId"] for row in projected["runs"]} == {"run-one", "run-two"}
    assert "private" not in json.dumps(projected)
    assert projected["infrastructureInstanceIds"] == ["infra-app"]
    # Current ownership removal/rebinding is authoritative; no cached IDs.
    monkeypatch.setattr(app.catalog, "operation_owners", lambda: [{**second, "applicationId": "new-owner"}])
    assert operation_projection(app, execution)["runs"] == []


def test_invalid_claimed_closure_fails_visibly():
    entry = {"instanceId": "first", "applicationId": "app"}
    app = SimpleNamespace(catalog=SimpleNamespace(operation_owners=lambda: [entry]))
    for extra in ({"receiptId": "invented"}, {"status": "applied", "lifecycleState": "CLOSED"},
                  {"receiptId": "invented", "closureReceipt": {"receiptId": "invented"}}):
        execution = SimpleNamespace(store=SimpleNamespace(all=lambda: [run(entry, **extra)]),
                                    _validate_run_closure_receipt=PortableExecutionService._validate_run_closure_receipt)
        with pytest.raises(PortableExecutionError):
            operation_projection(app, execution)


def test_real_http_fresh_run_restart_and_visible_store_failure(tmp_path, monkeypatch):
    for variable, child in (("XDG_CONFIG_HOME", "config"), ("XDG_DATA_HOME", "data"), ("XDG_STATE_HOME", "state")):
        monkeypatch.setenv(variable, str(tmp_path / child))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    product = service_product_fixture(tmp_path, ROOT)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    store = RunStore(app.layout.operations_root / "portable-runs.json")
    from stateport_persistent_app.infrastructure import LocalLibvirtAdapter
    from test_infrastructure import FakeRunner
    repository = _repo(tmp_path / 'nixos-homelab')
    (repository / 'Makefile').write_text('vm-persistent-stop:\n\ttrue\n')
    source_bytes = (repository / 'flake.nix').read_bytes()
    app.catalog.register_external(repository, instance_id='http-infra', name='HTTP Infra',
        application_id='nixos-infrastructure', source={'sourceKind': 'local'})
    adapter = LocalLibvirtAdapter(repository, instance_id='http-infra',
        state_root=app.layout.state_root / 'infrastructure' / 'http-infra', runner=FakeRunner())
    plan = adapter.plan('observe')
    durable = adapter.run(plan['planDigest'])
    def session():
        with urlopen(base + "/session", timeout=5) as response:
            return response.headers["Set-Cookie"].split(";", 1)[0]
    def read(cookie):
        with urlopen(Request(base + "/v1/operations", headers={"Cookie": cookie}), timeout=5) as response:
            return json.loads(response.read())["result"]
    for restarted in (False, True):
        app.service_start(port=port, repo_root=product)
        try:
            with pytest.raises(HTTPError) as refused:
                read("invalid")
            assert refused.value.code in (401, 403)
            cookie = session()
            if not restarted:
                assert read(cookie)["runs"] == []
                entry = register(app, "new-app")
                store.create(run(entry))
            projected = read(cookie)
            assert projected["formatVersion"] == "stateport.operations/v1"
            assert projected["runs"][0]["runId"] == "run-one"
            assert "private" not in json.dumps(projected)
            assert projected['observationErrors'] == []
            assert projected['infrastructurePlans'][0]['id'] == plan['planDigest']
            assert projected['infrastructurePlans'][0]['receiptId'] == durable['receipt']['receiptId']
            assert projected['infrastructurePlans'][0]['state'] == 'completed'
            assert (repository / 'flake.nix').read_bytes() == source_bytes
            if restarted:
                store.path.write_text('{"runs":"invalid"}')
                with pytest.raises(HTTPError) as unavailable:
                    read(cookie)
                assert unavailable.value.code >= 400
        finally:
            app.service_stop()


def test_valid_applied_closure_projects_only_receipt_identity(tmp_path, monkeypatch):
    # Existing synthetic adapter fixture; actual governed apply and durable receipt.
    from test_portable_apply_integrity import _approved_proposal
    service, app, _root, run_id = _approved_proposal(tmp_path, monkeypatch, "operation-index")
    result = service.apply_proposal(run_id)["run"]
    projection = operation_projection(app, service)
    record = next(row for row in projection["runs"] if row["runId"] == run_id)
    assert record["receiptId"] == result["closureReceipt"]["receiptId"]
    assert record["status"] == "applied"
    assert "closureReceipt" not in record and "proposal" not in record and "runSpec" not in record
    service.store.update(run_id, closureReceipt={**result["closureReceipt"], "canonicalStateAfter": "sha256:" + "0" * 64})
    with pytest.raises(PortableExecutionError, match="does not match"):
        operation_projection(app, service)


def test_stored_infrastructure_history_receipt_rebind_and_no_runtime_probes(tmp_path, monkeypatch):
    from stateport_persistent_app.infrastructure import LocalLibvirtAdapter, _digest
    from test_infrastructure import FakeRunner
    app = PersistentApp(LocalLayout(tmp_path / 'config', tmp_path / 'data', tmp_path / 'state'))
    app.layout.initialize()
    repository = _repo(tmp_path / 'nixos-homelab')
    (repository / 'Makefile').write_text('vm-persistent-stop:\n\ttrue\n')
    app.catalog.register_external(repository, instance_id='infra', name='Infra',
        application_id='nixos-infrastructure', source={'sourceKind': 'local'})
    # Actual durable adapter plans/runs/receipts; runtime commands use the existing
    # test runner. This is stored source-service proof, not libvirt qualification.
    fake = FakeRunner()
    adapter = LocalLibvirtAdapter(repository, instance_id='infra',
        state_root=app.layout.state_root / 'infrastructure' / 'infra', runner=fake)
    completed_plan = adapter.plan('observe')
    completed = adapter.run(completed_plan['planDigest'])
    pending = adapter.plan('stop')
    store = RunStore(app.layout.operations_root / 'portable-runs.json')
    execution = SimpleNamespace(store=store, _validate_run_closure_receipt=PortableExecutionService._validate_run_closure_receipt)
    unrelated = register(app, 'unrelated')
    store.create(run(unrelated))
    commands_before = list(fake.commands)
    for name in ('inspect', 'project_identity', '_domain_observation', '_ssh_policy', '_assert_plan_target_current'):
        monkeypatch.setattr(LocalLibvirtAdapter, name, lambda *_a, **_kw: pytest.fail('live infrastructure probe'))
    monkeypatch.setattr(app, 'locked_source', lambda *_a, **_kw: pytest.fail('source lock'))
    monkeypatch.setattr(app.catalog, 'list', lambda *_a, **_kw: pytest.fail('full inventory'))
    first = operation_projection(app, execution)
    assert first['observationErrors'] == []
    plans = {row['id']: row for row in first['infrastructurePlans']}
    assert plans[completed_plan['planDigest']]['receiptId'] == completed['receipt']['receiptId']
    assert plans[completed_plan['planDigest']]['state'] == 'completed'
    assert plans[pending['planDigest']]['state'] == 'awaiting_approval'
    assert str(repository) not in json.dumps(first)
    assert fake.commands == commands_before
    # Catalog data alone cannot authorize a directory replaced at the same path.
    retained = repository.with_name('retained-original')
    repository.rename(retained)
    repository.mkdir()
    replaced = operation_projection(app, execution)
    assert replaced['infrastructurePlans'] == []
    assert replaced['observationErrors'][0]['code'] == 'operation_binding_changed'
    assert len(replaced['runs']) == 1
    repository.rmdir()
    repository.symlink_to(retained, target_is_directory=True)
    assert operation_projection(app, execution)['observationErrors'][0]['code'] == 'operation_binding_unavailable'
    repository.unlink()
    retained.rename(repository)
    assert operation_projection(app, execution) == first
    # Reconstructed app reads exactly the same persisted state.
    restarted = PersistentApp(app.layout)
    assert operation_projection(restarted, execution) == first
    # Legacy plans remain an explicit observation refusal, with other valid
    # plans/runs retained; no invented failed execution or state migration.
    old_path = adapter._plans / (pending['planDigest'][7:] + '.json')
    legacy = json.loads(old_path.read_text())
    legacy.pop('repositoryBinding')
    legacy['planDigest'] = _digest({key: value for key, value in legacy.items() if key != 'planDigest'})
    old_path.unlink()
    (adapter._plans / (legacy['planDigest'][7:] + '.json')).write_text(json.dumps(legacy))
    partial = operation_projection(app, execution)
    assert len(partial['infrastructurePlans']) == 1
    assert partial['observationErrors'][0]['code'] == 'operation_binding_unavailable'
    assert len(partial['runs']) == 1
    # Same basename and same Git history are insufficient: a new directory
    # registered with the same instance ID cannot inherit the prior plans.
    app.catalog.forget('infra')
    assert operation_projection(app, execution)['infrastructurePlans'] == []
    assert operation_projection(app, execution)['observationErrors'] == []
    import shutil
    clone = tmp_path / 'clone' / repository.name
    shutil.copytree(repository, clone)
    restarted.catalog.register_external(clone, instance_id='infra', name='Infra',
        application_id='nixos-infrastructure', source={'sourceKind': 'local'})
    rebound = operation_projection(app, execution)
    assert rebound['infrastructurePlans'] == []
    assert 'operation_binding_changed' in {error['code'] for error in rebound['observationErrors']}
    assert len(rebound['runs']) == 1
    assert (adapter._plans / (completed_plan['planDigest'][7:] + '.json')).exists()


def test_malformed_infrastructure_store_is_visible_without_erasing_other_runs(tmp_path):
    app = PersistentApp(LocalLayout(tmp_path / 'config', tmp_path / 'data', tmp_path / 'state'))
    app.layout.initialize()
    app.catalog.register_external(_repo(tmp_path / 'repo'), instance_id='infra', name='Infra',
        application_id='nixos-infrastructure', source={'sourceKind': 'local'})
    root = app.layout.state_root / 'infrastructure' / 'infra' / 'plans'
    root.mkdir(parents=True)
    (root / ('a' * 64 + '.json')).write_text('{')
    store = RunStore(app.layout.operations_root / 'portable-runs.json')
    store.create(run(register(app, 'other')))
    execution = SimpleNamespace(store=store, _validate_run_closure_receipt=PortableExecutionService._validate_run_closure_receipt)
    result = operation_projection(app, execution)
    assert result['infrastructurePlans'] == []
    assert result['observationErrors'][0]['code'] == 'plan_invalid'
    assert len(result['runs']) == 1


@pytest.mark.parametrize('case', ['approved', 'expired', 'failed', 'malformed_approval', 'malformed_receipt', 'orphan_run'])
def test_stored_infrastructure_status_and_refusal_semantics(tmp_path, case):
    from stateport_persistent_app.infrastructure import InfrastructureError, LocalLibvirtAdapter, _digest
    from test_infrastructure import FakeRunner, _adapter, _run_record_path
    adapter, fake = _adapter(tmp_path, FakeRunner(fail_make=True))
    plan = adapter.plan('stop')
    if case in {'approved', 'failed', 'malformed_approval', 'malformed_receipt'}:
        adapter.approve(plan['planDigest'], 'local-user')
    if case in {'failed', 'malformed_receipt'}:
        with pytest.raises(InfrastructureError):
            adapter.run(plan['planDigest'])
    if case == 'expired':
        path = adapter._plans / (plan['planDigest'][7:] + '.json')
        plan['expiresAt'] = '2000-01-01T00:00:00Z'
        plan['planDigest'] = _digest({key: value for key, value in plan.items() if key != 'planDigest'})
        path.unlink()
        (adapter._plans / (plan['planDigest'][7:] + '.json')).write_text(json.dumps(plan))
    if case == 'malformed_approval':
        (adapter._approvals / (plan['planDigest'][7:] + '.json')).write_text('{}')
    if case == 'malformed_receipt':
        path = _run_record_path(adapter, plan)
        record = json.loads(path.read_text())
        record['receipt']['receiptId'] = 'invented'
        path.write_text(json.dumps(adapter._seal_run(record)))
    if case == 'orphan_run':
        root = adapter._ensure_run_root(create=True)
        (root / 'unknown.json').write_text('{}')
    before = list(fake.commands)
    metadata = adapter.repository_root.stat()
    binding = LocalLibvirtAdapter.current_repository_binding(str(adapter.repository_root),
        {'device': metadata.st_dev, 'inode': metadata.st_ino})
    rows, errors = LocalLibvirtAdapter.stored_operations(state_root=adapter.state_root,
        instance_id=adapter.instance_id, repository_binding=binding)
    assert fake.commands == before
    if case in {'malformed_approval', 'malformed_receipt'}:
        assert rows == [] and len(errors) == 1
    elif case == 'orphan_run':
        assert rows[0]['state'] == 'awaiting_approval'
        assert errors[0]['code'] == 'operation_store_unavailable'
    else:
        assert errors == []
        assert rows[0]['state'] == {'approved': 'approved', 'expired': 'blocked', 'failed': 'failed'}[case]
        if case == 'failed':
            persisted = json.loads(_run_record_path(adapter, plan).read_text())
            assert rows[0]['receiptId'] == persisted['receipt']['receiptId']
            assert persisted['error']['code'] in rows[0]['error']


def test_new_and_legacy_plan_execution_binding_refuses_without_effect_and_fresh_plan_works(tmp_path):
    import shutil
    from stateport_persistent_app.infrastructure import InfrastructureError, LocalLibvirtAdapter, _digest
    from test_infrastructure import _adapter
    original, fake = _adapter(tmp_path)
    plan = original.plan('stop')
    original.approve(plan['planDigest'], 'local-user')
    clone = tmp_path / 'clone' / original.repository_root.name
    shutil.copytree(original.repository_root, clone)
    replacement = LocalLibvirtAdapter(clone, instance_id=original.instance_id,
        state_root=original.state_root, runner=fake)
    # Identical history/name cannot inherit an approval on a different directory.
    assert original.project_identity().to_dict() == replacement.project_identity().to_dict()
    before = list(fake.commands)
    for action in (lambda: replacement.approve(plan['planDigest'], 'local-user'),
                   lambda: replacement.run(plan['planDigest'])):
        with pytest.raises(InfrastructureError) as refused:
            action()
        assert refused.value.code == 'plan_stale'
    assert fake.commands == before
    assert not replacement._runs.exists()
    # Old metadata is retained as evidence, but cannot initiate new work.
    legacy = original.plan('observe')
    path = original._plans / (legacy['planDigest'][7:] + '.json')
    legacy.pop('repositoryBinding')
    legacy['planDigest'] = _digest({key: value for key, value in legacy.items() if key != 'planDigest'})
    legacy_path = original._plans / (legacy['planDigest'][7:] + '.json')
    path.unlink()
    legacy_path.write_text(json.dumps(legacy))
    bytes_before = legacy_path.read_bytes()
    before = list(fake.commands)
    for action in (lambda: original.approve(legacy['planDigest'], 'local-user'),
                   lambda: original.run(legacy['planDigest'])):
        with pytest.raises(InfrastructureError, match='legacy plan') as refused:
            action()
        assert refused.value.code == 'plan_stale'
    assert fake.commands == before
    assert legacy_path.read_bytes() == bytes_before
    fresh = replacement.plan('stop')
    assert fresh['planDigest'] != plan['planDigest']
    replacement.approve(fresh['planDigest'], 'local-user')
    result = replacement.run(fresh['planDigest'])
    assert result['state'] == 'completed'
    assert result['receipt']['planDigest'] == fresh['planDigest']
    assert [command for command in fake.commands[len(before):] if command[0] == 'make'] == [('make', 'vm-persistent-stop')]
