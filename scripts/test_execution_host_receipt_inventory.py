import json
from pathlib import Path

import jsonschema
import pytest

pytest_plugins = ["test_provision_execution_host"]
from test_provision_execution_host import _apply, _verified  # noqa: E402
from stateport_release import execution_host_provisioning as prov  # noqa: E402


SCHEMA = json.loads((Path(__file__).parents[1] / "packages/release-contracts/src/stateport_release/schemas/execution-host-provisioning-receipt.v1.schema.json").read_text())


def test_receipt_schema_keeps_managed_resources_optional_for_old_receipts():
    assert "managedResources" not in SCHEMA["required"]


def test_receipt_schema_rejects_traversal_and_wrong_preservation_scope():
    validator = jsonschema.Draft202012Validator(SCHEMA["properties"]["managedResources"])
    value = {
        "units": [{"kind": "container", "path": "/var/lib/stateport-control/.config/containers/systemd/../x.container", "owner": "stateport-control:stateport-control", "uid": 65531, "contentDigest": "sha256:" + "a" * 64}],
        "dataVolumesPreserved": True, "providerAuthenticationPreserved": True, "preservationScope": "uninstall-guarantee",
    }
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(value)


def test_success_receipt_inventory_matches_observed_plan(sim, monkeypatch):
    accounts, host, runner, daemon = sim
    del accounts, host, runner
    monkeypatch.setattr(prov, "observe_linux_substrate", lambda: type("S", (), {"substrate": "wsl2"})())
    daemon.start()
    verified = _verified("wsl2-ubuntu2404-linux-amd64-rootless-podman-quadlet")
    receipt = _apply(sim, verified=verified)
    inventory = receipt["managedResources"]["units"]
    assert inventory
    plan = prov.render_provisioning_plan(
        verified.target, verified.index.document["signed"]["images"],
        verification_basis="signature-verified-test",
    )
    expected = {write["path"]: write for write in plan["writes"]
                if write["path"].endswith((".container", ".network"))}
    assert {item["path"] for item in inventory} == set(expected)
    assert len({item["path"] for item in inventory}) == len(inventory)
    for item in inventory:
        write = expected[item["path"]]
        assert item["owner"] == write["owner"]
        assert item["contentDigest"] == write["contentDigest"]
        assert item["uid"] == (prov.CONTROL_UID
                                if item["owner"].startswith("stateport-control:")
                                else prov.EXEC_UID)
        if item["kind"] == "container":
            assert item.get("containerName")


def test_inventory_omits_unit_secrets_and_failed_apply_omits_inventory(sim, monkeypatch):
    _accounts, _host, runner, daemon = sim
    monkeypatch.setattr(prov, "observe_linux_substrate", lambda: type("S", (), {"substrate": "wsl2"})())
    daemon.start()
    verified = _verified("wsl2-ubuntu2404-linux-amd64-rootless-podman-quadlet")
    materialization = {"accepted/" + "0" * 64 + "/stateport-control/stateport-web.container": b"[Container]\nContainerName=stateport-web\nEnvironment=SECRET_TOKEN=do-not-record\n"}
    receipt = _apply(sim, verified=verified, control_plane_materialization=materialization)
    serialized = json.dumps(receipt["managedResources"])
    assert "do-not-record" not in serialized
    assert any(item.get("containerName") == "stateport-web" for item in receipt["managedResources"]["units"])
    runner.fail_on = lambda argv: prov.Completed(1, "", "simulated failure") if "pull" in argv else None
    failed = _apply(sim, verified=verified)
    assert failed["result"] == "failed"
    assert "managedResources" not in failed


@pytest.mark.parametrize("name_lines", [b"", b"ContainerName=one\nContainerName=two\n", b"ContainerName=unsafe;name\n", b"ContainerName=stateport-@@STATEPORT_REVISION:stateport-web:validation@@\n"])
def test_ambiguous_container_name_refuses_before_provisioning_effects(sim, monkeypatch, name_lines):
    _accounts, _host, _runner, daemon = sim
    monkeypatch.setattr(prov, "observe_linux_substrate", lambda: type("S", (), {"substrate": "wsl2"})())
    daemon.start()
    verified = _verified("wsl2-ubuntu2404-linux-amd64-rootless-podman-quadlet")
    materialization = {
        "accepted/" + "0" * 64 + "/stateport-control/stateport-web.container":
        b"[Container]\nImage=example.invalid/web@sha256:" + b"a" * 64 + b"\n" + name_lines
    }
    with pytest.raises(prov.ReleaseContractError, match="ContainerName"):
        _apply(sim, verified=verified, control_plane_materialization=materialization)
