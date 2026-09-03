#!/usr/bin/env python3
"""Focused tests for the sealed alpha.4 workspace workload boundary.

Covers the workspace workload kind in the daemon contract, the hardened
create argv (daemon-owned volumes only), and the WorkspaceSpec adapter in
``execution_host.workspaces`` — all without a container runtime.
"""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "execution-host" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "runtime-contracts" / "src"))

from execution_host import daemon_contract as contract  # noqa: E402
from execution_host.engine import (  # noqa: E402
    EngineError,
    PodmanCliEngine,
    assert_create_argv_hardened,
    build_create_argv,
    cache_volume_name,
)
from execution_host.workspaces import (  # noqa: E402
    WorkspaceRuntime,
    WorkspaceRuntimeError,
    sealed_workspace_workload,
)

IMAGE = "docker.io/library/python@sha256:" + "b" * 64
DIGEST = "sha256:" + "b" * 64
SHA = "a" * 40


def workspace_spec(**changes):
    value = {
        "kind": "workspace",
        "workloadId": "workspace.demo",
        "image": {"reference": IMAGE},
        "parameters": {
            "workspaceId": "workspace.demo",
            "workspaceSpecDigest": DIGEST,
            "volumeName": "stateport-workspace-workspace.demo",
            "workSeconds": 0,
            "emitBytes": 0,
        },
        "timeoutSeconds": 900,
        "outputByteBound": 4096,
        "resources": {"memoryMaxBytes": 268435456, "pidsMax": 128},
    }
    parameters = changes.pop("parameters", {})
    value.update(changes)
    value["parameters"].update(parameters)
    return value


def canonical_workspace_spec(**changes):
    value = {
        "formatVersion": "stateport.workspace-spec/v1",
        "workspaceId": "workspace.demo",
        "imageDigest": DIGEST,
        "workspacePath": "/workspace",
        "shell": ["/bin/sh"],
        "resources": {
            "memoryMaxBytes": 268435456,
            "cpuQuotaPercent": 100,
            "pidsMax": 128,
            "diskMaxBytes": 268435456,
        },
        "networkProfile": {"mode": "disabled", "allowlist": []},
        "cacheVolumes": [],
        "lifecyclePolicy": {
            "idleTimeoutSeconds": 900,
            "stopAfterIdle": True,
            "preserveDataOnRemove": True,
        },
    }
    value.update(changes)
    return value


# ----------------------------------------------------------------- contract


def test_workspace_workload_is_sealed_and_volume_is_daemon_owned():
    normalized = contract.validate_workload_spec(workspace_spec())
    argv = build_create_argv(normalized)
    assert argv[argv.index("--volume") + 1] == "stateport-workspace-workspace.demo:/workspace:rw"
    assert argv[argv.index("--workdir") + 1] == "/workspace"
    assert "--network" in argv and argv[argv.index("--network") + 1] == "none"
    assert "--read-only" in argv
    with pytest.raises(ValueError):
        invalid = workspace_spec()
        invalid["parameters"]["volumeName"] = "/host/data:/workspace"
        contract.validate_workload_spec(invalid)
    with pytest.raises(ValueError):
        invalid = workspace_spec()
        invalid["parameters"]["volumeName"] = "other-volume"
        contract.validate_workload_spec(invalid)


def test_workspace_kind_does_not_accept_arbitrary_command_or_mount_fields():
    invalid = workspace_spec()
    invalid["command"] = ["sh", "-c", "id"]
    with pytest.raises(ValueError):
        contract.validate_workload_spec(invalid)
    invalid = workspace_spec()
    invalid["parameters"]["hostPath"] = "/home/operator"
    with pytest.raises(ValueError):
        contract.validate_workload_spec(invalid)


def test_workspace_shell_is_typed_argv_never_shell_text():
    normalized = contract.validate_workload_spec(
        workspace_spec(parameters={"shell": ["/bin/bash", "-l"]})
    )
    assert normalized["parameters"]["shell"] == ["/bin/bash", "-l"]
    with pytest.raises(ValueError):
        contract.validate_workload_spec(workspace_spec(parameters={"shell": ["sh"]}))
    # A typed argv is passed verbatim to exec: "-c" is an ordinary argument
    # because nothing is ever shell-joined.  Relative or traversing
    # interpreter paths are refused.
    with pytest.raises(ValueError):
        contract.validate_workload_spec(workspace_spec(parameters={"shell": ["../bin/sh"]}))


def test_workspace_cache_volumes_are_bounded_and_daemon_owned():
    normalized = contract.validate_workload_spec(
        workspace_spec(
            parameters={
                "cacheVolumes": [
                    {"volumeId": "pip", "mountPath": "/workspace/.cache/pip", "readOnly": False}
                ]
            }
        )
    )
    argv = build_create_argv(normalized)
    volumes = [argv[index + 1] for index, item in enumerate(argv) if item == "--volume"]
    expected_cache = cache_volume_name("workspace.demo", "pip")
    assert f"{expected_cache}:/workspace/.cache/pip:rw" in volumes
    for bad_mount in ("/etc", "/workspace", "/workspace/../etc", "/workspace/a,b"):
        with pytest.raises(ValueError):
            contract.validate_workload_spec(
                workspace_spec(
                    parameters={
                        "cacheVolumes": [
                            {"volumeId": "pip", "mountPath": bad_mount, "readOnly": False}
                        ]
                    }
                )
            )


def test_workspace_cache_volume_names_are_workspace_private():
    first = contract.validate_workload_spec(
        workspace_spec(
            parameters={
                "cacheVolumes": [
                    {"volumeId": "pip", "mountPath": "/workspace/.cache", "readOnly": False}
                ]
            }
        )
    )
    second = workspace_spec(
        workloadId="workspace.other",
        parameters={
            "workspaceId": "workspace.other",
            "volumeName": "stateport-workspace-workspace.other",
            "cacheVolumes": [
                {"volumeId": "pip", "mountPath": "/workspace/.cache", "readOnly": False}
            ],
        },
    )
    second = contract.validate_workload_spec(second)
    first_argv = build_create_argv(first)
    first_cache = [
        value
        for index, value in enumerate(first_argv)
        if index > 0 and first_argv[index - 1] == "--volume" and value.startswith("stateport-cache-")
    ]
    second_argv = build_create_argv(second)
    second_cache = [
        value
        for index, value in enumerate(second_argv)
        if index > 0 and second_argv[index - 1] == "--volume" and value.startswith("stateport-cache-")
    ]
    assert len(first_cache) == len(second_cache) == 1
    assert first_cache[0] != second_cache[0]


def test_workspace_volume_identity_and_quota_semantics_fail_closed():
    calls = []

    def runner(argv, **kwargs):
        calls.append(list(argv))
        if argv[1:3] == ["volume", "create"]:
            return subprocess.CompletedProcess(argv, 0, stdout=argv[-1] + "\n", stderr="")
        if argv[1:3] == ["volume", "inspect"]:
            # A pre-created same-name volume without daemon ownership labels.
            return subprocess.CompletedProcess(argv, 0, stdout='{"Labels": {}}\n', stderr="")
        raise AssertionError(f"unexpected engine call: {argv}")

    normalized = contract.validate_workload_spec(workspace_spec())
    engine = PodmanCliEngine(runner=runner)
    with pytest.raises(EngineError, match="exact daemon ownership labels"):
        engine.create(normalized)
    assert all(call[1:3] != ["create", "--name"] for call in calls)
    enforcement = engine.resource_enforcement(normalized)
    disk = enforcement["persistentVolumeDiskMaxBytes"]
    assert disk["status"] == "unsupported"
    assert disk["requestedBytes"] == normalized["parameters"]["diskMaxBytes"]
    argv = build_create_argv(normalized)
    assert argv[argv.index("--tmpfs") + 1].endswith("size=16777216")


def test_workspace_identity_cannot_claim_another_daemon_volume():
    with pytest.raises(ValueError, match="workload's daemon-owned volume"):
        contract.validate_workload_spec(
            workspace_spec(parameters={"volumeName": "stateport-workspace-workspace.other"})
        )


def test_workspace_base_revision_and_network_mode():
    normalized = contract.validate_workload_spec(
        workspace_spec(parameters={"baseRevision": SHA, "networkMode": "developer"})
    )
    assert normalized["parameters"]["baseRevision"] == SHA
    argv = build_create_argv(normalized)
    # A developer workspace keeps podman's default rootless network.
    assert "--network" not in argv
    with pytest.raises(ValueError):
        contract.validate_workload_spec(workspace_spec(parameters={"baseRevision": "abc123"}))
    with pytest.raises(ValueError):
        contract.validate_workload_spec(workspace_spec(parameters={"networkMode": "host"}))


def test_create_argv_hardening_accepts_only_daemon_owned_volumes():
    normalized = contract.validate_workload_spec(workspace_spec())
    argv = build_create_argv(normalized)
    assert_create_argv_hardened(argv)
    with pytest.raises(EngineError):
        evil = list(argv)
        evil[evil.index("--volume") + 1] = "/home/operator:/workspace:rw"
        assert_create_argv_hardened(evil)
    with pytest.raises(EngineError):
        evil = list(argv) + ["--volume", "stateport-workspace-x:/etc:rw"]
        assert_create_argv_hardened(evil)
    with pytest.raises(EngineError):
        evil = [item for item in argv if item != "--network" and item != "none"]
        evil.extend(["--network", "host"])
        assert_create_argv_hardened(evil)


def test_terminal_and_exec_payloads_are_typed_and_bounded():
    raw = {
        "formatVersion": contract.OPERATION_FORMAT,
        "operationId": "op-1",
        "operation": "openTerminal",
        "requester": {"grantId": "grant-1", "authorityGrantDigest": DIGEST},
        "timeoutSeconds": 30,
        "outputByteBound": 4096,
        "payload": {
            "workloadId": "workspace.demo",
            "sessionId": "terminal.demo",
            "columns": 80,
            "rows": 24,
        },
    }
    request = contract.validate_operation_request(raw)
    assert contract.validate_request_payload(request, raw["payload"]) == {
        "workloadId": "workspace.demo",
        "sessionId": "terminal.demo",
        "columns": 80,
        "rows": 24,
    }
    with pytest.raises(ValueError):
        contract.validate_request_payload(
            request,
            {"workloadId": "workspace.demo", "sessionId": "terminal.demo", "columns": 0, "rows": 24},
        )
    signal_request = contract.validate_operation_request(dict(raw, operation="signalTerminal"))
    payload = contract.validate_request_payload(
        signal_request, {"sessionId": "terminal.demo", "signal": "SIGINT"}
    )
    assert payload["signal"] == "SIGINT"
    with pytest.raises(ValueError):
        contract.validate_request_payload(
            signal_request, {"sessionId": "terminal.demo", "signal": "SIGKILL"}
        )
    exec_request = contract.validate_operation_request(dict(raw, operation="execWorkload"))
    payload = contract.validate_request_payload(
        exec_request, {"workloadId": "workspace.demo", "argv": ["echo", "a;b"]}
    )
    assert payload["argv"] == ["echo", "a;b"]
    with pytest.raises(ValueError):
        contract.validate_request_payload(exec_request, {"workloadId": "workspace.demo", "argv": []})


# ------------------------------------------------------------------ adapter


class FakeClient:
    def __init__(self):
        self.calls = []

    def create_workspace(self, spec):
        self.calls.append(("create", spec))
        return {"result": {"state": "created"}}

    def list_workloads(self):
        self.calls.append(("list",))
        return {"result": {"workloads": []}}

    def status(self, workspace_id):
        self.calls.append(("status", workspace_id))
        return {"result": {"state": "running"}}

    def start(self, workspace_id):
        self.calls.append(("start", workspace_id))
        return {"result": {"state": "running"}}

    def stop(self, workspace_id):
        self.calls.append(("stop", workspace_id))
        return {"result": {"state": "stopped"}}

    def remove_workload(self, workspace_id):
        self.calls.append(("remove", workspace_id))
        return {"result": {"state": "removed"}, "cleanup": {"detail": "volume preserved"}}


def test_sealed_workload_carries_every_workspace_spec_field():
    workload = sealed_workspace_workload(
        canonical_workspace_spec(
            shell=["/bin/bash", "-l"],
            cacheVolumes=[{"volumeId": "pip", "mountPath": "/workspace/.cache", "readOnly": True}],
            networkProfile={"mode": "developer", "allowlist": []},
        ),
        image_reference=IMAGE,
        base_revision=SHA,
    )
    parameters = workload["parameters"]
    assert parameters["volumeName"] == "stateport-workspace-workspace.demo"
    assert parameters["workspaceSpecDigest"].startswith("sha256:")
    assert parameters["baseRevision"] == SHA
    assert parameters["shell"] == ["/bin/bash", "-l"]
    assert parameters["networkMode"] == "developer"
    assert parameters["cacheVolumes"] == [
        {"volumeId": "pip", "mountPath": "/workspace/.cache", "readOnly": True}
    ]
    assert parameters["stopAfterIdle"] is True
    assert workload["timeoutSeconds"] == 900
    with pytest.raises(WorkspaceRuntimeError, match="allowlist"):
        sealed_workspace_workload(
            canonical_workspace_spec(
                networkProfile={"mode": "developer", "allowlist": ["registry.example"]}
            ),
            image_reference=IMAGE,
        )
    with pytest.raises(WorkspaceRuntimeError, match="does not match"):
        sealed_workspace_workload(
            canonical_workspace_spec(),
            image_reference="docker.io/library/python@sha256:" + "c" * 64,
        )
    with pytest.raises(WorkspaceRuntimeError, match="base revision"):
        sealed_workspace_workload(
            canonical_workspace_spec(), image_reference=IMAGE, base_revision="not-a-sha"
        )


def test_workspace_lifecycle_adapter_only_binds_digest_image_and_preserves_volume():
    client = FakeClient()
    runtime = WorkspaceRuntime(client, image_reference=IMAGE)
    assert runtime.create(canonical_workspace_spec())["result"]["state"] == "created"
    assert client.calls[0][1]["kind"] == "workspace"
    assert runtime.restart("workspace.demo")["result"]["state"] == "running"
    assert runtime.remove("workspace.demo")["cleanup"]["detail"] == "volume preserved"
    assert runtime.list()["result"]["workloads"] == []
    with pytest.raises(WorkspaceRuntimeError, match="digest-pinned"):
        WorkspaceRuntime(client, image_reference="workspace:latest")
