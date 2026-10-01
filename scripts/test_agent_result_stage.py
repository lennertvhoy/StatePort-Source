#!/usr/bin/env python3
"""Unit/render tests for the native installed-product agent-result stage."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for relative in (str(ROOT), str(ROOT / "scripts"), str(ROOT / "scripts/qualification")):
    if relative not in sys.path:
        sys.path.insert(0, relative)

import journey_common  # noqa: E402
import run_agent_result_stage as stage  # noqa: E402

WEB = "sha256:" + "a" * 64
API = "sha256:" + "b" * 64
WORKER = "sha256:" + "c" * 64
WORKSPACE_IMAGE = "sha256:" + "d" * 64
EXPECTED_IMAGES = {
    "stateport-web": WEB,
    "stateport-api": API,
    "stateport-worker": WORKER,
    "stateport-dev-workspace": WORKSPACE_IMAGE,
}
WORKSPACE_REFERENCE = (
    "127.0.0.1:5002/stateport-alpha/stateport-dev-workspace@" + WORKSPACE_IMAGE
)
CONTROL_IDS = ("stateport-web", "stateport-api", "stateport-worker")
SERVICES = {
    service_id: {
        "unit": service_id + ".service",
        "port": str(8080 + index),
        "container": service_id,
    }
    for index, service_id in enumerate(CONTROL_IDS)
}
DISTRO = "StatePort-Rehearsal-agent-result-fixture"
OUTPUT_TEXT = '{"type":"text","text":"Linux 7.1.9-arch1-2 x86_64"}\n'


def _digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _mirror_evidence() -> dict:
    """Retained candidate-mirror J1 evidence, exactly as J4 validation returns it."""
    return {
        "evidenceClass": "candidate_mirror",
        "transportClass": "prepublication-mirror",
        "identityClass": "candidate-mirror",
        "ownerPathQualification": False,
        "publicTransportBoundary": False,
        "rehearsalBaseline": {
            "schema": "stateport.rehearsal-baseline/v1",
            "substrate": "native-wsl2",
            "rootfsIdentity": journey_common.WSL_ROOTFS_IDENTITY,
            "evidenceClass": "candidate_mirror",
            "transportClass": "prepublication-mirror",
            "identityClass": "candidate-mirror",
            "ownerPathQualification": False,
            "publicTransportBoundary": False,
            "distroName": DISTRO,
            "machineId": "a" * 32,
            "windowsIdentity": "Microsoft Windows 11|10.0|26200",
        },
        "nativeIdentity": {
            "machineId": "a" * 32,
            "windowsIdentity": "Microsoft Windows 11|10.0|26200",
        },
    }


def _owner_evidence() -> dict:
    """Retained owner-path J1 evidence: no candidate-mirror markers at all."""
    return {
        "rehearsalBaseline": {
            "schema": "stateport.rehearsal-baseline/v1",
            "substrate": "native-wsl2",
            "rootfsIdentity": journey_common.WSL_ROOTFS_IDENTITY,
            "evidenceClass": "owner_path_qualification",
            "distroName": DISTRO,
            "machineId": "a" * 32,
            "windowsIdentity": "Microsoft Windows 11|10.0|26200",
        },
        "nativeIdentity": {
            "machineId": "a" * 32,
            "windowsIdentity": "Microsoft Windows 11|10.0|26200",
        },
    }


def _facts() -> dict:
    return {"releaseId": "release-test-1", "version": "0.1.0-test.1", "images": EXPECTED_IMAGES}


def _ready_readiness() -> dict:
    return {
        "available": True,
        "refusals": [],
        "providerDirectory": {
            "configured": True,
            "present": True,
            "files": {"providerEnv": True, "opencodeJson": True, "model": True},
        },
        "workspace": {"status": "absent", "workloadId": "agent-workspace"},
    }


def _run_record(run_id: str = "agent-run-" + "1" * 32, *, objective: str | None = None,
                output_text: str = OUTPUT_TEXT, status: str = "completed",
                exit_status: int | None = 0, image_reference: str = WORKSPACE_REFERENCE,
                objective_digest: str | None = None, output_digest: str | None = None,
                output_bytes: int | None = None, truncated: bool = False,
                refusal: dict | None = None) -> dict:
    objective = stage.OBJECTIVE if objective is None else objective
    return {
        "formatVersion": "stateport.agent-run-receipt/v1",
        "runId": run_id,
        "status": status,
        "objective": objective,
        "objectiveDigest": objective_digest if objective_digest is not None else _digest(objective),
        "workspaceId": "agent-workspace",
        "imageReference": image_reference,
        "workspaceSpecDigest": "sha256:" + "9" * 64,
        "grantId": "agent-workspace-v1",
        "authorityGrantDigest": "sha256:" + "8" * 64,
        "createOperationId": "op-create",
        "startOperationId": "op-start",
        "execOperationId": "op-exec",
        "exitStatus": exit_status,
        "outputDigest": output_digest if output_digest is not None else _digest(output_text),
        "outputBytes": (
            output_bytes if output_bytes is not None else len(output_text.encode("utf-8"))
        ),
        "truncated": truncated,
        "refusal": refusal,
        "startedAt": "2026-09-17T08:00:00Z",
        "finishedAt": "2026-09-17T08:00:20Z",
        "createdAt": "2026-09-17T08:00:00Z",
        "updatedAt": "2026-09-17T08:00:20Z",
    }


def _output_document(run_id: str = "agent-run-" + "1" * 32, *, output_text: str = OUTPUT_TEXT,
                     truncated: bool = False, output_bytes: int | None = None) -> dict:
    return {
        "runId": run_id,
        "output": output_text,
        "truncated": truncated,
        "outputBytes": (
            output_bytes if output_bytes is not None else len(output_text.encode("utf-8"))
        ),
    }


def _container_payload(image_digest: str = WORKSPACE_IMAGE) -> dict:
    return {
        "id": "d" * 64,
        "name": "stateport-exec-agent-workspace",
        "image": "e" * 64,
        "imageDigest": image_digest,
        "state": "running",
        "running": True,
        "readOnly": True,
        "networkMode": "pasta",
        "memory": 1073741824,
        "pidsLimit": 256,
        "mounts": [
            {"Type": "volume", "Source": "/vol/workspace", "Destination": "/workspace", "RW": True},
            {
                "Type": "bind",
                "Source": "/var/lib/stateport-exec/stateport-execution-host/agent-provider",
                "Destination": "/stateport-provider",
                "RW": False,
            },
        ],
        "labels": {
            "io.stateport.execution.managed": "true",
            "io.stateport.execution.workload": "agent-workspace",
            "io.stateport.execution.kind": "workspace",
            "io.stateport.credentials": "operator-volume-only",
        },
    }


class FakeNativeVM:
    """Scripted native guest: implements only the seams this stage uses."""

    native_wsl = True
    distro_name = DISTRO

    def __init__(self, *, container: dict | None = None, container_absent: bool = False,
                 exec_user_absent: bool = False) -> None:
        self.commands: list = []
        self.teardown_calls = 0
        self.container = container if container is not None else _container_payload()
        self.container_absent = container_absent
        self.exec_user_absent = exec_user_absent

    def ssh(self, command, **kwargs):
        self.commands.append(command)
        if "id -u stateport-exec" in command:
            if self.exec_user_absent:
                return subprocess.CompletedProcess([], 0, "", "")
            return subprocess.CompletedProcess([], 0, "65532\n", "")
        if "podman container inspect" in command:
            if self.container_absent:
                return subprocess.CompletedProcess([], 125, "", "no such container")
            return subprocess.CompletedProcess(
                [], 0, json.dumps(self.container) + "\n", ""
            )
        raise AssertionError(f"unexpected ssh command: {command[:200]}")

    def teardown(self):
        self.teardown_calls += 1


class FakeControlPlane:
    """Scripted operator session over the installed control plane's HTTP surface."""

    def __init__(self, *, readiness: dict | None = None, run: dict | None = None,
                 output: dict | None = None, run_states: list | None = None,
                 actor_role: str = "platform_operator",
                 handshake_error: Exception | None = None,
                 run_error: Exception | None = None) -> None:
        self.calls: list = []
        self.readiness = readiness if readiness is not None else _ready_readiness()
        self.run = run if run is not None else _run_record()
        self.output = output if output is not None else _output_document()
        self.run_states = list(run_states) if run_states is not None else None
        self.actor_role = actor_role
        self.handshake_error = handshake_error
        self.run_error = run_error

    def handshake(self) -> str:
        self.calls.append(("HANDSHAKE",))
        if self.handshake_error is not None:
            raise self.handshake_error
        return "csrf-token"

    def request(self, method, path, body=None, headers=None, csrf=False, timeout=90):
        self.calls.append((method, path, body, csrf))
        if path == "/v1/status":
            return {"actor": {"role": self.actor_role, "actorId": "platform-operator"}}
        if path == "/v1/agent/status":
            return self.readiness
        if path == "/v1/agent/run":
            if csrf is not True or not isinstance(body, dict) or set(body) != {"objective"}:
                raise AssertionError(f"unsafe agent-run submission: csrf={csrf} body={body!r}")
            if self.run_error is not None:
                raise self.run_error
            return {
                "runId": self.run["runId"],
                "status": "running",
                "objective": body["objective"],
                "workspaceId": "agent-workspace",
                "startedAt": "2026-09-17T08:00:00Z",
            }
        if path == f"/v1/agent/runs/{self.run['runId']}":
            if self.run_states:
                state = self.run_states.pop(0)
                return {**self.run, "status": state}
            return self.run
        if path == f"/v1/agent/runs/{self.run['runId']}/output":
            return self.output
        raise AssertionError(f"unexpected request: {method} {path}")


def _patch_guest(monkeypatch, control: FakeControlPlane) -> None:
    monkeypatch.setattr(stage, "GuestJsonClient", lambda _vm, _port: control)
    monkeypatch.setattr(stage, "discover_services", lambda _vm: SERVICES)
    monkeypatch.setattr(stage, "wait_service_healthy", lambda *a, **k: None)


def _run(vm, tmp_path, evidence, *, prepublication_mirror: bool, control: FakeControlPlane,
         objective: str = stage.OBJECTIVE):
    return stage.execute_agent_result_stage(
        vm, facts=_facts(), evidence=evidence,
        prepublication_mirror=prepublication_mirror,
        receipt_out=tmp_path / "agent-result-receipt.json",
        objective=objective,
        run_timeout_s=10,
        poll_interval_s=0.0,
    )


def _receipt(tmp_path) -> dict:
    return json.loads((tmp_path / "agent-result-receipt.json").read_text(encoding="utf-8"))


def _steps(receipt: dict) -> dict:
    return {entry["name"]: entry for entry in receipt["steps"]}


def test_agent_result_stage_positive_candidate_mirror_receipt(tmp_path, monkeypatch) -> None:
    vm = FakeNativeVM()
    control = FakeControlPlane(run_states=["running", "running"])
    _patch_guest(monkeypatch, control)

    summary = _run(vm, tmp_path, _mirror_evidence(), prepublication_mirror=True,
                   control=control)

    receipt = _receipt(tmp_path)
    assert receipt["result"] == "passed"
    assert receipt["formatVersion"] == "stateport.journey-receipt/v1"
    assert receipt["journeyId"] == "native-agent-result"
    assert receipt["lane"] == "integratedQualification"
    assert receipt["mode"] == "prepublication-mirror"
    assert receipt["evidenceClass"] == "candidate_mirror"
    assert receipt["transportClass"] == "prepublication-mirror"
    assert receipt["identityClass"] == "candidate-mirror"
    assert receipt["ownerPathQualification"] is False
    assert receipt["publicTransportBoundary"] is False
    assert receipt["limitations"].startswith("One bounded objective executed")
    assert summary["mode"] == "prepublication-mirror"
    assert summary["status"] == "completed" and summary["exitStatus"] == 0
    assert summary["runId"] == "agent-run-" + "1" * 32
    assert summary["outputDigest"] == _digest(OUTPUT_TEXT)
    assert summary["outputBytes"] == len(OUTPUT_TEXT.encode("utf-8"))
    assert summary["containerId"] == "d" * 64
    assert summary["containerImageDigest"] == WORKSPACE_IMAGE
    assert summary["signedImageId"] == "stateport-dev-workspace"

    steps = _steps(receipt)
    assert steps["lane-class"]["ok"] is True
    assert steps["control-plane-health"]["services"] == SERVICES
    assert steps["web-session-handshake"]["csrfPresent"] is True
    assert "csrfToken" not in json.dumps(receipt)
    assert steps["operator-session"]["actorRole"] == "platform_operator"
    assert steps["agent-readiness"]["available"] is True
    assert steps["agent-readiness"]["providerDirectory"]["files"]["providerEnv"] is True
    assert steps["agent-run-accepted"]["runId"] == "agent-run-" + "1" * 32
    assert steps["agent-run-accepted"]["objectiveDigest"] == _digest(stage.OBJECTIVE)
    assert steps["agent-run-terminal"]["ok"] is True
    assert steps["agent-run-terminal"]["run"]["outputDigest"] == _digest(OUTPUT_TEXT)
    assert steps["agent-run-receipt-binding"]["ok"] is True
    assert steps["agent-run-receipt-binding"]["grantId"] == "agent-workspace-v1"
    assert steps["agent-output-digest"]["ok"] is True
    assert steps["agent-output-digest"]["outputDigest"] == _digest(OUTPUT_TEXT)
    assert steps["agent-output-digest"]["recordedOutputDigest"] == _digest(OUTPUT_TEXT)
    assert steps["agent-output-digest"]["truncated"] is False
    assert steps["agent-workspace-container"]["ok"] is True
    assert steps["agent-workspace-container"]["checks"]["imageDigestMatchesRun"] is True
    assert steps["agent-workspace-container"]["checks"]["signedImageBound"] is True
    assert steps["agent-workspace-container"]["checks"]["providerBindReadOnly"] is True
    assert steps["agent-workspace-container"]["labels"]["io.stateport.credentials"] == (
        "operator-volume-only"
    )
    assert steps["agent-workspace-container"]["readOnly"] is True

    # Exactly three status polls: two running then the settled record.
    status_calls = [call for call in control.calls
                    if call[0] == "GET" and "/v1/agent/runs/" in call[1]
                    and not call[1].endswith("/output")]
    assert len(status_calls) == 3
    assert all(call[1].endswith("agent-run-" + "1" * 32) for call in status_calls)
    post = [call for call in control.calls if call[0] == "POST"]
    assert post == [("POST", "/v1/agent/run", {"objective": stage.OBJECTIVE}, True)]
    assert any("podman container inspect" in command for command in vm.commands)
    assert vm.teardown_calls == 0


def test_agent_result_stage_positive_owner_path_receipt_has_no_mirror_markers(
    tmp_path, monkeypatch
) -> None:
    vm = FakeNativeVM()
    control = FakeControlPlane()
    _patch_guest(monkeypatch, control)

    _run(vm, tmp_path, _owner_evidence(), prepublication_mirror=False, control=control)

    receipt = _receipt(tmp_path)
    assert receipt["result"] == "passed"
    assert receipt["mode"] == "public-transport"
    assert receipt["evidenceClass"] == "owner_path_qualification"
    assert "transportClass" not in receipt
    assert receipt["hostsMappingRequired"] is False


def test_agent_result_stage_refuses_absent_provider_credential(tmp_path, monkeypatch) -> None:
    vm = FakeNativeVM()
    readiness = _ready_readiness()
    readiness["available"] = False
    readiness["providerDirectory"]["files"]["providerEnv"] = False
    readiness["refusals"] = [
        {"reason": "provider_directory_incomplete", "detail": "provider.env is missing or unsafe"}
    ]
    control = FakeControlPlane(readiness=readiness)
    _patch_guest(monkeypatch, control)

    with pytest.raises(AssertionError, match="not ready"):
        _run(vm, tmp_path, _owner_evidence(), prepublication_mirror=False, control=control)

    receipt = _receipt(tmp_path)
    assert receipt["result"] == "failed"
    steps = _steps(receipt)
    assert steps["agent-readiness"]["ok"] is False
    assert steps["agent-readiness"]["providerDirectory"]["files"]["providerEnv"] is False
    assert steps["agent-readiness"]["refusals"][0]["reason"] == "provider_directory_incomplete"
    assert "agent-run-accepted" not in steps
    assert not [call for call in control.calls if call[0] == "POST"]
    assert receipt["steps"][-1]["name"] == "agent-result-stage-failure"


def test_agent_result_stage_refuses_unreachable_control_plane(tmp_path, monkeypatch) -> None:
    vm = FakeNativeVM()
    control = FakeControlPlane(handshake_error=journey_common.Refusal(
        "curl_failed", "exit=7 could not connect", None
    ))
    _patch_guest(monkeypatch, control)

    with pytest.raises(journey_common.Refusal, match="curl_failed"):
        _run(vm, tmp_path, _owner_evidence(), prepublication_mirror=False, control=control)

    receipt = _receipt(tmp_path)
    assert receipt["result"] == "failed"
    failure = receipt["steps"][-1]
    assert failure["name"] == "agent-result-stage-failure"
    assert failure["refusalCode"] == "curl_failed"
    assert failure["httpStatus"] is None
    assert "web-session-handshake" not in _steps(receipt)


def test_agent_result_stage_refuses_missing_control_plane_services(tmp_path, monkeypatch) -> None:
    vm = FakeNativeVM()
    control = FakeControlPlane()
    _patch_guest(monkeypatch, control)

    def missing(_vm):
        raise SystemExit("incomplete control plane discovery: {}")

    monkeypatch.setattr(stage, "discover_services", missing)

    with pytest.raises(SystemExit, match="incomplete control plane discovery"):
        _run(vm, tmp_path, _owner_evidence(), prepublication_mirror=False, control=control)

    receipt = _receipt(tmp_path)
    assert receipt["result"] == "failed"
    assert receipt["steps"][-1]["name"] == "agent-result-stage-failure"
    assert "control-plane-health" not in _steps(receipt)


def test_agent_result_stage_refuses_non_operator_session(tmp_path, monkeypatch) -> None:
    vm = FakeNativeVM()
    control = FakeControlPlane(actor_role="local_user")
    _patch_guest(monkeypatch, control)

    with pytest.raises(AssertionError, match="not the platform operator"):
        _run(vm, tmp_path, _owner_evidence(), prepublication_mirror=False, control=control)

    receipt = _receipt(tmp_path)
    assert receipt["result"] == "failed"
    assert _steps(receipt)["operator-session"]["ok"] is False
    assert not [call for call in control.calls if call[0] == "POST"]


@pytest.mark.parametrize("status,exit_status,refusal", [
    ("failed", 1, {"reason": "agent_run_failed", "detail": "provider refused the request"}),
    ("refused", None, {"reason": "execution_unavailable",
                       "detail": "execution host is unavailable"}),
])
def test_agent_result_stage_refuses_terminal_run_failure(
    tmp_path, monkeypatch, status, exit_status, refusal
) -> None:
    vm = FakeNativeVM()
    run = _run_record(status=status, exit_status=exit_status, refusal=refusal)
    control = FakeControlPlane(run=run)
    _patch_guest(monkeypatch, control)

    with pytest.raises(AssertionError, match="did not complete successfully"):
        _run(vm, tmp_path, _owner_evidence(), prepublication_mirror=False, control=control)

    receipt = _receipt(tmp_path)
    assert receipt["result"] == "failed"
    terminal = _steps(receipt)["agent-run-terminal"]
    assert terminal["ok"] is False
    assert terminal["status"] == status
    assert "agent-output-digest" not in _steps(receipt)
    assert "agent-workspace-container" not in _steps(receipt)


def test_agent_result_stage_refuses_output_digest_mismatch(tmp_path, monkeypatch) -> None:
    vm = FakeNativeVM()
    run = _run_record(output_digest="sha256:" + "f" * 64)
    control = FakeControlPlane(run=run)
    _patch_guest(monkeypatch, control)

    with pytest.raises(AssertionError, match="does not re-derive"):
        _run(vm, tmp_path, _owner_evidence(), prepublication_mirror=False, control=control)

    receipt = _receipt(tmp_path)
    assert receipt["result"] == "failed"
    assert _steps(receipt)["agent-output-digest"]["ok"] is False
    assert _steps(receipt)["agent-output-digest"]["outputDigest"] == _digest(OUTPUT_TEXT)
    assert "agent-workspace-container" not in _steps(receipt)


def test_agent_result_stage_refuses_truncated_output(tmp_path, monkeypatch) -> None:
    vm = FakeNativeVM()
    run = _run_record(truncated=True, output_digest=_digest(OUTPUT_TEXT + "tail"))
    output = _output_document(truncated=True)
    control = FakeControlPlane(run=run, output=output)
    _patch_guest(monkeypatch, control)

    with pytest.raises(AssertionError, match="does not re-derive"):
        _run(vm, tmp_path, _owner_evidence(), prepublication_mirror=False, control=control)

    receipt = _receipt(tmp_path)
    assert receipt["result"] == "failed"
    assert _steps(receipt)["agent-output-digest"]["truncated"] is True


def test_agent_result_stage_refuses_unbound_objective_digest(tmp_path, monkeypatch) -> None:
    vm = FakeNativeVM()
    run = _run_record(objective_digest="sha256:" + "0" * 64)
    control = FakeControlPlane(run=run)
    _patch_guest(monkeypatch, control)

    with pytest.raises(AssertionError, match="does not bind the submitted objective"):
        _run(vm, tmp_path, _owner_evidence(), prepublication_mirror=False, control=control)

    receipt = _receipt(tmp_path)
    assert receipt["result"] == "failed"
    assert _steps(receipt)["agent-run-receipt-binding"]["ok"] is False


def test_agent_result_stage_refuses_unsigned_workspace_image(tmp_path, monkeypatch) -> None:
    vm = FakeNativeVM()
    unsigned = "sha256:" + "7" * 64
    run = _run_record(image_reference="127.0.0.1:5002/stateport-alpha/dev@" + unsigned)
    container = _container_payload(image_digest=unsigned)
    control = FakeControlPlane(run=run)
    _patch_guest(monkeypatch, control)
    vm.container = container

    with pytest.raises(AssertionError, match="container identity does not match"):
        _run(vm, tmp_path, _owner_evidence(), prepublication_mirror=False, control=control)

    receipt = _receipt(tmp_path)
    assert receipt["result"] == "failed"
    container_step = _steps(receipt)["agent-workspace-container"]
    assert container_step["ok"] is False
    assert container_step["checks"]["imageDigestMatchesRun"] is True
    assert container_step["checks"]["signedImageBound"] is False


def test_agent_result_stage_refuses_container_image_mismatch(tmp_path, monkeypatch) -> None:
    vm = FakeNativeVM(container=_container_payload(image_digest="sha256:" + "6" * 64))
    control = FakeControlPlane()
    _patch_guest(monkeypatch, control)

    with pytest.raises(AssertionError, match="container identity does not match"):
        _run(vm, tmp_path, _owner_evidence(), prepublication_mirror=False, control=control)

    receipt = _receipt(tmp_path)
    assert receipt["result"] == "failed"
    container_step = _steps(receipt)["agent-workspace-container"]
    assert container_step["checks"]["imageDigestMatchesRun"] is False


def test_agent_result_stage_refuses_absent_workspace_container(tmp_path, monkeypatch) -> None:
    vm = FakeNativeVM(container_absent=True)
    control = FakeControlPlane()
    _patch_guest(monkeypatch, control)

    with pytest.raises(AssertionError, match="container identity is unavailable"):
        _run(vm, tmp_path, _owner_evidence(), prepublication_mirror=False, control=control)

    receipt = _receipt(tmp_path)
    assert receipt["result"] == "failed"
    assert "agent-workspace-container" not in _steps(receipt)


def test_agent_result_stage_refuses_absent_execution_identity(tmp_path, monkeypatch) -> None:
    vm = FakeNativeVM(exec_user_absent=True)
    control = FakeControlPlane()
    _patch_guest(monkeypatch, control)

    with pytest.raises(AssertionError, match="stateport-exec is absent"):
        _run(vm, tmp_path, _owner_evidence(), prepublication_mirror=False, control=control)

    assert _receipt(tmp_path)["result"] == "failed"


def test_agent_result_stage_refuses_qemu_or_simulation_substrate_before_guest_calls() -> None:
    qemu = _owner_evidence()
    qemu["rehearsalBaseline"]["substrate"] = "qemu-wsl-identity-simulation"
    with pytest.raises(ValueError, match="retained native WSL2 J1 baseline"):
        stage.enforce_agent_result_lane(qemu, prepublication_mirror=False)
    with pytest.raises(ValueError, match="retained native J1 baseline"):
        stage.enforce_agent_result_lane({}, prepublication_mirror=True)


@pytest.mark.parametrize("evidence_factory,flag", [
    (_owner_evidence, True),   # mirror flag against an owner-path receipt
    (_mirror_evidence, False),  # owner default against a candidate-mirror receipt
])
def test_agent_result_stage_refuses_unmatched_lane_class(evidence_factory, flag) -> None:
    with pytest.raises(ValueError, match="shared lane gate"):
        stage.enforce_agent_result_lane(evidence_factory(), prepublication_mirror=flag)


def test_agent_result_stage_refuses_lane_mismatch_before_any_guest_call(
    tmp_path, monkeypatch
) -> None:
    vm = FakeNativeVM()
    control = FakeControlPlane()
    _patch_guest(monkeypatch, control)

    with pytest.raises(ValueError, match="shared lane gate"):
        _run(vm, tmp_path, _mirror_evidence(), prepublication_mirror=False, control=control)

    receipt = _receipt(tmp_path)
    assert receipt["result"] == "failed"
    assert [entry["name"] for entry in receipt["steps"]] == ["agent-result-stage-failure"]
    assert control.calls == []
    assert vm.commands == []


def test_agent_result_stage_refuses_simulation_vm(tmp_path, monkeypatch) -> None:
    vm = FakeNativeVM()
    vm.native_wsl = False
    control = FakeControlPlane()
    _patch_guest(monkeypatch, control)

    with pytest.raises(AssertionError, match="native WSL2 lane"):
        _run(vm, tmp_path, _owner_evidence(), prepublication_mirror=False, control=control)

    assert _receipt(tmp_path)["result"] == "failed"


def test_agent_result_stage_refuses_unbounded_objective(tmp_path, monkeypatch) -> None:
    vm = FakeNativeVM()
    control = FakeControlPlane()
    _patch_guest(monkeypatch, control)

    with pytest.raises(ValueError, match="bounded non-empty string"):
        _run(vm, tmp_path, _owner_evidence(), prepublication_mirror=False, control=control,
             objective="x" * 257)
    assert not (tmp_path / "agent-result-receipt.json").exists()


def test_agent_result_stage_main_records_durable_preflight_failure(tmp_path, monkeypatch) -> None:
    def refuse(*_args, **_kwargs):
        raise ValueError("retained full-J1 receipt is not a candidate-mirror receipt")

    monkeypatch.setattr(stage, "validate_retained_candidate_inputs", refuse)
    receipt_out = tmp_path / "agent-result.json"
    monkeypatch.setattr(sys, "argv", [
        "run_agent_result_stage.py", "--receipt-out", str(receipt_out),
        "--vm-dir", str(tmp_path / "vm"), "--candidate-dir", str(tmp_path / "candidate"),
        "--site-root", str(tmp_path / "site"), "--native-wsl2",
        "--wsl-distro-name", DISTRO,
    ])
    assert stage.main() == 1
    receipt = json.loads(receipt_out.read_text(encoding="utf-8"))
    assert receipt["result"] == "failed"
    assert len(receipt["steps"]) == 1
    assert receipt["steps"][0]["name"] == "input-preflight"
    assert receipt["steps"][0]["ok"] is False
    assert "ValueError" in receipt["steps"][0]["error"]


@pytest.mark.parametrize("extra", [
    [],                                        # no --native-wsl2
    ["--native-wsl2"],                         # no distro name
])
def test_agent_result_stage_cli_requires_the_native_lane(tmp_path, monkeypatch, extra) -> None:
    monkeypatch.setattr(sys, "argv", [
        "run_agent_result_stage.py", "--receipt-out", str(tmp_path / "agent-result.json"),
        "--vm-dir", str(tmp_path / "vm"), "--candidate-dir", str(tmp_path / "candidate"),
        "--site-root", str(tmp_path / "site"), *extra,
    ])
    with pytest.raises(SystemExit) as refused:
        stage.main()
    assert refused.value.code == 2
    assert not (tmp_path / "agent-result.json").exists()


def test_agent_result_stage_main_attaches_and_executes_stage(tmp_path, monkeypatch) -> None:
    evidence = _mirror_evidence()
    monkeypatch.setattr(stage, "validate_retained_candidate_inputs",
                        lambda *_a, **_k: (_facts(), evidence))
    seen: dict = {}

    class Vm:
        def teardown(self):
            seen["teardown"] = True

    vm = Vm()

    def fake_boot(*_args, **kwargs):
        seen["boot"] = kwargs
        return vm

    monkeypatch.setattr(stage, "boot_native_follow_on", fake_boot)

    def fake_execute(guest, *, facts, evidence, prepublication_mirror, receipt_out,
                     run_timeout_s=None):
        seen["stage"] = (guest, prepublication_mirror, Path(receipt_out), run_timeout_s)
        return {"mode": "prepublication-mirror"}

    monkeypatch.setattr(stage, "execute_agent_result_stage", fake_execute)
    receipt_out = tmp_path / "agent-result.json"
    monkeypatch.setattr(sys, "argv", [
        "run_agent_result_stage.py", "--receipt-out", str(receipt_out),
        "--vm-dir", str(tmp_path / "vm"), "--candidate-dir", str(tmp_path / "candidate"),
        "--site-root", str(tmp_path / "site"), "--native-wsl2",
        "--wsl-distro-name", DISTRO, "--prepublication-mirror",
    ])
    assert stage.main() == 0
    assert seen["stage"] == (vm, True, receipt_out, 1200.0)
    assert seen["boot"]["distro_name"] == DISTRO
    assert seen["boot"]["expected_identity"] == evidence["nativeIdentity"]
    assert seen["boot"]["expected_baseline"] == evidence["rehearsalBaseline"]
    assert seen["teardown"] is True


def test_j4_agent_result_stage_flags_require_the_native_lane(tmp_path, monkeypatch) -> None:
    import run_journey_j4 as j4

    base = [
        "run_journey_j4.py", "--receipt-out", str(tmp_path / "j4.json"),
        "--vm-dir", str(tmp_path / "vm"), "--candidate-dir", str(tmp_path / "candidate"),
        "--site-root", str(tmp_path / "site"),
    ]
    monkeypatch.setattr(sys, "argv", [*base, "--agent-result-stage"])
    with pytest.raises(SystemExit) as refused:
        j4.main()
    assert refused.value.code == 2

    monkeypatch.setattr(sys, "argv", [
        *base, "--native-wsl2", "--wsl-distro-name", DISTRO, "--agent-result-stage",
    ])
    with pytest.raises(SystemExit) as refused:
        j4.main()
    assert refused.value.code == 2


def _stub_j4_plane(monkeypatch, j4, *, vm) -> None:
    monkeypatch.setattr(j4, "validate_retained_candidate_inputs",
                        lambda *_a, **_k: (_facts(), _owner_evidence()))
    monkeypatch.setattr(j4, "boot_native_follow_on", lambda *_a, **_k: vm)
    monkeypatch.setattr(j4, "discover_services", lambda _vm: SERVICES)
    monkeypatch.setattr(j4, "wait_all_healthy", lambda *_a, **_k: None)
    monkeypatch.setattr(j4, "verify_installed_image_digests",
                        lambda *_a, **_k: {"mismatches": {}, "observed": {}, "declared": {},
                                           "containers": {}})


def test_j4_invokes_the_agent_result_stage_before_the_reboot_stage(
    tmp_path, monkeypatch
) -> None:
    import run_journey_j4 as j4
    import run_reboot_stage as reboot_stage

    class Vm:
        native_wsl = True

        def teardown(self):
            pass

    vm = Vm()
    _stub_j4_plane(monkeypatch, j4, vm=vm)
    invoked: list = []

    def stop_after_agent_stage(guest, *, facts, evidence, prepublication_mirror,
                               receipt_out, **kwargs):
        invoked.append(("agent", guest, prepublication_mirror, Path(receipt_out)))
        raise RuntimeError("agent stage reached")

    monkeypatch.setattr(stage, "execute_agent_result_stage", stop_after_agent_stage)
    monkeypatch.setattr(reboot_stage, "execute_reboot_stage",
                        lambda *_a, **_k: pytest.fail("reboot stage ran before the agent stage"))

    receipt_out = tmp_path / "j4.json"
    agent_out = tmp_path / "agent-result.json"
    monkeypatch.setattr(sys, "argv", [
        "run_journey_j4.py", "--receipt-out", str(receipt_out),
        "--vm-dir", str(tmp_path / "vm"), "--candidate-dir", str(tmp_path / "candidate"),
        "--site-root", str(tmp_path / "site"), "--native-wsl2",
        "--wsl-distro-name", DISTRO, "--agent-result-stage",
        "--agent-result-stage-receipt-out", str(agent_out),
        "--reboot-stage", "--reboot-stage-receipt-out", str(tmp_path / "reboot.json"),
    ])

    assert j4.main() == 1
    assert invoked == [("agent", vm, False, agent_out)]
    document = json.loads(receipt_out.read_text(encoding="utf-8"))
    names = [entry["name"] for entry in document["steps"]]
    assert names.index("control-plane-bound-to-candidate") < names.index("driver-error")
    assert "uninstall-retaining-state" not in names


def test_j4_runs_the_reboot_stage_after_a_successful_agent_result_stage(
    tmp_path, monkeypatch
) -> None:
    import run_journey_j4 as j4
    import run_reboot_stage as reboot_stage

    class Vm:
        native_wsl = True

        def teardown(self):
            pass

    vm = Vm()
    _stub_j4_plane(monkeypatch, j4, vm=vm)
    order: list = []

    monkeypatch.setattr(
        stage, "execute_agent_result_stage",
        lambda *_a, **_k: order.append("agent") or {"mode": "public-transport"},
    )

    def stop_at_reboot(*_a, **_k):
        order.append("reboot")
        raise RuntimeError("reboot stage reached")

    monkeypatch.setattr(reboot_stage, "execute_reboot_stage", stop_at_reboot)

    receipt_out = tmp_path / "j4.json"
    monkeypatch.setattr(sys, "argv", [
        "run_journey_j4.py", "--receipt-out", str(receipt_out),
        "--vm-dir", str(tmp_path / "vm"), "--candidate-dir", str(tmp_path / "candidate"),
        "--site-root", str(tmp_path / "site"), "--native-wsl2",
        "--wsl-distro-name", DISTRO, "--agent-result-stage",
        "--agent-result-stage-receipt-out", str(tmp_path / "agent-result.json"),
        "--reboot-stage", "--reboot-stage-receipt-out", str(tmp_path / "reboot.json"),
    ])

    assert j4.main() == 1
    assert order == ["agent", "reboot"]
    document = json.loads(receipt_out.read_text(encoding="utf-8"))
    names = [entry["name"] for entry in document["steps"]]
    assert names.index("agent-result-stage") < names.index("driver-error")


class _DiagnosticVM:
    """Scripted guest for the readiness-refusal diagnostic collector."""

    def __init__(self, rows: list[str], mounts: dict[str, str]) -> None:
        self.rows = rows
        self.mounts = mounts
        self.commands: list[str] = []

    def ssh(self, command, **_kwargs):
        self.commands.append(command)
        if "podman ps -a" in command:
            return subprocess.CompletedProcess([], 0, "\n".join(self.rows) + "\n", "")
        if "podman inspect" in command:
            for cid, payload in self.mounts.items():
                if f" {cid} " in command:
                    return subprocess.CompletedProcess([], 0, payload + "\n", "")
            return subprocess.CompletedProcess([], 1, "", "no such container")
        if "stat -c" in command:
            return subprocess.CompletedProcess([], 0, "1000:1000 755 /vol/x\n", "")
        if "id -u" in command:
            return subprocess.CompletedProcess([], 0, "1000\n1001\n", "")
        raise AssertionError(f"unexpected ssh command: {command[:200]}")

    def stat_targets(self) -> list[str]:
        return [command for command in self.commands if "stat -c" in command]


def _mounts_json(*sources: str, key: str = "Source") -> str:
    return json.dumps(
        [
            {"Type": "bind", key: source, "Destination": f"/d{index}", "RW": False}
            for index, source in enumerate(sources)
        ]
    )


def test_collect_container_diagnostics_uses_capitalised_source_without_truncation() -> None:
    # Five containers and four distinct sources: proves neither the old
    # per-container cap (4) nor the old ownership cap (3) silently drops proof.
    rows = [
        f"{index:064x} stateport-c{index} image:tag Up {index} hours"
        for index in range(1, 6)
    ]
    mounts = {
        f"{1:064x}": _mounts_json(
            "/vol/a", "/vol/b", "/vol/c", "/var/lib/stateport/agent-provider"
        ),
        f"{2:064x}": _mounts_json("/vol/a"),
        f"{3:064x}": "not json at all",
        f"{4:064x}": _mounts_json("/legacy", key="source"),
        f"{5:064x}": _mounts_json(),
    }
    vm = _DiagnosticVM(rows, mounts)

    entries = stage._collect_container_diagnostics(vm)

    container_entries = [entry for entry in entries if "id" in entry]
    assert len(container_entries) == 5
    # Mounts are the full parsed list, never a truncated string.
    first = container_entries[0]
    assert isinstance(first["mounts"], list) and len(first["mounts"]) == 4
    # A probe that does not parse keeps the raw text instead of losing it.
    unparsed = container_entries[2]
    assert unparsed["mounts"] == [] and isinstance(unparsed["mountsRaw"], str)
    # Ownership is stat'd for every distinct source, capitalised and fallback.
    stat_targets = vm.stat_targets()
    for source in ("/vol/a", "/vol/b", "/vol/c",
                   "/var/lib/stateport/agent-provider", "/legacy"):
        assert any(f"'{source}'" in command for command in stat_targets)
    ownership = [entry for entry in entries if "mountSourceOwnership" in entry]
    assert len(ownership) == 1 and len(ownership[0]["mountSourceOwnership"]) == 5
    # Under the safety valves nothing is reported as omitted.
    assert not [entry for entry in entries if "omitted" in entry]


def test_collect_container_diagnostics_reports_caps_explicitly(monkeypatch) -> None:
    monkeypatch.setattr(stage, "_MAX_CONTAINERS", 2)
    monkeypatch.setattr(stage, "_MAX_MOUNT_SOURCES", 1)
    rows = [f"{index:064x} stateport-c{index} image:tag Up" for index in range(1, 4)]
    mounts = {
        f"{1:064x}": _mounts_json("/vol/a", "/vol/b"),
        f"{2:064x}": _mounts_json(),
        f"{3:064x}": _mounts_json(),
    }
    vm = _DiagnosticVM(rows, mounts)

    entries = stage._collect_container_diagnostics(vm)

    assert len([entry for entry in entries if "id" in entry]) == 2
    omitted = [entry["omitted"] for entry in entries if "omitted" in entry]
    assert omitted == [{"containers": 1, "mountSources": 1}]


def test_readiness_projection_keeps_reason_and_detail_but_bounds_text() -> None:
    projection = stage.readiness_projection(
        {
            "available": False,
            "refusals": [
                {"reason": "agent_workspace_authority_invalid", "detail": "x" * 900},
                {"reason": 5, "detail": "ignored"},
            ],
        }
    )
    assert projection["available"] is False
    refusal = projection["refusals"][0]
    assert refusal["reason"] == "agent_workspace_authority_invalid"
    assert len(refusal["detail"]) == 300


def test_j4_without_the_flag_never_invokes_the_agent_result_stage(
    tmp_path, monkeypatch
) -> None:
    import run_journey_j4 as j4

    def unexpected(*_args, **_kwargs):
        raise AssertionError("agent result stage must not run without --agent-result-stage")

    monkeypatch.setattr(stage, "execute_agent_result_stage", unexpected)
    monkeypatch.setattr(j4, "validate_retained_candidate_inputs",
                        lambda *_a, **_k: (_facts(), _owner_evidence()))
    monkeypatch.setattr(j4, "boot_retained_vm",
                        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("boot refused")))
    receipt_out = tmp_path / "j4.json"
    monkeypatch.setattr(sys, "argv", [
        "run_journey_j4.py", "--receipt-out", str(receipt_out),
        "--vm-dir", str(tmp_path / "vm"), "--candidate-dir", str(tmp_path / "candidate"),
        "--site-root", str(tmp_path / "site"), "--archive-root", str(tmp_path / "archives"),
    ])
    assert j4.main() == 1
    receipt = json.loads(receipt_out.read_text(encoding="utf-8"))
    assert receipt["result"] == "failed"
    assert "driver-error" in [entry["name"] for entry in receipt["steps"]]
