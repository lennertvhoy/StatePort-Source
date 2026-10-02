#!/usr/bin/env python3
"""Unit/render tests for the native reboot-survival stage (plan items D and H)."""

from __future__ import annotations

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
import run_reboot_stage as stage  # noqa: E402

WEB = "sha256:" + "a" * 64
API = "sha256:" + "b" * 64
WORKER = "sha256:" + "c" * 64
EXPECTED_IMAGES = {
    "stateport-web": WEB,
    "stateport-api": API,
    "stateport-worker": WORKER,
    "stateport-playwright": "sha256:" + "d" * 64,
}
CONTROL_IDS = ("stateport-web", "stateport-api", "stateport-worker")
SERVICES = {
    service_id: {
        "unit": service_id + ".service",
        "port": str(8080 + index),
        "container": service_id,
    }
    for index, service_id in enumerate(CONTROL_IDS)
}
DISTRO = "StatePort-Rehearsal-reboot-fixture"


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
        "nativeIdentity": {"machineId": "a" * 32, "windowsIdentity": "Microsoft Windows 11|10.0|26200"},
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
        "nativeIdentity": {"machineId": "a" * 32, "windowsIdentity": "Microsoft Windows 11|10.0|26200"},
    }


def _facts() -> dict:
    return {"releaseId": "release-test-1", "version": "0.1.0-test.1", "images": EXPECTED_IMAGES}


def _observation(container_suffix: str, *, drift: dict | None = None, mismatch: bool = False) -> dict:
    observed = {service_id: EXPECTED_IMAGES[service_id] for service_id in CONTROL_IDS}
    if drift:
        observed.update(drift)
    containers = {
        service_id: {
            "containerId": char * 64,
            "imageDigest": observed[service_id],
            "name": service_id,
        }
        for service_id, char in zip(CONTROL_IDS, container_suffix)
    }
    mismatches = {}
    if mismatch:
        mismatches = {
            "stateport-api": {
                "expected": API,
                "observed": drift["stateport-api"] if drift else None,
                "reason": "live-inspection-failed-or-malformed",
            }
        }
    return {
        "observed": observed,
        "declared": observed,
        "containers": containers,
        "declaredMismatches": {},
        "mismatches": mismatches,
    }


class FakeNativeVM:
    """Scripted native guest: implements only the seams this stage uses."""

    native_wsl = True
    distro_name = DISTRO

    def __init__(self, *, mapping_present: bool = True, regenerate_hosts: bool = True,
                 seam_verify_ok: bool = True, unit_state: str = "active",
                 running_after_shutdown=()) -> None:
        self.commands: list = []
        self.wsl_commands: list = []
        self.prepared = 0
        self.booted = 0
        self.teardown_calls = 0
        self.mapping_present = mapping_present
        self.regenerate_hosts = regenerate_hosts
        self.seam_verify_ok = seam_verify_ok
        self.unit_state = unit_state
        self.running_after_shutdown = tuple(running_after_shutdown)
        # Set by boot_native_follow_on on the real attached NativeWSL object.
        self.expected_native_identity = {
            "machineId": "a" * 32,
            "windowsIdentity": "Microsoft Windows 11|10.0|26200",
        }
        self.rehearsal_baseline = {"schema": "stateport.rehearsal-baseline/v1",
                                   "distroName": DISTRO, "evidenceClass": "candidate_mirror"}

    def ssh(self, command, **kwargs):
        self.commands.append(command)
        if "systemctl --user is-active" in command:
            rows = "".join(f"{SERVICES[service_id]['unit']}\t{self.unit_state}\n"
                           for service_id in CONTROL_IDS)
            return subprocess.CompletedProcess([], 0, rows, "")
        if command.startswith("grep -Eq") and "printf 'MAPPED" in command:
            return subprocess.CompletedProcess([], 0,
                                               ("MAPPED" if self.mapping_present else "ABSENT") + "\n", "")
        if "tee -a /etc/hosts" in command:
            self.mapping_present = True
            return subprocess.CompletedProcess([], 0, "", "")
        if "PREPUBLICATION-REBOOT-SEAMS-OK" in command:
            if self.seam_verify_ok:
                return subprocess.CompletedProcess(
                    [], 0, "PUBLICATION-RESOLVED=10.0.2.2,\nPREPUBLICATION-REBOOT-SEAMS-OK\n", "")
            return subprocess.CompletedProcess(
                [], 1, "HOSTNAME-RESOLUTION-NOT-MIRRORED resolved=\n", "")
        raise AssertionError(f"unexpected ssh command: {command[:160]}")

    def _wsl(self, arguments, *, check=True, timeout=600):
        self.wsl_commands.append(list(arguments))
        if arguments == ["--shutdown"]:
            if self.regenerate_hosts:
                self.mapping_present = False
            return subprocess.CompletedProcess([], 0, "", "")
        if arguments == ["--list", "--running", "--quiet"]:
            names = "".join(f"{name}\n" for name in self.running_after_shutdown)
            return subprocess.CompletedProcess([], 0, names, "")
        raise AssertionError(f"unexpected wsl argv: {arguments}")

    def prepare(self, *, reuse=False):
        assert reuse is True
        self.prepared += 1

    def boot(self):
        self.booted += 1

    def teardown(self):
        self.teardown_calls += 1


def _patch_health(monkeypatch, observations: list) -> None:
    remaining = list(observations)

    def fake_digests(_vm, _expected):
        return dict(remaining.pop(0))

    monkeypatch.setattr(journey_common, "discover_services", lambda _vm: SERVICES)
    monkeypatch.setattr(journey_common, "wait_service_healthy", lambda *a, **k: None)
    monkeypatch.setattr(journey_common, "verify_installed_image_digests", fake_digests)


def _run(vm, tmp_path, evidence, *, prepublication_mirror: bool):
    return stage.execute_reboot_stage(
        vm, facts=_facts(), evidence=evidence,
        prepublication_mirror=prepublication_mirror,
        receipt_out=tmp_path / "reboot-receipt.json",
    )


def _receipt(tmp_path) -> dict:
    return json.loads((tmp_path / "reboot-receipt.json").read_text(encoding="utf-8"))


def test_reboot_stage_positive_candidate_mirror_receipt(tmp_path, monkeypatch) -> None:
    vm = FakeNativeVM()
    _patch_health(monkeypatch, [_observation("def"), _observation("123")])

    summary = _run(vm, tmp_path, _mirror_evidence(), prepublication_mirror=True)

    receipt = _receipt(tmp_path)
    assert receipt["result"] == "passed"
    assert receipt["formatVersion"] == "stateport.journey-receipt/v1"
    assert receipt["journeyId"] == "native-reboot-survival"
    assert receipt["mode"] == "prepublication-mirror"
    assert receipt["evidenceClass"] == "candidate_mirror"
    assert receipt["transportClass"] == "prepublication-mirror"
    assert receipt["identityClass"] == "candidate-mirror"
    assert receipt["ownerPathQualification"] is False
    assert receipt["publicTransportBoundary"] is False
    assert receipt["hostsMappingRequired"] is True
    assert receipt["limitations"].startswith("Control-plane unit/endpoint health")
    assert summary["mode"] == "prepublication-mirror"
    assert summary["imageDigestsStable"] is True
    assert summary["observedImageDigests"] == {
        service_id: EXPECTED_IMAGES[service_id] for service_id in CONTROL_IDS
    }
    steps = {entry["name"]: entry for entry in receipt["steps"]}
    assert steps["lane-class"]["ok"] is True
    assert steps["pre-shutdown-health"]["ok"] is True
    assert steps["guest-shutdown"]["argv"] == ["wsl.exe", "--shutdown"]
    assert steps["guest-shutdown"]["exitCode"] == 0
    assert steps["guest-shutdown"]["runningDistributions"] == []
    assert steps["guest-reattach"]["distroName"] == DISTRO
    assert steps["lane-seams-reattached"]["mappingPresentAfterBoot"] is False
    assert steps["lane-seams-reattached"]["resolved"] == "10.0.2.2,"
    assert steps["post-shutdown-health"]["ok"] is True
    assert steps["digest-stability"]["imageDigestsStable"] is True
    assert steps["digest-stability"]["containers"]["stateport-web"]["containerIdStable"] is False
    assert steps["digest-stability"]["containers"]["stateport-web"]["imageDigestStable"] is True
    # The stage performs exactly the reviewed shutdown/reattach cycle and the
    # mirror seam re-apply; it never tears down the caller's distribution.
    assert vm.wsl_commands == [["--shutdown"], ["--list", "--running", "--quiet"]]
    assert vm.prepared == 1 and vm.booted == 1 and vm.teardown_calls == 0
    assert any("tee -a /etc/hosts" in command for command in vm.commands)


def test_reboot_stage_positive_owner_path_receipt_has_no_mirror_seams(tmp_path, monkeypatch) -> None:
    vm = FakeNativeVM()
    _patch_health(monkeypatch, [_observation("def"), _observation("def")])

    _run(vm, tmp_path, _owner_evidence(), prepublication_mirror=False)

    receipt = _receipt(tmp_path)
    assert receipt["result"] == "passed"
    assert receipt["mode"] == "public-transport"
    assert receipt["evidenceClass"] == "owner_path_qualification"
    assert receipt["hostsMappingRequired"] is False
    assert "transportClass" not in receipt
    steps = {entry["name"]: entry for entry in receipt["steps"]}
    assert steps["lane-seams-reattached"] == {
        "name": "lane-seams-reattached", "ok": True, "required": False, "mode": "public-dns"}
    assert not any("etc/hosts" in command for command in vm.commands)


def test_reboot_stage_refuses_digest_drift_after_reboot(tmp_path, monkeypatch) -> None:
    vm = FakeNativeVM()
    drift = {"stateport-api": "sha256:" + "e" * 64}
    _patch_health(monkeypatch, [_observation("def"), _observation("123", drift=drift)])

    with pytest.raises(AssertionError, match="digests changed"):
        _run(vm, tmp_path, _owner_evidence(), prepublication_mirror=False)

    receipt = _receipt(tmp_path)
    assert receipt["result"] == "failed"
    assert receipt["mode"] == "public-transport"
    assert receipt["steps"][-1]["name"] == "reboot-stage-failure"
    assert receipt["steps"][-1]["ok"] is False
    assert "digests changed" in receipt["steps"][-1]["error"]
    assert "digest-stability" not in [entry["name"] for entry in receipt["steps"]]


def test_reboot_stage_refuses_post_reboot_image_identity_mismatch(tmp_path, monkeypatch) -> None:
    vm = FakeNativeVM()
    drift = {"stateport-api": "sha256:" + "e" * 64}
    _patch_health(monkeypatch, [_observation("def"), _observation("123", drift=drift, mismatch=True)])

    with pytest.raises(AssertionError, match="image identity mismatch"):
        _run(vm, tmp_path, _mirror_evidence(), prepublication_mirror=True)

    receipt = _receipt(tmp_path)
    assert receipt["result"] == "failed"
    assert "post-shutdown-health" not in [entry["name"] for entry in receipt["steps"]]


def test_reboot_stage_refuses_missing_hosts_mapping_after_reapply(tmp_path, monkeypatch) -> None:
    vm = FakeNativeVM(seam_verify_ok=False)
    _patch_health(monkeypatch, [_observation("def"), _observation("123")])

    with pytest.raises(AssertionError, match="mirror seams did not survive"):
        _run(vm, tmp_path, _mirror_evidence(), prepublication_mirror=True)

    receipt = _receipt(tmp_path)
    assert receipt["result"] == "failed"
    assert any("tee -a /etc/hosts" in command for command in vm.commands)
    assert "lane-seams-reattached" not in [entry["name"] for entry in receipt["steps"]]


def test_reboot_stage_refuses_hosts_mapping_absent_before_shutdown(tmp_path, monkeypatch) -> None:
    vm = FakeNativeVM(mapping_present=False, regenerate_hosts=False)
    _patch_health(monkeypatch, [_observation("def"), _observation("123")])

    with pytest.raises(AssertionError, match="absent before the shutdown"):
        _run(vm, tmp_path, _mirror_evidence(), prepublication_mirror=True)

    receipt = _receipt(tmp_path)
    assert receipt["result"] == "failed"
    assert vm.wsl_commands == []


def test_reboot_stage_refuses_a_shutdown_that_leaves_the_distro_running(tmp_path, monkeypatch) -> None:
    vm = FakeNativeVM(running_after_shutdown=(DISTRO,))
    _patch_health(monkeypatch, [_observation("def"), _observation("123")])

    with pytest.raises(AssertionError, match="still running"):
        _run(vm, tmp_path, _mirror_evidence(), prepublication_mirror=True)

    assert _receipt(tmp_path)["result"] == "failed"


def test_reboot_stage_refuses_reattach_without_retained_identity(tmp_path, monkeypatch) -> None:
    vm = FakeNativeVM()
    vm.expected_native_identity = None
    _patch_health(monkeypatch, [_observation("def"), _observation("123")])

    with pytest.raises(AssertionError, match="no retained J1 identity binding"):
        _run(vm, tmp_path, _owner_evidence(), prepublication_mirror=False)

    receipt = _receipt(tmp_path)
    assert receipt["result"] == "failed"
    assert "guest-reattach" not in [entry["name"] for entry in receipt["steps"]]


def test_reboot_stage_refuses_inactive_control_units(tmp_path, monkeypatch) -> None:
    vm = FakeNativeVM(unit_state="inactive")
    _patch_health(monkeypatch, [_observation("def"), _observation("123")])

    with pytest.raises(AssertionError, match="units are not active"):
        _run(vm, tmp_path, _owner_evidence(), prepublication_mirror=False)

    assert _receipt(tmp_path)["result"] == "failed"


def test_reboot_stage_refuses_qemu_or_simulation_substrate_before_guest_calls() -> None:
    qemu = _owner_evidence()
    qemu["rehearsalBaseline"]["substrate"] = "qemu-wsl-identity-simulation"
    with pytest.raises(ValueError, match="retained native WSL2 J1 baseline"):
        stage.enforce_reboot_lane(qemu, prepublication_mirror=False)
    with pytest.raises(ValueError, match="retained native J1 baseline"):
        stage.enforce_reboot_lane({}, prepublication_mirror=True)


@pytest.mark.parametrize("evidence_factory,flag", [
    (_owner_evidence, True),   # mirror flag against an owner-path receipt
    (_mirror_evidence, False),  # owner default against a candidate-mirror receipt
])
def test_reboot_stage_refuses_unmatched_lane_class(evidence_factory, flag) -> None:
    with pytest.raises(ValueError, match="lane mismatch"):
        stage.enforce_reboot_lane(evidence_factory(), prepublication_mirror=flag)


def test_reboot_stage_refuses_mixed_or_unbound_lane_markers() -> None:
    baseline = _mirror_evidence()["rehearsalBaseline"]
    simulation = {"rehearsalBaseline": {**baseline, "evidenceClass": "simulation_only"}}
    with pytest.raises(ValueError, match="lane mismatch"):
        stage.enforce_reboot_lane(simulation, prepublication_mirror=True)
    with pytest.raises(ValueError, match="lane mismatch"):
        stage.enforce_reboot_lane(simulation, prepublication_mirror=False)
    mixed = _mirror_evidence()
    mixed["ownerPathQualification"] = True
    with pytest.raises(ValueError, match="lane mismatch"):
        stage.enforce_reboot_lane(mixed, prepublication_mirror=True)
    unbound = _mirror_evidence()
    unbound["rehearsalBaseline"] = {**baseline, "transportClass": "anonymous-public"}
    with pytest.raises(ValueError, match="lane mismatch"):
        stage.enforce_reboot_lane(unbound, prepublication_mirror=True)


def test_reboot_stage_main_records_durable_preflight_failure(tmp_path, monkeypatch) -> None:
    def refuse(*_args, **_kwargs):
        raise ValueError("retained full-J1 receipt is not a candidate-mirror receipt")

    monkeypatch.setattr(stage, "validate_retained_candidate_inputs", refuse)
    receipt_out = tmp_path / "reboot.json"
    monkeypatch.setattr(sys, "argv", [
        "run_reboot_stage.py", "--receipt-out", str(receipt_out),
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
def test_reboot_stage_cli_requires_the_native_lane(tmp_path, monkeypatch, extra) -> None:
    monkeypatch.setattr(sys, "argv", [
        "run_reboot_stage.py", "--receipt-out", str(tmp_path / "reboot.json"),
        "--vm-dir", str(tmp_path / "vm"), "--candidate-dir", str(tmp_path / "candidate"),
        "--site-root", str(tmp_path / "site"), *extra,
    ])
    with pytest.raises(SystemExit) as refused:
        stage.main()
    assert refused.value.code == 2
    assert not (tmp_path / "reboot.json").exists()


def test_reboot_stage_main_attaches_and_executes_stage(tmp_path, monkeypatch) -> None:
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

    def fake_execute(guest, *, facts, evidence, prepublication_mirror, receipt_out):
        seen["stage"] = (guest, prepublication_mirror, Path(receipt_out))
        return {"mode": "prepublication-mirror"}

    monkeypatch.setattr(stage, "execute_reboot_stage", fake_execute)
    receipt_out = tmp_path / "reboot.json"
    monkeypatch.setattr(sys, "argv", [
        "run_reboot_stage.py", "--receipt-out", str(receipt_out),
        "--vm-dir", str(tmp_path / "vm"), "--candidate-dir", str(tmp_path / "candidate"),
        "--site-root", str(tmp_path / "site"), "--native-wsl2",
        "--wsl-distro-name", DISTRO, "--prepublication-mirror",
    ])
    assert stage.main() == 0
    assert seen["stage"] == (vm, True, receipt_out)
    assert seen["boot"]["distro_name"] == DISTRO
    assert seen["boot"]["expected_identity"] == evidence["nativeIdentity"]
    assert seen["boot"]["expected_baseline"] == evidence["rehearsalBaseline"]
    assert seen["teardown"] is True


def test_j4_reboot_stage_flags_require_the_native_lane(tmp_path, monkeypatch) -> None:
    import run_journey_j4 as j4

    base = [
        "run_journey_j4.py", "--receipt-out", str(tmp_path / "j4.json"),
        "--vm-dir", str(tmp_path / "vm"), "--candidate-dir", str(tmp_path / "candidate"),
        "--site-root", str(tmp_path / "site"),
    ]
    monkeypatch.setattr(sys, "argv", [*base, "--reboot-stage"])
    with pytest.raises(SystemExit) as refused:
        j4.main()
    assert refused.value.code == 2

    monkeypatch.setattr(sys, "argv", [
        *base, "--native-wsl2", "--wsl-distro-name", DISTRO, "--reboot-stage",
    ])
    with pytest.raises(SystemExit) as refused:
        j4.main()
    assert refused.value.code == 2


def test_j4_invokes_the_reboot_stage_before_any_lifecycle_mutation(tmp_path, monkeypatch) -> None:
    import run_journey_j4 as j4

    evidence = _owner_evidence()
    monkeypatch.setattr(j4, "validate_retained_candidate_inputs",
                        lambda *_a, **_k: (_facts(), evidence))

    class Vm:
        native_wsl = True

        def teardown(self):
            pass

    vm = Vm()
    monkeypatch.setattr(j4, "boot_native_follow_on", lambda *_a, **_k: vm)
    monkeypatch.setattr(j4, "discover_services", lambda _vm: SERVICES)
    monkeypatch.setattr(j4, "wait_all_healthy", lambda *_a, **_k: None)
    monkeypatch.setattr(j4, "verify_installed_image_digests",
                        lambda *_a, **_k: {"mismatches": {}, "observed": {}, "declared": {},
                                           "containers": {}})
    invoked: list = []

    def stop_after_stage(guest, *, facts, evidence, prepublication_mirror, receipt_out):
        invoked.append((guest, prepublication_mirror, Path(receipt_out)))
        raise RuntimeError("stage reached")

    monkeypatch.setattr(stage, "execute_reboot_stage", stop_after_stage)
    receipt_out = tmp_path / "j4.json"
    stage_out = tmp_path / "reboot.json"
    monkeypatch.setattr(sys, "argv", [
        "run_journey_j4.py", "--receipt-out", str(receipt_out),
        "--vm-dir", str(tmp_path / "vm"), "--candidate-dir", str(tmp_path / "candidate"),
        "--site-root", str(tmp_path / "site"), "--native-wsl2",
        "--wsl-distro-name", DISTRO, "--reboot-stage",
        "--reboot-stage-receipt-out", str(stage_out),
    ])

    assert j4.main() == 1
    assert invoked == [(vm, False, stage_out)]
    names = [entry["name"] for entry in json.loads(receipt_out.read_text(encoding="utf-8"))["steps"]]
    assert names.index("control-plane-bound-to-candidate") < names.index("driver-error")
    assert "uninstall-retaining-state" not in names


def test_j4_without_the_flag_never_invokes_the_reboot_stage(tmp_path, monkeypatch) -> None:
    import run_journey_j4 as j4

    def unexpected(*_args, **_kwargs):
        raise AssertionError("reboot stage must not run without --reboot-stage")

    monkeypatch.setattr(stage, "execute_reboot_stage", unexpected)
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
