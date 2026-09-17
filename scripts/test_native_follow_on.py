#!/usr/bin/env python3
"""Unit/render tests for the native installed-product follow-on journey driver."""

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
import run_native_follow_on as follow_on  # noqa: E402

WEB = "sha256:" + "a" * 64
API = "sha256:" + "b" * 64
WORKER = "sha256:" + "c" * 64
PLAYWRIGHT = "sha256:" + "d" * 64
INSTALLER = "sha256:" + "e" * 64
PACKAGE_BUNDLE = "sha256:" + "f" * 64
IMAGES = {
    "stateport-web": WEB,
    "stateport-api": API,
    "stateport-worker": WORKER,
    "stateport-playwright": PLAYWRIGHT,
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
DISTRO = "StatePort-Rehearsal-follow-on-fixture"
VERSION = "0.1.0-fixture.1"
MACHINE_ID = "a" * 32
WINDOWS_IDENTITY = "Microsoft Windows 11|10.0|26200"
UNINSTALL_PATH = (
    "/home/rehearsal/.local/state/stateport-install/receipts/"
    "uninstall_receipt_" + "0" * 32 + ".json"
)
INSTALL_PATH = (
    "/home/rehearsal/.local/state/stateport-install/receipts/"
    "install_receipt_" + "1" * 32 + ".json"
)
MIRROR_PHASES = (
    "bootstrap-fetch",
    "transport-probe",
    "materialization-preflight",
    "install",
    "post-bootstrap-runtime-smoke",
    "install-rerun",
    "guest-runtime-smoke",
    "prepublication-mirror-boundary",
)
OWNER_PHASES = tuple(
    name for name in MIRROR_PHASES if name != "prepublication-mirror-boundary"
) + ("public-transport-boundary",)


def _digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _signature_digest(signed: dict) -> str:
    canonical = json.dumps(
        signed, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _signed_index(*, package_bundle: bool = True) -> dict:
    signed = {
        "release": {
            "releaseId": "stateport-alpha-0.1.0-fixture.1",
            "version": VERSION,
            "channel": "alpha",
        },
        "targets": [{"targetId": "wsl2-ubuntu2404-linux-amd64", "services": []}],
        "source": {"commit": "0" * 40, "tree": "1" * 40},
        "artifacts": {"installer": {"digest": INSTALLER}},
        "images": [
            {"imageId": image_id, "digest": digest,
             "reference": f"registry.invalid/stateport-alpha/{image_id}@{digest}"}
            for image_id, digest in sorted(IMAGES.items())
        ],
    }
    if package_bundle:
        signed["artifacts"]["podmanPackageBundle"] = {"digest": PACKAGE_BUNDLE}
    return {"signed": signed, "signatures": [{"subjectDigest": _signature_digest(signed)}]}


def _staged_inputs(
    tmp_path: Path,
    *,
    package_bundle: bool = True,
    transport: str = "prepublication-mirror",
    result: str = "passed",
    version: str = VERSION,
    binding_overrides: dict | None = None,
    phases: tuple | None = None,
    phases_failed: tuple = (),
    extra_phases: tuple = (),
    baseline_overrides: dict | None = None,
) -> tuple[Path, Path, dict]:
    """Real staged site + J1 receipt bytes; returns (site_root, j1_receipt, facts)."""
    site = tmp_path / "site"
    (site / "download" / version).mkdir(parents=True, exist_ok=True)
    bootstrap = site / "download" / "install.sh"
    bootstrap.write_bytes(f"#!/bin/sh\necho stateport {VERSION}\n".encode("utf-8"))
    index_path = site / "download" / version / "release-index.json"
    index_path.write_text(json.dumps(_signed_index(package_bundle=package_bundle), indent=1),
                          encoding="utf-8")
    facts = journey_common.load_release_facts_from_index(index_path)
    binding: dict = {
        "releaseIndexDigest": facts["releaseIndexSha256"],
        "signedPayloadDigest": facts["signedPayloadDigest"],
        "images": facts["images"],
        "bootstrapDigest": _digest(bootstrap.read_text(encoding="utf-8")),
        "bootstrapUrl": follow_on.PRODUCTION_BOOTSTRAP_URL,
    }
    if package_bundle:
        binding["podmanPackageBundleDigest"] = facts["podmanPackageBundleDigest"]
    binding.update(binding_overrides or {})
    baseline: dict = {
        "schema": "stateport.rehearsal-baseline/v1",
        "substrate": "native-wsl2",
        "rootfsIdentity": journey_common.WSL_ROOTFS_IDENTITY,
        "distroName": DISTRO,
        "machineId": MACHINE_ID,
        "windowsIdentity": WINDOWS_IDENTITY,
    }
    receipt: dict = {
        "result": result,
        "version": version,
        "binding": binding,
        "rehearsalBaseline": baseline,
    }
    if transport == "prepublication-mirror":
        classes = {
            "evidenceClass": "candidate_mirror",
            "transportClass": "prepublication-mirror",
            "identityClass": "candidate-mirror",
            "ownerPathQualification": False,
            "publicTransportBoundary": False,
        }
        receipt.update(classes)
        baseline.update(classes)
    else:
        receipt["evidenceClass"] = "owner_path_qualification"
        baseline["evidenceClass"] = "owner_path_qualification"
    baseline.update(baseline_overrides or {})
    names = phases if phases is not None else (
        MIRROR_PHASES if transport == "prepublication-mirror" else OWNER_PHASES
    )
    receipt["phases"] = {
        name: {"ok": name not in phases_failed} for name in (*names, *extra_phases)
    }
    j1_receipt = tmp_path / "receipt.json"
    j1_receipt.write_text(json.dumps(receipt, indent=1), encoding="utf-8")
    return site, j1_receipt, facts


def _uninstall_doc(facts: dict) -> dict:
    return {
        "schema": "stateport.uninstall-receipt/v1",
        "receiptId": "uninstall_receipt_" + "0" * 32,
        "action": "uninstall",
        "result": "succeeded",
        "installation": {
            "releaseId": facts["releaseId"],
            "releaseIndexDigest": facts["releaseIndexSha256"],
            "signedPayloadDigest": facts["signedPayloadDigest"],
            "installedIdentityId": "identity-fixture",
            "stateRoot": "/home/rehearsal/.local/state/stateport-install",
            "liveQuadletRoot": "/var/lib/stateport-control/.config/containers/systemd",
        },
        "preserved": {"volumes": ["stateport-studystate-data"], "paths": ["/home/rehearsal"]},
        "removed": {"volumes": ["stateport-control-network"]},
    }


def _install_doc(facts: dict) -> dict:
    return {
        "schema": "stateport.install-receipt/v1",
        "receiptId": "install_receipt_" + "1" * 32,
        "operation": "install",
        "result": "succeeded",
        "release": {
            "releaseId": facts["releaseId"],
            "version": facts["version"],
            "channel": facts["channel"],
            "signedPayloadDigest": facts["signedPayloadDigest"],
            "sourceCommit": facts["sourceCommit"],
            "sourceTree": facts["sourceTree"],
        },
        "releaseIndexDigest": facts["releaseIndexSha256"],
        "installPlanDigest": "sha256:" + "9" * 64,
    }


def _cp(returncode: int, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


class FakeLifecycleVM:
    """Scripted native guest implementing exactly the seams the lifecycle uses."""

    native_wsl = True
    distro_name = DISTRO

    def __init__(self, facts: dict, *, uninstall_rc: int = 0, reinstall_rc: int = 0,
                 units: str = "0\n", state_kept: bool = True,
                 uninstall_doc: dict | None = None, install_doc: dict | None = None,
                 uninstall_writes_receipt: bool = True,
                 reinstall_writes_receipt: bool = True,
                 bootstrap_digest: str = "", installer_digest: str | None = None) -> None:
        self.facts = facts
        self.uninstall_rc = uninstall_rc
        self.reinstall_rc = reinstall_rc
        self.units = units
        self.state_kept = state_kept
        self.uninstall_doc = uninstall_doc if uninstall_doc is not None else _uninstall_doc(facts)
        self.install_doc = install_doc if install_doc is not None else _install_doc(facts)
        self.uninstall_writes_receipt = uninstall_writes_receipt
        self.reinstall_writes_receipt = reinstall_writes_receipt
        self.bootstrap_digest = bootstrap_digest
        self.installer_digest = installer_digest or str(facts["installerDigest"])
        self.fetches: list[tuple[str, str, str]] = []
        self.ssh_calls: list[str] = []
        self.install_calls: list[tuple[str, list[str], int]] = []
        self.uninstall_receipts: list[str] = []
        self.install_receipts: list[str] = []
        self.teardown_calls = 0

    def fetch_public_artifact(self, url: str, destination: str, expected_digest: str) -> None:
        self.fetches.append((url, destination, expected_digest))

    def ssh(self, command, check=True, timeout=None, **kwargs):
        self.ssh_calls.append(command)
        if command.startswith("sha256sum /tmp/stateport-bootstrap"):
            return _cp(0, self.bootstrap_digest.removeprefix("sha256:")
                       + "  /tmp/stateport-bootstrap\n")
        if command.startswith("sha256sum /tmp/stateport-installer"):
            return _cp(0, self.installer_digest.removeprefix("sha256:")
                       + "  /tmp/stateport-installer\n")
        if "receipts/uninstall_receipt_*.json" in command:
            return _cp(0, "".join(path + "\n" for path in self.uninstall_receipts))
        if "receipts/install_receipt_*.json" in command:
            return _cp(0, "".join(path + "\n" for path in self.install_receipts))
        if "--uninstall" in command:
            if self.uninstall_writes_receipt:
                self.uninstall_receipts.insert(0, UNINSTALL_PATH)
            return _cp(self.uninstall_rc, "", "")
        if command.startswith("sudo cat "):
            target = command.removeprefix("sudo cat ").strip("'")
            document = self.uninstall_doc if "uninstall_receipt" in target else self.install_doc
            return _cp(0, json.dumps(document), "")
        if command.startswith("sudo sha256sum "):
            target = command.removeprefix("sudo sha256sum ").strip("'")
            document = self.uninstall_doc if "uninstall_receipt" in target else self.install_doc
            payload = json.dumps(document).encode("utf-8")
            return _cp(0, hashlib.sha256(payload).hexdigest() + "  " + target + "\n")
        if "systemd/*.container" in command:
            return _cp(0, self.units, "")
        if command.startswith("test -d "):
            return _cp(0 if self.state_kept else 1, "", "")
        raise AssertionError(f"unexpected ssh command: {command[:200]}")

    def ssh_install(self, command, *, confirmations, timeout):
        self.install_calls.append((command, list(confirmations), timeout))
        if self.reinstall_writes_receipt:
            self.install_receipts.insert(0, INSTALL_PATH)
        return _cp(self.reinstall_rc, "", "")

    def teardown(self):
        self.teardown_calls += 1


def _patch_health(monkeypatch, *, mismatches: dict | None = None) -> None:
    monkeypatch.setattr(follow_on, "discover_services", lambda _vm: SERVICES)
    monkeypatch.setattr(follow_on, "wait_service_healthy", lambda *args, **kwargs: None)
    containers = {
        service_id: {"containerId": char * 64, "imageDigest": IMAGES[service_id], "name": service_id}
        for service_id, char in zip(CONTROL_IDS, ("1", "2", "3"))
    }
    monkeypatch.setattr(
        follow_on,
        "verify_installed_image_digests",
        lambda _vm, expected: {
            "observed": {service_id: expected[service_id] for service_id in CONTROL_IDS},
            "declared": {service_id: expected[service_id] for service_id in CONTROL_IDS},
            "containers": containers,
            "declaredMismatches": {},
            "mismatches": mismatches or {},
        },
    )


def _fake_vm(facts: dict, evidence: dict, **kwargs) -> FakeLifecycleVM:
    return FakeLifecycleVM(
        facts, bootstrap_digest=str(evidence["bootstrapDigest"]), **kwargs
    )


def _run_lifecycle(vm, tmp_path, facts, evidence, *, prepublication_mirror=True) -> dict:
    return follow_on.execute_lifecycle_stage(
        vm,
        facts=facts,
        evidence=evidence,
        prepublication_mirror=prepublication_mirror,
        receipt_out=tmp_path / "lifecycle-receipt.json",
        install_timeout_s=60,
        uninstall_timeout_s=30,
    )


def _receipt(tmp_path, name: str = "lifecycle-receipt.json") -> dict:
    return json.loads((tmp_path / name).read_text(encoding="utf-8"))


def _steps(receipt: dict) -> dict:
    return {entry["name"]: entry for entry in receipt["steps"]}


# ---------------------------------------------------------------- staged inputs


def test_load_staged_candidate_inputs_mirror_lane(tmp_path) -> None:
    site, j1, _ = _staged_inputs(tmp_path)
    facts, evidence = follow_on.load_staged_candidate_inputs(
        j1, site, native_distro_name=DISTRO, prepublication_mirror=True
    )
    assert facts["version"] == VERSION
    assert facts["releaseId"] == "stateport-alpha-0.1.0-fixture.1"
    assert evidence["evidenceClass"] == "candidate_mirror"
    assert evidence["transportClass"] == "prepublication-mirror"
    assert evidence["identityClass"] == "candidate-mirror"
    assert evidence["ownerPathQualification"] is False
    assert evidence["publicTransportBoundary"] is False
    assert evidence["admissibleForQualification"] is False
    assert evidence["lane"] == "native-prepublication-candidate"
    assert evidence["nativeIdentity"] == {
        "machineId": MACHINE_ID,
        "windowsIdentity": WINDOWS_IDENTITY,
    }
    assert evidence["rehearsalBaseline"]["distroName"] == DISTRO
    assert evidence["bootstrapDigest"] == _digest(
        (site / "download" / "install.sh").read_text(encoding="utf-8")
    )
    assert evidence["installerDigest"] == INSTALLER
    assert evidence["bootstrapUrl"] == follow_on.PRODUCTION_BOOTSTRAP_URL
    assert evidence["fullJ1Receipt"] == str(j1)
    assert evidence["fullJ1ReceiptSha256"] == _digest(j1.read_text(encoding="utf-8"))


def test_load_staged_candidate_inputs_owner_path_lane(tmp_path) -> None:
    site, j1, _ = _staged_inputs(tmp_path, transport="owner-path")
    _, evidence = follow_on.load_staged_candidate_inputs(
        j1, site, native_distro_name=DISTRO, prepublication_mirror=False
    )
    assert "evidenceClass" not in evidence
    assert "lane" not in evidence
    assert "ownerPathQualification" not in evidence


def test_load_staged_candidate_inputs_refuses_no_candidate_dir_requirement(tmp_path) -> None:
    """A staged site without a candidate/qualification dir is enough (no fabrication)."""
    site, j1, _ = _staged_inputs(tmp_path)
    assert not (site / "qualification-receipt.json").exists()
    assert not (site / "artifacts").exists()
    follow_on.load_staged_candidate_inputs(
        j1, site, native_distro_name=DISTRO, prepublication_mirror=True
    )


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"result": "failed"}, "not a pass for this candidate version"),
        ({"version": "0.1.0-other.1"}, "not a pass for this candidate version"),
        ({"binding_overrides": {"releaseIndexDigest": "sha256:" + "9" * 64}},
         "identity does not match the candidate"),
        ({"binding_overrides": {"signedPayloadDigest": "sha256:" + "9" * 64}},
         "identity does not match the candidate"),
        ({"binding_overrides": {"images": {"stateport-web": "sha256:" + "9" * 64}}},
         "identity does not match the candidate"),
        ({"phases_failed": ("install",)}, "does not contain every passing phase"),
        ({"extra_phases": ("unexpected",)}, "does not contain every passing phase"),
        ({"transport": "owner-path"}, "not a candidate-mirror prepublication receipt"),
        ({"baseline_overrides": {"distroName": "StatePort-Rehearsal-other"}},
         "not a candidate-mirror prepublication receipt"),
        ({"baseline_overrides": {"machineId": "xyz"}}, "incomplete identity binding"),
        ({"baseline_overrides": {"windowsIdentity": "  "}}, "incomplete identity binding"),
    ],
)
def test_load_staged_candidate_inputs_refusals(tmp_path, kwargs, message) -> None:
    site, j1, _ = _staged_inputs(tmp_path, **kwargs)
    with pytest.raises(ValueError, match=message):
        follow_on.load_staged_candidate_inputs(
            j1, site, native_distro_name=DISTRO, prepublication_mirror=True
        )


def test_load_staged_candidate_inputs_refuses_mixed_public_boundary(tmp_path) -> None:
    site, j1, _ = _staged_inputs(
        tmp_path, extra_phases=("public-transport-boundary",)
    )
    with pytest.raises(ValueError, match="mixed evidence is refused"):
        follow_on.load_staged_candidate_inputs(
            j1, site, native_distro_name=DISTRO, prepublication_mirror=True
        )


def test_load_staged_candidate_inputs_refuses_bootstrap_digest_drift(tmp_path) -> None:
    site, j1, _ = _staged_inputs(tmp_path)
    (site / "download" / "install.sh").write_bytes(b"#!/bin/sh\necho tampered\n")
    with pytest.raises(ValueError, match="staged bootstrap bytes do not match"):
        follow_on.load_staged_candidate_inputs(
            j1, site, native_distro_name=DISTRO, prepublication_mirror=True
        )


def test_load_staged_candidate_inputs_refuses_absent_staged_index(tmp_path) -> None:
    site, j1, _ = _staged_inputs(tmp_path)
    (site / "download" / VERSION / "release-index.json").unlink()
    with pytest.raises(ValueError, match="staged release index is unavailable"):
        follow_on.load_staged_candidate_inputs(
            j1, site, native_distro_name=DISTRO, prepublication_mirror=True
        )


# ---------------------------------------------------------------- lifecycle stage


def test_lifecycle_stage_positive_candidate_mirror(tmp_path, monkeypatch) -> None:
    site, j1, facts = _staged_inputs(tmp_path)
    _, evidence = follow_on.load_staged_candidate_inputs(
        j1, site, native_distro_name=DISTRO, prepublication_mirror=True
    )
    _patch_health(monkeypatch)
    vm = _fake_vm(facts, evidence)

    summary = _run_lifecycle(vm, tmp_path, facts, evidence)

    receipt = _receipt(tmp_path)
    assert receipt["result"] == "passed"
    assert receipt["journeyId"] == "native-follow-on-lifecycle"
    assert receipt["mode"] == "prepublication-mirror"
    assert receipt["evidenceClass"] == "candidate_mirror"
    assert summary["releaseId"] == facts["releaseId"]
    assert summary["uninstallReceiptPath"] == UNINSTALL_PATH
    assert summary["installReceiptPath"] == INSTALL_PATH
    steps = _steps(receipt)
    assert steps["candidate-lifecycle-artifacts-staged"]["ok"] is True
    assert steps["uninstall-retaining-state"]["ok"] is True
    assert steps["reinstall-identical-release"]["ok"] is True
    assert steps["reinstalled-health"]["ok"] is True
    assert steps["uninstall-retaining-state"]["unitsLeft"] == 0
    assert steps["uninstall-retaining-state"]["stateRootPreserved"] is True
    # Anonymous HTTPS transport only: no local path and no scp.
    assert vm.fetches == [
        (follow_on.PRODUCTION_BOOTSTRAP_URL, "/tmp/stateport-bootstrap",
         evidence["bootstrapDigest"]),
        (f"https://lennertvhoy.github.io/StatePort-Site/download/{VERSION}/stateport-installer",
         "/tmp/stateport-installer", INSTALLER),
    ]
    assert vm.install_calls == [
        (f"{follow_on.LIFECYCLE_ENV} sh /tmp/stateport-bootstrap",
         follow_on.PACKAGE_CONFIRMATIONS, 60)
    ]


def test_lifecycle_stage_legacy_release_uses_single_confirmation(tmp_path, monkeypatch) -> None:
    site, j1, facts = _staged_inputs(tmp_path, package_bundle=False)
    assert "podmanPackageBundleDigest" not in facts
    _, evidence = follow_on.load_staged_candidate_inputs(
        j1, site, native_distro_name=DISTRO, prepublication_mirror=True
    )
    _patch_health(monkeypatch)
    vm = _fake_vm(facts, evidence)

    _run_lifecycle(vm, tmp_path, facts, evidence)

    assert vm.install_calls[0][1] == follow_on.LEGACY_CONFIRMATIONS


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"uninstall_rc": 1, "uninstall_writes_receipt": False}, "retain-uninstall did not converge"),
        ({"uninstall_writes_receipt": False}, "retain-uninstall did not converge"),
        ({"units": "2\n"}, "retain-uninstall did not converge"),
        ({"state_kept": False}, "retain-uninstall did not converge"),
    ],
)
def test_lifecycle_stage_refuses_unconverged_uninstall(tmp_path, monkeypatch, kwargs, message) -> None:
    site, j1, facts = _staged_inputs(tmp_path)
    _, evidence = follow_on.load_staged_candidate_inputs(
        j1, site, native_distro_name=DISTRO, prepublication_mirror=True
    )
    _patch_health(monkeypatch)
    vm = _fake_vm(facts, evidence, **kwargs)

    with pytest.raises(AssertionError, match=message):
        _run_lifecycle(vm, tmp_path, facts, evidence)

    receipt = _receipt(tmp_path)
    assert receipt["result"] == "failed"
    assert _steps(receipt)["uninstall-retaining-state"]["ok"] is False
    assert vm.install_calls == []


def test_lifecycle_stage_refuses_uninstall_receipt_identity_mismatch(tmp_path, monkeypatch) -> None:
    site, j1, facts = _staged_inputs(tmp_path)
    _, evidence = follow_on.load_staged_candidate_inputs(
        j1, site, native_distro_name=DISTRO, prepublication_mirror=True
    )
    _patch_health(monkeypatch)
    wrong = _uninstall_doc(facts)
    wrong["installation"]["releaseIndexDigest"] = "sha256:" + "9" * 64
    vm = _fake_vm(facts, evidence, uninstall_doc=wrong)

    with pytest.raises(AssertionError, match="retain-uninstall did not converge"):
        _run_lifecycle(vm, tmp_path, facts, evidence)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"reinstall_rc": 1, "reinstall_writes_receipt": False},
         "identical reinstall did not converge"),
        ({"reinstall_writes_receipt": False},
         "identical reinstall did not converge"),
    ],
)
def test_lifecycle_stage_refuses_unconverged_reinstall(tmp_path, monkeypatch, kwargs, message) -> None:
    site, j1, facts = _staged_inputs(tmp_path)
    _, evidence = follow_on.load_staged_candidate_inputs(
        j1, site, native_distro_name=DISTRO, prepublication_mirror=True
    )
    _patch_health(monkeypatch)
    vm = _fake_vm(facts, evidence, **kwargs)

    with pytest.raises(AssertionError, match=message):
        _run_lifecycle(vm, tmp_path, facts, evidence)

    receipt = _receipt(tmp_path)
    assert receipt["result"] == "failed"
    assert _steps(receipt)["reinstall-identical-release"]["ok"] is False


def test_lifecycle_stage_refuses_reinstall_receipt_identity_mismatch(tmp_path, monkeypatch) -> None:
    site, j1, facts = _staged_inputs(tmp_path)
    _, evidence = follow_on.load_staged_candidate_inputs(
        j1, site, native_distro_name=DISTRO, prepublication_mirror=True
    )
    _patch_health(monkeypatch)
    wrong = _install_doc(facts)
    wrong["release"]["releaseId"] = "stateport-alpha-0.1.0-other.1"
    vm = _fake_vm(facts, evidence, install_doc=wrong)

    with pytest.raises(AssertionError, match="identical reinstall did not converge"):
        _run_lifecycle(vm, tmp_path, facts, evidence)


def test_lifecycle_stage_refuses_image_digest_mismatch(tmp_path, monkeypatch) -> None:
    site, j1, facts = _staged_inputs(tmp_path)
    _, evidence = follow_on.load_staged_candidate_inputs(
        j1, site, native_distro_name=DISTRO, prepublication_mirror=True
    )
    _patch_health(monkeypatch, mismatches={"stateport-web": {"expected": WEB, "observed": None,
                                                             "reason": "fixture"}})
    vm = _fake_vm(facts, evidence)

    with pytest.raises(AssertionError, match="signed image identity"):
        _run_lifecycle(vm, tmp_path, facts, evidence)

    assert _steps(_receipt(tmp_path))["reinstalled-health"]["ok"] is False


def test_lifecycle_stage_refuses_lane_mismatch_before_any_guest_call(tmp_path) -> None:
    site, j1, facts = _staged_inputs(tmp_path, transport="owner-path")
    _, evidence = follow_on.load_staged_candidate_inputs(
        j1, site, native_distro_name=DISTRO, prepublication_mirror=False
    )
    vm = _fake_vm(facts, evidence)

    with pytest.raises(ValueError, match="lane mismatch"):
        follow_on.execute_lifecycle_stage(
            vm,
            facts=facts,
            evidence=evidence,
            prepublication_mirror=True,
            receipt_out=tmp_path / "lifecycle-receipt.json",
        )

    assert vm.fetches == []
    assert vm.ssh_calls == []
    assert _receipt(tmp_path)["result"] == "failed"


def test_lifecycle_stage_refuses_simulation_vm(tmp_path) -> None:
    site, j1, facts = _staged_inputs(tmp_path)
    _, evidence = follow_on.load_staged_candidate_inputs(
        j1, site, native_distro_name=DISTRO, prepublication_mirror=True
    )

    class QemuVm:
        native_wsl = False

    with pytest.raises(AssertionError, match="native WSL2 lane"):
        follow_on.execute_lifecycle_stage(
            QemuVm(),
            facts=facts,
            evidence=evidence,
            prepublication_mirror=True,
            receipt_out=tmp_path / "lifecycle-receipt.json",
        )


# ---------------------------------------------------------------- follow-on journey


def _write_stub_receipt(path: Path, journey_id: str) -> dict:
    receipt = journey_common.JourneyReceipt(journey_id, {"stub": True})
    receipt.out_path = path
    receipt.document["result"] = "passed"
    receipt.write(path)
    return {"receiptPath": str(path), "mode": "prepublication-mirror",
            "evidenceClass": "candidate_mirror"}


def test_follow_on_journey_runs_stages_in_acceptance_order(tmp_path, monkeypatch) -> None:
    site, j1, facts = _staged_inputs(tmp_path)
    _, evidence = follow_on.load_staged_candidate_inputs(
        j1, site, native_distro_name=DISTRO, prepublication_mirror=True
    )
    order: list[str] = []

    def agent_stub(vm, *, receipt_out, **kwargs):
        order.append("agent")
        return _write_stub_receipt(receipt_out, "native-agent-result")

    def reboot_stub(vm, *, receipt_out, **kwargs):
        order.append("reboot")
        return _write_stub_receipt(receipt_out, "native-reboot-survival")

    def lifecycle_stub(vm, *, receipt_out, **kwargs):
        order.append("lifecycle")
        return _write_stub_receipt(receipt_out, "native-follow-on-lifecycle")

    monkeypatch.setattr(follow_on, "execute_agent_result_stage", agent_stub)
    monkeypatch.setattr(follow_on, "execute_reboot_stage", reboot_stub)
    monkeypatch.setattr(follow_on, "execute_lifecycle_stage", lifecycle_stub)

    vm = _fake_vm(facts, evidence)
    summary = follow_on.execute_follow_on(
        vm,
        facts=facts,
        evidence=evidence,
        prepublication_mirror=True,
        receipt_out=tmp_path / "follow-on.json",
        agent_result_receipt_out=tmp_path / "agent.json",
        reboot_receipt_out=tmp_path / "reboot.json",
        lifecycle_receipt_out=tmp_path / "lifecycle.json",
    )

    assert order == ["agent", "reboot", "lifecycle"]
    receipt = json.loads((tmp_path / "follow-on.json").read_text(encoding="utf-8"))
    assert receipt["result"] == "passed"
    assert receipt["journeyId"] == "native-follow-on-journey"
    assert receipt["mode"] == "prepublication-mirror"
    assert receipt["evidenceClass"] == "candidate_mirror"
    steps = _steps(receipt)
    assert steps["agent-result-stage"]["ok"] is True
    assert steps["reboot-survival-stage"]["ok"] is True
    assert steps["lifecycle-stage"]["ok"] is True
    for step in ("agent-result-stage", "reboot-survival-stage", "lifecycle-stage"):
        assert steps[step]["receiptSha256"].startswith("sha256:")
    assert summary["receiptPath"] == str(tmp_path / "follow-on.json")


def test_follow_on_journey_failure_skips_later_stages(tmp_path, monkeypatch) -> None:
    site, j1, facts = _staged_inputs(tmp_path)
    _, evidence = follow_on.load_staged_candidate_inputs(
        j1, site, native_distro_name=DISTRO, prepublication_mirror=True
    )
    called: list[str] = []

    def agent_fail(vm, *, receipt_out, **kwargs):
        called.append("agent")
        raise AssertionError("provider endpoint absent")

    def never(vm, *, receipt_out, **kwargs):
        called.append("other")
        return _write_stub_receipt(receipt_out, "unused")

    monkeypatch.setattr(follow_on, "execute_agent_result_stage", agent_fail)
    monkeypatch.setattr(follow_on, "execute_reboot_stage", never)
    monkeypatch.setattr(follow_on, "execute_lifecycle_stage", never)

    with pytest.raises(AssertionError, match="provider endpoint absent"):
        follow_on.execute_follow_on(
            _fake_vm(facts, evidence),
            facts=facts,
            evidence=evidence,
            prepublication_mirror=True,
            receipt_out=tmp_path / "follow-on.json",
            agent_result_receipt_out=tmp_path / "agent.json",
            reboot_receipt_out=tmp_path / "reboot.json",
            lifecycle_receipt_out=tmp_path / "lifecycle.json",
        )

    assert called == ["agent"]
    receipt = json.loads((tmp_path / "follow-on.json").read_text(encoding="utf-8"))
    assert receipt["result"] == "failed"
    assert _steps(receipt)["follow-on-failure"]["ok"] is False


def test_follow_on_journey_refuses_lane_mismatch(tmp_path) -> None:
    site, j1, facts = _staged_inputs(tmp_path, transport="owner-path")
    _, evidence = follow_on.load_staged_candidate_inputs(
        j1, site, native_distro_name=DISTRO, prepublication_mirror=False
    )
    vm = _fake_vm(facts, evidence)

    with pytest.raises(ValueError, match="lane mismatch"):
        follow_on.execute_follow_on(
            vm,
            facts=facts,
            evidence=evidence,
            prepublication_mirror=True,
            receipt_out=tmp_path / "follow-on.json",
            agent_result_receipt_out=tmp_path / "agent.json",
            reboot_receipt_out=tmp_path / "reboot.json",
            lifecycle_receipt_out=tmp_path / "lifecycle.json",
        )


# ---------------------------------------------------------------- main / CLI


def test_main_records_durable_preflight_failure(tmp_path, monkeypatch, capsys) -> None:
    site, j1, _ = _staged_inputs(tmp_path)
    (site / "download" / VERSION / "release-index.json").unlink()
    booted: list = []
    monkeypatch.setattr(follow_on, "boot_native_follow_on",
                        lambda *args, **kwargs: booted.append(args))
    argv = [
        "run_native_follow_on.py",
        "--native-wsl2", "--wsl-distro-name", DISTRO, "--prepublication-mirror",
        "--receipt-out", str(tmp_path / "follow-on.json"),
        "--j1-receipt", str(j1),
        "--site-root", str(site),
        "--vm-dir", str(tmp_path),
        "--agent-result-receipt-out", str(tmp_path / "agent.json"),
        "--reboot-receipt-out", str(tmp_path / "reboot.json"),
        "--lifecycle-receipt-out", str(tmp_path / "lifecycle.json"),
    ]
    monkeypatch.setattr(sys, "argv", argv)

    assert follow_on.main() == 1
    assert booted == []
    receipt = json.loads((tmp_path / "follow-on.json").read_text(encoding="utf-8"))
    assert receipt["result"] == "failed"
    assert _steps(receipt)["input-preflight"]["ok"] is False
    assert "staged release index is unavailable" in _steps(receipt)["input-preflight"]["error"]


def test_main_attaches_and_runs_follow_on(tmp_path, monkeypatch) -> None:
    site, j1, facts = _staged_inputs(tmp_path)
    calls: list = []

    class Vm:
        native_wsl = True
        distro_name = DISTRO

        def teardown(self):
            calls.append("teardown")

    def fake_boot(work_dir, *, site_root, distro_name, expected_identity, expected_baseline):
        calls.append(("boot", str(work_dir), str(site_root), distro_name,
                      expected_identity, expected_baseline["distroName"]))
        return Vm()

    def fake_follow_on(vm, **kwargs):
        calls.append(("execute", kwargs["receipt_out"].name))
        receipt = journey_common.JourneyReceipt("native-follow-on-journey", {"stub": True})
        receipt.out_path = kwargs["receipt_out"]
        receipt.document["result"] = "passed"
        receipt.write(kwargs["receipt_out"])
        return {"mode": "prepublication-mirror"}

    monkeypatch.setattr(follow_on, "boot_native_follow_on", fake_boot)
    monkeypatch.setattr(follow_on, "execute_follow_on", fake_follow_on)
    argv = [
        "run_native_follow_on.py",
        "--native-wsl2", "--wsl-distro-name", DISTRO, "--prepublication-mirror",
        "--receipt-out", str(tmp_path / "follow-on.json"),
        "--j1-receipt", str(j1),
        "--site-root", str(site),
        "--vm-dir", str(tmp_path),
        "--agent-result-receipt-out", str(tmp_path / "agent.json"),
        "--reboot-receipt-out", str(tmp_path / "reboot.json"),
        "--lifecycle-receipt-out", str(tmp_path / "lifecycle.json"),
    ]
    monkeypatch.setattr(sys, "argv", argv)

    assert follow_on.main() == 0
    assert calls[0] == ("boot", str(tmp_path), str(site), DISTRO,
                        {"machineId": MACHINE_ID, "windowsIdentity": WINDOWS_IDENTITY}, DISTRO)
    assert calls[-1] == "teardown"


def test_main_attach_failure_writes_durable_failure(tmp_path, monkeypatch) -> None:
    site, j1, _ = _staged_inputs(tmp_path)

    def fail_boot(*args, **kwargs):
        raise SystemExit("attached native WSL2 identity differs from retained J1")

    monkeypatch.setattr(follow_on, "boot_native_follow_on", fail_boot)
    argv = [
        "run_native_follow_on.py",
        "--native-wsl2", "--wsl-distro-name", DISTRO, "--prepublication-mirror",
        "--receipt-out", str(tmp_path / "follow-on.json"),
        "--j1-receipt", str(j1),
        "--site-root", str(site),
        "--vm-dir", str(tmp_path),
        "--agent-result-receipt-out", str(tmp_path / "agent.json"),
        "--reboot-receipt-out", str(tmp_path / "reboot.json"),
        "--lifecycle-receipt-out", str(tmp_path / "lifecycle.json"),
    ]
    monkeypatch.setattr(sys, "argv", argv)

    assert follow_on.main() == 1
    receipt = json.loads((tmp_path / "follow-on.json").read_text(encoding="utf-8"))
    assert receipt["result"] == "failed"
    assert "identity differs" in _steps(receipt)["input-preflight"]["error"]


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        ([], "pass --native-wsl2"),
        (["--native-wsl2"], "--wsl-distro-name"),
    ],
)
def test_cli_requires_the_native_lane(tmp_path, extra, message) -> None:
    required = [
        "--receipt-out", str(tmp_path / "follow-on.json"),
        "--j1-receipt", str(tmp_path / "receipt.json"),
        "--site-root", str(tmp_path),
        "--vm-dir", str(tmp_path),
        "--agent-result-receipt-out", str(tmp_path / "agent.json"),
        "--reboot-receipt-out", str(tmp_path / "reboot.json"),
        "--lifecycle-receipt-out", str(tmp_path / "lifecycle.json"),
    ]
    completed = subprocess.run(
        [sys.executable, str(Path(follow_on.__file__)), *extra, *required],
        capture_output=True, text=True,
    )
    assert completed.returncode == 2
    assert message in completed.stderr
    assert not (tmp_path / "follow-on.json").exists()


def test_cli_process_boundary_writes_failed_receipt_for_missing_inputs(tmp_path) -> None:
    completed = subprocess.run(
        [
            sys.executable, str(Path(follow_on.__file__)),
            "--native-wsl2", "--wsl-distro-name", DISTRO, "--prepublication-mirror",
            "--receipt-out", str(tmp_path / "follow-on.json"),
            "--j1-receipt", str(tmp_path / "missing-receipt.json"),
            "--site-root", str(tmp_path),
            "--vm-dir", str(tmp_path),
            "--agent-result-receipt-out", str(tmp_path / "agent.json"),
            "--reboot-receipt-out", str(tmp_path / "reboot.json"),
            "--lifecycle-receipt-out", str(tmp_path / "lifecycle.json"),
        ],
        capture_output=True, text=True,
    )
    assert completed.returncode == 1
    receipt = json.loads((tmp_path / "follow-on.json").read_text(encoding="utf-8"))
    assert receipt["result"] == "failed"
    assert "retained full-J1 receipt is unavailable" in _steps(receipt)["input-preflight"]["error"]


# ---------------------------------------------------------------- shared helper


def test_load_release_facts_from_index_omits_candidate_dir(tmp_path) -> None:
    index_path = tmp_path / "release-index.json"
    index_path.write_text(json.dumps(_signed_index()), encoding="utf-8")
    without = journey_common.load_release_facts_from_index(index_path)
    assert "candidateDir" not in without
    with_dir = journey_common.load_release_facts_from_index(index_path, candidate_dir=tmp_path)
    assert with_dir["candidateDir"] == str(tmp_path)


def test_validate_native_j1_receipt_returns_lane_evidence(tmp_path) -> None:
    _, j1, facts = _staged_inputs(tmp_path)
    native = journey_common.validate_native_j1_receipt(
        j1, facts, native_distro_name=DISTRO, prepublication_mirror=True
    )
    assert native["laneEvidence"]["evidenceClass"] == "candidate_mirror"
    assert native["laneEvidence"]["admissibleForQualification"] is False
    assert native["baseline"]["distroName"] == DISTRO
    assert native["binding"]["bootstrapDigest"].startswith("sha256:")
    assert native["fullJ1ReceiptSha256"].startswith("sha256:")
