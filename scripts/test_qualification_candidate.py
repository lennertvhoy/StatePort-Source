from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from infra.qualification import wsl2_rehearsal as rehearsal
from qualification import build_j1_candidate as candidate
import render_wsl2_install_bootstrap as bootstrap


def _stock_baseline_output() -> str:
    names = ("podman", "netavark", "aardvark-dns", "runc", "slirp4netns", "zstd")
    packages = "".join(f"PKG|{name}|absent|-|-\n" for name in names)
    return (packages + "APT|" + "1" * 64 + "\nUSRLOCAL|" + "2" * 64
            + "\nSYSTEMD|" + "3" * 64 + "\nPODMAN|absent\nZSTD|absent\nQUADLET|absent\n")


def test_qualification_import_resolves_the_candidate_builder() -> None:
    assert Path(candidate.__file__).resolve() == ROOT / "scripts/qualification/build_j1_candidate.py"


def test_template_supply_chain_and_arbitrary_updater_are_inadmissible(tmp_path: Path) -> None:
    with pytest.raises(candidate.QualificationError, match="template index"):
        candidate.validate_lane_inputs(
            candidate_provenance=tmp_path / "provenance.yaml",
            candidate_bundle=tmp_path / "bundle",
            evidence_dir=tmp_path / "evidence",
            template_index=tmp_path / "template.json",
        )

    with pytest.raises(candidate.QualificationError, match="updater"):
        candidate.validate_lane_inputs(
            candidate_provenance=tmp_path / "provenance.yaml",
            candidate_bundle=tmp_path / "bundle",
            evidence_dir=tmp_path / "evidence",
            updater=tmp_path / "arbitrary.whl",
        )


def test_nonexistent_public_snapshot_identity_is_refused() -> None:
    with pytest.raises(candidate.QualificationError, match="local qualification authority"):
        candidate.validate_local_snapshot_identity(
            {
                "authorityUrl": "https://github.com/lennertvhoy/StatePort-Source.git",
                "commit": "9" * 40,
                "tree": "a" * 40,
                "ref": "refs/heads/qualification-900002",
            }
        )


def test_updater_bytes_must_match_candidate_provenance(tmp_path: Path) -> None:
    updater = tmp_path / "updater.whl"
    updater.write_bytes(b"wheel-bytes")
    record = {"sha256": hashlib.sha256(b"different-wheel").hexdigest(), "bytes": 15}
    with pytest.raises(candidate.QualificationError, match="updater wheel"):
        candidate.validate_updater_binding(record, updater)


def test_grype_database_receipt_preserves_detailed_observation_and_latest_proof(
    tmp_path: Path,
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    path = evidence / "stateport-web.grype-db.json"
    path.write_text(
        json.dumps(
            {
                "databaseObservedAt": "2026-08-21T08:30:00Z",
                "freshnessClass": "latest-available-grace",
                "latestDatabaseCheck": {
                    "exitCode": 0,
                    "meaning": "up-to-date-no-newer-database",
                    "observedAt": "2026-08-21T08:29:00Z",
                },
            }
        ),
        encoding="utf-8",
    )
    result = candidate.grype_database_receipt_evidence(evidence, ["stateport-web"])
    assert result["stateport-web"]["databaseObservedAt"] == "2026-08-21T08:30:00Z"
    assert result["stateport-web"]["latestDatabaseCheck"]["exitCode"] == 0
    assert result["stateport-web"]["sha256"] == candidate._digest(path)


def test_production_key_identity_is_refused() -> None:
    with pytest.raises(candidate.QualificationError, match="qualification key"):
        candidate.validate_qualification_key_id("stateport-alpha-2026-08")


def test_qualification_provisioner_uses_candidate_trust_root(tmp_path: Path) -> None:
    provisioner = tmp_path / "provisioner"
    provisioner.write_bytes(
        b"sha256:798d6ea6e2703993758f0fb45618b1f05b40f6ef116e7d286fd5a6867859b8ad "
        b"stateport-alpha-private-2026-08 "
        b"sha256:df24c1ccdcf1ecf72da6d8d81ae8b0ffaca8d399826091b107cc4d6905915ea5"
    )
    public_key = tmp_path / "qualification.pub"
    public_key.write_bytes(b"qualification-key")
    candidate.specialize_qualification_provisioner(
        provisioner,
        trust_public_key=public_key,
        trust_key_id="stateport-qualification-900001",
        trust_key_fingerprint="sha256:" + "4" * 64,
    )
    result = provisioner.read_bytes()
    assert candidate._digest(public_key).encode("ascii") in result
    assert b"stateport-qualification-900001" in result
    assert b"sha256:" + b"4" * 64 in result


def test_qualification_wheel_rebinds_only_trust_root(tmp_path: Path) -> None:
    wheel = tmp_path / "updater.whl"
    production_contract = b"f\"{volume['mountPath']}:rw,U\""
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "stateport_release/execution_host_provisioning.py",
            b"stateport-alpha-private-2026-08 "
            b"sha256:df24c1ccdcf1ecf72da6d8d81ae8b0ffaca8d399826091b107cc4d6905915ea5",
        )
        archive.writestr("stateport_release/contract.py", production_contract)

    candidate.specialize_qualification_wheel(
        wheel,
        trust_key_id="stateport-qualification-900001",
        trust_key_fingerprint="sha256:" + "4" * 64,
    )

    with zipfile.ZipFile(wheel) as archive:
        provisioning = archive.read("stateport_release/execution_host_provisioning.py")
        assert b"stateport-qualification-900001" in provisioning
        assert b"sha256:" + b"4" * 64 in provisioning
        assert archive.read("stateport_release/contract.py") == production_contract


def test_preserved_receipt_version_is_the_only_approved_j1_identity() -> None:
    assert candidate.qualification_version({"identity": {"version": "0.0.0-j1.0"}}) == "0.0.0-j1.0"
    with pytest.raises(candidate.QualificationError, match="approved J1 qualification identity"):
        candidate.qualification_version({"identity": {"version": "0.1.0-alpha.900001"}})


def test_qualification_bootstrap_admission_is_explicitly_local_only() -> None:
    signed = {
        "release": {
            "releaseId": "stateport-j1-integrated-qualification-900001",
            "qualification": "candidate",
        },
        "publication": {"publishedAt": None},
        "source": {
            "candidateProvenance": {
                "document": {"classification": "local_qualification_candidate"}
            }
        },
    }
    document = {"signed": signed}
    root_url = "https://127.0.0.1:5443/StatePort-Site/download/0.0.0-j1.0"
    assert bootstrap._release_label(
        document,
        version="0.0.0-j1.0",
        trust_key_id="stateport-qualification-900001-key",
        release_root_url=root_url,
    ) == ("J1 qualification 0", "j1-0")
    signed["publication"]["publishedAt"] = "2026-08-20T00:00:00Z"
    with pytest.raises(ValueError, match="unpublished candidate"):
        bootstrap._release_label(
            document,
            version="0.0.0-j1.0",
            trust_key_id="stateport-qualification-900001-key",
            release_root_url=root_url,
        )


def test_registry_loader_uses_only_the_exact_qualification_version(tmp_path: Path) -> None:
    site_root = tmp_path / "site"
    exact = site_root / "download" / "0.0.0-j1.0"
    other = site_root / "download" / "0.1.0-alpha.7"
    exact.mkdir(parents=True)
    other.mkdir(parents=True)
    (exact / "release-index.json").write_text(
        json.dumps({"signed": {"images": [{"imageId": "exact-image", "digest": "sha256:" + "1" * 64}]}}),
        encoding="utf-8",
    )
    (other / "release-index.json").write_text(
        json.dumps({"signed": {"images": [{"imageId": "ignored-image", "digest": "sha256:" + "2" * 64}]}}),
        encoding="utf-8",
    )
    vm = rehearsal.VM(tmp_path / "work", site_root, tmp_path / "archives")
    images = vm._registry_images("0.0.0-j1.0")
    assert ("exact-image", "sha256:" + "1" * 64) in images
    assert "ignored-image" not in [image_id for image_id, _ in images]
    with pytest.raises(ValueError, match="exact qualification release index"):
        vm._registry_images("0.0.0-j1.1")


def test_guest_registry_transport_mirrors_only_digest_qualified_production_images() -> None:
    config = rehearsal.GUEST_REGISTRIES_CONF
    assert 'location="127.0.0.1:5443"\ninsecure=true' in config
    assert 'prefix="ghcr.io/lennertvhoy"' in config
    assert 'location="ghcr.io/lennertvhoy"' in config
    assert "mirror-by-digest-only=true" in config
    assert 'location="127.0.0.1:5443/stateport-alpha"\ninsecure=true' in config


def test_public_transport_receipt_excludes_guest_staging_seams(tmp_path: Path) -> None:
    vm = rehearsal.VM(
        tmp_path / "work",
        tmp_path / "site",
        tmp_path / "archives",
        public_transport=True,
    )
    transport = vm.transport_receipt()
    assert transport == {
        "siteTransport": {
            "mode": "anonymous-public-pages",
            "url": "https://lennertvhoy.github.io/StatePort-Site",
            "guestLocalServer": False,
        },
        "guestRegistryTransport": {
            "mode": "anonymous-public-ghcr",
            "sourcePrefix": "ghcr.io/lennertvhoy",
            "guestLocalMirror": False,
            "retainedArchiveTransport": False,
        },
    }


def test_public_transport_setup_never_copies_or_installs_local_transport(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    vm = rehearsal.VM(
        work,
        tmp_path / "site",
        tmp_path / "archives",
        public_transport=True,
    )
    commands: list[str] = []
    transfers: list[tuple[str, str]] = []

    def fake_ssh(command: str, **_: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        stdout = ""
        if command.startswith("set -eu;for package in podman netavark"):
            stdout = _stock_baseline_output()
        elif "PUBLIC-TRANSPORT-BOUNDARY-OK" in command:
            stdout = "PUBLIC-TRANSPORT-BOUNDARY-OK resolved=185.199.108.153,\n"
        elif command.startswith("for package in podman netavark aardvark-dns runc slirp4netns"):
            stdout = "\n".join(
                f"{name}|absent|-|-"
                for name in ("podman", "netavark", "aardvark-dns", "runc", "slirp4netns")
            ) + "\n"
        elif command.endswith("| sha256sum"):
            stdout = "a" * 64 + "  -\n"
        return subprocess.CompletedProcess([], 0, stdout, "")

    vm.ssh = fake_ssh  # type: ignore[method-assign]
    vm.scp_in = lambda source, target: transfers.append((source, target))  # type: ignore[method-assign]
    vm.setup("0.1.0-alpha.11")

    assert [target for _, target in transfers] == [
        "stage/uname",
        "stage/powershell.exe",
        "stage/sitecustomize.py",
    ]
    setup = next(command for command in commands if command.startswith("set -eu;for i in $(seq 1 100)"))
    subprocess.run(["/bin/sh", "-n", "-c", setup], check=True)
    for forbidden in (
        "docker-registry",
        "mv stage/site ",
        "stage/oci-archives",
        "stage/ca.crt",
        "registry-config.yml",
        "registries.conf",
        "/etc/hosts",
        "stateport-podman.list",
        "apt-get install",
        "sudo apt-get update",
        "sudo apt-get install",
    ):
        assert forbidden not in setup
    # The pristine-stock capability gate is a native-WSL2 owner-path contract.
    # The QEMU simulation lane's pinned server cloud image legitimately ships
    # zstd, so the hard gate must not be applied there.
    assert "PODMAN-PRESENT-BEFORE-BOOTSTRAP" not in setup
    assert "QUESTING-SOURCE-PRESENT" not in setup
    boundary = next(command for command in commands if "PUBLIC-TRANSPORT-BOUNDARY-OK" in command)
    assert "test ! -e /home/rehearsal/stage/site" in boundary
    assert "test ! -e /home/rehearsal/stage/oci-archives" in boundary
    assert vm.public_transport_boundary == {
        "ok": True,
        "stdoutTail": "PUBLIC-TRANSPORT-BOUNDARY-OK resolved=185.199.108.153,\n",
    }
    assert vm.rehearsal_baseline is not None
    assert vm.rehearsal_baseline["evidenceClass"] == "simulation_only"
    assert vm.rehearsal_baseline["substrate"] == "qemu-wsl-identity-simulation"
    assert vm.rehearsal_baseline["rootfsIdentity"] == rehearsal.QEMU_ROOTFS_IDENTITY
    assert vm.rehearsal_baseline["podmanVersionBeforeBootstrap"] is None
    assert vm.rehearsal_baseline["capabilityProvisioner"] == "exact_public_bootstrap_only"
    assert vm.rehearsal_baseline["extraBinaries"] == []
    assert vm.rehearsal_baseline["usrLocalChanges"] == [
        "/usr/local/bin/uname",
        "/usr/local/bin/powershell.exe",
    ]
    assert commands.index("timeout 420 cloud-init status --wait >/dev/null") < commands.index(
        next(command for command in commands if command.startswith("set -eu;for package in podman"))
    )


def test_stock_capability_gate_is_native_wsl_only(tmp_path: Path) -> None:
    """The pristine-stock gate enforces the owner-path WSL2 rootfs contract.

    The QEMU simulation lane's pinned server cloud image ships zstd, so the
    gate must not be applied there; the native WSL2 lane must keep it so a
    podman/netavark/zstd-bearing rootfs can never falsely pass as stock.
    """
    qemu = rehearsal.VM(tmp_path / "qemu", tmp_path / "site", tmp_path / "archives",
                        public_transport=True)
    assert not qemu.native_wsl
    qemu_setup = _rendered_setup_command(qemu, "0.1.0-alpha.11")
    assert qemu_setup  # a real setup command is still rendered
    assert "PODMAN-PRESENT-BEFORE-BOOTSTRAP" not in qemu_setup
    assert "QUESTING-SOURCE-PRESENT" not in qemu_setup

    native = rehearsal.NativeWSL(tmp_path / "native", tmp_path / "site",
                                 tmp_path / "archives",
                                 distro_name="StatePort-Rehearsal-gate",
                                 public_transport=True)
    assert native.native_wsl
    rendered = _rendered_setup_command(native, "0.1.0-alpha.11")
    assert "PODMAN-PRESENT-BEFORE-BOOTSTRAP" in rendered
    assert "RUNTIME-PACKAGE-PRESENT-BEFORE-BOOTSTRAP" in rendered
    assert "QUESTING-SOURCE-PRESENT" in rendered


def _rendered_setup_command(vm: rehearsal.VM, version: str) -> str:
    """Render the guest setup command string without running a real guest."""
    vm.work.mkdir(parents=True, exist_ok=True)
    vm.identity_shims = vm.usr_local_changes = vm.runtime_configuration_changes = []
    sent: list[str] = []

    def fake_ssh(command: str, **_: object) -> subprocess.CompletedProcess[str]:
        sent.append(command)
        if command.startswith("set -eu;for package in podman netavark"):
            return subprocess.CompletedProcess([], 0, _stock_baseline_output(), "")
        return subprocess.CompletedProcess([], 0, "SELFTEST-OK\n", "")

    vm.ssh = fake_ssh  # type: ignore[method-assign]
    vm.scp_in = lambda source, target: None  # type: ignore[method-assign]
    vm.setup(version)
    return next((c for c in sent if c.startswith("set -eu;for i in $(seq 1 100)")), "")


def test_native_wsl_captures_stock_baseline_before_guest_mutation(tmp_path: Path) -> None:
    vm = rehearsal.NativeWSL(tmp_path / "native", tmp_path / "site", tmp_path / "archives",
                             distro_name="StatePort-Rehearsal-test", public_transport=True)
    commands: list[tuple[str, str]] = []
    wsl_calls: list[tuple[str, ...]] = []

    def fake_wsl(arguments: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        wsl_calls.append(tuple(arguments))
        stdout = "  StatePort-Rehearsal-test    Running    2\n" if "--verbose" in arguments else ""
        return subprocess.CompletedProcess([], 0, stdout, "")

    def fake_ssh(command: str, **_: object) -> subprocess.CompletedProcess[str]:
        commands.append((vm.exec_user, command))
        if command.startswith("set -eu;for package in podman netavark"):
            return subprocess.CompletedProcess([], 0, _stock_baseline_output(), "")
        if command.startswith("powershell.exe -NoProfile"):
            return subprocess.CompletedProcess([], 0, "Microsoft Windows 11|10.0|26200\n", "")
        if command == "cat /etc/machine-id":
            return subprocess.CompletedProcess([], 0, "a" * 32 + "\n", "")
        return subprocess.CompletedProcess([], 0, "", "")

    vm._wsl = fake_wsl  # type: ignore[method-assign]
    vm.ssh = fake_ssh  # type: ignore[method-assign]
    vm.boot()

    assert commands[0][0] == "root"
    assert commands[0][1].startswith("set -eu;for package in podman netavark")
    assert any("useradd" in command for _, command in commands)
    assert all("linger" not in command for _, command in commands)
    assert all("/etc/wsl.conf" not in command for _, command in commands)
    assert any(user == "rehearsal" for user, _ in commands)
    assert vm.rehearsal_baseline is not None
    assert vm.rehearsal_baseline["evidenceClass"] == "owner_path_qualification"
    assert vm.rehearsal_baseline["substrate"] == "native-wsl2"
    assert vm.rehearsal_baseline["rootfsIdentity"] == rehearsal.WSL_ROOTFS_IDENTITY
    assert ("--terminate", "StatePort-Rehearsal-test") in wsl_calls


def test_failed_verification_does_not_publish_create_only_output(tmp_path: Path) -> None:
    staging = tmp_path / "candidate.staging"
    final = tmp_path / "candidate-v9"
    staging.mkdir()
    (staging / "release-index.json").write_text("partial\n", encoding="utf-8")
    candidate.discard_unverified_output(staging, final)
    assert not final.exists()
    assert not (staging / "release-index.json").exists()


def test_phase0_receipt_binds_index_archives_and_bootstrap() -> None:
    expected = {
        "releaseIndexDigest": "sha256:" + "1" * 64,
        "signedPayloadDigest": "sha256:" + "2" * 64,
        "bootstrapDigest": "sha256:" + "3" * 64,
        "archives": {"stateport-api": {"archiveDigest": "sha256:" + "4" * 64, "manifestDigest": "sha256:" + "5" * 64}},
    }
    receipt = {
        "mode": "phase0-transport",
        "result": "passed",
        "binding": expected,
        "phases": {
            "bootstrap-fetch": {"ok": True},
            "transport-probe": {"ok": True},
            "materialization-preflight": {"ok": True},
        },
    }
    assert rehearsal.validate_phase0_receipt(receipt, expected) is True
    changed = json.loads(json.dumps(receipt))
    changed["binding"]["bootstrapDigest"] = "sha256:" + "6" * 64
    with pytest.raises(ValueError, match="phase-0 receipt"):
        rehearsal.validate_phase0_receipt(changed, expected)


def test_public_phase0_binding_does_not_require_staged_archives(tmp_path: Path) -> None:
    site_root = tmp_path / "site" / "download" / "0.1.0-alpha.test"
    site_root.mkdir(parents=True)
    (site_root.parent / "install.sh").write_text("bootstrap", encoding="utf-8")
    (site_root / "release-index.json").write_text(
        json.dumps({
            "signed": {
                "release": {"version": "0.1.0-alpha.test"},
                "images": [{"imageId": "stateport-web", "digest": "sha256:" + "a" * 64}],
                "targets": [],
            }
        }),
        encoding="utf-8",
    )

    binding = rehearsal.phase0_binding(
        site_root.parent.parent,
        "0.1.0-alpha.test",
        None,
    )

    assert binding["images"] == {"stateport-web": "sha256:" + "a" * 64}
    assert "archives" not in binding


def test_local_public_refuses_changed_bootstrap_before_signature_or_vm(tmp_path, monkeypatch):
    calls = []

    def changed(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "different release", "")

    monkeypatch.setattr(rehearsal, "run", changed)
    with pytest.raises(ValueError, match="public candidate mismatch for install.sh"):
        rehearsal.public_binding(tmp_path)
    assert len(calls) == 1
    assert not (tmp_path / "public-inputs/install.sh").exists()


@pytest.mark.parametrize("failure", ["admission", "prepare", "boot", "setup", "install", "install-rerun", "cleanup", None])
def test_local_rehearsal_retains_failure_and_cleans_only_owned_files(tmp_path, monkeypatch, failure):
    vm_dir = tmp_path / "vm"
    vm_dir.mkdir()
    for name in ("vm.qcow2", "seed.iso", "id_ed25519", "id_ed25519.pub", "user-data", "console.log"):
        (vm_dir / name).write_text("owned fixture")
    foreign = tmp_path / "foreign.qcow2"
    foreign.write_text("untouched")
    stopped = []

    def step(name):
        def invoke(*args, **kwargs):
            if failure == name:
                raise RuntimeError("injected " + name)
        return invoke

    monkeypatch.setattr(rehearsal.VM, "phase_gate", step("admission"))
    monkeypatch.setattr(rehearsal.VM, "prepare", step("prepare"))
    monkeypatch.setattr(rehearsal.VM, "boot", step("boot"))
    monkeypatch.setattr(rehearsal.VM, "setup", step("setup"))

    def rehearse(vm, *args, **kwargs):
        vm.current_receipt = {"result": "passed", "phases": {"install": {"ok": True}}}
        if failure in {"install", "install-rerun"}:
            vm.current_receipt["phases"][failure] = {"ok": False, "stdoutTail": "retained failure"}
            raise RuntimeError("injected " + failure)
        return vm.current_receipt

    def teardown(vm):
        stopped.append(True)
        if failure == "cleanup":
            raise RuntimeError("injected cleanup")

    monkeypatch.setattr(rehearsal.VM, "rehearse", rehearse)
    monkeypatch.setattr(rehearsal.VM, "teardown", teardown)
    status = rehearsal.run_local_vm(tmp_path, {})
    receipt = json.loads((tmp_path / "receipt.json").read_text())
    assert status == (0 if failure is None else 1)
    assert receipt["result"] == ("passed" if failure is None else "failed")
    assert stopped == [True]
    assert foreign.read_text() == "untouched"
    assert (vm_dir / "console.log").exists()
    assert (vm_dir / "vm.qcow2").exists() == (failure == "cleanup")
    if failure in {"install", "install-rerun"}:
        assert receipt["phases"][failure]["stdoutTail"] == "retained failure"


def test_fresh_rehearsal_refuses_existing_overlay(tmp_path):
    (tmp_path / "vm.qcow2").write_text("unique guest")
    vm = rehearsal.VM(tmp_path, tmp_path, tmp_path)
    with pytest.raises(ValueError, match="existing overlay"):
        vm.prepare()
    assert (tmp_path / "vm.qcow2").read_text() == "unique guest"


def test_failure_watcher_captures_transient_web_runtime_evidence() -> None:
    watcher = rehearsal.FAILURE_WATCHER
    assert "sleep 0.1" in watcher
    assert "cd /" in watcher
    assert "podman events" in watcher
    assert "--filter label=io.stateport.service.id=stateport-web" in watcher
    assert "ContainerName=" in watcher
    assert "Image=" in watcher
    assert "eventContainerId" in watcher
    assert "container-id" in watcher
    assert "--no-trunc" in watcher
    assert "stateport-j1-runtime-trace" in watcher
    assert "exec runuser -u stateport-control" in watcher
    assert "chown -R stateport-control:stateport-control" in watcher
    assert "container=stateport-web" not in watcher
    assert "podman inspect \"$container\"" in watcher
    assert "podman logs \"$container\"" in watcher
    assert "{{json .Path}}" in watcher
    assert "{{json .Args}}" in watcher
    assert "{{.State.ExitCode}}" in watcher
    assert "{{json .State.Error}}" in watcher
    assert "{{json .Mounts}}" in watcher
    assert "{{json .Config.Entrypoint}} {{json .Config.Cmd}} {{.Config.User}}" in watcher
    assert "--entrypoint /bin/sh" in watcher
    assert "command -v python3" in watcher
    assert "test -f /workspace/apps/web/container-service.py" in watcher
    assert "systemctl --user status" in watcher
    assert "systemctl --user show" in watcher
    assert "journalctl --user -u" in watcher


def test_failed_install_embeds_watcher_snapshots_before_late_diagnostics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vm = rehearsal.VM(tmp_path / "work", tmp_path / "site", tmp_path / "archives")
    calls: list[str] = []

    def fake_ssh(command: str, **_: object) -> SimpleNamespace:
        calls.append(command)
        if "podman run --rm docker.io/library/alpine" in command:
            return SimpleNamespace(returncode=0, stdout="SMOKE-OK\n", stderr="")
        return SimpleNamespace(returncode=0, stdout="ok\n", stderr="")

    def fake_ssh_install(command: str, **_: object) -> SimpleNamespace:
        calls.append(command)
        if "sh /tmp/install.sh" in command and not any(
            probe in command for probe in ("--transport-probe", "--materialization-preflight")
        ):
            return SimpleNamespace(returncode=2, stdout="failed", stderr="")
        return SimpleNamespace(returncode=0, stdout="ok\n", stderr="")

    monkeypatch.setattr(vm, "ssh", fake_ssh)
    monkeypatch.setattr(vm, "ssh_install", fake_ssh_install)
    monkeypatch.setattr(vm, "_start_failure_watcher", lambda **_kwargs: calls.append("watcher:start"))
    monkeypatch.setattr(vm, "_stop_failure_watcher", lambda: calls.append("watcher:stop"))
    monkeypatch.setattr(vm, "_collect_failure_snapshots", lambda receipt: (calls.append("watcher:collect"), receipt.update({"failureSnapshots": {}})))
    monkeypatch.setattr(vm, "_collect_diagnostics", lambda receipt: calls.append("diagnostics"))

    receipt = vm.rehearse("0.0.0-j1.1", binding={"bootstrapDigest": "sha256:ok"})

    assert receipt["result"] == "failed"
    install = next(i for i, call in enumerate(calls) if "sh /tmp/install.sh" in call and "--" not in call)
    assert calls.index("watcher:start") < install < calls.index("watcher:stop")
    assert calls.index("watcher:collect") < calls.index("diagnostics")


def test_diagnostic_j1_receipt_is_explicitly_non_admissible(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vm = rehearsal.VM(Path("/tmp/work"), Path("/tmp/site"), Path("/tmp/archives"))
    monkeypatch.setattr(
        vm,
        "ssh",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout="ok\n", stderr=""),
    )
    monkeypatch.setattr(vm, "_collect_diagnostics", lambda _receipt: None)
    receipt = vm.rehearse(
        "0.0.0-j1.10",
        binding={"bootstrapDigest": "sha256:ok", "signedPayloadDigest": "sha256:" + "1" * 64},
        diagnostic=True,
        expected_candidate="candidate-v10",
        expected_signed_payload="sha256:" + "1" * 64,
    )
    assert receipt["mode"] == "j1-diagnostic"
    assert receipt["diagnostic"]["admissibleForQualification"] is False
    assert receipt["diagnostic"]["changedPrecondition"] == "revision-qualified-container-watcher"


def test_retained_diagnostic_restarts_only_the_revision_qualified_web_unit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vm = rehearsal.VM(tmp_path / "work", tmp_path / "site", tmp_path / "archives")
    calls: list[str] = []

    monkeypatch.setattr(vm, "enable_guest_swap", lambda: "SwapTotal 6G")
    monkeypatch.setattr(vm, "_start_failure_watcher", lambda **_kwargs: calls.append("watcher:start"))
    monkeypatch.setattr(vm, "_stop_failure_watcher", lambda: calls.append("watcher:stop"))
    monkeypatch.setattr(vm, "_collect_failure_snapshots", lambda receipt: receipt.update({"failureSnapshots": {}}))
    monkeypatch.setattr(vm, "_collect_diagnostics", lambda receipt: receipt.update({"diagnostics": "collected"}))
    monkeypatch.setattr(
        vm,
        "ssh",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout="revisionQualifiedUnit=stateport-rev-web.service\nEXIT-127-OBSERVED\n",
            stderr="",
        ),
    )

    receipt = vm.diagnose_retained(
        binding={"signedPayloadDigest": "sha256:" + "1" * 64},
        expected_candidate="candidate-v4",
        expected_web_digest="sha256:" + "2" * 64,
    )

    assert receipt["result"] == "diagnostic_complete"
    assert receipt["diagnostic"]["admissibleForQualification"] is False
    assert receipt["phases"]["guest-swap"]["ok"] is True
    assert receipt["phases"]["revision-qualified-web-restart"]["ok"] is True
    assert calls == ["watcher:start", "watcher:stop"]


def test_governor_admits_declared_diagnostic_budget_with_busy_swap_but_no_thrash(
    tmp_path: Path,
) -> None:
    meminfo = tmp_path / "meminfo"
    meminfo.write_text(
        "MemAvailable: 8650752 kB\nSwapTotal: 8388608 kB\nSwapFree: 4194304 kB\n",
        encoding="ascii",
    )
    pressure = tmp_path / "pressure"
    pressure.write_text("some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n", encoding="ascii")
    vmstat = tmp_path / "vmstat"
    vmstat.write_text("pswpin 10\npswpout 20\n", encoding="ascii")
    result = subprocess.run(
        [str(Path.home() / ".kimi-code/governor/preflight.sh")],
        check=False,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "STATEPORT_GOVERNOR_MEMINFO": str(meminfo),
            "STATEPORT_GOVERNOR_PRESSURE": str(pressure),
            "STATEPORT_GOVERNOR_VMSTAT": str(vmstat),
            "STATEPORT_GOVERNOR_OOM_FIXTURE": "false",
            "STATEPORT_GOVERNOR_REQUESTED_VM_MEMORY_MIB": "4096",
            "STATEPORT_GOVERNOR_QEMU_OVERHEAD_MIB": "768",
            "STATEPORT_GOVERNOR_HOST_RESERVE_MIB": "3584",
        },
    )
    assert result.returncode == 0, result.stderr + result.stdout
    assert "ADMITTED" in result.stdout
    assert "swap_occupancy_pct=50" in result.stdout


def test_build_refuses_integrated_phase_execution_without_separate_guards(
    tmp_path: Path,
) -> None:
    """The integrated build callable must refuse until a separate guarded phase admits it.

    REVIEW-010 required that direct integrated candidate construction cannot run
    unguarded; the build entry point now fails closed with the phase-separation
    refusal before any source, evidence, signing, or qualification side effect.
    """
    source = tmp_path / "source"
    source.mkdir()
    build_receipt = tmp_path / "build-receipt.json"
    build_receipt.write_text(
        json.dumps(
            {
                "formatVersion": "stateport.release-image-build-receipt/v1",
                "identity": {"version": "0.0.0-j1.0"},
                "images": {"stateport-api": {}, "stateport-web": {}},
            }
        ),
        encoding="utf-8",
    )

    def inputs(output: Path) -> dict[str, object]:
        return {
            "source": source,
            "source_commit": "b" * 40,
            "build_receipt": build_receipt,
            "private_detectors": tmp_path,
            "wheelhouse": tmp_path,
            "podman_package_bundle": tmp_path / "podman-package-bundle.tar",
            "topology": tmp_path / "topology.yaml",
            "signing_key": tmp_path / "signing.key",
            "trust_public_key": tmp_path / "trust.pub",
            "trust_key_id": "stateport-qualification-900001-key",
            "trust_key_fingerprint": "sha256:" + "2" * 64,
            "expires_at": "2099-01-01T00:00:00Z",
            "output": output,
        }

    with pytest.raises(candidate.QualificationError) as refused:
        candidate.build(**inputs(tmp_path / "candidate-900001"))
    assert candidate.INTEGRATED_PHASE_REFUSAL in str(refused.value)
    assert not (tmp_path / ".candidate-900001.staging").exists()

    with pytest.raises(candidate.QualificationError) as main_refused:
        candidate.main(
            [
                "--source", str(source),
                "--source-commit", "b" * 40,
                "--build-receipt", str(build_receipt),
                "--private-detectors", str(tmp_path),
                "--wheelhouse", str(tmp_path),
                "--podman-package-bundle", str(tmp_path / "podman-package-bundle.tar"),
                "--topology", str(tmp_path / "topology.yaml"),
                "--signing-key", str(tmp_path / "signing.key"),
                "--trust-public-key", str(tmp_path / "trust.pub"),
                "--trust-key-id", "stateport-qualification-900001-key",
                "--trust-key-fingerprint", "sha256:" + "2" * 64,
                "--expires-at", "2099-01-01T00:00:00Z",
                "--output", str(tmp_path / "candidate-900001"),
            ]
        )
    assert candidate.INTEGRATED_PHASE_REFUSAL in str(main_refused.value)


@pytest.mark.parametrize('native', [False, True])
def test_full_journey_needs_no_separate_phase0_but_rejects_stale_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native: bool,
) -> None:
    """Fixture-only CLI admission: actual guest probes still own qualification."""
    site = tmp_path / 'site'
    (site / 'download').mkdir(parents=True)
    (site / 'download/install.sh').write_text('fixture')
    archives = tmp_path / 'archives'
    archives.mkdir()
    (archives / 'fixture.oci.tar').write_bytes(b'fixture')
    binding = {'bootstrapDigest': 'sha256:' + 'a' * 64}
    monkeypatch.setattr(rehearsal, 'require_guard', lambda *args: None)
    monkeypatch.setattr(rehearsal, 'phase0_binding', lambda *args: binding)
    class GuestReached(RuntimeError):
        pass
    def reached(*args, **kwargs):
        raise GuestReached('guest construction reached')
    monkeypatch.setattr(rehearsal, 'NativeWSL' if native else 'VM', reached)
    argv = ['wsl2_rehearsal.py', '--site-root', str(site), '--archive-root', str(archives),
            '--version', '0.1.0-alpha.999', '--receipt-out', str(tmp_path / 'receipt.json')]
    if native:
        argv += ['--native-wsl2', '--public-transport']
    monkeypatch.setattr(sys, 'argv', argv)
    with pytest.raises(GuestReached):
        rehearsal.main()
    stale = tmp_path / 'stale.json'
    stale.write_text(json.dumps({'mode': 'phase0-transport', 'result': 'failed', 'binding': binding}))
    monkeypatch.setattr(sys, 'argv', [*argv, '--phase0-receipt', str(stale)])
    with pytest.raises(SystemExit, match='full J1 mode refused'):
        rehearsal.main()

@pytest.mark.parametrize('missing_binary', [False, True])
@pytest.mark.parametrize('sandbox_result', [
    'passed', 'failed', 'incomplete', 'missing_parent', 'missing_version',
    'wrong_runtime', 'invalid_version', 'non_object',
])
def test_installed_provider_smoke_requires_cli_without_authentication(monkeypatch, missing_binary, sandbox_result):
    from qualification import journey_common
    observed = dict(executableInstalled=not missing_binary, configured=False, connected=False,
                    authenticationStatus='unverified', requestStatus='unverified', telemetryStatus='unavailable')
    requests = []
    sandbox_calls = []
    class Guest:
        payload = {}
        def ssh(self, command, **_):
            import shlex
            if command.startswith('sudo runuser '):
                sandbox_calls.append(command)
                assert 'stateport-control' in command
                assert 'podman exec --user 65532:65532 ' + 'a' * 64 in command
                assert 'provider_sandbox_probe' not in command  # actual payload, no guest checkout
                result = {'result': 'passed', 'insideWrite': 'passed', 'outsideWrite': 'refused',
                          'symlinkEscape': 'refused', 'networkSocket': 'refused',
                          'childProcess': 'passed', 'namespaces': 'isolated',
                          'authentication': 'not attempted', 'runtime': 'web',
                          'parentNetworkSocket': 'permitted',
                          'providerVersion': 'codex-cli 0.146.0+stateport.2'}
                if sandbox_result == 'incomplete':
                    result.pop('outsideWrite')
                elif sandbox_result == 'missing_parent':
                    result.pop('parentNetworkSocket')
                elif sandbox_result == 'missing_version':
                    result.pop('providerVersion')
                elif sandbox_result == 'wrong_runtime':
                    result['runtime'] = 'workspace'
                elif sandbox_result == 'invalid_version':
                    result['providerVersion'] = 'unknown'
                elif sandbox_result == 'non_object':
                    result = []
                return subprocess.CompletedProcess([], int(sandbox_result == 'failed'), json.dumps(result), 'sandbox refused')
            if command == 'cat /tmp/journey-resp.json':
                return subprocess.CompletedProcess([], 0, json.dumps({'ok': True, 'result': self.payload}), '')
            argv = shlex.split(command)
            assert argv[0] == 'curl'
            method = argv[argv.index('-X') + 1]
            path = argv[-1].removeprefix('http://127.0.0.1:8080')
            requests.append((method, path))
            assert method == 'GET'
            if path == '/session':
                self.payload = {'csrfToken': 'fixture-session'}
            elif path == '/v1/execution-host':
                self.payload = {'executionHost': {'status': 'available', 'grantBound': True}}
            else:
                assert path == '/v1/provider/status'
                self.payload = observed
            return subprocess.CompletedProcess([], 0, '200', '')
    guest = Guest()
    monkeypatch.setattr(journey_common, 'discover_services', lambda _: {'stateport-web': {'port': 8080}})
    monkeypatch.setattr(journey_common, 'wait_service_healthy', lambda *a, **k: None)
    monkeypatch.setattr(journey_common, 'verify_installed_image_digests', lambda *a: {
        'mismatches': {}, 'containers': {'stateport-web': {'containerId': 'a' * 64}}})
    binding = {'images': {}, 'providerRuntimeRequired': True}
    if missing_binary:
        with pytest.raises(ValueError, match='provider observations'):
            rehearsal.installed_service_smoke(guest, binding)
    elif sandbox_result == 'passed':
        assert rehearsal.installed_service_smoke(guest, binding)['providerFreshObservations'] == observed
    else:
        with pytest.raises(ValueError, match='provider sandbox'):
            rehearsal.installed_service_smoke(guest, binding)
    assert len(sandbox_calls) == (0 if missing_binary else 1)
    assert requests == [('GET', '/session'), ('GET', '/v1/execution-host'), ('GET', '/v1/provider/status')]


def _image_identity_fixture(*, units=None, live=None, unit_exit=0, live_exit=0):
    from qualification import journey_common
    import subprocess
    names = ('stateport-web', 'stateport-api', 'stateport-worker')
    expected = {name: 'sha256:' + char * 64 for name, char in zip(names, 'abc')}
    if units is None:
        units = '\n'.join(f'{name}\t{expected[name]}\tcontainer-{name}' for name in names)
    if live is None:
        live = '\n'.join(f'{name}\t{char * 64}\t{expected[name]}\ttrue\t{name}\taccepted\tcontainer-{name}' for name, char in zip(names, 'def'))
    class VM:
        def __init__(self): self.commands = []
        def ssh(self, command, **kwargs):
            self.commands.append(command)
            assert kwargs == {'check': False, 'timeout': 60}
            output, code = (units, unit_exit) if len(self.commands) == 1 else (live, live_exit)
            return subprocess.CompletedProcess(command, code, output, 'SECRET_INSPECT_STDERR_CANARY')
    vm = VM()
    return journey_common, vm, expected


def test_installed_image_identity_observes_running_containers_separately_from_units():
    common, vm, expected = _image_identity_fixture()
    result = common.verify_installed_image_digests(vm, expected)
    assert result['mismatches'] == {}
    assert result['declared'] == expected == result['observed']
    assert result['containers']['stateport-web']['containerId'] == 'd' * 64
    assert 'sudo runuser -u stateport-control' in vm.commands[1]
    assert 'podman ps --no-trunc --filter status=running' in vm.commands[1]
    assert 'label=io.stateport.profile=accepted' in vm.commands[1]
    assert 'podman container inspect --format' in vm.commands[1]
    assert '{{.ImageDigest}}' in vm.commands[1]
    assert '{{.Id}}\t{{.ImageDigest}}' in vm.commands[1]
    assert r'{{.Id}}\t{{.ImageDigest}}' not in vm.commands[1]
    assert vm.commands[1].index('invalid-running-count') < vm.commands[1].index('podman container inspect')
    assert '.Config.Env' not in vm.commands[1] and '{{json .}}' not in vm.commands[1]


@pytest.mark.parametrize('defect', ['zero', 'duplicate', 'stopped', 'wrong-profile', 'wrong-label', 'wrong-name', 'wrong-digest', 'malformed', 'inspect-error'])
def test_unit_digest_alone_cannot_pass_live_image_qualification(defect):
    _, _, expected = _image_identity_fixture()
    names = tuple(expected)
    live = [f'{name}\t{char * 64}\t{expected[name]}\ttrue\t{name}\taccepted\tcontainer-{name}' for name, char in zip(names, 'def')]
    exit_code = 0
    if defect == 'zero': live.pop(0)
    elif defect == 'duplicate': live.append(live[0])
    elif defect == 'stopped': live[0] = live[0].replace('\ttrue\t', '\tfalse\t')
    elif defect == 'wrong-profile': live[0] = live[0].replace('\taccepted\t', '\tvalidation\t')
    elif defect == 'wrong-label': live[0] = live[0].replace('\tstateport-web\taccepted', '\tstateport-api\taccepted')
    elif defect == 'wrong-name': live[0] = live[0].replace('container-stateport-web', 'foreign-container')
    elif defect == 'wrong-digest': live[0] = live[0].replace(expected['stateport-web'], 'sha256:' + '0' * 64)
    elif defect == 'malformed': live[0] = 'SECRET_INSPECT_STDOUT_CANARY'
    else: exit_code = 125
    common, vm, expected = _image_identity_fixture(live='\n'.join(live), live_exit=exit_code)
    result = common.verify_installed_image_digests(vm, expected)
    assert result['declaredMismatches'] == {}
    assert 'stateport-web' in result['mismatches']
    assert 'SECRET_INSPECT' not in json.dumps(result)


@pytest.mark.parametrize('defect', ['duplicate', 'missing', 'wrong-digest', 'read-error'])
def test_declared_unit_identity_remains_an_independent_gate(defect):
    _, _, expected = _image_identity_fixture()
    units = [f'{name}\t{digest}\tcontainer-{name}' for name, digest in expected.items()]
    if defect == 'duplicate': units.append(units[0])
    elif defect == 'missing': units.pop(0)
    elif defect == 'wrong-digest': units[0] = units[0].replace(expected['stateport-web'], 'sha256:' + '0' * 64)
    common, vm, expected = _image_identity_fixture(units='\n'.join(units), unit_exit=1 if defect == 'read-error' else 0)
    result = common.verify_installed_image_digests(vm, expected)
    assert result['observed'] == expected
    assert 'stateport-web' in result['declaredMismatches']
    assert 'stateport-web' in result['mismatches']
    assert 'SECRET_INSPECT' not in json.dumps(result)


def test_candidate_must_include_every_control_image_before_guest_access():
    common, vm, expected = _image_identity_fixture()
    expected.pop('stateport-worker')
    with pytest.raises(ValueError, match='every control-service image'):
        common.verify_installed_image_digests(vm, expected)
    assert vm.commands == []


@pytest.mark.parametrize("answers", [["install-packages", "install-exact"], ["install"]])
def test_install_driver_answers_split_prompts_over_real_pipe(tmp_path: Path, monkeypatch, answers) -> None:
    vm = rehearsal.VM(tmp_path / "vm", tmp_path / "site", tmp_path / "archives")
    prompts = {
        "install-packages": "Type install-packages to authorize this exact authenticated package plan:",
        "install-exact": "Type install-exact to authorize this exact plan:",
        "install": "Type install:",
    }
    program = "import sys,time\n"
    for answer in answers:
        prompt = prompts[answer]
        program += (f"sys.stdout.write({prompt[:9]!r}); sys.stdout.flush(); time.sleep(.02)\n"
                    f"sys.stdout.write({prompt[9:]!r}); sys.stdout.flush()\n"
                    f"assert sys.stdin.readline().strip() == {answer!r}\n")
    program += "print('installed-result')\n"
    monkeypatch.setattr(vm, "_install_argv", lambda _: [sys.executable, "-c", program])
    result = vm.ssh_install("unused", confirmations=answers, timeout=5)
    assert result.returncode == 0
    assert "installed-result" in result.stdout


@pytest.mark.parametrize("program,expected", [
    ("raise SystemExit(7)", 7),
    ("print('premature success')", RuntimeError),
    ("import time; print('waiting',flush=True); time.sleep(20)", subprocess.TimeoutExpired),
])
def test_install_driver_preserves_failures_and_bounds_wait(tmp_path: Path, monkeypatch, program, expected) -> None:
    vm = rehearsal.VM(tmp_path / "vm", tmp_path / "site", tmp_path / "archives")
    monkeypatch.setattr(vm, "_install_argv", lambda _: [sys.executable, "-c", program])
    if isinstance(expected, int):
        assert vm.ssh_install("unused", confirmations=["install"], timeout=2).returncode == expected
    else:
        with pytest.raises(expected):
            vm.ssh_install("unused", confirmations=["install"], timeout=.2)


def test_native_install_transport_uses_exact_wsl_distro_and_user(tmp_path: Path) -> None:
    import shlex
    native = rehearsal.NativeWSL(tmp_path / "native", tmp_path / "site", tmp_path / "archives",
                                 distro_name="StatePort-Rehearsal-installer")
    native.exec_user = "rehearsal"
    command = "printf '%s' 'literal $HOME; $(false)'"
    argv = native._install_argv(command)
    assert argv[:6] == ["wsl.exe", "--distribution", native.distro_name, "--user", "rehearsal", "--"]
    assert argv[6:8] == ["script", "-qefc"]
    assert shlex.split(argv[8]) == ["sh", "-lc", command]
    assert argv[9] == "/dev/null"
    assert "ssh" not in argv


def test_journey_artifact_transport_selects_native_public_fetch(tmp_path: Path) -> None:
    from qualification import journey_common

    class Native:
        native_wsl = True

        def __init__(self):
            self.calls = []

        def fetch_public_artifact(self, url, destination, digest):
            self.calls.append((url, destination, digest))

        def scp_in(self, *_):
            raise AssertionError("native transport must not copy a host path")

    native = Native()
    digest = "sha256:" + "a" * 64
    journey_common.transport_artifact(
        native, tmp_path / "installer", "/tmp/stateport-installer",
        public_url="https://example.invalid/download/stateport-installer",
        expected_digest=digest,
    )
    assert native.calls == [
        ("https://example.invalid/download/stateport-installer",
         "/tmp/stateport-installer", digest)
    ]


def test_journey_artifact_transport_retains_qemu_local_copy(tmp_path: Path) -> None:
    from qualification import journey_common

    class Guest:
        native_wsl = False

        def __init__(self):
            self.calls = []

        def scp_in(self, source, destination):
            self.calls.append((source, destination))

    guest = Guest()
    source = tmp_path / "bootstrap"
    source.write_text("bytes")
    journey_common.transport_artifact(guest, source, "/tmp/stateport-bootstrap")
    assert guest.calls == [(str(source), "/tmp/stateport-bootstrap")]


def test_native_attach_refuses_missing_distro(monkeypatch, tmp_path: Path) -> None:
    native = rehearsal.NativeWSL(tmp_path / "native", tmp_path / "site", None,
                                 distro_name="StatePort-Rehearsal-missing",
                                 attach_existing=True)
    monkeypatch.setattr(rehearsal.os, "name", "nt")
    native._wsl = lambda *args, **kwargs: subprocess.CompletedProcess([], 0, "Other\n", "")
    with pytest.raises(SystemExit, match="distro is not registered"):
        native.prepare(reuse=True)


def test_native_attach_never_imports_rootfs(monkeypatch, tmp_path: Path) -> None:
    native = rehearsal.NativeWSL(tmp_path / "native", tmp_path / "site", None,
                                 distro_name="StatePort-Rehearsal-existing",
                                 attach_existing=True)
    monkeypatch.setattr(rehearsal.os, "name", "nt")
    calls = []
    def fake_wsl(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess([], 0, "StatePort-Rehearsal-existing\n", "")
    native._wsl = fake_wsl
    native.prepare(reuse=True)
    assert not any("--import" in args for args in calls)


def test_native_constructor_accepts_candidate_bootstrap_url(tmp_path: Path) -> None:
    url = "https://example.invalid/download/0.1.0-alpha.17/bootstrap.sh"
    native = rehearsal.NativeWSL(tmp_path / "native", tmp_path / "site", None,
                                 distro_name="StatePort-Rehearsal-url",
                                 bootstrap_url=url)
    assert native.bootstrap_url == url


@pytest.mark.parametrize("identity", [
    None, {}, {"machineId": "a" * 32},
    {"windowsIdentity": "Windows|10|1"},
    {"machineId": "", "windowsIdentity": "Windows|10|1"},
    {"machineId": "b" * 31, "windowsIdentity": "Windows|10|1"},
    {"machineId": "a" * 32, "windowsIdentity": ""},
])
def test_native_attach_refuses_incomplete_identity_before_guest_call(identity, tmp_path: Path) -> None:
    from qualification.journey_common import boot_native_follow_on
    work, site = tmp_path / "native", tmp_path / "site"
    work.mkdir(); site.mkdir()
    with pytest.raises(ValueError, match="identity binding"):
        boot_native_follow_on(work, site_root=site,
                             distro_name="StatePort-Rehearsal-identity",
                             expected_identity=identity,
                             expected_baseline={"distroName": "StatePort-Rehearsal-identity"})


def test_native_attach_preserves_exact_j1_baseline_on_success(monkeypatch, tmp_path: Path) -> None:
    baseline = {"schema": "stateport.rehearsal-baseline/v1", "distroName": "StatePort-Rehearsal-preserve",
                "machineId": "a" * 32, "windowsIdentity": "Windows|10|26200"}
    native = rehearsal.NativeWSL(tmp_path / "native", tmp_path / "site", None,
                                 distro_name=baseline["distroName"], attach_existing=True)
    native.expected_native_baseline = dict(baseline)
    native.expected_native_identity = {"machineId": baseline["machineId"], "windowsIdentity": baseline["windowsIdentity"]}
    monkeypatch.setattr(rehearsal.os, "name", "nt")
    native._wsl = lambda args, **kwargs: subprocess.CompletedProcess([], 0,
        ("StatePort-Rehearsal-preserve Running 2\n" if "--verbose" in args
         else "StatePort-Rehearsal-preserve\n"), "")
    native.prepare(reuse=True)
    native._capture_rehearsal_baseline = lambda: (_ for _ in ()).throw(AssertionError("recaptured baseline"))
    native.ssh = lambda command, **kwargs: subprocess.CompletedProcess([], 0,
        ("a" * 32 + "\n") if command == "cat /etc/machine-id" else "Windows|10|26200\n", "")
    native.boot()
    assert native.rehearsal_baseline == baseline


@pytest.mark.parametrize("identity", [None, {}, {"machineId": "a" * 32, "windowsIdentity": 123}])
def test_direct_native_boot_refuses_missing_identity_without_guest_calls(tmp_path, identity):
    native = rehearsal.NativeWSL(tmp_path / "native", tmp_path / "site", None,
                                 distro_name="StatePort-Rehearsal-no-identity", attach_existing=True)
    native.expected_native_identity = identity
    native._wsl = lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("guest touched"))
    with pytest.raises(SystemExit, match="identity binding"):
        native.boot()


def test_native_attach_refuses_conflicting_retained_baseline_before_guest_calls(tmp_path):
    from qualification.journey_common import boot_native_follow_on
    work, site = tmp_path / "work", tmp_path / "site"
    work.mkdir(); site.mkdir()
    with pytest.raises(ValueError, match="identity binding"):
        boot_native_follow_on(work, site_root=site, distro_name="StatePort-Rehearsal-conflict",
            expected_identity={"machineId": "a" * 32, "windowsIdentity": "Windows|10|26200"},
            expected_baseline={"distroName": "StatePort-Rehearsal-conflict",
                               "machineId": "b" * 32, "windowsIdentity": "Windows|10|26200"})


def test_candidate_artifact_urls_bind_default_and_versioned_paths() -> None:
    from qualification.journey_common import candidate_artifact_urls
    assert candidate_artifact_urls("0.1.0-alpha.17", "https://lennertvhoy.github.io/StatePort-Site/download/install.sh") == (
        "https://lennertvhoy.github.io/StatePort-Site/download/install.sh",
        "https://lennertvhoy.github.io/StatePort-Site/download/0.1.0-alpha.17/stateport-installer",
    )
    assert candidate_artifact_urls("0.1.0-alpha.17", "https://example.invalid/download/0.1.0-alpha.17/bootstrap.sh")[1].endswith("/stateport-installer")
    with pytest.raises(ValueError, match="HTTPS"):
        candidate_artifact_urls("0.1.0-alpha.17", "http://example.invalid/bootstrap.sh")


def test_native_workspace_browser_never_starts_local_registry() -> None:
    from qualification import run_journey_j2
    class NativeGuest:
        native_wsl = True
        def __init__(self): self.commands = []
        def ssh(self, command, **kwargs):
            self.commands.append(command)
            raise AssertionError("native path attempted local registry SSH probe")
    guest = NativeGuest()
    run_journey_j2._ensure_qualification_registry(guest)
    assert guest.commands == []


def test_native_browser_uses_exact_signed_namespace_and_shipped_podman():
    from qualification import run_journey_j2 as driver
    digest = "sha256:" + "a" * 64
    reference = "ghcr.io/another-owner/fresh-release/path/browser@" + digest
    class Guest:
        native_wsl = True
        public_image_references = {"stateport-playwright": reference}
        commands = []
        def ssh(self, command, **kwargs):
            self.commands.append(command)
            return subprocess.CompletedProcess([], 0, "pull complete\n" + digest + "\n", "")
    guest = Guest()
    image, native = driver._qualification_browser_transport(guest, digest)
    assert (image, native) == (reference, True)
    driver._verify_qualification_browser_image(guest, image, digest, native)
    assert len(guest.commands) == 1
    assert reference in guest.commands[0] and "--tls-verify=true" in guest.commands[0]
    assert "skopeo" not in guest.commands[0] and "127.0.0.1:5443" not in guest.commands[0]
    assert "--tls-verify=false" not in guest.commands[0]


@pytest.mark.parametrize("prefix", ["ghcr.io.evil/user/image", "ghcr.io/user/../image", "ghcr.io/user//image", "localhost/image"])
def test_native_browser_refuses_unbound_registry_reference(prefix):
    from qualification import run_journey_j2 as driver
    digest = "sha256:" + "a" * 64
    guest = type("Guest", (), {"native_wsl": True, "public_image_references": {
        "stateport-playwright": prefix + "@" + digest}})()
    with pytest.raises(AssertionError):
        driver._qualification_browser_transport(guest, digest)


def test_browser_simulation_retains_existing_mirror_and_native_refuses_digest_drift():
    from qualification import run_journey_j2 as driver
    digest = "sha256:" + "a" * 64
    guest = type("Guest", (), {"native_wsl": False})()
    assert driver._qualification_browser_transport(guest, digest) == (
        "127.0.0.1:5443/stateport-alpha/stateport-playwright@" + digest, False)
    guest.native_wsl = True
    guest.public_image_references = {"stateport-playwright": "ghcr.io/user/browser@sha256:" + "b" * 64}
    with pytest.raises(AssertionError, match="digest"):
        driver._qualification_browser_transport(guest, digest)


def test_native_attach_rejects_changed_identity(monkeypatch, tmp_path: Path) -> None:
    native = rehearsal.NativeWSL(tmp_path / "native", tmp_path / "site", None,
                                 distro_name="StatePort-Rehearsal-identity",
                                 attach_existing=True)
    native.expected_native_identity = {"machineId": "a" * 32,
                                       "windowsIdentity": "old"}
    native.expected_native_baseline = {"machineId": "a" * 32,
                                      "windowsIdentity": "old",
                                      "distroName": native.distro_name}
    monkeypatch.setattr(native, "_wsl", lambda args, **kwargs:
                        subprocess.CompletedProcess([], 0,
                            "StatePort-Rehearsal-identity Running 2\n" if "--verbose" in args else "StatePort-Rehearsal-identity\n", ""))
    monkeypatch.setattr(rehearsal.os, "name", "nt")
    native.prepare(reuse=True)
    native._capture_rehearsal_baseline = lambda: {"schema": "stateport.rehearsal-baseline/v1"}
    def ssh(command, **kwargs):
        if command == "cat /etc/machine-id":
            return subprocess.CompletedProcess([], 0, "b" * 32 + "\n", "")
        return subprocess.CompletedProcess([], 0, "Windows|10|26200\n", "")
    native.ssh = ssh
    with pytest.raises(SystemExit, match="identity differs"):
        native.boot()
