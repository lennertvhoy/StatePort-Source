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
        return subprocess.CompletedProcess([], 0, "", "")

    vm._wsl = fake_wsl  # type: ignore[method-assign]
    vm.ssh = fake_ssh  # type: ignore[method-assign]
    vm.boot()

    assert commands[0][0] == "root"
    assert commands[0][1].startswith("set -eu;for package in podman netavark")
    assert "useradd" in commands[1][1]
    assert commands[2][0] == "rehearsal"
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
