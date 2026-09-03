from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import sys

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from infra.qualification import ubuntu2404_guest_stage as guest  # noqa: E402
from infra.qualification import ubuntu2404_stage as contract  # noqa: E402


def _candidate() -> dict[str, object]:
    return {
        "releaseId": "stateport-test",
        "version": "0.1.0-alpha.4",
        "targetId": "linux-amd64-rootless-podman-quadlet",
        "releaseIndexDigest": "sha256:" + "a" * 64,
        "signedPayloadDigest": "sha256:" + "b" * 64,
        "sourceCommit": "c" * 40,
        "sourceTree": "d" * 40,
        "publicSource": {"authorityUrl": "https://example.invalid/source.git", "ref": "refs/heads/main", "commit": "e" * 40, "tree": "f" * 40},
        "imageDigests": ["sha256:" + "1" * 64],
        "installerDigest": "sha256:" + "2" * 64,
    }


def _stage() -> dict[str, object]:
    return {
        "provisionerPath": guest.PROVISIONER,
        "provisionerInstallArgv": ["sudo", "-n", "install", "-D", "-o", "root", "-g", "root", "-m", "0555", "/tmp/artifacts/executionHostProvisioner", guest.PROVISIONER],
        "rootPreflightArgv": ["sudo", "-n", guest.PROVISIONER, "qualification-preflight"],
        "materializeArgv": ["sudo", "-n", guest.PROVISIONER, "materialize", "--execution-host-provisioner", guest.PROVISIONER, "--execution-host-provisioner-digest", "sha256:" + "0" * 64, "--execution-host-provisioner-bytes", "0", "--updater-wheel", "/tmp/artifacts/updater", "--updater-wheel-digest", "sha256:" + "8" * 64, "--release-index", "/tmp/index.json", "--bundle-root", "/tmp", "--cosign", "/tmp/cosign", "--cosign-digest", "sha256:" + "6" * 64, "--trust-public-key", "/tmp/release.pub", "--trust-public-key-digest", "sha256:" + "3" * 64, "--trust-key-id", "stateport-test", "--trust-key-fingerprint", "sha256:" + "7" * 64],
        "provisionArgv": [guest.PROVISIONER, "provision", "--release-index", "/tmp/index.json", "--bundle-root", "/tmp", "--cosign", "/tmp/cosign", "--trust-public-key", "/tmp/release.pub", "--trust-key-id", "stateport-test", "--trust-key-fingerprint", "sha256:" + "7" * 64, "--channel", "alpha", "--receipt-out", "/tmp/provision.json"],
        "provisionReceiptPath": "/tmp/provision.json",
        "healthArgv": [guest.PROVISIONER, "health-probe", "--socket", "{socket}"],
        "installArgv": ["/tmp/install.sh", "--release-index", "/tmp/index.json", "--bundle-root", "/tmp", "--cosign", "/tmp/cosign", "--trust-public-key", "/tmp/release.pub", "--trust-key-id", "stateport-test", "--trust-key-fingerprint", "sha256:" + "7" * 64, "--channel", "alpha", "--updater-wheel", "/tmp/artifacts/updater", "--execution-host-provisioner", "/tmp/artifacts/executionHostProvisioner", "--compose", "/tmp/compose.release.yaml", "--source-archive", "/tmp/artifacts/sourceArchive", "--release-notes", "/tmp/artifacts/releaseNotes", "--known-limitations", "/tmp/artifacts/knownLimitations", "--execution-host-receipt", "/tmp/provision.json", "--yes"],
        "uninstallArgv": ["/tmp/install.sh", "--uninstall"],
        "purgeArgv": ["/tmp/install.sh", "--purge", "--confirm-purge", "{confirm_purge}"],
        "rootCleanupArgv": ["sudo", "-n", guest.PROVISIONER, "qualification-cleanup", "--release-index", "/tmp/index.json", "--bundle-root", "/tmp", "--receipt", "/tmp/provision.json"],
        "restartArgv": ["systemctl", "--user", "restart", "stateport.service"],
        "journeyArgv": ["/tmp/studystate-journey", "--application", "StudyState", "--phase", "{phase}"],
        "stateRoot": "/tmp/stateport",
        "liveQuadletRoot": "/tmp/quadlets",
        "ownedPaths": ["/tmp/quadlets/stateport.container", guest.PROVISIONER],
        "preservedPaths": ["/tmp/preserved"],
        "ownedServices": ["stateport.service", "stateport-execution-host.service", "podman.socket"],
        "ownedImages": ["stateport-test"],
        "checkoutPaths": ["/workspace"],
    }


def _config(tmp_path: Path) -> dict[str, object]:
    candidate = _candidate()
    return {
        "schema": "stateport.qualification.ubuntu2404-config/v1",
        "candidate": candidate,
        "artifacts": {"releaseIndex": {"path": str(tmp_path / "index.json"), "sha256": candidate["releaseIndexDigest"]}, "signedPayload": {"path": str(tmp_path / "payload"), "sha256": candidate["signedPayloadDigest"]}, "installer": {"path": str(tmp_path / "install.sh"), "sha256": candidate["installerDigest"]}, "executionHostProvisioner": {"path": str(tmp_path / "artifacts" / "executionHostProvisioner"), "sha256": "sha256:" + "0" * 64}, "updater": {"path": str(tmp_path / "artifacts" / "updater"), "sha256": "sha256:" + "8" * 64}},
        "verification": {"publicKey": {"path": str(tmp_path / "release.pub"), "sha256": "sha256:" + "3" * 64}, "signatureBundle": {"path": str(tmp_path / "release-index.sigstore.json"), "sha256": "sha256:" + "4" * 64}, "predecessorSignatureBundle": {"path": str(tmp_path / "predecessor-bundle" / "release-index.sigstore.json"), "sha256": "sha256:" + "5" * 64}, "cosign": {"path": str(tmp_path / "cosign"), "sha256": "sha256:" + "6" * 64}, "keyId": "stateport-test", "publicKeyFingerprint": "sha256:" + "7" * 64},
        "guest": {"guestId": "ubuntu-test", "distribution": "ubuntu", "version": "24.04", "isolationContract": "exactly-one-clean-ubuntu-24.04-guest-no-checkout-no-preexisting-stateport"},
        "receipt": {"path": str(tmp_path / "receipt.json"), "sha256": "sha256:" + "9" * 64},
        "guestStage": _stage(),
    }


def test_command_boundary_rejects_shell_or_wrong_provisioner(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config["guestStage"]["provisionArgv"] = ["sh", "-c", "provision"]  # type: ignore[index]
    with pytest.raises(guest.GuestStageRefusal, match="fixed root provisioner"):
        guest._require_command_shape(config["guestStage"], _values())  # type: ignore[arg-type]


def test_command_boundary_accepts_noninteractive_root_boundary(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config["guestStage"]["provisionArgv"] = ["sudo", "-n", *config["guestStage"]["provisionArgv"]]  # type: ignore[index]
    guest._require_command_shape(config["guestStage"], _values())  # type: ignore[arg-type]


def test_command_boundary_requires_parent_creation_for_clean_host(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config["guestStage"]["provisionerInstallArgv"].remove("-D")  # type: ignore[index,union-attr]
    with pytest.raises(guest.GuestStageRefusal, match="fixed root path"):
        guest._require_command_shape(config["guestStage"], _values())  # type: ignore[arg-type]


def test_qualification_created_provisioner_parent_is_removed(tmp_path: Path) -> None:
    parent = tmp_path / "libexec"
    calls: list[list[str]] = []
    root_directory = os.stat_result((stat.S_IFDIR | 0o755, 0, 0, 0, 0, 0, 0, 0, 0, 0))

    def missing_parent(path: Path) -> os.stat_result:
        if path == parent:
            raise FileNotFoundError(path)
        return root_directory

    assert not guest._safe_provisioner_parent_exists(
        parent,
        missing_parent,
    )
    assert guest._remove_created_provisioner_parent(
        parent,
        False,
        lambda argv: calls.append(list(argv)) or guest.Completed(0),
        lambda path: False,
    )
    assert calls == [["sudo", "-n", "/usr/bin/rmdir", str(parent)]]


def test_preexisting_safe_provisioner_parent_is_preserved(tmp_path: Path) -> None:
    parent = tmp_path / "libexec"
    parent.mkdir()
    root_directory = os.stat_result((stat.S_IFDIR | 0o755, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    calls: list[list[str]] = []

    assert guest._safe_provisioner_parent_exists(parent, lambda path: root_directory)
    assert not guest._remove_created_provisioner_parent(
        parent,
        True,
        lambda argv: calls.append(list(argv)) or guest.Completed(0),
        lambda path: True,
    )
    assert not calls


def test_unsafe_provisioner_parent_is_refused(tmp_path: Path) -> None:
    parent = tmp_path / "libexec"
    parent.mkdir()
    root_directory = os.stat_result((stat.S_IFDIR | 0o755, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    writable_directory = os.stat_result((stat.S_IFDIR | 0o775, 0, 0, 0, 0, 0, 0, 0, 0, 0))

    with pytest.raises(guest.GuestStageRefusal, match="directory is unsafe"):
        guest._safe_provisioner_parent_exists(
            parent,
            lambda path: writable_directory if path == parent else root_directory,
        )


@pytest.mark.parametrize(
    "unsafe",
    [
        os.stat_result((stat.S_IFREG | 0o755, 0, 0, 0, 0, 0, 0, 0, 0, 0)),
        os.stat_result((stat.S_IFDIR | 0o755, 0, 0, 0, 1000, 0, 0, 0, 0, 0)),
        os.stat_result((stat.S_IFDIR | 0o755, 0, 0, 0, 0, 1000, 0, 0, 0, 0)),
    ],
)
def test_unsafe_provisioner_ancestor_is_refused(
    tmp_path: Path, unsafe: os.stat_result
) -> None:
    parent = tmp_path / "local" / "libexec"
    root_directory = os.stat_result((stat.S_IFDIR | 0o755, 0, 0, 0, 0, 0, 0, 0, 0, 0))

    with pytest.raises(guest.GuestStageRefusal, match="directory is unsafe"):
        guest._safe_provisioner_parent_exists(
            parent,
            lambda path: unsafe if path == parent.parent else root_directory,
        )


def test_symlinked_provisioner_parent_is_refused(tmp_path: Path) -> None:
    parent = tmp_path / "libexec"
    root_directory = os.stat_result((stat.S_IFDIR | 0o755, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    symlink = os.stat_result((stat.S_IFLNK | 0o777, 0, 0, 0, 0, 0, 0, 0, 0, 0))

    with pytest.raises(guest.GuestStageRefusal, match="unsafe symlink"):
        guest._safe_provisioner_parent_exists(
            parent,
            lambda path: symlink if path == parent else root_directory,
        )


def test_symlinked_provisioner_ancestor_is_refused(tmp_path: Path) -> None:
    ancestor = tmp_path / "local"
    root_directory = os.stat_result((stat.S_IFDIR | 0o755, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    symlink = os.stat_result((stat.S_IFLNK | 0o777, 0, 0, 0, 0, 0, 0, 0, 0, 0))

    with pytest.raises(guest.GuestStageRefusal, match="unsafe symlink"):
        guest._safe_provisioner_parent_exists(
            ancestor / "libexec",
            lambda path: symlink if path == ancestor else root_directory,
        )


def test_provisioner_parent_cleanup_fails_closed(tmp_path: Path) -> None:
    parent = tmp_path / "libexec"

    with pytest.raises(guest.GuestStageRefusal, match="cleanup failed"):
        guest._remove_created_provisioner_parent(
            parent,
            False,
            lambda argv: guest.Completed(1, stderr="not empty"),
            lambda path: True,
        )
    with pytest.raises(guest.GuestStageRefusal, match="parent remains"):
        guest._remove_created_provisioner_parent(
            parent,
            False,
            lambda argv: guest.Completed(0),
            lambda path: True,
        )


def _values() -> dict[str, str]:
    return {
        "installer": "/tmp/install.sh",
        "release_index": "/tmp/index.json",
        "provision_receipt": "/tmp/provision.json",
        "state_root": "/tmp/stateport",
        "live_quadlet_root": "/tmp/quadlets",
        "socket": "{socket}",
        "bundle_root": "/tmp",
        "cosign": "/tmp/cosign",
        "public_key": "/tmp/release.pub",
        "key_id": "stateport-test",
        "public_key_fingerprint": "sha256:" + "7" * 64,
        "channel": "alpha",
        "phase": "install",
        "updater_wheel": "/tmp/artifacts/updater",
        "updater_wheel_digest": "sha256:" + "8" * 64,
        "cosign_digest": "sha256:" + "6" * 64,
        "public_key_digest": "sha256:" + "3" * 64,
        "execution_host_provisioner": "/tmp/artifacts/executionHostProvisioner",
        "execution_host_provisioner_digest": "sha256:" + "0" * 64,
        "execution_host_provisioner_bytes": "0",
        "compose": "/tmp/compose.release.yaml",
        "source_archive": "/tmp/artifacts/sourceArchive",
        "release_notes": "/tmp/artifacts/releaseNotes",
        "known_limitations": "/tmp/artifacts/knownLimitations",
    }


def test_command_boundary_rejects_missing_predecessor_transport(tmp_path: Path) -> None:
    config = _config(tmp_path)
    install = config["guestStage"]["installArgv"]  # type: ignore[index]
    position = install.index("--bundle-root")  # type: ignore[union-attr]
    del install[position : position + 2]  # type: ignore[index]
    with pytest.raises(guest.GuestStageRefusal, match="exactly invoke"):
        guest._require_command_shape(config["guestStage"], _values())  # type: ignore[arg-type]


def test_command_boundary_rejects_duplicate_or_trailing_arguments(tmp_path: Path) -> None:
    config = _config(tmp_path)
    provision = config["guestStage"]["provisionArgv"]  # type: ignore[index]
    provision.extend(["--release-index", "/tmp/other.json"])  # type: ignore[union-attr]
    with pytest.raises(guest.GuestStageRefusal, match="exactly invoke"):
        guest._require_command_shape(config["guestStage"], _values())  # type: ignore[arg-type]

    config = _config(tmp_path)
    config["guestStage"]["healthArgv"].append("--unexpected")  # type: ignore[index,union-attr]
    with pytest.raises(guest.GuestStageRefusal, match="fixed live protocol probe"):
        guest._require_command_shape(config["guestStage"], _values())  # type: ignore[arg-type]


def test_capability_probe_is_observed_and_fails_closed() -> None:
    stage = _stage()
    outputs = {
        ("uname", "-s"): "Linux\n", ("uname", "-r"): "6.8.0-79-generic\n", ("uname", "-m"): "x86_64\n", ("stat", "-fc", "%T", "/sys/fs/cgroup"): "cgroup2fs\n",
        ("podman", "--version"): "podman version 5.0.0\n", ("id", "-un"): "operator\n",
        ("podman", "images", "--format", "json"): "[]\n", ("systemctl", "--user", "list-units", "--all", "--plain", "--no-legend"): "\n",
    }

    def run(argv: list[str] | tuple[str, ...]) -> guest.Completed:
        key = tuple(argv)
        if key == ("podman", "info", "--format", "json"):
            return guest.Completed(0, '{"host":{"rootless":true}}\n')
        if key == ("systemctl", "--user", "is-system-running"):
            return guest.Completed(0, "running\n")
        return guest.Completed(0, outputs.get(key, ""))

    def read(path: Path) -> bytes:
        if str(path) == "/etc/os-release":
            return b'ID=ubuntu\nVERSION_ID="24.04"\n'
        if str(path) == "/etc/subuid":
            return b"other:100000:65536\n"
        if str(path) == "/etc/subgid":
            return b"operator:200000:65536\n"
        return b""

    with pytest.raises(guest.GuestStageRefusal, match="required Linux capability"):
        guest._facts(stage, run, read, lambda path: str(path) in {"/usr/libexec/podman/quadlet"})


@pytest.mark.parametrize(
    "podman_host",
    [
        {"rootless": True},
        {"security": {"rootless": True}},
    ],
)
def test_capability_probe_accepts_supported_rootless_podman_layouts(
    podman_host: dict[str, object],
) -> None:
    stage = _stage()
    outputs = {
        ("uname", "-s"): "Linux\n", ("uname", "-r"): "6.8.0-79-generic\n", ("uname", "-m"): "x86_64\n", ("stat", "-fc", "%T", "/sys/fs/cgroup"): "cgroup2fs\n",
        ("podman", "--version"): "podman version 5.0.0\n", ("id", "-un"): "operator\n",
        ("podman", "images", "--format", "json"): "[]\n", ("systemctl", "--user", "list-units", "--all", "--plain", "--no-legend"): "\n",
    }

    def run(argv: list[str] | tuple[str, ...]) -> guest.Completed:
        key = tuple(argv)
        if key == ("podman", "info", "--format", "json"):
            return guest.Completed(0, json.dumps({"host": podman_host}) + "\n")
        if key == ("systemctl", "--user", "is-system-running"):
            return guest.Completed(0, "running\n")
        return guest.Completed(0, outputs.get(key, ""))

    def read(path: Path) -> bytes:
        if str(path) == "/etc/os-release":
            return b'ID=ubuntu\nVERSION_ID="24.04"\n'
        if str(path) in {"/etc/subuid", "/etc/subgid"}:
            return b"operator:100000:65536\n"
        return b""

    _, facts = guest._facts(
        stage,
        run,
        read,
        lambda path: str(path) == "/usr/libexec/podman/quadlet",
    )
    assert facts["rootlessPodman"] is True
    assert facts["wslDetected"] is False
    assert facts["eligible"] is True


def test_capability_probe_refuses_wsl_even_when_every_runtime_capability_matches() -> None:
    stage = _stage()
    outputs = {
        ("uname", "-s"): "Linux\n",
        ("uname", "-r"): "6.6.87.2-microsoft-standard-WSL2\n",
        ("uname", "-m"): "x86_64\n",
        ("stat", "-fc", "%T", "/sys/fs/cgroup"): "cgroup2fs\n",
        ("podman", "--version"): "podman version 5.0.0\n",
        ("id", "-un"): "operator\n",
        ("podman", "images", "--format", "json"): "[]\n",
        ("systemctl", "--user", "list-units", "--all", "--plain", "--no-legend"): "\n",
    }

    def run(argv: list[str] | tuple[str, ...]) -> guest.Completed:
        key = tuple(argv)
        if key == ("podman", "info", "--format", "json"):
            return guest.Completed(0, '{"host":{"rootless":true}}\n')
        if key == ("systemctl", "--user", "is-system-running"):
            return guest.Completed(0, "running\n")
        return guest.Completed(0, outputs.get(key, ""))

    def read(path: Path) -> bytes:
        if str(path) == "/etc/os-release":
            return b'ID=ubuntu\nVERSION_ID="24.04"\n'
        if str(path) in {"/etc/subuid", "/etc/subgid"}:
            return b"operator:100000:65536\n"
        return b""

    with pytest.raises(guest.GuestStageRefusal, match="wsl_substrate_unqualified"):
        guest._facts(
            stage,
            run,
            read,
            lambda path: str(path) == "/usr/libexec/podman/quadlet",
        )


@pytest.mark.parametrize(
    "podman_info",
    [
        {"host": {"rootless": True, "security": {"rootless": False}}},
        {"host": {"rootless": "false", "security": {"rootless": True}}},
        {"host": {"rootless": True, "security": "invalid"}},
        {"host": "invalid", "rootless": True},
    ],
)
def test_capability_probe_refuses_invalid_rootless_podman_observations(
    podman_info: dict[str, object],
) -> None:
    stage = _stage()

    def run(argv: list[str] | tuple[str, ...]) -> guest.Completed:
        key = tuple(argv)
        if key == ("podman", "info", "--format", "json"):
            return guest.Completed(0, json.dumps(podman_info) + "\n")
        if key == ("systemctl", "--user", "is-system-running"):
            return guest.Completed(0, "running\n")
        outputs = {
            ("uname", "-s"): "Linux\n", ("uname", "-r"): "6.8.0-79-generic\n", ("uname", "-m"): "x86_64\n", ("stat", "-fc", "%T", "/sys/fs/cgroup"): "cgroup2fs\n",
            ("podman", "--version"): "podman version 5.0.0\n", ("id", "-un"): "operator\n",
            ("podman", "images", "--format", "json"): "[]\n", ("systemctl", "--user", "list-units", "--all", "--plain", "--no-legend"): "\n",
        }
        return guest.Completed(0, outputs.get(key, ""))

    def read(path: Path) -> bytes:
        if str(path) == "/etc/os-release":
            return b'ID=ubuntu\nVERSION_ID="24.04"\n'
        if str(path) in {"/etc/subuid", "/etc/subgid"}:
            return b"operator:100000:65536\n"
        return b""

    with pytest.raises(guest.GuestStageRefusal, match="required Linux capability"):
        guest._facts(
            stage,
            run,
            read,
            lambda path: str(path) == "/usr/libexec/podman/quadlet",
        )


def test_fixture_mode_is_not_qualifying_evidence(tmp_path: Path) -> None:
    config = _config(tmp_path)
    fixture_input = tmp_path / "fixture.json"
    fixture_input.write_text(json.dumps({"receipt": {"schema": guest.FORMAT}}), encoding="utf-8")
    receipt = guest._fixture(fixture_input, tmp_path / "fixture-evidence", tmp_path / "fixture-receipt.json")
    assert receipt["evidenceClass"] == "fixture"
    config["candidate"] = receipt.get("candidate", _candidate())
    with pytest.raises(contract.QualificationRefusal, match="fixture or simulated"):
        contract.validate_receipt(receipt, config)


def test_user_image_cleanup_uses_every_signed_digest_reference() -> None:
    references = [
        "registry.example/api@sha256:" + "1" * 64,
        "registry.example/worker@sha256:" + "2" * 64,
    ]
    present = set(references)
    calls: list[list[str]] = []

    def run(argv: list[str] | tuple[str, ...]) -> guest.Completed:
        command = list(argv)
        calls.append(command)
        reference = command[-1]
        if command[1:3] == ["image", "exists"]:
            return guest.Completed(0 if reference in present else 1)
        if command[1:3] == ["image", "rm"]:
            present.remove(reference)
            return guest.Completed(0)
        return guest.Completed(255, stderr="unexpected command")

    guest._remove_user_images(references, run)
    assert not present
    assert [call for call in calls if call[1:3] == ["image", "rm"]] == [
        ["podman", "image", "rm", reference] for reference in references
    ]


@pytest.mark.parametrize("returncode", [2, 125, 255])
def test_user_image_cleanup_refuses_probe_errors(returncode: int) -> None:
    def run(_argv: list[str] | tuple[str, ...]) -> guest.Completed:
        return guest.Completed(returncode, stderr="probe failed")

    with pytest.raises(guest.GuestStageRefusal, match="probe failed"):
        guest._remove_user_images(
            ["registry.example/api@sha256:" + "1" * 64], run
        )


def test_user_owned_absence_requires_exact_inactive_service_status() -> None:
    stage = _stage()
    stage["ownedPaths"] = [guest.PROVISIONER]
    stage["ownedServices"] = ["stateport.service"]

    with pytest.raises(guest.GuestStageRefusal, match="absence probe failed"):
        guest._user_owned_absent(
            stage,
            lambda _path: False,
            lambda _argv: guest.Completed(4, "unknown\n"),
        )

    guest._user_owned_absent(
        stage,
        lambda _path: False,
        lambda _argv: guest.Completed(3, "inactive\n"),
    )
