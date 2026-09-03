#!/usr/bin/env python3
"""Execute the Ubuntu 24.04 qualification journey inside the guest.

This is intentionally a small argv-based adapter around the existing release
verification, root provisioner, installer, and protocol contracts.  It does
not manufacture evidence when a guest capability or lifecycle observation is
missing.  ``--fixture`` is test-only evidence and is never real_guest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Callable, Mapping, Sequence

try:
    from . import ubuntu2404_stage as contract
except ImportError:  # direct execution on a clean guest
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from infra.qualification import ubuntu2404_stage as contract


ROOT = Path(__file__).resolve().parents[2]
FORMAT = "stateport.qualification.ubuntu2404-receipt/v1"
PROVISIONER = "/usr/local/libexec/stateport-execution-host-provision"
PODMAN_FLOOR = (5, 0, 0)
STAGES = (
    "capability_evaluation",
    "provisioning",
    "install",
    "protocol_health",
    "persistence_reboot",
    "reinstall_convergence",
    "cleanup",
)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class GuestStageRefusal(ValueError):
    """The guest stage cannot safely produce qualification evidence."""


class Completed:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


Runner = Callable[[Sequence[str]], Completed]
ReadFile = Callable[[Path], bytes]
Exists = Callable[[Path], bool]
Stat = Callable[[Path], os.stat_result]


def _canonical(value: object) -> bytes:
    return json.dumps(value, allow_nan=False, sort_keys=True, separators=(",", ":")).encode()


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _digest_file(path: Path, label: str) -> str:
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise GuestStageRefusal(f"{label} is unavailable or symlinked: {path}") from exc
    if path.is_symlink() or not path.is_file() or resolved != path.absolute():
        raise GuestStageRefusal(f"{label} is unavailable or symlinked: {path}")
    return _digest_bytes(path.read_bytes())


def _json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise GuestStageRefusal(f"{label} is not readable JSON: {exc}") from exc
    if not isinstance(value, Mapping):
        raise GuestStageRefusal(f"{label} is not a JSON object")
    return dict(value)


def _write_json(path: Path, value: Mapping[str, Any]) -> str:
    if path.is_symlink() or path.exists() and not path.is_file():
        raise GuestStageRefusal(f"refusing unsafe evidence path: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    data = _canonical(value) + b"\n"
    path.write_bytes(data)
    return _digest_bytes(data)


def _placeholder(value: str, label: str) -> None:
    raw = value.removeprefix("sha256:")
    if raw and len(set(raw)) == 1:
        raise GuestStageRefusal(f"{label} is a placeholder")


def _is_placeholder(value: str) -> bool:
    raw = value.removeprefix("sha256:")
    return bool(raw) and len(set(raw)) == 1


def _run(runner: Runner, argv: Sequence[str], label: str) -> Completed:
    if not argv or any(not isinstance(item, str) or not item for item in argv):
        raise GuestStageRefusal(f"{label} is not an explicit argv")
    result = runner(argv)
    if result.returncode != 0:
        raise GuestStageRefusal(f"{label} failed with exit {result.returncode}: {result.stderr[-300:]}")
    return result


def _one_json(result: Completed, label: str) -> dict[str, Any]:
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise GuestStageRefusal(f"{label} did not emit one JSON object: {exc}") from exc
    if not isinstance(value, Mapping):
        raise GuestStageRefusal(f"{label} did not emit one JSON object")
    return dict(value)


def _version(value: str) -> tuple[int, ...] | None:
    match = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", value)
    return tuple(int(part) for part in match.groups(default="0")) if match else None


def _argv(spec: Mapping[str, Any], name: str, values: Mapping[str, str]) -> list[str]:
    raw = spec.get(name)
    if not isinstance(raw, list) or not raw or any(not isinstance(item, str) or not item for item in raw):
        raise GuestStageRefusal(f"guestStage.{name} must be an explicit argv")
    try:
        return [item.format(**values) for item in raw]
    except KeyError as exc:
        raise GuestStageRefusal(f"guestStage.{name} has an unknown placeholder: {exc}") from exc


def _require_option(argv: Sequence[str], flag: str, value: str, label: str) -> None:
    if argv.count(flag) != 1:
        raise GuestStageRefusal(f"{label} must contain exactly one {flag}")
    position = argv.index(flag)
    if position + 1 >= len(argv) or argv[position + 1] != value:
        raise GuestStageRefusal(f"{label} must bind {flag} to the configured value")


def _require_command_shape(stage: Mapping[str, Any], values: Mapping[str, str]) -> None:
    provisioner_install = _argv(stage, "provisionerInstallArgv", values)
    if provisioner_install != [
        "sudo",
        "-n",
        "install",
        "-D",
        "-o",
        "root",
        "-g",
        "root",
        "-m",
        "0555",
        values["execution_host_provisioner"],
        PROVISIONER,
    ]:
        raise GuestStageRefusal(
            "provisionerInstallArgv must install only the verified provisioner at the fixed root path"
        )
    if _argv(stage, "rootPreflightArgv", values) != [
        "sudo",
        "-n",
        PROVISIONER,
        "qualification-preflight",
    ]:
        raise GuestStageRefusal(
            "rootPreflightArgv must invoke only the fixed provisioner qualification preflight"
        )
    materialize = _argv(stage, "materializeArgv", values)
    materialize_command = materialize[2:] if materialize[:2] == ["sudo", "-n"] else materialize
    expected_materialize = [
        PROVISIONER,
        "materialize",
        "--execution-host-provisioner",
        PROVISIONER,
        "--execution-host-provisioner-digest",
        values["execution_host_provisioner_digest"],
        "--execution-host-provisioner-bytes",
        values["execution_host_provisioner_bytes"],
        "--updater-wheel",
        values["updater_wheel"],
        "--updater-wheel-digest",
        values["updater_wheel_digest"],
        "--release-index",
        values["release_index"],
        "--bundle-root",
        values["bundle_root"],
        "--cosign",
        values["cosign"],
        "--cosign-digest",
        values["cosign_digest"],
        "--trust-public-key",
        values["public_key"],
        "--trust-public-key-digest",
        values["public_key_digest"],
        "--trust-key-id",
        values["key_id"],
        "--trust-key-fingerprint",
        values["public_key_fingerprint"],
    ]
    if materialize_command != expected_materialize:
        raise GuestStageRefusal(
            "materializeArgv must exactly invoke the fixed root provisioner materialization boundary"
        )
    provision = _argv(stage, "provisionArgv", values)
    provision_command = provision[2:] if provision[:2] == ["sudo", "-n"] else provision
    expected_provision = [
        PROVISIONER,
        "provision",
        "--release-index",
        values["release_index"],
        "--bundle-root",
        values["bundle_root"],
        "--cosign",
        values["cosign"],
        "--trust-public-key",
        values["public_key"],
        "--trust-key-id",
        values["key_id"],
        "--trust-key-fingerprint",
        values["public_key_fingerprint"],
        "--channel",
        values["channel"],
        "--receipt-out",
        values["provision_receipt"],
    ]
    if provision_command != expected_provision:
        raise GuestStageRefusal(
            "provisionArgv must exactly invoke the fixed root provisioner"
        )
    health = _argv(stage, "healthArgv", values)
    health_command = health[2:] if health[:2] == ["sudo", "-n"] else health
    if health_command != [PROVISIONER, "health-probe", "--socket", values["socket"]]:
        raise GuestStageRefusal("healthArgv must invoke the fixed live protocol probe")
    install = _argv(stage, "installArgv", values)
    expected_install = [
        values["installer"],
        "--release-index",
        values["release_index"],
        "--bundle-root",
        values["bundle_root"],
        "--cosign",
        values["cosign"],
        "--trust-public-key",
        values["public_key"],
        "--trust-key-id",
        values["key_id"],
        "--trust-key-fingerprint",
        values["public_key_fingerprint"],
        "--channel",
        values["channel"],
        "--updater-wheel",
        values["updater_wheel"],
        "--execution-host-provisioner",
        values["execution_host_provisioner"],
        "--compose",
        values["compose"],
        "--source-archive",
        values["source_archive"],
        "--release-notes",
        values["release_notes"],
        "--known-limitations",
        values["known_limitations"],
        "--execution-host-receipt",
        values["provision_receipt"],
        "--yes",
    ]
    if install != expected_install:
        raise GuestStageRefusal(
            "installArgv must exactly invoke the candidate installer and signed artifacts"
        )
    if _argv(stage, "uninstallArgv", values) != [values["installer"], "--uninstall"]:
        raise GuestStageRefusal("uninstallArgv must be the installer uninstall mode")
    purge_values = {**values, "confirm_purge": "{confirm_purge}"}
    if _argv(stage, "purgeArgv", purge_values) != [
        values["installer"],
        "--purge",
        "--confirm-purge",
        "{confirm_purge}",
    ]:
        raise GuestStageRefusal("purgeArgv must be the explicit installer purge mode")
    if _argv(stage, "rootCleanupArgv", values) != [
        "sudo",
        "-n",
        PROVISIONER,
        "qualification-cleanup",
        "--release-index",
        values["release_index"],
        "--bundle-root",
        values["bundle_root"],
        "--receipt",
        values["provision_receipt"],
    ]:
        raise GuestStageRefusal(
            "rootCleanupArgv must invoke only the fixed provisioner qualification cleanup"
        )
    restart = _argv(stage, "restartArgv", values)
    if not (
        len(restart) == 4 and restart[:3] == ["systemctl", "--user", "restart"]
        or restart == ["sudo", "-n", "reboot"]
    ):
        raise GuestStageRefusal("restartArgv must perform an actual service restart or reboot")
    journey = _argv(stage, "journeyArgv", values)
    if (
        not any("{phase}" in item for item in stage["journeyArgv"])
        or not Path(journey[0]).name.startswith("studystate-")
        or journey[1:] != ["--application", "StudyState", "--phase", values.get("phase", "{phase}")]
    ):
        raise GuestStageRefusal("journeyArgv must identify StudyState and support phase substitution")


def _candidate(
    config: Mapping[str, Any], manifest: Path | None
) -> tuple[dict[str, Any], list[str]]:
    if manifest is not None:
        raise GuestStageRefusal(
            "verified-candidate manifests are not qualification authority; verify exact inputs now"
        )
    try:
        validated = contract.validate_config(config)
    except Exception as exc:
        raise GuestStageRefusal(f"existing release verification contract refused candidate: {exc}") from exc
    candidate = validated["candidate"]
    for value, label in ((candidate["releaseIndexDigest"], "release index"), (candidate["signedPayloadDigest"], "signed payload"), (candidate["installerDigest"], "installer")):
        _placeholder(str(value), label)
    references = validated.get("_signedImageReferences")
    if (
        not isinstance(references, list)
        or not references
        or any(not isinstance(reference, str) or not reference for reference in references)
    ):
        raise GuestStageRefusal("verified candidate has no signed image references")
    return dict(candidate), list(references)


def _facts(
    stage: Mapping[str, Any], runner: Runner, read_file: ReadFile, exists: Exists
) -> tuple[dict[str, Any], dict[str, Any]]:
    def out(argv: Sequence[str], label: str) -> str:
        return _run(runner, argv, label).stdout.strip()

    os_release: dict[str, str] = {}
    for line in read_file(Path("/etc/os-release")).decode("utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            os_release[key] = value.strip().strip('"')
    kernel = out(["uname", "-s"], "Linux kernel probe")
    kernel_release = out(["uname", "-r"], "Linux kernel release probe")
    architecture = out(["uname", "-m"], "architecture probe")
    cgroup = out(["stat", "-fc", "%T", "/sys/fs/cgroup"], "cgroup probe")
    podman_version = out(["podman", "--version"], "Podman version probe")
    info = _one_json(_run(runner, ["podman", "info", "--format", "json"], "Podman info probe"), "Podman info")
    host = info.get("host") if "host" in info else info
    rootless_observations: list[bool] = []
    rootless_shape_valid = isinstance(host, Mapping)
    if isinstance(host, Mapping):
        if "rootless" in host:
            rootless_shape_valid = rootless_shape_valid and isinstance(host["rootless"], bool)
            if isinstance(host["rootless"], bool):
                rootless_observations.append(host["rootless"])
        if "security" in host:
            security = host["security"]
            rootless_shape_valid = rootless_shape_valid and isinstance(security, Mapping)
            if isinstance(security, Mapping) and "rootless" in security:
                rootless_shape_valid = rootless_shape_valid and isinstance(security["rootless"], bool)
                if isinstance(security["rootless"], bool):
                    rootless_observations.append(security["rootless"])
    rootless = rootless_shape_valid and bool(rootless_observations) and all(rootless_observations)
    systemd = _run(runner, ["systemctl", "--user", "is-system-running"], "systemd-user probe")
    user = out(["id", "-un"], "user probe")
    def has_mapping(path: Path) -> bool:
        return any(
            line.split(":", 1)[0] == user
            for line in read_file(path).decode("utf-8", errors="replace").splitlines()
            if ":" in line
        )

    subuid = has_mapping(Path("/etc/subuid"))
    subgid = has_mapping(Path("/etc/subgid"))
    quadlet = any(exists(Path(path)) for path in ("/usr/libexec/podman/quadlet", "/usr/lib/podman/quadlet", "/usr/lib/systemd/user-generators/podman-user-generator"))
    images = _run(runner, ["podman", "images", "--format", "json"], "Podman image inventory")
    services = _run(runner, ["systemctl", "--user", "list-units", "--all", "--plain", "--no-legend"], "service inventory")
    image_text = images.stdout.lower()
    service_text = services.stdout.lower()
    checkout_paths = [Path(item) for item in stage["checkoutPaths"]]
    checkout = any(exists(path) or exists(path / ".git") for path in checkout_paths)
    prior_state = any(
        exists(Path(path))
        for path in (stage["stateRoot"], stage["liveQuadletRoot"], *stage["ownedPaths"])
    )
    try:
        proc_version = read_file(Path("/proc/version")).decode(
            "utf-8", errors="replace"
        )
    except OSError:
        proc_version = ""
    wsl_detected = any(
        "microsoft" in value.casefold() for value in (kernel_release, proc_version)
    )
    facts = {
        "kernel": kernel,
        "kernelRelease": kernel_release,
        "wslDetected": wsl_detected,
        "architecture": architecture,
        "cgroupVersion": "v2" if cgroup == "cgroup2fs" else cgroup,
        "podmanVersion": podman_version.removeprefix("podman version ").strip(),
        "podmanVersionMeetsFloor": _version(podman_version) is not None and _version(podman_version) >= PODMAN_FLOOR,
        "rootlessPodman": rootless,
        "quadlet": quadlet,
        "systemdUserServices": systemd.returncode == 0,
        "subuidMapping": subuid,
        "subgidMapping": subgid,
    }
    facts["eligible"] = all((kernel == "Linux", bool(kernel_release), not wsl_detected, architecture in {"x86_64", "amd64"}, facts["cgroupVersion"] == "v2", facts["podmanVersionMeetsFloor"], rootless, quadlet, facts["systemdUserServices"], subuid, subgid))
    guest = {"osRelease": os_release, "checkoutPresent": checkout, "preExistingState": prior_state, "preExistingImages": "stateport" in image_text, "preExistingServices": "stateport" in service_text, "facts": facts}
    if os_release.get("ID") != "ubuntu" or os_release.get("VERSION_ID") != "24.04":
        raise GuestStageRefusal("guest is not Ubuntu 24.04")
    if wsl_detected:
        raise GuestStageRefusal("wsl_substrate_unqualified")
    if checkout or prior_state or guest["preExistingImages"] or guest["preExistingServices"]:
        raise GuestStageRefusal(
            "guest is not clean: checkout, state, image, or service residue observed"
        )
    if not facts["eligible"]:
        raise GuestStageRefusal("guest lacks a required Linux capability")
    return guest, facts


def _root_owned(path: Path, stat_fn: Stat) -> None:
    try:
        observed = stat_fn(path)
    except OSError as exc:
        raise GuestStageRefusal(f"root-owned provisioning receipt is unavailable: {path}") from exc
    if (
        path.is_symlink()
        or observed.st_uid != 0
        or observed.st_gid != 0
        or stat.S_IMODE(observed.st_mode) != 0o644
    ):
        raise GuestStageRefusal("provisioning receipt is not root-owned and non-writable")


def _root_owned_executable(path: Path, stat_fn: Stat) -> None:
    try:
        observed = stat_fn(path)
    except OSError as exc:
        raise GuestStageRefusal(f"root-owned provisioner is unavailable: {path}") from exc
    if (
        path.is_symlink()
        or observed.st_uid != 0
        or observed.st_gid != 0
        or stat.S_IMODE(observed.st_mode) != 0o555
    ):
        raise GuestStageRefusal("installed provisioner is not root-owned and non-writable")


def _safe_root_directory(path: Path, lstat_fn: Stat) -> None:
    try:
        observed = lstat_fn(path)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise GuestStageRefusal(f"provisioner path directory is unavailable: {path}") from exc
    if stat.S_ISLNK(observed.st_mode):
        raise GuestStageRefusal(f"unsafe symlink in provisioner path: {path}")
    if (
        not stat.S_ISDIR(observed.st_mode)
        or observed.st_uid != 0
        or observed.st_gid != 0
        or stat.S_IMODE(observed.st_mode) & 0o022
    ):
        raise GuestStageRefusal(f"provisioner path directory is unsafe: {path}")


def _safe_provisioner_parent_exists(path: Path, lstat_fn: Stat) -> bool:
    for ancestor in reversed(path.parents):
        _safe_root_directory(ancestor, lstat_fn)
    try:
        _safe_root_directory(path, lstat_fn)
    except FileNotFoundError:
        return False
    return True


def _remove_created_provisioner_parent(
    path: Path, preexisting: bool, runner: Runner, exists: Exists
) -> bool:
    if preexisting:
        return False
    _run(runner, ["sudo", "-n", "/usr/bin/rmdir", str(path)], "provisioner parent cleanup")
    if exists(path) or path.is_symlink():
        raise GuestStageRefusal("qualification-created provisioner parent remains")
    return True


def _receipt_digest(path: Path, label: str) -> str:
    digest = _digest_file(path, label)
    _placeholder(digest, label)
    return digest


def _user_owned_absent(stage: Mapping[str, Any], exists: Exists, runner: Runner) -> None:
    user_paths = [path for path in stage["ownedPaths"] if path != PROVISIONER]
    if any(exists(Path(path)) for path in user_paths):
        raise GuestStageRefusal("owned resource remains after cleanup")
    root_services = {"stateport-execution-host.service", "podman.socket"}
    for service in (item for item in stage["ownedServices"] if item not in root_services):
        result = runner(["systemctl", "--user", "is-active", service])
        if result.returncode == 0:
            raise GuestStageRefusal(f"owned service remains active: {service}")
        if result.returncode != 3 or result.stdout.strip() != "inactive":
            raise GuestStageRefusal(f"owned service absence probe failed: {service}")


def _remove_user_images(references: Sequence[str], runner: Runner) -> None:
    for reference in references:
        before = runner(["podman", "image", "exists", reference])
        if before.returncode == 0:
            _run(runner, ["podman", "image", "rm", reference], "owned image cleanup")
        elif before.returncode != 1:
            raise GuestStageRefusal(f"owned image pre-cleanup probe failed: {reference}")
        after = runner(["podman", "image", "exists", reference])
        if after.returncode == 0:
            raise GuestStageRefusal(f"owned image remains: {reference}")
        if after.returncode != 1:
            raise GuestStageRefusal(f"owned image absence probe failed: {reference}")


def _run_journey(stage: Mapping[str, Any], runner: Runner, phase: str, values: Mapping[str, str]) -> dict[str, Any]:
    journey_values = {**values, "phase": phase}
    result = _one_json(_run(runner, _argv(stage, "journeyArgv", journey_values), f"StudyState {phase} journey"), f"StudyState {phase} journey")
    if result.get("result") != "passed" or result.get("application") != "StudyState" or not isinstance(result.get("stateDigest"), str) or not _DIGEST.fullmatch(result["stateDigest"]):
        raise GuestStageRefusal(f"StudyState {phase} journey did not prove durable state")
    return result


def run_guest(
    config: Mapping[str, Any], output: Path, *, runner: Runner | None = None,
    read_file: ReadFile | None = None, exists: Exists | None = None, stat_fn: Stat | None = None,
    verified_manifest: Path | None = None,
) -> dict[str, Any]:
    runner = runner or (lambda argv: _subprocess(argv))
    read_file = read_file or (lambda path: path.read_bytes())
    exists = exists or (lambda path: path.exists() and not path.is_symlink())
    stat_fn = stat_fn or (lambda path: path.lstat())
    candidate, signed_image_references = _candidate(config, verified_manifest)
    stage = config.get("guestStage")
    if not isinstance(stage, Mapping):
        raise GuestStageRefusal("guestStage configuration is required")
    release_index = Path(str(config["artifacts"]["releaseIndex"]["path"]))
    predecessor_bundle = Path(
        str(config["verification"]["predecessorSignatureBundle"]["path"])
    )
    if (
        predecessor_bundle.parent.name != "predecessor-bundle"
        or predecessor_bundle.parent.parent != release_index.parent
    ):
        raise GuestStageRefusal(
            "predecessor signature bundle is outside the release bundle root"
        )
    values = {
        "installer": str(config["artifacts"]["installer"]["path"]),
        "release_index": str(release_index),
        "provision_receipt": str(stage["provisionReceiptPath"]),
        "state_root": str(stage["stateRoot"]),
        "live_quadlet_root": str(stage["liveQuadletRoot"]),
        "socket": "{socket}",
        "bundle_root": str(release_index.parent),
        "cosign": str(config["verification"]["cosign"]["path"]),
        "public_key": str(config["verification"]["publicKey"]["path"]),
        "key_id": str(config["verification"]["keyId"]),
        "public_key_fingerprint": str(config["verification"]["publicKeyFingerprint"]),
        "channel": "alpha",
        "updater_wheel": str(release_index.parent / "artifacts" / "updater"),
        "updater_wheel_digest": str(
            config.get("artifacts", {}).get("updater", {}).get("sha256", "")
        ),
        "cosign_digest": str(config["verification"]["cosign"]["sha256"]),
        "public_key_digest": str(config["verification"]["publicKey"]["sha256"]),
        "execution_host_provisioner": str(
            config["artifacts"]["executionHostProvisioner"]["path"]
        ),
        "execution_host_provisioner_digest": str(
            config["artifacts"]["executionHostProvisioner"]["sha256"]
        ),
        "execution_host_provisioner_bytes": str(
            Path(str(config["artifacts"]["executionHostProvisioner"]["path"])).stat().st_size
        ),
        "compose": str(release_index.parent / "compose.release.yaml"),
        "source_archive": str(release_index.parent / "artifacts" / "sourceArchive"),
        "release_notes": str(release_index.parent / "artifacts" / "releaseNotes"),
        "known_limitations": str(
            release_index.parent / "artifacts" / "knownLimitations"
        ),
        "phase": "{phase}",
    }
    _require_command_shape(stage, values)
    guest, facts = _facts(stage, runner, read_file, exists)
    output.mkdir(parents=True, exist_ok=False)
    machine = read_file(Path("/etc/machine-id")).strip()
    boot = read_file(Path("/proc/sys/kernel/random/boot_id")).strip()
    if not machine or not boot:
        raise GuestStageRefusal("guest identity is incomplete")
    identity = {"machineIdDigest": _digest_bytes(machine), "bootIdDigest": _digest_bytes(boot), "osRelease": guest["osRelease"], "facts": facts}
    identity_digest = _digest_bytes(_canonical(identity))
    stage_records: list[dict[str, Any]] = []

    def stage_file(stage_id: str, body: Mapping[str, Any]) -> str:
        path = output / f"{stage_id}.json"
        receipt_body = {
            "schema": FORMAT + ".evidence",
            "stageId": stage_id,
            "candidate": candidate,
            "guestId": config["guest"]["guestId"],
            "guestIdentityDigest": identity_digest,
            **dict(body),
        }
        digest = _write_json(path, receipt_body)
        stage_records.append({"stageId": stage_id, "result": "passed", "receiptDigest": digest})
        return digest

    stage_file("capability_evaluation", {"facts": facts})
    installed_provisioner = Path(PROVISIONER)
    provisioner_parent = installed_provisioner.parent
    provisioner_parent_preexisting = _safe_provisioner_parent_exists(
        provisioner_parent, stat_fn
    )
    if installed_provisioner.exists() or installed_provisioner.is_symlink():
        raise GuestStageRefusal("clean guest already contains the fixed root provisioner path")
    _run(runner, _argv(stage, "provisionerInstallArgv", values), "root helper installation")
    if not _safe_provisioner_parent_exists(provisioner_parent, stat_fn):
        raise GuestStageRefusal("root helper installation did not create its safe parent")
    _root_owned_executable(installed_provisioner, stat_fn)
    if _digest_file(installed_provisioner, "installed execution-host provisioner") != values[
        "execution_host_provisioner_digest"
    ]:
        raise GuestStageRefusal("installed execution-host provisioner digest changed")
    preflight = _one_json(
        _run(runner, _argv(stage, "rootPreflightArgv", values), "root clean-host preflight"),
        "root clean-host preflight",
    )
    if preflight != {"schema": "stateport.qualification-clean-host/v1", "clean": True}:
        raise GuestStageRefusal("root clean-host preflight did not prove a clean execution host")
    _run(runner, _argv(stage, "materializeArgv", values), "root helper materialization")
    provision_argv = _argv(stage, "provisionArgv", values)
    _run(runner, provision_argv, "execution-host provisioning")
    provision_path = Path(str(stage["provisionReceiptPath"]))
    _root_owned(provision_path, stat_fn)
    provision = _json(provision_path, "execution-host provisioning receipt")
    if provision.get("schema") != "stateport.execution-host-provisioning-receipt/v1" or provision.get("result") != "succeeded":
        raise GuestStageRefusal("provisioning receipt does not prove success")
    expected_provisioning_identity = {
        "releaseIndexDigest": candidate["releaseIndexDigest"],
        "signedPayloadDigest": candidate["signedPayloadDigest"],
        "sourceCommit": candidate["sourceCommit"],
        "sourceTree": candidate["sourceTree"],
        "installerDigest": candidate["installerDigest"],
    }
    if any(provision.get(key) != value for key, value in expected_provisioning_identity.items()):
        raise GuestStageRefusal("provisioning receipt is not bound to the exact candidate")
    health = provision.get("health")
    if not isinstance(health, Mapping) or health.get("kind") != "describeCapabilities" or health.get("healthy") is not True:
        raise GuestStageRefusal("provisioning receipt lacks live describeCapabilities proof")
    provision_digest = _receipt_digest(provision_path, "provisioning receipt")
    image = provision.get("image") if isinstance(provision.get("image"), Mapping) else {}
    execution = {"digest": provision_digest, "imageId": str(image.get("imageId", "")), "sourceCommit": str(provision["sourceCommit"]), "sourceTree": str(provision["sourceTree"]), "imageDigest": str(image.get("expectedDigest", "")), "installerDigest": str(provision["installerDigest"]), "protocolHealth": {"describeCapabilities": True, "result": "passed", "receiptDigest": provision_digest}}
    if execution["imageDigest"] not in candidate["imageDigests"]:
        raise GuestStageRefusal("provisioning image is not candidate-bound")
    stage_file("provisioning", {"argv": provision_argv, "receiptPath": str(provision_path), "receiptDigest": provision_digest})
    install_before = set(Path(str(stage["stateRoot"])).glob("receipts/install_receipt_*.json")) if Path(str(stage["stateRoot"])).is_dir() else set()
    _run(runner, _argv(stage, "installArgv", values), "candidate installer")
    install_receipts = sorted(Path(str(stage["stateRoot"])).glob("receipts/install_receipt_*.json"))
    new_install = [path for path in install_receipts if path not in install_before and not path.is_symlink()]
    if not new_install:
        raise GuestStageRefusal("installer did not produce a new install receipt")
    install_path = new_install[-1]
    install = _json(install_path, "install receipt")
    if install.get("releaseIndexDigest") != candidate["releaseIndexDigest"] or install.get("release", {}).get("signedPayloadDigest") != candidate["signedPayloadDigest"]:
        raise GuestStageRefusal("install receipt is not candidate-bound")
    install_digest = _receipt_digest(install_path, "install receipt")
    stage_file("install", {"receiptPath": str(install_path), "receiptDigest": install_digest})
    socket_path = str(health.get("socketPath", ""))
    health_values = {**values, "socket": socket_path}
    live_health = _one_json(_run(runner, _argv(stage, "healthArgv", health_values), "live protocol health"), "live protocol health")
    if live_health.get("healthy") is not True:
        raise GuestStageRefusal("live describeCapabilities request did not pass")
    stage_file("protocol_health", {"argv": _argv(stage, "healthArgv", health_values), "health": live_health, "receiptDigest": _digest_bytes(_canonical(live_health))})
    journey = _run_journey(stage, runner, "install", values)
    _run(runner, _argv(stage, "restartArgv", values), "service restart")
    reread = _run_journey(stage, runner, "reread", values)
    if reread["stateDigest"] != journey["stateDigest"]:
        raise GuestStageRefusal("StudyState durable state changed across restart")
    stage_file("persistence_reboot", {"schema": FORMAT + ".evidence", "stageId": "persistence_reboot", "journey": journey, "reread": reread})
    install_identity = _json(Path(str(stage["stateRoot"])) / "updater" / "trust" / "install-trust.json", "install identity")
    installed_identity_id = install_identity.get("installedIdentityId")
    if not isinstance(installed_identity_id, str) or not installed_identity_id:
        raise GuestStageRefusal("install trust record lacks installedIdentityId")
    _run(runner, _argv(stage, "uninstallArgv", values), "safe uninstall")
    if any(not exists(Path(path)) for path in stage["preservedPaths"]):
        raise GuestStageRefusal("uninstall did not preserve the declared paths")
    _user_owned_absent(stage, exists, runner)
    _run(runner, _argv(stage, "purgeArgv", values | {"confirm_purge": installed_identity_id}), "owned purge")
    if exists(Path(str(stage["stateRoot"]))):
        raise GuestStageRefusal("purge did not delete the owned state root")
    _run(runner, _argv(stage, "installArgv", values), "candidate reinstall")
    reinstall_health = _one_json(_run(runner, _argv(stage, "healthArgv", {**values, "socket": socket_path}), "reinstall protocol health"), "reinstall protocol health")
    if reinstall_health.get("healthy") is not True:
        raise GuestStageRefusal("reinstall live describeCapabilities request did not pass")
    reinstall_journey = _run_journey(stage, runner, "reinstall", values)
    if reinstall_journey["stateDigest"] != journey["stateDigest"]:
        raise GuestStageRefusal("StudyState state did not converge after reinstall")
    stage_file("reinstall_convergence", {"journey": reinstall_journey, "health": reinstall_health, "stateRootDeleted": True})
    final_identity = _json(Path(str(stage["stateRoot"])) / "updater" / "trust" / "install-trust.json", "reinstall identity")
    final_identity_id = final_identity.get("installedIdentityId")
    if not isinstance(final_identity_id, str) or not final_identity_id:
        raise GuestStageRefusal("reinstall trust record lacks installedIdentityId")
    _run(runner, _argv(stage, "uninstallArgv", values), "final owned cleanup")
    _run(runner, _argv(stage, "purgeArgv", values | {"confirm_purge": final_identity_id}), "final owned purge")
    _user_owned_absent(stage, exists, runner)
    _remove_user_images(signed_image_references, runner)
    root_cleanup = _one_json(
        _run(runner, _argv(stage, "rootCleanupArgv", values), "final root-owned cleanup"),
        "final root-owned cleanup",
    )
    expected_cleanup = {
        "schema": "stateport.qualification-root-cleanup/v1",
        "accountsRemoved": True,
        "groupsRemoved": True,
        "imageRemoved": True,
        "rootArtifactsRemoved": True,
        "servicesRemoved": True,
        "subordinateMappingsRemoved": True,
    }
    if root_cleanup != expected_cleanup:
        raise GuestStageRefusal("root cleanup did not prove every execution-host postcondition")
    provisioner_parent_removed = _remove_created_provisioner_parent(
        provisioner_parent, provisioner_parent_preexisting, runner, exists
    )
    for path in (
        PROVISIONER,
        "/usr/local/lib/stateport/provisioning",
        "/usr/local/lib/stateport/tools/cosign",
        "/etc/stateport/alpha-2026-08-cosign.pub",
        "/etc/stateport/execution-host-provisioning.manifest",
    ):
        if exists(Path(path)):
            raise GuestStageRefusal(f"candidate-owned root artifact remains after cleanup: {path}")
    cleanup_digest = stage_file("cleanup", {"schema": FORMAT + ".evidence", "stageId": "cleanup", "ownedPaths": list(stage["ownedPaths"]), "ownedServices": list(stage["ownedServices"]), "ownedImages": list(stage["ownedImages"]), "signedImageReferences": signed_image_references, "rootCleanup": root_cleanup, "provisionerParentCreated": not provisioner_parent_preexisting, "provisionerParentRemoved": provisioner_parent_removed, "result": "passed"})
    receipt = {"schema": FORMAT, "evidenceClass": "real_guest", "candidate": candidate, "guest": {"guestId": config["guest"]["guestId"], "distribution": "ubuntu", "version": "24.04", "isolated": True, "sourceCheckoutPresent": False, "preExistingStatePortImages": False, "preExistingStatePortServices": False, "machineIdDigest": identity["machineIdDigest"], "bootIdDigest": identity["bootIdDigest"], "guestIdentityDigest": identity_digest, "hostFacts": {"kernel": facts["kernel"], "kernelRelease": facts["kernelRelease"], "wslDetected": facts["wslDetected"], "architecture": facts["architecture"], **{key: facts[key] for key in ("cgroupVersion", "podmanVersion", "podmanVersionMeetsFloor", "rootlessPodman", "quadlet", "systemdUserServices", "subuidMapping", "subgidMapping", "eligible")}}}, "executionHostReceipt": execution, "stages": stage_records, "cleanup": {"result": "passed", "removedImages": root_cleanup["imageRemoved"], "removedServices": root_cleanup["servicesRemoved"], "removedAccounts": root_cleanup["accountsRemoved"], "removedGroups": root_cleanup["groupsRemoved"], "removedSubordinateMappings": root_cleanup["subordinateMappingsRemoved"], "removedRootArtifacts": root_cleanup["rootArtifactsRemoved"] and (provisioner_parent_preexisting or provisioner_parent_removed)}}
    if [item["stageId"] for item in stage_records] != STAGES or any(item["result"] != "passed" for item in stage_records):
        raise GuestStageRefusal("stage evidence is incomplete")
    contract._validate_schema(receipt, contract.RECEIPT_SCHEMA, "Ubuntu qualification receipt")
    receipt_path = Path(str(config["receipt"]["path"]))
    digest = _write_json(receipt_path, receipt)
    configured_digest = str(config["receipt"]["sha256"])
    # The receipt contains guest-generated identity and lifecycle observations,
    # so its digest cannot be known before this stage runs.  A provisional
    # all-one digest is allowed only for this producer; the host validator
    # requires the observed digest before accepting qualification evidence.
    if not _is_placeholder(configured_digest) and digest != configured_digest:
        raise GuestStageRefusal("configured receipt digest does not match emitted receipt")
    return receipt


def cleanup_owned(config: Mapping[str, Any], runner: Runner) -> None:
    stage = config.get("guestStage")
    if not isinstance(stage, Mapping):
        raise GuestStageRefusal("guestStage configuration is required for cleanup")
    _run(runner, [str(item) for item in stage["uninstallArgv"]], "owned cleanup")


def _subprocess(argv: Sequence[str]) -> Completed:
    try:
        result = subprocess.run(list(argv), check=False, capture_output=True, text=True, shell=False, timeout=3600)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return Completed(255, "", str(exc))
    return Completed(result.returncode, result.stdout, result.stderr)


def _fixture(input_path: Path, output: Path, receipt_path: Path) -> dict[str, Any]:
    document = _json(input_path, "fixture input")
    receipt = document.get("receipt")
    if not isinstance(receipt, Mapping):
        raise GuestStageRefusal("fixture input must contain a receipt object")
    value = dict(receipt)
    value["evidenceClass"] = "fixture"
    output.mkdir(parents=True, exist_ok=False)
    for name, body in document.get("evidence", {}).items():
        if not isinstance(name, str) or not isinstance(body, Mapping) or Path(name).name != name:
            raise GuestStageRefusal("fixture evidence paths are unsafe")
        _write_json(output / name, body)
    _write_json(receipt_path, value)
    return value


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--verified-candidate-manifest", type=Path)
    parser.add_argument("--fixture", action="store_true", help="test-only deterministic fixture evidence; never real_guest")
    parser.add_argument("--fixture-input", type=Path)
    args = parser.parse_args(argv)
    try:
        config = _json(args.config, "Ubuntu guest-stage config")
        if args.fixture:
            if args.fixture_input is None:
                raise GuestStageRefusal("--fixture requires --fixture-input")
            receipt = _fixture(args.fixture_input, args.output, Path(str(config["receipt"]["path"])))
        else:
            if args.fixture_input is not None:
                raise GuestStageRefusal("--fixture-input is only valid with --fixture")
            receipt = run_guest(config, args.output, verified_manifest=args.verified_candidate_manifest)
    except (GuestStageRefusal, OSError, KeyError, TypeError) as exc:
        print(f"qualification guest stage: refused: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
