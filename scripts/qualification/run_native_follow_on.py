#!/usr/bin/env python3
"""Native installed-product follow-on: first result, reboot, uninstall, reinstall.

The alpha.18 native journey's pinned J1 harness proves install, services and
smokes.  W6 acceptance additionally needs, inside the *same* Windows guest boot:
one real OpenCode result through the installed control plane, reboot survival,
an uninstall that retains state, and an identical reinstall from the same
signed bytes.  This bounded driver composes the reviewed stages
(``run_agent_result_stage`` and ``run_reboot_stage``) with a minimal
retain-uninstall/identical-reinstall segment and runs them guest-side on the
retained distro through the reviewed ``NativeWSL`` seam.

Fail-closed rules:

- the lane gate is the shared reviewed one (``enforce_reboot_lane``): the
  retained J1 receipt selects ``candidate_mirror`` under
  ``--prepublication-mirror``, the owner path otherwise, and any mismatched
  flag or receipt class is refused before a candidate byte is fetched;
- the retained J1 receipt must be a *full* pass for the staged signed index
  (identity binding, lane class and every required phase) through the shared
  ``validate_native_j1_receipt`` implementation; a partial, foreign or mixed
  receipt is refused before any guest call;
- the staged candidate bytes (``download/install.sh`` and the signed
  ``download/<version>/release-index.json``) must match the retained J1
  binding and the signed index; the lifecycle artifacts themselves are only
  ever fetched anonymously over HTTPS from the candidate URLs (host mirror
  under the prepublication lane), never copied from a local path;
- the uninstall must report a durable ``uninstall`` receipt for this exact
  release identity, leave zero accepted units and still keep the state root;
- the reinstall must produce a *new* ``install_receipt_*.json`` that binds the
  same release id, version and signed payload digest, and the reinstalled
  control plane must be healthy with every running container at its signed
  image digest.

One boot, one durable top-level receipt; every stage writes its own durable
receipt and any failure writes ``result: failed`` and exits non-zero.  This
driver never reads, proxies or injects provider credentials: the agent-result
stage fails closed if the installed product has no admissible provider
endpoint, and that refusal is evidence, not a reason to fabricate a run.
"""
from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from journey_common import (  # noqa: E402
    JourneyReceipt,
    _exact_directory,
    _exact_file,
    _sha256_file,
    boot_native_follow_on,
    candidate_artifact_urls,
    discover_services,
    load_release_facts_from_index,
    log,
    validate_native_j1_receipt,
    verify_installed_image_digests,
    wait_service_healthy,
)
from run_agent_result_stage import execute_agent_result_stage  # noqa: E402
from run_journey_j4 import (  # noqa: E402
    LIFECYCLE_ENV,
    STATE_ROOT,
    UNITS_DIR,
    run_installer,
)
from run_reboot_stage import enforce_reboot_lane, execute_reboot_stage  # noqa: E402

PRODUCTION_BOOTSTRAP_URL = "https://lennertvhoy.github.io/StatePort-Site/download/install.sh"
CONTROL_SERVICES = ("stateport-web", "stateport-api", "stateport-worker")
PACKAGE_CONFIRMATIONS = ["install-packages", "install-exact"]
LEGACY_CONFIRMATIONS = ["install"]
VERSION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
LIMITATIONS = (
    "One bounded objective through the installed control plane, one WSL2 "
    "shutdown/reboot, one retain-state uninstall and one identical reinstall, "
    "all on the retained J1 distro inside one Windows guest boot. Provider "
    "material is inspected by shape only; credential contents are never read. "
    "Durable application-state adoption is asserted by the fuller J4 journey, "
    "not by this bounded driver."
)


def load_staged_candidate_inputs(
    j1_receipt: Path,
    site_root: Path,
    *,
    native_distro_name: str,
    prepublication_mirror: bool,
) -> tuple[dict[str, object], dict[str, object]]:
    """Validate the retained J1 receipt and the staged bytes; derive facts/evidence.

    The guest stages exactly two candidate files (``download/install.sh`` and
    ``download/<version>/release-index.json``); everything else this driver
    consumes is fetched over the lane's anonymous HTTPS transport.  No guest
    call happens here: a refused premise must never touch the distro.
    """
    j1_receipt = _exact_file(j1_receipt, "retained full-J1 receipt")
    site_root = _exact_directory(site_root, "staged candidate site root")
    try:
        document = json.loads(j1_receipt.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"retained full-J1 receipt is unreadable: {j1_receipt}") from exc
    if not isinstance(document, dict):
        raise ValueError("retained full-J1 receipt must be a JSON object")
    version = document.get("version")
    if not isinstance(version, str) or VERSION_PATTERN.fullmatch(version) is None:
        raise ValueError("retained full-J1 receipt has no usable release version")
    index_path = _exact_file(
        site_root / "download" / version / "release-index.json", "staged release index"
    )
    facts = load_release_facts_from_index(index_path)
    native = validate_native_j1_receipt(
        j1_receipt,
        facts,
        native_distro_name=native_distro_name,
        prepublication_mirror=prepublication_mirror,
    )
    binding = native["binding"]
    baseline = native["baseline"]
    bootstrap_path = _exact_file(site_root / "download" / "install.sh", "staged bootstrap")
    bootstrap_digest = _sha256_file(bootstrap_path)
    if binding.get("bootstrapDigest") != bootstrap_digest:
        raise ValueError("staged bootstrap bytes do not match the retained full-J1 binding")
    installer_digest = facts.get("installerDigest")
    if not isinstance(installer_digest, str) or DIGEST_PATTERN.fullmatch(installer_digest) is None:
        raise ValueError("signed release index has no installer digest")
    bootstrap_url = binding.get("bootstrapUrl")
    if not isinstance(bootstrap_url, str) or not bootstrap_url.startswith("https://"):
        bootstrap_url = PRODUCTION_BOOTSTRAP_URL
    evidence: dict[str, object] = {
        **native["laneEvidence"],
        "fullJ1Receipt": native["fullJ1Receipt"],
        "fullJ1ReceiptSha256": native["fullJ1ReceiptSha256"],
        "nativeIdentity": {
            "machineId": baseline["machineId"],
            "windowsIdentity": baseline["windowsIdentity"],
        },
        "rehearsalBaseline": baseline,
        "siteRoot": str(site_root),
        "bootstrapPath": str(bootstrap_path),
        "bootstrapDigest": bootstrap_digest,
        "installerDigest": installer_digest,
        "bootstrapUrl": bootstrap_url,
    }
    return facts, evidence


def _receipt_paths(vm, kind: str) -> list[str]:
    """List the guest's durable ``<kind>_receipt_*.json`` paths, newest first."""
    pattern = f"$HOME/.local/state/stateport-install/receipts/{kind}_receipt_*.json"
    listed = vm.ssh(f"ls -1t {pattern} 2>/dev/null", check=False, timeout=60)
    if listed.returncode != 0:
        return []
    return [line.strip() for line in listed.stdout.splitlines() if line.strip()]


def _read_receipt(vm, path: str) -> dict | None:
    content = vm.ssh(f"sudo cat {shlex.quote(path)}", check=False, timeout=60)
    if content.returncode != 0:
        return None
    try:
        document = json.loads(content.stdout)
    except json.JSONDecodeError:
        return None
    return document if isinstance(document, dict) else None


def _receipt_digest(vm, path: str) -> str | None:
    hashed = vm.ssh(f"sudo sha256sum {shlex.quote(path)}", check=False, timeout=60)
    if hashed.returncode != 0 or not hashed.stdout.strip():
        return None
    return "sha256:" + hashed.stdout.strip().split()[0]


def _guest_digest(vm, path: str) -> str | None:
    hashed = vm.ssh(f"sha256sum {shlex.quote(path)}", check=False, timeout=60)
    if hashed.returncode != 0 or not hashed.stdout.strip():
        return None
    return "sha256:" + hashed.stdout.strip().split()[0]


def _stage_lifecycle_artifacts(vm, *, facts: dict, evidence: dict) -> dict:
    """Fetch the exact bootstrap and installer through the lane's HTTPS transport.

    Native transport is anonymous HTTPS of the candidate URLs (the host mirror
    serves them under the prepublication lane); a local path, staged copy or
    host-side ``scp`` would silently convert native evidence into staged-host
    evidence and is never used.
    """
    bootstrap_url = str(evidence["bootstrapUrl"])
    bootstrap_url, installer_url = candidate_artifact_urls(str(facts["version"]), bootstrap_url)
    vm.fetch_public_artifact(bootstrap_url, "/tmp/stateport-bootstrap",
                             str(evidence["bootstrapDigest"]))
    vm.fetch_public_artifact(installer_url, "/tmp/stateport-installer",
                             str(evidence["installerDigest"]))
    observed_bootstrap = _guest_digest(vm, "/tmp/stateport-bootstrap")
    observed_installer = _guest_digest(vm, "/tmp/stateport-installer")
    return {
        "bootstrapUrl": bootstrap_url,
        "installerUrl": installer_url,
        "bootstrapDigest": evidence["bootstrapDigest"],
        "observedBootstrapDigest": observed_bootstrap,
        "installerDigest": evidence["installerDigest"],
        "observedInstallerDigest": observed_installer,
        "artifactsOk": (
            observed_bootstrap == evidence["bootstrapDigest"]
            and observed_installer == evidence["installerDigest"]
        ),
    }


def execute_lifecycle_stage(
    vm,
    *,
    facts: dict,
    evidence: dict,
    prepublication_mirror: bool,
    receipt_out: Path,
    install_timeout_s: int = 3600,
    uninstall_timeout_s: int = 1800,
) -> dict:
    """Retain-state uninstall followed by the identical signed reinstall."""
    receipt = JourneyReceipt(
        "native-follow-on-lifecycle",
        {"candidate": facts, "prerequisites": evidence},
    )
    receipt.out_path = receipt_out
    receipt.document["limitations"] = LIMITATIONS
    receipt.write(receipt_out)
    lane: dict = {}
    try:
        if not getattr(vm, "native_wsl", False):
            raise AssertionError("follow-on lifecycle requires the native WSL2 lane")
        lane = enforce_reboot_lane(evidence, prepublication_mirror=prepublication_mirror)
        receipt.document.update(lane)
        receipt.record("lane-class", True, **lane)

        expected_images = facts.get("images")
        if not isinstance(expected_images, dict) or not expected_images:
            raise AssertionError(
                "follow-on lifecycle requires the signed image set from the candidate facts"
            )

        staged = _stage_lifecycle_artifacts(vm, facts=facts, evidence=evidence)
        receipt.record(
            "candidate-lifecycle-artifacts-staged", bool(staged["artifactsOk"]), **staged
        )
        if not staged["artifactsOk"]:
            raise AssertionError("guest lifecycle artifact digest mismatch")

        before_uninstall = set(_receipt_paths(vm, "uninstall"))
        uninstall = run_installer(vm, "--uninstall", uninstall_timeout_s)
        produced = [
            path for path in _receipt_paths(vm, "uninstall") if path not in before_uninstall
        ]
        uninstall_doc = _read_receipt(vm, produced[0]) if produced else None
        uninstall_digest = _receipt_digest(vm, produced[0]) if produced else None
        units_left = vm.ssh(
            f"sudo sh -c 'ls {UNITS_DIR}/*.container 2>/dev/null | wc -l'",
            check=False,
            timeout=60,
        )
        units_count = int(units_left.stdout.strip() or "-1")
        state_root_kept = vm.ssh(f"test -d {STATE_ROOT}", check=False, timeout=60).returncode == 0
        installation = (
            uninstall_doc.get("installation") if isinstance(uninstall_doc, dict) else None
        )
        retain_ok = (
            uninstall.returncode == 0
            and len(produced) == 1
            and isinstance(uninstall_doc, dict)
            and uninstall_doc.get("action") == "uninstall"
            and uninstall_doc.get("result") in {"succeeded", "already_uninstalled"}
            and isinstance(installation, dict)
            and installation.get("releaseId") == facts["releaseId"]
            and installation.get("releaseIndexDigest") == facts["releaseIndexSha256"]
            and installation.get("signedPayloadDigest") == facts["signedPayloadDigest"]
            and units_count == 0
            and state_root_kept
        )
        receipt.record(
            "uninstall-retaining-state",
            retain_ok,
            exitCode=uninstall.returncode,
            receiptPath=produced[0] if produced else None,
            receiptSha256=uninstall_digest,
            uninstallReceiptStatus=(uninstall_doc or {}).get("status"),
            uninstallReceiptResult=(uninstall_doc or {}).get("result"),
            unitsLeft=units_count,
            stateRootPreserved=state_root_kept,
            installationIdentity=installation,
        )
        if not retain_ok:
            raise AssertionError(
                "retain-uninstall did not converge (exit="
                f"{uninstall.returncode}, newReceipts={len(produced)}, "
                f"units={units_count}, stateRootKept={state_root_kept})"
            )

        confirmations = (
            list(PACKAGE_CONFIRMATIONS)
            if facts.get("podmanPackageBundleDigest") is not None
            else list(LEGACY_CONFIRMATIONS)
        )
        before_install = set(_receipt_paths(vm, "install"))
        reinstall = vm.ssh_install(
            f"{LIFECYCLE_ENV} sh /tmp/stateport-bootstrap",
            confirmations=confirmations,
            timeout=install_timeout_s,
        )
        produced_installs = [
            path for path in _receipt_paths(vm, "install") if path not in before_install
        ]
        install_doc = _read_receipt(vm, produced_installs[0]) if produced_installs else None
        install_digest = _receipt_digest(vm, produced_installs[0]) if produced_installs else None
        release_block = install_doc.get("release") if isinstance(install_doc, dict) else None
        reinstall_ok = (
            reinstall.returncode == 0
            and len(produced_installs) == 1
            and isinstance(install_doc, dict)
            and install_doc.get("operation") == "install"
            and install_doc.get("result") == "succeeded"
            and isinstance(release_block, dict)
            and release_block.get("releaseId") == facts["releaseId"]
            and release_block.get("version") == facts["version"]
            and release_block.get("signedPayloadDigest") == facts["signedPayloadDigest"]
            and install_doc.get("releaseIndexDigest") == facts["releaseIndexSha256"]
        )
        receipt.record(
            "reinstall-identical-release",
            reinstall_ok,
            exitCode=reinstall.returncode,
            receiptPath=produced_installs[0] if produced_installs else None,
            receiptSha256=install_digest,
            releaseId=(release_block or {}).get("releaseId"),
            version=(release_block or {}).get("version"),
            signedPayloadDigest=(release_block or {}).get("signedPayloadDigest"),
            releaseIndexDigest=(install_doc or {}).get("releaseIndexDigest"),
            confirmations=confirmations,
        )
        if not reinstall_ok:
            raise AssertionError(
                "identical reinstall did not converge (exit="
                f"{reinstall.returncode}, newReceipts={len(produced_installs)})"
            )

        services = discover_services(vm)
        for service_id in CONTROL_SERVICES:
            wait_service_healthy(vm, services, service_id, deadline_s=420)
        digests = verify_installed_image_digests(vm, dict(expected_images))
        health_ok = not digests["mismatches"]
        receipt.record(
            "reinstalled-health",
            health_ok,
            services=services,
            imageDigests=digests["observed"],
            containers=digests["containers"],
            mismatches=digests["mismatches"],
        )
        if not health_ok:
            raise AssertionError(
                "reinstalled control plane does not match the signed image identity: "
                + json.dumps(digests["mismatches"], sort_keys=True)[:600]
            )

        receipt.document["result"] = "passed"
        summary = {
            "receiptPath": str(receipt_out),
            "mode": lane["mode"],
            "evidenceClass": lane["evidenceClass"],
            "uninstallReceiptPath": produced[0],
            "uninstallReceiptSha256": uninstall_digest,
            "installReceiptPath": produced_installs[0],
            "installReceiptSha256": install_digest,
            "releaseId": facts["releaseId"],
            "reinstalledImageDigests": digests["observed"],
        }
    except BaseException as exc:
        receipt.document["result"] = "failed"
        receipt.record(
            "lifecycle-stage-failure",
            False,
            error=f"{type(exc).__name__}: {exc}",
            mode=lane.get("mode"),
        )
        raise
    finally:
        receipt.write(receipt_out)
    return summary


def execute_follow_on(
    vm,
    *,
    facts: dict,
    evidence: dict,
    prepublication_mirror: bool,
    receipt_out: Path,
    agent_result_receipt_out: Path,
    reboot_receipt_out: Path,
    lifecycle_receipt_out: Path,
    agent_run_timeout_s: float = 1200.0,
    agent_poll_interval_s: float = 3.0,
    install_timeout_s: int = 3600,
    uninstall_timeout_s: int = 1800,
) -> dict:
    """Run the four acceptance stages in order on one attached native VM.

    The caller owns the VM; the stages never tear it down, so a failure keeps
    the retained distro for diagnosis.  Every sub-receipt is digest-bound in
    the top-level receipt.
    """
    lane = enforce_reboot_lane(evidence, prepublication_mirror=prepublication_mirror)
    receipt = JourneyReceipt(
        "native-follow-on-journey",
        {"candidate": facts, "prerequisites": evidence},
    )
    receipt.out_path = receipt_out
    receipt.document["limitations"] = LIMITATIONS
    receipt.document.update(lane)
    receipt.write(receipt_out)
    try:
        if not getattr(vm, "native_wsl", False):
            raise AssertionError("the follow-on journey requires the native WSL2 lane")
        receipt.record("lane-class", True, **lane)

        agent_summary = execute_agent_result_stage(
            vm,
            facts=facts,
            evidence=evidence,
            prepublication_mirror=prepublication_mirror,
            receipt_out=agent_result_receipt_out,
            run_timeout_s=agent_run_timeout_s,
            poll_interval_s=agent_poll_interval_s,
        )
        receipt.record(
            "agent-result-stage",
            True,
            **agent_summary,
            receiptSha256=_sha256_file(agent_result_receipt_out),
        )

        reboot_summary = execute_reboot_stage(
            vm,
            facts=facts,
            evidence=evidence,
            prepublication_mirror=prepublication_mirror,
            receipt_out=reboot_receipt_out,
        )
        receipt.record(
            "reboot-survival-stage",
            True,
            **reboot_summary,
            receiptSha256=_sha256_file(reboot_receipt_out),
        )

        lifecycle_summary = execute_lifecycle_stage(
            vm,
            facts=facts,
            evidence=evidence,
            prepublication_mirror=prepublication_mirror,
            receipt_out=lifecycle_receipt_out,
            install_timeout_s=install_timeout_s,
            uninstall_timeout_s=uninstall_timeout_s,
        )
        receipt.record(
            "lifecycle-stage",
            True,
            **lifecycle_summary,
            receiptSha256=_sha256_file(lifecycle_receipt_out),
        )

        receipt.document["result"] = "passed"
        summary = {
            "receiptPath": str(receipt_out),
            "mode": lane["mode"],
            "evidenceClass": lane["evidenceClass"],
            "agentResultReceipt": str(agent_result_receipt_out),
            "rebootReceipt": str(reboot_receipt_out),
            "lifecycleReceipt": str(lifecycle_receipt_out),
        }
    except BaseException as exc:
        receipt.document["result"] = "failed"
        receipt.record(
            "follow-on-failure",
            False,
            error=f"{type(exc).__name__}: {exc}",
            mode=lane.get("mode"),
        )
        raise
    finally:
        receipt.write(receipt_out)
    return summary


def _write_preflight_failure(
    args,
    exc: BaseException,
    *,
    j1_receipt: Path,
    site_root: Path,
) -> None:
    receipt = JourneyReceipt(
        "native-follow-on-journey",
        {
            "j1Receipt": str(j1_receipt),
            "siteRoot": str(site_root),
            "distroName": args.wsl_distro_name,
        },
    )
    receipt.out_path = args.receipt_out
    receipt.record("input-preflight", False, error=f"{type(exc).__name__}: {exc}")
    receipt.document["result"] = "failed"
    receipt.write(args.receipt_out)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Native installed-product follow-on journey "
        "(first OpenCode result -> reboot -> retain-uninstall -> identical reinstall)"
    )
    parser.add_argument("--receipt-out", type=Path, required=True,
                        help="durable top-level follow-on journey receipt")
    parser.add_argument("--j1-receipt", type=Path, required=True,
                        help="retained native full-J1 receipt (guest vm_dir/receipt.json)")
    parser.add_argument("--site-root", type=Path, required=True,
                        help="staged candidate site root (guest C:\\StatePort-r2\\site)")
    parser.add_argument("--vm-dir", type=Path, required=True,
                        help="native work directory holding the retained J1 receipt")
    parser.add_argument("--native-wsl2", action="store_true")
    parser.add_argument("--wsl-distro-name")
    parser.add_argument("--prepublication-mirror", action="store_true",
                        help="validate a candidate-mirror (pre-publication) native J1 receipt; "
                             "never owner-path or public-route proof")
    parser.add_argument("--agent-result-receipt-out", type=Path, required=True)
    parser.add_argument("--reboot-receipt-out", type=Path, required=True)
    parser.add_argument("--lifecycle-receipt-out", type=Path, required=True)
    parser.add_argument("--agent-run-timeout-seconds", type=float, default=1200.0,
                        help="bounded wait for the agent run to reach a terminal state")
    parser.add_argument("--agent-poll-interval-seconds", type=float, default=3.0)
    parser.add_argument("--install-timeout-seconds", type=int, default=3600,
                        help="bounded wait for the identical reinstall bootstrap")
    parser.add_argument("--uninstall-timeout-seconds", type=int, default=1800,
                        help="bounded wait for the retain-state uninstall")
    args = parser.parse_args()

    if not args.native_wsl2:
        parser.error("the follow-on journey is a native WSL2 driver; pass --native-wsl2")
    if not args.wsl_distro_name:
        parser.error("--native-wsl2 requires --wsl-distro-name")

    j1_receipt = args.j1_receipt
    site_root = args.site_root
    try:
        facts, evidence = load_staged_candidate_inputs(
            j1_receipt,
            site_root,
            native_distro_name=args.wsl_distro_name,
            prepublication_mirror=args.prepublication_mirror,
        )
    except Exception as exc:  # noqa: BLE001 - preflight failure must be durable
        _write_preflight_failure(args, exc, j1_receipt=j1_receipt, site_root=site_root)
        log(f"result: failed -> {args.receipt_out} ({type(exc).__name__}: {exc})")
        return 1

    vm = None
    try:
        lane = enforce_reboot_lane(evidence, prepublication_mirror=args.prepublication_mirror)
        vm = boot_native_follow_on(
            args.vm_dir,
            site_root=args.site_root,
            distro_name=args.wsl_distro_name,
            expected_identity=evidence["nativeIdentity"],
            expected_baseline=evidence["rehearsalBaseline"],
        )
        log(f"attached retained native distro {args.wsl_distro_name} ({lane['mode']})")
        summary = execute_follow_on(
            vm,
            facts=facts,
            evidence=evidence,
            prepublication_mirror=args.prepublication_mirror,
            receipt_out=args.receipt_out,
            agent_result_receipt_out=args.agent_result_receipt_out,
            reboot_receipt_out=args.reboot_receipt_out,
            lifecycle_receipt_out=args.lifecycle_receipt_out,
            agent_run_timeout_s=args.agent_run_timeout_seconds,
            agent_poll_interval_s=args.agent_poll_interval_seconds,
            install_timeout_s=args.install_timeout_seconds,
            uninstall_timeout_s=args.uninstall_timeout_seconds,
        )
        log(f"result: passed -> {args.receipt_out} ({summary['mode']})")
        return 0
    except (Exception, SystemExit) as exc:
        # Every stage finalizes its own failed receipt; an attach failure before
        # the journey starts still needs one durable failure document.
        if not args.receipt_out.exists():
            _write_preflight_failure(args, exc, j1_receipt=j1_receipt, site_root=site_root)
        log(f"result: failed -> {args.receipt_out} ({type(exc).__name__}: {exc})")
        return 1
    finally:
        if vm is not None:
            vm.teardown()


if __name__ == "__main__":
    sys.exit(main())
