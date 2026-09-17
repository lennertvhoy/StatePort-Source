#!/usr/bin/env python3
"""Native WSL2 reboot-survival stage: shutdown, re-attach, health and digest receipt.

Plan items D and H for the alpha.18 native journey: the install lane leaves the
control plane healthy, but no committed runner proves the installed system
survives ``wsl.exe --shutdown`` and a fresh boot.  This bounded stage shuts the
whole WSL2 utility VM down, re-attaches through the same reviewed ``NativeWSL``
seam the J2/J4 drivers use, re-applies the prepublication hosts mapping that WSL
regenerates on every boot, and asserts the defined health set: every accepted
control unit active, every published control endpoint responding, and the signed
image identity of every running service container unchanged.

The caller owns the attached VM (this stage never unregisters or tears it down),
so a journey driver can invoke it in-process between its install and uninstall
stages.  Every run writes one durable journey receipt; any failed assertion
writes ``result: failed`` and exits non-zero.  The lane class of the retained J1
receipt is preserved exactly: ``candidate_mirror`` under
``--prepublication-mirror``, the owner path otherwise, and a mismatched flag or
receipt is refused before any guest call.

``wsl.exe --shutdown`` stops every WSL2 distribution on the host, exactly the
reboot the alpha.18 plan names.  Qualification runs it inside the disposable
Windows guest; a direct owner-host run also stops the owner's other running
distributions for the duration of the reboot.
"""
from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from journey_common import (  # noqa: E402
    EVIDENCE_CLASS_CANDIDATE_MIRROR,
    IDENTITY_CLASS_CANDIDATE_MIRROR,
    TRANSPORT_CLASS_PREPUBLICATION_MIRROR,
    WSL_ROOTFS_IDENTITY,
    JourneyReceipt,
    boot_native_follow_on,
    control_user_env,
    log,
    validate_retained_candidate_inputs,
)
from wsl2_rehearsal import (  # noqa: E402
    HOSTNAME,
    PREPUBLICATION_HOST_MIRROR_GATEWAY,
)

CONTROL_SERVICES = ("stateport-web", "stateport-api", "stateport-worker")
SHUTDOWN_ARGV = ["--shutdown"]
OWNER_PATH_CLASS = "owner_path_qualification"
PREPUBLICATION_CA_PATH = "/usr/local/share/ca-certificates/stateport-prepublication-mirror.crt"
PREPUBLICATION_REGISTRIES_PATH = (
    "/etc/containers/registries.conf.d/99-stateport-prepublication-mirror.conf"
)


def enforce_reboot_lane(evidence: object, *, prepublication_mirror: bool) -> dict:
    """Return the lane identity this stage stamps; refuse any unmatched class.

    The stage never converts evidence between lanes: ``--prepublication-mirror``
    requires the candidate-mirror retained J1 receipt, the default requires the
    owner-path one, and anything else (including simulation baselines) is a
    mismatch that must be refused before the guest is touched.
    """
    baseline = evidence.get("rehearsalBaseline") if isinstance(evidence, dict) else None
    if not isinstance(baseline, dict):
        raise ValueError("reboot stage requires one retained native J1 baseline")
    if (
        baseline.get("substrate") != "native-wsl2"
        or baseline.get("rootfsIdentity") != WSL_ROOTFS_IDENTITY
    ):
        raise ValueError("reboot stage requires the retained native WSL2 J1 baseline")
    observed = baseline.get("evidenceClass")
    if prepublication_mirror:
        if (
            observed != EVIDENCE_CLASS_CANDIDATE_MIRROR
            or baseline.get("transportClass") != TRANSPORT_CLASS_PREPUBLICATION_MIRROR
            or baseline.get("identityClass") != IDENTITY_CLASS_CANDIDATE_MIRROR
            or baseline.get("ownerPathQualification") is not False
            or baseline.get("publicTransportBoundary") is not False
            or evidence.get("evidenceClass") != EVIDENCE_CLASS_CANDIDATE_MIRROR
            or evidence.get("ownerPathQualification") is not False
        ):
            raise ValueError(
                "reboot stage lane mismatch: --prepublication-mirror requires a "
                "candidate-mirror retained J1 receipt"
            )
        return {
            "mode": "prepublication-mirror",
            "evidenceClass": EVIDENCE_CLASS_CANDIDATE_MIRROR,
            "transportClass": TRANSPORT_CLASS_PREPUBLICATION_MIRROR,
            "identityClass": IDENTITY_CLASS_CANDIDATE_MIRROR,
            "ownerPathQualification": False,
            "publicTransportBoundary": False,
            "hostsMappingRequired": True,
        }
    if observed != OWNER_PATH_CLASS or evidence.get("evidenceClass") not in (None, OWNER_PATH_CLASS):
        raise ValueError(
            "reboot stage lane mismatch: the owner path requires an "
            "owner_path_qualification retained J1 receipt"
        )
    return {
        "mode": "public-transport",
        "evidenceClass": OWNER_PATH_CLASS,
        "hostsMappingRequired": False,
    }


def _unit_states(vm, services: dict) -> dict:
    """Read each accepted control unit's active state under the control identity."""
    units = [services[service_id]["unit"] for service_id in CONTROL_SERVICES]
    script = control_user_env() + r"""
set -u
for unit in "$@"; do
  state=$(run_control systemctl --user is-active "$unit" 2>/dev/null || true)
  printf '%s\t%s\n' "$unit" "$state"
done
"""
    remote = (
        "sudo runuser -u stateport-control -- bash -c "
        + shlex.quote(script)
        + " reboot-stage "
        + " ".join(shlex.quote(unit) for unit in units)
    )
    result = vm.ssh(remote, check=False, timeout=120)
    if result.returncode != 0:
        raise AssertionError(
            "control unit state probe failed: " + (result.stderr or "").strip()[-500:]
        )
    observed: dict = {}
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) != 2 or not parts[0] or parts[0] in observed:
            raise AssertionError(f"malformed control unit state row: {line!r}")
        observed[parts[0]] = parts[1]
    if set(observed) != set(units):
        raise AssertionError(
            f"control unit state probe is incomplete: {sorted(observed)} != {sorted(units)}"
        )
    return observed


def observe_installed_health(vm, expected_images: dict) -> dict:
    """The defined post-stage health set, asserted before it is recorded."""
    from journey_common import (
        discover_services,
        verify_installed_image_digests,
        wait_service_healthy,
    )

    services = discover_services(vm)
    for service_id in CONTROL_SERVICES:
        wait_service_healthy(vm, services, service_id, deadline_s=420)
    units = _unit_states(vm, services)
    inactive = sorted(unit for unit, state in units.items() if state != "active")
    if inactive:
        raise AssertionError(f"control units are not active: {inactive}")
    digests = verify_installed_image_digests(vm, dict(expected_images))
    if digests["mismatches"]:
        raise AssertionError(f"installed image identity mismatch: {digests['mismatches']}")
    return {
        "services": services,
        "units": units,
        "imageDigests": digests["observed"],
        "declaredImageDigests": digests["declared"],
        "containers": digests["containers"],
    }


def _strict_hosts_mapping_command() -> str:
    return (
        f"grep -Eq '^{PREPUBLICATION_HOST_MIRROR_GATEWAY}[[:space:]]+{HOSTNAME}"
        f"([[:space:]]|$)' /etc/hosts && printf 'MAPPED\\n' || printf 'ABSENT\\n'"
    )


def _hosts_mapping_state(vm) -> dict:
    command = _strict_hosts_mapping_command()
    result = vm.ssh(command, check=False, timeout=60)
    marker = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""
    if result.returncode != 0 or marker not in {"MAPPED", "ABSENT"}:
        raise AssertionError(
            "prepublication hosts mapping probe failed: "
            + (result.stderr or result.stdout or "").strip()[-500:]
        )
    return {"mapped": marker == "MAPPED", "probe": command}


def reapply_prepublication_seams(vm) -> dict:
    """Re-apply the WSL-regenerated hosts mapping and verify every mirror seam.

    WSL rewrites ``/etc/hosts`` on every distribution boot; the prepublication
    lane's production-hostname mapping is therefore expected to be absent after
    the reboot.  The re-apply is the exact ``grep || append`` seam the harness
    installs, and the verification refuses when the mapping, the rehearsal CA,
    the registries stanza, or the gateway resolution is missing.
    """
    after_boot = _hosts_mapping_state(vm)
    reapply = (
        f"grep -q '{HOSTNAME}' /etc/hosts || printf '%s\\n' "
        f"'{PREPUBLICATION_HOST_MIRROR_GATEWAY} {HOSTNAME}' | sudo tee -a /etc/hosts >/dev/null"
    )
    applied = vm.ssh(reapply, check=False, timeout=60)
    if applied.returncode != 0:
        raise AssertionError(
            "prepublication hosts mapping re-apply failed: "
            + (applied.stderr or applied.stdout or "").strip()[-500:]
        )
    verify = (
        "set -eu;"
        f"test -e {PREPUBLICATION_CA_PATH};"
        f"test -e {PREPUBLICATION_REGISTRIES_PATH};"
        f"grep -Eq '^{PREPUBLICATION_HOST_MIRROR_GATEWAY}[[:space:]]+{HOSTNAME}"
        "([[:space:]]|$)' /etc/hosts;"
        f"resolved=$(getent ahostsv4 {HOSTNAME} | awk '{{print $1}}' | sort -u | tr '\\n' ',');"
        f"case \",$resolved\" in *,\"{PREPUBLICATION_HOST_MIRROR_GATEWAY}\",*) ;; *) "
        "echo \"HOSTNAME-RESOLUTION-NOT-MIRRORED resolved=$resolved\"; exit 1;; esac;"
        "printf 'PUBLICATION-RESOLVED=%s\\n' \"$resolved\";"
        "printf 'PREPUBLICATION-REBOOT-SEAMS-OK\\n'"
    )
    checked = vm.ssh(verify, check=False, timeout=120)
    if checked.returncode != 0 or "PREPUBLICATION-REBOOT-SEAMS-OK" not in checked.stdout:
        raise AssertionError(
            "prepublication mirror seams did not survive the reboot: "
            + (checked.stderr or checked.stdout or "").strip()[-1000:]
        )
    resolved = ""
    for line in checked.stdout.splitlines():
        if line.startswith("PUBLICATION-RESOLVED="):
            resolved = line.removeprefix("PUBLICATION-RESOLVED=")
    return {
        "required": True,
        "mappingPresentAfterBoot": after_boot["mapped"],
        "reapplyCommand": reapply,
        "resolved": resolved,
    }


def _running_distributions(vm) -> set:
    result = vm._wsl(["--list", "--running", "--quiet"], check=False, timeout=60)
    if result.returncode != 0:
        raise AssertionError(
            "could not list running WSL distributions: "
            + (result.stderr or "").strip()[-300:]
        )
    return {
        line.strip().replace("\x00", "").casefold()
        for line in result.stdout.splitlines()
        if line.strip().replace("\x00", "")
    }


def reattach_native_vm(vm) -> dict:
    """Re-attach the retained distribution and re-prove its J1 identity binding."""
    vm.prepare(reuse=True)
    vm.boot()
    identity = getattr(vm, "expected_native_identity", None)
    baseline = getattr(vm, "rehearsal_baseline", None)
    if not isinstance(identity, dict) or not identity:
        raise AssertionError("re-attached native VM has no retained J1 identity binding")
    return {
        "distroName": getattr(vm, "distro_name", None),
        "machineId": identity.get("machineId"),
        "windowsIdentity": identity.get("windowsIdentity"),
        "baselineClass": baseline.get("evidenceClass") if isinstance(baseline, dict) else None,
    }


def _digest_stability(pre: dict, post: dict) -> dict:
    per_service: dict = {}
    containers: dict = {}
    stable = True
    for service_id in sorted(set(pre["imageDigests"]) | set(post["imageDigests"])):
        before = pre["imageDigests"].get(service_id)
        after = post["imageDigests"].get(service_id)
        per_service[service_id] = {"pre": before, "post": after}
        if before is None or before != after:
            stable = False
        pre_container = pre["containers"].get(service_id) or {}
        post_container = post["containers"].get(service_id) or {}
        containers[service_id] = {
            "preContainerId": pre_container.get("containerId"),
            "postContainerId": post_container.get("containerId"),
            "preImageDigest": pre_container.get("imageDigest"),
            "postImageDigest": post_container.get("imageDigest"),
            "containerIdStable": pre_container.get("containerId") == post_container.get("containerId"),
            "imageDigestStable": pre_container.get("imageDigest") == post_container.get("imageDigest"),
        }
        if containers[service_id]["imageDigestStable"] is not True:
            stable = False
    return {
        "imageDigestsStable": stable,
        "perService": per_service,
        "containers": containers,
    }


def execute_reboot_stage(
    vm,
    *,
    facts: dict,
    evidence: dict,
    prepublication_mirror: bool,
    receipt_out: Path,
) -> dict:
    """Run one observed shutdown/re-attach/assertion cycle on an attached VM.

    The caller owns the VM; this function never tears it down, so a journey can
    invoke the stage in-process.  The receipt is written on every step and again
    on failure before the exception propagates.
    """
    receipt = JourneyReceipt(
        "native-reboot-survival",
        {"candidate": facts, "prerequisites": evidence},
    )
    receipt.out_path = receipt_out
    receipt.document["limitations"] = (
        "Control-plane unit/endpoint health and signed image identity only; "
        "durable application state, provider execution, and the update/rollback "
        "lifecycle are asserted by the calling journey on the same retained distro."
    )
    receipt.write(receipt_out)
    lane: dict = {}
    try:
        if not getattr(vm, "native_wsl", False):
            raise AssertionError("reboot stage requires the native WSL2 lane")

        lane = enforce_reboot_lane(evidence, prepublication_mirror=prepublication_mirror)
        receipt.document.update(lane)
        receipt.record("lane-class", True, **lane)

        expected_images = facts.get("images")
        if not isinstance(expected_images, dict) or not expected_images:
            raise AssertionError("reboot stage requires the signed image set from the candidate facts")

        pre = observe_installed_health(vm, expected_images)
        receipt.record("pre-shutdown-health", True, **pre)

        if lane["hostsMappingRequired"]:
            pre_mapping = _hosts_mapping_state(vm)
            if not pre_mapping["mapped"]:
                raise AssertionError(
                    "prepublication hosts mapping is absent before the shutdown: "
                    + json.dumps(pre_mapping)
                )
            receipt.record("pre-shutdown-lane-seams", True, **pre_mapping)

        shutdown = vm._wsl(list(SHUTDOWN_ARGV), check=False, timeout=180)
        if shutdown.returncode != 0:
            raise AssertionError(
                "wsl.exe --shutdown failed: " + (shutdown.stderr or "").strip()[-500:]
            )
        running = _running_distributions(vm)
        if getattr(vm, "distro_name", "").casefold() in running:
            raise AssertionError("WSL distribution is still running after wsl.exe --shutdown")
        receipt.record(
            "guest-shutdown",
            True,
            argv=["wsl.exe", *SHUTDOWN_ARGV],
            exitCode=shutdown.returncode,
            runningDistributions=sorted(running),
        )

        attach = reattach_native_vm(vm)
        receipt.record("guest-reattach", True, **attach)

        if lane["hostsMappingRequired"]:
            seams = reapply_prepublication_seams(vm)
        else:
            seams = {"required": False, "mode": "public-dns"}
        receipt.record("lane-seams-reattached", True, **seams)

        post = observe_installed_health(vm, expected_images)
        receipt.record("post-shutdown-health", True, **post)

        stability = _digest_stability(pre, post)
        if stability["imageDigestsStable"] is not True:
            raise AssertionError(
                "installed image digests changed across the reboot: "
                + json.dumps(stability)
            )
        receipt.record("digest-stability", True, **stability)

        receipt.document["result"] = "passed"
        summary = {
            "receiptPath": str(receipt_out),
            "mode": lane["mode"],
            "evidenceClass": lane["evidenceClass"],
            "hostsMappingRequired": lane["hostsMappingRequired"],
            "observedImageDigests": post["imageDigests"],
            "imageDigestsStable": stability["imageDigestsStable"],
        }
    except BaseException as exc:
        receipt.document["result"] = "failed"
        receipt.record(
            "reboot-stage-failure",
            False,
            error=f"{type(exc).__name__}: {exc}",
            mode=lane.get("mode"),
        )
        raise
    finally:
        receipt.write(receipt_out)
    return summary


def _stage_receipt_is_terminal(path: Path) -> bool:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    return document.get("result") in {"passed", "failed"}


def _write_attach_failure(args, facts: dict, evidence: dict, exc: BaseException) -> None:
    if _stage_receipt_is_terminal(args.receipt_out):
        return
    receipt = JourneyReceipt(
        "native-reboot-survival",
        {"candidate": facts, "prerequisites": evidence},
    )
    receipt.out_path = args.receipt_out
    receipt.record("attach", False, error=f"{type(exc).__name__}: {exc}")
    receipt.document["result"] = "failed"
    receipt.write(args.receipt_out)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Native WSL2 reboot-survival stage (plan items D and H)"
    )
    parser.add_argument("--receipt-out", type=Path, required=True)
    parser.add_argument("--vm-dir", type=Path, required=True)
    parser.add_argument("--candidate-dir", type=Path, required=True)
    parser.add_argument("--site-root", type=Path, required=True)
    parser.add_argument("--native-wsl2", action="store_true")
    parser.add_argument("--wsl-distro-name")
    parser.add_argument("--prepublication-mirror", action="store_true",
                        help="validate a candidate-mirror (pre-publication) native J1 receipt; "
                             "never owner-path or public-route proof")
    parser.add_argument("--qualification-build-receipt", type=Path)
    args = parser.parse_args()

    if not args.native_wsl2:
        parser.error("the reboot stage is a native WSL2 driver; pass --native-wsl2")
    if not args.wsl_distro_name:
        parser.error("--native-wsl2 requires --wsl-distro-name")

    try:
        facts, prerequisite_evidence = validate_retained_candidate_inputs(
            args.candidate_dir, args.vm_dir, args.site_root, None,
            native_distro_name=args.wsl_distro_name,
            qualification_build_receipt=args.qualification_build_receipt,
            prepublication_mirror=args.prepublication_mirror,
        )
    except Exception as exc:  # noqa: BLE001 - preflight failure must be durable
        receipt = JourneyReceipt(
            "native-reboot-survival",
            {
                "candidateDir": str(args.candidate_dir),
                "vmDir": str(args.vm_dir),
                "siteRoot": str(args.site_root),
                "distroName": args.wsl_distro_name,
            },
        )
        receipt.out_path = args.receipt_out
        receipt.record("input-preflight", False, error=f"{type(exc).__name__}: {exc}")
        receipt.document["result"] = "failed"
        receipt.write(args.receipt_out)
        log(f"result: failed -> {args.receipt_out}")
        return 1

    vm = None
    try:
        vm = boot_native_follow_on(
            args.vm_dir, site_root=args.site_root,
            distro_name=args.wsl_distro_name,
            expected_identity=prerequisite_evidence["nativeIdentity"],
            expected_baseline=prerequisite_evidence["rehearsalBaseline"],
        )
        summary = execute_reboot_stage(
            vm, facts=facts, evidence=prerequisite_evidence,
            prepublication_mirror=args.prepublication_mirror,
            receipt_out=args.receipt_out,
        )
        log(f"result: passed -> {args.receipt_out} ({summary['mode']})")
        return 0
    except (Exception, SystemExit) as exc:
        # execute_reboot_stage finalizes its own failed receipt; an attach
        # failure before the stage still needs one durable failure document.
        _write_attach_failure(args, facts, prerequisite_evidence, exc)
        log(f"result: failed -> {args.receipt_out} ({type(exc).__name__}: {exc})")
        return 1
    finally:
        if vm is not None:
            vm.teardown()


if __name__ == "__main__":
    sys.exit(main())
