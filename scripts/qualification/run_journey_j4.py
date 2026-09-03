#!/usr/bin/env python3
"""Release journey J4 driver: backup, restore, retain-reinstall, purge, recover."""
from __future__ import annotations

import argparse
import base64
import json
import secrets
import shlex
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from journey_common import (  # noqa: E402
    GuestJsonClient,
    JourneyReceipt,
    Refusal,
    boot_retained_vm,
    discover_services,
    log,
    validate_retained_candidate_inputs,
    verify_installed_image_digests,
    wait_service_healthy,
)
from run_journey_j2 import (  # noqa: E402
    RECORD_ACTION,
    _object_digest,
    _study_state_snapshot,
    governed_chain,
)

LIFECYCLE_ENV = "WSL_INTEROP=/run/WSL/1_interop WSL_DISTRO_NAME=Ubuntu-24.04"
# The rootless install runs as the SSH/rehearsal user; its install root is
# $XDG_STATE_HOME/stateport-install under that user's home (the installer
# root, NOT the stateport-control user, and NOT the bare stateport path).
STATE_ROOT = "$HOME/.local/state/stateport-install"
UNITS_DIR = "/var/lib/stateport-control/.config/containers/systemd"


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def pick(doc, *names):
    for name in names:
        value = doc.get(name) if isinstance(doc, dict) else None
        if value:
            return value, name
    return None, None


def mutate(receipt, web, step, method, path, body):
    try:
        return web.request(method, path, body, csrf=True)
    except Refusal as refusal:
        receipt.document.setdefault("refusals", []).append(
            {"step": step, "code": refusal.code, "message": refusal.message,
             "status": refusal.status})
        raise


def run_bootstrap(vm, timeout: int):
    return vm.ssh(
        f"{LIFECYCLE_ENV} sh /tmp/stateport-bootstrap",
        check=False,
        timeout=timeout,
        tty=True,
        stdin_text="install\n",
    )


def run_installer(vm, argline: str, timeout: int):
    return vm.ssh(
        " ".join(
            (
                LIFECYCLE_ENV,
                "python3 /tmp/stateport-installer",
                argline,
                f'--state-root "{STATE_ROOT}"',
            )
        ),
        check=False,
        timeout=timeout,
    )


def stage_interrupted_uninstall(vm, root: str):
    marker = f"{root}/stop-completed"
    script = f"""#!/bin/sh
mutating=0
for argument in "$@"; do
  [ "$argument" = stop ] && mutating=1
done
/usr/bin/systemctl "$@"
result=$?
if [ "$mutating" -eq 1 ] && [ "$result" -eq 0 ] && [ ! -e {shlex.quote(marker)} ]; then
  : > {shlex.quote(marker)}
  sleep 300
fi
exit "$result"
"""
    encoded = base64.b64encode(script.encode("utf-8")).decode("ascii")
    staged = vm.ssh(
        f"rm -rf {shlex.quote(root)} && mkdir -m 0777 {shlex.quote(root)} && "
        f"mkdir -m 0755 {shlex.quote(root + '/bin')} && "
        f"printf %s {shlex.quote(encoded)} | base64 -d > "
        f"{shlex.quote(root + '/bin/systemctl')} && "
        f"chmod 0755 {shlex.quote(root + '/bin/systemctl')}",
        check=False,
        timeout=60,
    )
    return staged, marker


def newest_receipt_document(vm, kind: str):
    pattern = f"$HOME/.local/state/stateport-install/receipts/{kind}_receipt_*.json"
    listed = vm.ssh(f"ls -1t {pattern} 2>/dev/null | head -n 1", check=False, timeout=60)
    path = listed.stdout.strip().splitlines()[0] if listed.stdout.strip() else ""
    if not path:
        return None
    content = vm.ssh(f"sudo cat {shlex.quote(path)}", check=False, timeout=60)
    if content.returncode != 0:
        return None
    try:
        return json.loads(content.stdout)
    except json.JSONDecodeError:
        return None


def collect_instance_ids(payload):
    if isinstance(payload, list):
        entries = payload
    elif isinstance(payload, dict):
        entries = None
        for key in ("instances", "entries", "items", "results", "data"):
            if isinstance(payload.get(key), list):
                entries = payload[key]
                break
        if entries is None and isinstance(payload.get("result"), (list, dict)):
            return collect_instance_ids(payload["result"])
    else:
        return []
    ids = []
    for entry in entries:
        if isinstance(entry, str):
            ids.append(entry)
        elif isinstance(entry, dict):
            value = entry.get("instanceId") or entry.get("id")
            if value:
                ids.append(str(value))
    return ids


def wait_all_healthy(vm, services):
    for service_id in ("stateport-web", "stateport-api", "stateport-worker"):
        wait_service_healthy(vm, services, service_id, deadline_s=420)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt-out", type=Path, required=True)
    parser.add_argument("--vm-dir", type=Path, required=True)
    parser.add_argument("--candidate-dir", type=Path, required=True)
    parser.add_argument("--site-root", type=Path, required=True)
    parser.add_argument("--archive-root", type=Path, required=True)
    args = parser.parse_args()

    try:
        facts, prerequisite_evidence = validate_retained_candidate_inputs(
            args.candidate_dir, args.vm_dir, args.site_root, args.archive_root
        )
    except Exception as exc:  # noqa: BLE001 - preflight failure must be durable
        receipt = JourneyReceipt(
            "J4-backup-restore-retain-purge-recover",
            {
                "candidateDir": str(args.candidate_dir),
                "vmDir": str(args.vm_dir),
                "siteRoot": str(args.site_root),
                "archiveRoot": str(args.archive_root),
            },
        )
        receipt.out_path = args.receipt_out
        receipt.record("input-preflight", False, error=f"{type(exc).__name__}: {exc}")
        receipt.document["result"] = "failed"
        receipt.write(args.receipt_out)
        log(f"result: failed -> {args.receipt_out}")
        return 1
    receipt = JourneyReceipt(
        "J4-backup-restore-retain-purge-recover",
        {"candidate": facts, "prerequisites": prerequisite_evidence},
    )
    receipt.out_path = args.receipt_out
    receipt.write(args.receipt_out)

    vm = None
    try:
        receipt.record("input-preflight", True, **prerequisite_evidence)
        vm = boot_retained_vm(
            args.vm_dir, site_root=args.site_root, archive_root=args.archive_root
        )
        services = discover_services(vm)
        wait_all_healthy(vm, services)
        digests = verify_installed_image_digests(vm, dict(facts["images"]))  # type: ignore[arg-type]
        receipt.record("control-plane-bound-to-candidate",
                       not digests["mismatches"], services=services)  # type: ignore[union-attr]

        web = GuestJsonClient(vm, services["stateport-web"]["port"])
        session = web.request("GET", "/session")
        web.handshake()
        receipt.record("web-session-handshake", True,
                       session={k: v for k, v in session.items() if k != "csrfToken"})

        catalog = web.request("GET", "/v1/applications")
        study = next(e for e in catalog["applications"] if e["applicationId"] == "studystate.sample")
        identity = study["applicationIdentity"]

        instance_id = "j4journey-" + secrets.token_hex(4)
        installed = mutate(receipt, web, "fixture-install-browser-consent",
                           "POST", "/v1/application-fixtures/install",
                           {"applicationId": "studystate.sample", "instanceId": instance_id,
                            "name": "Release Journey StudyState",
                            "applicationDescriptorDigest": identity["descriptorDigest"],
                            "applicationPackageDigest": identity["packageDigest"],
                            "experienceDescriptorDigest": study["experienceIdentity"]["descriptorDigest"]})
        lifecycle = installed.get("lifecycle") or {}
        fixture_ok = lifecycle.get("revisionId") == "v0001"
        receipt.record("fixture-install-browser-consent", fixture_ok,
                       instanceId=instance_id,
                       revisionId=lifecycle.get("revisionId"),
                       releaseVersion=lifecycle.get("releaseVersion"),
                       receiptId=(installed.get("receipt") or {}).get("receiptId"))
        expect(fixture_ok, f"unexpected fixture install identity: {installed}")

        baseline = web.request("GET", f"/v1/instances/{instance_id}")
        baseline_package = baseline.get("packageState")
        expect(isinstance(baseline_package, dict), "StudyState baseline is unavailable")
        activities = baseline_package.get("activities")
        activity = next(
            (
                entry
                for entry in activities
                if isinstance(entry, dict) and isinstance(entry.get("id"), str)
            ),
            None,
        ) if isinstance(activities, list) else None
        expect(isinstance(activity, dict), "StudyState baseline has no mutable activity")
        reflection = "J4 exact-candidate backup and lifecycle evidence."
        mutation = governed_chain(
            web,
            instance_id,
            RECORD_ACTION,
            {"activityId": activity["id"], "evidenceSummary": reflection},
        )
        mutated = web.request("GET", f"/v1/instances/{instance_id}")
        durable_package = mutated.get("packageState")
        durable_snapshot = _study_state_snapshot(durable_package)
        baseline_snapshot = _study_state_snapshot(baseline_package)
        applied_run = mutation.get("applied")
        durable_state_created = (
            isinstance(durable_package, dict)
            and durable_snapshot != baseline_snapshot
            and isinstance(applied_run, dict)
            and applied_run.get("canonicalStateBefore") != applied_run.get("canonicalStateAfter")
        )
        receipt.record(
            "durable-application-state-created",
            durable_state_created,
            instanceId=instance_id,
            activityId=activity["id"],
            runId=mutation.get("runId"),
            proposalDigest=mutation.get("proposalDigest"),
            canonicalStateBefore=(applied_run or {}).get("canonicalStateBefore"),
            canonicalStateAfter=(applied_run or {}).get("canonicalStateAfter"),
            semanticStateBefore=_object_digest(baseline_snapshot),
            semanticStateAfter=_object_digest(durable_snapshot),
        )
        expect(durable_state_created, "governed StudyState mutation did not create durable state")

        backup = mutate(receipt, web, "backup-verified", "POST",
                        f"/v1/instances/{instance_id}/backup", {})
        backup_document = backup.get("backupReceipt")
        backup_receipt = (
            backup_document.get("receiptId") if isinstance(backup_document, dict) else None
        )
        backup_ok = (isinstance(backup_receipt, str) and backup_receipt.startswith("backup-")
                     and backup.get("validation") == "verified"
                     and isinstance(backup_document, dict)
                     and backup_document.get("status") == "verified"
                     and backup_document.get("instanceId") == instance_id
                     and bool(backup.get("archiveDigest"))
                     and bool(backup.get("archiveFileDigest")))
        receipt.record("backup-verified", backup_ok,
                       receiptId=backup_receipt,
                       status=(backup_document or {}).get("status"),
                       releaseId=facts["releaseId"],
                       signedPayloadDigest=facts["signedPayloadDigest"],
                       semanticStateDigest=_object_digest(durable_snapshot),
                       archiveDigest=backup.get("archiveDigest"),
                       archiveFileDigest=backup.get("archiveFileDigest"),
                       rawKeys=sorted(backup))
        expect(backup_ok, f"backup response missing expected fields: {sorted(backup)}")

        recovery = web.request("GET", f"/v1/instances/{instance_id}/recovery")
        # The recovery projection nests the newest verified backup under
        # ``latest`` (not a flat list keyed by receiptId).
        latest = recovery.get("latest") if isinstance(recovery, dict) else None
        listed_entry = latest if isinstance(latest, dict) else None
        listed_verified = (
            isinstance(listed_entry, dict)
            and str(listed_entry.get("receiptId") or "") == str(backup_receipt)
            and listed_entry.get("status") == "verified"
        )
        receipt.record("recovery-lists-backup", listed_verified,
                       rawKeys=sorted(recovery) if isinstance(recovery, dict) else [],
                       observed=listed_entry or {})
        expect(listed_verified, "backup not listed verified in recovery surface")

        copy_instance = "j4copy-" + secrets.token_hex(4)
        plan_resp = mutate(receipt, web, "restore-plan-created", "POST",
                           f"/v1/instances/{instance_id}/recovery/restore/plan",
                           {"backupReceiptId": backup_receipt,
                            "destinationInstanceId": copy_instance})
        plan_digest, plan_key = pick(plan_resp, "planDigest", "restorePlanDigest")
        receipt.record("restore-plan-created", bool(plan_digest),
                       destinationInstanceId=copy_instance, digestKey=plan_key,
                       rawKeys=sorted(plan_resp))
        expect(bool(plan_digest), f"restore plan lacks digest: {sorted(plan_resp)}")

        approved = mutate(receipt, web, "restore-approved", "POST",
                          f"/v1/instances/{instance_id}/recovery/restore/approve",
                          {"planDigest": plan_digest})
        approval_digest, approval_key = pick(approved, "approvalDigest", "digest")
        if approval_digest is None and isinstance(approved.get("approval"), dict):
            approval_digest, approval_key = pick(approved["approval"], "digest", "approvalDigest")
        receipt.record("restore-approved", bool(approval_digest), digestKey=approval_key,
                       rawKeys=sorted(approved))
        expect(bool(approval_digest), f"approve response lacks approval digest: {sorted(approved)}")

        applied = mutate(receipt, web, "restore-applied", "POST",
                         f"/v1/instances/{instance_id}/recovery/restore/apply",
                         {"planDigest": plan_digest, "approvalDigest": approval_digest})
        result_block = applied.get("result") if isinstance(applied.get("result"), dict) else {}
        validation = next((source["validation"] for source in (result_block, applied)
                            if isinstance(source.get("validation"), (dict, bool))), None)
        validation_ok = (validation.get("valid") is True if isinstance(validation, dict)
                          else validation is True)
        catalog_identity = (result_block.get("catalogIdentity")
                             or applied.get("catalogIdentity"))
        restored = web.request("GET", f"/v1/instances/{copy_instance}")
        restored_package = restored.get("packageState")
        restored_snapshot = _study_state_snapshot(restored_package)
        restore_ok = (
            applied.get("status") == "validated"
            and bool(validation_ok)
            and bool(catalog_identity)
            and result_block.get("archiveDigest") == backup.get("archiveDigest")
            and restored_snapshot == durable_snapshot
        )
        receipt.record("restore-applied", restore_ok,
                        destinationInstanceId=copy_instance,
                       restoreReceiptId=applied.get("receiptId"),
                        validationOk=validation_ok,
                       archiveDigest=result_block.get("archiveDigest"),
                       semanticStateDigest=_object_digest(restored_snapshot),
                       expectedSemanticStateDigest=_object_digest(durable_snapshot),
                        catalogIdentity=catalog_identity,
                        rawKeys=sorted(applied))
        expect(restore_ok,
               f"restore apply did not reproduce the backed-up canonical state: {sorted(applied)}")

        vm.scp_in(str(prerequisite_evidence["bootstrapPath"]), "/tmp/stateport-bootstrap")
        vm.scp_in(str(prerequisite_evidence["installerPath"]), "/tmp/stateport-installer")
        guest_bootstrap = vm.ssh(
            "sha256sum /tmp/stateport-bootstrap", check=False, timeout=60
        )
        guest_installer = vm.ssh(
            "sha256sum /tmp/stateport-installer", check=False, timeout=60
        )
        observed_bootstrap = (
            "sha256:" + guest_bootstrap.stdout.strip().split()[0]
            if guest_bootstrap.returncode == 0 and guest_bootstrap.stdout.strip()
            else None
        )
        observed_installer = (
            "sha256:" + guest_installer.stdout.strip().split()[0]
            if guest_installer.returncode == 0 and guest_installer.stdout.strip()
            else None
        )
        artifacts_ok = (
            observed_bootstrap == prerequisite_evidence["bootstrapDigest"]
            and observed_installer == prerequisite_evidence["installerDigest"]
        )
        receipt.record(
            "candidate-lifecycle-artifacts-staged",
            artifacts_ok,
            bootstrap={
                "hostPath": prerequisite_evidence["bootstrapPath"],
                "expectedDigest": prerequisite_evidence["bootstrapDigest"],
                "observedDigest": observed_bootstrap,
            },
            installer={
                "hostPath": prerequisite_evidence["installerPath"],
                "expectedDigest": prerequisite_evidence["installerDigest"],
                "observedDigest": observed_installer,
            },
        )
        expect(artifacts_ok, "guest lifecycle artifact digest mismatch")

        uninstall = run_installer(vm, "--uninstall", 1800)
        uninstall_doc = newest_receipt_document(vm, "uninstall") if uninstall.returncode == 0 else None
        units_left = vm.ssh(f"sudo sh -c 'ls {UNITS_DIR}/*.container 2>/dev/null | wc -l'",
                            check=False, timeout=60)
        units_count = int(units_left.stdout.strip() or "-1")
        state_root_kept = vm.ssh(f"test -d {STATE_ROOT}", check=False, timeout=60).returncode == 0
        retain_ok = (
            uninstall.returncode == 0
            and isinstance(uninstall_doc, dict)
            and uninstall_doc.get("action") == "uninstall"
            and uninstall_doc.get("result") in {"succeeded", "already_uninstalled"}
            and units_count == 0
            and state_root_kept
        )
        receipt.record("uninstall-retaining-state", retain_ok,
                       exitCode=uninstall.returncode,
                       uninstallReceiptStatus=(uninstall_doc or {}).get("status"),
                       uninstallReceiptResult=(uninstall_doc or {}).get("result"),
                       rawKeys=sorted(uninstall_doc) if isinstance(uninstall_doc, dict) else [],
                       unitsLeft=units_count, stateRootPreserved=state_root_kept)
        expect(retain_ok,
               f"retain-uninstall did not converge (exit={uninstall.returncode}, "
               f"units={units_count}, stateRootKept={state_root_kept})")

        adopt = run_bootstrap(vm, 3600)
        expect(adopt.returncode == 0, f"adopting reinstall failed: {adopt.stderr[-300:]}")
        services = discover_services(vm)
        wait_all_healthy(vm, services)
        web = GuestJsonClient(vm, services["stateport-web"]["port"])
        web.handshake()
        instances = web.request("GET", "/v1/instances")
        observed_ids = collect_instance_ids(instances)
        adopted = web.request("GET", f"/v1/instances/{instance_id}")
        adopted_snapshot = _study_state_snapshot(adopted.get("packageState"))
        adopt_ok = instance_id in observed_ids and adopted_snapshot == durable_snapshot
        receipt.record("reinstall-adopts-retained-state", adopt_ok,
                       reinstallExitCode=adopt.returncode,
                       expectedSemanticStateDigest=_object_digest(durable_snapshot),
                       observedSemanticStateDigest=_object_digest(adopted_snapshot),
                       observedInstanceIds=observed_ids[:20],
                       rawKeys=sorted(instances) if isinstance(instances, dict) else [])
        expect(adopt_ok, "adopting reinstall did not preserve the exact durable state")

        interrupt_root = f"/tmp/j4-interrupt-{secrets.token_hex(4)}"
        shim, interruption_marker = stage_interrupted_uninstall(vm, interrupt_root)
        expect(shim.returncode == 0, f"could not stage lifecycle interruption: {shim.stderr[-200:]}")
        interrupted = vm.ssh(
            f"{LIFECYCLE_ENV} timeout --signal=TERM --kill-after=5s 45s env "
            f"PATH={shlex.quote(interrupt_root + '/bin')}:/usr/local/sbin:/usr/local/bin:"
            f"/usr/sbin:/usr/bin:/sbin:/bin python3 /tmp/stateport-installer "
            f'--uninstall --state-root "{STATE_ROOT}"',
            check=False,
            timeout=300,
        )
        effect_completed = vm.ssh(
            f"test -f {shlex.quote(interruption_marker)}", check=False, timeout=30
        ).returncode == 0
        resumed = run_installer(vm, "--uninstall", 1800)
        vm.ssh(f"rm -rf {shlex.quote(interrupt_root)}", check=False, timeout=30)
        recover_ok = (
            interrupted.returncode != 0 and effect_completed and resumed.returncode == 0
        )
        receipt.record("interrupted-transition-recovers", recover_ok,
                       interruptedExitCode=interrupted.returncode,
                       effectCompletedBeforeSignal=effect_completed,
                       resumedExitCode=resumed.returncode)
        expect(recover_ok, "partially completed uninstall did not resume to convergence")

        trust = vm.ssh(f"sudo cat {STATE_ROOT}/updater/trust/install-trust.json",
                       check=False, timeout=60)
        expect(trust.returncode == 0,
               f"install-trust.json unreadable: {trust.stderr[-200:]}")
        identity_id = str(json.loads(trust.stdout).get("installedIdentityId") or "")
        expect(bool(identity_id), "installedIdentityId missing from install-trust.json")
        purge = vm.ssh(
            f"{LIFECYCLE_ENV} python3 /tmp/stateport-installer --purge "
            f'--confirm-purge {shlex.quote(identity_id)} --state-root "{STATE_ROOT}"',
            check=False, timeout=1800,
        )
        state_root_gone = vm.ssh(f"test ! -d {STATE_ROOT}", check=False, timeout=60).returncode == 0
        purge_receipt = vm.ssh(
            "ls $HOME/.local/state/stateport-install.purge-receipt.json 2>/dev/null "
            "|| ls $HOME/.local/state/*.purge-receipt.json",
            check=False, timeout=60)
        purge_receipt_path = (
            purge_receipt.stdout.strip().splitlines()[0]
            if purge_receipt.stdout.strip()
            else ""
        )
        purge_document_result = vm.ssh(
            f"cat {shlex.quote(purge_receipt_path)}" if purge_receipt_path else "false",
            check=False,
            timeout=60,
        )
        try:
            purge_document = (
                json.loads(purge_document_result.stdout)
                if purge_document_result.returncode == 0
                else None
            )
        except json.JSONDecodeError:
            purge_document = None
        removed = purge_document.get("removed") if isinstance(purge_document, dict) else None
        removed_volumes = removed.get("volumes") if isinstance(removed, dict) else None
        volume_absence = {}
        if isinstance(removed_volumes, list):
            for volume in removed_volumes:
                expect(isinstance(volume, str) and bool(volume), "purge receipt volume is invalid")
                quoted = shlex.quote(volume)
                owner_checks = {
                    "installUser": vm.ssh(
                        f"podman volume exists {quoted}", check=False, timeout=60
                    ).returncode,
                    "controlUser": vm.ssh(
                        "sudo runuser -u stateport-control -- env "
                        "HOME=/var/lib/stateport-control "
                        "XDG_RUNTIME_DIR=/run/user/$(id -u stateport-control) "
                        f"podman volume exists {quoted}",
                        check=False,
                        timeout=60,
                    ).returncode,
                }
                volume_absence[volume] = owner_checks
        volumes_absent = (
            isinstance(removed_volumes, list)
            and bool(removed_volumes)
            and all(code == 1 for checks in volume_absence.values() for code in checks.values())
        )
        purge_installation = (
            purge_document.get("installation") if isinstance(purge_document, dict) else None
        )
        purge_ok = (
            purge.returncode == 0
            and state_root_gone
            and isinstance(purge_document, dict)
            and purge_document.get("action") == "purge"
            and purge_document.get("result") == "succeeded"
            and isinstance(purge_installation, dict)
            and purge_installation.get("installedIdentityId") == identity_id
            and volumes_absent
        )
        receipt.record("purge-with-explicit-authority", purge_ok,
                       installedIdentityId=identity_id, exitCode=purge.returncode,
                       stateRootAbsent=state_root_gone,
                       purgeReceiptPath=purge_receipt_path or None,
                       removedVolumes=removed_volumes,
                       volumeAbsence=volume_absence)
        expect(purge_ok, "purge did not remove the exact owned state and volumes")

        fresh = run_bootstrap(vm, 3600)
        expect(fresh.returncode == 0, f"clean reinstall failed: {fresh.stderr[-300:]}")
        services = discover_services(vm)
        wait_all_healthy(vm, services)
        readyz = vm.ssh(f"curl -fsS -m 10 http://127.0.0.1:{services['stateport-api']['port']}/readyz",
                        check=False, timeout=60)
        try:
            ready_doc = json.loads(readyz.stdout) if readyz.stdout.strip() else {}
        except json.JSONDecodeError:
            ready_doc = {"raw": readyz.stdout[-200:]}
        ready_flag = ready_doc.get("ready", ready_doc.get("ok")) if isinstance(ready_doc, dict) else None
        web = GuestJsonClient(vm, services["stateport-web"]["port"])
        web.handshake()
        fresh_catalog = web.request("GET", "/v1/applications")
        fresh_study = next(
            entry
            for entry in fresh_catalog["applications"]
            if entry["applicationId"] == "studystate.sample"
        )
        fresh_identity = fresh_study["applicationIdentity"]
        fresh_instance_id = "j4fresh-" + secrets.token_hex(4)
        fresh_installed = mutate(
            receipt,
            web,
            "clean-reinstall-stateware-smoke",
            "POST",
            "/v1/application-fixtures/install",
            {
                "applicationId": "studystate.sample",
                "instanceId": fresh_instance_id,
                "name": "J4 Recovered StudyState",
                "applicationDescriptorDigest": fresh_identity["descriptorDigest"],
                "applicationPackageDigest": fresh_identity["packageDigest"],
                "experienceDescriptorDigest": fresh_study["experienceIdentity"]["descriptorDigest"],
            },
        )
        fresh_projection = web.request("GET", f"/v1/instances/{fresh_instance_id}")
        fresh_package = fresh_projection.get("packageState")
        recovered = (
            readyz.returncode == 0
            and bool(ready_flag)
            and isinstance(fresh_package, dict)
            and bool(fresh_package.get("activities"))
            and (fresh_installed.get("lifecycle") or {}).get("revisionId") == "v0001"
        )
        receipt.record("clean-reinstall-recovered", recovered,
                       reinstallExitCode=fresh.returncode,
                       readyFlag=ready_flag,
                       instanceId=fresh_instance_id,
                       semanticStateDigest=(
                           _object_digest(_study_state_snapshot(fresh_package))
                           if isinstance(fresh_package, dict)
                           else None
                       ),
                       rawKeys=sorted(ready_doc) if isinstance(ready_doc, dict) else [])
        expect(recovered, "clean reinstall did not recover healthy Stateware operation")

        receipt.document["result"] = "passed"
    except Refusal as refusal:
        receipt.record("typed-refusal", False, code=refusal.code,
                       message=refusal.message, status=refusal.status)
        receipt.document["result"] = "failed"
    except Exception as exc:  # noqa: BLE001 - the receipt must carry the failure out
        receipt.record("driver-error", False, error=f"{type(exc).__name__}: {exc}")
        receipt.document["result"] = "failed"
    finally:
        if vm is not None:
            vm.teardown()
    receipt.write(args.receipt_out)
    log(f"result: {receipt.document['result']} -> {args.receipt_out}")
    return 0 if receipt.document["result"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
