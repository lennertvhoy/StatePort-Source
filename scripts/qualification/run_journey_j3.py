#!/usr/bin/env python3
"""Release journey J3 driver: successor apply, manual rollback, sabotaged auto-rollback."""
from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from journey_common import (  # noqa: E402
    GuestJsonClient,
    JourneyReceipt,
    Refusal,
    boot_retained_vm,
    control_user_env,
    discover_services,
    load_release_facts,
    log,
    validate_retained_candidate_inputs,
    wait_service_healthy,
)

REGISTRY = "127.0.0.1:5443/stateport-alpha"
STAGE = "/var/lib/stateport-control/v19stage"
STATUS_ROOTS = (
    # The rootless install's root is $XDG_STATE_HOME/stateport-install under
    # the SSH/rehearsal user's home (the installer root, not the bare
    # stateport path).  The stateport-control user only owns live quadlet
    # units/volumes.
    "$HOME/.local/state/stateport-install",
    "$HOME/.local/state/stateport",
    "/var/lib/stateport-control/.local/state/stateport",
)
TRIPLE_KEYS = ("releaseId", "version", "signedPayloadDigest")
FLAG_ALTS = {
    "--release-index": ["--index", "--release-index-file"],
    "--plan-id": ["--plan"],
    "--authorization": ["--auth", "--authorization-file"],
    "--output": ["--out"],
}


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def parse_jsonish(text: str):
    try:
        return json.loads(text.strip())
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                return None
    return None


def triple_matches(current, facts) -> bool:
    return isinstance(current, dict) and all(current.get(key) == facts[key]
                                             for key in TRIPLE_KEYS)


def extract_plan_id(doc, raw: str):
    sources = [doc] if isinstance(doc, dict) else []
    if sources and isinstance(sources[0].get("plan"), dict):
        sources.append(sources[0]["plan"])
    for source in sources:
        value = next((source[key] for key in ("planId", "plan_id", "id")
                      if isinstance(source.get(key), str) and source[key]), None)
        if value:
            return value
    match = re.search(r'"planId"\s*:\s*"([^"]+)"', raw)
    return match.group(1) if match else None


def read_json_file(vm, path: str) -> dict:
    result = vm.ssh(f"sudo cat {shlex.quote(path)} 2>/dev/null", check=False, timeout=60)
    doc = parse_jsonish(result.stdout) if result.returncode == 0 else None
    return doc if isinstance(doc, dict) else {}


def read_current(vm, sr: str) -> dict:
    return read_json_file(vm, f"{sr}/updater/status.json").get("current") or {}


def find_state_root(vm):
    # Expand $HOME as the SSH user (the rootless install ran as that user);
    # sudo cat would otherwise expand it to root's home.
    expanded = vm.ssh("echo $HOME", check=False, timeout=30).stdout.strip()
    for candidate in STATUS_ROOTS:
        resolved = candidate.replace("$HOME", expanded) if expanded else candidate
        doc = read_json_file(vm, f"{resolved}/updater/status.json")
        if doc:
            return resolved, doc
    return None, {}


def newest_update_receipt(vm, sr: str) -> dict:
    listed = vm.ssh(f"sudo sh -c 'ls -1t {sr}/updater/receipts/update_receipt_*.json "
                    f"2>/dev/null | head -n 1'", check=False, timeout=60)
    path = listed.stdout.strip().splitlines()[0] if listed.stdout.strip() else ""
    return read_json_file(vm, path) if path else {}


def updater_cmd(updater: str, sr: str, argline: str) -> str:
    inner = (f"export XDG_RUNTIME_DIR=/run/user/$(id -u); "
             f"{updater} --state-root {sr} {argline}")
    if sr.startswith("/var/lib/stateport-control/"):
        # Control-owned state root: run as stateport-control.
        return f"sudo runuser -u stateport-control -- bash -c {shlex.quote(inner)}"
    # The rootless install's state root lives under the SSH user's home and
    # is owned by that user; the updater must run as its owner.
    return f"bash -c {shlex.quote(inner)}"


def run_updater(vm, updater: str, sr: str, argline: str, timeout: int = 900):
    invocation = updater_cmd(updater, sr, argline)
    result = vm.ssh(invocation, check=False, timeout=timeout)
    low = (result.stdout + result.stderr).lower()
    if result.returncode == 0 or not any(
            token in low for token in ("unknown", "unrecognized", "invalid option")):
        return result, invocation, None
    help_note = vm.ssh(updater_cmd(updater, sr, "--help"),
                       check=False, timeout=120).stdout[-800:]
    changed = argline
    for flag, alts in FLAG_ALTS.items():
        for alt in alts:
            if flag in changed and alt in help_note:
                changed = changed.replace(flag, alt)
                break
    if changed == argline:
        return result, invocation, help_note
    retry_cmd = updater_cmd(updater, sr, changed)
    retry = vm.ssh(retry_cmd, check=False, timeout=timeout)
    if retry.returncode == 0:
        return retry, retry_cmd, help_note
    return result, invocation, help_note


def updater_step(receipt, vm, updater: str, sr: str, argline: str, timeout: int = 900):
    verb = argline.split()[0]
    result, invocation, help_note = run_updater(vm, updater, sr, argline, timeout)
    receipt.record(f"updater-{verb}", result.returncode == 0, invocation=invocation,
                   helpNote=help_note, exitCode=result.returncode,
                   raw=result.stdout[-400:])
    return result.returncode == 0, result.stdout


def launch_background_apply(vm, updater: str, sr: str):
    inner = (f"export XDG_RUNTIME_DIR=/run/user/$(id -u); "
             f"nohup {updater} --state-root {sr} apply >/tmp/j3-e2-apply.log 2>&1 & echo $!")
    if sr.startswith("/var/lib/stateport-control/"):
        invocation = f"sudo runuser -u stateport-control -- bash -c {shlex.quote(inner)}"
    else:
        invocation = f"bash -c {shlex.quote(inner)}"
    result = vm.ssh(invocation, check=False, timeout=60)
    pid = result.stdout.strip().splitlines()[-1].strip() if result.stdout.strip() else ""
    return pid if pid.isdigit() else None


def accepted_api_unit(vm) -> str:
    script = ("for f in /var/lib/stateport-control/.config/containers/systemd/*.container; "
              "do [ -f \"$f\" ] || continue; grep -q '^Label=io.stateport.profile=accepted$' "
              "\"$f\" || continue; grep -q '^Label=io.stateport.service.id=stateport-api$' "
              "\"$f\" || continue; basename \"$f\" .container; break; done")
    result = vm.ssh(f"sudo sh -c {shlex.quote(script)}", check=False, timeout=60)
    name = result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""
    return f"{name}.service" if name and "-accepted-" in name else ""


def stop_accepted_unit(vm, unit: str):
    inner = control_user_env() + f"; run_control systemctl --user stop {unit}"
    return vm.ssh(f"sudo runuser -u stateport-control -- bash -c {shlex.quote(inner)}",
                  check=False, timeout=120)


def poll_for(action, timeout_s: int, interval: float):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        outcome = action()
        if outcome:
            return outcome
        time.sleep(interval)
    return None


def guest_tail(vm, path: str) -> str:
    return vm.ssh(f"sudo tail -n 40 {shlex.quote(path)} 2>/dev/null",
                  check=False, timeout=60).stdout[-1500:]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt-out", type=Path, required=True)
    parser.add_argument("--predecessor-vm-dir", type=Path, required=True)
    parser.add_argument("--predecessor-candidate-dir", type=Path, required=True)
    parser.add_argument("--predecessor-site-root", type=Path, required=True)
    parser.add_argument("--predecessor-archive-root", type=Path, required=True)
    parser.add_argument("--successor-dir", type=Path, required=True)
    parser.add_argument("--archive-root", type=Path, required=True)
    args = parser.parse_args()

    pred_candidate = args.predecessor_candidate_dir
    if not args.archive_root.is_absolute():
        raise SystemExit("successor archive root must be an absolute path")
    archive_root = args.archive_root
    facts = load_release_facts(args.successor_dir)
    pred_facts, predecessor_evidence = validate_retained_candidate_inputs(
        pred_candidate,
        args.predecessor_vm_dir,
        args.predecessor_site_root,
        args.predecessor_archive_root,
    )
    receipt = JourneyReceipt("J3-updater-apply-rollback-auto-rollback", {
        "successor": facts, "predecessor": pred_facts,
        "predecessorPrerequisites": predecessor_evidence,
        "archiveRoot": str(archive_root),
        "predecessorCandidateDir": str(pred_candidate)})
    receipt.out_path = args.receipt_out
    receipt.write(args.receipt_out)

    vm = boot_retained_vm(
        args.predecessor_vm_dir,
        site_root=args.predecessor_site_root,
        archive_root=args.predecessor_archive_root,
    )
    try:
        sr, status_doc = find_state_root(vm)
        current = status_doc.get("current")
        identity_ok = bool(sr) and triple_matches(current, pred_facts)
        receipt.record("predecessor-identity-verified", identity_ok, stateRoot=sr,
                       observedCurrent=current if isinstance(current, dict) else {},
                       rawKeys=sorted(status_doc))
        expect(identity_ok, f"predecessor status.json identity mismatch at {sr}")
        updater = f"{sr}/bin/stateport-update"
        present = vm.ssh(f"sudo test -x {updater}", check=False, timeout=30)
        expect(present.returncode == 0, f"updater binary missing at {updater}")

        archives = sorted(archive_root.glob("*.oci.tar"))
        expect(bool(archives), f"no oci archives under {archive_root}")
        loaded = []
        for archive in archives:
            image_id = archive.name.removesuffix(".oci.tar")
            vm.scp_in(str(archive), f"/tmp/{archive.name}")
            push = vm.ssh(
                f"sudo runuser -u stateport-control -- skopeo copy --dest-tls-verify=false "
                f"oci-archive:/tmp/{archive.name} docker://{REGISTRY}/{image_id}",
                check=False, timeout=1200)
            loaded.append({"imageId": image_id, "exitCode": push.returncode})
            if push.returncode != 0:
                break
        load_ok = bool(loaded) and all(entry["exitCode"] == 0 for entry in loaded)
        receipt.record("successor-archives-loaded", load_ok, loaded=loaded,
                       registry=REGISTRY)
        expect(load_ok, f"registry load failed: {loaded[-1:]}")

        vm.ssh(f"sudo mkdir -p {STAGE} && sudo chown stateport-control:stateport-control {STAGE}",
               check=False, timeout=60)
        for name in ("release-index.json", "release-index.sigstore.json"):
            source = args.successor_dir / name
            expect(source.is_file(), f"missing successor input {source}")
            vm.scp_in(str(source), f"/tmp/{name}")
            copied = vm.ssh(f"sudo cp /tmp/{name} {STAGE}/{name} && sudo chown "
                            f"stateport-control:stateport-control {STAGE}/{name}",
                            check=False, timeout=60)
            expect(copied.returncode == 0, f"staging {name} failed: {copied.stderr[-200:]}")
        bundle_staged = False
        bundle_src = args.successor_dir / "predecessor-bundle"
        if bundle_src.is_dir():
            vm.scp_in(str(bundle_src), "/tmp/j3-predecessor-bundle")
            bundle_staged = vm.ssh(
                f"sudo rm -rf {STAGE}/predecessor-bundle && "
                f"sudo cp -r /tmp/j3-predecessor-bundle {STAGE}/predecessor-bundle && "
                f"sudo chown -R stateport-control:stateport-control {STAGE}/predecessor-bundle",
                check=False, timeout=300).returncode == 0
        receipt.record("successor-inputs-staged", True, stage=STAGE,
                       bundleStaged=bundle_staged)

        index_arg = f"--release-index {STAGE}/release-index.json"
        ok, _ = updater_step(receipt, vm, updater, sr, f"status {index_arg}")
        expect(ok, "updater status precheck failed")
        ok, plan_text = updater_step(receipt, vm, updater, sr, f"plan {index_arg}")
        plan_id = extract_plan_id(parse_jsonish(plan_text), plan_text)
        receipt.record("update-plan-id-captured", bool(plan_id), planId=plan_id)
        expect(bool(plan_id), "updater plan did not yield a planId")
        ok, _ = updater_step(receipt, vm, updater, sr,
                             f"authorize --plan-id {plan_id} --output {STAGE}/auth.json")
        expect(ok, "updater authorize failed")

        ok, _ = updater_step(receipt, vm, updater, sr, "apply", timeout=3000)
        e1_receipt = newest_update_receipt(vm, sr)
        e1_current = read_current(vm, sr)
        e1_ok = (ok and e1_receipt.get("result") in ("accepted", "succeeded")
                 and triple_matches(e1_current, facts))
        receipt.record("e1-clean-apply-healthy-route", e1_ok,
                       receiptResult=e1_receipt.get("result"),
                       receiptChecks=e1_receipt.get("checks"),
                       currentAfter=e1_current)
        expect(e1_ok, "clean apply did not reach successor with a healthy receipt")

        ok, _ = updater_step(receipt, vm, updater, sr,
                             f"rollback --plan-id {plan_id} --authorization {STAGE}/auth.json",
                             timeout=1800)
        rb_current = read_current(vm, sr)
        rb_ok = ok and triple_matches(rb_current, pred_facts)
        receipt.record("manual-rollback-restores-predecessor", rb_ok,
                       currentAfter=rb_current)
        expect(rb_ok, "manual rollback did not restore the predecessor")

        ok, plan2_text = updater_step(receipt, vm, updater, sr, f"plan {index_arg}")
        plan2_id = extract_plan_id(parse_jsonish(plan2_text), plan2_text)
        auth2_ok, _ = updater_step(receipt, vm, updater, sr,
                                   f"authorize --plan-id {plan2_id} --output {STAGE}/auth2.json")
        e2_ready = ok and bool(plan2_id) and auth2_ok
        receipt.record("e2-fresh-plan-authorized", e2_ready, planId=plan2_id)
        expect(e2_ready, "fresh E2 plan/authorize failed")

        pid = launch_background_apply(vm, updater, sr)
        receipt.record("e2-apply-launched-background", pid is not None, applyPid=pid)
        expect(pid is not None, "background sabotaged apply failed to launch")

        def switch_found():
            listed = vm.ssh(f"sudo sh -c 'ls {sr}/updater/host-effects/*/switch.json "
                            f"2>/dev/null'", check=False, timeout=30)
            lines = [line for line in listed.stdout.strip().splitlines() if line.strip()]
            return lines[0] if lines else None

        switch_path = poll_for(switch_found, 20 * 60, 3)
        receipt.record("e2-host-effect-switch-observed", switch_path is not None,
                       switchJson=switch_path)
        expect(switch_path is not None, "host-effects switch.json never appeared")

        unit = accepted_api_unit(vm)
        stopped = stop_accepted_unit(vm, unit) if unit else None
        sabotage_ok = bool(unit) and stopped is not None and stopped.returncode == 0
        receipt.record("e2-successor-unit-stopped", sabotage_ok, unit=unit,
                       exitCode=stopped.returncode if stopped else None)
        expect(sabotage_ok, f"could not stop exactly one successor api unit (unit={unit!r})")

        exited = poll_for(lambda: vm.ssh(f"sudo kill -0 {pid}",
                                         check=False, timeout=30).returncode != 0,
                          15 * 60, 10)
        e2_receipt = newest_update_receipt(vm, sr)
        rollback_info = e2_receipt.get("rollback") or {}
        e2_current = read_current(vm, sr)
        e2_ok = (bool(exited) and e2_receipt.get("result") == "rolled_back"
                 and rollback_info.get("succeeded") is True
                 and triple_matches(e2_current, pred_facts))
        receipt.record("e2-sabotaged-apply-auto-rolled-back", e2_ok, applyPid=pid,
                       applyExited=bool(exited), receiptResult=e2_receipt.get("result"),
                       rollbackSucceeded=rollback_info.get("succeeded"),
                       receiptChecks=e2_receipt.get("checks"),
                       currentAfter=e2_current,
                       applyLogTail=guest_tail(vm, "/tmp/j3-e2-apply.log"))
        expect(e2_ok, "sabotaged apply did not auto-roll back to the predecessor")

        services = discover_services(vm)
        for service_id in ("stateport-web", "stateport-api", "stateport-worker"):
            wait_service_healthy(vm, services, service_id, deadline_s=420)
        readyz = vm.ssh(f"curl -fsS -m 10 http://127.0.0.1:{services['stateport-api']['port']}/readyz",
                        check=False, timeout=60)
        ready_doc = parse_jsonish(readyz.stdout) or {}
        ready_flag = (ready_doc.get("ready", ready_doc.get("ok"))
                      if isinstance(ready_doc, dict) else None)
        web = GuestJsonClient(vm, services["stateport-web"]["port"])
        web.handshake()
        catalog = web.request("GET", "/v1/applications")
        app_ids = ([entry.get("applicationId") for entry in catalog.get("applications", [])]
                   if isinstance(catalog, dict) else [])
        receipt.record("predecessor-health-proven",
                       readyz.returncode == 0 and bool(ready_flag)
                       and "studystate.sample" in app_ids,
                       readyFlag=ready_flag, applicationIds=app_ids)

        receipt.document["result"] = "passed"
    except Refusal as refusal:
        receipt.record("typed-refusal", False, code=refusal.code,
                       message=refusal.message, status=refusal.status)
        receipt.document["result"] = "failed"
    except Exception as exc:  # noqa: BLE001 - the receipt must carry the failure out
        receipt.record("driver-error", False, error=f"{type(exc).__name__}: {exc}")
        receipt.document["result"] = "failed"
    finally:
        vm.teardown()
    receipt.write(args.receipt_out)
    log(f"result: {receipt.document['result']} -> {args.receipt_out}")
    return 0 if receipt.document["result"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
