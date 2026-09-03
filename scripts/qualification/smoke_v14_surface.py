#!/usr/bin/env python3
"""Bounded live probe of the retained candidate-v14 guest surface.

Answers, with evidence, the three facts the journey drivers depend on:
service/port/unit discovery with exact image-digest binding, where fixture
installs materialize relative to the web/product-data vs api/operations
volume split, and where shipped template revisions live for upgrade paths.
Writes one receipt; changes nothing on the guest but one smoke instance.
"""
from __future__ import annotations

import argparse
import json
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from journey_common import (  # noqa: E402
    GuestJsonClient,
    JourneyReceipt,
    Refusal,
    boot_retained_vm,
    discover_services,
    load_release_facts,
    log,
    verify_installed_image_digests,
    wait_service_healthy,
)

CONTAINER_PROBE = (
    "echo ---INST---; ls -1 /var/lib/stateport/instances 2>/dev/null | head -20; "
    "echo ---WS---; ls -1R /workspace/.stateport 2>/dev/null | head -60; "
    "echo ---REV---; find / -maxdepth 8 -type d -name v0002 "
    "-path '*studystate*' 2>/dev/null | head -5; "
    "echo ---FIXT---; find / -maxdepth 9 -type d -name 'studystate-sample' "
    "2>/dev/null | head -5"
)


def probe_container(vm, name: str) -> dict:
    cmd = (
        "sudo runuser -u stateport-control -- bash -c "
        f"'export XDG_RUNTIME_DIR=/run/user/$(id -u); "
        f"podman exec {name} bash -lc {json.dumps(CONTAINER_PROBE)}'"
    )
    result = vm.ssh(cmd, timeout=180)
    return {
        "exit": result.returncode,
        "stdout": result.stdout[-5000:],
        "stderr": result.stderr[-800:],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt-out", type=Path, required=True)
    parser.add_argument("--vm-dir", type=Path, required=True)
    parser.add_argument("--candidate-dir", type=Path, required=True)
    parser.add_argument("--site-root", type=Path, required=True)
    parser.add_argument("--archive-root", type=Path, required=True)
    args = parser.parse_args()

    facts = load_release_facts(args.candidate_dir)
    receipt = JourneyReceipt("SMOKE-CONTROL-SURFACE", {"candidate": facts})
    receipt.out_path = args.receipt_out
    receipt.write(args.receipt_out)

    vm = boot_retained_vm(
        args.vm_dir, site_root=args.site_root, archive_root=args.archive_root,
    )
    receipt.record("boot-retained-vm", True, workDir=str(args.vm_dir))
    try:
        services = discover_services(vm)
        receipt.record("discover-services", True, services=services)

        for service_id in ("stateport-web", "stateport-api", "stateport-worker"):
            wait_service_healthy(vm, services, service_id, deadline_s=420)
        receipt.record("control-plane-healthy", True)

        digests = verify_installed_image_digests(vm, dict(facts["images"]))  # type: ignore[arg-type]
        receipt.record(
            "installed-image-digests-match-candidate",
            not digests["mismatches"],  # type: ignore[union-attr]
            **digests,
        )

        web = GuestJsonClient(vm, services["stateport-web"]["port"])
        csrf = web.handshake()
        receipt.record("web-session-handshake", bool(csrf))

        catalog = web.request("GET", "/v1/applications")
        entries = catalog.get("applications") if isinstance(catalog, dict) else None
        study = None
        if isinstance(entries, list):
            study = next(
                (e for e in entries
                 if isinstance(e, dict) and e.get("applicationId") == "studystate.sample"),
                None,
            )
        receipt.record(
            "applications-catalog",
            study is not None,
            catalogKeys=list(catalog) if isinstance(catalog, dict) else str(type(catalog)),
            studystateEntry=study,
        )
        if study is None:
            raise SystemExit("studystate.sample missing from applications catalog")

        identity = study.get("applicationIdentity") or {}
        experience = study.get("experienceIdentity") or {}
        instance_id = "j2smoke-" + secrets.token_hex(4)
        install_body = {
            "applicationId": "studystate.sample",
            "instanceId": instance_id,
            "name": "Journey Smoke",
            "applicationDescriptorDigest": identity.get("descriptorDigest"),
            "applicationPackageDigest": identity.get("packageDigest"),
            "experienceDescriptorDigest": experience.get("descriptorDigest"),
        }
        try:
            installed = web.request(
                "POST", "/v1/application-fixtures/install", install_body, csrf=True,
            )
            receipt.record("fixture-install-smoke-instance", True,
                           instanceId=instance_id, response=installed)
        except Refusal as refusal:
            journal = vm.ssh(
                "sudo runuser -u stateport-control -- bash -c "
                f"'export XDG_RUNTIME_DIR=/run/user/$(id -u); "
                f"journalctl --user -u {services['stateport-web']['unit']} "
                "--no-pager -n 60 | tail -60'",
                check=False, timeout=120,
            )
            receipt.record(
                "fixture-install-smoke-instance", False,
                instanceId=instance_id,
                code=refusal.code, message=refusal.message,
                status=refusal.status, request=install_body,
                webJournalTail=journal.stdout[-6000:],
                catalogEntry=study,
            )

        probes = {
            runtime: probe_container(vm, name)
            for runtime, name in (("web", "stateport-web"), ("api", "stateport-api"))
        }
        receipt.record(
            "container-probes",
            all(p["exit"] == 0 for p in probes.values()),
            probes=probes,
        )

        api = GuestJsonClient(vm, services["stateport-api"]["port"])
        readyz = api.request("GET", "/readyz")
        receipt.record("api-readyz", bool(readyz.get("ready")), readyz=readyz)

        capabilities_raw = vm.ssh(
            f"curl -sS -m 15 http://127.0.0.1:{services['stateport-api']['port']}/v1/capabilities",
            check=False, timeout=60,
        )
        receipt.document["capabilitiesProbe"] = {
            "exit": capabilities_raw.returncode,
            "stdout": capabilities_raw.stdout[:2000],
        }

        receipt.document["result"] = "complete"
    finally:
        vm.teardown()
    receipt.write(args.receipt_out)
    log(f"result: {receipt.document['result']} -> {args.receipt_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
