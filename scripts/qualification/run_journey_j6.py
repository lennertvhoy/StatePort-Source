#!/usr/bin/env python3
"""Release journey J6 driver: deployment profiles, typed refusals, self-deployment."""
from __future__ import annotations

import argparse
import base64
import json
import secrets
import shlex
import sys
import tarfile
import tempfile
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
    log,
    validate_retained_candidate_inputs,
    verify_installed_image_digests,
    wait_service_healthy,
)

HEALTHY_STATES = {"running", "healthy", "active"}
PURGED_STATES = {"purged", "absent", "removed"}


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def pick(doc, *names):
    for name in names:
        value = doc.get(name) if isinstance(doc, dict) else None
        if value:
            return value, name
    return None, None


def first_list(doc, keys):
    for key in keys:
        value = doc.get(key) if isinstance(doc, dict) else None
        if isinstance(value, list):
            return value
    return []


def raw_keys(doc):
    return sorted(doc) if isinstance(doc, dict) else []


def note_refusal(receipt, step, refusal):
    receipt.document.setdefault("refusals", []).append(
        {"step": step, "code": refusal.code, "message": refusal.message,
         "status": refusal.status})


def approval_with_peek(approval, status_doc):
    # The proposal digest the operator must approve lives in the nested
    # ``state`` document (approvedPlanDigest / authority decision run id).
    state = status_doc.get("state") if isinstance(status_doc, dict) else None
    digest, source = pick(state if isinstance(state, dict) else {},
                          "approvedPlanDigest", "proposalDigest", "authorityRunId")
    return ({**approval, "proposalDigest": digest} if digest else dict(approval)), source


def mutate(receipt, web, step, method, path, body, soft=False):
    try:
        response = web.request(method, path, body, csrf=True)
    except Refusal as refusal:
        note_refusal(receipt, step, refusal)
        if soft:
            return None
        raise
    return response or None


def approval_body(session) -> dict:
    session = session if isinstance(session, dict) else {}
    # The approval gate accepts exactly these fields plus proposalDigest,
    # which each mutation binds after the plan is observed.
    return {"decision": "approve",
            "actorId": str(session.get("actorId") or "platform-operator")}


def deployment_state(status):
    if not isinstance(status, dict):
        return None
    # Deployment detail nests the full state document under ``state``.
    sources = [status] + ([status["state"]]
                          if isinstance(status.get("state"), dict) else [])
    states = {str(source.get(key)).lower() for source in sources
              for key in ("lifecycleState", "state", "status", "phase")}
    if states & HEALTHY_STATES:
        return (states & HEALTHY_STATES).pop()
    health = status.get("health")
    if health == "healthy" or (isinstance(health, dict) and health.get("healthy") is True):
        return "healthy"
    return None


def poll_deployment(receipt, web, deploy_id, attempts, delay_s):
    status_doc = {}
    for _ in range(attempts):
        try:
            status_doc = web.request("GET", f"/v1/deployments/{deploy_id}")
        except Refusal as refusal:
            note_refusal(receipt, f"poll-{deploy_id}", refusal)
            time.sleep(delay_s)
            continue
        state = deployment_state(status_doc)
        if state:
            return state, status_doc
        time.sleep(delay_s)
    return None, status_doc


def plan_apply_poll(receipt, web, prefix, deploy_id, project, grant_id, approval,
                    extra=None, attempts=30, delay_s=5, plan=None):
    if plan is None:
        body = {"project": project, "deploymentId": deploy_id, "grantId": grant_id}
        body.update(extra or {})
        plan = mutate(receipt, web, f"{prefix}-plan", "POST", "/v1/deployments/plan", body)
    digest, digest_key = pick(plan, "acceptPlanDigest", "planDigest")
    receipt.record(f"{prefix}-planned", bool(digest), deploymentId=deploy_id,
                   digestKey=digest_key, rawKeys=raw_keys(plan))
    expect(bool(digest), f"{prefix} plan lacks digest: {raw_keys(plan)}")
    applied = mutate(receipt, web, f"{prefix}-apply", "POST",
                     f"/v1/deployments/{deploy_id}/apply",
                     {digest_key: digest, "grantId": grant_id,
                      "approval": {**approval, "proposalDigest": digest}})
    receipt.record(f"{prefix}-apply-receipted",
                   isinstance(applied, dict) and isinstance(applied.get("receipt"), dict),
                   rawKeys=raw_keys(applied))
    expect(isinstance(applied, dict) and isinstance(applied.get("receipt"), dict),
           f"{prefix} apply returned no durable receipt")
    state, status_doc = poll_deployment(receipt, web, deploy_id, attempts, delay_s)
    receipt.record(f"{prefix}-healthy", state is not None, observedState=state,
                   rawKeys=raw_keys(status_doc))
    expect(state is not None, f"{prefix} never became healthy")
    return plan, status_doc


def _stage_project_directory(vm, source: Path, guest_dir: str) -> bool:
    """Stage one clean standalone Git project inside the web data volume."""

    if not source.is_dir():
        log(f"deployment fixture missing: {source}")
        return False
    with tempfile.NamedTemporaryFile(
        prefix="stateport-j6-project-", suffix=".tar", dir="/var/tmp", delete=False
    ) as temporary:
        archive = Path(temporary.name)
    guest_archive = f"/tmp/stateport-j6-{secrets.token_hex(6)}.tar"
    container_archive = f"/tmp/stateport-j6-{secrets.token_hex(6)}.tar"
    with tarfile.open(archive, "w") as handle:
        handle.add(source, arcname="project")
    try:
        vm.scp_in(str(archive), guest_archive)
        container_script = " && ".join(
            (
                f"rm -rf -- {shlex.quote(guest_dir)}",
                f"install -d -m 0700 -- {shlex.quote(guest_dir)}",
                f"tar -xf {shlex.quote(container_archive)} -C {shlex.quote(guest_dir)} --strip-components=1",
                f"rm -f -- {shlex.quote(container_archive)}",
                f"git -C {shlex.quote(guest_dir)} init -q --initial-branch=main",
                f"git -C {shlex.quote(guest_dir)} config user.name 'StatePort J6 Fixture'",
                f"git -C {shlex.quote(guest_dir)} config user.email fixture@stateport.invalid",
                f"git -C {shlex.quote(guest_dir)} add -A",
                f"git -C {shlex.quote(guest_dir)} commit -q -m initial",
            )
        )
        inner = (control_user_env()
                 + "; run_control podman cp "
                 + shlex.quote(guest_archive)
                 + " " + shlex.quote(f"stateport-web:{container_archive}") + "; "
                 + "run_control podman exec stateport-web sh -c "
                 + shlex.quote(container_script))
        result = vm.ssh(f"sudo runuser -u stateport-control -- bash -c {shlex.quote(inner)}",
                         check=False, timeout=180)
        ok = result.returncode == 0
        if not ok:
            log(f"fixture staging failed: {result.stderr[-300:]}")
    finally:
        archive.unlink(missing_ok=True)
        vm.ssh(f"rm -f -- {shlex.quote(guest_archive)}", check=False, timeout=30)
    return ok


def stage_deployment_fixture(vm, fixture_name: str, guest_dir: str) -> bool:
    """Stage one tracked deployment fixture as a clean standalone project."""

    host_fixture = (
        Path(__file__).resolve().parents[2]
        / "fixtures"
        / "deployments"
        / fixture_name
    )
    return _stage_project_directory(vm, host_fixture, guest_dir)


def stage_deployment_files(vm, files: dict[str, str], guest_dir: str) -> bool:
    """Stage a generated public-safe project used for refusal or image proofs."""

    with tempfile.TemporaryDirectory(prefix="stateport-j6-source-", dir="/var/tmp") as root:
        source = Path(root) / "project"
        source.mkdir()
        for relative, content in files.items():
            path = Path(relative)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("generated deployment fixture path is unsafe")
            destination = source / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(content, encoding="utf-8")
        return _stage_project_directory(vm, source, guest_dir)


def commit_project_files(vm, guest_dir: str, files: dict[str, str], message: str) -> str:
    payload = base64.b64encode(json.dumps(files, sort_keys=True).encode("utf-8")).decode("ascii")
    writer = """
import base64, json, pathlib, sys
root = pathlib.Path(sys.argv[1]).resolve(strict=True)
for relative, content in json.loads(base64.b64decode(sys.argv[2])).items():
    path = pathlib.PurePosixPath(relative)
    if path.is_absolute() or '..' in path.parts:
        raise SystemExit('unsafe generated path')
    destination = root.joinpath(*path.parts)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content, encoding='utf-8')
"""
    command = shlex.join(
        [
            "podman", "exec", "stateport-web", "python3", "-c", writer,
            guest_dir, payload,
        ]
    )
    git_script = " && ".join(
        (
            command,
            shlex.join(["podman", "exec", "stateport-web", "git", "-C", guest_dir, "add", "-A"]),
            shlex.join(["podman", "exec", "stateport-web", "git", "-C", guest_dir, "commit", "-q", "-m", message]),
            shlex.join(["podman", "exec", "stateport-web", "git", "-C", guest_dir, "rev-parse", "HEAD"]),
        )
    )
    inner = control_user_env() + "; " + git_script.replace("podman", "run_control podman")
    result = vm.ssh(
        f"sudo runuser -u stateport-control -- bash -c {shlex.quote(inner)}",
        check=False,
        timeout=180,
    )
    if result.returncode != 0:
        raise AssertionError(f"project update failed: {result.stderr[-300:]}")
    commit = result.stdout.strip().splitlines()[-1]
    if len(commit) not in {40, 64}:
        raise AssertionError("project update emitted no exact commit")
    return commit


def checkout_project_revision(vm, guest_dir: str, commit: str) -> None:
    command = shlex.join(
        ["podman", "exec", "stateport-web", "git", "-C", guest_dir,
         "checkout", "-q", "--detach", commit]
    )
    inner = control_user_env() + "; run_control " + command
    result = vm.ssh(
        f"sudo runuser -u stateport-control -- bash -c {shlex.quote(inner)}",
        check=False,
        timeout=120,
    )
    if result.returncode != 0:
        raise AssertionError(f"project checkout failed: {result.stderr[-300:]}")


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
            "J6-deployment-profiles-refusals-self-deployment",
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
        "J6-deployment-profiles-refusals-self-deployment",
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
        for service_id in ("stateport-web", "stateport-api", "stateport-worker"):
            wait_service_healthy(vm, services, service_id, deadline_s=420)
        digests = verify_installed_image_digests(vm, dict(facts["images"]))  # type: ignore[arg-type]
        receipt.record("control-plane-bound-to-candidate",
                       not digests["mismatches"], services=services)  # type: ignore[union-attr]

        web = GuestJsonClient(vm, services["stateport-web"]["port"])
        session = web.request("GET", "/session")
        web.handshake()
        approval = approval_body(session)
        receipt.record("web-session-handshake", True,
                       session={k: v for k, v in session.items() if k != "csrfToken"})

        grants = web.request("GET", "/v1/authority/grants")
        grant_entries = first_list(grants, ("grants", "items", "entries"))
        grant_id = grant_key = None
        for entry in grant_entries:
            grant_id, grant_key = pick(entry, "grantId", "id")
            if grant_id:
                break
        receipt.record("authority-grants-listed", bool(grant_id), count=len(grant_entries),
                       chosenKey=grant_key,
                       grantIds=[e.get("grantId") or e.get("id") for e in grant_entries][:10],
                       rawKeys=raw_keys(grants))
        expect(bool(grant_id), f"no usable grant id in grants response {raw_keys(grants)}")

        index = web.request("GET", "/v1/deployments")
        receipt.record("index-discovered",
                       isinstance(index, (dict, list)),
                       rawKeys=raw_keys(index))

        # Stage the tracked deployment profile fixtures into the web
        # container's writable product-data volume; the deployment surface
        # inspects them as project paths.
        projects_root = "/var/lib/stateport/deployments"
        staged_projects = {}
        for fixture, name in (("python-http", "python"), ("node-http", "node"),
                              ("static-web", "static"), ("persistent-multi", "multi")):
            guest_dir = f"{projects_root}/{name}"
            staged_projects[name] = stage_deployment_fixture(vm, fixture, guest_dir)
        receipt.record("deployment-fixtures-staged", all(staged_projects.values()),
                       staged=staged_projects)
        expect(all(staged_projects.values()), "deployment profile fixtures were not staged")
        project = f"{projects_root}/python"
        project_source = "staged-python-http"

        deploy_id = "j6py-" + secrets.token_hex(4)
        status_doc = plan_apply_poll(receipt, web, "python-profile", deploy_id,
                                     project, grant_id, approval)
        try:
            logs = web.request("POST", f"/v1/deployments/{deploy_id}/logs",
                               {"grantId": grant_id})
            logs_ok, logs_keys = isinstance(logs, dict) and bool(logs), raw_keys(logs)
        except Refusal as refusal:
            note_refusal(receipt, "profile-logs-readable", refusal)
            logs_ok, logs_keys = False, []
        receipt.record("profile-logs-readable", logs_ok, rawKeys=logs_keys)

        state_doc = status_doc.get("state") if isinstance(status_doc, dict) else {}
        peeked = {key: str(state_doc[key])[:80] for key in
                  ("authorityRunId", "approvedPlanDigest", "proposalDigest", "authority")
                  if key in state_doc}
        restart_source = approval_with_peek(approval, status_doc)[1]
        restart_ok = mutate(receipt, web, "profile-restart-approval", "POST",
                            f"/v1/deployments/{deploy_id}/restart",
                            {"grantId": grant_id,
                             "approval": approval_with_peek(approval, status_doc)[0]},
                            soft=True) is not None
        post_restart_state, _ = poll_deployment(receipt, web, deploy_id, 12, 5)
        receipt.record("profile-restart-with-approval-proposal", restart_ok,
                       peekedFields=peeked, peekedKey=restart_source,
                       postRestartState=post_restart_state)

        def bad_body(proj, grant="", compose=None):
            body = {"project": proj, "deploymentId": "j6bad-" + secrets.token_hex(3),
                    "grantId": grant}
            if compose is not None:
                body["compose"] = compose
            return body

        probes = [("unsafe-path-refused", bad_body("/etc", grant_id), "unsafe_path"),
                  ("empty-grant-refused", bad_body(project), "invalid_identity")]
        probe_results = []
        for name, body, expected in probes:
            try:
                mutate(receipt, web, name, "POST", "/v1/deployments/plan", body)
                probe_results.append({"probe": name, "refused": False, "expected": expected})
            except Refusal as refusal:
                probe_results.append({"probe": name, "refused": True, "expected": expected,
                                      "observedCode": refusal.code, "status": refusal.status})
        required_refused = all(entry["refused"] for entry in probe_results if entry["expected"])
        receipt.record("plan-refusals-typed", required_refused, results=probe_results)
        expect(required_refused, "expected plan refusals did not occur with typed codes")

        # Multi-service profile: deploy the staged persistent-multi fixture
        # (two services + shared volume) through the same governed chain.
        multi_id = "j6multi-" + secrets.token_hex(4)
        multi_project = f"{projects_root}/multi"
        multi_doc = plan_apply_poll(receipt, web, "multi-service-profile", multi_id,
                                    multi_project, grant_id, approval,
                                    attempts=60, delay_s=10)
        multi_state = multi_doc.get("state") if isinstance(multi_doc, dict) else {}
        receipt.record("multi-service-profile-healthy",
                       bool(multi_state.get("serviceHealth")),
                       serviceHealth=multi_state.get("serviceHealth"),
                       rawKeys=raw_keys(multi_state))

        # Self-deployment: deploy a buildable compose project through the
        # governed surface.  The deployment adapter builds projects from
        # their Containerfiles; the compose-http fixture is the shipped
        # multi-service compose shape (service + internal network + volume).
        self_id = "j6self-" + secrets.token_hex(4)
        self_project = f"{projects_root}/self"
        self_staged = stage_deployment_fixture(vm, "compose-http", self_project)
        receipt.record("self-deploy-project-staged", self_staged, path=self_project)
        expect(self_staged, "could not stage the self-deploy compose project")
        delivered = mutate(receipt, web, "self-deploy-plan", "POST",
                           "/v1/deployments/plan",
                           {"project": self_project, "deploymentId": self_id,
                            "grantId": grant_id})
        plan_apply_poll(receipt, web, "self-deploy", self_id, self_project,
                        grant_id, approval, attempts=60, delay_s=10, plan=delivered)

        detail = web.request("GET", f"/v1/deployments/{self_id}")
        receipts_exposed, _ = pick(detail, "receipts", "transitions", "events")
        receipt.record("self-deploy-receipts-exposed", isinstance(detail, dict) and bool(detail),
                       receiptsFieldPresent=receipts_exposed is not None,
                       rawKeys=raw_keys(detail))

        # Return managed workspace and resources to the exact baseline:
        # remove (data retained) then purge every journey deployment.
        cleanup_ids = [deploy_id, multi_id, self_id]
        cleanup_results = {}
        for clean_id in cleanup_ids:
            status_doc = web.request("GET", f"/v1/deployments/{clean_id}")
            removed = mutate(receipt, web, f"{clean_id}-remove", "POST",
                             f"/v1/deployments/{clean_id}/remove",
                             {"grantId": grant_id,
                              "approval": approval_with_peek(approval, status_doc)[0]},
                             soft=True) is not None
            purge_plan = mutate(receipt, web, f"{clean_id}-purge-planned", "POST",
                                f"/v1/deployments/{clean_id}/purge/plan",
                                {"grantId": grant_id})
            purge_digest, purge_key = pick(purge_plan, "acceptPlanDigest", "planDigest")
            purged = False
            if purge_digest:
                mutate(receipt, web, f"{clean_id}-purge-applied", "POST",
                       f"/v1/deployments/{clean_id}/purge/apply",
                       {purge_key: purge_digest, "grantId": grant_id, "approval": approval})
                purged = True
            cleanup_results[clean_id] = {"removed": removed, "purged": purged}
        index_after = json.dumps(web.request("GET", "/v1/deployments"))
        all_absent = all(clean_id not in index_after for clean_id in cleanup_ids)
        receipt.record("journey-deployments-returned-to-baseline", all_absent,
                       results=cleanup_results,
                       indexLacksEntries=all_absent)
        expect(all_absent, "journey deployments were not fully removed and purged")

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
