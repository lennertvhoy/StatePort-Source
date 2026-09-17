#!/usr/bin/env python3
"""Native installed-product agent-result stage: one real OpenCode result, digest-bound.

The alpha.18 native journey proves install, reboot survival, retain-uninstall,
purge and reinstall, but no committed stage proves the installed product itself
produces a real agent result.  This bounded stage drives the installed control
plane exactly as the product does: it opens the loopback browser session, submits
one bounded objective through the operator+CSRF ``POST /v1/agent/run`` route,
waits for the durable run receipt to settle, re-derives the output digest from
the session-gated ``GET /v1/agent/runs/<id>/output`` read, and captures the
bounded identity of the sealed workspace container that executed the run.

Fail-closed rules:

- the lane gate is exactly the reboot stage's: the retained J1 receipt selects
  ``candidate_mirror`` under ``--prepublication-mirror``, the owner path
  otherwise, and any mismatched flag or receipt class is refused before a guest
  call;
- the product's own readiness projection must report the provider directory
  (``provider.env`` and ``opencode.json`` by shape only), a reachable execution
  host and the configured workspace image as available, otherwise the stage
  refuses before submitting anything;
- the session must be the platform operator; credential contents are never
  read, printed, logged or digested by this stage;
- the run must settle ``completed`` with exit status 0, the objective digest,
  output digest and output byte count must match the durable run receipt, and
  the workspace container's image digest, identity labels, read-only rootfs and
  provider bind must match the recorded run; any mismatch is a failed receipt.

The caller owns the attached VM (this stage never tears it down), so a journey
driver can invoke it in-process before its lifecycle mutations.  Every run
writes one durable journey receipt; any failed assertion writes
``result: failed`` and exits non-zero.  The stage asserts one agent result and
its evidence bindings only: durable application state, reboot survival and the
uninstall/reinstall lifecycle remain the calling journey's assertions.
"""
from __future__ import annotations

import argparse
import hashlib
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
    boot_native_follow_on,
    discover_services,
    log,
    validate_retained_candidate_inputs,
    wait_service_healthy,
)
from run_reboot_stage import enforce_reboot_lane  # noqa: E402

OBJECTIVE = "Use the bash tool to run `uname -srm`, then reply with its exact output."
OBJECTIVE_MAX_CHARS = 256
AGENT_WORKSPACE_ID = "agent-workspace"
EXEC_USER = "stateport-exec"
RUN_ID_PATTERN = re.compile(r"^agent-run-[0-9a-f]{32}$")
CONTAINER_ID_PATTERN = re.compile(r"^[0-9a-f]{64}$")
DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
TERMINAL_STATUSES = frozenset({"completed", "failed", "refused"})
CONTAINER_NAME = f"stateport-exec-{AGENT_WORKSPACE_ID}"
PROVIDER_MOUNT = "/stateport-provider"
WORKSPACE_MOUNT = "/workspace"
_LABEL_ALLOWLIST = (
    "io.stateport.execution.managed",
    "io.stateport.execution.workload",
    "io.stateport.execution.kind",
    "io.stateport.credentials",
)
_CONTAINER_TEMPLATE = (
    '{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},'
    '"imageDigest":{{json .ImageDigest}},"state":{{json .State.Status}},'
    '"running":{{json .State.Running}},"readOnly":{{json .HostConfig.ReadonlyRootfs}},'
    '"networkMode":{{json .HostConfig.NetworkMode}},"memory":{{json .HostConfig.Memory}},'
    '"pidsLimit":{{json .HostConfig.PidsLimit}},"mounts":{{json .Mounts}},'
    '"labels":{{json .Config.Labels}}}'
)
LIMITATIONS = (
    "One bounded objective executed by the installed control plane through the "
    "real operator HTTP surface, bound to the durable run receipt, the re-derived "
    "output digest and the sealed workspace container identity; durable application "
    "state, reboot survival and the uninstall/reinstall lifecycle are asserted by "
    "the calling journey. Provider material is inspected by shape only through the "
    "product readiness projection; credential contents are never read."
)


def _digest_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _last_digest(reference: object) -> str | None:
    if isinstance(reference, str) and "@sha256:" in reference:
        return "sha256:" + reference.rsplit("@sha256:", 1)[1]
    return None


def enforce_agent_result_lane(evidence: object, *, prepublication_mirror: bool) -> dict:
    """Apply the shared native lane gate; one implementation, no drift.

    The rule is exactly the reboot stage's retained-J1 lane rule.  The refusal is
    re-raised with the calling stage named so a mismatch is never mistaken for a
    reboot-stage invocation.
    """
    try:
        return enforce_reboot_lane(evidence, prepublication_mirror=prepublication_mirror)
    except ValueError as exc:
        raise ValueError(f"agent result stage refused by the shared lane gate: {exc}") from exc


def _bounded_refusals(readiness: dict) -> list[dict[str, str]]:
    refusals: list[dict[str, str]] = []
    raw = readiness.get("refusals")
    if not isinstance(raw, list):
        return refusals
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        reason = entry.get("reason")
        detail = entry.get("detail")
        if isinstance(reason, str) and isinstance(detail, str):
            refusals.append({"reason": reason[:200], "detail": detail[:300]})
    return refusals


def readiness_projection(readiness: object) -> dict:
    """Bounded shape-only projection of the product readiness document."""
    if not isinstance(readiness, dict):
        raise AssertionError("the installed agent readiness projection is missing")
    provider = readiness.get("providerDirectory")
    provider = provider if isinstance(provider, dict) else {}
    files = provider.get("files")
    files = files if isinstance(files, dict) else {}
    workspace = readiness.get("workspace")
    workspace = workspace if isinstance(workspace, dict) else {}
    workload_id = workspace.get("workloadId")
    return {
        "available": readiness.get("available") is True,
        "providerDirectory": {
            "configured": provider.get("configured") is True,
            "present": provider.get("present") is True,
            "files": {
                "providerEnv": files.get("providerEnv") is True,
                "opencodeJson": files.get("opencodeJson") is True,
                "model": files.get("model") is True,
            },
        },
        "workspace": {
            "status": workspace.get("status") if isinstance(workspace.get("status"), str) else None,
            "workloadId": workload_id if isinstance(workload_id, str) else None,
        },
        "refusals": _bounded_refusals(readiness),
    }


def _readiness_ready(projection: dict) -> bool:
    provider = projection["providerDirectory"]
    return bool(
        projection["available"]
        and provider["present"]
        and provider["files"]["providerEnv"]
        and provider["files"]["opencodeJson"]
    )


def wait_for_terminal_run(web, run_id: str, *, deadline_s: float,
                          poll_interval_s: float) -> dict:
    """Poll the session-gated run status until it settles; bounded and typed."""
    deadline = time.time() + max(0.0, deadline_s)
    while True:
        current = web.request("GET", f"/v1/agent/runs/{run_id}", timeout=90)
        if not isinstance(current, dict) or current.get("runId") != run_id:
            raise AssertionError("agent run status did not return the submitted run id")
        status = current.get("status")
        if status in TERMINAL_STATUSES:
            return current
        if status != "running":
            raise AssertionError(f"agent run reported an unexpected status: {status!r}")
        if time.time() >= deadline:
            raise AssertionError(
                f"agent run did not reach a terminal state within {deadline_s:g}s"
            )
        time.sleep(max(0.0, poll_interval_s))


def observe_workspace_container(vm) -> dict:
    """Read the bounded identity of the sealed agent workspace container.

    The container is owned by the rootless ``stateport-exec`` runtime; only the
    fields that prove identity and hardening leave the guest.  Raw inspect data,
    environment variables and provider file contents are never returned.
    """
    uid_result = vm.ssh("id -u stateport-exec 2>/dev/null || true", check=False, timeout=30)
    uid = uid_result.stdout.strip()
    if not uid.isdigit():
        raise AssertionError("installed execution identity stateport-exec is absent")
    exec_env = (
        f"XDG_RUNTIME_DIR=/run/user/{uid} "
        f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus"
    )
    command = (
        f"sudo runuser -u {EXEC_USER} -- env {exec_env} podman container inspect "
        f"{shlex.quote(CONTAINER_NAME)} --format {shlex.quote(_CONTAINER_TEMPLATE)}"
    )
    result = vm.ssh(command, check=False, timeout=120)
    if result.returncode != 0:
        raise AssertionError(
            "agent workspace container identity is unavailable: "
            + (result.stderr or result.stdout or "").strip()[-500:]
        )
    try:
        observed = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"agent workspace container identity is malformed: {exc}") from exc
    if not isinstance(observed, dict):
        raise AssertionError("agent workspace container identity is not an object")
    container_id = observed.get("id")
    image_digest = observed.get("imageDigest")
    name = observed.get("name")
    state = observed.get("state")
    if not isinstance(container_id, str) or CONTAINER_ID_PATTERN.fullmatch(container_id) is None:
        raise AssertionError("agent workspace container id is malformed")
    if not isinstance(image_digest, str) or DIGEST_PATTERN.fullmatch(image_digest) is None:
        raise AssertionError("agent workspace container image digest is malformed")
    if name != CONTAINER_NAME:
        raise AssertionError(f"agent workspace container name is unexpected: {name!r}")
    if not isinstance(state, str) or not state:
        raise AssertionError("agent workspace container state is missing")
    mounts: list[dict] = []
    raw_mounts = observed.get("mounts")
    if not isinstance(raw_mounts, list):
        raise AssertionError("agent workspace container mounts are malformed")
    for item in raw_mounts:
        if not isinstance(item, dict) or not isinstance(item.get("Destination"), str):
            raise AssertionError("agent workspace container mount entry is malformed")
        mounts.append(
            {
                "type": item.get("Type") if isinstance(item.get("Type"), str) else None,
                "source": item.get("Source") if isinstance(item.get("Source"), str) else None,
                "destination": item["Destination"],
                "ro": item.get("RW") is False,
            }
        )
    raw_labels = observed.get("labels")
    raw_labels = raw_labels if isinstance(raw_labels, dict) else {}
    labels = {
        key: raw_labels[key]
        for key in _LABEL_ALLOWLIST
        if isinstance(raw_labels.get(key), str)
    }
    memory = observed.get("memory")
    pids_limit = observed.get("pidsLimit")
    network_mode = observed.get("networkMode")
    return {
        "id": container_id,
        "containerName": name,
        "image": observed.get("image") if isinstance(observed.get("image"), str) else None,
        "imageDigest": image_digest,
        "state": state,
        "running": observed.get("running") is True,
        "readOnly": observed.get("readOnly") is True,
        "networkMode": network_mode if isinstance(network_mode, str) else None,
        "memory": memory if isinstance(memory, int) and not isinstance(memory, bool) else None,
        "pidsLimit": (
            pids_limit if isinstance(pids_limit, int) and not isinstance(pids_limit, bool) else None
        ),
        "mounts": mounts,
        "labels": labels,
    }


def _container_evidence_ok(container: dict, run: dict, signed_images: dict) -> dict:
    """Cross-check the container identity against the durable run receipt."""
    run_image_digest = _last_digest(run.get("imageReference"))
    signed_image_id = None
    if run_image_digest is not None:
        signed_image_id = next(
            (
                image_id
                for image_id, digest in sorted(signed_images.items())
                if digest == run_image_digest
            ),
            None,
        )
    destinations = {mount["destination"]: mount for mount in container["mounts"]}
    provider = destinations.get(PROVIDER_MOUNT)
    workspace = destinations.get(WORKSPACE_MOUNT)
    labels = container["labels"]
    checks = {
        "imageDigestMatchesRun": (
            run_image_digest is not None and container["imageDigest"] == run_image_digest
        ),
        "signedImageBound": signed_image_id is not None,
        "managedLabel": labels.get("io.stateport.execution.managed") == "true",
        "workloadLabel": labels.get("io.stateport.execution.workload") == AGENT_WORKSPACE_ID,
        "kindLabel": labels.get("io.stateport.execution.kind") == "workspace",
        "readOnlyRootfs": container["readOnly"] is True,
        "providerBindReadOnly": provider is not None and provider["ro"] is True,
        "workspaceMountPresent": workspace is not None and workspace["type"] == "volume",
    }
    return {
        "evidenceOk": all(checks.values()),
        "checks": checks,
        "runImageDigest": run_image_digest,
        "signedImageId": signed_image_id,
    }


def _terminal_failure_detail(run: dict) -> str:
    refusal = run.get("refusal")
    if isinstance(refusal, dict):
        return json.dumps(refusal, sort_keys=True)[:400]
    return f"status={run.get('status')!r} exitStatus={run.get('exitStatus')!r}"


def execute_agent_result_stage(
    vm,
    *,
    facts: dict,
    evidence: dict,
    prepublication_mirror: bool,
    receipt_out: Path,
    objective: str = OBJECTIVE,
    run_timeout_s: float = 1200,
    poll_interval_s: float = 3.0,
) -> dict:
    """Run one observed agent-result cycle on an attached native VM.

    The caller owns the VM; this function never tears it down, so a journey can
    invoke the stage in-process.  The receipt is written on every step and again
    on failure before the exception propagates.
    """
    if (
        not isinstance(objective, str)
        or not objective.strip()
        or "\x00" in objective
        or len(objective) > OBJECTIVE_MAX_CHARS
    ):
        raise ValueError("agent result stage objective must be one bounded non-empty string")
    receipt = JourneyReceipt(
        "native-agent-result",
        {"candidate": facts, "prerequisites": evidence},
    )
    receipt.out_path = receipt_out
    receipt.document["limitations"] = LIMITATIONS
    receipt.write(receipt_out)
    lane: dict = {}
    try:
        if not getattr(vm, "native_wsl", False):
            raise AssertionError("agent result stage requires the native WSL2 lane")

        lane = enforce_agent_result_lane(evidence, prepublication_mirror=prepublication_mirror)
        receipt.document.update(lane)
        receipt.record("lane-class", True, **lane)

        signed_images = facts.get("images")
        if not isinstance(signed_images, dict) or not signed_images:
            raise AssertionError(
                "agent result stage requires the signed image set from the candidate facts"
            )

        services = discover_services(vm)
        wait_service_healthy(vm, services, "stateport-web", deadline_s=420)
        receipt.record("control-plane-health", True, services=services)

        web = GuestJsonClient(vm, services["stateport-web"]["port"])
        token = web.handshake()
        receipt.record("web-session-handshake", True, session="local", csrfPresent=bool(token))

        status = web.request("GET", "/v1/status")
        actor = status.get("actor") if isinstance(status, dict) else None
        actor_role = actor.get("role") if isinstance(actor, dict) else None
        actor_id = actor.get("actorId") if isinstance(actor, dict) else None
        operator_ok = actor_role == "platform_operator"
        receipt.record(
            "operator-session",
            operator_ok,
            actorRole=actor_role if isinstance(actor_role, str) else None,
            actorId=actor_id if isinstance(actor_id, str) else None,
        )
        if not operator_ok:
            raise AssertionError(
                "the installed web session is not the platform operator; "
                "the agent-run mutation boundary would refuse it"
            )

        readiness = readiness_projection(web.request("GET", "/v1/agent/status"))
        ready = _readiness_ready(readiness)
        receipt.record("agent-readiness", ready, **readiness)
        if not ready:
            raise AssertionError(
                "the installed agent surface is not ready: "
                + json.dumps(readiness["refusals"], sort_keys=True)[:600]
            )

        submitted = web.request(
            "POST", "/v1/agent/run", {"objective": objective}, csrf=True, timeout=90
        )
        run_id = submitted.get("runId") if isinstance(submitted, dict) else None
        accepted = (
            isinstance(run_id, str)
            and RUN_ID_PATTERN.fullmatch(run_id) is not None
            and submitted.get("workspaceId") == AGENT_WORKSPACE_ID
        )
        receipt.record(
            "agent-run-accepted",
            accepted,
            runId=run_id if isinstance(run_id, str) else None,
            status=submitted.get("status") if isinstance(submitted, dict) else None,
            workspaceId=submitted.get("workspaceId") if isinstance(submitted, dict) else None,
            objectiveDigest=_digest_text(objective),
        )
        if not accepted:
            observed = sorted(submitted) if isinstance(submitted, dict) else submitted
            raise AssertionError(
                f"POST /v1/agent/run did not accept a bounded run: {observed!r}"
            )

        run = wait_for_terminal_run(
            web, run_id, deadline_s=run_timeout_s, poll_interval_s=poll_interval_s
        )
        completed = run.get("status") == "completed" and run.get("exitStatus") == 0
        receipt.record(
            "agent-run-terminal",
            completed,
            run=run,
            exitStatus=run.get("exitStatus"),
            status=run.get("status"),
        )
        if not completed:
            raise AssertionError(
                f"agent run did not complete successfully: {_terminal_failure_detail(run)}"
            )

        objective_matches = (
            run.get("objective") == objective
            and run.get("objectiveDigest") == _digest_text(objective)
            and run.get("formatVersion") == "stateport.agent-run-receipt/v1"
        )
        receipt.record(
            "agent-run-receipt-binding",
            objective_matches,
            objectiveDigest=run.get("objectiveDigest"),
            recordedObjectiveDigest=_digest_text(objective),
            imageReference=run.get("imageReference"),
            workspaceSpecDigest=run.get("workspaceSpecDigest"),
            grantId=run.get("grantId"),
            authorityGrantDigest=run.get("authorityGrantDigest"),
            execOperationId=run.get("execOperationId"),
            createOperationId=run.get("createOperationId"),
            startOperationId=run.get("startOperationId"),
            startedAt=run.get("startedAt"),
            finishedAt=run.get("finishedAt"),
        )
        if not objective_matches:
            raise AssertionError("the durable run receipt does not bind the submitted objective")

        output = web.request("GET", f"/v1/agent/runs/{run_id}/output", timeout=90)
        output_text = output.get("output") if isinstance(output, dict) else None
        truncated = bool(
            (isinstance(output, dict) and output.get("truncated") is True)
            or run.get("truncated") is True
        )
        derived_digest = _digest_text(output_text) if isinstance(output_text, str) else None
        output_bytes = len(output_text.encode("utf-8")) if isinstance(output_text, str) else None
        digest_ok = (
            not truncated
            and isinstance(output.get("runId"), str)
            and output.get("runId") == run_id
            and isinstance(output_text, str)
            and derived_digest == run.get("outputDigest")
            and output_bytes == run.get("outputBytes")
            and output.get("outputBytes") == run.get("outputBytes")
        )
        receipt.record(
            "agent-output-digest",
            digest_ok,
            outputDigest=derived_digest,
            recordedOutputDigest=run.get("outputDigest"),
            outputBytes=output_bytes,
            recordedOutputBytes=run.get("outputBytes"),
            truncated=truncated,
        )
        if not digest_ok:
            raise AssertionError(
                "the bounded agent output does not re-derive the recorded run digest"
            )

        container = observe_workspace_container(vm)
        cross_check = _container_evidence_ok(container, run, signed_images)
        receipt.record(
            "agent-workspace-container", cross_check["evidenceOk"], **container, **cross_check
        )
        if not cross_check["evidenceOk"]:
            raise AssertionError(
                "the agent workspace container identity does not match the recorded run: "
                + json.dumps(cross_check, sort_keys=True)[:600]
            )

        receipt.document["result"] = "passed"
        summary = {
            "receiptPath": str(receipt_out),
            "mode": lane["mode"],
            "evidenceClass": lane["evidenceClass"],
            "runId": run_id,
            "status": run.get("status"),
            "exitStatus": run.get("exitStatus"),
            "objectiveDigest": _digest_text(objective),
            "outputDigest": derived_digest,
            "outputBytes": output_bytes,
            "containerId": container["id"],
            "containerImageDigest": container["imageDigest"],
            "signedImageId": cross_check["signedImageId"],
        }
    except BaseException as exc:
        receipt.document["result"] = "failed"
        detail: dict[str, object] = {
            "error": f"{type(exc).__name__}: {exc}",
            "mode": lane.get("mode"),
        }
        if isinstance(exc, Refusal):
            detail.update(
                {
                    "refusalCode": exc.code,
                    "refusalMessage": exc.message,
                    "httpStatus": exc.status,
                }
            )
        receipt.record("agent-result-stage-failure", False, **detail)
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
        "native-agent-result",
        {"candidate": facts, "prerequisites": evidence},
    )
    receipt.out_path = args.receipt_out
    receipt.record("attach", False, error=f"{type(exc).__name__}: {exc}")
    receipt.document["result"] = "failed"
    receipt.write(args.receipt_out)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Native installed-product agent-result stage "
        "(first OpenCode result through the installed control plane)"
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
    parser.add_argument("--run-timeout-seconds", type=float, default=1200.0,
                        help="bounded wait for the agent run to reach a terminal state")
    parser.add_argument("--qualification-build-receipt", type=Path)
    args = parser.parse_args()

    if not args.native_wsl2:
        parser.error("the agent-result stage is a native WSL2 driver; pass --native-wsl2")
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
            "native-agent-result",
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
        summary = execute_agent_result_stage(
            vm, facts=facts, evidence=prerequisite_evidence,
            prepublication_mirror=args.prepublication_mirror,
            receipt_out=args.receipt_out,
            run_timeout_s=args.run_timeout_seconds,
        )
        log(f"result: passed -> {args.receipt_out} ({summary['mode']})")
        return 0
    except (Exception, SystemExit) as exc:
        # execute_agent_result_stage finalizes its own failed receipt; an attach
        # failure before the stage still needs one durable failure document.
        _write_attach_failure(args, facts, prerequisite_evidence, exc)
        log(f"result: failed -> {args.receipt_out} ({type(exc).__name__}: {exc})")
        return 1
    finally:
        if vm is not None:
            vm.teardown()


if __name__ == "__main__":
    sys.exit(main())
