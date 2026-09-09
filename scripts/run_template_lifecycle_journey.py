#!/usr/bin/env python3
"""Run the exact local-service template journey against three real Git templates.

The journey crosses the same HTTP/session/CSRF boundaries as the production
browser. It proves discovery, inspection, explicit plan/approval, isolated
materialization, application experience resolution, governed action execution,
activity receipts, and service restart continuity. Repository commands are
never executed by StatePort; only the reviewed adapter actions bundled here run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
for source_root in sorted((ROOT / "packages").glob("*/src")):
    sys.path.insert(0, str(source_root))



def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout.strip()


def _create_generic_template(root: Path) -> Path:
    root.mkdir(parents=True)
    (root / "template.yaml").write_text(
        """apiVersion: statedd.stateport.io/v1alpha1
kind: Template
metadata:
  id: journey-generic-template
  name: Journey Generic Template
  version: 1.0.0
spec:
  domain: project
  lifecycle: [draft, active]
  allowedActions: [{name: read_state, level: L0}]
  schemas: []
  agentContract:
    role: assistant
    responsibilities: [Inspect the declared template]
    forbiddenActions: [Execute repository commands]
""",
        encoding="utf-8",
    )
    (root / "README.md").write_text(
        "# Journey Generic Template\n\nA real declarative StateSpec template.\n",
        encoding="utf-8",
    )
    _git(root, "init", "-q", "--initial-branch=main")
    _git(root, "config", "user.name", "StatePort journey")
    _git(root, "config", "user.email", "journey@stateport.invalid")
    _git(root, "add", "--all")
    _git(root, "commit", "-q", "-m", "generic template")
    return root


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class BrowserClient:
    def __init__(self, port: int) -> None:
        self.base = f"http://127.0.0.1:{port}"
        self.cookie = ""
        self.csrf = ""

    def request(self, path: str, *, body: dict[str, Any] | None = None) -> Any:
        data = None if body is None else json.dumps(body).encode("utf-8")
        headers = {"Accept": "application/json"}
        if self.cookie:
            headers["Cookie"] = self.cookie
        if body is not None:
            headers.update(
                {
                    "Content-Type": "application/json",
                    "Origin": self.base,
                    "X-StatePort-CSRF": self.csrf,
                }
            )
        request = Request(
            self.base + path,
            data=data,
            method="POST" if body is not None else "GET",
            headers=headers,
        )
        try:
            with urlopen(request, timeout=20) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"{request.method} {path} returned {exc.code}: {detail}") from exc
        if not isinstance(payload, dict) or payload.get("ok") is not True:
            raise RuntimeError(f"{request.method} {path} returned an invalid envelope")
        return payload["result"]

    def establish_session(self) -> None:
        request = Request(self.base + "/session", method="GET")
        with urlopen(request, timeout=20) as response:
            payload = json.loads(response.read().decode("utf-8"))
            self.cookie = response.headers["Set-Cookie"].split(";", 1)[0]
        self.csrf = str(payload["result"]["csrfToken"])

    def frontend(self) -> str:
        with urlopen(self.base + "/", timeout=20) as response:
            if response.status != 200:
                raise RuntimeError("production frontend was not served")
            return response.read().decode("utf-8")


def _source_status(root: Path) -> dict[str, str]:
    return {
        "commit": _git(root, "rev-parse", "HEAD"),
        "tree": _git(root, "rev-parse", "HEAD^{tree}"),
        "statusDigest": hashlib.sha256(
            _git(root, "status", "--porcelain=v1", "--untracked-files=all").encode("utf-8")
        ).hexdigest(),
    }


def _install_and_execute(
    browser: BrowserClient,
    candidate: dict[str, Any],
    *,
    adapter_id: str,
    instance_id: str,
) -> dict[str, Any]:
    inspection = browser.request(
        "/v1/repository-import/inspect",
        body={"candidateId": candidate["candidateId"]},
    )
    template = inspection.get("template")
    if not isinstance(template, dict) or template.get("adapterId") != adapter_id:
        raise RuntimeError(f"candidate did not resolve to adapter {adapter_id}")
    if inspection.get("mutated") is not False or template.get("repositoryCommandsExecuted") is not False:
        raise RuntimeError("repository inspection did not prove its non-mutating boundary")

    plan = browser.request(
        "/v1/template-import/plan",
        body={
            "candidateId": candidate["candidateId"],
            "inspectionDigest": inspection["inspectionDigest"],
            "instanceId": instance_id,
            "name": str(template["displayName"]),
        },
    )
    actor_id = browser.request("/v1/status")["actor"]["actorId"]
    installed = browser.request(
        "/v1/template-import/install",
        body={
            "plan": plan,
            "approval": {
                "decision": "approve",
                "actorId": actor_id,
                "planDigest": plan["planDigest"],
            },
        },
    )
    if installed.get("managedCopyCreated") is not True or installed.get("sourceRepositoryMutated") is not False:
        raise RuntimeError("template installation did not prove isolated materialization")

    detail = browser.request(f"/v1/instances/{instance_id}")
    source = detail.get("source", {})
    if (
        source.get("management") != "isolated_template"
        or source.get("adapterId") != adapter_id
        or source.get("workingTreeChangesExcluded") is not True
        or source.get("resolvedCommit") != inspection["sourceIdentity"]["headCommit"]
        or source.get("resolvedTree") != inspection["sourceIdentity"]["headTree"]
    ):
        raise RuntimeError("installed source identity differs from the inspected Git snapshot")

    experience = browser.request(f"/v1/instances/{instance_id}/experience")
    if experience.get("instanceBinding", {}).get("applicationId") != template["applicationId"]:
        raise RuntimeError("application experience is not bound to the imported adapter")
    actions = browser.request(f"/v1/instances/{instance_id}/actions")["actions"]
    if not actions:
        raise RuntimeError("imported template has no reviewed actions")
    action_id = str(actions[0]["actionId"])
    prepared = browser.request(
        f"/v1/instances/{instance_id}/execution/prepare",
        body={
            "expectedInstanceId": instance_id,
            "actionId": action_id,
            "engineId": "synthetic",
            "inputs": {},
        },
    )["run"]
    approved = browser.request(
        f"/v1/runs/{prepared['runId']}/approve",
        body={"expectedInstanceId": instance_id, "expectedRevision": prepared["revision"]},
    )
    executed = browser.request(
        f"/v1/runs/{approved['runId']}/execute",
        body={"expectedInstanceId": instance_id, "expectedRevision": approved["revision"]},
    )["run"]
    if (
        executed.get("status") != "result_validating"
        or executed.get("lifecycleState") != "CLOSED"
        or executed.get("runResult", {}).get("executionStatus") != "completed"
    ):
        raise RuntimeError(f"reviewed action did not reach validated closed state for {instance_id}")
    result = executed.get("result")
    if not isinstance(result, dict) or result.get("canonicalStateUnchanged") is not True:
        raise RuntimeError("reviewed inspection action did not preserve canonical state")

    receipts = browser.request(f"/v1/instances/{instance_id}/receipts")["receipts"]
    if not any(item.get("receiptId") == installed.get("receiptId") for item in receipts):
        raise RuntimeError("template import activity receipt is missing")
    return {
        "instanceId": instance_id,
        "applicationId": template["applicationId"],
        "adapterId": adapter_id,
        "sourceCommit": source["resolvedCommit"],
        "sourceTree": source["resolvedTree"],
        "workingTreeDirtyAtInspection": inspection["sourceIdentity"]["dirty"],
        "workingTreeChangesExcluded": source["workingTreeChangesExcluded"],
        "installReceiptId": installed["receiptId"],
        "actionId": action_id,
        "runId": executed["runId"],
        "actionSummary": result.get("summary"),
        "conversationId": installed["conversationId"],
    }


def run(projectstate: Path, studystate: Path) -> dict[str, Any]:
    from stateport_persistent_app import LocalLayout, PersistentApp

    projectstate = projectstate.resolve(strict=True)
    studystate = studystate.resolve(strict=True)
    source_before = {
        "projectstate-v6": _source_status(projectstate),
        "studystate": _source_status(studystate),
    }
    with tempfile.TemporaryDirectory(prefix="stateport-template-journey-") as temporary:
        temp = Path(temporary)
        generic = _create_generic_template(temp / "sources" / "generic-template")
        invalid = _create_generic_template(temp / "sources" / "invalid-template")
        (invalid / "template.yaml").write_text(
            "apiVersion: statedd.stateport.io/v1alpha1\nkind: Template\n"
            "metadata: {id: invalid-template, name: Invalid, version: '1.0.0'}\n",
            encoding="utf-8",
        )
        _git(invalid, "add", "template.yaml")
        _git(invalid, "commit", "-q", "-m", "invalid manifest refusal fixture")
        source_before["statespec-template"] = _source_status(generic)
        os.environ["XDG_CONFIG_HOME"] = str(temp / "xdg" / "config")
        os.environ["XDG_DATA_HOME"] = str(temp / "xdg" / "data")
        os.environ["XDG_STATE_HOME"] = str(temp / "xdg" / "state")
        os.environ["STATEPORT_REPOSITORY_ROOTS"] = os.pathsep.join(
            (str(projectstate), str(studystate), str(generic), str(invalid))
        )

        layout = LocalLayout.from_environment()
        layout.initialize()
        app = PersistentApp(layout)
        port = _free_port()
        app.service_start(port=port, repo_root=ROOT)
        try:
            browser = BrowserClient(port)
            browser.establish_session()
            frontend = browser.frontend()
            if "stateport-build" not in frontend and "<div id=\"root\"></div>" not in frontend:
                raise RuntimeError("production frontend shell was not served")
            candidates = browser.request("/v1/repository-import/local-candidates")["candidates"]
            rejected = [candidate for candidate in candidates
                        if candidate.get("inspection", {}).get("template", {}).get("validation", {}).get("status") == "failed"]
            if len(rejected) != 1:
                raise RuntimeError("invalid template was not reported as a failed contract")
            rejected_candidate = rejected[0]
            rejected_digest = rejected_candidate["inspection"]["inspectionDigest"]
            try:
                browser.request("/v1/repository-import/register", body={
                    "candidateId": rejected_candidate["candidateId"],
                    "inspectionDigest": rejected_digest,
                    "instanceId": "journey-invalid-template",
                    "name": "Invalid template must not register",
                    "approval": {"decision": "approve", "actorId": "local-user", "proposalDigest": rejected_digest},
                })
            except RuntimeError as exc:
                if "template_contract_invalid" not in str(exc):
                    raise
            else:
                raise RuntimeError("invalid template fell through to ordinary repository registration")
            if (layout.instances_root / "journey-invalid-template").exists():
                raise RuntimeError("invalid template created a partial instance")
            if any(entry.get("instanceId") == "journey-invalid-template" for entry in app.catalog.list()):
                raise RuntimeError("invalid template created a partial catalog registration")
            by_adapter: dict[str, dict[str, Any]] = {}
            for candidate in candidates:
                inspection = candidate.get("inspection", {})
                template = inspection.get("template") if isinstance(inspection, dict) else None
                if isinstance(template, dict) and isinstance(template.get("adapterId"), str):
                    by_adapter[template["adapterId"]] = candidate
            required = {"projectstate-v6", "studystate", "statespec-template"}
            if required - set(by_adapter):
                raise RuntimeError(f"template discovery missed adapters: {sorted(required - set(by_adapter))}")
            imported = [
                _install_and_execute(
                    browser,
                    by_adapter[adapter_id],
                    adapter_id=adapter_id,
                    instance_id=f"journey-{adapter_id}",
                )
                for adapter_id in ("projectstate-v6", "studystate", "statespec-template")
            ]
        finally:
            app.service_stop()

        app = PersistentApp(LocalLayout.from_environment())
        app.service_start(port=port, repo_root=ROOT)
        try:
            restarted = BrowserClient(port)
            restarted.establish_session()
            for record in imported:
                instance_id = record["instanceId"]
                detail = restarted.request(f"/v1/instances/{instance_id}")
                if detail.get("instance", {}).get("pathState") != "present":
                    raise RuntimeError(f"{instance_id} did not survive service restart")
                if detail.get("source", {}).get("adapterId") != record["adapterId"]:
                    raise RuntimeError(f"{instance_id} source binding changed after restart")
                if not restarted.request(f"/v1/instances/{instance_id}/actions")["actions"]:
                    raise RuntimeError(f"{instance_id} lost its reviewed actions after restart")
                conversation = restarted.request(f"/v1/instances/{instance_id}/conversation")
                if conversation.get("thread", {}).get("conversationId") != record["conversationId"]:
                    raise RuntimeError(f"{instance_id} conversation identity changed after restart")
        finally:
            app.service_stop()

        source_after = {
            "projectstate-v6": _source_status(projectstate),
            "studystate": _source_status(studystate),
            "statespec-template": _source_status(generic),
        }
        if source_after != source_before:
            raise RuntimeError("a source repository changed during the template journey")
        return {
            "formatVersion": "stateport.template-lifecycle-journey/v1",
            "result": "passed",
            "serviceBoundary": "production_http_session_csrf",
            "frontendServed": True,
            "sourceRepositoriesUnchanged": True,
            "restartContinuity": "passed",
            "invalidTemplateRegistration": "refused_without_managed_instance",
            "templates": imported,
        }



def installed_phase(port: int, phase: str, identity: dict[str, Any], receipt: Path) -> dict[str, Any]:
    """Exercise an already running service; never start or modify its runtime."""
    required = {"projectstate-v6", "studystate", "statespec-template", "invalid"}
    sources = identity.get("sources", {})
    if set(sources) != required or not re.fullmatch(r"[a-z][a-z0-9-]{1,40}", str(identity.get("instancePrefix", ""))):
        raise RuntimeError("identity requires unique instancePrefix and four exact source bindings")
    for binding in sources.values():
        path = binding.get("path", "")
        if not isinstance(path, str) or not path.startswith("/imports/") or any(part in {"", ".", ".."} for part in path.split("/")[1:]):
            raise RuntimeError("source path must be an exact child of signed /imports mount")
        if not re.fullmatch(r"[0-9a-f]{40}", str(binding.get("commit", ""))):
            raise RuntimeError("source commit must be a full Git commit")
    if len({item["path"] for item in sources.values()}) != 4:
        raise RuntimeError("source paths must be distinct")
    previous = json.loads(receipt.read_text()) if receipt.exists() else None
    if previous is not None and previous.get("identity") != identity:
        raise RuntimeError("existing receipt belongs to a different identity")
    if phase == "execute" and previous is not None:
        raise RuntimeError("execute receipt already exists; use recheck after restart")
    if phase == "recheck" and (previous is None or previous.get("result") != "passed"):
        raise RuntimeError("recheck requires a passed execute receipt")
    browser = BrowserClient(port)
    browser.establish_session()
    browser.frontend()
    candidates = browser.request("/v1/repository-import/local-candidates")["candidates"]
    selected = {}
    for adapter, binding in sources.items():
        matches = [c for c in candidates if c.get("relativeLocation") == binding["path"].removeprefix("/imports/")
                   and c.get("inspection", {}).get("sourceIdentity", {}).get("headCommit") == binding["commit"]]
        if len(matches) != 1:
            raise RuntimeError(f"exact source binding unavailable or ambiguous: {adapter}")
        selected[adapter] = matches[0]
    prefix = identity["instancePrefix"]
    invalid_id = prefix + "-invalid"
    if phase == "execute":
        before = browser.request("/v1/instances")["instances"]
        if any(str(item.get("instanceId", item.get("id", ""))).startswith(prefix + "-") for item in before):
            raise RuntimeError("instance prefix already exists")
        rejected = selected["invalid"]
        inspection = rejected["inspection"]
        if inspection.get("template", {}).get("validation", {}).get("status") != "failed":
            raise RuntimeError("invalid fixture did not fail template validation")
        digest = inspection["inspectionDigest"]
        actor = browser.request("/v1/status")["actor"]["actorId"]
        try:
            browser.request("/v1/repository-import/register", body={"candidateId": rejected["candidateId"],
                "inspectionDigest": digest, "instanceId": invalid_id, "name": "Invalid fixture",
                "approval": {"decision": "approve", "actorId": actor, "proposalDigest": digest}})
        except RuntimeError as exc:
            if "template_contract_invalid" not in str(exc):
                raise
        else:
            raise RuntimeError("invalid template registration was accepted")
        if browser.request("/v1/instances")["instances"] != before:
            raise RuntimeError("invalid template registration left visible residue")
        records = [_install_and_execute(browser, selected[adapter], adapter_id=adapter,
                   instance_id=prefix + "-" + adapter)
                   for adapter in ("projectstate-v6", "studystate", "statespec-template")]
    else:
        records = previous["templates"]
    if {record.get("adapterId") for record in records} != required - {"invalid"} or len(records) != 3:
        raise RuntimeError("receipt must bind exactly three template adapters")
    for record in records:
        instance_id = record["instanceId"]
        adapter = record["adapterId"]
        current_source = selected[adapter]["inspection"]["sourceIdentity"]
        if instance_id != prefix + "-" + adapter or record["sourceCommit"] != sources[adapter]["commit"] or record["sourceTree"] != current_source["headTree"]:
            raise RuntimeError("receipt/source identity mismatch")
        detail = browser.request(f"/v1/instances/{instance_id}")
        if detail.get("instance", {}).get("pathState") != "present":
            raise RuntimeError("durable instance unavailable")
        for key, expected in (("adapterId", record["adapterId"]), ("resolvedCommit", record["sourceCommit"]), ("resolvedTree", record["sourceTree"])):
            if detail.get("source", {}).get(key) != expected:
                raise RuntimeError("durable source binding changed")
        run = browser.request(f"/v1/runs/{record['runId']}")["run"]
        if run.get("instanceId") != instance_id or run.get("lifecycleState") != "CLOSED" or run.get("runResult", {}).get("executionStatus") != "completed" or run.get("result", {}).get("canonicalStateUnchanged") is not True:
            raise RuntimeError("durable completed run/result unavailable")
        if not any(item.get("receiptId") == record["installReceiptId"] for item in browser.request(f"/v1/instances/{instance_id}/receipts")["receipts"]):
            raise RuntimeError("durable import receipt unavailable")
        conversation = browser.request(f"/v1/instances/{instance_id}/conversation")
        if conversation.get("thread", {}).get("conversationId") != record["conversationId"]:
            raise RuntimeError("durable conversation binding changed")
    result = {"formatVersion": "stateport.template-lifecycle-journey/v1", "result": "passed",
              "environment": "installed_qemu_simulation_staged_sources", "identity": identity,
              "phase": phase, "templates": records, "serviceBoundary": "production_http_session_csrf",
              "executionScope": "bundled template inspection; synthetic engine, not real-provider or workload proof",
              "restartContinuity": "rechecked_after_external_restart" if phase == "recheck" else "awaiting_external_restart",
              "invalidTemplateRegistration": "refused_without_visible_catalog_residue"}
    destination = receipt if phase == "execute" else receipt.with_name(receipt.stem + ".recheck.json")
    with destination.open("x", encoding="utf-8") as output:
        output.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--projectstate",
        type=Path,
        default=ROOT.parent / "ProjectState_Template",
    )
    parser.add_argument(
        "--studystate",
        type=Path,
        default=ROOT.parent / "StudyState_Template",
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("--installed-port", type=int)
    parser.add_argument("--phase", choices=("execute", "recheck"), default="execute")
    parser.add_argument("--identity", type=Path, help="JSON with instancePrefix and sources: adapter -> {path, commit}")
    parser.add_argument("--receipt", type=Path)
    arguments = parser.parse_args()
    if arguments.installed_port is not None:
        if arguments.identity is None or arguments.receipt is None or arguments.output is not None:
            parser.error("installed mode requires --identity and --receipt and disallows --output")
        result = installed_phase(arguments.installed_port, arguments.phase, json.loads(arguments.identity.read_text()), arguments.receipt)
    else:
        if arguments.identity is not None or arguments.receipt is not None or arguments.phase != "execute":
            parser.error("installed identity/receipt/recheck requires --installed-port")
        result = run(arguments.projectstate, arguments.studystate)
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if arguments.output is not None:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(encoded, encoding="utf-8")
    sys.stdout.write(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
