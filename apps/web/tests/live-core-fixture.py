#!/usr/bin/env python3
"""Start a real AppServer with disposable public-safe core-workflow fixtures."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import signal
import tempfile
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any, Sequence


INFRASTRUCTURE_INSTANCE_ID = "live-core-infra"
UNAVAILABLE_INFRASTRUCTURE_INSTANCE_ID = "live-core-infra-unavailable"


class _InfrastructureFixtureRunner:
    """Deterministic subprocess boundary for browser-live infrastructure tests.

    Git observations still execute against the disposable repository. Host
    libvirt, Nix, SSH, and Make operations never execute: their bounded results
    are supplied here so the real AppServer, adapter, plans, approvals, leases,
    receipts, and browser client can be exercised without touching the host.
    """

    def __init__(self, *, domain_state: str) -> None:
        self.domain_state = domain_state

    def __call__(
        self,
        command: Sequence[str],
        **kwargs: Any,
    ) -> subprocess.CompletedProcess[str]:
        arguments = tuple(str(item) for item in command)
        if not arguments:
            return subprocess.CompletedProcess(arguments, 127, "", "empty command")

        # Repository and StatePort product identities remain real Git facts.
        if arguments[0] == "git":
            return subprocess.run(arguments, **kwargs)

        if arguments[:3] == ("virsh", "--connect", "qemu:///session"):
            operation = arguments[3] if len(arguments) > 3 else ""
            if operation == "domstate":
                if self.domain_state == "unavailable":
                    return subprocess.CompletedProcess(
                        arguments,
                        1,
                        "",
                        "error: fixture libvirt connection is unavailable\n",
                    )
                return subprocess.CompletedProcess(
                    arguments,
                    0,
                    f"{self.domain_state}\n",
                    "",
                )
            if operation == "domuuid":
                return subprocess.CompletedProcess(
                    arguments,
                    0,
                    "00000000-0000-0000-0000-000000000000\n",
                    "",
                )

        if arguments[0] == "make":
            target = arguments[1] if len(arguments) > 1 else ""
            if target == "vm-persistent-start":
                self.domain_state = "running"
            elif target == "vm-persistent-stop":
                self.domain_state = "shut off"
            return subprocess.CompletedProcess(arguments, 0, "", "")

        if arguments[0] == "nix":
            return subprocess.CompletedProcess(arguments, 0, "", "")

        if arguments[0] == "ssh":
            return subprocess.CompletedProcess(
                arguments,
                0,
                '{"verdict":"pass"}\n',
                "",
            )

        # A browser test must never execute the destructive repository script.
        return subprocess.CompletedProcess(
            arguments,
            126,
            "",
            "command is outside the deterministic live-core fixture boundary\n",
        )


def _source_roots(repo_root: Path) -> None:
    for parent in (repo_root / "packages", repo_root / "apps"):
        for source in sorted(parent.glob("*/src")):
            if source.is_dir():
                sys.path.insert(0, str(source))


def _canonical_instance_files(destination: Path, *, instance_id: str, name: str, source: dict[str, str]) -> None:
    """Write the canonical StateSpec identity files a real materialized
    instance carries, so backup-eligibility is exercised honestly instead of
    bypassed."""
    (destination / "instance.yaml").write_text(
        "apiVersion: statedd.stateport.io/v1alpha1\n"
        "kind: Instance\n"
        "metadata:\n"
        f"  id: {instance_id}\n"
        f"  name: {name}\n"
        "spec:\n"
        "  owner:\n"
        "    handle: live-core\n"
        "    name: Live Core\n"
        "  status: draft\n"
        "  templateRef:\n"
        f"    id: {source['templateId']}\n"
        "    path: fixtures/apps/development-reference\n",
        encoding="utf-8",
    )
    statedd = destination / ".statedd"
    statedd.mkdir()
    (statedd / "lock.yaml").write_text(
        "formatVersion: stateport.instance-lock/v1\n"
        f"instanceId: {instance_id}\n"
        "template:\n"
        "  source:\n"
        f"    templateId: {source['templateId']}\n"
        f"    resolvedCommit: {source['resolvedCommit']}\n"
        f"    resolvedTree: {source['resolvedTree']}\n"
        f"    manifestDigest: {source['manifestDigest']}\n"
        f"    sourceClass: {source['sourceClass']}\n"
        "files: []\n",
        encoding="utf-8",
    )


def _git(root: Path, *arguments: str) -> str:
    environment = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_AUTHOR_NAME": "StatePort live-core fixture",
        "GIT_AUTHOR_EMAIL": "stateport-live-core@example.invalid",
        "GIT_COMMITTER_NAME": "StatePort live-core fixture",
        "GIT_COMMITTER_EMAIL": "stateport-live-core@example.invalid",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    result = subprocess.run(
        ("/usr/bin/git", "-C", root, *arguments),
        check=True,
        capture_output=True,
        text=True,
        env=environment,
        timeout=15,
    )
    return result.stdout.strip()


def _materialize(
    source: Path,
    destination: Path,
    *,
    add_editable_file: bool = False,
    add_infrastructure_contract: bool = False,
) -> dict[str, str]:
    shutil.copytree(source, destination)
    if add_editable_file:
        (destination / "src").mkdir()
        (destination / "src" / "main.py").write_text("answer = 41\n", encoding="utf-8")
    if add_infrastructure_contract:
        (destination / "flake.nix").write_text(
            '{ description = "public-safe StatePort live-core fixture"; }\n',
            encoding="utf-8",
        )
        (destination / "Makefile").write_text(
            "vm-persistent-create:\n\t@true\n",
            encoding="utf-8",
        )
    _git(destination, "init", "--initial-branch=main", "--template=")
    _git(destination, "add", "--all")
    _git(destination, "-c", "commit.gpgSign=false", "commit", "-m", "public-safe live-core fixture")
    return {
        "resolvedCommit": _git(destination, "rev-parse", "HEAD"),
        "resolvedTree": _git(destination, "rev-parse", "HEAD^{tree}"),
        "manifestDigest": "sha256:" + hashlib.sha256(
            (destination / "application.yaml").read_bytes()
        ).hexdigest(),
        "sourceClass": "synthetic_fixture",
    }


def _actual_template_imports(app: Any, repo_root: Path, service_process: Any, *, web_root: Path | None = None) -> list[dict[str, Any]]:
    """Actual pinned sources through production HTTP import, before operator grants."""
    import threading
    sys.path.insert(0, str(repo_root / "scripts"))
    from run_template_lifecycle_journey import BrowserClient, _create_generic_template
    from execution_host.application_workspaces import catalog_identity
    from stateport_persistent_app.execution_host_proxy import prepare_workspace_source_seed
    from test_execution_host_daemon import _workspace_spec

    roots = app.layout.data_root / "actual-template-sources"
    roots.mkdir()
    def source_identity(source: Path) -> dict[str, str]:
        rows = [(path.relative_to(source).as_posix(), path.stat().st_mode & 0o7777, hashlib.sha256(path.read_bytes()).hexdigest()) for path in sorted(source.rglob("*")) if path.is_file() and ".git" not in path.relative_to(source).parts]
        return {"commit": _git(source, "rev-parse", "HEAD"), "tree": _git(source, "rev-parse", "HEAD^{tree}"), "status": _git(source, "status", "--porcelain=v1", "--untracked-files=all"), "filesDigest": hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()}

    records = []
    generic = _create_generic_template(roots / "Journey_Generic_Template")
    sources = (
        ("ProjectState_Template", "7e4cb7c3397324d09f768eeb1d722316714c46e1", "projectstate-v6", None),
        ("StudyState_Template", "3bf1048488001a1a33b7d55eec6e1acdc123607b", "studystate", None),
        ("Journey_Generic_Template", _git(generic, "rev-parse", "HEAD"), "statespec-template", generic),
    )
    for name, commit, adapter, generated_source in sources:
        source = generated_source or roots / name
        if generated_source is None:
            subprocess.run(["git", "clone", "--no-hardlinks", "--no-checkout", str(repo_root.parent / name), str(source)], check=True, capture_output=True)
            _git(source, "checkout", "--detach", commit)
        if _git(source, "rev-parse", "HEAD") != commit or _git(source, "status", "--porcelain=v1", "--untracked-files=all"):
            raise RuntimeError("actual template clone identity is not clean and pinned")
        records.append({"sourceRoot": str(source), "sourceCommit": commit, "adapterId": adapter, "instanceId": "actual-" + adapter, "sourceIdentityBefore": source_identity(source)})
    os.environ["STATEPORT_REPOSITORY_ROOTS"] = os.pathsep.join([os.environ.get("STATEPORT_REPOSITORY_ROOTS", ""), str(roots)])
    server = service_process.AppServer(("127.0.0.1", 0), app.layout, web_root or repo_root / "apps" / "web")
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    try:
        browser = BrowserClient(server.server_address[1])
        browser.establish_session()
        candidates = browser.request("/v1/repository-import/local-candidates")["candidates"]
        for record in records:
            matches = [c for c in candidates if c.get("inspection", {}).get("sourceIdentity", {}).get("headCommit") == record["sourceCommit"]]
            if len(matches) != 1:
                raise RuntimeError("actual template candidate missing or ambiguous")
            candidate = matches[0]
            inspection = browser.request("/v1/repository-import/inspect", body={"candidateId": candidate["candidateId"]})
            if inspection["template"]["adapterId"] != record["adapterId"]:
                raise RuntimeError("actual template adapter mismatch")
            name = inspection["template"]["displayName"]
            plan = browser.request("/v1/template-import/plan", body={"candidateId": candidate["candidateId"], "inspectionDigest": inspection["inspectionDigest"], "instanceId": record["instanceId"], "name": name})
            actor = browser.request("/v1/status")["actor"]["actorId"]
            installed = browser.request("/v1/template-import/install", body={"plan": plan, "approval": {"decision": "approve", "actorId": actor, "planDigest": plan["planDigest"]}})
            if installed.get("managedCopyCreated") is not True or installed.get("sourceRepositoryMutated") is not False:
                raise RuntimeError("actual template did not materialize an isolated managed copy")
            entry = app.catalog.get(record["instanceId"])
            record.update({"name": name, "managedRoot": entry["path"], "installReceiptId": installed["receiptId"]})
        for record in records:
            entry = app.catalog.get(record["instanceId"])
            spec = _workspace_spec("ui-" + record["instanceId"], parameters={"ownership": {"applicationId": entry["applicationId"], "instanceId": entry["instanceId"], "catalogIdentityDigest": catalog_identity(entry), "runId": None}})
            # Cheap admission premise before daemon boot: ordinary installed templates must be seedable.
            reviewed = prepare_workspace_source_seed(entry, spec)
            record["sourceReview"] = reviewed["parameters"]["sourceSeed"]
            if source_identity(Path(record["sourceRoot"])) != record["sourceIdentityBefore"]:
                raise RuntimeError("actual template source changed during HTTP import or seed review")
        return records
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def _application_workspace_daemon(
    app: Any,
    repo_root: Path,
    service_process: Any,
    actual_templates: list[dict[str, Any]] | None = None,
    *,
    reviewed_issuance: bool = False,
):
    """Opt-in real Podman fixture; grants remain trusted test-operator setup."""
    from functools import partial
    sys.path.insert(0, str(repo_root / "scripts"))
    from test_execution_host_daemon import DaemonHandle, _workspace_spec, _provision_grant, _governed_engine_environment, WORKLOAD_IMAGE
    from execution_host.application_workspaces import FORMAT, TRANSPORT_FORMAT, catalog_identity
    from execution_host.daemon_contract import canonical_digest, validate_workload_spec, workspace_template_for_image
    from stateport_persistent_app.execution_host_proxy import ExecutionHostProxy, prepare_workspace_source_seed

    root = Path(tempfile.mkdtemp(prefix="sp-ui-daemon-", dir="/tmp"))
    socket_root = Path(tempfile.mkdtemp(prefix="s-", dir="/tmp"))
    handle = DaemonHandle(root, socket_root=socket_root)
    engine_environment = json.loads(os.environ["STATEPORT_UI_ENGINE_ENV"])
    engine_environment, governed_scope = _governed_engine_environment(root, engine_environment)
    original_env = handle.env
    def daemon_env():
        value = original_env()
        for key in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "CONTAINERS_STORAGE_CONF"):
            value.pop(key, None)
        value.update(engine_environment)
        if reviewed_issuance:
            # The real installed unit supplies this exact image/spec pair.  The
            # fixture derives it from the cached test image and still lets the
            # daemon validate the matching private default grant at boot.
            value["STATEPORT_EXECUTION_HOST_WORKSPACE_IMAGE_REFERENCE"] = WORKLOAD_IMAGE
            value["STATEPORT_EXECUTION_HOST_WORKSPACE_SPEC_DIGEST"] = canonical_digest(workspace_template_for_image(WORKLOAD_IMAGE))
            value["STATEPORT_EXECUTION_HOST_ALLOWED_CLIENT_UID"] = str(os.geteuid())
            value["STATEPORT_EXECUTION_HOST_ALLOWED_CLIENT_GID"] = str(os.getegid())
        return value
    handle.env = daemon_env
    default_grant: dict[str, Any] | None = None
    if reviewed_issuance:
        from execution_host import daemon_contract
        from execution_host import application_workspaces as authority
        from stateport_release.execution_host_provisioning import (
            _DEFAULT_GRANT_BUDGETS, _DEFAULT_GRANT_OPERATIONS, _default_grant_document,
        )
        template = daemon_contract.workspace_template_for_image(WORKLOAD_IMAGE)
        # The fixture UID is the explicit control identity for both the
        # browser process and the short-lived issuer process.
        authority._CONTROL_UID = os.geteuid()
        default_grant = _default_grant_document(
            peer_uid=os.geteuid(), grant_id="control-plane-default",
            image_reference=WORKLOAD_IMAGE, base_revision=None,
            budgets=_DEFAULT_GRANT_BUDGETS, operations=_DEFAULT_GRANT_OPERATIONS,
            issued_at="2026-01-01T00:00:00Z", expires_at="2099-01-01T00:00:00Z",
            revocation_epoch=0, workspace_template=template,
        )
        default_grant = daemon_contract.validate_grant_document(default_grant)
        grants_dir = handle.state_dir / "grants"
        grants_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        default_grant_path = grants_dir / "control-plane-default.json"
        default_grant_path.write_text(
            json.dumps(default_grant, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        default_grant_path.chmod(0o600)
    handle.boot()
    rows = []
    workload_ids = []
    instance_ids = () if reviewed_issuance else (tuple(record["instanceId"] for record in actual_templates) if actual_templates else ("live-core-project", "live-core-study"))
    try:
        for instance_id in instance_ids:
            entry = app.catalog.get(instance_id)
            workload_id = "ui-" + instance_id + "-" + root.name.removeprefix("sp-ui-daemon-")
            workload_ids.append(workload_id)
            spec = _workspace_spec(workload_id, parameters={"ownership": {
                "applicationId": entry["applicationId"], "instanceId": instance_id,
                "catalogIdentityDigest": catalog_identity(entry), "runId": None,
            }})
            if actual_templates:
                spec = prepare_workspace_source_seed(entry, spec)
                record = next(row for row in actual_templates if row["instanceId"] == instance_id)
                record["sourceReview"] = spec["parameters"]["sourceSeed"]
            spec = validate_workload_spec(spec)
            grant = _provision_grant(handle, spec)
            rows.append({"grantId": grant["grantId"], "authorityGrantDigest": canonical_digest(grant), "workload": spec})
        manifest = root / "application-bindings.json"
        manifest_format = TRANSPORT_FORMAT if reviewed_issuance else FORMAT
        manifest.write_text(json.dumps({"formatVersion": manifest_format, "bindings": rows}), encoding="utf-8")
        manifest.chmod(0o644 if reviewed_issuance else 0o600)
        os.environ["STATEPORT_APPLICATION_WORKSPACE_BINDINGS"] = str(manifest)
        os.environ["STATEPORT_EXECUTION_SOCKET"] = str(handle.socket_path)
        os.environ["STATEPORT_APPLICATION_WORKSPACE_BINDINGS_FORMAT"] = manifest_format
        if reviewed_issuance:
            assert default_grant is not None
            os.environ["STATEPORT_EXECUTION_GRANT_ID"] = default_grant["grantId"]
            os.environ["STATEPORT_EXECUTION_GRANT_DIGEST"] = canonical_digest(default_grant)
            os.environ["STATEPORT_EXECUTION_HOST_WORKSPACE_IMAGE_REFERENCE"] = WORKLOAD_IMAGE
            os.environ["STATEPORT_EXECUTION_HOST_WORKSPACE_SPEC_DIGEST"] = canonical_digest(workspace_template_for_image(WORKLOAD_IMAGE))
        elif os.environ.get("STATEPORT_UI_NO_DEFAULT_GRANT") == "1":
            # Exercise application-owned bindings when the installation has no
            # default development grant. The per-application grants above
            # remain exact and independently usable.
            os.environ.pop("STATEPORT_EXECUTION_GRANT_ID", None)
            os.environ.pop("STATEPORT_EXECUTION_GRANT_DIGEST", None)
        else:
            os.environ["STATEPORT_EXECUTION_GRANT_ID"] = rows[0]["grantId"]
            os.environ["STATEPORT_EXECUTION_GRANT_DIGEST"] = rows[0]["authorityGrantDigest"]
        # Dynamic/v2 production transport rejects ambient socket overrides.
        # This existing constructor seam explicitly identifies the disposable
        # daemon; the installed fixed-socket rule remains unchanged.
        service_process.ExecutionHostProxy = partial(ExecutionHostProxy, bindings_owner_uid=os.geteuid(),
            **({"socket_path": handle.socket_path} if reviewed_issuance else {}))
        (app.layout.data_root / "ui-workspace-fixture.json").write_text(json.dumps({
            "manifest": str(manifest), "daemonRoot": str(root), "governedScope": governed_scope,
            "workloads": dict(zip(instance_ids, workload_ids)),
            "actualTemplates": actual_templates,
            "qualification": "reviewed source issuance fixture: dynamic default preparation grant, empty transport bindings, fixture UID transaction; no installed sudo authentication" if reviewed_issuance else ("real pinned template HTTP imports, source service/browser, fixture operator grants, seeded volumes" if actual_templates else "real Podman, source service/browser, fixture operator grants, empty volumes"),
            "reviewedIssuance": ({
                "issuerPath": str(Path(os.environ["STATEPORT_WORKSPACE_AUTHORITY_DIRECTORY"]) / "issuer.json"),
                "bindingsPath": str(manifest),
                "grantsDir": str(handle.state_dir / "grants"),
                "receiptsDir": str(app.layout.data_root / "workspace-authority-fixture-receipts"),
                "defaultGrantId": default_grant["grantId"] if default_grant else None,
                "imageReference": WORKLOAD_IMAGE if reviewed_issuance else None,
                "workspaceSpecDigest": canonical_digest(workspace_template_for_image(WORKLOAD_IMAGE)) if reviewed_issuance else None,
                "uidFixture": {"uid": os.geteuid(), "gid": os.getegid()},
            } if reviewed_issuance else None),
        }), encoding="utf-8")
    except BaseException:
        handle.stop()
        raise

    def cleanup():
        from execution_host.engine import MANAGED_LABEL_KEY, WORKLOAD_LABEL, KIND_LABEL, PodmanCliEngine
        from test_execution_host_daemon import WORKLOAD_IMAGE
        from execution_host.application_workspaces import read_binding_transport
        handle.stop()
        failures = []
        def podman(*args):
            return subprocess.run(["podman", *args], env=daemon_env(), capture_output=True, text=True, timeout=30)
        cleanup_rows = list(rows)
        if reviewed_issuance:
            try:
                # Issuance happens after boot in a separate process. Read only
                # the exact transport rows it published; never discover by
                # container name or sweep the engine.
                cleanup_rows = read_binding_transport(manifest)
            except (OSError, ValueError, TypeError) as exc:
                failures.append({"scope": "reviewed-issuance-bindings", "error": str(exc)})
                cleanup_rows = []
        for row in cleanup_rows:
            spec = row["workload"]
            workload_id = spec["workloadId"]
            container_name = "stateport-exec-" + workload_id
            try:
                exists = podman("container", "exists", container_name)
                if exists.returncode == 0:
                    inspected = podman("container", "inspect", "--format", "{{json .}}", container_name)
                    if inspected.returncode != 0:
                        raise RuntimeError("container identity unavailable")
                    info = json.loads(inspected.stdout)
                    labels = info.get("Config", {}).get("Labels", {})
                    if any(labels.get(key) != value for key, value in {MANAGED_LABEL_KEY: "true", WORKLOAD_LABEL: workload_id, KIND_LABEL: "workspace"}.items()) or info.get("ImageDigest") != WORKLOAD_IMAGE.rsplit("@", 1)[1] or info.get("Config", {}).get("Image", "").split("@", 1)[0].split(":", 1)[0] != WORKLOAD_IMAGE.split("@", 1)[0].split(":", 1)[0]:
                        raise RuntimeError("foreign container retained")
                    container_id = info.get("Id")
                    if reviewed_issuance:
                        ledger_path = handle.state_dir / "workloads" / f"{workload_id}.json"
                        ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
                        if ledger.get("containerId") != container_id or ledger.get("spec") != spec:
                            raise RuntimeError("container differs from the exact fixture ledger; retained")
                    if not isinstance(container_id, str) or len(container_id) != 64 or any(c not in "0123456789abcdef" for c in container_id):
                        raise RuntimeError("container immutable ID unavailable")
                    if podman("rm", "--force", container_id).returncode != 0:
                        raise RuntimeError("owned container removal failed")
                elif exists.returncode != 1:
                    raise RuntimeError("container presence unavailable")
                for volume_name, expected_labels in PodmanCliEngine._workspace_volume_claims(spec):
                    exists = podman("volume", "exists", volume_name)
                    if exists.returncode == 1:
                        continue
                    if exists.returncode != 0:
                        raise RuntimeError("volume presence unavailable")
                    inspected = podman("volume", "inspect", "--format", "{{json .}}", volume_name)
                    if inspected.returncode != 0:
                        raise RuntimeError("volume identity unavailable")
                    info = json.loads(inspected.stdout)
                    if info.get("Name") != volume_name or any(info.get("Labels", {}).get(key) != value for key, value in expected_labels.items()):
                        raise RuntimeError("foreign volume retained")
                    if podman("volume", "rm", volume_name).returncode != 0:
                        raise RuntimeError("owned volume removal failed")
            except (RuntimeError, ValueError, TypeError, KeyError, OSError, subprocess.TimeoutExpired) as exc:
                failures.append({"workloadId": workload_id, "error": str(exc)})
        (root / "cleanup-result.json").write_text(json.dumps({"failures": failures, "ownedWorkloads": [row["workload"]["workloadId"] for row in cleanup_rows]}), encoding="utf-8")
        if failures:
            raise RuntimeError("workspace fixture cleanup incomplete; retained objects recorded at " + str(root / "cleanup-result.json"))
        # Preserve the fixture ledger/manifest for evidence; only its verified runtime effects are removed.
    return cleanup


def _issue_reviewed_source_request(app: Any, request_path: Path, reviewed_digest: str) -> dict[str, Any]:
    """Run the production issuer against the fixture's already-running daemon.

    This process is intentionally issuance-only: the normal fixture process
    has already booted ``DaemonHandle`` and created the dynamic default grant.
    The UID substitutions make the filesystem transaction runnable by this
    unprivileged test process; they do not exercise installed sudo/root
    authentication.
    """
    if os.environ.get("STATEPORT_UI_REVIEWED_ISSUANCE") != "1":
        raise RuntimeError("reviewed source issuance requires STATEPORT_UI_REVIEWED_ISSUANCE=1")
    if not request_path.is_absolute() or ".." in request_path.parts:
        raise ValueError("reviewed request path must be absolute and contained")
    request_info = request_path.stat()
    if not request_path.is_file() or request_info.st_size <= 0 or request_info.st_size > 1024 * 1024:
        raise ValueError("reviewed request is not a bounded regular file")
    from execution_host import application_workspaces as authority
    from execution_host import daemon_contract
    from execution_host.workspace_source import verify_source_commit

    request = authority.validate_workspace_authority_request(json.loads(request_path.read_text(encoding="utf-8")))
    if request["formatVersion"] != authority.SOURCE_REQUEST_FORMAT or request["requestDigest"] != reviewed_digest:
        raise ValueError("reviewed request digest or source format differs")
    metadata_path = app.layout.data_root / "ui-workspace-fixture.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    issuance = metadata.get("reviewedIssuance")
    if not isinstance(issuance, dict):
        raise RuntimeError("reviewed issuance fixture metadata is absent")
    issuer_path = Path(str(issuance["issuerPath"]))
    issuer = json.loads(issuer_path.read_text(encoding="utf-8"))
    if (issuer.get("formatVersion") != "stateport.workspace-issuer-public/v3"
            or issuer.get("profileId") != authority.SOURCE_PROFILE_ID
            or issuer.get("profileDigest") != request["profileDigest"]
            or issuer.get("issuerContextDigest") != request["issuerContextDigest"]
            or issuer.get("sourceMode") != "reviewed-commit"):
        raise ValueError("reviewed issuer publication differs from request")
    template = daemon_contract.workspace_template_for_image(str(issuance["imageReference"]))
    if (issuance.get("workspaceSpecDigest") != daemon_contract.canonical_digest(template)
            or issuer.get("profile") != authority.source_authority_profile(template)):
        raise ValueError("reviewed issuer template differs from the cached image contract")
    default_grant_path = Path(str(issuance["grantsDir"])) / (str(issuance["defaultGrantId"]) + ".json")
    default_grant = daemon_contract.validate_grant_document(json.loads(default_grant_path.read_text(encoding="utf-8")))
    if (default_grant["grantId"] != "control-plane-default"
            or default_grant["imageReference"] != str(issuance["imageReference"])
            or default_grant["workloadSpecDigests"].get("default-dev") != daemon_contract.canonical_digest(template)):
        raise ValueError("fixture default grant does not bind the cached workspace template")
    entry = app.catalog.get(request["instanceId"])
    from execution_host.application_workspaces import catalog_identity
    if entry["applicationId"] != request["applicationId"] or catalog_identity(entry) != request["catalogIdentityDigest"]:
        raise ValueError("reviewed catalog identity changed")
    root = Path(str(entry["path"]))
    uid, gid = os.geteuid(), os.getegid()
    source_stat = root.stat()
    source_identity = (entry["filesystem"]["device"], entry["filesystem"]["inode"])
    if (source_stat.st_dev, source_stat.st_ino) != source_identity:
        raise ValueError("reviewed source directory differs from catalog identity")

    def verify_current() -> None:
        current = app.catalog.get(request["instanceId"])
        if current["applicationId"] != request["applicationId"] or catalog_identity(current) != request["catalogIdentityDigest"]:
            raise ValueError("reviewed catalog identity changed during issuance")
        if Path(str(current["path"])) != root:
            raise ValueError("reviewed source path changed during issuance")
        current_stat = Path(str(current["path"])).stat()
        if (current_stat.st_dev, current_stat.st_ino) != (source_stat.st_dev, source_stat.st_ino):
            raise ValueError("reviewed source directory identity changed during issuance")
        if json.loads(issuer_path.read_text(encoding="utf-8")) != issuer:
            raise ValueError("reviewed issuer publication changed during issuance")
        observed_default = daemon_contract.validate_grant_document(json.loads(default_grant_path.read_text(encoding="utf-8")))
        if observed_default != default_grant:
            raise ValueError("fixture default grant changed during issuance")
        fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino) != source_identity:
                raise ValueError("reviewed source directory changed while opening")
            verify_source_commit(fd, request["source"], owner_uid=uid)
        finally:
            os.close(fd)

    verify_current()
    from stateport_release import execution_host_provisioning as provisioning
    workload = authority.workspace_authority_workload_spec(request, issuer["profile"]["workload"])
    bindings_path = Path(str(issuance["bindingsPath"]))
    receipts_dir = Path(str(issuance["receiptsDir"]))
    receipts_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    previous = (authority._ROOT_UID, authority._EXEC_UID, authority._CONTROL_UID, provisioning.CONTROL_UID)
    authority._ROOT_UID = authority._EXEC_UID = authority._CONTROL_UID = uid
    provisioning.CONTROL_UID = uid
    try:
        # Reuse the production grant derivation, including its exact default
        # grant operation subset and budget inheritance.
        grant = provisioning._workspace_authority_grant(request, default_grant, authority_profile=issuer["profile"])
        grant = daemon_contract.validate_grant_document(grant)
        binding = {
            "grantId": grant["grantId"],
            "authorityGrantDigest": daemon_contract.canonical_digest(grant),
            "workload": workload,
        }
        issued = authority.issue_workspace_authority(
            request, grant=grant, binding=binding,
            context_digest=request["issuerContextDigest"],
            operator={"user": "fixture", "uid": uid, "gid": gid},
            grants_dir=Path(str(issuance["grantsDir"])), bindings_path=bindings_path,
            receipt_dir=receipts_dir, verify_current=verify_current,
            clock=lambda: datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"), binding_format=authority.TRANSPORT_FORMAT,
            authority_profile=issuer["profile"],
        )
    finally:
        authority._ROOT_UID, authority._EXEC_UID, authority._CONTROL_UID, provisioning.CONTROL_UID = previous
    return {"status": "issued", "workloadId": issued["workloadId"], "receiptDigest": issued["receiptDigest"]}


def _authority_proof_manager(app: Any, repo_root: Path, *, initialize: bool = False) -> Any:
    """Real authority primitive over an isolated, explicitly selected fixture repo."""
    from governed_runner.authority import AuthorityManager, grant_template
    directory = app.layout.data_root / "live-core-authority-repository"
    created = False
    if not directory.exists():
        if not initialize:
            raise RuntimeError("authority proof repository has not been initialized")
        directory.mkdir(mode=0o700)
        (directory / "config").mkdir()
        shutil.copyfile(repo_root / "config/authority-policy.v1.yaml", directory / "config/authority-policy.v1.yaml")
        for suffix in ("a", "b"):
            (directory / f"proof-{suffix}.txt").write_text("initial", encoding="utf-8")
        _git(directory, "init", "--initial-branch=main")
        _git(directory, "add", ".")
        _git(directory, "-c", "commit.gpgSign=false", "commit", "-m", "bounded authority fixture")
        created = True
    manager = AuthorityManager(directory)
    if created:
        for suffix in ("a", "b"):
            grant = grant_template(manager, grant_id=f"grant_browser_{suffix}", profile="balanced",
                actor_id="local-user", role="primary", branch_pattern="main", slice_id=None,
                application_id=None, run_id=None, paths=(f"proof-{suffix}.txt",),
                allow=("edit_scoped_files",), require_approval=(), forbid=(),
                owner_directive_id="OD-BROWSER-AUTHORITY-PROOF", expires_when="timestamp",
                expires_at="2099-01-01T00:00:00Z", max_actions=100,
                max_duration_seconds=7200, max_cost_usd=0)
            manager.activate_grant(grant, owner_actor_id="fixture-owner")
    # Existing fixture state is never reactivated on resume.
    return manager


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--resume", action="store_true", help="Reuse the same durable fixture state without rematerializing repositories")
    parser.add_argument("--actor-role", choices=("local_user", "platform_operator"), default="local_user")
    parser.add_argument("--authority-proof", action="store_true")
    parser.add_argument("--authority-consume", choices=("a", "b"))
    parser.add_argument("--authority-text", default="bounded effect")
    parser.add_argument("--issue-source-request", type=Path, help="Fixture-only issuance of a downloaded reviewed source request")
    parser.add_argument("--reviewed-request-digest", help="Exact digest approved by the fixture operator")
    args = parser.parse_args(argv)
    if bool(args.issue_source_request) != bool(args.reviewed_request_digest):
        parser.error("--issue-source-request and --reviewed-request-digest must be supplied together")
    repo_root = args.repo_root.resolve(strict=True)
    _source_roots(repo_root)

    from stateport_persistent_app import LocalLayout, PersistentApp
    from stateport_persistent_app.infrastructure import LocalLibvirtAdapter
    from stateport_goal_execution import GoalExecutionCoordinator
    import stateport_persistent_app.service_process as service_process
    from stateport_persistent_app.service_resilient_entry import (
        main as resilient_service_main,
    )

    app = PersistentApp(LocalLayout.from_environment())
    if args.issue_source_request is not None:
        # The normal fixture process owns daemon boot and remains running. This
        # short-lived process only attaches to its persisted metadata and
        # publishes the production transport binding transaction.
        print(json.dumps(_issue_reviewed_source_request(app, args.issue_source_request.resolve(), args.reviewed_request_digest)))
        return 0
    if args.authority_consume is not None:
        from governed_runner.authority import AuthorityRefusal
        manager = _authority_proof_manager(app, repo_root)
        if len(args.authority_text) > 128:
            raise ValueError("authority proof text is too long")
        marker = manager.checkout / f"proof-{args.authority_consume}.txt"
        try:
            _, receipt = manager.execute("edit_scoped_files", lambda: marker.write_text(args.authority_text, encoding="utf-8"),
                actor_id="local-user", grant_id=f"grant_browser_{args.authority_consume}",
                branch="main", paths=[marker.name])
            result = {"decision": "executed", "receipt": receipt}
        except AuthorityRefusal as error:
            result = {"decision": "refused", "reason": error.code, "receipt": error.receipt}
        result["receiptDirectory"] = str(manager.receipts_root)
        print(json.dumps(result))
        return 0
    if args.authority_proof:
        manager = _authority_proof_manager(app, repo_root, initialize=True)
        # Process-local fixture source selection, like the source HTTP harness;
        # production authorization routes and manager enforcement stay intact.
        service_process.platform_surface.authority_manager = lambda _server: manager
    if not args.resume:
        app.setup_init()

        project = app.layout.instances_root / "live-core-project"
        project_source = _materialize(
            repo_root / "fixtures" / "apps" / "development-reference",
            project,
            add_editable_file=True,
        )
        # The raw ProjectState checkout keeps its real Git history for source
        # and repository assertions, but its fixture lock must use the same
        # package identity as the production fixture installer. The editable
        # file belongs to the instance and is therefore excluded from this
        # immutable source digest.
        from stateport_portable_execution import PortableExecutionService
        project_package_digest = PortableExecutionService._fixture_tree_digest(
            repo_root / "fixtures" / "apps" / "development-reference"
        )
        project_source.update({
            "resolvedCommit": "fixture:" + project_package_digest[7:],
            "resolvedTree": project_package_digest[7:],
            "manifestDigest": project_package_digest,
        })
        # A real materialized instance carries canonical StateSpec identity files;
        # without them the backup subsystem correctly refuses to run.
        _canonical_instance_files(
            project,
            instance_id="live-core-project",
            name="Live Core Project",
            source={"templateId": "stateport.development-reference", **project_source},
        )
        _git(project, "add", "--all")
        _git(project, "-c", "commit.gpgSign=false", "commit", "-m", "canonical instance identity")
        app.catalog.register(
            project,
            instance_id="live-core-project",
            name="Live Core Project",
            source={
                "templateId": "stateport.development-reference",
                **project_source,
            },
        )

        # Use the production fixture installer so revision ownership and lock identity
        # match the runtime's trusted-action checks. A raw directory copy omits them.
        PortableExecutionService(app, repo_root).install_fixture_instance(
            "studystate.sample", "live-core-study", name="Live Core Study"
        )

        # Distinct public-safe repository-import candidate. It stays outside the
        # instance catalog until the browser completes read-only inspection and
        # explicitly approves the exact inspection digest.
        import_root = app.layout.data_root / "live-core-import-candidates"
        import_root.mkdir(parents=True, exist_ok=True)
        _materialize(
            repo_root / "fixtures" / "apps" / "development-reference",
            import_root / "nixos-homelab",
            add_infrastructure_contract=True,
        )

        # Two pre-registered external infrastructure applications exercise both
        # the honest unavailable state and the complete bounded service-fixture
        # lifecycle. The supported repository is intentionally dirty so the
        # browser must display that fact without treating a stopped VM as success.
        infrastructure_root = app.layout.data_root / "live-core-infrastructure"
        available_repository = infrastructure_root / "available" / "nixos-homelab"
        available_source = _materialize(
            repo_root / "fixtures" / "apps" / "development-reference",
            available_repository,
            add_infrastructure_contract=True,
        )
        (available_repository / "local-operator-note.txt").write_text(
            "public-safe uncommitted fixture evidence\n",
            encoding="utf-8",
        )
        app.register_external_repository(
            available_repository,
            instance_id=INFRASTRUCTURE_INSTANCE_ID,
            name="Live Core Infrastructure",
            application_id="nixos-infrastructure",
            source={"sourceKind": "synthetic_fixture", **available_source},
        )

        unavailable_repository = (
            infrastructure_root / "unavailable" / "nixos-homelab"
        )
        unavailable_source = _materialize(
            repo_root / "fixtures" / "apps" / "development-reference",
            unavailable_repository,
            add_infrastructure_contract=True,
        )
        app.register_external_repository(
            unavailable_repository,
            instance_id=UNAVAILABLE_INFRASTRUCTURE_INSTANCE_ID,
            name="Unavailable Live Core Infrastructure",
            application_id="nixos-infrastructure",
            source={"sourceKind": "synthetic_fixture", **unavailable_source},
        )

    else:
        for instance_id in ("live-core-project", "live-core-study", INFRASTRUCTURE_INSTANCE_ID, UNAVAILABLE_INFRASTRUCTURE_INSTANCE_ID):
            app.catalog.get(instance_id)
    os.environ["STATEPORT_REPOSITORY_ROOTS"] = str(app.layout.data_root / "live-core-import-candidates")

    fixture_runners = {
        INFRASTRUCTURE_INSTANCE_ID: _InfrastructureFixtureRunner(
            domain_state="shut off"
        ),
        UNAVAILABLE_INFRASTRUCTURE_INSTANCE_ID: _InfrastructureFixtureRunner(
            domain_state="unavailable"
        ),
    }

    def fixture_adapter(
        repository_root: Path | str,
        *,
        instance_id: str,
        state_root: Path | str,
        product_root: Path | str | None = None,
        **_: Any,
    ) -> LocalLibvirtAdapter:
        # Repository imports created during the suite also remain safely
        # environment-gated if their infrastructure view is opened later.
        runner = fixture_runners.setdefault(
            instance_id,
            _InfrastructureFixtureRunner(domain_state="unavailable"),
        )
        return LocalLibvirtAdapter(
            repository_root,
            instance_id=instance_id,
            state_root=state_root,
            product_root=product_root,
            runner=runner,
        )

    # This replacement is process-local to the disposable fixture. Production
    # service code and its real LocalLibvirtAdapter remain unchanged. The
    # resilient entry still delegates all unrelated routes to that same server.
    service_process.LocalLibvirtAdapter = fixture_adapter

    def fixture_goal_execution(*, record_root: Path) -> GoalExecutionCoordinator:
        # Production intentionally refuses synthetic execution. This
        # public-safe browser fixture explicitly opts into the test-only
        # provider-free backend so it can exercise the governed lifecycle.
        return GoalExecutionCoordinator(
            record_root=record_root,
            allow_synthetic_backend=True,
        )

    service_process.GoalExecutionCoordinator = fixture_goal_execution

    reviewed_issuance = os.environ.get("STATEPORT_UI_REVIEWED_ISSUANCE") == "1"
    source_authority = os.environ.get("STATEPORT_UI_SOURCE_AUTHORITY") == "1" or reviewed_issuance
    if reviewed_issuance and os.environ.get("STATEPORT_UI_REAL_WORKSPACES") != "1":
        raise RuntimeError("reviewed issuance fixture requires governed real workspace mode")
    if source_authority:
        # Publication alone creates no grant or installed root authentication
        # proof. Reviewed issuance mode separately provisions a fixture default
        # grant below and later invokes the transaction primitive with test UIDs.
        from functools import partial
        from datetime import datetime, timedelta, timezone
        from execution_host.application_workspaces import FORMAT, source_authority_profile
        from execution_host.daemon_contract import canonical_digest, workspace_template_for_image
        from stateport_release.execution_host_provisioning import default_sealed_workspace_workload
        sys.path.insert(0, str(repo_root / "scripts"))
        from test_execution_host_daemon import WORKLOAD_IMAGE
        from stateport_persistent_app.execution_host_proxy import ExecutionHostProxy
        directory = app.layout.config_root / "workspace-authority-fixture"
        directory.mkdir(mode=0o700, exist_ok=True)
        template = (workspace_template_for_image(WORKLOAD_IMAGE) if reviewed_issuance else default_sealed_workspace_workload())
        profile = source_authority_profile(template)
        publication = {"formatVersion": "stateport.workspace-issuer-public/v3",
            "issuerContextDigest": canonical_digest({"fixture": "source-browser-review-only"}),
            "profileId": profile["profileId"], "profileDigest": canonical_digest(profile),
            "sourceMode": "reviewed-commit", "profile": profile,
            "grantExpiresAtLimit": (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "operator": {"user": "fixture", "uid": os.geteuid(), "gid": os.getegid()}}
        (directory / "issuer.json").write_text(json.dumps(publication), encoding="utf-8")
        (directory / "bindings.json").write_text(json.dumps({"formatVersion": FORMAT, "bindings": []}), encoding="utf-8")
        for name in ("issuer.json", "bindings.json"):
            (directory / name).chmod(0o600)
        os.environ["STATEPORT_WORKSPACE_AUTHORITY_DIRECTORY"] = str(directory)
        os.environ["STATEPORT_APPLICATION_WORKSPACE_BINDINGS"] = str(directory / "bindings.json")
        os.environ.pop("STATEPORT_EXECUTION_GRANT_DIGEST", None)
        service_process.ExecutionHostProxy = partial(ExecutionHostProxy, bindings_owner_uid=os.geteuid())

    actual_templates = None
    if os.environ.get("STATEPORT_UI_ACTUAL_TEMPLATES") == "1":
        if os.environ.get("STATEPORT_UI_REAL_WORKSPACES") != "1":
            raise RuntimeError("actual-template workspace mode requires governed real workspace mode")
        actual_templates = _actual_template_imports(app, repo_root, service_process)
    workspace_operator = os.environ.get("STATEPORT_UI_REAL_WORKSPACES") == "1" or source_authority
    if workspace_operator:
        boundary = app.layout.config_root / "platform-operator-authority"
        boundary.write_text("explicit governed workspace fixture operator\n", encoding="utf-8")
        boundary.chmod(0o600)
    cleanup = _application_workspace_daemon(app, repo_root, service_process, actual_templates, reviewed_issuance=reviewed_issuance) if os.environ.get("STATEPORT_UI_REAL_WORKSPACES") == "1" else None
    if cleanup is not None:
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        return resilient_service_main(
            [
            "--port",
            str(args.port),
            "--repo-root",
            str(repo_root),
            "--actor-role",
            "platform_operator" if workspace_operator else args.actor_role,
            ]
        )
    finally:
        if cleanup is not None:
            cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
