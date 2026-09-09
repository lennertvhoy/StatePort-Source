"""Rootless daemon proof for a production-issued reviewed source workspace.

The authority UID substitutions in this test are fixture-only: they make the
filesystem transaction runnable as the current unprivileged test user.  This
does not claim native root issuance or production provisioning.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

pytest_plugins = ("test_execution_host_daemon",)

SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
import test_execution_host_daemon as daemon_test  # noqa: E402

from execution_host import application_workspaces as authority  # noqa: E402
from execution_host import daemon_contract as contract  # noqa: E402
from execution_host.workspace_source import verify_source_commit  # noqa: E402
from stateport_persistent_app.execution_host_proxy import (  # noqa: E402
    ExecutionHostProxy,
    _workspace_source_archive,
)


def _write_authority(path: Path, value: dict, mode: int) -> None:
    path.write_bytes(authority._authority_bytes(value))
    path.chmod(mode)


def _preflight_transport_binding(binding: dict, grant: dict, workload: dict, uid: int) -> None:
    """Validate the exact transport row before any daemon/container effect."""
    previous_control_uid = authority._CONTROL_UID
    authority._CONTROL_UID = uid
    try:
        rows = authority.validate_binding_transport({
            "formatVersion": authority.TRANSPORT_FORMAT,
            "bindings": [{**binding, "grant": grant}],
        })
    finally:
        authority._CONTROL_UID = previous_control_uid
    assert rows == [{**binding, "grant": grant}]
    assert contract.validate_workload_spec(workload) == workload


def _cleanup_owned_container(state_dir: Path, workload: dict, environment: dict[str, str]) -> None:
    """Best-effort exact-ID cleanup for failures before normal daemon removal."""
    from execution_host.engine import PodmanCliEngine

    ledger_path = state_dir / "workloads" / f"{workload['workloadId']}.json"
    if not ledger_path.exists():
        return
    try:
        row = json.loads(ledger_path.read_text(encoding="utf-8"))
        container_id = row.get("containerId")
        if not isinstance(container_id, str) or len(container_id) != 64:
            return
        engine = PodmanCliEngine(runner=lambda args, **kwargs: subprocess.run(args, **{**kwargs, "env": environment}))
        observed = engine.inspect(workload["workloadId"])
        if observed.get("containerId") != container_id:
            return
        if observed.get("running"):
            engine.stop(workload["workloadId"], expected_container_id=container_id)
        engine.remove(workload["workloadId"], expected_container_id=container_id)
    except (OSError, ValueError, RuntimeError):
        # The coordinator retains the temporary state and can inspect an
        # unresolved exact identity; never broaden this cleanup to a name.
        return


def _source_request(source: dict, *, instance_id: str, application_id: str, catalog_digest: str, profile: dict) -> dict:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    request = {
        "formatVersion": authority.SOURCE_REQUEST_FORMAT,
        "instanceId": instance_id,
        "applicationId": application_id,
        "catalogIdentityDigest": catalog_digest,
        "issuerContextDigest": "sha256:" + "b" * 64,
        "profileDigest": contract.canonical_digest(profile),
        "sourceMode": "reviewed-commit",
        "createdAt": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expiresAt": (now + timedelta(minutes=15)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "grantExpiresAt": (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": source,
        "sourceDigest": contract.canonical_digest(source),
    }
    request["requestDigest"] = contract.canonical_digest(request)
    return authority.validate_workspace_authority_request(request)


def test_production_reviewed_source_authority_seeds_and_recovers_rootless_daemon(tmp_path: Path) -> None:
    """Issue source authority, seed a real capsule, restart, remove, and recover."""
    from execution_host.application_workspaces import TRANSPORT_FORMAT, catalog_identity

    uid = os.geteuid()
    gid = os.getegid()
    layout_root = tmp_path / "source-layout"
    source = daemon_test._materialize_seeded_workspace_source(layout_root)
    source_stat = source.stat()
    entry = {
        "instanceId": "reviewed-source",
        "applicationId": "stateport.development-reference",
        "name": "Reviewed source fixture",
        "path": str(source),
        "pathState": "present",
        "status": "active",
        "filesystem": {"device": source_stat.st_dev, "inode": source_stat.st_ino, "kind": "directory"},
        "metadata": {"source": {"templateId": "stateport.development-reference"}},
    }
    catalog_digest = catalog_identity(entry)
    template = contract.workspace_template_for_image(daemon_test.WORKLOAD_IMAGE)
    profile = authority.source_authority_profile(template)
    with tempfile.TemporaryFile("w+b") as archive:
        source_facts = _workspace_source_archive(entry, archive, commit_witness=True)
    request = _source_request(
        source_facts,
        instance_id=entry["instanceId"],
        application_id=entry["applicationId"],
        catalog_digest=catalog_digest,
        profile=profile,
    )
    workload = authority.workspace_authority_workload_spec(request, profile["workload"])
    grant = daemon_test._grant_document("workspace-grant-" + request["requestDigest"][7:39], workload)
    grant.update(
        peerUid=uid,
        operations=list(profile["operations"]),
        baseRevision=source_facts["baseRevision"],
        issuedAt=request["createdAt"],
        expiresAt=request["grantExpiresAt"],
    )
    grant["budgets"].update(
        maxTimeoutSeconds=workload["timeoutSeconds"],
        maxOutputBytes=workload["outputByteBound"],
        maxMemoryMaxBytes=workload["resources"]["memoryMaxBytes"],
        maxPidsMax=workload["resources"]["pidsMax"],
        maxCpuQuotaPercent=workload["parameters"].get("cpuQuotaPercent", 100),
        maxDiskMaxBytes=workload["parameters"].get("diskMaxBytes", 16 * 1024 * 1024),
    )
    grant = contract.validate_grant_document(grant)
    binding = {
        "grantId": grant["grantId"],
        "authorityGrantDigest": contract.canonical_digest(grant),
        "workload": workload,
    }
    _preflight_transport_binding(binding, grant, workload, uid)
    source_originals = {
        row["path"]: ((source / row["path"]).read_bytes(), (source / row["path"]).stat().st_mode & 0o777)
        for row in source_facts["sourceInventory"]
    }
    source_identity = (source_stat.st_dev, source_stat.st_ino)

    handle = daemon_test.DaemonHandle(tmp_path / "daemon")
    environment, scope = daemon_test._governed_engine_environment(tmp_path, handle.env())
    handle.env = lambda: environment
    restarted = None
    created = False
    # UID overrides are strictly test transaction fixtures; no root helper
    # is invoked and no native root provisioning claim is made.
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(authority, "_ROOT_UID", uid)
    monkeypatch.setattr(authority, "_EXEC_UID", uid)
    monkeypatch.setattr(authority, "_CONTROL_UID", uid)
    try:
        handle.boot()
        grants = handle.state_dir / "grants"
        grants.mkdir(mode=0o700, exist_ok=True)
        public = tmp_path / "authority-public"
        public.mkdir(mode=0o755)
        receipts = public / "receipts"
        receipts.mkdir(mode=0o755)
        _write_authority(grants / "revocation.json", {"revocationEpoch": grant["revocationEpoch"], "revokedGrantIds": [], "pausedGrantIds": []}, 0o600)
        bindings = public / "bindings.json"
        issued = authority.issue_workspace_authority(
            request,
            grant=grant,
            binding=binding,
            context_digest=request["issuerContextDigest"],
            operator={"user": "fixture", "uid": uid, "gid": gid},
            grants_dir=grants,
            bindings_path=bindings,
            receipt_dir=receipts,
            verify_current=lambda: _verify_source_fd(source, source_facts, source_identity),
            clock=lambda: request["createdAt"],
            binding_format=TRANSPORT_FORMAT,
            authority_profile=profile,
        )
        assert issued["status"] == "issued"
        published = json.loads(bindings.read_text(encoding="utf-8"))
        assert published["formatVersion"] == TRANSPORT_FORMAT
        assert published["bindings"][0]["grant"]["baseRevision"] == source_facts["baseRevision"]
        assert published["bindings"][0]["workload"]["parameters"]["sourceSeed"]["reviewDigest"]

        proxy = ExecutionHostProxy(
            socket_path=handle.socket_path,
            bindings_path=bindings,
            bindings_format=TRANSPORT_FORMAT,
            bindings_owner_uid=uid,
            catalog_entry=lambda _iid: entry,
            catalog_entries=lambda: [entry],
            authority_grant_digest="",
        )
        created_receipt = proxy.create_application(
            entry["instanceId"],
            source_review_digest=workload["parameters"]["sourceSeed"]["reviewDigest"],
        )
        assert created_receipt["accepted"] is True
        assert created_receipt["result"]["sourceSeed"]["status"] == "complete"
        created = True
        bound = proxy.application_binding(entry["instanceId"])
        assert bound is not None
        workload_id = bound["workload"]["workloadId"]
        assert proxy.start(workload_id)["result"]["state"] == "running"
        first_ledger = json.loads((handle.state_dir / "workloads" / f"{workload_id}.json").read_text(encoding="utf-8"))
        assert daemon_test._governed_container_membership(first_ledger["containerId"], scope, environment=environment)["bookedScope"] == scope
        observed = proxy.exec(
            workload_id,
            ["sh", "-c", "test -x /workspace/workspace-proof.sh && /workspace/workspace-proof.sh && stat -c %a /workspace/workspace-proof.sh && printf durable-marker > /workspace/durable-marker"],
        )
        assert observed["result"]["exitStatus"] == 0
        assert "SEEDED_SOURCE_VERIFIED" in observed["result"]["output"]
        assert "755" in observed["result"]["output"]
        assert proxy.stop(workload_id)["result"]["state"] == "stopped"

        assert handle.process is not None
        handle.process.send_signal(signal.SIGKILL)
        handle.process.wait(timeout=30)
        handle.process = None
        restarted = daemon_test.DaemonHandle(tmp_path / "daemon")
        restart_overlay = tmp_path / "restart-overlay"
        restart_overlay.mkdir()
        restarted_env, restarted_scope = daemon_test._governed_engine_environment(restart_overlay, restarted.env())
        restarted.env = lambda: restarted_env
        restarted.boot()
        assert restarted_scope == scope
        recovered_proxy = ExecutionHostProxy(
            socket_path=restarted.socket_path,
            bindings_path=bindings,
            bindings_format=TRANSPORT_FORMAT,
            bindings_owner_uid=uid,
            catalog_entry=lambda _iid: entry,
            catalog_entries=lambda: [entry],
            authority_grant_digest="",
        )
        assert recovered_proxy.status_of(workload_id)["result"]["state"] == "stopped"
        assert recovered_proxy.start(workload_id)["result"]["state"] == "running"
        recovered_ledger = json.loads((restarted.state_dir / "workloads" / f"{workload_id}.json").read_text(encoding="utf-8"))
        assert daemon_test._governed_container_membership(recovered_ledger["containerId"], restarted_scope, environment=restarted_env)["bookedScope"] == restarted_scope
        preserved = recovered_proxy.exec(workload_id, ["sh", "-c", "cat /workspace/durable-marker; /workspace/workspace-proof.sh"])
        assert preserved["result"]["exitStatus"] == 0
        assert "durable-marker" in preserved["result"]["output"]
        assert "SEEDED_SOURCE_VERIFIED" in preserved["result"]["output"]
        assert recovered_proxy.stop(workload_id)["result"]["state"] == "stopped"
        assert recovered_proxy.remove(workload_id)["result"]["state"] == "removed"
        volume = workload["parameters"]["volumeName"]
        assert subprocess.run(["podman", "volume", "exists", volume], env=restarted_env, capture_output=True, timeout=30).returncode == 0
        reused = recovered_proxy.create_application(
            entry["instanceId"],
            source_review_digest=workload["parameters"]["sourceSeed"]["reviewDigest"],
        )
        assert reused["result"]["recovered"] is True
        assert recovered_proxy.start(workload_id)["result"]["state"] == "running"
        final = recovered_proxy.exec(workload_id, ["cat", "/workspace/durable-marker"])
        assert final["result"]["output"].strip() == "durable-marker"
        recovered_proxy.stop(workload_id)
        recovered_proxy.remove(workload_id)
        ledger = json.loads((restarted.state_dir / "workloads" / f"{workload_id}.json").read_text())
        assert sum(row["kind"] == "workspace-source-seeded" for row in ledger["receipts"]) == 1
        assert ledger["state"] == "removed"
        (tmp_path / "reviewed-source-daemon-proof.json").write_text(json.dumps({
            "environment": "source authority transaction with fixture UIDs; real rootless daemon/Podman; no installed root authentication",
            "requestDigest": request["requestDigest"], "sourceDigest": request["sourceDigest"],
            "workloadId": workload_id, "grantId": grant["grantId"], "receiptDigest": issued["receiptDigest"],
            "baseRevision": source_facts["baseRevision"], "fileCount": len(source_facts["sourceInventory"]),
            "bookedScope": scope, "sourceSeedCount": 1, "daemonRestart": "passed", "removeRecoverRetainedMarker": True,
        }, indent=2), encoding="utf-8")
    finally:
        monkeypatch.undo()
        if restarted is not None:
            restarted.stop()
        handle.stop()
        _cleanup_owned_container(handle.state_dir, workload, environment)
        if created:
            from execution_host.engine import PodmanCliEngine
            PodmanCliEngine(runner=lambda args, **kwargs: subprocess.run(args, **{**kwargs, "env": environment})).verify_workspace_volumes(workload)
        if created:
            removed = subprocess.run(['podman', 'volume', 'rm', workload['parameters']['volumeName']], env=environment, capture_output=True, text=True, timeout=30)
            if removed.returncode != 0:
                raise RuntimeError('reviewed source test volume cleanup failed; retained')
        assert (source.stat().st_dev, source.stat().st_ino) == source_identity
        for relative, (content, mode) in source_originals.items():
            assert (source / relative).read_bytes() == content
            assert (source / relative).stat().st_mode & 0o777 == mode


def _verify_source_fd(source: Path, source_facts: dict, source_identity: tuple[int, int]) -> None:
    root_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(root_fd)
        if (info.st_dev, info.st_ino) != source_identity:
            raise ValueError("reviewed source root identity changed")
        verify_source_commit(root_fd, source_facts, owner_uid=os.geteuid())
    finally:
        os.close(root_fd)
