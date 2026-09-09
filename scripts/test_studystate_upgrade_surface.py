#!/usr/bin/env python3
"""Acceptance tests for the revisioned studystate fixture and its governed upgrade surface."""

from __future__ import annotations

import json
import hashlib
import os
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import zipfile
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
for relative in (
    "packages/persistent-app/src",
    "packages/portable-execution/src",
    "packages/application-experience/src",
    "packages/execution-host/src",
    "packages/external-engine-runtime/src",
    "packages/codex-adapter/src",
    "packages/run-bundle/src",
    "packages/statedd-core/src",
    "packages/template-validator/src",
    "packages/instance-backup/src",
    "packages/instance-catalog/src",
    "packages/diagnostics/src",
    "packages/governed-api/src",
    "packages/approval-gate/src",
    "packages/quota-engine/src",
    "packages/audit-log/src",
    "packages/governed-runner/src",
    "packages/container-runner/src",
    "apps/runner/src",
    "scripts/qualification",
):
    path = ROOT / relative
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
for path in sorted((ROOT / "packages").glob("*/src")):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
for path in sorted((ROOT / "apps").glob("*/src")):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from governed_api import GovernedAPI  # noqa: E402
from governed_runner import InstanceLease  # noqa: E402
import journey_common  # noqa: E402
import run_journey_j4  # noqa: E402
from journey_common import (  # noqa: E402
    boot_retained_vm,
    discover_services,
    validate_retained_candidate_inputs,
)
from run_journey_j2 import (  # noqa: E402
    J2_REQUIRED_STEPS,
    RECORD_ACTION,
    UNDO_ACTION,
    _control_podman_exec_command,
    _contract_digest,
    _copy_guest_evidence,
    _existing_study_instances,
    _guided_mutation_binding,
    _guided_study_script,
    _gui_inspection_script,
    _object_digest,
    _required_step_failures,
    _study_state_snapshot,
    _undo_restoration_binding,
    governed_chain,
)
from stateport_persistent_app import LocalLayout, PersistentApp  # noqa: E402
from stateport_persistent_app.activity_receipts import ActivityReceiptError  # noqa: E402
from stateport_persistent_app.app import AppError, PersistentCatalog  # noqa: E402
from stateport_persistent_app.service_process import AppServer  # noqa: E402
from stateport_portable_execution.runtime import (  # noqa: E402
    PortableExecutionError,
    PortableExecutionService,
)
from statedd_core import LifecycleError, load_template_manifest, plan_upgrade  # noqa: E402
from statedd_core import approve_upgrade_plan, apply_upgrade, materialize_instance  # noqa: E402
from statedd_core.lifecycle import (  # noqa: E402
    _read_lock,
    _source_revision,
    _validate_lock,
    _write_yaml,
)


FIXTURE_APP = ROOT / "fixtures" / "apps" / "studystate-sample"
REVISIONS = ("v0001", "v0002")


def test_studystate_validation_rejects_empty_durable_state(tmp_path: Path) -> None:
    descriptor = yaml.safe_load((FIXTURE_APP / "application.yaml").read_text())
    command = shlex.split(descriptor["validationCommand"])
    state = tmp_path / "state/LEARNING.yaml"
    state.parent.mkdir()
    state.write_text("activities: []\nevidence: []\n", encoding="utf-8")
    assert subprocess.run(command, cwd=tmp_path, check=False).returncode == 0

    state.write_bytes(b"")
    assert subprocess.run(command, cwd=tmp_path, check=False).returncode != 0


@pytest.mark.parametrize(
    ("actor_role", "actor_id"),
    (("local_user", "local-user"), ("platform_operator", "platform-operator")),
)
def test_persistent_app_upgrades_the_selected_studystate_instance_with_independent_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    actor_role: str,
    actor_id: str,
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    if actor_role == "platform_operator":
        operator_boundary = app.layout.config_root / "platform-operator-authority"
        operator_boundary.write_text("authorized\n", encoding="utf-8")
        operator_boundary.chmod(0o600)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
    server = AppServer(
        ("127.0.0.1", 0),
        app.layout,
        ROOT / "apps" / "_template-upgrade-test-web",
        actor_role=actor_role,
    )
    thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.02},
        daemon=True,
    )
    thread.start()
    origin = f"http://127.0.0.1:{server.server_address[1]}"

    def request(path: str, body: dict[str, object] | None = None) -> tuple[int, dict[str, object]]:
        headers = {"Accept": "application/json"}
        if cookie:
            headers["Cookie"] = cookie
        if body is not None:
            headers.update({
                "Content-Type": "application/json",
                "Origin": origin,
                "X-StatePort-CSRF": str(session["csrfToken"]),
            })
        wire = Request(
            origin + path,
            data=json.dumps(body).encode("utf-8") if body is not None else None,
            headers=headers,
            method="POST" if body is not None else "GET",
        )
        try:
            with urlopen(wire) as response:
                return response.status, json.loads(response.read())
        except HTTPError as error:
            return error.code, json.loads(error.read())

    cookie = ""
    session: dict[str, object] = {}
    try:
        with urlopen(origin + "/session") as response:
            session = json.loads(response.read())["result"]
            cookie = response.headers["Set-Cookie"].split(";", 1)[0]
        status, catalog = request("/v1/applications")
        assert status == 200
        study = next(
            item
            for item in catalog["result"]["applications"]
            if item["applicationId"] == "studystate.sample"
        )
        status, installed = request("/v1/application-fixtures/install", {
            "applicationId": "studystate.sample",
            "instanceId": "study-upgrade",
            "name": "StudyState Upgrade",
            "applicationDescriptorDigest": study["applicationIdentity"]["descriptorDigest"],
            "applicationPackageDigest": study["applicationIdentity"]["packageDigest"],
            "experienceDescriptorDigest": study["experienceIdentity"]["descriptorDigest"],
        })
        assert status == 200 and installed["ok"] is True

        state_path = app.layout.instances_root / "study-upgrade" / "state" / "LEARNING.yaml"
        personal_state = state_path.read_text(encoding="utf-8").replace(
            "status: planned", "status: paused", 1
        )
        state_path.write_text(personal_state, encoding="utf-8")
        status, undeclared = request("/v1/instances/study-upgrade/template-upgrade/request", {
            "expectedInstanceId": "study-upgrade",
            "targetRevision": "v9999",
        })
        assert status == 409 and undeclared["error"]["code"] == "execution_refused"
        status, caller_path = request("/v1/instances/study-upgrade/template-upgrade/request", {
            "expectedInstanceId": "study-upgrade",
            "targetRevision": "v0002",
            "templatePath": "/caller/controlled",
        })
        assert status == 400 and caller_path["error"]["code"] == "operation_failed"
        original_target_resolver = server.template_upgrades.upgrade_target_binding_resolver
        server.template_upgrades.upgrade_target_binding_resolver = (
            lambda _instance_id, _instance_path, _template_path, supplied: {
                **supplied,
                "templateDigest": "sha256:" + "0" * 64,
            }
        )
        status, mismatched_target = request("/v1/instances/study-upgrade/template-upgrade/request", {
            "expectedInstanceId": "study-upgrade",
            "targetRevision": "v0002",
        })
        assert status == 409
        assert mismatched_target["error"]["code"] == "target_binding_mismatch"
        server.template_upgrades.upgrade_target_binding_resolver = original_target_resolver
        status, requested = request("/v1/instances/study-upgrade/template-upgrade/request", {
            "expectedInstanceId": "study-upgrade",
            "targetRevision": "v0002",
        })
        assert status == 200 and requested["ok"] is True, requested
        result = requested["result"]
        approval_id = result["approval"]["id"]
        plan_digest = result["plan"]["planDigest"]
        assert result["plan"]["target"]["version"] == "0.2.0"
        assert result["targetBinding"]["targetRevision"] == "v0002"

        status, approvals = request("/v1/approvals")
        assert status == 200
        projected = next(
            item
            for item in approvals["result"]["approvals"]
            if item["id"] == f"template_upgrade:{approval_id}"
        )
        assert projected["decision"] == {
            "kind": "template_upgrade",
            "expectedInstanceId": "study-upgrade",
            "expectedDigest": plan_digest,
        }
        assert "Target revision: v0002" in projected["scope"]

        self_decision = server.template_upgrades.dispatch(
            "POST",
            "/v1/approvals/decide",
            {
                "actor": "persistent-app-upgrade-requester",
                "approvalId": approval_id,
                "status": "approved",
            },
        )
        assert self_decision.status == 403
        assert self_decision.body["error"]["code"] == "approval_forbidden"

        status, mismatch = request("/v1/instances/study-upgrade/template-upgrade/approve", {
            "expectedInstanceId": "study-upgrade",
            "approvalId": approval_id,
            "expectedPlanDigest": "sha256:" + "0" * 64,
        })
        assert status == 409 and mismatch["error"]["code"] == "approval_mismatch"
        status, approved = request("/v1/instances/study-upgrade/template-upgrade/approve", {
            "expectedInstanceId": "study-upgrade",
            "approvalId": approval_id,
            "expectedPlanDigest": plan_digest,
        })
        assert status == 200 and approved["result"]["approval"]["status"] == "approved"
        state_path.write_text(personal_state + "\n", encoding="utf-8")
        status, stale = request("/v1/instances/study-upgrade/template-upgrade/apply", {
            "expectedInstanceId": "study-upgrade",
            "approvalId": approval_id,
            "expectedPlanDigest": plan_digest,
        })
        assert status == 409 and stale["error"]["code"] == "plan_stale", stale
        state_path.write_text(personal_state, encoding="utf-8")
        original_rebind = PersistentCatalog.rebind_replaced_directory
        original_record_receipt = server.activity_receipts.record_receipt
        rebind_attempts = 0
        activity_receipt_attempts = 0

        def fail_first_catalog_rebind(self, entry, expected_filesystem):
            nonlocal rebind_attempts
            rebind_attempts += 1
            if rebind_attempts == 1:
                raise AppError("injected post-commit catalog rebind failure")
            return original_rebind(self, entry, expected_filesystem)

        monkeypatch.setattr(
            PersistentCatalog,
            "rebind_replaced_directory",
            fail_first_catalog_rebind,
        )

        def fail_first_activity_receipt(*, instance_id, receipt):
            nonlocal activity_receipt_attempts
            activity_receipt_attempts += 1
            if activity_receipt_attempts == 1:
                raise ActivityReceiptError("injected post-commit activity receipt failure")
            return original_record_receipt(instance_id=instance_id, receipt=receipt)

        monkeypatch.setattr(
            server.activity_receipts,
            "record_receipt",
            fail_first_activity_receipt,
        )
        status, interrupted = request("/v1/instances/study-upgrade/template-upgrade/apply", {
            "expectedInstanceId": "study-upgrade",
            "approvalId": approval_id,
            "expectedPlanDigest": plan_digest,
        })
        assert status == 409 and interrupted["error"]["code"] == "catalog_rebind_refused"
        assert state_path.read_text(encoding="utf-8") == personal_state
        assert (app.layout.instances_root / "study-upgrade" / ".statedd" / "upgrade-receipt.yaml").is_file()

        status, activity_interrupted = request("/v1/instances/study-upgrade/template-upgrade/apply", {
            "expectedInstanceId": "study-upgrade",
            "approvalId": approval_id,
            "expectedPlanDigest": plan_digest,
        })
        assert status == 409, activity_interrupted
        assert activity_interrupted["error"]["code"] == "activity_receipts_refused"
        assert state_path.read_text(encoding="utf-8") == personal_state

        status, applied = request("/v1/instances/study-upgrade/template-upgrade/apply", {
            "expectedInstanceId": "study-upgrade",
            "approvalId": approval_id,
            "expectedPlanDigest": plan_digest,
        })
        assert status == 200 and applied["result"]["applied"] is True
        assert applied["result"]["authority"] == {
            "requestedBy": "persistent-app-upgrade-requester",
            "approvedBy": f"authenticated-{actor_role}-approver",
            "appliedBy": "persistent-app-upgrade-operator",
        }
        assert applied["result"]["authorityModel"] == "authenticated_session_with_internal_service_roles/v1"
        assert applied["result"]["authorityBindings"]["approvedBy"] == {
            "id": f"authenticated-{actor_role}-approver",
            "principalType": "authenticated_operator_session",
            "sessionActorId": actor_id,
            "sessionActorRole": actor_role,
        }
        assert rebind_attempts == 3
        assert activity_receipt_attempts == 2
        assert state_path.read_text(encoding="utf-8") == personal_state
        status, repeated = request("/v1/instances/study-upgrade/template-upgrade/apply", {
            "expectedInstanceId": "study-upgrade",
            "approvalId": approval_id,
            "expectedPlanDigest": plan_digest,
        })
        assert status == 200 and repeated["result"]["idempotent"] is True
        assert repeated["result"]["receipt"]["planDigest"] == plan_digest

        status, inspected = request("/v1/instances/study-upgrade")
        assert status == 200 and inspected["result"]["version"] == "0.2.0"
        assert inspected["result"]["instance"]["pathState"] == "present"
        assert inspected["result"]["health"] == "valid"
        status, actions = request("/v1/instances/study-upgrade/actions")
        assert status == 200
        assert "studystate.sample.study-tip/v1" in {
            item["actionId"] for item in actions["result"]["actions"]
        }
        status, receipts = request("/v1/instances/study-upgrade/receipts")
        assert status == 200
        assert any(
            item["receiptId"] == f"template-upgrade:{approval_id}"
            for item in receipts["result"]["receipts"]
        )

        status, exported = request("/v1/instances/study-upgrade/portable-export", {})
        assert status == 200
        archive = exported["result"]
        with zipfile.ZipFile(archive["archive"]) as package:
            archived_lock = package.read("files/.statedd/lock.yaml")
            archived_receipt = package.read("files/.statedd/upgrade-receipt.yaml")
        assert app.layout.data_root.as_posix().encode("utf-8") not in archived_lock
        assert app.layout.data_root.as_posix().encode("utf-8") not in archived_receipt
        destination = app.layout.instances_root / "study-upgrade-copy"
        status, preview = request("/v1/portable-import/preview", {
            "archive": {
                "path": archive["archive"],
                "archiveDigest": archive["archiveDigest"],
                "archiveFileDigest": archive["archiveFileDigest"],
            },
            "destination": {
                "path": destination.as_posix(),
                "instanceId": "study-upgrade-copy",
            },
            "identityPolicy": "reidentify",
        })
        assert status == 200
        status, imported = request("/v1/portable-import/apply", {
            "archive": {
                "path": archive["archive"],
                "archiveDigest": archive["archiveDigest"],
                "archiveFileDigest": archive["archiveFileDigest"],
            },
            "destination": {
                "path": destination.as_posix(),
                "instanceId": "study-upgrade-copy",
            },
            "identityPolicy": "reidentify",
            "expectedPlanDigest": preview["result"]["planDigest"],
            "approval": {
                "decision": "approve",
                "actorId": actor_id,
                "actorRole": actor_role,
            },
        })
        assert status == 200 and imported["result"]["destinationMutated"] is True, imported
        status, copied = request("/v1/instances/study-upgrade-copy")
        assert status == 200
        assert copied["result"]["version"] == "0.2.0"
        assert copied["result"]["packageState"] == inspected["result"]["packageState"]
        assert app.catalog.get("study-upgrade-copy")["applicationId"] == "studystate.sample"
        with pytest.raises(PortableExecutionError, match="explicit capability review"):
            server.execution.action_list("study-upgrade-copy")
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def test_j2_control_podman_exec_preserves_shell_boundaries() -> None:
    command = _control_podman_exec_command(
        "stateport-api-container",
        "python3",
        "-c",
        "print('quoted value'); path = '/workspace/with space'",
    )
    outer = shlex.split(command)
    assert outer[:7] == [
        "sudo",
        "runuser",
        "-u",
        "stateport-control",
        "--",
        "bash",
        "-c",
    ]
    inner = outer[-1]
    assert "\\$(id -u)" not in inner
    assert "env -i HOME=/var/lib/stateport-control" in inner
    assert "XDG_RUNTIME_DIR=/run/user/$uid" in inner
    exec_argv = shlex.split(inner.rsplit("; run_control ", 1)[1])
    assert exec_argv == [
        "podman",
        "exec",
        "--",
        "stateport-api-container",
        "python3",
        "-c",
        "print('quoted value'); path = '/workspace/with space'",
    ]


def test_j2_service_discovery_preserves_declared_container_names() -> None:
    class FakeVM:
        def ssh(self, command: str) -> SimpleNamespace:
            assert "ContainerName=" in command
            return SimpleNamespace(
                returncode=0,
                stderr="",
                stdout="\n".join(
                    [
                        "stateport-web\tweb.service\t18080\tstateport-web-declared",
                        "stateport-api\tapi.service\t18081\tstateport-api-declared",
                        "stateport-worker\tworker.service\t18082\tstateport-worker-declared",
                    ]
                ),
            )

    assert discover_services(FakeVM()) == {
        "stateport-web": {
            "unit": "web.service",
            "port": "18080",
            "container": "stateport-web-declared",
        },
        "stateport-api": {
            "unit": "api.service",
            "port": "18081",
            "container": "stateport-api-declared",
        },
        "stateport-worker": {
            "unit": "worker.service",
            "port": "18082",
            "container": "stateport-worker-declared",
        },
    }


def test_j2_service_discovery_rejects_duplicate_or_unsafe_container_names() -> None:
    class FakeVM:
        def __init__(self, stdout: str) -> None:
            self.stdout = stdout

        def ssh(self, _command: str) -> SimpleNamespace:
            return SimpleNamespace(returncode=0, stderr="", stdout=self.stdout)

    valid_tail = "\n".join(
        [
            "stateport-api\tapi.service\t18081\tstateport-api-declared",
            "stateport-worker\tworker.service\t18082\tstateport-worker-declared",
        ]
    )
    with pytest.raises(SystemExit, match="unsafe or duplicate"):
        discover_services(
            FakeVM(
                "stateport-web\tweb.service\t18080\tstateport-web-one\n"
                "stateport-web\tweb-two.service\t18083\tstateport-web-two\n"
                + valid_tail
            )
        )
    with pytest.raises(SystemExit, match="unsafe or duplicate"):
        discover_services(
            FakeVM("stateport-web\tweb.service\t18080\t--latest\n" + valid_tail)
        )


def test_j2_retained_vm_boot_failure_attempts_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    work_dir = tmp_path / "vm"
    site_root = tmp_path / "site"
    archive_root = tmp_path / "archives"
    work_dir.mkdir()
    site_root.mkdir()
    archive_root.mkdir()
    (work_dir / "vm.qcow2").write_bytes(b"fixture")

    class FailingVM:
        instance: "FailingVM | None" = None

        def __init__(self, *_args: object, **_kwargs: object) -> None:
            self.torn_down = False
            FailingVM.instance = self

        def phase_gate(self, _name: str) -> None:
            pass

        def prepare(self, *, reuse: bool) -> None:
            assert reuse is True

        def boot(self) -> None:
            raise RuntimeError("boot failed")

        def teardown(self) -> None:
            self.torn_down = True

    monkeypatch.setattr(journey_common, "VM", FailingVM)
    with pytest.raises(RuntimeError, match="boot failed"):
        boot_retained_vm(work_dir, site_root=site_root, archive_root=archive_root)
    assert FailingVM.instance is not None and FailingVM.instance.torn_down is True


def _retained_candidate_fixture(tmp_path: Path) -> dict[str, Path]:
    candidate_dir = tmp_path / "candidate"
    vm_dir = tmp_path / "full-j1" / "vm"
    site_root = tmp_path / "site"
    archive_root = tmp_path / "archives"
    for directory in (
        candidate_dir,
        vm_dir,
        site_root / "download" / "0.1.0-test.1",
        archive_root,
    ):
        directory.mkdir(parents=True)

    bootstrap = b"#!/bin/sh\nexit 0\n"
    archive = b"exact OCI archive"
    bootstrap_digest = "sha256:" + hashlib.sha256(bootstrap).hexdigest()
    archive_digest = "sha256:" + hashlib.sha256(archive).hexdigest()
    manifest_digest = "sha256:" + "d" * 64
    release_index = {
        "signed": {
            "release": {
                "releaseId": "release-test-1",
                "version": "0.1.0-test.1",
                "channel": "qualification",
            },
            "targets": [{"targetId": "wsl2-test"}],
            "source": {"commit": "a" * 40, "tree": "b" * 40},
            "artifacts": {
                "installer": {
                    "digest": "sha256:" + hashlib.sha256(b"exact installer").hexdigest()
                }
            },
            "images": [{"imageId": "stateport-web", "digest": manifest_digest}],
        },
        "signatures": [{"subjectDigest": "sha256:" + "c" * 64}],
    }
    release_index_bytes = (json.dumps(release_index, sort_keys=True) + "\n").encode()
    release_index_digest = "sha256:" + hashlib.sha256(release_index_bytes).hexdigest()
    (candidate_dir / "release-index.json").write_bytes(release_index_bytes)
    (candidate_dir / "bootstrap.sh").write_bytes(bootstrap)
    (candidate_dir / "artifacts").mkdir()
    (candidate_dir / "artifacts" / "installer").write_bytes(b"exact installer")
    (site_root / "download" / "install.sh").write_bytes(bootstrap)
    (site_root / "download" / "0.1.0-test.1" / "bootstrap.sh").write_bytes(bootstrap)
    (site_root / "download" / "0.1.0-test.1" / "stateport-installer").write_bytes(
        b"exact installer"
    )
    (site_root / "download" / "0.1.0-test.1" / "release-index.json").write_bytes(
        release_index_bytes
    )
    (archive_root / "stateport-web.oci.tar").write_bytes(archive)
    (vm_dir / "vm.qcow2").write_bytes(b"retained VM")

    build_receipt = tmp_path / "build-receipt.json"
    build_receipt.write_text('{"result":"passed"}\n', encoding="utf-8")
    build_receipt_digest = "sha256:" + hashlib.sha256(build_receipt.read_bytes()).hexdigest()
    qualification = {
        "candidateSourceCommit": "a" * 40,
        "candidateSourceTree": "b" * 40,
        "releaseIndexSha256": release_index_digest,
        "signedPayloadDigest": "sha256:" + "c" * 64,
        "buildReceipt": str(build_receipt),
        "buildReceiptSha256": build_receipt_digest,
    }
    (candidate_dir / "qualification-receipt.json").write_text(
        json.dumps(qualification), encoding="utf-8"
    )
    phases = {
        name: {"ok": True}
        for name in (
            "bootstrap-fetch",
            "public-transport-boundary",
            "transport-probe",
            "materialization-preflight",
            "install",
            "post-bootstrap-runtime-smoke",
            "install-rerun",
            "guest-runtime-smoke",
        )
    }
    full_j1 = {
        "result": "passed",
        "version": "0.1.0-test.1",
        "evidenceClass": "owner_path_qualification",
        "rehearsalBaseline": {
            "substrate": "native-wsl2",
            "rootfsIdentity": journey_common.WSL_ROOTFS_IDENTITY,
        },
        "binding": {
            "releaseIndexDigest": release_index_digest,
            "signedPayloadDigest": "sha256:" + "c" * 64,
            "bootstrapDigest": bootstrap_digest,
            "archives": {
                "stateport-web": {
                    "manifestDigest": manifest_digest,
                    "archiveDigest": archive_digest,
                }
            },
        },
        "phases": phases,
    }
    (vm_dir.parent / "receipt.json").write_text(json.dumps(full_j1), encoding="utf-8")
    return {
        "candidate_dir": candidate_dir,
        "vm_dir": vm_dir,
        "site_root": site_root,
        "archive_root": archive_root,
    }


def test_retained_candidate_preflight_binds_site_bootstrap_and_archives(tmp_path: Path) -> None:
    paths = _retained_candidate_fixture(tmp_path)
    _mark_retained_simulation(paths)
    facts, evidence = validate_retained_candidate_inputs(**paths, retained_simulation=True)

    assert facts["releaseId"] == "release-test-1"
    assert evidence["siteRoot"] == str(paths["site_root"])
    assert evidence["archiveRoot"] == str(paths["archive_root"])
    assert evidence["archiveDigests"]["stateport-web"].startswith("sha256:")


def _mark_retained_native(paths):
    """Model actual public native receipt topology, without archive authority."""
    receipt = json.loads((paths["vm_dir"].parent / "receipt.json").read_text())
    distro = "StatePort-Rehearsal-native-fixture"
    receipt["rehearsalBaseline"].update({
        "evidenceClass": "owner_path_qualification", "distroName": distro,
        "machineId": "a" * 32, "windowsIdentity": "Microsoft Windows 11|10.0|26200",
    })
    receipt["binding"]["images"] = {"stateport-web": "sha256:" + "d" * 64}
    receipt["binding"].pop("archives", None)
    (paths["vm_dir"] / "receipt.json").write_text(json.dumps(receipt))
    return {**paths, "archive_root": None, "native_distro_name": distro}


def test_native_retained_preflight_needs_neither_qemu_disk_nor_archives(tmp_path):
    paths = _retained_candidate_fixture(tmp_path)
    native = _mark_retained_native(paths)
    (paths["vm_dir"] / "vm.qcow2").unlink()
    (paths["archive_root"] / "stateport-web.oci.tar").unlink()
    facts, evidence = validate_retained_candidate_inputs(**native)
    assert facts["releaseId"] == "release-test-1"
    assert evidence["archiveRoot"] is None and evidence["archiveDigests"] == {}
    assert evidence["nativeIdentity"]["machineId"] == "a" * 32
    assert evidence["fullJ1Receipt"] == str(paths["vm_dir"] / "receipt.json")


@pytest.mark.parametrize("field,value", [
    ("machineId", None), ("machineId", ""), ("machineId", "a" * 31),
    ("windowsIdentity", None), ("windowsIdentity", "  "),
    ("distroName", "StatePort-Rehearsal-different"),
])
def test_native_retained_preflight_refuses_incomplete_identity(tmp_path, field, value):
    paths = _retained_candidate_fixture(tmp_path)
    native = _mark_retained_native(paths)
    validate_retained_candidate_inputs(**native)
    receipt_path = paths["vm_dir"] / "receipt.json"
    receipt = json.loads(receipt_path.read_text())
    receipt["rehearsalBaseline"][field] = value
    receipt_path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="identity|distro|native"):
        validate_retained_candidate_inputs(**native)


def test_native_preflight_accepts_transported_build_receipt_and_preserves_qualification_bytes(tmp_path):
    paths = _retained_candidate_fixture(tmp_path)
    native = _mark_retained_native(paths)
    (paths["vm_dir"] / "vm.qcow2").unlink()
    qualification_path = paths["candidate_dir"] / "qualification-receipt.json"
    before = qualification_path.read_bytes()
    qualification = json.loads(before)
    copied = tmp_path / "windows-workspace" / "build-receipt.json"
    copied.parent.mkdir()
    original = Path(qualification["buildReceipt"])
    copied.write_bytes(original.read_bytes())
    original.unlink()
    _, evidence = validate_retained_candidate_inputs(
        **native, qualification_build_receipt=copied
    )
    assert evidence["buildReceiptSha256"] == journey_common._sha256_file(copied)
    assert qualification_path.read_bytes() == before


def test_native_preflight_rejects_changed_transported_build_receipt(tmp_path):
    paths = _retained_candidate_fixture(tmp_path)
    native = _mark_retained_native(paths)
    copied = tmp_path / "copied-build-receipt.json"
    copied.write_text("changed")
    with pytest.raises(ValueError, match="build receipt digest mismatch"):
        validate_retained_candidate_inputs(**native, qualification_build_receipt=copied)


def _mark_retained_simulation(paths: dict[str, Path]) -> dict:
    receipt_path = paths["vm_dir"].parent / "receipt.json"
    receipt = json.loads(receipt_path.read_text())
    receipt.update({
        "mode": "j1",
        "evidenceClass": "simulation_only",
        "rehearsalBaseline": {
            "evidenceClass": "simulation_only",
            "substrate": "qemu-wsl-identity-simulation",
            "rootfsIdentity": journey_common.QEMU_ROOTFS_IDENTITY,
            "identityShims": ["wsl_kernel_identity_only", "windows_interop_identity_only"],
            "extraBinaries": ["cloud-guest-utils", "docker-registry", "skopeo"],
        },
        "siteTransport": {"mode": "guest-local-staged-pages", "guestLocalServer": True},
        "guestRegistryTransport": {
            "mode": "digest-only-prepublication-mirror", "digestOnly": True,
            "guestLocalMirror": True, "retainedArchiveTransport": True,
        },
    })
    receipt["phases"].pop("public-transport-boundary")
    receipt["phases"].update({name: {"ok": True} for name in (
        "guest-swap", "install-services", "install-rerun-services"
    )})
    receipt["binding"]["images"] = {"stateport-web": "sha256:" + "d" * 64}
    receipt_path.write_text(json.dumps(receipt))
    return receipt


def test_retained_simulation_requires_opt_in_and_preserves_fidelity(tmp_path: Path) -> None:
    paths = _retained_candidate_fixture(tmp_path)
    receipt = _mark_retained_simulation(paths)
    with pytest.raises(ValueError, match="genuine native WSL2"):
        validate_retained_candidate_inputs(**paths)
    facts, evidence = validate_retained_candidate_inputs(**paths, retained_simulation=True)
    assert facts["releaseId"] == "release-test-1"
    assert evidence["evidenceClass"] == "simulation_only"
    assert evidence["lane"] == "retained-installed-simulation"
    assert evidence["admissibleForQualification"] is False
    assert evidence["freshInstallEvidence"] is False
    assert evidence["rehearsalBaseline"] == receipt["rehearsalBaseline"]
    assert evidence["siteTransport"] == receipt["siteTransport"]
    assert evidence["guestRegistryTransport"] == receipt["guestRegistryTransport"]


def _production_retained_fixture(tmp_path: Path) -> tuple[dict, Path]:
    paths = _retained_candidate_fixture(tmp_path)
    _mark_retained_simulation(paths)
    (paths["candidate_dir"] / "qualification-receipt.json").unlink()
    digest = "sha256:" + "d" * 64
    builds = [{"ordinal": ordinal, "pushedDigest": digest,
               "digestFileDigest": "sha256:" + str(ordinal) * 64,
               "localImageId": "sha256:" + str(ordinal + 2) * 64} for ordinal in (1, 2)]
    comparison = {
        "formatVersion": "stateport.release-double-build-comparison/v1",
        "images": {"stateport-web": {
            "formatVersion": "stateport.double-build-comparison/v1",
            "imageId": "stateport-web", "reproducible": True,
            **{name: {"digest": build["pushedDigest"],
                      "digestObservationDigest": build["digestFileDigest"],
                      "localImageId": build["localImageId"]}
               for name, build in zip(("first", "second"), builds)},
        }},
    }
    proof_path = paths["candidate_dir"] / "supply-chain" / "double-build-comparison.json"
    proof_path.parent.mkdir()
    proof_path.write_text(json.dumps(comparison))
    index_path = paths["candidate_dir"] / "release-index.json"
    index = json.loads(index_path.read_text())
    index["signed"]["supplyChain"] = {"doubleBuildComparison": {
        "uri": "operator://release/supply-chain/double-build-comparison.json",
        "digest": journey_common._sha256_file(proof_path), "size": proof_path.stat().st_size,
        "mediaType": "application/json",
    }}
    index_path.write_text(json.dumps(index))
    (paths["site_root"] / "download" / "0.1.0-test.1" / "release-index.json").write_bytes(index_path.read_bytes())
    receipt_path = paths["vm_dir"].parent / "receipt.json"
    receipt = json.loads(receipt_path.read_text())
    receipt["binding"]["releaseIndexDigest"] = journey_common._sha256_file(index_path)
    receipt_path.write_text(json.dumps(receipt))
    archive_path = paths["archive_root"] / "stateport-web.oci.tar"
    build_path = tmp_path / "production-build-receipt.json"
    build_path.write_text(json.dumps({
        "formatVersion": "stateport.release-image-build-receipt/v1",
        "identity": {"commit": "a" * 40, "tree": "b" * 40, "version": "0.1.0-test.1"},
        "images": {"stateport-web": {
            "acceptedReference": "registry.example/stateport-web@" + digest,
            "reproducible": True, "builds": builds,
            "releaseAuthority": {"kind": "retained-oci-archive", "manifestDigest": digest,
                "digest": journey_common._sha256_file(archive_path),
                "sizeBytes": archive_path.stat().st_size},
        }},
    }))
    return paths, build_path


def test_production_retained_simulation_uses_real_receipt_without_synthetic_qualification(tmp_path: Path) -> None:
    paths, build_path = _production_retained_fixture(tmp_path)
    facts, evidence = validate_retained_candidate_inputs(**paths, retained_simulation=True, build_receipt=build_path)
    assert facts["releaseId"] == "release-test-1"
    assert evidence["buildReceipt"] == str(build_path)
    assert evidence["buildReceiptSha256"] == journey_common._sha256_file(build_path)
    assert "candidateQualificationReceipt" not in evidence
    assert evidence["admissibleForQualification"] is False
    assert not (paths["candidate_dir"] / "qualification-receipt.json").exists()
    with pytest.raises(ValueError, match="only for retained simulation"):
        validate_retained_candidate_inputs(**paths, build_receipt=build_path)
    with pytest.raises(ValueError, match="candidate qualification receipt"):
        validate_retained_candidate_inputs(**paths)


@pytest.mark.parametrize("drift", (
    "format", "source", "tree", "version", "image-set", "accepted", "first", "second",
    "ordinal", "reproducible", "observation", "local-id", "archive-digest", "archive-size",
    "archive-manifest", "proof-bytes", "proof-missing", "index-binding", "staged-index",
))
def test_production_retained_simulation_refuses_build_and_proof_drift(tmp_path: Path, drift: str) -> None:
    paths, build_path = _production_retained_fixture(tmp_path)
    receipt = json.loads(build_path.read_text())
    image = receipt["images"]["stateport-web"]
    if drift == "format":
        receipt["formatVersion"] = "invented"
    elif drift in {"source", "tree", "version"}:
        receipt["identity"][{"source": "commit"}.get(drift, drift)] = "f" * 40
    elif drift == "image-set":
        receipt["images"]["unexpected"] = dict(image)
    elif drift == "accepted":
        image["acceptedReference"] = "registry.example/stateport-web@sha256:" + "f" * 64
    elif drift in {"first", "second"}:
        image["builds"][0 if drift == "first" else 1]["pushedDigest"] = "sha256:" + "f" * 64
    elif drift == "ordinal":
        image["builds"][1]["ordinal"] = 1
    elif drift == "reproducible":
        image["reproducible"] = False
    elif drift == "observation":
        image["builds"][0]["digestFileDigest"] = "sha256:" + "f" * 64
    elif drift == "local-id":
        image["builds"][1]["localImageId"] = "other"
    elif drift.startswith("archive-"):
        image["releaseAuthority"][{"archive-digest": "digest", "archive-size": "sizeBytes", "archive-manifest": "manifestDigest"}[drift]] = "drift"
    elif drift.startswith("proof-"):
        proof_path = paths["candidate_dir"] / "supply-chain" / "double-build-comparison.json"
        if drift == "proof-missing":
            proof_path.unlink()
        else:
            proof_path.write_text('{}')
    elif drift == "index-binding":
        receipt_path = paths["vm_dir"].parent / "receipt.json"
        full_j1 = json.loads(receipt_path.read_text())
        full_j1["binding"]["releaseIndexDigest"] = "sha256:" + "f" * 64
        receipt_path.write_text(json.dumps(full_j1))
    else:
        (paths["site_root"] / "download" / "0.1.0-test.1" / "release-index.json").write_text('{}')
    build_path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError):
        validate_retained_candidate_inputs(**paths, retained_simulation=True, build_receipt=build_path)


@pytest.mark.parametrize("drift", (
    "native-class", "baseline-class", "rootfs", "substrate", "hidden-shims",
    "diagnostic", "partial-mode", "public-site", "missing-mirror", "images",
    "missing-install", "failed-rerun", "missing-services", "failed-services",
    "missing-swap", "failed-extra-phase", "failed-result",
))
def test_retained_simulation_refuses_incomplete_or_misclassified_evidence(tmp_path: Path, drift: str) -> None:
    paths = _retained_candidate_fixture(tmp_path)
    receipt = _mark_retained_simulation(paths)
    if drift == "native-class":
        receipt["evidenceClass"] = "owner_path_qualification"
    elif drift == "baseline-class":
        receipt["rehearsalBaseline"]["evidenceClass"] = "owner_path_qualification"
    elif drift == "rootfs":
        receipt["rehearsalBaseline"]["rootfsIdentity"] = journey_common.WSL_ROOTFS_IDENTITY
    elif drift == "substrate":
        receipt["rehearsalBaseline"]["substrate"] = "native-wsl2"
    elif drift == "hidden-shims":
        receipt["rehearsalBaseline"]["identityShims"] = []
    elif drift == "diagnostic":
        receipt["diagnostic"] = {"admissibleForQualification": False}
    elif drift == "partial-mode":
        receipt["mode"] = "phase0-transport"
    elif drift == "public-site":
        receipt["siteTransport"]["mode"] = "anonymous-public-pages"
    elif drift == "missing-mirror":
        receipt["guestRegistryTransport"]["retainedArchiveTransport"] = False
    elif drift == "images":
        receipt["binding"]["images"] = {}
    elif drift == "missing-install":
        receipt["phases"].pop("install")
    elif drift == "failed-rerun":
        receipt["phases"]["install-rerun"]["ok"] = False
    elif drift == "missing-services":
        receipt["phases"].pop("install-services")
    elif drift == "failed-services":
        receipt["phases"]["install-rerun-services"]["ok"] = False
    elif drift == "missing-swap":
        receipt["phases"].pop("guest-swap")
    elif drift == "failed-extra-phase":
        receipt["phases"]["unexpected"] = {"ok": False}
    else:
        receipt["result"] = "failed"
    (paths["vm_dir"].parent / "receipt.json").write_text(json.dumps(receipt))
    with pytest.raises(ValueError):
        validate_retained_candidate_inputs(**paths, retained_simulation=True)


@pytest.mark.parametrize(
    "drift",
    (
        "bootstrap",
        "installer",
        "release-index",
        "archive",
        "extra-archive",
        "qualification-identity",
        "full-j1-identity",
        "build-receipt",
    ),
)
@pytest.mark.parametrize("retained_simulation", (False, True))
def test_retained_candidate_preflight_refuses_artifact_drift(
    tmp_path: Path, drift: str, retained_simulation: bool
) -> None:
    paths = _retained_candidate_fixture(tmp_path)
    if retained_simulation:
        _mark_retained_simulation(paths)
        inputs = {**paths, "retained_simulation": True}
    else:
        if drift in {"archive", "extra-archive"}:
            pytest.skip("native public qualification has no staged archive dependency")
        inputs = _mark_retained_native(paths)
    # Prove that the chosen lane is valid before testing the named mutation.
    validate_retained_candidate_inputs(**inputs)
    version_root = paths["site_root"] / "download" / "0.1.0-test.1"
    if drift == "bootstrap":
        (paths["site_root"] / "download" / "install.sh").write_bytes(b"drift")
    elif drift == "installer":
        (version_root / "stateport-installer").write_bytes(b"drift")
    elif drift == "release-index":
        (version_root / "release-index.json").write_bytes(b"{}")
    elif drift == "archive":
        (paths["archive_root"] / "stateport-web.oci.tar").write_bytes(b"drift")
    elif drift == "extra-archive":
        (paths["archive_root"] / "unexpected.oci.tar").write_bytes(b"drift")
    elif drift == "qualification-identity":
        qualification_path = paths["candidate_dir"] / "qualification-receipt.json"
        qualification = json.loads(qualification_path.read_text(encoding="utf-8"))
        qualification["candidateSourceCommit"] = "f" * 40
        qualification_path.write_text(json.dumps(qualification), encoding="utf-8")
    elif drift == "full-j1-identity":
        receipt_path = (paths["vm_dir"].parent if retained_simulation else paths["vm_dir"]) / "receipt.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["binding"]["releaseIndexDigest"] = "sha256:" + "f" * 64
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    else:
        qualification = json.loads(
            (paths["candidate_dir"] / "qualification-receipt.json").read_text(
                encoding="utf-8"
            )
        )
        Path(qualification["buildReceipt"]).write_bytes(b"drift")

    with pytest.raises(ValueError):
        validate_retained_candidate_inputs(**inputs)


def test_retained_candidate_preflight_refuses_symlinked_root(tmp_path: Path) -> None:
    paths = _retained_candidate_fixture(tmp_path)
    alias = tmp_path / "candidate-alias"
    alias.symlink_to(paths["candidate_dir"], target_is_directory=True)
    paths["candidate_dir"] = alias

    with pytest.raises(ValueError, match="exact non-symlink directory"):
        validate_retained_candidate_inputs(**paths)


def test_j4_artifact_drift_records_failure_before_vm_boot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _retained_candidate_fixture(tmp_path)
    (paths["site_root"] / "download" / "install.sh").write_bytes(b"drift")
    receipt_out = tmp_path / "j4-receipt.json"
    booted = False

    def unexpected_boot(*_args: object, **_kwargs: object) -> None:
        nonlocal booted
        booted = True
        raise AssertionError("VM boot must not run after failed artifact preflight")

    monkeypatch.setattr(run_journey_j4, "boot_retained_vm", unexpected_boot)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_journey_j4.py",
            "--receipt-out",
            str(receipt_out),
            "--vm-dir",
            str(paths["vm_dir"]),
            "--candidate-dir",
            str(paths["candidate_dir"]),
            "--site-root",
            str(paths["site_root"]),
            "--archive-root",
            str(paths["archive_root"]),
        ],
    )

    assert run_journey_j4.main() == 1
    assert booted is False
    receipt = json.loads(receipt_out.read_text(encoding="utf-8"))
    assert receipt["result"] == "failed"
    assert len(receipt["steps"]) == 1
    assert receipt["steps"][0]["name"] == "input-preflight"
    assert receipt["steps"][0]["ok"] is False


def test_j4_uses_candidate_installer_for_lifecycle_and_bootstrap_for_reinstall() -> None:
    class CapturingVM:
        def __init__(self) -> None:
            self.commands: list[tuple[str, dict[str, object]]] = []

        def ssh(self, command: str, **kwargs: object) -> SimpleNamespace:
            self.commands.append((command, kwargs))
            return SimpleNamespace(returncode=0, stdout="", stderr="")

    vm = CapturingVM()
    run_journey_j4.run_installer(vm, "--uninstall", 1800)
    run_journey_j4.run_bootstrap(vm, 3600)

    uninstall, uninstall_options = vm.commands[0]
    reinstall, reinstall_options = vm.commands[1]
    assert "python3 /tmp/stateport-installer --uninstall" in uninstall
    assert '--state-root "$HOME/.local/state/stateport-install"' in uninstall
    assert "/tmp/stateport-bootstrap" not in uninstall
    assert uninstall_options["timeout"] == 1800
    assert reinstall.endswith("sh /tmp/stateport-bootstrap")
    assert reinstall_options["stdin_text"] == "install\n"
    assert reinstall_options["tty"] is True


def test_j2_gui_inspection_script_requires_all_release_contract_surfaces() -> None:
    script = _gui_inspection_script(
        "http://127.0.0.1:18080",
        "j2journey-demo",
        "run_proposal:run-j2-approval",
        "sha256:" + "a" * 64,
        "governed-run.run-j2-mutation.123456789abc",
    )
    assert "http://127.0.0.1:18080" in script
    assert "j2journey-demo" in script
    assert "run-j2-approval" in script
    assert "sha256:" + "a" * 64 in script
    assert "governed-run.run-j2-mutation.123456789abc" in script
    for selector in (
        'data-testid="recent-activity-section"',
        'data-testid="approval-detail"',
        'data-testid="application-receipts-page"',
        'data-testid="app-settings-context-lifecycle"',
    ):
        assert selector in script
    assert "Current estimated use" in script
    assert "Maximum input budget" in script
    assert "data-receipt-id" in script
    assert '[data-testid="approval-plan-digest"]' in script
    assert "renderedApprovalDigest" in script
    assert "fetch('/v1/approvals')" not in script
    assert "failed API responses" in script


def test_j2_guided_study_script_uses_shipped_install_and_mutation_surfaces() -> None:
    script = _guided_study_script(
        "http://127.0.0.1:18080",
        "Release Journey StudyState",
        "A durable browser-authored reflection.",
    )

    assert "http://127.0.0.1:18080" in script
    assert "Release Journey StudyState" in script
    assert "A durable browser-authored reflection." in script
    for selector in (
        '[data-testid="catalog-stub"]',
        '[data-testid="install-review"]',
        '[data-testid="instance-name-input"]',
        '[data-testid="confirm-install"]',
        '[data-testid="install-success"]',
        '[data-testid="open-instance"]',
        '[data-testid="study-native-journey"]',
        '[data-testid="study-open-reflection"]',
        '[data-testid="study-review-change"]',
        '[data-testid="study-change-preview"]',
        '[data-testid="study-review-reflection"]',
        '[data-testid="study-approve-apply"]',
        '[data-testid="study-applied"]',
    ):
        assert selector in script
    assert "POST' && url.pathname === '/v1/application-fixtures/install'" in script
    assert "POST' && /^\\/v1\\/runs\\/[^/]+\\/apply$/.test(url.pathname)" in script
    assert script.count("function contractDigest(value)") == 1
    assert script.index("function contractDigest(value)") < script.index("async function main()")
    assert "appliedRun.proposalDigest !== contractDigest(proposal)" in script
    assert "applicationReceipt.preStateDigest !== proposal.preStateDigest" in script
    assert "applicationReceipt.postStateDigest !== appliedRun.canonicalStateAfter" in script
    assert "closureReceipt.applicationReceiptDigest !== contractDigest(applicationReceipt)" in script
    assert "closureReceipt.canonicalStateBefore !== appliedRun.canonicalStateBefore" in script
    assert "proposal.preStateDigest !== appliedRun.canonicalStateBefore" not in script
    assert "failed API responses" in script


def test_j2_guided_mutation_binding_requires_exact_durable_reflection() -> None:
    reflection = "A durable browser-authored reflection."
    before_plan_digest = "sha256:" + "a" * 64
    after_plan_digest = "sha256:" + "b" * 64
    canonical_state_before = "sha256:" + "c" * 64
    application_state_before = "sha256:" + "d" * 64
    canonical_state_after = "sha256:" + "e" * 64
    proposal = {
        "proposalId": "proposal-guided",
        "applicationAction": RECORD_ACTION,
        "preStateDigest": application_state_before,
        "operation": {
            "type": "record_evidence",
            "activityId": "practice",
            "summary": reflection,
            "reflection": reflection,
            "evidenceId": "evidence-guided",
            "beforePlanDigest": before_plan_digest,
            "afterPlanDigest": after_plan_digest,
        },
    }
    proposal_digest = _contract_digest(proposal)
    applied = {
        "runId": "run-guided",
        "actionId": RECORD_ACTION,
        "proposalDigest": proposal_digest,
        "canonicalStateBefore": canonical_state_before,
        "canonicalStateAfter": canonical_state_after,
        "proposal": proposal,
        "receipt": {
            "proposalId": "proposal-guided",
            "preStateDigest": application_state_before,
            "postStateDigest": canonical_state_after,
            "postStateDigestAuthority": "stateport_full_regular_tree_snapshot",
        },
        "closureReceipt": {
            "proposalId": "proposal-guided",
            "proposalDigest": proposal_digest,
            "applicationReceiptDigest": _contract_digest({
                "proposalId": "proposal-guided",
                "preStateDigest": application_state_before,
                "postStateDigest": canonical_state_after,
                "postStateDigestAuthority": "stateport_full_regular_tree_snapshot",
            }),
            "canonicalStateBefore": canonical_state_before,
            "canonicalStateAfter": canonical_state_after,
        },
    }
    baseline = {"packageState": {"planDigest": before_plan_digest}}
    after = {
        "packageState": {
            "planDigest": after_plan_digest,
            "activities": [{"id": "practice", "state": "done"}],
            "evidence": [
                {
                    "id": "evidence-guided",
                    "title": reflection,
                    "state": "self_reported",
                }
            ],
            "lastTransition": {
                "kind": "evidence_applied",
                "proposalId": "proposal-guided",
                "activityId": "practice",
                "evidenceId": "evidence-guided",
                "beforePlanDigest": before_plan_digest,
                "afterPlanDigest": after_plan_digest,
            },
        }
    }

    binding = _guided_mutation_binding(applied, baseline, after, reflection)
    assert binding["proposalDigest"] == proposal_digest
    assert binding["evidenceId"] == "evidence-guided"
    assert binding["beforePlanDigest"] == before_plan_digest

    changed = json.loads(json.dumps(after))
    changed["packageState"]["evidence"][0]["title"] = "A different mutation"
    with pytest.raises(AssertionError, match="exact reviewed reflection"):
        _guided_mutation_binding(applied, baseline, changed, reflection)

    changed = json.loads(json.dumps(after))
    changed["packageState"]["lastTransition"]["afterPlanDigest"] = before_plan_digest
    with pytest.raises(AssertionError, match="transition digests"):
        _guided_mutation_binding(applied, baseline, changed, reflection)

    changed_applied = json.loads(json.dumps(applied))
    changed_applied["proposal"]["operation"]["beforePlanDigest"] = after_plan_digest
    changed_applied["proposalDigest"] = _contract_digest(changed_applied["proposal"])
    with pytest.raises(AssertionError, match="before and after state"):
        _guided_mutation_binding(changed_applied, baseline, after, reflection)

    changed_applied = json.loads(json.dumps(applied))
    changed_applied["proposalDigest"] = "sha256:" + "f" * 64
    with pytest.raises(AssertionError, match="before and after state"):
        _guided_mutation_binding(changed_applied, baseline, after, reflection)

    changed_applied = json.loads(json.dumps(applied))
    changed_applied["proposal"]["preStateDigest"] = "sha256:" + "f" * 64
    changed_applied["proposalDigest"] = _contract_digest(changed_applied["proposal"])
    with pytest.raises(AssertionError, match="before and after state"):
        _guided_mutation_binding(changed_applied, baseline, after, reflection)

    changed_applied = json.loads(json.dumps(applied))
    changed_applied["canonicalStateBefore"] = "sha256:" + "f" * 64
    with pytest.raises(AssertionError, match="before and after state"):
        _guided_mutation_binding(changed_applied, baseline, after, reflection)

    changed_applied = json.loads(json.dumps(applied))
    changed_applied["closureReceipt"]["applicationReceiptDigest"] = "sha256:" + "f" * 64
    with pytest.raises(AssertionError, match="before and after state"):
        _guided_mutation_binding(changed_applied, baseline, after, reflection)


def test_j2_evidence_copy_uses_bounded_nofollow_reader(tmp_path: Path) -> None:
    captured: dict[str, str] = {}

    class FakeVM:
        def ssh(self, command: str, **kwargs: object) -> SimpleNamespace:
            captured["command"] = command
            captured["stdin"] = str(kwargs.get("stdin_text"))
            return SimpleNamespace(
                returncode=0,
                stderr="",
                stdout="c2NyZWVuc2hvdA==",
            )

    destination = tmp_path / "screenshot.jpg"
    _copy_guest_evidence(FakeVM(), "/safe/evidence/screenshot.jpg", destination)

    assert destination.read_bytes() == b"screenshot"
    assert "O_NOFOLLOW" in captured["stdin"]
    assert "st_nlink != 1" in captured["stdin"]
    assert "stateport-control" in captured["stdin"]
    assert str(16 * 1024 * 1024) in captured["command"]


def test_j2_semantic_snapshot_ignores_timestamps_but_full_state_does_not() -> None:
    state = {
        "kind": "study-state",
        "goal": "Learn",
        "goalProgressPercent": 0,
        "planDigest": "sha256:" + "1" * 64,
        "activities": [
            {
                "id": "practice",
                "title": "Practice",
                "reason": "Learn",
                "state": "not_started",
                "updatedAt": "2026-01-01T00:00:00Z",
            }
        ],
        "evidence": [],
        "lastTransition": {"updatedAt": "2026-01-01T00:00:00Z"},
    }
    later = json.loads(json.dumps(state))
    later["activities"][0]["updatedAt"] = "2026-02-01T00:00:00Z"
    later["lastTransition"]["updatedAt"] = "2026-02-01T00:00:00Z"
    assert state != later
    assert _study_state_snapshot(state) == _study_state_snapshot(later)

    later["evidence"].append({"id": "e1", "title": "Proof", "state": "self_reported"})
    assert _object_digest(_study_state_snapshot(state)) != _object_digest(
        _study_state_snapshot(later)
    )


def test_j2_undo_binding_requires_the_complete_canonical_receipt_chain() -> None:
    current_plan = "sha256:" + "1" * 64
    restored_plan = "sha256:" + "2" * 64
    canonical_before = "sha256:" + "3" * 64
    canonical_after = "sha256:" + "4" * 64
    instance_id = "study-instance"
    review_run_id = "run-reviewed-undo"
    applied_run_id = "run-applied-undo"
    mutation_run_id = "run-applied-mutation"
    mutation_canonical_before = "sha256:" + "b" * 64
    mutation_canonical_after = "sha256:" + "c" * 64
    mutation_proposal = {
        "proposalId": "proposal-mutation",
        "applicationAction": RECORD_ACTION,
        "operation": {"afterPlanDigest": current_plan},
    }
    proposal = {
        "proposalId": "proposal-undo",
        "applicationAction": UNDO_ACTION,
        "preStateDigest": "sha256:" + "5" * 64,
        "operation": {
            "type": "undo_last_evidence",
            "appliedProposalId": mutation_proposal["proposalId"],
            "expectedCurrentPlanDigest": current_plan,
            "restoredPlanDigest": restored_plan,
        },
    }
    application_receipt = {
        "formatVersion": "stateport.application-apply-receipt/v1",
        "proposalId": proposal["proposalId"],
        "preStateDigest": proposal["preStateDigest"],
        "postStateDigest": canonical_after,
        "postStateDigestAuthority": "stateport_full_regular_tree_snapshot",
        "baseGit": "a" * 40,
        "finalGit": "a" * 40,
        "applicationReceipt": {
            "formatVersion": "studystate.sample.state-change-receipt/v1",
            "postStateDigest": "sha256:" + "6" * 64,
            "digest": "sha256:" + "7" * 64,
        },
        "validation": "passed",
    }
    applied = {
        "runId": applied_run_id,
        "instanceId": instance_id,
        "applicationId": "studystate.sample",
        "actionId": UNDO_ACTION,
        "status": "applied",
        "lifecycleState": "CLOSED",
        "proposal": proposal,
        "proposalDigest": _contract_digest(proposal),
        "canonicalStateBefore": canonical_before,
        "canonicalStateAfter": canonical_after,
        "receipt": application_receipt,
        "closureReceipt": {
            "receiptId": "governed-run.run-applied-undo.123456789abc",
            "runId": applied_run_id,
            "instanceId": instance_id,
            "applicationId": "studystate.sample",
            "actionId": UNDO_ACTION,
            "proposalId": proposal["proposalId"],
            "proposalDigest": _contract_digest(proposal),
            "applicationReceiptDigest": _contract_digest(application_receipt),
            "canonicalStateBefore": canonical_before,
            "canonicalStateAfter": canonical_after,
        },
    }
    reviewed = {
        "runId": review_run_id,
        "instanceId": instance_id,
        "applicationId": "studystate.sample",
        "actionId": UNDO_ACTION,
        "status": "state_change_rejected",
        "lifecycleState": "CLOSED",
        "proposal": proposal,
        "proposalDigest": _contract_digest(proposal),
        "canonicalStateBefore": canonical_before,
        "canonicalStateAfter": canonical_before,
        "result": {
            "canonicalStateUnchanged": True,
            "canonicalStateDigest": proposal["preStateDigest"],
        },
        "rejection": {"operatorId": "local-operator"},
    }
    mutation_receipt = {
        "proposalId": mutation_proposal["proposalId"],
        "postStateDigest": mutation_canonical_after,
        "applicationReceipt": {
            "postStateDigest": proposal["preStateDigest"],
        }
    }
    mutation = {
        "runId": mutation_run_id,
        "instanceId": instance_id,
        "applicationId": "studystate.sample",
        "actionId": RECORD_ACTION,
        "status": "applied",
        "lifecycleState": "CLOSED",
        "proposal": mutation_proposal,
        "proposalDigest": _contract_digest(mutation_proposal),
        "canonicalStateBefore": mutation_canonical_before,
        "canonicalStateAfter": mutation_canonical_after,
        "receipt": mutation_receipt,
        "closureReceipt": {
            "receiptId": "governed-run.run-applied-mutation.123456789abc",
            "runId": mutation_run_id,
            "instanceId": instance_id,
            "applicationId": "studystate.sample",
            "actionId": RECORD_ACTION,
            "proposalId": mutation_proposal["proposalId"],
            "proposalDigest": _contract_digest(mutation_proposal),
            "applicationReceiptDigest": _contract_digest(mutation_receipt),
            "canonicalStateBefore": mutation_canonical_before,
            "canonicalStateAfter": mutation_canonical_after,
        },
    }
    semantic_state = {"planDigest": restored_plan, "evidence": []}

    def validate(
        applied_candidate: object = applied,
        reviewed_candidate: object = reviewed,
        mutation_candidate: object = mutation,
    ) -> dict[str, str]:
        return _undo_restoration_binding(
            applied_candidate,
            reviewed_run=reviewed_candidate,
            mutation_run=mutation_candidate,
            expected_review_run_id=review_run_id,
            expected_applied_run_id=applied_run_id,
            expected_instance_id=instance_id,
            expected_current_plan_digest=current_plan,
            expected_restored_plan_digest=restored_plan,
            expected_semantic_state=semantic_state,
            actual_semantic_state=dict(semantic_state),
        )

    binding = validate()
    assert binding["canonicalStateBefore"] == canonical_before
    assert binding["canonicalStateAfter"] == canonical_after
    assert binding["reviewRunId"] == reviewed["runId"]
    assert binding["mutationCanonicalStateAfter"] == mutation_canonical_after
    assert mutation_canonical_after != canonical_before

    mismatched_review = json.loads(json.dumps(reviewed))
    mismatched_review["canonicalStateAfter"] = "sha256:" + "8" * 64
    with pytest.raises(AssertionError, match="closed GUI review"):
        validate(reviewed_candidate=mismatched_review)

    mismatched_review = json.loads(json.dumps(reviewed))
    mismatched_review["runId"] = "run-other-review"
    with pytest.raises(AssertionError, match="closed GUI review"):
        validate(reviewed_candidate=mismatched_review)

    mismatched_mutation = json.loads(json.dumps(mutation))
    mismatched_mutation["proposal"]["proposalId"] = "proposal-other-mutation"
    with pytest.raises(AssertionError, match="original reviewed mutation"):
        validate(mutation_candidate=mismatched_mutation)

    tampered = json.loads(json.dumps(applied))
    tampered["receipt"]["postStateDigest"] = "sha256:" + "9" * 64
    with pytest.raises(AssertionError, match="canonical state transition"):
        validate(applied_candidate=tampered)

    tampered = json.loads(json.dumps(applied))
    tampered["closureReceipt"]["applicationReceiptDigest"] = "sha256:" + "a" * 64
    with pytest.raises(AssertionError, match="canonical state transition"):
        validate(applied_candidate=tampered)

    tampered = json.loads(json.dumps(applied))
    tampered["closureReceipt"]["runId"] = "run-other-undo"
    with pytest.raises(AssertionError, match="canonical state transition"):
        validate(applied_candidate=tampered)


def test_j2_governed_chain_threads_each_returned_revision() -> None:
    proposal_digest = "sha256:" + "a" * 64

    class FakeClient:
        def __init__(self) -> None:
            self.calls: list[tuple[str, dict]] = []

        def request(self, method: str, path: str, body: dict, *, csrf: bool = False) -> dict:
            assert method == "POST"
            assert csrf is True
            self.calls.append((path, body))
            responses = {
                "/v1/instances/demo/execution/prepare": {
                    "run": {"runId": "run-demo", "revision": 3}
                },
                "/v1/runs/run-demo/approve": {"revision": 4},
                "/v1/runs/run-demo/execute": {
                    "run": {"revision": 5, "proposalDigest": proposal_digest}
                },
                "/v1/runs/run-demo/proposal-approve": {
                    "revision": 6,
                    "proposalDigest": proposal_digest,
                },
                "/v1/runs/run-demo/apply": {
                    "run": {
                        "runId": "run-demo",
                        "status": "applied",
                        "lifecycleState": "CLOSED",
                        "closureReceipt": {"receiptId": "governed-run.run-demo.123456789abc"},
                    }
                },
            }
            return responses[path]

    client = FakeClient()
    result = governed_chain(client, "demo", RECORD_ACTION, {"activityId": "practice"})

    assert result["proposalDigest"] == proposal_digest
    assert [call[1].get("expectedRevision") for call in client.calls] == [None, 3, 4, 5, 6]


def test_j2_required_steps_fail_closed_on_missing_failed_or_duplicate() -> None:
    steps = [{"name": name, "ok": True} for name in J2_REQUIRED_STEPS]
    assert _required_step_failures({"steps": steps}) == []

    failed = [dict(step) for step in steps]
    next(step for step in failed if step["name"] == "fixture-install-browser-consent")["ok"] = False
    assert _required_step_failures({"steps": failed}) == [
        "fixture-install-browser-consent:failed"
    ]

    missing = [step for step in steps if step["name"] != "gui-inspection-evidence"]
    assert _required_step_failures({"steps": missing}) == [
        "gui-inspection-evidence:missing"
    ]

    duplicate = [*steps, {"name": "portable-export-verified", "ok": True}]
    assert _required_step_failures({"steps": duplicate}) == [
        "portable-export-verified:duplicate"
    ]


def test_j2_retained_baseline_reports_existing_study_instances() -> None:
    assert _existing_study_instances(
        {
            "instances": [
                {
                    "applicationId": "other.sample",
                    "instanceId": "other-1",
                    "name": "Other",
                }
            ]
        }
    ) == []
    assert _existing_study_instances(
        {
            "instances": [
                {
                    "applicationId": "studystate.sample",
                    "instanceId": "study-1",
                    "name": "Prior StudyState journey",
                }
            ]
        }
    ) == [
        {"instanceId": "study-1", "name": "Prior StudyState journey"}
    ]

    with pytest.raises(AssertionError, match="identity is malformed"):
        _existing_study_instances(
            {
                "instances": [
                    {
                        "applicationId": "studystate.sample",
                        "instanceId": "",
                        "name": "Missing identity",
                    }
                ]
            }
        )

    with pytest.raises(AssertionError, match="application identity is malformed"):
        _existing_study_instances(
            {
                "instances": [
                    {
                        "instanceId": "unknown-application",
                        "name": "Unknown application",
                    }
                ]
            }
        )

    with pytest.raises(AssertionError, match="application identity is malformed"):
        _existing_study_instances(
            {
                "instances": [
                    {
                        "applicationId": "studystate.sample ",
                        "instanceId": "study-with-unsafe-app-id",
                        "name": "Unsafe application identity",
                    }
                ]
            }
        )


def _revision(revision: str) -> Path:
    return FIXTURE_APP / "revisions" / revision


def _write_instance_yaml(destination: Path, template_id: str) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "instance.yaml").write_text(
        "\n".join(
            [
                "formatVersion: stateport.application-instance/v1",
                "metadata:",
                "  id: surface-demo",
                "  name: Surface demo",
                "spec:",
                "  applicationId: studystate.sample",
                "  mode: fixture",
                "  grantedCapabilities:",
                "    - write_state",
                "  templateRef:",
                f"    id: {template_id}",
                "",
            ]
        ),
        encoding="utf-8",
    )


def test_fixture_revisions_are_two_distinct_materializable_revisions() -> None:
    first = load_template_manifest(_revision("v0001"))
    second = load_template_manifest(_revision("v0002"))
    assert first["templateId"] == second["templateId"] == "stateport.fixture.studystate-sample"
    assert first["templateVersion"] == "0.1.0"
    assert second["templateVersion"] == "0.2.0"
    assert first["sourceClass"] == second["sourceClass"] == "synthetic_fixture"
    assert first["productionEligible"] is False and second["productionEligible"] is False
    assert _source_revision(_revision("v0001"), first) != _source_revision(_revision("v0002"), second)


def test_descriptor_declares_the_install_revision_and_catalog() -> None:
    import yaml

    descriptor = yaml.safe_load((FIXTURE_APP / "application.yaml").read_text(encoding="utf-8"))
    lifecycle = descriptor["lifecycleTemplate"]
    assert lifecycle["templateId"] == "stateport.fixture.studystate-sample"
    assert lifecycle["installRevision"] == "v0001"
    assert set(lifecycle["revisions"]) == set(REVISIONS)
    for relative in lifecycle["revisions"].values():
        assert (_revision_path := FIXTURE_APP / relative / ".statedd" / "manifest.yaml").is_file()


def test_catalog_eligibility_advertises_the_revision_digest_installs_validate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    service = PortableExecutionService(app, ROOT)
    eligibility = service.browser_fixture_install_eligibility("studystate.sample")
    assert eligibility["eligible"] is True
    descriptor, _identity, _profile, _source_root, base_digest = service._browser_fixture_contract(
        "studystate.sample"
    )
    *_, revision_digest = service._fixture_revision_contract(
        "studystate.sample", _source_root, descriptor["lifecycleTemplate"]
    )
    assert revision_digest != base_digest
    assert eligibility["packageDigest"] == revision_digest
    installed = service.install_fixture_instance(
        "studystate.sample",
        "browser-consent-demo",
        expected_descriptor_digest=service.application_identity("studystate.sample")[
            "descriptorDigest"
        ],
        expected_package_digest=eligibility["packageDigest"],
        experience_descriptor_digest=_experience_digest(service),
        consent="explicit_browser_confirmation",
        actor_id="journey-operator",
    )
    assert installed["ok"] is True
    legacy = service.browser_fixture_install_eligibility("checklistdd")
    assert legacy["eligible"] is True and legacy["networkPolicy"] == "disabled"


def _experience_digest(service: PortableExecutionService) -> str:
    from stateport_application_experience import ExperienceRegistry, load_experience_policy

    registry = ExperienceRegistry(ROOT)
    descriptor = registry.get("studystate.sample")
    assert descriptor is not None
    return str(descriptor.descriptor_digest())


def test_service_install_materializes_a_valid_lifecycle_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    service = PortableExecutionService(app, ROOT)
    installed = service.install_fixture_instance("studystate.sample", "locked-demo")
    assert installed["ok"] is True
    provenance = installed["lifecycle"]
    assert provenance is not None
    assert provenance["formatVersion"] == "statedd.lock/v1"
    assert provenance["templateId"] == "stateport.fixture.studystate-sample"
    assert provenance["releaseVersion"] == "0.1.0"
    assert provenance["revisionId"] == "v0001"
    instance_root = app.layout.instances_root / "locked-demo"
    lock = _read_lock(instance_root / ".statedd" / "lock.yaml")
    _validate_lock(lock)
    assert lock["template"]["version"] == "0.1.0"
    assert lock["instanceId"] == "locked-demo"
    durable = app.application_install_receipt("locked-demo")
    assert durable["lifecycle"]["sourceRevision"] == provenance["sourceRevision"]
    legacy = service.install_fixture_instance("checklistdd", "legacy-copy-demo")
    assert legacy["ok"] is True and legacy["lifecycle"] is None
    assert {item["actionId"] for item in service.action_list("legacy-copy-demo")} == {
        "checklistdd.plan-next-item/v1",
        "checklistdd.complete-item/v1",
    }


def test_mutable_lock_hashes_cannot_authorize_modified_fixture_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    service = PortableExecutionService(app, ROOT)
    service.install_fixture_instance("studystate.sample", "tampered-source")
    instance = app.layout.instances_root / "tampered-source"
    script = instance / "scripts" / "study_actions.py"
    script.write_text(script.read_text(encoding="utf-8") + "\n# altered outside governance\n", encoding="utf-8")
    changed_digest = "sha256:" + hashlib.sha256(script.read_bytes()).hexdigest()
    lock_path = instance / ".statedd" / "lock.yaml"
    lock = _read_lock(lock_path)
    script_entry = next(item for item in lock["files"] if item["path"] == "scripts/study_actions.py")
    script_entry["sourceHash"] = changed_digest
    script_entry["materializedHash"] = changed_digest
    _write_yaml(lock_path, lock)

    with pytest.raises(PortableExecutionError, match="template-file identity changed"):
        service.action_list("tampered-source")
    exported = service.export_instance("tampered-source")
    destination = app.layout.instances_root / "tampered-copy"
    with pytest.raises(PortableExecutionError, match="template-file identity changed"):
        service.import_instance_archive(
            exported["archive"],
            destination,
            new_instance_id="tampered-copy",
            expected_archive_digest=exported["archiveDigest"],
            expected_archive_file_digest=exported["archiveFileDigest"],
        )
    assert not destination.exists()


def test_portable_export_refuses_an_active_instance_writer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    service = PortableExecutionService(app, ROOT)
    service.install_fixture_instance("studystate.sample", "export-lease")
    instance = app.layout.instances_root / "export-lease"

    with InstanceLease(
        app.layout.operations_root / "leases",
        instance,
        owner="test-active-writer",
    ):
        with pytest.raises(PortableExecutionError, match="active writer lease"):
            service.export_instance("export-lease")


def test_installed_instance_upgrades_to_the_second_revision_in_place(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    service = PortableExecutionService(app, ROOT)
    service.install_fixture_instance("studystate.sample", "upgrade-demo")
    instance_root = app.layout.instances_root / "upgrade-demo"
    learning_before = (instance_root / "state" / "LEARNING.yaml").read_bytes()

    plan = plan_upgrade(instance_root, _revision("v0002"))
    assert plan["safe"] is True and plan["blocked"] is False
    classifications = {entry["path"]: entry["classification"] for entry in plan["entries"]}
    assert classifications["actions.yaml"] == "changed"
    assert classifications["AGENTS.md"] == "changed"
    assert classifications["scripts/study_actions.py"] == "changed"

    approval = approve_upgrade_plan(plan, approved_by="journey-operator", reason="fixture upgrade journey")
    receipt = apply_upgrade(
        instance_root,
        _revision("v0002"),
        plan=plan,
        approval=approval,
        allow_fixture=True,
    )
    assert receipt["status"] == "applied"
    assert "study-tip" in (instance_root / "actions.yaml").read_text(encoding="utf-8")
    assert (instance_root / "state" / "LEARNING.yaml").read_bytes() == learning_before
    assert (instance_root / ".git").is_dir()

    replay = apply_upgrade(
        instance_root,
        _revision("v0002"),
        plan=plan,
        approval=approval,
        allow_fixture=True,
    )
    assert replay["idempotent"] is True

    rerun = plan_upgrade(instance_root, _revision("v0002"))
    assert rerun["safe"] is False
    assert any("higher numeric version" in reason for reason in rerun["reasons"])

    lock = _read_lock(instance_root / ".statedd" / "lock.yaml")
    _validate_lock(lock)
    assert lock["template"]["version"] == "0.2.0"


def test_legacy_durable_tree_lock_keeps_revision_identity_and_upgrades_safely(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    service = PortableExecutionService(app, ROOT)
    service.install_fixture_instance("studystate.sample", "legacy-lock")
    instance = app.layout.instances_root / "legacy-lock"
    lock_path = instance / ".statedd" / "lock.yaml"
    lock = _read_lock(lock_path)
    source_revision = lock["template"]["sourceRevision"]
    next(item for item in lock["files"] if item["path"] == "state/LEARNING.yaml")[
        "owner"
    ] = "template"
    next(item for item in lock["trees"] if item["path"] == "state")["owner"] = "template"
    _write_yaml(lock_path, lock)
    state_path = instance / "state" / "LEARNING.yaml"
    personal = state_path.read_text(encoding="utf-8").replace(
        "status: planned", "status: paused", 1
    )
    state_path.write_text(personal, encoding="utf-8")

    plan = plan_upgrade(instance, _revision("v0002"))
    assert plan["safe"] is True and plan["current"]["source"]["sourceDigest"] == source_revision
    approval = approve_upgrade_plan(plan, approved_by="legacy-reviewer")
    apply_upgrade(instance, _revision("v0002"), plan=plan, approval=approval, allow_fixture=True)
    assert state_path.read_text(encoding="utf-8") == personal
    upgraded_lock = _read_lock(lock_path)
    assert next(
        item for item in upgraded_lock["files"] if item["path"] == "state/LEARNING.yaml"
    )["owner"] == "instance"


def _governed_workspace(workspace: Path) -> tuple[GovernedAPI, Path, Path]:
    template_id = "stateport.fixture.studystate-sample"
    template = workspace / "target-revision"
    shutil.copytree(_revision("v0002"), template)
    instance = workspace / "instance"
    _write_instance_yaml(instance, template_id)
    shutil.copytree(_revision("v0001") / "state", instance / "state")
    materialize_instance(_revision("v0001"), instance, allow_fixture=True)
    api = GovernedAPI(
        workspace,
        identities={
            "requester": {"roles": ["user"], "instances": ["surface-demo"]},
            "reviewer": {"roles": ["approver"], "instances": ["surface-demo"]},
            "operator": {"roles": ["operator"], "instances": ["surface-demo"]},
        },
        operator_allowed_capabilities=["write_state"],
    )
    return api, template, instance


def test_capabilities_advertise_the_upgrade_mutation_when_enabled() -> None:
    with tempfile.TemporaryDirectory() as raw:
        api, _, _ = _governed_workspace(Path(raw))
        capabilities = api.dispatch("GET", "/v1/capabilities")
        assert capabilities.body["result"]["mutations"] == ["apply-upgrade", "materialize-instance"]


def test_governed_api_applies_an_approved_upgrade_with_exact_plan_binding() -> None:
    with tempfile.TemporaryDirectory() as raw:
        api, template, instance = _governed_workspace(Path(raw))
        requested = api.dispatch(
            "POST",
            "/v1/mutations/request",
            {
                "actor": "requester",
                "operation": "apply-upgrade",
                "instancePath": "instance",
                "templatePath": "target-revision",
                "reason": "revision 0002 rollout",
            },
        )
        assert requested.status == 200
        result = requested.body["result"]
        approval_id = result["approval"]["id"]
        assert result["approval"]["status"] == "pending"
        assert result["plan"]["planDigest"]
        assert result["plan"]["target"]["version"] == "0.2.0"

        decided = api.dispatch(
            "POST",
            "/v1/approvals/decide",
            {"actor": "reviewer", "approvalId": approval_id, "status": "approved"},
        )
        assert decided.status == 200 and decided.body["result"]["approval"]["status"] == "approved"

        self_apply = api.dispatch(
            "POST",
            "/v1/mutations/apply",
            {"actor": "requester", "approvalId": approval_id},
        )
        assert self_apply.status == 403

        applied = api.dispatch(
            "POST",
            "/v1/mutations/apply",
            {"actor": "operator", "approvalId": approval_id},
        )
        assert applied.status == 200
        assert applied.body["result"]["applied"] is True
        assert applied.body["result"]["idempotent"] is False
        assert applied.body["result"]["receipt"]["status"] == "applied"
        assert "study-tip" in (instance / "actions.yaml").read_text(encoding="utf-8")

        repeat = api.dispatch(
            "POST",
            "/v1/mutations/apply",
            {"actor": "operator", "approvalId": approval_id},
        )
        assert repeat.status == 200
        assert repeat.body["result"]["idempotent"] is True

        re_request = api.dispatch(
            "POST",
            "/v1/mutations/request",
            {
                "actor": "requester",
                "operation": "apply-upgrade",
                "instancePath": "instance",
                "templatePath": "target-revision",
            },
        )
        assert re_request.status == 409
        assert re_request.body["error"]["code"] == "upgrade_plan_blocked"


def test_governed_api_refuses_an_apply_when_the_approved_plan_is_no_longer_current() -> None:
    with tempfile.TemporaryDirectory() as raw:
        api, template, instance = _governed_workspace(Path(raw))
        requested = api.dispatch(
            "POST",
            "/v1/mutations/request",
            {
                "actor": "requester",
                "operation": "apply-upgrade",
                "instancePath": "instance",
                "templatePath": "target-revision",
            },
        )
        assert requested.status == 200
        approval_id = requested.body["result"]["approval"]["id"]
        api.dispatch(
            "POST",
            "/v1/approvals/decide",
            {"actor": "reviewer", "approvalId": approval_id, "status": "approved"},
        )
        (instance / "actions.yaml").write_text(
            (instance / "actions.yaml").read_text(encoding="utf-8") + "\n# local edit\n",
            encoding="utf-8",
        )
        stale = api.dispatch(
            "POST",
            "/v1/mutations/apply",
            {"actor": "operator", "approvalId": approval_id},
        )
        assert stale.status == 409
        assert stale.body["error"]["code"] == "plan_stale"
        assert "study-tip" not in (instance / "actions.yaml").read_text(encoding="utf-8")


def test_unmaterializable_revision_declaration_fails_closed(tmp_path: Path) -> None:
    broken = tmp_path / "broken-revision"
    shutil.copytree(_revision("v0001"), broken)
    manifest = broken / ".statedd" / "manifest.yaml"
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace(
            "id: stateport.fixture.studystate-sample", "id: stateport.fixture.other-sample"
        ),
        encoding="utf-8",
    )
    with pytest.raises(LifecycleError):
        load_template_manifest(broken)
