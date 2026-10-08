#!/usr/bin/env python3
"""Opt-in real rootless-Podman acceptance for deployment Slice A."""

from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import sys
import threading
from urllib.request import urlopen

import pytest


ROOT = Path(__file__).resolve().parents[1]
DEPLOYMENT_SRC = ROOT / "packages" / "deployment" / "src"
EXECUTION_SRC = ROOT / "packages" / "execution-host" / "src"
GOVERNED_SRC = ROOT / "packages" / "governed-runner" / "src"
ADMIN_SRC = ROOT / "apps" / "admin-cli" / "src"
for candidate in (DEPLOYMENT_SRC, EXECUTION_SRC, GOVERNED_SRC, ADMIN_SRC):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from stateport_deployment.podman import (  # noqa: E402
    LABEL_NETWORK,
    LABEL_PLAN,
    LABEL_REVISION,
    LABEL_SERVICE,
    LABEL_SOURCE,
    LABEL_STORAGE,
    RootlessPodmanAdapter,
)
from stateport_deployment.service import DeploymentService  # noqa: E402
from stateport_deployment.errors import AdapterError  # noqa: E402
from stateport_deployment.execution_host import (  # noqa: E402
    ExecutionHostDeploymentAdapter,
)
from execution_host import daemon_contract as execution_contract  # noqa: E402
from execution_host.client import ExecutionHostClient  # noqa: E402
from execution_host.daemon import DaemonConfig, ExecutionHostDaemon  # noqa: E402

from test_container_deployment import (  # noqa: E402
    apply_authorized,
    authority_harness,
    committed_fixture,
    governed_call,
    plan_authorized,
    reserve_for,
)


pytestmark = pytest.mark.skipif(
    os.environ.get("STATEPORT_RUN_PODMAN_TESTS") != "1",
    reason="real rootless-Podman acceptance is opt-in",
)


def _url(observation: dict[str, object], service_id: str, path: str) -> str:
    services = observation["services"]
    assert isinstance(services, dict)
    service = services[service_id]
    assert isinstance(service, dict)
    ports = service["ports"]
    assert isinstance(ports, list) and ports
    port = ports[0]
    assert isinstance(port, dict)
    address = "[::1]" if port["hostAddress"] == "::1" else port["hostAddress"]
    return f"http://{address}:{port['hostPort']}{path}"


def _read_retained_volume(
    adapter: RootlessPodmanAdapter, volume_name: str
) -> tuple[str, str]:
    inspected = json.loads(
        adapter._run(("volume", "inspect", volume_name), timeout=30).stdout
    )
    assert isinstance(inspected, list) and len(inspected) == 1
    mountpoint = inspected[0].get("Mountpoint") or inspected[0].get("mountpoint")
    assert isinstance(mountpoint, str) and mountpoint.startswith("/")
    value_path = f"{mountpoint}/value.txt"
    value = adapter._run(("unshare", "cat", value_path), timeout=30).stdout
    host_stat = Path(value_path).stat()
    ownership = f"{host_stat.st_uid}:{host_stat.st_gid}"
    return value, ownership


class SimulatedPodmanProcessLoss(BaseException):
    """Test-only hard process loss that bypasses adapter/service cleanup."""


class InterruptAfterVolumesAdapter(RootlessPodmanAdapter):
    def _create_networks_and_volumes(self, spec, plan_digest, names):
        result = super()._create_networks_and_volumes(spec, plan_digest, names)
        raise SimulatedPodmanProcessLoss("after exact volume creation")


def _cleanup_exact_plan_resources(
    adapter: RootlessPodmanAdapter, plan: dict[str, object]
) -> list[str]:
    spec = plan["spec"]
    assert isinstance(spec, dict)
    deployment_id = spec["metadata"]["deploymentId"]
    revision = plan["planDigest"]
    source_commit = spec["source"]["commit"]
    names = adapter.resource_names(spec)
    resources: list[tuple[str, str, tuple[str, ...], str, str | None]] = []
    resources.extend(
        ("container", name, ("rm", "--force", name), LABEL_SERVICE, service_id)
        for service_id, name in reversed(list(names["containers"].items()))
    )
    resources.extend(
        ("network", name, ("network", "rm", name), LABEL_NETWORK, network_id)
        for network_id, name in reversed(list(names["networks"].items()))
    )
    resources.extend(
        ("volume", name, ("volume", "rm", name), LABEL_STORAGE, storage_id)
        for storage_id, name in reversed(list(names["volumes"].items()))
    )
    resources.extend(
        (
            "image",
            f"{names['images'][item['id']]}:{revision[7:19]}",
            (
                "image",
                "rm",
                "--force",
                f"{names['images'][item['id']]}:{revision[7:19]}",
            ),
            LABEL_SERVICE,
            item["id"],
        )
        for item in spec["services"]
        if item["build"]["mode"] == "source"
    )
    failures: list[str] = []
    for kind, name, command, identity_label, identity in resources:
        try:
            observed = adapter._assert_owned(kind, name, deployment_id)
            if observed is None:
                continue
            labels = adapter._labels(observed)
            if (
                labels.get(LABEL_PLAN) != revision
                or labels.get(LABEL_REVISION) != revision
                or labels.get(LABEL_SOURCE) != source_commit
                or labels.get(identity_label) != identity
            ):
                failures.append(f"{kind}:{name}:identity_mismatch")
                continue
            adapter._run(command, timeout=60)
        except Exception as exc:
            failures.append(f"{kind}:{name}:{type(exc).__name__}:{exc}")
    for kind in ("container", "network", "volume", "image"):
        try:
            remaining = sorted(adapter._managed_names(kind, deployment_id))
        except Exception as exc:
            failures.append(f"{kind}:inventory:{type(exc).__name__}:{exc}")
        else:
            if remaining:
                failures.append(f"{kind}:remaining:{','.join(remaining)}")
    return failures


def test_real_execution_host_routes_deployment_effects_to_rootless_podman(
    tmp_path: Path,
) -> None:
    engine_socket = Path(
        os.environ.get(
            "STATEPORT_TEST_EXECUTION_ENGINE_SOCKET",
            f"{os.environ.get('XDG_RUNTIME_DIR', '')}/podman/podman.sock",
        )
    )
    if not engine_socket.is_socket():
        pytest.skip("the execution user's rootless Podman socket is not active")

    deployment_id = "execution-host-" + hashlib.sha256(
        str(tmp_path).encode("utf-8")
    ).hexdigest()[:12]
    project = committed_fixture(tmp_path, "python-http")
    actor = "execution-host-podman-test-owner"
    manager, _grant_id = authority_harness(
        tmp_path,
        deployment_id,
        actor=actor,
        project=project,
    )

    socket_dir = tmp_path / "execution-control"
    socket_dir.mkdir(mode=0o750)
    state_dir = tmp_path / "execution-state"
    grants_dir = state_dir / "grants"
    grants_dir.mkdir(parents=True, mode=0o700)
    grant = {
        "formatVersion": execution_contract.GRANT_FORMAT,
        "grantId": "deployment-podman-test-grant",
        "peerUid": os.geteuid(),
        "operations": list(execution_contract.DEPLOYMENT_OPERATIONS),
        "workloadIds": ["deployment-grant-anchor"],
        "workloadKinds": ["terminal"],
        "workloadSpecDigests": {},
        "imageReference": "docker.io/library/python@sha256:" + "b" * 64,
        "baseRevision": None,
        "issuedAt": "2026-08-01T00:00:00Z",
        "expiresAt": "2099-01-01T00:00:00Z",
        "revocationEpoch": 0,
        "deploymentScope": {
            "authorityMode": "canonical-control-plane",
            "targetAdapter": "rootless-podman-local",
            "targetId": "local",
            "allowDataPurge": True,
            "maxArchiveBytes": execution_contract.MAX_DEPLOYMENT_ARCHIVE_BYTES,
            "maxFiles": execution_contract.MAX_DEPLOYMENT_FILES,
        },
        "budgets": {
            "maxTimeoutSeconds": 3600,
            "maxOutputBytes": 1024 * 1024,
            "maxMemoryMaxBytes": execution_contract.MAX_MEMORY_MAX_BYTES,
            "maxPidsMax": execution_contract.MAX_PIDS_MAX,
            "maxActiveWorkloads": 4,
            "maxCpuQuotaPercent": 800,
            "maxDiskMaxBytes": 4 * 1024**3,
        },
    }
    execution_contract.validate_grant_document(grant)
    (grants_dir / "deployment-podman-test-grant.json").write_text(
        json.dumps(grant, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    class EmptyEngine:
        identity = {"engine": "deployment-test", "socket": "confined"}

        @staticmethod
        def version() -> dict[str, str]:
            return {"engine": "deployment-test", "engineVersion": "1"}

        @staticmethod
        def list_managed() -> list[dict[str, object]]:
            return []

    host_adapter = RootlessPodmanAdapter(
        executable="podman-remote",
        engine_socket=str(engine_socket),
    )
    daemon = ExecutionHostDaemon(
        DaemonConfig(
            socket_path=socket_dir / "control.sock",
            state_dir=state_dir,
            socket_group_gid=os.getegid(),
            allowed_client_uid=os.geteuid(),
            allowed_client_gid=os.getegid(),
            runtime_uid=os.geteuid(),
            runtime_gid=os.getegid(),
        ),
        EmptyEngine(),
        deployment_adapter=host_adapter,
    )
    daemon.boot()
    thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    thread.start()
    plan: dict[str, object] | None = None
    try:
        client = ExecutionHostClient(
            socket_dir / "control.sock",
            grant_id=grant["grantId"],
            authority_grant_digest=execution_contract.canonical_digest(grant),
            timeout_seconds=1200,
            output_byte_bound=256 * 1024,
        )
        service = DeploymentService(
            state_root=tmp_path / "deployment-state",
            adapter=ExecutionHostDeploymentAdapter(client),
            authority_manager=manager,
            actor=actor,
        )
        plan = plan_authorized(service, project, deployment_id)
        applied = apply_authorized(service, deployment_id, plan["planDigest"])
        assert applied["state"]["lifecycleState"] == "healthy"
        assert applied["runtime"]["observation"]["observedRevision"] == plan[
            "planDigest"
        ]
        assert applied["runtime"]["target"]["executionTransport"] == (
            "confined-local-rootless-socket"
        )

        removed = governed_call(
            service,
            "remove_deployment_runtime",
            deployment_id,
            lambda decision: service.remove(
                deployment_id,
                authority_decision=decision,
            ),
            run_id=plan["planDigest"],
        )
        assert removed["runtime"]["verifiedRuntimeAbsent"] is True
        assert list((state_dir / "deployment-snapshots").iterdir()) == []
    finally:
        daemon.shutdown()
        thread.join(timeout=5)
        if plan is not None:
            failures = _cleanup_exact_plan_resources(host_adapter, plan)
            if failures:
                detail = "execution-host Podman cleanup failed: " + "; ".join(
                    failures
                )
                if sys.exc_info()[0] is not None:
                    print(detail, file=sys.stderr)
                else:
                    pytest.fail(detail)


@pytest.mark.parametrize(
    "fixture",
    (
        "python-http",
        "node-http",
        "static-web",
        "persistent-multi",
        "compose-http",
        "containerfile-http",
        "dockerfile-http",
    ),
)
def test_real_rootless_podman_lifecycle(tmp_path: Path, fixture: str) -> None:
    project = committed_fixture(tmp_path, fixture)
    deployment_id = f"slice-a-{fixture}"
    adapter = RootlessPodmanAdapter(backup_root=tmp_path / "deployment-backups")
    actor = "podman-test-owner"
    manager, _grant_id = authority_harness(
        tmp_path, deployment_id, actor=actor, project=project
    )
    service = DeploymentService(
        state_root=tmp_path / "state",
        adapter=adapter,
        authority_manager=manager,
        actor=actor,
    )
    plan = plan_authorized(service, project, deployment_id)
    applied = None
    try:
        try:
            applied = apply_authorized(
                service, deployment_id, plan["planDigest"]
            )
        except AdapterError as exc:
            pytest.fail(f"{exc.code}: {exc}; details={json.dumps(exc.details, sort_keys=True)}")
        state = applied["state"]
        observation = applied["runtime"]["observation"]
        assert state["lifecycleState"] == "healthy"
        assert state["acceptedRevision"] == plan["planDigest"]
        assert observation["observedRevision"] == plan["planDigest"]
        assert observation["drift"] == []
        for item in observation["services"].values():
            assert item["ports"][0]["hostPort"] > 0
        health_path = "/" if fixture == "static-web" else "/health"
        with urlopen(_url(observation, next(iter(observation["services"])), health_path), timeout=5) as response:
            assert response.status == 200
        accepted = plan["planDigest"]
        logs = governed_call(
            service,
            "collect_deployment_logs",
            deployment_id,
            lambda decision: service.logs(
                deployment_id,
                authority_decision=decision,
                tail=50,
            ),
            run_id=accepted,
        )
        assert logs["redacted"] is True
        assert Path(logs["evidence"]["path"]).is_file()

        if fixture == "persistent-multi":
            with urlopen(_url(observation, "writer", "/set?value=retained-alpha"), timeout=5) as response:
                assert json.loads(response.read())["stored"] == "retained-alpha"
            backup_plan = governed_call(
                service,
                "plan_deployment",
                deployment_id,
                lambda decision: service.plan_backup(
                    deployment_id, authority_decision=decision
                ),
                run_id=accepted,
            )
            backed_up = governed_call(
                service,
                "backup_deployment_data",
                deployment_id,
                lambda decision: service.apply_data_plan(
                    deployment_id,
                    accept_plan_digest=backup_plan["planDigest"],
                    authority_decision=decision,
                ),
                run_id=backup_plan["planDigest"],
            )
            backup = backed_up["backup"]
            with urlopen(
                _url(backed_up["runtime"]["observation"], "writer", "/set?value=retained-beta"),
                timeout=5,
            ) as response:
                assert json.loads(response.read())["stored"] == "retained-beta"
            restore_plan = governed_call(
                service,
                "plan_deployment",
                deployment_id,
                lambda decision: service.plan_restore(
                    deployment_id,
                    backup_id=backup["backupId"],
                    authority_decision=decision,
                ),
                run_id=accepted,
            )
            restored = governed_call(
                service,
                "restore_deployment_data",
                deployment_id,
                lambda decision: service.apply_data_plan(
                    deployment_id,
                    accept_plan_digest=restore_plan["planDigest"],
                    authority_decision=decision,
                ),
                run_id=restore_plan["planDigest"],
            )
            assert restored["backup"]["status"] == "restored_consumed"
            observation = restored["runtime"]["observation"]
            with urlopen(_url(observation, "reader", "/value"), timeout=5) as response:
                assert json.loads(response.read())["value"] == "retained-alpha"
        restarted = governed_call(
            service,
            "restart_deployment",
            deployment_id,
            lambda decision: service.restart(
                deployment_id, authority_decision=decision
            ),
            run_id=accepted,
        )
        assert restarted["state"]["driftStatus"] == "in_sync"
        if fixture == "persistent-multi":
            restarted_observation = restarted["runtime"]["observation"]
            with urlopen(_url(restarted_observation, "reader", "/value"), timeout=5) as response:
                assert json.loads(response.read())["value"] == "retained-alpha"

        try:
            removed = governed_call(
                service,
                "remove_deployment_runtime",
                deployment_id,
                lambda decision: service.remove(
                    deployment_id, authority_decision=decision
                ),
                run_id=accepted,
            )
        except AdapterError as exc:
            pytest.fail(
                f"{exc.code}: {exc}; details={json.dumps(exc.details, sort_keys=True)}"
            )
        assert removed["state"]["lifecycleState"] == "removed_runtime_data_retained"
        assert removed["runtime"]["verifiedRuntimeAbsent"] is True
        if fixture == "persistent-multi":
            retained_volume = removed["state"]["storageIdentities"]["app-data"]
            retained_value, retained_ownership = _read_retained_volume(
                adapter, retained_volume
            )
            assert retained_value == "retained-alpha"
            assert retained_ownership == f"{os.geteuid()}:{os.getegid()}"
        after_remove = governed_call(
            service,
            "observe_deployment",
            deployment_id,
            lambda decision: service.status(
                deployment_id, authority_decision=decision
            ),
            run_id=accepted,
        )
        assert after_remove["state"]["driftStatus"] == "in_sync"
        if fixture == "persistent-multi":
            purge = governed_call(
                service,
                "plan_deployment",
                deployment_id,
                lambda decision: service.plan_purge(
                    deployment_id, authority_decision=decision
                ),
                run_id=accepted,
            )
            purged = governed_call(
                service,
                "purge_deployment_data",
                deployment_id,
                lambda decision: service.purge_data(
                    deployment_id,
                    accept_plan_digest=purge["planDigest"],
                    authority_decision=decision,
                ),
                run_id=purge["planDigest"],
            )
            assert purged["state"]["lifecycleState"] == "purged"
            assert purged["runtime"]["verifiedAbsent"] is True
            assert governed_call(
                service,
                "observe_deployment",
                deployment_id,
                lambda decision: service.status(
                    deployment_id, authority_decision=decision
                ),
                run_id=purge["planDigest"],
            )["state"]["driftStatus"] == "in_sync"
    finally:
        # Attempt every exact task-owned cleanup independently.  When another
        # failure is already active, report cleanup defects without replacing
        # the primary evidence.
        primary_failure_active = sys.exc_info()[0] is not None
        cleanup_failures: list[str] = []
        names = adapter.resource_names(plan["spec"])
        source_commit = plan["spec"]["source"]["commit"]
        expected_revision = plan["planDigest"]
        resources: list[tuple[str, str, tuple[str, ...], str, str | None]] = []
        resources.extend(
            (
                "container",
                name,
                ("rm", "--force", name),
                LABEL_SERVICE,
                service_id,
            )
            for service_id, name in reversed(
                list(names["containers"].items())
            )
        )
        resources.extend(
            (
                "network",
                name,
                ("network", "rm", name),
                LABEL_NETWORK,
                network_id,
            )
            for network_id, name in reversed(list(names["networks"].items()))
        )
        resources.extend(
            (
                "volume",
                name,
                ("volume", "rm", name),
                LABEL_STORAGE,
                storage_id,
            )
            for storage_id, name in reversed(list(names["volumes"].items()))
        )
        resources.extend(
            (
                "image",
                f"{names['images'][item['id']]}:{expected_revision[7:19]}",
                (
                    "image",
                    "rm",
                    "--force",
                    f"{names['images'][item['id']]}:{expected_revision[7:19]}",
                ),
                LABEL_SERVICE,
                item["id"],
            )
            for item in plan["spec"]["services"]
            if item["build"]["mode"] == "source"
        )
        for kind, name, command, identity_label, identity in resources:
            try:
                observed = adapter._assert_owned(kind, name, deployment_id)
                if observed is None:
                    continue
                labels = adapter._labels(observed)
                if (
                    labels.get(LABEL_PLAN) != expected_revision
                    or labels.get(LABEL_REVISION) != expected_revision
                    or labels.get(LABEL_SOURCE) != source_commit
                    or labels.get(identity_label) != identity
                ):
                    cleanup_failures.append(f"{kind}:{name}:identity_mismatch")
                    continue
                adapter._run(command, timeout=60)
            except Exception as exc:  # cleanup must continue through all kinds
                cleanup_failures.append(
                    f"{kind}:{name}:{type(exc).__name__}:{exc}"
                )
        for kind in ("container", "network", "volume", "image"):
            try:
                remaining = sorted(adapter._managed_names(kind, deployment_id))
            except Exception as exc:
                cleanup_failures.append(
                    f"{kind}:inventory:{type(exc).__name__}:{exc}"
                )
            else:
                if remaining:
                    cleanup_failures.append(
                        f"{kind}:remaining:{','.join(remaining)}"
                    )
        if cleanup_failures:
            detail = "real Podman cleanup failed: " + "; ".join(cleanup_failures)
            if primary_failure_active:
                print(detail, file=sys.stderr)
            else:
                pytest.fail(detail)


def test_real_rootless_podman_hard_interruption_reconciles_exactly(
    tmp_path: Path,
) -> None:
    project = committed_fixture(tmp_path, "persistent-multi")
    deployment_id = "slice-a-interrupted-persistent"
    actor = "podman-interruption-owner"
    manager, _grant_id = authority_harness(
        tmp_path, deployment_id, actor=actor, project=project
    )
    interrupting_adapter = InterruptAfterVolumesAdapter()
    state_root = tmp_path / "state"
    service = DeploymentService(
        state_root=state_root,
        adapter=interrupting_adapter,
        authority_manager=manager,
        actor=actor,
    )
    plan = plan_authorized(service, project, deployment_id)
    decision, _reservation = reserve_for(
        service,
        "apply_deployment",
        deployment_id,
        run_id=plan["planDigest"],
    )
    cleanup_adapter = RootlessPodmanAdapter()
    try:
        with pytest.raises(SimulatedPodmanProcessLoss):
            service.apply(
                deployment_id,
                accept_plan_digest=plan["planDigest"],
                authority_decision=decision,
            )
        interrupted = service.store.load_state(deployment_id)
        transition = interrupted["currentTransition"]
        assert interrupted["lifecycleState"] == "applying"
        assert transition["operation"] == "apply"
        context_path = (
            state_root
            / "records"
            / deployment_id
            / "build-contexts"
            / transition["operationId"]
        )
        assert context_path.is_dir()
        assert cleanup_adapter._managed_names("volume", deployment_id)
        assert cleanup_adapter._managed_names("network", deployment_id)

        recovered = DeploymentService(
            state_root=state_root,
            adapter=cleanup_adapter,
            authority_manager=manager,
            actor=actor,
        )
        observed = governed_call(
            recovered,
            "observe_deployment",
            deployment_id,
            lambda authority: recovered.status(
                deployment_id, authority_decision=authority
            ),
            run_id=plan["planDigest"],
        )
        assert observed["state"]["lifecycleState"] == "reconciliation_required"
        assert observed["state"]["driftStatus"] == "drifted"

        removed = governed_call(
            recovered,
            "remove_deployment_runtime",
            deployment_id,
            lambda authority: recovered.remove(
                deployment_id, authority_decision=authority
            ),
            run_id=plan["planDigest"],
        )
        assert removed["state"]["lifecycleState"] == "removed_runtime_data_retained"
        assert removed["runtime"]["recoveryOperation"] == "apply"
        assert removed["receipt"]["data"]["buildContextCleanup"]["status"] == "removed"
        assert not context_path.exists()
        assert cleanup_adapter._managed_names("container", deployment_id) == set()
        assert cleanup_adapter._managed_names("network", deployment_id) == set()
        assert cleanup_adapter._managed_names("image", deployment_id) == set()
        assert cleanup_adapter._managed_names("volume", deployment_id)

        original = recovered.reconcile_authority_receipts(
            deployment_id, request_id=decision["requestId"]
        )
        assert len(original["links"]) == 1
        interrupted_receipt = manager.get_receipt_for_request(
            decision["requestId"]
        )
        assert interrupted_receipt is not None
        assert interrupted_receipt["result"]["status"] == "failed"
        assert interrupted_receipt["result"]["code"] == "interrupted_apply_recovered"

        purge_plan = governed_call(
            recovered,
            "plan_deployment",
            deployment_id,
            lambda authority: recovered.plan_purge(
                deployment_id, authority_decision=authority
            ),
            run_id=plan["planDigest"],
        )
        purged = governed_call(
            recovered,
            "purge_deployment_data",
            deployment_id,
            lambda authority: recovered.purge_data(
                deployment_id,
                accept_plan_digest=purge_plan["planDigest"],
                authority_decision=authority,
            ),
            run_id=purge_plan["planDigest"],
        )
        assert purged["state"]["lifecycleState"] == "purged"
        for kind in ("container", "network", "volume", "image"):
            assert cleanup_adapter._managed_names(kind, deployment_id) == set()
    finally:
        failures = _cleanup_exact_plan_resources(cleanup_adapter, plan)
        if failures:
            detail = "interruption cleanup failed: " + "; ".join(failures)
            if sys.exc_info()[0] is not None:
                print(detail, file=sys.stderr)
            else:
                pytest.fail(detail)
