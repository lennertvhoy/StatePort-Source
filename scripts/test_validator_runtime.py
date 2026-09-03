from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import os
import threading

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "container-runner" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "execution-host" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "runtime-contracts" / "src"))

from container_runner import ExecutorError, ValidatorExecutor, ValidatorPlan  # noqa: E402
from execution_host import daemon_contract as execution_contract  # noqa: E402
from execution_host.client import (  # noqa: E402
    ExecutionHostClient,
    ExecutionHostRefusal,
)
from execution_host.daemon import DaemonConfig, ExecutionHostDaemon  # noqa: E402
from execution_host.engine import EngineError, build_create_argv  # noqa: E402
from execution_host.engine import KIND_LABEL, MANAGED_LABEL_KEY, WORKLOAD_LABEL  # noqa: E402
from execution_host.ledger import OperationLedger, reconcile_on_boot  # noqa: E402
from execution_host.validator_runtime import ValidatorRuntime, ValidatorRuntimeError  # noqa: E402


IMAGE = "registry.example/stateport-validator@sha256:" + "a" * 64


def test_validator_command_is_read_only_staging_only(tmp_path: Path):
    plan = ValidatorPlan(IMAGE, tmp_path, ("python3", "-m", "pytest"))
    argv = plan.build_command()
    assert "--network=none" in argv
    assert "--read-only" in argv
    assert "--cap-drop=ALL" in argv
    mount = argv[argv.index("--mount") + 1]
    assert f"src={tmp_path.resolve()}" in mount
    assert ",readonly" in mount
    assert "docker.sock" not in " ".join(argv)


def test_validator_refuses_mutable_images_and_isolation_overrides(tmp_path: Path):
    with pytest.raises(ExecutorError, match="digest-pinned"):
        ValidatorPlan("validator:latest", tmp_path, ("pytest",)).build_command()
    with pytest.raises(ExecutorError, match="override"):
        ValidatorPlan(IMAGE, tmp_path, ("sh", "--network=host")).build_command()
    with pytest.raises(ExecutorError, match="execution_host"):
        ValidatorExecutor().execute(ValidatorPlan(IMAGE, tmp_path, ("pytest",)))


def validator_data(staging: Path) -> dict[str, object]:
    return {
        "formatVersion": "stateport.validator-spec/v1",
        "validatorId": "validator.demo",
        "imageDigest": "sha256:" + "a" * 64,
        "stagingPath": str(staging),
        "commands": [["python3", "-m", "pytest"]],
        "resources": {
            "memoryMaxBytes": 268435456,
            "cpuQuotaPercent": 100,
            "pidsMax": 128,
            "diskMaxBytes": 67108864,
        },
        "timeoutSeconds": 30,
        "outputByteBound": 4096,
        "network": "disabled",
        "stagingReadOnly": True,
        "providerAccess": False,
        "runtimeSocketAccess": False,
        "hostMounts": [],
    }


def test_execution_host_validator_workload_is_sealed_and_read_only(tmp_path: Path):
    staging = tmp_path / "staging"
    staging.mkdir()
    data = validator_data(staging)
    from runtime_contracts import ValidatorSpec, canonical_digest  # noqa: PLC0415

    normalized = ValidatorSpec.from_dict(data).to_dict()
    workload = {
        "kind": "validator-run",
        "workloadId": "validator-run-demo",
        "image": {"reference": IMAGE},
        "parameters": {
            "validatorId": normalized["validatorId"],
            "validatorSpecDigest": ValidatorSpec.from_dict(data).digest,
            "stagingIdentityDigest": canonical_digest({"staging": "test"}),
            "stagingPath": str(staging),
            "commandDigest": canonical_digest(normalized["commands"][0]),
            "command": normalized["commands"][0],
            "network": "disabled",
            "stagingReadOnly": True,
            "providerAccess": False,
            "runtimeSocketAccess": False,
            "hostMounts": [],
        },
        "timeoutSeconds": 30,
        "outputByteBound": 4096,
        "resources": normalized["resources"],
    }
    validated = execution_contract.validate_workload_spec(workload)
    argv = build_create_argv(validated)
    assert "--network" in argv and argv[argv.index("--network") + 1] == "none"
    assert "--read-only" in argv
    assert "--mount" in argv
    mount = argv[argv.index("--mount") + 1]
    assert ",dst=/validator,readonly,relabel=private" in mount
    assert "--volume" not in argv
    assert "--env" not in argv


class FakeHostClient:
    def __init__(self):
        self.workloads = []

    def run_validator(self, workload):
        self.workloads.append(workload)
        return {
            "result": {
                "validatorId": workload["parameters"]["validatorId"],
                "workloadId": workload["workloadId"],
                "status": "passed",
                "classification": "passed",
                "imageDigest": IMAGE.rsplit("@", 1)[1],
                "commandIdentityDigest": workload["parameters"]["commandDigest"],
                "stagingIdentityDigest": workload["parameters"]["stagingIdentityDigest"],
                "observedExitStatus": 0,
                "evidenceLocation": "evidence/test.json",
                "evidenceDigest": "sha256:" + "c" * 64,
            }
        }


def test_validator_runtime_uses_host_and_never_agent_result(tmp_path: Path):
    staging = tmp_path / "staging"
    staging.mkdir()
    host = FakeHostClient()
    runtime = ValidatorRuntime(host, image_reference=IMAGE)
    result = runtime.run(validator_data(staging))
    assert result["status"] == "passed"
    assert len(host.workloads) == 1
    assert host.workloads[0]["parameters"]["providerAccess"] is False
    invalid = validator_data(staging)
    invalid["agentResult"] = {"status": "passed"}
    with pytest.raises(ValueError):
        runtime.run(invalid)


def test_validator_rejects_recursive_staging_tree_mutation_before_next_command(tmp_path: Path):
    staging = tmp_path / "staging"
    nested = staging / "nested"
    nested.mkdir(parents=True)
    (nested / "input.txt").write_text("before\n", encoding="utf-8")

    class MutatingHost(FakeHostClient):
        def run_validator(self, workload):
            receipt = super().run_validator(workload)
            if len(self.workloads) == 1:
                (nested / "input.txt").write_text("after\n", encoding="utf-8")
            return receipt

    data = validator_data(staging)
    data["commands"] = [["python3", "-c", "pass"], ["python3", "-c", "pass"]]
    host = MutatingHost()
    runtime = ValidatorRuntime(host, image_reference=IMAGE)
    with pytest.raises(ValidatorRuntimeError, match="staging mutated"):
        runtime.run(data)
    assert len(host.workloads) == 1


class ValidatorEngine:
    identity = {"engine": "fake-validator-engine", "socket": "owned-test-socket"}

    def __init__(self):
        self.items = {}
        self.removed = []
        self.created_specs = []

    def version(self):
        return {"engine": "fake-validator-engine", "engineVersion": "1"}

    def create(self, spec, *, timeout=None):
        self.created_specs.append(deepcopy(spec))
        self.items[spec["workloadId"]] = {
            "spec": spec,
            "running": False,
            "exitStatus": 0,
            "labels": {
                MANAGED_LABEL_KEY: "true",
                WORKLOAD_LABEL: spec["workloadId"],
                KIND_LABEL: spec["kind"],
            },
        }
        return "container-" + spec["workloadId"]

    def start(self, workload_id, *, timeout=None):
        # The fake models a validator that has completed independently before
        # the daemon observes it.
        self.items[workload_id]["running"] = False

    def inspect(self, workload_id):
        item = self.items.get(workload_id)
        if item is None:
            return {"present": False}
        return {
            "present": True,
            "running": item["running"],
            "status": "exited",
            "exitStatus": item["exitStatus"],
            "startedAt": "2026-01-01T00:00:00Z",
            "finishedAt": "2026-01-01T00:00:01Z",
            "imageDigest": item["spec"]["image"]["reference"].rsplit("@", 1)[1],
            "imageReference": item["spec"]["image"]["reference"],
            "labels": item["labels"],
        }

    def logs(self, workload_id, *, max_bytes):
        data = "validator output that is not persisted"
        encoded = data.encode()
        return {"bytes": data[:max_bytes], "byteCount": min(len(encoded), max_bytes), "truncated": len(encoded) > max_bytes}

    def remove(self, workload_id, *, force=True):
        self.items.pop(workload_id, None)
        self.removed.append(workload_id)

    def stop(self, workload_id, *, timeout=2):
        self.items[workload_id]["running"] = False

    def kill(self, workload_id):
        self.stop(workload_id, timeout=0)

    def list_managed(self):
        return [
            {
                "workloadId": workload_id,
                "state": "running",
                "labels": item["labels"],
            }
            for workload_id, item in self.items.items()
        ]


def daemon_workload(root: Path) -> dict[str, object]:
    staging = root / "candidate"
    staging.mkdir()
    (staging / "input.txt").write_text("candidate-bytes\n", encoding="utf-8")
    data = validator_data(staging)
    from runtime_contracts import ValidatorSpec, canonical_digest  # noqa: PLC0415
    from execution_host.staging_identity import staging_manifest_digest  # noqa: PLC0415

    normalized = ValidatorSpec.from_dict(data).to_dict()
    return execution_contract.validate_workload_spec(
        {
            "kind": "validator-run",
            "workloadId": "validator-run-daemon",
            "image": {"reference": IMAGE},
            "parameters": {
                "validatorId": normalized["validatorId"],
                "validatorSpecDigest": ValidatorSpec.from_dict(data).digest,
                "stagingIdentityDigest": staging_manifest_digest(staging),
                "stagingPath": str(staging),
                "commandDigest": canonical_digest(normalized["commands"][0]),
                "command": normalized["commands"][0],
                "network": "disabled",
                "stagingReadOnly": True,
                "providerAccess": False,
                "runtimeSocketAccess": False,
                "hostMounts": [],
            },
            "timeoutSeconds": 30,
            "outputByteBound": 4096,
            "resources": normalized["resources"],
        }
    )


def test_validator_runs_only_through_execution_host_and_writes_digest_evidence(tmp_path: Path):
    root = tmp_path / "validator-root"
    root.mkdir()
    socket_dir = tmp_path / "control"
    socket_dir.mkdir()
    os.chmod(socket_dir, 0o750)
    engine = ValidatorEngine()
    daemon = ExecutionHostDaemon(
        DaemonConfig(
            socket_path=socket_dir / "control.sock",
            state_dir=tmp_path / "state",
            socket_group_gid=os.getegid(),
            validator_staging_root=root,
        ),
        engine,
    )
    daemon.boot()
    thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    thread.start()
    try:
        workload = daemon_workload(root)
        grant_doc = {
            "formatVersion": execution_contract.GRANT_FORMAT,
            "grantId": "grant.validator",
            "peerUid": os.geteuid(),
            "operations": [
                operation
                for operation in execution_contract.OPERATIONS
                if operation not in execution_contract.DEPLOYMENT_OPERATIONS
            ],
            "workloadIds": [workload["workloadId"]],
            "workloadKinds": ["validator-run"],
            "workloadSpecDigests": {
                workload["workloadId"]: execution_contract.canonical_digest(workload)
            },
            "imageReference": IMAGE,
            "baseRevision": None,
            "issuedAt": "2026-08-08T00:00:00Z",
            "expiresAt": "2099-01-01T00:00:00Z",
            "revocationEpoch": 0,
            "budgets": {
                "maxTimeoutSeconds": 600,
                "maxOutputBytes": 1048576,
                "maxMemoryMaxBytes": 1073741824,
                "maxPidsMax": 512,
                "maxActiveWorkloads": 4,
                "maxCpuQuotaPercent": 800,
                "maxDiskMaxBytes": 4 * 1024**3,
            },
        }
        grants_dir = tmp_path / "state" / "grants"
        grants_dir.mkdir(parents=True, exist_ok=True)
        import json as _json  # noqa: PLC0415

        (grants_dir / "grant.validator.json").write_text(
            _json.dumps(grant_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        client = ExecutionHostClient(
            socket_dir / "control.sock",
            grant_id="grant.validator",
            authority_grant_digest=execution_contract.canonical_digest(grant_doc),
            output_byte_bound=1048576,
        )
        receipt = client.run_validator(workload)
        result = receipt["result"]
        assert result["status"] == "passed"
        assert result["observedExitStatus"] == 0
        assert result["evidenceDigest"].startswith("sha256:")
        evidence_path = daemon._ledger.state_dir / result["evidenceLocation"]  # noqa: SLF001
        evidence = _json.loads(evidence_path.read_text())
        assert evidence["classification"] == "passed"
        assert evidence["sealedCommandIdentityDigest"] == evidence[
            "observedCommandIdentityDigest"
        ]
        assert evidence["stagingIdentityDigest"] == evidence[
            "executionStagingIdentityDigest"
        ]
        assert evidence["clientWorkloadSpecDigest"] == execution_contract.canonical_digest(
            workload
        )
        assert evidence["executionWorkloadSpecDigest"] != evidence[
            "clientWorkloadSpecDigest"
        ]
        executed_path = Path(engine.created_specs[0]["parameters"]["stagingPath"])
        assert executed_path != Path(workload["parameters"]["stagingPath"])
        assert executed_path.parent == tmp_path / "state" / "validator-snapshots"
        assert list((tmp_path / "state" / "validator-snapshots").iterdir()) == []
        assert "validator output" not in evidence_path.read_text()
        assert receipt["cleanup"]["outcome"] == "performed"
        # Without a live grant the same operation is refused before the engine.
        intruder = ExecutionHostClient(
            socket_dir / "control.sock",
            grant_id="grant.intruder",
            authority_grant_digest="sha256:" + "d" * 64,
        )
        from execution_host.client import ExecutionHostRefusal  # noqa: PLC0415

        with pytest.raises(ExecutionHostRefusal, match="grant-unknown"):
            intruder.run_validator(workload)
    finally:
        daemon.shutdown()
        thread.join(timeout=2)


def test_validator_restart_recovery_interrupts_and_removes_workload(tmp_path: Path):
    root = tmp_path / "validator-root"
    root.mkdir()
    workload = daemon_workload(root)
    ledger = OperationLedger(tmp_path / "state")
    ledger.record_created(workload, at="2026-01-01T00:00:00Z", container_id="container")
    ledger.transition(workload["workloadId"], "running", at="2026-01-01T00:00:01Z")
    engine = ValidatorEngine()
    engine.create(workload)
    engine.start(workload["workloadId"])
    report = reconcile_on_boot(ledger, engine, at="2026-01-01T00:01:00Z")
    assert report["interrupted"] == [workload["workloadId"]]
    assert workload["workloadId"] in engine.removed
    assert ledger.get(workload["workloadId"])["state"] == "interrupted"


def _validator_daemon(tmp_path: Path, root: Path, engine=None):
    socket_dir = tmp_path / "control"
    socket_dir.mkdir()
    os.chmod(socket_dir, 0o750)
    daemon = ExecutionHostDaemon(
        DaemonConfig(
            socket_path=socket_dir / "control.sock",
            state_dir=tmp_path / "state",
            socket_group_gid=os.getegid(),
            validator_staging_root=root,
        ),
        engine or ValidatorEngine(),
    )
    daemon.boot()
    thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    thread.start()
    return daemon, thread


def _validator_client(tmp_path: Path, workload) -> ExecutionHostClient:
    grant_doc = {
        "formatVersion": execution_contract.GRANT_FORMAT,
        "grantId": "grant.validator",
        "peerUid": os.geteuid(),
        "operations": [
            operation
            for operation in execution_contract.OPERATIONS
            if operation not in execution_contract.DEPLOYMENT_OPERATIONS
        ],
        "workloadIds": [workload["workloadId"]],
        "workloadKinds": ["validator-run"],
        "workloadSpecDigests": {
            workload["workloadId"]: execution_contract.canonical_digest(workload)
        },
        "imageReference": IMAGE,
        "baseRevision": None,
        "issuedAt": "2026-08-08T00:00:00Z",
        "expiresAt": "2099-01-01T00:00:00Z",
        "revocationEpoch": 0,
        "budgets": {
            "maxTimeoutSeconds": 600,
            "maxOutputBytes": 1048576,
            "maxMemoryMaxBytes": 1073741824,
            "maxPidsMax": 512,
            "maxActiveWorkloads": 4,
            "maxCpuQuotaPercent": 800,
            "maxDiskMaxBytes": 4 * 1024**3,
        },
    }
    grants_dir = tmp_path / "state" / "grants"
    grants_dir.mkdir(parents=True, exist_ok=True)
    import json as _json  # noqa: PLC0415

    (grants_dir / "grant.validator.json").write_text(
        _json.dumps(grant_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return ExecutionHostClient(
        tmp_path / "control" / "control.sock",
        grant_id="grant.validator",
        authority_grant_digest=execution_contract.canonical_digest(grant_doc),
        output_byte_bound=1048576,
    )


def test_daemon_recomputes_staging_identity_and_refuses_mismatch(tmp_path: Path):
    root = tmp_path / "validator-root"
    root.mkdir()
    daemon, thread = _validator_daemon(tmp_path, root)
    try:
        workload = daemon_workload(root)
        forged = dict(workload)
        forged["parameters"] = dict(workload["parameters"], stagingIdentityDigest="sha256:" + "0" * 64)
        forged = execution_contract.validate_workload_spec(forged)
        client = _validator_client(tmp_path, forged)
        from execution_host.client import ExecutionHostRefusal  # noqa: PLC0415

        with pytest.raises(ExecutionHostRefusal, match="staging-identity-mismatch"):
            client.run_validator(forged)
        # The honest workload still passes.
        honest = _validator_client(tmp_path, workload)
        receipt = honest.run_validator(workload)
        assert receipt["result"]["classification"] == "passed"
    finally:
        daemon.shutdown()
        thread.join(timeout=2)


def test_daemon_refuses_staging_containing_symlinks(tmp_path: Path):
    root = tmp_path / "validator-root"
    root.mkdir()
    staging = root / "candidate"
    staging.mkdir()
    (staging / "real.txt").write_text("data\n", encoding="utf-8")
    (staging / "linked.txt").symlink_to(staging / "real.txt")
    daemon, thread = _validator_daemon(tmp_path, root)
    try:
        from execution_host.staging_identity import staging_manifest_digest  # noqa: PLC0415
        from runtime_contracts import ValidatorSpec, canonical_digest  # noqa: PLC0415

        data = validator_data(staging)
        normalized = ValidatorSpec.from_dict(data).to_dict()
        # The sealed spec claims an identity; the tree itself is inadmissible.
        workload = execution_contract.validate_workload_spec(
            {
                "kind": "validator-run",
                "workloadId": "validator-run-symlink",
                "image": {"reference": IMAGE},
                "parameters": {
                    "validatorId": normalized["validatorId"],
                    "validatorSpecDigest": ValidatorSpec.from_dict(data).digest,
                    "stagingIdentityDigest": "sha256:" + "0" * 64,
                    "stagingPath": str(staging),
                    "commandDigest": canonical_digest(normalized["commands"][0]),
                    "command": normalized["commands"][0],
                    "network": "disabled",
                    "stagingReadOnly": True,
                    "providerAccess": False,
                    "runtimeSocketAccess": False,
                    "hostMounts": [],
                },
                "timeoutSeconds": 30,
                "outputByteBound": 4096,
                "resources": normalized["resources"],
            }
        )
        client = _validator_client(tmp_path, workload)
        from execution_host.client import ExecutionHostRefusal  # noqa: PLC0415

        with pytest.raises(ExecutionHostRefusal, match="staging"):
            client.run_validator(workload)
    finally:
        daemon.shutdown()
        thread.join(timeout=2)


class SourceMutatingValidatorEngine(ValidatorEngine):
    def __init__(self, source: Path) -> None:
        super().__init__()
        self.source = source
        self.snapshot_files = {}

    def create(self, spec, *, timeout=None):
        snapshot = Path(spec["parameters"]["stagingPath"])
        self.snapshot_files = {
            item.relative_to(snapshot).as_posix(): item.read_bytes()
            for item in snapshot.rglob("*")
            if item.is_file()
        }
        self.source.write_text("mutated-after-snapshot\n", encoding="utf-8")
        (self.source.parent / "added-after-snapshot.txt").write_text(
            "not mounted\n", encoding="utf-8"
        )
        return super().create(spec, timeout=timeout)


def test_daemon_executes_snapshot_when_source_changes_after_copy(tmp_path: Path):
    root = tmp_path / "validator-root"
    root.mkdir()
    workload = daemon_workload(root)
    source = root / "candidate" / "input.txt"
    engine = SourceMutatingValidatorEngine(source)
    daemon, thread = _validator_daemon(tmp_path, root, engine)
    try:
        client = _validator_client(tmp_path, workload)
        result = client.run_validator(workload)["result"]
        assert result["classification"] == "passed"
        assert engine.snapshot_files == {"input.txt": b"candidate-bytes\n"}
        assert source.read_text(encoding="utf-8") == "mutated-after-snapshot\n"
        assert result["stagingIdentityDigest"] == result[
            "executionStagingIdentityDigest"
        ]
        assert result["clientWorkloadSpecDigest"] != result[
            "executionWorkloadSpecDigest"
        ]
        assert list((tmp_path / "state" / "validator-snapshots").iterdir()) == []
    finally:
        daemon.shutdown()
        thread.join(timeout=2)


class ValidatorStartCasEngine(ValidatorEngine):
    def __init__(self, state_dir: Path) -> None:
        super().__init__()
        self.state_dir = state_dir

    def start(self, workload_id, *, timeout=None):
        self.items[workload_id]["running"] = True
        ledger = OperationLedger(self.state_dir)
        current = ledger.get(workload_id)
        ledger.transition(
            workload_id,
            "cancelled",
            at="2026-08-08T00:00:05Z",
            finished_at="2026-08-08T00:00:05Z",
            expect_states={current["state"]},
            expect_version=current["version"],
        )


def test_validator_start_cas_race_cleans_container_and_snapshot(tmp_path: Path):
    root = tmp_path / "validator-root"
    root.mkdir()
    workload = daemon_workload(root)
    engine = ValidatorStartCasEngine(tmp_path / "state")
    daemon, thread = _validator_daemon(tmp_path, root, engine)
    try:
        client = _validator_client(tmp_path, workload)
        with pytest.raises(ExecutionHostRefusal, match="state-conflict"):
            client.run_validator(workload)
        entry = OperationLedger(tmp_path / "state").get(workload["workloadId"])
        assert entry["state"] == "cancelled"
        assert entry["receipts"][-1]["kind"] == "validator-start-cas-conflict"
        assert workload["workloadId"] not in engine.items
        assert list((tmp_path / "state" / "validator-snapshots").iterdir()) == []
    finally:
        daemon.shutdown()
        thread.join(timeout=2)


def test_snapshot_copy_is_bounded_and_rejects_special_files(tmp_path: Path):
    from execution_host.staging_identity import (  # noqa: PLC0415
        StagingIdentityError,
        create_staging_snapshot,
        staging_manifest_digest,
    )

    root = tmp_path / "root"
    source = root / "candidate"
    source.mkdir(parents=True)
    (source / "input.txt").write_bytes(b"four")
    snapshots = tmp_path / "snapshots"
    with pytest.raises(StagingIdentityError, match="byte bound"):
        create_staging_snapshot(
            source,
            trusted_root=root,
            snapshots_root=snapshots,
            workload_id="validator-bounded",
            max_bytes=3,
        )
    assert list(snapshots.iterdir()) == []
    fifo = source / "special.fifo"
    os.mkfifo(fifo)
    try:
        with pytest.raises(StagingIdentityError, match="unsupported file type"):
            staging_manifest_digest(source)
    finally:
        fifo.unlink()


def test_boot_reclaims_orphaned_validator_snapshots(tmp_path: Path):
    root = tmp_path / "validator-root"
    root.mkdir()
    orphan = tmp_path / "state" / "validator-snapshots" / "orphan"
    orphan.mkdir(parents=True)
    (orphan / "input.txt").write_text("stale\n", encoding="utf-8")
    daemon, thread = _validator_daemon(tmp_path, root)
    try:
        assert list((tmp_path / "state" / "validator-snapshots").iterdir()) == []
    finally:
        daemon.shutdown()
        thread.join(timeout=2)
