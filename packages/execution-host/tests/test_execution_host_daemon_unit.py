"""Unit tests for the execution-host daemon core.

Uses a fake in-memory engine; no container runtime is invoked.  Covers the
sealed contract shapes, the hardened argv builder, the crash-recovery
matrix, and supervision timeouts over a real confined Unix socket.
"""

from __future__ import annotations

from copy import deepcopy
import json
import os
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any, Mapping

import pytest
import jsonschema

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "packages" / "execution-host" / "src"))

from execution_host import daemon_contract as contract
from execution_host.client import (
    ExecutionHostClient,
    ExecutionHostRefusal,
    ExecutionHostTransportError,
)
from execution_host.daemon import (
    CLIENT_IDENTITY_FILE,
    DaemonBootError,
    DaemonConfig,
    ExecutionHostDaemon,
)
from execution_host.engine import (
    EngineError,
    KIND_LABEL,
    MANAGED_LABEL_KEY,
    PodmanCliEngine,
    WORKLOAD_LABEL,
    build_create_argv,
    container_name,
)
from execution_host.ledger import LedgerError, OperationLedger, reconcile_on_boot

DIGEST = "sha256:" + "a" * 64
IMAGE = f"docker.io/library/python@{'b' * 64}".replace("python@", "python@sha256:")


class FakeEngine:
    """In-memory engine honouring the PodmanCliEngine surface."""

    def __init__(self) -> None:
        self.containers: dict[str, dict[str, Any]] = {}
        self.identity = {"engine": "fake-cli", "socket": "fake"}
        self.stopped: list[str] = []
        self.removed: list[str] = []
        self.volume_claims_valid = True

    def version(self) -> dict[str, str]:
        return {"engine": "fake", "engineVersion": "0.0.0-test"}

    def create(self, spec: Mapping[str, Any], *, timeout: int | None = None) -> str:
        name = container_name(spec["workloadId"])
        self.containers[spec["workloadId"]] = {
            "name": name,
            "running": False,
            "exitStatus": None,
            "imageDigest": spec["image"]["reference"].rsplit("@", 1)[1],
            "imageReference": spec["image"]["reference"],
            "labels": {
                MANAGED_LABEL_KEY: "true",
                WORKLOAD_LABEL: spec["workloadId"],
                KIND_LABEL: spec["kind"],
            },
        }
        return "fake-container-" + spec["workloadId"]

    def start(self, workload_id: str, *, timeout: int | None = None) -> None:
        self.containers[workload_id]["running"] = True

    def stop(self, workload_id: str, *, timeout: int = 2) -> None:
        if workload_id in self.containers:
            self.containers[workload_id]["running"] = False
            self.containers[workload_id]["exitStatus"] = 137
            self.stopped.append(workload_id)

    def kill(self, workload_id: str) -> None:
        self.stop(workload_id, timeout=0)

    def remove(self, workload_id: str, *, force: bool = True) -> None:
        self.containers.pop(workload_id, None)
        self.removed.append(workload_id)

    def inspect(self, workload_id: str) -> dict[str, Any]:
        item = self.containers.get(workload_id)
        if item is None:
            return {"present": False}
        return {
            "present": True,
            "status": "running" if item["running"] else "exited",
            "running": item["running"],
            "exitStatus": item["exitStatus"],
            "startedAt": None,
            "finishedAt": None,
            "imageDigest": item["imageDigest"],
            "imageReference": item["imageReference"],
            "labels": item["labels"],
        }

    def verify_workspace_volumes(self, spec: Mapping[str, Any]) -> None:
        if not self.volume_claims_valid:
            raise EngineError("foreign workspace volume claim")

    @staticmethod
    def resource_enforcement(spec: Mapping[str, Any]) -> dict[str, Any]:
        if spec["kind"] != "workspace":
            return {}
        return {
            "persistentVolumeDiskMaxBytes": {
                "status": "unsupported",
                "requestedBytes": spec["parameters"].get("diskMaxBytes", 268435456),
            }
        }

    def logs(self, workload_id: str, *, max_bytes: int) -> dict[str, Any]:
        data = b"fake-output" * 100
        return {
            "bytes": data[:max_bytes].decode(),
            "byteCount": min(len(data), max_bytes),
            "truncated": len(data) > max_bytes,
        }

    def list_managed(self) -> list[dict[str, Any]]:
        return [
            {
                "workloadId": workload_id,
                "state": "running" if item["running"] else "exited",
                "labels": item["labels"],
            }
            for workload_id, item in self.containers.items()
        ]


def spec(workload_id: str = "wl-test", kind: str = "terminal", **changes: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "kind": kind,
        "workloadId": workload_id,
        "image": {"reference": IMAGE},
        "parameters": {"sessionId": "sess-1", "workSeconds": 60, "emitBytes": 0},
        "timeoutSeconds": 30,
        "outputByteBound": 4096,
        "resources": {"memoryMaxBytes": 268435456, "pidsMax": 128},
    }
    if kind == "agent-run":
        value["parameters"] = {"runSpecDigest": DIGEST, "statePackReference": "statepack:test", "workSeconds": 60, "emitBytes": 0}
        value["resources"] = {
            "memoryMaxBytes": 268435456,
            "cpuQuotaPercent": 100,
            "pidsMax": 128,
            "diskMaxBytes": 67108864,
        }
    value.update(changes)
    return value


def validator_spec(
    workload_id: str = "validator-unit",
    *,
    cpu_quota_percent: int = 100,
    disk_max_bytes: int = 67108864,
) -> dict[str, Any]:
    command = ["python3", "-c", "pass"]
    return {
        "kind": "validator-run",
        "workloadId": workload_id,
        "image": {"reference": IMAGE},
        "parameters": {
            "validatorId": "validator.unit",
            "validatorSpecDigest": DIGEST,
            "stagingIdentityDigest": DIGEST,
            "stagingPath": "/tmp/validator-unit",
            "commandDigest": contract.canonical_digest(command),
            "command": command,
            "network": "disabled",
            "stagingReadOnly": True,
            "providerAccess": False,
            "runtimeSocketAccess": False,
            "hostMounts": [],
        },
        "timeoutSeconds": 30,
        "outputByteBound": 4096,
        "resources": {
            "memoryMaxBytes": 268435456,
            "cpuQuotaPercent": cpu_quota_percent,
            "pidsMax": 128,
            "diskMaxBytes": disk_max_bytes,
        },
    }


# --------------------------------------------------------------- contract


def test_sealed_spec_accepts_every_kind() -> None:
    for kind, identity in (
        ("agent-run", {"runSpecDigest": DIGEST, "statePackReference": "statepack:test"}),
        ("capsule-service", {"serviceName": "svc-1"}),
        ("browser-journey", {"journeyId": "journey-1"}),
        ("terminal", {"sessionId": "sess-1"}),
    ):
        validated = contract.validate_workload_spec(
            spec(kind=kind, parameters={**identity, "workSeconds": 5, "emitBytes": 0})
        )
        assert validated["kind"] == kind


@pytest.mark.parametrize(
    "mutation",
    [
        lambda resources: resources.pop("cpuQuotaPercent"),
        lambda resources: resources.update({"burstCpuPercent": 100}),
    ],
)
def test_agent_run_resources_are_exact_and_complete(mutation) -> None:
    workload = spec("agent-resources", kind="agent-run")
    expected = dict(workload["resources"])
    assert contract.validate_workload_spec(workload)["resources"] == expected
    mutation(workload["resources"])
    with pytest.raises(ValueError, match="resources has an invalid shape"):
        contract.validate_workload_spec(workload)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda s: s.update(kind="arbitrary-shell"),
        lambda s: s.update(command=["rm", "-rf", "/"]),
        lambda s: s["image"].update(reference="docker.io/library/python:latest"),
        lambda s: s.update(timeoutSeconds=0),
        lambda s: s.update(outputByteBound=contract.MAX_OUTPUT_BYTES + 1),
        lambda s: s["parameters"].update(workSeconds=contract.MAX_WORK_SECONDS + 1),
        lambda s: s.update(apiKey="nope"),
        lambda s: s["resources"].update(pidsMax=4),
    ],
)
def test_sealed_spec_refuses_escape_hatches(mutation) -> None:
    value = spec()
    mutation(value)
    with pytest.raises(ValueError):
        contract.validate_workload_spec(value)


def test_request_envelope_and_digest_binding() -> None:
    request = {
        "formatVersion": contract.OPERATION_FORMAT,
        "operationId": "op-1",
        "operation": "createWorkload",
        "requester": {"grantId": "grant-1", "authorityGrantDigest": DIGEST},
        "timeoutSeconds": 30,
        "outputByteBound": 4096,
        "payload": {"workload": spec()},
    }
    validated = contract.validate_operation_request(request)
    assert validated["operation"] == "createWorkload"
    payload = contract.validate_request_payload(validated, request["payload"])
    assert payload["workload"]["workloadId"] == "wl-test"
    assert contract.canonical_digest(request) == contract.canonical_digest(dict(request))
    broken = dict(request, operation="execShell")
    with pytest.raises(ValueError):
        contract.validate_operation_request(broken)
    workload_too_slow = dict(request, timeoutSeconds=601)
    with pytest.raises(ValueError, match="timeoutSeconds"):
        contract.validate_operation_request(workload_too_slow)
    deployment_request = dict(
        request,
        operation="applyDeployment",
        timeoutSeconds=1200,
    )
    assert contract.validate_operation_request(deployment_request)[
        "timeoutSeconds"
    ] == 1200


def test_validator_command_digest_is_recomputed_at_admission() -> None:
    workload = validator_spec()
    workload["parameters"]["commandDigest"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError, match="commandDigest does not match"):
        contract.validate_workload_spec(workload)


def test_public_schema_is_operation_and_workload_kind_conditional() -> None:
    schema = json.loads(
        (ROOT / "schemas" / "execution-host-operation.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    validator = jsonschema.Draft202012Validator(schema)

    def request(operation: str, payload: Any = None, *, include_payload: bool = True):
        value = {
            "formatVersion": contract.OPERATION_FORMAT,
            "operationId": "schema-op",
            "operation": operation,
            "requester": {"grantId": "grant-1", "authorityGrantDigest": DIGEST},
            "timeoutSeconds": 30,
            "outputByteBound": 4096,
        }
        if include_payload:
            value["payload"] = payload
        return value

    valid = request("runValidator", {"workload": validator_spec()})
    validator.validate(valid)
    normalized_request = contract.validate_operation_request(valid)
    contract.validate_request_payload(normalized_request, valid["payload"])
    workload_too_slow = deepcopy(valid)
    workload_too_slow["timeoutSeconds"] = 601
    assert list(validator.iter_errors(workload_too_slow))
    valid_workloads = [
        spec("schema-agent", kind="agent-run"),
        spec(
            "schema-service",
            kind="capsule-service",
            parameters={"serviceName": "service-1"},
        ),
        spec(
            "schema-browser",
            kind="browser-journey",
            parameters={"journeyId": "journey-1"},
        ),
        spec("schema-terminal"),
        wspec("schema-workspace", parameters={"shell": ["/bin/sh"]}),
        validator_spec("schema-validator"),
    ]
    for workload in valid_workloads:
        validator.validate(request("createWorkload", {"workload": workload}))

    invalid_requests = [
        request("createWorkload", include_payload=False),
        request("describeCapabilities", {}),
        request("start", {"workloadId": "wl-1", "rows": 24}),
        request("runValidator", {"workload": spec("wl-terminal")}),
    ]
    missing_validator_resources = validator_spec("validator-missing-resources")
    missing_validator_resources["resources"].pop("cpuQuotaPercent")
    invalid_requests.append(
        request("runValidator", {"workload": missing_validator_resources})
    )
    missing_agent_resources = spec("agent-missing-resources", kind="agent-run")
    missing_agent_resources["resources"].pop("diskMaxBytes")
    invalid_requests.append(
        request("createWorkload", {"workload": missing_agent_resources})
    )
    extra_agent_resources = spec("agent-extra-resources", kind="agent-run")
    extra_agent_resources["resources"]["burstCpuPercent"] = 100
    invalid_requests.append(
        request("createWorkload", {"workload": extra_agent_resources})
    )
    wrong_kind_parameters = spec("wl-shape")
    wrong_kind_parameters["parameters"]["workspaceId"] = "wl-shape"
    invalid_requests.append(
        request("createWorkload", {"workload": wrong_kind_parameters})
    )
    relative_workspace_shell = wspec(
        "ws-relative-shell", parameters={"shell": ["sh"]}
    )
    invalid_requests.append(
        request("createWorkload", {"workload": relative_workspace_shell})
    )
    for value in invalid_requests:
        assert list(validator.iter_errors(value)), value
        with pytest.raises(ValueError):
            normalized = contract.validate_operation_request(value)
            contract.validate_request_payload(normalized, value.get("payload"))


def test_receipt_validation_round_trip() -> None:
    receipt = contract.refusal_receipt(
        DIGEST,
        "op-1",
        {"uid": 1, "gid": 1, "pid": 2, "grantId": "grant-1"},
        "contract-violation",
        "bad shape",
        received_at="2026-08-02T00:00:00Z",
        completed_at="2026-08-02T00:00:01Z",
    )
    assert contract.validate_receipt(receipt)["accepted"] is False


def test_deployment_operation_ledger_replays_exact_terminal_receipt(
    tmp_path: Path,
) -> None:
    ledger = OperationLedger(tmp_path)
    request = {
        "operationId": "deployment-operation-1",
        "operation": "observeDeployment",
        "payload": {"deploymentId": "deployment-1"},
    }
    request_digest = contract.canonical_digest(request)
    requester = {"uid": 1, "gid": 2, "pid": 3, "grantId": "grant-1"}
    admitted = ledger.admit_deployment_operation(
        request,
        request_digest=request_digest,
        requester=requester,
        at="2026-08-02T00:00:00Z",
    )
    assert admitted == {"status": "admitted", "receipt": None}
    assert ledger.admit_deployment_operation(
        request,
        request_digest=request_digest,
        requester=requester,
        at="2026-08-02T00:00:01Z",
    ) == {"status": "in-progress", "receipt": None}

    receipt = contract.refusal_receipt(
        request_digest,
        request["operationId"],
        requester,
        "deployment-effect-failed",
        "bounded failure",
        received_at="2026-08-02T00:00:00Z",
        completed_at="2026-08-02T00:00:02Z",
    )
    ledger.complete_deployment_operation(
        request["operationId"],
        request_digest=request_digest,
        receipt=receipt,
        at="2026-08-02T00:00:02Z",
    )
    replay = ledger.admit_deployment_operation(
        request,
        request_digest=request_digest,
        requester=requester,
        at="2026-08-02T00:00:03Z",
    )
    assert replay == {"status": "replay", "receipt": receipt}
    with pytest.raises(LedgerError, match="reused for a different request"):
        ledger.admit_deployment_operation(
            request,
            request_digest="sha256:" + "f" * 64,
            requester=requester,
            at="2026-08-02T00:00:04Z",
        )


def test_deployment_operation_ledger_interrupts_without_replaying_effect(
    tmp_path: Path,
) -> None:
    ledger = OperationLedger(tmp_path)
    request = {
        "operationId": "deployment-operation-interrupted",
        "operation": "applyDeployment",
        "payload": {"deploymentId": "deployment-1"},
    }
    request_digest = contract.canonical_digest(request)
    requester = {"uid": 1, "gid": 2, "pid": 3, "grantId": "grant-1"}
    ledger.admit_deployment_operation(
        request,
        request_digest=request_digest,
        requester=requester,
        at="2026-08-02T00:00:00Z",
    )

    assert ledger.interrupt_deployment_operations(
        at="2026-08-02T00:01:00Z"
    ) == [request["operationId"]]
    replay = ledger.admit_deployment_operation(
        request,
        request_digest=request_digest,
        requester=requester,
        at="2026-08-02T00:02:00Z",
    )
    receipt = contract.validate_receipt(replay["receipt"])
    assert replay["status"] == "replay"
    assert receipt["accepted"] is True
    assert receipt["result"]["failure"]["code"] == "operation-interrupted"
    assert receipt["result"]["failure"]["details"] == {
        "runtimeEffectUncertain": True,
        "automaticReplay": False,
    }


# ------------------------------------------------------------------ engine


def test_create_argv_is_hardened_and_sealed() -> None:
    argv = build_create_argv(contract.validate_workload_spec(spec()))
    assert "--privileged" not in argv
    assert "--network" in argv and argv[argv.index("--network") + 1] == "none"
    assert "--read-only" in argv
    assert "--cap-drop" in argv
    assert argv[argv.index("--cpus") + 1] == "1.0"
    assert argv[argv.index("--tmpfs") + 1] == "/tmp:rw,noexec,nosuid,nodev,size=16777216"
    joined = " ".join(argv)
    assert "podman.sock" not in joined and "docker.sock" not in joined
    with pytest.raises(EngineError):
        from execution_host.engine import assert_create_argv_hardened

        assert_create_argv_hardened(["create", "--privileged", IMAGE])


def test_agent_run_create_argv_enforces_exact_cpu_and_writable_disk() -> None:
    resources = {
        "memoryMaxBytes": 268435456,
        "cpuQuotaPercent": 175,
        "pidsMax": 128,
        "diskMaxBytes": 2 * 1024**3,
    }
    argv = build_create_argv(
        contract.validate_workload_spec(
            spec("agent-limits", kind="agent-run", resources=resources)
        )
    )
    assert argv[argv.index("--cpus") + 1] == "1.75"
    assert argv[argv.index("--tmpfs") + 1] == (
        "/tmp:rw,noexec,nosuid,nodev,size=2147483648"
    )
    assert argv.count("--tmpfs") == 1
    assert "--read-only" in argv
    assert "--volume" not in argv and "--mount" not in argv


@pytest.mark.parametrize(
    "socket_path",
    ["/run/podman/podman.sock", "/var/run/docker.sock", "relative.sock"],
)
def test_engine_refuses_control_plane_and_relative_sockets(socket_path: str) -> None:
    with pytest.raises(EngineError):
        PodmanCliEngine(socket_path=socket_path)


def test_engine_uses_owned_socket_via_container_host() -> None:
    engine = PodmanCliEngine(socket_path="/run/stateport-engine/podman.sock")
    env = engine._env()
    assert env["CONTAINER_HOST"] == "unix:///run/stateport-engine/podman.sock"
    assert "DOCKER_HOST" not in env


# --------------------------------------------------------- crash recovery


def _ledger_with(state_dir: Path, workload_id: str, state: str) -> OperationLedger:
    ledger = OperationLedger(state_dir)
    entry = ledger.record_created(
        contract.validate_workload_spec(spec(workload_id)), at="2026-08-02T00:00:00Z", container_id="c"
    )
    if state != "created":
        ledger.transition(workload_id, state, at="2026-08-02T00:00:01Z")
    return ledger


@pytest.mark.parametrize("container_present", [True, False])
def test_recovery_interrupts_non_terminal_workloads(tmp_path: Path, container_present: bool) -> None:
    ledger = _ledger_with(tmp_path, "wl-crash", "running")
    engine = FakeEngine()
    if container_present:
        engine.create(spec("wl-crash"))
        engine.start("wl-crash")
    report = reconcile_on_boot(ledger, engine, at="2026-08-02T01:00:00Z")
    assert report["interrupted"] == ["wl-crash"]
    assert ledger.get("wl-crash")["state"] == "interrupted"
    assert ledger.get("wl-crash")["receipts"][-1]["kind"] == "restart-recovery"
    assert "wl-crash" not in engine.containers


def test_recovery_removes_orphan_containers_and_terminal_leftovers(tmp_path: Path) -> None:
    ledger = _ledger_with(tmp_path, "wl-done", "exited")
    engine = FakeEngine()
    engine.create(spec("wl-done"))  # leftover container for a terminal entry
    engine.create(spec("wl-ghost"))  # orphan with no ledger entry at all
    report = reconcile_on_boot(ledger, engine, at="2026-08-02T01:00:00Z")
    assert sorted(report["orphansRemoved"]) == ["wl-done", "wl-ghost"]
    assert engine.containers == {}
    assert ledger.get("wl-done")["state"] == "exited"


def test_recovery_refuses_label_stripped_ephemeral_container(tmp_path: Path) -> None:
    ledger = _ledger_with(tmp_path, "wl-foreign", "running")
    engine = FakeEngine()
    engine.create(spec("wl-foreign"))
    engine.start("wl-foreign")
    engine.containers["wl-foreign"]["labels"].pop(MANAGED_LABEL_KEY)
    report = reconcile_on_boot(ledger, engine, at="2026-08-02T01:00:00Z")
    assert report["failures"]
    assert report["interrupted"] == []
    assert ledger.get("wl-foreign")["state"] == "running"
    assert engine.containers["wl-foreign"]["running"] is True


def test_recovery_journal_is_durable(tmp_path: Path) -> None:
    ledger = _ledger_with(tmp_path / "sub", "wl-journal", "running")
    reconcile_on_boot(ledger, FakeEngine(), at="2026-08-02T01:00:00Z")
    journal = list((tmp_path / "sub" / "recovery").glob("recovery-*.json"))
    assert len(journal) == 1
    assert json.loads(journal[0].read_text())["report"]["interrupted"] == ["wl-journal"]


# ------------------------------------------------- supervision over socket


def _boot(
    tmp_path: Path,
    engine: FakeEngine,
    interval: float = 0.05,
    *,
    clock: Any = None,
) -> ExecutionHostDaemon:
    socket_dir = tmp_path / "execution-control"
    socket_dir.mkdir()
    os.chmod(socket_dir, 0o750)
    config = DaemonConfig(
        socket_path=socket_dir / "control.sock",
        state_dir=tmp_path / "state",
        socket_group_gid=os.getegid(),
        supervise_interval_seconds=interval,
        **({"clock": clock} if clock is not None else {}),
    )
    daemon = ExecutionHostDaemon(config, engine)
    daemon.boot()
    import threading

    threading.Thread(target=daemon.serve_forever, daemon=True).start()
    return daemon


GRANT_ID = "grant-test"
EXPIRES = "2099-01-01T00:00:00Z"


def grant_document(workloads: list[Any], **changes: Any) -> dict[str, Any]:
    """Build a grant document binding every listed workload's exact spec.

    Items may be workload ids (bound to the default ``spec(id)``) or raw
    spec mappings.  Digests are computed over the contract-validated spec,
    exactly what the daemon verifies.
    """
    ids: list[str] = []
    digests: dict[str, str] = {}
    for item in workloads:
        raw = item if isinstance(item, dict) else spec(item)
        validated = contract.validate_workload_spec(raw)
        ids.append(validated["workloadId"])
        digests[validated["workloadId"]] = contract.canonical_digest(validated)
    doc: dict[str, Any] = {
        "formatVersion": contract.GRANT_FORMAT,
        "grantId": GRANT_ID,
        "peerUid": os.geteuid(),
        "operations": [
            operation
            for operation in contract.OPERATIONS
            if operation not in contract.DEPLOYMENT_OPERATIONS
        ],
        "workloadIds": ids,
        "workloadKinds": list(contract.WORKLOAD_KINDS),
        "workloadSpecDigests": digests,
        "imageReference": IMAGE,
        "baseRevision": None,
        "issuedAt": "2026-08-08T00:00:00Z",
        "expiresAt": EXPIRES,
        "revocationEpoch": 0,
        "budgets": {
            "maxTimeoutSeconds": 3600,
            "maxOutputBytes": 4194304,
            "maxMemoryMaxBytes": 1073741824,
            "maxPidsMax": 512,
            "maxActiveWorkloads": 8,
            "maxCpuQuotaPercent": 800,
            "maxDiskMaxBytes": 4 * 1024**3,
        },
    }
    doc.update(changes)
    return doc


def provision_grants(tmp_path: Path, *docs: dict[str, Any]) -> None:
    grants_dir = tmp_path / "state" / "grants"
    grants_dir.mkdir(parents=True, exist_ok=True)
    for doc in docs:
        (grants_dir / f"{doc['grantId']}.json").write_text(
            json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )


def write_revocation(tmp_path: Path, **changes: Any) -> None:
    grants_dir = tmp_path / "state" / "grants"
    grants_dir.mkdir(parents=True, exist_ok=True)
    doc = {"revokedGrantIds": [], "pausedGrantIds": [], "revocationEpoch": 0}
    doc.update(changes)
    (grants_dir / "revocation.json").write_text(
        json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _client(tmp_path: Path, doc: dict[str, Any] | None = None, **changes: Any) -> ExecutionHostClient:
    doc = doc if doc is not None else grant_document(["wl-placeholder"])
    digest = changes.pop("authority_grant_digest", contract.canonical_digest(doc))
    return ExecutionHostClient(
        tmp_path / "execution-control" / "control.sock",
        grant_id=doc["grantId"],
        authority_grant_digest=digest,
        **changes,
    )


def test_daemon_lifecycle_timeout_and_cancel_over_socket(tmp_path: Path) -> None:
    engine = FakeEngine()
    daemon = _boot(tmp_path, engine)
    try:
        doc = grant_document(["wl-unit"])
        provision_grants(tmp_path, doc)
        client = _client(tmp_path, doc)
        capabilities = client.describe_capabilities()
        capability_schema = json.loads(
            (ROOT / "schemas" / "execution-host-contract.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        jsonschema.Draft202012Validator(capability_schema).validate(
            capabilities["result"]
        )
        assert capabilities["result"]["sealedWorkloadsOnly"] is True
        assert capabilities["result"]["providerAccess"] is False
        assert capabilities["result"]["publicNetwork"] is False
        assert capabilities["result"]["peerIdentity"]["mechanism"] == "SO_PEERCRED"
        assert capabilities["result"]["transport"] == "confined-host-unix-socket"
        receipt = client.create_workload(spec("wl-unit"))
        assert receipt["result"]["state"] == "created"
        client.start("wl-unit")
        assert client.status("wl-unit")["result"]["state"] == "running"
        logs = _client(tmp_path, doc, output_byte_bound=64).logs("wl-unit")
        assert logs["result"]["truncated"] is True
        assert logs["result"]["byteCount"] == 64
        assert logs["result"]["outputByteBound"] == 64
        client.cancel("wl-unit")
        assert client.status("wl-unit")["result"]["state"] == "cancelled"
        client.remove_workload("wl-unit")
        assert "wl-unit" not in engine.containers
        garbage = client.collect_garbage()
        assert garbage["result"]["removedWorkloads"] == []
    finally:
        daemon.shutdown()


def test_supervision_marks_timeout(tmp_path: Path) -> None:
    engine = FakeEngine()
    daemon = _boot(tmp_path, engine)
    try:
        doc = grant_document([spec("wl-slow", timeoutSeconds=1)])
        provision_grants(tmp_path, doc)
        client = _client(tmp_path, doc)
        client.create_workload(spec("wl-slow", timeoutSeconds=1))
        client.start("wl-slow")
        deadline = time.time() + 10
        state = "running"
        while time.time() < deadline:
            state = client.status("wl-slow")["result"]["state"]
            if state == "timed_out":
                break
            time.sleep(0.1)
        assert state == "timed_out"
        entry = OperationLedger(tmp_path / "state").get("wl-slow")
        assert entry["receipts"][-1]["kind"] == "supervision-timeout"
    finally:
        daemon.shutdown()


def test_refusals_are_typed(tmp_path: Path) -> None:
    daemon = _boot(tmp_path, FakeEngine())
    try:
        doc = grant_document(["wl-dupe", "wl-missing"])
        provision_grants(tmp_path, doc)
        client = _client(tmp_path, doc)
        with pytest.raises(ExecutionHostRefusal, match="unknown-workload"):
            client.status("wl-missing")
        client.create_workload(spec("wl-dupe"))
        with pytest.raises(ExecutionHostRefusal, match="duplicate-workload"):
            client.create_workload(spec("wl-dupe"))
        client.start("wl-dupe")
        with pytest.raises(ExecutionHostRefusal, match="invalid-state"):
            client.start("wl-dupe")
    finally:
        daemon.shutdown()


# ------------------------------------------------------- grant enforcement


def _refusal(tmp_path: Path, doc: dict[str, Any], action: Any, **client_changes: Any) -> str:
    daemon = _boot(tmp_path, FakeEngine())
    try:
        if doc is not None:
            provision_grants(tmp_path, doc)
        client = _client(tmp_path, doc, **client_changes)
        with pytest.raises(ExecutionHostRefusal) as captured:
            action(client)
        return captured.value.reason
    finally:
        daemon.shutdown()


def test_grant_unknown_is_refused(tmp_path: Path) -> None:
    doc = grant_document(["wl-x"])
    # Nothing provisioned: the grant id has no stored document.
    reason = _refusal(tmp_path, None, lambda c: c.status("wl-x"))
    assert reason == "grant-unknown"


def test_fabricated_grant_digest_is_refused(tmp_path: Path) -> None:
    doc = grant_document(["wl-x"])
    reason = _refusal(
        tmp_path, doc, lambda c: c.status("wl-x"), authority_grant_digest=DIGEST
    )
    assert reason == "grant-digest-mismatch"


def test_grant_bound_to_other_peer_is_refused(tmp_path: Path) -> None:
    doc = grant_document(["wl-x"], peerUid=os.geteuid() + 1)
    reason = _refusal(tmp_path, doc, lambda c: c.status("wl-x"))
    assert reason == "grant-peer-mismatch"


def test_operation_outside_grant_is_refused(tmp_path: Path) -> None:
    doc = grant_document(["wl-x"], operations=["status"])
    reason = _refusal(tmp_path, doc, lambda c: c.cancel("wl-x"))
    assert reason == "grant-operation-denied"


def test_deployment_operations_require_an_explicit_v2_scope() -> None:
    doc = grant_document(["wl-x"], operations=["probeDeploymentTarget"])
    with pytest.raises(ValueError, match="requires a v2 deploymentScope"):
        contract.validate_grant_document(doc)

    doc["deploymentScope"] = {
        "authorityMode": "canonical-control-plane",
        "targetAdapter": "rootless-podman-local",
        "targetId": "local",
        "allowDataPurge": False,
        "maxArchiveBytes": contract.MAX_DEPLOYMENT_ARCHIVE_BYTES,
        "maxFiles": contract.MAX_DEPLOYMENT_FILES,
    }
    assert contract.validate_grant_document(doc)["deploymentScope"] == doc[
        "deploymentScope"
    ]


def test_legacy_workload_only_grant_remains_valid() -> None:
    doc = grant_document(["wl-x"], operations=["status"])
    doc["formatVersion"] = contract.LEGACY_GRANT_FORMAT
    assert contract.validate_grant_document(doc)["formatVersion"] == (
        contract.LEGACY_GRANT_FORMAT
    )


def test_workload_outside_grant_scope_is_refused(tmp_path: Path) -> None:
    doc = grant_document(["wl-allowed"])
    reason = _refusal(tmp_path, doc, lambda c: c.status("wl-other"))
    assert reason == "grant-workspace-mismatch"


def test_expired_grant_is_refused(tmp_path: Path) -> None:
    doc = grant_document(["wl-x"], expiresAt="2020-01-01T00:00:00Z")
    reason = _refusal(tmp_path, doc, lambda c: c.status("wl-x"))
    assert reason == "grant-expired"


def test_revoked_and_paused_grants_are_refused(tmp_path: Path) -> None:
    doc = grant_document(["wl-x"])
    daemon = _boot(tmp_path, FakeEngine())
    try:
        provision_grants(tmp_path, doc)
        client = _client(tmp_path, doc)
        with pytest.raises(ExecutionHostRefusal, match="unknown-workload"):
            client.status("wl-x")  # authorized, but no ledger entry yet
        write_revocation(tmp_path, revokedGrantIds=[GRANT_ID])
        with pytest.raises(ExecutionHostRefusal, match="grant-revoked"):
            client.status("wl-x")
        write_revocation(tmp_path, pausedGrantIds=[GRANT_ID])
        with pytest.raises(ExecutionHostRefusal, match="grant-paused"):
            client.status("wl-x")
        # Monotonic epoch: a grant minted at epoch 0 dies at store epoch 1.
        write_revocation(tmp_path, revocationEpoch=1)
        with pytest.raises(ExecutionHostRefusal, match="grant-revoked"):
            client.status("wl-x")
    finally:
        daemon.shutdown()


def test_wrong_image_is_refused_before_engine_access(tmp_path: Path) -> None:
    other_image = f"docker.io/library/alpine@sha256:{'c' * 64}"
    doc = grant_document(["wl-x"], imageReference=other_image)
    engine = FakeEngine()
    daemon = _boot(tmp_path, engine)
    try:
        provision_grants(tmp_path, doc)
        client = _client(tmp_path, doc)
        with pytest.raises(ExecutionHostRefusal, match="grant-image-mismatch"):
            client.create_workload(spec("wl-x"))
        assert engine.containers == {}
    finally:
        daemon.shutdown()


def test_grant_budgets_are_enforced(tmp_path: Path) -> None:
    doc = grant_document(
        ["wl-fat"],
        budgets={
            "maxTimeoutSeconds": 10,
            "maxOutputBytes": 4194304,
            "maxMemoryMaxBytes": 1073741824,
            "maxPidsMax": 512,
            "maxActiveWorkloads": 8,
            "maxCpuQuotaPercent": 800,
            "maxDiskMaxBytes": 4 * 1024**3,
        },
    )
    reason = _refusal(
        tmp_path, doc, lambda c: c.create_workload(spec("wl-fat", timeoutSeconds=30))
    )
    assert reason == "grant-budget-exceeded"


@pytest.mark.parametrize(
    ("budgets", "client_changes"),
    [
        ({"maxTimeoutSeconds": 10}, {"timeout_seconds": 30}),
        ({"maxOutputBytes": 1024}, {"output_byte_bound": 2048}),
    ],
)
def test_grant_budgets_cover_every_request_envelope(
    tmp_path: Path,
    budgets: dict[str, int],
    client_changes: dict[str, int],
) -> None:
    doc = grant_document(["wl-envelope"])
    doc["budgets"].update(budgets)
    reason = _refusal(
        tmp_path,
        doc,
        lambda client: client.status("wl-envelope"),
        **client_changes,
    )
    assert reason == "grant-budget-exceeded"


def test_grant_active_workload_budget_is_enforced(tmp_path: Path) -> None:
    doc = grant_document(
        ["wl-one", "wl-two"],
        budgets={
            "maxTimeoutSeconds": 3600,
            "maxOutputBytes": 4194304,
            "maxMemoryMaxBytes": 1073741824,
            "maxPidsMax": 512,
            "maxActiveWorkloads": 1,
            "maxCpuQuotaPercent": 800,
            "maxDiskMaxBytes": 4 * 1024**3,
        },
    )
    daemon = _boot(tmp_path, FakeEngine())
    try:
        provision_grants(tmp_path, doc)
        client = _client(tmp_path, doc)
        client.create_workload(spec("wl-one"))
        with pytest.raises(ExecutionHostRefusal, match="grant-budget-exceeded"):
            client.create_workload(spec("wl-two"))
        client.cancel("wl-one")
        # The terminal workload frees the action budget.
        client.create_workload(spec("wl-two"))
    finally:
        daemon.shutdown()


def test_grant_base_revision_binding(tmp_path: Path) -> None:
    base = "d" * 40
    bound = spec("wl-run", kind="agent-run")
    bound["parameters"]["baseRevision"] = base
    doc = grant_document([bound], baseRevision=base)
    daemon = _boot(tmp_path, FakeEngine())
    try:
        provision_grants(tmp_path, doc)
        client = _client(tmp_path, doc)
        with pytest.raises(ExecutionHostRefusal, match="grant-base-revision-mismatch"):
            client.create_workload(spec("wl-run", kind="agent-run"))
        assert client.create_workload(bound)["result"]["state"] == "created"
    finally:
        daemon.shutdown()


def test_describe_capabilities_stays_peer_gated_without_grant(tmp_path: Path) -> None:
    daemon = _boot(tmp_path, FakeEngine())
    try:
        client = _client(tmp_path)
        assert client.describe_capabilities()["result"]["sealedWorkloadsOnly"] is True
    finally:
        daemon.shutdown()


def test_capacity_counts_active_not_history(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(contract, "MAX_WORKLOADS", 2)
    doc = grant_document(["wl-a", "wl-b", "wl-c"])
    daemon = _boot(tmp_path, FakeEngine())
    try:
        provision_grants(tmp_path, doc)
        client = _client(tmp_path, doc)
        client.create_workload(spec("wl-a"))
        client.create_workload(spec("wl-b"))
        with pytest.raises(ExecutionHostRefusal, match="workload-limit"):
            client.create_workload(spec("wl-c"))
        client.cancel("wl-a")
        # wl-a is terminal; history must not consume capacity.
        client.create_workload(spec("wl-c"))
    finally:
        daemon.shutdown()


# ------------------------------------------------------- cleanup supervision


class FlakyKillEngine(FakeEngine):
    def __init__(self, failures: int) -> None:
        super().__init__()
        self._failures = failures
        self.kill_attempts = 0
        self.stop_attempts = 0

    def kill(self, workload_id: str) -> None:
        self.kill_attempts += 1
        if self.kill_attempts <= self._failures:
            raise EngineError("simulated engine outage")
        super().kill(workload_id)

    def stop(self, workload_id: str, *, timeout: int = 2) -> None:
        self.stop_attempts += 1
        if self.stop_attempts <= self._failures:
            raise EngineError("simulated engine outage")
        super().stop(workload_id, timeout=timeout)

    def remove(self, workload_id: str, *, force: bool = True) -> None:
        if self.stop_attempts <= self._failures:
            raise EngineError("simulated engine outage")
        super().remove(workload_id, force=force)


class StartHookEngine(FakeEngine):
    def __init__(self, hook: Any) -> None:
        super().__init__()
        self._hook = hook

    def start(self, workload_id: str, *, timeout: int | None = None) -> None:
        super().start(workload_id, timeout=timeout)
        self._hook(workload_id)


class ResidualStartHookEngine(StartHookEngine):
    def stop(self, workload_id: str, *, timeout: int = 2) -> None:
        raise EngineError("simulated stop outage")

    def remove(self, workload_id: str, *, force: bool = True) -> None:
        raise EngineError("simulated remove outage")


def test_cancel_without_verified_absence_enters_supervised_cleanup(tmp_path: Path) -> None:
    engine = FlakyKillEngine(failures=1)
    doc = grant_document(["wl-flaky"])
    daemon = _boot(tmp_path, engine, interval=0.05)
    try:
        provision_grants(tmp_path, doc)
        client = _client(tmp_path, doc)
        client.create_workload(spec("wl-flaky"))
        client.start("wl-flaky")
        receipt = client.cancel("wl-flaky")
        assert receipt["result"]["state"] == "cleanup_failed"
        assert receipt["cleanup"]["outcome"] == "failed"
        entry = OperationLedger(tmp_path / "state").get("wl-flaky")
        assert entry["receipts"][-1]["kind"] == "cancel-cleanup-failure"
        assert entry["receipts"][-1]["residual"]["engine"] == "fake-cli"
        # Supervision retries and recovers the terminal cancellation state.
        deadline = time.time() + 10
        state = "cleanup_failed"
        while time.time() < deadline:
            state = client.status("wl-flaky")["result"]["state"]
            if state == "cancelled":
                break
            time.sleep(0.1)
        assert state == "cancelled"
        entry = OperationLedger(tmp_path / "state").get("wl-flaky")
        assert entry["receipts"][-1]["kind"] == "cleanup-recovered"
    finally:
        daemon.shutdown()


def test_cleanup_escalates_with_residual_evidence(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr("execution_host.daemon.MAX_CLEANUP_RETRY_ATTEMPTS", 2)
    engine = FlakyKillEngine(failures=100)
    doc = grant_document(["wl-stuck"])
    daemon = _boot(tmp_path, engine, interval=0.05)
    try:
        provision_grants(tmp_path, doc)
        client = _client(tmp_path, doc)
        client.create_workload(spec("wl-stuck"))
        client.start("wl-stuck")
        assert client.cancel("wl-stuck")["result"]["state"] == "cleanup_failed"
        deadline = time.time() + 10
        escalated = False
        while time.time() < deadline:
            entry = OperationLedger(tmp_path / "state").get("wl-stuck")
            escalated = bool(entry.get("cleanupEscalated"))
            if escalated:
                break
            time.sleep(0.1)
        assert escalated
        # Non-terminal and supervised: the residual process evidence is exact.
        assert entry["state"] == "cleanup_failed"
        escalation = [r for r in entry["receipts"] if r["kind"] == "cleanup-escalated"]
        assert escalation and escalation[-1]["residual"]["containerPresent"] is True
    finally:
        daemon.shutdown()


def test_start_rechecks_live_authority_after_engine_effect(tmp_path: Path) -> None:
    doc = grant_document(["wl-revoke-at-start"])
    engine = StartHookEngine(
        lambda workload_id: write_revocation(tmp_path, revokedGrantIds=[GRANT_ID])
    )
    daemon = _boot(tmp_path, engine, interval=60)
    try:
        provision_grants(tmp_path, doc)
        client = _client(tmp_path, doc)
        client.create_workload(spec("wl-revoke-at-start"))
        with pytest.raises(ExecutionHostRefusal, match="grant-revoked"):
            client.start("wl-revoke-at-start")
        entry = OperationLedger(tmp_path / "state").get("wl-revoke-at-start")
        assert entry["state"] == "cancelled"
        assert entry["receipts"][-1]["kind"] == "start-authority-conflict"
        assert "wl-revoke-at-start" not in engine.containers
    finally:
        daemon.shutdown()


def test_start_cas_conflict_removes_effect_behind_terminal_state(tmp_path: Path) -> None:
    workload_id = "wl-start-cas"

    def cancel_after_start(current_workload_id: str) -> None:
        ledger = OperationLedger(tmp_path / "state")
        current = ledger.get(current_workload_id)
        ledger.transition(
            current_workload_id,
            "cancelled",
            at="2026-08-08T00:00:05Z",
            finished_at="2026-08-08T00:00:05Z",
            expect_states={current["state"]},
            expect_version=current["version"],
        )

    engine = StartHookEngine(cancel_after_start)
    doc = grant_document([workload_id])
    daemon = _boot(tmp_path, engine, interval=60)
    try:
        provision_grants(tmp_path, doc)
        client = _client(tmp_path, doc)
        client.create_workload(spec(workload_id))
        with pytest.raises(ExecutionHostRefusal, match="state-conflict"):
            client.start(workload_id)
        entry = OperationLedger(tmp_path / "state").get(workload_id)
        assert entry["state"] == "cancelled"
        assert entry["receipts"][-1]["kind"] == "start-cas-conflict"
        assert entry["receipts"][-1]["residual"]["containerPresent"] is False
        assert workload_id not in engine.containers
    finally:
        daemon.shutdown()


def test_start_cas_cleanup_failure_is_nonterminal_and_evidenced(tmp_path: Path) -> None:
    workload_id = "wl-start-residual"

    def cancel_after_start(current_workload_id: str) -> None:
        ledger = OperationLedger(tmp_path / "state")
        current = ledger.get(current_workload_id)
        ledger.transition(
            current_workload_id,
            "cancelled",
            at="2026-08-08T00:00:05Z",
            finished_at="2026-08-08T00:00:05Z",
            expect_states={current["state"]},
            expect_version=current["version"],
        )

    engine = ResidualStartHookEngine(cancel_after_start)
    doc = grant_document([workload_id])
    daemon = _boot(tmp_path, engine, interval=60)
    try:
        provision_grants(tmp_path, doc)
        client = _client(tmp_path, doc)
        client.create_workload(spec(workload_id))
        with pytest.raises(ExecutionHostRefusal, match="state-conflict"):
            client.start(workload_id)
        entry = OperationLedger(tmp_path / "state").get(workload_id)
        assert entry["state"] == "cleanup_failed"
        assert entry["cleanupTargetState"] == "cancelled"
        assert entry["receipts"][-1]["residual"]["containerRunning"] is True
    finally:
        daemon.shutdown()


def test_ledger_transitions_survive_concurrent_writers(tmp_path: Path) -> None:
    import threading

    ledger = OperationLedger(tmp_path / "state")
    ledger.record_created(spec("wl-race"), at="2026-08-08T00:00:00Z", container_id="c1")

    def worker(index: int) -> None:
        for step in range(20):
            ledger.transition(
                "wl-race",
                "running",
                at=f"2026-08-08T00:00:{step:02d}Z",
                receipt={"kind": "race", "detail": f"worker {index} step {step}"},
            )

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    entry = OperationLedger(tmp_path / "state").get("wl-race")
    assert entry["state"] == "running"
    assert len(entry["receipts"]) == 160
    # No fixed-.tmp collision debris remains.
    assert list((tmp_path / "state" / "workloads").glob("*.tmp")) == []


def test_keep_id_translates_confined_host_identities(tmp_path: Path) -> None:
    runtime_uid = os.geteuid()
    runtime_gid = os.getegid()
    uid_map = tmp_path / "uid_map"
    gid_map = tmp_path / "gid_map"
    overflow_uid = tmp_path / "overflowuid"
    overflow_gid = tmp_path / "overflowgid"
    uid_map.write_text(f"{runtime_uid} 0 1\n", encoding="utf-8")
    gid_map.write_text(f"{runtime_gid} 0 1\n", encoding="utf-8")
    overflow_uid.write_text("65534\n", encoding="utf-8")
    overflow_gid.write_text("65534\n", encoding="utf-8")
    config = DaemonConfig(
        socket_path=tmp_path / "execution-control/control.sock",
        state_dir=tmp_path / "state",
        socket_group_gid=runtime_gid + 10,
        allowed_client_uid=runtime_uid + 20,
        allowed_client_gid=runtime_gid + 20,
        runtime_uid=runtime_uid,
        runtime_gid=runtime_gid,
        user_namespace="keep-id",
        socket_directory_mode=0o2750,
        uid_map_path=uid_map,
        gid_map_path=gid_map,
        overflow_uid_path=overflow_uid,
        overflow_gid_path=overflow_gid,
    )
    daemon = ExecutionHostDaemon(config, FakeEngine())

    assert daemon._id_map_has_keep_id(uid_map, runtime_uid)
    assert daemon._id_map_has_keep_id(gid_map, runtime_gid)
    uid_map.write_text(f"{runtime_uid} {runtime_uid} 1\n", encoding="utf-8")
    assert not daemon._id_map_has_keep_id(uid_map, runtime_uid)
    assert daemon._expected_socket_gid() == 65534
    assert daemon._namespace_allowed_client_identity() == (65534, 65534)
    canonical = daemon._canonical_peer_identity({"pid": 12, "uid": 65534, "gid": 65534})
    assert canonical == {
        "pid": 12,
        "uid": runtime_uid + 20,
        "gid": runtime_gid + 20,
    }
    assert daemon._peer_is_authorized(canonical)
    assert not daemon._peer_is_authorized({"pid": 13, "uid": 60000, "gid": 60000})


def test_keep_id_authorizes_the_provisioned_bound_client(tmp_path: Path) -> None:
    runtime_uid = os.geteuid()
    runtime_gid = os.getegid()
    client_uid, client_gid = runtime_uid + 7, runtime_gid + 7
    socket_dir = tmp_path / "execution-control"
    socket_dir.mkdir()
    (socket_dir / CLIENT_IDENTITY_FILE).write_text(
        f"{client_uid}:{client_gid}\n", encoding="utf-8"
    )
    config = DaemonConfig(
        socket_path=socket_dir / "control.sock",
        state_dir=tmp_path / "state",
        socket_group_gid=runtime_gid + 10,
        allowed_client_uid=runtime_uid + 20,
        allowed_client_gid=runtime_gid + 20,
        runtime_uid=runtime_uid,
        runtime_gid=runtime_gid,
        user_namespace="keep-id",
        socket_directory_mode=0o2750,
        uid_map_path=tmp_path / "uid_map",
        gid_map_path=tmp_path / "gid_map",
        overflow_uid_path=tmp_path / "overflowuid",
        overflow_gid_path=tmp_path / "overflowgid",
    )
    daemon = ExecutionHostDaemon(config, FakeEngine())
    assert daemon._bound_client_identity() == (client_uid, client_gid)
    # The real web client is authorized alongside runtime and allowed client.
    assert daemon._peer_is_authorized({"pid": 1, "uid": client_uid, "gid": client_gid})
    canonical = daemon._canonical_peer_identity(
        {"pid": 1, "uid": client_uid, "gid": client_gid}
    )
    assert (canonical["uid"], canonical["gid"]) == (client_uid, client_gid)
    # A peer the transaction never admitted stays refused.
    assert not daemon._peer_is_authorized({"pid": 2, "uid": runtime_uid + 7, "gid": 60000})
    assert not daemon._peer_is_authorized({"pid": 3, "uid": 60000, "gid": runtime_gid + 7})


def test_malformed_client_identity_file_refuses_boot(tmp_path: Path) -> None:
    socket_dir = tmp_path / "execution-control"
    socket_dir.mkdir()
    for content in ("1000\n", "1000:gid\n", "abc:2000\n", "-5:1000\n", "1000:99999999999999\n"):
        (socket_dir / CLIENT_IDENTITY_FILE).write_text(content, encoding="utf-8")
        config = DaemonConfig(
            socket_path=socket_dir / "control.sock",
            state_dir=tmp_path / "state",
            user_namespace="keep-id",
            socket_directory_mode=0o2750,
        )
        daemon = ExecutionHostDaemon(config, FakeEngine())
        with pytest.raises(DaemonBootError, match="confined client identity"):
            daemon._bound_client_identity()
    (socket_dir / CLIENT_IDENTITY_FILE).unlink()
    config = DaemonConfig(
        socket_path=socket_dir / "control.sock",
        state_dir=tmp_path / "state",
        user_namespace="keep-id",
        socket_directory_mode=0o2750,
    )
    daemon = ExecutionHostDaemon(config, FakeEngine())
    assert daemon._bound_client_identity() is None
    # Without a bound identity, an unrelated peer is not admitted by the
    # keep-id mapping (the runtime identity itself stays authorized).
    assert not daemon._peer_is_authorized({"pid": 1, "uid": 12345, "gid": 12345})


def test_boot_refusals(tmp_path: Path) -> None:
    engine = FakeEngine()
    missing = DaemonConfig(
        socket_path=tmp_path / "absent" / "control.sock",
        state_dir=tmp_path / "state",
        socket_group_gid=os.getegid(),
    )
    with pytest.raises(DaemonBootError, match="absent"):
        ExecutionHostDaemon(missing, engine).boot()

    wrong_group_dir = tmp_path / "wrong-group"
    wrong_group_dir.mkdir()
    os.chmod(wrong_group_dir, 0o750)
    wrong_group = DaemonConfig(
        socket_path=wrong_group_dir / "control.sock",
        state_dir=tmp_path / "state",
        socket_group_gid=os.getegid() + 1,
    )
    with pytest.raises(DaemonBootError, match="group confinement failed"):
        ExecutionHostDaemon(wrong_group, engine).boot()

    wrong_mode_dir = tmp_path / "wrong-mode"
    wrong_mode_dir.mkdir()
    os.chmod(wrong_mode_dir, 0o755)
    wrong_mode = DaemonConfig(
        socket_path=wrong_mode_dir / "control.sock",
        state_dir=tmp_path / "state",
        socket_group_gid=os.getegid(),
    )
    with pytest.raises(DaemonBootError, match="0o750"):
        ExecutionHostDaemon(wrong_mode, engine).boot()


def test_client_socket_absent_is_typed(tmp_path: Path) -> None:
    client = _client(tmp_path)
    with pytest.raises(ExecutionHostTransportError, match="socket-absent"):
        client.describe_capabilities()


# ------------------------------------------------------ persistent workspaces


class _FakeTerminalProcess:
    pid = 432198

    def __init__(self) -> None:
        self.killed = False

    def kill(self) -> None:
        self.killed = True

    def wait(self, timeout: float | None = None) -> int:
        return 0


class WorkspaceFakeEngine(FakeEngine):
    """Fake engine with the workspace terminal/exec surface."""

    def __init__(self) -> None:
        super().__init__()
        import pty

        self._pty = pty
        self.terminal_slave_fds: dict[str, int] = {}
        self.resizes: list[tuple[int, int]] = []
        self.exec_calls: list[tuple[str, tuple[str, ...]]] = []

    def open_terminal(self, workload_id: str, *, columns: int, rows: int, shell=("/bin/sh",)):
        import tty

        master_fd, slave_fd = self._pty.openpty()
        # Raw line discipline: the test observes the exact byte path; the
        # signal semantics themselves are covered by the real-Podman suite.
        tty.setraw(slave_fd)
        self.terminal_slave_fds[workload_id] = slave_fd
        self._last_shell = tuple(shell)
        return _FakeTerminalProcess(), master_fd

    def resize_terminal(self, master_fd: int, *, columns: int, rows: int) -> None:
        self.resizes.append((columns, rows))

    def exec_workload(self, workload_id: str, argv, *, timeout: int, max_bytes: int):
        self.exec_calls.append((workload_id, tuple(argv)))
        data = ("fake-exec:" + " ".join(argv)).encode()
        return {
            "exitStatus": 0,
            "output": data[:max_bytes].decode(),
            "byteCount": min(len(data), max_bytes),
            "truncated": len(data) > max_bytes,
        }


class BlockingIdleStopEngine(WorkspaceFakeEngine):
    """Expose the window after an idle stop effect but before its receipt."""

    def __init__(self, workload_id: str) -> None:
        super().__init__()
        self._blocked_workload_id = workload_id
        self.stop_effect_applied = threading.Event()
        self.release_stop = threading.Event()

    def stop(self, workload_id: str, *, timeout: int = 2) -> None:
        super().stop(workload_id, timeout=timeout)
        if workload_id != self._blocked_workload_id:
            return
        self.stop_effect_applied.set()
        if not self.release_stop.wait(10):
            raise EngineError("test did not release the blocked idle stop")


def wspec(workload_id: str, **changes: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "kind": "workspace",
        "workloadId": workload_id,
        "image": {"reference": IMAGE},
        "parameters": {
            "workspaceId": workload_id,
            "workspaceSpecDigest": DIGEST,
            "volumeName": f"stateport-workspace-{workload_id}",
            "workSeconds": 0,
            "emitBytes": 0,
        },
        "timeoutSeconds": 600,
        "outputByteBound": 4096,
        "resources": {"memoryMaxBytes": 268435456, "pidsMax": 128},
    }
    parameters = changes.pop("parameters", {})
    value.update(changes)
    value["parameters"].update(parameters)
    return value


def _wait_client_state(client: ExecutionHostClient, workload_id: str, state: str, timeout: float = 10.0) -> str:
    deadline = time.time() + timeout
    current = "unknown"
    while time.time() < deadline:
        current = client.status(workload_id)["result"]["state"]
        if current == state:
            return current
        time.sleep(0.1)
    raise AssertionError(f"{workload_id} never reached {state}; last={current}")


def test_workspace_lifecycle_stop_restart_remove_preserves_volume(tmp_path: Path) -> None:
    engine = WorkspaceFakeEngine()
    daemon = _boot(tmp_path, engine)
    try:
        doc = grant_document([wspec("ws-unit")])
        provision_grants(tmp_path, doc)
        client = _client(tmp_path, doc)
        created = client.create_workspace(wspec("ws-unit"))
        assert created["result"]["state"] == "created"
        disk_enforcement = created["result"]["resourceEnforcement"][
            "persistentVolumeDiskMaxBytes"
        ]
        assert disk_enforcement["status"] == "unsupported"
        entry = OperationLedger(tmp_path / "state").get("ws-unit")
        assert entry["resourceEnforcement"] == created["result"]["resourceEnforcement"]
        client.start("ws-unit")
        assert client.stop("ws-unit")["result"]["state"] == "stopped"
        # A stopped workspace reattaches to its preserved container+volume.
        assert client.start("ws-unit")["result"]["state"] == "running"
        receipt = client.remove_workload("ws-unit")
        assert receipt["result"]["state"] == "removed"
        assert "volume is preserved" in receipt["cleanup"]["detail"]
    finally:
        daemon.shutdown()


def test_workspace_terminal_ops_over_socket(tmp_path: Path) -> None:
    engine = WorkspaceFakeEngine()
    daemon = _boot(tmp_path, engine)
    try:
        doc = grant_document([wspec("ws-term", parameters={"shell": ["/bin/bash", "-l"]})])
        provision_grants(tmp_path, doc)
        client = _client(tmp_path, doc)
        client.create_workspace(wspec("ws-term", parameters={"shell": ["/bin/bash", "-l"]}))
        client.start("ws-term")
        opened = client.open_terminal("ws-term", "sess-t1", columns=100, rows=30)
        result = opened["result"]
        assert result["targetClass"] == "capsule"
        assert result["executorPid"] == 432198
        assert engine._last_shell == ("/bin/bash", "-l")
        socket_path = Path(result["socketPath"])
        assert socket_path.parent == tmp_path / "execution-control" / "sessions"
        assert opened["observed"]["imageDigest"] == IMAGE.rsplit("@", 1)[1]
        # Bytes relay through the daemon-owned session socket into the PTY.
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(5)
        connection.connect(str(socket_path))
        connection.sendall(b"ls\n")
        deadline = time.time() + 5
        received = b""
        slave_fd = engine.terminal_slave_fds["ws-term"]
        os.set_blocking(slave_fd, False)
        while time.time() < deadline and b"ls\n" not in received:
            try:
                chunk = os.read(slave_fd, 4096)
                received += chunk
            except BlockingIOError:
                time.sleep(0.05)
        assert b"ls\n" in received
        # Typed signal arrives as the PTY control byte (SIGINT -> ^C).
        client.signal_terminal("sess-t1", signal="SIGINT")
        deadline = time.time() + 5
        signaled = b""
        while time.time() < deadline and b"\x03" not in signaled:
            try:
                chunk = os.read(slave_fd, 4096)
                signaled += chunk
            except BlockingIOError:
                time.sleep(0.05)
        assert b"\x03" in signaled
        client.resize_terminal("sess-t1", columns=120, rows=40)
        assert engine.resizes[-1] == (120, 40)
        assert client.close_terminal("sess-t1")["result"]["state"] == "closing"
        connection.close()
        with pytest.raises(ExecutionHostRefusal, match="unknown-terminal"):
            client.signal_terminal("sess-t1", signal="SIGINT")
    finally:
        daemon.shutdown()


def test_workspace_terminal_session_ops_stay_grant_scoped(tmp_path: Path) -> None:
    engine = WorkspaceFakeEngine()
    daemon = _boot(tmp_path, engine)
    try:
        owner = grant_document([wspec("ws-owned")])
        other = grant_document([wspec("ws-other")], grantId="grant-other")
        provision_grants(tmp_path, owner, other)
        owner_client = _client(tmp_path, owner)
        owner_client.create_workspace(wspec("ws-owned"))
        owner_client.start("ws-owned")
        owner_client.open_terminal("ws-owned", "sess-scope", columns=80, rows=24)
        # A grant that does not cover the workspace cannot drive its session.
        other_client = _client(tmp_path, other)
        with pytest.raises(ExecutionHostRefusal, match="grant-workspace-mismatch"):
            other_client.close_terminal("sess-scope")
        assert owner_client.close_terminal("sess-scope")["result"]["state"] == "closing"
    finally:
        daemon.shutdown()


def test_workspace_exec_is_typed_and_never_shell_joined(tmp_path: Path) -> None:
    engine = WorkspaceFakeEngine()
    daemon = _boot(tmp_path, engine)
    try:
        doc = grant_document([wspec("ws-exec")])
        provision_grants(tmp_path, doc)
        client = _client(tmp_path, doc)
        client.create_workspace(wspec("ws-exec"))
        client.start("ws-exec")
        receipt = client.exec_workload("ws-exec", ["echo", "a;b", "$(id)"])
        result = receipt["result"]
        assert result["exitStatus"] == 0
        assert result["output"] == "fake-exec:echo a;b $(id)"
        # The engine observed the exact argv boundary: three separate tokens.
        assert engine.exec_calls == [("ws-exec", ("echo", "a;b", "$(id)"))]
        assert receipt["observed"]["exitStatus"] == 0
        client.stop("ws-exec")
        with pytest.raises(ExecutionHostRefusal, match="workspace-not-running"):
            client.exec_workload("ws-exec", ["echo", "x"])
    finally:
        daemon.shutdown()


def test_workspace_enumeration_is_real_and_grant_scoped(tmp_path: Path) -> None:
    engine = WorkspaceFakeEngine()
    daemon = _boot(tmp_path, engine)
    try:
        doc_a = grant_document([wspec("ws-a")])
        doc_b = grant_document([wspec("ws-b")], grantId="grant-b")
        provision_grants(tmp_path, doc_a, doc_b)
        client_a = _client(tmp_path, doc_a)
        client_b = _client(tmp_path, doc_b)
        client_a.create_workspace(wspec("ws-a"))
        client_b.create_workspace(wspec("ws-b"))
        client_a.start("ws-a")
        listing = client_a.list_workloads()["result"]["workloads"]
        assert [item["workloadId"] for item in listing] == ["ws-a"]
        assert listing[0]["kind"] == "workspace"
        assert listing[0]["state"] == "running"
        assert listing[0]["running"] is True
        assert listing[0]["engineStatus"] == "running"
        both = client_b.list_workloads()["result"]["workloads"]
        assert [item["workloadId"] for item in both] == ["ws-b"]
    finally:
        daemon.shutdown()


def test_workspace_idle_timeout_measures_inactivity_not_lifetime(tmp_path: Path) -> None:
    engine = WorkspaceFakeEngine()
    daemon = _boot(tmp_path, engine, interval=0.05)
    try:
        doc = grant_document([wspec("ws-idle", timeoutSeconds=2)])
        provision_grants(tmp_path, doc)
        client = _client(tmp_path, doc)
        client.create_workspace(wspec("ws-idle", timeoutSeconds=2))
        client.start("ws-idle")
        # Real activity (a terminal signal) restarts the inactivity clock;
        # under a lifetime policy the workspace would stop 2s after start.
        time.sleep(1.2)
        client.open_terminal("ws-idle", "sess-idle", columns=80, rows=24)
        time.sleep(1.2)
        client.signal_terminal("sess-idle", signal="SIGINT")
        time.sleep(1.2)
        assert client.status("ws-idle")["result"]["state"] == "running"
        # No further activity: the inactivity bound now expires.
        _wait_client_state(client, "ws-idle", "stopped", timeout=10)
        entry = OperationLedger(tmp_path / "state").get("ws-idle")
        assert entry["receipts"][-1]["kind"] == "idle-timeout"
        assert "inactivity bound" in entry["receipts"][-1]["detail"]
        assert "volume preserved" in entry["receipts"][-1]["detail"]
        # The stopped workspace can start again against its preserved volume.
        assert client.start("ws-idle")["result"]["state"] == "running"
    finally:
        daemon.shutdown()


@pytest.mark.parametrize("poll_operation", ["status", "listWorkloads"])
def test_idle_stop_receipt_is_atomic_against_polling(
    tmp_path: Path, poll_operation: str
) -> None:
    idle_id = "ws-idle-race"
    other_id = "ws-unrelated"
    engine = BlockingIdleStopEngine(idle_id)
    daemon = _boot(tmp_path, engine, interval=0.01)
    poll_thread: threading.Thread | None = None
    try:
        idle = wspec(idle_id, timeoutSeconds=1)
        other = wspec(other_id)
        doc = grant_document([idle, other])
        provision_grants(tmp_path, doc)
        client = _client(tmp_path, doc)
        client.create_workspace(idle)
        client.create_workspace(other)
        client.start(idle_id)
        client.start(other_id)
        daemon._activity[idle_id] = time.monotonic() - 10  # noqa: SLF001
        assert engine.stop_effect_applied.wait(5)

        poll_started = threading.Event()
        poll_done = threading.Event()
        poll_result: dict[str, Any] = {}
        poll_errors: list[Exception] = []

        def poll() -> None:
            poll_started.set()
            try:
                if poll_operation == "status":
                    poll_result["receipt"] = client.status(idle_id)
                else:
                    poll_result["receipt"] = client.list_workloads()
            except Exception as exc:  # pragma: no cover - surfaced below
                poll_errors.append(exc)
            finally:
                poll_done.set()

        poll_thread = threading.Thread(target=poll, name=f"idle-{poll_operation}-poll")
        poll_thread.start()
        assert poll_started.wait(5)
        assert not poll_done.wait(0.25)

        # The held idle workload does not become a daemon-wide bottleneck.
        assert client.status(other_id)["result"]["state"] == "running"
        engine.release_stop.set()
        assert poll_done.wait(5)
        poll_thread.join(timeout=5)
        assert not poll_thread.is_alive()
        assert poll_errors == []

        receipt = poll_result["receipt"]
        if poll_operation == "status":
            assert receipt["result"]["state"] == "stopped"
        else:
            listed = {
                item["workloadId"]: item
                for item in receipt["result"]["workloads"]
            }
            assert listed[idle_id]["state"] == "stopped"

        entry = OperationLedger(tmp_path / "state").get(idle_id)
        assert entry["state"] == "stopped"
        assert [item["kind"] for item in entry["receipts"]] == ["idle-timeout"]
    finally:
        engine.release_stop.set()
        if poll_thread is not None:
            poll_thread.join(timeout=5)
        daemon.shutdown()


def test_workspace_without_stop_after_idle_is_not_idle_stopped(tmp_path: Path) -> None:
    engine = WorkspaceFakeEngine()
    daemon = _boot(tmp_path, engine, interval=0.05)
    try:
        doc = grant_document([wspec("ws-pinned", timeoutSeconds=1, parameters={"stopAfterIdle": False})])
        provision_grants(tmp_path, doc)
        client = _client(tmp_path, doc)
        client.create_workspace(
            wspec("ws-pinned", timeoutSeconds=1, parameters={"stopAfterIdle": False})
        )
        client.start("ws-pinned")
        time.sleep(1.5)
        assert client.status("ws-pinned")["result"]["state"] == "running"
    finally:
        daemon.shutdown()


def test_workspace_grant_base_revision_binding(tmp_path: Path) -> None:
    base = "d" * 40
    bound = wspec("ws-rev", parameters={"baseRevision": base})
    doc = grant_document([bound], baseRevision=base)
    daemon = _boot(tmp_path, WorkspaceFakeEngine())
    try:
        provision_grants(tmp_path, doc)
        client = _client(tmp_path, doc)
        with pytest.raises(ExecutionHostRefusal, match="grant-base-revision-mismatch"):
            client.create_workspace(wspec("ws-rev"))
        assert client.create_workspace(bound)["result"]["state"] == "created"
    finally:
        daemon.shutdown()


def _workspace_ledger_with(state_dir: Path, workload_id: str, state: str) -> OperationLedger:
    ledger = OperationLedger(state_dir)
    ledger.record_created(
        contract.validate_workload_spec(wspec(workload_id)), at="2026-08-02T00:00:00Z", container_id="c"
    )
    if state != "created":
        ledger.transition(workload_id, state, at="2026-08-02T00:00:01Z")
    return ledger


def test_recovery_adopts_surviving_workspace_containers(tmp_path: Path) -> None:
    ledger = _workspace_ledger_with(tmp_path, "ws-crash", "running")
    engine = WorkspaceFakeEngine()
    engine.create(wspec("ws-crash"))
    engine.start("ws-crash")
    report = reconcile_on_boot(ledger, engine, at="2026-08-02T01:00:00Z")
    assert report["adopted"] == ["ws-crash"]
    assert report["interrupted"] == []
    entry = ledger.get("ws-crash")
    assert entry["state"] == "running"
    assert entry["receipts"][-1]["kind"] == "restart-adopt"
    # Adopt-and-reattach: the container is never terminated by reconciliation.
    assert "ws-crash" in engine.containers
    assert engine.containers["ws-crash"]["running"] is True


def test_recovery_adopts_created_but_stopped_workspaces(tmp_path: Path) -> None:
    ledger = _workspace_ledger_with(tmp_path, "ws-stopped", "stopped")
    engine = WorkspaceFakeEngine()
    engine.create(wspec("ws-stopped"))  # created-but-stopped container survives
    report = reconcile_on_boot(ledger, engine, at="2026-08-02T01:00:00Z")
    assert report["adopted"] == ["ws-stopped"]
    assert ledger.get("ws-stopped")["state"] == "stopped"
    assert "ws-stopped" in engine.containers


@pytest.mark.parametrize("mismatch", ["managed-label", "kind-label", "image", "volume"])
def test_recovery_never_adopts_foreign_workspace_identity(
    tmp_path: Path, mismatch: str
) -> None:
    workload_id = "ws-foreign"
    ledger = _workspace_ledger_with(tmp_path, workload_id, "running")
    engine = WorkspaceFakeEngine()
    engine.create(wspec(workload_id))
    engine.start(workload_id)
    if mismatch == "managed-label":
        engine.containers[workload_id]["labels"].pop(MANAGED_LABEL_KEY)
    elif mismatch == "kind-label":
        engine.containers[workload_id]["labels"][KIND_LABEL] = "terminal"
    elif mismatch == "image":
        engine.containers[workload_id]["imageDigest"] = "sha256:" + "0" * 64
    else:
        engine.volume_claims_valid = False
    report = reconcile_on_boot(ledger, engine, at="2026-08-02T01:00:00Z")
    assert report["adopted"] == []
    assert report["failures"]
    assert ledger.get(workload_id)["state"] == "running"
    # A foreign name claim is preserved for operator inspection, never adopted
    # and never destructively removed by restart recovery.
    assert engine.containers[workload_id]["running"] is True


def test_recovery_receipts_absent_workspace_container_without_destroying_volume(tmp_path: Path) -> None:
    ledger = _workspace_ledger_with(tmp_path, "ws-gone", "running")
    engine = WorkspaceFakeEngine()  # no container: externally removed
    report = reconcile_on_boot(ledger, engine, at="2026-08-02T01:00:00Z")
    assert report["interrupted"] == ["ws-gone"]
    entry = ledger.get("ws-gone")
    assert entry["state"] == "interrupted"
    assert "data volume is preserved" in entry["receipts"][-1]["detail"]


# ------------------------------------------------ steer-4 authority hardening


def test_missing_or_corrupt_revocation_state_fails_closed(tmp_path: Path) -> None:
    doc = grant_document(["wl-rev"])
    daemon = _boot(tmp_path, FakeEngine())
    try:
        provision_grants(tmp_path, doc)
        client = _client(tmp_path, doc)
        client.create_workload(spec("wl-rev"))
        revocation = tmp_path / "state" / "grants" / "revocation.json"
        # Missing revocation state: nothing verifies, nothing fails open.
        revocation.unlink()
        with pytest.raises(ExecutionHostRefusal, match="revocation-state-missing"):
            client.status("wl-rev")
        # Corrupt revocation state: same fail-closed posture.
        revocation.write_text("{not json", encoding="utf-8")
        with pytest.raises(ExecutionHostRefusal, match="grant-store-corrupt"):
            client.status("wl-rev")
    finally:
        daemon.shutdown()


def test_grant_kind_binding_refuses_unlisted_kind(tmp_path: Path) -> None:
    doc = grant_document(["wl-kind"], workloadKinds=["workspace"])
    reason = _refusal(tmp_path, doc, lambda c: c.create_workload(spec("wl-kind")))
    assert reason == "grant-kind-denied"


def test_grant_spec_digest_binds_complete_sealed_spec(tmp_path: Path) -> None:
    doc = grant_document(["wl-digest"])
    daemon = _boot(tmp_path, FakeEngine())
    try:
        provision_grants(tmp_path, doc)
        client = _client(tmp_path, doc)
        # Same id/kind/image/budgets, but the sealed spec differs in a field
        # only the complete digest binds (workSeconds).
        changed = spec("wl-digest")
        changed["parameters"]["workSeconds"] = 61
        with pytest.raises(ExecutionHostRefusal, match="grant-spec-digest-mismatch"):
            client.create_workload(changed)
        # The exact bound spec passes.
        assert client.create_workload(spec("wl-digest"))["result"]["state"] == "created"
    finally:
        daemon.shutdown()


def test_grant_cpu_and_disk_ceilings(tmp_path: Path) -> None:
    doc = grant_document(
        [wspec("ws-cpu")],
        budgets={
            "maxTimeoutSeconds": 3600,
            "maxOutputBytes": 4194304,
            "maxMemoryMaxBytes": 1073741824,
            "maxPidsMax": 512,
            "maxActiveWorkloads": 8,
            "maxCpuQuotaPercent": 100,
            "maxDiskMaxBytes": 268435456,
        },
    )
    daemon = _boot(tmp_path, WorkspaceFakeEngine())
    try:
        provision_grants(tmp_path, doc)
        client = _client(tmp_path, doc)
        with pytest.raises(ExecutionHostRefusal, match="grant-budget-exceeded"):
            client.create_workspace(wspec("ws-cpu", parameters={"cpuQuotaPercent": 200}))
        with pytest.raises(ExecutionHostRefusal, match="grant-budget-exceeded"):
            client.create_workspace(wspec("ws-cpu", parameters={"diskMaxBytes": 536870912}))
        # A spec inside the ceilings still fails only on the digest binding,
        # proving the ceilings themselves admitted it.
        bound = wspec("ws-cpu", parameters={"cpuQuotaPercent": 50})
        with pytest.raises(ExecutionHostRefusal, match="grant-spec-digest-mismatch"):
            client.create_workspace(bound)
    finally:
        daemon.shutdown()


@pytest.mark.parametrize(
    ("field", "requested"),
    [
        ("memoryMaxBytes", 536870912),
        ("pidsMax", 256),
        ("cpuQuotaPercent", 200),
        ("diskMaxBytes", 134217728),
    ],
)
def test_grant_agent_run_resource_ceilings(
    tmp_path: Path, field: str, requested: int
) -> None:
    workload = spec(f"agent-{field}", kind="agent-run")
    workload["resources"][field] = requested
    doc = grant_document(
        [workload],
        budgets={
            "maxTimeoutSeconds": 3600,
            "maxOutputBytes": 4194304,
            "maxMemoryMaxBytes": 268435456,
            "maxPidsMax": 128,
            "maxActiveWorkloads": 8,
            "maxCpuQuotaPercent": 100,
            "maxDiskMaxBytes": 67108864,
        },
    )
    reason = _refusal(
        tmp_path, doc, lambda client: client.create_workload(workload)
    )
    assert reason == "grant-budget-exceeded"


def test_grant_validator_ceilings_use_validator_resources(tmp_path: Path) -> None:
    cpu_heavy = validator_spec("validator-cpu", cpu_quota_percent=200)
    disk_heavy = validator_spec("validator-disk", disk_max_bytes=134217728)
    doc = grant_document(
        [cpu_heavy, disk_heavy],
        budgets={
            "maxTimeoutSeconds": 3600,
            "maxOutputBytes": 4194304,
            "maxMemoryMaxBytes": 1073741824,
            "maxPidsMax": 512,
            "maxActiveWorkloads": 8,
            "maxCpuQuotaPercent": 100,
            "maxDiskMaxBytes": 67108864,
        },
    )
    daemon = _boot(tmp_path, FakeEngine())
    try:
        provision_grants(tmp_path, doc)
        client = _client(tmp_path, doc)
        with pytest.raises(ExecutionHostRefusal, match="grant-budget-exceeded"):
            client.run_validator(cpu_heavy)
        with pytest.raises(ExecutionHostRefusal, match="grant-budget-exceeded"):
            client.run_validator(disk_heavy)
        assert OperationLedger(tmp_path / "state").active_workload_ids() == set()
    finally:
        daemon.shutdown()


def _wait_ledger_state(state_dir: Path, workload_id: str, state: str, timeout: float = 10.0) -> dict[str, Any]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        entry = OperationLedger(state_dir).get(workload_id)
        if entry is not None and entry["state"] == state:
            return entry
        time.sleep(0.1)
    raise AssertionError(f"{workload_id} did not reach {state}")


def test_supervision_terminates_ephemeral_work_when_authority_withdrawn(tmp_path: Path) -> None:
    engine = FakeEngine()
    doc = grant_document(["wl-sweep"])
    daemon = _boot(tmp_path, engine, interval=0.05)
    try:
        provision_grants(tmp_path, doc)
        client = _client(tmp_path, doc)
        client.create_workload(spec("wl-sweep"))
        client.start("wl-sweep")
        # Withdraw authority out-of-band: the supervisor must terminate the
        # running workload without any new client request.
        write_revocation(tmp_path, revokedGrantIds=[GRANT_ID])
        entry = _wait_ledger_state(tmp_path / "state", "wl-sweep", "cancelled")
        assert entry["receipts"][-1]["kind"] == "authority-withdrawn"
        assert entry["receipts"][-1]["refusal"] == "grant-revoked"
        assert "wl-sweep" not in engine.containers
    finally:
        daemon.shutdown()


def test_supervision_stops_workspace_but_preserves_volume_when_authority_paused(tmp_path: Path) -> None:
    engine = WorkspaceFakeEngine()
    doc = grant_document([wspec("ws-sweep")])
    daemon = _boot(tmp_path, engine, interval=0.05)
    try:
        provision_grants(tmp_path, doc)
        client = _client(tmp_path, doc)
        client.create_workspace(wspec("ws-sweep"))
        client.start("ws-sweep")
        write_revocation(tmp_path, pausedGrantIds=[GRANT_ID])
        entry = _wait_ledger_state(tmp_path / "state", "ws-sweep", "stopped")
        assert entry["receipts"][-1]["kind"] == "authority-withdrawn"
        assert entry["receipts"][-1]["refusal"] == "grant-paused"
    finally:
        daemon.shutdown()


def test_supervision_terminates_on_epoch_advance(tmp_path: Path) -> None:
    engine = FakeEngine()
    doc = grant_document(["wl-exp"])
    daemon = _boot(tmp_path, engine, interval=0.05)
    try:
        provision_grants(tmp_path, doc)
        client = _client(tmp_path, doc)
        client.create_workload(spec("wl-exp"))
        client.start("wl-exp")
        write_revocation(tmp_path, revocationEpoch=1)
        entry = _wait_ledger_state(tmp_path / "state", "wl-exp", "cancelled")
        assert entry["receipts"][-1]["refusal"] == "grant-revoked"
    finally:
        daemon.shutdown()


def test_expired_grant_terminates_active_workload(tmp_path: Path) -> None:
    # Advance the daemon clock past the unchanged grant's expiry; replacing
    # the document would correctly be a grant-digest mismatch instead.
    engine = FakeEngine()
    now = {"value": "2026-08-08T00:00:00Z"}
    doc = grant_document(["wl-clock"], expiresAt="2026-08-08T00:00:10Z")
    daemon = _boot(tmp_path, engine, interval=0.05, clock=lambda: now["value"])
    try:
        provision_grants(tmp_path, doc)
        client = _client(tmp_path, doc)
        client.create_workload(spec("wl-clock"))
        client.start("wl-clock")
        now["value"] = "2026-08-08T00:00:11Z"
        entry = _wait_ledger_state(tmp_path / "state", "wl-clock", "cancelled")
        assert entry["receipts"][-1]["kind"] == "authority-withdrawn"
        assert entry["receipts"][-1]["refusal"] == "grant-expired"
    finally:
        daemon.shutdown()


def test_ledger_cas_and_versioning(tmp_path: Path) -> None:
    ledger = OperationLedger(tmp_path / "state")
    ledger.record_created(spec("wl-cas"), at="2026-08-08T00:00:00Z", container_id="c1")
    assert ledger.get("wl-cas")["version"] == 1
    ledger.transition(
        "wl-cas", "running", at="2026-08-08T00:00:01Z", expect_states={"created"}
    )
    assert ledger.get("wl-cas")["version"] == 2
    with pytest.raises(LedgerError, match="expected one of"):
        ledger.transition(
            "wl-cas", "running", at="2026-08-08T00:00:02Z", expect_states={"created"}
        )
    # The refused CAS write did not advance the version or the state.
    entry = ledger.get("wl-cas")
    assert entry["version"] == 2
    assert entry["state"] == "running"
    stale_version = entry["version"]
    ledger.transition(
        "wl-cas",
        "running",
        at="2026-08-08T00:00:03Z",
        expect_states={"running"},
        expect_version=stale_version,
    )
    with pytest.raises(LedgerError, match="expected version"):
        ledger.transition(
            "wl-cas",
            "running",
            at="2026-08-08T00:00:04Z",
            expect_states={"running"},
            expect_version=stale_version,
        )


def test_touch_activity_cannot_resurrect_a_terminal_workload(
    tmp_path: Path, monkeypatch: Any
) -> None:
    ledger = OperationLedger(tmp_path / "state")
    workload = contract.validate_workload_spec(wspec("ws-touch-race"))
    ledger.record_created(
        workload, at="2026-08-08T00:00:00Z", container_id="container"
    )
    ledger.transition(
        "ws-touch-race", "running", at="2026-08-08T00:00:01Z"
    )
    daemon = ExecutionHostDaemon(
        DaemonConfig(
            socket_path=tmp_path / "unused.sock",
            state_dir=tmp_path / "state",
            socket_group_gid=os.getegid(),
            clock=lambda: "2026-08-08T00:00:02Z",
        ),
        WorkspaceFakeEngine(),
    )
    daemon._ledger = ledger  # noqa: SLF001
    original_transition = ledger.transition

    def racing_transition(*args: Any, **kwargs: Any) -> dict[str, Any]:
        monkeypatch.setattr(ledger, "transition", original_transition)
        current = ledger.get("ws-touch-race")
        original_transition(
            "ws-touch-race",
            "cancelled",
            at="2026-08-08T00:00:02Z",
            finished_at="2026-08-08T00:00:02Z",
            expect_states={"running"},
            expect_version=current["version"],
        )
        return original_transition(*args, **kwargs)

    monkeypatch.setattr(ledger, "transition", racing_transition)
    with pytest.raises(LedgerError, match="expected one of"):
        daemon._touch_activity("ws-touch-race")  # noqa: SLF001
    assert ledger.get("ws-touch-race")["state"] == "cancelled"


def test_ledger_reservation_is_atomic_and_capacity_counted(tmp_path: Path) -> None:
    ledger = OperationLedger(tmp_path / "state")
    ledger.reserve(
        spec("wl-res"),
        at="2026-08-08T00:00:00Z",
        grant_id=GRANT_ID,
        grant_epoch=3,
        max_active=2,
        max_per_grant=1,
    )
    # The placeholder already consumes the per-grant budget and capacity.
    with pytest.raises(LedgerError, match="active workload budget"):
        ledger.reserve(
            spec("wl-other"),
            at="2026-08-08T00:00:01Z",
            grant_id=GRANT_ID,
            grant_epoch=3,
            max_active=2,
            max_per_grant=1,
        )
    with pytest.raises(LedgerError, match="already has a ledger entry"):
        ledger.reserve(
            spec("wl-res"),
            at="2026-08-08T00:00:02Z",
            grant_id=GRANT_ID,
            grant_epoch=3,
            max_active=2,
            max_per_grant=1,
        )
    # Finalize only from the reserved state; the grant epoch persists.
    finalized = ledger.finalize_reserved("wl-res", at="2026-08-08T00:00:03Z", container_id="c9")
    assert finalized["state"] == "created"
    assert finalized["containerId"] == "c9"
    assert finalized["grantEpoch"] == 3
    with pytest.raises(LedgerError, match="expected one of"):
        ledger.finalize_reserved("wl-res", at="2026-08-08T00:00:04Z", container_id="c10")
    # Aborting a reservation lands in a terminal state and frees capacity.
    ledger.reserve(
        spec("wl-abort"),
        at="2026-08-08T00:00:05Z",
        grant_id="grant-other",
        grant_epoch=0,
        max_active=2,
        max_per_grant=1,
    )
    ledger.abort_reserved(
        "wl-abort",
        at="2026-08-08T00:00:06Z",
        receipt={"kind": "create-engine-failure", "detail": "simulated"},
    )
    assert ledger.get("wl-abort")["state"] == "failed"
    assert ledger.active_workload_ids() == {"wl-res"}


def test_terminal_sessions_reject_cross_grant_identity(tmp_path: Path) -> None:
    engine = WorkspaceFakeEngine()
    daemon = _boot(tmp_path, engine)
    try:
        owner = grant_document([wspec("ws-id")])
        # A different grant covering the same workload id: scope passes,
        # identity must not.
        other = grant_document([wspec("ws-id")], grantId="grant-intruder")
        provision_grants(tmp_path, owner, other)
        owner_client = _client(tmp_path, owner)
        owner_client.create_workspace(wspec("ws-id"))
        owner_client.start("ws-id")
        owner_client.open_terminal("ws-id", "sess-id", columns=80, rows=24)
        intruder = _client(tmp_path, other)
        with pytest.raises(ExecutionHostRefusal, match="grant-identity-mismatch"):
            intruder.signal_terminal("sess-id", signal="SIGINT")
        assert owner_client.close_terminal("sess-id")["result"]["state"] == "closing"
    finally:
        daemon.shutdown()


def test_supervision_survives_racing_transitions(tmp_path: Path) -> None:
    # A cancel racing the sweep's stale snapshot must not kill the
    # supervisor thread: subsequent workloads are still supervised.
    engine = FakeEngine()
    doc = grant_document([spec("wl-race-a", timeoutSeconds=1), spec("wl-race-b", timeoutSeconds=1)])
    daemon = _boot(tmp_path, engine, interval=0.05)
    try:
        provision_grants(tmp_path, doc)
        client = _client(tmp_path, doc)
        client.create_workload(spec("wl-race-a", timeoutSeconds=1))
        client.start("wl-race-a")
        # Revoke the grant and cancel in the same instant: the sweep's
        # authority-withdrawn transition races the terminal cancel.
        write_revocation(tmp_path, revokedGrantIds=[GRANT_ID])
        client_cancel_error = None
        try:
            client.cancel("wl-race-a")
        except ExecutionHostRefusal as exc:
            client_cancel_error = exc.reason
        assert client_cancel_error in {None, "grant-revoked"}
        write_revocation(tmp_path)
        doc2 = grant_document([spec("wl-race-b", timeoutSeconds=1)], grantId="grant-b")
        provision_grants(tmp_path, doc2)
        client2 = _client(tmp_path, doc2)
        client2.create_workload(spec("wl-race-b", timeoutSeconds=1))
        client2.start("wl-race-b")
        # Supervision is still alive: the second workload times out on its own.
        deadline = time.time() + 10
        state = "running"
        while time.time() < deadline:
            state = client2.status("wl-race-b")["result"]["state"]
            if state == "timed_out":
                break
            time.sleep(0.1)
        assert state == "timed_out"
    finally:
        daemon.shutdown()


def test_withdrawn_authority_is_receipted_once_not_every_sweep(tmp_path: Path) -> None:
    engine = WorkspaceFakeEngine()
    doc = grant_document([wspec("ws-once")])
    daemon = _boot(tmp_path, engine, interval=0.05)
    try:
        provision_grants(tmp_path, doc)
        client = _client(tmp_path, doc)
        client.create_workspace(wspec("ws-once"))
        client.start("ws-once")
        write_revocation(tmp_path, revokedGrantIds=[GRANT_ID])
        entry = _wait_ledger_state(tmp_path / "state", "ws-once", "stopped")
        time.sleep(0.4)  # several more sweep intervals
        entry = OperationLedger(tmp_path / "state").get("ws-once")
        withdrawn = [r for r in entry["receipts"] if r.get("kind") == "authority-withdrawn"]
        assert len(withdrawn) == 1
    finally:
        daemon.shutdown()
