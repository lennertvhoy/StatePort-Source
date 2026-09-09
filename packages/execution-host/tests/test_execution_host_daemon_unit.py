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
import subprocess
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
            "containerId": "fake-container-" + spec["workloadId"],
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

    def _check_target(self, workload_id: str, expected_container_id: str | None) -> None:
        if expected_container_id is not None and self.containers.get(workload_id, {}).get("containerId") != expected_container_id:
            raise EngineError("exact container target no longer exists")

    def start(self, workload_id: str, *, timeout: int | None = None, expected_container_id: str | None = None) -> None:
        self._check_target(workload_id, expected_container_id)
        self.containers[workload_id]["running"] = True

    def stop(self, workload_id: str, *, timeout: int = 2, expected_container_id: str | None = None) -> None:
        self._check_target(workload_id, expected_container_id)
        if workload_id in self.containers:
            self.containers[workload_id]["running"] = False
            self.containers[workload_id]["exitStatus"] = 137
            self.stopped.append(workload_id)

    def kill(self, workload_id: str, *, expected_container_id: str | None = None) -> None:
        self.stop(workload_id, timeout=0, expected_container_id=expected_container_id)

    def remove(self, workload_id: str, *, force: bool = True, expected_container_id: str | None = None) -> None:
        self._check_target(workload_id, expected_container_id)
        self.containers.pop(workload_id, None)
        self.removed.append(workload_id)

    def inspect(self, workload_id: str) -> dict[str, Any]:
        item = self.containers.get(workload_id)
        if item is None:
            return {"present": False}
        return {
            "present": True,
            "containerId": item["containerId"],
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
                "detail": (
                    "portable rootless Podman named volumes do not expose an "
                    "enforceable per-volume byte quota"
                ),
            }
        }

    def logs(self, workload_id: str, *, max_bytes: int, expected_container_id: str | None = None) -> dict[str, Any]:
        self._check_target(workload_id, expected_container_id)
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
        contract.validate_workload_spec(spec(workload_id)), at="2026-08-02T00:00:00Z", container_id="fake-container-" + workload_id
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


def test_recovery_retains_unknown_containers_and_cleans_known_terminal_leftovers(tmp_path: Path) -> None:
    ledger = _ledger_with(tmp_path, "wl-done", "exited")
    engine = FakeEngine()
    engine.create(spec("wl-done"))  # leftover container for a terminal entry
    engine.create(spec("wl-ghost"))  # orphan with no ledger entry at all
    report = reconcile_on_boot(ledger, engine, at="2026-08-02T01:00:00Z")
    assert report["orphansRemoved"] == ["wl-done"]
    assert set(engine.containers) == {"wl-ghost"}
    assert engine.stopped == []
    assert engine.removed == ["wl-done"]
    assert report["failures"][0]["workloadId"] == "wl-ghost"
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
    **config_options: Any,
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
        **config_options,
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

    def kill(self, workload_id: str, *, expected_container_id: str | None = None) -> None:
        self.kill_attempts += 1
        if self.kill_attempts <= self._failures:
            raise EngineError("simulated engine outage")
        super().kill(workload_id, expected_container_id=expected_container_id)

    def stop(self, workload_id: str, *, timeout: int = 2, expected_container_id: str | None = None) -> None:
        self.stop_attempts += 1
        if self.stop_attempts <= self._failures:
            raise EngineError("simulated engine outage")
        super().stop(workload_id, timeout=timeout, expected_container_id=expected_container_id)

    def remove(self, workload_id: str, *, force: bool = True, expected_container_id: str | None = None) -> None:
        if self.stop_attempts <= self._failures:
            raise EngineError("simulated engine outage")
        super().remove(workload_id, force=force, expected_container_id=expected_container_id)


class StartHookEngine(FakeEngine):
    def __init__(self, hook: Any) -> None:
        super().__init__()
        self._hook = hook

    def start(self, workload_id: str, *, timeout: int | None = None, expected_container_id: str | None = None) -> None:
        super().start(workload_id, timeout=timeout, expected_container_id=expected_container_id)
        self._hook(workload_id)


class ResidualStartHookEngine(StartHookEngine):
    def stop(self, workload_id: str, *, timeout: int = 2, expected_container_id: str | None = None) -> None:
        raise EngineError("simulated stop outage")

    def remove(self, workload_id: str, *, force: bool = True, expected_container_id: str | None = None) -> None:
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


class _UnverifiedTerminalProcess(_FakeTerminalProcess):
    def wait(self, timeout: float | None = None) -> int:
        raise subprocess.TimeoutExpired("fake-terminal", timeout)


class WorkspaceFakeEngine(FakeEngine):
    """Fake engine with the workspace terminal/exec surface."""

    def __init__(self) -> None:
        super().__init__()
        import pty

        self._pty = pty
        self.terminal_slave_fds: dict[str, int] = {}
        self.resizes: list[tuple[int, int]] = []
        self.exec_calls: list[tuple[str, tuple[str, ...]]] = []

    def open_terminal(self, workload_id: str, *, columns: int, rows: int, shell=("/bin/sh",), expected_container_id: str | None = None):
        import tty

        self._check_target(workload_id, expected_container_id)
        master_fd, slave_fd = self._pty.openpty()
        # Raw line discipline: the test observes the exact byte path; the
        # signal semantics themselves are covered by the real-Podman suite.
        tty.setraw(slave_fd)
        self.terminal_slave_fds[workload_id] = slave_fd
        self._last_shell = tuple(shell)
        return _FakeTerminalProcess(), master_fd

    def resize_terminal(self, master_fd: int, *, columns: int, rows: int) -> None:
        self.resizes.append((columns, rows))

    def exec_workload(self, workload_id: str, argv, *, timeout: int, max_bytes: int, expected_container_id: str | None = None):
        self._check_target(workload_id, expected_container_id)
        self.exec_calls.append((workload_id, tuple(argv)))
        data = ("fake-exec:" + " ".join(argv)).encode()
        return {
            "exitStatus": 0,
            "output": data[:max_bytes].decode(),
            "byteCount": min(len(data), max_bytes),
            "truncated": len(data) > max_bytes,
        }


class UnverifiedWorkspaceEngine(WorkspaceFakeEngine):
    def open_terminal(self, workload_id: str, *, columns: int, rows: int, shell=("/bin/sh",), expected_container_id: str | None = None):
        _process, master_fd = super().open_terminal(
            workload_id,
            columns=columns,
            rows=rows,
            shell=shell,
            expected_container_id=expected_container_id,
        )
        return _UnverifiedTerminalProcess(), master_fd


class FailingWorkspaceCreateEngine(WorkspaceFakeEngine):
    def __init__(self) -> None:
        super().__init__()
        self.fail_create = False

    def create(self, spec: Mapping[str, Any], *, timeout: int | None = None) -> str:
        if self.fail_create:
            raise EngineError("simulated workspace create failure")
        return super().create(spec, timeout=timeout)


class BlockingIdleStopEngine(WorkspaceFakeEngine):
    """Expose the window after an idle stop effect but before its receipt."""

    def __init__(self, workload_id: str) -> None:
        super().__init__()
        self._blocked_workload_id = workload_id
        self.stop_effect_applied = threading.Event()
        self.release_stop = threading.Event()

    def stop(self, workload_id: str, *, timeout: int = 2, expected_container_id: str | None = None) -> None:
        super().stop(workload_id, timeout=timeout, expected_container_id=expected_container_id)
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
        recovered = client.create_workspace(wspec("ws-unit"))
        assert recovered["result"]["state"] == "created"
        assert recovered["result"]["recovered"] is True
        assert recovered["result"]["recoveredFromState"] == "removed"
        assert "volume reattached" in recovered["cleanup"]["detail"]
        entry = OperationLedger(tmp_path / "state").get("ws-unit")
        assert entry["receipts"][-1]["kind"] == "workspace-recovery-reserved"
        assert "ws-unit" in engine.containers
    finally:
        daemon.shutdown()


def test_workspace_recovery_requires_exact_owner_and_absent_container(tmp_path: Path) -> None:
    engine = WorkspaceFakeEngine()
    daemon = _boot(tmp_path, engine)
    try:
        owner = grant_document([wspec("ws-recover")])
        other = grant_document([wspec("ws-recover")], grantId="grant-other")
        provision_grants(tmp_path, owner, other)
        owner_client = _client(tmp_path, owner)
        owner_client.create_workspace(wspec("ws-recover"))
        owner_client.remove_workload("ws-recover")

        with pytest.raises(ExecutionHostRefusal, match="workspace-recovery-refused"):
            _client(tmp_path, other).create_workspace(wspec("ws-recover"))

        engine.create(wspec("ws-recover"))
        with pytest.raises(ExecutionHostRefusal, match="container-present"):
            owner_client.create_workspace(wspec("ws-recover"))
        assert OperationLedger(tmp_path / "state").get("ws-recover")["state"] == "removed"
    finally:
        daemon.shutdown()


def test_workspace_recovery_ledger_refuses_changed_sealed_spec(tmp_path: Path) -> None:
    ledger = OperationLedger(tmp_path / "state")
    original = wspec("ws-sealed")
    digest = contract.canonical_digest({"grantId": GRANT_ID})
    ledger.reserve(
        original,
        at="2026-08-08T00:00:00Z",
        grant_id=GRANT_ID,
        grant_epoch=0,
        max_active=8,
        max_per_grant=8,
        grant_digest=digest,
    )
    ledger.finalize_reserved("ws-sealed", at="2026-08-08T00:00:01Z", container_id="c")
    ledger.transition("ws-sealed", "removed", at="2026-08-08T00:00:02Z")
    changed = wspec("ws-sealed", resources={"memoryMaxBytes": 536870912, "pidsMax": 128})
    with pytest.raises(LedgerError, match="recovery spec does not match"):
        ledger.reserve_workspace_recovery(
            changed,
            at="2026-08-08T00:00:03Z",
            grant_id=GRANT_ID,
            grant_epoch=0,
            max_active=8,
            max_per_grant=8,
            grant_digest=digest,
        )
    assert ledger.get("ws-sealed")["state"] == "removed"


def test_failed_workspace_recovery_returns_to_retryable_terminal_state(tmp_path: Path) -> None:
    engine = FailingWorkspaceCreateEngine()
    daemon = _boot(tmp_path, engine)
    try:
        workspace = wspec("ws-retry")
        doc = grant_document([workspace])
        provision_grants(tmp_path, doc)
        client = _client(tmp_path, doc)
        client.create_workspace(workspace)
        client.remove_workload("ws-retry")

        engine.fail_create = True
        with pytest.raises(ExecutionHostRefusal, match="engine-failure"):
            client.create_workspace(workspace)
        failed = OperationLedger(tmp_path / "state").get("ws-retry")
        assert failed["state"] == "removed"
        assert failed["receipts"][-1]["kind"] == "create-engine-failure"
        assert failed["receipts"][-1]["cleanup"] == "engine workload absence verified"

        engine.fail_create = False
        assert client.create_workspace(workspace)["result"]["recovered"] is True
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
        assert client.close_terminal("sess-t1")["result"]["state"] == "closed"
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
        assert owner_client.close_terminal("sess-scope")["result"]["state"] == "closed"
    finally:
        daemon.shutdown()


def test_workspace_terminal_close_refuses_unverified_process_cleanup(tmp_path: Path) -> None:
    engine = UnverifiedWorkspaceEngine()
    daemon = _boot(tmp_path, engine)
    try:
        workspace = wspec("ws-term-unverified")
        doc = grant_document([workspace])
        provision_grants(tmp_path, doc)
        client = _client(tmp_path, doc)
        client.create_workspace(workspace)
        client.start(workspace["workloadId"])
        client.open_terminal(workspace["workloadId"], "sess-unverified", columns=80, rows=24)
        with pytest.raises(ExecutionHostRefusal, match="terminal-cleanup-unverified"):
            client.close_terminal("sess-unverified")
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
        assert listing[0]["ownership"] == {
            "grantId": GRANT_ID,
            "applicationId": None,
            "runId": None,
        }
        assert listing[0]["declaredLimits"] == {
            "memoryMaxBytes": 268435456,
            "pidsMax": 128,
            "timeoutSeconds": 600,
            "outputByteBound": 4096,
            "cpuQuotaPercent": 100,
            "diskMaxBytes": 268435456,
        }
        assert listing[0]["resourceEnforcement"] == {
            "persistentVolumeDiskMaxBytes": {
                "status": "unsupported",
                "requestedBytes": 268435456,
                "detail": (
                    "portable rootless Podman named volumes do not expose an "
                    "enforceable per-volume byte quota"
                ),
            }
        }
        both = client_b.list_workloads()["result"]["workloads"]
        assert [item["workloadId"] for item in both] == ["ws-b"]
    finally:
        daemon.shutdown()


def test_workload_operations_reject_overlapping_nonowner_grant(tmp_path: Path) -> None:
    engine = WorkspaceFakeEngine()
    daemon = _boot(tmp_path, engine)
    try:
        workspace = wspec("ws-owned-boundary")
        owner = grant_document([workspace])
        intruder = grant_document(
            [workspace], grantId="grant-overlapping-nonowner"
        )
        provision_grants(tmp_path, owner, intruder)
        owner_client = _client(tmp_path, owner)
        owner_client.create_workspace(workspace)
        owner_client.start("ws-owned-boundary")
        other_client = _client(tmp_path, intruder)

        assert other_client.list_workloads()["result"]["workloads"] == []
        operations = (
            lambda: other_client.status("ws-owned-boundary"),
            lambda: other_client.logs("ws-owned-boundary"),
            lambda: other_client.exec_workload("ws-owned-boundary", ["true"]),
            lambda: other_client.open_terminal(
                "ws-owned-boundary", "sess-intruder", columns=80, rows=24
            ),
            lambda: other_client.stop("ws-owned-boundary"),
            lambda: other_client.cancel("ws-owned-boundary"),
            lambda: other_client.remove_workload("ws-owned-boundary"),
        )
        for operation in operations:
            with pytest.raises(
                ExecutionHostRefusal, match="grant-identity-mismatch"
            ):
                operation()

        assert owner_client.status("ws-owned-boundary")["result"]["state"] == "running"
        owner_client.stop("ws-owned-boundary")
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
        contract.validate_workload_spec(wspec(workload_id)), at="2026-08-02T00:00:00Z", container_id="fake-container-" + workload_id
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
        assert owner_client.close_terminal("sess-id")["result"]["state"] == "closed"
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


def test_list_reports_only_the_calling_grants_allowed_operations(tmp_path: Path) -> None:
    daemon = _boot(tmp_path, WorkspaceFakeEngine())
    first = grant_document([wspec("ops-first")], grantId="ops-first-grant",
                           operations=["listWorkloads", "status", "start"])
    second = grant_document([wspec("ops-second")], grantId="ops-second-grant",
                            operations=["listWorkloads", "status", "stop"])
    try:
        provision_grants(tmp_path, first, second)
        for document in (first, second):
            result = _client(tmp_path, document).list_workloads()["result"]
            assert result["allowedOperations"] == sorted(document["operations"])
            assert result["workloads"] == []
        write_revocation(tmp_path, revokedGrantIds=[first["grantId"]])
        with pytest.raises(ExecutionHostRefusal):
            _client(tmp_path, first).list_workloads()
        assert _client(tmp_path, second).list_workloads()["result"]["allowedOperations"] == sorted(second["operations"])
    finally:
        daemon.shutdown()


def test_application_ownership_is_grant_bound_and_durable_across_recovery(tmp_path: Path) -> None:
    owner = {"applicationId": "projectstate", "instanceId": "project-one", "catalogIdentityDigest": DIGEST, "runId": "run-one"}
    workload = wspec("app-project", parameters={"ownership": owner})
    engine = WorkspaceFakeEngine()
    daemon = _boot(tmp_path, engine)
    try:
        doc = grant_document([workload])
        provision_grants(tmp_path, doc)
        client = _client(tmp_path, doc)
        changed = wspec("app-project", parameters={"ownership": {**owner, "instanceId": "other-instance"}})
        with pytest.raises(ExecutionHostRefusal, match="grant-spec-digest-mismatch"):
            client.create_workspace(changed)
        assert client.create_workspace(workload)["result"]["ownership"] == {"grantId": doc["grantId"], **owner}
        client.start("app-project")
        client.stop("app-project")
        client.remove_workload("app-project")
        assert client.create_workspace(workload)["result"]["ownership"]["instanceId"] == "project-one"
        assert OperationLedger(tmp_path / "state").get("app-project")["spec"]["parameters"]["ownership"] == owner
        assert client.list_workloads()["result"]["workloads"][0]["ownership"] == {"grantId": doc["grantId"], **owner}
        assert client.list_workloads()["result"]["workloads"][0]["allowedOperations"] == sorted(doc["operations"])
    finally:
        daemon.shutdown()


def test_operator_binding_renderer_requires_exact_catalog_and_grant():
    from execution_host.application_workspaces import catalog_identity, render_bindings
    entry = {"instanceId": "project-one", "applicationId": "projectstate", "filesystem": {"device": 1, "inode": 2, "kind": "directory"}, "metadata": {"source": {"resolvedCommit": "a" * 40}}}
    workload = contract.validate_workload_spec(wspec("application-one", parameters={"ownership": {"applicationId": "projectstate", "instanceId": "project-one", "catalogIdentityDigest": catalog_identity(entry), "runId": None}}))
    grant = grant_document([workload])
    reviewed = [{"catalogEntry": entry, "workload": workload, "grant": grant}]
    rendered = render_bindings(reviewed)
    assert rendered["bindings"][0]["authorityGrantDigest"] == contract.canonical_digest(grant)
    workload["parameters"]["shell"] = ["/bin/other"]
    with pytest.raises(ValueError, match="exact sealed workspace"):
        render_bindings(reviewed)


def test_revoked_default_and_first_application_do_not_hide_second_application(tmp_path: Path):
    for source in (ROOT / "packages").glob("*/src"):
        sys.path.insert(0, str(source))
    from execution_host.application_workspaces import render_bindings
    from stateport_persistent_app.execution_host_proxy import ExecutionHostProxy
    from execution_host.application_workspaces import catalog_identity
    entries = {}
    reviewed = []
    for number in (1, 2):
        iid = f"application-{number}"
        entry = {"instanceId": iid, "applicationId": f"template-{number}", "filesystem": {"device": 1, "inode": number, "kind": "directory"}, "metadata": {"source": {"resolvedCommit": str(number) * 40}}}
        workload = contract.validate_workload_spec(wspec(iid, parameters={"ownership": {"applicationId": entry["applicationId"], "instanceId": iid, "catalogIdentityDigest": catalog_identity(entry), "runId": None}}))
        grant = grant_document([workload], grantId=f"grant-{number}")
        entries[iid] = entry
        reviewed.append({"catalogEntry": entry, "workload": workload, "grant": grant})
    default = grant_document([wspec("default-dev")], grantId="default-grant")
    bindings = tmp_path / "bindings.json"
    bindings.write_text(json.dumps(render_bindings(reviewed)))
    daemon = _boot(tmp_path, WorkspaceFakeEngine())
    try:
        provision_grants(tmp_path, default, *(item["grant"] for item in reviewed))
        write_revocation(tmp_path, revokedGrantIds=["default-grant", "grant-1"])
        proxy = ExecutionHostProxy(socket_path=tmp_path / "execution-control" / "control.sock", grant_id="default-grant", authority_grant_digest=contract.canonical_digest(default), bindings_path=bindings, bindings_owner_uid=os.getuid(), catalog_entry=entries.__getitem__)
        assert proxy.status()["status"] == "available"  # Real daemon health is peer-only.
        assert proxy.create_application("application-2")["accepted"]
        observed = proxy.list()
        assert observed["accepted"]
        assert observed["result"]["defaultWorkspaceRefusal"]["reason"] == "grant-revoked"
        assert observed["result"]["applicationWorkspaces"][0]["reason"] == "grant-revoked"
        assert observed["result"]["applicationWorkspaces"][1]["status"] == "available"
        assert [row["workloadId"] for row in observed["result"]["workloads"]] == ["application-2"]
    finally:
        daemon.shutdown()


def _sealed_agent_source(tmp_path: Path, workload_id: str = "agent-source", content: bytes | None = None):
    import hashlib
    from execution_host.deployment_staging import build_deployment_archive
    source = tmp_path / (workload_id + "-input")
    source.mkdir()
    content = content if content is not None else b"print('source-only fixture')\n"
    (source / "main.py").write_bytes(content)
    (source / "main.py").chmod(0o644)
    digest = "sha256:" + hashlib.sha256(content).hexdigest()
    inventory = [{"path": "main.py", "mode": "100644", "contentDigest": digest}]
    context_digest = contract.canonical_digest([{"path": "main.py", "mode": "100644", "size": len(content), "sha256": digest}])
    archive_path = tmp_path / (workload_id + ".tar")
    with archive_path.open("w+b") as archive:
        metadata = build_deployment_archive(archive, plan={"sourceInventory": inventory, "overlay": {}}, context_root=source, overlay_root=source, context_digest=context_digest)
    workload = spec(workload_id, kind="agent-run")
    command = ["/usr/bin/python3", "main.py"]
    workload["parameters"].update(command=command, commandDigest=contract.canonical_digest(command), sourceInventory=inventory, sourceArchive=metadata)
    return contract.validate_workload_spec(workload), archive_path


def test_agent_source_contract_requires_exact_complete_non_path_payload(tmp_path):
    import copy
    workload, _archive = _sealed_agent_source(tmp_path)
    for field in ("command", "commandDigest", "sourceInventory", "sourceArchive"):
        malformed = copy.deepcopy(workload)
        malformed["parameters"].pop(field)
        with pytest.raises(ValueError, match="supplied together"):
            contract.validate_workload_spec(malformed)
    malformed = copy.deepcopy(workload)
    malformed["parameters"]["sourceSnapshotPath"] = "/arbitrary/host/path"
    with pytest.raises(ValueError, match="invalid shape"):
        contract.validate_workload_spec(malformed)
    malformed = copy.deepcopy(workload)
    malformed["parameters"]["command"].append("unapproved")
    with pytest.raises(ValueError, match="command digest"):
        contract.validate_workload_spec(malformed)
    for bad_path in ("../outside", "/absolute", "dir/../outside", "a\\b"):
        malformed = copy.deepcopy(workload)
        malformed["parameters"]["sourceInventory"][0]["path"] = bad_path
        with pytest.raises(ValueError, match="unsafe"):
            contract.validate_workload_spec(malformed)


def test_agent_source_fd_is_private_exact_bounded_and_cleaned(tmp_path):
    import copy
    class SourceEngine(FakeEngine):
        agent_source_commands_supported = True
        def create(self, workload, **kwargs):
            self.executed = copy.deepcopy(workload)
            return super().create(workload, **kwargs)
    workload, archive = _sealed_agent_source(tmp_path)
    engine = SourceEngine()
    daemon = _boot(tmp_path, engine)
    try:
        grant = grant_document([workload])
        provision_grants(tmp_path, grant)
        client = _client(tmp_path, grant)
        with pytest.raises(ExecutionHostRefusal, match="source-descriptor-required"):
            client.create_workload(workload)
        with archive.open("rb") as source:
            receipt = client.create_workload(workload, source_fd=source.fileno())
        admitted = Path(engine.executed["parameters"]["sourceSnapshotPath"])
        assert admitted.is_dir()
        assert admitted.stat().st_mode & 0o777 == 0o755
        assert (admitted / "main.py").read_text() == "print('source-only fixture')\n"
        assert receipt["result"]["source"]["candidateStorage"] == "bounded-ephemeral-tmpfs"
        assert receipt["result"]["source"]["durableChangedFiles"] is False
        stored = OperationLedger(tmp_path / "state").get(workload["workloadId"])
        assert stored["spec"] == workload
        assert str(admitted) not in json.dumps(receipt)
        client.remove_workload(workload["workloadId"])
        assert not admitted.parent.exists()
        assert OperationLedger(tmp_path / "state").get(workload["workloadId"])["sourceSnapshotPath"] is None
    finally:
        daemon.shutdown()


def test_agent_source_archive_cannot_exceed_candidate_disk_budget(tmp_path):
    budget = 16 * 1024 * 1024
    workload, archive = _sealed_agent_source(tmp_path, content=b"x" * (budget + 1))
    workload["resources"]["diskMaxBytes"] = budget
    engine = FakeEngine()
    engine.agent_source_commands_supported = True
    daemon = _boot(tmp_path, engine)
    try:
        grant = grant_document([workload])
        provision_grants(tmp_path, grant)
        with archive.open("rb") as source:
            with pytest.raises(ExecutionHostRefusal, match="source-admission-refused"):
                _client(tmp_path, grant).create_workload(workload, source_fd=source.fileno())
        assert engine.containers == {}
        entry = OperationLedger(tmp_path / "state").get(workload["workloadId"])
        assert entry["state"] == "failed"
        assert not list((tmp_path / "state" / "validator-snapshots").glob("*"))
    finally:
        daemon.shutdown()


def test_agent_source_requires_engine_command_support(tmp_path):
    workload, archive = _sealed_agent_source(tmp_path)
    engine = FakeEngine()
    daemon = _boot(tmp_path, engine)
    try:
        grant = grant_document([workload])
        provision_grants(tmp_path, grant)
        with archive.open("rb") as source:
            with pytest.raises(ExecutionHostRefusal, match="agent-command-unavailable"):
                _client(tmp_path, grant).create_workload(workload, source_fd=source.fileno())
        assert engine.containers == {}
        assert OperationLedger(tmp_path / "state").get(workload["workloadId"]) is None
    finally:
        daemon.shutdown()


def test_agent_source_exit_is_captured_without_log_reader_and_survives_remove(tmp_path):
    workload, archive = _sealed_agent_source(tmp_path)
    engine = FakeEngine()
    engine.agent_source_commands_supported = True
    daemon = _boot(tmp_path, engine)
    try:
        grant = grant_document([workload])
        provision_grants(tmp_path, grant)
        client = _client(tmp_path, grant)
        with archive.open('rb') as source:
            client.create_workload(workload, source_fd=source.fileno())
        client.start(workload['workloadId'])
        engine.containers[workload['workloadId']].update(running=False, exitStatus=7)
        ledger = OperationLedger(tmp_path / 'state')
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            entry = ledger.get(workload['workloadId'])
            if entry.get('sourceCommandOutput'):
                break
            time.sleep(.02)
        evidence = entry['sourceCommandOutput']
        assert evidence['exitStatus'] == 7
        assert evidence['terminationReason'] == 'exited'
        assert evidence['durableChangedFiles'] is False
        client.remove_workload(workload['workloadId'])
        assert workload['workloadId'] not in engine.containers
        result = client.logs(workload['workloadId'])['result']
        assert result['output'] == evidence['output']
        assert result['sourceCommand']['evidenceDigest'] == evidence['evidenceDigest']
        assert OperationLedger(tmp_path / 'state').get(workload['workloadId'])['sourceCommandOutput'] == evidence
    finally:
        daemon.shutdown()


def test_agent_source_cancel_capture_failure_retains_container_and_reason(tmp_path):
    class FailingLogs(FakeEngine):
        agent_source_commands_supported = True
        fail_logs = True
        def logs(self, workload_id, *, max_bytes, expected_container_id=None):
            if self.fail_logs:
                raise EngineError('capture unavailable')
            return super().logs(workload_id, max_bytes=max_bytes, expected_container_id=expected_container_id)
    workload, archive = _sealed_agent_source(tmp_path)
    engine = FailingLogs()
    daemon = _boot(tmp_path, engine, interval=60)
    try:
        grant = grant_document([workload])
        provision_grants(tmp_path, grant)
        client = _client(tmp_path, grant)
        with archive.open('rb') as source:
            client.create_workload(workload, source_fd=source.fileno())
        client.start(workload['workloadId'])
        result = client.cancel(workload['workloadId'])
        assert result['cleanup']['outcome'] != 'succeeded'
        assert workload['workloadId'] in engine.containers
        entry = OperationLedger(tmp_path / 'state').get(workload['workloadId'])
        assert entry['state'] == 'cleanup_failed'
        assert entry['sourceTerminationReason'] == 'cancelled'
        assert entry.get('sourceCommandOutput') is None
        engine.fail_logs = False
        client.remove_workload(workload['workloadId'])
        evidence = OperationLedger(tmp_path / 'state').get(workload['workloadId'])['sourceCommandOutput']
        assert evidence['terminationReason'] == 'cancelled'
        assert evidence['exitStatus'] == 137
        assert workload['workloadId'] not in engine.containers
    finally:
        daemon.shutdown()


def test_agent_source_boot_capture_failure_preserves_evidence_until_retry(tmp_path):
    class CaptureEngine(FakeEngine):
        agent_source_commands_supported = True
        fail_logs = False
        def logs(self, workload_id, *, max_bytes, expected_container_id=None):
            if self.fail_logs:
                raise EngineError('temporarily unavailable')
            return super().logs(workload_id, max_bytes=max_bytes, expected_container_id=expected_container_id)
    workload, archive = _sealed_agent_source(tmp_path)
    engine = CaptureEngine()
    daemon = _boot(tmp_path, engine, interval=60)
    grant = grant_document([workload])
    provision_grants(tmp_path, grant)
    client = _client(tmp_path, grant)
    try:
        with archive.open('rb') as source:
            client.create_workload(workload, source_fd=source.fileno())
        client.start(workload['workloadId'])
    finally:
        daemon.shutdown()
    engine.fail_logs = True
    ledger = OperationLedger(tmp_path / 'state')
    report = reconcile_on_boot(ledger, engine, at='2026-09-05T23:00:00Z')
    assert report['failures']
    assert workload['workloadId'] in engine.containers
    assert ledger.get(workload['workloadId'])['sourceTerminationReason'] == 'daemon-restart'
    engine.fail_logs = False
    report = reconcile_on_boot(ledger, engine, at='2026-09-05T23:00:01Z')
    assert not report['failures']
    assert workload['workloadId'] not in engine.containers
    evidence = ledger.get(workload['workloadId'])['sourceCommandOutput']
    assert evidence['terminationReason'] == 'daemon-restart'
    assert evidence['exitStatus'] == 137
@pytest.mark.parametrize("running", [False, True])
def test_empty_ledger_cannot_reconcile_another_daemon_workspace(tmp_path: Path, running: bool) -> None:
    engine = FakeEngine()
    owner = OperationLedger(tmp_path / "owner")
    workload = contract.validate_workload_spec(wspec("other-daemon-workspace"))
    container_id = engine.create(workload)
    owner.record_created(workload, at="2026-09-06T00:00:00Z", container_id=container_id)
    if running:
        engine.start(workload["workloadId"])
    original_entry = (owner.state_dir / "workloads" / (workload["workloadId"] + ".json")).read_bytes()
    original_effect = deepcopy(engine.containers)
    other = OperationLedger(tmp_path / "new-daemon")
    report = reconcile_on_boot(other, engine, at="2026-09-06T00:01:00Z")
    assert report["failures"] == [{"workloadId": workload["workloadId"], "error": "managed container has no reservation in this ledger; retained for operator reconciliation"}]
    assert report["adopted"] == report["interrupted"] == report["orphansRemoved"] == []
    assert other.all() == []
    assert engine.containers == original_effect
    assert engine.stopped == engine.removed == []
    assert (owner.state_dir / "workloads" / (workload["workloadId"] + ".json")).read_bytes() == original_entry
    # The original ledger still owns and can adopt its workspace.
    own_report = reconcile_on_boot(owner, engine, at="2026-09-06T00:02:00Z")
    assert own_report["failures"] == []
    assert own_report["adopted"] == [workload["workloadId"]]
    assert engine.stopped == engine.removed == []


def test_reserved_crash_effect_remains_owned_for_recovery_cleanup(tmp_path: Path) -> None:
    engine = FakeEngine()
    ledger = OperationLedger(tmp_path)
    workload = contract.validate_workload_spec(spec("reserved-before-effect"))
    ledger.reserve(workload, at="2026-09-06T00:00:00Z", grant_id=GRANT_ID, grant_epoch=0, max_active=8, max_per_grant=8)
    # Crash after effect creation but before finalizing the returned container ID.
    engine.create(workload)
    assert ledger.get(workload["workloadId"])["containerId"] is None
    report = reconcile_on_boot(ledger, engine, at="2026-09-06T00:01:00Z")
    assert report["failures"] == []
    assert report["interrupted"] == [workload["workloadId"]]
    assert engine.removed == [workload["workloadId"]]
    assert engine.containers == {}
    assert ledger.get(workload["workloadId"])["state"] == "interrupted"


def test_daemon_boot_refuses_unknown_managed_effect_without_starting_service(tmp_path: Path) -> None:
    engine = FakeEngine()
    engine.create(spec("retained-other-daemon"))
    engine.start("retained-other-daemon")
    original = deepcopy(engine.containers)
    with pytest.raises(DaemonBootError, match="no reservation in this ledger"):
        _boot(tmp_path, engine)
    assert engine.containers == original
    assert engine.stopped == engine.removed == []
    assert not (tmp_path / "execution-control" / "control.sock").exists()
    reports = list((tmp_path / "state" / "recovery").glob("*.json"))
    assert len(reports) == 1
    report = json.loads(reports[0].read_text())["report"]
    assert report["failures"][0]["workloadId"] == "retained-other-daemon"
    assert report["orphansRemoved"] == []


@pytest.mark.parametrize("kind,state", [("agent-run", "running"), ("agent-run", "exited"), ("workspace", "running")])
@pytest.mark.parametrize("replacement_id", [None, "same-name-replacement-id"])
def test_recovery_retains_same_name_replacement_despite_matching_labels_and_image(tmp_path: Path, kind: str, state: str, replacement_id: str | None) -> None:
    engine = FakeEngine()
    workload = contract.validate_workload_spec(wspec("replaced") if kind == "workspace" else spec("replaced"))
    original_id = engine.create(workload)
    ledger = OperationLedger(tmp_path)
    ledger.record_created(workload, at="2026-09-06T00:00:00Z", container_id=original_id)
    ledger.transition("replaced", state, at="2026-09-06T00:00:01Z")
    engine.start("replaced")
    engine.containers["replaced"]["containerId"] = replacement_id
    before = deepcopy(engine.containers)
    report = reconcile_on_boot(ledger, engine, at="2026-09-06T00:01:00Z")
    assert report["failures"] == [{"workloadId": "replaced", "error": "container ID does not match the durable ledger identity" if replacement_id is not None else "observed container ID is unavailable"}]
    assert report["adopted"] == report["interrupted"] == report["orphansRemoved"] == []
    assert engine.containers == before
    assert engine.stopped == engine.removed == []
    assert ledger.get("replaced")["state"] == state


def test_engine_inspect_projects_actual_immutable_container_identity() -> None:
    import subprocess
    observed_id = "a" * 64
    engine = PodmanCliEngine(runner=lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, json.dumps({"Id": observed_id, "State": {}, "Config": {}}), ""))
    assert engine.inspect("identity-projection")["containerId"] == observed_id


def test_explicit_workspace_control_refuses_same_name_replacement_id(tmp_path: Path) -> None:
    engine = WorkspaceFakeEngine()
    workload = wspec("replacement-control")
    grant = grant_document([workload])
    daemon = _boot(tmp_path, engine)
    try:
        provision_grants(tmp_path, grant)
        client = _client(tmp_path, grant)
        client.create_workspace(workload)
        engine.containers[workload["workloadId"]]["containerId"] = "foreign-replacement"
        before = deepcopy(engine.containers)
        with pytest.raises(ExecutionHostRefusal, match="foreign-container"):
            client.start(workload["workloadId"])
        assert engine.containers == before
        assert engine.stopped == engine.removed == []
    finally:
        daemon.shutdown()


@pytest.mark.parametrize("operation", ["start", "stop", "remove", "exec_workload", "open_terminal"])
def test_workspace_control_pins_checked_id_across_name_replacement(tmp_path: Path, operation: str) -> None:
    engine = WorkspaceFakeEngine()
    workload = wspec("name-race")
    grant = grant_document([workload])
    daemon = _boot(tmp_path, engine)
    try:
        provision_grants(tmp_path, grant)
        client = _client(tmp_path, grant)
        client.create_workspace(workload)
        if operation in {"stop", "exec_workload", "open_terminal"}:
            client.start("name-race")
        original_id = engine.containers["name-race"]["containerId"]
        original_method = getattr(engine, operation)
        observed_targets = []
        foreign = deepcopy(engine.containers["name-race"])
        foreign["containerId"] = "foreign-name-replacement"
        def race(workload_id, *args, **kwargs):
            observed_targets.append(kwargs.get("expected_container_id"))
            engine.containers[workload_id] = deepcopy(foreign)
            return original_method(workload_id, *args, **kwargs)
        setattr(engine, operation, race)
        actions = {
            "start": lambda: client.start("name-race"),
            "stop": lambda: client.stop("name-race"),
            "remove": lambda: client.remove_workload("name-race"),
            "exec_workload": lambda: client.exec_workload("name-race", ["true"]),
            "open_terminal": lambda: client.open_terminal("name-race", "term-race", columns=80, rows=24),
        }
        with pytest.raises(ExecutionHostRefusal):
            actions[operation]()
        assert observed_targets == [original_id]
        assert engine.containers["name-race"] == foreign
        assert engine.exec_calls == []
        assert engine.terminal_slave_fds == {}
    finally:
        daemon.shutdown()


@pytest.mark.parametrize("operation", ["stop", "remove"])
def test_recovery_pins_id_when_container_name_changes_after_inspection(tmp_path: Path, operation: str) -> None:
    ledger = _ledger_with(tmp_path, "recovery-race", "running")
    engine = FakeEngine()
    engine.create(spec("recovery-race"))
    engine.start("recovery-race")
    original_method = getattr(engine, operation)
    target_id = engine.containers["recovery-race"]["containerId"]
    observed = []
    def race(workload_id, **kwargs):
        observed.append(kwargs.get("expected_container_id"))
        engine.containers[workload_id]["containerId"] = "foreign-replacement"
        return original_method(workload_id, **kwargs)
    setattr(engine, operation, race)
    report = reconcile_on_boot(ledger, engine, at="2026-09-06T00:01:00Z")
    assert observed == [target_id]
    assert report["failures"]
    assert report["orphansRemoved"] == []
    assert engine.containers["recovery-race"]["containerId"] == "foreign-replacement"
    assert engine.removed == []


def test_engine_control_argv_uses_full_immutable_id_and_refuses_name_substitutes() -> None:
    import subprocess
    commands = []
    def run(args, **kwargs):
        commands.append(args)
        return subprocess.CompletedProcess(args, 0, "", "")
    engine = PodmanCliEngine(runner=run)
    target = "a" * 64
    engine.start("mutable-name", expected_container_id=target)
    engine.stop("mutable-name", expected_container_id=target)
    engine.remove("mutable-name", expected_container_id=target)
    engine.kill("mutable-name", expected_container_id=target)
    engine.exec_workload("mutable-name", ["true"], timeout=5, max_bytes=10, expected_container_id=target)
    assert len(commands) == 5
    assert all(target in args and container_name("mutable-name") not in args for args in commands)
    for invalid in ["--all", container_name("mutable-name"), "a" * 12]:
        with pytest.raises(EngineError, match="exact full ID"):
            engine.remove("mutable-name", expected_container_id=invalid)
    assert len(commands) == 5


def test_garbage_collection_retains_managed_container_without_this_ledger(tmp_path: Path) -> None:
    engine = FakeEngine()
    grant = grant_document(["known-only"])
    daemon = _boot(tmp_path, engine)
    try:
        provision_grants(tmp_path, grant)
        client = _client(tmp_path, grant)
        engine.create(spec("other-daemon-after-boot"))
        before = deepcopy(engine.containers)
        with pytest.raises(ExecutionHostRefusal, match="engine-failure"):
            client.collect_garbage()
        assert engine.containers == before
        assert engine.stopped == engine.removed == []
    finally:
        daemon.shutdown()


def _sealed_workspace_source(tmp_path):
    agent, archive = _sealed_agent_source(tmp_path)
    workload = wspec("workspace-source")
    workload['parameters'].update(ownership={'applicationId': 'app', 'instanceId': 'instance', 'catalogIdentityDigest': DIGEST, 'runId': None}, baseRevision='a' * 40)
    material = {key: agent['parameters'][key] for key in ('sourceInventory', 'sourceArchive')}
    material['descriptorDigest'] = DIGEST
    review = {'workloadId': workload['workloadId'], 'image': workload['image']['reference'], 'ownership': workload['parameters']['ownership'], 'baseRevision': workload['parameters']['baseRevision'], **material}
    workload['parameters']['sourceSeed'] = {**material, 'reviewDigest': contract.canonical_digest(review)}
    workload = contract.validate_workload_spec(workload)
    return workload, archive


def test_workspace_seed_admission_cannot_fall_back_to_empty_volume(tmp_path):
    workload, _ = _sealed_workspace_source(tmp_path)
    engine = FakeEngine()
    daemon = _boot(tmp_path, engine)
    try:
        grant = grant_document([workload])
        provision_grants(tmp_path, grant)
        with pytest.raises(ExecutionHostRefusal, match='workspace-seed-unavailable'):
            _client(tmp_path, grant).create_workspace(workload)
        assert engine.containers == {}
        assert OperationLedger(tmp_path / 'state').get(workload['workloadId']) is None
    finally:
        daemon.shutdown()


class SeedWorkspaceFakeEngine(WorkspaceFakeEngine):
    workspace_source_seed_supported = True
    fail_seed = False
    def __init__(self):
        super().__init__()
        self.seeds = {}
        self.seed_calls = 0
        self.helpers = {}
    def validate_workspace_seed_capability(self, spec):
        pass
    def seed_workspace(self, spec, *, snapshot_root, seed_id, timeout):
        self.seed_calls += 1
        assert Path(snapshot_root, 'context', 'main.py').is_file()
        assert Path(snapshot_root, 'seed-manifest.json').is_file()
        self.seeds[spec['workloadId']] = seed_id
        self.helpers[spec['workloadId']] = seed_id
        if self.fail_seed:
            raise EngineError('partial copy failure')
    def verify_workspace_seed_volume(self, spec, seed_id):
        if self.seeds.get(spec['workloadId']) != seed_id:
            raise EngineError('wrong seed identity')
    def finish_workspace_seed(self, spec, seed_id):
        self.helpers.pop(spec["workloadId"], None)
    def reconcile_workspace_seed(self, spec, seed_id):
        self.verify_workspace_seed_volume(spec, seed_id)
        self.finish_workspace_seed(spec, seed_id)


def test_workspace_seed_recovery_never_repeats_source_transfer(tmp_path):
    workload, archive = _sealed_workspace_source(tmp_path)
    engine = SeedWorkspaceFakeEngine()
    daemon = _boot(tmp_path, engine)
    try:
        grant = grant_document([workload])
        provision_grants(tmp_path, grant)
        client = _client(tmp_path, grant)
        with pytest.raises(ExecutionHostRefusal, match='source-descriptor-required'):
            client.create_workspace(workload)
        with archive.open('rb') as source:
            client.create_workspace(workload, source_fd=source.fileno())
        entry = OperationLedger(tmp_path / 'state').get(workload['workloadId'])
        assert entry['sourceSeedStatus'] == 'complete'
        assert entry['sourceSnapshotPath'] is None
        client.remove_workload(workload['workloadId'])
        seed_id = engine.seeds.pop(workload['workloadId'])
        with pytest.raises(ExecutionHostRefusal, match='workspace-seed-recovery-refused'):
            client.create_workspace(workload)
        assert OperationLedger(tmp_path / 'state').get(workload['workloadId'])['state'] == 'removed'
        engine.seeds[workload['workloadId']] = seed_id
        with archive.open('rb') as source:
            with pytest.raises(ExecutionHostRefusal, match='workspace-seed-recovery-refused'):
                client.create_workspace(workload, source_fd=source.fileno())
        client.create_workspace(workload)
        assert engine.seed_calls == 1
        assert OperationLedger(tmp_path / 'state').get(workload['workloadId'])['sourceSeedStatus'] == 'complete'
    finally:
        daemon.shutdown()


def test_workspace_seed_partial_copy_is_never_adopted_or_cleaned(tmp_path):
    workload, archive = _sealed_workspace_source(tmp_path)
    engine = SeedWorkspaceFakeEngine()
    engine.fail_seed = True
    daemon = _boot(tmp_path, engine)
    try:
        grant = grant_document([workload])
        provision_grants(tmp_path, grant)
        client = _client(tmp_path, grant)
        with archive.open('rb') as source:
            with pytest.raises(ExecutionHostRefusal, match='workspace-seed-failed'):
                client.create_workspace(workload, source_fd=source.fileno())
        ledger = OperationLedger(tmp_path / 'state')
        entry = ledger.get(workload['workloadId'])
        assert entry['sourceSeedStatus'] == 'failed'
        snapshot = Path(entry['sourceSnapshotPath'])
        assert snapshot.is_dir()
        with pytest.raises(ExecutionHostRefusal, match='workspace-seed-recovery-refused'):
            client.create_workspace(workload)
        with pytest.raises(ExecutionHostRefusal, match='workspace-seed-incomplete'):
            client.start(workload['workloadId'])
        with pytest.raises(ExecutionHostRefusal, match='engine-failure'):
            client.remove_workload(workload['workloadId'])
        assert snapshot.is_dir()
        report = reconcile_on_boot(ledger, engine, at='2026-09-05T23:40:00Z')
        assert any(row['workloadId'] == workload['workloadId'] for row in report['failures'])
        assert engine.seed_calls == 1
        assert snapshot.is_dir()
    finally:
        daemon.shutdown()


def test_workspace_seed_engine_refuses_existing_volume_and_unapproved_image(tmp_path, monkeypatch):
    from execution_host.engine import WORKSPACE_SEED_IMAGE
    workload, _ = _sealed_workspace_source(tmp_path)
    engine = PodmanCliEngine()
    with pytest.raises(EngineError, match='pinned Python'):
        engine.validate_workspace_seed_capability(workload)
    workload['image']['reference'] = WORKSPACE_SEED_IMAGE
    monkeypatch.setattr(engine, '_inspect_volume', lambda name: {'Labels': {}})
    commands = []
    monkeypatch.setattr(engine, '_run', lambda *a, **kw: commands.append(a))
    with pytest.raises(EngineError, match='pre-existing'):
        engine.seed_workspace(workload, snapshot_root=str(tmp_path), seed_id='a' * 64, timeout=30)
    assert commands == []


def test_workspace_seed_engine_uses_fixed_bounded_helper_and_reservation_label(tmp_path, monkeypatch):
    import subprocess
    from execution_host.engine import WORKSPACE_SEED_IMAGE, _WORKSPACE_SEED_SCRIPT
    workload, _ = _sealed_workspace_source(tmp_path)
    workload['image']['reference'] = WORKSPACE_SEED_IMAGE
    engine = PodmanCliEngine()
    volumes = {}
    commands = []
    monkeypatch.setattr(engine, '_inspect_volume', lambda name: {'Labels': volumes[name]} if name in volumes else None)
    monkeypatch.setattr(engine, '_ensure_volume', lambda name, labels: volumes.update({name: labels}))
    def run(args, *, timeout):
        commands.append((args, timeout))
        output = json.dumps(_seed_helper_inspection(workload, str(tmp_path))) if args[0] == 'inspect' else ('stateport-workspace-seed-verified\n' if args[0] == 'start' else 'b' * 64)
        return subprocess.CompletedProcess(args, 0, output, '')
    monkeypatch.setattr(engine, '_run', run)
    engine.seed_workspace(workload, snapshot_root=str(tmp_path), seed_id='a' * 64, timeout=30)
    command, timeout = commands[0]
    assert command[command.index('--network') + 1] == 'none'
    assert command[command.index('--timeout') + 1] == '30'
    assert command[command.index('--mount') + 1] == f'type=bind,src={tmp_path},dst=/seed-input,ro'
    assert command[-1] == _WORKSPACE_SEED_SCRIPT
    assert 'sourceSeed' not in command
    assert next(iter(volumes.values()))['io.stateport.execution.volume.seed'] == 'a' * 64
    compile(_WORKSPACE_SEED_SCRIPT, '<fixed-workspace-seed-helper>', 'exec')


def test_workspace_seed_crash_after_verified_copy_recovers_without_reseed(tmp_path):
    workload, archive = _sealed_workspace_source(tmp_path)
    engine = SeedWorkspaceFakeEngine()
    daemon = _boot(tmp_path, engine)
    try:
        grant = grant_document([workload])
        provision_grants(tmp_path, grant)
        client = _client(tmp_path, grant)
        with archive.open('rb') as source:
            client.create_workspace(workload, source_fd=source.fileno())
        # Restore the durable state at the crash window after copy verification,
        # before the main workspace container is created.
        engine.remove(workload['workloadId'])
        ledger = OperationLedger(tmp_path / 'state')
        ledger.transition(workload['workloadId'], 'reserved', at='2026-09-05T23:40:00Z', extra={'containerId': None})
        engine.helpers[workload['workloadId']] = ledger.get(workload['workloadId'])['sourceSeedId']
        report = reconcile_on_boot(ledger, engine, at='2026-09-05T23:40:01Z')
        assert not report['failures']
        assert ledger.get(workload['workloadId'])['state'] == 'interrupted'
        assert engine.helpers == {}
        receipt = client.create_workspace(workload)
        assert receipt['result']['sourceSeed']['reused'] is True
        assert engine.seed_calls == 1
    finally:
        daemon.shutdown()


def test_workspace_seed_helper_cleanup_uses_digest_and_immutable_container_id(tmp_path, monkeypatch):
    import subprocess
    from execution_host.engine import WORKSPACE_SEED_IMAGE
    workload, _ = _sealed_workspace_source(tmp_path)
    workload['image']['reference'] = WORKSPACE_SEED_IMAGE
    helper_id = 'c' * 64
    info = {'Id': helper_id, 'ImageDigest': WORKSPACE_SEED_IMAGE.rsplit('@', 1)[1], 'Config': {'Image': WORKSPACE_SEED_IMAGE.replace(':3.13-alpine3.23', ''), 'Labels': {'io.stateport.execution.seed': 'a' * 64}}, 'State': {'Running': False}}
    calls = []
    engine = PodmanCliEngine()
    def run(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, json.dumps(info) if args[0] == 'inspect' else helper_id, '')
    monkeypatch.setattr(engine, '_run', run)
    engine.finish_workspace_seed(workload, 'a' * 64)
    assert calls[-1] == ['rm', helper_id]
    info['ImageDigest'] = 'sha256:' + 'd' * 64
    calls.clear()
    with pytest.raises(EngineError, match='identity changed'):
        engine.finish_workspace_seed(workload, 'a' * 64)
    assert len(calls) == 1


def test_seeded_workspace_standard_volume_verification_requires_source_review(tmp_path, monkeypatch):
    workload, _ = _sealed_workspace_source(tmp_path)
    engine = PodmanCliEngine()
    claims = engine._workspace_volume_claims(workload)
    labels = dict(claims[0][1])
    assert labels['io.stateport.execution.volume.seed-review'] == workload['parameters']['sourceSeed']['reviewDigest']
    monkeypatch.setattr(engine, '_inspect_volume', lambda name: {'Labels': labels})
    engine.verify_workspace_volumes(workload)
    labels.pop('io.stateport.execution.volume.seed-review')
    with pytest.raises(EngineError, match='exact daemon ownership'):
        engine.verify_workspace_volumes(workload)


def _seed_helper_inspection(workload, root):
    from execution_host.engine import _WORKSPACE_SEED_SCRIPT
    return {
        'Id': 'b' * 64, 'ImageDigest': workload['image']['reference'].rsplit('@', 1)[1],
        'Config': {'Image': workload['image']['reference'], 'Labels': {'io.stateport.execution.seed': 'a' * 64}, 'Entrypoint': ['/usr/local/bin/python3'], 'Cmd': ['-c', _WORKSPACE_SEED_SCRIPT], 'Timeout': 30},
        'State': {'Running': False},
        'HostConfig': {'Privileged': False, 'ReadonlyRootfs': True, 'NetworkMode': 'none', 'PidMode': 'private', 'IpcMode': 'shareable', 'CapAdd': [], 'CapDrop': ['CAP_CHOWN', 'CAP_DAC_OVERRIDE', 'CAP_FOWNER', 'CAP_FSETID', 'CAP_KILL', 'CAP_NET_BIND_SERVICE', 'CAP_SETFCAP', 'CAP_SETGID', 'CAP_SETPCAP', 'CAP_SETUID', 'CAP_SYS_CHROOT'], 'Devices': [], 'PortBindings': {}, 'SecurityOpt': ['no-new-privileges'], 'Memory': workload['resources']['memoryMaxBytes'], 'PidsLimit': workload['resources']['pidsMax'], 'NanoCpus': workload['parameters']['cpuQuotaPercent'] * 10_000_000, 'Tmpfs': {'/tmp': 'rw,noexec,nosuid,nodev,size=16777216'}},
        'Mounts': [{'Type': 'bind', 'Source': root, 'Destination': '/seed-input', 'RW': False}, {'Type': 'volume', 'Name': workload['parameters']['volumeName'], 'Destination': '/workspace', 'RW': True}],
    }


@pytest.mark.parametrize('mutation', [
    lambda info: info.update(Id='c' * 64),
    lambda info: info['Config']['Labels'].update({'io.stateport.execution.seed': 'c' * 64}),
    lambda info: info.update(ImageDigest='sha256:' + 'c' * 64),
    lambda info: info['Config'].update(Cmd=['-c', 'unapproved']),
    lambda info: info['Mounts'][0].update(Source='/arbitrary'),
    lambda info: info['Mounts'][0].update(RW=True),
    lambda info: info['Mounts'][1].update(Name='other-volume'),
    lambda info: info['HostConfig'].update(NetworkMode='host'),
    lambda info: info['HostConfig'].update(Memory=0),
    lambda info: info['HostConfig'].update(Privileged=True),
    lambda info: info['HostConfig'].update(CapDrop=[]),
    lambda info: info['HostConfig'].update(Tmpfs={'/tmp': 'rw,exec,size=16777216'}),
])
def test_workspace_seed_prestart_inspection_refuses_mutated_configuration(tmp_path, mutation):
    workload, _ = _sealed_workspace_source(tmp_path)
    info = _seed_helper_inspection(workload, str(tmp_path))
    PodmanCliEngine._assert_seed_helper_configuration(info, workload, helper_id='b' * 64, seed_id='a' * 64, snapshot_root=str(tmp_path), timeout=30)
    mutation(info)
    with pytest.raises(ValueError):
        PodmanCliEngine._assert_seed_helper_configuration(info, workload, helper_id='b' * 64, seed_id='a' * 64, snapshot_root=str(tmp_path), timeout=30)


def test_workspace_seed_archive_refusal_before_volume_effect_does_not_block_boot_or_retry(tmp_path):
    workload, archive = _sealed_workspace_source(tmp_path)
    invalid = tmp_path / 'invalid.tar'
    data = bytearray(archive.read_bytes())
    data[0] ^= 1
    invalid.write_bytes(data)
    engine = SeedWorkspaceFakeEngine()
    daemon = _boot(tmp_path, engine, interval=60)
    try:
        grant = grant_document([workload])
        provision_grants(tmp_path, grant)
        client = _client(tmp_path, grant)
        with invalid.open('rb') as source:
            with pytest.raises(ExecutionHostRefusal, match='workspace-source-admission-refused'):
                client.create_workspace(workload, source_fd=source.fileno())
        ledger = OperationLedger(tmp_path / 'state')
        entry = ledger.get(workload['workloadId'])
        assert entry['sourceSeedStatus'] == 'not-started'
        assert entry['sourceSnapshotPath'] is None
        assert engine.seed_calls == 0
        report = reconcile_on_boot(ledger, engine, at='2026-09-06T00:00:00Z')
        assert report['failures'] == []
        assert ledger.get(workload['workloadId'])['state'] == 'interrupted'
        with archive.open('rb') as source:
            result = client.create_workspace(workload, source_fd=source.fileno())
        assert result['result']['sourceSeed']['reused'] is False
        assert engine.seed_calls == 1
    finally:
        daemon.shutdown()


class NameReplacingLogEngine(FakeEngine):
    def __init__(self):
        super().__init__()
        self.log_targets = []

    def logs(self, workload_id, *, max_bytes, expected_container_id=None):
        self.log_targets.append(expected_container_id)
        self.containers[workload_id]["containerId"] = "foreign-log-replacement"
        if expected_container_id is None:
            return {"bytes": "FOREIGN_PRIVATE_CANARY", "byteCount": 22, "truncated": False}
        self._check_target(workload_id, expected_container_id)
        raise AssertionError("replacement must not resolve the earlier exact target")


def test_live_log_read_does_not_disclose_same_name_replacement_output(tmp_path: Path) -> None:
    engine = NameReplacingLogEngine()
    daemon = _boot(tmp_path, engine)
    try:
        grant = grant_document(["private-log-race"])
        provision_grants(tmp_path, grant)
        client = _client(tmp_path, grant)
        client.create_workload(spec("private-log-race"))
        original_id = engine.containers["private-log-race"]["containerId"]
        with pytest.raises(ExecutionHostRefusal) as refused:
            client.logs("private-log-race")
        assert "FOREIGN_PRIVATE_CANARY" not in str(refused.value)
        assert engine.log_targets == [original_id]
        assert engine.stopped == engine.removed == []
        assert "FOREIGN_PRIVATE_CANARY" not in json.dumps(OperationLedger(tmp_path / "state").all())
    finally:
        daemon.shutdown()


def test_source_capture_does_not_persist_same_name_replacement_output(tmp_path: Path) -> None:
    workload, _archive = _sealed_agent_source(tmp_path)
    engine = NameReplacingLogEngine()
    original_id = engine.create(workload)
    engine.containers[workload["workloadId"]]["exitStatus"] = 0
    ledger = OperationLedger(tmp_path / "ledger")
    entry = ledger.record_created(workload, at="2026-09-06T00:00:00Z", container_id=original_id)
    with pytest.raises(LedgerError, match="could not be captured"):
        ledger.capture_source_command_output(entry, engine, at="2026-09-06T00:01:00Z", termination_reason="exited")
    assert engine.log_targets == [original_id]
    assert ledger.get(workload["workloadId"]).get("sourceCommandOutput") is None
    assert "FOREIGN_PRIVATE_CANARY" not in json.dumps(ledger.all())
    assert engine.stopped == engine.removed == []


def test_engine_log_reader_passes_exact_id_and_preserves_output_bound(tmp_path: Path) -> None:
    target = "a" * 64
    executable = tmp_path / "owned-log-fixture"
    executable.write_text("#!" + sys.executable + "\nimport sys\nprint('OWNED_OUTPUT' if sys.argv[1:] == ['logs', '" + target + "'] else 'FOREIGN_PRIVATE_CANARY')\n", encoding="utf-8")
    executable.chmod(0o755)
    engine = PodmanCliEngine(binary=str(executable))
    output = engine.logs("mutable-name", max_bytes=5, expected_container_id=target)
    assert output == {"bytes": "OWNED", "byteCount": 5, "truncated": True}


@pytest.mark.parametrize(('git_mode', 'unix_mode', 'accepted'), [
    ('100644', 0o644, True), ('100644', 0o600, True),
    ('100755', 0o755, True), ('100755', 0o700, True),
    ('100644', 0o700, False), ('100755', 0o600, False),
    ('100644', 0o666, False), ('100755', 0o777, False),
    ('100644', 0o400, False), ('100755', 0o500, False),
    ('100755', 0o4755, False), ('100755', 0o2755, False),
])
def test_source_archive_exact_public_or_managed_private_modes(tmp_path, git_mode, unix_mode, accepted):
    import hashlib
    import tarfile
    from execution_host.deployment_staging import build_deployment_archive, DeploymentStagingError
    source = tmp_path / 'source'
    source.mkdir()
    file = source / 'approved.txt'
    file.write_bytes(b'approved source')
    file.chmod(unix_mode)
    inventory = [{'path': file.name, 'mode': git_mode, 'contentDigest': 'sha256:' + hashlib.sha256(file.read_bytes()).hexdigest()}]
    archive = (tmp_path / "archive.tar").open("w+b")
    def build():
        return build_deployment_archive(archive, plan={'sourceInventory': inventory, 'overlay': {}}, context_root=source, overlay_root=source, context_digest=contract.canonical_digest([{'path': file.name, 'mode': git_mode, 'size': len(b'approved source'), 'sha256': inventory[0]['contentDigest']}]))
    if accepted:
        build()
        archive.seek(0)
        with tarfile.open(fileobj=archive) as tar:
            member = tar.getmember('context/approved.txt')
            assert member.mode == (0o755 if git_mode == '100755' else 0o644)
            assert tar.extractfile(member).read() == b'approved source'
        assert file.stat().st_mode & 0o7777 == unix_mode
    else:
        with pytest.raises(DeploymentStagingError, match='mode changed'):
            build()


def test_source_archive_refuses_mutation_after_hash(tmp_path, monkeypatch):
    from execution_host import deployment_staging as staging
    workload, _archive = _sealed_agent_source(tmp_path)
    source = tmp_path / 'agent-source-input'
    real_digest = staging._stream_digest
    def raced_digest(handle):
        result = real_digest(handle)
        (source / 'main.py').write_bytes(b'foreign mutation after original hash')
        return result
    monkeypatch.setattr(staging, '_stream_digest', raced_digest)
    with (tmp_path / 'raced.tar').open('w+b') as archive:
        with pytest.raises(staging.DeploymentStagingError, match='changed during transfer'):
            staging.build_deployment_archive(archive, plan={'sourceInventory': workload['parameters']['sourceInventory'], 'overlay': {}}, context_root=source, overlay_root=source, context_digest='sha256:' + 'a' * 64)


@pytest.mark.parametrize('replacement', ['symlink', 'inode'])
def test_source_archive_refuses_replacement_before_open(tmp_path, monkeypatch, replacement):
    from execution_host import deployment_staging as staging
    workload, _archive = _sealed_agent_source(tmp_path)
    source = tmp_path / 'agent-source-input'
    target = source / 'main.py'
    foreign = tmp_path / 'foreign'
    foreign.write_bytes(target.read_bytes())
    foreign.chmod(0o644)
    real_open = staging.os.open
    def raced_open(path, flags, *args, **kwargs):
        if Path(path) == target:
            target.unlink()
            if replacement == 'symlink':
                target.symlink_to(foreign)
            else:
                target.write_bytes(foreign.read_bytes())
                target.chmod(0o644)
        return real_open(path, flags, *args, **kwargs)
    monkeypatch.setattr(staging.os, 'open', raced_open)
    with (tmp_path / 'raced.tar').open('w+b') as archive:
        with pytest.raises((staging.DeploymentStagingError, OSError)):
            staging.build_deployment_archive(archive, plan={'sourceInventory': workload['parameters']['sourceInventory'], 'overlay': {}}, context_root=source, overlay_root=source, context_digest='sha256:' + 'a' * 64)
    assert foreign.read_bytes() == b"print('source-only fixture')\n"


@pytest.mark.parametrize('change', ['none', 'missing', 'revoked', 'stale', 'wrong-app', 'stopped', 'recreated', 'catalog-replaced', 'role', 'permission', 'operator-permission', 'pre-open-race'])
def test_platform_workspace_terminal_study_authority_and_ticket_revalidation(tmp_path, monkeypatch, change):
    for source in (ROOT / 'packages').glob('*/src'):
        sys.path.insert(0, str(source))
    sys.path.insert(0, str(ROOT / 'scripts'))
    from stateport_persistent_app import LocalLayout, PersistentApp
    from stateport_persistent_app.service_process import AppServer
    from stateport_persistent_app.execution_host_proxy import ExecutionHostProxy
    from execution_host.application_workspaces import FORMAT, catalog_identity
    from service_test_product import service_product_fixture
    from run_template_lifecycle_journey import BrowserClient
    from stateport_terminal_broker import TerminalAccessDenied

    class IncarnationEngine(WorkspaceFakeEngine):
        generation = 0
        def create(self, workload, *, timeout=None):
            super().create(workload, timeout=timeout)
            self.generation += 1
            cid = f'{self.generation:064x}'
            self.containers[workload['workloadId']]['containerId'] = cid
            return cid
        def open_terminal(self, workload_id, **kwargs):
            import subprocess
            _fake_process, master = super().open_terminal(workload_id, **kwargs)
            slave = self.terminal_slave_fds[workload_id]
            # Real child process/PTY for transport identity only; this is not a container proof.
            process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'], stdin=slave, stdout=slave, stderr=slave)
            return process, master

    layout = LocalLayout(tmp_path / 'config', tmp_path / 'data', tmp_path / 'app-state')
    app = PersistentApp(layout)
    app.setup_init()
    source = layout.instances_root / 'study-one'
    source.mkdir()
    entry = app.catalog.register(source, instance_id='study-one', name='Study workspace', application_id='studydd', source={'templateId': 'studydd'})
    engine = IncarnationEngine()
    daemon_root = tmp_path / 'daemon'
    daemon_root.mkdir()
    daemon = _boot(daemon_root, engine, interval=30)
    workload = wspec('study-workspace', parameters={'ownership': {'applicationId': 'studydd', 'instanceId': 'study-one', 'catalogIdentityDigest': catalog_identity(entry), 'runId': None}})
    workload = contract.validate_workload_spec(workload)
    grant = grant_document([workload])
    provision_grants(daemon_root, grant)
    client = _client(daemon_root, grant)
    client.create_workspace(workload)
    client.start('study-workspace')
    manifest = tmp_path / 'bindings.json'
    binding = {'grantId': grant['grantId'], 'authorityGrantDigest': contract.canonical_digest(grant), 'workload': workload}
    manifest.write_text(json.dumps({'formatVersion': FORMAT, 'bindings': [binding]}))
    manifest.chmod(0o600)
    boundary = layout.config_root / 'platform-operator-authority'
    boundary.write_text('trusted test operator')
    boundary.chmod(0o600)
    server = AppServer(('127.0.0.1', 0), layout, service_product_fixture(tmp_path, ROOT) / 'apps' / 'web', actor_role='platform_operator')
    server.execution_host = ExecutionHostProxy(socket_path=daemon_root / 'execution-control' / 'control.sock', bindings_path=manifest, bindings_owner_uid=os.getuid(), catalog_entry=server.workspace_catalog_entry)
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.02}, daemon=True)
    thread.start()
    browser = BrowserClient(server.server_address[1])
    try:
        browser.establish_session()
        with pytest.raises(RuntimeError, match='403'):
            browser.request('/v1/instances/study-one/terminal/prepare', body={'expectedInstanceId': 'study-one', 'columns': 80, 'rows': 24})
        experience = server.application_experience('studydd', 'study-one')
        assert experience is not None
        assert not any(row['id'] == 'workbench' and row['status'] in {'available', 'degraded'} for row in experience['capabilities'])
        server._terminal_binding_locked('study-one', workspace_only=True)
        target = browser.request('/v1/execution-host/workspaces/study-one/terminal/target')['target']
        assert target['targetClass'] == 'capsule'
        with pytest.raises(RuntimeError, match='403'):
            browser.request('/v1/execution-host/workspaces/study-one/terminal/prepare', body={'expectedInstanceId': 'wrong-instance', 'expectedTargetId': target['targetId'], 'columns': 80, 'rows': 24})
        with pytest.raises(RuntimeError, match='403'):
            browser.request('/v1/execution-host/workspaces/study-one/terminal/prepare', body={'expectedInstanceId': 'study-one', 'expectedTargetId': 'wrong-target', 'columns': 80, 'rows': 24})
        ticket = browser.request('/v1/execution-host/workspaces/study-one/terminal/prepare', body={'expectedInstanceId': 'study-one', 'expectedTargetId': target['targetId'], 'columns': 80, 'rows': 24})
        if change == 'missing':
            manifest.write_text(json.dumps({'formatVersion': FORMAT, 'bindings': []}))
        elif change == 'revoked':
            write_revocation(daemon_root, revokedGrantIds=[grant['grantId']])
        elif change in {'stale', 'wrong-app'}:
            field = 'catalogIdentityDigest' if change == 'stale' else 'applicationId'
            binding['workload']['parameters']['ownership'][field] = DIGEST if change == 'stale' else 'another-app'
            manifest.write_text(json.dumps({'formatVersion': FORMAT, 'bindings': [binding]}))
        elif change == 'stopped':
            client.stop('study-workspace')
        elif change == 'recreated':
            before = client.status('study-workspace')['result']['containerIdentityDigest']
            client.remove_workload('study-workspace')
            client.create_workspace(workload)
            client.start('study-workspace')
            assert client.status('study-workspace')['result']['containerIdentityDigest'] != before
        elif change == 'pre-open-race':
            gateway_client = server.terminal_brokers['study-one'][2]._client
            original_open = gateway_client.open_terminal
            def replace_before_open(*args, **kwargs):
                client.remove_workload('study-workspace')
                client.create_workspace(workload)
                client.start('study-workspace')
                return original_open(*args, **kwargs)
            monkeypatch.setattr(gateway_client, 'open_terminal', replace_before_open)
        elif change == 'catalog-replaced':
            source.rename(source.with_name('retained-original-study'))
            source.mkdir()
        elif change == 'role':
            server.actor_role = 'local_user'
        elif change in {'permission', 'operator-permission'}:
            removed_permission = 'application.terminal.use' if change == 'permission' else 'platform.authority.mutate'
            original = server.experience_policy.permissions_for
            monkeypatch.setattr(type(server.experience_policy), 'permissions_for', lambda self, role: original(role) - {removed_permission})
        if change not in {'none', 'recreated', 'pre-open-race'}:
            with pytest.raises(RuntimeError, match='403'):
                browser.request('/v1/execution-host/workspaces/study-one/terminal/target')
        auth = {'oneUseToken': ticket['oneUseToken'], 'instanceId': 'study-one', 'sessionId': ticket['sessionId'], 'purpose': ticket['purpose'], 'columns': 80, 'rows': 24}
        if change == 'none':
            accepted = server.accept_terminal_socket(auth, browser.base)
            assert accepted['session'].target_id == target['targetId']
        else:
            with pytest.raises((PermissionError, TerminalAccessDenied, ExecutionHostRefusal)) as refused:
                server.accept_terminal_socket(auth, browser.base)
            if change == 'pre-open-race':
                assert refused.value.reason == 'workspace-identity-changed'
            assert engine.terminal_slave_fds == {}
            if change == 'pre-open-race':
                fresh_target = browser.request('/v1/execution-host/workspaces/study-one/terminal/target')['target']
                assert fresh_target['targetId'] != target['targetId']
                fresh = browser.request('/v1/execution-host/workspaces/study-one/terminal/prepare', body={'expectedInstanceId': 'study-one', 'expectedTargetId': fresh_target['targetId'], 'columns': 80, 'rows': 24})
                fresh_auth = {**auth, 'oneUseToken': fresh['oneUseToken'], 'sessionId': fresh['sessionId'], 'purpose': fresh['purpose']}
                assert server.accept_terminal_socket(fresh_auth, browser.base)['session'].target_id == fresh_target['targetId']
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
        daemon.shutdown()


@pytest.mark.parametrize('digest', [None, '', 'sha256:short', 'SHA256:' + 'a' * 64])
def test_terminal_open_rejects_present_invalid_container_digest(digest):
    with pytest.raises(ValueError):
        contract.validate_request_payload({'operation': 'openTerminal'}, {'workloadId': 'workspace', 'sessionId': 'session', 'columns': 80, 'rows': 24, 'expectedContainerIdentityDigest': digest})


def _development_seed_source(tmp_path):
    workload, archive = _sealed_workspace_source(tmp_path)
    workload['image']['reference'] = contract.DEVELOPMENT_SEED_IMAGE
    seed = workload['parameters']['sourceSeed']
    seed['helperPolicy'] = contract.DEVELOPMENT_SEED_POLICY
    review = {'workloadId': workload['workloadId'], 'image': workload['image']['reference'],
              'ownership': workload['parameters']['ownership'], 'baseRevision': workload['parameters']['baseRevision'],
              **{key: value for key, value in seed.items() if key != 'reviewDigest'}}
    seed['reviewDigest'] = contract.canonical_digest(review)
    return contract.validate_workload_spec(workload), archive


def test_development_seed_policy_binds_normalized_spec_and_preserves_legacy(tmp_path):
    legacy, _ = _sealed_workspace_source(tmp_path)
    before = contract.canonical_digest(legacy)
    assert contract.canonical_digest(contract.validate_workload_spec(legacy)) == before
    assert 'helperPolicy' not in legacy['parameters']['sourceSeed']
    other = tmp_path / "development"
    other.mkdir()
    workload, _ = _development_seed_source(other)
    assert contract.validate_workload_spec(workload) == workload
    for field, value in [('helperPolicy', 'arbitrary'), ('user', '0:0')]:
        changed = deepcopy(workload)
        changed['parameters']['sourceSeed'][field] = value
        with pytest.raises(ValueError):
            contract.validate_workload_spec(changed)
    changed = deepcopy(workload)
    changed['image']['reference'] = IMAGE
    with pytest.raises(ValueError, match='exact development image'):
        contract.validate_workload_spec(changed)
    changed = deepcopy(workload)
    del changed['parameters']['sourceSeed']['helperPolicy']
    with pytest.raises(ValueError, match='review digest'):
        contract.validate_workload_spec(changed)


@pytest.mark.parametrize('mutation', ['user', 'userns', 'script', 'interpreter'])
def test_development_seed_refuses_inspection_before_start(tmp_path, monkeypatch, mutation):
    import subprocess
    from execution_host.engine import _DEVELOPMENT_SEED_SCRIPT
    workload, _ = _development_seed_source(tmp_path)
    info = _seed_helper_inspection(workload, str(tmp_path))
    info['Config'].update(User='10001:10001', Entrypoint=['/usr/bin/python3'], Cmd=['-c', _DEVELOPMENT_SEED_SCRIPT])
    info['HostConfig']['UsernsMode'] = 'host'
    PodmanCliEngine._assert_seed_helper_configuration(info, workload, helper_id='b'*64, seed_id='a'*64, snapshot_root=str(tmp_path), timeout=30)
    if mutation == 'user': info['Config']['User'] = '0:0'
    if mutation == 'userns': info['HostConfig']['UsernsMode'] = 'keep-id'
    if mutation == 'script': info['Config']['Cmd'] = ['-c', 'pass']
    if mutation == 'interpreter': info['Config']['Entrypoint'] = ['/bin/sh']
    engine = PodmanCliEngine()
    commands = []
    monkeypatch.setattr(engine, '_inspect_volume', lambda _: None)
    monkeypatch.setattr(engine, '_ensure_volume', lambda *_: None)
    def run(args, **kwargs):
        commands.append(args)
        return subprocess.CompletedProcess(args, 0, 'true' if args[0]=='info' else (json.dumps(info) if args[0]=='inspect' else 'b'*64), '')
    monkeypatch.setattr(engine, '_run', run)
    with pytest.raises(EngineError, match='configuration changed'):
        engine.seed_workspace(workload, snapshot_root=str(tmp_path), seed_id='a'*64, timeout=30)
    assert [command[0] for command in commands] == ['info', 'create', 'inspect']
    assert commands[1][commands[1].index('--user')+1] == '10001:10001'
    assert not any(':U' in arg for arg in commands[1])


def test_development_seed_wrong_policy_has_zero_engine_effects(tmp_path, monkeypatch):
    workload, _ = _development_seed_source(tmp_path)
    workload['parameters']['sourceSeed']['helperPolicy'] = 'unknown'
    engine = PodmanCliEngine()
    monkeypatch.setattr(engine, '_run', lambda *_args, **_kwargs: pytest.fail('engine effect'))
    monkeypatch.setattr(engine, '_inspect_volume', lambda *_args: pytest.fail('volume probe'))
    with pytest.raises(EngineError, match='policy/image'):
        engine.seed_workspace(workload, snapshot_root=str(tmp_path), seed_id='a'*64, timeout=30)


@pytest.mark.parametrize('observed', ['false', '', 'TRUE'])
def test_development_seed_rootful_or_unknown_refuses_before_volume(tmp_path, monkeypatch, observed):
    import subprocess
    workload, _ = _development_seed_source(tmp_path)
    engine = PodmanCliEngine()
    calls = []
    def run(args, **_kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, observed, '')
    monkeypatch.setattr(engine, '_run', run)
    monkeypatch.setattr(engine, '_inspect_volume', lambda *_: pytest.fail('volume effect'))
    monkeypatch.setattr(engine, '_ensure_volume', lambda *_: pytest.fail('volume effect'))
    with pytest.raises(EngineError, match='rootless'):
        engine.seed_workspace(workload, snapshot_root=str(tmp_path), seed_id='a'*64, timeout=30)
    with pytest.raises(EngineError, match='rootless'):
        engine.create(workload)
    assert all(command[0] == 'info' for command in calls)


def test_development_seed_workload_fixed_argv_and_mutations(tmp_path):
    from execution_host.engine import assert_create_argv_hardened, assert_development_seed_argv_hardened
    workload, _ = _development_seed_source(tmp_path)
    argv = build_create_argv(workload)
    assert_development_seed_argv_hardened(argv)
    with pytest.raises(EngineError):
        assert_create_argv_hardened(argv)
    for pair in [('--user', '0:0'), ('--userns', 'auto')]:
        changed = list(argv)
        changed[changed.index(pair[0])+1] = pair[1]
        with pytest.raises(EngineError):
            assert_development_seed_argv_hardened(changed)
    for extra in [['--user', '10001:10001'], ['--userns', 'host'], ['--userns=host'], ['-u', '10001']]:
        with pytest.raises(EngineError):
            assert_development_seed_argv_hardened([argv[0], *extra, *argv[1:]])


@pytest.mark.parametrize('field,value', [('rootless', False), ('rootless', None), ('user', '0:0'), ('usernsMode', 'auto')])
def test_development_seed_existing_container_mapping_refuses_controls(tmp_path, field, value):
    workload, _ = _development_seed_source(tmp_path)
    entry = {'spec': workload, 'containerId': 'b'*64}
    info = {'containerId': 'b'*64, 'rootless': True, 'user': '10001:10001', 'usernsMode': 'host',
            'labels': {MANAGED_LABEL_KEY: 'true', WORKLOAD_LABEL: workload['workloadId'], KIND_LABEL: 'workspace'},
            'imageDigest': workload['image']['reference'].rsplit('@',1)[1]}
    assert ExecutionHostDaemon._container_identity_error(workload['workloadId'], entry, info) is None
    info[field] = value
    assert 'namespace differs' in ExecutionHostDaemon._container_identity_error(workload['workloadId'], entry, info)
    from execution_host.ledger import _container_identity_error as recovery_identity_error
    assert 'namespace differs' in recovery_identity_error(entry, info)


def test_workspace_seed_snapshot_readability_under_private_umask(tmp_path):
    import stat
    workload, archive = _sealed_workspace_source(tmp_path)
    class ReadabilityEngine(SeedWorkspaceFakeEngine):
        checked = False
        def seed_workspace(self, spec, *, snapshot_root, seed_id, timeout):
            root = Path(snapshot_root)
            assert stat.S_IMODE(root.parent.stat().st_mode) == 0o700
            for path in [root, *root.rglob('*')]:
                mode = stat.S_IMODE(path.lstat().st_mode)
                assert not path.is_symlink()
                if path.is_dir(): assert mode & 0o005 == 0o005
                else: assert mode & 0o004 == 0o004
            self.checked = True
            super().seed_workspace(spec, snapshot_root=snapshot_root, seed_id=seed_id, timeout=timeout)
    engine = ReadabilityEngine()
    daemon = _boot(tmp_path, engine)
    previous = os.umask(0o077)
    try:
        grant = grant_document([workload])
        provision_grants(tmp_path, grant)
        with archive.open('rb') as source:
            _client(tmp_path, grant).create_workspace(workload, source_fd=source.fileno())
        assert engine.checked
    finally:
        os.umask(previous)
        daemon.shutdown()


def test_development_seed_boot_refuses_remapped_container_without_removal(tmp_path):
    workload, archive = _development_seed_source(tmp_path)
    class RemappedEngine(SeedWorkspaceFakeEngine):
        def inspect(self, workload_id):
            info = super().inspect(workload_id)
            if info.get('present'):
                info.update(rootless=True, user='10001:10001', usernsMode='auto')
            return info
    engine = RemappedEngine()
    daemon = _boot(tmp_path, engine)
    try:
        grant = grant_document([workload], imageReference=contract.DEVELOPMENT_SEED_IMAGE)
        provision_grants(tmp_path, grant)
        with archive.open('rb') as source:
            _client(tmp_path, grant).create_workspace(workload, source_fd=source.fileno())
        report = reconcile_on_boot(OperationLedger(tmp_path / 'state'), engine, at='2026-01-01T00:00:00Z')
        assert report['adopted'] == []
        assert report['failures'] and 'namespace differs' in report['failures'][0]['error']
        assert engine.removed == []
        assert workload['workloadId'] in engine.containers
    finally:
        daemon.shutdown()


def test_development_seed_script_actual_wrong_uid_refuses_before_copy(tmp_path):
    import subprocess
    from execution_host.engine import _DEVELOPMENT_SEED_SCRIPT
    if os.getuid() == 10001 and os.getgid() == 10001:
        pytest.skip('wrong-UID negative requires a different test-process identity')
    source = tmp_path / 'input'
    (source / 'context').mkdir(parents=True)
    (source / 'seed-manifest.json').write_text('{"sourceInventory": []}')
    target = tmp_path / 'target'
    target.mkdir()
    diagnostic_script = _DEVELOPMENT_SEED_SCRIPT.replace("'/seed-input/context'", repr(str(source / 'context'))).replace("'/seed-input/seed-manifest.json'", repr(str(source / 'seed-manifest.json'))).replace("'/workspace'", repr(str(target)))
    result = subprocess.run([sys.executable, '-c', diagnostic_script], capture_output=True, text=True, timeout=5)
    assert result.returncode != 0 and 'seed user differs' in result.stderr
    assert list(target.iterdir()) == []


SIGNED_IMAGE = 'ghcr.io/example/signed-development@sha256:' + 'd' * 64


class SignedBindingFakeEngine(FakeEngine):
    def bind_workspace_image_authority(self, reference, verify):
        self.workspace_image_reference = reference
        self.workspace_image_verify = verify


def _signed_default_grant():
    template = contract.workspace_template_for_image(SIGNED_IMAGE)
    return grant_document([template], grantId='control-plane-default', imageReference=SIGNED_IMAGE, workloadKinds=['workspace'])


def _signed_daemon(tmp_path):
    return _boot(tmp_path, SignedBindingFakeEngine(), workspace_image_reference=SIGNED_IMAGE,
                 workspace_spec_digest=contract.canonical_digest(contract.workspace_template_for_image(SIGNED_IMAGE)))


def test_signed_image_pair_configuration_fails_closed(tmp_path):
    for fields in ({'workspace_image_reference': SIGNED_IMAGE}, {'workspace_spec_digest': DIGEST},
                   {'workspace_image_reference': 'arbitrary:latest', 'workspace_spec_digest': DIGEST},
                   {'workspace_image_reference': SIGNED_IMAGE, 'workspace_spec_digest': DIGEST}):
        with pytest.raises(DaemonBootError):
            DaemonConfig(socket_path=tmp_path/'socket', state_dir=tmp_path/'state', **fields)


def test_signed_default_list_proves_exact_template_over_private_grant_socket(tmp_path):
    daemon = _signed_daemon(tmp_path)
    try:
        grant = _signed_default_grant()
        provision_grants(tmp_path, grant)
        result = _client(tmp_path, grant).list_workloads()['result']
        assert result == {'workloads': [], 'allowedOperations': sorted(grant['operations']), 'workspaceProfile': {'imageReference': SIGNED_IMAGE,
            'workloadSpecDigest': contract.canonical_digest(contract.workspace_template_for_image(SIGNED_IMAGE))}}
        malformed = deepcopy(grant)
        malformed['workloadSpecDigests']['default-dev'] = DIGEST
        provision_grants(tmp_path, malformed)
        with pytest.raises(ExecutionHostRefusal, match='workspace-image-mismatch'):
            _client(tmp_path, malformed).list_workloads()
    finally:
        daemon.shutdown()


@pytest.mark.parametrize('failure', ['missing', 'image', 'digest', 'expired', 'revoked'])
def test_signed_seed_private_base_refusal_before_any_engine_effect(tmp_path, failure):
    daemon = _signed_daemon(tmp_path)
    try:
        base = _signed_default_grant()
        if failure == 'image': base['imageReference'] = IMAGE
        if failure == 'digest': base['workloadSpecDigests']['default-dev'] = DIGEST
        if failure == 'expired': base['expiresAt'] = '2026-08-09T00:00:00Z'
        if failure != 'missing': provision_grants(tmp_path, base)
        if failure == 'revoked':
            revocation = tmp_path/'state/grants/revocation.json'
            value = json.loads(revocation.read_text());value['revokedGrantIds'] = ['control-plane-default']
            revocation.write_text(json.dumps(value))
        workload, _ = _sealed_workspace_source(tmp_path)
        workload['image']['reference'] = SIGNED_IMAGE
        workload['parameters']['sourceSeed']['helperPolicy'] = contract.SIGNED_DEVELOPMENT_SEED_POLICY
        engine = PodmanCliEngine(runner=lambda *_args, **_kwargs: pytest.fail('engine effect before base authorization'))
        engine.bind_workspace_image_authority(SIGNED_IMAGE, daemon._verify_workspace_image_authority)
        with pytest.raises(EngineError, match='base authority'):
            engine.seed_workspace(workload, snapshot_root=str(tmp_path), seed_id='a'*64, timeout=30)
        with pytest.raises(EngineError, match='base authority'):
            engine.create(workload)
    finally:
        daemon.shutdown()


def test_revoked_default_does_not_revoke_independent_app_grant(tmp_path):
    daemon = _signed_daemon(tmp_path)
    try:
        base = _signed_default_grant()
        app = grant_document([spec('independent')], grantId='independent-grant')
        provision_grants(tmp_path, base, app)
        revocation = tmp_path/'state/grants/revocation.json'
        value = json.loads(revocation.read_text());value['revokedGrantIds'] = ['control-plane-default']
        revocation.write_text(json.dumps(value))
        with pytest.raises(ExecutionHostRefusal, match='revoked'):
            _client(tmp_path, base).list_workloads()
        client = _client(tmp_path, app)
        assert 'workspaceProfile' not in client.list_workloads()['result']
        client.create_workload(spec('independent'))
        client.start('independent')
        assert client.status('independent')['result']['state'] == 'running'
    finally:
        daemon.shutdown()


def _signed_seed_source(tmp_path):
    workload, archive = _sealed_workspace_source(tmp_path)
    workload['image']['reference'] = SIGNED_IMAGE
    seed = workload['parameters']['sourceSeed']
    seed['helperPolicy'] = contract.SIGNED_DEVELOPMENT_SEED_POLICY
    review = {'workloadId': workload['workloadId'], 'image': SIGNED_IMAGE,
              'ownership': workload['parameters']['ownership'], 'baseRevision': workload['parameters']['baseRevision'],
              **{key: value for key, value in seed.items() if key != 'reviewDigest'}}
    seed['reviewDigest'] = contract.canonical_digest(review)
    return contract.validate_workload_spec(workload), archive


def test_signed_policy_normalization_does_not_authorize_image(tmp_path):
    workload, _ = _signed_seed_source(tmp_path)
    assert workload['image']['reference'] == SIGNED_IMAGE
    engine = PodmanCliEngine(runner=lambda *_a, **_kw: pytest.fail('unconfigured engine effect'))
    with pytest.raises(EngineError, match='binding is unavailable'):
        engine.validate_workspace_seed_capability(workload)


@pytest.mark.parametrize('repository', ['registry.example:5000/development', 'registry.example:5000/other'])
def test_signed_image_inspection_preserves_registry_port_and_ignores_only_tag(repository):
    import subprocess
    reference = 'registry.example:5000/development:approved@sha256:' + 'a'*64
    verified = []
    raw = {'Id': 'b'*64, 'ImageDigest': 'sha256:'+'a'*64,
           'Config': {'Image': repository+'@sha256:'+'a'*64, 'User': '10001:10001',
                      'Labels': {'io.stateport.execution.seed-policy': contract.SIGNED_DEVELOPMENT_SEED_POLICY}},
           'HostConfig': {'UsernsMode': 'host'}, 'State': {'Running': False}}
    def run(argv, **_kwargs):
        return subprocess.CompletedProcess(argv, 0, 'true' if argv[1] == 'info' else json.dumps(raw), '')
    engine = PodmanCliEngine(runner=run)
    engine.bind_workspace_image_authority(reference, lambda: verified.append(True))
    if repository.endswith('/other'):
        with pytest.raises(EngineError, match='image differs'):
            engine.inspect('work')
        assert verified == []
    else:
        assert engine.inspect('work')['workspaceImageVerified'] is True
        assert verified == [True]


def test_signed_policy_cannot_downgrade_recovery_observation(tmp_path):
    from execution_host.engine import development_seed_identity_error
    workload, _ = _signed_seed_source(tmp_path)
    info = {'rootless': True, 'user': '10001:10001', 'usernsMode': 'host'}
    assert 'base authority' in development_seed_identity_error(workload, info)


def test_revoked_signed_seed_base_refuses_mixed_ledger_boot_without_adoption(tmp_path):
    class SignedSeedEngine(SeedWorkspaceFakeEngine):
        def bind_workspace_image_authority(self, reference, verify):
            self.verify_base = verify
        def inspect(self, workload_id):
            info = super().inspect(workload_id)
            if workload_id == 'workspace-source' and info.get('present'):
                try:
                    self.verify_base()
                except Exception as exc:
                    raise EngineError('signed workspace base authority is unavailable') from exc
                info.update(rootless=True, user='10001:10001', usernsMode='host', workspaceImageVerified=True)
            return info
    engine = SignedSeedEngine()
    daemon = _boot(tmp_path, engine, workspace_image_reference=SIGNED_IMAGE,
                   workspace_spec_digest=contract.canonical_digest(contract.workspace_template_for_image(SIGNED_IMAGE)))
    workload, archive = _signed_seed_source(tmp_path)
    base = _signed_default_grant()
    seeded = grant_document([workload], grantId='seeded-app', imageReference=SIGNED_IMAGE)
    unrelated = grant_document([wspec('independent-workspace')], grantId='independent-app')
    try:
        provision_grants(tmp_path, base, seeded, unrelated)
        with archive.open('rb') as source:
            _client(tmp_path, seeded).create_workspace(workload, source_fd=source.fileno())
        _client(tmp_path, unrelated).create_workspace(wspec('independent-workspace'))
        revocation = tmp_path/'state/grants/revocation.json'
        value = json.loads(revocation.read_text());value['revokedGrantIds'] = ['control-plane-default']
        revocation.write_text(json.dumps(value))
    finally:
        daemon.shutdown()
    restarted = ExecutionHostDaemon(daemon._config, engine)
    try:
        with pytest.raises(DaemonBootError, match='restart reconciliation failed'):
            restarted.boot()
        assert 'workspace-source' in engine.containers and 'independent-workspace' in engine.containers
        assert engine.removed == []
    finally:
        restarted.shutdown()
