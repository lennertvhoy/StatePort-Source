#!/usr/bin/env python3
"""Deterministic tests for the governed Slice A deployment foundation."""

from __future__ import annotations

from copy import deepcopy
from argparse import Namespace
from datetime import datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Mapping, TypeVar

import jsonschema
import pytest
from referencing import Registry, Resource


ROOT = Path(__file__).resolve().parents[1]
DEPLOYMENT_SRC = ROOT / "packages" / "deployment" / "src"
EXECUTION_SRC = ROOT / "packages" / "execution-host" / "src"
ADMIN_SRC = ROOT / "apps" / "admin-cli" / "src"
GOVERNED_SRC = ROOT / "packages" / "governed-runner" / "src"
for candidate in (DEPLOYMENT_SRC, EXECUTION_SRC, ADMIN_SRC, GOVERNED_SRC):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from stateport_deployment.contracts import (  # noqa: E402
    LIFECYCLE_STATES,
    deployment_creation_changes,
    plan_digest,
    validate_deployment_spec,
    validate_plan,
    validate_transition,
)
from stateport_deployment.errors import (  # noqa: E402
    AdapterError,
    DeploymentError,
    DeploymentRefusal,
)
from stateport_deployment.execution_host import (  # noqa: E402
    ExecutionHostDeploymentAdapter,
)
from stateport_deployment.inspection import (  # noqa: E402
    authority_source_identity,
    inspect_project,
)
from stateport_deployment.podman import (  # noqa: E402
    LABEL_DEPLOYMENT,
    LABEL_MANAGED,
    LABEL_NETWORK,
    LABEL_PLAN,
    LABEL_REVISION,
    LABEL_SERVICE,
    LABEL_SOURCE,
    LABEL_STORAGE,
    MAX_OUTPUT_BYTES,
    CommandResult,
    RootlessPodmanAdapter,
)
import stateport_deployment.podman as podman_module  # noqa: E402
from stateport_deployment.service import DeploymentService, PYTHON_BASE  # noqa: E402
import stateport_deployment.service as deployment_service_module  # noqa: E402
from stateport_deployment.store import DeploymentStore  # noqa: E402
from stateport_deployment.util import (  # noqa: E402
    atomic_json,
    digest_value,
    exclusive_lock,
    strict_mapping_document,
)
from governed_runner.authority import (  # noqa: E402
    AuthorityError,
    AuthorityManager,
    grant_template,
)
import admin_cli.deployments as deployment_cli  # noqa: E402
from execution_host import daemon_contract as execution_contract  # noqa: E402
from execution_host.client import (  # noqa: E402
    ExecutionHostClient,
    ExecutionHostTransportError,
)
from execution_host.daemon import DaemonConfig, ExecutionHostDaemon  # noqa: E402
from execution_host.deployment_staging import (  # noqa: E402
    build_deployment_archive,
    reopen_archive_read_only,
)


FIXTURES = ROOT / "fixtures" / "deployments"
DIGEST = "sha256:" + "a" * 64
ACTOR = "test-owner"
SLICE_ID = "BL-DEPLOYMENT-SLICE-A-TEST-001"
TEST_BRANCH = "agent/container-deployment-local-001"
T = TypeVar("T")


@pytest.fixture(autouse=True)
def _stable_cli_branch(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep CLI authority deterministic regardless of the live checkout ref.

    CI checks out pull requests in detached HEAD, where ``git branch
    --show-current`` is empty; the real CLI intentionally refuses that, but
    synthetic CLI tests must bind a stable branch so the grant and reservation
    agree.
    """

    monkeypatch.setattr(deployment_cli, "_branch", lambda _manager: TEST_BRANCH)


def _format_checker() -> jsonschema.FormatChecker:
    """Return a date-time checker even when optional jsonschema extras are absent."""

    checker = jsonschema.FormatChecker()

    @checker.checks("date-time", raises=(TypeError, ValueError))
    def valid_date_time(value: object) -> bool:
        if not isinstance(value, str):
            return False
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return True

    return checker


def _git(*args: str, cwd: Path) -> str:
    completed = subprocess.run(
        ("git", *args), cwd=cwd, capture_output=True, text=True, check=True
    )
    return completed.stdout.strip()


def _git_with_input(cwd: Path, args: tuple[str, ...], value: str) -> str:
    completed = subprocess.run(
        ("git", *args),
        cwd=cwd,
        input=value,
        capture_output=True,
        text=True,
        check=True,
    )
    return completed.stdout.strip()


def authority_harness(
    tmp_path: Path,
    deployment_id: str,
    *,
    actor: str = ACTOR,
    project: Path | None = None,
) -> tuple[AuthorityManager, str]:
    manager = AuthorityManager(
        ROOT, state_root=tmp_path / f"authority-{digest_value(deployment_id)[7:19]}"
    )
    grant_id = f"grant_test_{digest_value(deployment_id)[7:23]}"
    grant = grant_template(
        manager,
        grant_id=grant_id,
        profile="balanced",
        actor_id=actor,
        role="primary",
        branch_pattern=TEST_BRANCH,
        slice_id=SLICE_ID,
        application_id=deployment_id,
        run_id=None,
        paths=(".",),
        allow=(
            "plan_deployment",
            "apply_deployment",
            "observe_deployment",
            "collect_deployment_logs",
            "restart_deployment",
            "remove_deployment_runtime",
            "backup_deployment_data",
            "restore_deployment_data",
            "purge_deployment_data",
        ),
        require_approval=(),
        forbid=(),
        owner_directive_id="OD-DEPLOYMENT-SLICE-A-TEST-001",
        expires_when="slice_closed",
        max_actions=100,
        max_duration_seconds=7200,
        max_cost_usd=0,
        deployment_sources=(
            [
                {
                    key: authority_source_identity(inspect_project(project))[key]
                    for key in ("repositoryIdentity", "projectPath")
                }
            ]
            if project is not None
            else None
        ),
    )
    manager.activate_grant(grant, owner_actor_id="test-owner")
    return manager, grant_id


def reserve_for(
    service: DeploymentService,
    action: str,
    deployment_id: str,
    *,
    run_id: str | None = None,
    source_identity: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    manager = service._authority_manager
    assert manager is not None
    active = manager.list_grants()["grants"]
    assert len(active) == 1
    decision, reservation = manager.reserve_action(
        action,
        actor_id=service.actor,
        grant_id=active[0]["grantId"],
        branch=TEST_BRANCH,
        slice_id=SLICE_ID,
        application_id=deployment_id,
        run_id=run_id,
        paths=(".",),
        estimated_duration_seconds=3600,
        source_identity=source_identity,
    )
    assert reservation is not None
    return decision, reservation


def decision_for(
    service: DeploymentService,
    action: str,
    deployment_id: str,
    *,
    run_id: str | None = None,
    source_identity: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return reserve_for(
        service,
        action,
        deployment_id,
        run_id=run_id,
        source_identity=source_identity,
    )[0]


def governed_call(
    service: DeploymentService,
    action: str,
    deployment_id: str,
    operation: Callable[[dict[str, Any]], T],
    *,
    run_id: str | None = None,
    source_identity: Mapping[str, Any] | None = None,
) -> T:
    """Run one test operation through the same reserve/finalize/link boundary as CLI."""

    manager = service._authority_manager
    assert manager is not None
    decision, reservation = reserve_for(
        service,
        action,
        deployment_id,
        run_id=run_id,
        source_identity=source_identity,
    )
    try:
        result = operation(decision)
    except Exception as exc:
        claimed = manager.has_claim(decision["requestId"])
        outcome = None
        if claimed:
            try:
                outcome = service.store.authority_effect_outcome(
                    deployment_id, decision["requestId"]
                )
            except DeploymentRefusal as outcome_exc:
                if outcome_exc.code != "deployment_not_found":
                    raise
        result_status = (
            outcome["status"]
            if outcome is not None
            else ("failed" if claimed else "not_executed")
        )
        claim = manager.get_claim(decision["requestId"]) if claimed else None
        receipt = manager.record_action(
            decision,
            result_status=result_status,
            summary=(
                outcome["summary"]
                if outcome is not None
                else f"Fixture operation failed with {type(exc).__name__}"
            ),
            code=(
                outcome["code"]
                if outcome is not None
                else getattr(exc, "code", "operation_failed")
            ),
            resource=outcome["resource"] if outcome is not None else None,
            reservation=reservation,
            claim=claim,
        )
        try:
            service.link_authority_receipt(deployment_id, receipt)
        except DeploymentRefusal:
            pass
        raise
    outcome = service.store.authority_effect_outcome(
        deployment_id, decision["requestId"]
    )
    assert outcome is not None and outcome["status"] == "succeeded"
    receipt = manager.record_action(
        decision,
        result_status=outcome["status"],
        summary=outcome["summary"],
        code=outcome["code"],
        resource=outcome["resource"],
        reservation=reservation,
        claim=manager.get_claim(decision["requestId"]),
    )
    service.link_authority_receipt(deployment_id, receipt)
    return result


def plan_authorized(
    service: DeploymentService,
    project: Path,
    deployment_id: str,
) -> dict[str, Any]:
    source_identity = authority_source_identity(service.inspect(project))
    return governed_call(
        service,
        "plan_deployment",
        deployment_id,
        lambda decision: service.plan(
            project,
            deployment_id=deployment_id,
            grant_id=decision["authorizedBy"]["id"],
            authority_decision=decision,
        ),
        source_identity=source_identity,
    )


def committed_fixture(tmp_path: Path, name: str) -> Path:
    destination = tmp_path / name
    shutil.copytree(FIXTURES / name, destination)
    _git("init", "--initial-branch=main", cwd=destination)
    _git("config", "user.name", "StatePort Fixture", cwd=destination)
    _git("config", "user.email", "fixture@stateport.invalid", cwd=destination)
    _git("add", ".", cwd=destination)
    _git("commit", "-m", "fixture", cwd=destination)
    return destination


def committed_project(
    tmp_path: Path, name: str, files: Mapping[str, str]
) -> Path:
    destination = tmp_path / name
    destination.mkdir()
    for relative, content in files.items():
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    _git("init", "--initial-branch=main", cwd=destination)
    _git("config", "user.name", "StatePort Fixture", cwd=destination)
    _git("config", "user.email", "fixture@stateport.invalid", cwd=destination)
    _git("add", ".", cwd=destination)
    _git("commit", "-m", "fixture", cwd=destination)
    return destination


def fake_podman_executable(tmp_path: Path) -> Path:
    executable = tmp_path / "podman"
    executable.write_text(
        """#!/usr/bin/env python3
import os
from pathlib import Path
import subprocess
import sys
import time

operation = sys.argv[1]
if operation == "spawn":
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    Path(sys.argv[2]).write_text(str(child.pid), encoding="utf-8")
    time.sleep(60)
elif operation == "flood":
    os.write(1, b"a" * 700000)
    os.write(2, b"b" * 700000)
else:
    raise SystemExit(2)
""",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    return executable


def test_adapter_timeout_terminates_entire_process_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_podman_executable(tmp_path)
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ.get('PATH', '')}")
    adapter = RootlessPodmanAdapter(timeout_seconds=1)
    child_pid_path = tmp_path / "child.pid"
    with pytest.raises(AdapterError, match="timed out") as observed:
        adapter._run(("spawn", str(child_pid_path)), timeout=1)
    assert observed.value.code == "adapter_timeout"
    child_pid = int(child_pid_path.read_text(encoding="utf-8"))
    child_stat = Path(f"/proc/{child_pid}/stat")
    deadline = time.monotonic() + 2
    while child_stat.exists() and time.monotonic() < deadline:
        try:
            fields = child_stat.read_text(encoding="utf-8").split()
        except (FileNotFoundError, ProcessLookupError):
            break
        if len(fields) > 2 and fields[2] in {"X", "Z"}:
            break
        time.sleep(0.02)
    if child_stat.exists():
        try:
            fields = child_stat.read_text(encoding="utf-8").split()
        except FileNotFoundError:
            fields = []
        assert not fields or (len(fields) > 2 and fields[2] in {"X", "Z"})


def test_adapter_output_uses_one_combined_capture_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_podman_executable(tmp_path)
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ.get('PATH', '')}")
    result = RootlessPodmanAdapter(timeout_seconds=5)._run(("flood",))
    captured = len(result.stdout.encode()) + len(result.stderr.encode())
    assert captured <= MAX_OUTPUT_BYTES + 2 * len("\n[truncated]")
    assert "[truncated]" in result.stdout + result.stderr


def test_adapter_observes_numeric_rootless_user_mapping() -> None:
    adapter = object.__new__(RootlessPodmanAdapter)
    commands: list[tuple[str, ...]] = []

    def record(argv: tuple[str, ...], **_kwargs: Any) -> CommandResult:
        commands.append(tuple(argv))
        return CommandResult(
            ("podman", *argv),
            0,
            "UID HUID\n10001 1000\n10001 1000\n",
            "",
        )

    adapter._run = record
    exact, evidence = adapter._runtime_user_mapping(
        "fixture-container", expected_uid=10001
    )
    assert exact is True
    assert evidence == {
        "status": "keep_id_exact",
        "processesObserved": 2,
        "hostUid": os.geteuid(),
        "containerUid": 10001,
        "returncode": 0,
    }
    assert commands == [("top", "fixture-container", "uid,huid")]


@pytest.mark.parametrize(
    ("kind", "payload", "expected"),
    (
        ("container", [{"names": ["container-one"]}], {"container-one"}),
        ("network", [{"name": "network-one"}], {"network-one"}),
        ("volume", [{"Name": "volume-one"}], {"volume-one"}),
        ("image", [{"id": "sha256:" + "b" * 64}], {"sha256:" + "b" * 64}),
    ),
)
def test_adapter_inventory_accepts_podman_json_field_variants(
    kind: str, payload: list[dict[str, Any]], expected: set[str]
) -> None:
    adapter = object.__new__(RootlessPodmanAdapter)
    adapter._run = lambda *_args, **_kwargs: CommandResult(
        ("podman",), 0, json.dumps(payload), ""
    )
    assert adapter._managed_names(kind, "deployment-fixture") == expected


def test_adapter_redacts_secret_sentinels_from_bounded_logs(
    tmp_path: Path,
) -> None:
    _service, _fake, _project, plan = planned_service(tmp_path)
    adapter = object.__new__(RootlessPodmanAdapter)
    adapter._assert_target_identity = lambda _spec: {}
    adapter._assert_exact_container = lambda *_args, **_kwargs: {}
    sentinel = "STATEPORT_TEST_SECRET_must_not_escape"
    adapter._run = lambda *_args, **_kwargs: CommandResult(
        ("podman", "logs"), 0, f"stdout {sentinel}\n", f"stderr {sentinel}\n"
    )
    result = adapter.logs(
        plan["spec"], expected_revision=plan["planDigest"]
    )
    serialized = json.dumps(result, sort_keys=True)
    assert sentinel not in serialized
    assert serialized.count("[REDACTED]") == 2


def test_container_runtime_clears_inherited_image_behavior_and_is_exact(
    tmp_path: Path,
) -> None:
    _service, _fake, _project, plan = planned_service(
        tmp_path, fixture="persistent-multi"
    )
    adapter = object.__new__(RootlessPodmanAdapter)
    commands: list[tuple[str, ...]] = []
    adapter._assert_owned = lambda *_args, **_kwargs: None

    def record(argv: tuple[str, ...], **_kwargs: Any) -> CommandResult:
        commands.append(tuple(argv))
        return CommandResult(("podman", *argv), 0, "a" * 64 + "\n", "")

    adapter._run = record
    names = adapter.resource_names(plan["spec"])
    images = {service["id"]: DIGEST for service in plan["spec"]["services"]}
    networks = dict(names["networks"])
    volumes = dict(names["volumes"])
    adapter._run_services(plan, names, images, networks, volumes)
    run_commands = [command for command in commands if command[0] == "run"]
    assert len(run_commands) == len(plan["spec"]["services"])
    for service, command in zip(plan["spec"]["services"], run_commands):
        assert "--entrypoint=[]" in command
        assert "--unsetenv-all" in command
        assert "--image-volume=ignore" in command
        assert "--read-only-tmpfs=false" in command
        assert "--cap-drop=all" in command
        assert "--security-opt=no-new-privileges" in command
        assert "--ipc=private" in command
        assert "--pid=private" in command
        assert "--uts=private" in command
        assert "--init" in command
        assert "/tmp:rw,noexec,nosuid,nodev,size=64m" in command
        assert "--log-driver" in command
        assert "k8s-file" in command
        for key, value in service["environment"].items():
            assert f"{key}={value}" in command
        for storage in service["storage"]:
            assert (
                f"{volumes[storage['id']]}:{storage['mountPath']}:rw,nodev,nosuid,noexec"
                in command
            )


def test_runtime_observation_detects_inherited_and_security_drift(
    tmp_path: Path,
) -> None:
    _service, _fake, _project, plan = planned_service(tmp_path)
    spec = plan["spec"]
    service = spec["services"][0]
    adapter = object.__new__(RootlessPodmanAdapter)
    names = adapter.resource_names(spec)
    image = DIGEST
    labels = {
        LABEL_MANAGED: "true",
        LABEL_DEPLOYMENT: spec["metadata"]["deploymentId"],
        LABEL_SERVICE: service["id"],
        LABEL_PLAN: plan["planDigest"],
        LABEL_SOURCE: spec["source"]["commit"],
        LABEL_REVISION: plan["planDigest"],
        LABEL_NETWORK: service["networks"][0],
    }
    image_record = {"Id": image, "Labels": labels}
    network_name = names["networks"][service["networks"][0]]
    port = service["ports"][0]
    container = {
        "Id": "c" * 64,
        "Image": image,
        "Labels": labels,
        "State": {"Running": True},
        "Config": {
            "User": f"{service['runtime']['user']['uid']}:{service['runtime']['user']['gid']}",
            "WorkingDir": service["runtime"]["workdir"],
            "Cmd": list(service["runtime"]["command"]),
            "Entrypoint": [],
            "Env": [
                *[f"{key}={value}" for key, value in service["environment"].items()],
                "HOSTNAME=" + "c" * 12,
            ],
            "Annotations": {
                "io.podman.annotations.userns": "keep-id:uid=10001,gid=10001"
            },
        },
        "HostConfig": {
            "ReadonlyRootfs": True,
            "Privileged": False,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges"],
            "PidsLimit": service["resources"]["pidsLimit"],
            "Memory": 256 * 1024 * 1024,
            "NanoCpus": int(service["resources"]["cpuLimit"] * 1_000_000_000),
            "Init": True,
            "UsernsMode": "private",
            "NetworkMode": network_name,
            "PidMode": "private",
            "IpcMode": "private",
            "Devices": [],
            "Tmpfs": {"/tmp": "rw,noexec,nosuid,nodev,size=64m"},
            "LogConfig": {"Type": "k8s-file", "Config": {"max-size": "1m"}},
        },
        "NetworkSettings": {
            "Networks": {network_name: {"Aliases": [service["id"]]}},
            "Ports": {
                f"{port['containerPort']}/tcp": [
                    {"HostIp": port["hostAddress"], "HostPort": "41001"}
                ]
            },
        },
        "Mounts": [],
    }
    adapter._assert_target_identity = lambda _spec: {
        "identityDigest": spec["target"]["identityDigest"]
    }
    adapter._assert_owned = lambda kind, _name, _deployment: (
        container
        if kind == "container"
        else (
            image_record
            if kind == "image"
            else {"Internal": True, "Labels": labels}
        )
    )
    adapter._managed_names = lambda kind, _deployment: (
        set(names[f"{kind}s"].values())
        if kind in {"container", "network", "volume"}
        else (
            {f"{names['images'][service['id']]}:{plan['planDigest'][7:19]}"}
            if kind == "image"
            else set()
        )
    )
    adapter._service_health = lambda _service, _name: (
        True,
        {"status": "healthy"},
    )
    adapter._runtime_capabilities = lambda _name: (
        True,
        {"status": "none", "processesObserved": 1, "returncode": 0},
    )
    adapter._runtime_user_mapping = lambda _name, expected_uid: (
        True,
        {
            "status": "keep_id_exact",
            "processesObserved": 1,
            "hostUid": os.geteuid(),
            "containerUid": expected_uid,
            "returncode": 0,
        },
    )
    observed = adapter.observe(
        spec,
        expected_revision=plan["planDigest"],
        expected_images={service["id"]: image},
        verify_health=True,
    )
    assert observed["drift"] == []

    # Podman 5.8 reports an exact 1 MiB k8s-file limit through Size instead
    # of Config even though the run command used max-size=1m.
    container["HostConfig"]["LogConfig"] = {
        "Type": "k8s-file",
        "Config": None,
        "Size": "1MB",
    }
    normalized = adapter.observe(
        spec,
        expected_revision=plan["planDigest"],
        expected_images={service["id"]: image},
    )
    assert "log_policy_changed:web" not in normalized["drift"]

    container["Mounts"].append(
        {
            "Type": "bind",
            "Source": "/run/user/1000/podman/podman.sock",
            "Destination": "/run/podman/podman.sock",
            "RW": True,
        }
    )
    mount_drift = adapter.observe(
        spec,
        expected_revision=plan["planDigest"],
        expected_images={service["id"]: image},
    )
    assert f"unsupported_mount_changed:{service['id']}" in mount_drift["drift"]
    container["Mounts"].clear()

    image_record["Id"] = "sha256:" + "b" * 64
    image_drift = adapter.observe(
        spec,
        expected_revision=plan["planDigest"],
        expected_images={service["id"]: image},
    )
    assert f"image_identity_changed:{service['id']}" in image_drift["drift"]
    image_record["Id"] = image

    container["Config"]["Entrypoint"] = ["/malicious"]
    container["Config"]["Env"].append("INHERITED=unsafe")
    container["HostConfig"]["SecurityOpt"] = [
        "no-new-privileges",
        "seccomp=unconfined",
    ]
    container["HostConfig"]["PidMode"] = "container:other"
    drifted = adapter.observe(
        spec,
        expected_revision=plan["planDigest"],
        expected_images={service["id"]: image},
    )
    assert f"entrypoint_changed:{service['id']}" in drifted["drift"]
    assert f"environment_changed:{service['id']}" in drifted["drift"]
    assert f"security_options_changed:{service['id']}" in drifted["drift"]
    assert f"host_namespace_runtime:{service['id']}" in drifted["drift"]


def test_http_health_is_observed_directly_not_self_attested(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _service, _fake, _project, plan = planned_service(tmp_path)
    service = deepcopy(plan["spec"]["services"][0])
    service["health"]["command"] = ["true"]
    adapter = object.__new__(RootlessPodmanAdapter)
    adapter._inspect = lambda _kind, _name: {
        "NetworkSettings": {
            "Ports": {
                f"{service['ports'][0]['containerPort']}/tcp": [
                    {
                        "HostIp": service["ports"][0]["hostAddress"],
                        "HostPort": "41001",
                    }
                ]
            }
        }
    }
    adapter._run = lambda *_args, **_kwargs: pytest.fail(
        "HTTP health must not execute the project-supplied command"
    )

    class Response:
        status = 503

        @staticmethod
        def read(_limit: int) -> bytes:
            return b"unhealthy"

    class Connection:
        def __init__(self, host: str, port: int, timeout: int) -> None:
            assert host == "127.0.0.1"
            assert port == 41001
            assert timeout == service["health"]["timeoutSeconds"]

        @staticmethod
        def request(method: str, path: str) -> None:
            assert (method, path) == ("GET", service["health"]["path"])

        @staticmethod
        def getresponse() -> Response:
            return Response()

        @staticmethod
        def close() -> None:
            return None

    monkeypatch.setattr(podman_module.http.client, "HTTPConnection", Connection)
    healthy, evidence = adapter._service_health(service, "fixture-container")
    assert healthy is False
    assert evidence["status"] == "unhealthy"
    assert evidence["statusCode"] == 503


@pytest.mark.parametrize("failure", ("missing", "wrong_label"))
def test_purge_preflights_every_volume_before_any_deletion(
    tmp_path: Path, failure: str
) -> None:
    _service, _fake, _project, plan = planned_service(
        tmp_path, fixture="persistent-multi"
    )
    spec = deepcopy(plan["spec"])
    spec["services"][0]["storage"].append(
        {
            "id": "audit-data",
            "mountPath": "/audit-data",
            "persistence": "retained",
        }
    )
    adapter = object.__new__(RootlessPodmanAdapter)
    names = adapter.resource_names(spec)
    expected = dict(names["volumes"])
    observed_volume_names = set(expected.values())
    if failure == "missing":
        observed_volume_names.remove(expected["audit-data"])
    commands: list[tuple[str, ...]] = []
    adapter._assert_target_identity = lambda _spec: {
        "identityDigest": spec["target"]["identityDigest"]
    }
    adapter._managed_names = lambda kind, _deployment: (
        set(observed_volume_names) if kind == "volume" else set()
    )

    def owned(kind: str, name: str, _deployment: str) -> dict[str, Any] | None:
        if kind != "volume" or name not in observed_volume_names:
            return None
        storage_id = next(key for key, value in expected.items() if value == name)
        return {
            "Labels": {
                LABEL_MANAGED: "true",
                LABEL_DEPLOYMENT: spec["metadata"]["deploymentId"],
                LABEL_STORAGE: storage_id,
                LABEL_PLAN: (
                    "sha256:" + "f" * 64
                    if failure == "wrong_label" and storage_id == "audit-data"
                    else plan["planDigest"]
                ),
                LABEL_REVISION: plan["planDigest"],
                LABEL_SOURCE: spec["source"]["commit"],
            }
        }

    adapter._assert_owned = owned
    adapter._run = lambda argv, **_kwargs: (
        commands.append(tuple(argv))
        or CommandResult(("podman", *argv), 0, "", "")
    )
    with pytest.raises(AdapterError) as refused:
        adapter.purge_data(
            spec,
            expected_volumes=expected,
            expected_revision=plan["planDigest"],
        )
    assert refused.value.code == "purge_identity_mismatch"
    assert commands == []


def test_partial_remove_distinguishes_interrupted_apply_from_interrupted_remove(
    tmp_path: Path,
) -> None:
    _service, _fake, _project, plan = planned_service(
        tmp_path, fixture="persistent-multi"
    )
    spec = plan["spec"]
    adapter = object.__new__(RootlessPodmanAdapter)
    adapter._assert_target_identity = lambda _spec: {
        "identityDigest": spec["target"]["identityDigest"]
    }
    adapter._managed_names = lambda _kind, _deployment: set()
    adapter._assert_owned = lambda *_args, **_kwargs: None
    adapter._run = lambda *_args, **_kwargs: pytest.fail(
        "an absent interrupted-apply resource must not be touched"
    )

    recovered_apply = adapter.remove_runtime(
        spec,
        expected_revision=plan["planDigest"],
        recovery_operation="apply",
    )
    assert recovered_apply["partialRecovery"] is True
    assert recovered_apply["retainedStorageIdentities"] == {}

    with pytest.raises(AdapterError) as missing_retained:
        adapter.remove_runtime(
            spec,
            expected_revision=plan["planDigest"],
            recovery_operation="remove",
        )
    assert missing_retained.value.code == "unknown_runtime_residue"
    assert missing_retained.value.details["inventoryDifferences"]["volume"][
        "missing"
    ]


class FakeAdapter:
    def __init__(self, *, target_digest: str = DIGEST, fail: bool = False) -> None:
        self.target_digest = target_digest
        self.fail = fail
        self.fail_cleanup: Mapping[str, Any] | None = None
        self.present = False
        self.plan: Mapping[str, Any] | None = None
        self.images: dict[str, str] = {}
        self.volumes: dict[str, str] = {}
        self.volume_data: dict[str, str] = {}
        self.backups: dict[str, dict[str, str]] = {}
        self.calls: list[str] = []

    def probe(self) -> dict[str, Any]:
        self.calls.append("probe")
        return {
            "adapter": "rootless-podman-local",
            "targetId": "local",
            "architecture": "linux-amd64",
            "identityDigest": self.target_digest,
        }

    def materialize_context(self, plan: Mapping[str, Any], destination: Path) -> dict[str, Any]:
        self.calls.append("materialize_context")
        return RootlessPodmanAdapter.materialize_context(self, plan, destination)

    def apply(self, plan: Mapping[str, Any], **_: Any) -> dict[str, Any]:
        self.calls.append("apply")
        self.plan = plan
        if self.fail:
            raise AdapterError(
                "health_verification_failed",
                "fixture failure",
                details={
                    "cleanup": dict(self.fail_cleanup)
                    if self.fail_cleanup is not None
                    else {"uncertain": [], "removed": {}, "verified": True}
                },
            )
        self.present = True
        self.images = {
            service["id"]: "sha256:" + format(index + 1, "064x")
            for index, service in enumerate(plan["spec"]["services"])
        }
        self.volumes = {
            item["id"]: f"volume-{item['id']}"
            for service in plan["spec"]["services"]
            for item in service["storage"]
        }
        self.volume_data = {
            storage_id: self.volume_data.get(storage_id, "fixture-data")
            for storage_id in self.volumes
        }
        health = {
            service["id"]: {"status": "healthy"}
            for service in plan["spec"]["services"]
        }
        observation = self.observe(plan["spec"])
        return {
            "adapter": "rootless-podman-local",
            "target": {
                "adapter": "rootless-podman-local",
                "targetId": "local",
                "architecture": "linux-amd64",
                "identityDigest": self.target_digest,
            },
            "networks": {
                network["id"]: f"fake-{network['id']}"
                for network in plan["spec"]["networks"]
            },
            "images": self.images,
            "imageMaterials": {
                service["id"]: {
                    "reference": (
                        service["image"]["reference"]
                        if service["build"]["mode"] == "image"
                        else deployment_service_module._expected_material_reference(
                            plan, service
                        )
                    ),
                    "manifestDigest": (
                        service["image"]["reference"]
                        if service["build"]["mode"] == "image"
                        else deployment_service_module._expected_material_reference(
                            plan, service
                        )
                    ).rsplit("@", 1)[1],
                    "imageDigest": (
                        self.images[service["id"]]
                        if service["build"]["mode"] == "image"
                        else "sha256:" + format(index + 101, "064x")
                    ),
                    "platform": "linux/amd64",
                }
                for index, service in enumerate(plan["spec"]["services"])
            },
            "services": {
                service["id"]: {
                    "name": observation["services"][service["id"]]["name"],
                    "containerId": observation["services"][service["id"]].get(
                        "containerId", f"fake-{service['id']}-id"
                    ),
                    "imageDigest": self.images[service["id"]],
                }
                for service in plan["spec"]["services"]
            },
            "health": health,
            "volumes": self.volumes,
            "observation": observation,
        }

    def observe(self, spec: Mapping[str, Any], **_: Any) -> dict[str, Any]:
        self.calls.append("observe")
        revision = self.plan["planDigest"] if self.present and self.plan else None
        services = {
            item["id"]: {
                "name": f"fake-{item['id']}",
                "present": self.present,
                "running": self.present,
                "imageDigest": self.images.get(item["id"]),
                "revision": revision,
                "sourceCommit": spec["source"]["commit"] if self.present else None,
                "containerId": f"fake-{item['id']}-id" if self.present else None,
            }
            for item in spec["services"]
        }
        drift = [] if self.present else [f"container_missing:{item['id']}" for item in spec["services"]]
        return {
            "observedAt": "2026-07-30T00:00:00Z",
            "targetIdentity": self.target_digest,
            "observedRevision": revision,
            "services": services,
            "drift": drift,
            "health": {item["id"]: {"status": "healthy"} for item in spec["services"]} if self.present else {},
            "networks": {
                network["id"]: {
                    "name": f"fake-{network['id']}",
                    "present": self.present,
                    "internal": True,
                }
                for network in spec["networks"]
            },
            "volumes": {
                item["id"]: {
                    "name": self.volumes.get(item["id"]),
                    "present": item["id"] in self.volumes,
                    "persistence": item["persistence"],
                    "planDigest": self.plan["planDigest"] if self.plan else None,
                    "revision": self.plan["planDigest"] if self.plan else None,
                    "sourceCommit": (
                        self.plan["spec"]["source"]["commit"]
                        if self.plan
                        else None
                    ),
                }
                for service in spec["services"] for item in service["storage"]
            },
            "images": {
                item["id"]: {
                    "name": f"fake-image-{item['id']}",
                    "present": self.present,
                    "imageDigest": self.images.get(item["id"]),
                }
                for item in spec["services"]
                if item["build"]["mode"] == "source"
            },
            "unexpectedResources": {
                "containers": [],
                "networks": [],
                "volumes": [],
                "images": [],
            },
            "status": "in_sync" if not drift else "drifted",
        }

    def logs(self, spec: Mapping[str, Any], **_: Any) -> dict[str, Any]:
        self.calls.append("logs")
        return {
            "deploymentId": spec["metadata"]["deploymentId"],
            "logs": {service["id"]: "fixture log\n" for service in spec["services"]},
            "redacted": True,
            "bounded": True,
        }

    def restart(self, spec: Mapping[str, Any], **_: Any) -> dict[str, Any]:
        self.calls.append("restart")
        if not self.present:
            raise AdapterError("runtime_missing", "fixture runtime is absent")
        return {
            "health": {item["id"]: {"status": "healthy"} for item in spec["services"]},
            "observation": self.observe(spec),
        }

    def remove_runtime(
        self,
        spec: Mapping[str, Any],
        *,
        recovery_operation: str | None = None,
        **_: Any,
    ) -> dict[str, Any]:
        self.calls.append("remove_runtime")
        self.present = False
        self.images = {}
        retained_ids = {
            item["id"]
            for service in spec["services"]
            for item in service["storage"]
            if item["persistence"] != "ephemeral"
        }
        retained_storage = {
            key: value for key, value in self.volumes.items() if key in retained_ids
        }
        return {
            "removed": {"containers": [item["id"] for item in spec["services"]], "networks": ["internal"]},
            "retainedVolumes": list(retained_storage.values()),
            "retainedStorageIdentities": retained_storage,
            "ordinaryRemovalPreservedData": True,
            "verifiedRuntimeAbsent": True,
            "partialRecovery": recovery_operation is not None,
            "recoveryOperation": recovery_operation,
        }

    def purge_data(
        self,
        _spec: Mapping[str, Any],
        *,
        expected_volumes: Mapping[str, str],
        expected_revision: str,
        recover_interrupted: bool = False,
    ) -> dict[str, Any]:
        self.calls.append("purge_data")
        if not isinstance(expected_revision, str) or not expected_revision.startswith(
            "sha256:"
        ):
            raise AdapterError(
                "purge_identity_mismatch", "fixture purge revision differs"
            )
        if dict(expected_volumes) != self.volumes:
            raise AdapterError(
                "purge_identity_mismatch", "fixture purge identity differs"
            )
        removed = list(expected_volumes.values())
        self.volumes = {}
        return {
            "purgedVolumes": removed,
            "alreadyAbsentVolumes": [],
            "irreversible": True,
            "verifiedAbsent": True,
            "interruptedRecovery": recover_interrupted,
        }

    def backup_data(
        self,
        spec: Mapping[str, Any],
        *,
        backup_id: str,
        expected_volumes: Mapping[str, str],
        expected_revision: str,
        **_: Any,
    ) -> dict[str, Any]:
        self.calls.append("backup_data")
        if not self.present or dict(expected_volumes) != {
            key: self.volumes[key] for key in expected_volumes
        }:
            raise AdapterError(
                "backup_identity_mismatch", "fixture backup identity differs"
            )
        snapshot = {
            storage_id: self.volume_data[storage_id]
            for storage_id in expected_volumes
        }
        self.backups[backup_id] = snapshot
        storage = {
            storage_id: {
                "artifactId": f"{backup_id}/{storage_id}.tar",
                "contentDigest": digest_value(snapshot[storage_id]),
                "fileCount": 1,
                "bytes": len(snapshot[storage_id].encode("utf-8")),
            }
            for storage_id in sorted(snapshot)
        }
        return {
            "backupId": backup_id,
            "sourceRevision": expected_revision,
            "createdAt": "2026-07-30T00:00:00Z",
            "storage": storage,
            "health": {
                service["id"]: {"status": "healthy"}
                for service in spec["services"]
            },
            "observation": self.observe(spec),
        }

    def restore_data(
        self,
        spec: Mapping[str, Any],
        *,
        backup: Mapping[str, Any],
        expected_volumes: Mapping[str, str],
        **_: Any,
    ) -> dict[str, Any]:
        self.calls.append("restore_data")
        backup_id = backup["backupId"]
        snapshot = self.backups.get(backup_id)
        if snapshot is None or dict(expected_volumes) != {
            key: self.volumes[key] for key in expected_volumes
        }:
            raise AdapterError(
                "backup_identity_mismatch", "fixture restore identity differs"
            )
        self.volume_data.update(snapshot)
        del self.backups[backup_id]
        return {
            "backupId": backup_id,
            "backupDigest": backup["backupDigest"],
            "backupConsumed": True,
            "restoredAt": "2026-07-30T00:01:00Z",
            "health": {
                service["id"]: {"status": "healthy"}
                for service in spec["services"]
            },
            "observation": self.observe(spec),
        }


def planned_service(tmp_path: Path, fixture: str = "python-http") -> tuple[DeploymentService, FakeAdapter, Path, dict[str, Any]]:
    project = committed_fixture(tmp_path, fixture)
    adapter = FakeAdapter()
    deployment_id = f"deployment-{fixture}"
    manager, grant_id = authority_harness(
        tmp_path, deployment_id, project=project
    )
    service = DeploymentService(
        state_root=tmp_path / "state",
        adapter=adapter,
        authority_manager=manager,
        actor=ACTOR,
    )
    assert grant_id
    plan = plan_authorized(service, project, deployment_id)
    return service, adapter, project, plan


def apply_authorized(
    service: DeploymentService, deployment_id: str, plan_digest: str
) -> dict[str, Any]:
    return governed_call(
        service,
        "apply_deployment",
        deployment_id,
        lambda decision: service.apply(
            deployment_id,
            accept_plan_digest=plan_digest,
            authority_decision=decision,
        ),
        run_id=plan_digest,
    )


@pytest.mark.parametrize(
    ("fixture", "detected"),
    (
        ("python-http", "python"),
        ("node-http", "node"),
        ("static-web", "static_web"),
        ("persistent-multi", "stateport_descriptor"),
        ("compose-http", "compose"),
        ("containerfile-http", "containerfile"),
        ("dockerfile-http", "containerfile"),
    ),
)
def test_inspection_is_read_only_and_supports_all_profiles(tmp_path: Path, fixture: str, detected: str) -> None:
    project = committed_fixture(tmp_path, fixture)
    before = sorted(path.relative_to(project).as_posix() for path in project.rglob("*") if ".git" not in path.parts)
    result = DeploymentService(state_root=tmp_path / "must-not-exist").inspect(project)
    after = sorted(path.relative_to(project).as_posix() for path in project.rglob("*") if ".git" not in path.parts)
    assert detected in result["detectedProjectTypes"]
    assert result["deterministicAssistedPlanningSupported"] is True
    assert result["unsafeConstructs"] == []
    assert result["sideEffects"] == []
    assert before == after
    assert not (tmp_path / "must-not-exist").exists()


def test_descriptor_inspection_exposes_exact_runtime_review_fields(
    tmp_path: Path,
) -> None:
    project = committed_fixture(tmp_path, "persistent-multi")
    inspection = inspect_project(project)
    assert inspection["commands"] == ["python3 app.py"]
    assert inspection["ports"] == [8080]
    assert inspection["persistentPaths"] == ["/data"]
    assert len(inspection["candidateServices"]) == 2
    for service in inspection["candidateServices"]:
        assert service["build"] == {
            "mode": "source",
            "context": ".",
            "containerfile": "Containerfile",
            "generated": False,
        }
        assert service["command"] == ["python3", "app.py"]
        assert service["ports"][0]["containerPort"] == 8080
        assert service["storage"] == [
            {
                "id": "app-data",
                "mountPath": "/data",
                "persistence": "retained",
            }
        ]
        assert service["health"]["type"] == "http"
        assert service["health"]["path"] == "/health"


@pytest.mark.parametrize("fixture", ("python-http", "node-http", "static-web"))
def test_assisted_inspection_and_plan_share_exact_generated_runtime_contract(
    tmp_path: Path, fixture: str
) -> None:
    service, _adapter, project, plan = planned_service(tmp_path, fixture)
    inspection = service.inspect(project)
    assert len(inspection["candidateServices"]) == 1
    candidate = inspection["candidateServices"][0]
    planned = plan["spec"]["services"][0]
    assert candidate["sourcePath"] == planned["sourcePath"]
    assert candidate["build"] == planned["build"]
    assert candidate["command"] == planned["runtime"]["command"]
    assert candidate["runtimeUser"] == planned["runtime"]["user"]
    assert candidate["ports"] == planned["ports"]
    assert candidate["storage"] == planned["storage"]
    assert candidate["health"] == planned["health"]
    assert candidate["networks"] == planned["networks"]


@pytest.mark.parametrize(
    ("service_addition", "service_replacement", "expected_finding"),
    (
        ("    restart: always\n", "", "compose:compose_unsupported"),
        ("    privileged: true\n", "", "compose:privileged_container"),
        ("    network_mode: host\n", "", "compose:host_namespace"),
        ("", '    user: "0:0"\n', "compose:root_runtime"),
        (
            "    volumes: [/etc:/data]\n",
            "",
            "compose:unsafe_mount",
        ),
        (
            "    volumes: [/:/data]\n",
            "",
            "compose:unsafe_mount",
        ),
        (
            "    volumes: [/home/stateport:/data]\n",
            "",
            "compose:unsafe_mount",
        ),
        (
            "    volumes: [/run/user/1000/podman/podman.sock:/run/engine.sock]\n",
            "",
            "compose:unsafe_mount",
        ),
        (
            "    environment:\n      MODE: ${MODE}\n",
            "",
            "compose:compose_unsupported",
        ),
        (
            "",
            "OMIT_HEALTH",
            "compose:missing_health",
        ),
    ),
)
def test_compose_inspection_and_planning_share_one_strict_contract(
    tmp_path: Path,
    service_addition: str,
    service_replacement: str,
    expected_finding: str,
) -> None:
    containerfile = (FIXTURES / "compose-http" / "Containerfile").read_text(
        encoding="utf-8"
    )
    app = (FIXTURES / "compose-http" / "app.py").read_text(encoding="utf-8")
    user = (
        service_replacement
        if service_replacement.startswith("    user")
        else '    user: "10001:10001"\n'
    )
    health = (
        ""
        if service_replacement == "OMIT_HEALTH"
        else "    healthcheck:\n"
        "      test: [CMD, python3, -c, \"import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health').read()\"]\n"
    )
    compose = (
        "name: strict-compose\n"
        "services:\n"
        "  web:\n"
        "    build: {context: ., dockerfile: Containerfile}\n"
        "    command: [python3, app.py]\n"
        + user
        + "    ports: [\"127.0.0.1:0:8080\"]\n"
        + health
        + service_addition
        + "networks:\n  internal: {}\n"
    )
    project = committed_project(
        tmp_path,
        "strict-compose",
        {"Containerfile": containerfile, "app.py": app, "compose.yaml": compose},
    )
    inspection = inspect_project(project)
    assert inspection["deterministicAssistedPlanningSupported"] is False
    assert expected_finding in inspection["unsafeConstructs"]


@pytest.mark.parametrize(
    ("fixture", "required_change_kinds"),
    (
        ("python-http", {"network", "service", "image", "port"}),
        ("node-http", {"network", "service", "image", "port"}),
        ("static-web", {"network", "service", "image", "port"}),
        (
            "persistent-multi",
            {"network", "service", "image", "port", "storage"},
        ),
        ("compose-http", {"network", "service", "image", "port"}),
        ("containerfile-http", {"network", "service", "image", "port"}),
        ("dockerfile-http", {"network", "service", "image", "port"}),
    ),
)
def test_all_fixture_plans_expose_exact_reviewable_resource_changes(
    tmp_path: Path, fixture: str, required_change_kinds: set[str]
) -> None:
    service, _adapter, _project, plan = planned_service(tmp_path, fixture)
    assert {item["kind"] for item in plan["changes"]} >= required_change_kinds
    assert plan["changes"] == deployment_creation_changes(plan["spec"])
    assert service.store.load_plan(
        plan["spec"]["metadata"]["deploymentId"], plan["planDigest"]
    ) == plan
    summary = deployment_cli._human_summary("plan", plan)
    assert "Changes:" in summary
    assert "Approval required:" in summary
    assert "Data-retention effects:" in summary


def test_plan_change_set_shows_secret_identifiers_without_values(
    tmp_path: Path,
) -> None:
    _service, _adapter, _project, plan = planned_service(tmp_path)
    spec = deepcopy(plan["spec"])
    spec["services"][0]["secrets"] = [
        {
            "id": "api-token",
            "binding": "secret-broker://fixture/api-token",
        }
    ]
    spec["authority"]["requireApproval"].append("secret_binding")
    changes = deployment_creation_changes(validate_deployment_spec(spec))
    secret_changes = [item for item in changes if item["kind"] == "secret_binding"]
    assert secret_changes == [
        {
            "kind": "secret_binding",
            "action": "bind",
            "id": "web.api-token",
            "serviceId": "web",
            "secretId": "api-token",
            "binding": "secret-broker://fixture/api-token",
        }
    ]


def test_human_deployment_summaries_expose_review_truth_without_secret_values(
    tmp_path: Path,
) -> None:
    service, _adapter, project, plan = planned_service(tmp_path)
    inspected = service.inspect(project)
    inspected["authorityReceipt"] = {
        "receiptId": "authority_receipt_fixture",
        "receiptDigest": DIGEST,
    }
    inspection_summary = deployment_cli._human_summary("inspect", inspected)
    assert "Side effects: none" in inspection_summary
    assert "Candidate services:" in inspection_summary
    assert "Authority receipt: authority_receipt_fixture" in inspection_summary

    plan["authorityReceipt"] = inspected["authorityReceipt"]
    plan_summary = deployment_cli._human_summary("plan", plan)
    assert "Changes:" in plan_summary
    assert "create service" in plan_summary
    assert "Authority receipt: authority_receipt_fixture" in plan_summary

    state = service.store.load_state("deployment-python-http")
    status_summary = deployment_cli._human_summary(
        "status",
        {
            "state": state,
            "receipt": {
                "receiptId": "receipt_fixture",
                "receiptDigest": DIGEST,
            },
            "authorityReceipt": inspected["authorityReceipt"],
        },
    )
    for expected in (
        "Source:",
        "Target:",
        "Images:",
        "Service health:",
        "Storage:",
        "Removal state:",
        "Retained data:",
        "Deployment receipt: receipt_fixture",
        "Authority receipt: authority_receipt_fixture",
        "Linked authority receipts:",
    ):
        assert expected in status_summary
    assert "STATEPORT_TEST_SECRET" not in inspection_summary + plan_summary + status_summary


def test_deployment_errors_use_typed_exit_categories() -> None:
    assert DeploymentRefusal("dirty_source", "refused").exit_code == 2
    assert AdapterError("health_verification_failed", "failed").exit_code == 3
    assert DeploymentRefusal(
        "authority_effect_unfinalized", "reconcile"
    ).exit_code == 4


@pytest.mark.parametrize(
    ("name", "files", "blocker"),
    (
        (
            "python-marker-only",
            {"pyproject.toml": "[project]\nname='marker-only'\n"},
            "python:python_runtime_command_unknown",
        ),
        (
            "python-dependencies",
            {"app.py": "print('x')\n", "requirements.txt": "flask==3.0.0\n"},
            "python:assisted_dependencies_unsupported",
        ),
        (
            "node-no-server",
            {"package.json": '{"scripts":{"start":"node server.js"}}\n'},
            "node:node_runtime_command_unknown",
        ),
        (
            "node-command",
            {
                "package.json": '{"scripts":{"start":"vite"}}\n',
                "server.js": "console.log('x')\n",
            },
            "node:assisted_command_unsupported",
        ),
        (
            "root-static-ambiguous",
            {"index.html": "ok\n", "README.md": "not a public asset\n"},
            "static:static_source_scope_ambiguous",
        ),
    ),
)
def test_inspection_reports_exact_assisted_profile_blockers(
    tmp_path: Path,
    name: str,
    files: Mapping[str, str],
    blocker: str,
) -> None:
    project = committed_project(tmp_path, name, files)
    inspection = inspect_project(project)
    assert inspection["deterministicAssistedPlanningSupported"] is False
    assert blocker in inspection["unknowns"]
    assert inspection["candidateServices"] == []


def test_nonviable_node_marker_does_not_hide_nested_static_profile(
    tmp_path: Path,
) -> None:
    project = committed_project(
        tmp_path,
        "nested-static",
        {
            "package.json": '{"scripts":{"start":"vite"}}\n',
            "dist/index.html": "<!doctype html><title>static</title>\n",
            "dist/app.js": "console.log('static')\n",
        },
    )
    inspection = inspect_project(project)
    assert inspection["deterministicAssistedPlanningSupported"] is True
    assert len(inspection["candidateServices"]) == 1
    candidate = inspection["candidateServices"][0]
    assert candidate["id"] == "web"
    assert candidate["source"] == "assisted_static"
    assert candidate["sourcePath"] == "dist"
    assert candidate["build"] == {
        "mode": "source",
        "context": "dist",
        "containerfile": "web.Containerfile",
        "generated": True,
    }
    assert candidate["ports"][0]["containerPort"] == 8080
    assert candidate["runtimeUser"]["mode"] == "nonroot"
    manager, _grant_id = authority_harness(
        tmp_path, "nested-static-deployment", project=project
    )
    service = DeploymentService(
        state_root=tmp_path / "nested-static-state",
        adapter=FakeAdapter(),
        authority_manager=manager,
        actor=ACTOR,
    )
    plan = plan_authorized(service, project, "nested-static-deployment")
    assert plan["spec"]["services"][0]["sourcePath"] == "dist"


def test_multiple_viable_assisted_profiles_are_typed_ambiguous(
    tmp_path: Path,
) -> None:
    project = committed_project(
        tmp_path,
        "ambiguous-assisted",
        {
            "app.py": "print('python')\n",
            "package.json": '{"scripts":{"start":"node server.js"}}\n',
            "server.js": "console.log('node')\n",
        },
    )
    inspection = inspect_project(project)
    assert inspection["deterministicAssistedPlanningSupported"] is False
    assert "assisted_profile_ambiguous" in inspection["unknowns"]
    assert {item["source"] for item in inspection["candidateServices"]} == {
        "assisted_python",
        "assisted_node",
    }


@pytest.mark.parametrize(
    ("mutation", "finding"),
    (
        ('ENTRYPOINT ["/bin/sh"]\n', "descriptor:containerfile_unsupported"),
        ("ADD app.py /tmp/app.py\n", "descriptor:containerfile_unsupported"),
    ),
)
def test_descriptor_containerfiles_use_the_strict_declared_build_contract(
    tmp_path: Path, mutation: str, finding: str
) -> None:
    project = committed_fixture(tmp_path, "persistent-multi")
    containerfile = project / "Containerfile"
    containerfile.write_text(
        containerfile.read_text(encoding="utf-8") + mutation,
        encoding="utf-8",
    )
    _git("add", "Containerfile", cwd=project)
    _git("commit", "-m", "unsafe declared build", cwd=project)
    inspection = inspect_project(project)
    assert finding in inspection["unsafeConstructs"]
    assert inspection["deterministicAssistedPlanningSupported"] is False
    manager, _ = authority_harness(
        tmp_path, "unsafe-descriptor", project=project
    )
    service = DeploymentService(
        state_root=tmp_path / "state",
        adapter=FakeAdapter(),
        authority_manager=manager,
        actor=ACTOR,
    )
    with pytest.raises(DeploymentRefusal, match="unsafe deployment constructs"):
        plan_authorized(service, project, "unsafe-descriptor")


def test_project_descriptor_cannot_spoof_generated_overlay_provenance(
    tmp_path: Path,
) -> None:
    project = committed_fixture(tmp_path, "persistent-multi")
    descriptor = project / "stateport.deployment.yaml"
    descriptor.write_text(
        descriptor.read_text(encoding="utf-8").replace(
            "generated: false", "generated: true", 1
        ),
        encoding="utf-8",
    )
    _git("add", "stateport.deployment.yaml", cwd=project)
    _git("commit", "-m", "spoof generated build", cwd=project)
    inspection = inspect_project(project)
    assert "descriptor:generated_build_forbidden" in inspection["unsafeConstructs"]
    assert inspection["deterministicAssistedPlanningSupported"] is False


def test_git_commit_replacement_cannot_change_inspected_source(
    tmp_path: Path,
) -> None:
    project = committed_fixture(tmp_path, "python-http")
    original_commit = _git("rev-parse", "HEAD", cwd=project)
    original_bytes = (project / "app.py").read_bytes()
    malicious_blob = _git_with_input(
        project,
        ("hash-object", "-w", "--stdin"),
        "raise SystemExit('replacement executed')\n",
    )
    tree_lines = _git("ls-tree", original_commit, cwd=project).splitlines()
    replacement_tree = "\n".join(
        f"100644 blob {malicious_blob}\tapp.py"
        if line.endswith("\tapp.py")
        else line
        for line in tree_lines
    )
    replacement_tree_id = _git_with_input(
        project, ("mktree",), replacement_tree + "\n"
    )
    replacement_commit = _git(
        "commit-tree", replacement_tree_id, "-m", "replacement", cwd=project
    )
    _git("replace", original_commit, replacement_commit, cwd=project)
    inspection = inspect_project(project)
    app = next(
        item for item in inspection["source"]["inventory"] if item["path"] == "app.py"
    )
    assert inspection["source"]["commit"] == original_commit
    assert app["contentDigest"] == "sha256:" + hashlib.sha256(original_bytes).hexdigest()


def test_materialization_ignores_blob_replacements_and_hostile_git_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, _fake, project, plan = planned_service(tmp_path)
    app = next(item for item in plan["sourceInventory"] if item["path"] == "app.py")
    original = (project / "app.py").read_bytes()
    malicious_blob = _git_with_input(
        project,
        ("hash-object", "-w", "--stdin"),
        "raise SystemExit('replacement executed')\n",
    )
    _git("replace", app["objectId"], malicious_blob, cwd=project)
    for name in (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    ):
        monkeypatch.setenv(name, str(tmp_path / "attacker"))
    adapter = object.__new__(RootlessPodmanAdapter)
    destination = tmp_path / "materialized"
    receipt = adapter.materialize_context(plan, destination)
    observed = next(item for item in receipt["files"] if item["path"] == "app.py")
    assert (destination / "app.py").read_bytes() == original
    assert observed["sha256"] == app["contentDigest"]

    tampered = deepcopy(plan)
    tampered["sourceInventory"][0]["contentDigest"] = DIGEST
    with pytest.raises(AdapterError, match="materialized exactly"):
        adapter.materialize_context(tampered, tmp_path / "tampered-materialization")


def test_execution_host_transfers_exact_context_by_descriptor_and_cleans_snapshot(
    tmp_path: Path,
) -> None:
    service, _planning_adapter, project, plan = planned_service(
        tmp_path, "persistent-multi"
    )
    deployment_id = plan["spec"]["metadata"]["deploymentId"]

    class EmptyEngine:
        identity = {"engine": "fake-cli", "socket": "fake"}

        @staticmethod
        def version() -> dict[str, str]:
            return {"engine": "fake", "engineVersion": "0.0.0-test"}

        @staticmethod
        def list_managed() -> list[dict[str, Any]]:
            return []

    class HostAdapter(FakeAdapter):
        transferred: dict[str, bytes]

        def apply(
            self,
            received_plan: Mapping[str, Any],
            *,
            context_root: Path,
            overlay_root: Path,
            **kwargs: Any,
        ) -> dict[str, Any]:
            self.transferred = {
                item["path"]: (context_root / item["path"]).read_bytes()
                for item in received_plan["sourceInventory"]
            }
            assert self.transferred == {
                item["path"]: (project / item["path"]).read_bytes()
                for item in received_plan["sourceInventory"]
            }
            assert {
                path: (overlay_root / path).read_text(encoding="utf-8")
                for path in received_plan["overlay"]
            } == received_plan["overlay"]
            return super().apply(received_plan, **kwargs)

    socket_dir = tmp_path / "execution-control"
    socket_dir.mkdir(mode=0o750)
    state_dir = tmp_path / "execution-state"
    grants_dir = state_dir / "grants"
    grants_dir.mkdir(parents=True, mode=0o700)
    image = "docker.io/library/python@sha256:" + "b" * 64
    workload = execution_contract.validate_workload_spec(
        {
            "kind": "terminal",
            "workloadId": "deployment-grant-anchor",
            "image": {"reference": image},
            "parameters": {"sessionId": "deployment-grant-anchor"},
            "timeoutSeconds": 30,
            "outputByteBound": 4096,
            "resources": {"memoryMaxBytes": 268435456, "pidsMax": 128},
        }
    )
    grant = {
        "formatVersion": execution_contract.GRANT_FORMAT,
        "grantId": "deployment-test-grant",
        "peerUid": os.geteuid(),
        "operations": list(execution_contract.OPERATIONS),
        "workloadIds": [workload["workloadId"]],
        "workloadKinds": [workload["kind"]],
        "workloadSpecDigests": {
            workload["workloadId"]: execution_contract.canonical_digest(workload)
        },
        "imageReference": image,
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
            "maxOutputBytes": execution_contract.MAX_OUTPUT_BYTES,
            "maxMemoryMaxBytes": execution_contract.MAX_MEMORY_MAX_BYTES,
            "maxPidsMax": execution_contract.MAX_PIDS_MAX,
            "maxActiveWorkloads": 8,
            "maxCpuQuotaPercent": 800,
            "maxDiskMaxBytes": 4 * 1024**3,
        },
    }
    (grants_dir / "deployment-test-grant.json").write_text(
        json.dumps(grant, sort_keys=True) + "\n", encoding="utf-8"
    )
    host_adapter = HostAdapter()
    daemon = ExecutionHostDaemon(
        DaemonConfig(
            socket_path=socket_dir / "control.sock",
            state_dir=state_dir,
            socket_group_gid=os.getegid(),
            allowed_client_uid=os.geteuid(),
            allowed_client_gid=os.getegid(),
            runtime_uid=os.geteuid(),
            runtime_gid=os.getegid(),
            supervise_interval_seconds=0.05,
        ),
        EmptyEngine(),
        deployment_adapter=host_adapter,
    )
    daemon.boot()
    thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    thread.start()
    try:
        client = ExecutionHostClient(
            socket_dir / "control.sock",
            grant_id=grant["grantId"],
            authority_grant_digest=execution_contract.canonical_digest(grant),
            timeout_seconds=30,
        )
        remote = ExecutionHostDeploymentAdapter(client)
        decision, _reservation = reserve_for(
            service,
            "apply_deployment",
            deployment_id,
            run_id=plan["planDigest"],
        )
        authority_reference = service._verify_authority(
            decision,
            action="apply_deployment",
            deployment_id=deployment_id,
            run_id=plan["planDigest"],
        )
        control_context = execution_contract.build_deployment_control_context(
            "operation-descriptor-transfer",
            authority_reference,
        )
        context_root = tmp_path / "control-context"
        context_receipt = remote.materialize_context(plan, context_root)
        assert context_receipt["contextDigest"]
        overlay_root = service.store.verify_overlay(
            deployment_id, plan["planId"], plan["overlay"]
        )
        with tempfile.TemporaryFile(mode="w+b", dir=tmp_path) as writable_archive:
            writable_metadata = build_deployment_archive(
                writable_archive,
                plan=plan,
                context_root=context_root,
                overlay_root=overlay_root,
                context_digest=context_receipt["contextDigest"],
            )
            payload = {
                "deploymentId": deployment_id,
                "plan": dict(plan),
                "sourceArchive": dict(writable_metadata),
                "failpoint": None,
                "controlContext": dict(control_context),
            }
            normalized_payload = execution_contract.validate_request_payload(
                {"operation": "applyDeployment"}, payload
            )
            public_request = {
                "formatVersion": execution_contract.OPERATION_FORMAT,
                "operationId": execution_contract.deployment_host_operation_id(
                    "applyDeployment", normalized_payload
                ),
                "operation": "applyDeployment",
                "requester": {
                    "grantId": grant["grantId"],
                    "authorityGrantDigest": execution_contract.canonical_digest(grant),
                },
                "timeoutSeconds": 30,
                "outputByteBound": execution_contract.MAX_OUTPUT_BYTES,
                "payload": payload,
            }
            public_schema = json.loads(
                (ROOT / "schemas" / "execution-host-operation.v1.schema.json").read_text(
                    encoding="utf-8"
                )
            )
            public_validator = jsonschema.Draft202012Validator(public_schema)
            public_request["timeoutSeconds"] = 1200
            public_validator.validate(public_request)
            public_request["timeoutSeconds"] = 1201
            assert list(public_validator.iter_errors(public_request))
            public_request["timeoutSeconds"] = 30

            tampered_context = deepcopy(control_context)
            tampered_context["authority"]["scope"]["applicationId"] = "other-deployment"
            tampered_context["contextDigest"] = execution_contract.canonical_digest(
                {
                    key: value
                    for key, value in tampered_context.items()
                    if key != "contextDigest"
                }
            )
            with pytest.raises(ValueError, match="authority decision does not bind"):
                client.apply_deployment(
                    plan,
                    writable_metadata,
                    source_fd=writable_archive.fileno(),
                    control_context=tampered_context,
                )
            with pytest.raises(
                ExecutionHostTransportError,
                match="not a read-only regular file",
            ):
                client.apply_deployment(
                    plan,
                    writable_metadata,
                    source_fd=writable_archive.fileno(),
                    control_context=control_context,
                )
        def invoke() -> dict[str, Any]:
            read_fd: int | None = None
            with tempfile.TemporaryFile(mode="w+b", dir=tmp_path) as archive:
                metadata = build_deployment_archive(
                    archive,
                    plan=plan,
                    context_root=context_root,
                    overlay_root=overlay_root,
                    context_digest=context_receipt["contextDigest"],
                )
                read_fd = reopen_archive_read_only(archive)
            try:
                return client.apply_deployment(
                    plan,
                    metadata,
                    source_fd=read_fd,
                    control_context=control_context,
                )
            finally:
                os.close(read_fd)

        first = invoke()
        replay = invoke()
        assert replay == first
        assert first["result"]["value"]["adapter"] == "rootless-podman-local"
        assert host_adapter.calls[:2] == ["apply", "observe"]
        assert host_adapter.calls.count("apply") == 1

        backup_plan_digest = digest_value(
            {"operation": "backup_data", "revision": plan["planDigest"]}
        )
        backup_decision, _ = reserve_for(
            service,
            "backup_deployment_data",
            deployment_id,
            run_id=backup_plan_digest,
        )
        backup_authority = service._verify_authority(
            backup_decision,
            action="backup_deployment_data",
            deployment_id=deployment_id,
            run_id=backup_plan_digest,
        )
        backup_context = execution_contract.build_deployment_control_context(
            "operation-backup-data", backup_authority
        )
        expected_volumes = {"app-data": "volume-app-data"}
        backup_receipt = client.backup_deployment_data(
            plan["spec"],
            backup_id="backup-execution-host",
            plan_digest=backup_plan_digest,
            expected_volumes=expected_volumes,
            expected_revision=plan["planDigest"],
            expected_images=host_adapter.images,
            infrastructure=None,
            control_context=backup_context,
        )
        backup_value = backup_receipt["result"]["value"]
        backup_identity = {
            "backupId": backup_value["backupId"],
            "sourceRevision": backup_value["sourceRevision"],
            "createdAt": backup_value["createdAt"],
            "storage": backup_value["storage"],
        }
        backup = {
            **backup_identity,
            "backupDigest": digest_value(backup_identity),
            "status": "available",
            "restoredAt": None,
        }
        assert backup_value["storage"]["app-data"]["artifactId"] == (
            "backup-execution-host/app-data.tar"
        )
        host_adapter.volume_data["app-data"] = "changed-after-backup"

        restore_plan_digest = digest_value(
            {
                "operation": "restore_data",
                "backupDigest": backup["backupDigest"],
            }
        )
        restore_decision, _ = reserve_for(
            service,
            "restore_deployment_data",
            deployment_id,
            run_id=restore_plan_digest,
        )
        restore_authority = service._verify_authority(
            restore_decision,
            action="restore_deployment_data",
            deployment_id=deployment_id,
            run_id=restore_plan_digest,
        )
        restore_context = execution_contract.build_deployment_control_context(
            "operation-restore-data", restore_authority
        )
        restored = client.restore_deployment_data(
            plan["spec"],
            backup=backup,
            plan_digest=restore_plan_digest,
            expected_volumes=expected_volumes,
            expected_revision=plan["planDigest"],
            expected_images=host_adapter.images,
            infrastructure=None,
            control_context=restore_context,
        )
        replayed_restore = client.restore_deployment_data(
            plan["spec"],
            backup=backup,
            plan_digest=restore_plan_digest,
            expected_volumes=expected_volumes,
            expected_revision=plan["planDigest"],
            expected_images=host_adapter.images,
            infrastructure=None,
            control_context=restore_context,
        )
        assert replayed_restore == restored
        assert restored["result"]["value"]["backupConsumed"] is True
        assert host_adapter.volume_data["app-data"] == "fixture-data"
        assert host_adapter.calls.count("backup_data") == 1
        assert host_adapter.calls.count("restore_data") == 1

        tampered_backup = deepcopy(backup)
        tampered_backup["storage"]["app-data"]["bytes"] += 1
        with pytest.raises(ValueError, match="backup digest"):
            client.restore_deployment_data(
                plan["spec"],
                backup=tampered_backup,
                plan_digest=restore_plan_digest,
                expected_volumes=expected_volumes,
                expected_revision=plan["planDigest"],
                expected_images=host_adapter.images,
                infrastructure=None,
                control_context=restore_context,
            )
        bounded_client = ExecutionHostClient(
            socket_dir / "control.sock",
            grant_id=grant["grantId"],
            authority_grant_digest=execution_contract.canonical_digest(grant),
            timeout_seconds=30,
            output_byte_bound=64,
        )
        with pytest.raises(AdapterError) as bounded:
            ExecutionHostDeploymentAdapter(bounded_client).probe()
        assert bounded.value.code == "output_bound_exceeded"
        snapshots = state_dir / "deployment-snapshots"
        assert snapshots.is_dir()
        assert list(snapshots.iterdir()) == []
    finally:
        daemon.shutdown()
        thread.join(timeout=2)


def test_exact_plan_apply_status_restart_remove_and_separate_purge(tmp_path: Path) -> None:
    service, adapter, _project, plan = planned_service(tmp_path, "persistent-multi")
    state = service.store.load_state("deployment-persistent-multi")
    assert state["lifecycleState"] == "awaiting_approval"
    assert adapter.calls.count("apply") == 0

    deployment_id = "deployment-persistent-multi"
    result = apply_authorized(service, deployment_id, plan["planDigest"])
    assert result["state"]["lifecycleState"] == "healthy"
    assert result["state"]["acceptedRevision"] == plan["planDigest"]
    assert result["state"]["observedRevision"] == plan["planDigest"]
    assert len(result["approvalReceipts"]) == 2
    assert result["contextCleanup"]["status"] == "removed"
    assert not any(
        (service.store._deployment_root(deployment_id) / "build-contexts").iterdir()
    )
    accepted = service.authority_run_id(deployment_id)
    assert governed_call(
        service,
        "observe_deployment",
        deployment_id,
        lambda decision: service.status(
            deployment_id, authority_decision=decision
        ),
        run_id=accepted,
    )["state"]["driftStatus"] == "in_sync"
    assert governed_call(
        service,
        "collect_deployment_logs",
        deployment_id,
        lambda decision: service.logs(
            deployment_id, authority_decision=decision
        ),
        run_id=accepted,
    )["redacted"] is True
    assert governed_call(
        service,
        "restart_deployment",
        deployment_id,
        lambda decision: service.restart(
            deployment_id, authority_decision=decision
        ),
        run_id=accepted,
    )["state"]["lifecycleState"] == "healthy"

    removed = governed_call(
        service,
        "remove_deployment_runtime",
        deployment_id,
        lambda decision: service.remove(
            deployment_id, authority_decision=decision
        ),
        run_id=accepted,
    )
    assert removed["state"]["lifecycleState"] == "removed_runtime_data_retained"
    assert removed["state"]["retainedDataState"] == "retained"
    assert set(removed["state"]["storageIdentities"].values()) == set(
        removed["runtime"]["retainedVolumes"]
    )
    with pytest.raises(DeploymentRefusal, match="awaiting a purge approval"):
        governed_call(
            service,
            "purge_deployment_data",
            deployment_id,
            lambda decision: service.purge_data(
                deployment_id,
                accept_plan_digest=plan["planDigest"],
                authority_decision=decision,
            ),
            run_id=plan["planDigest"],
        )
    purge_plan = governed_call(
        service,
        "plan_deployment",
        deployment_id,
        lambda decision: service.plan_purge(
            deployment_id, authority_decision=decision
        ),
        run_id=accepted,
    )
    assert purge_plan["destructiveEffects"] == [
        {"kind": "volume", "name": name, "irreversible": True}
        for name in sorted(removed["state"]["storageIdentities"].values())
    ]
    purged = governed_call(
        service,
        "purge_deployment_data",
        deployment_id,
        lambda decision: service.purge_data(
            deployment_id,
            accept_plan_digest=purge_plan["planDigest"],
            authority_decision=decision,
        ),
        run_id=purge_plan["planDigest"],
    )
    assert purged["state"]["lifecycleState"] == "purged"
    assert purged["state"]["retainedDataState"] == "purged"


def test_expired_plan_can_be_replaced_but_never_applied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = committed_fixture(tmp_path, "python-http")
    deployment_id = "expired-plan-replacement"
    manager, _grant_id = authority_harness(
        tmp_path, deployment_id, project=project
    )
    adapter = FakeAdapter()
    service = DeploymentService(
        state_root=tmp_path / "state-expired-plan",
        adapter=adapter,
        authority_manager=manager,
        actor=ACTOR,
    )
    real_datetime = deployment_service_module.datetime

    class PastDateTime(datetime):
        @classmethod
        def now(cls, tz: Any = None) -> datetime:
            return real_datetime.now(tz) - timedelta(hours=2)

    monkeypatch.setattr(deployment_service_module, "datetime", PastDateTime)
    expired = plan_authorized(service, project, deployment_id)
    monkeypatch.setattr(deployment_service_module, "datetime", real_datetime)
    successor = plan_authorized(service, project, deployment_id)
    assert successor["planDigest"] != expired["planDigest"]
    state = service.store.load_state(deployment_id)
    assert state["lifecycleState"] == "awaiting_approval"
    assert state["desiredRevision"] == successor["planDigest"]

    with pytest.raises(DeploymentRefusal) as raised:
        apply_authorized(service, deployment_id, expired["planDigest"])
    assert raised.value.code == "plan_expired"
    assert "apply" not in adapter.calls

    accepted = apply_authorized(service, deployment_id, successor["planDigest"])
    assert accepted["state"]["acceptedRevision"] == successor["planDigest"]


def test_plan_digest_is_not_a_wildcard_approval(tmp_path: Path) -> None:
    service, adapter, _project, plan = planned_service(tmp_path)
    with pytest.raises(DeploymentRefusal, match="not found"):
        governed_call(
            service,
            "apply_deployment",
            "deployment-python-http",
            lambda decision: service.apply(
                "deployment-python-http",
                accept_plan_digest=DIGEST,
                authority_decision=decision,
            ),
            run_id=DIGEST,
        )
    assert "apply" not in adapter.calls
    state = service.store.load_state("deployment-python-http")
    assert state["lifecycleState"] == "awaiting_approval"
    assert state["approvedPlanDigest"] is None
    assert plan["planDigest"] != DIGEST


@pytest.mark.parametrize(
    "mutator",
    (
        lambda value: value.update(action="purge_deployment_data"),
        lambda value: value.update(actorId="other-actor"),
        lambda value: value["scope"].update(applicationId="other-deployment"),
        lambda value: value["authorizedBy"].update(id="grant-other"),
        lambda value: value.update(decisionDigest=DIGEST),
    ),
)
def test_runtime_effect_requires_exact_canonical_authority(
    tmp_path: Path, mutator: Any
) -> None:
    service, adapter, _project, plan = planned_service(tmp_path)
    deployment_id = "deployment-python-http"
    decision = decision_for(
        service,
        "apply_deployment",
        deployment_id,
        run_id=plan["planDigest"],
    )
    mutator(decision)
    if decision["decisionDigest"] != DIGEST:
        body = {key: value for key, value in decision.items() if key != "decisionDigest"}
        decision["decisionDigest"] = digest_value(body)
    with pytest.raises(DeploymentRefusal):
        service.apply(
            deployment_id,
            accept_plan_digest=plan["planDigest"],
            authority_decision=decision,
        )
    assert "apply" not in adapter.calls
    assert service.store.load_state(deployment_id)["lifecycleState"] == "awaiting_approval"


def test_missing_authority_cannot_start_runtime(tmp_path: Path) -> None:
    service, adapter, _project, plan = planned_service(tmp_path)
    with pytest.raises(DeploymentRefusal) as raised:
        service.apply(
            "deployment-python-http",
            accept_plan_digest=plan["planDigest"],
            authority_decision=None,
        )
    assert raised.value.code == "authority_required"
    assert "apply" not in adapter.calls


def test_reserved_authority_decision_is_claimable_exactly_once(tmp_path: Path) -> None:
    service, adapter, _project, plan = planned_service(tmp_path)
    deployment_id = "deployment-python-http"
    apply_authorized(service, deployment_id, plan["planDigest"])
    decision, reservation = reserve_for(
        service,
        "observe_deployment",
        deployment_id,
        run_id=plan["planDigest"],
    )
    first = service.status(deployment_id, authority_decision=decision)
    assert first["state"]["driftStatus"] == "in_sync"
    calls_before_replay = list(adapter.calls)
    with pytest.raises(DeploymentRefusal) as raised:
        service.status(deployment_id, authority_decision=decision)
    assert raised.value.code == "authority_invalid"
    assert raised.value.details["authorityCode"] == "authority_reservation_already_claimed"
    assert adapter.calls == calls_before_replay
    manager = service._authority_manager
    assert manager is not None
    receipt = manager.record_action(
        decision,
        result_status="succeeded",
        summary="Exact observation completed once",
        reservation=reservation,
        claim=manager.get_claim(decision["requestId"]),
    )
    linked = service.link_authority_receipt(deployment_id, receipt)
    assert linked["authorityReceipt"]["claimId"] == receipt["claim"]["claimId"]


def test_wrong_local_action_binding_does_not_burn_reserved_authority(
    tmp_path: Path,
) -> None:
    service, _adapter, _project, plan = planned_service(tmp_path)
    deployment_id = "deployment-python-http"
    apply_authorized(service, deployment_id, plan["planDigest"])
    decision, reservation = reserve_for(
        service,
        "observe_deployment",
        deployment_id,
        run_id=plan["planDigest"],
    )
    with pytest.raises(DeploymentRefusal) as raised:
        service.restart(deployment_id, authority_decision=decision)
    assert raised.value.code == "authority_scope_mismatch"
    manager = service._authority_manager
    assert manager is not None
    assert manager.has_claim(decision["requestId"]) is False
    result = service.status(deployment_id, authority_decision=decision)
    assert result["state"]["driftStatus"] == "in_sync"
    assert manager.has_claim(decision["requestId"]) is True
    receipt = manager.record_action(
        decision,
        result_status="succeeded",
        summary="Correctly bound observation completed",
        reservation=reservation,
        claim=manager.get_claim(decision["requestId"]),
    )
    service.link_authority_receipt(deployment_id, receipt)


def test_initial_plan_authority_binds_the_exact_external_source(
    tmp_path: Path,
) -> None:
    first = committed_fixture(tmp_path, "python-http")
    second = committed_fixture(tmp_path, "node-http")
    deployment_id = "deployment-source-bound"
    manager, grant_id = authority_harness(
        tmp_path, deployment_id, project=first
    )
    service = DeploymentService(
        state_root=tmp_path / "state-source-bound",
        adapter=FakeAdapter(),
        authority_manager=manager,
        actor=ACTOR,
    )
    first_identity = authority_source_identity(service.inspect(first))
    decision, reservation = reserve_for(
        service,
        "plan_deployment",
        deployment_id,
        source_identity=first_identity,
    )
    with pytest.raises(DeploymentRefusal) as raised:
        service.plan(
            second,
            deployment_id=deployment_id,
            grant_id=grant_id,
            authority_decision=decision,
        )
    assert raised.value.code == "authority_scope_mismatch"
    assert manager.has_claim(decision["requestId"]) is False
    assert not (tmp_path / "state-source-bound").exists()

    plan = service.plan(
        first,
        deployment_id=deployment_id,
        grant_id=grant_id,
        authority_decision=decision,
    )
    assert plan["spec"]["source"]["commit"] == first_identity["commit"]
    receipt = manager.record_action(
        decision,
        result_status="succeeded",
        summary="Exact source-bound plan completed",
        reservation=reservation,
        claim=manager.get_claim(decision["requestId"]),
        resource={"planDigest": plan["planDigest"]},
    )
    service.link_authority_receipt(deployment_id, receipt)


def test_canonical_authority_receipt_is_copied_and_linked(tmp_path: Path) -> None:
    service, _adapter, _project, _plan = planned_service(tmp_path)
    deployment_id = "deployment-python-http"
    state = service.store.load_state(deployment_id)
    assert len(state["authorityReceipts"]) == 1
    link = state["authorityReceipts"][0]
    manager = service._authority_manager
    assert manager is not None
    canonical = manager.get_receipt(link["receiptId"])
    assert link["grantId"] == canonical["authorizedBy"]["id"]
    assert link["resultStatus"] == "succeeded"
    assert link["reservationId"] == canonical["reservation"]["reservationId"]
    assert link["reservationDigest"] == canonical["reservation"]["reservationDigest"]
    assert link["claimId"] == canonical["claim"]["claimId"]
    assert link["claimDigest"] == canonical["claim"]["claimDigest"]
    evidence_path = Path(link["evidence"]["path"])
    assert json.loads(evidence_path.read_text(encoding="utf-8"))["payload"] == canonical
    assert state["authorityReceipts"] == [link]
    duplicate = service.link_authority_receipt(deployment_id, canonical)
    assert duplicate["alreadyLinked"] is True
    assert duplicate["state"] == state


def test_project_descriptor_cannot_grant_itself(tmp_path: Path) -> None:
    project = committed_fixture(tmp_path, "persistent-multi")
    descriptor = project / "stateport.deployment.yaml"
    descriptor.write_text(
        descriptor.read_text(encoding="utf-8").replace(
            "grantId: null", "grantId: grant_project_self"
        ),
        encoding="utf-8",
    )
    _git("add", "stateport.deployment.yaml", cwd=project)
    _git("commit", "-m", "request self grant", cwd=project)
    service = DeploymentService(
        state_root=tmp_path / "state",
        adapter=FakeAdapter(),
        authority_manager=authority_harness(
            tmp_path, "deployment-self-grant", project=project
        )[0],
        actor=ACTOR,
    )
    plan = plan_authorized(service, project, "deployment-self-grant")
    assert plan["spec"]["authority"]["grantId"].startswith("grant_test_")


def test_cli_binds_real_canonical_grant_and_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    project = committed_fixture(tmp_path, "python-http")
    actor = "cli-test-owner"
    deployment_id = "deployment-cli-authority"
    slice_id = "BL-DEPLOYMENT-CLI-TEST-001"
    grant_id = "grant_cli_deployment_test"
    branch = TEST_BRANCH
    authority_root = tmp_path / "authority"
    manager = AuthorityManager(ROOT, state_root=authority_root)
    grant = grant_template(
        manager,
        grant_id=grant_id,
        profile="balanced",
        actor_id=actor,
        role="primary",
        branch_pattern=branch,
        slice_id=slice_id,
        application_id=deployment_id,
        run_id=None,
        paths=(".",),
        allow=("inspect_repository", "plan_deployment"),
        require_approval=(),
        forbid=(),
        owner_directive_id="OD-DEPLOYMENT-CLI-TEST-001",
        expires_when="slice_closed",
        max_actions=10,
        max_duration_seconds=7200,
        max_cost_usd=0,
        deployment_sources=[
            {
                key: authority_source_identity(inspect_project(project))[key]
                for key in ("repositoryIdentity", "projectPath")
            }
        ],
    )
    manager.activate_grant(grant, owner_actor_id="test-owner")
    service = DeploymentService(
        state_root=tmp_path / "deployment-state",
        adapter=FakeAdapter(),
        authority_manager=manager,
        actor=actor,
    )
    monkeypatch.setattr(
        deployment_cli, "_service", lambda _args, _manager: service
    )
    args = Namespace(
        repository=str(ROOT),
        authority_state_root=str(authority_root),
        authority_policy=None,
        grant_id=grant_id,
        slice_id=slice_id,
        actor_id=actor,
        deployment_state_root=str(tmp_path / "deployment-state"),
        deploy_command="plan",
        project=str(project),
        target="local",
        deployment_id=deployment_id,
        json=True,
    )
    assert deployment_cli.deployment_cmd(args) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["spec"]["authority"]["grantId"] == grant_id
    assert payload["authorityReceipt"]["schema"] == "stateport.authority-action-receipt/v1"
    assert payload["authorityReceipt"]["result"]["status"] == "succeeded"
    assert payload["authorityReceipt"]["result"]["resource"]["planDigest"] == payload["planDigest"]
    assert payload["authorityReceipt"]["result"]["resource"]["sourceIdentity"] == authority_source_identity(payload["spec"])
    state = service.store.load_state(deployment_id)
    assert len(state["authorityReceipts"]) == 1
    assert state["authorityReceipts"][0]["receiptId"] == payload["authorityReceipt"]["receiptId"]


def test_admin_cli_service_uses_only_the_confined_execution_host_adapter(
    tmp_path: Path,
) -> None:
    socket_path = tmp_path / "execution-host.sock"
    grant_digest = "sha256:" + "7" * 64
    args = Namespace(
        deployment_state_root=str(tmp_path / "deployments"),
        actor_id="cli-execution-host-owner",
        execution_host_socket=str(socket_path),
        execution_host_grant_id="execution-host-grant",
        execution_host_grant_digest=grant_digest,
        execution_host_timeout_seconds=1200,
    )
    service = deployment_cli._service(
        args,
        AuthorityManager(ROOT, state_root=tmp_path / "authority"),
    )

    assert isinstance(service.adapter, ExecutionHostDeploymentAdapter)
    assert service.adapter._client is not None
    assert service.adapter._client.socket_path == socket_path
    assert service.adapter._client.grant_id == "execution-host-grant"
    assert service.adapter._client.authority_grant_digest == grant_digest


def test_deployment_service_has_no_implicit_local_podman_adapter(
    tmp_path: Path,
) -> None:
    service = DeploymentService(state_root=tmp_path / "deployments")

    with pytest.raises(DeploymentRefusal) as refused:
        _ = service.adapter
    assert refused.value.code == "deployment_adapter_required"


def test_cli_refuses_state_root_inside_source_before_materialization_with_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = committed_fixture(tmp_path, "python-http")
    actor = "cli-state-root-owner"
    deployment_id = "deployment-cli-state-root"
    slice_id = "BL-DEPLOYMENT-STATE-ROOT-TEST-001"
    grant_id = "grant_cli_state_root_test"
    branch = TEST_BRANCH
    authority_root = tmp_path / "authority"
    unsafe_state_root = project / ".stateport-deployments"
    manager = AuthorityManager(ROOT, state_root=authority_root)
    grant = grant_template(
        manager,
        grant_id=grant_id,
        profile="balanced",
        actor_id=actor,
        role="primary",
        branch_pattern=branch,
        slice_id=slice_id,
        application_id=deployment_id,
        run_id=None,
        paths=(".",),
        allow=("inspect_repository", "plan_deployment"),
        require_approval=(),
        forbid=(),
        owner_directive_id="OD-DEPLOYMENT-STATE-ROOT-TEST-001",
        expires_when="slice_closed",
        max_actions=10,
        max_duration_seconds=7200,
        max_cost_usd=0,
        deployment_sources=[
            {
                key: authority_source_identity(inspect_project(project))[key]
                for key in ("repositoryIdentity", "projectPath")
            }
        ],
    )
    manager.activate_grant(grant, owner_actor_id="test-owner")
    service = DeploymentService(
        state_root=unsafe_state_root,
        adapter=FakeAdapter(),
        authority_manager=manager,
        actor=actor,
    )
    monkeypatch.setattr(
        deployment_cli, "_service", lambda _args, _manager: service
    )
    args = Namespace(
        repository=str(ROOT),
        authority_state_root=str(authority_root),
        authority_policy=None,
        grant_id=grant_id,
        slice_id=slice_id,
        actor_id=actor,
        deployment_state_root=str(unsafe_state_root),
        deploy_command="plan",
        project=str(project),
        target="local",
        deployment_id=deployment_id,
        json=True,
    )

    assert deployment_cli.deployment_cmd(args) == 2
    payload = json.loads(capsys.readouterr().err)
    assert payload["code"] == "unsafe_state_root"
    receipt = payload["details"]["authorityReceipt"]
    assert receipt["result"]["status"] == "not_executed"
    assert receipt["result"]["code"] == "unsafe_state_root"
    assert not unsafe_state_root.exists()
    assert _git("status", "--porcelain", cwd=project) == ""


def test_state_root_must_be_disjoint_from_source_control_and_authority_roots(
    tmp_path: Path,
) -> None:
    project = committed_fixture(tmp_path, "python-http")
    manager, _grant_id = authority_harness(
        tmp_path, "deployment-state-separation", project=project
    )
    inspection = inspect_project(project)
    control_candidate = ROOT / ".stateport-deployment-state-root-guard-test"
    authority_candidate = manager.state_root / "deployments"
    absent_candidates = (control_candidate, authority_candidate)
    assert all(not candidate.exists() for candidate in absent_candidates)

    for unsafe_root in (
        project / ".stateport-deployments",
        project.parent,
        control_candidate,
        authority_candidate,
    ):
        service = DeploymentService(
            state_root=unsafe_root,
            adapter=FakeAdapter(),
            authority_manager=manager,
            actor=ACTOR,
        )
        with pytest.raises(DeploymentRefusal) as raised:
            service.assert_state_root_separate(inspection)
        assert raised.value.code == "unsafe_state_root"

    assert all(not candidate.exists() for candidate in absent_candidates)
    assert _git("status", "--porcelain", cwd=project) == ""


def test_cli_complete_slice_a_lifecycle_uses_one_governed_state_and_receipts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = committed_fixture(tmp_path, "persistent-multi")
    actor = "cli-lifecycle-owner"
    deployment_id = "deployment-cli-lifecycle"
    slice_id = "BL-DEPLOYMENT-CLI-LIFECYCLE-001"
    grant_id = "grant_cli_lifecycle_test"
    branch = TEST_BRANCH
    authority_root = tmp_path / "authority"
    state_root = tmp_path / "deployment-state"
    manager = AuthorityManager(ROOT, state_root=authority_root)
    grant = grant_template(
        manager,
        grant_id=grant_id,
        profile="balanced",
        actor_id=actor,
        role="primary",
        branch_pattern=branch,
        slice_id=slice_id,
        application_id=None,
        run_id=None,
        paths=(".",),
        allow=(
            "inspect_repository",
            "plan_deployment",
            "apply_deployment",
            "observe_deployment",
            "collect_deployment_logs",
            "restart_deployment",
            "remove_deployment_runtime",
            "purge_deployment_data",
        ),
        require_approval=(),
        forbid=(),
        owner_directive_id="OD-DEPLOYMENT-CLI-LIFECYCLE-001",
        expires_when="slice_closed",
        max_actions=30,
        max_duration_seconds=7200,
        max_cost_usd=0,
        deployment_sources=[
            {
                key: authority_source_identity(inspect_project(project))[key]
                for key in ("repositoryIdentity", "projectPath")
            }
        ],
    )
    manager.activate_grant(grant, owner_actor_id="test-owner")
    adapter = FakeAdapter()
    service = DeploymentService(
        state_root=state_root,
        adapter=adapter,
        authority_manager=manager,
        actor=actor,
    )
    monkeypatch.setattr(
        deployment_cli, "_service", lambda _args, _manager: service
    )
    base = {
        "repository": str(ROOT),
        "authority_state_root": str(authority_root),
        "authority_policy": None,
        "grant_id": grant_id,
        "slice_id": slice_id,
        "actor_id": actor,
        "deployment_state_root": str(state_root),
    }

    inspect_args = Namespace(
        **base, deploy_command="inspect", project=str(project), json=False
    )
    assert deployment_cli.deployment_cmd(inspect_args) == 0
    inspection_output = capsys.readouterr().out
    assert "Side effects: none" in inspection_output
    assert "Authority receipt:" in inspection_output

    plan_args = Namespace(
        **base,
        deploy_command="plan",
        project=str(project),
        target="local",
        deployment_id=deployment_id,
        json=True,
    )
    assert deployment_cli.deployment_cmd(plan_args) == 0
    plan = json.loads(capsys.readouterr().out)
    plan_digest_value = plan["planDigest"]
    assert plan["authorityReceipt"]["result"]["status"] == "succeeded"
    assert plan["inspectionAuthorityReceipt"]["result"]["status"] == "succeeded"

    apply_args = Namespace(
        **base,
        deploy_command="apply",
        deployment=deployment_id,
        accept_plan_digest=plan_digest_value,
        json=False,
    )
    assert deployment_cli.deployment_cmd(apply_args) == 0
    assert "Lifecycle: healthy" in capsys.readouterr().out

    status_args = Namespace(
        **base, deploy_command="status", deployment=deployment_id, json=True
    )
    assert deployment_cli.deployment_cmd(status_args) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["state"]["acceptedRevision"] == plan_digest_value
    assert status["authorityReceipt"]["result"]["status"] == "succeeded"

    logs_args = Namespace(
        **base,
        deploy_command="logs",
        deployment=deployment_id,
        service=None,
        tail=20,
        json=False,
    )
    assert deployment_cli.deployment_cmd(logs_args) == 0
    logs_output = capsys.readouterr().out
    assert "fixture log" in logs_output
    assert "Authority receipt:" in logs_output

    restart_args = Namespace(
        **base, deploy_command="restart", deployment=deployment_id, json=True
    )
    assert deployment_cli.deployment_cmd(restart_args) == 0
    restarted = json.loads(capsys.readouterr().out)
    assert restarted["state"]["lifecycleState"] == "healthy"

    remove_args = Namespace(
        **base, deploy_command="remove", deployment=deployment_id, json=False
    )
    assert deployment_cli.deployment_cmd(remove_args) == 0
    removal_output = capsys.readouterr().out
    assert "Lifecycle: removed_runtime_data_retained" in removal_output
    assert "Retained data: retained" in removal_output

    purge_plan_args = Namespace(
        **base, deploy_command="plan-purge", deployment=deployment_id, json=True
    )
    assert deployment_cli.deployment_cmd(purge_plan_args) == 0
    purge_plan = json.loads(capsys.readouterr().out)
    assert purge_plan["operation"] == "purge_data"
    assert purge_plan["destructiveEffects"]

    purge_args = Namespace(
        **base,
        deploy_command="purge-data",
        deployment=deployment_id,
        accept_plan_digest=purge_plan["planDigest"],
        json=False,
    )
    assert deployment_cli.deployment_cmd(purge_args) == 0
    purge_output = capsys.readouterr().out
    assert "Lifecycle: purged" in purge_output
    assert "Authority receipt:" in purge_output

    final = service.store.load_state(deployment_id)
    assert final["lifecycleState"] == "purged"
    assert final["storageIdentities"] == {}
    assert not adapter.present
    assert adapter.volumes == {}
    assert len(final["authorityReceipts"]) >= 8

    canonical = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in manager.receipts_root.glob("*.json")
        if json.loads(path.read_text(encoding="utf-8"))["scope"].get(
            "applicationId"
        )
        == deployment_id
    ]
    by_action: dict[str, list[dict[str, Any]]] = {}
    for receipt in canonical:
        by_action.setdefault(receipt["action"], []).append(receipt)
    apply_resource = by_action["apply_deployment"][0]["result"]["resource"]
    assert apply_resource["sourceIdentity"]["commit"] == plan["spec"]["source"]["commit"]
    assert apply_resource["runtimeDigest"] == digest_value(
        apply_resource["runtime"]
    )
    observation_resource = by_action["observe_deployment"][0]["result"][
        "resource"
    ]
    assert observation_resource["observationDigest"] == digest_value(
        observation_resource["observation"]
    )
    log_receipt = by_action["collect_deployment_logs"][0]
    assert log_receipt["action"] == "collect_deployment_logs"
    assert log_receipt["result"]["resource"]["logEvidence"][
        "evidenceId"
    ].startswith("evidence_logs_")
    assert log_receipt["result"]["resource"]["redacted"] is True
    restart_resource = by_action["restart_deployment"][0]["result"]["resource"]
    assert restart_resource["runtimeDigest"] == digest_value(
        restart_resource["runtime"]
    )
    removal_resource = by_action["remove_deployment_runtime"][0]["result"][
        "resource"
    ]
    assert removal_resource["runtimeRemoval"]["verifiedRuntimeAbsent"] is True
    assert removal_resource["logEvidence"]["evidenceId"].startswith(
        "evidence_pre_removal_logs_"
    )
    purge_resource = by_action["purge_deployment_data"][0]["result"]["resource"]
    assert purge_resource["purgeResult"]["verifiedAbsent"] is True
    assert purge_resource["purgeResult"]["purgedVolumes"]
    assert purge_resource["purgeResultDigest"] == digest_value(
        purge_resource["purgeResult"]
    )


def test_human_review_output_exposes_exact_inspection_plan_and_purge_contract(
    tmp_path: Path,
) -> None:
    service, _adapter, project, plan = planned_service(
        tmp_path, "persistent-multi"
    )
    inspection = service.inspect(project)
    inspection["authorityReceipt"] = {
        "receiptId": "authority_receipt_inspect",
        "receiptDigest": DIGEST,
    }
    inspection_text = deployment_cli._human_summary("inspect", inspection)
    assert "Build contexts:" in inspection_text
    assert "Commands:" in inspection_text
    assert "Health signals:" in inspection_text
    assert "Authority receipt: authority_receipt_inspect" in inspection_text

    plan["inspectionAuthorityReceipt"] = {
        "receiptId": "authority_receipt_inspection",
        "receiptDigest": DIGEST,
    }
    plan_text = deployment_cli._human_summary("plan", plan)
    assert "Service contracts:" in plan_text
    assert "command:" in plan_text
    assert "workdir:" in plan_text
    assert "user: nonroot uid=10001" in plan_text
    assert "health: http" in plan_text
    assert "resources:" in plan_text
    assert "context=." in plan_text
    assert "containerfile=" in plan_text
    assert f"Overlay digest: {digest_value(plan['overlay'])}" in plan_text
    assert "Inspection authority receipt: authority_receipt_inspection" in plan_text

    deployment_id = plan["spec"]["metadata"]["deploymentId"]
    applied = apply_authorized(service, deployment_id, plan["planDigest"])
    applied_text = deployment_cli._human_summary("apply", applied)
    assert "Approval receipt 1:" in applied_text
    accepted = service.authority_run_id(deployment_id)
    governed_call(
        service,
        "remove_deployment_runtime",
        deployment_id,
        lambda decision: service.remove(
            deployment_id, authority_decision=decision
        ),
        run_id=accepted,
    )
    purge_plan = governed_call(
        service,
        "plan_deployment",
        deployment_id,
        lambda decision: service.plan_purge(
            deployment_id, authority_decision=decision
        ),
        run_id=accepted,
    )
    purge_text = deployment_cli._human_summary("plan-purge", purge_plan)
    for effect in purge_plan["destructiveEffects"]:
        assert effect["name"] in purge_text
    assert "irreversible=true" in purge_text
    assert "retained → purged" in purge_text


@pytest.mark.parametrize(
    ("error", "expected_exit", "category"),
    (
        (DeploymentRefusal("dirty_source", "dirty"), 2, "refused"),
        (AdapterError("health_failed", "unhealthy"), 3, "runtime failed"),
        (
            DeploymentError("authority_effect_outcome_unknown", "unknown"),
            4,
            "reconciliation required",
        ),
        (
            DeploymentError("evidence_integrity_failed", "invalid"),
            4,
            "reconciliation required",
        ),
        (
            DeploymentError("operation_contract_error", "invalid shape"),
            70,
            "internal error",
        ),
    ),
)
@pytest.mark.parametrize("as_json", (False, True))
def test_cli_exit_categories_are_stable_for_human_and_json(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    error: DeploymentError,
    expected_exit: int,
    category: str,
    as_json: bool,
) -> None:
    def fail_authority(_args: Namespace) -> None:
        raise error

    monkeypatch.setattr(deployment_cli, "_authority", fail_authority)
    args = Namespace(deploy_command="status", json=as_json)
    assert deployment_cli.deployment_cmd(args) == expected_exit
    stderr = capsys.readouterr().err
    if as_json:
        assert json.loads(stderr)["code"] == error.code
    else:
        assert stderr.startswith(f"{category} [{error.code}]")


def test_human_cli_refusal_includes_exact_receipt_identity(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    receipt = {
        "receiptId": "authority_receipt_refused",
        "receiptDigest": DIGEST,
    }
    error = DeploymentRefusal(
        "unsafe_path",
        "unsafe",
        details={"authorityReceipt": receipt},
    )

    def fail_authority(_args: Namespace) -> None:
        raise error

    monkeypatch.setattr(deployment_cli, "_authority", fail_authority)
    assert (
        deployment_cli.deployment_cmd(
            Namespace(deploy_command="status", json=False)
        )
        == 2
    )
    stderr = capsys.readouterr().err
    assert "Authority receipt: authority_receipt_refused" in stderr
    assert DIGEST in stderr


def test_human_render_contract_failure_is_typed_without_traceback(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class Manager:
        checkout = ROOT

        @staticmethod
        def execute(*_args: Any, **_kwargs: Any) -> tuple[dict[str, Any], dict[str, Any]]:
            return {"malformed": True}, {
                "receiptId": "authority_receipt_render",
                "receiptDigest": DIGEST,
            }

    monkeypatch.setattr(deployment_cli, "_authority", lambda _args: Manager())
    monkeypatch.setattr(deployment_cli, "_service", lambda _args, _manager: object())
    monkeypatch.setattr(deployment_cli, "_branch", lambda _manager: "test")

    def invalid_render(_command: str, _result: Mapping[str, Any]) -> str:
        raise KeyError("missing")

    monkeypatch.setattr(deployment_cli, "_human_summary", invalid_render)
    args = Namespace(
        deploy_command="inspect",
        json=False,
        actor_id=ACTOR,
        grant_id="grant_test",
        slice_id=SLICE_ID,
        project="fixture",
    )
    assert deployment_cli.deployment_cmd(args) == 70
    stderr = capsys.readouterr().err
    assert "failed [operation_contract_error]" in stderr
    assert "Traceback" not in stderr


def test_stale_source_invalidates_approval(tmp_path: Path) -> None:
    service, adapter, project, plan = planned_service(tmp_path)
    (project / "app.py").write_text("print('changed')\n", encoding="utf-8")
    with pytest.raises(DeploymentRefusal, match="changed after plan approval"):
        apply_authorized(
            service, "deployment-python-http", plan["planDigest"]
        )
    assert "apply" not in adapter.calls


def test_failed_apply_can_be_replanned_without_erasing_evidence(tmp_path: Path) -> None:
    service, adapter, project, first = planned_service(tmp_path)
    adapter.fail = True
    with pytest.raises(AdapterError):
        apply_authorized(
            service, "deployment-python-http", first["planDigest"]
        )
    failed = service.store.load_state("deployment-python-http")
    assert failed["lifecycleState"] == "failed"
    assert failed["currentTransition"] is None
    assert not any(
        (
            service.store._deployment_root("deployment-python-http")
            / "build-contexts"
        ).iterdir()
    )
    adapter.fail = False
    second = plan_authorized(service, project, "deployment-python-http")
    assert service.store.load_plan("deployment-python-http", first["planDigest"], require_unexpired=False)
    assert service.store.load_plan("deployment-python-http", second["planDigest"], require_unexpired=False)
    accepted = apply_authorized(
        service, "deployment-python-http", second["planDigest"]
    )
    assert accepted["state"]["acceptedRevision"] == second["planDigest"]


def test_failed_apply_retains_written_data_until_separately_approved_purge(
    tmp_path: Path,
) -> None:
    service, adapter, project, first = planned_service(
        tmp_path, "persistent-multi"
    )
    deployment_id = "deployment-persistent-multi"
    retained = {
        item["id"]: f"volume-{item['id']}"
        for service_spec in first["spec"]["services"]
        for item in service_spec["storage"]
        if item["persistence"] != "ephemeral"
    }
    adapter.fail = True
    adapter.fail_cleanup = {
        "uncertain": [],
        "removed": {"containers": [], "networks": [], "volumes": [], "images": []},
        "verified": True,
        "runtimeEffectPossible": True,
        "volumesRetained": sorted(retained.values()),
        "retainedStorageIdentities": retained,
    }
    with pytest.raises(AdapterError):
        apply_authorized(service, deployment_id, first["planDigest"])
    failed = service.store.load_state(deployment_id)
    assert failed["lifecycleState"] == "failed"
    assert failed["acceptedRevision"] is None
    assert failed["storageIdentities"] == retained
    assert failed["retainedDataState"] == "retained_after_failed_apply"

    adapter.volumes = dict(retained)
    observed = governed_call(
        service,
        "observe_deployment",
        deployment_id,
        lambda decision: service.status(
            deployment_id, authority_decision=decision
        ),
        run_id=first["planDigest"],
    )
    assert observed["state"]["lifecycleState"] == "failed"
    assert observed["state"]["driftStatus"] == "in_sync"
    with pytest.raises(DeploymentRefusal) as retry:
        plan_authorized(service, project, deployment_id)
    assert retry.value.code == "invalid_transition"
    with pytest.raises(DeploymentRefusal) as remove:
        service.remove(deployment_id, authority_decision=None)
    assert remove.value.code == "retained_data_disposition_required"

    purge_plan = governed_call(
        service,
        "plan_deployment",
        deployment_id,
        lambda decision: service.plan_purge(
            deployment_id, authority_decision=decision
        ),
        run_id=first["planDigest"],
    )
    assert purge_plan["predecessorRevision"] == first["planDigest"]
    assert purge_plan["dataRetentionEffects"] == [
        {"from": "retained_after_failed_apply", "to": "purged"}
    ]
    adapter.fail = False
    purged = governed_call(
        service,
        "purge_deployment_data",
        deployment_id,
        lambda decision: service.purge_data(
            deployment_id,
            accept_plan_digest=purge_plan["planDigest"],
            authority_decision=decision,
        ),
        run_id=purge_plan["planDigest"],
    )
    assert purged["state"]["lifecycleState"] == "purged"
    assert purged["state"]["storageIdentities"] == {}


def test_overlay_tamper_fails_before_runtime_effect(tmp_path: Path) -> None:
    service, adapter, _project, plan = planned_service(tmp_path)
    overlay = service.store.overlay_root("deployment-python-http", plan["planId"])
    (overlay / "web.Containerfile").write_text("FROM scratch\n", encoding="utf-8")
    with pytest.raises(DeploymentRefusal, match="differs from the approved plan"):
        apply_authorized(
            service, "deployment-python-http", plan["planDigest"]
        )
    assert not any(
        (
            service.store._deployment_root("deployment-python-http")
            / "build-contexts"
        ).iterdir()
    )
    assert "apply" not in adapter.calls


def test_target_identity_change_refuses_before_approval(tmp_path: Path) -> None:
    service, adapter, _project, plan = planned_service(tmp_path)
    adapter.target_digest = "sha256:" + "b" * 64
    with pytest.raises(DeploymentRefusal, match="target identity changed"):
        apply_authorized(
            service, "deployment-python-http", plan["planDigest"]
        )
    assert service.store.load_state("deployment-python-http")["approvedPlanDigest"] is None


def test_dirty_source_and_duplicate_deployment_fail_closed(tmp_path: Path) -> None:
    project = committed_fixture(tmp_path, "python-http")
    (project / "untracked.txt").write_text("dirty\n", encoding="utf-8")
    dirty_manager, dirty_grant_id = authority_harness(
        tmp_path, "dirty", actor="local-owner", project=project
    )
    dirty_adapter = FakeAdapter()
    service = DeploymentService(
        state_root=tmp_path / "state-dirty",
        adapter=dirty_adapter,
        authority_manager=dirty_manager,
    )
    source_identity = authority_source_identity(service.inspect(project))
    decision, reservation = dirty_manager.reserve_action(
        "plan_deployment",
        actor_id="local-owner",
        grant_id=dirty_grant_id,
        branch=TEST_BRANCH,
        slice_id=SLICE_ID,
        application_id="dirty",
        run_id=None,
        paths=(".",),
        estimated_duration_seconds=3600,
        source_identity=source_identity,
    )
    assert decision["decision"] == "denied"
    assert decision["reason"] == "dirty_source"
    assert decision["requestedCapabilities"]["sourceIdentity"] == source_identity
    assert reservation is None
    receipt = dirty_manager.record_action(
        decision,
        result_status="not_executed",
        summary="Dirty source was not executed",
        code="dirty_source",
    )
    assert receipt["result"]["status"] == "not_executed"
    assert receipt["reservation"] is None
    assert receipt["claim"] is None
    assert dirty_manager.get_receipt_for_request(decision["requestId"]) == receipt
    assert not (tmp_path / "state-dirty" / "records" / "dirty").exists()
    assert dirty_adapter.calls == []
    (project / "untracked.txt").unlink()
    duplicate_manager, _ = authority_harness(
        tmp_path, "duplicate", actor="local-owner", project=project
    )
    service = DeploymentService(
        state_root=tmp_path / "state-duplicate",
        adapter=FakeAdapter(),
        authority_manager=duplicate_manager,
    )
    plan_authorized(service, project, "duplicate")
    with pytest.raises(DeploymentRefusal, match="successor plan"):
        plan_authorized(service, project, "duplicate")


def test_finalized_authority_receipt_reconciles_without_effect_replay(
    tmp_path: Path,
) -> None:
    project = committed_fixture(tmp_path, "python-http")
    manager, _grant_id = authority_harness(
        tmp_path, "receipt-recovery", project=project
    )
    first_adapter = FakeAdapter()
    state_root = tmp_path / "state-receipt-recovery"
    service = DeploymentService(
        state_root=state_root,
        adapter=first_adapter,
        authority_manager=manager,
        actor=ACTOR,
    )
    source_identity = authority_source_identity(service.inspect(project))
    decision, reservation = reserve_for(
        service,
        "plan_deployment",
        "receipt-recovery",
        source_identity=source_identity,
    )
    result = service.plan(
        project,
        deployment_id="receipt-recovery",
        grant_id=decision["authorizedBy"]["id"],
        authority_decision=decision,
    )
    canonical = manager.record_action(
        decision,
        result_status="succeeded",
        summary="Plan completed before response loss",
        resource={
            "deploymentId": "receipt-recovery",
            "planId": result["planId"],
            "planDigest": result["planDigest"],
            "sourceIdentity": authority_source_identity(result["spec"]),
            "targetIdentity": result["spec"]["target"]["identityDigest"],
        },
        reservation=reservation,
        claim=manager.get_claim(decision["requestId"]),
    )
    before = service.store.load_state("receipt-recovery")
    assert before["authorityReceipts"] == []
    effect_calls = list(first_adapter.calls)

    # Simulate a crash after canonical finalization but before the atomic
    # deployment-side evidence/link transaction begins.
    recovery_adapter = FakeAdapter()
    recovered = DeploymentService(
        state_root=state_root,
        adapter=recovery_adapter,
        authority_manager=AuthorityManager(
            ROOT,
            state_root=manager.state_root,
        ),
        actor=ACTOR,
    )
    reconciliation = recovered.reconcile_authority_receipts("receipt-recovery")
    assert len(reconciliation["links"]) == 1
    assert reconciliation["links"][0]["alreadyLinked"] is False
    assert recovery_adapter.calls == []
    assert first_adapter.calls == effect_calls
    linked = recovered.store.load_state("receipt-recovery")
    assert [item["receiptId"] for item in linked["authorityReceipts"]] == [
        canonical["receiptId"]
    ]
    evidence_files = list(
        (state_root / "records" / "receipt-recovery" / "evidence").glob("*.json")
    )
    assert len(evidence_files) == 1

    # Replaying the exact link after response loss is a pure no-op.
    state_revision = linked["revision"]
    deployment_receipts = list(linked["receipts"])
    duplicate = recovered.link_authority_receipt("receipt-recovery", canonical)
    assert duplicate["alreadyLinked"] is True
    unchanged = recovered.store.load_state("receipt-recovery")
    assert unchanged["revision"] == state_revision
    assert unchanged["receipts"] == deployment_receipts
    assert len(list((state_root / "records" / "receipt-recovery" / "evidence").glob("*.json"))) == 1
    assert recovered.reconcile_authority_receipts("receipt-recovery")["links"] == []

    tampered = deepcopy(canonical)
    tampered["result"]["summary"] = "tampered"
    with pytest.raises(DeploymentRefusal, match="differs from canonical"):
        recovered.link_authority_receipt("receipt-recovery", tampered)
    assert recovered.store.load_state("receipt-recovery") == unchanged


def test_rich_effect_outcome_reconciles_after_canonical_finalization_loss(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, adapter, _project, plan = planned_service(tmp_path)
    deployment_id = plan["spec"]["metadata"]["deploymentId"]
    manager = service._authority_manager
    assert manager is not None
    grant_id = manager.list_grants()["grants"][0]["grantId"]
    args = Namespace(actor_id=ACTOR, grant_id=grant_id, slice_id=SLICE_ID)
    original_record_action = manager.record_action

    def lose_finalization(*_args: Any, **_kwargs: Any) -> None:
        raise AuthorityError(
            "fixture_finalization_lost",
            "test-only loss after the deployment outcome commit",
        )

    monkeypatch.setattr(manager, "record_action", lose_finalization)
    with pytest.raises(DeploymentError) as lost:
        deployment_cli._run_governed(
            manager=manager,
            service=service,
            args=args,
            action="apply_deployment",
            deployment_id=deployment_id,
            run_id=plan["planDigest"],
            operation=lambda decision: service.apply(
                deployment_id,
                accept_plan_digest=plan["planDigest"],
                authority_decision=decision,
            ),
        )
    assert lost.value.code == "authority_finalization_pending"
    assert lost.value.exit_code == 4
    assert lost.value.details["authorityCode"] == "fixture_finalization_lost"
    assert adapter.calls.count("apply") == 1
    claims = list(manager.claims_root.glob("*.json"))
    request_ids = [
        json.loads(path.read_text(encoding="utf-8"))["requestId"]
        for path in claims
    ]
    unfinished_request = next(
        request_id
        for request_id in request_ids
        if manager.get_receipt_for_request(request_id) is None
    )
    outcome = service.store.authority_effect_outcome(
        deployment_id, unfinished_request
    )
    assert outcome is not None
    assert outcome["resource"]["runtimeDigest"] == digest_value(
        outcome["resource"]["runtime"]
    )

    monkeypatch.setattr(manager, "record_action", original_record_action)
    before = list(adapter.calls)
    reconciliation = service.reconcile_authority_receipts(
        deployment_id, request_id=unfinished_request
    )
    assert len(reconciliation["links"]) == 1
    canonical = manager.get_receipt_for_request(unfinished_request)
    assert canonical is not None
    assert canonical["result"] == outcome
    assert adapter.calls == before


def test_current_request_is_reserved_before_prior_receipt_reconciliation(
    tmp_path: Path,
) -> None:
    project = committed_fixture(tmp_path, "python-http")
    deployment_id = "receipt-recovery-continues"
    manager, grant_id = authority_harness(
        tmp_path, deployment_id, project=project
    )
    adapter = FakeAdapter()
    service = DeploymentService(
        state_root=tmp_path / "state-receipt-recovery-continues",
        adapter=adapter,
        authority_manager=manager,
        actor=ACTOR,
    )
    source_identity = authority_source_identity(service.inspect(project))
    decision, reservation = reserve_for(
        service,
        "plan_deployment",
        deployment_id,
        source_identity=source_identity,
    )
    plan = service.plan(
        project,
        deployment_id=deployment_id,
        grant_id=grant_id,
        authority_decision=decision,
    )
    outcome = service.store.authority_effect_outcome(
        deployment_id, decision["requestId"]
    )
    assert outcome is not None
    prior = manager.record_action(
        decision,
        result_status=outcome["status"],
        summary=outcome["summary"],
        code=outcome["code"],
        resource=outcome["resource"],
        reservation=reservation,
        claim=manager.get_claim(decision["requestId"]),
    )
    assert service.store.load_state(deployment_id)["authorityReceipts"] == []

    args = Namespace(actor_id=ACTOR, grant_id=grant_id, slice_id=SLICE_ID)
    observed = deployment_cli._run_governed(
        manager=manager,
        service=service,
        args=args,
        action="observe_deployment",
        deployment_id=deployment_id,
        run_id=plan["planDigest"],
        operation=lambda current: service.status(
            deployment_id, authority_decision=current
        ),
    )
    assert observed["priorAuthorityReconciliation"]["links"][0][
        "authorityReceipt"
    ]["receiptId"] == prior["receiptId"]
    assert observed["authorityReceipt"]["result"]["status"] == "succeeded"
    assert adapter.calls.count("observe") == 1


def test_missing_deployment_preflight_is_receipted_without_creating_state(
    tmp_path: Path,
) -> None:
    deployment_id = "missing-preflight"
    manager, grant_id = authority_harness(tmp_path, deployment_id)
    state_root = tmp_path / "must-not-be-created"
    service = DeploymentService(
        state_root=state_root,
        adapter=FakeAdapter(),
        authority_manager=manager,
        actor=ACTOR,
    )
    args = Namespace(actor_id=ACTOR, grant_id=grant_id, slice_id=SLICE_ID)

    with pytest.raises(DeploymentRefusal) as refused:
        deployment_cli._run_governed(
            manager=manager,
            service=service,
            args=args,
            action="observe_deployment",
            deployment_id=deployment_id,
            run_id_resolver=lambda: service.peek_authority_run_id(
                deployment_id, "observe_deployment"
            ),
            operation=lambda _decision: pytest.fail(
                "a failed scope preflight must not execute"
            ),
        )
    assert refused.value.code == "deployment_not_found"
    receipt = getattr(refused.value, "authority_receipt")
    assert receipt["action"] == "observe_deployment"
    assert receipt["scope"]["runId"] is None
    assert receipt["result"]["status"] == "not_executed"
    assert receipt["result"]["code"] == "deployment_not_found"
    assert not state_root.exists()


def test_claimed_effect_with_unreadable_outcome_gets_unknown_receipt_without_replay(
    tmp_path: Path,
) -> None:
    service, adapter, _project, plan = planned_service(tmp_path)
    deployment_id = plan["spec"]["metadata"]["deploymentId"]
    manager = service._authority_manager
    assert manager is not None
    grant_id = manager.list_grants()["grants"][0]["grantId"]
    args = Namespace(actor_id=ACTOR, grant_id=grant_id, slice_id=SLICE_ID)

    def unreadable_outcome(_deployment_id: str, _request_id: str) -> None:
        raise DeploymentRefusal(
            "evidence_integrity_failed", "test-only unreadable outcome"
        )

    service.store.authority_effect_outcome = unreadable_outcome  # type: ignore[method-assign]
    with pytest.raises(DeploymentError) as uncertain:
        deployment_cli._run_governed(
            manager=manager,
            service=service,
            args=args,
            action="apply_deployment",
            deployment_id=deployment_id,
            run_id=plan["planDigest"],
            operation=lambda decision: service.apply(
                deployment_id,
                accept_plan_digest=plan["planDigest"],
                authority_decision=decision,
            ),
        )
    assert uncertain.value.code == "authority_effect_outcome_unknown"
    receipt = getattr(uncertain.value, "authority_receipt")
    assert receipt["result"]["status"] == "failed"
    assert receipt["result"]["code"] == "authority_effect_outcome_unknown"
    assert receipt["result"]["resource"]["effectDisposition"] == "unknown"
    assert receipt["result"]["resource"]["reconciliationRequired"] is True
    assert adapter.calls.count("apply") == 1


def _interrupt_apply_after_claim(
    tmp_path: Path,
    deployment_id: str,
    *,
    fixture: str = "python-http",
) -> tuple[
    DeploymentService,
    FakeAdapter,
    AuthorityManager,
    str,
    dict[str, Any],
    dict[str, Any],
]:
    project = committed_fixture(tmp_path, fixture)
    manager, grant_id = authority_harness(
        tmp_path, deployment_id, project=project
    )
    adapter = FakeAdapter()
    service = DeploymentService(
        state_root=tmp_path / f"state-{deployment_id}",
        adapter=adapter,
        authority_manager=manager,
        actor=ACTOR,
    )
    plan = plan_authorized(service, project, deployment_id)
    decision, _reservation = reserve_for(
        service,
        "apply_deployment",
        deployment_id,
        run_id=plan["planDigest"],
    )
    reference = service._verify_authority(
        decision,
        action="apply_deployment",
        deployment_id=deployment_id,
        run_id=plan["planDigest"],
    )
    service.store.approve_and_reserve(
        deployment_id,
        plan,
        actor=ACTOR,
        authority_reference=reference,
    )
    assert manager.has_claim(decision["requestId"])
    assert manager.get_receipt_for_request(decision["requestId"]) is None
    return service, adapter, manager, grant_id, plan, decision


@pytest.mark.parametrize("runtime_present", (False, True))
def test_observation_finalizes_interrupted_apply_without_replay(
    tmp_path: Path, runtime_present: bool
) -> None:
    deployment_id = f"interrupted-apply-{'present' if runtime_present else 'absent'}"
    service, adapter, manager, grant_id, plan, interrupted = (
        _interrupt_apply_after_claim(tmp_path, deployment_id)
    )
    if runtime_present:
        adapter.present = True
        adapter.plan = plan
        adapter.images = {
            service_spec["id"]: "sha256:" + format(index + 1, "064x")
            for index, service_spec in enumerate(plan["spec"]["services"])
        }
        adapter.volumes = {
            storage["id"]: f"volume-{storage['id']}"
            for service_spec in plan["spec"]["services"]
            for storage in service_spec["storage"]
        }
    args = Namespace(
        actor_id=ACTOR,
        grant_id=grant_id,
        slice_id=SLICE_ID,
    )
    result = deployment_cli._run_governed(
        manager=manager,
        service=service,
        args=args,
        action="observe_deployment",
        deployment_id=deployment_id,
        run_id=plan["planDigest"],
        operation=lambda decision: service.status(
            deployment_id, authority_decision=decision
        ),
    )
    expected_state = "healthy" if runtime_present else "failed"
    expected_status = "succeeded" if runtime_present else "failed"
    assert result["state"]["lifecycleState"] == expected_state
    assert result["authorityReconciliation"]["links"][0]["alreadyLinked"] is False
    original_receipt = manager.get_receipt_for_request(interrupted["requestId"])
    assert original_receipt is not None
    assert original_receipt["result"]["status"] == expected_status
    assert original_receipt["result"]["resource"]["lifecycleState"] == expected_state
    assert "apply" not in adapter.calls
    assert service.reconcile_authority_receipts(deployment_id)["links"] == []
    assert manager.get_receipt_for_request(interrupted["requestId"]) == original_receipt


def test_ambiguous_interrupted_apply_remains_unfinalized_and_is_not_replayed(
    tmp_path: Path,
) -> None:
    deployment_id = "interrupted-apply-ambiguous"
    service, adapter, manager, grant_id, plan, interrupted = (
        _interrupt_apply_after_claim(tmp_path, deployment_id)
    )
    original_observe = adapter.observe

    def ambiguous_observe(
        spec: Mapping[str, Any], **options: Any
    ) -> dict[str, Any]:
        observation = original_observe(spec, **options)
        observation["unexpectedResources"]["containers"] = ["unknown-runtime"]
        return observation

    adapter.observe = ambiguous_observe  # type: ignore[method-assign]
    args = Namespace(
        actor_id=ACTOR,
        grant_id=grant_id,
        slice_id=SLICE_ID,
    )
    result = deployment_cli._run_governed(
        manager=manager,
        service=service,
        args=args,
        action="observe_deployment",
        deployment_id=deployment_id,
        run_id=plan["planDigest"],
        operation=lambda decision: service.status(
            deployment_id, authority_decision=decision
        ),
    )
    assert result["state"]["lifecycleState"] == "reconciliation_required"
    assert result["authorityEffectPending"]["unresolved"][0]["requestId"] == interrupted["requestId"]
    assert manager.get_receipt_for_request(interrupted["requestId"]) is None
    assert "apply" not in adapter.calls

    with pytest.raises(DeploymentRefusal) as blocked:
        deployment_cli._run_governed(
            manager=manager,
            service=service,
            args=args,
            action="restart_deployment",
            deployment_id=deployment_id,
            run_id=plan["planDigest"],
            operation=lambda _decision: pytest.fail(
                "an unresolved claimed effect must block a new mutation"
            ),
        )
    assert blocked.value.code == "authority_effect_unfinalized"
    assert manager.get_receipt_for_request(interrupted["requestId"]) is None
    assert "apply" not in adapter.calls


@pytest.mark.parametrize("residue", ("image", "volume"))
def test_interrupted_apply_with_owned_residue_remains_unfinalized(
    tmp_path: Path, residue: str
) -> None:
    deployment_id = f"interrupted-apply-{residue}-residue"
    fixture = "persistent-multi" if residue == "volume" else "python-http"
    service, adapter, manager, grant_id, plan, interrupted = (
        _interrupt_apply_after_claim(
            tmp_path,
            deployment_id,
            fixture=fixture,
        )
    )
    original_observe = adapter.observe

    def residue_observe(
        spec: Mapping[str, Any], **options: Any
    ) -> dict[str, Any]:
        observation = original_observe(spec, **options)
        if residue == "image":
            service_id = plan["spec"]["services"][0]["id"]
            observation["images"][service_id].update(
                present=True,
                imageDigest="sha256:" + "9" * 64,
            )
        else:
            storage_id = next(iter(observation["volumes"]))
            observation["volumes"][storage_id].update(
                present=True,
                name=f"retained-{storage_id}",
            )
        return observation

    adapter.observe = residue_observe  # type: ignore[method-assign]
    args = Namespace(actor_id=ACTOR, grant_id=grant_id, slice_id=SLICE_ID)
    result = deployment_cli._run_governed(
        manager=manager,
        service=service,
        args=args,
        action="observe_deployment",
        deployment_id=deployment_id,
        run_id=plan["planDigest"],
        operation=lambda decision: service.status(
            deployment_id, authority_decision=decision
        ),
    )

    assert result["state"]["lifecycleState"] == "reconciliation_required"
    assert result["authorityEffectPending"]["unresolved"][0]["requestId"] == interrupted["requestId"]
    assert manager.get_receipt_for_request(interrupted["requestId"]) is None
    assert "apply" not in adapter.calls


def test_separately_authorized_remove_aborts_exact_interrupted_apply(
    tmp_path: Path,
) -> None:
    deployment_id = "interrupted-apply-exact-abort"
    service, adapter, manager, grant_id, plan, interrupted = (
        _interrupt_apply_after_claim(tmp_path, deployment_id)
    )
    original_observe = adapter.observe

    def image_residue(
        spec: Mapping[str, Any], **options: Any
    ) -> dict[str, Any]:
        observation = original_observe(spec, **options)
        service_id = plan["spec"]["services"][0]["id"]
        observation["images"][service_id].update(
            present=True,
            imageDigest="sha256:" + "8" * 64,
        )
        return observation

    adapter.observe = image_residue  # type: ignore[method-assign]
    args = Namespace(actor_id=ACTOR, grant_id=grant_id, slice_id=SLICE_ID)
    observed = deployment_cli._run_governed(
        manager=manager,
        service=service,
        args=args,
        action="observe_deployment",
        deployment_id=deployment_id,
        run_id=plan["planDigest"],
        operation=lambda decision: service.status(
            deployment_id, authority_decision=decision
        ),
    )
    assert observed["state"]["lifecycleState"] == "reconciliation_required"

    removed = deployment_cli._run_governed(
        manager=manager,
        service=service,
        args=args,
        action="remove_deployment_runtime",
        deployment_id=deployment_id,
        run_id=plan["planDigest"],
        operation=lambda decision: service.remove(
            deployment_id, authority_decision=decision
        ),
    )
    assert removed["state"]["lifecycleState"] == "removed_runtime_data_retained"
    assert removed["runtime"]["partialRecovery"] is True
    assert removed["authorityReconciliation"]["reconciled"]
    interrupted_receipt = manager.get_receipt_for_request(interrupted["requestId"])
    assert interrupted_receipt is not None
    assert interrupted_receipt["result"]["status"] == "failed"
    assert interrupted_receipt["result"]["code"] == "interrupted_apply_recovered"
    assert removed["authorityReceipt"]["result"]["status"] == "succeeded"
    assert "apply" not in adapter.calls
    assert "remove_runtime" in adapter.calls


def test_interrupted_first_apply_retained_data_purge_uses_exact_predecessor(
    tmp_path: Path,
) -> None:
    deployment_id = "interrupted-first-apply-retained-purge"
    service, adapter, _manager, _grant_id, plan, _interrupted = (
        _interrupt_apply_after_claim(
            tmp_path,
            deployment_id,
            fixture="persistent-multi",
        )
    )
    adapter.plan = plan
    adapter.volumes = {
        item["id"]: f"volume-{item['id']}"
        for service_spec in plan["spec"]["services"]
        for item in service_spec["storage"]
    }

    observed = governed_call(
        service,
        "observe_deployment",
        deployment_id,
        lambda decision: service.status(
            deployment_id,
            authority_decision=decision,
        ),
        run_id=plan["planDigest"],
    )
    assert observed["state"]["lifecycleState"] == "reconciliation_required"

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
    assert removed["state"]["lifecycleState"] == "removed_runtime_data_retained"
    assert removed["state"]["acceptedRevision"] is None
    assert removed["state"]["approvedPlanDigest"] == plan["planDigest"]

    purge_plan = governed_call(
        service,
        "plan_deployment",
        deployment_id,
        lambda decision: service.plan_purge(
            deployment_id,
            authority_decision=decision,
        ),
        run_id=plan["planDigest"],
    )
    assert purge_plan["predecessorRevision"] == plan["planDigest"]
    assert purge_plan["dataRetentionEffects"] == [
        {"from": "retained", "to": "purged"}
    ]


class SimulatedStoreCrash(BaseException):
    pass


@pytest.mark.parametrize(
    "boundary",
    (
        "after_journal",
        "after_plan_1",
        "after_overlay_file_1_1",
        "after_overlay_1",
        "after_receipt_1",
        "after_receipt_2",
        "before_state",
        "after_state",
        "before_journal_cleanup",
    ),
)
def test_deployment_creation_recovers_every_commit_boundary(
    tmp_path: Path, boundary: str
) -> None:
    source_service, _adapter, _project, plan = planned_service(
        tmp_path / "source"
    )
    deployment_id = plan["spec"]["metadata"]["deploymentId"]
    authority_reference = source_service.store.authority_decision_references(
        deployment_id
    )[0]
    state_root = tmp_path / f"wal-{boundary}"

    def failpoint(name: str) -> None:
        if name == boundary:
            raise SimulatedStoreCrash(name)

    crashing = DeploymentStore(state_root, failpoint=failpoint)
    with pytest.raises(SimulatedStoreCrash):
        crashing.create_from_plan(
            plan,
            actor=ACTOR,
            authority_reference=authority_reference,
        )
    recovered = DeploymentStore(state_root)
    state = recovered.load_state(deployment_id)
    assert state["revision"] == 1
    assert state["lifecycleState"] == "awaiting_approval"
    assert len(state["receipts"]) == 2
    assert recovered.load_plan(
        deployment_id, plan["planDigest"], require_unexpired=False
    ) == plan
    assert recovered.verify_overlay(
        deployment_id,
        plan["planId"],
        plan["overlay"],
    ).is_dir()
    root = state_root / "records" / deployment_id
    assert not (root / ".pending-commit.json").exists()
    assert len(list((root / "receipts").glob("*.json"))) == 2
    assert len(list((root / "plans").glob("*.json"))) == 1


@pytest.mark.parametrize(
    "boundary",
    ("after_journal", "after_receipt_1", "before_state", "after_state"),
)
def test_deployment_mutation_recovers_exactly_once(
    tmp_path: Path, boundary: str
) -> None:
    service, _adapter, _project, _plan = planned_service(tmp_path)
    deployment_id = "deployment-python-http"
    root = service.store.root
    before = service.store.load_state(deployment_id)

    def failpoint(name: str) -> None:
        if name == boundary:
            raise SimulatedStoreCrash(name)

    crashing = DeploymentStore(root, failpoint=failpoint)
    with pytest.raises(SimulatedStoreCrash):
        crashing.mutate(
            deployment_id,
            event="wal_fixture_mutation",
            actor=ACTOR,
            data={"fixture": True},
            mutation=lambda state: state.update(driftStatus="drifted"),
        )
    recovered = DeploymentStore(root)
    after = recovered.load_state(deployment_id)
    assert after["revision"] == before["revision"] + 1
    assert after["driftStatus"] == "drifted"
    events = [
        json.loads(path.read_text(encoding="utf-8"))["event"]
        for path in (root / "records" / deployment_id / "receipts").glob(
            "*.json"
        )
    ]
    assert events.count("wal_fixture_mutation") == 1
    assert recovered.load_state(deployment_id) == after


def test_authority_scope_peek_refuses_pending_wal_without_recovery_or_mutation(
    tmp_path: Path,
) -> None:
    service, _adapter, _project, plan = planned_service(tmp_path)
    deployment_id = plan["spec"]["metadata"]["deploymentId"]
    root = service.store.root

    def failpoint(name: str) -> None:
        if name == "after_journal":
            raise SimulatedStoreCrash(name)

    with pytest.raises(SimulatedStoreCrash):
        DeploymentStore(root, failpoint=failpoint).mutate(
            deployment_id,
            event="pending_scope_fixture",
            actor=ACTOR,
            data={"fixture": True},
            mutation=lambda state: state.update(driftStatus="drifted"),
        )
    record = root / "records" / deployment_id
    before = {
        path.relative_to(record).as_posix(): path.read_bytes()
        for path in sorted(record.rglob("*"))
        if path.is_file()
    }

    readonly = DeploymentStore(root, create=False)
    with pytest.raises(DeploymentRefusal) as blocked:
        readonly.peek_authority_run_id(deployment_id, "observe_deployment")
    assert blocked.value.code == "deployment_reconciliation_required"
    after = {
        path.relative_to(record).as_posix(): path.read_bytes()
        for path in sorted(record.rglob("*"))
        if path.is_file()
    }
    assert after == before
    assert (record / ".pending-commit.json").is_file()


@pytest.mark.parametrize(
    "boundary",
    (
        "after_journal",
        "after_evidence_1",
        "after_receipt_1",
        "before_state",
        "after_state",
        "before_journal_cleanup",
    ),
)
def test_deployment_evidence_recovers_in_the_same_commit(
    tmp_path: Path, boundary: str
) -> None:
    service, _adapter, _project, _plan = planned_service(tmp_path)
    deployment_id = "deployment-python-http"
    reference, document = service.store.prepare_evidence(
        deployment_id,
        kind="fixture_evidence",
        value={"bounded": True, "value": "public-safe"},
    )

    def failpoint(name: str) -> None:
        if name == boundary:
            raise SimulatedStoreCrash(name)

    crashing = DeploymentStore(service.store.root, failpoint=failpoint)
    with pytest.raises(SimulatedStoreCrash):
        crashing.mutate(
            deployment_id,
            event="fixture_evidence_recorded",
            actor=ACTOR,
            data={"evidence": reference},
            mutation=lambda _state: None,
            evidence_documents=(document,),
        )
    recovered = DeploymentStore(service.store.root)
    state = recovered.load_state(deployment_id)
    evidence_path = Path(reference["path"])
    assert evidence_path.is_file()
    assert evidence_path.stat().st_mode & 0o777 == 0o600
    assert json.loads(evidence_path.read_text(encoding="utf-8")) == document
    matching = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in (
            service.store.root / "records" / deployment_id / "receipts"
        ).glob("*.json")
        if json.loads(path.read_text(encoding="utf-8"))["event"]
        == "fixture_evidence_recorded"
    ]
    assert len(matching) == 1
    assert matching[0]["data"]["evidence"] == reference
    assert not (
        service.store.root
        / "records"
        / deployment_id
        / ".pending-commit.json"
    ).exists()
    assert recovered.load_state(deployment_id) == state


def test_deployment_evidence_closure_rejects_missing_tampered_and_orphaned_files(
    tmp_path: Path,
) -> None:
    service, _adapter, _project, _plan = planned_service(tmp_path)
    deployment_id = "deployment-python-http"
    reference, document = service.store.prepare_evidence(
        deployment_id,
        kind="closure_fixture",
        value={"bounded": True},
    )
    service.store.mutate(
        deployment_id,
        event="closure_evidence_recorded",
        actor=ACTOR,
        data={"evidence": reference},
        mutation=lambda _state: None,
        evidence_documents=(document,),
    )
    evidence_path = Path(reference["path"])
    exact = evidence_path.read_bytes()

    evidence_path.unlink()
    with pytest.raises(DeploymentRefusal) as missing:
        service.store.load_state(deployment_id)
    assert missing.value.code == "evidence_closure_invalid"
    evidence_path.write_bytes(exact)
    evidence_path.chmod(0o600)

    tampered = json.loads(exact)
    tampered["payload"]["bounded"] = False
    evidence_path.write_text(json.dumps(tampered), encoding="utf-8")
    evidence_path.chmod(0o600)
    with pytest.raises(DeploymentRefusal) as corrupt:
        service.store.load_state(deployment_id)
    assert corrupt.value.code == "evidence_integrity_failed"
    evidence_path.write_bytes(exact)
    evidence_path.chmod(0o600)

    orphan = evidence_path.parent / "evidence_orphan_0000000000000000.json"
    orphan.write_text("{}\n", encoding="utf-8")
    orphan.chmod(0o600)
    with pytest.raises(DeploymentRefusal) as extra:
        service.store.load_state(deployment_id)
    assert extra.value.code == "evidence_closure_invalid"


def test_deployment_plan_inventory_is_referentially_closed(tmp_path: Path) -> None:
    service, _adapter, _project, plan = planned_service(tmp_path)
    deployment_id = "deployment-python-http"
    plan_path = service.store.plan_path(deployment_id, plan["planId"])
    exact = plan_path.read_bytes()
    plan_path.unlink()
    with pytest.raises(DeploymentRefusal) as missing:
        service.store.load_state(deployment_id)
    assert missing.value.code == "plan_closure_invalid"
    plan_path.write_bytes(exact)
    plan_path.chmod(0o600)

    orphan = deepcopy(plan)
    orphan["planId"] = "plan_orphan"
    orphan["planDigest"] = plan_digest(orphan)
    orphan_path = plan_path.parent / "plan_orphan.json"
    atomic_json(orphan_path, orphan, create_only=True)
    with pytest.raises(DeploymentRefusal) as extra:
        service.store.load_state(deployment_id)
    assert extra.value.code == "plan_closure_invalid"


def test_terminal_authority_outcomes_reconcile_without_replaying_effects(
    tmp_path: Path,
) -> None:
    project = committed_fixture(tmp_path, "persistent-multi")
    manager, grant_id = authority_harness(
        tmp_path, "terminal-outcomes", project=project
    )
    adapter = FakeAdapter()
    state_root = tmp_path / "terminal-state"
    service = DeploymentService(
        state_root=state_root,
        adapter=adapter,
        authority_manager=manager,
        actor=ACTOR,
    )
    deployment_id = "terminal-outcomes"

    def reconcile_exact(decision: Mapping[str, Any]) -> dict[str, Any]:
        calls = list(adapter.calls)
        outcome = service.store.authority_effect_outcome(
            deployment_id, decision["requestId"]
        )
        assert outcome is not None
        recovered = DeploymentService(
            state_root=state_root,
            adapter=adapter,
            authority_manager=AuthorityManager(
                ROOT, state_root=manager.state_root
            ),
            actor=ACTOR,
        )
        linked = recovered.reconcile_authority_receipts(
            deployment_id, request_id=decision["requestId"]
        )
        assert adapter.calls == calls
        assert len(linked["links"]) == 1
        canonical = manager.get_receipt_for_request(decision["requestId"])
        assert canonical is not None
        assert canonical["result"] == outcome
        assert recovered.reconcile_authority_receipts(deployment_id)["links"] == []
        return linked

    source_identity = authority_source_identity(service.inspect(project))
    plan_decision, _ = reserve_for(
        service,
        "plan_deployment",
        deployment_id,
        source_identity=source_identity,
    )
    plan = service.plan(
        project,
        deployment_id=deployment_id,
        grant_id=grant_id,
        authority_decision=plan_decision,
    )
    reconcile_exact(plan_decision)

    apply_decision, _ = reserve_for(
        service,
        "apply_deployment",
        deployment_id,
        run_id=plan["planDigest"],
    )
    applied = service.apply(
        deployment_id,
        accept_plan_digest=plan["planDigest"],
        authority_decision=apply_decision,
    )
    assert applied["state"]["lifecycleState"] == "healthy"
    reconcile_exact(apply_decision)

    restart_decision, _ = reserve_for(
        service,
        "restart_deployment",
        deployment_id,
        run_id=plan["planDigest"],
    )
    service.restart(deployment_id, authority_decision=restart_decision)
    reconcile_exact(restart_decision)

    remove_decision, _ = reserve_for(
        service,
        "remove_deployment_runtime",
        deployment_id,
        run_id=plan["planDigest"],
    )
    removed = service.remove(deployment_id, authority_decision=remove_decision)
    assert removed["state"]["lifecycleState"] == "removed_runtime_data_retained"
    reconcile_exact(remove_decision)

    purge_plan = governed_call(
        service,
        "plan_deployment",
        deployment_id,
        lambda decision: service.plan_purge(
            deployment_id, authority_decision=decision
        ),
        run_id=plan["planDigest"],
    )
    purge_decision, _ = reserve_for(
        service,
        "purge_deployment_data",
        deployment_id,
        run_id=purge_plan["planDigest"],
    )
    purged = service.purge_data(
        deployment_id,
        accept_plan_digest=purge_plan["planDigest"],
        authority_decision=purge_decision,
    )
    assert purged["state"]["lifecycleState"] == "purged"
    reconcile_exact(purge_decision)


def test_failed_terminal_authority_outcome_reconciles_without_apply_replay(
    tmp_path: Path,
) -> None:
    service, adapter, _project, plan = planned_service(tmp_path)
    deployment_id = plan["spec"]["metadata"]["deploymentId"]
    adapter.fail = True
    decision, _ = reserve_for(
        service,
        "apply_deployment",
        deployment_id,
        run_id=plan["planDigest"],
    )
    with pytest.raises(AdapterError):
        service.apply(
            deployment_id,
            accept_plan_digest=plan["planDigest"],
            authority_decision=decision,
        )
    calls = list(adapter.calls)
    outcome = service.store.authority_effect_outcome(
        deployment_id, decision["requestId"]
    )
    assert outcome is not None
    assert outcome["status"] == "failed"
    reconciled = service.reconcile_authority_receipts(
        deployment_id, request_id=decision["requestId"]
    )
    assert len(reconciled["links"]) == 1
    assert adapter.calls == calls
    canonical = service._authority_manager.get_receipt_for_request(
        decision["requestId"]
    )
    assert canonical is not None
    assert canonical["result"] == outcome


def test_deployment_store_rejects_tampered_or_conflicting_journal(
    tmp_path: Path,
) -> None:
    source_service, _adapter, _project, plan = planned_service(
        tmp_path / "source"
    )
    deployment_id = plan["spec"]["metadata"]["deploymentId"]
    authority_reference = source_service.store.authority_decision_references(
        deployment_id
    )[0]

    def crash_after_journal(name: str) -> None:
        if name == "after_journal":
            raise SimulatedStoreCrash(name)

    tampered_root = tmp_path / "tampered"
    with pytest.raises(SimulatedStoreCrash):
        DeploymentStore(tampered_root, failpoint=crash_after_journal).create_from_plan(
            plan, actor=ACTOR, authority_reference=authority_reference
        )
    journal_path = (
        tampered_root / "records" / deployment_id / ".pending-commit.json"
    )
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    journal["transactionDigest"] = "sha256:" + "0" * 64
    journal_path.write_text(json.dumps(journal), encoding="utf-8")
    with pytest.raises(DeploymentRefusal) as tampered:
        DeploymentStore(tampered_root).load_state(deployment_id)
    assert tampered.value.code == "transaction_invalid"

    overlay_conflict_root = tmp_path / "overlay-conflict"
    with pytest.raises(SimulatedStoreCrash):
        DeploymentStore(
            overlay_conflict_root, failpoint=crash_after_journal
        ).create_from_plan(
            plan, actor=ACTOR, authority_reference=authority_reference
        )
    conflicting_overlay = (
        overlay_conflict_root
        / "records"
        / deployment_id
        / "overlays"
        / plan["planId"]
    )
    conflicting_overlay.mkdir(mode=0o700)
    first_overlay_path = sorted(plan["overlay"])[0]
    conflict_file = conflicting_overlay / first_overlay_path
    conflict_file.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    conflict_file.write_text("conflicting overlay\n", encoding="utf-8")
    conflict_file.chmod(0o600)
    with pytest.raises(DeploymentRefusal) as overlay_conflict:
        DeploymentStore(overlay_conflict_root).load_state(deployment_id)
    assert overlay_conflict.value.code == "overlay_conflict"
    assert not (
        overlay_conflict_root
        / "records"
        / deployment_id
        / "state.json"
    ).exists()

    conflict_root = tmp_path / "conflict"
    with pytest.raises(SimulatedStoreCrash):
        DeploymentStore(conflict_root, failpoint=crash_after_journal).create_from_plan(
            plan, actor=ACTOR, authority_reference=authority_reference
        )
    conflict_journal = json.loads(
        (
            conflict_root
            / "records"
            / deployment_id
            / ".pending-commit.json"
        ).read_text(encoding="utf-8")
    )
    conflicting_state = deepcopy(conflict_journal["nextState"])
    conflicting_state["revision"] += 10
    conflicting_state = DeploymentStore._seal_state(conflicting_state)
    atomic_json(
        conflict_root / "records" / deployment_id / "state.json",
        conflicting_state,
        create_only=True,
    )
    with pytest.raises(DeploymentRefusal) as conflict:
        DeploymentStore(conflict_root).load_state(deployment_id)
    assert conflict.value.code == "transaction_conflict"


def test_deployment_reader_never_observes_a_live_partial_commit(
    tmp_path: Path,
) -> None:
    service, _adapter, _project, _plan = planned_service(tmp_path)
    deployment_id = "deployment-python-http"
    lock_path = service.store._lock_path(deployment_id)
    with exclusive_lock(lock_path):
        with pytest.raises(DeploymentRefusal) as busy:
            DeploymentStore(service.store.root).load_state(deployment_id)
    assert busy.value.code == "deployment_busy"


def test_receipt_orphan_and_tamper_are_detected(tmp_path: Path) -> None:
    service, _adapter, _project, _plan = planned_service(tmp_path)
    receipt_root = tmp_path / "state" / "records" / "deployment-python-http" / "receipts"
    orphan = receipt_root / "receipt_orphan.json"
    orphan.write_text("{}\n", encoding="utf-8")
    with pytest.raises(DeploymentRefusal, match="orphaned evidence"):
        service.store.load_state("deployment-python-http")
    orphan.unlink()
    first = sorted(receipt_root.glob("*.json"))[0]
    value = json.loads(first.read_text(encoding="utf-8"))
    value["event"] = "tampered"
    first.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(DeploymentRefusal, match="integrity check failed"):
        service.store.load_state("deployment-python-http")


def test_resealed_relationally_invalid_state_is_rejected(tmp_path: Path) -> None:
    service, _adapter, _project, _plan = planned_service(tmp_path)
    deployment_id = "deployment-python-http"
    state = service.store.load_state(deployment_id)
    state["lifecycleState"] = "healthy"
    invalid = DeploymentStore._seal_state(state)
    state_path = service.store._state_path(deployment_id)
    state_path.write_text(
        json.dumps(invalid, sort_keys=True) + "\n", encoding="utf-8"
    )
    with pytest.raises(DeploymentRefusal) as rejected:
        service.store.load_state(deployment_id)
    assert rejected.value.code == "state_invalid"


def test_state_root_never_chmods_arbitrary_existing_directory(tmp_path: Path) -> None:
    unsafe = tmp_path / "shared"
    unsafe.mkdir(mode=0o755)
    before = unsafe.stat().st_mode & 0o777
    with pytest.raises(DeploymentRefusal, match="already be owner-private"):
        DeploymentService(state_root=unsafe, adapter=FakeAdapter()).store
    assert unsafe.stat().st_mode & 0o777 == before


def test_state_root_rejects_symlink_in_existing_ancestor(tmp_path: Path) -> None:
    real = tmp_path / "real"
    existing = real / "existing"
    existing.mkdir(parents=True, mode=0o700)
    link = tmp_path / "linked"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(DeploymentRefusal, match="traverses a symlink"):
        DeploymentService(state_root=link / "existing", adapter=FakeAdapter()).store


def test_contract_refuses_unsafe_variants(tmp_path: Path) -> None:
    _service, _adapter, _project, plan = planned_service(tmp_path)
    base = plan["spec"]

    mutations = (
        (lambda value: value["services"][0]["runtime"]["user"].update(uid=0), "root_runtime"),
        (lambda value: value["services"][0]["ports"][0].update(hostAddress="0.0.0.0"), "public_port_forbidden"),
        (lambda value: value["services"][0]["build"].update(context="../escape"), "unsafe_path"),
        (lambda value: value["services"][0]["build"].update(context="/tmp/escape"), "unsafe_path"),
        (lambda value: value["services"][0]["environment"].update(API_TOKEN="literal"), "secret_value_forbidden"),
        (lambda value: value["services"][0]["storage"].append({"id": "bad", "mountPath": "/proc/data", "persistence": "retained"}), "unsafe_mount"),
        (lambda value: value["services"][0]["health"].update(type="missing"), "missing_health"),
    )
    for mutation, code in mutations:
        candidate = deepcopy(base)
        mutation(candidate)
        with pytest.raises(DeploymentRefusal) as raised:
            validate_deployment_spec(candidate)
        assert raised.value.code == code


def test_inspection_refuses_a_tracked_source_symlink(tmp_path: Path) -> None:
    project = tmp_path / "tracked-symlink"
    project.mkdir()
    (project / "app.py").write_text("print('safe')\n", encoding="utf-8")
    (project / "linked.py").symlink_to("app.py")
    _git("init", "--initial-branch=main", cwd=project)
    _git("config", "user.name", "StatePort Fixture", cwd=project)
    _git("config", "user.email", "fixture@stateport.invalid", cwd=project)
    _git("add", ".", cwd=project)
    _git("commit", "-m", "symlink fixture", cwd=project)

    with pytest.raises(DeploymentRefusal) as raised:
        inspect_project(project)
    assert raised.value.code == "symlink_escape"


def test_local_adapter_refuses_secret_binding_before_runtime_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _service, _fake, _project, plan = planned_service(tmp_path)
    candidate = deepcopy(plan)
    candidate["spec"]["services"][0]["secrets"] = [
        {"id": "api-token", "binding": "secret-broker://fixture/api-token"}
    ]
    adapter = RootlessPodmanAdapter()
    monkeypatch.setattr(adapter, "_assert_target_identity", lambda _spec: {})
    monkeypatch.setattr(
        adapter,
        "_run",
        lambda *_args, **_kwargs: pytest.fail("runtime command must not execute"),
    )

    with pytest.raises(AdapterError) as raised:
        adapter.apply(
            candidate,
            context_root=tmp_path / "context",
            overlay_root=tmp_path / "overlay",
        )
    assert raised.value.code == "secret_binding_unavailable"


def test_local_adapter_refuses_an_occupied_explicit_host_port(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _service, _fake, _project, plan = planned_service(tmp_path)
    candidate = deepcopy(plan)
    adapter = RootlessPodmanAdapter()
    monkeypatch.setattr(adapter, "_assert_owned", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        adapter,
        "_run",
        lambda *_args, **_kwargs: pytest.fail("Podman must not run for an occupied port"),
    )
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as occupied:
        occupied.bind(("127.0.0.1", 0))
        occupied.listen()
        candidate["spec"]["services"][0]["ports"][0]["hostPort"] = (
            occupied.getsockname()[1]
        )
        names = adapter.resource_names(candidate["spec"])
        with pytest.raises(AdapterError) as raised:
            adapter._run_services(
                candidate,
                names,
                {"web": DIGEST},
                {"internal": "fixture-network"},
                {},
            )
    assert raised.value.code == "port_unavailable"


@pytest.mark.parametrize("running", (False, True))
def test_local_adapter_fails_closed_for_exited_or_never_healthy_service(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    running: bool,
) -> None:
    _service, _fake, _project, plan = planned_service(tmp_path)
    adapter = RootlessPodmanAdapter()
    monkeypatch.setattr(
        adapter,
        "_inspect",
        lambda *_args, **_kwargs: {"State": {"Running": running}},
    )
    if running:
        clock = iter((0.0, 1.0, 10_000.0))
        monkeypatch.setattr(podman_module.time, "monotonic", lambda: next(clock))
        monkeypatch.setattr(podman_module.time, "sleep", lambda _seconds: None)
        monkeypatch.setattr(
            adapter,
            "_service_health",
            lambda *_args, **_kwargs: (
                False,
                {"status": "unhealthy", "checkedAt": "2026-07-30T00:00:00Z"},
            ),
        )
    with pytest.raises(AdapterError) as raised:
        adapter.verify_health(
            plan["spec"],
            {"containers": {"web": "fixture-container"}},
        )
    assert raised.value.code == "health_verification_failed"


@pytest.mark.parametrize(
    ("format_name", "document"),
    (
        ("json", '{"schema":"a","schema":"b"}'),
        ("json", '{"value":NaN}'),
        ("yaml", "source: &source\n  value: one\ncopy: *source\n"),
        ("yaml", "schema: one\nschema: two\n"),
    ),
)
def test_structured_deployment_inputs_reject_ambiguous_documents(
    format_name: str, document: str
) -> None:
    with pytest.raises(DeploymentRefusal) as raised:
        strict_mapping_document(
            document,
            format_name=format_name,
            label="fixture descriptor",
        )
    assert raised.value.code == "descriptor_invalid"


def test_structured_deployment_inputs_have_a_depth_limit() -> None:
    document = "{}"
    for _index in range(70):
        document = '{"nested":' + document + "}"
    with pytest.raises(DeploymentRefusal) as raised:
        strict_mapping_document(
            document,
            format_name="json",
            label="deep fixture",
        )
    assert raised.value.code == "document_too_complex"


def test_plan_expiry_and_transition_matrix(tmp_path: Path) -> None:
    _service, _adapter, _project, plan = planned_service(tmp_path)
    from datetime import datetime, timezone

    expiry = datetime.fromisoformat(plan["expiresAt"].replace("Z", "+00:00"))
    with pytest.raises(DeploymentRefusal, match="expired"):
        validate_plan(plan, now=expiry)
    assert LIFECYCLE_STATES
    validate_transition("planned", "awaiting_approval")
    with pytest.raises(DeploymentRefusal):
        validate_transition("healthy", "purged")


def test_json_schemas_are_strict_and_validate_runtime_documents(tmp_path: Path) -> None:
    service, _adapter, project, plan = planned_service(tmp_path)
    inspection = inspect_project(project)
    schemas = {
        name: json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
        for name in (
            "deployment.v1.schema.json",
            "deployment-plan.v1.schema.json",
            "deployment-state.v1.schema.json",
            "deployment-receipt.v1.schema.json",
            "deployment-inspection.v1.schema.json",
            "deployment-evidence.v1.schema.json",
        )
    }
    for schema in schemas.values():
        jsonschema.Draft202012Validator.check_schema(schema)
        assert schema["additionalProperties"] is False
    format_checker = _format_checker()
    jsonschema.Draft202012Validator(
        schemas["deployment.v1.schema.json"], format_checker=format_checker
    ).validate(plan["spec"])
    registry = Registry().with_resource(
        schemas["deployment.v1.schema.json"]["$id"],
        Resource.from_contents(schemas["deployment.v1.schema.json"]),
    )
    jsonschema.Draft202012Validator(
        schemas["deployment-plan.v1.schema.json"],
        registry=registry,
        format_checker=format_checker,
    ).validate(plan)
    jsonschema.Draft202012Validator(
        schemas["deployment-inspection.v1.schema.json"],
        format_checker=format_checker,
    ).validate(inspection)
    state = service.store.load_state("deployment-python-http")
    jsonschema.Draft202012Validator(
        schemas["deployment-state.v1.schema.json"],
        format_checker=format_checker,
    ).validate(state)
    receipt = json.loads(next((tmp_path / "state" / "records" / "deployment-python-http" / "receipts").glob("*.json")).read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(
        schemas["deployment-receipt.v1.schema.json"],
        format_checker=format_checker,
    ).validate(receipt)
    _reference, evidence = service.store.prepare_evidence(
        "deployment-python-http",
        kind="schema_fixture",
        value={"publicSafe": True},
    )
    jsonschema.Draft202012Validator(
        schemas["deployment-evidence.v1.schema.json"],
        format_checker=format_checker,
    ).validate(evidence)


@pytest.mark.parametrize(
    "mutation",
    (
        "runtime_secret_sentinel",
        "health_secret_sentinel",
        "secret_environment_key",
        "secret_environment_value",
        "relative_repository_root",
        "uppercase_port_id",
        "uppercase_secret_id",
    ),
)
def test_deployment_schema_and_runtime_reject_the_same_structural_boundaries(
    tmp_path: Path, mutation: str
) -> None:
    _service, _adapter, _project, plan = planned_service(tmp_path)
    candidate = deepcopy(plan["spec"])
    service = candidate["services"][0]
    if mutation == "runtime_secret_sentinel":
        service["runtime"]["command"].append("STATEPORT_TEST_SECRET_fixture")
    elif mutation == "health_secret_sentinel":
        service["health"]["command"].append("STATEPORT_TEST_SECRET_fixture")
    elif mutation == "secret_environment_key":
        service["environment"]["API_TOKEN"] = "identifier-only"
    elif mutation == "secret_environment_value":
        service["environment"]["SAFE_VALUE"] = "STATEPORT_TEST_SECRET_fixture"
    elif mutation == "relative_repository_root":
        candidate["source"]["repositoryRoot"] = "relative/source"
    elif mutation == "uppercase_port_id":
        service["ports"][0]["name"] = "HTTP"
        service["health"]["portName"] = "HTTP"
    elif mutation == "uppercase_secret_id":
        service["secrets"].append(
            {
                "id": "API-Token",
                "binding": "secret-broker://fixture/api-token",
            }
        )
    else:  # pragma: no cover - parameter list owns this boundary
        raise AssertionError(mutation)

    with pytest.raises(DeploymentRefusal):
        validate_deployment_spec(candidate)
    schema = json.loads(
        (ROOT / "schemas" / "deployment.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    errors = list(
        jsonschema.Draft202012Validator(
            schema, format_checker=_format_checker()
        ).iter_errors(candidate)
    )
    assert errors, f"JSON Schema accepted runtime-refused structure: {mutation}"


def test_canonical_mixed_case_grant_identity_has_schema_runtime_parity(
    tmp_path: Path,
) -> None:
    _service, _adapter, _project, plan = planned_service(tmp_path)
    schema = json.loads(
        (ROOT / "schemas" / "deployment.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    validator = jsonschema.Draft202012Validator(schema)
    accepted = deepcopy(plan["spec"])
    accepted["authority"]["grantId"] = "grant_MixedCase_123"
    validate_deployment_spec(accepted)
    validator.validate(accepted)

    refused = deepcopy(accepted)
    refused["authority"]["grantId"] = "not-a-grant"
    with pytest.raises(DeploymentRefusal):
        validate_deployment_spec(refused)
    assert list(validator.iter_errors(refused))


@pytest.mark.parametrize("mutation", ("unknown_health_port", "unknown_network"))
def test_relational_references_are_schema_valid_but_runtime_refused(
    tmp_path: Path, mutation: str
) -> None:
    _service, _adapter, _project, plan = planned_service(tmp_path)
    candidate = deepcopy(plan["spec"])
    service = candidate["services"][0]
    if mutation == "unknown_health_port":
        service["health"]["portName"] = "missing"
    elif mutation == "unknown_network":
        service["networks"] = ["missing"]
    else:  # pragma: no cover - parameter list owns this boundary
        raise AssertionError(mutation)
    schema = json.loads(
        (ROOT / "schemas" / "deployment.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.Draft202012Validator(schema).validate(candidate)
    with pytest.raises(DeploymentRefusal):
        validate_deployment_spec(candidate)


def test_inspection_schema_requires_one_uniform_review_projection(
    tmp_path: Path,
) -> None:
    schema = json.loads(
        (ROOT / "schemas" / "deployment-inspection.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    validator = jsonschema.Draft202012Validator(schema)
    inspections: list[dict[str, Any]] = []
    for fixture in (
        "python-http",
        "node-http",
        "static-web",
        "persistent-multi",
        "compose-http",
        "containerfile-http",
        "dockerfile-http",
    ):
        project = committed_fixture(tmp_path, fixture)
        inspection = inspect_project(project)
        validator.validate(inspection)
        assert inspection["candidateServices"]
        inspections.append(inspection)

    base = inspections[0]
    candidate = base["candidateServices"][0]
    malformed = (
        {},
        {**candidate, "unknown": True},
        {key: value for key, value in candidate.items() if key != "health"},
        {**candidate, "command": "python3 app.py"},
    )
    for service in malformed:
        document = deepcopy(base)
        document["candidateServices"] = [service]
        assert list(validator.iter_errors(document))

    invalid_declared = committed_project(
        tmp_path,
        "invalid-declared-python",
        {
            "app.py": "print('public-safe')\n",
            "pyproject.toml": "[project]\nname='fixture'\nversion='0.1.0'\n",
            "stateport.deployment.json": json.dumps(
                {"schema": "stateport.deployment/v1", "metadata": {}}
            ),
        },
    )
    invalid_inspection = inspect_project(invalid_declared)
    assert invalid_inspection["candidateServices"] == []
    assert invalid_inspection["deterministicAssistedPlanningSupported"] is False
    validator.validate(invalid_inspection)


@pytest.mark.parametrize(
    "invalid_timestamp",
    (
        "2026-02-30T00:00:00Z",
        "2026-07-30T00:00:00+00:00",
        "2026-07-30T00:00:00.123Z",
    ),
)
def test_canonical_timestamps_fail_closed_in_schema_and_runtime_documents(
    tmp_path: Path, invalid_timestamp: str
) -> None:
    service, _adapter, _project, plan = planned_service(tmp_path)
    deployment_id = plan["spec"]["metadata"]["deploymentId"]
    checker = _format_checker()
    deployment_schema = json.loads(
        (ROOT / "schemas" / "deployment.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    plan_schema = json.loads(
        (ROOT / "schemas" / "deployment-plan.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    registry = Registry().with_resource(
        deployment_schema["$id"], Resource.from_contents(deployment_schema)
    )
    malformed_plan = deepcopy(plan)
    malformed_plan["createdAt"] = invalid_timestamp
    malformed_plan["planDigest"] = plan_digest(malformed_plan)
    with pytest.raises(DeploymentRefusal):
        validate_plan(malformed_plan, now=None)
    assert list(
        jsonschema.Draft202012Validator(
            plan_schema, registry=registry, format_checker=checker
        ).iter_errors(malformed_plan)
    )

    state = service.store.load_state(deployment_id)
    state["transitionHistory"][0]["at"] = invalid_timestamp
    state = DeploymentStore._seal_state(state)
    with pytest.raises(DeploymentRefusal):
        service.store._validate_state(
            state, deployment_id, validate_documents=False
        )
    state_schema = json.loads(
        (ROOT / "schemas" / "deployment-state.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    assert list(
        jsonschema.Draft202012Validator(
            state_schema, format_checker=checker
        ).iter_errors(state)
    )

    receipt_path = next(
        (tmp_path / "state" / "records" / deployment_id / "receipts").glob(
            "*.json"
        )
    )
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["createdAt"] = invalid_timestamp
    receipt["receiptDigest"] = digest_value(
        {key: value for key, value in receipt.items() if key != "receiptDigest"}
    )
    with pytest.raises(DeploymentRefusal):
        service.store._validate_receipt(receipt, deployment_id)
    receipt_schema = json.loads(
        (ROOT / "schemas" / "deployment-receipt.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    assert list(
        jsonschema.Draft202012Validator(
            receipt_schema, format_checker=checker
        ).iter_errors(receipt)
    )

    decision, _reservation = reserve_for(
        service,
        "apply_deployment",
        deployment_id,
        run_id=plan["planDigest"],
    )
    authority_reference = service._verify_authority(
        decision,
        action="apply_deployment",
        deployment_id=deployment_id,
        run_id=plan["planDigest"],
    )
    applying, _receipts, _operation_id = service.store.approve_and_reserve(
        deployment_id,
        plan,
        actor=service.actor,
        authority_reference=authority_reference,
    )
    applying["currentTransition"]["startedAt"] = invalid_timestamp
    applying = DeploymentStore._seal_state(applying)
    with pytest.raises(DeploymentRefusal):
        service.store._validate_state(
            applying, deployment_id, validate_documents=False
        )
    assert list(
        jsonschema.Draft202012Validator(
            state_schema, format_checker=checker
        ).iter_errors(applying)
    )


@pytest.mark.parametrize(
    "mutation",
    (
        "uppercase_deployment_id",
        "public_host_address",
        "unsafe_storage_path",
        "root_runtime",
        "mutable_image",
        "missing_source_identity",
        "missing_grant_identity",
        "apply_with_predecessor",
        "traversing_build_context",
    ),
)
def test_plan_schema_fails_closed_with_runtime_contract(
    tmp_path: Path, mutation: str
) -> None:
    _service, _adapter, _project, original = planned_service(
        tmp_path, "persistent-multi"
    )
    plan = deepcopy(original)
    service = plan["spec"]["services"][0]
    if mutation == "uppercase_deployment_id":
        plan["spec"]["metadata"]["deploymentId"] = "Uppercase"
    elif mutation == "public_host_address":
        next(
            item for item in plan["spec"]["services"] if item["ports"]
        )["ports"][0]["hostAddress"] = "0.0.0.0"
    elif mutation == "unsafe_storage_path":
        next(
            item for item in plan["spec"]["services"] if item["storage"]
        )["storage"][0]["mountPath"] = "/etc/stateport"
    elif mutation == "root_runtime":
        service["runtime"]["user"]["uid"] = 0
    elif mutation == "mutable_image":
        service["build"]["mode"] = "image"
        service["image"]["reference"] = "example.invalid/app:latest"
    elif mutation == "missing_source_identity":
        plan["spec"]["source"]["treeDigest"] = None
    elif mutation == "missing_grant_identity":
        plan["spec"]["authority"]["grantId"] = None
    elif mutation == "apply_with_predecessor":
        plan["predecessorRevision"] = DIGEST
    elif mutation == "traversing_build_context":
        service["build"]["context"] = "../private"
    else:  # pragma: no cover - parameter list owns this boundary
        raise AssertionError(mutation)
    plan["planDigest"] = plan_digest(plan)

    with pytest.raises(DeploymentRefusal):
        validate_plan(plan, now=None)

    deployment_schema = json.loads(
        (ROOT / "schemas" / "deployment.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    plan_schema = json.loads(
        (ROOT / "schemas" / "deployment-plan.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    registry = Registry().with_resource(
        deployment_schema["$id"], Resource.from_contents(deployment_schema)
    )
    errors = list(
        jsonschema.Draft202012Validator(
            plan_schema,
            registry=registry,
            format_checker=_format_checker(),
        ).iter_errors(plan)
    )
    assert errors, f"JSON Schema accepted runtime-invalid case: {mutation}"
