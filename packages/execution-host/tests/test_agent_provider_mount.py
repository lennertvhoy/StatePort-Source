"""Sealed read-only agent provider directory: contract, engine, workspace seam.

These are pure argv/contract tests: no container runtime is invoked.  The
mount is reachable only for the exact ``agentProviderProfile`` marker on a
``workspace`` workload with ``networkMode == "developer"``, always binds the
fixed daemon-owned directory at ``/stateport-provider`` read-only, and every
other shape fails closed.
"""
from __future__ import annotations

import os
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "packages/execution-host/src"))
sys.path.insert(0, str(ROOT / "packages/runtime-contracts/src"))

from execution_host import daemon_contract as contract  # noqa: E402
from execution_host.engine import (  # noqa: E402
    AGENT_PROVIDER_CONTAINER_PATH,
    EngineError,
    PodmanCliEngine,
    agent_provider_mount_argument,
    assert_agent_provider_argv_hardened,
    assert_create_argv_hardened,
    build_create_argv,
)
from execution_host.workspaces import (  # noqa: E402
    WorkspaceRuntimeError,
    sealed_workspace_workload,
)

MARKER = contract.AGENT_PROVIDER_PROFILE
IMAGE = "example.test/workspace@sha256:" + "a" * 64
DIGEST = "sha256:" + "b" * 64


def workspace_workload(
    workload_id: str = "ws-provider",
    *,
    network: str = "developer",
    profile: str | None = None,
    **parameter_changes: object,
) -> dict:
    parameters: dict = {
        "workspaceId": workload_id,
        "workspaceSpecDigest": DIGEST,
        "volumeName": f"stateport-workspace-{workload_id}",
        "networkMode": network,
        "cacheVolumes": [],
        "cpuQuotaPercent": 100,
        "diskMaxBytes": 268435456,
        "workSeconds": 0,
        "emitBytes": 0,
    }
    if profile is not None:
        parameters["agentProviderProfile"] = profile
    parameters.update(parameter_changes)
    return {
        "kind": "workspace",
        "workloadId": workload_id,
        "image": {"reference": IMAGE},
        "parameters": parameters,
        "timeoutSeconds": 600,
        "outputByteBound": 65536,
        "resources": {"memoryMaxBytes": 268435456, "pidsMax": 128},
    }


def provider_directory(tmp_path: Path) -> Path:
    directory = tmp_path / "provider"
    directory.mkdir(mode=0o700)
    return directory


# ------------------------------------------------------------------ contract


def test_profile_is_sealed_string_and_binds_the_digest_deterministically() -> None:
    assert MARKER == "opencode-provider-v1"
    first = contract.validate_workload_spec(workspace_workload(profile=MARKER))
    second = contract.validate_workload_spec(workspace_workload(profile=MARKER))
    assert first["parameters"]["agentProviderProfile"] == MARKER
    assert contract.canonical_digest(first) == contract.canonical_digest(second)
    without = contract.validate_workload_spec(workspace_workload())
    assert "agentProviderProfile" not in without["parameters"]
    assert contract.canonical_digest(first) != contract.canonical_digest(without)


def test_profile_is_refused_without_the_developer_network_mode() -> None:
    with pytest.raises(ValueError, match="developer network mode"):
        contract.validate_workload_spec(workspace_workload(network="none", profile=MARKER))


def test_unknown_profile_value_is_refused() -> None:
    with pytest.raises(ValueError, match="sealed agent provider profile"):
        contract.validate_workload_spec(workspace_workload(profile="some-other-provider"))
    with pytest.raises(EngineError, match="sealed value"):
        agent_provider_mount_argument(
            {"agentProviderProfile": "some-other-provider", "networkMode": "developer"}, "/tmp"
        )


@pytest.mark.parametrize("kind", ["agent-run", "capsule-service", "browser-journey", "terminal"])
def test_profile_is_refused_for_every_other_workload_kind(kind: str) -> None:
    value = workspace_workload(profile=MARKER)
    value["kind"] = kind
    with pytest.raises(ValueError):
        contract.validate_workload_spec(value)


def test_client_supplied_provider_path_and_extra_field_are_not_representable() -> None:
    # The marker may carry only the fixed string, never a path.
    with pytest.raises(ValueError):
        contract.validate_workload_spec(workspace_workload(profile="/etc/stateport-provider"))
    # No additional client field may name a host directory.
    with pytest.raises(ValueError):
        contract.validate_workload_spec(
            workspace_workload(profile=MARKER, providerDirectory="/etc")
        )
    with pytest.raises(ValueError):
        contract.validate_workload_spec(
            workspace_workload(profile=MARKER, providerDirectoryDigest=DIGEST)
        )


# -------------------------------------------------------------------- engine


def test_marker_developer_mounts_exactly_the_fixed_path_read_only(tmp_path: Path) -> None:
    directory = provider_directory(tmp_path)
    spec = contract.validate_workload_spec(workspace_workload(profile=MARKER))
    argv = build_create_argv(spec, provider_directory=str(directory))
    assert AGENT_PROVIDER_CONTAINER_PATH == "/stateport-provider"
    assert argv.count("--mount") == 1
    expected = (
        f"type=bind,src={directory},dst=/stateport-provider,readonly,relabel=private"
    )
    assert argv[argv.index("--mount") + 1] == expected
    # Developer mode keeps the existing no-flag network path; the workspace
    # volume is retained and no other mount exists.
    assert "--network" not in argv
    assert "--volume" in argv
    assert argv.count("--volume") == 1
    assert_agent_provider_argv_hardened(argv, provider_directory=str(directory))


def test_marker_without_configured_directory_refuses(tmp_path: Path) -> None:
    spec = contract.validate_workload_spec(workspace_workload(profile=MARKER))
    with pytest.raises(EngineError, match="not configured"):
        build_create_argv(spec)
    with pytest.raises(EngineError, match="unavailable"):
        build_create_argv(spec, provider_directory=str(tmp_path / "absent"))


def test_marker_requires_developer_mode_at_engine_seam(tmp_path: Path) -> None:
    directory = provider_directory(tmp_path)
    with pytest.raises(EngineError, match="developer network mode"):
        agent_provider_mount_argument(
            {"agentProviderProfile": MARKER, "networkMode": "none"}, str(directory)
        )


def test_symlinked_directory_and_symlinked_parent_refuse(tmp_path: Path) -> None:
    spec = contract.validate_workload_spec(workspace_workload(profile=MARKER))
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(EngineError, match="symlink"):
        build_create_argv(spec, provider_directory=str(link))
    nested = link / "child"
    nested.mkdir()
    with pytest.raises(EngineError, match="symlink"):
        build_create_argv(spec, provider_directory=str(nested))


def test_foreign_owned_directory_refuses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    directory = provider_directory(tmp_path)
    spec = contract.validate_workload_spec(workspace_workload(profile=MARKER))
    monkeypatch.setattr(os, "geteuid", lambda: 123456)
    monkeypatch.setattr(os, "getegid", lambda: 123456)
    with pytest.raises(EngineError, match="owned by the execution user"):
        build_create_argv(spec, provider_directory=str(directory))


def test_unsafe_directory_paths_refuse(tmp_path: Path) -> None:
    spec = contract.validate_workload_spec(workspace_workload(profile=MARKER))
    for unsafe in ["relative/provider", "/", "/tmp/../etc", "/tmp/provider,ro=false", "/tmp\\provider"]:
        with pytest.raises(EngineError):
            build_create_argv(spec, provider_directory=unsafe)
    file_path = tmp_path / "provider-file"
    file_path.write_text("not a directory")
    with pytest.raises(EngineError, match="not a real directory"):
        build_create_argv(spec, provider_directory=str(file_path))


def test_provider_argv_hardening_refuses_tampering(tmp_path: Path) -> None:
    directory = provider_directory(tmp_path)
    spec = contract.validate_workload_spec(workspace_workload(profile=MARKER))
    expected = (
        f"type=bind,src={directory},dst=/stateport-provider,readonly,relabel=private"
    )

    def hardened() -> list[str]:
        return build_create_argv(spec, provider_directory=str(directory))

    tampered = hardened()
    tampered[tampered.index("--mount") + 1] = tampered[tampered.index("--mount") + 1].replace(
        "readonly", "rw"
    )
    with pytest.raises(EngineError, match="sealed read-only provider mount"):
        assert_agent_provider_argv_hardened(tampered, provider_directory=str(directory))

    tampered = hardened()
    tampered[tampered.index("--mount") + 1] = expected.replace(
        "/stateport-provider", "/stateport-provider-other"
    )
    with pytest.raises(EngineError, match="sealed read-only provider mount"):
        assert_agent_provider_argv_hardened(tampered, provider_directory=str(directory))

    tampered = hardened()
    tampered[tampered.index("--mount") + 1] = expected.replace(
        f"src={directory}", "src=/somewhere/else"
    )
    with pytest.raises(EngineError, match="sealed read-only provider mount"):
        assert_agent_provider_argv_hardened(tampered, provider_directory=str(directory))

    tampered = hardened()
    position = tampered.index("--mount")
    tampered[position:position] = ["--mount", expected]
    with pytest.raises(EngineError, match="sealed read-only provider mount"):
        assert_agent_provider_argv_hardened(tampered, provider_directory=str(directory))

    tampered = hardened()
    index = tampered.index("--volume")
    del tampered[index:index + 2]
    with pytest.raises(EngineError, match="workspace volume"):
        assert_agent_provider_argv_hardened(tampered, provider_directory=str(directory))

    tampered = hardened()
    tampered.insert(1, "--network")
    tampered.insert(2, "none")
    with pytest.raises(EngineError, match="developer network profile"):
        assert_agent_provider_argv_hardened(tampered, provider_directory=str(directory))


def test_generic_hardening_still_forbids_the_provider_mount(tmp_path: Path) -> None:
    directory = provider_directory(tmp_path)
    spec = contract.validate_workload_spec(workspace_workload(profile=MARKER))
    argv = build_create_argv(spec, provider_directory=str(directory))
    # No other engine path can accept a provider mount: the generic workspace
    # hardening refuses any --mount outright.
    with pytest.raises(EngineError):
        assert_create_argv_hardened(argv)


def test_default_and_developer_workspaces_are_unchanged_without_the_marker() -> None:
    none_spec = contract.validate_workload_spec(workspace_workload(network="none"))
    none_argv = build_create_argv(none_spec)
    assert "--mount" not in none_argv
    assert none_argv[none_argv.index("--network") + 1] == "none"
    developer_spec = contract.validate_workload_spec(workspace_workload(network="developer"))
    developer_argv = build_create_argv(developer_spec)
    assert "--mount" not in developer_argv
    assert "--network" not in developer_argv


def test_seeded_developer_workspace_with_marker_keeps_the_provider_mount(tmp_path: Path) -> None:
    directory = provider_directory(tmp_path)
    spec = workspace_workload(profile=MARKER)
    spec["image"] = {"reference": contract.DEVELOPMENT_SEED_IMAGE}
    spec["parameters"]["sourceSeed"] = {"helperPolicy": contract.DEVELOPMENT_SEED_POLICY}
    argv = build_create_argv(spec, provider_directory=str(directory))
    assert argv.count("--mount") == 1
    assert argv[argv.index("--mount") + 1] == (
        f"type=bind,src={directory},dst=/stateport-provider,readonly,relabel=private"
    )
    assert "--user" in argv and "--userns" in argv
    assert_agent_provider_argv_hardened(
        argv, provider_directory=str(directory), seed_namespace=True
    )


# ------------------------------------------------------- create-time engine


def test_engine_create_time_validation_refuses_before_any_effect(tmp_path: Path) -> None:
    spec = contract.validate_workload_spec(workspace_workload(profile=MARKER))
    engine = PodmanCliEngine(provider_directory=str(tmp_path / "absent"))
    with pytest.raises(EngineError, match="unavailable"):
        engine.validate_agent_provider_capability(spec)
    calls: list[object] = []
    engine = PodmanCliEngine(
        provider_directory=str(tmp_path / "absent"),
        runner=lambda *args, **kwargs: calls.append(args),
    )
    with pytest.raises(EngineError, match="unavailable"):
        engine.create(spec)
    # Refusal happens before the volume or container create reaches the engine.
    assert calls == []


def test_engine_accepts_the_validated_directory(tmp_path: Path) -> None:
    directory = provider_directory(tmp_path)
    spec = contract.validate_workload_spec(workspace_workload(profile=MARKER))
    engine = PodmanCliEngine(provider_directory=str(directory))
    engine.validate_agent_provider_capability(spec)  # no raise
    # A non-marked workspace is a no-op for this capability.
    engine.validate_agent_provider_capability(
        contract.validate_workload_spec(workspace_workload(network="none"))
    )


# ------------------------------------------------------------ workspace seam


def workspace_declaration(mode: str = "developer") -> dict:
    return {
        "formatVersion": "stateport.workspace-spec/v1",
        "workspaceId": "ws-seam",
        "imageDigest": "sha256:" + "d" * 64,
        "workspacePath": "/workspace",
        "shell": ["/bin/sh"],
        "resources": {
            "memoryMaxBytes": 268435456,
            "cpuQuotaPercent": 100,
            "pidsMax": 128,
            "diskMaxBytes": 268435456,
        },
        "networkProfile": {"mode": mode, "allowlist": []},
        "cacheVolumes": [],
        "lifecyclePolicy": {
            "idleTimeoutSeconds": 3600,
            "stopAfterIdle": True,
            "preserveDataOnRemove": True,
        },
    }


def test_workspace_seam_default_is_unchanged_and_profile_is_gated() -> None:
    declaration = workspace_declaration()
    image = "example.test/workspace@sha256:" + "d" * 64
    default = sealed_workspace_workload(declaration, image_reference=image)
    assert "agentProviderProfile" not in default["parameters"]
    selected = sealed_workspace_workload(
        declaration, image_reference=image, agent_provider_profile=MARKER
    )
    assert selected["parameters"]["agentProviderProfile"] == MARKER
    assert selected["parameters"]["networkMode"] == "developer"
    assert contract.canonical_digest(selected) != contract.canonical_digest(default)
    with pytest.raises(WorkspaceRuntimeError, match="developer network"):
        sealed_workspace_workload(
            workspace_declaration("disabled"),
            image_reference=image,
            agent_provider_profile=MARKER,
        )
    with pytest.raises(WorkspaceRuntimeError, match="sealed value"):
        sealed_workspace_workload(
            declaration, image_reference=image, agent_provider_profile="other"
        )
