from __future__ import annotations

from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages/sandbox-runtime/src"))

from sandbox_runtime import SandboxBoundary, SandboxError, SandboxPolicy  # noqa: E402


def test_sandbox_policy_denies_canonical_mount_and_secret_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    input_root = tmp_path / "input"
    input_root.mkdir()
    staging_parent = tmp_path / "staging-parent"
    staging_parent.mkdir()
    policy = SandboxPolicy(staging_parent, read_only_inputs=(input_root,))
    bad_input = staging_parent / "canonical"
    bad_input.mkdir()
    with pytest.raises(SandboxError):
        SandboxBoundary(SandboxPolicy(staging_parent, read_only_inputs=(bad_input,)))

    boundary = SandboxBoundary(policy)
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-propagate")
    environment = boundary.environment()
    assert "OPENAI_API_KEY" not in environment
    assert "HOME" not in environment
    scoped = boundary.environment({"HOME": str(staging_parent / "home"), "TMPDIR": str(staging_parent / "tmp")})
    assert scoped["HOME"].startswith(str(staging_parent))
    controls = policy.to_dict()
    assert controls["canonicalStateMount"] is False
    assert controls["homeMount"] is False
    assert controls["privileged"] is False
    command = boundary.podman_command(("python3", "-c", "pass"), staging_parent / "canonical")
    assert "--network" in command and "none" in command
    assert "--cap-drop=ALL" in command and "--read-only" in command
    assert "--privileged" not in command and "/var/run/docker.sock" not in " ".join(command)


def test_staging_is_ephemeral_and_observation_is_truthful(tmp_path: Path) -> None:
    boundary = SandboxBoundary(SandboxPolicy(tmp_path))
    with boundary.staging() as path:
        assert path.is_dir()
        (path / "output.txt").write_text("fixture", encoding="utf-8")
    assert not path.exists()
    observation = SandboxBoundary.observe()
    assert observation.runtime == "rootless-podman"
    assert observation.available is observation.rootless
    assert observation.container_enforced is False
    assert observation.network_isolation == "unproven"

    staging_observation = SandboxBoundary.observe_staging_copy().to_dict()
    assert staging_observation["runtime"] == "host-process"
    assert staging_observation["executionBoundary"] == "staging_copy_only"
    assert staging_observation["containerEnforced"] is False
    assert staging_observation["networkIsolation"] == "unproven"
    assert staging_observation["canonicalAccessIsolation"] == "unproven"
