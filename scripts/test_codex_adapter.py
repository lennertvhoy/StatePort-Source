from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys
import threading
import time

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "execution-host" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "external-engine-runtime" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "codex-adapter" / "src"))

from codex_adapter import CodexAdapter, CodexProbe  # noqa: E402
from execution_host.contracts import AgentRunSpec, CapabilityRequest  # noqa: E402


def make_spec() -> AgentRunSpec:
    return AgentRunSpec(
        "run:codex-test", "instance:codex-test", "revision:test", "bounded staging task",
        "statepack:test", "sha256:" + "a" * 64, (CapabilityRequest("nonInteractiveExecution"),),
        ("cancellation",), "codex", "codex-cli", "0.144.4", "gpt-5.6-luna",
        "operator_authenticated_unverified", ("read_staging", "write_staging"), "workspace-write",
        {"token": 100, "costMinor": 0, "timeSeconds": 5, "steps": 2},
        ("python3 -c pass",), ("artifacts/result.json",), {"host": "codex-test"},
        approval_required_level="local_operator",
    )


def test_unavailable_codex_fails_closed_without_auth_inspection(tmp_path: Path) -> None:
    adapter = CodexAdapter(CodexProbe(None, "unavailable", False, False, False, "not installed"))
    capabilities = adapter.capabilities()
    assert capabilities.production_eligible is False
    assert capabilities.capabilities["nonInteractiveExecution"] == "unsupported"
    with pytest.raises(RuntimeError, match="unavailable"):
        adapter.prepare_command(make_spec(), tmp_path)


def test_codex_command_is_ephemeral_json_staging_bound_and_contains_objective(
    tmp_path: Path,
) -> None:
    adapter = CodexAdapter(CodexProbe("/usr/bin/codex", "0.144.4", True, True, True, "fixture"))
    command = adapter.prepare_command(make_spec(), tmp_path)
    assert command[:5] == ("/usr/bin/codex", "--ask-for-approval", "never", "exec", "--json")
    assert "--ephemeral" in command and "--sandbox" in command and "workspace-write" in command
    assert "--skip-git-repo-check" in command
    assert tmp_path.as_posix() in command
    assert "canonical" in command[-1].lower()
    assert "bounded staging task" in command[-1]


def test_codex_objective_is_bounded_before_process_start(tmp_path: Path) -> None:
    adapter = CodexAdapter(CodexProbe("/usr/bin/codex", "0.144.4", True, True, True, "fixture"))
    oversized = replace(make_spec(), objective="x" * (32 * 1024 + 1))
    with pytest.raises(ValueError, match="32KiB"):
        adapter.prepare_command(oversized, tmp_path)


def test_installed_probe_marks_telemetry_unavailable_and_auth_unverified(tmp_path: Path) -> None:
    adapter = CodexAdapter(CodexProbe("/usr/bin/codex", "0.144.4", True, True, True, "fixture"))
    capabilities = adapter.capabilities()
    assert capabilities.authentication_route_classes == ("operator_authenticated_unverified",)
    assert capabilities.capabilities["tokenTelemetry"] == "unavailable"
    assert capabilities.capabilities["costTelemetry"] == "unavailable"


def test_codex_execution_is_cancellable_and_cannot_mutate_canonical_state(tmp_path: Path) -> None:
    canonical = tmp_path / "canonical"
    staging = tmp_path / "staging"
    canonical.mkdir()
    staging.mkdir()
    canonical_marker = canonical / "state.txt"
    canonical_marker.write_text("canonical\n", encoding="utf-8")
    fake_codex = tmp_path / "fake-codex"
    fake_codex.write_text(
        "#!/usr/bin/env python3\n"
        "from pathlib import Path\n"
        "import json, time\n"
        "Path('staging-only.txt').write_text('bounded\\n', encoding='utf-8')\n"
        "print(json.dumps({'type': 'turn.started'}), flush=True)\n"
        "time.sleep(30)\n",
        encoding="utf-8",
    )
    fake_codex.chmod(0o700)
    adapter = CodexAdapter(CodexProbe(str(fake_codex), "fixture", True, True, True, "fixture"))
    cancel = threading.Event()

    def request_cancel() -> None:
        deadline = time.monotonic() + 2
        while not (staging / "staging-only.txt").exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        cancel.set()

    thread = threading.Thread(target=request_cancel)
    thread.start()
    result = adapter.execute(make_spec(), staging, cancel_event=cancel)
    thread.join(timeout=2)

    assert result.cancelled and not result.ok
    assert result.cleanup in {"terminated", "killed", "already_exited"}
    assert (staging / "staging-only.txt").read_text(encoding="utf-8") == "bounded\n"
    assert canonical_marker.read_text(encoding="utf-8") == "canonical\n"


def test_codex_execution_exposes_durable_process_supervision_identity(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    fake_codex = tmp_path / "fake-codex"
    fake_codex.write_text(
        "#!/usr/bin/env python3\n"
        "import json\n"
        "print(json.dumps({'type': 'item.completed', 'item': {'type': 'agent_message', 'text': 'ok'}}))\n",
        encoding="utf-8",
    )
    fake_codex.chmod(0o700)
    adapter = CodexAdapter(CodexProbe(str(fake_codex), "fixture", True, True, True, "fixture"))
    started = []
    finished = []
    generation = "generation." + "b" * 64

    result = adapter.execute(
        make_spec(),
        staging,
        on_started=started.append,
        on_finished=finished.append,
        process_generation=generation,
    )

    assert result.ok
    assert len(started) == len(finished) == 1
    assert started[0] == finished[0]
    assert started[0].process_generation == generation
