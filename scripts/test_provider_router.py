#!/usr/bin/env python3
"""Focused tests for the first durable Codex provider authority."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "execution-host" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "external-engine-runtime" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "codex-adapter" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "opencode-adapter" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "persistent-app" / "src"))

from execution_host.contracts import BackendCapabilities  # noqa: E402
from external_engine_runtime import ProcessIdentity, ProcessResult  # noqa: E402
from stateport_persistent_app.provider_credentials import (  # noqa: E402
    PROVIDER_CREDENTIAL_ENV,
    ProviderCredentialStore,
)
from stateport_persistent_app.provider_router import (  # noqa: E402
    ProviderRouter,
    ProviderRouterError,
)


CAPS = (
    "structuredEvents", "nonInteractiveExecution", "cancellation", "sessionResume",
    "repositoryInstructions", "customTools", "mcpEquivalent", "approvalIntegration",
    "sandboxSupport", "changedFileReporting", "tokenTelemetry", "costTelemetry",
)


class FakeProbe:
    installed = True


class FakeAdapter:
    def __init__(self, stdout: str, *, returncode: int = 0) -> None:
        self.probe = FakeProbe()
        self.stdout = stdout
        self.returncode = returncode
        self.spec = None
        self.generation = None
        self.environment = None

    def capabilities(self) -> BackendCapabilities:
        values = {name: "unsupported" for name in CAPS}
        values.update(
            structuredEvents="supported",
            nonInteractiveExecution="supported",
            cancellation="supported",
            repositoryInstructions="supported",
            sandboxSupport="environment-gated",
            changedFileReporting="supported",
            tokenTelemetry="unavailable",
            costTelemetry="unavailable",
        )
        return BackendCapabilities(
            "codex", "codex-cli", "fixture", "managed", values,
            ("operator_authenticated_unverified",),
            ("read_staging", "write_staging"),
            production_eligible=False,
        )

    def execute(
        self,
        spec,
        staging_root,
        *,
        cancel_event=None,
        on_started=None,
        on_finished=None,
        process_generation=None,
        environment=None,
    ) -> ProcessResult:
        del cancel_event, staging_root
        self.spec = spec
        self.generation = process_generation
        self.environment = environment
        identity = ProcessIdentity(123, 123, "1", process_generation)
        if on_started:
            on_started(identity)
        if on_finished:
            on_finished(identity)
        return ProcessResult(
            ("codex",), self.returncode, self.stdout, "", False, False,
            False, 12, "not_required",
        )


def profile(path: Path) -> None:
    ProviderRouter.configure_codex(path, model_identifier="gpt-5.6-codex")


def opencode_profile(path: Path) -> None:
    ProviderRouter.configure(path, provider_id="opencode", model_identifier="opencode/deepseek-v4-flash-free")


class FakeOpenCodeProbe:
    def __init__(self, installed: bool = True) -> None:
        self.installed = installed


class FakeOpenCodeAdapter:
    """Stand-in for the managed OpenCode adapter using the shared contract."""

    def __init__(self, stdout: str, *, returncode: int = 0, installed: bool = True) -> None:
        self.probe = FakeOpenCodeProbe(installed)
        self.stdout = stdout
        self.returncode = returncode
        self.spec = None
        self.generation = None
        self.environment = None

    def capabilities(self) -> BackendCapabilities:
        values = {name: "unsupported" for name in CAPS}
        values.update(
            structuredEvents="supported",
            nonInteractiveExecution="supported",
            cancellation="supported",
            repositoryInstructions="supported",
            sandboxSupport="supported",
            changedFileReporting="supported",
            tokenTelemetry="unsupported",
            costTelemetry="unsupported",
        )
        return BackendCapabilities(
            "opencode", "opencode-cli", "1.18.31", "managed", values,
            ("operator_authenticated_unverified",),
            ("read_staging", "write_staging"),
            production_eligible=False,
        )

    def execute(
        self,
        spec,
        staging_root,
        *,
        cancel_event=None,
        on_started=None,
        on_finished=None,
        process_generation=None,
        environment=None,
    ) -> ProcessResult:
        del cancel_event, staging_root
        self.spec = spec
        self.generation = process_generation
        self.environment = environment
        identity = ProcessIdentity(456, 456, "1", process_generation)
        if on_started:
            on_started(identity)
        if on_finished:
            on_finished(identity)
        return ProcessResult(
            ("opencode",), self.returncode, self.stdout, "", False, False,
            False, 9, "not_required",
        )


def invoke(router: ProviderRouter, staging: Path, **callbacks):
    return router.invoke(
        work_id="assistant.abc",
        attempt_id="attempt.assistant.abc.1",
        attempt_ordinal=1,
        instance_id="instance.study",
        conversation_id="conv.study",
        message_id="msg.study",
        source_sequence=1,
        objective="Explain the learner's next step.",
        context_digest="sha256:" + "a" * 64,
        staging_root=staging,
        **callbacks,
    )


def test_profile_is_durable_digest_bound_and_contains_no_credentials() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "provider.json"
        written = ProviderRouter.configure_codex(
            path, model_identifier="gpt-5.6-codex", time_seconds=60, steps=4
        )
        reloaded = ProviderRouter(path, adapter=FakeAdapter(""))
        assert reloaded.runtime_profile["profileDigest"] == written["profileDigest"]
        persisted = path.read_text(encoding="utf-8")
        assert "apiKey" not in persisted and "credential" not in persisted
        assert path.stat().st_mode & 0o777 == 0o600


def test_profile_tampering_fails_closed() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "provider.json"
        profile(path)
        value = json.loads(path.read_text(encoding="utf-8"))
        value["model"]["id"] = "changed"
        path.write_text(json.dumps(value), encoding="utf-8")
        with pytest.raises(ProviderRouterError, match="digest"):
            ProviderRouter(path, adapter=FakeAdapter(""))


def test_router_invokes_only_injected_hardened_adapter_with_exact_identity() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        config = root / "provider.json"
        staging = root / "staging"
        staging.mkdir()
        profile(config)
        stdout = "\n".join(
            [
                json.dumps({"type": "turn.started"}),
                json.dumps(
                    {
                        "type": "item.completed",
                        "item": {"type": "agent_message", "text": "Grounded answer"},
                    }
                ),
                json.dumps(
                    {
                        "type": "turn.completed",
                        "usage": {"input_tokens": 10, "output_tokens": 4},
                    }
                ),
            ]
        )
        adapter = FakeAdapter(stdout)
        router = ProviderRouter(config, adapter=adapter)
        started = []
        finished = []

        result = invoke(router, staging, on_started=started.append, on_finished=finished.append)

        assert result.assistant_text == "Grounded answer"
        assert result.usage == {
            "availability": "exact",
            "inputTokens": 10,
            "outputTokens": 4,
        }
        assert adapter.spec.objective == "Explain the learner's next step."
        assert adapter.spec.instance_id == "instance.study"
        assert adapter.spec.statepack_digest == "sha256:" + "a" * 64
        assert adapter.generation.startswith("generation.")
        # Codex invocations carry no environment override; only managed OpenCode
        # invocations receive the operator credential and XDG locations.
        assert adapter.environment is None
        assert started == finished and len(started) == 1


def test_router_unwraps_only_exact_assistant_message_envelopes() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        config = root / "provider.json"
        staging = root / "staging"
        staging.mkdir()
        profile(config)
        for envelope_type in ("assistant_response", "assistant_message"):
            wrapped = json.dumps(
                {
                    "type": envelope_type,
                    "content": "A concise, user-facing answer.",
                }
            )
            result = invoke(
                ProviderRouter(
                    config,
                    adapter=FakeAdapter(
                        json.dumps(
                            {
                                "type": "item.completed",
                                "item": {"type": "agent_message", "text": wrapped},
                            }
                        )
                    ),
                ),
                staging,
            )
            assert result.assistant_text == "A concise, user-facing answer."

        non_envelope = json.dumps(
            {"type": "assistant_response", "content": "Keep me", "extra": True}
        )
        result = invoke(
            ProviderRouter(
                config,
                adapter=FakeAdapter(
                    json.dumps(
                        {
                            "type": "item.completed",
                            "item": {"type": "agent_message", "text": non_envelope},
                        }
                    )
                ),
            ),
            staging,
        )
        assert result.assistant_text == non_envelope


def test_router_rejects_malformed_or_message_free_provider_output() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        config = root / "provider.json"
        staging = root / "staging"
        staging.mkdir()
        profile(config)
        with pytest.raises(ProviderRouterError, match="JSONL"):
            invoke(ProviderRouter(config, adapter=FakeAdapter("not json")), staging)
        no_message = json.dumps({"type": "turn.completed"})
        with pytest.raises(ProviderRouterError, match="assistant message"):
            invoke(ProviderRouter(config, adapter=FakeAdapter(no_message)), staging)


def test_router_surfaces_process_failure_without_fabricating_assistant_text() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        config = root / "provider.json"
        staging = root / "staging"
        staging.mkdir()
        profile(config)
        router = ProviderRouter(config, adapter=FakeAdapter("", returncode=1))
        with pytest.raises(ProviderRouterError, match="provider_failed"):
            invoke(router, staging)


def test_opencode_selection_routes_to_the_lazy_opencode_adapter(monkeypatch) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        config = root / "provider.json"
        staging = root / "staging"
        staging.mkdir()
        opencode_profile(config)
        stdout = json.dumps(
            {
                "type": "text",
                "timestamp": 1,
                "sessionID": "ses.fixture",
                "part": {"type": "text", "text": "OpenCode grounded answer"},
            }
        )
        monkeypatch.setattr(
            "opencode_adapter.OpenCodeAdapter",
            lambda: FakeOpenCodeAdapter(stdout),
        )
        # No adapter injected: the router must resolve the persisted
        # OpenCode selection through the managed adapter import.
        result = invoke(ProviderRouter(config), staging)
        assert result.assistant_text == "OpenCode grounded answer"
        assert result.provider == {"id": "opencode-local"}
        assert result.adapter == {"id": "opencode-cli", "version": "1.18.31"}


def test_opencode_missing_executable_refuses_with_typed_code() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        config = root / "provider.json"
        staging = root / "staging"
        staging.mkdir()
        opencode_profile(config)
        router = ProviderRouter(config, adapter=FakeOpenCodeAdapter("", installed=False))
        with pytest.raises(ProviderRouterError, match="provider_executable_unavailable"):
            invoke(router, staging)


def test_opencode_authentication_error_event_maps_to_typed_refusal() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        config = root / "provider.json"
        staging = root / "staging"
        staging.mkdir()
        opencode_profile(config)
        stdout = json.dumps(
            {
                "type": "error",
                "timestamp": 1,
                "sessionID": "ses.fixture",
                "error": {"name": "ProviderAuthError", "data": {"providerID": "fixture"}},
            }
        )
        with pytest.raises(ProviderRouterError, match="provider_authentication_unverified"):
            invoke(ProviderRouter(config, adapter=FakeOpenCodeAdapter(stdout)), staging)


def test_opencode_non_authentication_error_is_not_mislabelled() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        config = root / "provider.json"
        staging = root / "staging"
        staging.mkdir()
        opencode_profile(config)
        stdout = json.dumps(
            {
                "type": "error",
                "timestamp": 1,
                "sessionID": "ses.fixture",
                "error": {"name": "UnknownError", "data": {"message": "unknown"}},
            }
        )
        with pytest.raises(ProviderRouterError, match="assistant message"):
            invoke(ProviderRouter(config, adapter=FakeOpenCodeAdapter(stdout)), staging)


def opencode_env_shim(directory: Path, record_path: Path) -> Path:
    """Materialize a fake `opencode` that records its real invocation environment.

    It answers the managed executable probe (``--version``, ``run --help``) and,
    for a real ``run`` invocation, writes every observed environment entry to
    ``record_path`` before emitting one normal assistant text event. It never
    prints the environment, so no value can reach the event stream.
    """
    directory.mkdir(parents=True, exist_ok=True)
    executable = directory / "opencode"
    executable.write_text(
        f'#!{sys.executable}\n'
        'import json, os, sys\n'
        f'record = {str(record_path)!r}\n'
        'if "--version" in sys.argv:\n'
        '    print("1.18.31")\n'
        'elif "run" in sys.argv and "--help" in sys.argv:\n'
        '    print("run --format json --model --auto")\n'
        'elif "run" in sys.argv:\n'
        '    with open(record, "w", encoding="utf-8") as handle:\n'
        '        for key in sorted(os.environ):\n'
        '            handle.write(key + "=" + os.environ[key] + "\\n")\n'
        '    print(json.dumps({"type": "text", "part": {"type": "text", "text": "shim answer"}}))\n'
        'else:\n'
        '    print("run --format json")\n'
    )
    executable.chmod(0o700)
    return executable


def recorded_environment(record_path: Path) -> dict[str, str]:
    return dict(
        line.split("=", 1)
        for line in record_path.read_text(encoding="utf-8").splitlines()
        if "=" in line
    )


def test_router_passes_credential_and_xdg_environment_to_opencode_adapter(tmp_path, monkeypatch):
    home = tmp_path / "provider-home"
    ProviderCredentialStore(home).store("xai", "xai-fake-key")
    monkeypatch.setenv("STATEPORT_OPENCODE_HOME", str(home))
    config = tmp_path / "provider.json"
    staging = tmp_path / "staging"
    staging.mkdir()
    opencode_profile(config)
    stdout = json.dumps({"type": "text", "part": {"type": "text", "text": "ok"}})
    adapter = FakeOpenCodeAdapter(stdout)
    invoke(ProviderRouter(config, adapter=adapter), staging)
    assert adapter.environment is not None
    assert adapter.environment["XAI_API_KEY"] == "xai-fake-key"
    assert adapter.environment["XDG_DATA_HOME"] == str(home / "data")
    assert adapter.environment["XDG_CONFIG_HOME"] == str(home / "config")
    # The existing filtered environment base is retained, nothing else is added.
    assert "HOME" in adapter.environment


def test_opencode_invocation_injects_key_and_xdg_through_the_real_adapter(tmp_path, monkeypatch):
    home = tmp_path / "provider-home"
    ProviderCredentialStore(home).store("groq", "gsk-fake-inject")
    record = tmp_path / "recorded-env.txt"
    opencode_env_shim(tmp_path / "bin", record)
    monkeypatch.setenv(
        "PATH", os.pathsep.join([str(tmp_path / "bin"), os.environ.get("PATH", "/usr/bin:/bin")])
    )
    monkeypatch.setenv("STATEPORT_OPENCODE_HOME", str(home))
    monkeypatch.setenv("SECRET_CANARY", "must-not-leak")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")
    monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/dbus")
    config = tmp_path / "provider.json"
    staging = tmp_path / "staging"
    staging.mkdir()
    opencode_profile(config)

    result = invoke(ProviderRouter(config), staging)

    assert result.assistant_text == "shim answer"
    recorded = recorded_environment(record)
    assert recorded["GROQ_API_KEY"] == "gsk-fake-inject"
    assert recorded["XDG_DATA_HOME"] == str(home / "data")
    assert recorded["XDG_CONFIG_HOME"] == str(home / "config")
    # No unrelated host environment leaks into the provider subprocess.
    for leaked in ("SECRET_CANARY", "SSH_AUTH_SOCK", "DBUS_SESSION_BUS_ADDRESS"):
        assert leaked not in recorded


def test_opencode_invocation_without_credential_omits_every_key_variable(tmp_path, monkeypatch):
    home = tmp_path / "provider-home"
    record = tmp_path / "recorded-env.txt"
    opencode_env_shim(tmp_path / "bin", record)
    monkeypatch.setenv(
        "PATH", os.pathsep.join([str(tmp_path / "bin"), os.environ.get("PATH", "/usr/bin:/bin")])
    )
    monkeypatch.setenv("STATEPORT_OPENCODE_HOME", str(home))
    config = tmp_path / "provider.json"
    staging = tmp_path / "staging"
    staging.mkdir()
    opencode_profile(config)

    # With no credential the invocation still runs (OpenCode reports its own
    # authentication result) and carries the operator-owned XDG locations only.
    result = invoke(ProviderRouter(config), staging)

    assert result.assistant_text == "shim answer"
    recorded = recorded_environment(record)
    assert recorded["XDG_DATA_HOME"] == str(home / "data")
    assert recorded["XDG_CONFIG_HOME"] == str(home / "config")
    for env_var in PROVIDER_CREDENTIAL_ENV.values():
        assert env_var not in recorded
