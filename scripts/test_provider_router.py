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
            "opencode", "opencode-cli", "1.19.3", "managed", values,
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


def _sandbox_run(stdout: str = "", *, stderr: str = "", returncode: int = 0,
                 timed_out: bool = False):
    """A SandboxRun with a scripted process result, for the router's own logic."""
    from stateport_persistent_app.agent_sandbox import SandboxResult, SandboxRun

    process = ProcessResult(
        ("opencode",), returncode, stdout, stderr, timed_out, False, False, 12, "not_required"
    )
    return SandboxRun(
        result=SandboxResult(
            status="completed", refusal=None, exit_code=returncode, duration_seconds=0.012,
            final_text="", events=0, tokens={}, egress=(), sandbox_digest="sha256:" + "0" * 64,
        ),
        process=process,
        events=(),
    )


class FakeSandbox:
    """Stand-in for the agent sandbox launcher: records the route, replays a result."""

    def __init__(self, run):
        self.run = run
        self.calls: list[dict] = []

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        return self.run

    @property
    def route(self):
        return self.calls[-1]["route"]


def _sandbox_with(monkeypatch, run, *, binary: str = "/fixture/opencode") -> FakeSandbox:
    sandbox = FakeSandbox(run)
    monkeypatch.setattr(
        "stateport_persistent_app.provider_router.run_harness_in_sandbox", sandbox
    )
    monkeypatch.setattr(
        "stateport_persistent_app.provider_router.resolve_harness_binary",
        lambda: Path(binary),
    )
    return sandbox


def test_opencode_selection_runs_in_the_agent_sandbox_with_no_tools(monkeypatch) -> None:
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
        sandbox = _sandbox_with(monkeypatch, _sandbox_run(stdout))
        # No adapter injected: the router must resolve the persisted
        # OpenCode selection through the managed adapter import, and the run
        # itself must happen in the agent sandbox.
        result = invoke(ProviderRouter(config), staging)
        assert result.assistant_text == "OpenCode grounded answer"
        assert result.provider == {"id": "opencode-local"}
        assert result.adapter == {"id": "opencode-cli", "version": "1.19.3"}
        route = sandbox.route
        # Chat never gets tools, and egress is limited to the provider.
        assert route.harness == "opencode"
        assert route.tools == "none"
        assert route.model == "opencode/deepseek-v4-flash-free"
        assert set(route.allow_hosts) == {"opencode.ai", "models.opencode.ai"}
        assert route.credential_file is None
        # The run happens on the caller's staging directory, as /work.
        assert sandbox.calls[0]["workdir"] == staging
        assert "Reply with" in sandbox.calls[0]["prompt"] or sandbox.calls[0]["prompt"]


def test_the_opencode_route_never_uses_the_plain_subprocess_path(monkeypatch) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        config = root / "provider.json"
        staging = root / "staging"
        staging.mkdir()
        opencode_profile(config)
        adapter = FakeOpenCodeAdapter("")
        adapter.execute = lambda *args, **kwargs: pytest.fail(  # type: ignore[method-assign]
            "the managed OpenCode route must not run a plain subprocess"
        )
        monkeypatch.setattr(
            "opencode_adapter.OpenCodeAdapter",
            lambda: adapter,
        )
        _sandbox_with(monkeypatch, _sandbox_run(
            json.dumps({"type": "text", "part": {"type": "text", "text": "sandboxed"}})
        ))
        result = invoke(ProviderRouter(config), staging)
        assert result.assistant_text == "sandboxed"


def test_an_unavailable_sandbox_refuses_with_a_typed_reason(monkeypatch) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        config = root / "provider.json"
        staging = root / "staging"
        staging.mkdir()
        opencode_profile(config)
        monkeypatch.setattr(
            "opencode_adapter.OpenCodeAdapter",
            lambda: FakeOpenCodeAdapter(""),
        )
        monkeypatch.setattr(
            "stateport_persistent_app.provider_router.resolve_harness_binary",
            lambda: None,
        )
        with pytest.raises(ProviderRouterError, match="sandbox_unavailable"):
            invoke(ProviderRouter(config), staging)


def test_the_opencode_route_carries_the_adopted_signin_when_there_is_one(tmp_path, monkeypatch) -> None:
    home = tmp_path / "provider-home"
    auth = home / "data" / "opencode" / "auth.json"
    auth.parent.mkdir(parents=True)
    auth.write_text(json.dumps({"opencode": {"type": "api", "key": "fixture"}}), encoding="utf-8")
    monkeypatch.setenv("STATEPORT_OPENCODE_HOME", str(home))
    config = tmp_path / "provider.json"
    staging = tmp_path / "staging"
    staging.mkdir()
    opencode_profile(config)
    monkeypatch.setattr(
        "opencode_adapter.OpenCodeAdapter",
        lambda: FakeOpenCodeAdapter(""),
    )
    sandbox = _sandbox_with(monkeypatch, _sandbox_run(
        json.dumps({"type": "text", "part": {"type": "text", "text": "sandboxed"}})
    ))
    invoke(ProviderRouter(config), staging)
    # The sandbox receives the sign-in as a file and reduces it itself.
    assert sandbox.route.credential_file == auth


def test_an_account_route_carries_the_operator_credential_and_only_its_own_host(
    tmp_path, monkeypatch
) -> None:
    home = tmp_path / "provider-home"
    ProviderCredentialStore(home).store("anthropic", "sk-ant-fixture")
    monkeypatch.setenv("STATEPORT_OPENCODE_HOME", str(home))
    config = tmp_path / "provider.json"
    staging = tmp_path / "staging"
    staging.mkdir()
    ProviderRouter.configure(
        config, provider_id="opencode", model_identifier="anthropic/claude-fixture"
    )
    monkeypatch.setattr(
        "opencode_adapter.OpenCodeAdapter",
        lambda: FakeOpenCodeAdapter(""),
    )
    sandbox = _sandbox_with(monkeypatch, _sandbox_run(
        json.dumps({"type": "text", "part": {"type": "text", "text": "sandboxed"}})
    ))
    invoke(ProviderRouter(config), staging)
    route = sandbox.route
    assert route.tools == "none"
    assert route.credential_file == home / "provider.env"
    # Egress is the provider's own API host and the model catalogue; nothing else.
    assert set(route.allow_hosts) == {"api.anthropic.com", "models.opencode.ai"}


def test_an_account_route_without_a_credential_refuses_before_any_process(
    tmp_path, monkeypatch
) -> None:
    home = tmp_path / "provider-home"
    monkeypatch.setenv("STATEPORT_OPENCODE_HOME", str(home))
    config = tmp_path / "provider.json"
    staging = tmp_path / "staging"
    staging.mkdir()
    ProviderRouter.configure(
        config, provider_id="opencode", model_identifier="anthropic/claude-fixture"
    )
    monkeypatch.setattr(
        "opencode_adapter.OpenCodeAdapter",
        lambda: FakeOpenCodeAdapter(""),
    )
    _sandbox_with(monkeypatch, _sandbox_run(""))
    with pytest.raises(ProviderRouterError, match="credential_unavailable"):
        invoke(ProviderRouter(config), staging)


def test_an_unknown_provider_route_is_refused(tmp_path, monkeypatch) -> None:
    config = tmp_path / "provider.json"
    staging = tmp_path / "staging"
    staging.mkdir()
    ProviderRouter.configure(
        config, provider_id="opencode", model_identifier="unknown-provider/some-model"
    )
    monkeypatch.setattr(
        "opencode_adapter.OpenCodeAdapter",
        lambda: FakeOpenCodeAdapter(""),
    )
    _sandbox_with(monkeypatch, _sandbox_run(""))
    with pytest.raises(ProviderRouterError, match="route_invalid"):
        invoke(ProviderRouter(config), staging)


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


def test_opencode_authentication_error_event_maps_to_typed_refusal(monkeypatch) -> None:
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
        _sandbox_with(monkeypatch, _sandbox_run(stdout))
        with pytest.raises(ProviderRouterError, match="provider_authentication_unverified"):
            invoke(ProviderRouter(config, adapter=FakeOpenCodeAdapter(stdout)), staging)


def test_opencode_non_authentication_error_is_not_mislabelled(monkeypatch) -> None:
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
        _sandbox_with(monkeypatch, _sandbox_run(stdout))
        with pytest.raises(ProviderRouterError, match="assistant message"):
            invoke(ProviderRouter(config, adapter=FakeOpenCodeAdapter(stdout)), staging)


def opencode_env_shim(directory: Path) -> Path:
    """Materialize a fake `opencode` that records its real invocation environment.

    It answers the managed executable probe (``--version``, ``run --help``) and,
    for a real ``run`` invocation, writes every observed environment entry into
    the sandbox's working directory before emitting one normal assistant text
    event. It never prints the environment, so no value can reach the event
    stream.
    """
    directory.mkdir(parents=True, exist_ok=True)
    executable = directory / "opencode"
    executable.write_text(
        f'#!{sys.executable}\n'
        'import json, os, sys\n'
        'if "--version" in sys.argv:\n'
        '    print("1.19.3")\n'
        'elif "run" in sys.argv and "--help" in sys.argv:\n'
        '    print("run --format json --model --auto")\n'
        'elif "run" in sys.argv:\n'
        '    with open("/work/recorded-env.txt", "w", encoding="utf-8") as handle:\n'
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


def _sandbox_runtime(tmp_path, monkeypatch) -> None:
    """Isolate the sandbox runtime root and keep the catalogue fetch out."""
    from stateport_persistent_app import agent_sandbox

    runtime = tmp_path / "sandbox-runtime"
    runtime.mkdir(mode=0o700, exist_ok=True)
    monkeypatch.setenv(agent_sandbox.RUNTIME_DIR_ENV, str(runtime))
    monkeypatch.setattr(agent_sandbox, "_catalogue_fetcher", lambda path: False)
    if not agent_sandbox.sandbox_available()[0]:
        pytest.skip("the agent sandbox is unavailable on this host")


def test_the_sandbox_hands_the_operator_credential_to_the_harness_only(
    tmp_path, monkeypatch
):
    """The account route's key reaches the harness; the host HOME does not."""
    _sandbox_runtime(tmp_path, monkeypatch)
    home = tmp_path / "provider-home"
    ProviderCredentialStore(home).store("groq", "gsk-fake-inject")
    shim = opencode_env_shim(tmp_path / "bin")
    monkeypatch.setenv("STATEPORT_OPENCODE_HOME", str(home))
    monkeypatch.setenv("STATEPORT_OPENCODE_BINARY", str(shim))
    monkeypatch.setenv("SECRET_CANARY", "must-not-leak")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")
    monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/dbus")
    config = tmp_path / "provider.json"
    staging = tmp_path / "staging"
    staging.mkdir()
    ProviderRouter.configure(
        config, provider_id="opencode", model_identifier="groq/some-model"
    )

    result = invoke(ProviderRouter(config), staging)

    assert result.assistant_text == "shim answer"
    recorded = recorded_environment(staging / "recorded-env.txt")
    # The operator's key is the one credential the sandbox hands over.
    assert recorded["GROQ_API_KEY"] == "gsk-fake-inject"
    # The harness runs with the sandbox's own HOME, not the operator's.
    assert recorded["HOME"] != str(Path.home())
    assert recorded["XDG_DATA_HOME"] != str(home / "data")
    # No unrelated host environment leaks into the provider subprocess.
    for leaked in ("SECRET_CANARY", "SSH_AUTH_SOCK", "DBUS_SESSION_BUS_ADDRESS"):
        assert leaked not in recorded


def test_the_free_route_hands_the_harness_no_credential_at_all(tmp_path, monkeypatch):
    _sandbox_runtime(tmp_path, monkeypatch)
    home = tmp_path / "provider-home"
    shim = opencode_env_shim(tmp_path / "bin")
    monkeypatch.setenv("STATEPORT_OPENCODE_HOME", str(home))
    monkeypatch.setenv("STATEPORT_OPENCODE_BINARY", str(shim))
    config = tmp_path / "provider.json"
    staging = tmp_path / "staging"
    staging.mkdir()
    opencode_profile(config)

    # With no credential the run still happens (OpenCode reports its own
    # authentication result) and carries no provider key at all.
    result = invoke(ProviderRouter(config), staging)

    assert result.assistant_text == "shim answer"
    recorded = recorded_environment(staging / "recorded-env.txt")
    for env_var in PROVIDER_CREDENTIAL_ENV.values():
        assert env_var not in recorded
    assert recorded["HOME"] != str(Path.home())
