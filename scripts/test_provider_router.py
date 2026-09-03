#!/usr/bin/env python3
"""Focused tests for the first durable Codex provider authority."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "execution-host" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "external-engine-runtime" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "codex-adapter" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "persistent-app" / "src"))

from execution_host.contracts import BackendCapabilities  # noqa: E402
from external_engine_runtime import ProcessIdentity, ProcessResult  # noqa: E402
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
    ) -> ProcessResult:
        del cancel_event, staging_root
        self.spec = spec
        self.generation = process_generation
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
