#!/usr/bin/env python3
"""Focused tests for run-bound evidence and the typed credential boundary.

Proves the provider token never reaches evidence, receipts, or the handle, and
that dishonest finishes are refused:
- RunEvidence round-trips to an identical recomputable digest
- a revoked-grant finish is recorded refused, never success
- a provider binding never emits the secret, only an opaque handle/config id
- a leaked-token resolution (handle token call) that fails fails closed
- evidence for a provider the run never used is refused
- the decision digest is recomputable from fields with no secrets in them
"""
from __future__ import annotations

from pathlib import Path
import hashlib
import sys
import threading

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "execution-host" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "runtime-contracts" / "src"))

from execution_host.provider_bindings import (  # noqa: E402
    ProviderBindError,
    ProviderBindingHandle,
    ProviderBindingManager,
    ProviderSecretUnavailable,
    RunEvidenceService,
    scrubbed_environment,
)
from runtime_contracts import RunEvidence, RunLease, canonical_digest  # noqa: E402

DIGEST = "sha256:" + "a" * 64
OUTPUT_DIGEST = "sha256:" + "b" * 64
START = "2026-08-07T00:00:00Z"
END = "2026-08-07T01:00:00Z"


def _evidence(**overrides) -> dict:
    value = {
        "formatVersion": RunEvidence.FORMAT,
        "runId": "run.1",
        "workspaceId": "ws.1",
        "executorKind": "opencode",
        "imageDigest": DIGEST,
        "startedAt": START,
        "endedAt": END,
        "outcome": "completed",
        "exitReason": "finished",
        "digestOfOutput": OUTPUT_DIGEST,
        "leaseId": "lease.1",
    }
    value.update(overrides)
    return value


def _service() -> RunEvidenceService:
    return RunEvidenceService()


def test_evidence_roundtrip_recomputes_identical_digest() -> None:
    evidence = RunEvidence.from_dict(_evidence())
    rebuilt = RunEvidence.from_dict(evidence.to_dict())
    assert evidence.digest == rebuilt.digest
    assert canonical_digest(rebuilt.to_dict()) == evidence.digest


def test_revoked_grant_finish_is_refused_not_success() -> None:
    svc = _service()
    svc.mark_provider_used("run.1", "provider.demo")
    evidence = svc.finish_evidence(
        run_id="run.1", workspace_id="ws.1", executor_kind="opencode",
        image_digest=DIGEST, lease_id="lease.1", started_at=START, ended_at=END,
        outcome="completed", exit_reason="claimed success", digest_of_output=OUTPUT_DIGEST,
        config_id="provider.demo", grant_revoked=True,
    )
    assert evidence.to_dict()["outcome"] == "refused"


def test_successful_finish_records_completed() -> None:
    svc = _service()
    svc.mark_provider_used("run.1", "provider.demo")
    evidence = svc.finish_evidence(
        run_id="run.1", workspace_id="ws.1", executor_kind="opencode",
        image_digest=DIGEST, lease_id="lease.1", started_at=START, ended_at=END,
        outcome="completed", exit_reason="ok", digest_of_output=OUTPUT_DIGEST,
        config_id="provider.demo", grant_revoked=False,
    )
    assert evidence.to_dict()["outcome"] == "completed"


def test_provider_handle_never_emits_secret_only_config_id() -> None:
    mgr = ProviderBindingManager(env={"SP_ANTHROPIC_KEY": "super-secret-token"})
    mgr.define_config("provider.demo", provider="anthropic", model="claude-sonnet", token_env="SP_ANTHROPIC_KEY")
    handle = mgr.bind(config_id="provider.demo", granted=True)
    assert isinstance(handle, ProviderBindingHandle)
    # the handle carries the opaque config id, never the token
    assert handle.config_id == "provider.demo"
    assert "super-secret-token" not in repr(handle)
    # the token is resolvable at call time but not stored on the handle
    assert handle.token() == "super-secret-token"
    mgr.revoke(handle)
    assert mgr.configured("provider.demo")
    with pytest.raises(ProviderSecretUnavailable, match="revoked"):
        handle.token()


def test_bind_without_grant_fails_closed() -> None:
    mgr = ProviderBindingManager(env={"SP_K": "x"})
    mgr.define_config("provider.demo", provider="anthropic", model="sonnet", token_env="SP_K")
    with pytest.raises(ProviderBindError):
        mgr.bind(config_id="provider.demo", granted=False)


def test_bind_unknown_config_fails_closed() -> None:
    mgr = ProviderBindingManager()
    with pytest.raises(ProviderBindError):
        mgr.bind(config_id="provider.missing", granted=True)


def test_token_resolution_failure_fails_the_run_closed() -> None:
    mgr = ProviderBindingManager(env={})
    mgr.define_config("provider.demo", provider="anthropic", model="sonnet", token_env="SP_NEVER_SET")
    handle = mgr.bind(config_id="provider.demo", granted=True)
    with pytest.raises(ProviderSecretUnavailable):
        handle.token()


def test_evidence_for_unused_provider_is_refused() -> None:
    svc = _service()
    # provider config never marked used for this run
    evidence = svc.finish_evidence(
        run_id="run.1", workspace_id="ws.1", executor_kind="opencode",
        image_digest=DIGEST, lease_id="lease.1", started_at=START, ended_at=END,
        outcome="completed", exit_reason="rogue", digest_of_output=OUTPUT_DIGEST,
        config_id="provider.ghost", grant_revoked=False,
    )
    assert evidence.to_dict()["outcome"] == "refused"


def test_provider_use_and_completion_are_run_scoped_under_concurrency() -> None:
    svc = _service()
    run_ids = ("run.concurrent.1", "run.concurrent.2")
    for run_id in run_ids:
        svc.mark_provider_used(run_id, "provider.demo")
    outcomes: dict[str, str] = {}
    lock = threading.Lock()

    def finish(run_id: str) -> None:
        evidence = svc.finish_evidence(
            run_id=run_id,
            workspace_id="ws.1",
            executor_kind="opencode",
            image_digest=DIGEST,
            lease_id=f"lease.{run_id}",
            started_at=START,
            ended_at=END,
            outcome="completed",
            exit_reason="ok",
            digest_of_output=OUTPUT_DIGEST,
            config_id="provider.demo",
            grant_revoked=False,
        )
        with lock:
            outcomes[run_id] = evidence.to_dict()["outcome"]

    threads = [threading.Thread(target=finish, args=(run_id,)) for run_id in run_ids]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
    assert outcomes == {run_id: "completed" for run_id in run_ids}


def test_decision_digest_recomputable_from_fields_and_secret_free() -> None:
    svc = _service()
    fields = {
        "runId": "run.1",
        "outcome": "completed",
        "digestOfOutput": OUTPUT_DIGEST,
    }
    digest = svc.decision_digest(fields)
    assert digest.startswith("sha256:")
    assert digest == canonical_digest(fields)
    for secret_hint in ("token", "secret", "api_key", "password", "credential"):
        assert secret_hint not in fields
    # evidence carries no token and no provider handle either
    blob = str(RunEvidence.from_dict(_evidence()).to_dict()).lower()
    for secret_hint in ("token", "secret", "api_key", "password", "credential"):
        assert secret_hint not in blob


def test_provider_secret_is_absent_from_child_environment_and_arguments(monkeypatch) -> None:
    """A child process spawned with the scrubbed environment never sees the secret."""
    import subprocess

    provider_value = "synthetic-provider-value"
    monkeypatch.setenv("SP_ANTHROPIC_KEY", provider_value)
    environment = scrubbed_environment()
    assert "SP_ANTHROPIC_KEY" not in environment

    argv = (
        sys.executable,
        "-I",
        "-c",
        "import os, sys; sys.stdout.write(os.getenv('SP_ANTHROPIC_KEY', 'missing'))",
    )
    completed = subprocess.run(
        argv, env=environment, capture_output=True, text=True, timeout=30, check=True
    )
    assert completed.stdout == "missing"
    assert not any(provider_value in item for item in argv)
