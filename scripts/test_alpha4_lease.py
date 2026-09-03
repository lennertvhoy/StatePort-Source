#!/usr/bin/env python3
"""Focused tests for idempotent run shutdown, lease transitions, and the
completion gate.

Covers the typed ``RunLease`` transition machine independently of the lifecycle
state files:
- granted -> renewed -> released; expiry; forced release on revocation
- idempotent shutdown: releasing/cancelling twice is the same terminal view,
  not an error
- cancellation of a not-finished run is recorded cancelled, never succeeded
- while a lease is held no run completes; once released a run completes once
  and only once
"""
from __future__ import annotations

from pathlib import Path
import os
import subprocess
import sys
import tempfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "execution-host" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "runtime-contracts" / "src"))

from execution_host.run_lease import RunCompletionGate, RunLeaseController, RunLeaseError  # noqa: E402
from runtime_contracts import RunLease  # noqa: E402

DIGEST = "sha256:" + "a" * 64


def _lease(lease_id: str, *, state: str = "granted", run_id: str = "run.1") -> RunLease:
    return RunLease.from_dict(
        {
            "formatVersion": RunLease.FORMAT,
            "leaseId": lease_id,
            "runId": run_id,
            "workspaceId": "ws.1",
            "executorKind": "opencode",
            "imageDigest": DIGEST,
            "claimPath": f"/tmp/stateport/lease-{lease_id}.json",
            "startedAt": "2026-08-07T00:00:00Z",
            "expiresAt": "2026-08-07T01:00:00Z",
            "state": state,
        }
    )


@pytest.fixture
def controller() -> RunLeaseController:
    return RunLeaseController(tempfile.mkdtemp(prefix="state-alpha4-lease-"))


@pytest.fixture
def gate() -> RunCompletionGate:
    return RunCompletionGate()


def _state(lease: RunLease) -> str:
    return lease.to_dict()["state"]


def test_granted_renews_and_releases(controller) -> None:
    lease = _lease("l1")
    renewed = controller.renew(lease)
    assert _state(renewed) == "renewed"
    released = controller.release(renewed)
    assert _state(released) == "released"


def test_granted_expires(controller) -> None:
    lease = _lease("l2")
    assert _state(controller.expire(lease)) == "expired"


def test_force_release_on_revocation(controller) -> None:
    lease = _lease("l3", state="renewed")
    assert _state(controller.force_release(lease)) == "revoked"


def test_illegal_transition_refused(controller) -> None:
    with pytest.raises(RunLeaseError):
        controller.renew(_lease("l4", state="released"))
    with pytest.raises(RunLeaseError):
        controller.renew(_lease("l5", state="revoked"))


def test_shutdown_is_idempotent(controller) -> None:
    lease = _lease("l6")
    once = controller.release(lease)
    twice = controller.release(once)
    assert _state(once) == _state(twice) == "released"
    # cancel twice on a terminal lease is not an error
    assert _state(controller.cancel(once)) == "released"
    assert _state(controller.cancel(twice)) == "released"


def test_forced_release_then_release_idempotent(controller) -> None:
    forced = controller.force_release(_lease("l7", state="granted"))
    again = controller.release(forced)
    assert _state(forced) == _state(again) == "revoked"


def test_held_lease_prevents_completion(gate) -> None:
    held = _lease("l8", state="granted")
    with pytest.raises(RunLeaseError) as exc:
        gate.complete(held, outcome="completed")
    assert "held" in str(exc.value)


def test_released_lease_completes_once_and_only_once(gate) -> None:
    released = _lease("l9", state="released")
    assert gate.complete(released, outcome="completed") is True
    assert gate.finished_outcome("l9") == "completed"
    with pytest.raises(RunLeaseError) as exc:
        gate.complete(released, outcome="completed")
    assert "already_completed" in str(exc.value)
    # never invent a second completion
    assert gate.finished_outcome("l9") == "completed"


def test_cancel_is_recorded_cancelled_never_succeeded(gate) -> None:
    lease = _lease("l10", state="released")
    gate.cancel_record("l10")
    gate.complete(lease, outcome="completed")
    assert gate.finished_outcome("l10") == "cancelled"


def test_refused_outcome_is_allowed(gate) -> None:
    lease = _lease("l11", state="expired")
    assert gate.complete(lease, outcome="refused") is True
    assert gate.finished_outcome("l11") == "refused"


def test_workspace_lease_is_exclusive_across_processes(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    child = """
from execution_host.agent_run_lifecycle import AgentRunLifecycle
from execution_host.run_authority import RunAuthority, RunGrant
import sys

digest = "sha256:" + "a" * 64
image = "example.invalid/stateagent@" + digest
authority = RunAuthority(host="exec-1")
grant = RunGrant(
    grant_id="grant.child", executor_kind="opencode", claimed_image=image,
    host="exec-1", scope="lease test", issued_at="2026-08-07T00:00:00Z",
    digest_pin=digest,
)
authority.register(grant)
lifecycle = AgentRunLifecycle(authority, state_dir=sys.argv[1], lease_duration_seconds=3600)
lifecycle.begin_run(
    {"runId": "run.child", "workspaceId": "workspace.shared", "imageDigest": digest,
     "authorityGrantDigest": grant.authority_digest},
    executor_kind="opencode", claimed_image=image, host="exec-1",
)
print("ready", flush=True)
"""
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(ROOT / "packages" / "execution-host" / "src"), str(ROOT / "packages" / "runtime-contracts" / "src")]
    )
    process = subprocess.Popen(
        [sys.executable, "-c", child, str(state_dir)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    try:
        assert process.stdout is not None
        assert process.stdout.readline().strip() == "ready"
        from execution_host.agent_run_lifecycle import AgentRunLifecycle, RunRefused
        from execution_host.run_authority import RunAuthority, RunGrant

        digest = "sha256:" + "a" * 64
        image = "example.invalid/stateagent@" + digest
        authority = RunAuthority(host="exec-1")
        grant = RunGrant(
            grant_id="grant.parent", executor_kind="opencode", claimed_image=image,
            host="exec-1", scope="lease test", issued_at="2026-08-07T00:00:00Z",
            digest_pin=digest,
        )
        authority.register(grant)
        lifecycle = AgentRunLifecycle(authority, state_dir=state_dir, lease_duration_seconds=3600)
        with pytest.raises(RunRefused, match="single_in_flight"):
            lifecycle.begin_run(
                {"runId": "run.parent", "workspaceId": "workspace.shared", "imageDigest": digest,
                 "authorityGrantDigest": grant.authority_digest},
                executor_kind="opencode", claimed_image=image, host="exec-1",
            )
        assert lifecycle.active_for("workspace.shared") == "run.child"
        assert process.stdin is not None
        process.stdin.write("\n")
        process.stdin.flush()
        assert process.wait(timeout=5) == 0
        next_ticket = lifecycle.begin_run(
            {"runId": "run.next", "workspaceId": "workspace.shared", "imageDigest": digest,
             "authorityGrantDigest": grant.authority_digest},
            executor_kind="opencode", claimed_image=image, host="exec-1",
        )
        lifecycle.release(next_ticket)
    finally:
        if process.poll() is None:
            if process.stdin is not None:
                process.stdin.write("\n")
                process.stdin.flush()
            process.kill()
            process.wait(timeout=5)
