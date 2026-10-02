#!/usr/bin/env python3
"""Focused tests for the authority-gated managed run lifecycle seam.

These prove the lifecycle path is inert the moment an owner typed grant is
missing, and that no provider handle, socket path, or secret ever appears in a
ticket or an error:
- no grant -> refuse before any adapter contact
- revoked grant -> refuse
- unset or mismatched digest -> refuse
- held single-in-flight per workspace -> refuse
- valid grant -> typed lease issued
- lease expiry fails the run closed
- revocation during a run terminates it
- no provider handle / socket path in any ticket or error datum
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import tempfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "execution-host" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "runtime-contracts" / "src"))

from execution_host.run_authority import RunAuthority, RunGrant  # noqa: E402
from execution_host.agent_run_lifecycle import (  # noqa: E402
    AgentRunLifecycle,
    ManagedAdapter,
    RunAdapterUnavailable,
    RunRefused,
    RunTicket,
)
from runtime_contracts import RunLease  # noqa: E402

DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64
IMAGE = "example.invalid/stateagent@sha256:" + "a" * 64
HOST = "exec-1"
KIND = "opencode"


def _grant_value(*, digest: str = DIGEST, grant_id: str = "grant.1") -> RunGrant:
    return RunGrant(
        grant_id=grant_id,
        executor_kind=KIND,
        claimed_image=IMAGE,
        host=HOST,
        scope="test grant",
        issued_at="2026-08-07T00:00:00Z",
        digest_pin=digest,
    )


OWNER_GRANT_DIGEST = _grant_value().authority_digest


def _grant(authority: RunAuthority, *, digest: str = DIGEST, grant_id: str = "grant.1") -> RunGrant:
    obj = _grant_value(digest=digest, grant_id=grant_id)
    authority.register(obj)
    return obj


def _lifecycle(authority: RunAuthority, *, duration: int = 3600, state_dir: str | None = None) -> AgentRunLifecycle:
    directory = state_dir or tempfile.mkdtemp(prefix="state-alpha4-lifecycle-")
    return AgentRunLifecycle(authority, state_dir=directory, lease_duration_seconds=duration)


def _spec(
    run_id: str = "run.1",
    workspace: str = "ws.1",
    digest: str | None = DIGEST,
    authority_digest: str = OWNER_GRANT_DIGEST,
) -> dict:
    return {
        "runId": run_id,
        "workspaceId": workspace,
        "imageDigest": digest,
        "authorityGrantDigest": authority_digest,
    }


def _lease_state(ticket: RunTicket) -> str:
    return json.loads(Path(ticket.claim_path).read_text(encoding="utf-8"))["state"]


@pytest.fixture
def authority() -> RunAuthority:
    return RunAuthority(host=HOST)


class _GateProbe(ManagedAdapter):
    """Adapter double that records whether it was ever reached."""

    def __init__(self, calls: list) -> None:
        self._calls = calls

    def run(self, spec, *, lease, provider=None):
        self._calls.append("contacted")
        return {"ok": True}


def test_no_grant_refuses_before_any_adapter_contact() -> None:
    auth = RunAuthority(host=HOST)
    lc = _lifecycle(auth)
    with pytest.raises(RunRefused) as exc:
        lc.begin_run(_spec(), executor_kind=KIND, claimed_image=IMAGE, host=HOST)
    assert "no_grant" in str(exc.value)


def test_revoked_grant_refuses() -> None:
    auth = RunAuthority(host=HOST)
    grant = _grant(auth)
    identity = grant.authority_digest
    auth.revoke(grant.grant_id)
    revoked = auth.grant(grant.grant_id)
    assert revoked is not None
    assert revoked.authority_digest == identity
    assert revoked.revoked
    lc = _lifecycle(auth)
    with pytest.raises(RunRefused) as exc:
        lc.begin_run(_spec(), executor_kind=KIND, claimed_image=IMAGE, host=HOST)
    assert "revoked" in str(exc.value)


def test_unset_digest_refuses() -> None:
    auth = RunAuthority(host=HOST)
    _grant(auth)
    lc = _lifecycle(auth)
    with pytest.raises(RunRefused) as exc:
        lc.begin_run(_spec(digest=None), executor_kind=KIND, claimed_image=IMAGE, host=HOST)
    assert "digest_unset" in str(exc.value)


def test_mismatched_digest_refuses() -> None:
    auth = RunAuthority(host=HOST)
    _grant(auth)
    lc = _lifecycle(auth)
    with pytest.raises(RunRefused) as exc:
        lc.begin_run(_spec(digest=OTHER_DIGEST), executor_kind=KIND, claimed_image=IMAGE, host=HOST)
    assert "digest_mismatch" in str(exc.value)


def test_wrong_owner_grant_digest_refuses_before_lease_creation(tmp_path: Path) -> None:
    auth = RunAuthority(host=HOST)
    _grant(auth)
    lc = _lifecycle(auth, state_dir=str(tmp_path))
    with pytest.raises(RunRefused, match="grant_identity_mismatch"):
        lc.begin_run(
            _spec(authority_digest=OTHER_DIGEST),
            executor_kind=KIND,
            claimed_image=IMAGE,
            host=HOST,
        )
    assert list((tmp_path / "leases").glob("lease.*.json")) == []


def test_single_in_flight_per_workspace() -> None:
    auth = RunAuthority(host=HOST)
    _grant(auth)
    lc = _lifecycle(auth)
    first = lc.begin_run(_spec(run_id="run.1", workspace="ws.1"), executor_kind=KIND, claimed_image=IMAGE, host=HOST)
    assert first.run_id == "run.1"
    with pytest.raises(RunRefused) as exc:
        lc.begin_run(_spec(run_id="run.2", workspace="ws.1"), executor_kind=KIND, claimed_image=IMAGE, host=HOST)
    assert "single_in_flight" in str(exc.value)
    separate = lc.begin_run(_spec(run_id="run.3", workspace="ws.2"), executor_kind=KIND, claimed_image=IMAGE, host=HOST)
    assert separate.run_id == "run.3"


def test_valid_grant_issues_ticket_with_typed_lease() -> None:
    auth = RunAuthority(host=HOST)
    _grant(auth)
    lc = _lifecycle(auth)
    ticket = lc.begin_run(_spec(), executor_kind=KIND, claimed_image=IMAGE, host=HOST)
    assert isinstance(ticket, RunTicket)
    assert isinstance(ticket.lease, RunLease)
    assert ticket.lease.to_dict()["state"] == "granted"
    assert ticket.lease_expires_at > ticket.started_at
    assert lc.is_active("ws.1")


def test_lease_expiry_fails_the_run_closed() -> None:
    auth = RunAuthority(host=HOST)
    _grant(auth)
    lc = _lifecycle(auth, duration=60)
    start = datetime(2026, 8, 7, 0, 0, tzinfo=timezone.utc)
    ticket = lc.begin_run(_spec(run_id="run.e"), executor_kind=KIND, claimed_image=IMAGE, host=HOST, clock=start)
    later = start + timedelta(seconds=120)
    assert lc.is_expired(ticket, clock=later)
    with pytest.raises(RunRefused) as exc:
        lc.fail_if_expired(ticket, clock=later)
    assert "run_lease_expired" in str(exc.value)
    assert not lc.is_active("ws.1")
    assert _lease_state(ticket) == "expired"


def test_renew_lease_extends_lifetime() -> None:
    auth = RunAuthority(host=HOST)
    _grant(auth)
    lc = _lifecycle(auth, duration=3600)
    start = datetime(2026, 8, 7, 0, 0, tzinfo=timezone.utc)
    ticket = lc.begin_run(_spec(run_id="run.r"), executor_kind=KIND, claimed_image=IMAGE, host=HOST, clock=start)
    renewed = lc.renew_lease(ticket, clock=start + timedelta(seconds=3000))
    assert renewed.lease_expires_at > ticket.lease_expires_at
    assert _lease_state(renewed) == "renewed"


def test_revocation_during_run_terminates_it() -> None:
    auth = RunAuthority(host=HOST)
    grant = _grant(auth)
    lc = _lifecycle(auth)
    ticket = lc.begin_run(_spec(run_id="run.1"), executor_kind=KIND, claimed_image=IMAGE, host=HOST)
    assert not lc.revoked_during_run(ticket)
    auth.revoke(grant.grant_id)
    # the adapter must never be reached once revoked
    calls: list = []
    with pytest.raises(RunRefused):
        lc.invoke(ticket, _GateProbe(calls), _spec(run_id="run.1"), clock=datetime.now(timezone.utc))
    assert calls == []
    lc.revoke_run(ticket)
    assert _lease_state(ticket) == "revoked"


def test_no_provider_handle_or_socket_path_in_ticket() -> None:
    auth = RunAuthority(host=HOST)
    _grant(auth)
    lc = _lifecycle(auth)
    ticket = lc.begin_run(_spec(run_id="run.x"), executor_kind=KIND, claimed_image=IMAGE, host=HOST)
    fields = set(ticket.__dataclass_fields__)
    for forbidden in ("socket", "handle", "token", "secret", "provider_config"):
        assert forbidden not in fields
    for forbidden in (".sock", "/var/run", "token", "secret", "api_key"):
        assert forbidden not in json.dumps(ticket.lease.to_dict()).lower()


def test_no_socket_or_handle_in_refusal_error() -> None:
    auth = RunAuthority(host=HOST)
    _grant(auth)
    lc = _lifecycle(auth)
    try:
        lc.begin_run(_spec(digest=OTHER_DIGEST), executor_kind=KIND, claimed_image=IMAGE, host=HOST)
        raise AssertionError("expected refusal")
    except RunRefused as exc:
        text = str(exc).lower()
        for forbidden in (".sock", "/var/run", "token", "secret", "api_key"):
            assert forbidden not in text
        assert "digest_mismatch" in text


def test_adapter_seam_refuses_every_kind_while_quarantined() -> None:
    from execution_host.agent_run_lifecycle import managed_adapter_for

    # No local-process provider adapter is shipped: every kind refuses closed
    # until a digest-pinned managed executor resolves through the execution
    # host (ephemeral container + run-bound gateway), never a local shim.
    with pytest.raises(RunAdapterUnavailable):
        managed_adapter_for(KIND)
    with pytest.raises(RunAdapterUnavailable):
        managed_adapter_for("untrusted-unknown-kind")
