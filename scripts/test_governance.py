#!/usr/bin/env python3
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for rel in ("packages/quota-engine/src", "packages/approval-gate/src", "packages/audit-log/src"):
    sys.path.insert(0, str(ROOT / rel))

from approval_gate import ApprovalGate, intersect_capabilities
from audit_log import AuditLog
from quota_engine import QuotaEngine, QuotaPolicy, UsageSnapshot


def test_quota_is_fail_closed_at_limits() -> None:
    engine = QuotaEngine(QuotaPolicy(runs_per_day=2, monthly_euro_estimate=1.0))
    assert engine.evaluate(UsageSnapshot(runs_today=1), estimated_cost=.2).allowed
    denied = engine.evaluate(UsageSnapshot(runs_today=2), estimated_cost=.2)
    assert not denied.allowed and denied.code == "quota_exceeded"
    assert not engine.evaluate(UsageSnapshot(), estimated_cost=2).allowed
    for invalid in (float("nan"), float("inf"), -1.0):
        decision = engine.evaluate(UsageSnapshot(), estimated_cost=invalid)
        assert not decision.allowed and decision.code == "invalid_cost"
    try:
        QuotaPolicy(monthly_euro_estimate=float("nan"))
    except ValueError:
        pass
    else:
        raise AssertionError("non-finite quota policy must fail closed")


def test_capabilities_are_intersection_not_union() -> None:
    effective = intersect_capabilities({"read", "write"}, {"read", "write"}, {"read"})
    assert effective == {"read"}
    gate = ApprovalGate()
    assert gate.capability("write_state", "write", {"write"}, {"write"}, {"read"}).allowed is False


def test_approval_transitions_are_explicit_and_terminal() -> None:
    gate = ApprovalGate()
    request = gate.request(operation="send", capability="send", instance_id="i1")
    approved = gate.transition(request.id, "approved", "reviewed")
    assert approved.status == "approved"
    try:
        gate.transition(request.id, "rejected")
    except ValueError:
        pass
    else:
        raise AssertionError("terminal approval must not transition")


def test_audit_log_is_append_only_and_hash_chained() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "audit.jsonl"
        log = AuditLog(path)
        first = log.append(event_type="run.requested", actor="tester", subject="i1", timestamp="2026-01-01T00:00:00Z")
        second = log.append(event_type="run.denied", actor="policy", subject="i1", timestamp="2026-01-01T00:01:00Z")
        assert first.previous_hash == "genesis"
        assert second.previous_hash == first.hash
        assert log.verify()
        loaded = AuditLog(path)
        assert len(loaded.events) == 2 and loaded.verify()
        path.write_text(path.read_text(encoding="utf-8").replace("run.denied", "run.approved"), encoding="utf-8")
        try:
            AuditLog(path)
        except ValueError:
            pass
        else:
            raise AssertionError("tampered audit log must fail closed")


def test_persistent_approval_and_audit_writes_do_not_lose_concurrent_updates() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        approval_path = root / "approvals.json"
        audit_path = root / "audit.jsonl"

        def write(index: int) -> None:
            ApprovalGate(approval_path).request(
                operation="run",
                capability="read_state",
                instance_id=f"i{index}",
            )
            AuditLog(audit_path).append(
                event_type="run.requested",
                actor=f"actor-{index}",
                subject=f"i{index}",
                timestamp="2026-01-01T00:00:00Z",
            )

        with ThreadPoolExecutor(max_workers=4) as executor:
            list(executor.map(write, range(12)))

        assert len(ApprovalGate(approval_path).all()) == 12
        audit = AuditLog(audit_path)
        assert len(audit.events) == 12
        assert audit.verify()


def test_idempotent_approval_request_is_atomic_and_immutable() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "approvals.json"

        def request_once(_: int):
            return ApprovalGate(path).request_once(
                "approval-fixed",
                operation="execute-run",
                capability="execute_container",
                instance_id="i1",
                actor="user",
                metadata={"runId": "run:1"},
            )

        with ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(request_once, range(8)))
        assert {request.id for request, _ in results} == {"approval-fixed"}
        assert sum(not idempotent for _, idempotent in results) == 1
        assert len(ApprovalGate(path).all()) == 1
        try:
            ApprovalGate(path).request_once(
                "approval-fixed",
                operation="execute-run",
                capability="execute_container",
                instance_id="i1",
                actor="user",
                metadata={"runId": "run:other"},
            )
        except ValueError:
            pass
        else:
            raise AssertionError("approval id must not be rebound")


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
    print("PASS")
