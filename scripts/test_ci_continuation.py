"""Focused tests for the fake-only blocked-CI continuation contract."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "ci-continuation" / "src"))

from ci_continuation import (  # noqa: E402
    AuthorizationDecision,
    BindingMismatchError,
    CIStatus,
    ContinuationState,
    ExactHeadBinding,
    FakeCIProvider,
    InvalidTransitionError,
    StaleAuthorizationError,
    WorkflowContinuation,
)


SHA = "a" * 40
OTHER_SHA = "b" * 40


def binding(head_sha: str = SHA) -> ExactHeadBinding:
    return ExactHeadBinding("octo/stateport", 17, head_sha)


def blocked_machine(*, outcomes=(CIStatus.RUNNING, CIStatus.BLOCKED_EXTERNAL)) -> WorkflowContinuation:
    exact = binding()
    machine = WorkflowContinuation(exact, FakeCIProvider(outcomes))
    machine.start_ci(exact)
    machine.poll_ci(exact)
    return machine


def await_decision(machine: WorkflowContinuation):
    return machine.await_human(machine.binding, actor="operator")


def authorize(machine: WorkflowContinuation, request, decision: AuthorizationDecision):
    return machine.authorize(request, decision, actor="human")


def test_blocked_ci_reaches_awaiting_human_and_exact_head_override_is_not_a_pass():
    machine = blocked_machine()
    assert machine.state is ContinuationState.CI_BLOCKED_EXTERNAL
    request = await_decision(machine)
    authorization = authorize(machine, request, AuthorizationDecision.EXACT_HEAD_OVERRIDE)

    machine.exact_head_override(machine.binding, authorization)

    assert machine.state is ContinuationState.EXACT_HEAD_OVERRIDE_APPROVED
    assert machine.remote_ci_passed is False
    assert machine.snapshot()["remoteCiPassed"] is False
    assert machine.audit[-1].data["note"] == "human override is not a CI pass"


def test_retry_uses_same_exact_head_and_can_finish_fake_ci():
    exact = binding()
    provider = FakeCIProvider(
        [CIStatus.RUNNING, CIStatus.BLOCKED_EXTERNAL, CIStatus.RUNNING, CIStatus.RUNNING, CIStatus.PASSED]
    )
    machine = WorkflowContinuation(exact, provider)
    machine.start_ci(exact)
    machine.poll_ci(exact)
    request = await_decision(machine)
    authorization = authorize(machine, request, AuthorizationDecision.RETRY)

    machine.retry(exact, authorization)
    assert machine.state is ContinuationState.CI_RUNNING
    assert machine.attempt == 2
    machine.poll_ci(exact)
    machine.poll_ci(exact)

    assert machine.state is ContinuationState.CI_PASSED
    assert provider.calls == [
        ("start", "fake-run-001", exact),
        ("poll", "fake-run-001", exact),
        ("start", "fake-run-002", exact),
        ("poll", "fake-run-002", exact),
        ("poll", "fake-run-002", exact),
    ]
    assert all(call[2] == exact for call in provider.calls)
    assert machine.remote_ci_passed is False


def test_cancel_is_terminal_and_no_remote_side_effect_is_possible():
    machine = blocked_machine(outcomes=(CIStatus.RUNNING, CIStatus.FAILED))
    request = await_decision(machine)
    machine.cancel(machine.binding, authorize(machine, request, AuthorizationDecision.CANCEL))

    assert machine.state is ContinuationState.CANCELLED
    with pytest.raises(InvalidTransitionError):
        machine.start_ci(machine.binding)
    assert machine.provider.calls == [("start", "fake-run-001", machine.binding), ("poll", "fake-run-001", machine.binding)]


def test_every_action_rejects_wrong_repository_pr_or_head():
    machine = blocked_machine()
    wrong_repo = ExactHeadBinding("other/stateport", machine.binding.pr_number, SHA)
    wrong_pr = ExactHeadBinding(machine.binding.repository, 18, SHA)
    wrong_head = ExactHeadBinding(machine.binding.repository, machine.binding.pr_number, OTHER_SHA)

    for wrong in (wrong_repo, wrong_pr, wrong_head):
        with pytest.raises(BindingMismatchError):
            machine.await_human(wrong)
    assert machine.state is ContinuationState.CI_BLOCKED_EXTERNAL


def test_stale_authorization_is_rejected_after_revision_changes_and_reuse():
    machine = blocked_machine()
    request = await_decision(machine)
    authorization = authorize(machine, request, AuthorizationDecision.RETRY)
    competing_authorization = authorize(machine, request, AuthorizationDecision.CANCEL)
    machine.cancel(machine.binding, competing_authorization)

    with pytest.raises(StaleAuthorizationError):
        machine.apply_authorization(machine.binding, authorization)


def test_audit_is_hash_chained_and_deterministic_without_timestamps():
    def run() -> list[dict]:
        machine = blocked_machine()
        request = await_decision(machine)
        machine.apply_authorization(
            machine.binding,
            authorize(machine, request, AuthorizationDecision.EXACT_HEAD_OVERRIDE),
        )
        assert machine.verify_audit()
        return [event.to_dict() for event in machine.audit]

    first = run()
    second = run()
    assert first == second
    assert first[0]["previousHash"] == "genesis"
    assert first[-1]["hash"].startswith("sha256:")


def test_provider_is_fake_only_and_invalid_script_is_rejected():
    with pytest.raises(ValueError):
        FakeCIProvider([CIStatus.PASSED])
    with pytest.raises(ValueError):
        ExactHeadBinding("octo/stateport", 17, "A" * 40)
    with pytest.raises(TypeError, match="FakeCIProvider"):
        WorkflowContinuation(binding(), object())  # type: ignore[arg-type]
