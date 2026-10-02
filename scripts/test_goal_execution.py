#!/usr/bin/env python3
"""Adversarial tests for optional CTO and domain-neutral goal execution."""

from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import threading
from collections.abc import Iterator

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
for relative in (
    "packages/goal-execution/src",
    "packages/application-experience/src",
):
    source = ROOT / relative
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from stateport_application_experience import (  # noqa: E402
    ApplicationExperienceDescriptor,
    ExperienceRegistry,
    load_experience_policy,
)
from stateport_goal_execution import (  # noqa: E402
    ACCEPTANCE_CONTRACT_FORMAT,
    CTO_MODE_POLICY_FORMAT,
    GOAL_EXECUTION_FORMAT,
    GOAL_ITEM_FORMAT,
    GOAL_PROPOSAL_FORMAT,
    GOAL_RECEIPT_FORMAT,
    ORCHESTRATOR_PROFILE_FORMAT,
    PROJECT_BOOTSTRAP_FORMAT,
    REVIEW_ISOLATION_FORMAT,
    REVIEW_REQUIREMENT_FORMAT,
    SLICE_PLAN_FORMAT,
    CtoModePolicy,
    DelegationPlan,
    ExecutionResult,
    GoalBudget,
    GoalContractError,
    GoalExecutionIntent,
    GoalExecutionSession,
    GoalExecutionState,
    GovernanceRefusal,
    InstanceApprovalLeaseRegistry,
    OrchestratorMode,
    OrchestratorProfile,
    ReviewRecord,
    ReviewRequirement,
    ReviewWorkspaceIsolation,
    canonical_digest,
    prepare_project_bootstrap,
    prepare_recommended_slice,
    verify_review_workspace,
)


BASE_COMMIT = "a" * 40
BASE_TREE = "b" * 40
FUNCTIONAL_COMMIT = "c" * 40
FUNCTIONAL_TREE = "d" * 40
TEST_RESULT_DIGEST = canonical_digest({"command": "focused", "passed": 24, "failed": 0})


def _git_test_command(*arguments: str) -> str:
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_AUTHOR_NAME": "StatePort Test",
        "GIT_AUTHOR_EMAIL": "stateport@example.invalid",
        "GIT_COMMITTER_NAME": "StatePort Test",
        "GIT_COMMITTER_EMAIL": "stateport@example.invalid",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    completed = subprocess.run(
        list(arguments),
        check=True,
        capture_output=True,
        text=True,
        env=environment,
        timeout=10,
    )
    return completed.stdout.strip()


@pytest.fixture
def verified_review_workspaces(
    tmp_path: Path,
) -> Iterator[tuple[Path, Path, ReviewWorkspaceIsolation]]:
    implementation = tmp_path / "implementation"
    review = tmp_path / "review"
    _git_test_command("git", "init", "--initial-branch=main", str(implementation))
    (implementation / "feature.txt").write_text("accepted\n", encoding="utf-8")
    _git_test_command("git", "-C", str(implementation), "add", "feature.txt")
    _git_test_command(
        "git", "-C", str(implementation), "commit", "-m", "accepted feature"
    )
    commit = _git_test_command("git", "-C", str(implementation), "rev-parse", "HEAD")
    tree = _git_test_command(
        "git", "-C", str(implementation), "rev-parse", "HEAD^{tree}"
    )
    _git_test_command("git", "clone", "--no-local", str(implementation), str(review))
    _git_test_command("git", "-C", str(review), "switch", "--detach", commit)
    entries = [review, *review.rglob("*")]
    for path in entries:
        path.chmod(path.stat().st_mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
    try:
        evidence = verify_review_workspace(
            review_worktree=review,
            implementation_worktree=implementation,
            reviewer_actor="independent-reviewer",
            expected_commit=commit,
            expected_tree=tree,
        )
        yield implementation, review, evidence
    finally:
        for path in entries:
            path.chmod(path.stat().st_mode | stat.S_IWUSR)


def _contracts(
    *,
    mode: OrchestratorMode = OrchestratorMode.ASSISTED,
    intended_profile: str = "terra-high",
    actual_profile: str = "platform-profile-unexposed",
    ambiguous: bool = False,
    effective_capabilities: frozenset[str] = frozenset(
        {"goal_execution", "cto_orchestration"}
    ),
    capability: str = "cto_orchestration",
    approval_leases: InstanceApprovalLeaseRegistry | None = None,
) -> GoalExecutionSession:
    profile = OrchestratorProfile(
        profile_id="development-cto-v1",
        application_id="stateport.synthetic-reference",
        orchestrator_actor="cto-orchestrator",
        mode=mode,
        capability=capability,
    )
    intent = GoalExecutionIntent(
        intent_id="intent-cto-bootstrap-v1",
        application_id="stateport.synthetic-reference",
        instance_id="synthetic-development-instance",
        requested_by="operator-requester",
        text="Continue this project in CTO mode.",
        requested_mode=mode,
    )
    bootstrap = prepare_project_bootstrap(
        intent=intent,
        repo_root=ROOT / "fixtures" / "apps" / "synthetic-reference",
        trusted_root=ROOT / "fixtures" / "apps",
        base_commit=BASE_COMMIT,
        base_tree=BASE_TREE,
        proposed_by="cto-orchestrator",
        profile=profile,
    )
    if ambiguous:
        bootstrap = replace(
            bootstrap,
            proposal=replace(
                bootstrap.proposal, ambiguities=("repository ownership is unresolved",)
            ),
        )
    plan, acceptance = prepare_recommended_slice(
        bootstrap, proposed_by="cto-orchestrator"
    )
    deviation = intended_profile != actual_profile
    delegation = DelegationPlan(
        plan_id="delegation-synthetic-v1",
        item_id=plan.item_id,
        implementer_actor="bounded-implementer",
        reviewer_actor="independent-reviewer",
        intended_profile=intended_profile,
        actual_profile=actual_profile,
        read_scope=("fixtures/apps/synthetic-reference",),
        write_scope=("packages/goal-execution", "scripts/test_goal_execution.py"),
        routing_deviation_reason="named model profile was not exposed by the platform"
        if deviation
        else None,
    )
    requirement = ReviewRequirement(
        requirement_id="review-synthetic-v1",
        item_id=plan.item_id,
        acceptance_contract_digest=acceptance.digest,
        reviewer_actor=delegation.reviewer_actor,
    )
    return GoalExecutionSession(
        profile=profile,
        policy=CtoModePolicy(),
        bootstrap=bootstrap,
        plan=plan,
        delegation=delegation,
        acceptance=acceptance,
        review_requirement=requirement,
        effective_capabilities=effective_capabilities,
        approval_leases=approval_leases or InstanceApprovalLeaseRegistry(),
    )


def _approve(
    session: GoalExecutionSession,
    *,
    actor: str = "operator-approver",
    administrator: bool = False,
) -> None:
    session.approve(
        actor=actor,
        expected_plan_digest=session.plan.digest,
        current_base_commit=session.plan.base_commit,
        current_base_tree=session.plan.base_tree,
        current_state_snapshot_digest=session.plan.state_snapshot_digest,
        approved_permissions=session.plan.required_permissions,
        approved_side_effect_class=session.plan.side_effect_class,
        approved_budget=session.plan.maximum_budget,
        administrator=administrator,
    )


def _begin(session: GoalExecutionSession, **overrides: object) -> None:
    values: dict[str, object] = {
        "actor": session.delegation.implementer_actor,
        "current_base_commit": session.plan.base_commit,
        "current_base_tree": session.plan.base_tree,
        "current_state_snapshot_digest": session.plan.state_snapshot_digest,
        "current_orchestrator_profile_digest": session.profile.digest,
        "current_policy_digest": session.effective_policy_digest,
        "current_delegation_plan_digest": session.delegation.digest,
        "actual_permissions": session.plan.required_permissions,
        "side_effect_class": session.plan.side_effect_class,
        "current_budget_ceiling": session.plan.maximum_budget,
    }
    values.update(overrides)
    session.begin_execution(**values)  # type: ignore[arg-type]


def _result(session: GoalExecutionSession, **overrides: object) -> ExecutionResult:
    values: dict[str, object] = {
        "result_id": "result-synthetic-v1",
        "item_id": session.plan.item_id,
        "plan_digest": session.plan.digest,
        "implementer_actor": session.delegation.implementer_actor,
        "functional_commit": FUNCTIONAL_COMMIT,
        "functional_tree": FUNCTIONAL_TREE,
        "test_result_digest": TEST_RESULT_DIGEST,
        "contract_versions": session.plan.contract_versions,
        "actual_permissions": session.plan.required_permissions,
        "side_effect_class": session.plan.side_effect_class,
        "used_budget": GoalBudget(token=0, cost_minor=0, time_seconds=10, steps=2),
        "tests_passed": True,
        "repository_clean": True,
    }
    values.update(overrides)
    return ExecutionResult(**values)  # type: ignore[arg-type]


def _isolation(
    session: GoalExecutionSession, **overrides: object
) -> ReviewWorkspaceIsolation:
    assert session.execution_result is not None
    result = session.execution_result
    values: dict[str, object] = {
        "evidence_id": "review-isolation-synthetic-v1",
        "reviewer_actor": session.delegation.reviewer_actor,
        "implementation_workspace_digest": canonical_digest(
            {"workspace": "implementation"}
        ),
        "review_workspace_digest": canonical_digest({"workspace": "review"}),
        "functional_commit": result.functional_commit,
        "functional_tree": result.functional_tree,
    }
    values.update(overrides)
    return ReviewWorkspaceIsolation(**values)  # type: ignore[arg-type]


def _review(
    session: GoalExecutionSession,
    *,
    isolation: ReviewWorkspaceIsolation | None = None,
    **overrides: object,
) -> ReviewRecord:
    assert session.execution_result is not None
    result = session.execution_result
    isolation = isolation or _isolation(session)
    values: dict[str, object] = {
        "review_id": "review-synthetic-v1",
        "item_id": result.item_id,
        "reviewer_actor": session.delegation.reviewer_actor,
        "functional_commit": result.functional_commit,
        "functional_tree": result.functional_tree,
        "test_result_digest": result.test_result_digest,
        "acceptance_contract_digest": session.acceptance.digest,
        "isolation_evidence_digest": isolation.digest,
        "contract_versions": result.contract_versions,
        "disposition": "accepted",
    }
    values.update(overrides)
    return ReviewRecord(**values)  # type: ignore[arg-type]


def _through_execution(
    session: GoalExecutionSession,
    isolation: ReviewWorkspaceIsolation | None = None,
) -> None:
    _approve(session)
    _begin(session)
    identity: dict[str, object] = {}
    if isolation is not None:
        identity = {
            "functional_commit": isolation.functional_commit,
            "functional_tree": isolation.functional_tree,
        }
    session.record_execution(_result(session, **identity))


def _through_review(
    session: GoalExecutionSession,
    workspaces: tuple[Path, Path, ReviewWorkspaceIsolation],
) -> None:
    implementation, review_worktree, isolation = workspaces
    _through_execution(session, isolation)
    session.submit_review(
        _review(session, isolation=isolation),
        review_worktree=review_worktree,
        implementation_worktree=implementation,
    )


def test_contracts_are_versioned_and_default_to_advisory() -> None:
    policy = CtoModePolicy()
    profile = OrchestratorProfile(
        profile_id="default-cto",
        application_id="stateport.development-reference",
        orchestrator_actor="orchestrator",
    )
    assert policy.to_dict()["formatVersion"] == CTO_MODE_POLICY_FORMAT
    assert profile.to_dict()["formatVersion"] == ORCHESTRATOR_PROFILE_FORMAT
    assert policy.default_mode is OrchestratorMode.ADVISORY
    assert profile.mode is OrchestratorMode.ADVISORY
    assert profile.capability == "goal_execution"
    assert [item.value for item in policy.allowed_modes] == [
        "off",
        "advisory",
        "assisted",
        "managed_approved_queue",
    ]
    assert policy.maximum_active_items == 1
    assert policy.routing_deviation_invalidates_output is False


def test_natural_language_is_proposal_only_and_bootstrap_is_offline_deterministic() -> (
    None
):
    session = _contracts(mode=OrchestratorMode.ADVISORY)
    manifest = session.bootstrap.manifest
    proposal = session.bootstrap.proposal
    assert manifest.to_dict()["formatVersion"] == PROJECT_BOOTSTRAP_FORMAT
    assert proposal.to_dict()["formatVersion"] == GOAL_PROPOSAL_FORMAT
    assert manifest.intent_digest.startswith("sha256:")
    assert (
        manifest.intent_digest == proposal.intent_digest == session.plan.intent_digest
    )
    assert manifest.originating_mode is OrchestratorMode.ADVISORY
    assert proposal.originating_mode is OrchestratorMode.ADVISORY
    assert session.plan.originating_mode is OrchestratorMode.ADVISORY
    assert (
        manifest.orchestrator_profile_digest
        == proposal.orchestrator_profile_digest
        == session.plan.orchestrator_profile_digest
        == session.profile.digest
    )
    assert manifest.proposal_only is True
    assert manifest.network_used is False
    assert manifest.canonical_state_effect == "none"
    assert manifest.repository_relative_path == "synthetic-reference"
    assert len(manifest.goal_items) == 3
    assert all(
        item.to_dict()["formatVersion"] == GOAL_ITEM_FORMAT
        for item in manifest.goal_items
    )
    assert proposal.approval_status == "unapproved"
    assert proposal.next_item_requires_new_approval is True

    again = _contracts(mode=OrchestratorMode.ADVISORY)
    assert again.bootstrap.manifest.digest == manifest.digest
    assert again.bootstrap.proposal.digest == proposal.digest


def test_off_mode_does_not_even_prepare_an_orchestrator_proposal() -> None:
    intent = GoalExecutionIntent(
        intent_id="off-intent",
        application_id="stateport.development-reference",
        instance_id="fixture-instance",
        requested_by="operator",
        text="Inspect this project.",
        requested_mode=OrchestratorMode.OFF,
    )
    profile = OrchestratorProfile(
        profile_id="off-profile",
        application_id=intent.application_id,
        orchestrator_actor="orchestrator",
        mode=OrchestratorMode.OFF,
    )
    with pytest.raises(GoalContractError, match="off mode"):
        prepare_project_bootstrap(
            intent=intent,
            repo_root=ROOT / "fixtures" / "apps" / "synthetic-reference",
            trusted_root=ROOT / "fixtures" / "apps",
            base_commit=BASE_COMMIT,
            base_tree=BASE_TREE,
            proposed_by="orchestrator",
            profile=profile,
        )


def test_bootstrap_rejects_untrusted_path_and_credential_shaped_fields(
    tmp_path: Path,
) -> None:
    intent = GoalExecutionIntent(
        intent_id="unsafe-intent",
        application_id="stateport.synthetic-reference",
        instance_id="fixture-instance",
        requested_by="operator",
        text="Inspect this project.",
    )
    profile = OrchestratorProfile(
        profile_id="fixture-profile",
        application_id=intent.application_id,
        orchestrator_actor="orchestrator",
        mode=intent.requested_mode,
    )
    with pytest.raises(GoalContractError, match="trusted fixture root"):
        prepare_project_bootstrap(
            intent=intent,
            repo_root=ROOT,
            trusted_root=ROOT / "fixtures" / "apps",
            base_commit=BASE_COMMIT,
            base_tree=BASE_TREE,
            proposed_by="orchestrator",
            profile=profile,
        )

    trusted = tmp_path / "fixtures"
    fixture = trusted / "synthetic-reference"
    shutil.copytree(ROOT / "fixtures" / "apps" / "synthetic-reference", fixture)
    application = yaml.safe_load(
        (fixture / "application.yaml").read_text(encoding="utf-8")
    )
    application["apiKey"] = "not-a-real-secret"
    (fixture / "application.yaml").write_text(
        yaml.safe_dump(application), encoding="utf-8"
    )
    with pytest.raises(GoalContractError, match="credential-like field"):
        prepare_project_bootstrap(
            intent=intent,
            repo_root=fixture,
            trusted_root=trusted,
            base_commit=BASE_COMMIT,
            base_tree=BASE_TREE,
            proposed_by="orchestrator",
            profile=profile,
        )


def test_bootstrap_binds_requested_identity_to_declared_application() -> None:
    intent = GoalExecutionIntent(
        intent_id="mismatched-application-intent",
        application_id="stateport.development-reference",
        instance_id="fixture-instance",
        requested_by="operator",
        text="Inspect this project.",
    )
    profile = OrchestratorProfile(
        profile_id="mismatched-application-profile",
        application_id=intent.application_id,
        orchestrator_actor="orchestrator",
        mode=intent.requested_mode,
    )
    with pytest.raises(GoalContractError, match="requested application"):
        prepare_project_bootstrap(
            intent=intent,
            repo_root=ROOT / "fixtures" / "apps" / "synthetic-reference",
            trusted_root=ROOT / "fixtures" / "apps",
            base_commit=BASE_COMMIT,
            base_tree=BASE_TREE,
            proposed_by="orchestrator",
            profile=profile,
        )

def test_default_advisory_mode_refuses_execution_approval() -> None:
    session = _contracts(mode=OrchestratorMode.ADVISORY)
    with pytest.raises(GovernanceRefusal) as failure:
        _approve(session)
    assert failure.value.code == "mode_does_not_permit_execution"
    assert session.state is GoalExecutionState.PROPOSAL_READY
    assert session.approval is None


def test_application_descriptor_cannot_self_grant_cto_execution() -> None:
    with pytest.raises(ValueError, match="independently resolved goal capabilities"):
        _contracts(effective_capabilities=frozenset({"goal_execution"}))


def test_domain_neutral_goal_profile_requires_no_cto_capability() -> None:
    session = _contracts(
        capability="goal_execution",
        effective_capabilities=frozenset({"goal_execution"}),
    )
    assert session.profile.required_capabilities == ("goal_execution",)
    assert session.state is GoalExecutionState.PROPOSAL_READY

    profiles = (
        OrchestratorProfile(
            profile_id="study-planner-v1",
            application_id="studydd",
            orchestrator_actor="study-planner",
            capability="goal_execution",
            goal_domain="study",
        ),
        OrchestratorProfile(
            profile_id="class-planner-v1",
            application_id="classdd",
            orchestrator_actor="class-planner",
            capability="goal_execution",
            goal_domain="classroom",
        ),
    )
    assert {profile.goal_domain for profile in profiles} == {"study", "classroom"}
    assert all(
        profile.required_capabilities == ("goal_execution",) for profile in profiles
    )


def test_studystate_and_classstate_domain_views_do_not_expose_cto_ui() -> None:
    registry = ExperienceRegistry(ROOT)
    study = registry.get("studydd")
    assert study is not None and study.display_name == "StudyState"
    class_source = yaml.safe_load(
        (ROOT / "fixtures" / "application-experiences" / "study-state.yaml").read_text(
            encoding="utf-8"
        )
    )
    class_source.update(
        {
            "applicationId": "classdd",
            "displayName": "ClassState",
            "description": "A classroom application with governed learning goals.",
            "legacyAliases": ["ClassDD"],
        }
    )
    classroom = ApplicationExperienceDescriptor.from_mapping(class_source)
    for descriptor in (study, classroom):
        assert "goal_execution" in {
            capability.value for capability in descriptor.capabilities
        }
        assert "cto_orchestration" not in {
            capability.value for capability in descriptor.capabilities
        }
        assert all(
            control.capability.value != "cto_orchestration"
            for control in descriptor.advanced_controls
        )


def test_begin_execution_refuses_an_unapproved_item() -> None:
    session = _contracts()
    with pytest.raises(GovernanceRefusal) as failure:
        _begin(session)
    assert failure.value.code == "unapproved_item"
    assert failure.value.terminal is False


@pytest.mark.parametrize(
    "actor",
    ["cto-orchestrator", "bounded-implementer", "independent-reviewer"],
)
def test_self_approval_is_forbidden_even_when_actor_claims_admin(actor: str) -> None:
    session = _contracts()
    with pytest.raises(GovernanceRefusal) as failure:
        _approve(session, actor=actor, administrator=True)
    assert failure.value.code == "self_approval_forbidden"
    assert session.approval is None


def test_ambiguity_is_a_terminal_stop() -> None:
    session = _contracts(ambiguous=True)
    with pytest.raises(GovernanceRefusal) as failure:
        _approve(session)
    assert failure.value.code == "ambiguous_scope"
    assert failure.value.terminal is True
    assert session.state is GoalExecutionState.STOPPED


@pytest.mark.parametrize(
    ("override", "code"),
    [
        ({"current_base_commit": "e" * 40}, "base_drift"),
        (
            {"actual_permissions": ("project.read", "project.write")},
            "permission_increase",
        ),
        ({"side_effect_class": "external"}, "external_side_effect"),
        (
            {
                "current_budget_ceiling": GoalBudget(
                    token=0, cost_minor=0, time_seconds=5, steps=1
                )
            },
            "budget_exceeded",
        ),
        (
            {"current_policy_digest": canonical_digest({"changed": "policy"})},
            "policy_drift",
        ),
        ({"ambiguity_detected": True}, "ambiguous_scope"),
    ],
)
def test_execution_stops_on_drift_increase_effect_budget_or_ambiguity(
    override: dict[str, object], code: str
) -> None:
    session = _contracts()
    _approve(session)
    with pytest.raises(GovernanceRefusal) as failure:
        _begin(session, **override)
    assert failure.value.code == code
    assert failure.value.terminal is True
    assert session.state is GoalExecutionState.STOPPED


def test_one_item_boundary_rejects_duplicate_approval() -> None:
    session = _contracts(mode=OrchestratorMode.MANAGED_APPROVED_QUEUE)
    _approve(session)
    with pytest.raises(GovernanceRefusal) as failure:
        _approve(session, actor="second-approver")
    assert failure.value.code == "invalid_state_transition"
    assert session.profile.maximum_active_items == 1


def test_instance_scoped_approval_lease_is_atomic_across_sessions() -> None:
    leases = InstanceApprovalLeaseRegistry()
    sessions = (
        _contracts(
            mode=OrchestratorMode.MANAGED_APPROVED_QUEUE,
            approval_leases=leases,
        ),
        _contracts(
            mode=OrchestratorMode.MANAGED_APPROVED_QUEUE,
            approval_leases=leases,
        ),
    )
    barrier = threading.Barrier(2)
    result_lock = threading.Lock()
    outcomes: list[tuple[int, str]] = []

    def attempt(index: int) -> None:
        barrier.wait(timeout=5)
        try:
            _approve(sessions[index], actor=f"operator-approver-{index}")
            outcome = "approved"
        except GovernanceRefusal as exc:
            outcome = exc.code
        with result_lock:
            outcomes.append((index, outcome))

    threads = tuple(
        threading.Thread(target=attempt, args=(index,)) for index in range(2)
    )
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert all(not thread.is_alive() for thread in threads)
    assert sorted(outcome for _, outcome in outcomes) == [
        "approved",
        "instance_approval_conflict",
    ]
    winner_index = next(index for index, outcome in outcomes if outcome == "approved")
    winner = sessions[winner_index]
    loser = sessions[1 - winner_index]
    assert winner.approval is not None and winner.instance_lease is not None
    assert loser.approval is None and loser.instance_lease is None
    assert (
        leases.active_for(winner.plan.application_id, winner.plan.instance_id)
        == winner.instance_lease
    )
    assert winner.approval.instance_lease_id == winner.instance_lease.lease_id


def test_default_sessions_share_the_instance_approval_boundary() -> None:
    source = _contracts(mode=OrchestratorMode.ASSISTED)

    def session() -> GoalExecutionSession:
        return GoalExecutionSession(
            profile=source.profile,
            policy=source.policy,
            bootstrap=source.bootstrap,
            plan=source.plan,
            delegation=source.delegation,
            acceptance=source.acceptance,
            review_requirement=source.review_requirement,
            effective_capabilities=frozenset(source.effective_capabilities),
        )

    first = session()
    second = session()
    _approve(first, actor="first-operator")
    with pytest.raises(GovernanceRefusal) as conflict:
        _approve(second, actor="second-operator")
    assert conflict.value.code == "instance_approval_conflict"
    with pytest.raises(GovernanceRefusal) as stopped:
        _begin(first, current_base_commit="e" * 40)
    assert stopped.value.code == "base_drift"
    assert first.instance_lease is None

    _approve(second, actor="second-operator")
    assert second.approval is not None
    with pytest.raises(GovernanceRefusal):
        _begin(second, current_base_commit="e" * 40)


def test_advisory_artifacts_cannot_be_reused_for_assisted_execution() -> None:
    advisory = _contracts(mode=OrchestratorMode.ADVISORY)
    escalated_profile = replace(
        advisory.profile,
        mode=OrchestratorMode.ASSISTED,
    )
    with pytest.raises(ValueError, match="fresh governed proposal"):
        GoalExecutionSession(
            profile=escalated_profile,
            policy=advisory.policy,
            bootstrap=advisory.bootstrap,
            plan=advisory.plan,
            delegation=advisory.delegation,
            acceptance=advisory.acceptance,
            review_requirement=advisory.review_requirement,
            effective_capabilities=frozenset(advisory.effective_capabilities),
            approval_leases=InstanceApprovalLeaseRegistry(),
        )

    assisted = _contracts(mode=OrchestratorMode.ASSISTED)
    proposal = assisted.bootstrap.proposal
    assert assisted.bootstrap.manifest.intent_digest == proposal.intent_digest
    assert proposal.intent_digest == assisted.plan.intent_digest
    assert proposal.originating_mode is OrchestratorMode.ASSISTED
    assert assisted.plan.originating_mode is OrchestratorMode.ASSISTED
    assert proposal.orchestrator_profile_digest == assisted.profile.digest
    assert assisted.plan.orchestrator_profile_digest == assisted.profile.digest
    _approve(assisted)
    assert assisted.approval is not None
    assert assisted.approval.intent_digest == assisted.plan.intent_digest
    assert assisted.approval.originating_mode is OrchestratorMode.ASSISTED


@pytest.mark.parametrize(
    "field",
    [
        "reviewer_actor",
        "functional_commit",
        "functional_tree",
        "test_result_digest",
        "acceptance_contract_digest",
        "contract_versions",
    ],
)
def test_review_requires_independent_exact_identity(
    field: str,
    verified_review_workspaces: tuple[Path, Path, ReviewWorkspaceIsolation],
) -> None:
    session = _contracts()
    implementation, review_worktree, isolation = verified_review_workspaces
    _through_execution(session, isolation)
    replacements: dict[str, object] = {
        "reviewer_actor": "unexpected-reviewer",
        "functional_commit": "e" * 40,
        "functional_tree": "f" * 40,
        "test_result_digest": canonical_digest({"different": True}),
        "acceptance_contract_digest": canonical_digest({"different": "contract"}),
        "contract_versions": ("stateport.incompatible/v1",),
    }
    with pytest.raises(GovernanceRefusal) as failure:
        session.submit_review(
            _review(
                session,
                isolation=isolation,
                **{field: replacements[field]},
            ),
            review_worktree=review_worktree,
            implementation_worktree=implementation,
        )
    assert failure.value.code in {"reviewer_not_independent", "review_binding_mismatch"}
    assert failure.value.terminal is True
    assert session.state is GoalExecutionState.STOPPED


def test_critical_review_failure_stops_and_cannot_close(
    verified_review_workspaces: tuple[Path, Path, ReviewWorkspaceIsolation],
) -> None:
    session = _contracts()
    implementation, review_worktree, isolation = verified_review_workspaces
    _through_execution(session, isolation)
    review = _review(
        session,
        isolation=isolation,
        disposition="rejected_with_reproduced_defects",
        critical_findings=("reproducer: exact plan digest is not preserved",),
    )
    with pytest.raises(GovernanceRefusal) as failure:
        session.submit_review(
            review,
            review_worktree=review_worktree,
            implementation_worktree=implementation,
        )
    assert failure.value.code == "critical_review_failed"
    assert session.state is GoalExecutionState.STOPPED
    with pytest.raises(GovernanceRefusal, match="operation requires"):
        session.close(decided_by="stateport-governor")


def test_review_contract_requires_clean_detached_separate_ownership() -> None:
    session = _contracts()
    _through_execution(session)
    with pytest.raises(GoalContractError, match="clean workspace"):
        _review(session, workspace_clean=False)
    with pytest.raises(GoalContractError, match="separate ownership"):
        _review(session, owned_original_implementation=True)
    with pytest.raises(GoalContractError, match="exact clean detached read-only"):
        _review(session, workspace_identity="implementation-worktree")
    assert (
        session.review_requirement.workspace_isolation
        == "clean_detached_read_only_worktree"
    )


def test_review_submission_requires_cross_bound_isolation_evidence(
    verified_review_workspaces: tuple[Path, Path, ReviewWorkspaceIsolation],
) -> None:
    session = _contracts()
    implementation, review_worktree, isolation = verified_review_workspaces
    _through_execution(session, isolation)
    different_workspace = replace(
        isolation,
        review_workspace_digest=canonical_digest(
            {"workspace": "different-review-worktree"}
        ),
    )
    review = _review(session, isolation=different_workspace)
    with pytest.raises(GovernanceRefusal) as failure:
        session.submit_review(
            review,
            review_worktree=review_worktree,
            implementation_worktree=implementation,
        )
    assert failure.value.code == "review_binding_mismatch"
    assert session.state is GoalExecutionState.STOPPED
    assert session.instance_lease is None


def test_review_submission_reinspects_instead_of_trusting_prior_evidence(
    verified_review_workspaces: tuple[Path, Path, ReviewWorkspaceIsolation],
) -> None:
    session = _contracts()
    implementation, review_worktree, isolation = verified_review_workspaces
    _through_execution(session, isolation)
    feature = review_worktree / "feature.txt"
    feature.chmod(feature.stat().st_mode | stat.S_IWUSR)

    with pytest.raises(GovernanceRefusal) as failure:
        session.submit_review(
            _review(session, isolation=isolation),
            review_worktree=review_worktree,
            implementation_worktree=implementation,
        )
    assert failure.value.code == "review_isolation_invalid"
    assert failure.value.terminal is True
    assert session.state is GoalExecutionState.STOPPED
    assert session.instance_lease is None


def test_stateport_verifies_concrete_clean_detached_read_only_worktree(
    tmp_path: Path,
) -> None:
    implementation = tmp_path / "implementation"
    review = tmp_path / "review"
    _git_test_command("git", "init", "--initial-branch=main", str(implementation))
    (implementation / "feature.txt").write_text("accepted\n", encoding="utf-8")
    _git_test_command("git", "-C", str(implementation), "add", "feature.txt")
    _git_test_command(
        "git", "-C", str(implementation), "commit", "-m", "accepted feature"
    )
    commit = _git_test_command(
        "git", "-C", str(implementation), "rev-parse", "HEAD"
    )
    tree = _git_test_command(
        "git", "-C", str(implementation), "rev-parse", "HEAD^{tree}"
    )
    _git_test_command("git", "clone", "--no-local", str(implementation), str(review))

    with pytest.raises(GoalContractError, match="detached"):
        verify_review_workspace(
            review_worktree=review,
            implementation_worktree=implementation,
            reviewer_actor="independent-reviewer",
            expected_commit=commit,
            expected_tree=tree,
        )
    _git_test_command("git", "-C", str(review), "switch", "--detach", commit)
    with pytest.raises(GoalContractError, match="expected commit and tree"):
        verify_review_workspace(
            review_worktree=review,
            implementation_worktree=implementation,
            reviewer_actor="independent-reviewer",
            expected_commit="e" * 40,
            expected_tree=tree,
        )
    review_alias = tmp_path / "review-alias"
    review_alias.symlink_to(review, target_is_directory=True)
    with pytest.raises(GoalContractError, match="symlinks"):
        verify_review_workspace(
            review_worktree=review_alias,
            implementation_worktree=implementation,
            reviewer_actor="independent-reviewer",
            expected_commit=commit,
            expected_tree=tree,
        )
    with pytest.raises(GoalContractError, match="filesystem read-only"):
        verify_review_workspace(
            review_worktree=review,
            implementation_worktree=implementation,
            reviewer_actor="independent-reviewer",
            expected_commit=commit,
            expected_tree=tree,
        )

    entries = [review, *review.rglob("*")]
    for path in entries:
        path.chmod(path.stat().st_mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
    try:
        evidence = verify_review_workspace(
            review_worktree=review,
            implementation_worktree=implementation,
            reviewer_actor="independent-reviewer",
            expected_commit=commit,
            expected_tree=tree,
        )
    finally:
        for path in entries:
            path.chmod(path.stat().st_mode | stat.S_IWUSR)

    assert evidence.to_dict()["formatVersion"] == REVIEW_ISOLATION_FORMAT
    assert evidence.functional_commit == commit
    assert evidence.functional_tree == tree
    assert evidence.workspace_isolation == "clean_detached_read_only_worktree"


def test_review_verification_ignores_local_fsmonitor_and_hashes_exact_tree_bytes(
    tmp_path: Path,
) -> None:
    implementation = tmp_path / "implementation"
    review = tmp_path / "review"
    _git_test_command("git", "init", "--initial-branch=main", str(implementation))
    (implementation / "feature.txt").write_text("accepted\n", encoding="utf-8")
    _git_test_command("git", "-C", str(implementation), "add", "feature.txt")
    _git_test_command("git", "-C", str(implementation), "commit", "-m", "accepted feature")
    commit = _git_test_command("git", "-C", str(implementation), "rev-parse", "HEAD")
    tree = _git_test_command("git", "-C", str(implementation), "rev-parse", "HEAD^{tree}")
    _git_test_command("git", "clone", "--no-local", str(implementation), str(review))
    _git_test_command("git", "-C", str(review), "switch", "--detach", commit)

    monitor = tmp_path / "empty-fsmonitor.sh"
    monitor.write_text("#!/bin/sh\nprintf 'stateport-token\\n'\n", encoding="utf-8")
    monitor.chmod(0o755)
    _git_test_command("git", "-C", str(review), "config", "core.fsmonitor", str(monitor))
    (review / "feature.txt").write_text("tampered\n", encoding="utf-8")
    entries = [review, *review.rglob("*")]
    for path in entries:
        path.chmod(path.stat().st_mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
    try:
        with pytest.raises(GoalContractError, match="content differs"):
            verify_review_workspace(
                review_worktree=review,
                implementation_worktree=implementation,
                reviewer_actor="independent-reviewer",
                expected_commit=commit,
                expected_tree=tree,
            )
    finally:
        for path in entries:
            path.chmod(path.stat().st_mode | stat.S_IWUSR)


def test_review_verification_ignores_local_replace_refs(
    tmp_path: Path,
) -> None:
    implementation = tmp_path / "implementation"
    review = tmp_path / "review"
    _git_test_command("git", "init", "--initial-branch=main", str(implementation))
    feature = implementation / "feature.txt"
    feature.write_text("original\n", encoding="utf-8")
    _git_test_command("git", "-C", str(implementation), "add", "feature.txt")
    _git_test_command("git", "-C", str(implementation), "commit", "-m", "original")
    original_commit = _git_test_command(
        "git", "-C", str(implementation), "rev-parse", "HEAD"
    )
    feature.write_text("replacement\n", encoding="utf-8")
    _git_test_command("git", "-C", str(implementation), "commit", "-am", "replacement")
    replacement_commit = _git_test_command(
        "git", "-C", str(implementation), "rev-parse", "HEAD"
    )
    replacement_tree = _git_test_command(
        "git", "-C", str(implementation), "rev-parse", "HEAD^{tree}"
    )
    _git_test_command("git", "clone", "--no-local", str(implementation), str(review))
    _git_test_command("git", "-C", str(review), "switch", "--detach", original_commit)
    _git_test_command(
        "git", "-C", str(review), "replace", original_commit, replacement_commit
    )
    _git_test_command("git", "-C", str(review), "reset", "--hard", original_commit)
    assert _git_test_command("git", "-C", str(review), "rev-parse", "HEAD") == original_commit
    assert (
        _git_test_command("git", "-C", str(review), "rev-parse", "HEAD^{tree}")
        == replacement_tree
    )

    entries = [review, *review.rglob("*")]
    for path in entries:
        path.chmod(path.stat().st_mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
    try:
        with pytest.raises(GoalContractError, match="expected commit and tree"):
            verify_review_workspace(
                review_worktree=review,
                implementation_worktree=implementation,
                reviewer_actor="independent-reviewer",
                expected_commit=original_commit,
                expected_tree=replacement_tree,
            )
    finally:
        for path in entries:
            path.chmod(path.stat().st_mode | stat.S_IWUSR)


def test_routing_deviation_is_retained_not_invalidated_and_receipt_stops_queue(
    verified_review_workspaces: tuple[Path, Path, ReviewWorkspaceIsolation],
) -> None:
    session = _contracts(
        intended_profile="terra-high", actual_profile="platform-profile-unexposed"
    )
    assert session.delegation.routing_deviated is True
    assert session.delegation.routing_deviation_invalidates_output is False
    _through_review(session, verified_review_workspaces)
    closure, receipt = session.close(decided_by="stateport-governor")
    assert closure.to_dict()["formatVersion"] == "stateport.closure-decision/v1"
    assert receipt.to_dict()["formatVersion"] == GOAL_RECEIPT_FORMAT
    assert receipt.routing_deviation_retained is True
    assert receipt.next_item_status == "stopped_unapproved"
    assert receipt.canonical_state_effect == "none"
    assert session.state is GoalExecutionState.CLOSED
    assert session.instance_lease is None
    assert session.snapshot()["backgroundLoop"] is False
    with pytest.raises(GovernanceRefusal) as failure:
        session.request_next_item("synthetic-state-integrity")
    assert failure.value.code == "next_item_unapproved"
    assert session.state is GoalExecutionState.CLOSED


def test_no_routing_deviation_needs_no_duplicate_run_or_reason(
    verified_review_workspaces: tuple[Path, Path, ReviewWorkspaceIsolation],
) -> None:
    session = _contracts(intended_profile="terra-high", actual_profile="terra-high")
    assert session.delegation.routing_deviated is False
    assert session.delegation.routing_deviation_reason is None
    _through_review(session, verified_review_workspaces)
    _, receipt = session.close(decided_by="stateport-governor")
    assert receipt.routing_deviation_retained is False


def test_slice_and_acceptance_contract_bind_same_exact_versions() -> None:
    session = _contracts()
    assert session.plan.to_dict()["formatVersion"] == SLICE_PLAN_FORMAT
    assert session.acceptance.to_dict()["formatVersion"] == ACCEPTANCE_CONTRACT_FORMAT
    assert (
        session.review_requirement.to_dict()["formatVersion"]
        == REVIEW_REQUIREMENT_FORMAT
    )
    assert tuple(session.plan.contract_versions) == tuple(
        session.acceptance.required_contract_versions
    )
    assert (
        session.plan.item_id
        == session.acceptance.item_id
        == session.review_requirement.item_id
    )
    assert session.bootstrap.manifest.intent_digest != session.plan.digest


def test_cto_control_is_development_only_and_studystate_never_requests_it() -> None:
    registry = ExperienceRegistry(ROOT)
    policy = load_experience_policy(
        ROOT / "config" / "application-experience-policy.yaml"
    )
    development = registry.get("stateport.development-reference")
    study = registry.get("studydd")
    assert development is not None and study is not None
    assert any(
        item.capability.value == "cto_orchestration"
        for item in development.advanced_controls
    )
    assert all(
        item.capability.value != "cto_orchestration" for item in study.advanced_controls
    )
    assert "cto_orchestration" not in {item.value for item in study.capabilities}
    resolved = registry.resolve(
        development.application_id,
        instance_grants=policy.grants_for(development.application_id),
        operator_permits=policy.operator_permits,
        runtime_capabilities=policy.runtime_capabilities,
        actor_permissions=policy.permissions_for("local_user"),
    )
    assert resolved is not None
    control = next(
        item
        for item in resolved["advancedControls"]
        if item["capability"] == "cto_orchestration"
    )
    assert control["visible"] is True
    assert control["status"] == "degraded"


def test_intent_contract_cannot_claim_execution_or_canonical_mutation() -> None:
    with pytest.raises(GoalContractError, match="proposal"):
        GoalExecutionIntent(
            intent_id="unsafe-intent",
            application_id="stateport.development-reference",
            instance_id="fixture-instance",
            requested_by="operator",
            text="Run everything.",
            proposal_only=False,
        )
    with pytest.raises(GoalContractError, match="proposal"):
        GoalExecutionIntent(
            intent_id="unsafe-intent",
            application_id="stateport.development-reference",
            instance_id="fixture-instance",
            requested_by="operator",
            text="Run everything.",
            canonical_state_effect="write",
        )
    intent = GoalExecutionIntent(
        intent_id="safe-intent",
        application_id="stateport.development-reference",
        instance_id="fixture-instance",
        requested_by="operator",
        text="Continue this project in CTO mode.",
    )
    assert intent.to_dict()["formatVersion"] == GOAL_EXECUTION_FORMAT
