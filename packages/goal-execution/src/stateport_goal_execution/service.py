"""In-memory state machine for one approved provider-free goal item.

The service validates evidence supplied by an execution adapter. It never
starts an agent, executes repository code, mutates files, or advances a queue.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import threading
from typing import Any, Callable

from .bootstrap import BootstrapProposal
from .contracts import (
    AcceptanceContract,
    ApprovalRecord,
    ClosureDecision,
    CtoModePolicy,
    DelegationPlan,
    ExecutionResult,
    GoalBudget,
    GoalExecutionReceipt,
    OrchestratorMode,
    OrchestratorProfile,
    ReviewRecord,
    ReviewRequirement,
    SAFE_SIDE_EFFECTS,
    SlicePlan,
    canonical_digest,
)
from .review_isolation import verify_review_workspace


class GoalExecutionState(str, Enum):
    PROPOSAL_READY = "proposal_ready"
    APPROVED = "approved"
    EXECUTING = "executing"
    AWAITING_REVIEW = "awaiting_independent_review"
    REVIEWED = "independently_reviewed"
    CLOSED = "closed"
    STOPPED = "stopped"


class GovernanceRefusal(RuntimeError):
    """Fail-closed refusal with a stable machine-readable reason."""

    def __init__(self, code: str, message: str, *, terminal: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.terminal = terminal


@dataclass(frozen=True)
class StopRecord:
    code: str
    message: str
    state_before_stop: str

    def to_dict(self) -> dict[str, str]:
        return {
            "formatVersion": "stateport.goal-execution-stop/v1",
            "code": self.code,
            "message": self.message,
            "stateBeforeStop": self.state_before_stop,
        }


@dataclass(frozen=True)
class InstanceApprovalLease:
    """One atomic instance-scoped approval lease owned by a session."""

    lease_id: str
    generation: int
    application_id: str
    instance_id: str
    plan_digest: str
    base_commit: str
    base_tree: str
    state_snapshot_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": "stateport.goal-instance-approval-lease/v1",
            "leaseId": self.lease_id,
            "generation": self.generation,
            "applicationId": self.application_id,
            "instanceId": self.instance_id,
            "planDigest": self.plan_digest,
            "baseCommit": self.base_commit,
            "baseTree": self.base_tree,
            "stateSnapshotDigest": self.state_snapshot_digest,
        }


class InstanceApprovalLeaseRegistry:
    """Process-shared atomic boundary for one active approved instance item."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._active: dict[tuple[str, str], tuple[InstanceApprovalLease, str]] = {}
        self._generations: dict[tuple[str, str], int] = {}
        self._owner_sequence = 0

    def allocate_owner(self) -> str:
        with self._lock:
            self._owner_sequence += 1
            return f"goal-session-{self._owner_sequence}"

    def acquire(
        self,
        *,
        owner: str,
        application_id: str,
        instance_id: str,
        plan_digest: str,
        base_commit: str,
        base_tree: str,
        state_snapshot_digest: str,
    ) -> InstanceApprovalLease | None:
        key = (application_id, instance_id)
        with self._lock:
            if key in self._active:
                return None
            generation = self._generations.get(key, 0) + 1
            self._generations[key] = generation
            seed = {
                "applicationId": application_id,
                "instanceId": instance_id,
                "generation": generation,
                "planDigest": plan_digest,
                "baseCommit": base_commit,
                "baseTree": base_tree,
                "stateSnapshotDigest": state_snapshot_digest,
            }
            lease = InstanceApprovalLease(
                lease_id="instance-lease-"
                + canonical_digest(seed).split(":", 1)[1][:24],
                generation=generation,
                application_id=application_id,
                instance_id=instance_id,
                plan_digest=plan_digest,
                base_commit=base_commit,
                base_tree=base_tree,
                state_snapshot_digest=state_snapshot_digest,
            )
            self._active[key] = (lease, owner)
            return lease

    def is_active(self, lease: InstanceApprovalLease, *, owner: str) -> bool:
        key = (lease.application_id, lease.instance_id)
        with self._lock:
            return self._active.get(key) == (lease, owner)

    def release(self, lease: InstanceApprovalLease, *, owner: str) -> bool:
        key = (lease.application_id, lease.instance_id)
        with self._lock:
            if self._active.get(key) != (lease, owner):
                return False
            del self._active[key]
            return True

    def active_for(
        self, application_id: str, instance_id: str
    ) -> InstanceApprovalLease | None:
        with self._lock:
            current = self._active.get((application_id, instance_id))
            return current[0] if current is not None else None


_DEFAULT_INSTANCE_APPROVAL_LEASES = InstanceApprovalLeaseRegistry()


class GoalExecutionSession:
    """Govern exactly one proposed item through approval, review and receipt."""

    def __init__(
        self,
        *,
        profile: OrchestratorProfile,
        policy: CtoModePolicy,
        bootstrap: BootstrapProposal,
        plan: SlicePlan,
        delegation: DelegationPlan,
        acceptance: AcceptanceContract,
        review_requirement: ReviewRequirement,
        effective_capabilities: frozenset[str],
        approval_leases: InstanceApprovalLeaseRegistry | None = None,
    ) -> None:
        manifest = bootstrap.manifest
        proposal = bootstrap.proposal
        if profile.mode not in policy.allowed_modes:
            raise ValueError("orchestrator mode is not permitted by policy")
        if (
            profile.application_id != manifest.application_id
            or plan.application_id != manifest.application_id
        ):
            raise ValueError(
                "orchestrator, manifest and plan application identities differ"
            )
        if plan.instance_id != manifest.instance_id:
            raise ValueError("manifest and plan instance identities differ")
        if (
            plan.manifest_digest != manifest.digest
            or proposal.manifest_digest != manifest.digest
        ):
            raise ValueError(
                "bootstrap manifest identity does not match the proposal or slice"
            )
        if plan.proposal_digest != proposal.digest:
            raise ValueError("slice plan is not bound to the proposal")
        if not (
            manifest.intent_digest == proposal.intent_digest == plan.intent_digest
            and manifest.originating_mode
            is proposal.originating_mode
            is plan.originating_mode
            is profile.mode
            and manifest.orchestrator_profile_digest
            == proposal.orchestrator_profile_digest
            == plan.orchestrator_profile_digest
            == profile.digest
        ):
            raise ValueError(
                "originating intent, mode and profile require a fresh governed proposal"
            )
        if plan.item_id != proposal.recommended_item_id:
            raise ValueError(
                "this bounded session may contain only the recommended item"
            )
        selected_item = next(
            (item for item in manifest.goal_items if item.item_id == plan.item_id),
            None,
        )
        if selected_item is None:
            raise ValueError("slice item is not present in the bootstrap manifest")
        if selected_item.domain != profile.goal_domain:
            raise ValueError("orchestrator profile and goal item domains differ")
        if (
            delegation.item_id != plan.item_id
            or acceptance.item_id != plan.item_id
            or review_requirement.item_id != plan.item_id
        ):
            raise ValueError("goal execution contracts are bound to different items")
        if review_requirement.acceptance_contract_digest != acceptance.digest:
            raise ValueError(
                "review requirement is not bound to the acceptance contract"
            )
        if review_requirement.reviewer_actor != delegation.reviewer_actor:
            raise ValueError(
                "delegation and review requirement name different reviewers"
            )
        independent_roles = {
            profile.orchestrator_actor,
            plan.proposed_by,
            delegation.implementer_actor,
        }
        if delegation.reviewer_actor in independent_roles:
            raise ValueError(
                "independent reviewer may not own proposal, orchestration or implementation"
            )
        if tuple(acceptance.required_contract_versions) != tuple(
            plan.contract_versions
        ):
            raise ValueError("acceptance contract versions do not match the slice plan")
        missing_capabilities = set(profile.required_capabilities) - set(
            effective_capabilities
        )
        if missing_capabilities:
            raise ValueError(
                "independently resolved goal capabilities are required: "
                + ", ".join(sorted(missing_capabilities))
            )

        self.profile = profile
        self.policy = policy
        self.bootstrap = bootstrap
        self.plan = plan
        self.delegation = delegation
        self.acceptance = acceptance
        self.review_requirement = review_requirement
        self.effective_capabilities = tuple(sorted(effective_capabilities))
        self.effective_policy_digest = canonical_digest(
            {
                "goalExecutionPolicy": policy.to_dict(),
                "effectiveCapabilities": list(self.effective_capabilities),
            }
        )
        self._approval_leases = (
            approval_leases
            if approval_leases is not None
            else _DEFAULT_INSTANCE_APPROVAL_LEASES
        )
        self._lease_owner = self._approval_leases.allocate_owner()
        self.instance_lease: InstanceApprovalLease | None = None
        self.state = GoalExecutionState.PROPOSAL_READY
        self.approval: ApprovalRecord | None = None
        self.execution_result: ExecutionResult | None = None
        self.review: ReviewRecord | None = None
        self.closure: ClosureDecision | None = None
        self.receipt: GoalExecutionReceipt | None = None
        self.stop_record: StopRecord | None = None

    def _release_instance_lease(self) -> None:
        if self.instance_lease is None:
            return
        self._approval_leases.release(
            self.instance_lease,
            owner=self._lease_owner,
        )
        self.instance_lease = None

    def _require_instance_lease(self) -> InstanceApprovalLease:
        lease = self.instance_lease
        if lease is None or not self._approval_leases.is_active(
            lease,
            owner=self._lease_owner,
        ):
            self._refuse(
                "instance_approval_lease_lost",
                "the instance-scoped approval lease is no longer active",
                terminal=True,
            )
        assert lease is not None
        return lease

    def _refuse(self, code: str, message: str, *, terminal: bool = False) -> None:
        if terminal and self.state not in {
            GoalExecutionState.CLOSED,
            GoalExecutionState.STOPPED,
        }:
            prior = self.state.value
            self.state = GoalExecutionState.STOPPED
            self.stop_record = StopRecord(
                code=code, message=message, state_before_stop=prior
            )
            self._release_instance_lease()
        raise GovernanceRefusal(code, message, terminal=terminal)

    def _expect(self, expected: GoalExecutionState) -> None:
        if self.state is not expected:
            self._refuse(
                "invalid_state_transition",
                f"operation requires {expected.value}; current state is {self.state.value}",
            )

    def approve(
        self,
        *,
        actor: str,
        expected_plan_digest: str,
        current_base_commit: str,
        current_base_tree: str,
        current_state_snapshot_digest: str,
        approved_permissions: tuple[str, ...],
        approved_side_effect_class: str,
        approved_budget: GoalBudget,
        administrator: bool = False,
    ) -> ApprovalRecord:
        """Create one explicit approval; an admin flag never bypasses separation."""

        del administrator
        self._expect(GoalExecutionState.PROPOSAL_READY)
        if self.profile.mode in {OrchestratorMode.OFF, OrchestratorMode.ADVISORY}:
            self._refuse(
                "mode_does_not_permit_execution",
                f"{self.profile.mode.value} mode may propose but may not approve execution",
            )
        if self.bootstrap.proposal.ambiguities:
            self._refuse(
                "ambiguous_scope",
                "ambiguous scope requires human clarification",
                terminal=True,
            )
        if actor in {
            self.profile.orchestrator_actor,
            self.plan.proposed_by,
            self.delegation.implementer_actor,
            self.delegation.reviewer_actor,
        }:
            self._refuse(
                "self_approval_forbidden",
                "work owners and reviewers may not approve their own slice",
            )
        if expected_plan_digest != self.plan.digest:
            self._refuse(
                "plan_identity_mismatch", "approval does not bind the exact slice plan"
            )
        if (
            current_base_commit != self.plan.base_commit
            or current_base_tree != self.plan.base_tree
        ):
            self._refuse(
                "base_drift", "repository base changed before approval", terminal=True
            )
        if current_state_snapshot_digest != self.plan.state_snapshot_digest:
            self._refuse(
                "base_drift",
                "canonical state snapshot changed before approval",
                terminal=True,
            )
        requested_permissions = set(self.plan.required_permissions)
        approved = set(approved_permissions)
        if approved - requested_permissions:
            self._refuse(
                "permission_increase",
                "approval attempted to add permissions",
                terminal=True,
            )
        if approved != requested_permissions:
            self._refuse(
                "approval_binding_mismatch",
                "approval must bind the plan's exact permission set",
            )
        if approved_side_effect_class not in SAFE_SIDE_EFFECTS:
            self._refuse(
                "external_side_effect",
                "external or unknown effects require a different governed path",
                terminal=True,
            )
        if approved_side_effect_class != self.plan.side_effect_class:
            self._refuse(
                "approval_binding_mismatch",
                "approval must bind the plan's exact side-effect class",
            )
        if approved_budget != self.plan.maximum_budget:
            self._refuse(
                "approval_binding_mismatch",
                "approval must bind the plan's exact budget",
            )

        lease = self._approval_leases.acquire(
            owner=self._lease_owner,
            application_id=self.plan.application_id,
            instance_id=self.plan.instance_id,
            plan_digest=self.plan.digest,
            base_commit=current_base_commit,
            base_tree=current_base_tree,
            state_snapshot_digest=current_state_snapshot_digest,
        )
        if lease is None:
            self._refuse(
                "instance_approval_conflict",
                "another approved item already owns this instance",
            )
        self.instance_lease = lease
        approval_seed = {
            "plan": self.plan.digest,
            "intent": self.plan.intent_digest,
            "originatingMode": self.plan.originating_mode.value,
            "profile": self.profile.digest,
            "policy": self.effective_policy_digest,
            "delegation": self.delegation.digest,
            "acceptance": self.acceptance.digest,
            "actor": actor,
            "baseCommit": current_base_commit,
            "baseTree": current_base_tree,
            "state": current_state_snapshot_digest,
            "instanceLease": lease.to_dict(),
        }
        try:
            approval = ApprovalRecord(
                approval_id="approval-"
                + canonical_digest(approval_seed).split(":", 1)[1][:24],
                application_id=self.plan.application_id,
                instance_id=self.plan.instance_id,
                item_id=self.plan.item_id,
                plan_digest=self.plan.digest,
                intent_digest=self.plan.intent_digest,
                originating_mode=self.plan.originating_mode,
                orchestrator_profile_digest=self.profile.digest,
                policy_digest=self.effective_policy_digest,
                delegation_plan_digest=self.delegation.digest,
                acceptance_contract_digest=self.acceptance.digest,
                contract_versions=self.plan.contract_versions,
                approver_actor=actor,
                base_commit=current_base_commit,
                base_tree=current_base_tree,
                state_snapshot_digest=current_state_snapshot_digest,
                instance_lease_id=lease.lease_id,
                instance_lease_generation=lease.generation,
                approved_permissions=tuple(sorted(approved_permissions)),
                approved_side_effect_class=approved_side_effect_class,
                approved_budget=approved_budget,
            )
        except Exception:
            self._release_instance_lease()
            raise
        self.approval = approval
        self.state = GoalExecutionState.APPROVED
        return approval

    def begin_execution(
        self,
        *,
        actor: str,
        current_base_commit: str,
        current_base_tree: str,
        current_state_snapshot_digest: str,
        current_orchestrator_profile_digest: str,
        current_policy_digest: str,
        current_delegation_plan_digest: str,
        actual_permissions: tuple[str, ...],
        side_effect_class: str,
        current_budget_ceiling: GoalBudget,
        ambiguity_detected: bool = False,
    ) -> None:
        if self.approval is None:
            self._refuse(
                "unapproved_item", "execution requires an explicit exact approval"
            )
        self._expect(GoalExecutionState.APPROVED)
        assert self.approval is not None
        lease = self._require_instance_lease()
        if (
            lease.lease_id != self.approval.instance_lease_id
            or lease.generation != self.approval.instance_lease_generation
        ):
            self._refuse(
                "instance_approval_lease_lost",
                "approval and instance lease identities differ",
                terminal=True,
            )
        if actor != self.delegation.implementer_actor:
            self._refuse(
                "implementer_identity_mismatch",
                "execution actor does not match the delegation plan",
            )
        if ambiguity_detected:
            self._refuse(
                "ambiguous_scope", "execution discovered ambiguous scope", terminal=True
            )
        if (
            current_base_commit != self.approval.base_commit
            or current_base_tree != self.approval.base_tree
            or current_state_snapshot_digest != self.approval.state_snapshot_digest
        ):
            self._refuse(
                "base_drift",
                "approved repository or state identity drifted",
                terminal=True,
            )
        if (
            current_orchestrator_profile_digest
            != self.approval.orchestrator_profile_digest
            or current_policy_digest != self.approval.policy_digest
            or current_delegation_plan_digest != self.approval.delegation_plan_digest
        ):
            self._refuse(
                "policy_drift",
                "approved profile, policy or delegation identity drifted",
                terminal=True,
            )
        if set(actual_permissions) - set(self.approval.approved_permissions):
            self._refuse(
                "permission_increase",
                "execution attempted to gain permissions",
                terminal=True,
            )
        if (
            side_effect_class not in SAFE_SIDE_EFFECTS
            or side_effect_class != self.approval.approved_side_effect_class
        ):
            self._refuse(
                "external_side_effect",
                "execution side-effect boundary changed",
                terminal=True,
            )
        if not self.approval.approved_budget.fits_within(current_budget_ceiling):
            self._refuse(
                "budget_exceeded",
                "current budget no longer covers the approved slice",
                terminal=True,
            )
        self.state = GoalExecutionState.EXECUTING

    def record_execution(self, result: ExecutionResult) -> None:
        self._expect(GoalExecutionState.EXECUTING)
        assert self.approval is not None
        self._require_instance_lease()
        if (
            result.item_id != self.plan.item_id
            or result.plan_digest != self.plan.digest
        ):
            self._refuse(
                "execution_identity_mismatch",
                "execution result is not bound to the approved item and plan",
                terminal=True,
            )
        if result.implementer_actor != self.delegation.implementer_actor:
            self._refuse(
                "implementer_identity_mismatch",
                "execution result names an unexpected implementer",
                terminal=True,
            )
        if set(result.actual_permissions) - set(self.approval.approved_permissions):
            self._refuse(
                "permission_increase",
                "execution result records unapproved permissions",
                terminal=True,
            )
        if (
            result.external_side_effects_observed
            or result.side_effect_class not in SAFE_SIDE_EFFECTS
            or result.side_effect_class != self.approval.approved_side_effect_class
        ):
            self._refuse(
                "external_side_effect",
                "execution observed an unapproved external side effect",
                terminal=True,
            )
        if not result.used_budget.fits_within(self.approval.approved_budget):
            self._refuse(
                "budget_exceeded",
                "execution exceeded the approved budget",
                terminal=True,
            )
        if tuple(result.contract_versions) != tuple(self.plan.contract_versions):
            self._refuse(
                "contract_version_mismatch",
                "execution used different contract versions",
                terminal=True,
            )
        if not result.tests_passed or not result.repository_clean:
            self._refuse(
                "acceptance_failed",
                "execution did not pass validation with a clean repository",
                terminal=True,
            )
        self.execution_result = result
        self.state = GoalExecutionState.AWAITING_REVIEW

    def submit_review(
        self,
        review: ReviewRecord,
        *,
        review_worktree: Path,
        implementation_worktree: Path,
    ) -> None:
        self._expect(GoalExecutionState.AWAITING_REVIEW)
        assert self.execution_result is not None and self.approval is not None
        self._require_instance_lease()
        forbidden = {
            self.profile.orchestrator_actor,
            self.plan.proposed_by,
            self.delegation.implementer_actor,
            self.approval.approver_actor,
        }
        if (
            review.reviewer_actor in forbidden
            or review.reviewer_actor != self.review_requirement.reviewer_actor
        ):
            self._refuse(
                "reviewer_not_independent",
                "reviewer does not satisfy role separation",
                terminal=True,
            )
        try:
            isolation = verify_review_workspace(
                review_worktree=review_worktree,
                implementation_worktree=implementation_worktree,
                reviewer_actor=review.reviewer_actor,
                expected_commit=self.execution_result.functional_commit,
                expected_tree=self.execution_result.functional_tree,
            )
        except Exception:
            self._refuse(
                "review_isolation_invalid",
                "StatePort could not verify the required review-workspace isolation",
                terminal=True,
            )
        exact_binding = (
            review.item_id == self.execution_result.item_id
            and review.functional_commit == self.execution_result.functional_commit
            and review.functional_tree == self.execution_result.functional_tree
            and review.test_result_digest == self.execution_result.test_result_digest
            and review.acceptance_contract_digest == self.acceptance.digest
            and tuple(review.contract_versions)
            == tuple(self.execution_result.contract_versions)
            and review.isolation_evidence_digest == isolation.digest
            and isolation.reviewer_actor == review.reviewer_actor
            and isolation.functional_commit == review.functional_commit
            and isolation.functional_tree == review.functional_tree
            and isolation.workspace_isolation
            == self.review_requirement.workspace_isolation
        )
        if not exact_binding:
            self._refuse(
                "review_binding_mismatch",
                "review must bind the exact commit, tree, tests, acceptance contract and versions",
                terminal=True,
            )
        self.review = review
        if not review.accepted:
            self._refuse(
                "critical_review_failed",
                "independent critical review reproduced a defect",
                terminal=True,
            )
        self.state = GoalExecutionState.REVIEWED

    def close(
        self,
        *,
        decided_by: str,
        closure_guard: Callable[[], bool] | None = None,
    ) -> tuple[ClosureDecision, GoalExecutionReceipt]:
        self._expect(GoalExecutionState.REVIEWED)
        self._require_instance_lease()
        assert (
            self.approval is not None
            and self.execution_result is not None
            and self.review is not None
        )
        if decided_by in {
            self.profile.orchestrator_actor,
            self.plan.proposed_by,
            self.delegation.implementer_actor,
            self.review.reviewer_actor,
            self.approval.approver_actor,
        }:
            self._refuse(
                "closure_authority_not_independent",
                "closure authority must be independent of slice roles",
            )
        closure_seed = {
            "itemId": self.plan.item_id,
            "result": self.execution_result.digest,
            "review": self.review.digest,
            "decidedBy": decided_by,
        }
        closure = ClosureDecision(
            decision_id="closure-"
            + canonical_digest(closure_seed).split(":", 1)[1][:24],
            item_id=self.plan.item_id,
            decided_by=decided_by,
            status="closed",
            functional_commit=self.execution_result.functional_commit,
            functional_tree=self.execution_result.functional_tree,
            test_result_digest=self.execution_result.test_result_digest,
            review_digest=self.review.digest,
            reasons=(
                "acceptance criteria passed",
                "independent exact-identity review accepted",
            ),
        )
        receipt_seed = {
            "approval": self.approval.digest,
            "execution": self.execution_result.digest,
            "review": self.review.digest,
            "closure": closure.digest,
        }
        receipt = GoalExecutionReceipt(
            receipt_id="receipt-"
            + canonical_digest(receipt_seed).split(":", 1)[1][:24],
            application_id=self.plan.application_id,
            instance_id=self.plan.instance_id,
            item_id=self.plan.item_id,
            approval_digest=self.approval.digest,
            execution_result_digest=self.execution_result.digest,
            review_digest=self.review.digest,
            closure_decision_digest=closure.digest,
            routing_deviation_retained=self.delegation.routing_deviated,
        )
        if closure_guard is not None and not closure_guard():
            self._refuse(
                "base_drift",
                "repository identity changed at the closure boundary",
                terminal=True,
            )
        self.closure = closure
        self.receipt = receipt
        self.state = GoalExecutionState.CLOSED
        self._release_instance_lease()
        return closure, receipt

    def request_next_item(self, item_id: str) -> None:
        del item_id
        self._refuse(
            "next_item_unapproved",
            "the protocol stops before the next item; prepare and approve a fresh exact slice",
        )

    def stop(self, *, code: str, message: str) -> None:
        """Persist a terminal coordinator-observed stop and release its lease."""

        self._refuse(code, message, terminal=True)

    def snapshot(self) -> dict[str, Any]:
        return {
            "formatVersion": "stateport.goal-execution-session/v1",
            "state": self.state.value,
            "mode": self.profile.mode.value,
            "effectiveCapabilities": list(self.effective_capabilities),
            "effectivePolicyDigest": self.effective_policy_digest,
            "itemId": self.plan.item_id,
            "proposalDigest": self.bootstrap.proposal.digest,
            "planDigest": self.plan.digest,
            "approval": self.approval.to_dict() if self.approval else None,
            "instanceApprovalLease": self.instance_lease.to_dict()
            if self.instance_lease
            else None,
            "executionResult": self.execution_result.to_dict()
            if self.execution_result
            else None,
            "review": self.review.to_dict() if self.review else None,
            "closure": self.closure.to_dict() if self.closure else None,
            "receipt": self.receipt.to_dict() if self.receipt else None,
            "stop": self.stop_record.to_dict() if self.stop_record else None,
            "nextItemRequiresNewApproval": True,
            "backgroundLoop": False,
            "canonicalStateEffect": "none",
        }
