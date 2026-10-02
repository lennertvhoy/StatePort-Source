"""Strict immutable contracts for provider-neutral governed goal execution.

The contracts record intent, policy, immutable identity and evidence. They do
not execute an agent, grant a capability, approve work, or mutate canonical
application state.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
import json
import re
from typing import Any, ClassVar, Iterable, Mapping


GOAL_EXECUTION_FORMAT = "stateport.goal-execution/v1"
ORCHESTRATOR_PROFILE_FORMAT = "stateport.orchestrator-profile/v1"
CTO_MODE_POLICY_FORMAT = "stateport.cto-mode-policy/v1"
PROJECT_BOOTSTRAP_FORMAT = "stateport.project-bootstrap-manifest/v1"
GOAL_ITEM_FORMAT = "stateport.goal-item/v1"
GOAL_PROPOSAL_FORMAT = "stateport.goal-proposal/v1"
SLICE_PLAN_FORMAT = "stateport.slice-plan/v1"
DELEGATION_PLAN_FORMAT = "stateport.delegation-plan/v1"
ACCEPTANCE_CONTRACT_FORMAT = "stateport.acceptance-contract/v1"
REVIEW_REQUIREMENT_FORMAT = "stateport.review-requirement/v1"
APPROVAL_RECORD_FORMAT = "stateport.goal-approval/v1"
EXECUTION_RESULT_FORMAT = "stateport.goal-execution-result/v1"
REVIEW_RECORD_FORMAT = "stateport.goal-review/v1"
REVIEW_ISOLATION_FORMAT = "stateport.review-workspace-isolation/v1"
CLOSURE_DECISION_FORMAT = "stateport.closure-decision/v1"
GOAL_RECEIPT_FORMAT = "stateport.goal-execution-receipt/v1"

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40,64}$")
_PERMISSION = re.compile(r"^[a-z][a-z0-9._-]{1,127}$")
_SIDE_EFFECTS = frozenset({"none", "idempotent", "compensated", "external", "unknown"})
_SAFE_SIDE_EFFECTS = frozenset({"none", "idempotent"})
_REVIEW_DISPOSITIONS = frozenset(
    {"accepted", "accepted_with_bounded_followups", "rejected_with_reproduced_defects"}
)
_CLOSURE_STATUSES = frozenset({"closed", "reopened", "stopped"})
_SECRET_FIELD = re.compile(
    r"(?:api[_-]?key|authorization|cookie|credential|password|secret|access[_-]?token|refresh[_-]?token|private[_-]?key)",
    re.IGNORECASE,
)


class GoalContractError(ValueError):
    """Raised when a goal-execution contract is not safe or self-consistent."""


class OrchestratorMode(str, Enum):
    OFF = "off"
    ADVISORY = "advisory"
    ASSISTED = "assisted"
    MANAGED_APPROVED_QUEUE = "managed_approved_queue"


def _canonical(value: Any) -> str:
    if hasattr(value, "to_dict"):
        value = value.to_dict()
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def canonical_digest(value: Any) -> str:
    return "sha256:" + sha256(_canonical(value).encode("utf-8")).hexdigest()


def _text(value: object, label: str, *, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise GoalContractError(f"{label} must be a non-empty bounded string")
    if any(ord(character) < 32 and character not in "\n\t" for character in value):
        raise GoalContractError(f"{label} contains control characters")
    return value.strip()


def _identifier(value: object, label: str) -> str:
    result = _text(value, label, maximum=128)
    if not _ID.fullmatch(result):
        raise GoalContractError(f"{label} is not a safe identifier")
    return result


def _digest(value: object, label: str) -> str:
    result = _text(value, label, maximum=71)
    if not _DIGEST.fullmatch(result):
        raise GoalContractError(f"{label} must be a sha256 digest")
    return result


def _git_sha(value: object, label: str) -> str:
    result = _text(value, label, maximum=64)
    if not _GIT_SHA.fullmatch(result):
        raise GoalContractError(f"{label} must be an immutable Git SHA")
    return result


def _items(
    values: Iterable[object],
    label: str,
    *,
    identifiers: bool = False,
    nonempty: bool = False,
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise GoalContractError(f"{label} must be a bounded sequence")
    result = tuple(
        _identifier(value, label) if identifiers else _text(value, label, maximum=512)
        for value in values
    )
    if (
        len(result) > 128
        or (nonempty and not result)
        or len(set(result)) != len(result)
    ):
        raise GoalContractError(f"{label} must be a unique bounded sequence")
    return result


def _permissions(
    values: Iterable[object], label: str = "permissions"
) -> tuple[str, ...]:
    result = _items(values, label, nonempty=True)
    if any(not _PERMISSION.fullmatch(value) for value in result):
        raise GoalContractError(f"{label} contains an invalid permission")
    return tuple(sorted(result))


def _safe_relative_path(value: object, label: str) -> str:
    result = _text(value, label, maximum=512)
    parts = result.replace("\\", "/").split("/")
    if (
        result.startswith("/")
        or "\\" in result
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise GoalContractError(
            f"{label} must be a repository-relative non-traversing path"
        )
    return result


def _paths(
    values: Iterable[object], label: str, *, nonempty: bool = False
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise GoalContractError(f"{label} must be a bounded sequence")
    result = tuple(_safe_relative_path(value, label) for value in values)
    if (
        len(result) > 128
        or (nonempty and not result)
        or len(set(result)) != len(result)
    ):
        raise GoalContractError(f"{label} must be a unique bounded path sequence")
    return result


def _no_secret_fields(value: Any, location: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise GoalContractError(f"{location} has a non-string field")
            if _SECRET_FIELD.search(key):
                raise GoalContractError(
                    f"credential-like field is forbidden at {location}.{key}"
                )
            _no_secret_fields(item, f"{location}.{key}")
    elif isinstance(value, (tuple, list)):
        for index, item in enumerate(value):
            _no_secret_fields(item, f"{location}[{index}]")


class _Contract:
    FORMAT: ClassVar[str]

    def to_dict(self) -> dict[str, Any]:
        raise NotImplementedError

    @property
    def digest(self) -> str:
        value = self.to_dict()
        _no_secret_fields(value)
        return canonical_digest(value)


@dataclass(frozen=True)
class GoalBudget:
    token: int
    cost_minor: int
    time_seconds: int
    steps: int

    def __post_init__(self) -> None:
        for label, value in self.to_dict().items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise GoalContractError(
                    f"budget {label} must be a non-negative integer"
                )

    def to_dict(self) -> dict[str, int]:
        return {
            "token": self.token,
            "costMinor": self.cost_minor,
            "timeSeconds": self.time_seconds,
            "steps": self.steps,
        }

    def fits_within(self, ceiling: "GoalBudget") -> bool:
        return all(
            self.to_dict()[key] <= ceiling.to_dict()[key] for key in self.to_dict()
        )


@dataclass(frozen=True)
class GoalExecutionIntent(_Contract):
    FORMAT: ClassVar[str] = GOAL_EXECUTION_FORMAT
    intent_id: str
    application_id: str
    instance_id: str
    requested_by: str
    text: str
    requested_mode: OrchestratorMode = OrchestratorMode.ADVISORY
    proposal_only: bool = True
    canonical_state_effect: str = "none"

    def __post_init__(self) -> None:
        for label, value in (
            ("intent id", self.intent_id),
            ("application id", self.application_id),
            ("instance id", self.instance_id),
            ("requesting actor", self.requested_by),
        ):
            _identifier(value, label)
        _text(self.text, "intent text", maximum=4000)
        if not isinstance(self.requested_mode, OrchestratorMode):
            raise GoalContractError("requested mode is unsupported")
        if not self.proposal_only or self.canonical_state_effect != "none":
            raise GoalContractError(
                "natural-language intent may only create a noncanonical proposal"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "intentId": self.intent_id,
            "applicationId": self.application_id,
            "instanceId": self.instance_id,
            "requestedBy": self.requested_by,
            "text": self.text,
            "requestedMode": self.requested_mode.value,
            "proposalOnly": self.proposal_only,
            "canonicalStateEffect": self.canonical_state_effect,
        }


@dataclass(frozen=True)
class OrchestratorProfile(_Contract):
    FORMAT: ClassVar[str] = ORCHESTRATOR_PROFILE_FORMAT
    profile_id: str
    application_id: str
    orchestrator_actor: str
    mode: OrchestratorMode = OrchestratorMode.ADVISORY
    capability: str = "goal_execution"
    goal_domain: str = "development"
    maximum_active_items: int = 1
    may_self_approve: bool = False
    background_loop: bool = False

    def __post_init__(self) -> None:
        _identifier(self.profile_id, "orchestrator profile id")
        _identifier(self.application_id, "application id")
        _identifier(self.orchestrator_actor, "orchestrator actor")
        if not isinstance(self.mode, OrchestratorMode):
            raise GoalContractError("orchestrator mode is unsupported")
        if self.capability not in {"goal_execution", "cto_orchestration"}:
            raise GoalContractError(
                "orchestrator profile must use a governed goal capability"
            )
        _identifier(self.goal_domain, "goal domain")
        if self.maximum_active_items != 1:
            raise GoalContractError("exactly one approved item may be active")
        if self.may_self_approve or self.background_loop:
            raise GoalContractError(
                "self-approval and background backlog loops are forbidden"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "profileId": self.profile_id,
            "applicationId": self.application_id,
            "orchestratorActor": self.orchestrator_actor,
            "mode": self.mode.value,
            "capability": self.capability,
            "goalDomain": self.goal_domain,
            "maximumActiveItems": self.maximum_active_items,
            "maySelfApprove": self.may_self_approve,
            "backgroundLoop": self.background_loop,
        }

    @property
    def required_capabilities(self) -> tuple[str, ...]:
        if self.capability == "cto_orchestration":
            return ("goal_execution", "cto_orchestration")
        return ("goal_execution",)


@dataclass(frozen=True)
class CtoModePolicy(_Contract):
    FORMAT: ClassVar[str] = CTO_MODE_POLICY_FORMAT
    default_mode: OrchestratorMode = OrchestratorMode.ADVISORY
    allowed_modes: tuple[OrchestratorMode, ...] = tuple(OrchestratorMode)
    require_explicit_approval: bool = True
    require_independent_review: bool = True
    maximum_active_items: int = 1
    routing_deviation_invalidates_output: bool = False
    stop_conditions: tuple[str, ...] = (
        "ambiguous_scope",
        "permission_increase",
        "critical_review_failed",
        "base_drift",
        "budget_exceeded",
        "external_side_effect",
        "policy_drift",
        "next_item_unapproved",
    )
    full_rerun_allowed_only_for: tuple[str, ...] = (
        "controlled_benchmark",
        "material_defect",
        "unsafe_execution",
        "irrecoverable_provenance",
        "explicit_human_request",
    )

    def __post_init__(self) -> None:
        if self.default_mode is not OrchestratorMode.ADVISORY:
            raise GoalContractError("CTO mode must default to advisory")
        if tuple(self.allowed_modes) != tuple(OrchestratorMode):
            raise GoalContractError(
                "CTO policy must explicitly support all four governed modes"
            )
        if not self.require_explicit_approval or not self.require_independent_review:
            raise GoalContractError("approval and independent review are mandatory")
        if self.maximum_active_items != 1:
            raise GoalContractError("CTO policy permits one active approved item")
        if self.routing_deviation_invalidates_output:
            raise GoalContractError(
                "model identity alone may not invalidate correct output"
            )
        required_stops = {
            "ambiguous_scope",
            "permission_increase",
            "critical_review_failed",
            "base_drift",
            "budget_exceeded",
            "external_side_effect",
            "next_item_unapproved",
        }
        if not required_stops.issubset(
            set(
                _items(
                    self.stop_conditions,
                    "stop conditions",
                    identifiers=True,
                    nonempty=True,
                )
            )
        ):
            raise GoalContractError("CTO policy is missing mandatory stop conditions")
        if set(self.full_rerun_allowed_only_for) != {
            "controlled_benchmark",
            "material_defect",
            "unsafe_execution",
            "irrecoverable_provenance",
            "explicit_human_request",
        }:
            raise GoalContractError("CTO policy has an unsafe full-rerun rule")

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "defaultMode": self.default_mode.value,
            "allowedModes": [item.value for item in self.allowed_modes],
            "requireExplicitApproval": self.require_explicit_approval,
            "requireIndependentReview": self.require_independent_review,
            "maximumActiveItems": self.maximum_active_items,
            "routingDeviation": {
                "invalidatesOutput": self.routing_deviation_invalidates_output
            },
            "stopConditions": list(self.stop_conditions),
            "fullRerunAllowedOnlyFor": list(self.full_rerun_allowed_only_for),
        }


@dataclass(frozen=True)
class GoalItem(_Contract):
    FORMAT: ClassVar[str] = GOAL_ITEM_FORMAT
    item_id: str
    domain: str
    objective: str
    user_value: str
    dependencies: tuple[str, ...]
    scope: tuple[str, ...]
    exclusions: tuple[str, ...]
    owner_role: str
    required_permissions: tuple[str, ...]
    acceptance_criteria: tuple[str, ...]
    validation_commands: tuple[str, ...]
    side_effect_class: str
    evidence_requirements: tuple[str, ...]
    status: str = "proposed"

    def __post_init__(self) -> None:
        _identifier(self.item_id, "goal item id")
        _identifier(self.domain, "goal domain")
        _text(self.objective, "goal objective", maximum=500)
        _text(self.user_value, "goal user value", maximum=500)
        _items(self.dependencies, "goal dependencies", identifiers=True)
        _items(self.scope, "goal scope", nonempty=True)
        _items(self.exclusions, "goal exclusions", nonempty=True)
        _identifier(self.owner_role, "goal owner role")
        _permissions(self.required_permissions)
        _items(self.acceptance_criteria, "acceptance criteria", nonempty=True)
        _items(self.validation_commands, "validation commands", nonempty=True)
        if self.side_effect_class not in _SIDE_EFFECTS:
            raise GoalContractError("goal side-effect class is unsupported")
        _items(self.evidence_requirements, "evidence requirements", nonempty=True)
        if self.status != "proposed":
            raise GoalContractError("bootstrap may only create proposed goal items")

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "itemId": self.item_id,
            "domain": self.domain,
            "objective": self.objective,
            "userValue": self.user_value,
            "dependencies": list(self.dependencies),
            "scope": list(self.scope),
            "exclusions": list(self.exclusions),
            "ownerRole": self.owner_role,
            "requiredPermissions": list(self.required_permissions),
            "acceptanceCriteria": list(self.acceptance_criteria),
            "validationCommands": list(self.validation_commands),
            "sideEffectClass": self.side_effect_class,
            "evidenceRequirements": list(self.evidence_requirements),
            "status": self.status,
        }


@dataclass(frozen=True)
class ProjectBootstrapManifest(_Contract):
    FORMAT: ClassVar[str] = PROJECT_BOOTSTRAP_FORMAT
    manifest_id: str
    application_id: str
    instance_id: str
    intent_digest: str
    originating_mode: OrchestratorMode
    orchestrator_profile_digest: str
    repository_relative_path: str
    repository_digest: str
    base_commit: str
    base_tree: str
    state_snapshot_digest: str
    privacy_classification: str
    inspected_files: tuple[str, ...]
    architecture_boundaries: tuple[str, ...]
    source_of_truth_map: tuple[str, ...]
    risks: tuple[str, ...]
    goal_items: tuple[GoalItem, ...]
    proposal_only: bool = True
    network_used: bool = False
    canonical_state_effect: str = "none"

    def __post_init__(self) -> None:
        _identifier(self.manifest_id, "bootstrap manifest id")
        _identifier(self.application_id, "application id")
        _identifier(self.instance_id, "instance id")
        _digest(self.intent_digest, "intent digest")
        if not isinstance(self.originating_mode, OrchestratorMode):
            raise GoalContractError("bootstrap originating mode is unsupported")
        _digest(
            self.orchestrator_profile_digest,
            "bootstrap orchestrator profile digest",
        )
        _safe_relative_path(self.repository_relative_path, "repository relative path")
        _digest(self.repository_digest, "repository digest")
        _git_sha(self.base_commit, "base commit")
        _git_sha(self.base_tree, "base tree")
        _digest(self.state_snapshot_digest, "state snapshot digest")
        if self.privacy_classification != "public_safe":
            raise GoalContractError("bootstrap fixture must be explicitly public-safe")
        for path in self.inspected_files:
            _safe_relative_path(path, "inspected file")
        if not self.inspected_files or len(set(self.inspected_files)) != len(
            self.inspected_files
        ):
            raise GoalContractError("inspected files must be non-empty and unique")
        _items(self.architecture_boundaries, "architecture boundaries", nonempty=True)
        _items(self.source_of_truth_map, "source-of-truth map", nonempty=True)
        _items(self.risks, "risk register", nonempty=True)
        if not 1 <= len(self.goal_items) <= 7:
            raise GoalContractError(
                "bootstrap must produce a short strategic goal list"
            )
        ids = [item.item_id for item in self.goal_items]
        if len(set(ids)) != len(ids):
            raise GoalContractError("bootstrap goal item ids must be unique")
        known = set(ids)
        if any(not set(item.dependencies).issubset(known) for item in self.goal_items):
            raise GoalContractError(
                "goal dependencies must reference this bootstrap manifest"
            )
        if (
            not self.proposal_only
            or self.network_used
            or self.canonical_state_effect != "none"
        ):
            raise GoalContractError(
                "bootstrap inspection must remain offline and proposal-only"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "manifestId": self.manifest_id,
            "applicationId": self.application_id,
            "instanceId": self.instance_id,
            "intentDigest": self.intent_digest,
            "originatingMode": self.originating_mode.value,
            "orchestratorProfileDigest": self.orchestrator_profile_digest,
            "repository": {
                "relativePath": self.repository_relative_path,
                "digest": self.repository_digest,
                "baseCommit": self.base_commit,
                "baseTree": self.base_tree,
                "stateSnapshotDigest": self.state_snapshot_digest,
            },
            "privacyClassification": self.privacy_classification,
            "inspectedFiles": list(self.inspected_files),
            "architectureBoundaries": list(self.architecture_boundaries),
            "sourceOfTruthMap": list(self.source_of_truth_map),
            "risks": list(self.risks),
            "goalItems": [item.to_dict() for item in self.goal_items],
            "proposalOnly": self.proposal_only,
            "networkUsed": self.network_used,
            "canonicalStateEffect": self.canonical_state_effect,
        }


@dataclass(frozen=True)
class GoalProposal(_Contract):
    FORMAT: ClassVar[str] = GOAL_PROPOSAL_FORMAT
    proposal_id: str
    manifest_digest: str
    intent_digest: str
    originating_mode: OrchestratorMode
    orchestrator_profile_digest: str
    proposed_by: str
    item_ids: tuple[str, ...]
    recommended_item_id: str
    ambiguities: tuple[str, ...] = ()
    approval_status: str = "unapproved"
    canonical_state_effect: str = "none"
    next_item_requires_new_approval: bool = True

    def __post_init__(self) -> None:
        _identifier(self.proposal_id, "goal proposal id")
        _digest(self.manifest_digest, "bootstrap manifest digest")
        _digest(self.intent_digest, "proposal intent digest")
        if not isinstance(self.originating_mode, OrchestratorMode):
            raise GoalContractError("proposal originating mode is unsupported")
        _digest(
            self.orchestrator_profile_digest,
            "proposal orchestrator profile digest",
        )
        _identifier(self.proposed_by, "proposal actor")
        item_ids = _items(
            self.item_ids, "proposal item ids", identifiers=True, nonempty=True
        )
        _identifier(self.recommended_item_id, "recommended item id")
        if self.recommended_item_id not in item_ids:
            raise GoalContractError("recommended item must be present in the proposal")
        _items(self.ambiguities, "proposal ambiguities")
        if (
            self.approval_status != "unapproved"
            or self.canonical_state_effect != "none"
        ):
            raise GoalContractError(
                "a proposal cannot approve itself or alter canonical state"
            )
        if not self.next_item_requires_new_approval:
            raise GoalContractError("every next item requires a new explicit approval")

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "proposalId": self.proposal_id,
            "manifestDigest": self.manifest_digest,
            "intentDigest": self.intent_digest,
            "originatingMode": self.originating_mode.value,
            "orchestratorProfileDigest": self.orchestrator_profile_digest,
            "proposedBy": self.proposed_by,
            "itemIds": list(self.item_ids),
            "recommendedItemId": self.recommended_item_id,
            "ambiguities": list(self.ambiguities),
            "approvalStatus": self.approval_status,
            "canonicalStateEffect": self.canonical_state_effect,
            "nextItemRequiresNewApproval": self.next_item_requires_new_approval,
        }


@dataclass(frozen=True)
class SlicePlan(_Contract):
    FORMAT: ClassVar[str] = SLICE_PLAN_FORMAT
    plan_id: str
    application_id: str
    instance_id: str
    item_id: str
    manifest_digest: str
    proposal_digest: str
    intent_digest: str
    originating_mode: OrchestratorMode
    orchestrator_profile_digest: str
    base_commit: str
    base_tree: str
    state_snapshot_digest: str
    required_permissions: tuple[str, ...]
    side_effect_class: str
    maximum_budget: GoalBudget
    validation_commands: tuple[str, ...]
    contract_versions: tuple[str, ...]
    proposed_by: str
    network_policy: str = "disabled"
    approval_required: bool = True

    def __post_init__(self) -> None:
        _identifier(self.plan_id, "slice plan id")
        _identifier(self.application_id, "application id")
        _identifier(self.instance_id, "instance id")
        _identifier(self.item_id, "goal item id")
        _digest(self.manifest_digest, "manifest digest")
        _digest(self.proposal_digest, "proposal digest")
        _digest(self.intent_digest, "slice intent digest")
        if not isinstance(self.originating_mode, OrchestratorMode):
            raise GoalContractError("slice originating mode is unsupported")
        _digest(
            self.orchestrator_profile_digest,
            "slice orchestrator profile digest",
        )
        _git_sha(self.base_commit, "base commit")
        _git_sha(self.base_tree, "base tree")
        _digest(self.state_snapshot_digest, "state snapshot digest")
        _permissions(self.required_permissions)
        if self.side_effect_class not in _SIDE_EFFECTS:
            raise GoalContractError("slice side-effect class is unsupported")
        if not isinstance(self.maximum_budget, GoalBudget):
            raise GoalContractError("slice maximum budget is invalid")
        _items(self.validation_commands, "slice validation commands", nonempty=True)
        _items(self.contract_versions, "slice contract versions", nonempty=True)
        _identifier(self.proposed_by, "slice proposer")
        if self.network_policy != "disabled" or not self.approval_required:
            raise GoalContractError(
                "this bounded slice must be offline and approval-bound"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "planId": self.plan_id,
            "applicationId": self.application_id,
            "instanceId": self.instance_id,
            "itemId": self.item_id,
            "manifestDigest": self.manifest_digest,
            "proposalDigest": self.proposal_digest,
            "intentDigest": self.intent_digest,
            "originatingMode": self.originating_mode.value,
            "orchestratorProfileDigest": self.orchestrator_profile_digest,
            "baseCommit": self.base_commit,
            "baseTree": self.base_tree,
            "stateSnapshotDigest": self.state_snapshot_digest,
            "requiredPermissions": list(self.required_permissions),
            "sideEffectClass": self.side_effect_class,
            "maximumBudget": self.maximum_budget.to_dict(),
            "validationCommands": list(self.validation_commands),
            "contractVersions": list(self.contract_versions),
            "proposedBy": self.proposed_by,
            "networkPolicy": self.network_policy,
            "approvalRequired": self.approval_required,
        }


@dataclass(frozen=True)
class DelegationPlan(_Contract):
    FORMAT: ClassVar[str] = DELEGATION_PLAN_FORMAT
    plan_id: str
    item_id: str
    implementer_actor: str
    reviewer_actor: str
    intended_profile: str
    actual_profile: str
    read_scope: tuple[str, ...]
    write_scope: tuple[str, ...]
    routing_deviation_reason: str | None = None
    routing_deviation_invalidates_output: bool = False
    independent_read_only_review: bool = True

    def __post_init__(self) -> None:
        _identifier(self.plan_id, "delegation plan id")
        _identifier(self.item_id, "goal item id")
        _identifier(self.implementer_actor, "implementer actor")
        _identifier(self.reviewer_actor, "reviewer actor")
        if self.implementer_actor == self.reviewer_actor:
            raise GoalContractError("implementer and independent reviewer must differ")
        _identifier(self.intended_profile, "intended profile")
        _identifier(self.actual_profile, "actual profile")
        _paths(self.read_scope, "delegation read scope", nonempty=True)
        _paths(self.write_scope, "delegation write scope", nonempty=True)
        deviated = self.intended_profile != self.actual_profile
        if deviated != (self.routing_deviation_reason is not None):
            raise GoalContractError(
                "routing deviations require an exact reason and exact matches do not"
            )
        if self.routing_deviation_reason is not None:
            _text(
                self.routing_deviation_reason, "routing deviation reason", maximum=500
            )
        if self.routing_deviation_invalidates_output:
            raise GoalContractError("routing deviation alone may not invalidate output")
        if not self.independent_read_only_review:
            raise GoalContractError(
                "delegated work requires independent read-only review"
            )

    @property
    def routing_deviated(self) -> bool:
        return self.intended_profile != self.actual_profile

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "planId": self.plan_id,
            "itemId": self.item_id,
            "implementerActor": self.implementer_actor,
            "reviewerActor": self.reviewer_actor,
            "intendedProfile": self.intended_profile,
            "actualProfile": self.actual_profile,
            "readScope": list(self.read_scope),
            "writeScope": list(self.write_scope),
            "routingDeviation": {
                "occurred": self.routing_deviated,
                "reason": self.routing_deviation_reason,
                "invalidatesOutput": self.routing_deviation_invalidates_output,
            },
            "independentReadOnlyReview": self.independent_read_only_review,
        }


@dataclass(frozen=True)
class AcceptanceContract(_Contract):
    FORMAT: ClassVar[str] = ACCEPTANCE_CONTRACT_FORMAT
    contract_id: str
    item_id: str
    criteria: tuple[str, ...]
    validation_commands: tuple[str, ...]
    required_contract_versions: tuple[str, ...]
    require_clean_repository: bool = True
    require_receipt: bool = True

    def __post_init__(self) -> None:
        _identifier(self.contract_id, "acceptance contract id")
        _identifier(self.item_id, "goal item id")
        _items(self.criteria, "acceptance criteria", nonempty=True)
        _items(
            self.validation_commands, "acceptance validation commands", nonempty=True
        )
        _items(
            self.required_contract_versions, "required contract versions", nonempty=True
        )
        if not self.require_clean_repository or not self.require_receipt:
            raise GoalContractError(
                "clean repository and closure receipt are mandatory"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "contractId": self.contract_id,
            "itemId": self.item_id,
            "criteria": list(self.criteria),
            "validationCommands": list(self.validation_commands),
            "requiredContractVersions": list(self.required_contract_versions),
            "requireCleanRepository": self.require_clean_repository,
            "requireReceipt": self.require_receipt,
        }


@dataclass(frozen=True)
class ReviewRequirement(_Contract):
    FORMAT: ClassVar[str] = REVIEW_REQUIREMENT_FORMAT
    requirement_id: str
    item_id: str
    acceptance_contract_digest: str
    reviewer_actor: str
    bind_exact_commit: bool = True
    bind_exact_tree: bool = True
    bind_exact_tests: bool = True
    bind_exact_contract_versions: bool = True
    independent_read_only: bool = True
    workspace_isolation: str = "clean_detached_read_only_worktree"
    critical: bool = True

    def __post_init__(self) -> None:
        _identifier(self.requirement_id, "review requirement id")
        _identifier(self.item_id, "goal item id")
        _digest(self.acceptance_contract_digest, "acceptance contract digest")
        _identifier(self.reviewer_actor, "reviewer actor")
        if not all(
            (
                self.bind_exact_commit,
                self.bind_exact_tree,
                self.bind_exact_tests,
                self.bind_exact_contract_versions,
                self.independent_read_only,
                self.critical,
            )
        ):
            raise GoalContractError(
                "high-risk closure requires exact independent critical review"
            )
        if self.workspace_isolation != "clean_detached_read_only_worktree":
            raise GoalContractError(
                "independent review requires an exact clean detached read-only worktree"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "requirementId": self.requirement_id,
            "itemId": self.item_id,
            "acceptanceContractDigest": self.acceptance_contract_digest,
            "reviewerActor": self.reviewer_actor,
            "bindExactCommit": self.bind_exact_commit,
            "bindExactTree": self.bind_exact_tree,
            "bindExactTests": self.bind_exact_tests,
            "bindExactContractVersions": self.bind_exact_contract_versions,
            "independentReadOnly": self.independent_read_only,
            "workspaceIsolation": self.workspace_isolation,
            "critical": self.critical,
        }


@dataclass(frozen=True)
class ApprovalRecord(_Contract):
    FORMAT: ClassVar[str] = APPROVAL_RECORD_FORMAT
    approval_id: str
    application_id: str
    instance_id: str
    item_id: str
    plan_digest: str
    intent_digest: str
    originating_mode: OrchestratorMode
    orchestrator_profile_digest: str
    policy_digest: str
    delegation_plan_digest: str
    acceptance_contract_digest: str
    contract_versions: tuple[str, ...]
    approver_actor: str
    base_commit: str
    base_tree: str
    state_snapshot_digest: str
    instance_lease_id: str
    instance_lease_generation: int
    approved_permissions: tuple[str, ...]
    approved_side_effect_class: str
    approved_budget: GoalBudget
    status: str = "approved"
    explicit: bool = True

    def __post_init__(self) -> None:
        _identifier(self.approval_id, "approval id")
        _identifier(self.application_id, "approved application id")
        _identifier(self.instance_id, "approved instance id")
        _identifier(self.item_id, "goal item id")
        _digest(self.plan_digest, "plan digest")
        _digest(self.intent_digest, "approved intent digest")
        if not isinstance(self.originating_mode, OrchestratorMode):
            raise GoalContractError("approved originating mode is unsupported")
        _digest(self.orchestrator_profile_digest, "orchestrator profile digest")
        _digest(self.policy_digest, "goal execution policy digest")
        _digest(self.delegation_plan_digest, "delegation plan digest")
        _digest(self.acceptance_contract_digest, "acceptance contract digest")
        _items(self.contract_versions, "approved contract versions", nonempty=True)
        _identifier(self.approver_actor, "approver actor")
        _git_sha(self.base_commit, "approved base commit")
        _git_sha(self.base_tree, "approved base tree")
        _digest(self.state_snapshot_digest, "approved state snapshot digest")
        _identifier(self.instance_lease_id, "instance approval lease id")
        if (
            isinstance(self.instance_lease_generation, bool)
            or not isinstance(self.instance_lease_generation, int)
            or self.instance_lease_generation < 1
        ):
            raise GoalContractError(
                "instance approval lease generation must be positive"
            )
        _permissions(self.approved_permissions, "approved permissions")
        if self.approved_side_effect_class not in _SAFE_SIDE_EFFECTS:
            raise GoalContractError(
                "unsafe side effects cannot receive this bounded approval"
            )
        if self.status != "approved" or not self.explicit:
            raise GoalContractError("execution requires an explicit approved record")

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "approvalId": self.approval_id,
            "applicationId": self.application_id,
            "instanceId": self.instance_id,
            "itemId": self.item_id,
            "planDigest": self.plan_digest,
            "intentDigest": self.intent_digest,
            "originatingMode": self.originating_mode.value,
            "orchestratorProfileDigest": self.orchestrator_profile_digest,
            "policyDigest": self.policy_digest,
            "delegationPlanDigest": self.delegation_plan_digest,
            "acceptanceContractDigest": self.acceptance_contract_digest,
            "contractVersions": list(self.contract_versions),
            "approverActor": self.approver_actor,
            "baseCommit": self.base_commit,
            "baseTree": self.base_tree,
            "stateSnapshotDigest": self.state_snapshot_digest,
            "instanceLeaseId": self.instance_lease_id,
            "instanceLeaseGeneration": self.instance_lease_generation,
            "approvedPermissions": list(self.approved_permissions),
            "approvedSideEffectClass": self.approved_side_effect_class,
            "approvedBudget": self.approved_budget.to_dict(),
            "status": self.status,
            "explicit": self.explicit,
        }


@dataclass(frozen=True)
class ExecutionResult(_Contract):
    FORMAT: ClassVar[str] = EXECUTION_RESULT_FORMAT
    result_id: str
    item_id: str
    plan_digest: str
    implementer_actor: str
    functional_commit: str
    functional_tree: str
    test_result_digest: str
    contract_versions: tuple[str, ...]
    actual_permissions: tuple[str, ...]
    side_effect_class: str
    used_budget: GoalBudget
    tests_passed: bool
    repository_clean: bool
    external_side_effects_observed: bool = False

    def __post_init__(self) -> None:
        _identifier(self.result_id, "execution result id")
        _identifier(self.item_id, "goal item id")
        _digest(self.plan_digest, "plan digest")
        _identifier(self.implementer_actor, "implementer actor")
        _git_sha(self.functional_commit, "functional commit")
        _git_sha(self.functional_tree, "functional tree")
        _digest(self.test_result_digest, "test result digest")
        _items(self.contract_versions, "execution contract versions", nonempty=True)
        _permissions(self.actual_permissions, "actual permissions")
        if self.side_effect_class not in _SIDE_EFFECTS:
            raise GoalContractError("execution side-effect class is unsupported")
        if not isinstance(self.tests_passed, bool) or not isinstance(
            self.repository_clean, bool
        ):
            raise GoalContractError("execution outcome flags must be boolean")

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "resultId": self.result_id,
            "itemId": self.item_id,
            "planDigest": self.plan_digest,
            "implementerActor": self.implementer_actor,
            "functionalCommit": self.functional_commit,
            "functionalTree": self.functional_tree,
            "testResultDigest": self.test_result_digest,
            "contractVersions": list(self.contract_versions),
            "actualPermissions": list(self.actual_permissions),
            "sideEffectClass": self.side_effect_class,
            "usedBudget": self.used_budget.to_dict(),
            "testsPassed": self.tests_passed,
            "repositoryClean": self.repository_clean,
            "externalSideEffectsObserved": self.external_side_effects_observed,
        }


@dataclass(frozen=True)
class ReviewWorkspaceIsolation(_Contract):
    FORMAT: ClassVar[str] = REVIEW_ISOLATION_FORMAT
    evidence_id: str
    reviewer_actor: str
    implementation_workspace_digest: str
    review_workspace_digest: str
    functional_commit: str
    functional_tree: str
    verifier_id: str = "stateport.review-workspace-verifier.v1"
    workspace_isolation: str = "clean_detached_read_only_worktree"
    head_detached: bool = True
    workspace_clean: bool = True
    filesystem_read_only: bool = True
    separate_from_implementation: bool = True

    def __post_init__(self) -> None:
        _identifier(self.evidence_id, "review isolation evidence id")
        _identifier(self.reviewer_actor, "review isolation actor")
        _digest(
            self.implementation_workspace_digest,
            "implementation workspace digest",
        )
        _digest(self.review_workspace_digest, "review workspace digest")
        if self.implementation_workspace_digest == self.review_workspace_digest:
            raise GoalContractError(
                "review and implementation workspaces must have distinct identities"
            )
        _git_sha(self.functional_commit, "isolated review commit")
        _git_sha(self.functional_tree, "isolated review tree")
        if self.verifier_id != "stateport.review-workspace-verifier.v1":
            raise GoalContractError("review isolation verifier is unsupported")
        if self.workspace_isolation != "clean_detached_read_only_worktree":
            raise GoalContractError(
                "review isolation must be clean, detached and read-only"
            )
        if not all(
            (
                self.head_detached,
                self.workspace_clean,
                self.filesystem_read_only,
                self.separate_from_implementation,
            )
        ):
            raise GoalContractError(
                "review isolation evidence must prove every isolation property"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "evidenceId": self.evidence_id,
            "reviewerActor": self.reviewer_actor,
            "implementationWorkspaceDigest": self.implementation_workspace_digest,
            "reviewWorkspaceDigest": self.review_workspace_digest,
            "functionalCommit": self.functional_commit,
            "functionalTree": self.functional_tree,
            "verifierId": self.verifier_id,
            "workspaceIsolation": self.workspace_isolation,
            "headDetached": self.head_detached,
            "workspaceClean": self.workspace_clean,
            "filesystemReadOnly": self.filesystem_read_only,
            "separateFromImplementation": self.separate_from_implementation,
        }


@dataclass(frozen=True)
class ReviewRecord(_Contract):
    FORMAT: ClassVar[str] = REVIEW_RECORD_FORMAT
    review_id: str
    item_id: str
    reviewer_actor: str
    functional_commit: str
    functional_tree: str
    test_result_digest: str
    acceptance_contract_digest: str
    isolation_evidence_digest: str
    contract_versions: tuple[str, ...]
    disposition: str
    critical_findings: tuple[str, ...] = ()
    read_only: bool = True
    workspace_identity: str = "clean_detached_read_only_worktree"
    workspace_clean: bool = True
    owned_original_implementation: bool = False

    def __post_init__(self) -> None:
        _identifier(self.review_id, "review id")
        _identifier(self.item_id, "goal item id")
        _identifier(self.reviewer_actor, "reviewer actor")
        _git_sha(self.functional_commit, "reviewed commit")
        _git_sha(self.functional_tree, "reviewed tree")
        _digest(self.test_result_digest, "reviewed test result digest")
        _digest(self.acceptance_contract_digest, "reviewed acceptance contract digest")
        _digest(self.isolation_evidence_digest, "review isolation evidence digest")
        _items(self.contract_versions, "reviewed contract versions", nonempty=True)
        if self.disposition not in _REVIEW_DISPOSITIONS:
            raise GoalContractError("review disposition is unsupported")
        _items(self.critical_findings, "critical review findings")
        if not self.read_only:
            raise GoalContractError("independent acceptance must be read-only")
        if self.workspace_identity != "clean_detached_read_only_worktree":
            raise GoalContractError(
                "review workspace must use the exact clean detached read-only isolation"
            )
        if not self.workspace_clean or self.owned_original_implementation:
            raise GoalContractError(
                "independent acceptance requires a clean workspace and separate ownership"
            )
        if (
            self.disposition != "rejected_with_reproduced_defects"
            and self.critical_findings
        ):
            raise GoalContractError("accepted review cannot contain critical findings")
        if (
            self.disposition == "rejected_with_reproduced_defects"
            and not self.critical_findings
        ):
            raise GoalContractError("rejection requires a concrete reproduced defect")

    @property
    def accepted(self) -> bool:
        return self.disposition in {"accepted", "accepted_with_bounded_followups"}

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "reviewId": self.review_id,
            "itemId": self.item_id,
            "reviewerActor": self.reviewer_actor,
            "functionalCommit": self.functional_commit,
            "functionalTree": self.functional_tree,
            "testResultDigest": self.test_result_digest,
            "acceptanceContractDigest": self.acceptance_contract_digest,
            "isolationEvidenceDigest": self.isolation_evidence_digest,
            "contractVersions": list(self.contract_versions),
            "disposition": self.disposition,
            "criticalFindings": list(self.critical_findings),
            "readOnly": self.read_only,
            "workspaceIdentity": self.workspace_identity,
            "workspaceClean": self.workspace_clean,
            "ownedOriginalImplementation": self.owned_original_implementation,
        }


@dataclass(frozen=True)
class ClosureDecision(_Contract):
    FORMAT: ClassVar[str] = CLOSURE_DECISION_FORMAT
    decision_id: str
    item_id: str
    decided_by: str
    status: str
    functional_commit: str
    functional_tree: str
    test_result_digest: str
    review_digest: str
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        _identifier(self.decision_id, "closure decision id")
        _identifier(self.item_id, "goal item id")
        _identifier(self.decided_by, "closure authority")
        if self.status not in _CLOSURE_STATUSES:
            raise GoalContractError("closure status is unsupported")
        _git_sha(self.functional_commit, "closure commit")
        _git_sha(self.functional_tree, "closure tree")
        _digest(self.test_result_digest, "closure test result digest")
        _digest(self.review_digest, "closure review digest")
        _items(self.reasons, "closure reasons", nonempty=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "decisionId": self.decision_id,
            "itemId": self.item_id,
            "decidedBy": self.decided_by,
            "status": self.status,
            "functionalCommit": self.functional_commit,
            "functionalTree": self.functional_tree,
            "testResultDigest": self.test_result_digest,
            "reviewDigest": self.review_digest,
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True)
class GoalExecutionReceipt(_Contract):
    FORMAT: ClassVar[str] = GOAL_RECEIPT_FORMAT
    receipt_id: str
    application_id: str
    instance_id: str
    item_id: str
    approval_digest: str
    execution_result_digest: str
    review_digest: str
    closure_decision_digest: str
    routing_deviation_retained: bool
    next_item_status: str = "stopped_unapproved"
    canonical_state_effect: str = "none"

    def __post_init__(self) -> None:
        _identifier(self.receipt_id, "receipt id")
        _identifier(self.application_id, "application id")
        _identifier(self.instance_id, "instance id")
        _identifier(self.item_id, "goal item id")
        for label, value in (
            ("approval digest", self.approval_digest),
            ("execution result digest", self.execution_result_digest),
            ("review digest", self.review_digest),
            ("closure decision digest", self.closure_decision_digest),
        ):
            _digest(value, label)
        if self.next_item_status != "stopped_unapproved":
            raise GoalContractError("receipt must stop before an unapproved next item")
        if self.canonical_state_effect != "none":
            raise GoalContractError(
                "this provider-free proof cannot mutate canonical state"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.FORMAT,
            "receiptId": self.receipt_id,
            "applicationId": self.application_id,
            "instanceId": self.instance_id,
            "itemId": self.item_id,
            "approvalDigest": self.approval_digest,
            "executionResultDigest": self.execution_result_digest,
            "reviewDigest": self.review_digest,
            "closureDecisionDigest": self.closure_decision_digest,
            "routingDeviationRetained": self.routing_deviation_retained,
            "nextItemStatus": self.next_item_status,
            "canonicalStateEffect": self.canonical_state_effect,
        }


SAFE_SIDE_EFFECTS = _SAFE_SIDE_EFFECTS
