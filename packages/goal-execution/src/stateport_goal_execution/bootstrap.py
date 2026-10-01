"""Deterministic offline bootstrap inspection for public-safe repositories."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import re
from typing import Any, Mapping

import yaml

from .contracts import (
    ACCEPTANCE_CONTRACT_FORMAT,
    CTO_MODE_POLICY_FORMAT,
    DELEGATION_PLAN_FORMAT,
    GOAL_ITEM_FORMAT,
    GOAL_PROPOSAL_FORMAT,
    ORCHESTRATOR_PROFILE_FORMAT,
    PROJECT_BOOTSTRAP_FORMAT,
    REVIEW_ISOLATION_FORMAT,
    REVIEW_REQUIREMENT_FORMAT,
    SLICE_PLAN_FORMAT,
    AcceptanceContract,
    GoalBudget,
    GoalContractError,
    GoalExecutionIntent,
    GoalItem,
    GoalProposal,
    OrchestratorProfile,
    ProjectBootstrapManifest,
    SlicePlan,
    canonical_digest,
)


_SECRET_FIELD = re.compile(
    r"(?:api[_-]?key|authorization|cookie|credential|password|secret|access[_-]?token|refresh[_-]?token|private[_-]?key)",
    re.IGNORECASE,
)
_EXPECTED_FILES = ("actions.yaml", "application.yaml")
_MAX_FILE_BYTES = 64 * 1024


@dataclass(frozen=True)
class BootstrapProposal:
    manifest: ProjectBootstrapManifest
    proposal: GoalProposal

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": "stateport.bootstrap-proposal/v1",
            "manifest": self.manifest.to_dict(),
            "proposal": self.proposal.to_dict(),
            "proposalOnly": True,
            "networkUsed": False,
            "canonicalStateEffect": "none",
        }


def _reject_secret_fields(
    value: Any,
    location: str,
    *,
    seen: set[int] | None = None,
    depth: int = 0,
    entries: list[int] | None = None,
) -> None:
    seen = seen if seen is not None else set()
    entries = entries if entries is not None else [0]
    if depth > 32:
        raise GoalContractError(f"bootstrap data is nested too deeply at {location}")
    if isinstance(value, Mapping):
        if id(value) in seen:
            raise GoalContractError(
                f"bootstrap data contains a recursive or repeated alias at {location}"
            )
        seen.add(id(value))
        entries[0] += len(value)
        if entries[0] > 4096:
            raise GoalContractError("bootstrap data exceeds the structural entry limit")
        for key, item in value.items():
            if not isinstance(key, str):
                raise GoalContractError(f"{location} contains a non-string field")
            if _SECRET_FIELD.search(key):
                raise GoalContractError(
                    f"credential-like field is forbidden at {location}.{key}"
                )
            _reject_secret_fields(
                item, f"{location}.{key}", seen=seen, depth=depth + 1, entries=entries
            )
    elif isinstance(value, list):
        if id(value) in seen:
            raise GoalContractError(
                f"bootstrap data contains a recursive or repeated alias at {location}"
            )
        seen.add(id(value))
        entries[0] += len(value)
        if entries[0] > 4096:
            raise GoalContractError("bootstrap data exceeds the structural entry limit")
        for index, item in enumerate(value):
            _reject_secret_fields(
                item,
                f"{location}[{index}]",
                seen=seen,
                depth=depth + 1,
                entries=entries,
            )


def _load_public_safe_fixture(
    repo_root: Path, trusted_root: Path
) -> tuple[str, dict[str, Any], dict[str, Any]]:
    if repo_root.is_symlink() or trusted_root.is_symlink():
        raise GoalContractError("bootstrap roots may not be symlinks")
    try:
        trusted = trusted_root.resolve(strict=True)
        root = repo_root.resolve(strict=True)
        relative = root.relative_to(trusted)
    except (OSError, ValueError) as exc:
        raise GoalContractError(
            "bootstrap repository must be below the trusted fixture root"
        ) from exc
    if not root.is_dir() or relative == Path("."):
        raise GoalContractError(
            "bootstrap repository must be a bounded child directory"
        )

    values: dict[str, dict[str, Any]] = {}
    digest = sha256()
    for name in _EXPECTED_FILES:
        path = root / name
        if path.is_symlink() or not path.is_file() or path.parent.resolve() != root:
            raise GoalContractError(
                f"required bootstrap file is unavailable or unsafe: {name}"
            )
        size = path.stat().st_size
        if size <= 0 or size > _MAX_FILE_BYTES:
            raise GoalContractError(
                f"bootstrap file exceeds the bounded size policy: {name}"
            )
        raw = path.read_bytes()
        try:
            value = yaml.safe_load(raw.decode("utf-8"))
        except (UnicodeDecodeError, yaml.YAMLError) as exc:
            raise GoalContractError(f"bootstrap file is not safe YAML: {name}") from exc
        if not isinstance(value, dict):
            raise GoalContractError(f"bootstrap file must contain an object: {name}")
        _reject_secret_fields(value, name)
        values[name] = value
        digest.update(name.encode("utf-8") + b"\0" + raw + b"\0")

    application = values["application.yaml"]
    actions = values["actions.yaml"]
    if application.get("formatVersion") != "stateport.application/v1":
        raise GoalContractError("synthetic fixture application contract is unsupported")
    application_id = application.get("applicationId")
    if (
        not isinstance(application_id, str)
        or actions.get("applicationId") != application_id
    ):
        raise GoalContractError("synthetic fixture identities do not agree")
    if (
        application.get("privacyClassification") != "public_safe"
        or application.get("productionEligible") is not False
    ):
        raise GoalContractError(
            "bootstrap fixture must be public-safe and production-ineligible"
        )
    if actions.get(
        "formatVersion"
    ) != "stateport.application-action/v1" or not isinstance(
        actions.get("actions"), list
    ):
        raise GoalContractError("synthetic fixture action contract is unsupported")
    if any(
        item.get("networkPolicy") != "disabled"
        for item in actions["actions"]
        if isinstance(item, dict)
    ):
        raise GoalContractError(
            "offline bootstrap fixture may not request network access"
        )
    return (
        relative.as_posix(),
        application,
        actions | {"_repositoryDigest": "sha256:" + digest.hexdigest()},
    )


def prepare_project_bootstrap(
    *,
    intent: GoalExecutionIntent,
    repo_root: Path,
    trusted_root: Path,
    base_commit: str,
    base_tree: str,
    proposed_by: str,
    profile: OrchestratorProfile,
) -> BootstrapProposal:
    """Inspect two reviewed declarations and return a proposal without effects.

    No command, hook, package script, model, provider or network adapter is
    invoked. The returned backlog is a development specialization of the
    domain-neutral goal-item contract.
    """

    if intent.requested_mode.value == "off":
        raise GoalContractError("off mode does not prepare orchestrator proposals")
    if (
        intent.application_id != profile.application_id
        or intent.requested_mode is not profile.mode
    ):
        raise GoalContractError(
            "bootstrap intent mode and application must match the originating profile"
        )
    relative, application, actions = _load_public_safe_fixture(repo_root, trusted_root)
    if application["applicationId"] != intent.application_id:
        raise GoalContractError(
            "bootstrap application identity does not match the requested application"
        )
    repository_digest = actions.pop("_repositoryDigest")
    action_ids = tuple(
        str(item.get("actionId"))
        for item in actions["actions"]
        if isinstance(item, dict) and isinstance(item.get("actionId"), str)
    )
    if not action_ids:
        raise GoalContractError(
            "synthetic fixture must declare at least one typed action"
        )
    state_snapshot_digest = canonical_digest(
        {
            "applicationId": application["applicationId"],
            "stateLayout": application.get("stateLayout"),
            "actions": list(action_ids),
        }
    )

    items = (
        GoalItem(
            item_id="synthetic-contract-boundary",
            domain="development",
            objective="Validate the public-safe application and typed action boundary.",
            user_value="The existing application can be adopted without executing repository code or guessing its authority model.",
            dependencies=(),
            scope=("application.yaml", "actions.yaml"),
            exclusions=(
                "network access",
                "canonical state mutation",
                "provider execution",
            ),
            owner_role="contract-reviewer",
            required_permissions=("project.read",),
            acceptance_criteria=(
                "application and action identities agree",
                "all declared action network policies are disabled",
                "bootstrap inspection records an immutable fixture digest",
            ),
            validation_commands=(
                "python3 -m pytest -q scripts/test_goal_execution.py",
            ),
            side_effect_class="none",
            evidence_requirements=(
                "exact repository digest",
                "independent review bound to commit and tree",
            ),
        ),
        GoalItem(
            item_id="synthetic-state-integrity",
            domain="development",
            objective="Verify the declared canonical and generated state ownership boundary.",
            user_value="Future slices can preserve user-owned state while treating generated files as disposable.",
            dependencies=("synthetic-contract-boundary",),
            scope=("state layout declaration", "validation boundary"),
            exclusions=("writing fixture state", "installing runtime dependencies"),
            owner_role="state-reviewer",
            required_permissions=("project.read",),
            acceptance_criteria=(
                "state ownership is explicit",
                "validation remains deterministic and offline",
            ),
            validation_commands=(
                "python3 -m pytest -q scripts/test_application_registry.py",
            ),
            side_effect_class="none",
            evidence_requirements=("source-of-truth map", "validation result digest"),
        ),
        GoalItem(
            item_id="synthetic-application-presentation",
            domain="development",
            objective="Propose an application-native presentation after contract acceptance.",
            user_value="A user sees an application experience while development machinery stays optional.",
            dependencies=("synthetic-contract-boundary", "synthetic-state-integrity"),
            scope=("trusted declarative application view", "conversation attachment"),
            exclusions=(
                "arbitrary package frontend code",
                "global CTO navigation",
                "platform administration",
            ),
            owner_role="experience-reviewer",
            required_permissions=("project.read",),
            acceptance_criteria=(
                "application view is declarative",
                "Workbench remains optional",
            ),
            validation_commands=(
                "python3 -m pytest -q scripts/test_application_experience.py",
            ),
            side_effect_class="none",
            evidence_requirements=(
                "capability resolution",
                "StudyState non-exposure regression",
            ),
        ),
    )
    manifest = ProjectBootstrapManifest(
        manifest_id="bootstrap-synthetic-reference-v1",
        application_id=intent.application_id,
        instance_id=intent.instance_id,
        intent_digest=intent.digest,
        originating_mode=intent.requested_mode,
        orchestrator_profile_digest=profile.digest,
        repository_relative_path=relative,
        repository_digest=repository_digest,
        base_commit=base_commit,
        base_tree=base_tree,
        state_snapshot_digest=state_snapshot_digest,
        privacy_classification="public_safe",
        inspected_files=_EXPECTED_FILES,
        architecture_boundaries=(
            "StatePort owns permissions approvals validation review and receipts",
            "repository declarations are inspected as data and never executed",
            "natural language remains proposal-only and noncanonical",
        ),
        source_of_truth_map=(
            "application.yaml defines the portable application declaration",
            "actions.yaml defines typed actions and their bounded policies",
            "StatePort contracts govern execution and closure",
        ),
        risks=(
            "fixture does not prove a live provider integration",
            "fixture does not prove production readiness",
            "every later item requires a fresh exact approval",
        ),
        goal_items=items,
    )
    proposal = GoalProposal(
        proposal_id="proposal-synthetic-reference-v1",
        manifest_digest=manifest.digest,
        intent_digest=intent.digest,
        originating_mode=intent.requested_mode,
        orchestrator_profile_digest=profile.digest,
        proposed_by=proposed_by,
        item_ids=tuple(item.item_id for item in items),
        recommended_item_id=items[0].item_id,
    )
    return BootstrapProposal(manifest=manifest, proposal=proposal)


def prepare_recommended_slice(
    bootstrap: BootstrapProposal,
    *,
    proposed_by: str,
    maximum_budget: GoalBudget | None = None,
) -> tuple[SlicePlan, AcceptanceContract]:
    """Prepare one exact slice; this function does not approve or execute it."""

    manifest = bootstrap.manifest
    proposal = bootstrap.proposal
    item = next(
        item
        for item in manifest.goal_items
        if item.item_id == proposal.recommended_item_id
    )
    contract_versions = (
        ORCHESTRATOR_PROFILE_FORMAT,
        CTO_MODE_POLICY_FORMAT,
        PROJECT_BOOTSTRAP_FORMAT,
        GOAL_ITEM_FORMAT,
        GOAL_PROPOSAL_FORMAT,
        SLICE_PLAN_FORMAT,
        DELEGATION_PLAN_FORMAT,
        ACCEPTANCE_CONTRACT_FORMAT,
        REVIEW_REQUIREMENT_FORMAT,
        REVIEW_ISOLATION_FORMAT,
    )
    plan = SlicePlan(
        plan_id="slice-synthetic-contract-boundary-v1",
        application_id=manifest.application_id,
        instance_id=manifest.instance_id,
        item_id=item.item_id,
        manifest_digest=manifest.digest,
        proposal_digest=proposal.digest,
        intent_digest=proposal.intent_digest,
        originating_mode=proposal.originating_mode,
        orchestrator_profile_digest=proposal.orchestrator_profile_digest,
        base_commit=manifest.base_commit,
        base_tree=manifest.base_tree,
        state_snapshot_digest=manifest.state_snapshot_digest,
        required_permissions=item.required_permissions,
        side_effect_class=item.side_effect_class,
        maximum_budget=maximum_budget
        or GoalBudget(token=0, cost_minor=0, time_seconds=30, steps=3),
        validation_commands=item.validation_commands,
        contract_versions=contract_versions,
        proposed_by=proposed_by,
    )
    acceptance = AcceptanceContract(
        contract_id="accept-synthetic-contract-boundary-v1",
        item_id=item.item_id,
        criteria=item.acceptance_criteria,
        validation_commands=item.validation_commands,
        required_contract_versions=contract_versions,
    )
    return plan, acceptance
