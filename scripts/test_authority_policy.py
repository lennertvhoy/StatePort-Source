#!/usr/bin/env python3
"""Deterministic regressions for standing authority and action receipts."""

from __future__ import annotations

from datetime import datetime, timezone
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any

import jsonschema
import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "packages" / "governed-runner" / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from governed_runner.authority import (  # noqa: E402
    AUTHORITY_ACTION_RECEIPT_SCHEMA,
    AuthorityError,
    AuthorityManager,
    AuthorityRefusal,
    grant_template,
)


NOW = datetime(2026, 7, 29, 16, 0, tzinfo=timezone.utc)


def _run(repository: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _manager(tmp_path: Path) -> AuthorityManager:
    repository = tmp_path / "repository"
    repository.mkdir()
    _run(repository, "init", "-q")
    _run(repository, "config", "user.email", "authority@example.invalid")
    _run(repository, "config", "user.name", "Authority Fixture")
    config = repository / "config"
    config.mkdir()
    shutil.copyfile(ROOT / "config" / "authority-policy.v1.yaml", config / "authority-policy.v1.yaml")
    (repository / "README.md").write_text("fixture\n", encoding="utf-8")
    _run(repository, "add", ".")
    _run(repository, "commit", "-qm", "fixture")
    return AuthorityManager(repository, state_root=tmp_path / "state", clock=lambda: NOW)


def _grant(
    manager: AuthorityManager,
    *,
    grant_id: str = "grant_fixture_primary",
    profile: str = "balanced",
    actor_id: str = "agent-primary",
    role: str = "primary",
    branch_pattern: str | None = "agent/*",
    slice_id: str | None = "BL-FIXTURE-001",
    paths: tuple[str, ...] = (".",),
    allow: tuple[str, ...] = (),
    require_approval: tuple[str, ...] = (),
    forbid: tuple[str, ...] = (),
    parent_grant_id: str | None = None,
    can_delegate: bool = False,
    kind: str = "standing",
    expires_when: str = "slice_closed",
    max_actions: int | None = None,
    max_duration_seconds: int | None = 21_600,
    max_cost_usd: float | None = 10.0,
    network: str = "denied",
    allowed_domains: tuple[str, ...] = (),
    providers: tuple[str, ...] = (),
    secret_capabilities: tuple[str, ...] = (),
    deployment_sources: tuple[dict[str, str], ...] | None = None,
) -> dict:
    return grant_template(
        manager,
        grant_id=grant_id,
        profile=profile,
        actor_id=actor_id,
        role=role,
        branch_pattern=branch_pattern,
        slice_id=slice_id,
        application_id=None,
        run_id=None,
        paths=paths,
        allow=allow,
        require_approval=require_approval,
        forbid=forbid,
        owner_directive_id="OD-FIXTURE-001",
        expires_when=expires_when,
        parent_grant_id=parent_grant_id,
        can_delegate=can_delegate,
        kind=kind,
        max_actions=max_actions,
        max_duration_seconds=max_duration_seconds,
        max_cost_usd=max_cost_usd,
        network=network,
        allowed_domains=allowed_domains,
        providers=providers,
        secret_capabilities=secret_capabilities,
        deployment_sources=deployment_sources,
    )


def _activate(manager: AuthorityManager, grant: dict) -> dict:
    return manager.activate_grant(grant, owner_actor_id="owner-local")["grant"]


def _redigest_decision(decision: dict) -> dict:
    body = {key: value for key, value in decision.items() if key != "decisionDigest"}
    encoded = json.dumps(
        body,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    decision["decisionDigest"] = "sha256:" + hashlib.sha256(encoded).hexdigest()
    return decision


def _redigest_document(value: dict, digest_field: str) -> dict:
    body = {key: item for key, item in value.items() if key != digest_field}
    encoded = json.dumps(
        body,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    value[digest_field] = "sha256:" + hashlib.sha256(encoded).hexdigest()
    return value


def _source_identity(
    repository_hex: str = "a", *, project_path: str = ".", dirty: bool = False
) -> dict[str, object]:
    return {
        "repositoryIdentity": "sha256:" + repository_hex * 64,
        "projectPath": project_path,
        "commit": "1" * 40,
        "treeDigest": "sha256:" + "2" * 64,
        "dirty": dirty,
        "dirtyDigest": "sha256:" + ("3" if dirty else "0") * 64,
        "descriptorDigest": "sha256:" + "4" * 64,
    }


def _source_selector(source: dict[str, object]) -> dict[str, str]:
    return {
        "repositoryIdentity": str(source["repositoryIdentity"]),
        "projectPath": str(source["projectPath"]),
    }


def test_balanced_is_default_and_hard_denies_are_explicit(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    assert manager.policy.default_profile == "balanced"
    assert manager.policy.hard_deny == {"force_push", "history_rewrite", "disable_safety_gates"}
    assert manager.policy.mode_for("balanced", "edit_scoped_files") == "auto_with_receipt"
    assert manager.policy.mode_for("balanced", "push_private_branch") == "approve_scope_once"
    assert manager.policy.mode_for("balanced", "apply_deployment") == "ask_each_time"
    assert manager.policy.mode_for("balanced", "merge") == "ask_each_time"


def test_grants_bind_the_exact_policy_and_legacy_records_fail_closed(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    grant = _activate(manager, _grant(manager))
    assert grant["policyDigest"] == manager.policy.policy_digest

    policy_value = yaml.safe_load((ROOT / "config/authority-policy.v1.yaml").read_text(encoding="utf-8"))
    policy_value["profiles"]["balanced"]["autoWithReceipt"].remove("edit_scoped_files")
    policy_value["profiles"]["balanced"]["approveScopeOnce"].append("edit_scoped_files")
    changed = AuthorityManager(
        manager.repository,
        state_root=manager.state_root,
        policy=manager.policy.from_mapping(policy_value),
    )
    assert changed.get_grant(grant["grantId"])["status"] == "policy_changed"
    decision = changed.evaluate(
        "run_tests",
        actor_id="agent-primary",
        grant_id=grant["grantId"],
        branch="agent/work",
        slice_id="BL-FIXTURE-001",
    )
    assert decision["decision"] == "denied"
    assert decision["reason"] == "grant_policy_changed"

    legacy_input = {
        key: value
        for key, value in _grant(manager, grant_id="grant_fixture_legacy").items()
        if key != "policyDigest"
    }
    legacy_input["grantDigest"] = None
    legacy = manager.prepare_grant(legacy_input)
    legacy_stored = {key: value for key, value in legacy.items() if key != "policyDigest"}
    manager._grant_path(legacy["grantId"]).write_text(json.dumps(legacy_stored), encoding="utf-8")
    assert manager.get_grant(legacy["grantId"])["status"] == "policy_unbound"


def test_read_and_tests_are_grantless_but_mutation_needs_scope(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    inspect = manager.evaluate("inspect_repository", actor_id="agent-primary")
    tests = manager.evaluate("run_tests", actor_id="agent-primary")
    edit = manager.evaluate("edit_scoped_files", actor_id="agent-primary", branch="agent/work", paths=["README.md"])
    assert inspect["decision"] == tests["decision"] == "authorized"
    assert inspect["authorizedBy"]["type"] == "policy_default"
    assert edit["decision"] == "approval_required"
    assert edit["reason"] == "standing_grant_required"


def test_balanced_grant_authorizes_local_work_and_named_private_transport(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    grant = _activate(manager, _grant(manager, allow=("push_private_branch", "open_draft_pr")))
    common = {
        "actor_id": "agent-primary",
        "grant_id": grant["grantId"],
        "branch": "agent/work",
        "slice_id": "BL-FIXTURE-001",
    }
    edit = manager.evaluate("edit_scoped_files", paths=["packages/example.py"], **common)
    push = manager.evaluate("push_private_branch", **common)
    merge = manager.evaluate("merge", assurances=["exact_head_verified", "required_gates_passed"], **common)
    assert edit["decision"] == push["decision"] == "authorized"
    assert push["policy"] == "auto_with_receipt"
    assert merge["decision"] == "approval_required"


def test_unique_matching_grant_is_selected_without_repeating_its_id(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    grant = _activate(manager, _grant(manager, allow=("push_private_branch",)))
    decision = manager.evaluate(
        "push_private_branch",
        actor_id="agent-primary",
        branch="agent/work",
        slice_id="BL-FIXTURE-001",
    )
    assert decision["decision"] == "authorized"
    assert decision["authorizedBy"]["id"] == grant["grantId"]


def test_multiple_matching_grants_fail_closed_as_ambiguous(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    _activate(manager, _grant(manager, grant_id="grant_fixture_first"))
    _activate(manager, _grant(manager, grant_id="grant_fixture_second"))
    decision = manager.evaluate(
        "run_tests",
        actor_id="agent-primary",
        branch="agent/work",
        slice_id="BL-FIXTURE-001",
    )
    assert decision["decision"] == "denied"
    assert decision["reason"] == "conflicting_policy_rules"


@pytest.mark.parametrize(
    ("branch", "slice_id", "paths", "reason"),
    [
        ("main", "BL-FIXTURE-001", ["packages/example.py"], "branch_outside_grant"),
        ("agent/work", "BL-OTHER-001", ["packages/example.py"], "sliceId_outside_grant"),
        ("agent/work", "BL-FIXTURE-001", ["secrets/example"], "path_outside_grant"),
    ],
)
def test_scope_mismatch_denies_without_ambiguity(
    tmp_path: Path,
    branch: str,
    slice_id: str,
    paths: list[str],
    reason: str,
) -> None:
    manager = _manager(tmp_path)
    grant = _activate(manager, _grant(manager, paths=("packages",)))
    decision = manager.evaluate(
        "edit_scoped_files",
        actor_id="agent-primary",
        grant_id=grant["grantId"],
        branch=branch,
        slice_id=slice_id,
        paths=paths,
    )
    assert decision["decision"] == "denied"
    assert decision["reason"] == reason


def test_deployment_source_scope_is_explicit_and_exact(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    source_a = _source_identity("a")
    source_b = _source_identity("b")
    legacy = _activate(
        manager,
        _grant(
            manager,
            grant_id="grant_fixture_legacy_source",
            allow=("plan_deployment",),
        ),
    )
    common = {
        "action": "plan_deployment",
        "actor_id": "agent-primary",
        "branch": "agent/work",
        "slice_id": "BL-FIXTURE-001",
        "application_id": "deployment-source",
        "paths": (".",),
    }
    denied = manager.evaluate(
        grant_id=legacy["grantId"], source_identity=source_a, **common
    )
    assert denied["decision"] == "denied"
    assert denied["reason"] == "deployment_source_outside_grant"

    exact = _activate(
        manager,
        _grant(
            manager,
            grant_id="grant_fixture_exact_source",
            allow=("plan_deployment",),
            deployment_sources=(_source_selector(source_a),),
        ),
    )
    authorized = manager.evaluate(
        grant_id=exact["grantId"], source_identity=source_a, **common
    )
    assert authorized["decision"] == "authorized"
    wrong_repository = manager.evaluate(
        grant_id=exact["grantId"], source_identity=source_b, **common
    )
    assert wrong_repository["decision"] == "denied"
    assert wrong_repository["reason"] == "deployment_source_outside_grant"
    wrong_path = manager.evaluate(
        grant_id=exact["grantId"],
        source_identity=_source_identity("a", project_path="other"),
        **common,
    )
    assert wrong_path["reason"] == "deployment_source_outside_grant"

    successor = deepcopy(source_a)
    successor["commit"] = "5" * 40
    successor["treeDigest"] = "sha256:" + "6" * 64
    successor_decision = manager.evaluate(
        grant_id=exact["grantId"], source_identity=successor, **common
    )
    assert successor_decision["decision"] == "authorized"
    assert successor_decision["requestedCapabilities"]["sourceIdentity"] == successor


def test_deployment_source_scope_filters_implicit_grants_and_revalidation(
    tmp_path: Path,
) -> None:
    manager = _manager(tmp_path)
    source_a = _source_identity("a")
    source_b = _source_identity("b")
    grant_a = _activate(
        manager,
        _grant(
            manager,
            grant_id="grant_fixture_source_a",
            allow=("plan_deployment",),
            deployment_sources=(_source_selector(source_a),),
        ),
    )
    _activate(
        manager,
        _grant(
            manager,
            grant_id="grant_fixture_source_b",
            allow=("plan_deployment",),
            deployment_sources=(_source_selector(source_b),),
        ),
    )
    common = {
        "actor_id": "agent-primary",
        "branch": "agent/work",
        "slice_id": "BL-FIXTURE-001",
        "application_id": "deployment-source",
        "paths": (".",),
    }
    selected = manager.evaluate(
        "plan_deployment", source_identity=source_a, **common
    )
    assert selected["decision"] == "authorized"
    assert selected["authorizedBy"]["id"] == grant_a["grantId"]

    substituted = deepcopy(selected)
    substituted["requestedCapabilities"]["sourceIdentity"] = source_b
    _redigest_decision(substituted)
    with pytest.raises(AuthorityError) as raised:
        manager._reserve_evaluated_decision(substituted)
    assert raised.value.code == "deployment_source_outside_grant"


def test_deployment_source_scope_delegation_and_shape_fail_closed(
    tmp_path: Path,
) -> None:
    manager = _manager(tmp_path)
    source = _source_identity("a")
    parent = _activate(
        manager,
        _grant(
            manager,
            grant_id="grant_fixture_source_parent",
            allow=("plan_deployment",),
            can_delegate=True,
        ),
    )
    child = _grant(
        manager,
        grant_id="grant_fixture_source_child",
        actor_id="agent-child",
        role="subagent",
        allow=("plan_deployment",),
        parent_grant_id=parent["grantId"],
        deployment_sources=(_source_selector(source),),
    )
    with pytest.raises(AuthorityRefusal) as broadened:
        manager.activate_grant(child, owner_actor_id="owner-local")
    assert broadened.value.code == "delegation_scope_broadened"

    malformed_cases = (
        [],
        [{"repositoryIdentity": "not-a-digest", "projectPath": "."}],
        [{"repositoryIdentity": "sha256:" + "a" * 64, "projectPath": "../x"}],
        [
            {"repositoryIdentity": "sha256:" + "a" * 64, "projectPath": "."},
            {"repositoryIdentity": "sha256:" + "a" * 64, "projectPath": "."},
        ],
    )
    for index, selectors in enumerate(malformed_cases):
        value = _grant(
            manager,
            grant_id=f"grant_fixture_bad_source_{index}",
        )
        value["scope"]["deploymentSources"] = selectors
        value["grantDigest"] = None
        with pytest.raises(AuthorityError, match="deployment source"):
            manager.prepare_grant(value)


def test_subagent_grant_must_be_narrower_and_cannot_change_project_state(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    parent = _activate(
        manager,
        _grant(
            manager,
            grant_id="grant_fixture_parent",
            profile="delegated",
            paths=("packages",),
            can_delegate=True,
            network="allowlisted",
            allowed_domains=("api.example.invalid",),
            providers=("fixture-provider",),
        ),
    )
    child = _activate(
        manager,
        _grant(
            manager,
            grant_id="grant_fixture_child",
            profile="guarded",
            actor_id="agent-child",
            role="subagent",
            branch_pattern="agent/child-*",
            paths=("packages/example",),
            parent_grant_id=parent["grantId"],
            network="denied",
        ),
    )
    read = manager.evaluate(
        "inspect_repository",
        actor_id="agent-child",
        grant_id=child["grantId"],
        branch="agent/child-one",
        slice_id="BL-FIXTURE-001",
    )
    state = manager.evaluate(
        "update_project_state",
        actor_id="agent-child",
        grant_id=child["grantId"],
        branch="agent/child-one",
        slice_id="BL-FIXTURE-001",
        paths=["PROJECT_STATE.yaml"],
    )
    assert read["decision"] == "authorized"
    assert state["decision"] == "denied"
    assert state["reason"] == "subagent_default_deny"


def test_subagent_cannot_broaden_parent_file_scope(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    parent = _activate(
        manager,
        _grant(manager, grant_id="grant_fixture_parent", profile="delegated", paths=("packages",), can_delegate=True),
    )
    child = _grant(
        manager,
        grant_id="grant_fixture_child",
        profile="guarded",
        actor_id="agent-child",
        role="subagent",
        paths=(".",),
        parent_grant_id=parent["grantId"],
    )
    with pytest.raises(AuthorityRefusal, match="delegation_scope_broadened"):
        manager.activate_grant(child, owner_actor_id="owner-local")


def test_parent_revocation_immediately_expires_child_authority(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    parent = _activate(
        manager,
        _grant(manager, grant_id="grant_fixture_parent", profile="delegated", can_delegate=True),
    )
    child = _activate(
        manager,
        _grant(
            manager,
            grant_id="grant_fixture_child",
            profile="guarded",
            actor_id="agent-child",
            role="subagent",
            parent_grant_id=parent["grantId"],
        ),
    )
    manager.revoke_grant(
        parent["grantId"],
        actor_id="owner-local",
        owner_directive_id="OD-REVOKE-PARENT-001",
        reason="parent scope withdrawn",
    )
    decision = manager.evaluate(
        "run_tests",
        actor_id="agent-child",
        grant_id=child["grantId"],
        branch="agent/child-one",
        slice_id="BL-FIXTURE-001",
    )
    assert decision["decision"] == "denied"
    assert decision["reason"] == "grant_parent_inactive"
    assert manager.get_grant(child["grantId"])["status"] == "parent_inactive"


def test_child_actions_consume_the_parent_action_budget(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    parent = _activate(
        manager,
        _grant(
            manager,
            grant_id="grant_fixture_parent",
            profile="delegated",
            can_delegate=True,
            max_actions=1,
        ),
    )
    child = _activate(
        manager,
        _grant(
            manager,
            grant_id="grant_fixture_child",
            profile="guarded",
            actor_id="agent-child",
            role="subagent",
            parent_grant_id=parent["grantId"],
            max_actions=1,
        ),
    )
    manager.execute(
        "run_tests",
        lambda: "passed",
        actor_id="agent-child",
        grant_id=child["grantId"],
        branch="agent/child-one",
        slice_id="BL-FIXTURE-001",
    )
    assert manager.get_grant(parent["grantId"])["status"] == "budget_exhausted"
    assert manager.get_grant(child["grantId"])["status"] == "parent_inactive"


def test_pause_resume_and_revoke_are_immediate_and_receipted(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    grant = _activate(manager, _grant(manager))
    common = {
        "actor_id": "agent-primary",
        "grant_id": grant["grantId"],
        "branch": "agent/work",
        "slice_id": "BL-FIXTURE-001",
        "paths": ["README.md"],
    }
    paused = manager.set_paused(
        paused=True,
        actor_id="owner-local",
        owner_directive_id="OD-PAUSE-001",
        reason="operator pause",
    )
    assert paused["receipt"]["result"]["status"] == "succeeded"
    assert manager.evaluate("edit_scoped_files", **common)["reason"] == "autonomous_execution_paused"
    manager.set_paused(
        paused=False,
        actor_id="owner-local",
        owner_directive_id="OD-RESUME-001",
        reason="operator resume",
    )
    assert manager.evaluate("edit_scoped_files", **common)["decision"] == "authorized"
    revoked = manager.revoke_grant(
        grant["grantId"],
        actor_id="owner-local",
        owner_directive_id="OD-REVOKE-001",
        reason="owner revoked scope",
    )
    assert revoked["receipt"]["authorizedBy"]["type"] == "owner_directive"
    assert manager.evaluate("edit_scoped_files", **common)["reason"] == "grant_revoked"


def test_pause_failure_leaves_explicit_recovery_attention(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager = _manager(tmp_path)
    _activate(manager, _grant(manager))

    def fail_receipt(*_args: object, **_kwargs: object) -> dict[str, Any]:
        raise AuthorityError("receipt_write_failed", "injected receipt failure")

    monkeypatch.setattr(manager, "_owner_receipt_unlocked", fail_receipt)
    with pytest.raises(AuthorityError, match="receipt_write_failed"):
        manager.set_paused(
            paused=True,
            actor_id="owner-local",
            owner_directive_id="OD-PAUSE-FAILURE-001",
            reason="operator pause",
        )
    attention = manager.recovery_attention()
    assert attention[0]["operation"] == "pause"
    assert manager.inspect()["recoveryAttention"] == attention


def test_revoke_failure_leaves_explicit_recovery_attention(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager = _manager(tmp_path)
    grant = _activate(manager, _grant(manager))

    def fail_receipt(*_args: object, **_kwargs: object) -> dict[str, Any]:
        raise AuthorityError("receipt_write_failed", "injected receipt failure")

    monkeypatch.setattr(manager, "_owner_receipt_unlocked", fail_receipt)
    with pytest.raises(AuthorityError, match="receipt_write_failed"):
        manager.revoke_grant(
            grant["grantId"],
            actor_id="owner-local",
            owner_directive_id="OD-REVOKE-FAILURE-001",
            reason="owner revoked scope",
        )
    attention = manager.recovery_attention()
    assert attention[0]["operation"] == "revoke"
    assert attention[0]["targetId"] == grant["grantId"]
    assert manager.inspect()["recoveryAttention"] == attention


def test_one_time_override_is_consumed_after_one_recorded_action(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    grant = _activate(
        manager,
        _grant(
            manager,
            kind="one_time",
            expires_when="one_action",
            allow=("push_private_branch",),
            max_actions=1,
        ),
    )
    kwargs = {
        "actor_id": "agent-primary",
        "grant_id": grant["grantId"],
        "branch": "agent/work",
        "slice_id": "BL-FIXTURE-001",
    }
    result, receipt = manager.execute("push_private_branch", lambda: "ok", **kwargs)
    assert result == "ok"
    assert receipt["schema"] == AUTHORITY_ACTION_RECEIPT_SCHEMA
    assert receipt["authorizedBy"]["id"] == grant["grantId"]
    assert receipt["policy"] == "auto_with_receipt"
    assert receipt["result"]["status"] == "succeeded"
    jsonschema.Draft202012Validator(
        json.loads((ROOT / "schemas/authority-grant.v1.schema.json").read_text(encoding="utf-8")),
        format_checker=jsonschema.FormatChecker(),
    ).validate(grant)
    jsonschema.Draft202012Validator(
        json.loads((ROOT / "schemas/authority-action-receipt.v1.schema.json").read_text(encoding="utf-8")),
        format_checker=jsonschema.FormatChecker(),
    ).validate(receipt)
    reservation = manager.get_reservation(receipt["requestId"])
    claim = manager.get_claim(receipt["requestId"])
    jsonschema.Draft202012Validator(
        json.loads(
            (
                ROOT / "schemas/authority-action-reservation.v1.schema.json"
            ).read_text(encoding="utf-8")
        ),
        format_checker=jsonschema.FormatChecker(),
    ).validate(reservation)
    jsonschema.Draft202012Validator(
        json.loads(
            (ROOT / "schemas/authority-action-claim.v1.schema.json").read_text(
                encoding="utf-8"
            )
        ),
        format_checker=jsonschema.FormatChecker(),
    ).validate(claim)
    assert receipt["reservation"] == {
        "reservationId": reservation["reservationId"],
        "reservationDigest": reservation["reservationDigest"],
    }
    assert receipt["claim"] == {
        "claimId": claim["claimId"],
        "claimDigest": claim["claimDigest"],
    }
    assert manager.evaluate("push_private_branch", **kwargs)["reason"] == "grant_consumed"


def test_reservation_consumes_budget_before_operation_and_survives_crash(
    tmp_path: Path,
) -> None:
    manager = _manager(tmp_path)
    grant = _activate(
        manager,
        _grant(
            manager,
            kind="one_time",
            expires_when="one_action",
            allow=("push_private_branch",),
            max_actions=1,
        ),
    )
    kwargs = {
        "actor_id": "agent-primary",
        "grant_id": grant["grantId"],
        "branch": "agent/work",
        "slice_id": "BL-FIXTURE-001",
    }
    decision, reservation = manager.reserve_action(
        "push_private_branch", **kwargs
    )
    assert decision["decision"] == "authorized"
    assert reservation is not None
    refused, second_reservation = manager.reserve_action(
        "push_private_branch", **kwargs
    )
    assert refused["decision"] == "denied"
    assert refused["reason"] in {"grant_consumed", "action_budget_exceeded"}
    assert second_reservation is None
    assert manager.get_reservation(decision["requestId"]) == reservation
    assert manager.get_grant(grant["grantId"])["status"] in {
        "consumed",
        "budget_exhausted",
    }


def test_authorized_action_cannot_finalize_without_preexecution_reservation(
    tmp_path: Path,
) -> None:
    manager = _manager(tmp_path)
    grant = _activate(manager, _grant(manager, allow=("push_private_branch",)))
    decision = manager.evaluate(
        "push_private_branch",
        actor_id="agent-primary",
        grant_id=grant["grantId"],
        branch="agent/work",
        slice_id="BL-FIXTURE-001",
    )
    with pytest.raises(AuthorityError) as raised:
        manager.record_action(
            decision,
            result_status="succeeded",
            summary="must not reserve at finalization",
        )
    assert raised.value.code == "authority_reservation_required"


def test_reservation_cannot_finalize_a_different_self_digested_decision(
    tmp_path: Path,
) -> None:
    manager = _manager(tmp_path)
    grant = _activate(manager, _grant(manager, allow=("push_private_branch",)))
    decision, reservation = manager.reserve_action(
        "push_private_branch",
        actor_id="agent-primary",
        grant_id=grant["grantId"],
        branch="agent/work",
        slice_id="BL-FIXTURE-001",
    )
    assert reservation is not None
    forged = deepcopy(decision)
    forged["scope"]["applicationId"] = "forged-application"
    _redigest_decision(forged)
    with pytest.raises(AuthorityError) as raised:
        manager.record_action(
            forged,
            result_status="succeeded",
            summary="forged finalization",
            reservation=reservation,
        )
    assert raised.value.code == "authority_reservation_mismatch"


def test_incomplete_merge_assurances_cannot_be_forged_into_a_reservation(
    tmp_path: Path,
) -> None:
    manager = _manager(tmp_path)
    grant = _activate(manager, _grant(manager, profile="delegated"))
    decision = manager.evaluate(
        "merge",
        actor_id="agent-primary",
        grant_id=grant["grantId"],
        branch="agent/work",
        slice_id="BL-FIXTURE-001",
        assurances=("exact_head_verified",),
    )
    assert decision["decision"] == "approval_required"
    forged = deepcopy(decision)
    forged.update(
        decision="authorized",
        policy="auto_with_receipt",
        reason="standing_scope_approved",
        missingAssurances=[],
    )
    _redigest_decision(forged)
    assert not hasattr(manager, "reserve_decision")
    with pytest.raises(AuthorityError) as raised:
        manager._reserve_evaluated_decision(forged)
    assert raised.value.code == "merge_assurance_missing"


def test_pending_estimated_cost_is_reserved_before_finalization(
    tmp_path: Path,
) -> None:
    manager = _manager(tmp_path)
    grant = _activate(
        manager,
        _grant(manager, max_actions=10, max_cost_usd=1.0),
    )
    common = {
        "actor_id": "agent-primary",
        "grant_id": grant["grantId"],
        "branch": "agent/work",
        "slice_id": "BL-FIXTURE-001",
        "estimated_cost_usd": 0.75,
    }
    first, reservation = manager.reserve_action("run_tests", **common)
    assert first["decision"] == "authorized"
    assert reservation is not None
    second, second_reservation = manager.reserve_action("run_tests", **common)
    assert second["decision"] == "approval_required"
    assert second["reason"] == "cost_budget_exceeded"
    assert second_reservation is None


@pytest.mark.parametrize("control", ("pause", "revoke"))
def test_pause_or_revoke_after_reservation_blocks_the_effect(
    tmp_path: Path, control: str
) -> None:
    manager = _manager(tmp_path)
    grant = _activate(manager, _grant(manager, allow=("push_private_branch",)))
    decision, reservation = manager.reserve_action(
        "push_private_branch",
        actor_id="agent-primary",
        grant_id=grant["grantId"],
        branch="agent/work",
        slice_id="BL-FIXTURE-001",
    )
    assert reservation is not None
    if control == "pause":
        manager.set_paused(
            paused=True,
            actor_id="owner-local",
            owner_directive_id="OD-PAUSE-RESERVED-001",
            reason="pause before effect",
        )
    else:
        manager.revoke_grant(
            grant["grantId"],
            actor_id="owner-local",
            owner_directive_id="OD-REVOKE-RESERVED-001",
            reason="revoke before effect",
        )
    with pytest.raises(AuthorityError) as raised:
        manager.claim_reserved_decision(decision)
    assert raised.value.code in {"autonomous_execution_paused", "grant_inactive"}


def test_claimed_action_cannot_be_finalized_as_not_executed(
    tmp_path: Path,
) -> None:
    manager = _manager(tmp_path)
    grant = _activate(manager, _grant(manager, allow=("push_private_branch",)))
    decision, reservation = manager.reserve_action(
        "push_private_branch",
        actor_id="agent-primary",
        grant_id=grant["grantId"],
        branch="agent/work",
        slice_id="BL-FIXTURE-001",
    )
    assert reservation is not None
    claimed = manager.claim_reserved_decision(decision)
    with pytest.raises(AuthorityError) as raised:
        manager.record_action(
            decision,
            result_status="not_executed",
            summary="must not erase a claimed effect",
            reservation=reservation,
            claim=claimed["claim"],
        )
    assert raised.value.code == "authority_claim_outcome_mismatch"


def test_claim_cross_link_tamper_fails_closed(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    grant = _activate(manager, _grant(manager, allow=("push_private_branch",)))
    decision, reservation = manager.reserve_action(
        "push_private_branch",
        actor_id="agent-primary",
        grant_id=grant["grantId"],
        branch="agent/work",
        slice_id="BL-FIXTURE-001",
    )
    assert reservation is not None
    claimed = manager.claim_reserved_decision(decision)["claim"]
    path = manager._claim_path(claimed["claimId"])
    tampered = deepcopy(claimed)
    tampered["reservationDigest"] = "sha256:" + "f" * 64
    _redigest_document(tampered, "claimDigest")
    path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(AuthorityError, match="canonical reservation"):
        manager.get_claim(decision["requestId"])


def test_result_evidence_failure_is_terminally_receipted(
    tmp_path: Path,
) -> None:
    manager = _manager(tmp_path)
    observed: list[str] = []

    def operation() -> str:
        observed.append("effect")
        return "done"

    def broken_projection(_result: str) -> dict:
        raise RuntimeError("projection failed")

    with pytest.raises(RuntimeError) as raised:
        manager.execute(
            "run_tests",
            operation,
            actor_id="agent-primary",
            resource_from_result=broken_projection,
        )
    assert observed == ["effect"]
    receipt = getattr(raised.value, "authority_receipt")
    assert receipt["result"]["status"] == "failed"
    assert receipt["result"]["code"] == "result_evidence_failed"
    assert receipt["claim"] is not None


def test_network_provider_secret_and_budget_limits_escalate(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    grant = _activate(
        manager,
        _grant(
            manager,
            allow=("network_access", "provider_access", "real_secret_use"),
            network="allowlisted",
            allowed_domains=("api.example.invalid",),
            providers=("fixture-provider",),
            secret_capabilities=("fixture-secret",),
            max_duration_seconds=60,
            max_cost_usd=1.0,
        ),
    )
    base = {
        "actor_id": "agent-primary",
        "grant_id": grant["grantId"],
        "branch": "agent/work",
        "slice_id": "BL-FIXTURE-001",
    }
    assert manager.evaluate("network_access", domains=["api.example.invalid"], **base)["decision"] == "authorized"
    assert manager.evaluate("network_access", domains=["other.example.invalid"], **base)["reason"] == "network_domain_outside_grant"
    assert manager.evaluate("provider_access", provider="other-provider", **base)["reason"] == "provider_outside_grant"
    assert manager.evaluate("real_secret_use", secret_capabilities=["other-secret"], **base)["reason"] == "secret_capability_outside_grant"
    assert manager.evaluate("run_tests", estimated_duration_seconds=61, **base)["reason"] == "time_budget_exceeded"
    assert manager.evaluate("run_tests", estimated_cost_usd=1.01, **base)["reason"] == "cost_budget_exceeded"
    with pytest.raises(AuthorityError, match="exact requested domains"):
        manager.evaluate("network_access", **base)
    with pytest.raises(AuthorityError, match="exact provider"):
        manager.evaluate("provider_access", **base)
    with pytest.raises(AuthorityError, match="exact capability"):
        manager.evaluate("real_secret_use", **base)


def test_delegated_merge_requires_exact_head_and_gate_assurances(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    grant = _activate(manager, _grant(manager, profile="delegated"))
    base = {
        "actor_id": "agent-primary",
        "grant_id": grant["grantId"],
        "branch": "agent/work",
        "slice_id": "BL-FIXTURE-001",
    }
    missing = manager.evaluate("merge", assurances=["exact_head_verified"], **base)
    complete = manager.evaluate("merge", assurances=["exact_head_verified", "required_gates_passed"], **base)
    assert missing["decision"] == "approval_required"
    assert missing["reason"] == "merge_assurance_missing"
    assert complete["decision"] == "authorized"


def test_non_negotiable_deny_cannot_be_overridden_by_grant(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    grant = _activate(manager, _grant(manager, profile="delegated", allow=("force_push",)))
    decision = manager.evaluate(
        "force_push",
        actor_id="agent-primary",
        grant_id=grant["grantId"],
        branch="agent/work",
        slice_id="BL-FIXTURE-001",
    )
    assert decision["decision"] == "denied"
    assert decision["reason"] == "non_negotiable_policy"


def test_refused_execution_produces_not_executed_receipt(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    called = False

    def operation() -> str:
        nonlocal called
        called = True
        return "should not run"

    with pytest.raises(AuthorityRefusal) as captured:
        manager.execute(
            "push_private_branch",
            operation,
            actor_id="agent-primary",
            branch="agent/work",
            slice_id="BL-FIXTURE-001",
        )
    assert called is False
    receipt = captured.value.receipt
    assert receipt is not None
    assert receipt["result"]["status"] == "not_executed"
    assert manager.get_receipt(receipt["receiptId"]) == receipt


def test_tampered_grant_and_receipt_fail_closed(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    grant = _activate(manager, _grant(manager))
    grant_path = manager._grant_path(grant["grantId"])
    tampered = json.loads(grant_path.read_text(encoding="utf-8"))
    tampered["profile"] = "delegated"
    grant_path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(AuthorityError, match="grant digest is invalid"):
        manager.get_grant(grant["grantId"])
