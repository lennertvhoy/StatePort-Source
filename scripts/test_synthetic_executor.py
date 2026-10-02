"""Focused tests for the deterministic, non-production synthetic executor."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "execution-host" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "synthetic-executor" / "src"))

from execution_host.contracts import AgentRunSpec, CapabilityRequest, validate_run_result  # noqa: E402
from synthetic_executor import (  # noqa: E402
    EVENT_FORMAT_VERSION,
    Scenario,
    SyntheticEventError,
    SyntheticExecutor,
    assert_production_ineligible,
    validate_events,
)


def spec() -> AgentRunSpec:
    return AgentRunSpec(
        "run:synthetic",
        "instance:synthetic",
        "revision:synthetic",
        "exercise deterministic synthetic execution",
        "statepack:synthetic",
        "sha256:" + "a" * 64,
        (CapabilityRequest("structuredEvents"), CapabilityRequest("nonInteractiveExecution")),
        ("changedFileReporting",),
        "synthetic",
        "synthetic-executor",
        "1.0.0",
        "synthetic-model",
        "external_manual",
        (),
        "synthetic-sandbox",
        {"token": 100, "costMinor": 0, "timeSeconds": 10, "steps": 10},
        ("python3 scripts/validate_repo.py",),
        ("evidence/result.json",),
        {"fixture": "synthetic"},
        approval_required_level="external_manual",
        repository_instructions=("Read the repository instructions.",),
    )


@pytest.mark.parametrize(
    ("scenario", "status", "failure", "termination"),
    [
        (Scenario.SUCCESS, "completed", None, "success"),
        (Scenario.APPROVAL_REQUIRED, "prepared", "approval_required", "success"),
        (Scenario.REJECTED_ACTION, "failed", "rejected_action", "success"),
        (Scenario.CANCELLATION, "cancelled", "cancelled", "cancelled"),
        (Scenario.TIMEOUT, "failed", "timeout", "timeout"),
        (Scenario.MALFORMED_EVENT, "failed", "malformed_event", "success"),
        (Scenario.VALIDATION_FAILURE, "failed", "validation_failure", "success"),
        (Scenario.NO_OP, "completed", None, "success"),
    ],
)
def test_every_scripted_scenario_returns_bound_result(
    scenario, status, failure, termination
) -> None:
    execution = SyntheticExecutor().run(spec(), scenario=scenario)
    assert execution.run_result["executionStatus"] == status
    assert execution.run_result["failureClassification"] == failure
    assert execution.run_result["terminationClassification"] == termination
    assert execution.run_result["verificationStatus"] == "synthetic_test_only"
    assert execution.production_eligible is False
    assert validate_run_result(execution.run_result, spec())["runId"] == "run:synthetic"
    assert validate_events(execution.events, run_id="run:synthetic") == execution.events


def test_success_has_structured_tools_proposal_validation_and_noop_has_none() -> None:
    executor = SyntheticExecutor()
    success = executor.run(spec(), scenario="success")
    assert [event["eventType"] for event in success.events] == [
        "run.started",
        "tool.requested",
        "tool.requested",
        "file.change_proposed",
        "validation.completed",
        "run.completed",
    ]
    assert [request["tool"] for request in success.tool_requests] == ["statepack.read", "file_change.propose"]
    assert success.tool_requests[0]["simulated"] is True
    assert success.changed_file_proposals[0]["materialized"] is False
    assert success.run_result["changedFiles"] == list(success.changed_file_proposals)
    assert success.run_result["validationOutcomes"][0]["executed"] is False

    noop = executor.run(spec(), scenario=Scenario.NO_OP)
    assert noop.tool_requests == ()
    assert noop.changed_file_proposals == ()
    assert [event["eventType"] for event in noop.events] == ["run.started", "run.no_op", "run.completed"]


def test_approval_and_rejection_are_distinct_and_do_not_materialize_changes() -> None:
    executor = SyntheticExecutor()
    approval = executor.run(spec(), scenario=Scenario.APPROVAL_REQUIRED)
    assert approval.run_result["executionStatus"] == "prepared"
    assert [event["eventType"] for event in approval.events][-2:] == ["approval.required", "run.paused"]
    assert approval.changed_file_proposals == ()

    rejected = executor.run(spec(), scenario=Scenario.REJECTED_ACTION)
    assert rejected.run_result["failureClassification"] == "rejected_action"
    assert [event["eventType"] for event in rejected.events][-2:] == ["action.rejected", "run.failed"]
    assert rejected.changed_file_proposals == ()


def test_usage_marker_is_explicit_but_run_result_telemetry_is_honest() -> None:
    execution = SyntheticExecutor().run(spec())
    assert execution.usage.to_dict() == {
        "marker": "synthetic-deterministic-v1",
        "tokenUnits": 17,
        "costMinor": 0,
        "realProviderUsage": False,
    }
    assert execution.run_result["usage"] == {
        "token": {"quality": "unavailable", "value": None},
        "cost": {"quality": "unavailable", "value": None},
    }
    assert any("usage marker: synthetic-deterministic-v1" in warning for warning in execution.run_result["warnings"])
    assert any(item["kind"] == "synthetic_usage_marker" for item in execution.run_result["producedArtifacts"])


def test_repeated_runs_have_identical_events_digests_and_results() -> None:
    executor = SyntheticExecutor()
    first = executor.run(spec(), scenario=Scenario.VALIDATION_FAILURE)
    second = executor.run(spec(), scenario=Scenario.VALIDATION_FAILURE)
    assert first.events == second.events
    assert first.event_digest == second.event_digest
    assert first.run_result == second.run_result
    assert json.dumps(first.to_dict(), sort_keys=True) == json.dumps(second.to_dict(), sort_keys=True)
    assert first.events[-1]["digest"].startswith("sha256:")


def test_event_validator_rejects_tampering_and_malformed_envelopes() -> None:
    execution = SyntheticExecutor().run(spec())
    tampered = [dict(event) for event in execution.events]
    tampered[1]["payload"] = {"tool": "network.request"}
    with pytest.raises(SyntheticEventError, match="digest"):
        validate_events(tampered, run_id=spec().run_id)

    malformed = [copy.deepcopy(execution.events[0])]
    del malformed[0]["payload"]
    with pytest.raises(SyntheticEventError, match="invalid shape"):
        validate_events(malformed, run_id=spec().run_id)

    assert execution.events[0]["formatVersion"] == EVENT_FORMAT_VERSION


def test_capabilities_and_production_boundary_are_explicit() -> None:
    executor = SyntheticExecutor()
    capabilities = executor.describe_capabilities()
    assert capabilities.test_only is True
    assert capabilities.production_eligible is False
    assert executor.production_eligible is False
    with pytest.raises(ValueError, match="production-ineligible"):
        assert_production_ineligible(type("BadExecutor", (), {"describe_capabilities": lambda self: capabilities, "production_eligible": True})())


def test_adapter_surface_returns_unchanged_run_result_and_rejects_bad_prepared_identity() -> None:
    executor = SyntheticExecutor()
    prepared = executor.prepare(spec(), scenario=Scenario.SUCCESS)
    result = executor.execute(prepared)
    assert set(result) == {
        "formatVersion",
        "runId",
        "runSpecDigest",
        "backend",
        "model",
        "authenticationRouteClass",
        "statePack",
        "toolPolicy",
        "sandbox",
        "executionStatus",
        "verificationStatus",
        "timestamps",
        "failureClassification",
        "terminationClassification",
        "usage",
        "changedFiles",
        "validationOutcomes",
        "producedArtifacts",
        "approvalReference",
        "auditReferences",
        "warnings",
        "degradations",
    }
    invalid = dict(prepared)
    invalid["productionEligible"] = True
    with pytest.raises(ValueError, match="production-ineligible"):
        executor.run(invalid)
