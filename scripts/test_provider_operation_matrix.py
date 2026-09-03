#!/usr/bin/env python3
"""Truthfulness checks for the non-probing provider operation matrix."""

from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages/execution-host/src"))

from execution_host import PROVIDER_OPERATION_FIELDS, provider_operation_matrix  # noqa: E402


def test_matrix_covers_every_required_operation_for_each_provider_without_probe_results() -> (
    None
):
    matrix = provider_operation_matrix()
    assert matrix["formatVersion"] == "stateport.provider-operation-matrix/v1"
    assert (
        matrix["observation"]
        == "static_implementation_truth_no_provider_or_credential_probe"
    )
    rows = {item["provider"]: item["operations"] for item in matrix["providers"]}
    assert set(rows) == {"codex", "opencode", "pi"}
    for operations in rows.values():
        assert set(operations) == set(PROVIDER_OPERATION_FIELDS)
        assert all(set(claim) == {"status", "basis"} for claim in operations.values())


def test_codex_existing_work_remains_environment_gated_and_ineligible() -> None:
    rows = {
        item["provider"]: item["operations"]
        for item in provider_operation_matrix()["providers"]
    }
    codex = rows["codex"]
    assert codex["detection"]["status"] == "implemented"
    assert codex["preparation"]["status"] == "implemented"
    for operation in ("processInvocation", "structuredOutput", "liveModelExecution"):
        assert codex[operation]["status"] == "environment_gated"
    assert codex["eventStreaming"]["status"] == "not_implemented"
    assert codex["resume"]["status"] == "unsupported"
    assert codex["filesystemDiffCapture"]["status"] == "not_implemented"
    assert codex["authenticationReadiness"]["status"] == "unverified"
    assert codex["spendReadiness"]["status"] == "unverified"
    assert codex["productionEligibility"]["status"] == "ineligible"


def test_opencode_and_pi_do_not_borrow_codex_or_fake_backend_readiness() -> None:
    rows = {
        item["provider"]: item["operations"]
        for item in provider_operation_matrix()["providers"]
    }
    pi_operations = rows["pi"]
    assert pi_operations["detection"]["status"] == "implemented"
    for operation in (
        "preparation",
        "processInvocation",
        "eventStreaming",
        "resume",
        "cancel",
        "structuredOutput",
        "filesystemDiffCapture",
    ):
        assert pi_operations[operation]["status"] == "not_implemented"
    assert pi_operations["liveModelExecution"]["status"] == "environment_gated"
    assert pi_operations["authenticationReadiness"]["status"] == "unverified"
    assert pi_operations["spendReadiness"]["status"] == "unverified"
    assert pi_operations["productionEligibility"]["status"] == "ineligible"

    opencode = rows["opencode"]
    assert opencode["detection"]["status"] == "implemented"
    for operation in (
        "preparation",
        "processInvocation",
        "eventStreaming",
        "cancel",
        "structuredOutput",
        "filesystemDiffCapture",
    ):
        assert opencode[operation]["status"] == "implemented"
    assert opencode["resume"]["status"] == "unsupported"
    assert opencode["liveModelExecution"]["status"] == "environment_gated"
    assert opencode["authenticationReadiness"]["status"] == "unverified"
    assert opencode["spendReadiness"]["status"] == "unverified"
    assert opencode["productionEligibility"]["status"] == "ineligible"
    assert "isolated post-agent validation is not implemented" in opencode[
        "productionEligibility"
    ]["basis"]
