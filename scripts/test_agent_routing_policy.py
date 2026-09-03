"""Focused regression tests for the declarative agent-routing policy."""
from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "packages" / "statedd-core" / "src"))

from validate_agent_routing_policy import load_policy, validate_policy_data

POLICY_PATH = ROOT / "config" / "agent-routing-policy.yaml"
SCHEMA_PATH = ROOT / "schemas" / "agent-routing-policy.schema.json"
VALIDATOR = ROOT / "scripts" / "validate_agent_routing_policy.py"


def policy() -> dict[str, object]:
    return copy.deepcopy(load_policy(POLICY_PATH))


def issues(data: dict[str, object]) -> list[object]:
    return validate_policy_data(data, json.loads(SCHEMA_PATH.read_text(encoding="utf-8")))


def test_policy_parser_and_schema_semantics_agree_for_canonical_policy() -> None:
    assert not issues(policy())
    result = subprocess.run([sys.executable, str(VALIDATOR)], cwd=ROOT, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stdout + result.stderr


def test_unknown_profile_is_rejected() -> None:
    data = policy()
    data["roles"]["scout"]["preferredProfile"] = "unknown-profile"  # type: ignore[index]
    assert any("preferredProfile" in issue.path for issue in issues(data))


def test_invalid_access_is_rejected() -> None:
    data = policy()
    data["roles"]["defaultImplementer"]["access"] = "network-admin"  # type: ignore[index]
    assert any("access" in issue.path for issue in issues(data))


def test_max_depth_above_one_is_rejected() -> None:
    data = policy()
    data["limits"]["maxDepth"] = 2  # type: ignore[index]
    assert any(issue.path == "$.limits.maxDepth" for issue in issues(data))


def test_read_only_roles_cannot_receive_write_access() -> None:
    for role in ("scout", "architect", "reviewer"):
        data = policy()
        data["roles"][role]["access"] = "workspace-write"  # type: ignore[index]
        assert any(issue.path == f"$.roles.{role}.access" for issue in issues(data))


def test_missing_escalation_criteria_are_rejected() -> None:
    data = policy()
    data["escalation"]["passingTestsUnclear"].remove("recovery")  # type: ignore[index]
    assert any(issue.path == "$.escalation.passingTestsUnclear" for issue in issues(data))


def test_second_failed_repair_loop_is_rejected() -> None:
    data = policy()
    data["escalation"]["failedRepairLoops"] = 2  # type: ignore[index]
    assert any(issue.path == "$.escalation.failedRepairLoops" for issue in issues(data))


def test_model_identity_alone_cannot_invalidate_correct_output() -> None:
    data = policy()
    data["routingDeviation"]["invalidatesOutput"] = True  # type: ignore[index]
    assert any(issue.path == "$.routingDeviation.invalidatesOutput" for issue in issues(data))


def test_model_identity_alone_cannot_authorize_a_full_rerun() -> None:
    data = policy()
    data["routingDeviation"]["fullRerunAllowedOnlyFor"][0] = "model_identity_only"  # type: ignore[index]
    assert any(issue.path == "$.routingDeviation.fullRerunAllowedOnlyFor" for issue in issues(data))


def test_routing_deviation_review_and_ledger_cannot_be_disabled() -> None:
    for field in ("requireLedgerEntry", "requireReview"):
        data = policy()
        data["routingDeviation"][field] = False  # type: ignore[index]
        assert any(issue.path == f"$.routingDeviation.{field}" for issue in issues(data))


def test_parser_rejects_duplicate_mapping_keys() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        invalid = Path(tmpdir) / "policy.yaml"
        invalid.write_text(POLICY_PATH.read_text(encoding="utf-8") + "policyVersion: 1\n", encoding="utf-8")
        result = subprocess.run([sys.executable, str(VALIDATOR), str(invalid)], cwd=ROOT, capture_output=True, text=True, check=False)
    assert result.returncode == 1
    assert "duplicate mapping key" in result.stdout
