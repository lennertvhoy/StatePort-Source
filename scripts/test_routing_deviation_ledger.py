"""Focused regressions for routing-deviation provenance and review truth."""
from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "packages" / "statedd-core" / "src"))

from validate_agent_routing_policy import load_policy
from validate_routing_deviation_ledger import load_ledger, validate_ledger_data

LEDGER_PATH = ROOT / "docs" / "operations" / "routing-deviation-ledger.yaml"
LEDGER_SCHEMA_PATH = ROOT / "schemas" / "routing-deviation-ledger.v1.schema.json"
POLICY_PATH = ROOT / "config" / "agent-routing-policy.yaml"
VALIDATOR = ROOT / "scripts" / "validate_routing_deviation_ledger.py"


def ledger() -> dict[str, object]:
    return copy.deepcopy(load_ledger(LEDGER_PATH))


def policy() -> dict[str, object]:
    return copy.deepcopy(load_policy(POLICY_PATH))


def issues(data: dict[str, object]) -> list[object]:
    schema = json.loads(LEDGER_SCHEMA_PATH.read_text(encoding="utf-8"))
    return validate_ledger_data(data, schema, policy())


def first_entry(data: dict[str, object]) -> dict[str, object]:
    return data["entries"][0]  # type: ignore[index,return-value]


def test_canonical_ledger_is_schema_and_semantically_valid() -> None:
    assert not issues(ledger())
    result = subprocess.run([sys.executable, str(VALIDATOR)], cwd=ROOT, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stdout + result.stderr


def test_assignment_13_historical_record_is_conservative_and_complete() -> None:
    entry = first_entry(ledger())
    assert entry["assignment"] == "assignment-13"
    assert entry["intendedProfile"] == "terra-high"
    assert entry["actualProfile"] == "gpt-5.6-sol/max"
    assert entry["incrementalCost"]["availability"] == "unknown"  # type: ignore[index]
    assert entry["rerun"] == {  # type: ignore[index]
        "occurred": True,
        "profile": "terra-high",
        "trigger": "model_identity_only",
        "allowedReason": None,
        "worktreeIsolation": "same_modified_worktree",
        "compliance": "historical_noncompliance",
    }
    assert entry["producedWork"]["commits"]["values"] == [  # type: ignore[index]
        "6f49b99564bfaefc8f1d0aecef23d81b34b6cd11",
        "dd12d96be9b006032f42302290d16282c313daa1",
    ]
    assert entry["testResult"]["status"] == "passed"  # type: ignore[index]
    assert entry["review"]["disposition"] == "rejected_with_reproduced_defects"  # type: ignore[index]
    assert entry["review"]["independent"] is True  # type: ignore[index]
    assert entry["review"]["worktreeIsolation"] == "clean_detached_worktree"  # type: ignore[index]
    assert entry["retainedWork"]["status"] == "retained"  # type: ignore[index]
    assert entry["discardedWork"]["attribution"] == "unknown_exact"  # type: ignore[index]


def test_same_modified_worktree_cannot_be_called_independent_review() -> None:
    data = ledger()
    review = first_entry(data)["review"]  # type: ignore[index]
    review.update(  # type: ignore[union-attr]
        {
            "disposition": "accepted",
            "access": "read-only",
            "originalImplementationOwner": False,
            "worktreeIsolation": "same_modified_worktree",
            "independent": True,
        }
    )
    assert any(issue.path.endswith(".review.worktreeIsolation") for issue in issues(data))


def test_original_implementer_cannot_claim_independent_acceptance() -> None:
    data = ledger()
    review = first_entry(data)["review"]  # type: ignore[index]
    review.update(  # type: ignore[union-attr]
        {
            "disposition": "accepted",
            "access": "read-only",
            "originalImplementationOwner": True,
            "worktreeIsolation": "clean_detached_worktree",
            "independent": True,
        }
    )
    assert any(issue.path.endswith(".review.originalImplementationOwner") for issue in issues(data))


def test_write_capable_reviewer_cannot_claim_independent_acceptance() -> None:
    data = ledger()
    review = first_entry(data)["review"]  # type: ignore[index]
    review.update(  # type: ignore[union-attr]
        {
            "disposition": "accepted",
            "access": "workspace-write",
            "originalImplementationOwner": False,
            "worktreeIsolation": "clean_detached_worktree",
            "independent": True,
        }
    )
    assert any(issue.path.endswith(".review.access") for issue in issues(data))


def test_final_acceptance_cannot_hide_non_independent_review() -> None:
    data = ledger()
    review = first_entry(data)["review"]  # type: ignore[index]
    review["disposition"] = "accepted"  # type: ignore[index]
    review["independent"] = False  # type: ignore[index]
    assert any(issue.path.endswith(".review.disposition") for issue in issues(data))


def test_model_identity_only_cannot_be_relabelled_as_a_compliant_rerun() -> None:
    data = ledger()
    first_entry(data)["rerun"]["compliance"] = "compliant"  # type: ignore[index]
    assert any(issue.path.endswith(".rerun") or issue.path.endswith(".rerun.trigger") for issue in issues(data))


def test_unknown_incremental_cost_cannot_contain_an_invented_amount() -> None:
    data = ledger()
    first_entry(data)["incrementalCost"]["amountMinor"] = 1  # type: ignore[index]
    assert any(issue.path.endswith(".incrementalCost") for issue in issues(data))


def test_entry_ids_must_be_unique() -> None:
    data = ledger()
    data["entries"].append(copy.deepcopy(first_entry(data)))  # type: ignore[index,union-attr]
    assert any(issue.path.endswith(".entryId") for issue in issues(data))
