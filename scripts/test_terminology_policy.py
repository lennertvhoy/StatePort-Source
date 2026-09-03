"""Focused tests for the Stateware and StateSpec naming migration boundary."""
from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "scripts", ROOT / "packages" / "statedd-core" / "src"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from validate_terminology_policy import load_policy, validate_policy_data

POLICY = ROOT / "config" / "terminology-policy.yaml"
SCHEMA = ROOT / "schemas" / "terminology-policy.v1.schema.json"


def data() -> dict[str, object]:
    return copy.deepcopy(load_policy(POLICY))


def issues(value: dict[str, object]):
    return validate_policy_data(value, json.loads(SCHEMA.read_text(encoding="utf-8")))


def product(value: dict[str, object], name: str) -> dict[str, object]:
    return next(item for item in value["products"] if item["publicName"] == name)  # type: ignore[index,return-value]


def test_canonical_policy_is_valid_and_uses_stateware_vocabulary() -> None:
    value = data()
    assert not issues(value)
    assert value["category"]["publicName"] == "Stateware"  # type: ignore[index]
    assert value["methodology"]["publicName"] == "State-Centric Engineering"  # type: ignore[index]
    assert value["portableSpecification"]["publicName"] == "StateSpec"  # type: ignore[index]


def test_public_product_names_cannot_reintroduce_dd_suffix() -> None:
    value = data()
    product(value, "StudyState")["publicName"] = "StudyDD"
    assert any("DD suffix" in issue.message or "exact public product set" in issue.message for issue in issues(value))


def test_legacy_alias_cannot_be_deleted_during_public_rename() -> None:
    value = data()
    product(value, "ClassState")["legacyNames"] = []
    assert any("ClassDD" in issue.message or "legacyNames" in issue.path for issue in issues(value))


def test_machine_identifiers_remain_until_versioned_migration() -> None:
    value = data()
    product(value, "StudyState")["machineIdentifiers"] = []
    assert any("machineIdentifiers" in issue.path for issue in issues(value))


def test_unclassified_legacy_usage_is_not_an_allowed_category() -> None:
    value = data()
    value["compatibility"]["allowedRemainingCategories"].append("unclassified")  # type: ignore[index]
    assert any("allowedRemainingCategories" in issue.path for issue in issues(value))


def test_current_public_entrypoints_use_stateware_names() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    # README is the public product face and carries the StateSpec/StateDD
    # compatibility boundary; AGENTS.md is the agent operating contract whose
    # identity block intentionally names repository identity, not spec naming.
    assert "**Product category:** Stateware" in readme
    assert "**Portable specification:** StateSpec (formerly StateDD)" in readme
    assert "`StateDD` remains a compatibility identifier" in readme
    output = subprocess.run(
        [str(ROOT / "stateport"), "--help"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert "Validate a StateSpec template folder" in output
    assert "Run a StateSpec instance locally" in output
    assert "StudyState demo" in output
    assert "Validate a StateDD template folder" not in output
    assert "StudyDD demo" not in output


def test_current_application_descriptors_and_template_titles_use_public_names() -> None:
    expected = {
        "fixtures/apps/studydd/application.yaml": "displayName: StudyState",
        "fixtures/apps/checklistdd/application.yaml": "displayName: ChecklistState",
        "templates/classdd/template.yaml": "name: ClassState for StatePort",
        "templates/projectdd/template.yaml": "name: ProjectState for StatePort",
    }
    forbidden = ("displayName: StudyDD", "displayName: ChecklistDD", "name: ClassDD for StatePort", "name: ProjectDD for StatePort")
    for relative, marker in expected.items():
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert marker in text
        assert not any(item in text for item in forbidden)


def test_operator_validation_output_uses_statespec_language() -> None:
    output = subprocess.run(
        [sys.executable, str(ROOT / "scripts/statedd_validate_schema.py")],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert "STATEPORT STATESPEC VALIDATION" in output
    assert "All StateSpec schema checks passed" in output
    assert "STATEPORT STATEDD VALIDATION" not in output
