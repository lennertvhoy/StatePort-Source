from __future__ import annotations

from pathlib import Path
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]
for relative in (
    "packages/persistent-app/src",
    "packages/portable-execution/src",
    "packages/execution-host/src",
    "packages/external-engine-runtime/src",
    "packages/codex-adapter/src",
    "packages/run-bundle/src",
    "packages/statedd-core/src",
    "packages/template-validator/src",
    "packages/instance-backup/src",
    "packages/instance-catalog/src",
    "packages/diagnostics/src",
):
    sys.path.insert(0, str(ROOT / relative))

from stateport_portable_execution.registry import discover_application_descriptors  # noqa: E402


def test_registry_discovers_checklistdd_without_domain_imports() -> None:
    descriptors = discover_application_descriptors(ROOT)
    checklist = next(item for item in descriptors if item["applicationId"] == "checklistdd")
    assert checklist["privacyClassification"] == "public_safe"
    assert checklist["actionsPath"] == "actions.yaml"
    assert "studydd" not in (ROOT / "packages/portable-execution/src/stateport_portable_execution/registry.py").read_text(encoding="utf-8").lower()


def test_registry_discovers_public_safe_studystate_sample_without_domain_imports() -> None:
    descriptors = discover_application_descriptors(ROOT)
    study = next(item for item in descriptors if item["applicationId"] == "studystate.sample")
    assert study["displayName"] == "StudyState Sample"
    assert study["privacyClassification"] == "public_safe"
    assert study["productionEligible"] is False
    assert study["sourceProfile"] == "fixture:studystate-sample"


def test_registry_discovers_public_safe_development_application_with_optional_workbench() -> None:
    descriptors = discover_application_descriptors(ROOT)
    development = next(item for item in descriptors if item["applicationId"] == "stateport.development-reference")
    assert development["displayName"] == "ProjectState"
    assert development["privacyClassification"] == "public_safe"
    assert development["productionEligible"] is False
    assert development["sourceProfile"] == "fixture:development-reference"
    root = (ROOT / development["descriptorPath"]).parent
    assert root.joinpath("state/PROJECT.yaml").is_file()
    assert root.joinpath("README.md").is_file()
    actions = yaml.safe_load(root.joinpath("actions.yaml").read_text(encoding="utf-8"))
    assert actions["formatVersion"] == "stateport.application-action/v1"
    assert actions["applicationId"] == development["applicationId"]
    assert actions["actions"][0]["actionId"] == "stateport.development.inspect-project/v1"


def test_checklistdd_is_independent_of_studydd_files() -> None:
    checklist = ROOT / "fixtures/apps/checklistdd"
    assert (checklist / "application.yaml").is_file()
    assert (checklist / "actions.yaml").is_file()
    assert (checklist / "state/CHECKLIST.yaml").is_file()
    assert not list(checklist.rglob("*studydd*"))
