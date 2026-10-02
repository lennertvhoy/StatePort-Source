#!/usr/bin/env python3
"""Unit tests for the StateDD template validator."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for _src in [
    ROOT / "packages" / "statedd-core" / "src",
    ROOT / "packages" / "template-validator" / "src",
    ROOT / "apps" / "admin-cli" / "src",
]:
    if str(_src) not in sys.path:
        sys.path.insert(0, str(_src))

from statedd_core import Instance, Template
from statedd_core.yaml import parse_yaml_text
from template_validator import validate_instance, validate_template


def test_valid_template_passes() -> None:
    result = validate_template(ROOT / "templates" / "classdd")
    assert result.ok, result.issues


def test_valid_instance_passes() -> None:
    result = validate_instance(ROOT / "instances" / "demo-classdd")
    assert result.ok, result.issues


def test_dataclasses_can_load_demo_files() -> None:
    template_text = (ROOT / "templates" / "classdd" / "template.yaml").read_text(
        encoding="utf-8"
    )
    template = Template.from_dict(parse_yaml_text(template_text))
    assert template.kind == "Template"
    assert template.metadata.id == "classdd"

    instance_text = (ROOT / "instances" / "demo-classdd" / "instance.yaml").read_text(
        encoding="utf-8"
    )
    instance = Instance.from_dict(parse_yaml_text(instance_text))
    assert instance.kind == "Instance"
    assert instance.metadata.id == "demo-classdd"


def _copy_template_to(destination: Path) -> Path:
    source = ROOT / "templates" / "classdd"
    shutil.copytree(source, destination / "classdd")
    return destination / "classdd"


def _copy_instance_to(destination: Path) -> Path:
    source = ROOT / "instances" / "demo-classdd"
    shutil.copytree(source, destination / "demo-classdd")
    return destination / "demo-classdd"


def test_missing_template_yaml_fails() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        template_path = _copy_template_to(Path(tmpdir))
        (template_path / "template.yaml").unlink()
        result = validate_template(template_path)
        assert not result.ok
        assert any("template.yaml" in issue.path for issue in result.issues)


def test_v2_template_yaml_is_optional() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        template_path = Path(tmpdir) / "v2"
        shutil.copytree(ROOT / "fixtures" / "templates" / "lifecycle-v2-minimal", template_path)
        (template_path / "template.yaml").unlink()
        result = validate_template(template_path)
        assert result.ok, result.issues


def test_malformed_template_yaml_fails() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        template_path = _copy_template_to(Path(tmpdir))
        (template_path / "template.yaml").write_text(
            "{unclosed\nspec: {}\n", encoding="utf-8"
        )
        result = validate_template(template_path)
        assert not result.ok
        assert any("YAML" in issue.message for issue in result.issues)


def test_missing_contract_fails() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        template_path = _copy_template_to(Path(tmpdir))
        (template_path / ".statedd" / "contract.md").unlink()
        result = validate_template(template_path)
        assert not result.ok
        assert any("contract.md" in issue.path for issue in result.issues)


def test_missing_readme_fails() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        template_path = _copy_template_to(Path(tmpdir))
        (template_path / "README.md").unlink()
        result = validate_template(template_path)
        assert not result.ok
        assert any("README.md" in issue.path for issue in result.issues)


def test_wrong_template_kind_fails() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        template_path = _copy_template_to(Path(tmpdir))
        text = (template_path / "template.yaml").read_text(encoding="utf-8")
        text = text.replace("kind: Template", "kind: WrongKind")
        (template_path / "template.yaml").write_text(text, encoding="utf-8")
        result = validate_template(template_path)
        assert not result.ok
        assert any("kind" in issue.path for issue in result.issues)


def test_non_string_schema_path_fails() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        template_path = _copy_template_to(Path(tmpdir))
        text = (template_path / "template.yaml").read_text(encoding="utf-8")
        text = text.replace(
            "schemas:\n    - state/class.yaml",
            "schemas:\n    - state/class.yaml\n    - 123",
        )
        (template_path / "template.yaml").write_text(text, encoding="utf-8")
        result = validate_template(template_path)
        assert not result.ok
        assert any("must be a string" in issue.message for issue in result.issues)


def test_allowed_actions_not_list_fails() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        template_path = _copy_template_to(Path(tmpdir))
        text = (template_path / "template.yaml").read_text(encoding="utf-8")
        text = text.replace(
            "allowedActions:\n",
            "allowedActions: not-a-list\n",
        )
        # Removing the original list items keeps the YAML valid while
        # leaving allowedActions as a non-list scalar.
        lines = text.splitlines()
        filtered: list[str] = []
        in_allowed_actions_list = False
        for line in lines:
            if line.strip() == "allowedActions: not-a-list":
                filtered.append(line)
                in_allowed_actions_list = True
                continue
            if in_allowed_actions_list:
                if line.startswith("  ") and not line.startswith("    "):
                    in_allowed_actions_list = False
                else:
                    continue
            filtered.append(line)
        (template_path / "template.yaml").write_text(
            "\n".join(filtered) + "\n", encoding="utf-8"
        )
        result = validate_template(template_path)
        assert not result.ok
        assert any("expected a list" in issue.message for issue in result.issues)


def test_template_without_state_directory_passes() -> None:
    """Templates do not need a state/ folder; schemas are instance-level."""
    result = validate_template(ROOT / "templates" / "classdd")
    assert result.ok, result.issues


def test_missing_instance_yaml_fails() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        instance_path = _copy_instance_to(Path(tmpdir))
        (instance_path / "instance.yaml").unlink()
        result = validate_instance(instance_path)
        assert not result.ok
        assert any("instance.yaml" in issue.path for issue in result.issues)


def test_missing_instance_readme_fails() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        instance_path = _copy_instance_to(Path(tmpdir))
        (instance_path / "README.md").unlink()
        result = validate_instance(instance_path)
        assert not result.ok
        assert any("README.md" in issue.path for issue in result.issues)


def test_template_ref_not_mapping_fails() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        instance_path = _copy_instance_to(Path(tmpdir))
        text = (instance_path / "instance.yaml").read_text(encoding="utf-8")
        text = text.replace(
            "templateRef:\n    id: classdd\n    path: ../../templates/classdd",
            "templateRef: not-a-mapping",
        )
        (instance_path / "instance.yaml").write_text(text, encoding="utf-8")
        result = validate_instance(instance_path)
        assert not result.ok
        assert any("expected a mapping" in issue.message for issue in result.issues)


def test_absolute_template_ref_path_fails() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        instance_path = _copy_instance_to(Path(tmpdir))
        text = (instance_path / "instance.yaml").read_text(encoding="utf-8")
        text = text.replace(
            "path: ../../templates/classdd",
            "path: /etc/passwd",
        )
        (instance_path / "instance.yaml").write_text(text, encoding="utf-8")
        result = validate_instance(instance_path)
        assert not result.ok
        assert any("absolute" in issue.message.lower() for issue in result.issues)


def test_broken_template_ref_fails() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        instance_path = _copy_instance_to(Path(tmpdir))
        text = (instance_path / "instance.yaml").read_text(encoding="utf-8")
        text = text.replace(
            "path: ../../templates/classdd", "path: ../../templates/missing"
        )
        (instance_path / "instance.yaml").write_text(text, encoding="utf-8")
        result = validate_instance(instance_path)
        assert not result.ok
        assert any("template path" in issue.message.lower() for issue in result.issues)


def test_invalid_referenced_template_propagates_issues() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        template_path = tmp_path / "templates" / "classdd"
        instance_path = tmp_path / "instances" / "demo-classdd"
        shutil.copytree(ROOT / "templates" / "classdd", template_path)
        shutil.copytree(ROOT / "instances" / "demo-classdd", instance_path)
        (template_path / ".statedd" / "contract.md").unlink()
        result = validate_instance(instance_path)
        assert not result.ok
        assert any("template:" in issue.path for issue in result.issues)


def test_template_ref_id_mismatch_fails() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        instance_path = _copy_repo_to(Path(tmpdir))
        text = (instance_path / "instance.yaml").read_text(encoding="utf-8")
        text = text.replace("id: classdd", "id: wrong-id")
        (instance_path / "instance.yaml").write_text(text, encoding="utf-8")
        result = validate_instance(instance_path)
        assert not result.ok
        assert any("id" in issue.message.lower() for issue in result.issues)


def test_missing_state_file_fails() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        # Mirror the repo layout so the instance's relative templateRef resolves.
        repo = Path(tmpdir) / "repo"
        repo.mkdir()
        (repo / "instances").mkdir()
        (repo / "templates").mkdir()
        shutil.copytree(
            ROOT / "instances" / "demo-classdd", repo / "instances" / "demo-classdd"
        )
        shutil.copytree(
            ROOT / "templates" / "classdd", repo / "templates" / "classdd"
        )
        instance_path = repo / "instances" / "demo-classdd"
        (instance_path / "state" / "topics.yaml").unlink()
        result = validate_instance(instance_path)
        assert not result.ok
        assert any("state/topics.yaml" in issue.path for issue in result.issues)


def test_malformed_instance_yaml_fails() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        instance_path = _copy_instance_to(Path(tmpdir))
        (instance_path / "instance.yaml").write_text(
            "spec: not-a-mapping\n", encoding="utf-8"
        )
        result = validate_instance(instance_path)
        assert not result.ok
        assert any("expected a mapping" in issue.message for issue in result.issues)


def test_non_string_template_ref_path_fails() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        instance_path = _copy_instance_to(Path(tmpdir))
        text = (instance_path / "instance.yaml").read_text(encoding="utf-8")
        text = text.replace("path: ../../templates/classdd", "path: 123")
        (instance_path / "instance.yaml").write_text(text, encoding="utf-8")
        result = validate_instance(instance_path)
        assert not result.ok
        assert any("must be a string" in issue.message for issue in result.issues)


def _copy_repo_to(destination: Path) -> Path:
    """Copy the demo template and instance into a mirrored repo layout."""
    repo = destination / "repo"
    repo.mkdir()
    (repo / "instances").mkdir()
    (repo / "templates").mkdir()
    shutil.copytree(ROOT / "instances" / "demo-classdd", repo / "instances" / "demo-classdd")
    shutil.copytree(ROOT / "templates" / "classdd", repo / "templates" / "classdd")
    return repo / "instances" / "demo-classdd"


def test_traversal_template_ref_path_fails() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        instance_path = _copy_repo_to(Path(tmpdir))
        text = (instance_path / "instance.yaml").read_text(encoding="utf-8")
        text = text.replace("path: ../../templates/classdd", "path: ../../../etc")
        (instance_path / "instance.yaml").write_text(text, encoding="utf-8")
        result = validate_instance(instance_path)
        assert not result.ok
        assert any("traversal" in issue.message.lower() for issue in result.issues)


def test_empty_template_ref_path_fails() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        instance_path = _copy_instance_to(Path(tmpdir))
        text = (instance_path / "instance.yaml").read_text(encoding="utf-8")
        text = text.replace("path: ../../templates/classdd", "path: \"\"")
        (instance_path / "instance.yaml").write_text(text, encoding="utf-8")
        result = validate_instance(instance_path)
        assert not result.ok
        assert any(
            "path" in issue.path.lower() and "empty" in issue.message.lower()
            for issue in result.issues
        )


def test_traversal_schema_path_fails() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        instance_path = _copy_repo_to(Path(tmpdir))
        template_path = instance_path.parents[1] / "templates" / "classdd"
        text = (template_path / "template.yaml").read_text(encoding="utf-8")
        text = text.replace("state/class.yaml", "../etc/passwd")
        (template_path / "template.yaml").write_text(text, encoding="utf-8")
        result = validate_instance(instance_path)
        assert not result.ok
        assert any("traversal" in issue.message.lower() for issue in result.issues)


def test_absolute_schema_path_fails() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        instance_path = _copy_repo_to(Path(tmpdir))
        template_path = instance_path.parents[1] / "templates" / "classdd"
        text = (template_path / "template.yaml").read_text(encoding="utf-8")
        text = text.replace("state/class.yaml", "/etc/passwd")
        (template_path / "template.yaml").write_text(text, encoding="utf-8")
        result = validate_instance(instance_path)
        assert not result.ok
        assert any("absolute" in issue.message.lower() for issue in result.issues)


def test_lifecycle_not_list_fails() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        template_path = _copy_template_to(Path(tmpdir))
        text = (template_path / "template.yaml").read_text(encoding="utf-8")
        text = text.replace(
            "lifecycle:\n    - draft\n    - active\n    - archived",
            "lifecycle: not-a-list",
        )
        (template_path / "template.yaml").write_text(text, encoding="utf-8")
        result = validate_template(template_path)
        assert not result.ok
        assert any(
            "spec.lifecycle" in issue.path and "expected a list" in issue.message
            for issue in result.issues
        )


def test_agent_contract_not_mapping_fails() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        template_path = _copy_template_to(Path(tmpdir))
        lines = (template_path / "template.yaml").read_text(encoding="utf-8").splitlines()
        filtered: list[str] = []
        in_agent_contract = False
        for line in lines:
            if line.strip() == "agentContract:":
                indent = len(line) - len(line.lstrip(" "))
                filtered.append(" " * indent + "agentContract: not-a-mapping")
                in_agent_contract = True
                continue
            if in_agent_contract:
                if not line.startswith("    "):
                    in_agent_contract = False
                else:
                    continue
            filtered.append(line)
        (template_path / "template.yaml").write_text(
            "\n".join(filtered) + "\n", encoding="utf-8"
        )
        result = validate_template(template_path)
        assert not result.ok
        assert any(
            "spec.agentContract" in issue.path and "expected a mapping" in issue.message
            for issue in result.issues
        )


def test_allowed_action_name_not_string_fails() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        template_path = _copy_template_to(Path(tmpdir))
        text = (template_path / "template.yaml").read_text(encoding="utf-8")
        text = text.replace(
            "- name: read_state\n      level: L0",
            "- name: 123\n      level: L0",
        )
        (template_path / "template.yaml").write_text(text, encoding="utf-8")
        result = validate_template(template_path)
        assert not result.ok
        assert any(
            "allowedActions[0].name" in issue.path and "must be a string" in issue.message
            for issue in result.issues
        )


def test_allowed_action_level_not_string_fails() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        template_path = _copy_template_to(Path(tmpdir))
        text = (template_path / "template.yaml").read_text(encoding="utf-8")
        text = text.replace(
            "- name: read_state\n      level: L0",
            "- name: read_state\n      level: 0",
        )
        (template_path / "template.yaml").write_text(text, encoding="utf-8")
        result = validate_template(template_path)
        assert not result.ok
        assert any(
            "allowedActions[0].level" in issue.path and "must be a string" in issue.message
            for issue in result.issues
        )


def test_allowed_action_level_out_of_range_fails() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        template_path = _copy_template_to(Path(tmpdir))
        text = (template_path / "template.yaml").read_text(encoding="utf-8")
        text = text.replace(
            "- name: delete_instance\n      level: L4",
            "- name: delete_instance\n      level: L9",
        )
        (template_path / "template.yaml").write_text(text, encoding="utf-8")
        result = validate_template(template_path)
        assert not result.ok
        assert any(
            "allowedActions" in issue.path
            and "level" in issue.path
            and "must be one of" in issue.message
            for issue in result.issues
        )


def test_owner_not_mapping_fails() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        instance_path = _copy_instance_to(Path(tmpdir))
        text = (instance_path / "instance.yaml").read_text(encoding="utf-8")
        text = text.replace(
            "owner:\n    name: Demo Trainer\n    handle: \"@demo_trainer\"",
            "owner: not-a-mapping",
        )
        (instance_path / "instance.yaml").write_text(text, encoding="utf-8")
        result = validate_instance(instance_path)
        assert not result.ok
        assert any(
            "spec.owner" in issue.path and "expected a mapping" in issue.message
            for issue in result.issues
        )


def test_owner_name_empty_fails() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        instance_path = _copy_instance_to(Path(tmpdir))
        text = (instance_path / "instance.yaml").read_text(encoding="utf-8")
        text = text.replace("name: Demo Trainer", "name: \"\"")
        (instance_path / "instance.yaml").write_text(text, encoding="utf-8")
        result = validate_instance(instance_path)
        assert not result.ok
        assert any(
            "spec.owner.name" in issue.path and "non-empty string" in issue.message
            for issue in result.issues
        )


def test_owner_handle_empty_fails() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        instance_path = _copy_instance_to(Path(tmpdir))
        text = (instance_path / "instance.yaml").read_text(encoding="utf-8")
        text = text.replace("handle: \"@demo_trainer\"", "handle: \"\"")
        (instance_path / "instance.yaml").write_text(text, encoding="utf-8")
        result = validate_instance(instance_path)
        assert not result.ok
        assert any(
            "spec.owner.handle" in issue.path and "non-empty string" in issue.message
            for issue in result.issues
        )


def test_status_empty_fails() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        instance_path = _copy_instance_to(Path(tmpdir))
        text = (instance_path / "instance.yaml").read_text(encoding="utf-8")
        text = text.replace("status: active", "status: \"\"")
        (instance_path / "instance.yaml").write_text(text, encoding="utf-8")
        result = validate_instance(instance_path)
        assert not result.ok
        assert any(
            "spec.status" in issue.path and "non-empty string" in issue.message
            for issue in result.issues
        )


def test_template_ref_id_empty_fails() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        instance_path = _copy_instance_to(Path(tmpdir))
        text = (instance_path / "instance.yaml").read_text(encoding="utf-8")
        text = text.replace("id: classdd", "id: \"\"")
        (instance_path / "instance.yaml").write_text(text, encoding="utf-8")
        result = validate_instance(instance_path)
        assert not result.ok
        assert any(
            "spec.templateRef.id" in issue.path and "non-empty string" in issue.message
            for issue in result.issues
        )


def test_template_ref_path_empty_fails() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        instance_path = _copy_instance_to(Path(tmpdir))
        text = (instance_path / "instance.yaml").read_text(encoding="utf-8")
        text = text.replace("path: ../../templates/classdd", "path: \"\"")
        (instance_path / "instance.yaml").write_text(text, encoding="utf-8")
        result = validate_instance(instance_path)
        assert not result.ok
        assert any(
            "spec.templateRef.path" in issue.path and "non-empty string" in issue.message
            for issue in result.issues
        )


def test_symlink_escape_via_template_ref_fails() -> None:
    """A templateRef path that resolves through a symlink outside the project root is rejected."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "instances").mkdir()
        (repo / "templates").mkdir()

        # The real template lives outside the project root.
        escaped_template = tmp_path / "escaped_template"
        shutil.copytree(ROOT / "templates" / "classdd", escaped_template)

        # instances/demo-classdd is a normal directory with a valid instance.yaml.
        shutil.copytree(ROOT / "instances" / "demo-classdd", repo / "instances" / "demo-classdd")

        # templates/classdd is a symlink pointing outside repo.
        os.symlink(escaped_template, repo / "templates" / "classdd", target_is_directory=True)

        instance_path = repo / "instances" / "demo-classdd"
        result = validate_instance(instance_path)
        assert not result.ok
        assert any(
            "traversal" in issue.message.lower() or "symlink" in issue.message.lower()
            for issue in result.issues
        )


def test_wrapper_smoke() -> None:
    """Optional smoke test: the repo-root wrapper invokes the CLI."""
    result = subprocess.run(
        [str(ROOT / "stateport"), "validate-template", str(ROOT / "templates" / "classdd")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "valid" in result.stdout


if __name__ == "__main__":
    test_valid_template_passes()
    test_valid_instance_passes()
    test_dataclasses_can_load_demo_files()
    test_missing_template_yaml_fails()
    test_malformed_template_yaml_fails()
    test_missing_contract_fails()
    test_missing_readme_fails()
    test_wrong_template_kind_fails()
    test_non_string_schema_path_fails()
    test_allowed_actions_not_list_fails()
    test_template_without_state_directory_passes()
    test_missing_instance_yaml_fails()
    test_missing_instance_readme_fails()
    test_template_ref_not_mapping_fails()
    test_absolute_template_ref_path_fails()
    test_broken_template_ref_fails()
    test_invalid_referenced_template_propagates_issues()
    test_template_ref_id_mismatch_fails()
    test_missing_state_file_fails()
    test_malformed_instance_yaml_fails()
    test_non_string_template_ref_path_fails()
    test_traversal_template_ref_path_fails()
    test_empty_template_ref_path_fails()
    test_traversal_schema_path_fails()
    test_absolute_schema_path_fails()
    test_lifecycle_not_list_fails()
    test_agent_contract_not_mapping_fails()
    test_allowed_action_name_not_string_fails()
    test_allowed_action_level_not_string_fails()
    test_allowed_action_level_out_of_range_fails()
    test_owner_not_mapping_fails()
    test_owner_name_empty_fails()
    test_owner_handle_empty_fails()
    test_status_empty_fails()
    test_template_ref_id_empty_fails()
    test_template_ref_path_empty_fails()
    test_symlink_escape_via_template_ref_fails()
    test_wrapper_smoke()
    print("PASS")
