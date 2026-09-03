#!/usr/bin/env python3
"""Unit tests for statedd-core model loading."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for _src in [
    ROOT / "packages" / "statedd-core" / "src",
]:
    if str(_src) not in sys.path:
        sys.path.insert(0, str(_src))

from statedd_core import Instance, Template
from statedd_core.yaml import StateDDYamlError, parse_yaml_text


def test_gdpr_boolean_strings_coerce_correctly() -> None:
    """String forms of booleans in GDPR metadata must parse as their boolean value."""
    instance_yaml = """
apiVersion: statedd.io/v1
kind: Instance
metadata:
  id: demo
  name: Demo
spec:
  templateRef:
    id: classdd
    path: ../../templates/classdd
  status: active
  owner:
    name: Alice
    handle: alice
  gdpr:
    pseudonymised: "false"
    dpiaRequired: "true"
"""
    instance = Instance.from_dict(parse_yaml_text(instance_yaml))
    assert instance.spec.gdpr.pseudonymised is False
    assert instance.spec.gdpr.dpia_required is True


def test_missing_approval_policy_fails_closed_to_explicit_approval() -> None:
    instance_yaml = """
apiVersion: statedd.io/v1
kind: Instance
metadata:
  id: demo
  name: Demo
spec:
  templateRef:
    id: classdd
    path: ../../templates/classdd
  status: active
  owner:
    name: Alice
    handle: alice
"""
    policy = Instance.from_dict(parse_yaml_text(instance_yaml)).spec.approval_policy
    assert (policy.L2, policy.L3, policy.L4, policy.L5) == (
        "require_explicit_approval",
        "require_explicit_approval",
        "require_explicit_approval",
        "require_explicit_approval",
    )


def _expect_load_failure(yaml_text: str, model_class: type) -> None:
    try:
        model_class.from_dict(parse_yaml_text(yaml_text))
    except ValueError:
        return
    raise AssertionError(f"expected ValueError loading {model_class.__name__}")


def test_instance_rejects_missing_metadata_id() -> None:
    yaml_text = """
apiVersion: statedd.io/v1
kind: Instance
metadata:
  name: Demo
spec:
  templateRef:
    id: classdd
    path: ../../templates/classdd
  status: active
  owner:
    name: Alice
    handle: alice
"""
    _expect_load_failure(yaml_text, Instance)


def test_instance_rejects_missing_template_ref_path() -> None:
    yaml_text = """
apiVersion: statedd.io/v1
kind: Instance
metadata:
  id: demo
  name: Demo
spec:
  templateRef:
    id: classdd
  status: active
  owner:
    name: Alice
    handle: alice
"""
    _expect_load_failure(yaml_text, Instance)


def test_instance_rejects_missing_owner_handle() -> None:
    yaml_text = """
apiVersion: statedd.io/v1
kind: Instance
metadata:
  id: demo
  name: Demo
spec:
  templateRef:
    id: classdd
    path: ../../templates/classdd
  status: active
  owner:
    name: Alice
"""
    _expect_load_failure(yaml_text, Instance)


def test_template_rejects_missing_metadata_id() -> None:
    yaml_text = """
apiVersion: statedd.io/v1
kind: Template
metadata:
  name: Demo
  version: "1.0"
spec:
  domain: education
  lifecycle:
    - active
  allowedActions:
    - name: read
      level: L1
  schemas:
    - state/class.yaml
  agentContract:
    role: assistant
"""
    _expect_load_failure(yaml_text, Template)


def _expect_yaml_error(yaml_text: str) -> None:
    try:
        parse_yaml_text(yaml_text)
    except StateDDYamlError:
        return
    raise AssertionError("expected StateDDYamlError")


def test_folded_scalar_joins_lines_and_preserves_paragraph_breaks() -> None:
    text = """
description: >
  This is a long
  folded sentence.

  And a second paragraph
  on more lines.
"""
    data = parse_yaml_text(text)
    assert data["description"] == "This is a long folded sentence.\n\nAnd a second paragraph on more lines."


def test_literal_scalar_preserves_line_breaks() -> None:
    text = """
body: |
  line one
  line two

  line three
"""
    data = parse_yaml_text(text)
    assert data["body"] == "line one\nline two\n\nline three"


def test_duplicate_mapping_key_is_rejected() -> None:
    _expect_yaml_error("""
key: one
key: two
""")


def test_duplicate_key_in_inline_mapping_is_rejected() -> None:
    _expect_yaml_error("""
items:
  - name: a
    name: b
""")


def _nested_yaml(depth: int) -> str:
    text = ""
    for i in range(depth):
        text += "  " * i + "key:\n"
    text += "  " * depth + "value: 1\n"
    return text


def test_recursion_depth_limit() -> None:
    _expect_yaml_error(_nested_yaml(110))


def test_custom_recursion_depth_allows_reasonable_nesting() -> None:
    data = parse_yaml_text(_nested_yaml(10), max_depth=20)
    for _ in range(10):
        data = data["key"]
    assert data == {"value": 1}


def test_scalar_rejects_positive_sign_integer() -> None:
    _expect_yaml_error("value: +123")


def test_scalar_rejects_floats() -> None:
    _expect_yaml_error("value: 1.0")


def test_scalar_rejects_inf() -> None:
    _expect_yaml_error("value: .inf")


def test_scalar_rejects_yes_no() -> None:
    _expect_yaml_error("value: yes")
    _expect_yaml_error("value: no")


def test_scalar_rejects_tilde_null() -> None:
    _expect_yaml_error("value: ~")


def test_scalar_allows_quoted_nonstandard_forms() -> None:
    data = parse_yaml_text('value: "+123"\nother: "1.0"\nmore: "yes"\n')
    assert data["value"] == "+123"
    assert data["other"] == "1.0"
    assert data["more"] == "yes"


def test_allowed_actions_rejects_non_dict_entry() -> None:
    yaml_text = """
apiVersion: statedd.io/v1
kind: Template
metadata:
  id: demo
  name: Demo
  version: "1.0"
spec:
  domain: education
  lifecycle:
    - active
  allowedActions:
    - not-a-mapping
  schemas:
    - state/class.yaml
  agentContract:
    role: assistant
"""
    _expect_load_failure(yaml_text, Template)


def test_quota_rejects_string_numbers() -> None:
    yaml_text = """
apiVersion: statedd.io/v1
kind: Template
metadata:
  id: demo
  name: Demo
  version: "1.0"
spec:
  domain: education
  lifecycle:
    - active
  allowedActions:
    - name: read
      level: L1
  schemas:
    - state/class.yaml
  agentContract:
    role: assistant
  quotas:
    runsPerDay: "100"
"""
    _expect_load_failure(yaml_text, Template)


def test_quota_rejects_boolean_values() -> None:
    yaml_text = """
apiVersion: statedd.io/v1
kind: Template
metadata:
  id: demo
  name: Demo
  version: "1.0"
spec:
  domain: education
  lifecycle:
    - active
  allowedActions:
    - name: read
      level: L1
  schemas:
    - state/class.yaml
  agentContract:
    role: assistant
  quotas:
    messagesPerDay: true
"""
    _expect_load_failure(yaml_text, Template)


def test_retention_days_rejects_string() -> None:
    yaml_text = """
apiVersion: statedd.io/v1
kind: Instance
metadata:
  id: demo
  name: Demo
spec:
  templateRef:
    id: classdd
    path: ../../templates/classdd
  status: active
  owner:
    name: Alice
    handle: alice
  retentionDays: "365"
"""
    _expect_load_failure(yaml_text, Instance)


def test_action_level_rejects_invalid_level() -> None:
    yaml_text = """
apiVersion: statedd.io/v1
kind: Template
metadata:
  id: demo
  name: Demo
  version: "1.0"
spec:
  domain: education
  lifecycle:
    - active
  allowedActions:
    - name: read
      level: L9
  schemas:
    - state/class.yaml
  agentContract:
    role: assistant
"""
    _expect_load_failure(yaml_text, Template)


def test_action_level_accepts_l0_through_l5() -> None:
    yaml_text = """
apiVersion: statedd.io/v1
kind: Template
metadata:
  id: demo
  name: Demo
  version: "1.0"
spec:
  domain: education
  lifecycle:
    - active
  allowedActions:
    - name: l0
      level: L0
    - name: l5
      level: L5
  schemas:
    - state/class.yaml
  agentContract:
    role: assistant
"""
    template = Template.from_dict(parse_yaml_text(yaml_text))
    assert [a.level for a in template.spec.allowed_actions] == ["L0", "L5"]


if __name__ == "__main__":
    test_gdpr_boolean_strings_coerce_correctly()
    test_instance_rejects_missing_metadata_id()
    test_instance_rejects_missing_template_ref_path()
    test_instance_rejects_missing_owner_handle()
    test_template_rejects_missing_metadata_id()
    test_folded_scalar_joins_lines_and_preserves_paragraph_breaks()
    test_literal_scalar_preserves_line_breaks()
    test_duplicate_mapping_key_is_rejected()
    test_duplicate_key_in_inline_mapping_is_rejected()
    test_recursion_depth_limit()
    test_custom_recursion_depth_allows_reasonable_nesting()
    test_scalar_rejects_positive_sign_integer()
    test_scalar_rejects_floats()
    test_scalar_rejects_inf()
    test_scalar_rejects_yes_no()
    test_scalar_rejects_tilde_null()
    test_scalar_allows_quoted_nonstandard_forms()
    test_allowed_actions_rejects_non_dict_entry()
    test_quota_rejects_string_numbers()
    test_quota_rejects_boolean_values()
    test_retention_days_rejects_string()
    test_action_level_rejects_invalid_level()
    test_action_level_accepts_l0_through_l5()
    print("PASS")
