#!/usr/bin/env python3
"""Regression coverage for StateSpec logical schemas and approval metadata."""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
for relative in ("packages/statedd-core/src", "packages/template-validator/src", "scripts"):
    sys.path.insert(0, str(ROOT / relative))

from statedd_core import (  # noqa: E402
    INSTANCE_SCHEMA_ID,
    LOCK_SCHEMA_ID,
    Instance,
    SchemaRegistryError,
    create_instance,
    load_schema_registry,
)
from statedd_core.yaml import parse_yaml_text  # noqa: E402
from template_validator.validator import validate_instance, validate_template  # noqa: E402
from validate_statespec_schema_registry import validate_repository  # noqa: E402


class _IndentedSafeDumper(yaml.SafeDumper):
    def increase_indent(self, flow: bool = False, indentless: bool = False) -> None:
        return super().increase_indent(flow, False)


def _write_yaml(path: Path, value: object) -> None:
    path.write_text(
        yaml.dump(value, Dumper=_IndentedSafeDumper, sort_keys=False),
        encoding="utf-8",
    )


def test_repository_registry_and_generated_locks_pass() -> None:
    result = validate_repository(ROOT)
    assert result["observed"] == [
        "statedd.stateport.io/instance/v1alpha1",
        "statedd.stateport.io/lock/v1",
    ]
    assert result["generatedLockVariants"] == ["v1", "v2-local"]


def test_lock_preserves_a_domain_specific_instance_schema_identity(tmp_path: Path) -> None:
    lock = create_instance(
        ROOT / "fixtures/templates/lifecycle-v2-minimal",
        tmp_path / "domain-lock",
        instance_id="domain-lock",
        name="Domain lock",
        owner_name="Synthetic Owner",
        owner_handle="synthetic-owner",
        allow_fixture=True,
    )
    lock["template"]["instanceSchemaVersion"] = "studydd.instance-layout/v1"
    registry = load_schema_registry(
        ROOT / "config/statespec-schema-registry.v1.json", root=ROOT
    )

    assert registry.validate(LOCK_SCHEMA_ID, lock) == []
    lock["template"]["instanceSchemaVersion"] = ""
    assert registry.validate(LOCK_SCHEMA_ID, lock)


@pytest.mark.parametrize(
    "logical_id",
    ["statedd.stateport.io/instance/v999", "example.invalid/schema", "foo/bar"],
)
def test_lock_rejects_unregistered_or_unbounded_instance_schema_identities(
    tmp_path: Path,
    logical_id: str,
) -> None:
    lock = create_instance(
        ROOT / "fixtures/templates/lifecycle-v2-minimal",
        tmp_path / "invalid-domain-lock",
        instance_id="invalid-domain-lock",
        name="Invalid domain lock",
        owner_name="Synthetic Owner",
        owner_handle="synthetic-owner",
        allow_fixture=True,
    )
    lock["template"]["instanceSchemaVersion"] = logical_id
    registry = load_schema_registry(
        ROOT / "config/statespec-schema-registry.v1.json", root=ROOT
    )

    assert registry.validate(LOCK_SCHEMA_ID, lock)


def _external_layout_template(tmp_path: Path) -> Path:
    template = tmp_path / "external-layout"
    shutil.copytree(ROOT / "fixtures/templates/lifecycle-v2-minimal", template)
    manifest_path = template / ".statedd" / "manifest.yaml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    manifest["instanceLayoutContract"] = "example.instance-layout/v1"
    manifest["template"]["instanceSchemaVersion"] = "example.instance-layout/v1"
    manifest["modules"][0]["assets"].extend(
        ["instance-layout-contract", "external-bootstrap-contract"]
    )
    instance_asset = next(
        asset for asset in manifest["assets"] if asset["path"] == "instance.yaml"
    )
    instance_asset["role"] = "instance_lifecycle_descriptor"
    instance_asset["schema"] = "example.instance/v1"
    manifest["assets"].append(
        {
            "id": "instance-layout-contract",
            "path": "contracts/example.instance-layout.yaml",
            "kind": "file",
            "owner": "template",
            "role": "instance_layout_contract",
            "provisionPolicy": "copy_from_template",
            "updatePolicy": "replace_if_unmodified",
            "required": True,
            "schema": "example.instance-layout/v1",
            "sensitivity": "public",
            "source": "contracts/example.instance-layout.yaml",
            "selectingModules": ["core"],
        }
    )
    manifest["assets"].append(
        {
            "id": "external-bootstrap-contract",
            "path": ".statedd/example.bootstrap.yaml",
            "kind": "file",
            "owner": "template",
            "role": "typed_instance_bootstrap_contract",
            "provisionPolicy": "copy_from_template",
            "updatePolicy": "replace_if_unmodified",
            "required": True,
            "schema": "example.bootstrap/v1",
            "sensitivity": "public",
            "source": ".statedd/example.bootstrap.yaml",
            "selectingModules": ["core"],
        }
    )
    _write_yaml(manifest_path, manifest)
    (template / "contracts").mkdir()
    (template / "contracts" / "example.instance-layout.yaml").write_text(
        "---\n"
        "contract_id: example.instance-layout/v1\n"
        "kind: example_instance_layout\n"
        "modes:\n"
        "  draft:\n"
        "    marker:\n"
        "      path: state/MODE.yaml\n"
        "      field: mode\n"
        "      value: draft\n"
        "validation:\n"
        "  entry_point: scripts/check_fixture.py\n"
        "  command: python3 scripts/check_fixture.py\n"
        "  mapping:\n"
        "    descriptor: enforced\n",
        encoding="utf-8",
    )
    _write_yaml(
        template / ".statedd" / "example.bootstrap.yaml",
        {
            "formatVersion": "example.bootstrap/v1",
            "templateId": "stateport.fixture.lifecycle-v2-minimal",
            "fields": [
                {"id": "instance_id", "type": "identifier", "required": True},
                {"id": "display_name", "type": "string", "required": True},
                {"id": "owner_name", "type": "string", "required": True},
                {"id": "owner_handle", "type": "string", "required": True},
            ],
            "writes": [
                {
                    "path": "instance.yaml",
                    "format": "yaml",
                    "document": {
                        "apiVersion": "statedd.stateport.io/v1alpha1",
                        "kind": "Instance",
                        "metadata": {
                            "id": {"field": "instance_id"},
                            "name": {"field": "display_name"},
                        },
                        "spec": {
                            "mode": "draft",
                            "status": "draft",
                            "templateRef": {
                                "id": "stateport.fixture.lifecycle-v2-minimal",
                                "path": ".",
                            },
                            "owner": {
                                "name": {"field": "owner_name"},
                                "handle": {"field": "owner_handle"},
                            },
                        },
                    },
                }
            ],
        },
    )
    (template / "scripts").mkdir()
    (template / "scripts" / "check_fixture.py").write_text(
        "#!/usr/bin/env python3\n",
        encoding="utf-8",
    )
    return template


def test_external_layout_schema_is_bound_to_manifest_assets_and_contract(tmp_path: Path) -> None:
    template = _external_layout_template(tmp_path)
    assert validate_template(template).ok

    manifest_path = template / ".statedd" / "manifest.yaml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    manifest["instanceLayoutContract"] = "example.instance-layout/v2"
    _write_yaml(manifest_path, manifest)
    result = validate_template(template)
    assert not result.ok
    assert any("must exactly match" in issue.message for issue in result.issues)


@pytest.mark.parametrize(
    ("asset_path", "field", "value"),
    [
        ("contracts/example.instance-layout.yaml", "owner", "generated"),
        ("contracts/example.instance-layout.yaml", "required", False),
        ("instance.yaml", "kind", "tree"),
        ("instance.yaml", "owner", "template"),
        ("instance.yaml", "required", False),
    ],
)
def test_external_layout_rejects_weak_or_misowned_contract_assets(
    tmp_path: Path,
    asset_path: str,
    field: str,
    value: object,
) -> None:
    template = _external_layout_template(tmp_path)
    manifest_path = template / ".statedd" / "manifest.yaml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    asset = next(item for item in manifest["assets"] if item["path"] == asset_path)
    asset[field] = value
    _write_yaml(manifest_path, manifest)

    assert not validate_template(template).ok


def test_external_layout_contract_rejects_duplicate_top_level_identity(
    tmp_path: Path,
) -> None:
    template = _external_layout_template(tmp_path)
    contract_path = template / "contracts" / "example.instance-layout.yaml"
    contract_path.write_text(
        contract_path.read_text(encoding="utf-8")
        + "contract_id: example.instance-layout/v1\n",
        encoding="utf-8",
    )

    result = validate_template(template)

    assert not result.ok
    assert any("duplicate mapping key" in issue.message for issue in result.issues)


def test_external_layout_contract_is_read_with_a_hard_size_limit(
    tmp_path: Path,
) -> None:
    template = _external_layout_template(tmp_path)
    contract_path = template / "contracts" / "example.instance-layout.yaml"
    contract_path.write_bytes(b"#" + b"x" * (256 * 1024))

    result = validate_template(template)

    assert not result.ok
    assert any("bounded validation limit" in issue.message for issue in result.issues)


def test_external_layout_contract_rejects_aliases_and_expansion(
    tmp_path: Path,
) -> None:
    template = _external_layout_template(tmp_path)
    contract_path = template / "contracts" / "example.instance-layout.yaml"
    contract_path.write_text(
        "---\n"
        "contract_id: &identity example.instance-layout/v1\n"
        "kind: example_instance_layout\n"
        "modes:\n"
        "  draft:\n"
        "    marker: {path: state/MODE.yaml, field: mode, value: draft}\n"
        "validation:\n"
        "  entry_point: scripts/check_fixture.py\n"
        "  command: python3 scripts/check_fixture.py\n"
        "  mapping: {descriptor: *identity}\n",
        encoding="utf-8",
    )

    result = validate_template(template)

    assert not result.ok
    assert any("aliases are not allowed" in issue.message for issue in result.issues)


@pytest.mark.parametrize("limit", ["depth", "nodes"])
def test_external_layout_contract_rejects_structural_expansion(
    tmp_path: Path,
    limit: str,
) -> None:
    template = _external_layout_template(tmp_path)
    contract_path = template / "contracts" / "example.instance-layout.yaml"
    if limit == "depth":
        expansion = "root:\n" + "".join(
            "  " * depth + f"level_{depth}:\n" for depth in range(1, 70)
        ) + "  " * 70 + "value: bounded\n"
    else:
        expansion = "".join(f"field_{index}: value\n" for index in range(4100))
    contract_path.write_text(
        "---\n"
        "contract_id: example.instance-layout/v1\n"
        "kind: example_instance_layout\n"
        "modes:\n"
        "  draft:\n"
        "    marker: {path: state/MODE.yaml, field: mode, value: draft}\n"
        "validation:\n"
        "  entry_point: scripts/check_fixture.py\n"
        "  command: python3 scripts/check_fixture.py\n"
        "  mapping:\n"
        + "".join(f"    {line}\n" for line in expansion.splitlines()),
        encoding="utf-8",
    )

    result = validate_template(template)

    assert not result.ok
    expected_limit = "YAML depth limit" if limit == "depth" else "YAML node limit"
    assert any(expected_limit in issue.message for issue in result.issues)


def test_external_contract_and_marker_reject_symlinked_ancestors_without_path_leak(
    tmp_path: Path,
) -> None:
    template = _external_layout_template(tmp_path)
    outside_contracts = tmp_path / "outside-contracts"
    (template / "contracts").rename(outside_contracts)
    (template / "contracts").symlink_to(outside_contracts, target_is_directory=True)

    template_result = validate_template(template)

    assert not template_result.ok
    assert any("symlink" in issue.message for issue in template_result.issues)
    assert outside_contracts.as_posix() not in "\n".join(
        issue.message for issue in template_result.issues
    )

    (template / "contracts").unlink()
    outside_contracts.rename(template / "contracts")
    instance = tmp_path / "symlink-marker-instance"
    create_instance(
        template,
        instance,
        instance_id="symlink-marker-instance",
        name="Symlink marker instance",
        owner_name="Synthetic Owner",
        owner_handle="synthetic-owner",
        allow_fixture=True,
    )
    descriptor_path = instance / "instance.yaml"
    descriptor = yaml.safe_load(descriptor_path.read_text(encoding="utf-8"))
    descriptor["spec"]["mode"] = "draft"
    descriptor["spec"]["templateRef"]["path"] = "."
    _write_yaml(descriptor_path, descriptor)
    outside_state = tmp_path / "outside-state"
    outside_state.mkdir()
    _write_yaml(outside_state / "MODE.yaml", {"mode": "draft"})
    shutil.rmtree(instance / "state")
    (instance / "state").symlink_to(outside_state, target_is_directory=True)

    instance_result = validate_instance(instance, template_path_override=template)

    assert not instance_result.ok
    assert any("safely" in issue.message for issue in instance_result.issues)
    assert outside_state.as_posix() not in "\n".join(
        issue.message for issue in instance_result.issues
    )


def test_external_layout_rejects_unrelated_foreign_schema_ids(tmp_path: Path) -> None:
    template = _external_layout_template(tmp_path)
    manifest_path = template / ".statedd" / "manifest.yaml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    asset = next(item for item in manifest["assets"] if item.get("schema") is None)
    asset["schema"] = "unrelated.schema/v1"
    _write_yaml(manifest_path, manifest)

    result = validate_template(template)

    assert not result.ok
    assert any("not admitted by the exact" in issue.message for issue in result.issues)


def test_external_bootstrap_rejects_conflicting_writes(tmp_path: Path) -> None:
    template = _external_layout_template(tmp_path)
    bootstrap_path = template / ".statedd" / "example.bootstrap.yaml"
    bootstrap = yaml.safe_load(bootstrap_path.read_text(encoding="utf-8"))
    bootstrap["writes"].append(json.loads(json.dumps(bootstrap["writes"][0])))
    _write_yaml(bootstrap_path, bootstrap)

    result = validate_template(template)

    assert not result.ok
    assert any("destination conflicts" in issue.message for issue in result.issues)


def test_external_bootstrap_recursively_rejects_undeclared_field_references(
    tmp_path: Path,
) -> None:
    template = _external_layout_template(tmp_path)
    bootstrap_path = template / ".statedd" / "example.bootstrap.yaml"
    bootstrap = yaml.safe_load(bootstrap_path.read_text(encoding="utf-8"))
    bootstrap["writes"][0]["document"]["spec"]["nested"] = [
        {"value": {"field": "undeclared"}}
    ]
    _write_yaml(bootstrap_path, bootstrap)

    result = validate_template(template)

    assert not result.ok
    assert any("undeclared field" in issue.message for issue in result.issues)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("scalar-key", "unsupported top-level fields"),
        ("nul-path", "safe relative path"),
        ("string-path-field", "identifier fields"),
    ],
)
def test_external_bootstrap_malformed_paths_fail_closed(
    tmp_path: Path,
    mutation: str,
    message: str,
) -> None:
    template = _external_layout_template(tmp_path)
    bootstrap_path = template / ".statedd" / "example.bootstrap.yaml"
    bootstrap = yaml.safe_load(bootstrap_path.read_text(encoding="utf-8"))
    if mutation == "scalar-key":
        bootstrap[1] = "unsupported"
    elif mutation == "nul-path":
        bootstrap["writes"][0]["path"] = "unsafe\x00path"
    else:
        bootstrap["writes"].append(
            {
                "path": "targets/{display_name}/TARGET.yaml",
                "format": "text",
                "template": "synthetic\n",
            }
        )
    _write_yaml(bootstrap_path, bootstrap)

    result = validate_template(template)

    assert not result.ok
    assert any(message in issue.message for issue in result.issues)


def test_external_instance_requires_a_manifest_bound_lock(tmp_path: Path) -> None:
    template = _external_layout_template(tmp_path)
    instance = tmp_path / "unlocked-external-instance"
    create_instance(
        template,
        instance,
        instance_id="unlocked-external-instance",
        name="Unlocked external instance",
        owner_name="Synthetic Owner",
        owner_handle="synthetic-owner",
        allow_fixture=True,
    )
    (instance / ".statedd" / "lock.yaml").unlink()

    result = validate_instance(instance, template_path_override=template)

    assert not result.ok
    assert any("require a lifecycle lock" in issue.message for issue in result.issues)


def test_instance_lock_binds_template_path_revision_and_provenance(
    tmp_path: Path,
) -> None:
    template = _external_layout_template(tmp_path)
    instance = tmp_path / "locked-external-instance"
    create_instance(
        template,
        instance,
        instance_id="locked-external-instance",
        name="Locked external instance",
        owner_name="Synthetic Owner",
        owner_handle="synthetic-owner",
        allow_fixture=True,
    )
    descriptor_path = instance / "instance.yaml"
    descriptor = yaml.safe_load(descriptor_path.read_text(encoding="utf-8"))
    descriptor["spec"]["mode"] = "draft"
    descriptor["spec"]["templateRef"]["path"] = "."
    _write_yaml(descriptor_path, descriptor)
    (instance / "state").mkdir(exist_ok=True)
    _write_yaml(instance / "state" / "MODE.yaml", {"mode": "draft"})
    assert validate_instance(instance, template_path_override=template).ok

    identical_template = tmp_path / "identical-external-layout"
    shutil.copytree(template, identical_template)
    result = validate_instance(instance, template_path_override=identical_template)
    assert not result.ok
    assert any("exact selected template path" in issue.message for issue in result.issues)

    lock_path = instance / ".statedd" / "lock.yaml"
    lock = yaml.safe_load(lock_path.read_text(encoding="utf-8"))
    original_lock = lock_path.read_text(encoding="utf-8")
    lock["template"]["source"]["sourceClass"] = "compatibility_fixture"
    _write_yaml(lock_path, lock)
    result = validate_instance(instance, template_path_override=template)
    assert not result.ok
    assert any("exact selected template provenance" in issue.message for issue in result.issues)

    lock_path.write_text(original_lock, encoding="utf-8")
    contract_path = template / "contracts" / "example.instance-layout.yaml"
    contract_path.write_text(
        contract_path.read_text(encoding="utf-8") + "# source revision drift\n",
        encoding="utf-8",
    )
    result = validate_instance(instance, template_path_override=template)
    assert not result.ok
    assert any("source revision" in issue.message for issue in result.issues)


@pytest.mark.parametrize("binding", ["selectedModules", "fileOwnership"])
def test_instance_lock_binds_manifest_modules_and_ownership(
    tmp_path: Path,
    binding: str,
) -> None:
    template = _external_layout_template(tmp_path)
    instance = tmp_path / f"manifest-bound-{binding.lower()}"
    create_instance(
        template,
        instance,
        instance_id=f"manifest-bound-{binding.lower()}",
        name="Manifest-bound external instance",
        owner_name="Synthetic Owner",
        owner_handle="synthetic-owner",
        allow_fixture=True,
    )
    lock_path = instance / ".statedd" / "lock.yaml"
    lock = yaml.safe_load(lock_path.read_text(encoding="utf-8"))
    if binding == "selectedModules":
        lock["template"]["selectedModules"] = []
    else:
        lock["files"][0]["owner"] = (
            "instance" if lock["files"][0]["owner"] == "template" else "template"
        )
    _write_yaml(lock_path, lock)

    result = validate_instance(instance, template_path_override=template)

    assert not result.ok
    assert any(
        "selectedModules" in issue.path or "ownership binding" in issue.message
        for issue in result.issues
    )


def test_instance_lock_requires_available_source_provenance(tmp_path: Path) -> None:
    template = _external_layout_template(tmp_path)
    instance = tmp_path / "offline-external-instance"
    create_instance(
        template,
        instance,
        instance_id="offline-external-instance",
        name="Offline external instance",
        owner_name="Synthetic Owner",
        owner_handle="synthetic-owner",
        allow_fixture=True,
    )
    lock_path = instance / ".statedd" / "lock.yaml"
    lock = yaml.safe_load(lock_path.read_text(encoding="utf-8"))
    unavailable = (tmp_path / "unavailable-source").as_posix()
    lock["template"]["sourcePath"] = unavailable
    lock["template"]["source"]["checkoutLocation"] = unavailable
    _write_yaml(lock_path, lock)

    result = validate_instance(instance, template_path_override=template)

    assert not result.ok
    assert any(
        "source path is not an available template directory" in issue.message
        for issue in result.issues
    )


def test_external_layout_rejects_mismatched_descriptor_and_contract_ids(tmp_path: Path) -> None:
    template = _external_layout_template(tmp_path)
    manifest_path = template / ".statedd" / "manifest.yaml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    instance_asset = next(
        asset for asset in manifest["assets"] if asset["path"] == "instance.yaml"
    )
    instance_asset["schema"] = "example.instances/v1"
    _write_yaml(manifest_path, manifest)
    contract_path = template / "contracts" / "example.instance-layout.yaml"
    contract = yaml.safe_load(contract_path.read_text(encoding="utf-8"))
    contract["contract_id"] = "example.instance-layout/v2"
    _write_yaml(contract_path, contract)

    result = validate_template(template)
    assert not result.ok
    assert any("instance.yaml asset schema" in issue.message for issue in result.issues)
    assert any("layout contract_id" in issue.message for issue in result.issues)


def test_external_layout_id_does_not_bypass_stateport_instance_schema(tmp_path: Path) -> None:
    template = _external_layout_template(tmp_path)
    instance = tmp_path / "external-instance"
    create_instance(
        template,
        instance,
        instance_id="external-instance",
        name="External instance",
        owner_name="Synthetic Owner",
        owner_handle="synthetic-owner",
        allow_fixture=True,
    )
    descriptor_path = instance / "instance.yaml"
    descriptor = yaml.safe_load(descriptor_path.read_text(encoding="utf-8"))
    descriptor["apiVersion"] = "malformed.external/v1"
    _write_yaml(descriptor_path, descriptor)

    result = validate_instance(instance, template_path_override=template)
    assert not result.ok
    assert any("apiVersion" in issue.path for issue in result.issues)


def test_external_layout_validates_domain_mode_against_its_declared_marker(
    tmp_path: Path,
) -> None:
    template = _external_layout_template(tmp_path)
    instance = tmp_path / "external-domain-instance"
    create_instance(
        template,
        instance,
        instance_id="external-domain-instance",
        name="External domain instance",
        owner_name="Synthetic Owner",
        owner_handle="synthetic-owner",
        allow_fixture=True,
    )
    descriptor_path = instance / "instance.yaml"
    descriptor = yaml.safe_load(descriptor_path.read_text(encoding="utf-8"))
    descriptor["spec"]["mode"] = "draft"
    descriptor["spec"]["templateRef"]["path"] = "."
    _write_yaml(descriptor_path, descriptor)
    (instance / "state").mkdir(exist_ok=True)
    _write_yaml(instance / "state" / "MODE.yaml", {"mode": "draft"})
    assert validate_instance(instance, template_path_override=template).ok

    descriptor["spec"]["mode"] = "undeclared"
    _write_yaml(descriptor_path, descriptor)
    result = validate_instance(instance, template_path_override=template)

    assert not result.ok
    assert any("external layout contract" in issue.message for issue in result.issues)


def test_empty_declared_template_lifecycle_does_not_skip_status_validation(
    tmp_path: Path,
) -> None:
    template = tmp_path / "empty-lifecycle-template"
    shutil.copytree(ROOT / "fixtures/templates/lifecycle-v2-minimal", template)
    template_path = template / "template.yaml"
    template_data = yaml.safe_load(template_path.read_text(encoding="utf-8"))
    template_data["spec"]["lifecycle"] = []
    _write_yaml(template_path, template_data)
    instance = tmp_path / "empty-lifecycle-instance"
    create_instance(
        template,
        instance,
        instance_id="empty-lifecycle-instance",
        name="Empty lifecycle instance",
        owner_name="Synthetic Owner",
        owner_handle="synthetic-owner",
        allow_fixture=True,
    )

    result = validate_instance(instance, template_path_override=template)

    assert not result.ok
    assert any("lifecycle must be a non-empty list" in issue.message for issue in result.issues)


@pytest.mark.parametrize(
    "decision",
    ["auto", "require_approval", "require_admin", 1, True],
)
def test_legacy_or_non_string_approval_values_fail_closed(decision: object) -> None:
    value = parse_yaml_text(
        (ROOT / "instances/demo-classdd/instance.yaml").read_text(encoding="utf-8")
    )
    value["spec"]["approvalPolicy"]["L2"] = decision
    with pytest.raises(ValueError, match="require_explicit_approval"):
        Instance.from_dict(value)
    registry = load_schema_registry(
        ROOT / "config/statespec-schema-registry.v1.json", root=ROOT
    )
    assert registry.validate(INSTANCE_SCHEMA_ID, value)


def test_missing_policy_keeps_all_write_levels_explicit() -> None:
    value = parse_yaml_text(
        (ROOT / "instances/demo-classdd/instance.yaml").read_text(encoding="utf-8")
    )
    value["spec"].pop("approvalPolicy")
    policy = Instance.from_dict(value).spec.approval_policy
    assert {policy.L2, policy.L3, policy.L4, policy.L5} == {
        "require_explicit_approval"
    }


def test_registry_refuses_traversal_and_symlinks() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary) / "repo"
        shutil.copytree(ROOT / "schemas", root / "schemas")
        (root / "config").mkdir(parents=True)
        value = json.loads(
            (ROOT / "config/statespec-schema-registry.v1.json").read_text(
                encoding="utf-8"
            )
        )
        value["entries"][0]["path"] = "../outside.json"
        path = root / "config/registry.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        with pytest.raises(SchemaRegistryError, match="escapes"):
            load_schema_registry(path, root=root)

        value["entries"][0]["path"] = "schemas/linked.json"
        os.symlink(root / "schemas/instance.v1alpha1.schema.json", root / "schemas/linked.json")
        path.write_text(json.dumps(value), encoding="utf-8")
        with pytest.raises(SchemaRegistryError, match="symlink"):
            load_schema_registry(path, root=root)


def test_schema_id_mismatch_fails() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary) / "repo"
        shutil.copytree(ROOT / "schemas", root / "schemas")
        (root / "config").mkdir(parents=True)
        registry_path = root / "config/registry.json"
        registry_path.write_text(
            (ROOT / "config/statespec-schema-registry.v1.json").read_text(
                encoding="utf-8"
            ),
            encoding="utf-8",
        )
        schema_path = root / "schemas/instance.v1alpha1.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        schema["$id"] = "wrong"
        schema_path.write_text(json.dumps(schema), encoding="utf-8")
        with pytest.raises(SchemaRegistryError, match="mismatched"):
            load_schema_registry(registry_path, root=root)
