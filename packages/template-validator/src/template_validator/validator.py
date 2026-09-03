"""High-level validation API for StateDD templates and instances."""

from __future__ import annotations

from pathlib import Path
import os
import re
import stat

import yaml

from statedd_core import (
    INSTANCE_SCHEMA_ID,
    LOCK_SCHEMA_ID,
    MANIFEST_V2_FORMAT,
    Instance,
    SchemaRegistryError,
    describe_template_source,
    find_builtin_schema_registry,
    template_source_revision,
    validate_lifecycle_lock,
    validate_lifecycle_lock_against_manifest,
)
from statedd_core.lifecycle import LifecycleError, load_template_manifest
from template_validator.checks import (
    INSTANCE_REQUIRED_FILES,
    TEMPLATE_REQUIRED_FILES,
    check_instance_schema,
    check_required_files,
    check_schema_files_exist,
    check_template_ref_resolves,
    check_template_schema,
    check_yaml_parseable,
)
from template_validator.result import ValidationIssue, ValidationResult


_LOGICAL_SCHEMA_ID = re.compile(
    r"^[a-z][a-z0-9.-]{0,63}(?:/[a-z0-9][a-z0-9._-]{0,63}){1,3}$"
)
_EXTERNAL_LAYOUT_SCHEMA_ID = re.compile(
    r"^(?P<domain>[a-z][a-z0-9.-]{0,47})\.instance-layout/(?P<version>v[a-z0-9._-]{0,31})$"
)
_BOOTSTRAP_IDENTIFIER = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_BOOTSTRAP_FIELD_ID = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_BOOTSTRAP_PLACEHOLDER = re.compile(r"\{([a-z][a-z0-9_]*)\}")
_STATEPORT_INSTANCE_SPEC_FIELDS = {
    "templateRef",
    "status",
    "grantedCapabilities",
    "allowedCapabilities",
    "owner",
    "retentionDays",
    "quotas",
    "approvalPolicy",
    "gdpr",
}
_EXTERNAL_CONTRACT_BYTES_LIMIT = 256 * 1024


class _UniqueSafeLoader(yaml.SafeLoader):
    _MAX_NODES = 4096
    _MAX_DEPTH = 64

    def __init__(self, stream: object) -> None:
        self._node_count = 0
        self._node_depth = 0
        super().__init__(stream)

    def compose_node(self, parent: yaml.Node | None, index: int | None) -> yaml.Node:
        if self.check_event(yaml.AliasEvent):
            event = self.peek_event()
            raise yaml.composer.ComposerError(
                None,
                None,
                "YAML aliases are not allowed in external contracts",
                event.start_mark,
            )
        self._node_count += 1
        if self._node_count > self._MAX_NODES:
            event = self.peek_event()
            raise yaml.composer.ComposerError(
                None,
                None,
                "external contract exceeds the YAML node limit",
                event.start_mark,
            )
        self._node_depth += 1
        if self._node_depth > self._MAX_DEPTH:
            event = self.peek_event()
            raise yaml.composer.ComposerError(
                None,
                None,
                "external contract exceeds the YAML depth limit",
                event.start_mark,
            )
        try:
            return super().compose_node(parent, index)
        finally:
            self._node_depth -= 1


def _construct_unique_mapping(
    loader: yaml.SafeLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[object, object]:
    seen: set[object] = set()
    for key_node, _value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in seen
        except TypeError as exc:
            raise yaml.constructor.ConstructorError(
                None, None, "mapping keys must be scalar values", key_node.start_mark
            ) from exc
        if duplicate:
            raise yaml.constructor.ConstructorError(
                None, None, f"duplicate mapping key {key!r}", key_node.start_mark
            )
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


_UniqueSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _contract_issues(data: object, logical_id: str, path: str) -> list[ValidationIssue]:
    try:
        registry = find_builtin_schema_registry()
        issues = registry.validate(logical_id, data)
    except (OSError, UnicodeError, ValueError, SchemaRegistryError) as exc:
        return [ValidationIssue(path, f"schema registry validation failed: {exc}")]
    return [ValidationIssue(f"{path}:{issue.path}", issue.message) for issue in issues]


def _instance_contract_issues(
    data: object,
    locked_instance_schema: object,
) -> list[ValidationIssue]:
    if (
        isinstance(locked_instance_schema, str)
        and not locked_instance_schema.startswith("statedd.stateport.io/")
        and isinstance(data, dict)
        and isinstance(data.get("spec"), dict)
    ):
        projected = dict(data)
        projected["spec"] = {
            key: value
            for key, value in data["spec"].items()
            if key in _STATEPORT_INSTANCE_SPEC_FIELDS
        }
        return _contract_issues(projected, INSTANCE_SCHEMA_ID, "instance.yaml")
    return _contract_issues(data, INSTANCE_SCHEMA_ID, "instance.yaml")


def _logical_schema_issue(value: object, path: str) -> ValidationIssue | None:
    if not isinstance(value, str) or not _LOGICAL_SCHEMA_ID.fullmatch(value):
        return ValidationIssue(
            path,
            "schema ID must be a bounded logical ID",
        )
    return None


def _safe_contract_path(value: object) -> str | None:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        return None
    relative = Path(value)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        return None
    return relative.as_posix()


def _path_has_symlink_component(path: Path) -> bool:
    absolute = Path(os.path.abspath(path))
    cursor = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        cursor /= part
        try:
            if stat.S_ISLNK(os.lstat(cursor).st_mode):
                return True
        except ValueError:
            return True
        except OSError:
            return False
    return False


def _bounded_regular_file_bytes(
    root: Path,
    relative_path: str,
    *,
    maximum_bytes: int | None,
) -> bytes:
    safe_path = _safe_contract_path(relative_path)
    if safe_path is None or _path_has_symlink_component(root):
        raise OSError("unsafe confined file")
    directory_flags = (
        os.O_RDONLY
        | os.O_CLOEXEC
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    file_flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptors: list[int] = []
    file_descriptor = -1
    try:
        descriptors.append(os.open(Path(os.path.abspath(root)), directory_flags))
        parts = Path(safe_path).parts
        for part in parts[:-1]:
            descriptors.append(os.open(part, directory_flags, dir_fd=descriptors[-1]))
        file_descriptor = os.open(parts[-1], file_flags, dir_fd=descriptors[-1])
        metadata = os.fstat(file_descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise OSError("confined path is not a regular file")
        if maximum_bytes is None:
            return b""
        if metadata.st_size > maximum_bytes:
            return os.read(file_descriptor, maximum_bytes + 1)
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining > 0:
            chunk = os.read(file_descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    finally:
        if file_descriptor >= 0:
            os.close(file_descriptor)
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _bounded_yaml_mapping(
    root: Path,
    relative_path: str,
    label: str,
) -> tuple[dict[str, object] | None, ValidationIssue | None]:
    try:
        raw = _bounded_regular_file_bytes(
            root,
            relative_path,
            maximum_bytes=_EXTERNAL_CONTRACT_BYTES_LIMIT,
        )
    except OSError:
        return None, ValidationIssue(
            relative_path,
            f"could not read {label} safely",
        )
    if len(raw) > _EXTERNAL_CONTRACT_BYTES_LIMIT:
        return None, ValidationIssue(relative_path, f"{label} exceeds the bounded validation limit")
    try:
        text = raw.decode("utf-8")
        lines = text.splitlines()
        if lines and lines[0].strip() == "---":
            text = "\n".join(lines[1:]) + "\n"
        value = yaml.load(text, Loader=_UniqueSafeLoader)
    except (UnicodeError, ValueError, RecursionError, yaml.YAMLError) as exc:
        return None, ValidationIssue(relative_path, f"{label} is invalid YAML: {exc}")
    if not isinstance(value, dict):
        return None, ValidationIssue(relative_path, f"{label} must be a YAML mapping")
    return value, None


def _external_contract(
    root: Path,
    relative_path: str,
) -> tuple[dict[str, object] | None, ValidationIssue | None]:
    value, issue = _bounded_yaml_mapping(root, relative_path, "layout contract")
    if issue or value is None:
        return None, issue
    contract_id = value.get("contract_id")
    modes = value.get("modes")
    validation = value.get("validation")
    if not isinstance(contract_id, str) or not _LOGICAL_SCHEMA_ID.fullmatch(contract_id):
        return None, ValidationIssue(
            relative_path,
            "layout contract must declare exactly one bounded top-level contract_id",
        )
    if not isinstance(value.get("kind"), str) or not value["kind"]:
        return None, ValidationIssue(relative_path, "layout contract kind is required")
    if not isinstance(modes, dict) or not modes:
        return None, ValidationIssue(relative_path, "layout contract modes must be a non-empty mapping")
    for mode_name, mode_contract in modes.items():
        marker = mode_contract.get("marker") if isinstance(mode_contract, dict) else None
        if (
            not isinstance(mode_name, str)
            or not mode_name
            or not isinstance(marker, dict)
            or _safe_contract_path(marker.get("path")) is None
            or not isinstance(marker.get("field"), str)
            or not marker["field"]
            or not isinstance(marker.get("value"), str)
            or not marker["value"]
        ):
            return None, ValidationIssue(
                relative_path,
                "every layout mode must declare one safe typed marker",
            )
    if (
        not isinstance(validation, dict)
        or _safe_contract_path(validation.get("entry_point")) is None
        or not isinstance(validation.get("command"), str)
        or not validation["command"]
        or not isinstance(validation.get("mapping"), dict)
        or not validation["mapping"]
    ):
        return None, ValidationIssue(
            relative_path,
            "layout contract must declare a bounded non-empty validation mapping",
        )
    return value, None


def _external_instance_contract_issues(
    data: object,
    target: Path,
    contract: dict[str, object],
) -> list[ValidationIssue]:
    spec = data.get("spec") if isinstance(data, dict) else None
    modes = contract.get("modes")
    if not isinstance(spec, dict) or not isinstance(modes, dict):
        return [ValidationIssue("instance.yaml", "external layout instance contract is incomplete")]
    mode = spec.get("mode")
    mode_contract = modes.get(mode) if isinstance(mode, str) else None
    if not isinstance(mode_contract, dict):
        return [
            ValidationIssue(
                "instance.yaml:spec.mode",
                "instance mode is not declared by the external layout contract",
            )
        ]
    marker = mode_contract.get("marker")
    if not isinstance(marker, dict):
        return [ValidationIssue("instance.yaml:spec.mode", "layout mode marker is invalid")]
    marker_path = _safe_contract_path(marker.get("path"))
    marker_field = marker.get("field")
    marker_value = marker.get("value")
    if marker_path is None or not isinstance(marker_field, str):
        return [ValidationIssue("instance.yaml:spec.mode", "layout mode marker is invalid")]
    marker_data, marker_issue = _bounded_yaml_mapping(
        target,
        marker_path,
        "layout mode marker",
    )
    if marker_issue:
        return [ValidationIssue(marker_path, marker_issue.message)]
    if marker_data is None:
        return [ValidationIssue(marker_path, "layout mode marker must be a YAML mapping")]
    issues: list[ValidationIssue] = []
    if marker_data.get(marker_field) != marker_value or mode != marker_value:
        issues.append(
            ValidationIssue(
                "instance.yaml:spec.mode",
                "instance mode does not match the external layout marker",
            )
        )
    for marker_name, descriptor_name in (
        ("personalized", "personalized"),
        ("public_safe", "publicSafe"),
    ):
        if marker_name in marker_data and spec.get(descriptor_name) is not marker_data[marker_name]:
            issues.append(
                ValidationIssue(
                    f"instance.yaml:spec.{descriptor_name}",
                    f"instance {descriptor_name} does not match the external layout marker",
                )
            )
    return issues


def _bootstrap_reference_issues(
    value: object,
    fields: dict[str, dict[str, object]],
    path: str,
) -> list[ValidationIssue]:
    if isinstance(value, dict):
        if set(value) == {"field"}:
            field_id = value.get("field")
            if not isinstance(field_id, str) or field_id not in fields:
                return [
                    ValidationIssue(
                        path,
                        "bootstrap document references an undeclared field",
                    )
                ]
            return []
        issues: list[ValidationIssue] = []
        for key, item in value.items():
            issues.extend(
                _bootstrap_reference_issues(item, fields, f"{path}.{key}")
            )
        return issues
    if isinstance(value, list):
        issues = []
        for index, item in enumerate(value):
            issues.extend(
                _bootstrap_reference_issues(item, fields, f"{path}[{index}]")
            )
        return issues
    return []


def _bootstrap_placeholder_issues(
    value: object,
    fields: dict[str, dict[str, object]],
    path: str,
    *,
    path_template: bool = False,
) -> list[ValidationIssue]:
    if not isinstance(value, str):
        return [ValidationIssue(path, "bootstrap template must be a string")]
    issues: list[ValidationIssue] = []
    for field_id in _BOOTSTRAP_PLACEHOLDER.findall(value):
        field = fields.get(field_id)
        if field is None:
            issues.append(
                ValidationIssue(
                    path,
                    f"bootstrap template references undeclared field {field_id!r}",
                )
            )
        elif path_template and field.get("type") != "identifier":
            issues.append(
                ValidationIssue(
                    path,
                    "bootstrap destination placeholders must reference identifier fields",
                )
            )
    remainder = _BOOTSTRAP_PLACEHOLDER.sub("", value)
    if "{" in remainder or "}" in remainder:
        issues.append(ValidationIssue(path, "bootstrap template placeholder syntax is invalid"))
    return issues


def _bootstrap_descriptor_contract(
    bootstrap: dict[str, object],
) -> tuple[dict[str, object] | None, dict[str, dict[str, object]], list[ValidationIssue]]:
    issues: list[ValidationIssue] = []
    supported_top_level = {
        "formatVersion",
        "templateId",
        "instanceMode",
        "seedModes",
        "fields",
        "seeds",
        "writes",
    }
    unknown_top_level = [
        key
        for key in bootstrap
        if not isinstance(key, str) or key not in supported_top_level
    ]
    if unknown_top_level:
        issues.append(
            ValidationIssue(
                "bootstrap",
                "external bootstrap contains unsupported top-level fields: "
                + ", ".join(sorted(repr(key) for key in unknown_top_level)),
            )
        )
    instance_mode = bootstrap.get("instanceMode")
    if instance_mode is not None and (
        not isinstance(instance_mode, str) or not instance_mode
    ):
        issues.append(
            ValidationIssue(
                "bootstrap:instanceMode",
                "bootstrap instanceMode must be a non-empty string",
            )
        )
    seed_modes = bootstrap.get("seedModes")
    if seed_modes is not None and (
        not isinstance(seed_modes, list)
        or not seed_modes
        or any(not isinstance(item, str) or not item for item in seed_modes)
        or len(set(seed_modes)) != len(seed_modes)
    ):
        issues.append(
            ValidationIssue(
                "bootstrap:seedModes",
                "bootstrap seedModes must be a unique non-empty string list",
            )
        )
    raw_fields = bootstrap.get("fields")
    fields: dict[str, dict[str, object]] = {}
    if not isinstance(raw_fields, list):
        issues.append(ValidationIssue("bootstrap:fields", "bootstrap fields must be a list"))
    else:
        for index, field in enumerate(raw_fields):
            field_id = field.get("id") if isinstance(field, dict) else None
            field_type = field.get("type") if isinstance(field, dict) else None
            if (
                not isinstance(field_id, str)
                or _BOOTSTRAP_FIELD_ID.fullmatch(field_id) is None
                or field_id in fields
                or field_type not in {"string", "identifier", "enum"}
                or not isinstance(field.get("required"), bool)
                or set(field) - {"id", "type", "required", "default", "values"}
            ):
                issues.append(
                    ValidationIssue(
                        f"bootstrap:fields[{index}]",
                        "bootstrap field identity or type is invalid",
                    )
                )
                continue
            if field_type == "enum" and (
                not isinstance(field.get("values"), list)
                or not field["values"]
                or any(not isinstance(item, str) for item in field["values"])
            ):
                issues.append(
                    ValidationIssue(
                        f"bootstrap:fields[{index}].values",
                        "bootstrap enum field must declare string values",
                    )
                )
                continue
            default = field.get("default")
            if default is not None and not isinstance(default, str):
                issues.append(
                    ValidationIssue(
                        f"bootstrap:fields[{index}].default",
                        "bootstrap field default must be a string",
                    )
                )
                continue
            if (
                field_type == "identifier"
                and isinstance(default, str)
                and default
                and _BOOTSTRAP_IDENTIFIER.fullmatch(default) is None
            ):
                issues.append(
                    ValidationIssue(
                        f"bootstrap:fields[{index}].default",
                        "bootstrap identifier default is invalid",
                    )
                )
                continue
            if (
                field_type == "enum"
                and default is not None
                and default not in field.get("values", [])
            ):
                issues.append(
                    ValidationIssue(
                        f"bootstrap:fields[{index}].default",
                        "bootstrap enum default must be one of its values",
                    )
                )
                continue
            fields[field_id] = field

    destinations: dict[str, str] = {}

    def admit_destination(value: object, path: str) -> str | None:
        safe_path = _safe_contract_path(value)
        if safe_path is None:
            issues.append(ValidationIssue(path, "bootstrap destination must be a safe relative path"))
            return None
        folded = safe_path.casefold()
        previous = destinations.get(folded)
        if previous is not None:
            issues.append(
                ValidationIssue(
                    path,
                    f"bootstrap destination conflicts with {previous}",
                )
            )
            return safe_path
        for other_folded, other in destinations.items():
            if folded.startswith(other_folded + "/") or other_folded.startswith(folded + "/"):
                issues.append(
                    ValidationIssue(
                        path,
                        f"bootstrap destination conflicts with {other}",
                    )
                )
                break
        destinations[folded] = path
        issues.extend(
            _bootstrap_placeholder_issues(
                safe_path,
                fields,
                path,
                path_template=True,
            )
        )
        return safe_path

    seeds = bootstrap.get("seeds", [])
    if not isinstance(seeds, list):
        issues.append(ValidationIssue("bootstrap:seeds", "bootstrap seeds must be a list"))
    else:
        for index, seed in enumerate(seeds):
            path = f"bootstrap:seeds[{index}]"
            if not isinstance(seed, dict) or set(seed) != {"path", "source"}:
                issues.append(ValidationIssue(path, "bootstrap seed declaration is invalid"))
                continue
            admit_destination(seed.get("path"), f"{path}.path")
            if _safe_contract_path(seed.get("source")) is None:
                issues.append(
                    ValidationIssue(
                        f"{path}.source",
                        "bootstrap seed source must be a safe relative path",
                    )
                )

    writes = bootstrap.get("writes")
    descriptor_writes: list[dict[str, object]] = []
    if not isinstance(writes, list) or not writes:
        issues.append(ValidationIssue("bootstrap:writes", "bootstrap writes must be a non-empty list"))
    else:
        for index, write in enumerate(writes):
            path = f"bootstrap:writes[{index}]"
            if not isinstance(write, dict):
                issues.append(ValidationIssue(path, "bootstrap write must be a mapping"))
                continue
            destination = admit_destination(write.get("path"), f"{path}.path")
            write_format = write.get("format")
            if write_format == "yaml":
                if set(write) != {"path", "format", "document"} or not isinstance(
                    write.get("document"), dict
                ):
                    issues.append(
                        ValidationIssue(
                            path,
                            "bootstrap YAML write must contain exactly one mapping document",
                        )
                    )
                else:
                    issues.extend(
                        _bootstrap_reference_issues(
                            write["document"], fields, f"{path}.document"
                        )
                    )
                    if destination == "instance.yaml":
                        descriptor_writes.append(write)
            elif write_format == "text":
                if set(write) != {"path", "format", "template"}:
                    issues.append(
                        ValidationIssue(
                            path,
                            "bootstrap text write must contain exactly one template",
                        )
                    )
                else:
                    issues.extend(
                        _bootstrap_placeholder_issues(
                            write.get("template"), fields, f"{path}.template"
                        )
                    )
            else:
                issues.append(
                    ValidationIssue(path, "bootstrap write format must be yaml or text")
                )
    if len(descriptor_writes) != 1 or not isinstance(
        descriptor_writes[0].get("document") if descriptor_writes else None,
        dict,
    ):
        issues.append(
            ValidationIssue(
                "bootstrap:writes",
                "external bootstrap must declare exactly one typed instance.yaml document",
            )
        )
        return None, fields, issues
    return dict(descriptor_writes[0]["document"]), fields, issues


def _bootstrap_value_issues(
    actual: object,
    expected: object,
    fields: dict[str, dict[str, object]],
    path: str,
) -> list[ValidationIssue]:
    if isinstance(expected, dict) and set(expected) == {"field"}:
        field_id = expected.get("field")
        field = fields.get(field_id) if isinstance(field_id, str) else None
        if field is None:
            return [ValidationIssue(path, "descriptor references an undeclared bootstrap field")]
        field_type = field.get("type")
        valid = isinstance(actual, str)
        if field_type == "identifier":
            valid = valid and _BOOTSTRAP_IDENTIFIER.fullmatch(actual) is not None
        elif field_type == "enum":
            valid = valid and actual in field.get("values", [])
        return [] if valid else [ValidationIssue(path, f"descriptor value is not a valid {field_type} bootstrap field")]
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return [ValidationIssue(path, "descriptor value must be a mapping")]
        issues: list[ValidationIssue] = []
        if set(actual) != set(expected):
            issues.append(
                ValidationIssue(
                    path,
                    "descriptor keys do not match the exact external bootstrap contract",
                )
            )
        for key in sorted(set(actual) & set(expected)):
            issues.extend(
                _bootstrap_value_issues(
                    actual[key], expected[key], fields, f"{path}.{key}"
                )
            )
        return issues
    if isinstance(expected, list):
        if not isinstance(actual, list) or len(actual) != len(expected):
            return [ValidationIssue(path, "descriptor list does not match the external bootstrap contract")]
        issues: list[ValidationIssue] = []
        for index, (actual_item, expected_item) in enumerate(zip(actual, expected)):
            issues.extend(
                _bootstrap_value_issues(
                    actual_item, expected_item, fields, f"{path}[{index}]"
                )
            )
        return issues
    return [] if actual == expected else [
        ValidationIssue(path, "descriptor value does not match the exact external bootstrap contract")
    ]


def _external_bootstrap_issues(
    bootstrap: dict[str, object],
    *,
    expected_format: str,
    expected_template_id: object,
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    if bootstrap.get("formatVersion") != expected_format:
        issues.append(ValidationIssue("bootstrap:formatVersion", "bootstrap format does not match its manifest schema"))
    if bootstrap.get("templateId") != expected_template_id:
        issues.append(ValidationIssue("bootstrap:templateId", "bootstrap template identity does not match the manifest"))
    _document, _fields, descriptor_issues = _bootstrap_descriptor_contract(bootstrap)
    issues.extend(descriptor_issues)
    return issues


def _external_instance_descriptor_issues(
    data: object,
    bootstrap: dict[str, object],
) -> list[ValidationIssue]:
    document, fields, issues = _bootstrap_descriptor_contract(bootstrap)
    if document is None:
        return issues
    return issues + _bootstrap_value_issues(data, document, fields, "instance.yaml")


def _descriptor_identity(descriptor: dict[str, object]) -> dict[str, object]:
    return {
        key: value
        for key, value in descriptor.items()
        if key not in {"cacheDigest", "checkoutLocation", "requestedRef"}
    }


def _locked_template_binding_issues(
    instance_root: Path,
    template_root: Path,
    lock_data: dict[str, object],
    manifest: dict[str, object],
    *,
    exact_selected_path: bool,
    selected_source_descriptor: dict[str, object] | None = None,
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    locked_template = lock_data.get("template")
    if not isinstance(locked_template, dict):
        return [ValidationIssue(".statedd/lock.yaml:template", "lock template binding is invalid")]
    expected = {
        "id": manifest.get("templateId"),
        "version": manifest.get("templateVersion"),
    }
    if manifest.get("formatVersion") == MANIFEST_V2_FORMAT:
        template_contract = manifest.get("template")
        expected.update(
            {
                "manifestFormatVersion": manifest.get("formatVersion"),
                "stateddSpecVersion": (
                    template_contract.get("stateddSpecVersion")
                    if isinstance(template_contract, dict)
                    else None
                ),
                "instanceSchemaVersion": (
                    template_contract.get("instanceSchemaVersion")
                    if isinstance(template_contract, dict)
                    else None
                ),
                "selectedModules": manifest.get("selectedModules"),
            }
        )
    for field, value in expected.items():
        if locked_template.get(field) != value:
            issues.append(
                ValidationIssue(
                    f".statedd/lock.yaml:template.{field}",
                    f"lock template {field} does not match the exact selected template",
                )
            )

    try:
        validate_lifecycle_lock_against_manifest(
            lock_data,
            manifest,
            template_root,
        )
    except (LifecycleError, OSError, UnicodeError, ValueError) as exc:
        issues.append(
            ValidationIssue(
                ".statedd/lock.yaml",
                f"lock ownership binding does not match the exact selected template: {exc}",
            )
        )

    selected_path = Path(os.path.abspath(template_root))
    try:
        selected_revision = template_source_revision(selected_path)
    except (LifecycleError, OSError, UnicodeError, ValueError):
        issues.append(
            ValidationIssue(
                ".statedd/lock.yaml:template.sourceRevision",
                "could not verify the selected template source safely",
            )
        )
    else:
        if locked_template.get("sourceRevision") != selected_revision:
            issues.append(
                ValidationIssue(
                    ".statedd/lock.yaml:template.sourceRevision",
                    "lock source revision does not match the exact selected template",
                )
            )

    raw_source_path = locked_template.get("sourcePath")
    if not isinstance(raw_source_path, str) or not raw_source_path:
        issues.append(
            ValidationIssue(
                ".statedd/lock.yaml:template.sourcePath",
                "lock source path is unavailable",
            )
        )
        return issues
    locked_path = Path(raw_source_path)
    if not locked_path.is_absolute():
        locked_path = instance_root / locked_path
    locked_path = Path(os.path.abspath(locked_path))
    if _path_has_symlink_component(locked_path):
        issues.append(
            ValidationIssue(
                ".statedd/lock.yaml:template.sourcePath",
                "lock source path is not a safe template directory",
            )
        )
        return issues
    if not locked_path.is_dir():
        issues.append(
            ValidationIssue(
                ".statedd/lock.yaml:template.sourcePath",
                "lock source path is not an available template directory",
            )
        )
        return issues
    if exact_selected_path and selected_path != locked_path:
        issues.append(
            ValidationIssue(
                ".statedd/lock.yaml:template.sourcePath",
                "lock source path does not match the exact selected template path",
            )
        )

    try:
        source_revision = template_source_revision(locked_path)
        current_descriptor = (
            dict(selected_source_descriptor)
            if selected_source_descriptor is not None
            else describe_template_source(locked_path)
        )
    except (LifecycleError, OSError, UnicodeError, ValueError):
        issues.append(
            ValidationIssue(
                ".statedd/lock.yaml:template.sourceRevision",
                "could not verify the locked template source safely",
            )
        )
        return issues

    if (
        locked_template.get("sourceRevision") != source_revision
        and not any(
            issue.path == ".statedd/lock.yaml:template.sourceRevision"
            for issue in issues
        )
    ):
        issues.append(
            ValidationIssue(
                ".statedd/lock.yaml:template.sourceRevision",
                "lock source revision does not match the exact selected template",
            )
        )
    locked_descriptor = locked_template.get("source")
    if not isinstance(locked_descriptor, dict) or _descriptor_identity(
        locked_descriptor
    ) != _descriptor_identity(current_descriptor):
        issues.append(
            ValidationIssue(
                ".statedd/lock.yaml:template.source",
                "lock source descriptor does not match the exact selected template provenance",
            )
        )
    else:
        descriptor_location = locked_descriptor.get(
            "checkoutLocation", locked_descriptor.get("path")
        )
        descriptor_path = (
            Path(descriptor_location)
            if isinstance(descriptor_location, str) and descriptor_location
            else None
        )
        if descriptor_path is not None and not descriptor_path.is_absolute():
            descriptor_path = instance_root / descriptor_path
        if (
            descriptor_path is None
            or Path(os.path.abspath(descriptor_path)) != locked_path
        ):
            issues.append(
                ValidationIssue(
                    ".statedd/lock.yaml:template.source",
                    "lock source descriptor path does not match the exact selected template path",
                )
            )
    return issues


def _manifest_schema_issues(
    manifest: dict[str, object],
    root: Path,
    raw_manifest: dict[str, object],
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    try:
        registry = find_builtin_schema_registry()
        assets = manifest.get("assets", [])
        template = manifest.get("template")
        external_schema_ids: set[str] = set()
        external_schema_prefix: str | None = None
        if (
            manifest.get("formatVersion") == MANIFEST_V2_FORMAT
            and isinstance(template, dict)
            and isinstance(template.get("instanceSchemaVersion"), str)
        ):
            layout_match = _EXTERNAL_LAYOUT_SCHEMA_ID.fullmatch(
                template["instanceSchemaVersion"]
            )
            if layout_match is not None:
                external_schema_prefix = f"{layout_match.group('domain')}."
                external_schema_ids = {
                    template["instanceSchemaVersion"],
                    f"{layout_match.group('domain')}.instance/{layout_match.group('version')}",
                    f"{layout_match.group('domain')}.bootstrap/{layout_match.group('version')}",
                }
        for index, asset in enumerate(assets):
            if not isinstance(asset, dict):
                continue
            logical_id = asset.get("schema")
            if logical_id is None:
                continue
            path = f".statedd/manifest.yaml:assets[{index}].schema"
            logical_issue = _logical_schema_issue(logical_id, path)
            if logical_issue:
                issues.append(logical_issue)
                continue
            assert isinstance(logical_id, str)
            if logical_id.startswith("statedd.stateport.io/"):
                registry.schema(logical_id)
            elif (
                logical_id != MANIFEST_V2_FORMAT
                and logical_id not in external_schema_ids
                and (
                    external_schema_prefix is None
                    or not logical_id.startswith(external_schema_prefix)
                )
            ):
                issues.append(
                    ValidationIssue(
                        path,
                        "schema ID is not admitted by the exact instance layout contract",
                    )
                )
        if (
            manifest.get("formatVersion") == MANIFEST_V2_FORMAT
            and isinstance(template, dict)
        ):
            logical_id = template.get("instanceSchemaVersion")
            logical_path = ".statedd/manifest.yaml:template.instanceSchemaVersion"
            logical_issue = _logical_schema_issue(logical_id, logical_path)
            if logical_issue:
                issues.append(logical_issue)
            else:
                assert isinstance(logical_id, str)
                if logical_id.startswith("statedd.stateport.io/"):
                    registry.schema(logical_id)
                    declared = {
                        asset.get("schema")
                        for asset in assets
                        if isinstance(asset, dict) and asset.get("path") == "instance.yaml"
                    }
                    if declared != {logical_id}:
                        issues.append(
                            ValidationIssue(
                                ".statedd/manifest.yaml:template.instanceSchemaVersion",
                                "instance schema version must match the instance.yaml asset schema",
                            )
                        )
                else:
                    raw_layout_id = raw_manifest.get("instanceLayoutContract")
                    if raw_layout_id != logical_id:
                        issues.append(
                            ValidationIssue(
                                ".statedd/manifest.yaml:instanceLayoutContract",
                                "external instance layout contract must exactly match template.instanceSchemaVersion",
                            )
                        )
                    layout_match = _EXTERNAL_LAYOUT_SCHEMA_ID.fullmatch(logical_id)
                    expected_instance_schema = None
                    expected_bootstrap_schema = None
                    if layout_match is None:
                        issues.append(
                            ValidationIssue(
                                logical_path,
                                "external instance schema identity must use <domain>.instance-layout/<version>",
                            )
                        )
                    else:
                        expected_instance_schema = (
                            f"{layout_match.group('domain')}.instance/"
                            f"{layout_match.group('version')}"
                        )
                        expected_bootstrap_schema = (
                            f"{layout_match.group('domain')}.bootstrap/"
                            f"{layout_match.group('version')}"
                        )
                    layout_assets = [
                        asset
                        for asset in assets
                        if isinstance(asset, dict)
                        and asset.get("role") == "instance_layout_contract"
                    ]
                    if len(layout_assets) != 1:
                        issues.append(
                            ValidationIssue(
                                ".statedd/manifest.yaml:assets",
                                "external instance schema requires exactly one instance_layout_contract asset",
                            )
                        )
                    else:
                        layout_asset = layout_assets[0]
                        if (
                            layout_asset.get("kind") != "file"
                            or layout_asset.get("owner") != "template"
                            or layout_asset.get("required") is not True
                            or layout_asset.get("schema") != logical_id
                            or layout_asset.get("provisionPolicy") != "copy_from_template"
                            or layout_asset.get("updatePolicy") != "replace_if_unmodified"
                        ):
                            issues.append(
                                ValidationIssue(
                                    ".statedd/manifest.yaml:assets",
                                    "instance_layout_contract asset must be a required template file with the exact layout schema ID and immutable materialization policy",
                                )
                            )
                        source_path = layout_asset.get("source")
                        safe_source_path = _safe_contract_path(source_path)
                        if (
                            safe_source_path is not None
                            and layout_asset.get("path") == safe_source_path
                        ):
                            external_contract, contract_issue = _external_contract(
                                root, safe_source_path
                            )
                            if contract_issue:
                                issues.append(
                                    ValidationIssue(safe_source_path, contract_issue.message)
                                )
                            elif (
                                external_contract is None
                                or external_contract.get("contract_id") != logical_id
                            ):
                                issues.append(
                                    ValidationIssue(
                                        f"{safe_source_path}:contract_id",
                                        "layout contract_id must match the manifest layout schema ID",
                                    )
                                )
                            else:
                                validation = external_contract.get("validation")
                                entry_point = (
                                    _safe_contract_path(validation.get("entry_point"))
                                    if isinstance(validation, dict)
                                    else None
                                )
                                command = (
                                    validation.get("command")
                                    if isinstance(validation, dict)
                                    else None
                                )
                                entry_exists = False
                                if entry_point is not None:
                                    try:
                                        _bounded_regular_file_bytes(
                                            root,
                                            entry_point,
                                            maximum_bytes=None,
                                        )
                                    except OSError:
                                        pass
                                    else:
                                        entry_exists = True
                                if not entry_exists or command != f"python3 {entry_point}":
                                    issues.append(
                                        ValidationIssue(
                                            safe_source_path,
                                            "layout validation command must bind one existing template file",
                                        )
                                    )
                        else:
                            issues.append(
                                ValidationIssue(
                                    ".statedd/manifest.yaml:assets",
                                    "instance_layout_contract asset path and template source must be the same safe relative file",
                                )
                            )
                    instance_assets = [
                        asset
                        for asset in assets
                        if isinstance(asset, dict)
                        and asset.get("path") == "instance.yaml"
                        and asset.get("role") == "instance_lifecycle_descriptor"
                    ]
                    if len(instance_assets) != 1:
                        issues.append(
                            ValidationIssue(
                                ".statedd/manifest.yaml:assets",
                                "external layout requires exactly one instance_lifecycle_descriptor asset",
                            )
                        )
                    else:
                        instance_asset = instance_assets[0]
                        if (
                            instance_asset.get("kind") != "file"
                            or instance_asset.get("owner") != "instance"
                            or instance_asset.get("required") is not True
                            or instance_asset.get("provisionPolicy") != "create_if_missing"
                            or instance_asset.get("updatePolicy") != "preserve"
                            or (
                                expected_instance_schema is not None
                                and instance_asset.get("schema")
                                != expected_instance_schema
                            )
                        ):
                            issues.append(
                                ValidationIssue(
                                    ".statedd/manifest.yaml:assets",
                                    f"instance.yaml asset schema must be {expected_instance_schema!r} and the asset must be a required instance-owned preserved file",
                                )
                            )
                    bootstrap_assets = [
                        asset
                        for asset in assets
                        if isinstance(asset, dict)
                        and asset.get("role") == "typed_instance_bootstrap_contract"
                    ]
                    if len(bootstrap_assets) != 1:
                        issues.append(
                            ValidationIssue(
                                ".statedd/manifest.yaml:assets",
                                "external layout requires exactly one typed_instance_bootstrap_contract asset",
                            )
                        )
                    else:
                        bootstrap_asset = bootstrap_assets[0]
                        bootstrap_source = _safe_contract_path(
                            bootstrap_asset.get("source")
                        )
                        if (
                            bootstrap_asset.get("kind") != "file"
                            or bootstrap_asset.get("owner") != "template"
                            or bootstrap_asset.get("required") is not True
                            or bootstrap_asset.get("schema")
                            != expected_bootstrap_schema
                            or bootstrap_asset.get("provisionPolicy")
                            != "copy_from_template"
                            or bootstrap_asset.get("updatePolicy")
                            != "replace_if_unmodified"
                            or bootstrap_source is None
                            or bootstrap_asset.get("path") != bootstrap_source
                        ):
                            issues.append(
                                ValidationIssue(
                                    ".statedd/manifest.yaml:assets",
                                    f"external bootstrap must be a required template file with schema {expected_bootstrap_schema!r}",
                                )
                            )
                        else:
                            bootstrap, bootstrap_issue = _bounded_yaml_mapping(
                                root,
                                bootstrap_source,
                                "external bootstrap contract",
                            )
                            if bootstrap_issue:
                                issues.append(bootstrap_issue)
                            elif bootstrap is not None:
                                issues.extend(
                                    _external_bootstrap_issues(
                                        bootstrap,
                                        expected_format=str(
                                            expected_bootstrap_schema
                                        ),
                                        expected_template_id=template.get("id"),
                                    )
                                )
    except (OSError, UnicodeError, ValueError, SchemaRegistryError) as exc:
        issues.append(ValidationIssue(".statedd/manifest.yaml", f"schema resolution failed: {exc}"))
    return issues


def validate_template(path: Path | str) -> ValidationResult:
    """Validate a StateSpec template folder."""
    target = Path(path)
    issues: list[ValidationIssue] = []
    if _path_has_symlink_component(target):
        return ValidationResult(
            valid=False,
            issues=(
                ValidationIssue("template", "template path must not traverse a symlink"),
            ),
        )

    manifest_path = target / ".statedd" / "manifest.yaml"
    manifest_data = None
    manifest_safe = not _path_has_symlink_component(manifest_path)
    if manifest_path.exists() and not manifest_safe:
        issues.append(
            ValidationIssue(
                ".statedd/manifest.yaml",
                "manifest path must not traverse a symlink",
            )
        )
    elif manifest_path.exists() and manifest_path.is_file():
        manifest_issues, manifest_data = check_yaml_parseable(manifest_path)
        issues.extend(manifest_issues)
    is_v2 = (
        isinstance(manifest_data, dict)
        and manifest_data.get("formatVersion") == MANIFEST_V2_FORMAT
    )
    required_files = [".statedd/manifest.yaml"] if is_v2 else TEMPLATE_REQUIRED_FILES
    issues.extend(check_required_files(target, required_files))

    template_yaml = target / "template.yaml"
    if template_yaml.exists() and _path_has_symlink_component(template_yaml):
        issues.append(
            ValidationIssue("template.yaml", "template metadata path must not traverse a symlink")
        )
    elif template_yaml.exists() and template_yaml.is_file():
        parse_issues, data = check_yaml_parseable(template_yaml)
        issues.extend(parse_issues)
        if data is not None:
            issues.extend(check_template_schema(data))

    if manifest_path.exists() and manifest_safe:
        try:
            normalized_manifest = load_template_manifest(target)
        except (LifecycleError, OSError, ValueError) as exc:
            issues.append(ValidationIssue(".statedd/manifest.yaml", str(exc)))
        else:
            issues.extend(
                _manifest_schema_issues(
                    normalized_manifest,
                    target,
                    manifest_data if isinstance(manifest_data, dict) else {},
                )
            )

    return ValidationResult(valid=not issues, issues=tuple(issues))


def validate_instance(
    path: Path | str,
    *,
    template_path_override: Path | str | None = None,
    template_source_descriptor_override: dict[str, object] | None = None,
) -> ValidationResult:
    """Validate an instance and, when supplied, its already-verified source."""
    target = Path(path)
    issues: list[ValidationIssue] = []
    if _path_has_symlink_component(target):
        return ValidationResult(
            valid=False,
            issues=(
                ValidationIssue("instance", "instance path must not traverse a symlink"),
            ),
        )

    issues.extend(check_required_files(target, INSTANCE_REQUIRED_FILES))

    lock_path = target / ".statedd" / "lock.yaml"
    lock_data: dict[str, object] | None = None
    if lock_path.exists():
        if not lock_path.is_file() or _path_has_symlink_component(lock_path):
            issues.append(ValidationIssue(".statedd/lock.yaml", "lock must be a regular non-symlink file"))
        else:
            lock_parse_issues, parsed_lock = check_yaml_parseable(lock_path)
            issues.extend(
                ValidationIssue(".statedd/lock.yaml", issue.message)
                for issue in lock_parse_issues
            )
            if isinstance(parsed_lock, dict):
                lock_data = parsed_lock
                issues.extend(_contract_issues(lock_data, LOCK_SCHEMA_ID, ".statedd/lock.yaml"))
                try:
                    validate_lifecycle_lock(lock_data)
                except LifecycleError as exc:
                    issues.append(ValidationIssue(".statedd/lock.yaml", str(exc)))
    locked_template = lock_data.get("template") if isinstance(lock_data, dict) else None
    locked_instance_schema = (
        locked_template.get("instanceSchemaVersion")
        if isinstance(locked_template, dict)
        else None
    )

    instance_yaml = target / "instance.yaml"
    data: object | None = None
    if instance_yaml.exists() and _path_has_symlink_component(instance_yaml):
        issues.append(
            ValidationIssue("instance.yaml", "instance descriptor path must not traverse a symlink")
        )
    elif instance_yaml.exists() and instance_yaml.is_file():
        parse_issues, data = check_yaml_parseable(instance_yaml)
        issues.extend(parse_issues)
        if data is not None:
            issues.extend(check_instance_schema(data))
            issues.extend(_instance_contract_issues(data, locked_instance_schema))
            try:
                Instance.from_dict(data)
            except ValueError as exc:
                issues.append(ValidationIssue("instance.yaml", str(exc)))
            spec = data.get("spec") if isinstance(data, dict) else None
            template_ref_path = ""
            template_ref_id = ""
            if isinstance(spec, dict):
                template_ref = spec.get("templateRef", {})
                if isinstance(template_ref, dict):
                    template_ref_id = template_ref.get("id", "")
                    raw_path = template_ref.get("path", "")
                    if isinstance(raw_path, str):
                        template_ref_path = raw_path
                    else:
                        issues.append(
                            ValidationIssue(
                                "spec.templateRef.path",
                                "template path must be a string",
                            )
                        )
            if (
                isinstance(spec, dict)
                and isinstance(template_ref, dict)
                and isinstance(raw_path, str)
                and template_ref_path
            ):
                if template_path_override is None:
                    raw_template_path = target / template_ref_path
                    if _path_has_symlink_component(raw_template_path):
                        issues.append(
                            ValidationIssue(
                                "spec.templateRef.path",
                                "template path must not traverse a symlink",
                            )
                        )
                        template_path = None
                    else:
                        ref_issues, template_path = check_template_ref_resolves(
                            target, template_ref_path
                        )
                        issues.extend(ref_issues)
                else:
                    template_path = Path(template_path_override)
                    if (
                        not template_path.is_dir()
                        or _path_has_symlink_component(template_path)
                    ):
                        issues.append(
                            ValidationIssue(
                                "spec.templateRef.path",
                                "trusted template override must be a real directory",
                            )
                        )
                        template_path = None
                if template_path is not None:
                    template_result = validate_template(template_path)
                    for issue in template_result.issues:
                        prefix = "template"
                        if issue.path:
                            prefix = f"template:{issue.path}"
                        issues.append(
                            ValidationIssue(
                                prefix,
                                issue.message,
                            )
                        )
                    if template_result.ok:
                        # v2's manifest is authoritative and does not require a
                        # compatibility template.yaml document.
                        template_yaml_path = template_path / "template.yaml"
                        template_data = None
                        if template_yaml_path.is_file():
                            # Re-read the referenced compatibility template to
                            # discover its legacy state-file declarations.
                            _, template_data = check_yaml_parseable(template_yaml_path)
                        normalized_template = load_template_manifest(template_path)
                        if isinstance(locked_template, dict):
                            issues.extend(
                                _locked_template_binding_issues(
                                    target,
                                    template_path,
                                    lock_data,
                                    normalized_template,
                                    exact_selected_path=(
                                        template_path_override is not None
                                    ),
                                    selected_source_descriptor=(
                                        template_source_descriptor_override
                                        if isinstance(
                                            template_source_descriptor_override,
                                            dict,
                                        )
                                        else None
                                    ),
                                )
                            )
                        template_contract = normalized_template.get("template")
                        template_instance_schema = (
                            template_contract.get("instanceSchemaVersion")
                            if isinstance(template_contract, dict)
                            else None
                        )
                        external_instance_schema = (
                            template_instance_schema
                            if isinstance(template_instance_schema, str)
                            and _EXTERNAL_LAYOUT_SCHEMA_ID.fullmatch(
                                template_instance_schema
                            )
                            else None
                        )
                        if external_instance_schema is not None and not isinstance(
                            locked_template, dict
                        ):
                            issues.append(
                                ValidationIssue(
                                    ".statedd/lock.yaml",
                                    "external layout instances require a lifecycle lock",
                                )
                            )
                        if (
                            isinstance(locked_instance_schema, str)
                            and template_instance_schema != locked_instance_schema
                        ):
                            issues.append(
                                ValidationIssue(
                                    ".statedd/lock.yaml:template.instanceSchemaVersion",
                                    "lock instance schema identity does not match the exact template",
                                )
                            )
                        if (
                            external_instance_schema is not None
                        ):
                            assets = normalized_template.get("assets")
                            layout_assets = [
                                asset
                                for asset in assets
                                if isinstance(asset, dict)
                                and asset.get("role")
                                == "instance_layout_contract"
                            ] if isinstance(assets, list) else []
                            if len(layout_assets) == 1:
                                source_path = _safe_contract_path(
                                    layout_assets[0].get("source")
                                )
                                if source_path is not None:
                                    external_contract, contract_issue = _external_contract(
                                        template_path, source_path
                                    )
                                    if contract_issue:
                                        issues.append(contract_issue)
                                    elif external_contract is not None:
                                        issues.extend(
                                            _external_instance_contract_issues(
                                                data,
                                                target,
                                                external_contract,
                                            )
                                        )
                            bootstrap_assets = [
                                asset
                                for asset in assets
                                if isinstance(asset, dict)
                                and asset.get("role")
                                == "typed_instance_bootstrap_contract"
                            ] if isinstance(assets, list) else []
                            if len(bootstrap_assets) == 1:
                                bootstrap_source = _safe_contract_path(
                                    bootstrap_assets[0].get("source")
                                )
                                if bootstrap_source is not None:
                                    bootstrap, bootstrap_issue = _bounded_yaml_mapping(
                                        template_path,
                                        bootstrap_source,
                                        "external bootstrap contract",
                                    )
                                    if bootstrap_issue:
                                        issues.append(bootstrap_issue)
                                    elif bootstrap is not None:
                                        issues.extend(
                                            _external_instance_descriptor_issues(
                                                data,
                                                bootstrap,
                                            )
                                        )
                        template_metadata = (
                            template_data.get("metadata")
                            if isinstance(template_data, dict)
                            else None
                        )
                        template_id = (
                            template_metadata.get("id")
                            if isinstance(template_metadata, dict)
                            else normalized_template.get("templateId")
                        )
                        if template_ref_id and template_id != template_ref_id:
                            issues.append(
                                ValidationIssue(
                                    "spec.templateRef.id",
                                    f"template id mismatch: instance references "
                                    f"'{template_ref_id}' but template has id "
                                    f"'{template_id}'",
                                )
                            )
                        template_spec = (
                            template_data.get("spec")
                            if isinstance(template_data, dict)
                            else None
                        )
                        lifecycle_declared = (
                            isinstance(template_spec, dict)
                            and "lifecycle" in template_spec
                        )
                        lifecycle = (
                            template_spec.get("lifecycle")
                            if lifecycle_declared
                            else None
                        )
                        status = spec.get("status")
                        if (
                            lifecycle_declared
                            and (not isinstance(lifecycle, list) or not lifecycle)
                        ):
                            issues.append(
                                ValidationIssue(
                                    "template:spec.lifecycle",
                                    "template lifecycle must be a non-empty list",
                                )
                            )
                        elif (
                            isinstance(status, str)
                            and isinstance(lifecycle, list)
                            and status not in lifecycle
                        ):
                            issues.append(
                                ValidationIssue(
                                    "spec.status",
                                    f"instance status {status!r} is not declared by the template lifecycle",
                                )
                            )
                        schema_list = (
                            template_spec.get("schemas", [])
                            if isinstance(template_spec, dict)
                            else []
                        )
                        issues.extend(
                            check_schema_files_exist(
                                target,
                                schema_list,
                                path_prefix="state",
                            )
                        )

    if isinstance(lock_data, dict) and isinstance(data, dict):
        metadata = data.get("metadata")
        instance_id = metadata.get("id") if isinstance(metadata, dict) else None
        if isinstance(instance_id, str) and lock_data.get("instanceId") != instance_id:
            issues.append(
                ValidationIssue(
                    ".statedd/lock.yaml:instanceId",
                    "lock instanceId does not match instance metadata.id",
                )
            )

    return ValidationResult(valid=not issues, issues=tuple(issues))
