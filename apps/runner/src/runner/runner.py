"""Minimal local runner for StateSpec instances."""

from __future__ import annotations

from pathlib import Path
from typing import Any, TypeVar

T = TypeVar("T")

from statedd_core import Instance, LifecycleError, MANIFEST_V2_FORMAT, Template, load_template_manifest
from statedd_core.yaml import StateDDYamlError, parse_yaml_text
from template_validator import validate_instance
from template_validator.checks import _resolve_confined_path, check_template_ref_resolves
from template_validator.result import ValidationIssue

from runner.result import RunResult


def _format_issue(issue: ValidationIssue) -> str:
    """Format a validation issue as a single string."""
    return f"{issue.path}: {issue.message}"


def _load_yaml(path: Path) -> tuple[list[str], Any]:
    """Load a YAML file, returning (errors, data)."""
    try:
        text = path.read_text(encoding="utf-8")
        return [], parse_yaml_text(text)
    except StateDDYamlError as exc:
        return [f"could not parse {path.name}: {exc}"], None
    except (OSError, UnicodeDecodeError) as exc:
        return [f"could not read {path.name}: {exc}"], None


def _load_model(
    yaml_path: Path, model_class: type[T], label: str
) -> tuple[list[str], T | None]:
    """Parse a YAML file into a StateDD model dataclass."""
    errors, data = _load_yaml(yaml_path)
    if errors:
        return errors, None
    if not isinstance(data, dict):
        return [f"invalid {label}: expected a mapping"], None
    try:
        return [], model_class.from_dict(data)
    except (AttributeError, TypeError, ValueError) as exc:
        return [f"invalid {label}: {exc}"], None


ALLOWED_STATUSES = {"active", "archived", "draft"}


def _validate_status(status: str) -> str | None:
    """Return an error message if ``status`` is not an allowed value."""
    if status not in ALLOWED_STATUSES:
        allowed = ", ".join(sorted(ALLOWED_STATUSES))
        return f"invalid instance status '{status}': must be one of {allowed}"
    return None


def run_instance(
    instance_path: Path | str,
    *,
    template_path_override: Path | str | None = None,
) -> RunResult:
    """Run a StateSpec instance in echo mode.

    The runner loads the instance and its referenced template, verifies that
    every schema-listed state file exists, and returns a deterministic result.
    No state is mutated.

    When ``instance.yaml`` cannot be loaded, the returned ``RunResult.status``
    is the empty string to indicate that the instance status is unknown.

    Validation split:

    - The runner performs its own loading, template-ref resolution, and
      schema-file checks so it can produce deterministic, runner-specific
      logs and errors.
    - ``validate_instance`` is then invoked defensively to catch structural
      and schema issues that the runner's targeted checks may have missed.

    This overlap is intentional: the runner wants clear operational output
    for the paths it owns, while the validator provides a broader safety net.
    """
    target = Path(instance_path)
    logs: list[str] = ["runner started"]
    status = ""

    try:
        instance_errors, instance = _load_model(
            target / "instance.yaml", Instance, "instance.yaml"
        )
        if instance_errors:
            return RunResult(
                status="", logs=tuple(logs), errors=tuple(instance_errors)
            )

        logs.append(f"instance loaded: {instance.metadata.id}")
        status = instance.spec.status

        status_error = _validate_status(status)
        if status_error:
            return RunResult(
                status=status, logs=tuple(logs), errors=(status_error,)
            )

        if template_path_override is None:
            ref_issues, template_dir = check_template_ref_resolves(
                target, instance.spec.template_ref.path
            )
            if ref_issues or template_dir is None:
                errors = [_format_issue(issue) for issue in ref_issues]
                return RunResult(status=status, logs=tuple(logs), errors=tuple(errors))
        else:
            template_dir = Path(template_path_override)
            if not template_dir.is_dir() or template_dir.is_symlink():
                return RunResult(
                    status=status,
                    logs=tuple(logs),
                    errors=("trusted template override must be a real directory",),
                )

        try:
            manifest = load_template_manifest(template_dir)
        except LifecycleError as exc:
            return RunResult(status=status, logs=tuple(logs), errors=(str(exc),))

        template = None
        if manifest["formatVersion"] != MANIFEST_V2_FORMAT:
            template_errors, template = _load_model(
                template_dir / "template.yaml", Template, "template.yaml"
            )
            if template_errors:
                return RunResult(
                    status=status, logs=tuple(logs), errors=tuple(template_errors)
                )

        template_id = manifest["templateId"]
        if template_id != instance.spec.template_ref.id:
            return RunResult(
                status=status,
                logs=tuple(logs),
                errors=(
                    (
                        f"template id mismatch: instance references "
                        f"'{instance.spec.template_ref.id}' but template has id "
                        f"'{template_id}'"
                    ),
                ),
            )

        logs.append(f"template loaded: {template_id}")

        schema_errors: list[str] = []
        present_schemas: list[str] = []
        schema_paths = template.spec.schemas if template is not None else []
        for schema_path in schema_paths:
            if not isinstance(schema_path, str):
                schema_errors.append(
                    f"schema path must be a string, got {type(schema_path).__name__}"
                )
                continue
            confinement_issues, schema_file = _resolve_confined_path(
                target, schema_path, f"spec.schemas: {schema_path}"
            )
            if confinement_issues:
                schema_errors.append(_format_issue(confinement_issues[0]))
                continue
            if schema_file is None or not schema_file.is_file():
                schema_errors.append(f"missing required state file: {schema_path}")
            else:
                present_schemas.append(schema_path)

        if present_schemas:
            logs.append(f"state files present: {', '.join(present_schemas)}")

        if schema_errors:
            return RunResult(
                status=status, logs=tuple(logs), errors=tuple(schema_errors)
            )

        validation = validate_instance(
            target,
            template_path_override=template_dir,
        )
        if not validation.ok:
            errors = [_format_issue(issue) for issue in validation.issues]
            return RunResult(status=status, logs=tuple(logs), errors=tuple(errors))

        if status != "active":
            logs.append(
                f"instance status is {status}, runner continuing in echo mode"
            )

        return RunResult(status=status, logs=tuple(logs), errors=())
    except Exception as exc:  # noqa: BLE001 - safety net for malformed inputs
        return RunResult(
            status=status,
            logs=tuple(logs),
            errors=(f"unexpected runner error: {exc}",),
        )
