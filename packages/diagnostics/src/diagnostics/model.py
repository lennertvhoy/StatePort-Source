"""Typed, secret-safe diagnostics shared by StatePort operators and tools."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import json
import re
from typing import Any, Mapping, TypeAlias


class DiagnosticCode(str, Enum):
    """Stable diagnostic families; codes are part of the operator contract."""

    ENV = "SP-ENV"
    SOURCE = "SP-SOURCE"
    INSTANCE = "SP-INSTANCE"
    LOCK = "SP-LOCK"
    LIFECYCLE = "SP-LIFECYCLE"
    RUN = "SP-RUN"
    APPROVAL = "SP-APPROVAL"
    BACKUP = "SP-BACKUP"
    HOST = "SP-HOST"
    CI = "SP-CI"
    INSTANCE_ROOT_NOT_FOUND = "SP-INSTANCE-ROOT-NOT-FOUND"
    INSTANCE_ROOT_NOT_DIRECTORY = "SP-INSTANCE-ROOT-NOT-DIRECTORY"
    INSTANCE_ROOT_INACCESSIBLE = "SP-INSTANCE-ROOT-INACCESSIBLE"
    SOURCE_EXPLICIT_REQUIRED = "SP-SOURCE-EXPLICIT-REQUIRED"
    SOURCE_REPOSITORY_NOT_FOUND = "SP-SOURCE-REPOSITORY-NOT-FOUND"
    SOURCE_MANIFEST_NOT_FOUND = "SP-SOURCE-MANIFEST-NOT-FOUND"
    SOURCE_COMMIT_NOT_FOUND = "SP-SOURCE-COMMIT-NOT-FOUND"
    SOURCE_TEMPLATE_ID_MISMATCH = "SP-SOURCE-TEMPLATE-ID-MISMATCH"
    SOURCE_IDENTITY_MISMATCH = "SP-SOURCE-IDENTITY-MISMATCH"


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class Component(str, Enum):
    ENVIRONMENT = "environment"
    SOURCE = "source"
    INSTANCE = "instance"
    LOCK = "lock"
    LIFECYCLE = "lifecycle"
    RUN = "run"
    APPROVAL = "approval"
    BACKUP = "backup"
    HOST = "host"
    CI = "ci"


CODE_ORDER: tuple[DiagnosticCode, ...] = (
    DiagnosticCode.ENV,
    DiagnosticCode.SOURCE,
    DiagnosticCode.INSTANCE,
    DiagnosticCode.LOCK,
    DiagnosticCode.LIFECYCLE,
    DiagnosticCode.RUN,
    DiagnosticCode.APPROVAL,
    DiagnosticCode.BACKUP,
    DiagnosticCode.HOST,
    DiagnosticCode.CI,
    DiagnosticCode.INSTANCE_ROOT_NOT_FOUND,
    DiagnosticCode.INSTANCE_ROOT_NOT_DIRECTORY,
    DiagnosticCode.INSTANCE_ROOT_INACCESSIBLE,
    DiagnosticCode.SOURCE_EXPLICIT_REQUIRED,
    DiagnosticCode.SOURCE_REPOSITORY_NOT_FOUND,
    DiagnosticCode.SOURCE_MANIFEST_NOT_FOUND,
    DiagnosticCode.SOURCE_COMMIT_NOT_FOUND,
    DiagnosticCode.SOURCE_TEMPLATE_ID_MISMATCH,
    DiagnosticCode.SOURCE_IDENTITY_MISMATCH,
)

CODE_COMPONENT: dict[DiagnosticCode, Component] = {
    DiagnosticCode.ENV: Component.ENVIRONMENT,
    DiagnosticCode.SOURCE: Component.SOURCE,
    DiagnosticCode.INSTANCE: Component.INSTANCE,
    DiagnosticCode.LOCK: Component.LOCK,
    DiagnosticCode.LIFECYCLE: Component.LIFECYCLE,
    DiagnosticCode.RUN: Component.RUN,
    DiagnosticCode.APPROVAL: Component.APPROVAL,
    DiagnosticCode.BACKUP: Component.BACKUP,
    DiagnosticCode.HOST: Component.HOST,
    DiagnosticCode.CI: Component.CI,
    DiagnosticCode.INSTANCE_ROOT_NOT_FOUND: Component.INSTANCE,
    DiagnosticCode.INSTANCE_ROOT_NOT_DIRECTORY: Component.INSTANCE,
    DiagnosticCode.INSTANCE_ROOT_INACCESSIBLE: Component.INSTANCE,
    DiagnosticCode.SOURCE_EXPLICIT_REQUIRED: Component.SOURCE,
    DiagnosticCode.SOURCE_REPOSITORY_NOT_FOUND: Component.SOURCE,
    DiagnosticCode.SOURCE_MANIFEST_NOT_FOUND: Component.SOURCE,
    DiagnosticCode.SOURCE_COMMIT_NOT_FOUND: Component.SOURCE,
    DiagnosticCode.SOURCE_TEMPLATE_ID_MISMATCH: Component.SOURCE,
    DiagnosticCode.SOURCE_IDENTITY_MISMATCH: Component.SOURCE,
}

JSONValue: TypeAlias = None | bool | int | float | str | list["JSONValue"] | dict[str, "JSONValue"]

_SECRET_KEY = re.compile(
    r"(?:api[_-]?key|authorization|cookie|credential|password|private[_-]?key|secret|token)",
    re.IGNORECASE,
)
_SECRET_VALUE = re.compile(
    r"(?:bearer\s+[A-Za-z0-9._~+/=-]+|(?:sk|gh[pousr]|xox[baprs])-[-_A-Za-z0-9]{12,})",
    re.IGNORECASE,
)
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(api[_-]?key|authorization|cookie|credential|password|private[_-]?key|secret|token)"
    r"\s*[:=]\s*([^\s,;]+)"
)
_REDACTED = "<redacted>"


def _safe_text(value: str) -> str:
    value = _SECRET_ASSIGNMENT.sub(lambda match: f"{match.group(1)}={_REDACTED}", value)
    return _REDACTED if _SECRET_VALUE.search(value) else value


def _safe_json(value: Any, *, key: str | None = None) -> JSONValue:
    """Convert values to JSON primitives while removing secret material."""

    if key is not None and _SECRET_KEY.search(key):
        return _REDACTED
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, Enum):
        return _safe_json(value.value, key=key)
    if isinstance(value, str):
        return _safe_text(value)
    if isinstance(value, Mapping):
        result: dict[str, JSONValue] = {}
        for raw_key, raw_value in value.items():
            if not isinstance(raw_key, str) or not raw_key:
                raise TypeError("diagnostic detail keys must be non-empty strings")
            result[raw_key] = _safe_json(raw_value, key=raw_key)
        return dict(sorted(result.items()))
    if isinstance(value, (list, tuple)):
        return [_safe_json(item) for item in value]
    raise TypeError(f"diagnostic details are not JSON-safe: {type(value).__name__}")


@dataclass(frozen=True)
class Diagnostic:
    """One stable, serializable observation from a StatePort check.

    ``info`` is a passing observation.  Warnings are non-fatal by default;
    errors and critical findings make a doctor report fail.
    """

    code: DiagnosticCode | str
    severity: Severity | str
    component: Component | str
    explanation: str
    details: Mapping[str, Any] = field(default_factory=dict)
    remediation: str = "No action required."
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        try:
            code = DiagnosticCode(self.code)
        except ValueError as exc:
            raise ValueError(f"unknown diagnostic code: {self.code!r}") from exc
        try:
            severity = Severity(self.severity)
        except ValueError as exc:
            raise ValueError(f"unknown diagnostic severity: {self.severity!r}") from exc
        try:
            component = Component(self.component)
        except ValueError as exc:
            raise ValueError(f"unknown diagnostic component: {self.component!r}") from exc
        for name, value in (("explanation", self.explanation), ("remediation", self.remediation)):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        if not isinstance(self.details, Mapping):
            raise TypeError("details must be a mapping")
        if not isinstance(self.evidence, (tuple, list)) or any(
            not isinstance(item, str) or not item.strip() for item in self.evidence
        ):
            raise TypeError("evidence must contain non-empty strings")
        safe_details = _safe_json(self.details)
        safe_explanation = _safe_text(self.explanation)
        safe_remediation = _safe_text(self.remediation)
        safe_evidence = tuple(_safe_json(item) for item in self.evidence)
        object.__setattr__(self, "code", code)
        object.__setattr__(self, "severity", severity)
        object.__setattr__(self, "component", component)
        object.__setattr__(self, "explanation", safe_explanation)
        object.__setattr__(self, "remediation", safe_remediation)
        object.__setattr__(self, "details", safe_details)
        object.__setattr__(self, "evidence", safe_evidence)

    @property
    def is_failure(self) -> bool:
        return self.severity in (Severity.ERROR, Severity.CRITICAL)

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            "code": self.code.value,
            "severity": self.severity.value,
            "component": self.component.value,
            "explanation": self.explanation,
            "details": self.details,
            "remediation": self.remediation,
            "evidence": list(self.evidence),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def diagnostic_sort_key(item: Diagnostic) -> tuple[Any, ...]:
    """Return a stable ordering key independent of construction order."""

    return (
        CODE_ORDER.index(item.code),
        item.severity.value,
        item.component.value,
        item.explanation,
        json.dumps(item.details, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
        tuple(item.evidence),
    )


@dataclass(frozen=True)
class DoctorReport:
    diagnostics: tuple[Diagnostic, ...]
    skipped_checks: tuple[dict[str, str], ...] = ()

    def __post_init__(self) -> None:
        ordered = tuple(sorted(self.diagnostics, key=diagnostic_sort_key))
        object.__setattr__(self, "diagnostics", ordered)

    @property
    def ok(self) -> bool:
        return not any(item.is_failure for item in self.diagnostics)

    @property
    def warnings(self) -> int:
        return sum(item.severity is Severity.WARNING for item in self.diagnostics)

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            "ok": self.ok,
            "warnings": self.warnings,
            "diagnostics": [item.to_dict() for item in self.diagnostics],
            "skippedChecks": [dict(item) for item in self.skipped_checks],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
