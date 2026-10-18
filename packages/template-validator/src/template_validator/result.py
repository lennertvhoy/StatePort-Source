"""Result types for template/instance validation."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ValidationIssue:
    """A single validation problem."""

    path: str
    message: str

    def __str__(self) -> str:
        return f"{self.path}: {self.message}"


@dataclass(frozen=True)
class ValidationResult:
    """Outcome of validating a template or instance."""

    valid: bool
    issues: tuple[ValidationIssue, ...] = field(default_factory=tuple)

    @property
    def ok(self) -> bool:
        """True when the target is valid and has no issues."""
        return self.valid and not self.issues
