"""StateDD template and instance validator."""

from template_validator.result import ValidationIssue, ValidationResult
from template_validator.validator import validate_instance, validate_template

__all__ = [
    "ValidationIssue",
    "ValidationResult",
    "validate_template",
    "validate_instance",
]
