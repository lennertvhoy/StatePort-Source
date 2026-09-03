"""Fail-closed error taxonomy for the API-native boundary."""

from __future__ import annotations

import builtins
from enum import Enum
from typing import Any

from .models import redact


class RetryClassification(str, Enum):
    NEVER = "never"
    TRANSIENT = "transient"
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    UNKNOWN = "unknown"

    @property
    def retryable(self) -> bool:
        return self in {self.TRANSIENT, self.RATE_LIMITED, self.TIMEOUT}


class ApiNativeError(Exception):
    code = "api_native_error"
    retry_classification = RetryClassification.NEVER

    def __init__(self, message: str, *, code: str | None = None, retry_classification: RetryClassification | None = None, details: Any = None) -> None:
        self.message = str(message)
        self.code = code or self.code
        self.retry_classification = RetryClassification(retry_classification or self.retry_classification)
        self.details = redact(details) if details is not None else None
        super().__init__(self.message)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"type": type(self).__name__, "code": self.code, "message": self.message, "retryClass": self.retry_classification.value}
        if self.details is not None:
            result["details"] = self.details
        return redact(result)


class StrictModelError(ApiNativeError):
    code = "invalid_model"


class RunSpecBindingError(ApiNativeError):
    code = "runspec_binding_mismatch"


class NetworkPolicyError(ApiNativeError):
    code = "network_policy_denied"


class IdempotencyConflictError(ApiNativeError):
    code = "idempotency_conflict"


class TransportError(ApiNativeError):
    code = "transport_error"
    retry_classification = RetryClassification.UNKNOWN


class ProviderError(ApiNativeError):
    code = "provider_error"


class TimeoutError(ApiNativeError):
    code = "timeout"
    retry_classification = RetryClassification.TIMEOUT


class CancellationError(ApiNativeError):
    code = "cancelled"
    retry_classification = RetryClassification.CANCELLED


class RetryExhaustedError(ApiNativeError):
    code = "retry_exhausted"
    retry_classification = RetryClassification.NEVER


class ToolCallValidationError(ApiNativeError):
    code = "tool_call_invalid"

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message, code=code)


class ApprovalRequiredError(ApiNativeError):
    code = "approval_required"

    def __init__(self, call_id: str, capability: str) -> None:
        self.call_id = call_id
        self.capability = capability
        super().__init__(f"tool call {call_id} requires approval", details={"callId": call_id, "capability": capability})


def classify_retry(error: BaseException) -> RetryClassification:
    """Classify local/provider failures without guessing that unknown is safe."""

    if isinstance(error, ApiNativeError):
        return error.retry_classification
    if isinstance(error, (TimeoutError, builtins.TimeoutError)):
        return RetryClassification.TIMEOUT
    if isinstance(error, (ConnectionError, OSError)):
        return RetryClassification.TRANSIENT
    return RetryClassification.UNKNOWN
