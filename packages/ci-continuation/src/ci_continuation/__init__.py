"""Deterministic, fake-provider-only blocked-CI continuation state machine."""

from ci_continuation.machine import (
    AuditRecord,
    AuthorizationDecision,
    BindingMismatchError,
    CIObservation,
    CIStatus,
    ContinuationState,
    DecisionRequest,
    ExactHeadBinding,
    FakeCIProvider,
    HumanAuthorization,
    InvalidTransitionError,
    ProviderContractError,
    StaleAuthorizationError,
    StateMachineError,
    WorkflowContinuation,
)

__all__ = [
    "AuditRecord",
    "AuthorizationDecision",
    "BindingMismatchError",
    "CIObservation",
    "CIStatus",
    "ContinuationState",
    "DecisionRequest",
    "ExactHeadBinding",
    "FakeCIProvider",
    "HumanAuthorization",
    "InvalidTransitionError",
    "ProviderContractError",
    "StaleAuthorizationError",
    "StateMachineError",
    "WorkflowContinuation",
]
