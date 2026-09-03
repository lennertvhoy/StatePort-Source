"""Typed deployment refusals and runtime failures."""

from __future__ import annotations

from typing import Any, Mapping


EXIT_REFUSED = 2
EXIT_RUNTIME_FAILED = 3
EXIT_RECONCILIATION_REQUIRED = 4
EXIT_INTERNAL_ERROR = 70

_RECONCILIATION_CODES = frozenset(
    {
        "authority_effect_unfinalized",
        "authority_effect_outcome_unknown",
        "authority_finalization_pending",
        "authority_link_pending",
        "deployment_busy",
        "deployment_commit_uncertain",
        "evidence_integrity_failed",
        "plan_closure_invalid",
        "receipt_chain_invalid",
        "state_integrity_failed",
        "transaction_invalid",
        "transaction_conflict",
        "unknown_runtime_residue",
    }
)

_INTERNAL_CODES = frozenset(
    {
        "invalid_operation_result",
        "operation_contract_error",
    }
)


def _exit_code(code: str, *, adapter: bool) -> int:
    if code in _INTERNAL_CODES:
        return EXIT_INTERNAL_ERROR
    if code in _RECONCILIATION_CODES or "reconciliation" in code or "uncertain" in code:
        return EXIT_RECONCILIATION_REQUIRED
    return EXIT_RUNTIME_FAILED if adapter else EXIT_REFUSED


class DeploymentError(RuntimeError):
    """A deployment operation was refused or failed at a known boundary."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        details: Mapping[str, Any] | None = None,
        exit_code: int | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.details = dict(details or {})
        self.exit_code = (
            _exit_code(code, adapter=isinstance(self, AdapterError))
            if exit_code is None
            else exit_code
        )


class DeploymentRefusal(DeploymentError):
    """A policy, identity, approval, or state boundary rejected an action."""


class AdapterError(DeploymentError):
    """The execution adapter could not prove a requested runtime outcome."""


__all__ = [
    "AdapterError",
    "DeploymentError",
    "DeploymentRefusal",
    "EXIT_INTERNAL_ERROR",
    "EXIT_RECONCILIATION_REQUIRED",
    "EXIT_REFUSED",
    "EXIT_RUNTIME_FAILED",
]
