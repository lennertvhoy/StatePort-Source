"""Governed container deployment contracts and adapters."""

from .contracts import (
    DEPLOYMENT_SCHEMA,
    INSPECTION_SCHEMA,
    LIFECYCLE_STATES,
    PLAN_SCHEMA,
    RECEIPT_SCHEMA,
    STATE_SCHEMA,
)
from .errors import AdapterError, DeploymentError, DeploymentRefusal
from .authority import validate_authority_decision, validate_authority_receipt


def __getattr__(name: str) -> object:
    # The execution-host image needs only the low-level deployment contracts
    # and Podman adapter. Keep the authority-backed service (and its governed
    # runner dependency) lazy so that host-side imports remain minimal.
    if name == "DeploymentService":
        from .service import DeploymentService

        return DeploymentService
    raise AttributeError(name)

__all__ = [
    "AdapterError",
    "DEPLOYMENT_SCHEMA",
    "DeploymentError",
    "DeploymentRefusal",
    "DeploymentService",
    "INSPECTION_SCHEMA",
    "LIFECYCLE_STATES",
    "PLAN_SCHEMA",
    "RECEIPT_SCHEMA",
    "STATE_SCHEMA",
    "validate_authority_decision",
    "validate_authority_receipt",
]
