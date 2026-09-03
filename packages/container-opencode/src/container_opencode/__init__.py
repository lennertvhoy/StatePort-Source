"""
QUARANTINED: container-opencode was audited and found to have critical bugs
in its standalone helper path. The enforcer and escape-test verifier are
retained for reference and local testing only. Do not use in production
without a full re-audit. See packages/opencode-adapter for the adapter
quarantine notice.
"""

from .enforcer import (
    ContainerOpenCodeEnforcer,
    EscapeTestResult,
    EnforcerConfig,
    OpenCodeExecutionMode,
    verify_container_enforcement,
)

__all__ = [
    "ContainerOpenCodeEnforcer",
    "EscapeTestResult",
    "EnforcerConfig",
    "OpenCodeExecutionMode",
    "verify_container_enforcement",
]
