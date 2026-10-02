"""Persistent, integrity-checked admission around the deterministic runner."""

from governed_runner.jobs import (
    CONTAINER_ECHO_COMMAND,
    CONTAINER_JOB_PAYLOAD_FORMAT,
    JOB_FORMAT,
    JOB_QUEUE_SCHEMA,
    JOB_STATES,
    TERMINAL_JOB_STATES,
    JobConflictError,
    JobLeaseError,
    JobQueue,
    JobQueueError,
    JobStateError,
)
from governed_runner.lease import (
    INSTANCE_LEASE_FORMAT,
    InstanceLease,
    InstanceLeaseBusy,
    InstanceLeaseError,
)
from governed_runner.ledger import RunLedger
from governed_runner.state import (
    StateSnapshot,
    diff_snapshots,
    digest_snapshot,
    restore_snapshot,
    snapshot_files,
)

__all__ = [
    "CONTAINER_ECHO_COMMAND",
    "CONTAINER_JOB_PAYLOAD_FORMAT",
    "ATTEMPT_CLASSIFICATIONS",
    "EVIDENCE_STORE_SCHEMA",
    "EvidenceConflictError",
    "EvidenceIntegrityError",
    "EvidenceStateError",
    "EvidenceStoreError",
    "INSTANCE_LEASE_FORMAT",
    "JOB_FORMAT",
    "JOB_QUEUE_SCHEMA",
    "JOB_STATES",
    "TERMINAL_JOB_STATES",
    "InstanceLease",
    "InstanceLeaseBusy",
    "InstanceLeaseError",
    "JobConflictError",
    "JobLeaseError",
    "JobQueue",
    "JobQueueError",
    "JobStateError",
    "OperationalEvidenceStore",
    "AgentNativeCockpit",
    "AssistedCockpit",
    "AssistedHandoff",
    "DeterministicFakeBackend",
    "FakeBackendScenario",
    "ManagedCockpit",
    "CockpitCoordinator",
    "CockpitError",
    "CockpitStateError",
    "GateReport",
    "PendingProposalReference",
    "PreparedCockpitJob",
    "RunLedger",
    "StateSnapshot",
    "digest_snapshot",
    "diff_snapshots",
    "restore_snapshot",
    "snapshot_files",
    "WorkspaceBudget",
    "WorkspaceLifecycleError",
    "WorkspaceLifecycleManager",
    "WorkspaceLifecycleRefusal",
    "AUTHORITY_ACTION_RECEIPT_SCHEMA",
    "AUTHORITY_ACTION_RESERVATION_SCHEMA",
    "AUTHORITY_ACTION_CLAIM_SCHEMA",
    "AUTHORITY_DECISION_SCHEMA",
    "AUTHORITY_GRANT_SCHEMA",
    "AUTHORITY_MODES",
    "AUTHORITY_POLICY_SCHEMA",
    "AUTHORITY_PROFILES",
    "AuthorityError",
    "AuthorityManager",
    "AuthorityPolicy",
    "AuthorityRefusal",
    "grant_template",
]


_EVIDENCE_EXPORTS = frozenset({
    "ATTEMPT_CLASSIFICATIONS", "EVIDENCE_STORE_SCHEMA", "EvidenceConflictError",
    "EvidenceIntegrityError", "EvidenceStateError", "EvidenceStoreError",
    "OperationalEvidenceStore",
})

_COCKPIT_EXPORTS = frozenset({
    "AgentNativeCockpit", "AssistedCockpit", "AssistedHandoff", "CockpitCoordinator",
    "CockpitError", "CockpitStateError", "GateReport", "PendingProposalReference", "PreparedCockpitJob",
})

_MANAGED_EXPORTS = frozenset({
    "DeterministicFakeBackend", "FakeBackendScenario", "ManagedCockpit",
})

_WORKSPACE_EXPORTS = frozenset({
    "WorkspaceBudget", "WorkspaceLifecycleError", "WorkspaceLifecycleManager",
    "WorkspaceLifecycleRefusal",
})

_AUTHORITY_EXPORTS = frozenset({
    "AUTHORITY_ACTION_RECEIPT_SCHEMA", "AUTHORITY_ACTION_RESERVATION_SCHEMA", "AUTHORITY_ACTION_CLAIM_SCHEMA", "AUTHORITY_DECISION_SCHEMA", "AUTHORITY_GRANT_SCHEMA",
    "AUTHORITY_MODES", "AUTHORITY_POLICY_SCHEMA", "AUTHORITY_PROFILES", "AuthorityError",
    "AuthorityManager", "AuthorityPolicy", "AuthorityRefusal", "grant_template",
})


def __getattr__(name: str):
    """Load the optional runtime-contract-dependent evidence lane on demand."""
    if name in _EVIDENCE_EXPORTS:
        from governed_runner import evidence
        return getattr(evidence, name)
    if name in _COCKPIT_EXPORTS:
        from governed_runner import cockpit
        return getattr(cockpit, name)
    if name in _MANAGED_EXPORTS:
        from governed_runner import managed
        return getattr(managed, name)
    if name in _WORKSPACE_EXPORTS:
        from governed_runner import workspaces
        return getattr(workspaces, name)
    if name in _AUTHORITY_EXPORTS:
        from governed_runner import authority
        return getattr(authority, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
