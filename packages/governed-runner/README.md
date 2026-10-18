# Governed runner boundary

This package provides the operational run-plan ledger and canonical instance
snapshot/diff helpers used by StatePort's governed API. It does not invoke a
model, start a container, enable network access, or grant workflow write
capabilities.

The first execution mode wraps the existing deterministic echo runner. A plan
records actor, instance/template paths, capability and quota decisions, and a
validated isolated execution-plan shape. Execution compares canonical file
hashes before and after the run and restores unexpected writes.

## Local job queue

`JobQueue(path, clock=...)` is a SQLite-backed operational queue. Payloads must
be JSON objects with an explicit `formatVersion`. `enqueue` binds an
idempotency key to an immutable canonical payload digest; retrying the same
key and payload returns the same record, while a different payload fails.

`claim(worker_id=..., lease_seconds=...)` atomically selects the oldest queued
or expired leased job, assigns a random lease token, and increments its attempt
count. `heartbeat`, `complete`, and `fail` require the matching unexpired token.
Succeeded, failed, and cancelled jobs are immutable. `get` and `list` expose
durable operational records; the injected UTC clock makes expiry behavior
deterministic in tests. This queue does not itself authenticate workers or
authorize execution.

## Operational event evidence and receipts

`OperationalEvidenceStore(path, max_events=..., max_journal_bytes=...)` adds
a separate SQLite evidence lane for semantic attempts. A semantic attempt has
its own `semanticAttemptNumber`; it is deliberately unrelated to, and never
renames or changes the meaning of, `JobQueue.attemptCount` lease claims.

Call `create_attempt(parent_job_id=..., attempt_id=..., run_id=...)`, then
append normalized `runtime_contracts.AgentEvent` values in contiguous sequence
order. The first event must be `run.started`. The sole terminal event must be
appended with its classification and exact `runtime_contracts.RunReceipt` in
the same transaction. Its journal count and deterministic digest must match
the receipt, after which the attempt, journal, and receipt are immutable.

The store recursively removes credential-like fields and redacts common
credential values before database persistence. Optional adapter metadata is
separately bounded and redacted; it is not part of the canonical AgentEvent
journal or StateSpec state. `parent_summary` retains the first attempt result
separately from the eventual result and leaves unavailable metrics unavailable.
This evidence lane does not execute a host, retry work, escalate models,
repair state, perform external side effects, or mutate canonical StateSpec data.

## Agent-native cockpit lifecycle

`AgentNativeCockpit` composes the existing contracts, evidence store, and
writer lease into `prepare`, `adopt`, `verify`, and `close`.  It accepts an
external agent only after the exact prepared `AgentRunSpec` is adopted; it
never starts a provider session or requires a provider SDK.  Both declared
argv gates use an explicit staging cwd, default-deny environment allowlist,
bounded output, timeout, and process-group reaping.  A staging diff is
captured, but this slice never copies it into a canonical instance: any dirty
or forbidden diff closes as a typed report-and-stop and must use the existing
approved portable proposal/apply boundary separately.

Preparation also requires caller-observed repository and instance identities,
a clean disjoint canonical/staging pair at the exact base SHA, and a
credential-free gate environment allowlist. Preflight mutation fails closed.
Closure rechecks canonical and post-verification workspace identity, validates
the reported runtime/tool identity, verifies the referenced RunBundle on disk,
then binds the terminal receipt to the bounded event journal. This coordination
layer does not itself prove network or container isolation.

## Assisted cockpit handoff

`AssistedCockpit` is a mode-specific entry point over that same coordinator;
it is not a second runner, evidence store, receipt format, or proposal/apply
path. After the same identity check, lease, clean-snapshot check, and passed
preflight, it creates an immutable `stateport.assisted-handoff/v1` record. The
handoff binds the exact workflow declaration, `TaskManifest`,
`ContextManifest`, `AgentProfile`, `AgentRunSpec`, and recommended
`RuntimeProfile`, and records only a bounded `human_controlled` external-agent identity. It has
no absolute workspace or credential locations, provider session IDs, chat
history, prompts, or authentication material.

The human-operated process remains outside StatePort ownership. Adoption must
present the original handoff digest, RunSpec, and external-agent identity; it
cannot be repeated or reordered. Verification, report-and-stop behavior,
RunBundle checks, terminal event, immutable receipt, and lease release are
the common lifecycle. Assisted receipts use mode `assisted`, mark the runtime
as recommended/human-controlled, and preserve declared authentication and
unavailable usage rather than claiming provider supervision or invented
telemetry. The mode never retries, repairs, escalates, calls a provider, or
copies a staging diff into canonical state.

## Managed deterministic fake backend

`ManagedCockpit` is the third entry point over the same coordinator. It accepts
only the production-ineligible `DeterministicFakeBackend`, negotiates the exact
existing `BackendCapabilities` and `AgentRunSpec`, and exposes explicit
`capabilities`, `start`, `resume`, `cancel`, and `health` operations. No model,
provider, credential, automatic retry, repair, escalation, or canonical apply
is reachable from this slice.

The subprocess receives the staging repository, a credential-free environment
allowlist, and an ephemeral `HOME` and `TMPDIR` inside that staging workspace.
It streams only normalized nonterminal `AgentEvent` vocabulary into the same
bounded/redacted operational journal. Completion then uses the common declared
verification, Git diff gate, report-and-stop behavior, `RunResult`, immutable
`RunBundle`, terminal event, `RunReceipt`, and lease release path.

This host-process path is recorded as `staging_copy_only`, with
`containerEnforced: false`, `networkIsolation: unproven`, and canonical-access
isolation unproven. A staging copy is not a container or network-isolation
proof. Explicit resume is available only after the deterministic interrupted
state; it is never an automatic retry.

## Instance writer lease

`InstanceLease(lease_directory, instance_path, owner=...)` derives a stable key
from the resolved instance path and acquires a non-blocking `fcntl.flock` in a
symlink-safe operational lease directory. Use it as a context manager around
the complete single-writer transaction. The JSON lock-file content is
diagnostic metadata only: it can be stale or modified and must never be treated
as lease authority. Only the kernel lock held by the open file description is
authoritative.

## Managed Git workspace lifecycle

`WorkspaceLifecycleManager` is the sole authority for StatePort-managed agent
worktrees. Its mutable records live outside Git under the StatePort operational
state root, bound to the exact repository identity. The tracked
`config/workspace-lifecycle.v1.yaml` supplies one strict global budget.

Creation acquires a repository-wide lock, inventories Git and every typed
lease, rejects unknown or expired residue, creates one branch/worktree, verifies
its exact identity, and persists a creation receipt and active lease. There is
no unmanaged fallback. Evidence export captures the branch, head, tree, patch,
and supplied artifacts outside the temporary checkout. Closure automatically
removes clean integrated, rejected, or durably archived workspaces and branches;
dirty, untracked, ignored, running, or uncertain residue requires an expiring
`retained_exception` and remains a closure blocker. The admin CLI exposes this
contract through `stateport workspace ...`, and the repository closure gate
rejects active, stale, leaked, or unclassified workspace state.

## Standing authority

`AuthorityManager` adds typed per-action profiles, scoped grants, narrower
subgrant validation, pause/revoke/scope expiry, budget checks, and immutable
action receipts in a separate operator-private state store. `balanced` is the
default profile: routine reversible local work is receipt-bearing, while
private transport needs a named grant scope and consequential actions escalate.

The admin CLI exposes inspection, grant activation, one-time overrides, pause,
resume, revoke, and receipt lookup through `stateport authority ...`.
`stateport workspace` evaluates and receipts creation, evidence export,
retirement, and closure through that authority boundary before calling the
lifecycle manager. The policy is declared authority; sandbox, egress, process,
and secret-broker controls remain separately required effective enforcement.
