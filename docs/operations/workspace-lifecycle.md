# Workspace lifecycle corrective design

Status: corrective lifecycle control implemented; standing-authority
integration implemented locally; repeated real-slice effectiveness evidence
and product acceptance remain separate.

## Existing surface

- `governed_runner.InstanceLease` is the canonical kernel-backed writer lock
  used by agent-native, assisted, and managed cockpit flows. It protects an
  instance while a process is alive, but it does not inventory Git worktrees,
  survive process exit as lifecycle state, apply a global budget, or retire a
  branch.
- The admin CLI is the shared agent-native entry point. `stateport workspace`
  is the only supported creation, evidence-export, retirement, and
  slice-closure path for StatePort-managed worktrees.
- Goal execution creates disposable full clones for managed staging and
  read-only review, and removes them in `finally` blocks. StateBench and local
  demos likewise use bounded temporary fixture repositories. These are not
  registered worktrees in a developer repository and remain fixture/source
  lifecycle paths, not a second managed-workspace authority.
- `scripts/local_closure_gate.py` is the repository-level closure entry point
  and now consumes the repository-wide workspace audit before running its
  normal validation plan.
- StateBench DevLoop consumes the fixed workspace-lifecycle observation vector
  and retains the escaped-process incident as a permanent regression fixture.

## Canonical integration

`packages/governed-runner` provides one `WorkspaceLifecycleManager`, exposed
through `stateport workspace ...`. This keeps writer admission,
operational evidence, and lifecycle closure in the existing governed-runner
boundary while keeping the process-local `InstanceLease` contract intact.
StatePort-managed agent worktrees must use this manager; there is no fallback
to direct `git worktree add`.

The CLI mutation boundary additionally evaluates a typed grant through the
standing-authority manager described in [`authority.md`](authority.md). The
workspace manager remains the lifecycle authority; the authority manager says
whether this actor may invoke that operation at this repository, branch, and
slice scope. Both lifecycle and authorization receipts survive worktree
retirement.

The manager owns:

1. exact repository and inventory observation;
2. a non-blocking repository lifecycle lock;
3. strict persisted workspace leases and external-workspace classifications;
4. the global budget decision;
5. create, evidence export, residue classification, retirement, and receipts;
6. immutable workspace metric observations.

The Local Closure Gate consumes the manager's read-only audit and fails when
the inventory is unknown, a managed lease remains active or expired, a branch
is unresolved, or a prior slice has incomplete cleanup.

## Durable store and budget

Mutable authority lives outside Git at
`$XDG_STATE_HOME/stateport/operations/workspaces/repositories/<repository-key>`.
It contains create-only transaction/failure receipts, versioned lease records,
explicit external-workspace classifications, checkout-independent evidence,
cleanup receipts, and append-only observations. The repository key binds the
resolved common Git directory, repository root, object format, and safe origin
identity. Every write is lock-protected, atomic, file-and-directory synced,
and symlink confined; malformed or stale state fails closed.

The tracked `config/workspace-lifecycle.v1.yaml` is the one budget authority.
It limits registered and active writable worktrees, unknown worktrees,
unreconciled managed branches, and expired leases, and blocks creation when a
prior slice has incomplete cleanup. The primary checkout is implicit only when
clean. Existing non-managed worktrees require an exact explicit classification;
a primary checkout with protected pre-existing residue additionally requires a
status-digest-bound creation-base classification.

## Closure and rollback

Evidence export records the exact repository, branch, head, tree, base-to-head
patch, supplied test/browser/artifact/StateBench/subagent bindings, and their
digests in the external store before retirement. Rejected or archived unique
heads receive a verified Git bundle before their temporary branch is removed.

Normal closure removes only the exact clean worktree and branch proven to
belong to the lease, then makes the lease terminal and writes a durable cleanup
receipt. Dirty tracked files, untracked or ignored content, active processes,
identity disagreement, or uncertain ownership are never force-removed; they
require a reasoned, expiring `retained_exception` and block clean slice closure.
For the final workspace in a slice, `stateport workspace close --close-slice`
also proves there is no remaining slice residue and then expires the slice's
standing authority. A failed residue proof leaves the grant unexpired.

Slice identifiers are single-use. Once an immutable slice-closure receipt
exists, managed creation refuses that identifier. Historical operational state
containing a later lease under a closed identifier is reported as
`slice_identifier_reused`; the older receipt is never returned as current
closure proof.

If creation fails after Git mutation, rollback is limited to the transaction's
exact path and newly created branch after identity and cleanliness checks. Any
uncertainty is preserved and emitted as typed failure residue. A later audit
therefore sees either a valid lease, a classified external workspace, or an
explicit unknown that blocks further creation.
