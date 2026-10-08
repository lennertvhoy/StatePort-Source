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

### Explicit development-image source seed prerequisite

`parameters.sourceSeed.helperPolicy` may explicitly select
`stateport.development-python-seed/v1`. Absence retains the existing pinned
Python-image helper and unchanged source-review normalization. The new policy
accepts only the fixed development-image digest in the daemon contract. Its
policy identifier participates in the source review and normalized workload
specification, so an existing exact operator grant cannot acquire this behavior
without approving the changed specification. No arbitrary helper image,
interpreter, command, UID, or namespace is accepted.

The policy uses that same image's `/usr/bin/python3`, the fixed seed script,
and UID/GID `10001:10001`. Helper and eventual workspace explicitly share the
execution account's rootless Podman user namespace. Independently observed
rootless status and exact user/namespace inspection are required; rootful,
unavailable, or remapped observations refuse. Existing generic argv restrictions
remain in force outside this exact policy. The helper refuses a nonempty or
incorrectly owned target before copying. It does not chown or adopt existing
volumes. Partial seed effects remain retained, and restart adoption checks the
same identity contract.

Snapshot files retain verified regular-file modes; its manifest is explicitly
readable inside the read-only helper mount even when the daemon uses umask077.
Only the snapshot subtree permits traversal; its daemon-private parent remains
private. Original application files are never chmodded by this step.

This is a source prerequisite, not activation of seeded operator issuance.
Actual pinned-image interpreter/user metadata, fresh-volume ownership,
provider-user writes, and installed restart remain subject to the real governed
runtime journey. The new policy must not be presented as qualified from the
existing Python-image fixture or source tests.

### Fresh signed development-image binding

New release topology explicitly selects `workspaceImageId: stateport-dev-workspace`.
The existing verified signed image set supplies its immutable reference after the
image build. Fresh provisioning derives the known `default-dev` template from
that reference, binds its complete normalized digest into the private
`control-plane-default` grant, and publishes the same image/spec pair to the web
and daemon units. It pulls and verifies this image in the execution account's
store through the existing image step. The image digest therefore does not need
to be written back into the source that produced the image.

The two installed configuration values are
`STATEPORT_EXECUTION_HOST_WORKSPACE_IMAGE_REFERENCE` and
`STATEPORT_EXECUTION_HOST_WORKSPACE_SPEC_DIGEST`. A partial, malformed, or
contradictory pair refuses. Both absent preserves the immutable legacy contract;
fresh provisioning refuses an existing different or legacy binding rather than
migrating its grant or unit. A dynamic fixed-default `listWorkloads` response
includes `workspaceProfile` with `imageReference` and `workloadSpecDigest` only
after checking the exact live private default grant. The web compares that pair
with its installed configuration before preparing a dynamic profile. This proves
image/spec binding and grant liveness; actual actions still require their normal
operation, budget, and workload authorization checks.

`stateport.signed-development-python-seed/v1` is a separate explicit helper
policy. Normalization binds the policy and pinned image into the source review
and workload digest, but normalization alone grants no authority. In addition
to the exact requesting grant, seed effects and recovery require the daemon's
installed image binding and live fixed private default grant. The existing
fixed Python and fixed development-image policies retain their behavior.
The helper command, UID, rootless namespace, snapshot readability, and
refusal-only target ownership checks remain unchanged. Seeded operator issuance
is not activated by this prerequisite.

Revoking the default grant does not transitively revoke independent existing
empty/terminal application grants on a running daemon. The new signed seed
policy deliberately depends on that base grant: a ledger containing such a
workspace refuses reconciliation when the base becomes unavailable or revoked.
The existing global fail-closed boot rule then prevents daemon startup, including
unrelated work on that restart. Effects are retained; no automatic adoption or
quarantine is introduced. This mixed-ledger restart limitation must be resolved
or explicitly qualified before activating signed seeded issuance. Source tests
and fake-engine transport tests do not establish installed image, volume,
provider execution, or restart qualification.
