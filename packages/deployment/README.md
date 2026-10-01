# StatePort deployment foundation

This package owns deployment intent and evidence. It is deliberately separate
from the Podman execution adapter: plans, approvals, accepted revisions,
observations, transitions, and receipts remain StatePort state even when the
runtime is absent.

Slice A supports local Linux AMD64 rootless Podman. A project is inspected
without mutation, an exact Git source inventory is bound into a versioned
`stateport.deployment/v1` plan, and the owner approves that plan by SHA-256.
The adapter then materialises tracked Git blobs into a private build context;
it never builds from an uncontrolled working tree. Every runtime resource has
deterministic names and StatePort ownership labels.

The alpha contract intentionally refuses root containers, privileged or host
namespaces, host bind mounts, symlinks, mutable image tags, missing health
checks, plaintext secret-like configuration, and non-loopback exposure.
Ordinary removal retains named volumes. Purge is a separate irreversible plan
and exact approval.

Durable records live below `$XDG_STATE_HOME/stateport/deployments` by default.
Plans and receipts are create-only; mutable state is atomically replaced and
integrity-bound. Receipt chains make interrupted operations observable rather
than silently replaying unknown effects.

## Slice A design

The package is split along the trust boundary:

- `inspection.py` reads the exact committed Git tree and produces one uniform,
  reviewable projection for StatePort descriptors, strict Compose files,
  Containerfile/Dockerfile projects, and deterministic Python, Node, or static
  assistance.
- `contracts.py` validates immutable specifications and plans. Approval binds
  the plan digest, source inventory, target identity, generated overlay, and
  expiry; changing any of them invalidates the approval.
- `store.py` owns desired, accepted, and observed state plus create-only plans,
  evidence, and hash-chained transition receipts. Its write-ahead transaction
  record makes publication and crash recovery deterministic.
- `authority.py` bridges deployment results to canonical standing-authority
  decisions. Every effect is reserved and claimed before execution; its rich
  outcome is committed atomically with deployment state before canonical
  finalization, so a lost response can reconcile without replay.
- `podman.py` is a replaceable execution adapter. It receives an exact plan and
  materialized context, performs bounded rootless Podman operations, and
  returns direct observations. Podman labels and objects are evidence, never
  canonical deployment truth.
- `service.py` is the only lifecycle coordinator used by the CLI. Invalid
  transitions, stale sources or targets, unbound secrets, drift, and uncertain
  partial effects fail closed with typed outcomes.

The implemented lifecycle is `discovered -> planned -> awaiting_approval ->
approved -> applying -> verifying -> healthy`, with explicit degraded, failed,
removed-runtime/data-retained, purged, and reconciliation-required outcomes.
Ordinary status observation may reconcile only a durably identified interrupted
transition. Unknown or non-idempotent external effects are never retried.

## Revision updates and rollback

A healthy or degraded deployment accepts an exact update plan. Update and
rollback plans carry `revisionId`, `supersedes`, and `rollbackOf` lineage:
`revisionId` is the plan digest itself, `supersedes` names the still-accepted
predecessor, and a rollback plan must restore the exact specification of the
revision it names. The update change set is the exact diff against the
superseded revision, verified by the store.

Updates apply as a stop-swap: container names and host ports are stable per
deployment, so a concurrent blue/green pair is impossible. New revision images
are built before any runtime change, the verified predecessor containers are
then stopped and replaced, and the new revision is health-gated with the same
bounded polling as a first apply. The mandatory `rollbackOnFailedHealth`
policy authorizes automatic rollback: any post-swap failure re-applies the
exact predecessor runtime before the failure is reported, and the deployment
returns to its still-accepted revision through `updating ->
rollback_required -> rolling_back -> healthy`. Shared networks and volumes
cannot be relabelled by Podman, so durable state records the exact
creating-revision identity of each shared resource; observations validate
their labels against that identity instead of the running revision. An update
may add networks or storage but may never remove or reshape them — removal
destroys data and stays behind the separately approved remove/purge flow.

Still excluded: remote SSH, image-registry distribution, and the deployment
UI. Those are subsequent slices; this package does not imply that they
already exist.
