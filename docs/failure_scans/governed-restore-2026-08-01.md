# Failure Scan — governed restore

## Failure boundary

The prior low-level restore command could mutate from an arbitrary archive
path without a persisted exact plan, approval digest, catalog transaction, or
durable status. Archive publication also had overwrite and staging-ownership
race hazards in the older audited state.

## Current response

- The low-level command is dry-run-only.
- The product resolves only an indexed, verified managed backup.
- Plans are path-free, self-digested, expiring, and bind source, destination,
  archive digests, absence preconditions, and explicit limitations.
- A platform operator approves the exact plan digest; approval cannot be
  replayed for a changed plan or after expiry.
- Apply rechecks source, backup, destination, catalog, and expiry state; it
  publishes no-replace, validates StateSpec, creates fresh Git identity, and
  registers only the exact new instance.
- Success and failure records survive restart. Ambiguous failure requires
  inspection and is never automatically retried.
- The source instance is unchanged and the receipt states that external side
  effects were not restored.
- Browser projections never expose an archive path.

## Regression cases

`scripts/test_governed_restore.py` covers the successful transaction,
idempotent receipt replay, destination and backup drift, exact approval,
direct-mutation refusal, same-identity refusal, path redaction, operator HTTP
execution, and normal-user denial. Archived no-replace and staging-ownership
tests are retained in `scripts/test_instance_backup.py`.
