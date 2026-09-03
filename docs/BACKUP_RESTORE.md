# Backup and restore

Backups use the deterministic `stateport.instance-backup/v1` archive contract.
The private backup index binds the managed archive to its payload digest, file
digest, source/lock identity, and `stateport.backup-receipt/v1` receipt.
Archives are published with mode `0600` through the qualified Linux
descriptor-anchored, atomic no-replace path. Git metadata and secret-looking
files are excluded or refused.

## Governed restore

The supported product restore is deliberately narrower than the archive
library. It always creates a different instance identity inside StatePort's
managed instance root; it never overwrites the source or an existing path.

1. `restore-plan` resolves only an indexed managed backup, revalidates its
   archive bytes, performs a dry run, proves the destination is absent, and
   persists a path-free `stateport.restore-plan/v1` contract.
2. `restore-approve` binds a platform or local operator to the exact plan
   digest and a bounded expiry in `stateport.restore-approval/v1`.
3. `restore-apply` reloads the persisted plan and approval, rechecks backup,
   source, destination, and expiry drift, atomically restores with the
   `reidentify` policy, runs StateSpec validation, creates a fresh Git base,
   registers the new instance, and records `stateport.restore-receipt/v1`.
   When the source has receipt-bound source access, the plan explicitly names
   the exact source receipt and access class; apply rechecks it and the terminal
   receipt names the new destination receipt. Missing or changed access is not
   inherited silently.
4. Exact retries after a committed receipt return that receipt rather than
   repeating the filesystem mutation. An interrupted or unvalidated result is
   retained for operator inspection; it is not silently deleted or retried.

Example:

```bash
./stateport instance recovery-status source-instance --json
./stateport instance restore-plan source-instance \
  --backup-receipt backup-0123456789abcdef01234567 \
  --destination-instance-id source-instance-restored --json > restore-plan.json
./stateport instance restore-approve source-instance \
  --plan-digest sha256:PLAN_DIGEST --json > restore-approval.json
./stateport instance restore-apply source-instance \
  --plan-digest sha256:PLAN_DIGEST \
  --approval-digest sha256:APPROVAL_DIGEST --json
```

The plan and approval values passed to the later commands are the exact values
printed by the prior command. The Settings → Backup & recovery surface exposes
the same contract for an authenticated platform-operator session. The browser
never supplies an archive path.

The low-level `stateport backup restore` command is dry-run only. Direct
mutation through that command is refused so it cannot bypass plan, approval,
catalog registration, validation, or receipts.

## Boundaries

- Restore covers verified filesystem state only. It cannot undo or replay
  network, financial, messaging, provider, or other external side effects.
- No automatic retry is permitted for unknown or non-idempotent external work.
- The source instance remains unchanged. Removal of the newly restored
  instance is a separate governed lifecycle operation.
- Backup encryption, automatic scheduling, and retention enforcement remain
  deferred and must not be inferred from archive verification.
