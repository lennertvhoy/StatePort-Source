# Backup And Restore Durability

StatePort local instance backups contain a digest-bound manifest and a
machine-readable `inventory` with `included` and `excluded` durable-state
entries. Host Git metadata is excluded. Portable exports also reject transient
engine/runtime state rather than silently making it canonical.

Restores materialize into a confined staging directory, fsync every restored
regular file and directory recursively, then publish with Linux
`RENAME_NOREPLACE` and fsync the target parent after publication. Existing
paths, symlinked ancestors, archive links, and archive traversal are refused.

Managed restore is always a new reidentified instance. The exact plan binds the
source instance, backup receipt and archive digests, managed target identity,
catalog identity including the restored directory device/inode, and final
restore receipt. An exact already-receipted retry revalidates that effect and
directory identity before returning; an unrelated existing or replacement
target is never overwritten or removed. Portable import replay binds the exact
plan, approval digest, receipt, and materialized target device/inode, then
applies the same catalog-inode and complete-tree verification before returning.

Each managed restore has a durable per-plan effect journal. Restart or
`recovery-status` reconciliation can complete an applied filesystem/catalog
effect when the receipt was not yet published, but it does not guess when the
target or catalog identity cannot be verified. Crash tests can inject failures
at archive/restore writes and publication, effect-journal writes/renames,
catalog registration, receipt boundaries, and post-materialization cleanup.
Source backup verification opens the managed archive through a no-follow
descriptor anchor, and rollback deletes only the materialized inode it owns.
Archive, receipt, and source-file reads are descriptor-anchored and verify
inode, size, timestamps, and pathname identity after reading; concurrent
replacement fails closed. Mode changes are followed by file fsync before
publication, and newly created artifact, receipt, index, and journal
directories are fsynced at their durable commit boundaries.
Export copies use the same descriptor-bound source bytes and digest checks.
Rollback first quarantines the exact expected directory inode, then removes it
through descriptor-relative traversal; a replaced or foreign target is retained
for inspection. If publication parent fsync is uncertain, a durable recovery
marker is written instead of claiming a clean success or deleting the target.

Portable export accepts an explicit archive destination outside the source
instance and publishes it without overwrite. The result reports whether the
observed archive device differs from the source device; source-volume deletion
survival is only true when the operator chose a separate device. Secret-looking
filenames, sensitive keys/values in metadata, configuration, and source,
manifest-classified `secret` files, and secret-classified template/source
metadata are rejected rather than archived. Reidentification rewrites only
identity fields bound to the archived old instance identity. This feature
restores declared file modes and does not provide scheduling, encryption, retention, or full-host
disaster recovery. Interrupted canonical applies are recovered from the
durable transaction marker when the post-commit digest and receipt agree;
otherwise the run remains explicitly operator-inspection-required.
