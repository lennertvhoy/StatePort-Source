# StatePort file-workspace broker

This package is the server-owned filesystem boundary for an optional
development Workbench. It is not a browser filesystem API and is never
available merely because an application package requests an editor.

`FileWorkspaceProfile` binds one authenticated actor set, development
application, instance, absolute project root, cataloged device/inode identity,
effective capabilities, explicit path classifications, and size limits.
StatePort constructs that profile after
intersecting application requests with instance grants and operator policy.
StudyState has no development Workbench capability and is rejected.

The v1 transport operations are:

- `listDirectory`
- `readFile`
- `readFileMetadata`
- `prepareWrite`
- `previewDiff`
- `commitWrite`
- `discardWrite`
- `renamePath`
- `createFile`
- `deletePath`

Paths are canonical repository-relative POSIX names. The broker holds an open
descriptor for the configured project root, re-opens the configured path with
descriptor-relative `O_NOFOLLOW` traversal, and compares the cataloged
device/inode before operations; the browser cannot submit or change the root.
Reserved runtime, Git, dependency, bounded credential-like, binary, oversized,
unknown, external, and symlinked paths fail closed. The local service declares
specific source/document subtrees and root files instead of assigning blanket
application ownership to every path.

Saving is staged. The broker acquires the existing kernel-backed StatePort
writer lease, verifies the exact Git base and original content hash, validates
the candidate, returns a bounded unified diff, and accepts only the exact diff
digest the operator reviewed. The mutation boundary prepares Git's own
`update-ref` transaction to verify and lock dereferenced `HEAD` against normal
Git writers. Every internal Git subprocess fixes `core.hooksPath=/dev/null` and
ignores user and system Git configuration, so a repository-controlled
`reference-transaction` hook cannot execute inside the privileged broker
transaction. Existing-file commits use Linux
`renameat2(RENAME_EXCHANGE)` while new files and regular-file renames use
`renameat2(RENAME_NOREPLACE)`. Deletes first move the target to a private
same-directory recovery name. The broker then rechecks the actual displaced
file, content hash, root and ancestor identities, and exact Git base after the
kernel mutation. A failed post-check rolls back only values whose exact inode
and bytes remain proved. A concurrent value is never unlinked or overwritten:
the broker retains byte-exact original and browser-candidate recovery evidence,
refuses the receipt, and quarantines further mutation. Irreversible backup
cleanup is followed by another check and byte-preserving restoration before a
receipt can be refused. Unsupported atomic primitives fail closed.

A normal stale operation retains the current value on disk and keeps the
candidate only in bounded ephemeral broker memory until it is discarded or
expires. An unresolved rollback or cleanup also writes an atomic, private
quarantine record under the StatePort lease/runtime directory, outside the
project root. The record is bound to the application, instance, and exact root
identity and survives broker restart. New brokers refuse every write while it
exists. Clearing requires an authenticated writer, the instance lease, the
exact quarantine-record digest, a verified recovery disposition, the same root
identity, and proof that no broker recovery artifact remains. Status and clear
receipts contain bounded identities, hashes, counts, and reason codes—never
project paths, file contents, recovery bytes, or credentials.
An autonomous race-safe reaper removes expired candidates and releases their
writer leases without waiting for another request to the broker.

Canonical StateSpec paths are read-only in file-workspace v1 because the
generic file broker is not the authoritative StatePort state-transaction
boundary. Generated paths are visibly classified and read-only; disposable
paths remain explicitly classified. V1 rename and delete operations cover
regular files only, require an exact base and hash, and never mutate canonical
files.

Known boundary: `O_NOFOLLOW` and descriptor-relative operations provide the
implemented Linux/POSIX proof. This is application policy and concurrency
governance, not a sandbox against another hostile process running as the same
OS user. Such processes must be isolated separately.
