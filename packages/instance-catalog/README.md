# StatePort instance catalog

`instance_catalog` is a small, authoritative local index of StatePort
instances. It records only operator-facing metadata: a stable catalog ID,
display name, confined relative path, filesystem identity, adoption mode, and
timestamps. It never reads instance file contents.

The catalog is persisted as versioned JSON and updated with an exclusive
sidecar lock, a temporary file, `fsync`, and `os.replace`. Every operation
that observes an instance path rejects symlinks, absolute paths, traversal,
and paths outside the configured instance root. `refresh()` detects missing,
stale, and moved directories by filesystem identity without following
symlinks.

New records also retain the filesystem ID observed through an open directory
descriptor. Across sessions, that ID and the inode identify the directory even
if Linux assigns a different mount-local device number. Device and inode must
still agree during each descriptor observation. A different filesystem ID or
directory inode remains a refusal; this does not authorize adopting a replacement
filesystem or restoring a copied catalog onto another installation.

Legacy records acquire the filesystem ID only while their original device and
inode still match. An already-stale legacy record is not repaired by guessing.
The application separately validates managed marker content and inode, and
migrates marker metadata only with an unchanged catalog record. Workspace reviews
bind the new filesystem identity, so migration requires a new review before an
older workspace grant can be used again.

Example:

```python
from instance_catalog import InstanceCatalog

catalog = InstanceCatalog(".stateport/instances.json", "~/StatePort/instances")
record = catalog.import_instance("old-project", name="Old project")
catalog.archive(record.instance_id)
catalog.refresh()
```

`register()` and `import_instance()` are read-only adoption operations. They
do not create, alter, rename, or delete the adopted directory. `forget()`
removes only the catalog record; it never deletes the instance.
