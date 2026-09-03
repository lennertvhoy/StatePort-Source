# StatePort instance catalog

`instance_catalog` is a small, authoritative local index of StatePort
instances. It records only operator-facing metadata: a stable catalog ID,
display name, confined relative path, filesystem identity, adoption mode, and
timestamps. It never opens or parses files below an instance directory.

The catalog is persisted as versioned JSON and updated with an exclusive
sidecar lock, a temporary file, `fsync`, and `os.replace`. Every operation
that observes an instance path rejects symlinks, absolute paths, traversal,
and paths outside the configured instance root. `refresh()` detects missing,
stale, and moved directories by filesystem identity without following
symlinks.

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
