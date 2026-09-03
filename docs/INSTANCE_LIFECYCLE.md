# Persistent instance lifecycle

Creation resolves an immutable source, validates typed bootstrap input, builds
an exact plan, binds an operator approval to its digest, stages the instance,
validates it, atomically publishes it, then writes the lock, receipt, catalog
entry, and audit metadata. A failed transaction leaves no published instance.

`instance list`, `inspect`, `verify`, `import`, and `forget` operate on catalog
metadata while the instance repository remains authoritative. `forget` never
deletes the instance.
