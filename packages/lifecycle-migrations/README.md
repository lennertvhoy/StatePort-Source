# StatePort lifecycle migrations

`lifecycle_migrations` contains the StatePort-owned migration boundary for
instance data. Migrations are typed data contracts with a closed operation set
(`copy`, `move`, `delete`, `write_text`, and exact-once `replace_text`).

Registry entries must be StatePort-owned, declare exact instance-owned read and
write paths, and carry a deterministic contract digest. The executor confines
every path beneath the instance root, rejects symlinks and reserved control
paths, writes a receipt last, returns an idempotent result for a matching
receipt, and restores the pre-migration files if an operation or receipt write
fails.

There is intentionally no callback, command, import path, expression, or
template-provided code execution surface.
