# Troubleshooting

- Run `./stateport setup status` and `./stateport doctor --root .` first.
- A stopped or stale service is diagnosed with `./stateport service status`.
- Use an explicit local StudyState Git mirror with `--source-mirror` during
  offline alpha testing.
- A moved or symlinked instance must be revalidated or explicitly imported;
  catalog metadata is not canonical.
- Invalid roots report one primary diagnostic and mark dependent checks
  skipped rather than emitting misleading secondary errors.
- API and worker probe semantics, structured logs, and safe diagnostic fields
  are documented in [`operations/observability.md`](operations/observability.md).
