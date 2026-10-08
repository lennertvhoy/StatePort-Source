# StatePort Admin CLI

> Local command-line interface for StatePort.

## Purpose

The admin CLI lets a developer or operator inspect and manage StatePort instances and templates locally.

## Commands

```bash
stateport validate-template templates/classdd
stateport validate-instance instances/demo-classdd
stateport inspect-overrides instances/demo-classdd templates/classdd
stateport plan-upgrade instances/demo-classdd templates/classdd
stateport context-build instances/demo-classdd --task "prepare next lesson" --model configured-model --budget 2000
stateport context-inspect pack.json
stateport context-compare eager.json compact.json
stateport instance recovery-status source-instance --json
stateport instance restore-plan source-instance --backup-receipt backup-RECEIPT --destination-instance-id source-instance-restored --json
stateport instance restore-approve source-instance --plan-digest sha256:PLAN --json
stateport instance restore-apply source-instance --plan-digest sha256:PLAN --approval-digest sha256:APPROVAL --json
```

Use `--json` for structured output:

```bash
stateport validate-template templates/classdd --json
stateport validate-instance instances/demo-classdd --json
stateport inspect-overrides instances/demo-classdd templates/classdd
stateport plan-upgrade instances/demo-classdd templates/classdd
```

## Running

From the repo root, use the `stateport` wrapper:

```bash
./stateport validate-template templates/classdd
```

The wrapper sets `PYTHONPATH` and delegates to `apps/admin-cli/src/admin_cli/main.py`.

## Configuration

Environment variables:

- `STATEPORT_TEMPLATES_DIR`
- `STATEPORT_INSTANCES_DIR`
- `STATEPORT_LOG_LEVEL` — strict API/worker operational log threshold:
  `debug`, `info`, `warning`, or `error` (default `info`). Invalid values fail
  service startup; the admin CLI itself does not reinterpret the value.

## Status

The lifecycle commands are read-only: `inspect-overrides` classifies local
changes against the immutable lock, while `plan-upgrade` compares an instance
with a candidate template and emits a versioned dry-run plan. Neither command
applies an upgrade or edits workflow files.

The context commands are also read-only. `context-build` emits a disposable
StatePack JSON document; `context-inspect` validates its manifest shape and
`context-compare` reports configuration differences. They never write canonical
instance state or treat a generated pack as a second source of truth.

Managed restore is a separate exact-plan transaction. It accepts only a
verified backup already indexed by StatePort, always restores to a new instance
identity, and requires a stored operator approval before apply. The lower-level
`backup restore` command permits dry-run inspection only; it cannot mutate an
instance or bypass the recovery receipts.
