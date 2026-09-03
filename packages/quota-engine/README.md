# quota-engine

> Tracks and enforces usage quotas for StatePort runners.

## Purpose

The quota engine evaluates whether a proposed run or tool call is within budget:

- Runs per day/month
- Messages per day/month
- Token estimates
- Tool calls
- Web searches
- Execution time
- Files touched
- Expensive-model use
- Monthly euro budget estimate

## Outcomes

- allow
- warn
- require approval
- block

## Status

Implemented as a deterministic admission check used by the governed API. It
also provides an independent stdlib-SQLite usage ledger for durable,
subject-scoped quota reservations. The ledger uses atomic reservations so
concurrent workers count active reservations before admitting more work,
persists terminal outcomes across restarts, and keeps its versioned database
as operational metadata rather than workflow state.

`UsageLedger.reserve()` binds a caller-supplied reservation id immutably to the
subject, operation, estimated cost, and quota policy. `commit()` replaces the
reserved estimate with one non-negative actual-cost observation; `release()`
frees only an active reservation. Repeating the same valid transition is
idempotent, while attempts to rebind an id or change a committed cost fail
closed.

This package does not grant identity or capabilities. Cost fields are admission
estimates and observations only: the ledger does not provide invoices,
currency conversion, provider reconciliation, or production billing accuracy.
