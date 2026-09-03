# Runtime contracts

`runtime_contracts` is the machine-readable contract boundary for a governed
workflow. `stateport.workflow/v1` expresses template lifecycle semantics and
may reference profiles, but does not select runtime or context objects.
Task, runtime, context, and agent declarations bind a specific attempted run;
normalized events are bounded and redaction-aware; a receipt references
`RunResult` and `RunBundle` rather than reimplementing either.

It describes work and evidence; it does not execute a host, persist events,
select permissions, or own canonical StateSpec state. `AgentRunSpec`, `RunResult`,
and `RunBundle` remain external execution-host artifacts referenced only by
identifier and digest.

Every contract is immutable, rejects unknown and credential-like fields, uses
repository-relative paths only, and has a deterministic `sha256:` digest.
