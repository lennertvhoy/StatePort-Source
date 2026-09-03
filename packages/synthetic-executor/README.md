# Synthetic executor

`synthetic_executor` is a deterministic reference fixture for StatePort's
`AgentRunSpec` and `RunResult` contracts. It scripts success, approval,
rejection, cancellation, timeout, malformed-event, validation-failure, and
no-op outcomes.

It is permanently test-only: `productionEligible` is `false`, no provider or
network client is used, no arbitrary shell or validation command is started,
and no workspace file is read or written. Tool calls and changed files are
structured simulated requests and proposals. Event envelopes use a stable
sequence, logical timestamp, and hash chain so repeated runs have identical
event and result digests.

`SyntheticExecutor.run()` returns a `SyntheticExecution` trace wrapper.
`SyntheticExecutor.execute()` returns only the unchanged `RunResult v1`
payload, allowing existing contract validation to be used without adding
synthetic fields to `AgentRunSpec` or `RunResult`.
