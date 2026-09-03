# API-native adapter foundation

This package is a provider-neutral boundary for direct model/API adapters. It
does not contain a provider SDK, endpoint, credential, or live transport.
Callers inject an object implementing `stream(request, deadline,
cancel_event)`. The included `LocalDeterministicTransport` is a test fixture
only.

The boundary is intentionally strict:

- outbound and inbound events carry exact RunSpec, model, configuration, and
  idempotency identity;
- streams are contiguous and normalized before callers observe them;
- cancellation, deadlines, and retry classification fail closed;
- tool calls are schema- and capability-checked, then stopped at an explicit
  approval boundary; this package never executes a tool;
- network policy is declared in the RunSpec binding and the local fixture
  accepts only `disabled`;
- telemetry is labelled `exact`, `approximate`, or `unavailable`;
- diagnostics are recursively redacted and credential-shaped fields are
  rejected.

The package binds to the existing `AgentRunSpec` by attributes and digest. It
does not modify or replace the execution-host contract.
