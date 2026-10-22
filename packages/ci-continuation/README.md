# Blocked-CI continuation contract

`ci_continuation` is a local, deterministic state machine for preserving the
exact repository/PR/head identity while a required CI result is unavailable or
failed. It is intentionally a test-only contract slice.

The only provider is `FakeCIProvider`, an in-memory scripted provider. There is
no GitHub client, network call, checkout, push, PR mutation, merge, or workflow
dispatch. A `WorkflowContinuation` rejects any provider that is not the fake
provider and binds every action and observation to the exact `owner/repository`,
positive PR number, and lowercase 40-character head SHA supplied at creation.

The normal path is:

```text
PR_READY -> CI_RUNNING -> CI_PASSED
                     \-> CI_FAILED -> AWAITING_HUMAN_DECISION
                     \-> CI_BLOCKED_EXTERNAL -> AWAITING_HUMAN_DECISION
```

From `AWAITING_HUMAN_DECISION`, an exact-current-revision authorization can:

- `retry`, which starts another fake run for the same exact head;
- `cancel`, which enters terminal `CANCELLED`; or
- `exact_head_override`, which enters terminal
  `EXACT_HEAD_OVERRIDE_APPROVED`.

The override is an explicit human decision and is never represented as
`CI_PASSED`. `remote_ci_passed` is always false because this module has no
remote provider. Authorizations include the exact binding and state revision;
reusing one, applying one after a state change, or presenting one for another
head is rejected as stale. State changes and provider observations are recorded
in a deterministic hash-chained audit tuple.

This module does not claim remote CI acceptance or closure-grade delivery.
