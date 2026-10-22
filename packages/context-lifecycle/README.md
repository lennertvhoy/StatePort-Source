# StatePort context lifecycle

This package governs ephemeral conversation context without turning a provider
session, summary, or handoff into canonical application state.

`stateport.context-lifecycle/v1` defines bounded budgets, compression and
handoff thresholds, mandatory continuity categories, and conservative session
resume guards. Effective policy resolution takes the most restrictive
compatible value from the supplied template, instance, operator, user,
backend, and active-budget layers. Missing layers are reported rather than
invented.

The normal product preference is one of `Faster`, `Balanced`, or `Deeper`.
These modes map to typed candidate policies; they are not arbitrary prompt or
provider configuration fields. The committed Balanced values are product
candidates, not StateBench-backed performance claims.

Compression and handoff artifacts preserve the active task, requirements,
completed and pending work, decisions, approvals, unresolved risks, exact Git
and working-tree identities, acceptance criteria, validation state, relevant
state references, recent receipt digests, and the next action. Artifacts and
their transcript-free receipts are written under StatePort operational state,
never inside the application repository. They explicitly declare
`canonicalStateMutation: false` and `ephemeral_noncanonical` authority.

A handoff starts a fresh provider session while retaining the same logical
conversation. Resume fails closed unless the conversation, instance,
workstream, runtime profile, base/head/tree/working-tree identity, context
manifest provenance, and freshness guards still match. Runtime compatibility
is deliberately exact-digest in v1.

Provider token use is labelled `observed`, `estimated`, or `unavailable`.
StatePort never presents an estimate as provider-observed accounting. Raw
transcripts, prompts, terminal capture, credentials, and unselected private
data are excluded from the lifecycle contract.

The browser surface remains application-attached under Advanced controls. It
can save the bounded mode preference and request manual compact or handoff only
after the shared conversation contains a real user message. The server—not the
browser—compiles the typed continuity contract from that channel-neutral
conversation and exact Git identity. Browser mutations carry only the expected
instance, base SHA, policy digest, and continuity digest; stale or invented
bindings fail closed.
