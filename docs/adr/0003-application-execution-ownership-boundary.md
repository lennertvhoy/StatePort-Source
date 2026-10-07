# ADR-0003: Application–Execution Ownership Boundary

**Status:** accepted (boundary decision; implementation scoped under BL-BOUNDARY-001)
**Date:** 2026-07-25
**Backlog:** BL-BOUNDARY-001

## Context

StatePort carries two valid product stories:

- **Application plane:** persistent applications, ongoing relationships,
  user-owned state, proactive work, adjustable oversight.
- **Execution plane:** coding-agent harnesses, controlled environments,
  provider integrations, permissions, evidence, and validation.

Earlier framing work oscillated between these stories: a harness-first
narrative (2026-07-23) was partially reverted by the app-platform positioning
correction (BL-POSITIONING-001), and the opinionated-execution-provider model
(BL-EXEC-PROVIDER-001) described the harness honestly without stating who owns
what across the seam. The missing piece is not another choice between the two
stories but the explicit contract between them:

> StatePort should own intent, authority, state, evidence, and acceptance. The
> harness may own execution behaviour, but it must never silently become the
> source of truth.

Without this boundary stated as an organising principle, execution can quietly
become identity, authority, truth, or acceptance — and StatePort's canonical
state stops being canonical.

## Decision

### StatePort is the composition of the two planes

Applications provide the purpose. Harnesses provide execution. StatePort owns
the boundary that prevents execution from becoming identity, authority, truth,
or acceptance. The harness story is not the wrong story; it is the execution
foundation beneath the application story.

### Ownership model

"Own" means **be the canonical system of record and control**, not originate
everything.

| Concern | Proper owner |
| --- | --- |
| User goal and declared constraints | User/application, represented canonically by StatePort |
| Domain interpretation and validation | Stateware application |
| Run lifecycle and activation | StatePort |
| Execution planning and tool-use strategy | Harness |
| Capability grants and limits | StatePort |
| Enforcement of hard boundaries | StatePort plus container/OS infrastructure |
| Scratch work and candidate output | Harness |
| Canonical state promotion | StatePort |
| Raw provider telemetry | Harness/provider |
| Evidence record and provenance | StatePort |
| Technical validation | Application validators coordinated by StatePort |
| Final acceptance | Human or application policy, recorded by StatePort |

The harness is permitted to decide **how to attempt the work**. It must not
silently decide:

- what the real objective has become;
- what it is authorized to do;
- which files or memories are canonical;
- whether its own claims count as evidence;
- whether the result is accepted;
- whether an unfinished run is complete.

### Execution modes

Coding agents normally edit files directly, which contradicts a naive
"agent proposes, system applies" model. Every governed run must therefore
declare one of three explicit execution modes:

- **Transactional:** the harness writes to a staging area or worktree;
  StatePort validates and promotes.
- **Supervised direct:** the harness may write directly, and the system
  clearly states that atomic governance is not guaranteed.
- **Read-only advisory:** the harness can inspect and propose but cannot
  mutate.

Calling direct writable execution "governed" merely because a receipt is
generated afterward is a prohibited over-claim.

### Declared, effective, and observed authority

A StatePort policy saying "workspace only" does not establish control when the
harness has ambient filesystem access, unrestricted shell, inherited
credentials, network access, access to other repositories, or the ability to
spawn unmanaged processes. StatePort must distinguish:

- **declared authority:** what policy permits;
- **effective authority:** what the environment technically allows;
- **observed behaviour:** what evidence shows actually happened.

Declared policy is never presented as an enforced guarantee unless the
environment supports it.

### Intent record

StatePort owns a canonical intent record per run: original request,
interpreted objective, constraints, success criteria, exclusions, delegated
sub-objectives, and revision history. A harness may produce a plan or propose
a revised interpretation; it may not silently rewrite the accepted intent.
This matters most for long-running human-on-the-loop applications, where
small interpretation drift compounds over weeks.

### Context ownership

StatePort owns the context manifest, source selection, provenance, sensitivity
filtering, required inclusions, and the version or hash of supplied context.
The harness may create ephemeral working summaries; those summaries must not
silently become canonical application knowledge. Where providers hide their
internal context processing, StatePort reports the limitation rather than
implying full reproducibility.

### Evidence separates observation from assertion

A harness saying "tests passed" is a claim. A captured test process with exit
code `0` is evidence. An independently rerun test is stronger evidence.
Receipts distinguish at least:

- harness-reported claims;
- StatePort-observed actions;
- filesystem or process evidence;
- independent validation;
- human acceptance.

### Completion and acceptance are different state machines

A harness may only report "execution finished and this is my candidate
result." StatePort retains explicit states:

```text
requested
→ authorized
→ executing
→ candidate_produced
→ validated
→ applied
→ human_accepted
→ shipped
```

Applications may skip stages by policy, but stages never collapse into an
ambiguous "done."

### Execution fingerprint

"Pi," "Codex," or "OpenCode" is not sufficient provenance. Every meaningful
run records an execution fingerprint: harness version, model version, system
instructions, adapter version, enabled tools, sandbox configuration,
environment image, context policy, and reasoning settings. Otherwise StatePort
preserves the result but cannot explain which runtime semantics produced it.

### Concurrency and canonical state

StatePort owning state implies owning revision identity, conflict detection,
write ordering, idempotency, and recovery from partial application. Without
leases, optimistic concurrency, or revision checks, two individually valid
runs can produce invalid combined state.

### External side effects

Files can be staged and rolled back; emails, deployments, purchases, messages,
and infrastructure changes may not be reversible. External actions require
preconditions, idempotency keys, dry-run or preview support, explicit
side-effect classification, post-action verification, compensation procedures
where possible, and honest recording when rollback is impossible. A receipt
does not make an irreversible action reversible.

### Refined portability claim

> State and application continuity are portable. Execution behaviour is
> provider-dependent, explicitly profiled, and never assumed equivalent.

A recurring cold-start conformance test operationalises this: destroy every
harness session and runtime process, start with only the declared StatePort
application state, and verify the application can continue correctly.

## Underweighted architectural risks

The following are architectural questions surfaced during this decision, not
confirmed implementation defects. Each is tracked under BL-BOUNDARY-001:

1. **Direct-write contradiction** — a writable mount containing canonical
   state means the harness already controls mutation; StatePort observes but
   did not mediate.
2. **Hidden state becomes the real application** — harness sessions,
   provider-side conversation state, internal summaries, cached plans,
   tool-specific databases, undocumented memory, or a surviving daemon can
   make canonical StatePort state insufficient to resume the application.
3. **Intent drift during planning** — harnesses reinterpret, expand, or
   "improve" requests while planning.
4. **Unenforceable authority** — declared policy outruns what the environment
   technically enforces.
5. **Context sits on the ownership boundary** — the harness determines
   behaviour from the context it actually receives and may summarize,
   truncate, reorder, or omit internally.
6. **Evidence collapsing into transcript** — without the claim/observation
   distinction, the evidence layer becomes a polished record of what the
   agent said.
7. **Completion/acceptance collapse** — harness "done" must never mark work
   validated, accepted, or shipped.
8. **Insufficient provider provenance** — behaviour changes with harness,
   model, adapter, tools, sandbox, image, context policy, and reasoning
   settings.
9. **Concurrent executors** — scheduled workers, interactive chats,
   background evaluators, and coding agents acting on one application without
   concurrency control.
10. **External side effects treated like file changes** — irreversible actions
    need a separate classification and compensation model.

## Required architecture tests

Before this boundary may be treated as implemented (as opposed to decided),
the following tests must exist and pass:

1. A harness cannot change canonical state without either mediated promotion
   or an explicit direct-write mode.
2. Destroying all harness sessions does not destroy application continuity
   (cold-start conformance).
3. A harness cannot silently modify accepted intent.
4. Effective permissions match declared permissions.
5. Receipts distinguish reported claims from independently observed evidence.
6. Harness completion cannot directly mark work accepted.
7. Every run records its execution fingerprint.
8. Concurrent runs cannot silently overwrite one another.
9. Cancellation terminates or clearly identifies unmanaged residual work.
10. External side effects are classified separately from reversible state
    mutations.

## Consequences

- `docs/POSITIONING.md` gains the ownership-boundary section as the framing
  source of record; `PROJECT_DNA.yaml` gains the `ownership_boundary_model`
  block.
- BL-BOUNDARY-001 scopes the engineering: execution modes, intent record,
  authority triad surfacing, evidence tiers, lifecycle state machine,
  execution fingerprint, concurrency control, side-effect classification, and
  the ten architecture tests. Each sub-item is its own reviewed slice, and
  most are gated behind the active P0 release freeze.
- This ADR is a boundary decision only. It claims no implementation,
  validation, release, or human acceptance. Existing AGENTS.md rules already
  encode several of these properties (leases and base-SHA binding, no
  unattended autonomy, host observations are noncanonical); the ADR organises
  them into one explicit contract rather than changing those rules.
