# StatePort Positioning

> Canonical framing source of record for how StatePort is positioned. This is a
> positioning and architecture-framing document, not a release, availability, or
> superiority claim. Current delivery state is bounded explicitly in §6.

## 1. Central positioning

StatePort is an application platform for durable, user-owned AI systems that
maintain state, pursue objectives, and operate across sessions. Applications
such as StudyState, StateSpec, ClassState, and LifeState are not limited to
responding to individual prompts. They can observe relevant changes, plan work,
perform permitted actions, evaluate outcomes, and adapt over time.

StatePort supports multiple models of human oversight, and **governance is the
mechanism that makes persistent and increasingly autonomous applications
trustworthy, controllable, portable, and appropriate for different users and
risk environments — not the purpose of the product by itself.**

### Framing correction

An earlier framing risked presenting StatePort as *"a governance system that
happens to run AI applications."* The stronger and intended vision is the
inverse:

> StatePort is a platform for durable, user-owned, stateful applications that
> can act over time. Governance determines how much freedom each application
> receives.

Governance is an **enabling control layer**, not the main product outcome. It
must appear in the argument *after* the reader understands what valuable thing
is being governed.

## 2. Argument hierarchy

1. **Problem:** AI interactions are temporary, stateless, reactive, and fragmented.
2. **Stateware:** durable, inspectable state becomes the foundation for persistent
   applications.
3. **StatePort:** a portable runtime and lifecycle platform for these stateful
   applications.
4. **App experience:** StudyState, StateSpec, ClassState, LifeState, and other
   domain-specific applications.
5. **Continuous operation:** applications can observe, plan, act, evaluate, and
   adapt over time — supervised, interruptible, and receipted (never "naked"
   autonomy).
6. **Oversight spectrum:** human-driven, human-in-the-loop, human-on-the-loop,
   and bounded autonomy.
7. **Governance and security:** authority, approvals, auditability, isolation,
   privacy, and evidence.
8. **Portability and evolution:** versioned applications, user ownership,
   migrations, rollback, and benchmarking.

Points 5 and 6 carry the novelty. They must rest on concrete mechanisms (§5),
not aspiration.

## 3. What makes StatePort distinctive: continuous, supervised operation

A Stateware application is not a single-turn responder. Over time it can:

- maintain durable awareness of goals and state;
- notice changes and opportunities;
- initiate useful work;
- continue multi-step processes;
- adapt plans based on evidence;
- surface exceptions, uncertainty, and important decisions;
- remain interruptible and understandable.

The user should not need to continuously prompt the system or approve routine,
reversible work. They should remain **in control without becoming the workflow
engine**. That requires first-class platform support for:

- visible current objectives and active work;
- pause, stop, redirect, undo, and rollback;
- configurable authority boundaries;
- action budgets and rate limits;
- confidence and uncertainty escalation;
- exception-based notifications;
- receipts and inspectable state changes;
- reversible low-risk actions;
- approval gates only where consequences justify them;
- escalation from autonomous execution to human review when conditions change.

This is broader and more useful than framing everything as approvals and
governance.

## 4. Oversight spectrum — a per-action policy, not a per-app label

StatePort supports an **oversight spectrum**, configurable per application,
capability, action, and risk level:

| Mode | Behaviour | Example |
| --- | --- | --- |
| Human-driven | AI assists only when requested | User asks StudyState to explain a topic |
| Human-in-the-loop | Execution stops at defined approval gates | Approve publishing, deployment, deletion, payment, external communication |
| Human-on-the-loop | The application operates continuously while the user supervises and can intervene | StudyState manages reviews, detects weak areas, adjusts the learning plan |
| Bounded autonomy | The application acts independently inside explicit permissions and budgets | StateSpec runs tests, repairs failures, prepares a reviewed pull request |

The key architectural point: **the oversight mode belongs to the action policy,
not permanently to the entire platform or even the entire app.** One application
may autonomously reorganize tomorrow's review queue, ask for confirmation before
changing a certification target, and prohibit sharing personal data without
explicit approval — three different oversight policies within one application.

### Default by application class

- **Human-on-the-loop is the normal experience for assistive domain apps**
  (StudyState, ClassState, LifeState). Requiring approval for every meaningful
  action would destroy their value.
- **Bounded autonomy is the normal target for engineering/automation apps**
  (StateSpec CI, test, repair, PR preparation), still inside explicit
  permissions, budgets, and escalation rules.

Same runtime, same contracts, different default policy. This reinforces the
per-action-policy principle rather than contradicting it.

## 5. The spectrum is configured policy over one runtime, not four products

Each oversight mode maps onto contracts StatePort already defines; no mode
requires a separate platform:

- **Human-driven / human-in-the-loop** — `RuntimeProfile` approval policy, the
  approval gate, and `deny_by_default_for` external/destructive actions.
- **Human-on-the-loop** — a leased write run bound to a base Git SHA, bounded
  budgets and rate limits, exception-based notifications, and the ability to
  pause, redirect, or reverse; every action produces a `RunReceipt` and
  inspectable state diff.
- **Bounded autonomy** — the same lease/receipt/transaction closure, plus
  reversible-only-by-default action scope, hard budget/rate caps, and
  confidence-based escalation that hands control back to a human when
  conditions change.

This generalizes the locked **three-level authorization** (free reads → bounded
pre-approved grants → ask-every-time), which is already an early instance of
oversight-as-per-action-policy. It also mirrors the failure-repair mode ladder
in `PROJECT_DNA.yaml` (`governed_improvement_contract.modes`:
off/observe/suggest/safe_auto_repair/managed_optimization), applied here to
normal application operation rather than to failure recovery.

## 6. Honesty boundary — delivered versus declared

This spectrum is the **architectural target space**, not a current capability
claim.

- **Delivered today:** the left and centre of the spectrum — human-driven,
  human-in-the-loop, and human-on-the-loop operation, with every action
  receipted.
- **Locked product vision (2026-07-19):** three-level authorization, every
  action receipted, and **no unattended autonomy**; agents never modify the
  platform.
- **Bounded autonomy** is a **declared future capability** that the spectrum
  makes architectural room for. It is distinct from "unattended autonomy":
  bounded autonomy always carries explicit permissions, budgets, escalation
  rules, and reversal. Like every platform feature, it requires its own
  authority, threat model, test suite, integration evidence, rollback, and
  product acceptance before it is delivered — it does not inherit release trust
  from this positioning document.

No claim here is a release, installation, remote-CI, human-acceptance, or
superiority claim. Comparative performance claims require a controlled,
reproducible benchmark that does not yet exist.

## 7. Relationship to governance

Governance remains substantial, but it appears after the reader understands what
valuable thing is being governed. Approvals, audit, isolation, privacy, and
evidence are the mechanisms that let autonomy increase safely; they are not the
product outcome. See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the trust
boundaries and [`SECURITY.md`](SECURITY.md) for the safety model.

## 8. Execution providers are opinionated, not interchangeable

A coding agent is not merely a model plus tools. It arrives inside a behavioural
harness — system prompt and defaults, planning and acting, tool set and
result presentation, filesystem and shell access, approval behaviour, context
selection/compression/memory, retry/timeout/recovery, subagent orchestration,
model selection and reasoning effort, edit-vs-patch-vs-commit semantics,
completion interpretation, and evidence recording. **The harness is part of the
agent's semantics, not an interchangeable transport layer.** The same model
behaves substantially differently across Pi, Codex, Claude Code, or OpenCode.

StatePort therefore treats external coding agents as **opinionated execution
providers**, not neutral interchangeable workers.

### Three explicit layers

1. **StatePort control plane** — owns canonical application state, objectives,
   identity and authorization, capability grants, budgets and deadlines,
   lifecycle state, approval gates, validation requirements, evidence
   retention, cancellation intent, and final acceptance.
2. **Harness adapter** — translates between the StatePort execution contract and
   a particular harness. It *declares what it can actually guarantee* rather
   than pretending every harness supports the same features, and records
   explicit degradation where a guarantee is partial or absent.
3. **External execution harness** — Pi, Codex, Claude Code, OpenCode, or another
   runtime performs work according to both the StatePort request and its own
   internal behaviour. StatePort observes and constrains it as far as
   technically possible, but does not claim to completely define it.

### What StatePort does and does not promise (portability levels)

| Level | Meaning | Promised? |
| --- | --- | --- |
| Package portability | A StateSpec package runs through any conforming adapter | Yes |
| Execution compatibility | An adapter can receive a task and return a result | Yes |
| Behavioural equivalence | Identical agent behaviour across harnesses | **No** |
| Security equivalence | Identical safety posture from the harness itself | **No** — enforced uniformly *outside* the host, not equivalent *from* the host |
| Evidence equivalence | Identical event/tool/usage shape | **No** — contracts are shared; per-surface shape degrades and is recorded |

### Claim boundaries

- **Defensible:** StatePort coordinates multiple agent harnesses through
  adapters while preserving canonical state, application lifecycle, policy, and
  externally validated outcomes.
- **Weak (needs heavy qualification):** "Agents are interchangeable because
  StatePort provides a common adapter interface."
- **Indefensible:** "An application behaves consistently and securely regardless
  of which underlying agent harness executes it." Adapters translate a common
  contract and declare guarantees; they cannot strip hidden system instructions,
  proprietary context management, host-side retry, internal safety policy,
  implicit model routing, or tool-call formatting.

### How safety is actually enforced

Prompt instructions are **not** a security boundary. Critical controls are
enforced beneath or around the agent: container/VM isolation, scoped filesystem
mounts, network denial or egress control, short-lived credentials, resource
limits, process-tree ownership and termination, repository worktrees, and
transactional staging. The harness is assumed capable of misunderstanding or
ignoring behavioural instructions; the operating environment still enforces the
important boundaries. Completion is never taken from the harness's "done"
statement — StatePort determines acceptance through its own tests, schemas,
diff gates, and human acceptance.

### Requirements versus preferences

The execution contract separates hard **requirements** (a provider must not
violate them — e.g. confirmed process-tree cancellation, denied network,
workspace-only filesystem, structured evidence) from substitutable
**preferences** (a provider may substitute — e.g. model, reasoning effort,
parallelism). A provider may substitute preferences; it must never silently
violate a requirement, and a run is refused when the selected provider cannot
meet a required guarantee rather than silently degrading.

### Pi as the reference provider

Pi is the **initial reference execution provider** because its interfaces allow
StatePort to exercise the required lifecycle and observability controls. Other
harnesses are supported through adapters and capability profiles, **not** by
assumed behavioural equivalence.

## 9. StatePort owns the application boundary

The application plane (§1–§6) and the execution plane (§8) are both valid
product stories; StatePort is their composition. The organising principle of
that composition is the ownership boundary:

> **StatePort owns intent, authority, state, evidence, and acceptance. The
> harness may own execution behaviour, but it must never silently become the
> source of truth.**

"Own" means *be the canonical system of record and control*, not originate
everything. The harness decides **how to attempt the work**; it must not
silently decide what the real objective has become, what it is authorized to
do, which files or memories are canonical, whether its own claims count as
evidence, whether the result is accepted, or whether an unfinished run is
complete. The full ownership table and the binding decision are
[ADR-0003](adr/0003-application-execution-ownership-boundary.md); the
machine-readable form is the `ownership_boundary_model` block in
`PROJECT_DNA.yaml`.

Four consequences shape every product and engineering claim:

- **Execution modes are explicit.** Governed runs are transactional (staging
  or worktree, StatePort promotes), supervised direct (direct writes with
  atomic governance explicitly *not* guaranteed), or read-only advisory. A
  receipt generated after a direct write does not make the write "governed."
- **Authority has three forms.** Declared authority (what policy permits),
  effective authority (what the environment technically allows), and observed
  behaviour (what evidence shows happened) are reported separately. Declared
  policy is never presented as an enforced guarantee the environment cannot
  back.
- **Completion and acceptance are different state machines.** A harness
  reports a candidate result; StatePort's own validation, application policy,
  and human acceptance move a run through `requested → authorized → executing
  → candidate_produced → validated → applied → human_accepted → shipped`.
- **Portability is restated.** State and application continuity are portable;
  execution behaviour is provider-dependent, explicitly profiled, and never
  assumed equivalent. The operational test is cold-start conformance: destroy
  every harness session and runtime process and verify the application
  continues from declared StatePort state alone.

The ten underweighted architectural risks (direct-write contradiction, hidden
state, intent drift, unenforceable authority, context on the boundary,
evidence-as-transcript, completion collapse, provenance gaps, concurrent
executors, external side effects) and the ten required architecture tests are
recorded in ADR-0003 and scoped as engineering under `BL-BOUNDARY-001`. They
are architectural questions, not confirmed implementation defects.

## 10. Propagation

This document is the framing source of record. It propagates to:

- `PROJECT_DNA.yaml` — `project` positioning fields, the
  `application_oversight_model` block, the `execution_provider_model` block,
  and the `ownership_boundary_model` block.
- `README.md` and `docs/ARCHITECTURE.md` — lead framing, three-layer model,
  ownership boundary, and core thesis.
- `docs/adr/0003-application-execution-ownership-boundary.md` — the binding
  ownership-boundary decision, risk register, and required architecture tests.
- `docs/NAMING.md` and `docs/DOCUMENTATION_MAP.md` — provider vocabulary and
  topic naming.
- The Stateware whitepaper and the public site (`StatePort-Site`) — derived from
  this canonical source in a separate, scoped slice.
- In-product copy — where framing appears in the application shell.

Status of propagation is tracked in `STATUS.md` and `NEXT_ACTIONS.md`.
