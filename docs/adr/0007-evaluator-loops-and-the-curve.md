# ADR-0007: Applications declare an evaluator; improvement is a governed loop

**Status:** accepted by the coordinator-architect under the owner's 2026-10-21 delegation of scope; product acceptance stays the owner's
**Date:** 2026-10-21
**Supersedes in part:** ARCHITECTURE.md "no unattended autonomy", the "data, never plugins" rule for template actions, the Idealised refusal R2 as worded, and the treatment of Stateware v1.2 as the newest model

## Context

Stateware 1.1 puts an AI application's durable identity in its state and the rules for changing it. StatePort implements that
boundary carefully: exact sources, locked instances, capability intersection, digest-bound approvals, receipts. On the published
Alpha.24 bytes, though, a stranger gets very little the model promises:

- Imported ProjectState and StudyState instances expose one StatePort-owned `inspect` action that reads `STATE.yaml` and
  changes nothing. A template cannot declare an action. No independent third template exists.
- No AI path (chat, coding agent, provider) has ever been measured on published bytes. Agent output is never saved into
  application state. Installation can finish without any provider.
- The web UI has about 830 controls. Several throw `unavailable` in the client, and the mock adapter ships in the production bundle.
  Two deployed services (`stateport-api`, `stateport-worker`) have no caller.
- Runtime product code (about 203k lines) is outweighed by release, verification and evidence machinery (about 290k lines).

The theory has the same gap, one level up. It says how a change is *permitted* and *recorded*, but never what makes a change
*good*. Without that, autonomy can only be a permission question, and "keep up with the field autonomously" has nothing to
optimise against. ProjectState already answers the question for projects: a human-owned outcome, one primary journey, and a
deterministic gate (`projectstate_gate.py`) that a passing secondary check can never turn green. The answer generalises.

A 2026-10-21 probe showed that OpenCode's free models answer with no account and no key (`opencode run --standalone -m
opencode/deepseek-v4.1-flash-free`). A stranger can therefore get a real model path on a fresh machine. During a model's
free period, OpenCode Zen says the data it receives may be used to improve that model.

## Decision

### 1. An application is (state, outcome, evaluator, actions, grants)

Every Stateware application declares five things:

| Part | Owner | Meaning |
|---|---|---|
| State `S` | instance owner | the instance files (a Git repository); the conversation log and receipts are part of the same durable record and are backed up with it (target: stored inside the instance under `.stateport/`; today they live in StatePort's per-instance management directory) |
| Outcome `O` | instance owner | what the work is for (`PROJECT.md` in ProjectState; the study target in StudyState) |
| Evaluator `E` | template author | a deterministic check `E(S) -> verdict` (pass / not yet / invalid) with a reason; never a model's opinion |
| Actions `Π` | template author | named units of work: `check` (runs E or another read-only check) or `agent` (a model works on a copy of S and returns a change) |
| Grants `G` | instance owner | what may run, with which model, budget and expiry, and which changes may apply without asking |

A run of an `agent` action produces a **proposal**: the exact diff against a named base revision, plus `E` before and after.
Applying a proposal is a Git commit to the instance, bound to the proposal digest and its base. If the base has moved, the
proposal is void. The evaluator is re-run on the result, and the receipt records both verdicts.

ProjectState's `E` is its own gate. StudyState's `E` is its state-file checks. A third-party template declares `E` and its
actions in `template.yaml` (`spec.evaluator`, `spec.actions`), and the public template contract says so.

### 2. Template actions run template code only inside the sandbox

Changed from "data, never plugins". A template may now ship the code for its `check` actions, for example ProjectState's
vendored gate. That code runs only inside the sandbox: no network, read-only state copy, scrubbed environment, a time limit,
and its own process tree. It never runs in the control plane. Its file digest goes in the receipt. An `agent` action's
instructions are template text: they shape what the model is asked to do and never widen what it may do.

### 3. Improvement is the same loop at three levels ("chase the curve")

The instruments improve every week: models, harnesses, prompts, template releases. Because state is separate from the instruments,
an instrument can be swapped. Because the evaluator is declared, a swap can be judged. Because a swap is a receipted policy
change, it can be autonomous and reversible. The loop has five steps: observe, evaluate, propose, apply, record.

| Level | What changes | Evaluated by | Applies |
|---|---|---|---|
| L1 instruments | which model/route runs which action class | a frozen task suite per action class, graded by deterministic checks; a candidate must beat the incumbent | automatically under an owner grant ("keep up automatically"), reversible, else as a proposal |
| L2 application definition | template releases (e.g. ProjectState 6.x), action instructions | the template's evaluator on the instance, before and after | always a proposal |
| L3 platform | StatePort itself | the clean-machine primary journey | only as a signed additive successor, after the journey passes; owner acceptance last |

**The fixed-point law.** No loop may change its own evaluator, its holdout tasks, or its own authority. Each evaluator is owned one
level up: L1 suites by StatePort, L2 evaluators by the template author, L3's journey by the owner. Authority only narrows, and
deleting a policy file narrows to the safe default. A loop that misses its own measure over its declared window parks itself
with a receipt.

This rewords refusal R2: no agent modifies the *running* platform, its evaluator, its authority or its release path. Agents
may author *candidate successors* through the same signed additive path as humans. The A17 self-rebuild is then a candidate
artifact, not a self-modification.

**Predictive admission (the honest "world model").** The receipt journal is a dataset of (action, route, context, outcome,
cost). The first predictor is an empirical table: pass rate and cost per (action class, route), with sample counts. It is a
ranking hint and a pre-filter, pinned by digest and updated only by L1. A learned predictor (JEPA-style or otherwise) can
replace the table later under the same rule: it may rank, never widen.

### 4. Autonomy is a lease

Changed from "no unattended autonomy". Every degree of autonomy is one runtime with one mechanism: a **lease** with a holder,
scope (actions, instances), route, budget, expiry and auto-apply scope. A lease can be paused or revoked and stops at its budget
or expiry. Auto-apply covers only reversible instance-local changes that the evaluator does not judge worse. Anything external,
destructive or authority-changing asks every time. Work applied under a lease is *applied*, never *accepted*.

### 5. Product scope for the next successor

Scope decisions, each with its reason:

- **Add** a zero-account default model route (OpenCode free models). It is enabled only after an explicit consent that names
  what leaves the machine and quotes the free-period data-use terms. Reason: without it, no stranger has any AI path.
- **Add** real actions for ProjectState (`gate`, `next-action`), StudyState (`check`, `plan-next-session`) and a published
  independent third template. Reason: owner criterion 3, and the template model is the product.
- **Add** proposal review and apply (diff, evaluator before/after, approve/reject, Git commit, receipt). Reason: this is how
  agent work becomes durable state.
- **Add** the L1 loop as a visible page ("Models"): observed free models, the frozen suite, scores, the current route, and
  "keep up automatically". Reason: the owner's core idea, made measurable on the reference machine.
- **Remove from the UI** any control that cannot perform its effect on the installed product (Scenario Lab, mock data,
  Codex device sign-in, libvirt deployments, StateBench page, preview routes, development-candidate sources). If a removed
  operation is still reachable elsewhere, it says why it is unavailable. Reason: "controls tell the truth" (A15) and criterion 2.
- **Keep** the existing release machinery as is unless it blocks shipping a fix.

### 6. Vocabulary (one meaning per word)

- **Owner** is the person whose instance it is. **Operator** is the person who runs the StatePort host. On the reference
  machine they are the same person in two roles.
- **Effective authority** = template request ∩ instance grant ∩ operator policy ∩ host capability ∩ lease (when one is held).
- **ContextPack** is the disposable model context, formerly the context sense of "StatePack". **StatePack** now names only
  the distribution envelope (ADR-0006).
- **Run**: one execution of one action, from admission to receipt.

## Consequences

- The whitepaper gains a 2.0 candidate built on v1.1 (not v1.2), adding sections on the evaluator, the loops and leases.
  v1.1 stays the public edition until the owner accepts 2.0.
- `ARCHITECTURE.md` and `ARCHITECTURE_OVERVIEW.md` describe this model and the components that actually ship.
- The acceptance list gains **useful work**: on the clean machine, each of the three templates runs an agent action with
  a real model. The result becomes a proposal, is applied, and survives restart.
- Free-model data use is a disclosed consent, never a default. A user who declines still gets the full non-AI product, and
  can connect their own OpenCode account or API key instead.
- Isolation claims stay at their evidence level: the sandbox and container boundaries are stated as implemented, and as
  measured only where a journey measured them.
