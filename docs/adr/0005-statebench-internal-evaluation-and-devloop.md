# ADR-0005: StateBench internal evaluation and continual dev-loop boundary

**Status:** accepted; bounded collector and vector evaluator implemented, continual loop open
**Date:** 2026-07-28
**Backlog:** STATEBENCH-PROTOCOL-ARCH-001, STATEBENCH-DEVLOOP-EVAL-001, BL-DEVLOOP-OBSERVATORY-001

## Context

StatePort already contains a provider-neutral evaluator contract, versioned
suites and cases, evidence-quality observations, critical-violation handling,
hidden evaluator assets, deterministic calibration generation, interruption
and continuation modelling, a medium synthetic development project, Git
closure checks, and paired synthetic single-agent/CTO workflows. Those
foundations prove evaluator and harness behaviour only. They do not establish
a continual evaluation loop over real StatePort development or any superiority
claim.

Git history is the immutable identity and chronology backbone, but it does not
contain discarded attempts, repeated failures before commit, browser defects,
human redirection, abandoned branches, agent overclaims, or cost observations.
A trustworthy development-loop account therefore needs bounded evidence from
Git, tests, agent runs, browser journeys, reviews, corrections, incidents, and
acceptance decisions.

## Decision

StateBench remains a trusted subsystem inside StatePort. It is not a separate
repository, a separate product, or a default normal-user surface. Inspection
belongs under optional developer details, advanced evaluation, internal
release gates, and permission-gated platform operations.

StateBench evaluates three explicit families without collapsing them into one
universal score:

1. product journeys, including durable transition, approval, continuity, and
   exact Undo semantics;
2. development-loop quality, including convergence, evidence timing, rework,
   steering, cost, and honest closure; and
3. portability conformance across native, imported, agent-package, and
   standalone deployment profiles using semantic rather than pixel or provider
   equivalence.

### Read-only DevLoop Observatory

`BL-DEVLOOP-OBSERVATORY-001` will incrementally collect a deterministic,
read-only trace from the last evaluated behavioural and state heads. It records
commit identity and ancestry, typed path classifications, reverts and
supersession, branch divergence, test/run/browser outcomes, review and
acceptance status, and explicitly linked owner corrections. Missing history,
rewritten ancestry, or divergence invalidates incremental evaluation and
requires an explicit rescan.

Collection does not require a model. Raw `git log -p`, conversations, and
unbounded traces are not normal CTO input. The collector first derives
structured metrics; selected excerpts cross the Sensitive Data Gateway before
model context. Raw conversations, credentials, personal data, private source
content, and free-form paths are neither fleet telemetry nor default evaluator
input.

### StateBench DevLoop profile

`STATEBENCH-DEVLOOP-EVAL-001` reports a result vector including first-pass
slice success, failure-discovery stage, rework and scope growth, evidence and
state lag, branch-divergence cost, human steering and repeated correction,
false closure, retry/repair, accepted value relative to observed cost, test
escape, unrelated-work preservation, and rollback success. Metrics retain
their evidence quality, uncertainty, and applicable configuration identity.

Repeated real-project runs, representative repositories and languages, sealed
private holdouts, confidence intervals, variance, real token/cost accounting,
rotating tasks, and correlation with human product judgments remain the
separate `STATEBENCH-REAL-PROJECT-CORPUS-001` programme.

### CTO, evaluator, and promotion authority

The CTO is an untrusted optimizer. It may receive the compact trace and create
a few bounded, reversible hypotheses with expected effect, cost, affected
policy, and rollback. It may not change its operating policy, evaluator rules,
thresholds, private holdouts, permissions, history, or failing checks and then
declare improvement.

StateBench is the trusted evaluator. It compares the current loop with a
challenger on a controlled task family, preserving the complete execution
configuration and separate first-attempt and recovered outcomes. The product
owner remains the promotion authority. A successful slice is not a universal
conclusion, and usage-driven improvement is not controlled comparative
evidence.

## Sequencing

The bounded implementation now provides the read-only explicit-head collector,
path-free structural trace, strict trace loader, and fixed evidence-quality
ResultVector. It does not provide an operational after-slice trigger, complete
run/browser/review ingestion, Sensitive Data Gateway handoff to a model, CTO
proposal generation, challenger execution, private corpus, real-project
statistics, feedback loop, or policy promotion.

## Consequences

- StateBench has one clear home and three bounded evaluation families.
- Git remains authoritative for identity and chronology, not a complete trace.
- The CTO may propose; StateBench evaluates; the owner promotes or rejects.
- Product, development-loop, and portability evidence share hard safety and
  state-integrity gates while retaining separate result vectors.
- Official scores and private holdouts remain StatePort-owned and absent from
  public template repositories.
