# StateBench v0

Stdlib-only configuration and result primitives for controlled StatePort
comparisons. It captures complete configurations, repeated runs, separate
scorecards, and explicit self-reported/verified/official tiers without
declaring a universal winner or storing private holdouts.

StateBench also resolves pre-existing local Git checkouts into strict immutable
snapshot configurations. Requested branches or tags are resolution-time inputs
only; the resulting identity records a public HTTPS repository, exact commit
and tree, deterministic tracked-content digest, compatibility mode/wrapper,
and local-read-only provenance. It never fetches or serializes a checkout path.

For public-safe benchmark setup, StateBench can materialize a supplied Git
bundle into a clean isolated worktree and operate a temporary local bare remote
with normal fast-forward-only pushes. These helpers are fixture infrastructure,
not canonical-source adoption, RunBundle ingestion, or a benchmark claim.

The interruption harness builds on those local-only helpers. It accepts
externally supplied Stage-A and Stage-B launcher protocol objects, forces a
versioned bounded event-count or explicit-checkpoint interruption, releases
Stage A, and gives Stage B only the same task/policy plus repository and
declared durable StateSpec files. Its evidence is structural Git/trigger facts;
it never stores or forwards chat, transcripts, prompt caches, provider
sessions, evaluator paths, or a model loop.

## StateBench calibration evaluator

`statebench.evaluator` adds strict v1 contracts for `BenchmarkSuite`,
`BenchmarkCase`, `BenchmarkRunSpec`, `EvaluatorResult`, named
`MetricObservation`s, `CriticalViolation`s, pairings, and reports. It reuses
snapshot and continuation identities; it does not add a result tier or a
universal score. Critical violations dominate functional success, and
producer-authored RunBundle scores remain untrusted references.

Run `python3 scripts/statebench_alpha_calibration.py --output /tmp/statebench-alpha`
to generate `calibration.json` and `calibration.md`. The deterministic,
public-safe calibration always carries `HARNESS CALIBRATION ONLY` and `NO MODEL
OR SNAPSHOT SUPERIORITY CLAIM`. Hidden evaluator assets are outside the
generated candidate worktree; this is structural in-process separation, not
an OS or container-isolation claim.

## Real-project calibration

`statebench.real-project/v1` is a separate calibration family for multi-stage
development workflows. Its public-safe reference project spans a typed API,
persistence, service, CLI and web presentation; it also exercises a misleading
visible test, preserved unrelated dirty work, forced interruption,
repository-only continuation, exact independent review, Git closure and a
typed handoff. Single-agent and CTO-orchestrated synthetic runs use an
identical scenario, runtime, profiles, tools, budgets and evaluator. Their
report contains raw hard outcomes and diagnostics only—no universal score or
workflow-superiority claim.

## DevLoop structural profile

`statebench.devloop` adds the first bounded implementation slice from ADR-0005.
`DevLoopCollector` takes explicit base/current behavioural and state commit
identities, proves their required ancestry, verifies that state heads are
state-only descendants, and emits `statebench.devloop-structural-trace/v1`.
The trace contains commit/tree/parent identities, commit timestamps, and typed
path-class counts only. It never emits repository locations, raw paths, diffs,
commit messages, authors, or conversations. Missing base history, divergence,
and a mistyped state descendant fail closed and require a full rescan.

`DevLoopEvaluator` emits a fixed `statebench.devloop-evaluation/v1` vector for
first-pass outcome, discovery stage, rework, scope growth, evidence/state lag,
divergence cost, steering/correction, false closure, retry/repair, observed
time/tokens/cost, accepted value per cost, escapes, preservation, and rollback.
Every value keeps its evidence quality and bounded evidence references. Missing
facts remain `unavailable`; they are never inferred from a clean final Git
history. The report has no aggregate developer score, performance claim,
automatic policy mutation, or promotion decision.

This slice does not add an operational trigger, model context, CTO proposal
generation, Sensitive Data Gateway integration, real-run corpus, private
holdouts, confidence intervals, human-judgment correlation, or a process
superiority claim.
