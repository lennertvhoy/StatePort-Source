# Keep-up loop, level 1: model routes (design spec)

Implements ADR-0007 §3 at the instrument level for the Alpha.26 successor. Scope: one local owner, OpenCode as the agent
harness, the `opencode/*` free models first; own accounts and API keys use the same route mechanism.

## Why it must exist

OpenCode's free catalogue is fetched live and changes from call to call (2026-10-21 probes: `opencode models` listed
`deepseek-v4.1-flash-free` and `beam-free` on one call, other names on the next). A hard-coded model name breaks within
weeks. A free model's terms also change when its free period ends. The route has to be observed, measured and replaced
continuously, and that is the owner's core idea: chase the curve autonomously, inside limits.

## State (operator-level, under the web service state directory)

| File | Content |
|---|---|
| `model-routes/consent.json` | per destination (`opencode-free`): granted at, the exact terms text shown, its sha256, granted by |
| `model-routes/catalogue.json` | last observation: time, harness version, every listed model id, `free` flag (id ends in `-free`) |
| `model-routes/policy.json` | `routes`: action class -> model id (`agent.edit-state` is the only class in Alpha.26); `pinned` flags; `lease` for automatic updates `{enabled, grantedAt, expiresAt, maxSuiteRunsPerDay}` |
| `model-routes/results/<runId>.json` | one suite run: suite id + digest, model, per task pass/fail + seconds + reason, totals |
| `model-routes/receipts.jsonl` | append-only: consent, observation deltas, suite runs, route changes (from, to, why, by: owner or lease) |

Deleting `policy.json` restores the safe default: no route until the owner chooses or consents (it never widens).

## Observe

`opencode models` runs with the bundled binary, an isolated HOME and no credentials, with a 60-second timeout. The result is
diffed against `catalogue.json`. A model disappearing from the catalogue, or a new free model appearing, is an observation
delta and is receipted.

## Evaluate: the frozen suite

`fixtures/model-suite/v1/` is shipped with StatePort, and its digest is recorded in every result. Each task has:

- a tiny fixture repository (ProjectState-shaped, StudyState-shaped, plain files);
- an instruction in the same form as a real agent action;
- a deterministic checker: Python, no model, that reads the resulting files and returns pass/fail with a reason.

The tasks run through **the same agent runner as instance actions**, on a temporary copy, with the same sandbox and the same
egress rule. That way the suite measures the real path. Tasks run serially, each with a 180-second limit. A run costs the
reference machine one agent process at a time.

No owner data is ever used. The suite is StatePort-owned and versioned. The loop cannot edit it, and a new suite version
ships only in a release (the fixed-point law).

## Decide

A candidate replaces the incumbent for a class only if:

1. it passes every task the incumbent passes (no regression on any critical task), and
2. it passes more tasks overall, or the same tasks with a median time below 0.8 × the incumbent's.

Ties keep the incumbent. A model without a result never wins. If the incumbent has disappeared from the catalogue, the
best measured remaining free model takes over; with none measured, the route becomes "none" and agent actions explain why
("no measured free model is available; evaluate now or connect an account").

## Apply

- **With the lease** ("Keep up automatically", default off, granted for 30 days, renewable): route changes apply
  automatically and are receipted and notified. The lease never covers a new destination: switching to a model behind a
  different provider or terms asks first.
- **Without the lease**: a route change is a proposal on the Models page ("Switch to X: 3/3 vs 2/3, 41 s vs 63 s") with
  Switch and Dismiss.
- The owner can pin a route. A pinned route is never changed automatically.

## Schedule (deterministic gate first, model only if the gate finds work)

A timer in the web service checks once at startup and then every 24 h. It observes the catalogue, which is cheap, and starts a suite
run only if the lease is enabled and either (a) the incumbent vanished, (b) a new free model appeared, or (c) the last
measurement of the incumbent is older than 7 days. At most `maxSuiteRunsPerDay` runs (default 1) and at most 3 candidates
per run.

## API (web service, same session/CSRF rules as every mutation)

| Method + path | Effect |
|---|---|
| `GET /v1/models` | catalogue, consent state, routes, lease, latest results per model, pending route proposal, last receipts |
| `POST /v1/models/consent` | `{destination: "opencode-free", termsSha256}`; records consent; required before any free-model call |
| `DELETE /v1/models/consent` | withdraws consent; routes to that destination become "none" |
| `POST /v1/models/observe` | refresh the catalogue now |
| `POST /v1/models/evaluate` | `{models: [...]}` (max 3); starts a suite run; returns `runId` |
| `GET /v1/models/runs/<runId>` | progress and result |
| `POST /v1/models/route` | `{actionClass, model, pin}`; owner choice, receipted |
| `POST /v1/models/lease` | `{enabled, days}`; grant or revoke automatic updates |
| `POST /v1/models/proposal/<id>` | `{decision: "switch" | "dismiss"}` |

## UI: Settings → Models

- A consent card: the exact terms text and a link to the provider's page, with Accept and Not now.
- The current route per class, with its last score and age.
- A catalogue table: model, free or account, last result (n/N, median time), with Evaluate.
- A "Keep up automatically" switch showing the lease expiry.
- A pending proposal card.
- History from `receipts.jsonl`.
- The page states plainly that scores come from StatePort's practice tasks, not from the owner's work.

## As built (level 1, 2026-10-21)

The API shapes are in [API_CONTRACT_WEB.md](../API_CONTRACT_WEB.md#model-routes-keep-up-loop-level-1). These refinements
came from measurements of the pinned opencode 1.18.31 on 2026-10-21:

- **Action classes**: `agent.edit-state` and `chat`. Both are decided by the same suite results and routed
  independently, so each can be pinned on its own.
- **The catalogue is a union over time.** Each observation makes up to 3 `opencode models` calls within the
  60-second budget and records `lastSeenAt` per model. A model vanishes only after it goes unseen for 7 days, and
  that is receipted once. The raw `models.json` from the last call is kept at `model-routes/cache/models.json`
  (written atomically). The sandbox pre-seeds each fresh per-run HOME from it, so a cold HOME never falls back to
  the binary's stale bundled snapshot.
- **Probe first.** Every measurement starts with one 30-second prompt. Being listed does not mean a model runs:
  4 of 6 listed free models failed within 2 s in one probe series. Failure classes: 410 deprecated, 402 endpoint
  unavailable, model-not-found, upstream 5xx and 429 mean the model is unavailable now. It is dropped from
  candidates and probed again after 24 h, and none of these is a quality failure. A 403 "free tier can only be
  used from within OpenCode" is a harness misconfiguration: it raises an alarm, stops the run, and is never held
  against the model. A probe timeout is retried once at the end of the same run. A task timeout counts as a task
  failure, and the scheduler re-measures that model once. A runner call that is still running 15 s past its limit
  is abandoned as a timeout.
- **Decide.** A measurement with zero passes never takes a route. An unmeasured incumbent is kept until it is
  measured, and the schedule measures it. A route goes to "none" automatically only when its model has vanished
  from the catalogue (a narrowing). One failed probe never does that.
- **Schedule.** With consent, each tick re-probes the incumbents, applies or proposes switches (probing a switch
  target first), and then runs the gate. Without consent a tick does nothing and writes nothing.
- **Free-route egress, measured**: `models.opencode.ai:443` (catalogue) and `opencode.ai:443` (Zen API). OpenCode
  also tries `registry.npmjs.org:443` to install `@opencode-ai/plugin` into a fresh config directory. Denying it
  did not break the runs, so it stays off the allowlist.
- **Chat.** A consented `chat` route selects the model of every chat call. With route selection wired in, a provider
  profile that names an OpenCode free model is refused without consent (`route_not_consented`).
