# Web AppServer contract v1

StatePort's installed application is served by the web AppServer in
[`packages/persistent-app`](../packages/persistent-app/)
(`service_process.py`). It is the same-origin boundary for the browser UI,
the terminal WebSocket, and the preview gateway
([`packages/preview-gateway`](../packages/preview-gateway/)): an
authenticated, loopback-only reverse proxy that is the sole product path to
a capsule's development/preview servers. This document records its
HTTP surface so the whole boundary is inspectable; the headless lifecycle
boundary is documented separately in
[API_CONTRACT.md](API_CONTRACT.md).

## Boundary and trust model

The AppServer is a **single-operator, local-first** service:

- The default bind is loopback-only; a public bind requires an explicit
  flag. The packaged container image binds publicly *inside the container*,
  where Compose/Quadlet port authority decides what is published; the
  default published mapping is loopback on the host.
- Browser access is gated by a same-origin cookie session
  (`stateport_session`). There is exactly one operator identity; ordinary
  instance reads rely on that session, and privileged platform operations
  additionally require per-route actor permissions (named below).
- Every `POST` except `/session` passes a blanket mutation guard: the
  request must carry a same-origin `Origin` header and the
  `X-StatePort-CSRF` header; cookie-bearing requests without an origin are
  rejected. New routes fail closed unless they opt out deliberately.
- The `Host` header is validated against loopback aliases, and origin
  checks are DNS-rebinding resistant.
- Request bodies are strictly shape-checked against per-route allowlists.
- Errors are typed: domain failures return `409` with a reason code;
  unexpected failures return `400 operation_failed` without internals.

### Preview gateway trust model

The preview gateway proxies `/preview/{capsuleId}/{serviceId}/...` to the
registered loopback upstream of one preview route:

- Routes are registered, rewritten, and revoked only through the
  session-gated management mutations below; each binds an opaque
  `(capsuleId, serviceId, revisionDigest)` triple to `127.0.0.1:port`
  (no host field — non-loopback upstreams are impossible by construction).
  `capsuleId` remains an opaque namespaced binding owned by the deployment
  record.
- Every proxied request requires the operator session, but StatePort
  identity never crosses the gateway: inbound `Cookie`, `Origin`, and
  `X-StatePort-CSRF` headers are stripped, and upstream `Set-Cookie` values
  are rewritten to host-only cookies scoped to the route path. Upstream
  root-relative `Location` redirects are rewritten into the route
  namespace.
- The namespace fails closed: `engine`, `engine-socket`, `metadata`,
  `control-plane`, `session`, `health`, `v1`, and `api` destinations are
  refused, path traversal is rejected, and a route registered for one
  capsule cannot be reached through another capsule's path. Routes expire
  and can be revoked; both refuse typed at resolution.
- WebSocket upgrades (HMR) are validated like the terminal socket
  (loopback host/origin, version 13, bounded subprotocols) and relayed
  frame-for-frame; the gateway acts as a strict RFC 6455 client upstream.
- Route expiry/revocation and the rollback rewrite are receipted
  (`stateport.preview-route-receipt/v1` chain); a rewrite rebinds the route
  atomically so in-flight requests never observe a partial binding.

## Unauthenticated routes

| Method | Route | Purpose |
|---|---|---|
| GET | `/health` | service status and identity |
| GET | `/session` | session state |
| GET | `/` , `/index.html`, allowlisted Vite assets, `/favicon.ico` | static application shell |
| GET | `/v1/terminal/socket` | terminal WebSocket upgrade (session cookie verified inside the handler) |
| POST | `/session` | establish the operator session (sole unauthenticated mutation) |

## Session-gated read routes

| Route | Notes |
|---|---|
| `/v1/settings`, `/v1/status`, `/v1/instances`, `/v1/applications`, `/v1/application-experiences`, `/v1/execution/engines`, `/v1/approvals` | platform state |
| `/v1/sources`, `/v1/sources/{id}` | source catalog; inspect requires `platform.source.inspect` |
| `/v1/repository-import/local-candidates` | local import candidates |
| `/v1/platform/statebench` | requires StateBench permission |
| `/v1/runs/{id}`, `/v1/runs/{id}/bundle`, `/v1/runs/{id}/statebench` | run inspection and evidence |
| `/v1/instances/{id}` and sub-resources | instance detail: `experience`, `conversation`, `conversation/retention`, `conversation/attachments[/{aid}]` (CSRF-checked even on GET), `activity`, `receipts[/{rid}]`, `settings`, `context-lifecycle`, `goal-execution`, `infrastructure[/grant]`, `actions`, `execution/engines`, `execution/history`, `health`, `source`, `ownership`, `recovery`, `runs`, `approvals` |
| `/v1/instances/{id}/file-workspace/{listDirectory,readFile,readFileMetadata}` | brokered file workspace reads |
| `/v1/privacy/export` | requires privacy-export permission; `stateport.privacy-export/v1` with `conversations` and `attachments`. `complete` is `false` and `skippedInstances` (`[{instanceId, reason: <exception class name>}]`) lists every instance whose conversation could not be exported (still HTTP 200); `complete: true` with an empty list otherwise |
| `/v1/deployments`, `/v1/deployments/{id}` | governed deployment index and detail (observed runtime state, authority runs, receipts) |
| `/v1/authority/profiles`, `/v1/authority/grants`, `/v1/authority/grants/{id}` | local authority store projections: profiles, grants, and pause control state |
| `/v1/updater/status`, `/v1/updater/policy`, `/v1/updater/rollback` | installed updater projections (read-only; `409 updater_state_unavailable` when no installed updater state exists on the host) |
| `/v1/preview-routes` | preview route registry index with derived status |
| `/preview/{capsuleId}/{serviceId}/...` | session-gated reverse proxy to the registered loopback preview upstream (HTTP GET/POST and WebSocket/HMR; not a StatePort mutation boundary) |

## Session-gated mutation routes

All routes below require the mutation guard; digest-bound approvals are
noted explicitly. A digest-bound approval is the body member
`approval: {"decision": "approve", "actorId": <operator actor>,
"proposalDigest": <digest>}` where the digest is the exact value named by
the route (plan digest, grant digest, control digest, authority-run id, or
observed updater status digest). The server recomputes the current value
and refuses with `409 approval_digest_mismatch` when the observed state has
moved since the operator reviewed it.

The updater surface follows the installed-updater trust model: status,
policy, and rollback projections are read-only observations of the
installed updater state; policy mutation executes through canonical
installed authority (the same engine path as the updater CLI); rollback
planning re-verifies historic release signatures and therefore requires
the installed control-plane trust root on the host, refusing typed when it
is absent. Rollback *apply* is never exposed over HTTP — it remains an
installed-authority CLI operation.

| Route | Notes |
|---|---|
| `/v1/repository-import/inspect` | candidate inspection: `{candidateId}`, or a public template `{url, revision?}` where `revision` is a full 40-character commit, a branch or tag name, or absent for the default branch; a name is resolved once and the result, review and approval bind the resolved commit (`sourceIdentity.headCommit`) |
| `/v1/repository-import/register` | exact local-operator approval + digest match |
| `/v1/instances/{id}/infrastructure/{plan,approve,run}` | governed infrastructure actions |
| `/v1/instances/{id}/infrastructure/grant/{prepare,approve}` | grant lifecycle |
| `/v1/settings`, `/v1/settings/preview`, `/v1/settings/rollback` | global settings with preview and rollback |
| `/v1/instances/{id}/{settings,settings-preview,settings-rollback}` | per-instance settings |
| `/v1/instances/{id}/activity/{attentionId}/{read,acknowledge}` | attention lifecycle |
| `/v1/sources/{id}/development-resolve` | operator permission; compare-digest identity proof |
| `/v1/instances/{id}/terminal/prepare` | terminal session preparation |
| `/v1/instances/{id}/file-workspace/{prepareWrite,createFile,previewDiff,commitWrite,discardWrite,renamePath,deletePath}` | brokered write transaction lifecycle |
| `/v1/catalog/refresh` | catalog refresh |
| `/v1/execution-host/workloads` | receipted default workload creation behind the sanctioned proxy |
| `/v1/execution-host/workloads/{start,stop,cancel,remove}` | receipted workload lifecycle operations |
| `/v1/execution-host/workloads/exec` | strictly typed argv execution, receipted |
| `/v1/privacy/purge` | requires privacy-purge permission |
| `/v1/instances/{id}/recovery/restore/{plan,approve,apply}` | requires `platform.recovery.restore` |
| `/v1/instances/{id}/{portable-export,backup,synthetic-run}` | export, backup, and synthetic execution |
| `/v1/instances/{id}/conversation/messages`, `/conversation/export` | conversation mutation and export |
| `/v1/instances/{id}/conversation/clear` | requires the literal body marker `CLEAR_CONVERSATION` |
| `/v1/instances/{id}/conversation/attachments` upload/delete/export | attachment lifecycle |
| `/v1/instances/{id}/context-lifecycle/{preference,compact,handoff}` | context policy and lifecycle |
| `/v1/instances/{id}/goal-execution/{prepare,approve,execute,review,close}` | goal execution lifecycle |
| `/v1/portable-import/preview`, `/v1/portable-import/apply` | apply requires approval identity compare-digest |
| `/v1/application-fixtures/install` | descriptor/package/experience digest binding |
| `/v1/instances/{id}/execution/prepare` | execution preparation |
| `/v1/runs/{id}/{approve,execute,cancel,proposal-approve,proposal-reject,apply}` | run lifecycle |
| `/v1/deployments/plan` | governed deployment plan; auto-dispatches to an update plan for a healthy/degraded deployment or when `rollbackOf` names an exact source revision |
| `/v1/deployments/{id}/apply` | applies an accepted plan (apply/update/rollback); digest-bound approval on `acceptPlanDigest`; `purge_data` plans purge retained deployment data |
| `/v1/deployments/{id}/status`, `/v1/deployments/{id}/logs` | governed observe/logs reads through the deployment authority grant |
| `/v1/deployments/{id}/restart`, `/v1/deployments/{id}/remove` | digest-bound approval tied to the pending authority run |
| `/v1/deployments/{id}/purge/plan` | plans retained-data purge; refused typed (`retained_data_missing`) when no retained storage exists |
| `/v1/authority/grants/{id}/revoke` | owner directive + reason; digest-bound approval on the grant digest |
| `/v1/authority/pause` | pause/unpause the local authority store; unpause requires digest-bound approval on the control digest |
| `/v1/updater/policy` | installed update-policy mutation through canonical installed authority; digest-bound approval on the observed status digest; the service computes the policy digest server-side |
| `/v1/updater/rollback` | plans the exact retained-predecessor rollback; digest-bound approval on the observed status digest; requires the installed control-plane trust root (`409 control_plane_trust_invalid` without it); the plan stages the rollback and applying it remains installed-authority-CLI-only (`applyBoundary: installed-authority-cli`) |
| `/v1/preview-routes` | register a preview route (capsuleId, serviceId, revisionDigest, upstreamPort, ttlSeconds); receipted; one active route per capsule/service |
| `/v1/preview-routes/{id}/revoke` | revoke a route with a reason; receipted; resolution refuses typed afterwards |
| `/v1/preview-routes/{id}/rewrite` | atomic rollback rewrite: rebind revisionDigest and upstream port in one locked, receipted write |

## Model routes (keep-up loop, level 1)

Implements [docs/design/keep-up-loop.md](design/keep-up-loop.md) in
`packages/persistent-app` (`model_routes.py`, `model_routes_http.py`,
`model_route_binding.py`). State lives under the service state directory in
`model-routes/` (`consent.json`, `catalogue.json`, `policy.json`,
`results/<runId>.json`, `receipts.jsonl`, `cache/models.json`).

Every route needs the session cookie. `POST` and `DELETE` also need the
mutation guard (same-origin `Origin` + `X-StatePort-CSRF`) and the
`application.provider.manage` actor permission. In the validation release
profile they are refused with `403 model_routes_disabled`. Bodies are exact:
an unknown or missing member is `400 request_shape_invalid`. Errors use the
common envelope `{"ok": false, "error": {"code", "message", "diagnostic"}}`.

| Method + path | Body | Success `result` |
|---|---|---|
| `GET /v1/models` | none | the projection below |
| `POST /v1/models/consent` | `{"destination": "opencode-free", "termsSha256": "<consent.terms.sha256>"}` | projection |
| `DELETE /v1/models/consent` | none, `{}` or `{"destination": "opencode-free"}` | projection (every free route becomes `null`, the lease is revoked, pending proposals are superseded) |
| `POST /v1/models/observe` | `{}` | projection (the catalogue is refreshed now; this needs no consent and sends no user data) |
| `POST /v1/models/evaluate` | `{"models": ["opencode/<id>-free", ...]}` (1 to 3 distinct observed free models) | `{"runId": "run-YYYYMMDDTHHMMSSZ-<8hex>", "state": "queued"}`. The run is background, serial, and one at a time |
| `GET /v1/models/runs/<runId>` | none | the run record below |
| `POST /v1/models/route` | `{"actionClass": "agent.edit-state" \| "chat", "model": "<id>" \| null, "pin": true \| false}` | projection (owner choice, receipted; supersedes pending proposals for that class) |
| `POST /v1/models/lease` | `{"enabled": true \| false, "days": 1..30}` (`days` optional, default 30) | projection |
| `POST /v1/models/proposal/<proposalId>` | `{"decision": "switch" \| "dismiss"}` | projection |

`DELETE` is accepted only on `/v1/models/consent`. Every other path still
answers `501 request_method_unsupported`.

Typed refusals:

| Status | Code | When |
|---|---|---|
| 400 | `request_shape_invalid`, `models_invalid`, `too_many_models`, `action_class_unknown`, `route_invalid`, `lease_invalid`, `proposal_decision_invalid`, `destination_unsupported` (consent for a destination other than `opencode-free`) | invalid request |
| 403 | `csrf_token_invalid`, `model_routes_access_denied`, `model_routes_disabled` | authorization |
| 404 | `run_not_found`, `proposal_not_found`, `not_found` | unknown id or route |
| 409 | `terms_mismatch` (the digest is not the current terms text), `route_not_consented`, `model_unknown` (not observed; observe first), `destination_unsupported` (only `opencode/*-free` models can be routed, probed or evaluated in this release), `evaluation_in_progress`, `proposal_stale` | state conflict |
| 502 | `observation_failed`, `observation_timed_out` | `opencode models` failed or exceeded 60 s |
| 503 | `harness_unavailable` (no executable), `suite_invalid` (the frozen suite failed its digest check) | runtime |

### `GET /v1/models` projection (`stateport.models-projection/v1`)

```text
{
  formatVersion: "stateport.models-projection/v1",
  status: { state: "ready" | "not_consented" | "no_route" | "harness_unavailable",
            detail: string, harness: { id: "opencode", present: bool, version: string | null },
            readyClasses?: [actionClass], alarm?: Alarm | null },
  consent: { destination: "opencode-free", state: "granted" | "not_granted" | "stale",
             grantedAt: iso | null, grantedBy: string | null, grantedTermsSha256: string | null,
             terms: { provider: "OpenCode Zen", url: "https://opencode.ai/docs/zen",
                      text: string,               // show exactly this text
                      sha256: "sha256:<hex>" } }, // send exactly this back to consent
  catalogue: { observedAt: iso | null, observations: int | null,
               harness: { id: "opencode", version: string | null } | null,
               lastError: { code, at } | null, availabilityWindowSeconds: 604800,
               cache: { path, sha256, storedAt } | null,
               models: [ { id, free: bool, destination: "opencode-free" | "<provider>-account",
                           listedNow: bool, usable: bool, firstSeenAt, lastSeenAt, seenCount,
                           lastProbe: Probe | null,
                           latestResult: { runId, finishedAt, state, available, complete, passed,
                                           total, medianSeconds, suiteDigest, current: bool } | null } ] },
  alarms: [Alarm],                                   // newest first
  routes: [ { actionClass: "agent.edit-state" | "chat", model: string | null, pinned: bool,
              setBy: "owner" | "lease" | "schedule" | <actor id> | null, setAt: iso | null,
              why: string | null, ageSeconds: int | null, score: Score | null,
              usable: bool | null, refusal: { code, message } | null } ],   // always both classes, in this order
  lease: { enabled: bool, state: "off" | "active" | "expired" | "inactive", grantedAt, expiresAt,
           maxSuiteRunsPerDay: int, runsToday: int, maxDays: 30, defaultDays: 30 },
  suite: { valid: true, id, version, digest, taskCount, taskTimeoutSeconds,
           tasks: [ { id, title, critical } ] } | { valid: false, reason },
  evaluation: { activeRunId: string | null, maxModels: 3, lastRunId: string | null },
  proposal: Proposal | null,                         // the newest pending proposal
  proposals: [Proposal],                             // every pending proposal
  schedule: { running: bool, intervalSeconds: 86400, nextTickAt: iso | null, lastGate: object | null },
  receipts: [Receipt],                               // newest first, at most 50
  scoresNote: "Scores come from StatePort's practice tasks, not from your work."
}
Probe    = { status: "ok" | "unavailable" | "timeout" | "harness_error" | "unmeasured",
             cause: null | "model_unavailable" | "upstream_error" | "rate_limited" | "timeout"
                    | "harness_misconfigured" | "sandbox_refused" | "empty_reply" | "failed",
             at, seconds, sandboxStatus, refusal, retried?: true }
Score    = { passed, total, medianSeconds, runId, finishedAt, timeouts }
Proposal = { id: "proposal-<12hex>", actionClass, from: string | null, to: string, reason, why,
             candidate: Score | null, incumbent: Score | null, suiteDigest, createdAt,
             status: "pending", summary: "Switch to X: 3/4 vs 2/4, 41 s vs 63 s" }
Alarm    = { code: "harness_misconfigured", model: string | null, at, detail }
Receipt  = { formatVersion: "stateport.model-route-receipt/v1", receiptId, sequence, type, at, by,
             previousDigest, digest, ...fields of the type }
```

`route.refusal.code` is the same typed refusal agent actions receive:
`route_not_consented`, `no_measured_route` (no measured free model: "evaluate
now or connect an account"), `route_not_configured` (measured models exist
but none is chosen; accept the proposal or choose one), `harness_unavailable`.
`status.state` is `ready` only when a consented route and the executable both
exist. It is not a promise that a free model answers right now.

Receipt types: `consent.granted`, `consent.withdrawn`, `catalogue.observed`
(`added`, `freeAdded`, `vanished`), `catalogue.observation_failed`,
`model.probed` (on a status change), `suite.run_started`, `suite.run_finished`,
`route.changed` (`actionClass`, `from`, `to`, `why`, `by`, optional `candidate`
and `incumbent` scores), `proposal.created`, `proposal.dismissed`,
`lease.granted`, `lease.revoked`, `lease.expired`, `harness.alarm` and
`schedule.tick` (`gate`). The log is append-only and hash-chained:
`previousDigest` names the prior line's `digest`.

### `GET /v1/models/runs/<runId>` (`stateport.model-suite-run/v1`)

```text
{ formatVersion, runId, sequence, state: "queued" | "running" | "completed" | "failed" | "interrupted",
  error?: "harness_misconfigured" | <exception class>, trigger: "owner" | "schedule", by,
  createdAt, startedAt, finishedAt, suite: { id, version, digest }, harness: { id, version },
  requestedModels: [id], retryModels: [id],
  progress: { completedTasks, totalTasks, currentModel, currentTask },
  models: [ { model, probe: Probe | null, available: bool, complete: bool, isRetry: bool, timeouts?: int,
              totals: { passed, total, medianSeconds } | null,
              tasks: [ { taskId, passed: bool, seconds, reason, status: "checked" | "not_run",
                         failure: string | null, sandboxStatus, exitCode, tokens, egressDenied: int,
                         hardTimeout: bool } ] } ] }
```

Only a `complete` and `available` model entry counts as a measurement. A
failed probe means "unavailable now", never a quality failure.

`GET /v1/provider/status` also carries `modelRoute`, the same object as the
projection's `status` (`state: "disabled"` in the validation profile).

## Actions and proposals

A template action is either a `check` (a deterministic evaluator) or an
`agent` (a model that edits a disposable copy of the instance). The contract
template authors write against is
[`docs/TEMPLATE_CONTRACT.md`](TEMPLATE_CONTRACT.md); this section records the
shapes the run record carries.

### The run record

`GET /v1/runs/{id}` and every run transition (`/v1/runs/{id}/{approve,execute,cancel,proposal-approve,proposal-reject,apply}`)
return `{ok: true, result: {"run": <record>}}`. The record is
`stateport.governed-action-run/v1`; the members the UI reads for an action are:

| Member | Shape |
|---|---|
| `actionId` | the action's id, `<applicationId>.<name>/v1` |
| `executorKind` | `script` or `agent` |
| `mutationPolicy` | `none` or `propose_only` |
| `inputs` | the action's inputs, exactly as approved (their digest is `runSpec.benchmarkConfiguration.inputsDigest`) |
| `status` | the run status (`state_change_proposed`, `state_change_approved`, `applied`, `result_rejected`, …) |
| `proposal` | the pending file-change proposal, or `null` |
| `proposalPaths` | the sorted paths the proposal touches |
| `proposalDigest` | the digest the proposal approval binds |
| `evaluator` | `{actionId, before, after}` — the evaluator verdicts of this run |
| `result` | the typed result of the run (`verdict`, `summary`, `findings` for a check; `agent`, `evaluator` for an agent run) |
| `receipt` | after an apply: the apply receipt, including the Git commit |

### The file-change proposal

`proposal` is `stateport.file-change-proposal/v1`:

```json
{
  "formatVersion": "stateport.file-change-proposal/v1",
  "kind": "files",
  "proposalId": "proposal-<16 hex>",
  "applicationAction": "acme.notes.summarize/v1",
  "runId": "run-<20 hex>",
  "preStateDigest": "sha256:<64 hex>",
  "baseGit": "<the instance HEAD the proposal was computed against>",
  "operations": [
    {"operation": "write", "path": "notes/SUMMARY.md",
     "contentDigest": "sha256:<64 hex>", "blobRef": "sha256/<64 hex>",
     "bytes": 412, "previousDigest": null},
    {"operation": "delete", "path": "notes/OLD.md", "previousDigest": "sha256:<64 hex>"}
  ],
  "directories": {"added": ["notes"], "removed": []},
  "files": [{"path": "notes/SUMMARY.md", "change": "added", "additions": 12, "deletions": 0, "binary": false}],
  "patch": "--- a/notes/SUMMARY.md\n+++ b/notes/SUMMARY.md\n…",
  "patchTruncated": false,
  "patchDigest": "sha256:<64 hex>",
  "stats": {"filesChanged": 1, "added": 1, "modified": 0, "deleted": 0,
            "additions": 12, "deletions": 0, "bytesWritten": 412,
            "gitMetadataChangesIgnored": 0},
  "writablePolicy": {"ownership": {"notes/": "instance"}, "protected": [".git/", ".stateport/"],
                     "narrowing": ["notes/"], "limits": {}},
  "summary": "the agent's last words, bounded",
  "evaluator": {
    "actionId": "acme.notes.check/v1",
    "before": {"verdict": "not_yet", "summary": "…", "findings": [], "actionId": "…",
               "execution": "…", "durationMs": 12},
    "after":  {"verdict": "passed",  "summary": "…", "findings": [], "actionId": "…",
               "execution": "…", "durationMs": 11}
  },
  "producer": {"kind": "agent", "engine": "agent-sandbox", "route": {"model": "opencode/<id>-free"}}
}
```

- `files[]` is the reviewable change list: `path`, `change`
  (`added` | `modified` | `deleted`), `additions`, `deletions`.
- `patch` is a bounded unified diff; `patchTruncated` says whether it was cut
  at the size bound (`files[]` and `stats` are always complete).
- `evaluator.before` is the verdict on the staged base, `evaluator.after` the
  verdict on the candidate. Each verdict is `passed` | `not_yet` | `invalid`
  with a `summary` and `findings`; it also names the `actionId` that judged
  it, the `execution` boundary it ran under and how long it took.
- The new file contents are **not** inline: they are stored content-addressed
  under the run's operations directory and referenced by `blobRef`.

A run that changed nothing has `proposal: null` and reports only the
evaluator's `before` verdict.

### Refusals

A refused run keeps its typed reason in `stateChangeRefusal`:
`{code, message, paths}`. The codes are `protected_path` (a protected or
owner-owned path), `not_instance_owned` (the path is not instance-owned),
`outside_action_writable_paths` (outside the action's `writablePaths`),
`change_too_large` (over the size budget), `unsafe_output` (a link or special
file was left behind), `mutation_not_permitted` (a read-only action changed
something) and `proposal_stale` (the instance moved on). A refused run never
reaches canonical state and its content store is discarded.

Applying a proposal is a separate, digest-bound approval. `POST
/v1/runs/{id}/proposal-approve` binds the proposal digest, the base Git SHA,
the changed paths, the evaluator verdicts and StatePort's own writer. `POST
/v1/runs/{id}/apply` then writes the files and makes exactly one Git commit in
the instance (author `StatePort`), and records the commit in `receipt.commit`.

## Observability and logging

Operational events follow the redacted `stateport.operational-event/v1`
contract from [`packages/observability`](../packages/observability/) with
server-generated request IDs. The AppServer also keeps a plaintext local log
for operator diagnostics; provider exception text is never written to it
(only bounded reason tokens or exception class names), so credentials and
URLs cannot leak through that channel.
