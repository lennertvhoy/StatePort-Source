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
| `/v1/privacy/export` | requires privacy-export permission |
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
| `/v1/repository-import/inspect` | candidate inspection |
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

## Observability and logging

Operational events follow the redacted `stateport.operational-event/v1`
contract from [`packages/observability`](../packages/observability/) with
server-generated request IDs. The AppServer also keeps a plaintext local log
for operator diagnostics; provider exception text is never written to it
(only bounded reason tokens or exception class names), so credentials and
URLs cannot leak through that channel.
