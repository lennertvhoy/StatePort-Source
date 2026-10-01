# Governed API v1

StatePort has a headless API boundary for lifecycle and context contracts. The
transport-neutral implementation is
[`packages/governed-api`](../packages/governed-api/); the loopback development
adapter is [`apps/api`](../apps/api/).

## Boundary

Clients use one policy-enforcing boundary. They do not receive a primitive for
editing instance files, applying an upgrade, changing a lock, or running a
template with elevated capabilities. The v1 process is local and workspace
confined; it is not an authentication, multi-tenant, hosted, or production
service. The default constructor has no operator capabilities and therefore
remains read-only. An embedding service must configure identities, operator
capabilities, and a trusted authentication boundary before enabling mutations.

Every request is JSON and every response has a stable envelope:

```json
{"ok": true, "result": {}}
```

Errors use:

```json
{"ok": false, "error": {"code": "...", "message": "..."}}
```

## Operations

| Method | Route | Required body | Result |
|---|---|---|---|
| GET | `/health` | — | API version, status, read-only flag |
| GET | `/v1/capabilities` | — | available operations, mutation mode, and identity configuration |
| POST | `/v1/validate/template` | `path` | validator result and structured issues |
| POST | `/v1/validate/instance` | `path` | validator result and structured issues |
| POST | `/v1/lifecycle/overrides` | `instancePath`, `templatePath` | `statedd.override-report/v1` |
| POST | `/v1/lifecycle/upgrade-plan` | `instancePath`, `templatePath` | `statedd.upgrade-plan/v1`, always dry-run |
| POST | `/v1/mutations/request` (`operation: apply-upgrade`) | `actor`, `operation`, `instancePath`, `templatePath` | pending approval plus the exact bound `statedd.upgrade-plan/v1` digest |
| POST | `/v1/context/build` | `instancePath`, `task`, `model`, `budgetTokens` | disposable `statepack/v1` |
| POST | `/v1/context/inspect` | `pack` or workspace-relative pack path | shape/freshness inspection |
| POST | `/v1/context/compare` | `left`, `right` pack or workspace-relative paths | configuration-dimension comparison |
| POST | `/v1/policy/check` | requested/granted/operator capability lists | fail-closed capability intersection |
| POST | `/v1/quota/check` | quota limits, usage, estimated cost | fail-closed quota decision |
| POST | `/v1/identity/check` | `actor`, optional `instanceId` | configured identity and scope check |
| POST | `/v1/mutations/request` | `actor`, `operation`, `instancePath`, `templatePath` | pending approval for a supported mutation |
| POST | `/v1/approvals/decide` | `actor`, `approvalId`, `status` | persisted approved/rejected/cancelled request |
| POST | `/v1/approvals/list` | `actor` | approvals visible in the actor's instance scope |
| POST | `/v1/mutations/apply` | `actor`, `approvalId` | validated, audited, idempotent materialisation or upgrade apply |
| POST | `/v1/runs/plan` | `actor`, `instancePath`, `templatePath`, optional `mode` | persisted governed echo-run plan |
| POST | `/v1/runs/execute` | `actor`, `runId` | deterministic runner result with state-integrity evidence |
| POST | `/v1/runs/list` | `actor` | run records visible in the actor's instance scope |
| POST | `/v1/runs/inspect` | `actor`, `runId` | one persisted run record |

All supplied filesystem paths resolve beneath the configured workspace and may
not traverse symlinks. Invalid context packs are a successful transport
operation with `result.valid: false`, while malformed requests, forbidden
paths, unsupported routes, and core operation failures use non-2xx statuses.

## Approval-backed mutation contract

The supported mutations are `materialize-instance` and `apply-upgrade`, both of
which require the `write_state` capability. The API derives requested capabilities from the
template's explicit `requestedCapabilities`/`capabilities` or its
`allowedActions`, and instance grants from `spec.grantedCapabilities` or
`spec.allowedCapabilities`. It intersects those values with the operator
capabilities configured on `GovernedAPI`; request bodies cannot grant
themselves access. Missing or malformed policy inputs produce an empty
effective set.

Mutation requests are persisted below the operational `.stateport/` directory,
not in canonical workflow state. A requester cannot approve its own request
unless it has the `admin` role. Applying a request requires an approved record,
an instance-scoped operator identity, a fresh capability intersection, and
post-write validation. `apply-upgrade` additionally binds its approval to one
exact `statedd.upgrade-plan/v1` digest at request time: blocked plans are
refused before an approval can exist, the plan is re-planned immediately before
any write, and a digest mismatch is refused with `plan_stale` instead of
applying a stale plan. The implementation snapshots the instance and restores
it when validation fails, records append-only hash-chained audit events, and
treats a repeated apply as idempotent. Automatic arbitrary file writes are not
included in this mutation contract; runner routes and the HTTP adapter's
optional local bearer boundary are separate contracts.

The context compiler continues to exclude `secret` facts under the default
operator policy, carries source hashes and fact-level provenance, and never
persists a generated pack as workflow truth. Exact model tokenization and
mutation approval is now explicit for the narrow lifecycle operation above.

## Governed echo-run contract

`/v1/runs/plan` is a read-only L0 admission boundary. It requires the
`read_state` capability to be present in the template request, instance grant,
and configured operator policy. It records a persistent plan containing the
actor, instance/template identity, quota decision, and a validated
`stateport.container-execution/v1` plan with network disabled, read-only root,
non-root execution, and `apply: false`. Planning never creates a runtime or
starts a process.

`/v1/runs/execute` invokes only the existing deterministic echo runner. Before
and after file snapshots are compared by hash. Unexpected changes are
restored, the run fails with `stateIntegrity: restored_unexpected_write`, and a
metadata-only diff is recorded. Successful runs produce
`stateIntegrity: preserved`, an empty `filesChanged` list, runner logs/errors,
and audit events. No model provider, network access, container process, tool
call, or workflow write capability is implied by these routes.

## HTTP authentication

The loopback adapter accepts `STATEPORT_AUTH_TOKENS_JSON` as an environment-only
mapping of actor id to bearer token. When configured, every POST request except
the public health/capabilities GET routes requires `Authorization: Bearer ...`.
The adapter hashes tokens in memory, compares hashes in constant time, injects
the authenticated actor into the governed request, and rejects a conflicting
body actor. Tokens are never persisted or included in audit data. An empty token
mapping is not authentication, and the HTTP launcher refuses configured
identities or operator capabilities unless at least one bearer credential is
configured. The all-empty local default remains unauthenticated and read-only.
`STATEPORT_OIDC_CONFIG_JSON` is also supported for pinned, offline RS256 JWT
validation against a static JWKS and explicit provider-subject-to-local-actor
mapping. It performs no discovery, refresh, introspection, login, revocation,
or session handling; those remain embedding-service responsibilities. Both
authentication modes are local configuration boundaries, not a hosted identity
lifecycle.

## Approval-bound container echo jobs

`/v1/runs/plan` accepts `mode: container_echo` as a plan-only request. The
execution image must be immutable before `/v1/runs/request-execution` can
create the durable approval request. An approved request can be published once
through `/v1/runs/enqueue` as a SQLite-backed immutable job whose payload binds
the run, approval, plan digest, template digest, fixed command, executor
configuration, and usage reservation. `/v1/jobs/list` and
`/v1/jobs/inspect` expose scoped operational records; `/v1/usage/inspect`
exposes quota evidence, not billing.

The explicitly operated local worker revalidates those bindings, current
capability intersection, immutable image, template digest, and usage
reservation before execution. It acquires a kernel-backed instance writer
lease, stages template and instance snapshots read-only, disables networking,
captures bounded structured output, and verifies durable state integrity after
the container exits. Compose leaves this worker execution disabled and mounts
no engine socket by default.
