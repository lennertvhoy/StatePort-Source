# Acceptance Freezes

> Accepted user-facing milestone ledger.

This is a dated historical ledger. The opening paragraph and the `220`-test
count below describe the 2026-07-12 freeze only; they are not current-head
status. Remote CI later resumed and passed the six-job exact-head validation
for private Slice A PRs #29 and #30. Current truth and current suite results
live in `STATUS.md`, `PROJECT_STATE.yaml`, and `docs/EVIDENCE_LOG.md`.

At this 2026-07-12 freeze, no remote acceptance freeze existed. The local lifecycle, StateIR/StatePack, governed API, bearer/pinned-offline-OIDC binding, governance primitives, governed echo-run contract, approval-bound queue, durable usage ledger, kernel-backed lease, isolated worker staging, explicitly enabled immutable-image executor, disabled-by-default Compose worker, StateBench contracts, contribution bundle, container contract, GUI, and Compose-shape candidates passed that slice's complete 220-test suite and repository validation. Remote CI was then unverified because the observed workflow was blocked before steps by account billing limits. Hosted identity lifecycle, automatic upgrade apply, migration execution, arbitrary mutation, distributed worker execution, live benchmark evidence, and performance claims remained out of scope for that freeze.

## 2026-07-12 — Approval-bound local container execution boundary

- Added pinned offline RS256 OIDC validation with static JWKS and explicit
  provider-subject-to-local-actor mapping; discovery, refresh, introspection,
  login, revocation, and session handling remain outside this boundary.
- Added durable SQLite usage reservations, approval-bound queue admission,
  immutable image enforcement, kernel-backed instance leases, isolated
  read-only execution-input staging, bounded structured output evidence, and
  post-run canonical-state integrity checks.
- Kept the Compose worker disabled by default and supplied no container-engine
  socket. Explicit local worker execution requires operator enablement and an
  immutable SHA-256 runner image.
- Local acceptance: `python3 -m pytest scripts/ -q` passed with 220 tests;
  repository/schema validation, compileall, and diff checks passed. The real
  Podman normal-layout flow also passed with preserved state and no leftover
  staging/runtime directories.

## 2026-07-11 — Self-hosted execution boundary local slice

- Added environment-only bearer authentication with constant-time token checks and HTTP actor binding; conflicting body identities are rejected and tokens never enter audit records.
- Added a Docker/Podman executor command builder with fixed image configuration, read-only root, non-root user, network disabled, dropped capabilities, no-new-privileges, fixed mounts, and explicit approval-id/process-enable gates. Default execution remains disabled.
- Added a Compose worker health/capability surface that advertises echo/plan-only operation and rejects all control POSTs. It does not consume jobs or start containers.
- Added authentication, executor, worker, and Compose acceptance tests, including symlinked mount-parent rejection. No hosted identity provider, worker queue, model provider, network access, or enabled container runtime was introduced.

## 2026-07-11 — Governed echo-run local slice

- Added persistent `stateport.governed-run/v1` plans and outcomes for deterministic echo mode.
- Required `read_state` in the server-derived template request, instance grant, and operator policy intersection; run planning remains L0/read-only and does not require approval.
- Captured an isolated `stateport.container-execution/v1` plan with network disabled and `apply: false` without creating a runtime or starting a container.
- Added before/after canonical file snapshots and metadata-only diffs. Unexpected runner writes are restored and fail the run with explicit integrity status.
- Added run list/inspect, persistence-across-reload, template-reference binding, and unexpected-write restoration tests. No model, network, container, tool, or workflow-write capability was introduced.

## 2026-07-11 — Approval-backed lifecycle mutation local slice

- Added explicit configured local identities with per-instance scope and role checks; the API remains read-only when no identity and operator policy are configured.
- Added server-derived template requests, instance grants, and operator-policy intersection with fail-closed malformed-input handling.
- Added persistent approval requests, self-approval prevention, quota admission, append-only hash-chained audit events, and idempotent `materialize-instance` execution.
- Added instance snapshot/restore around post-write validation and regression coverage for identity denial, capability denial, approval persistence, audit evidence, self-approval rejection, and repeated apply.
- No trusted authentication, arbitrary file write, automatic upgrade apply, runner execution, or performance claim was introduced.

## 2026-07-10 — StateIR/StatePack local slice

- Added `statedd.state-ir/v1` source-linked facts from manifest-owned YAML and Markdown without changing canonical files.
- Added `statepack/v1` disposable packs with separate selection and rendering dimensions, `human`/`compact`/`ultra`/`audit`/`task` profiles, eager/compact-context/modular selection labels, explicit source hashes, staleness, truncation, and token-measurement metadata.
- Added read-only `context-build`, `context-inspect`, and `context-compare` CLI commands plus focused package and CLI acceptance tests.
- Default token counting is explicitly approximate (`whitespace-v1`); exact model-aware counting requires a configured callback and tokenizer identifier. Domain schemas, semantic migrations, persisted pack ownership, and controlled benchmark evidence remain future work.

## 2026-07-10 — Governed API v1 local slice

- Added `stateport.api/v1` as a transport-neutral, workspace-confined, read-only dispatcher over template/instance validation, override inspection, dry-run upgrade planning, and StatePack build/inspect/compare.
- Added `apps/api/` and `stateport-api` as a loopback-by-default stdlib HTTP adapter. `GET /v1/capabilities` advertises an empty mutation set; no client can apply an upgrade or edit workflow files through this boundary.
- Added structured error envelopes, path traversal/symlink rejection, invalid-pack result semantics, and five acceptance tests. Identity, capability intersection, approvals, audit, usage, cost, runner, and approved mutation remain the next contract.

## 2026-07-10 — Broad backlog foundation local slice

- Added fail-closed quota decisions, capability intersection, approval transitions, and append-only hash-chained audit events.
- Added StateBench v0 candidate/configuration/repetition/report primitives and explicit result tiers without winner claims or private holdouts.
- Added privacy-filtered contribution bundles requiring eligible changed files, evidence, version bump, and later review/secret scanning.
- Added the isolated container execution plan contract, instance-first GUI inspection surface, and read-only local Compose shape.
- Added governed API policy/quota checks and expanded CI coverage. `podman compose config`, image builds, healthy API startup, web startup, loopback API/UI smoke checks, and teardown passed; the first web start hit and then cleared a pre-existing host-port 8080 collision.
