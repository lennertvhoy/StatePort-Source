# BL-WORKSPACE-002 frontend feature matrix

This matrix prevents the canonical frontend from deleting an existing
StatePort capability or presenting a conceptual design as implemented.
Executable preservation authority lives in:

- `config/functionality-preservation.v1.yaml`
- `config/frontend-dynamic-preservation.v1.yaml`
- `schemas/functionality-preservation.v1.schema.json`
- `schemas/frontend-dynamic-preservation.v1.schema.json`
- `scripts/validate_application_experience.py`

The current machine inventory contains six application-experience
descriptors, thirteen preserved route families, 60 static controls, 116
backend API operations, 18 capabilities, ten aliases, twelve dynamic controls,
ten dynamic file operations, and seven dynamic behaviors. Counts describe the
active worktree and must be regenerated at the final commit.

## Current backed product

| Product surface | Current authority and outcome | Preservation rule |
|---|---|---|
| Applications | Backend instances, activity/attention, recovery state, exact experience descriptors | Render observed values; keep application selection and capability guards |
| Catalog | Reviewed packages, descriptor/package/experience digests, source trust, exact fixture-install receipt | Never make an unresolved source installable |
| Repository import | Opaque allowlisted candidate, read-only inspection, exact digest/actor approval, registration/conversation/receipt | Never accept a browser raw path as source identity |
| Sources | Public bounded registry plus separately operator-gated exact development-candidate evidence | Verification remains non-production evidence |
| StudyState/ChecklistState | Trusted progress/action/notification components and application-bound Conversation | Browser-local domain edits must say local draft |
| ProjectState | Trusted application overview, governed Runs, Context, and optional Workbench | Keep every development tool capability-gated and application-scoped |
| Conversation | Operational shared Web/Telegram projection, attachments, retry, export, clear, draft/search/pin/quote UX | Never claim transcript or agent prose is canonical state |
| Runs | Exact action/engine/history, prepare/approve/execute/cancel, proposal decision/apply, post-apply bundle/evidence/receipt | Approved ≠ executed; executed ≠ applied; applied ≠ validated |
| Settings/Context | Revision-bound backend settings plus local presentation preferences; exact compact/handoff continuity | Do not create a second context/retention authority |
| Files | Broker-owned tree/read/save/create/rename/delete with base/hash/diff/receipt/refusal semantics | No direct filesystem access or silent save; regular files only |
| Terminal | Explicit authenticated PTY, strict ready, resize/end, search/fit/paste guard, in-memory tabs | No pre-ready input, auto refresh reattach, or transcript persistence |
| Infrastructure | Exact plan/digest/approval/run/validation/receipt/grant states | Stopped is neutral; completed is not healthy without evidence |
| Orchestration | Bounded exact slice through prepare/approve/execute/review/close | No hidden loop, self-approval, or automatic next item |
| Receipts | Human summary plus raw exact detail and application-native links | Preserve outcome, validation, human acceptance, and raw identity separately |
| StateBench | Operator-only path-free verified RunBundle rows and per-run evidence | Calibration only; no score/ranking/superiority inference |
| Platform deployments | Governed deployment index/detail with observed runtime state, drift, and authority runs; plan/apply/observe/logs/restart/remove/purge wired through the canonical authority boundary | Observed projection only; every mutation crosses deployment authority and is digest-bound |
| Standing authority | Profiles, grants with owner-directive revocation, and digest-bound pause/unpause of the local authority store | Pause refuses all governed mutations; revoke binds the exact grant digest |
| Installed updater | Status/policy/rollback projections; digest-bound policy mutation; rollback plan only | Rollback apply is `installed-authority-cli` only — never an HTTP apply button |
| Preview routes | Loopback reverse-proxy registry with derived status; register/revoke/atomic rewrite | Loopback-only upstreams; one active route per capsule/service; identity never crosses the gateway |
| Mobile/appearance | Same application state across responsive layouts; four themes, density, font scale, reduced motion | No separate mobile authority or clipped/hidden action |

## Explicit current gaps

| Gap | Current truth | Required boundary |
|---|---|---|
| Sanitized Markdown preview | Editor has Markdown language support, search/replace, diff review, and governed save, but no rendered preview | StatePort-owned sanitizer, link policy, accessibility, large-document and hostile-content tests |
| Synthetic-validation UI | Existing endpoint accepts `statedd.lock/v1`; installed applications use `stateport.application-lock/v1` | Versioned compatible lock contract, explicit capability, unchanged-canonical-state proof |
| Global activity destination | Application-scoped attention exists; no separate cross-application inbox authority | Permission, retention, ordering, and exact owning-item mutation contract |
| Full ContextManifest inspector | Effective lifecycle/continuity controls exist; source-by-source lossiness/provenance is not projected | Redacted backend projection of included/excluded sources, hashes, freshness, sensitivity, lossiness, budget |
| Complete runtime/degradation inspector | Engine availability and reasons exist; full RuntimeProfile/capability intersection is not shown | Safe backend projection without credentials or inferred spend readiness |
| Package update | Lifecycle foundations exist; Catalog does not execute a three-way transactional update | Exact old/current/new identity, ownership, conflict/migration plan, approval, transaction, validation, rollback, receipt |
| Live restore acceptance | Operator-only restore-as-new-instance is implemented with exact plan/approval/receipt contracts | Exact-head browser journey, restart persistence, source immutability, and registered restored-instance evidence |
| Aggregate StateBench programme | Bounded verified rows and per-run evidence exist | Frozen complete configuration, independent evaluator, critical gates, first/eventual outcomes, forced continuation, protected holdouts |

The executable preservation validator is authoritative about whether a gap is
still present. A prose row may not hide a failed control or operation check.

## Conceptual and roadmap-only features

These may be omitted or labelled unavailable. They may not display fabricated
data or success:

| Concept | Classification and exact dependency |
|---|---|
| Dedicated cross-application activity/attention inbox | planned after a scoped backend projection |
| Rich discovery categories, trust/self-hosted filters, ratings | deferred pending catalog/query/trust contracts |
| Browser-installable ClassState/LifeState | deferred pending canonical packages/descriptors/receipts |
| Conversational application setup | planned only as typed proposal → preview → approval → materialize → validate → receipt |
| Model-backed tutor/adaptive quiz/recommendations | deferred pending accepted engine, pedagogy, privacy, evidence, teacher policy |
| Calendar/web-research proactivity | deferred pending connectors, grants, provenance, privacy, retention |
| CLI or execution host as Conversation channel | deferred pending channel adapter preserving one conversation identity |
| Provider/model routing and fallback | deferred pending complete RuntimeProfile, budgets, auth-route identity, effect policy |
| Durable Runs/Sessions cockpit and subagent tree | planned after attempt graph, normalized events, isolation, budgets, review |
| Scoped knowledge/memory | deferred pending authority, provenance, sensitivity, expiry, conflict, approval |
| Automations/triggers | deferred pending idempotency, uncompensated-effect policy, scheduler/webhook security |
| Skills registry | deferred pending pinned reviewed source, capability and update authority |
| Live application preview | planned after a loopback/isolation preview broker and threat model |
| PWA/background notifications | deferred pending caching/update, privacy, permission, offline-truth contracts |
| Automatic template/platform repair, unlimited retry, hidden routing | rejected; conflicts with bounded recovery and no-duplicate-authority rules |

## Dynamic preservation

The supplemental manifest requires:

- tree/list/read and exact metadata;
- prepare, preview, commit, discard, create, rename, and delete operations;
- file rows/tabs, refresh, find, replace, Markdown preview, change review,
  confirm, and discard controls;
- descriptor-generated native run preparation/execution;
- CodeMirror lazy loading, governed mobile review/save, stale-write refusal,
  lease/basis binding, two-version preservation, and explicit resolution.

Current functional equivalences:

- Atomic `readFile` metadata supersedes a second metadata request only while it
  still includes exact path, content hash, base SHA, read-only flag, and
  encoding.
- Governed mobile review/save supersedes a blanket mobile-read-only editor
  because it preserves the same broker authority, explicit diff, stale
  refusal, confirmation, and receipt.
- CodeMirror-first editing supersedes an editor-brand requirement because it
  retains language support, diff review, theming, accessibility, and the
  broker boundary.

Markdown syntax highlighting does **not** supersede rendered Markdown preview.

## Exact route model

Canonical route families:

```text
#/applications
#/catalog
#/sources[/:sourceId]
#/statebench
#/deployments
#/authority
#/updater
#/preview-routes
#/approvals[/:approvalId]
#/settings[/:group]
#/app/:instanceId
#/app/:instanceId/conversation
#/app/:instanceId/runs
#/app/:instanceId/settings
#/app/:instanceId/receipts/:receiptId
#/app/:instanceId/workbench
#/app/:instanceId/workbench/{files,terminal,deployments,orchestration,receipts}
```

Historical aliases normalize into these routes while preserving exact
application/query identity. They are compatibility paths, not another
product.

## Accepted stronger current designs

- Application-first, trusted descriptor registry instead of a global
  infrastructure-first home.
- Seven resizable Workbench presets plus maximize/focus instead of a fixed
  pane count.
- StatePort-owned CodeMirror editing with governed diff transactions.
- Derived/polled Operation Center until a normalized global stream authority
  exists.
- Kind-specific approvals rather than an invented generic mutation.
- Thirteen visible orchestration stages mapped to current backend states.
- Four appearance modes, density/font scaling, reduced motion, responsive
  drawer, command palette, rebindable shortcuts, paste guard, and typed
  cross-tool bridges.

Each equivalence remains valid only while tests show equal-or-stronger
authority, scope, lifecycle honesty, validation, rollback, evidence,
accessibility, and recovery.

## Acceptance rule

No feature is accepted merely because a component or similarly named type
exists. Acceptance requires the mapped backend authority, capability gate,
focused tests, appropriate real-service evidence, honest lifecycle state,
rollback, and claim classification. Product-owner acceptance remains a
separate recorded decision.
