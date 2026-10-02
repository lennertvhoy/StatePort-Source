# Frontend live-truth matrix

Historical scope: 2026-08-01 audit-reconciliation candidate based on private
integration head `2cb10aa4595d3eb06bd6f6fba5ae7d5f9be758bf`, since integrated
(PRs #31/#32) and superseded by the Slice B convergence (PR #34) and the
release-assembler line. Historical browser
results below remain scoped to their recorded source; ignored worktree paths
are not durable evidence and must be regenerated for final alpha acceptance.

## Evidence labels

- **live-tested:** exercised through the actual production build and StatePort
  AppServer.
- **browser-tested:** exercised in Playwright against the isolated mock/demo
  build; useful for interaction, responsive, and accessibility evidence only.
- **contract-tested:** adapter request/response and backend behavior are tested,
  but the integrated browser workflow has not been proven at the final head.
- **implemented:** current executable path exists without sufficient evidence
  for a stronger label.
- **honestly unavailable:** hidden, disabled, or explicit because the backend,
  capability, actor, or product contract is absent.

None of these labels means remote CI, canonical release, production
qualification, product-owner acceptance, or human acceptance.

## Runtime and shell

| Surface | Authority and behavior | Current evidence | Remaining exact gate |
|---|---|---|---|
| Canonical frontend | One React 19.2.3 / TypeScript 5.9.3 / Vite 7.3.6 / CodeMirror 6 product under `apps/web`; no parallel browser runtime. | build/static contract-tested; AppServer live-tested | final exact-commit build/static scan |
| Production adapter | HTTP is build-bound; mock override is refused; demo is isolated; no production fallback. | build-isolation and adapter tests; AppServer live-tested | final network scan across representative failure routes |
| AppServer | Same-origin static/session/API/terminal, strict marker and asset allowlist, CSP/cache/Host/request framing. | focused service/security tests and ephemeral AppServer smoke | final Compose/container plus exact runtime identity |
| Application shell | Applications, Catalog, Sources, Approvals, Settings; selected application retained across its routes. | browser-tested across eight viewports; representative AppServer routes live-tested | guided product-owner acceptance |
| Mobile shell | Drawer/focus restoration, no 320×568/390×844 topbar collision, secondary actions in accessible overflow. | historical focused mobile browser matrix passed; its ignored screenshot directory was not retained | regenerate exact-head artifacts under the external operator evidence root and complete final review |
| Appearance | light, dark, high-contrast light/dark, compact/comfortable density, 125% font, reduced motion. | 4-case preference matrix and focused mobile/desktop screenshots passed | final full matrix and human review |

## Global surfaces

| Surface | Authority and behavior | Current evidence | Remaining exact gate |
|---|---|---|---|
| Applications | Real instance projection, capability summary, attention/activity, last application continuity. | contract/component tested; live-core shell exercised | final representative StudyState/ProjectState/ChecklistState/NixOS switch matrix |
| Catalog install | Backend package list; install binds descriptor/package/experience digests and links the exact application receipt. | contract/component/service tested | live reviewed fixture installation at final head |
| Repository import | Opaque allowlisted candidate → read-only inspection → exact digest/actor approval → registration/conversation/receipt. | contract/component/backend tested | final live registration and stale-digest refusal |
| Sources | Bounded public status; only exact platform operator can request redacted detail/verification; development candidate stays non-production. | **live-tested 3/3** in `apps/web/.playwright-mcp/canonical-source-current/results.json` | rerun after final commit with explicit public fixture |
| Platform StateBench | Operator-only path-free verified RunBundle rows, rejected/unverified counts, `authoritativePerformanceClaim: false`; normal user makes no endpoint request. | **live-tested** within the same 3/3 role matrix | aggregate/full-vector program remains separate future work |
| Approvals | Kind-specific owning workflow; exact revision/digest; no invented generic mutation. | contract/component/service tested | live representative run/infrastructure/grant/orchestration decisions |
| Global Settings | Revision-bound safe server preferences and rollback; appearance/density/shortcuts stay explicitly local. | contract/component tested | live stale-revision and rollback receipt |

## Application surfaces

| Surface | Authority and behavior | Current evidence | Remaining exact gate |
|---|---|---|---|
| Descriptor views | Trusted StatePort-owned registry maps declared components/routes and effective capabilities; unknown declarations fail closed. | contract/component/backend tested | final live application/capability route matrix |
| Overview | Observed status/progress/actions only; StudyState/ChecklistState browser edits are labelled local drafts. | component/browser tested | domain-specific governed mutation contracts remain future work |
| Conversation | Operational/noncanonical shared Web/Telegram projection; send/retry/attachments/delete/export/clear; no false streaming. | contract/component/service tested | full live attachment/retry/export/clear/restart journey |
| Runs | Actions/engines/history, prepare, exact approval, execute/cancel, proposal approve/reject, apply, post-apply bundle/StateBench and closure receipt; applied ≠ validated. | **live-tested** for bounded apply/bundle journey; screenshot `output/playwright/live-core-20260719/runs-applied-with-bundle.png` | final mismatch, reject/cancel, first/eventual, and receipt cross-link matrix |
| Context lifecycle | Effective policy/preference, usage/Git/continuity identities, compact/handoff receipts, no canonical-state mutation. | **live-tested** bounded handoff; screenshot `output/playwright/live-core-20260719/context-handoff-recorded.png` | final compact, stale-digest, and canonical-before/after proof |
| Application receipts | Exact application-scoped list/detail; outcome and validation separate; raw evidence retained; no client-side verification claim. | contract/component/backend tested; run closure indexes a receipt | final live list/detail/cross-link matrix |

## Workbench surfaces

| Surface | Authority and behavior | Current evidence | Remaining exact gate |
|---|---|---|---|
| Workbench shell | Capability-gated, resizable presets, maximize/focus, state-preserving panels, mobile layouts. | component/e2e/screenshot tested | final resize/persistence visual review |
| Files list/read/save | Application-scoped broker, exact hash/base, prepare/preview/confirm, receipt/readback, stale/read-only/path refusal. | **live-tested** bounded governed write; screenshot `output/playwright/live-core-20260719/files-governed-write.png` | final stale/read-only/path-escape matrix |
| Files create/rename/delete | Regular-file-only broker operations; create uses listed base + diff transaction; rename/delete require prior exact read; delete is separately destructive. | focused typecheck/lint/build, 4 files / 33 frontend tests and 129 backend/preservation tests pass; real service exercised create→rename→delete and exact receipt detail | rerun globally clean: unrelated goal-execution polling returned 409 after the repository became dirty; review older generic-save receipt validation |
| Markdown preview | Syntax highlighting exists; no sanitized rendered preview. | **honestly unavailable** / preserved P2 gap | define sanitizer and preview accessibility tests |
| Terminal | Explicit prepare/connect, exact one-use-token auth, strict ready, no pre-ready input, binary PTY input, resize/end controls, no auto refresh reconnect. | **live-tested** PTY/resize; screenshot `output/playwright/live-core-current/terminal-live-pty.png` | final hostile-frame, maximize, search/paste, cleanup matrix |
| Infrastructure | Target/health/dirty distinctions, read-only plan, exact approval/run/receipt/grant; validation only from explicit successful evidence. | contract/component/service tested | safe live fixture; destructive operation remains separately gated |
| Orchestration | Bounded prepare/approve/execute/independent review/close; exact objective/base/revision/digests; no hidden loop or automatic next item. | contract/component/service tested | live bounded slice |
| Workbench receipts | Application receipt index/detail and raw evidence. | contract/component tested | final live cross-link from run/file/infrastructure |

## Recovery and deferred surfaces

| Surface | Current truth | Classification |
|---|---|---|
| Backup and restore | Inspection and verified backup creation are connected; operator-only exact-plan restore creates a new managed instance, preserves the source, validates/registers the result, and records a path-free receipt. | implemented / backend, HTTP, client, and component contract-tested; live browser/restart proof open |
| Synthetic validation | Endpoint expects `statedd.lock/v1`; installed applications use `stateport.application-lock/v1`; no resolved capability. | deliberately deferred, not missing UI work |
| Durable terminal sessions | Tabs are browser memory; refresh never silently reattaches. | honestly unavailable |
| Global live operation/notification streams | Current views are bounded polling/derivation and labelled accordingly. | honestly non-streaming |
| Package update/export/import | Lifecycle foundations exist, but no complete governed browser update transaction. Restore is tracked separately above. | planned after exact contract |
| Preview/knowledge/automations/skills/subagents/provider routing/PWA | No accepted production authorities. | deferred roadmap |

## Current browser evidence

- Demo/responsive suite: 210 executed tests passed with 686 intentional
  project/viewport gates across eight projects; executed Axe checks had no
  serious or critical result.
- Canonical Sources/StateBench: 3/3 production-AppServer cases passed,
  including normal-user no-call, exact operator row, and 320×568.
- Live core: the recorded 2026-07-19 matrix passed three bounded Runs,
  Context, and Files workflows; a later focused live terminal case passed.
- Mobile visual closure: collision/focus cases historically passed at 320×568
  and 390×844. The ignored worktree screenshot path was not retained; final
  artifacts must be regenerated under the external operator evidence root.

These are worktree artifacts and must be regenerated or explicitly rebound to
the final commit before clean-tree closure is claimed.
