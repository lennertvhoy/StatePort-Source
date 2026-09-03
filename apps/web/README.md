# StatePort Web

StatePort is the lifecycle platform and governed cockpit of the Stateware
family: it installs durable applications as user-owned instances, compiles
their context, negotiates execution capabilities, enforces exact approvals,
applies typed state changes transactionally, validates the result, and
records receipts and evidence. Language models, coding agents, and terminal
harnesses are replaceable compute inside that boundary — they never own the
application's truth.

This is the canonical StatePort web frontend: React 19.2.3, strict TypeScript
5.9.3, Vite 7.3.6, CodeMirror 6, and xterm.js 6. It presents Applications,
Catalog, Sources, Approvals, Settings, per-application Overview,
Conversation, governed Runs, Context lifecycle, receipts, and a
capability-gated Workbench (Files, Terminal, Deployments, Orchestration,
Receipts), with a command palette, an Operation Center, and a dev-only
Scenario Lab.

There is no parallel frontend runtime. Development can use the deterministic
mock adapter. Distributable production builds are bound to the same-origin
HTTP adapter; production never falls back to mock data, and transport or
validation failures remain an honest error state. See
`docs/INTEGRATION_MANIFEST.md` for the current verification and rollback
contract.

## Status

The frontend is integrated with the current StatePort AppServer. Focused
contract, component, backend, production-AppServer, and responsive browser
evidence exists for the major current workflows. The final exact-worktree
full ladder is rerun after the active concurrent slices land; no historical
test count in this README should be treated as final-head evidence. Local
machine validation is not remote CI, release, or human acceptance.

Every production endpoint is documented in
`docs/CURRENT_BACKEND_CONTRACT.md`. Remaining backend seams are classified in
`docs/BACKEND_GAPS.md`, and cross-product completeness is tracked in
`../../docs/MASTER_COVERAGE_LEDGER.md`.

## Quick start

```bash
npm install
npm run dev          # mock adapter (deterministic seed data) → http://localhost:3000
npm run build        # production build → dist/ (HTTP adapter, service-eligible)
npm run build:demo   # static demo build → dist-demo/ (mock adapter, isolated)
npm run preview      # serve the production build locally → http://localhost:4173
npm run preview:demo # serve the isolated demo build locally
```

- `npm run dev` starts Vite on port **3000** (see `server.port` in
  `vite.config.ts`) with the mock adapter: realistic seed data, simulated
  latency, full feature set, Scenario Lab enabled.
- `npm run build` type-checks (`tsc -b`) and emits a static bundle to
  `dist/`. Production builds are bound to the **http** adapter, emit
  `dist/stateport-build.json`, and expect to be served same-origin by the
  StatePort service. A mock override makes this build fail.
- `npm run build:demo` builds with `--mode demo`, which loads `.env.demo`
  (`VITE_STATEPORT_ADAPTER=mock`) and emits `dist-demo/` with its own
  machine-readable mock/demo identity. It cannot replace or empty `dist/`.
  This artifact needs no backend and is suitable for design review and
  screenshots; AppServer will not accept it as the product build.
- Public-safe StudyState captures opt into the existing demo route with
  `?capture=studystate`; this fixes the mock clock and reset/send identities
  without changing the HTTP or production path. The `stateport-build.json`
  marker remains the source commit/tree provenance for the captured build.

## Scripts

| Script | What it does |
|---|---|
| `npm run dev` | Vite dev server on :3000, mock adapter, HMR. |
| `npm run build` | `tsc -b && vite build` — type-checked, HTTP-bound production bundle and marker in `dist/`. |
| `npm run build:demo` | `vite build --mode demo` — isolated static mock bundle and marker in `dist-demo/`. |
| `npm run preview` | Serve the production build locally (Vite preview, :4173). |
| `npm run preview:demo` | Serve `dist-demo/` locally for design review. |
| `npm run typecheck` | `tsc -b --noEmit` — strict TypeScript, no emit. |
| `npm run lint` | ESLint over the repo (includes `jsx-a11y` rules). |
| `npm run test` | Run the complete current Vitest unit/contract/component suite. |
| `npm run test:watch` | Vitest in watch mode. |
| `npm run test:e2e` | Playwright suite across the validation viewports; builds and previews the isolated demo artifact on `STATEPORT_E2E_PORT` (default `4173`). Requires `npx playwright install chromium` once. |
| `npm run test:build-isolation` | Starting from a production build, builds demo mode, proves `dist/` stayed byte-identical, checks both markers, and proves production+mock is refused. |
| `npm run test:live-core-browser` | Rebuild the HTTP artifact and run the real-AppServer core workflow browser fixture. |
| `npm run screenshots` | `playwright test --grep @screenshots` — the responsive screenshot matrix (route matrix × light/dark + scenario + mobile states; committed PNGs under `docs/screenshots/`). |
| `npm run check:frontend` | `typecheck` + `lint` + `test` in one gate. |
| `npm run check:dependencies` | Validate the complete installed tree, prove removed direct packages stay unimported, prove every retained generated UI module is reachable, and verify the documented mock-persistence boundary. |

Vitest's host-safety invariant applies to full, watch, and focused runs: one or
two isolated fork workers, with at most two concurrent tests per worker.
Playwright uses the same one-or-two-worker ceiling across the viewport matrix.

The Playwright project matrix covers 1440×900, 1280×800, 1024×768,
768×1024, 430×932, 390×844, 360×800, and 320×568. The mock/demo suite owns
wide responsive and scenario coverage; `test:live-core-browser` and
`test:canonical-source-browser` are separate real-AppServer gates. Axe
checks reject serious and critical findings on the executed routes. Record
the exact current-head test counts in `docs/EVIDENCE_LOG.md`, not here.

## Architecture map

```
 ┌───────────────────────────────────────────────────────────────────────┐
 │ Routes (HashRouter, lazy)           src/App.tsx                       │
 │   #/applications #/catalog #/sources #/statebench #/approvals #/settings│
 │   #/app/:id  /conversation  /runs  /settings  /receipts/:receiptId     │
 │   #/app/:id/workbench{,/files,/terminal,/deployments,/orchestration,  │
 │                       /receipts}                                      │
 │   legacy hashes (#home, #app/<id>, …) normalized in src/legacyRoutes  │
 ├───────────────────────────────────────────────────────────────────────┤
 │ Features (one folder per surface)     src/features/*                  │
 │   applications · catalog · approvals · settings · app-overview        │
 │   conversation · files · terminal · infrastructure · orchestration    │
 │   receipts · workbench · bridge (cross-tool hand-off store)           │
 ├───────────────────────────────────────────────────────────────────────┤
 │ Shell                                 src/shell/*                     │
 │   AppShell (sidebar/rail/drawer + topbar + status-bar slot)           │
 │   WorkbenchShell + WorkbenchSlots (panel regions, presets, focus)     │
 │   CommandPalette + command registry · KeyboardShortcuts · ScenarioLab │
 ├───────────────────────────────────────────────────────────────────────┤
 │ Client boundary (typed, the ONLY data seam)   src/client/             │
 │   client.ts   — StatePortClient: typed domain client interfaces       │
 │   types.ts    — domain types + ClientError(network|http|validation|   │
 │                 unavailable|not_implemented)                          │
 │   schemas.ts  — zod runtime validation at the boundary                │
 │   index.ts    — getClient(): adapter selection, singleton             │
 ├───────────────────┬───────────────────────────────────────────────────┤
 │ Mock adapter      │ Http adapter (production)                         │
 │ src/client/mock/  │ src/client/http/                                  │
 │ deterministic     │ transport.ts  — same-origin fetch, CSRF, 401      │
 │ seed, simulated   │   refresh+retry, envelope normalization           │
 │ latency, Scenario │ endpoints.ts  — every path, centralized           │
 │ Lab behaviors,    │ mappers.ts    — wire→domain, fail-closed          │
 │ localStorage      │ domains*.ts   — domain clients over the transport │
 │ persistence       │ terminalSocket.ts — authenticated WS protocol     │
 └───────────────────┴───────────────────────────────────────────────────┘
```

Rule: route components and stores **never** call `fetch` directly. All data
flows through `getClient()`; every response is zod-validated at the adapter
boundary; unknown or malformed data fails closed.

## Adapter selection

| Situation | Adapter used |
|---|---|
| `VITE_STATEPORT_ADAPTER=mock` or `=http` during `npm run dev` | The explicit development adapter is used. |
| `npm run dev` (development build), env unset | `mock` |
| `npm run build` | `http`; an explicit `mock` override is refused. |
| `npm run build:demo` | `mock` (forced by `.env.demo`); an explicit `http` override is refused. |

Selection happens once in `src/client/index.ts` (`getClient()`); the two
adapters are never mixed — in http mode the mock adapter is never
constructed, and mock data never leaks into production fallback behavior.
`stateport-build.json` makes the distributable and source identity
machine-readable. AppServer requires the strict
`stateport.web-build/v3` production/HTTP marker before selecting the real
`apps/web/dist`. The marker carries an exact 40-hex source commit/tree pair
when available, a non-authoritative source ref, a dirty boolean, and a
deterministic UTC build time only when `SOURCE_DATE_EPOCH` (direct Vite) or
`STATEPORT_BUILD_SOURCE_DATE_EPOCH` (OCI) is supplied. Missing provenance is
recorded as `unknown` and dirty; it is never manufactured as clean.

### Compose product service

The `stateport-web` Compose service runs this production artifact through the
same loopback-only AppServer as `stateport service start`; it is not a
standalone static server. AppServer owns `index.html`, the reviewed
Vite-manifest asset allowlist, `/session`, `/v1/*`, and the terminal WebSocket
on the single `http://127.0.0.1:8080` origin.

Compose is a local development/self-hosting shape and must be started from an
ordinary Git clone. It mounts only that clone's `.git` metadata read-only so
AppServer can record the exact runtime repository identity; repository history
is not copied into the OCI image. Durable local application data lives in the
`stateport-product-data` volume, outside the image. The separately named
`stateport-api` service remains the bounded governed-API development surface;
the browser does not use it as a fallback or second frontend backend.

OCI builds deliberately do not copy `.git`. Release/CI callers can bind the
artifact and OCI labels to reviewed source evidence by supplying:

```bash
STATEPORT_BUILD_SOURCE_COMMIT=<exact-40-hex-commit> \
STATEPORT_BUILD_SOURCE_TREE=<exact-40-hex-tree> \
STATEPORT_BUILD_SOURCE_REF=<display-ref> \
STATEPORT_BUILD_SOURCE_DIRTY=false \
STATEPORT_BUILD_SOURCE_DATE_EPOCH=<non-negative-seconds> \
podman compose build stateport-web
```

Omit these only when an honest `unknown` + dirty artifact is acceptable.
`sourceRef` is metadata and never substitutes for the commit/tree pair.

## Documentation

| Document | Contents |
|---|---|
| `docs/INTEGRATION_MANIFEST.md` | Canonical replacement outcome, build/runtime wiring, verification order, rollback, and acceptance checklist. |
| `docs/CURRENT_BACKEND_CONTRACT.md` | Every production endpoint the http adapter uses: paths, methods, shapes, format versions, validation assumptions (⚠️-marked), consuming UI surface. |
| `docs/STATEWARE_CONTEXT.md` | The Stateware paradigm this UI implements: application boundary, canonical state vs projections, governed lifecycle, execution modes, context compilation, receipts. |
| `docs/BACKEND_GAPS.md` | Features with typed seams but no current backend contract — proposed capability IDs, contracts, and why they stay hidden in production. |
| `docs/DESIGN_SYSTEM.md` | The binding design contract: tokens, themes, the 7-state semantic status layer, layout, components, accessibility. |
| `docs/COMPETITIVE_POSITIONING.md` | How the product meets the strong agent-workspace baseline and where StatePort is stronger. |
| `docs/PRODUCT_DECISIONS.md` | Significant product/architecture decisions and their rationale. |
| `docs/BACKEND_INTEGRATION.md` | Developer how-to: mock vs live service, env vars, drift reconciliation, adding an endpoint. |
| `docs/SHORTCUTS.md` | Complete keyboard shortcut reference, rebinding, IME safety. |

## Layout of the package

```
├── index.html · vite.config.ts · tailwind.config.js · playwright.config.ts
├── src/
│   ├── main.tsx · App.tsx · legacyRoutes.ts · semantic.ts
│   ├── client/        # typed boundary + mock/http adapters (above)
│   ├── components/    # shared UI (StatusBadge, EmptyState, Drawer, …)
│   ├── features/      # one folder per product surface (+ __tests__)
│   ├── shell/         # AppShell, WorkbenchShell, palette, shortcuts
│   ├── state/         # zustand stores (workspace, shortcuts, session)
│   ├── styles/        # tokens.css — the design tokens (4 themes)
│   └── test/          # test setup
├── tests/e2e/         # Playwright demo/responsive suite (a11y + screenshot matrix)
└── docs/              # the documents above (+ screenshots/ — committed matrix PNGs)
```
