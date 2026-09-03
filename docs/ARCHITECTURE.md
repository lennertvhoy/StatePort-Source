# StatePort Architecture

> High-level architecture for the StatePort runtime.

For the short product-path diagram and a compact ownership map, start with
[`ARCHITECTURE_OVERVIEW.md`](ARCHITECTURE_OVERVIEW.md). This document remains
the detailed architecture reference.

## Core thesis

StatePort is an application platform for durable, user-owned AI systems that
maintain state, pursue objectives, and operate across sessions. The installed
application is the visible product; runtime and lifecycle machinery normally
stays backstage. Governance — the policy, approval, quota, audit, and receipt
boundary below — is the enabling control layer that makes persistent operation
safe and adjustable; it is not the product outcome.

## Continuous operation and oversight

A Stateware application is built for continuous, supervised operation: it
observes relevant changes, plans work, performs permitted actions, evaluates
outcomes, and adapts over time, while remaining interruptible, inspectable, and
receipted. The user stays in control without approving every routine, reversible
step.

Oversight is a **per-action policy**, not a permanent label on an app or on the
platform. One application may run routine reorganisation autonomously, ask for
confirmation before a consequential change, and prohibit an external side effect
unless explicitly approved. The spectrum and its mechanism mapping are defined
in [`POSITIONING.md`](POSITIONING.md) and `PROJECT_DNA.yaml`
(`application_oversight_model`):

- **Human-driven** — assists only when requested.
- **Human-in-the-loop** — stops at defined approval gates.
- **Human-on-the-loop** — operates continuously under supervision, with pause,
  redirect, undo, budgets, exception notifications, and receipts. This is the
  normal experience for assistive domain applications.
- **Bounded autonomy** — acts independently inside explicit permissions,
  budgets, and escalation rules; the normal target for engineering/automation
  applications. This is a declared future capability, distinct from unattended
  autonomy; the locked product vision remains *no unattended autonomy*.

Canonical template repositories own reusable workflow/domain content. StatePort
owns lifecycle resolution, locking, ownership, policy, audit, and evaluation.
The durable, file-based **StateSpec instance** owns private instance truth.
Execution hosts and wrappers do not own durable state. They are **opinionated
execution providers**, not interchangeable: each host embeds its own behavioural
policies, context management, tool semantics, safety constraints, and lifecycle
assumptions, declared through capability profiles and recorded degradation
rather than assumed equivalent (see [`POSITIONING.md`](POSITIONING.md) §8).

The previous small generic-dashboard decision is superseded by this
application-platform hierarchy. Its history remains in the backlog. The
generic dashboard survives as an advanced platform-operations projection; it
is not the normal user's home. The exact preservation/migration mapping is
validated from `config/functionality-preservation.v1.yaml`.

## Execution provider layers

Execution is split into three layers with explicit ownership:

1. **StatePort control plane** — canonical state, objectives, identity and
   authorization, capability grants, budgets, approval gates, validation
   requirements, evidence retention, cancellation intent, and final acceptance.
2. **Harness adapter** — translates the StatePort execution contract to a
   particular host, declares what it can actually guarantee, and records
   explicit degradation where a guarantee is partial or absent.
3. **External execution harness** — Pi, Codex, OpenCode, or another runtime
   performs work under both the StatePort request and its own internal
   behaviour.

Adapters translate a common contract and declare per-provider guarantees; the
adapter seam is a translation boundary, not an interchangeability promise. Prompt
instructions are not a security boundary: critical controls are enforced outside
the host (container/VM isolation, scoped mounts, network denial, short-lived
credentials, process-tree ownership, worktrees, transactional staging), and
StatePort determines acceptance through its own validation rather than the host's
"done" statement.

The binding contract across this seam is the **ownership boundary**
([ADR-0003](adr/0003-application-execution-ownership-boundary.md),
[`POSITIONING.md`](POSITIONING.md) §9): StatePort owns intent, authority,
state, evidence, and acceptance; the harness owns only execution behaviour and
must never silently become the source of truth. Governed runs declare an
explicit execution mode (transactional, supervised direct, or read-only
advisory), authority is reported as declared/effective/observed, receipts
separate harness claims from observed evidence, and harness completion
produces a candidate result — never an accepted one.

## Architecture formula

```
canonical external template source
  -> StatePort resolve / verify / lock / materialise lifecycle
    -> durable StateSpec instance + immutable source lock
      -> StateIR + disposable StatePack
        -> policy / approval / quota / audit boundary
          -> capability-checked execution-host adapter
            -> opinionated execution-host provider (declared capabilities/degradation)
              -> application shell + channel adapters (web / Telegram / CLI)
```

## Components

### 1. Canonical StateSpec Template Source

A template defines:

- Folder structure
- Markdown/YAML schemas
- Lifecycle rules
- Review cadence
- Allowed actions
- Agent contract
- Validation rules
- Domain-specific workflows

`StateDD_Template` remains the compatibility repository identifier for the
StateSpec Template. `StudyDD_Template` remains the compatibility repository
identifier for StudyState domain content. A future template repository owns its own domain
content only after its identity and authority are explicitly designated.

Repository-local source-like inputs are not canonical by location. StatePort
may carry minimal synthetic or narrowly justified compatibility fixtures, but
they are non-production and use the classes defined in the private-internal
`TEMPLATE_SOURCE_AND_FIXTURE_POLICY.md`.
The former StudyState/legacy-StudyDD skeleton is now the explicit synthetic fixture at
`fixtures/templates/studydd-minimal`. It is non-production and cannot claim or
inherit canonical StudyState authority.

### 2. StateSpec Instance

One durable state workspace per user/team/project/class/client.

Contains:

- `instance.yaml` — instance config and template reference
- `state/` — durable state files
- `inbox/` — new inputs awaiting processing
- `actions/` — proposed or executed actions
- `decisions/` — recorded decisions
- `reminders/` — scheduled follow-ups
- `evidence/` — supporting evidence
- `audit/` — audit events

No secrets are stored in the instance folder.

### 3. Headless Runner and Execution Hosts

The runner:

- Reads instance state
- Reads template contract
- Plans changes
- Proposes changes before risky edits
- Edits files only within allowed scope
- Runs validators
- Returns a structured result
- Produces audit events

The runner contract and execution host are replaceable. Pi is the reference
host direction; Codex, OpenCode, direct API, and future hosts must declare
their actual capabilities and degradations. A narrow opt-in local Codex
conversation adapter is merged and wired into the `stateport` CLI wrapper,
using the hardened adapter/process runtime; it was originally evidenced on the
archived `agent/bl-ai-vertical-002` branch and remains a bounded local path,
not a production-qualified host integration. Pi has no adapter or connection
path in the current working tree; see
[`operations/CODEX_PROVIDER_SETUP.md`](operations/CODEX_PROVIDER_SETUP.md).

Supported shapes are sequenced as:

- portable StateSpec contract through files, StatePort CLI, StatePack, and
  deterministic validation;
- capability-negotiated host adapters;
- controlled direct-API execution for CI/benchmarking/managed fallback;
- container or later cloud isolation around, never instead of, durable state.

### 4. Tool Gateway

Controls access to tools:

- Web search
- File operations
- GitHub
- Calendar/mail (future)
- Model providers
- Code execution
- External message sending

Every tool call records:

- Tool name
- Risk level
- Quota impact
- Approval requirement
- Audit event

### 5. Quota Engine

Tracks:

- Runs per day/month
- Messages per day/month
- Token estimates
- Tool calls
- Web searches
- Execution time
- Files touched
- Expensive-model use
- Monthly euro budget estimate

Outcomes:

- allow
- warn
- require approval
- block

### 6. Approval Gate

Risk levels:

- **L0** — read-only
- **L1** — propose-only
- **L2** — local state file edit
- **L3** — external side effect
- **L4** — destructive or expensive action
- **L5** — admin/security/compliance action

Approval required for:

- Sending messages to third parties
- Sending email
- Editing calendar
- Pushing to GitHub
- Deleting files
- Touching many files
- Spending above threshold
- Using expensive models
- Changing secrets
- Changing Terraform/IaC
- Changing access controls

### 7. Audit Log

Every run produces structured events:

- timestamp
- instance id
- actor
- trigger
- files read
- files changed
- tool calls
- approvals requested
- approvals granted/denied
- quota impact
- result
- errors
- validation result

Secrets and full sensitive payloads are redacted by default.

### 8. Wrapper Layer

First wrappers:

- CLI adapter
- Telegram adapter skeleton

The Telegram adapter is thin:

```
Telegram message -> normalized input -> runner request -> approval/result -> Telegram response
```

Telegram and web bind to one StatePort-owned conversation identity. Neither is
the source of truth; typed proposals, approvals, validated transactions, and
receipts remain authoritative. Channel tokens come from environment variables
or a secret store only.

### 9. Application experience shell

Trusted declarative application packages contribute only StatePort-owned
components through this contract:

```text
ApplicationPackage
  -> declares ApplicationExperienceDescriptor capabilities and views
  -> StatePort intersects instance grants, operator policy, runtime support,
     and actor permissions
  -> the application shell renders the application-native experience
  -> advanced controls remain progressively disclosed
  -> platform operations remain separately permission-gated
```

The four presentation layers are application, application-attached
conversation, advanced controls, and platform operations. The default home is
installed-application-first. Packages cannot inject arbitrary JavaScript,
HTML, CSS, routes, permissions, or runtime code.

The Workbench is an optional capability for development applications. xterm.js
is presentation only; the StatePort broker owns local PTY, SSH, optional Herdr,
tokens, limits, and cleanup. StatePort-owned CodeMirror is a responsive
presentation over the application-scoped, symlink-safe, hash- and base-bound,
diff-first file broker; create, rename, delete, and writes never bypass broker
policy or receipt authority. CTO mode is a governed optional goal orchestrator,
defaults to advisory, and cannot approve or independently review its own work.
StateBench is primarily backstage update evidence.

### 10. Control Plane / Dashboard

The local application shell and bounded operator projections are implemented
as foundations. The generic operator plane is not the default home and is not
a hosted or production control plane. Advanced operators may inspect:

- instances
- templates
- users/admins
- quotas
- costs
- approvals
- audit logs
- deployments
- secrets references
- backups/exports

### 11. Azure Deployment

Terraform-managed skeleton targeting a single Ubuntu 24.04 LTS VM with
rootless Podman, ACR, Key Vault, and managed identity (the earlier Container
Apps sketch is superseded; no AKS in the alpha). Offline-validated only — no
live Azure resources exist. See [`AZURE_DEPLOYMENT.md`](AZURE_DEPLOYMENT.md).

## Data flow

1. Input arrives through an application view or channel adapter.
2. StatePort normalizes it into the shared application conversation or a typed
   job/proposal; adapters never write canonical files directly.
3. The runner reads the exact instance state and template contract.
4. StatePort checks capability, path, lease, base, tool, and risk boundaries.
5. Quota and policy evaluate budget, permissions, and external effects.
6. The approval gate blocks or escalates risky actions.
7. The runner executes only the approved bounded action; canonical writes use
   validation and transaction contracts.
8. StatePort emits receipts and bounded audit metadata.
9. Application and bound channels receive the authorized result projection.

## Trust boundaries

- **StatePort lifecycle engine** — resolves, verifies, locks, plans, and governs;
  it does not own external template content.
- **Canonical template source** — authoritative only for its designated template
  ID and cannot grant permissions or define authoritative evaluation.
- **Private instance** — owns durable user/project truth and explicit overrides;
  it is never an implicit public contribution source.
- **Generated StatePack** — disposable context derived from named canonical
  inputs, never durable truth.
- **Execution host / model provider** — backend-specific loop and model service;
  cannot override instance policy, approvals, locks, audit, or evidence.
- **Agent sandbox** — runner process/container; must not have unlimited network
  or host access and never becomes durable storage.
- **Remote source provider** — transports repository/ref objects; mutable refs
  require immutable resolution and digest verification.
- **Telegram or another wrapper** — external interface; no durable domain state.

**Isolation principle:** environmental isolation enforces boundaries that cannot
depend on agent or host compliance. The harness is assumed capable of
misunderstanding or ignoring behavioural instructions; container/VM isolation,
scoped filesystem mounts, network denial, short-lived credentials, and
process-tree ownership enforce the important boundaries regardless. Prompt
instructions are not a security boundary.

## Source-of-truth rules

- The designated canonical repository is the source of truth for reusable
  template content.
- The instance folder is the source of truth for private instance content,
  preferences, extensions, and explicit overrides.
- The StatePort lock is the source of truth for the exact installed upstream
  identity and installed hashes.
- Generated files, caches, host sessions, and benchmark adapters are not source
  authorities.
- Chat history is not the source of truth.
- Telegram state is not the source of truth.
- Agent memory is not the source of truth.
- All durable changes must be reflected in instance files and audit events.

## Local vs cloud runtime boundaries

Local mode:

- Runner runs directly on the developer machine.
- Instances are local folders or git repos.
- Secrets come from environment variables.
- Good for development and single-user demos.

Cloud mode (future):

- Runner runs in Azure Container Apps.
- Instances may be backed by Azure Storage or git volumes.
- Secrets come from Azure Key Vault.
- Admin dashboard manages instances and approvals.

## Wrapper boundaries

Wrappers:

- Receive external input
- Normalize it
- Write to `inbox/`
- Trigger the runner
- Return a response

Wrappers must not:

- Store durable domain state
- Bypass approval gates
- Log secrets
- Make direct tool calls outside the runner

## Anti-overbuild rules

- Do not build a full SaaS yet.
- Do not build the dashboard yet.
- Do not build billing yet.
- Do not deploy Azure resources yet.
- Do not run `terraform apply`.
- Do not use real API keys.
- Do not store secrets in repo files.
- Do not build brittle keyword-routing logic.
- Do not build a giant chatbot app.
- Do not hide source of truth in chat history or agent memory.
