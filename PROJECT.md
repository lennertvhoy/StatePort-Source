# StatePort

## User

The primary user is a student or project owner on a fresh Windows 11 machine
with Ubuntu 24.04 under WSL2. They should not need to understand StatePort's
release machinery, container internals, or repository layout.

## Outcome

The user visits the StatePort site, reads clear and accurate documentation,
copies one installer command into fresh Ubuntu WSL, and gets a complete working
StatePort. From the product UI they can import and use the real ProjectState and
StudyState templates and any other template that satisfies the supported public
template contract. The API, worker, execution host, persistence, restart, and
template actions work together; success is not limited to a compiled frontend.

## Owner acceptance additions — 2026-09-05

The next product session must establish both UI correctness and UI completeness.
Every visible feature must work through its real backend/orchestration effect,
including durable state and failure/recovery behavior. Separately, all operations
needed for the supported product journey must be available in the UI. Inspect
container/workspace lifecycle controls, coding-agent/provider selection and
management, orchestration, approvals, execution, results and recovery explicitly.
An API or CLI capability alone does not satisfy a required UI operation. Inventory
supported and intended agents/providers; record missing implementations or controls
honestly rather than silently shrinking the supported product to what already works.

The product must run efficiently on a decent office laptop: a decent general-purpose
CPU, 16 GB total system RAM, SSD storage and integrated graphics. No discrete GPU
may be required for the supported product journey. Exact CPU and free-disk figures
are not specified. Measure the complete installed stack, including WSL/container
and browser overhead, idle and representative active workloads, CPU, memory, swap,
disk growth and responsiveness. Leave usable capacity for ordinary office work;
do not treat all 16 GB as StatePort's memory budget. Identify and remove unnecessary
services, polling, duplicate work and unbounded concurrency using measurements.
Resource reductions must preserve functionality, persistence and isolation.

A dependable anonymous installer remains a foundation of acceptance. Agent-owned
UI and efficiency checks must ultimately run against the complete installed product;
a developer environment alone does not establish readiness. Routine qualification
stays on the workstation using bounded virtualization/containers, not the owner's
work laptop. The hardware target is a product requirement, not a claim of measured
compatibility or authorization to move tests to that laptop.

## Scope

Owner execution directive, 2026-09-05: prepare the next session as a sustained
orchestrator with bounded parallel work until 2026-09-06 07:00 Europe/Brussels
(05:00 UTC). Prioritize complete application workspace management, qualified
provider execution, installed UI journeys and measured office-machine resource
use. The execution plan is in `evidence/one-line-release-001/overnight-handoff.md`;
this time window does not relax product acceptance or authorize unqualified release.

- Excellent public documentation centered on the supported user journey.
- One anonymous, integrity-checked installer command for Windows 11 + WSL2 +
  Ubuntu 24.04 AMD64.
- A working web UI, control API, worker, execution host, persistent state, and
  reboot survival.
- A general external-template lifecycle: resolve or select source, validate,
  materialize an isolated instance, register it, expose honest capabilities and
  actions, execute approved work, persist results, and recover safely.
- Proven journeys for the actual ProjectState template, actual StudyState
  template, and an independent third valid template.
- Additive Alpha.15 release artifacts; all earlier published bytes and the
  unpublished defective Alpha.14 candidate remain immutable.
- Owner-authorized 2026-09-05 continuation targets the already-published
  Alpha.16 successor for the local public rehearsal, preserving Alpha.15 and
  Alpha.16 bytes and all native complete-product acceptance boundaries.

## Non-goals

- Calling a frontend build, unit-test count, synthetic fixture, staged installer,
  or simulated WSL identity a completed product.
- Replacing the strict one-line installation requirement with Docker Compose,
  a developer checkout, manual dependency setup, or a second launcher.
- Supporting WSL1, native Linux, macOS, or arbitrary untrusted template behavior
  in this slice.
- Claiming human acceptance, independent audit, stability, or production
  qualification without the corresponding evidence.
- Workflow machinery, counters, control-head rebinding, or release ceremony that
  does not reduce a user-visible uncertainty.

## Durable constraints

- ProjectState coordination files are never application runtime dependencies.
- Published versioned/signed artifacts are immutable and provenance remains
  exact from source tree through installed runtime.
- Templates never grant themselves authority. Requested capabilities must be
  intersected with explicit instance/operator grants.
- No browser or public client receives a host control socket, signing secret, or
  third-party subscription credential.
- Destructive, privileged, external, and non-idempotent effects fail closed and
  remain attributable.
- Qualification distinguishes the genuine fresh Windows 11 WSL2 Ubuntu 24.04
  path from QEMU, staged transport, prepared hosts, and local development.
- The human owns these outcome and acceptance boundaries. Agents may make them
  more observable but may not weaken them.
