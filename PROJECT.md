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

## Scope

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
- Additive Alpha.14 release artifacts; all earlier published bytes remain
  immutable.

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
