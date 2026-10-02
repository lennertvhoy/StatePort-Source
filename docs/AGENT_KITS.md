# Agent Kits — superseded direction, retained for design history

**Current decision (2026-07-28):** ADR-0006 and
`BL-STATEPACK-EXPORT-001` supersede a separate Agent Kit package. The useful
template-first, capability-intersection, OCI, provenance, and no-personal-state
constraints below now belong to the `agent-package` StatePack export profile.
A bounded StatePack application exporter and declared profile manifest now
exist; no standalone runtime profile is built. This document remains as design
history and must not be read as an active parallel packaging architecture.

## Why this direction exists

StatePort templates already describe durable application behavior, while the
runtime, policy, and host adapter decide how that behavior is executed. An
**Agent Kit** would make that useful as a small, installable, modular package:
one reviewed use case, an exact template release, an explicit runtime profile,
and a governed way to invoke it from an application, terminal, or supported
chat client.

This is the open, portable counterpart to the convenience people seek from
managed agent studios. It must not become a prompt marketplace, a second
benchmark product, or a way for templates to smuggle arbitrary code,
permissions, credentials, or browser behavior into an installation.

**Historical status:** originally planned as `BL-AGENT-KITS-001`; now
superseded by `BL-STATEPACK-EXPORT-001`. A bounded StatePack application
distribution schema and CLI foundation now exist; no separate Agent Kit,
registry, OCI runtime image, public export flow, or user-facing install exists.

## Product shape

An Agent Kit is an immutable, release-bound descriptor with four separate
layers:

| Layer | Owns | Must not own |
| --- | --- | --- |
| Template release | Domain workflow, declarative views, requested capabilities, deterministic self-tests | Operator policy, credentials, arbitrary frontend code |
| Kit manifest | Exact source identity, entry points, compatible runtime profile, public metadata, integrity data | Mutable instance state, secrets, a claim that the host is equivalent |
| Instance | Personal state, explicit grants, local overrides, audit and receipts | Canonical template content or an implicit template upgrade |
| Runtime adapter | Actual host capability, authentication route observation, sandbox and degradation declaration | Canonical state authority, policy grants, private template content |

The export should be **template-first by default**. It produces a kit that can
instantiate an owned application; it does not silently copy a user's instance,
conversation, source files, credentials, or private evidence. A separately
governed backup/export path is required for personal-state movement.

## Proposed package contract

The eventual manifest is intentionally small and inspectable. A draft shape:

```yaml
formatVersion: stateport.agent-kit/v1
kit:
  id: study-review
  version: 0.1.0
  purpose: guided-review
template:
  source: immutable-release-reference
  commit: exact-commit
  manifestDigest: sha256:...
runtime:
  profile: host-neutral-profile-id
  requiredCapabilities:
    - conversation
    - bounded-context
policy:
  requestedCapabilities:
    - read_application_state
  grants: resolved-at-install-time
entrypoints:
  - id: review
    kind: declared-action
integrity:
  manifestDigest: sha256:...
```

This is a design sketch, not a schema. Installation would resolve the source
again, intersect template requests with instance grants and operator policy,
and create a receipt. A template cannot grant itself a permission merely by
appearing in the kit.

## Docker-first distribution, later

For the first public release shape, a kit may eventually have a Docker/OCI
delivery profile. The image is a replaceable runtime artifact, never the home
of durable StateSpec data or credentials. A user must be able to inspect the
manifest, mount their owned instance deliberately, and choose a supported
execution host without the kit rewriting their workflow files outside a lease
and transaction.

The first supported distribution story is therefore deliberately narrower
than a general app store:

1. A template maintainer publishes an immutable, public release.
2. StatePort verifies source identity, manifest, policy, and declared
   self-tests, then produces a reviewable kit candidate.
3. An operator reviews exact runtime capabilities and grants; a release tag or
   image digest binds the published kit.
4. A user installs a fresh instance or explicitly imports a separately
   governed backup.
5. StatePort records installation, run, validation, and closure receipts.

Development candidates may be exported for isolated test evidence only. They
must be labelled non-production, must not become a public install source, and
must never inherit release trust from a matching version number.

## Independence from StateBench

An Agent Kit must be useful without a benchmark. StateBench may later evaluate
an exact kit configuration as one input to a controlled comparison, but it
does not create the kit, grant permission, select a winner, or turn a local
test into a public release claim. The complete configuration would still need
to name the template release, kit manifest, runtime adapter, host version,
model, auth route, sandbox, tools, and context policy.

## Required design and acceptance gates

Before implementation begins, this direction needs all of the following:

- the P0 release freeze resolved for the active exact implementation line;
- an ADR and versioned schema with public and private fixture rules;
- an explicit OCI/Docker provenance and signing decision, without durable
  data or secrets in image layers;
- a threat model for third-party templates, registry intake, capability
  escalation, secrets, update/revocation, and untrusted runtime adapters;
- an ownership-aware install, update, export, import, and rollback contract;
- at least one public-safe fixture and a no-StateSpec baseline for any future
  benchmark claim; and
- end-to-end validation on an exact release candidate, including agent-native
  CLI use, the application surface, a declared degraded host, and human
  acceptance.

Until those gates exist, the right public description is an **Agent Kits
roadmap**, not a product feature or a download.
