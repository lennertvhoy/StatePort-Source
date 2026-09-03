# ADR-0006: StatePack portability envelope and export profiles

**Status:** accepted; bounded application envelope implemented, complete export journey open
**Date:** 2026-07-28
**Backlog:** BL-STATEPACK-EXPORT-001

## Context

StatePort already implements two relevant foundations:

- `statepack/v1` is deterministic, disposable model context compiled from
  StateSpec through StateIR. It is noncanonical working memory.
- `stateport.instance-portable/v1` exports canonical instance files with safe
  paths, file/archive digests, dry-run import, expected-digest checks,
  re-identification, and explicit capture consistency while excluding Git,
  runtime data, StatePort internals, and engine sessions.

The requested export capability is broader: it must transport reusable
applications, private instances, derived deployments, agent-facing
interfaces, capability and secret requirements, provenance, and conformance
proof. A collection of platform-specific exporters would fragment those
semantics and create multiple sources of truth.

## Decision

StatePort will extend its existing StatePack and portable-instance contracts
with one versioned **StatePack distribution envelope**. StatePack is the
product-family name; existing `statepack/v1` keeps its exact meaning as
disposable compiled context. A future distribution schema must use a distinct
format identifier and typed `kind`; it may not silently reinterpret
`statepack/v1` or `stateport.instance-portable/v1`.

The envelope composes standards-based interfaces and artifacts around
StatePort-owned lifecycle semantics. Platform and cloud targets are derived
profiles over the same package, never canonical application forks.

### Package kinds

1. `stateport.application` is reusable and distributable. It contains an
   application descriptor, schemas, trusted declarative UI, actions,
   workflows, migrations, validation, requested capabilities, safe defaults,
   public documentation, agent instructions, and interface declarations. It
   contains no personal instance state.
2. `stateport.instance` is private and user-owned. It contains durable state,
   local history, receipts, approvals, application-version binding, and
   migration position. Publication as an application template is forbidden by
   default. The existing portable-instance contract is its starting point.
3. `stateport.deployment` is derived and replaceable. It contains or references
   an OCI image, runtime configuration, health and storage contracts, network
   policy, secret references, deployment profile, provenance, and SBOM. It is
   never the source of application or user truth.

Secrets are typed requirements and references only. No secret value, provider
credential, personal learner data, machine path, transcript, runtime cache, or
engine session belongs in a distributable application or deployment package.

### Standards composition

The envelope owns durable StatePort identity, ownership, transition,
approval, migration, Undo, capability-degradation, and receipt semantics. It
may include version-pinned declarations for:

- MCP tools, resources, and prompts;
- an A2A agent card for a running remote-agent interface;
- an OpenAPI description for the application HTTP API;
- OCI images and associated provenance artifacts; and
- an SPDX SBOM.

These standards are interfaces within the envelope. None replaces StateSpec
state, StatePort policy, or acceptance authority. Exact specification versions
and validators are selected and pinned during implementation rather than
claimed by this ADR.

### Export profiles

The initial profiles are:

- `stateport-native`: full governed StatePort lifecycle and normal import;
- `agent-package`: repository, schemas, `AGENTS.md`, declared actions, and
  optional MCP/A2A interfaces with honest capability degradation; and
- `standalone-web-oci`: a minimal web runtime, durable local volume, OpenAPI,
  one declared execution adapter, and Compose-first self-hosting without the
  full development Workbench.

Kubernetes, managed clouds, registries, serverless targets, hosted StatePort,
and static/read-only exports remain later adapters. “Deploy anywhere” is not
an initial claim.

## First slice

`BL-STATEPACK-EXPORT-001` exports the fictional public-safe StudyState
application deterministically, previews inclusions/exclusions, crosses the
Sensitive Data Gateway, validates schemas and checksums, imports into a clean
second StatePort root, runs the native journey, builds and runs the standalone
OCI profile, and asks StateBench to compare semantic receipts. Acceptance
requires equal approved-plan and Undo digests, clean rollback and migration
planning, no secrets/PII/transient state, validated included interfaces, OCI
SBOM/provenance, and explicit degradation. Human acceptance remains separate.

This first slice does not include arbitrary frontend frameworks, real private
learner export as a public template, embedded credentials, automatic
publication, a marketplace, every cloud provider, or provider behavioural
equivalence.

## Relationship to prior Agent Kits direction

`BL-STATEPACK-EXPORT-001` supersedes the separate `BL-AGENT-KITS-001` package
direction. The valid template-first, permission-intersection, OCI, provenance,
and no-personal-state constraints survive as requirements of the
`agent-package` profile. StateBench remains independent of package trust while
evaluating exact package configurations for portability conformance.

## Sequencing

The bounded implementation delivers a distinct deterministic application
envelope, preview/export/inspect, schema and CLI, no-replace archive safety, and
dry-run/atomic import into a new destination. It reserves but does not implement
private-instance or deployment exporters. The standalone OCI profile is
truthfully `declared_not_built`; no OCI image, Compose runtime, SBOM,
provenance, MCP, A2A, or OpenAPI artifact is included. Sensitive Data Gateway
publication enforcement and the native/standalone semantic journey remain
required before the complete first-slice acceptance can be claimed.
