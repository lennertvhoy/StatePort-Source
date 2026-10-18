# Naming

> Public vocabulary and compatibility rules for StatePort.

## The category

**Stateware** is software whose durable, inspectable state and governed
lifecycle contracts form the application boundary while agents and models
remain **opinionated execution providers** — declared per host through
capability profiles, not interchangeable processors. Behaviour, guarantees, and
evidence shape differ across hosts and are not equivalent.

**State-Centric Engineering** (SCE) is the engineering practice behind
Stateware: canonical state, explicit authority boundaries, reproducible
execution, and evidence-backed closure.

## The portable specification

**StateSpec** defines portable files, schemas, ownership rules, lifecycle
contracts, context compilation, validation, and evidence requirements for a
Stateware application.

StateSpec was formerly called **StateDD**. `StateDD` remains a compatibility
identifier in existing schema IDs, format versions, packages, paths, source
locks, and receipts until separately versioned migrations retire each use.

## Product names

| Public name | Meaning | Compatibility name |
|---|---|---|
| StatePort | Runtime, package ecosystem, and lifecycle platform | unchanged |
| StateBench | Evaluation system | unchanged |
| StatePack | Compiled task context | unchanged |
| StateIR | Normalized state representation | unchanged |
| StateSpec Template | Portable application-template contract | StateDD Template |
| StudyState | Learning application/template | StudyDD |
| ClassState | Classroom application/template | ClassDD |
| InfraState | Infrastructure application/template | InfraDD |
| ProjectState | Project application/template | ProjectDD |
| ClientState | Client application/template | ClientDD |
| LifeState | Personal-life application/template | LifeDD |
| ChecklistState | Checklist application/template | ChecklistDD |

## Migration rule

Public names change first. Existing repository names, remotes, schema and
format identifiers, package/import names, filesystem paths, commands,
environment variables, persisted records, and Git history remain compatible
until a versioned migration proves dual-read behavior and rollback.

The machine-readable authority is
[`config/terminology-policy.yaml`](../config/terminology-policy.yaml). The
architectural decision and rationale are recorded in
[`ADR-002`](adr/ADR-002-stateware-public-naming.md).

Every remaining legacy occurrence must be classified as one of:

- compatibility alias;
- machine identifier;
- historical record;
- legal text;
- archived reference.

Unclassified legacy wording in a current public or operator surface is a
migration defect. Historical evidence and legal text are not silently
rewritten.

## Public product name

**StatePort** remains the candidate platform name. It is a working name until
domain, GitHub, EUIPO/Benelux trademark, company-name, and common-law checks
are complete.

Do not claim legal or regulatory certification. Use bounded language such as
“designed for GDPR-conscious European deployments.”

## Internal shorthand

- “StateSpec” is the public specification name.
- “legacy StateDD identifier” means an intentionally preserved compatibility
  identifier, not current public naming.
- “application” is the installed, visible product.
- “instance” is one durable application workspace.
- “template” is a reusable StateSpec definition.
