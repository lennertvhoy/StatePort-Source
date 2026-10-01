# ADR-002: Stateware public naming and StateSpec compatibility

Status: accepted for public terminology; physical-identifier migration remains staged.

## Decision

The product category is **Stateware**. The engineering method is
**State-Centric Engineering** (SCE). The portable application specification is
**StateSpec**.

The public application names are **StudyState**, **ClassState**,
**InfraState**, **ProjectState**, **ClientState**, **LifeState**, and
**ChecklistState**. StatePort, StateBench, StatePack, and StateIR keep their
names.

Stateware means software whose durable, inspectable state and governed
lifecycle contracts form the application boundary while agents and models
remain replaceable processors. State-Centric Engineering is the practice of
building that software around canonical state, explicit authority,
reproducible execution, and evidence-backed closure.

## Compatibility boundary

This decision changes public and current architectural language. It does not
authorize an uncontrolled physical rename. Existing identifiers continue to
work through explicit aliases, including:

- `statedd-template-v5`, `.statedd`, `.studydd`, and existing format versions;
- schema IDs, repository names, remotes, branches, and Git history;
- package/import/module, CLI, environment-variable, and database identifiers;
- source locks, receipts, bundles, fixture IDs, release digests, and backlog
  IDs.

New presentation metadata carries a public name, legacy names, and
compatibility status. Advanced identity views may show a legacy machine ID as
such; normal application views use the public name.

The migration gate is not a zero-result text search. Completion requires no
unclassified legacy term in a current public or operator surface. Every
remaining occurrence must be classified as a compatibility alias, machine
identifier, historical record, legal text, or archived reference.

Legal wording, repository renames, schema/version changes, and executable
identifier migrations require separately reviewed changes with dual-read
compatibility, rollback, and deprecation evidence.

## History

Earlier project decisions used “StateDD,” “State-Driven Development,”
“StudyDD,” and “ClassDD.” Those records remain historically accurate. Current
documentation may say “StateSpec, formerly called StateDD” where continuity
matters, but new public copy uses the new vocabulary.
