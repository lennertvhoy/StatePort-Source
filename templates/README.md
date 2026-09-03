# Legacy Bundled Development Sources

This directory contains bootstrap/development inputs for StatePort's current
local lifecycle v1 tests. Directory placement and a valid template manifest do
not make any child a canonical or production-installable source.

Canonical content authorities are external repositories selected through the
rules in the private-internal canonical-template-source-boundary ADR
(`docs/adr/0001`).
Fixture classes and production exclusions are defined in the private-internal
`docs/TEMPLATE_SOURCE_AND_FIXTURE_POLICY.md`.

The former StudyDD-named bootstrap skeleton was moved to the explicit synthetic
fixture boundary at `fixtures/templates/studydd-minimal`. It is not a bundled
template, must not be used for a real instance, and must never be copied from
`StudyDD_Template` or a private instance.
