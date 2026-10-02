# Lifecycle Manifest v2

**Status:** implemented local contract plus immutable Git resolution and
transactional upgrade proof; remote CI acceptance remains separate
**Backlog:** BL-STUDYDD-ADOPT-001

## Normalized model

The compatibility schema ID `statedd.template-manifest/v2` keeps template
identity separate from source resolution. `template` contains the stable
template ID, release version, StateSpec version, and instance-schema version.
`formatVersion`
identifies the manifest format itself. A local checkout path, source digest,
and a future resolved commit are represented by the source descriptor and the
instance lock, never by mutable template identity metadata.

`modules` are the normalized selection unit. They have stable IDs, contract
versions, dependency and conflict lists, capability requests, asset selections,
self-test declarations, and deterministic dependency-first ordering.
`selectedModules` is resolved without executing manifest-provided code.

`assets` declare exact `file` paths or explicit `tree` paths. Every selected
asset records owner, role, provision policy, update policy, required status,
schema, sensitivity, generator/composer identifier where applicable, and its
selecting modules. Owners are exactly `template`, `instance`, or `generated`.
Exact/tree collisions, duplicate paths, cyclic/unknown module dependencies,
module conflicts, unsafe paths, unsafe source symlinks, and unsafe destination
symlinks fail closed.

An external `<domain>.instance-layout/<version>` identity is not accepted as
an arbitrary schema escape. Its required template-owned layout contract is
size-bounded, duplicate-key-safe YAML with one declared mode-marker and
validation mapping. Its required instance descriptor and bootstrap contract
must be exact, file-shaped, owner-correct assets. Instance validation checks
the domain mode marker and validates the complete descriptor against the exact
bootstrap document from the pinned template; undeclared domain fields or
malformed values fail closed.

The optional instance record `.statedd/overrides.yaml` uses
`statedd.instance-overrides/v1`. An ejection names one template-owned exact
file and a reason. It becomes instance-owned for classification and is excluded
from automatic upstream replacement. This is validation and normalized state,
not semantic merge resolution.

## Compatibility

v1 files are read without being rewritten. The deterministic normalizer adds
the common identity shape and explicitly reports v1 limitations: no source
class/install eligibility, modules, owned trees, or explicit ejections. v1
materialisation and lock behavior remain compatible.

For v2 local-development sources, `statedd.source/v2` records source class,
production eligibility, checkout location, content digest, and a null
`resolvedCommit`. The null is deliberate: this slice performs no Git resolution
or fetching. v2 locks additionally retain manifest/spec/schema versions and
the selected module list.

## Materialisation support matrix

| Declared strategy | Current behavior |
|---|---|
| Exact template file: `copy_from_template` + `replace_if_unmodified` | Implemented; copied and locked. |
| Exact instance file: `create_if_missing` + `preserve` | Implemented. |
| Exact generated file: `generated_output` + `generated`, generator `materializer` | Implemented for the lifecycle lock. |
| Instance tree: `create_if_missing` + `preserve` | Implemented; created once and preserved. |
| `composed_output` / `compose` | Declared and parsed, but rejected before writes. |
| `schema_migration_intent` / `schema_migrate` | Declared and parsed, but rejected before writes. |
| `append_only_state` / `append_only` | Declared and parsed, but rejected before writes. |
| `retire` | Declared and parsed, but rejected before writes. |
| Arbitrary deep merge, prose composition, upgrade apply, Git source resolution | Unsupported in this slice; no fallback behavior. |

Manifest-level production selection accepts only a v2 `canonical_source` with
`productionEligible: true`. That declaration is necessary but not sufficient:
the StatePort canonical catalog must also identify a verified immutable release
tag and grant release trust. Synthetic and compatibility fixtures are rejected
even when their manifests otherwise validate, and a `development_candidate`
catalog observation remains production-unavailable even when its upstream
manifest is canonical-source shaped.

## Canonical release catalog boundary

`sources/canonical/studydd.yaml` is strict, tracked catalog metadata. It records
the stable StatePort source/application identity, legacy identifiers, remote
content authority, immutable release-ref policy, expected manifest contract,
required modules and self-tests, derived trust/installability, and bounded
observations. It is neither a checkout nor a lock.

The StudyState canonical release is currently unresolved because upstream
`refs/heads/main` does not contain the required lifecycle manifest and no
verified immutable release tag has been accepted. Production installability
therefore remains false. A separately labelled `development_candidate` records
commit `cffc45a2f69f8719b950abce37988667b1712830`, tree
`e518c185fab3dbd1624cf76d017f566e4aad317f`, manifest digest
`sha256:425008e382cc87076e05a3ae02a6915167107bcbb74dc2ffe7236650c0591671`,
and source digest
`sha256:0e575f528d962095ee0c2a9ed3bd2d45ad3d126869686a556ae96f675a0e5222`.
It may enter only an explicit isolated development path.

Catalog resolution must delegate to `SourceContract` and
`resolve_source_contract()`. The resulting `statedd.source/v2` descriptor,
installation plan, exact approval, transactional materialisation, lifecycle
lock, and receipt remain the only installed identity path. Mutable refs, local
paths, fixtures, private instances, incomplete identities, missing requirements,
and catalog/schema disagreements fail closed.

## Immutable Git source resolution

`resolve_git_source()` resolves a requested ref once, requires a clean
checkout, and records the full commit and tree IDs, repository, requested ref,
checkout location, manifest digest, and StatePort source digest in one
`statedd.source/v2` descriptor. The ref is never used as the lock identity;
the commit, tree, and digests are. A lock-bound checkout is re-verified before
planning or materialisation, and a dirty or retargeted checkout fails closed.

Canonical v2 sources may contain checked-in generated compatibility views. The
StatePort materializer copies those baselines without executing arbitrary
source-provided generators. Template-owned trees declared `preserve` are not
recursively merged during an upgrade.

## Lock-bound transactional upgrade

`plan_upgrade()` returns a deterministic `planDigest`. `approve_upgrade_plan()`
binds an operator approval to that exact digest. `apply_upgrade()` refuses
stale plans, conflicts, overrides, and mismatched approvals; copies the
instance into an isolated staging directory; applies only template-owned exact
file actions; materializes and validates the staged target; swaps the staged
instance atomically with rollback on failure; and writes the upgrade receipt
last. A matching successful receipt makes a rerun idempotent.

The historical controlled StudyState release-candidate proof used the
compatibility `StudyDD_Template` repository identity and resolved baseline
commit `211d69bd96da6c67874fa81bcd50149e55cfca90` and upgrade commit
`09d77948297df49e8796b875e49c4445e97c11c9`. It remains evidence for staged,
idempotent lifecycle upgrade mechanics, not current canonical-release status.
Full historical evidence is recorded in
`docs/evidence/2026-07-12-golden-path-git-upgrade/` (private evidence, not
part of the public export).

## Fixture boundary

`fixtures/templates/lifecycle-v2-minimal` and
`fixtures/templates/studydd-minimal` are invented, public-safe StatePort
synthetic fixtures. Their identities start with `stateport.fixture.`, their
source class is `synthetic_fixture`, and they are not in a production catalog.
Synthetic and compatibility fixtures also require explicit test/development
opt-in before local materialisation.
