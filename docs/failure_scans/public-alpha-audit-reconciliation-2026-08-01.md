# Failure Scan — public-alpha audit reconciliation

## Scope

The point-in-time audit against `b4932f0` exposed release-policy,
candidate-identity, generated-artifact, build-identity, dependency, schema,
observability, restore, and repository-hygiene boundaries. This scan binds the
failure classes to durable prevention on the successor candidate based on
`2cb10aa4595d3eb06bd6f6fba5ae7d5f9be758bf`.

## Prevented recurrences

- Public export enumerates `git ls-files` from an exact committed tree.
  Untracked owner material is inspected separately and cannot become public
  source authority.
- Local release outputs, audit material, browser artifacts, SQLite runtime
  files, caches, and operator state have explicit local-only roots and staged
  content checks.
- An external public candidate must carry repository, commit, tree,
  materialization receipt, bundle digest, retention state, and recovery
  commands. The source tree is derived from the retained source commit; the
  retained materializer, exporter, and policy blobs are hashed. Contract-only
  validation never claims that the external bundle was inspected. A bare
  non-resolving SHA is invalid.
- Production web identity binds source commit and tree jointly. Missing or
  one-sided provenance cannot produce a clean marker, and a mismatched commit
  or tree cannot satisfy exact-checkout service startup. Automatic builds
  record observed dirty state; injected builds default to dirty unless their
  caller explicitly supplies the claim. Vite, the source installer, and CI
  derive tree/time from one resolved commit rather than rereading moving
  `HEAD`. Dirty development builds remain explicit; clean release-artifact
  admission closes in Slice B.
- Runtime and test dependencies are separated in hash-locked manifests;
  required image installation cannot fall through `|| true`.
- StateSpec manifest schema IDs resolve through a strict registry and actual
  documents are schema-validated before lifecycle mutation.
- Operational events are bounded, redacted JSONL with strict log level,
  service/request identity, local-only sinks, liveness, and readiness.
- Governed restore is plan → exact approval → restore as a new identity →
  validation/catalog registration → immutable receipt. Direct mutation and
  archive paths supplied by a browser are refused. Persistent restore status
  revalidates artifact names, formats, bindings, and digests. Restore reads,
  immutable publication, and locks traverse descriptor-confined directories;
  unexpected entries, symlink ancestry, hard-linked artifacts, byte/count
  overflow, and post-open ownership changes fail closed. Deletion detection
  remains dependent on a future external index. Retained staging and
  dangling-symlink boundaries surface as operator attention.
- Workflow lint and a correctness-oriented Ruff gate are explicit. Historic
  style debt remains visible instead of being represented as a permanently red
  quality gate.
- Every API/worker test consumer declares the observability source root rather
  than relying on focused-test import order.
- The strict instance schema covers the capability grant fields actually used
  by governed admission, and full-suite mutation/runner tests protect that
  alignment.
- Frontend restore calls are required to remain in the executable
  functionality-preservation manifest.
- Terminal sandbox tests resolve tools inside the sandbox rather than injecting
  a host-only virtualenv path. Project isolation is retained in exact-head CI.
- Executable workflows pin Checkout v7.0.1's Node-24 action commit. A workflow
  regression rejects deprecated or floating Checkout identities.
- Browser-compatibility data is lockfile-pinned at reviewed minimum versions
  and the review itself expires on 2026-11-01. Older data or an unreviewed
  maintenance window fails the dependency gate before stale build warnings can
  become normal background noise.
- External-candidate bundle recovery sets its disposable clone's initial branch
  explicitly and then verifies the contract's exact remote candidate ref. The
  proof is independent of an operator's global Git default-branch setting.
- Public evidence uses typed operator locators rather than publishing absolute
  workstation paths.

## Residual classes

- The unstable React Router RSC advisory remains under a narrow applicability
  exception expiring 2026-08-12; affected RSC markers fail closed.
- Retention execution, generalized coverage measurement, Git-history size
  cleanup, live provider cost accounting, and localization are typed deferred
  work. None is represented as implemented.
- Git history is not rewritten merely to remove dead blobs. That would violate
  the mission's no-history-rewrite boundary.
- Platform update/rollback documentation closes with Slice B's executable
  updater; design prose is not accepted as proof.

## Regression evidence

The controlling tests are `test_local_artifact_policy.py`,
`test_candidate_provenance.py`, `test_web_bundle_budget.py`,
`test_python_dependency_policy.py`, `test_statespec_schema_registry.py`,
`test_observability.py`, `test_governed_restore.py`,
`test_post_mutation_security_matrix.py`, `test_api_auth.py`,
`test_governed_mutations.py`, `test_governed_runner.py`,
`test_application_experience.py`, `test_terminal_broker.py`, and
`test_ci_workflow.py`; browser-data freshness is covered by
`test_web_dependency_audit.py`.
Build-pair injection and runtime admission are additionally covered by
`build-isolation.test.mjs`, `test_service_process_startup.py`,
`test_service_lifecycle_identity.py`, `test_web_surface.py`,
`test_public_alpha_quickstart.py`, and `test_ci_workflow.py`.

This is implementing-session evidence. Review class is
`internal_multi_agent`; independence is not established.
