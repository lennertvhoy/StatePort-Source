# Bounded delegation and standing authority

StatePort's default operating philosophy is **bounded delegation with
transparent oversight**. Human control remains absolute, while routine
attention is reserved for decisions rather than reversible mechanics.

This document describes the headless authority foundation. The polished
Authority settings page is a separate product slice and is not claimed here.

## Profiles

The tracked `config/authority-policy.v1.yaml` classifies each action and defines
four profiles:

- **Guarded** automatically permits inspection, analysis, and local tests.
  Other mutations and process launches stop for approval.
- **Balanced** is the default. Scoped local edits, tests, commits, managed
  worktree creation and retirement, routine cleanup, and project-state updates
  run with receipts. Private pushes and draft pull requests run only when the
  standing grant names them and its branch scope matches. Merge, publication,
  deployment, destructive action, visibility changes, and real-secret use
  still stop for approval.
- **Delegated** additionally permits bounded private transport and merge after
  exact-head and required-gate assurances. Publication, deployment,
  destructive remote action, visibility changes, and real-secret use remain
  approval boundaries unless an owner issues a narrower explicit override.
- **Custom** requires one of `deny`, `ask_each_time`, `approve_scope_once`,
  `auto_and_notify`, or `auto_with_receipt` for every action class.

Force-push, history rewrite, and safety-gate disabling are non-negotiable
denials in the v1 policy. They cannot be enabled by a grant or break-glass
override.

## Authority sources and storage

Stable defaults and non-negotiable boundaries belong in `PROJECT_DNA.yaml` and
the tracked policy. Current state records only non-sensitive grant identifiers,
mode, and exceptional blocks. Complete active grants, revocations, pauses,
scope-closure markers, and action receipts live below
`$XDG_STATE_HOME/stateport/authority/repositories/<repository-key>` with private
directory and file modes. Secret values and sensitive capability bindings do
not belong in Git.

The store binds the canonical repository root and safe origin identity. Grants
also bind an actor, branch pattern, slice/application/run identifiers, file
prefixes, expiry, action count, duration, cost, network domains, providers, and
secret capability identifiers. Every new grant also binds the exact
authority-policy digest; a policy change makes earlier grants inactive until
an owner issues a replacement under the new policy. Pre-binding grant records
remain inspectable but inactive. Missing, malformed, conflicting, expired,
revoked, consumed, over-budget, or scope-mismatched authority fails closed.

`expiresWhen: slice_closed` and `run_closed` are enforced by durable closure
markers. `one_time` grants are consumed by the first recorded authorized
attempt, whether the underlying operation succeeds or fails.

## Action receipts

Every enforced action produces an immutable digest-bound authority receipt.
The receipt states:

```text
Action: pushed private branch
Authorized by: grant_42
Scope: BL-CONVERGENCE-001 / agent/*
Policy: auto_with_receipt
Result: succeeded
```

Machine fields additionally preserve the request and decision digests,
configured versus effective policy, actor, repository identity, exact scope,
timestamps, bounded cost, result code, and resource identifiers. A refused
action receives a `not_executed` receipt, so denial is observable without
pretending that an operation ran.

Workspace creation, evidence export, retirement, and slice closure are routed
through this boundary by `stateport workspace`. Existing workspace
creation/cleanup receipts remain lifecycle evidence; the attached authority
receipt states why the operation was allowed and whether the call succeeded.
Passing `--close-slice` to the final workspace retirement also runs the
residue gate and expires slice-scoped grants in the same command. It succeeds
only when no other lease or workspace residue remains for that slice.

## Subagents

A subagent grant must name an active delegating parent. Its branch, slice,
application, run, file, action, budget, network, provider, and secret scopes are
checked not to exceed the parent. Subagents cannot delegate again. The v1
default denies integration-branch pushes, global project-state changes, merge,
tag, release, deployment, visibility changes, destructive remote action,
real-secret use, authority-policy mutation, and further delegation.

This is declared authority, not proof that an arbitrary external harness is
technically sandboxed. StatePort reports declared, effective, and observed
authority separately. Host filesystem, network, process, and credential
enforcement still require the corresponding sandbox or broker controls.

## Operator commands

Inspect current authority and recent receipts:

```bash
./stateport authority inspect
./stateport authority receipt authority_receipt_<id>
```

Issue a bounded Balanced grant (illustrative identifiers only):

```bash
./stateport authority grant \
  --grant-id grant_slice_42 \
  --profile balanced \
  --actor-id agent-primary \
  --role primary \
  --branch-pattern 'agent/*' \
  --slice-id BL-CONVERGENCE-001 \
  --allow push_private_branch \
  --allow open_draft_pr \
  --require-approval merge \
  --require-approval deployment \
  --forbid force_push \
  --expires-when slice_closed \
  --owner-directive-id OD-EXAMPLE-001 \
  --owner-actor-id local-owner
```

Pause, resume, revoke, or grant one operation:

```bash
./stateport authority pause --owner-actor-id local-owner --owner-directive-id OD-PAUSE-001 --reason 'operator pause'
./stateport authority resume --owner-actor-id local-owner --owner-directive-id OD-RESUME-001 --reason 'operator resume'
./stateport authority revoke grant_slice_42 --owner-actor-id local-owner --owner-directive-id OD-REVOKE-001 --reason 'slice cancelled'
./stateport authority allow-once merge --grant-id grant_merge_once --actor-id agent-primary --branch-pattern 'agent/review' --slice-id BL-EXAMPLE-001 --owner-directive-id OD-MERGE-001 --owner-actor-id local-owner
```

Issuing, pausing, resuming, and revoking grants are themselves explicit owner
policy changes and receive receipts. Repository-local CLI access is the current
operator authentication boundary; a managed multi-user deployment must add its
authenticated owner boundary rather than treating possession of a grant file
as proof of identity.
