# approval-gate

> Risk-based approval gate for StatePort actions.

## Purpose

The approval gate decides whether an action can proceed based on its risk level:

- L0 — read-only
- L1 — propose-only
- L2 — local state file edit
- L3 — external side effect
- L4 — destructive or expensive action
- L5 — admin/security/compliance action

## Approval requirements

- L0/L1: logged, no approval required.
- L2: may require approval based on scope or file count.
- L3+: approval required unless pre-authorized.

## Status

Implemented as a fail-closed capability intersection and persistent approval
state machine. The API uses it for approval-backed lifecycle mutations; it is
not an authentication provider.
# Approval gate

Computes effective capability as template request ∩ instance grant ∩ operator
policy and provides an explicit pending/approved/rejected/cancelled transition
model. Terminal approvals cannot transition again.
