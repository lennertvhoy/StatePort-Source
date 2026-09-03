# Local Nix Infrastructure Daily-Driver Grant

StatePort uses one durable, application-scoped grant for routine use of the
existing local NixOS VM. The grant is bound to the exact repository root,
branch, application instance, libvirt domain and UUID. It is stored below the
StatePort XDG state root with a private directory and file.

The grant covers repository inspection, project file editing and terminal
capabilities already exposed by the application, plus VM observation,
read-only health checks, strict SSH after enrollment, start, graceful stop,
and restart. It does not cover creation, destruction, material rebuilds,
storage or network changes, credentials, host-key rotation, cloud actions, or
destructive Git operations.

The grant removes repeated approvals for reversible local lifecycle actions;
it does not weaken strict SSH verification. First enrollment remains a
one-time operator confirmation bound to the exact target, public key and
trusted provenance. A target identity, repository-root, policy or capability
scope change invalidates the grant and requires reapproval.

Every covered operation still creates a plan, emits progress, holds the
single-writer lease, and persists a receipt. Destructive or out-of-scope
operations retain exact approval.
