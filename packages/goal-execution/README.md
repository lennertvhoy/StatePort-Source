# Governed goal execution

`stateport_goal_execution` is the provider-neutral control protocol behind
optional application orchestrators. It is deliberately smaller than an agent
runtime: natural-language requests create proposals, explicit approvals bind
one item and one immutable base, and only independent review can support a
closure receipt.

Approvals acquire an atomic instance-scoped lease shared by all sessions in
the service process. A second session cannot approve the same instance until
the first closes or stops. Review submission makes StatePort re-inspect and
digest-bind a separate clean, detached and filesystem-read-only Git worktree;
caller-provided workspace labels or evidence objects are not acceptance
evidence.

The core vocabulary is domain-neutral. Development applications may present a
`ProjectBootstrapManifest` and backlog-shaped goal items; study and classroom
applications can specialize the same protocol without inheriting development
navigation or CTO terminology.

This foundation never starts an agent, executes an application-supplied
command, opens a network connection, mutates canonical state, or advances to a
second item. StatePort-owned Git identity and detached-clone commands are the
only subprocess boundary in the provider-free proof. The
application shell exposes domain goal controls only when the application
declares `goal_execution`. Development applications may additionally expose
CTO presentation only when `cto_orchestration` is independently permitted.

The persistent application includes one provider-free vertical controller for
development fixtures. It prepares an advisory or assisted proposal, requires
an authenticated exact-plan approval, performs only a bounded StatePort-owned
contract inspection, constructs a separate detached read-only review clone,
binds independent review to the exact commit/tree/result, and closes through a
distinct StatePort governor. Operational records are atomic, private, and
restart-safe. Git drift, review-isolation failure, or an operator switch to
`off` releases the instance lease and records an explicit terminal stop. This
controller is a protocol proof, not a coding-agent backend or autonomous
backlog loop.
