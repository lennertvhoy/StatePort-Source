# Isolated container execution contract

`packages/container-runner` separates a runtime-neutral execution plan from a
Docker/Podman command executor. Constructing and validating an
`ExecutionPlan` performs no mounts or process execution. `ContainerExecutor`
can construct the fixed runtime command and has an optional process boundary
that remains disabled by default.

Each plan has one immutable read-only template source, one durable instance
source mounted read-only to the container, and one ephemeral runtime
directory. A single-writer lease,
transactional validation, non-root execution, read-only root, no privilege
escalation, and network-disabled operation are mandatory. A plan cannot opt
itself into network access or relaxed isolation. The runtime directory must be
disjoint from the template and instance trees: it may not equal, contain, or
be contained by either one. `apply` remains false in v1 and denotes plan
capture; it is not process authorization. Optional process execution is a
separate executor decision.

The governed echo-run API may embed this plan in a persisted run record for
inspection and later executor integration. That embedding is plan capture
only: no runtime directory is created, no container is started, and no plan
can enable networking or relax isolation controls. The local worker creates
separate read-only input snapshots before invoking the executor, so a runner
cannot write canonical instance state through its container mounts.

`ContainerExecutor` now provides the command-construction and explicit
execution gate. It fixes the engine allow-list to Docker/Podman, the image at
configuration time, read-only root, non-root user, dropped capabilities,
no-new-privileges, network-disabled operation, and three fixed mounts. The
executor refuses to run unless process execution is enabled out of band and an
approval id is supplied; the default is disabled. The approval id is only a
required correlation value: `ContainerExecutor` does not load or validate an
approval record, so its trusted caller must verify the approval and bind it to
the exact execution before invoking the executor. The executor also refuses a
pre-existing runtime directory and removes only the runtime directory that it
created for its own invocation. The explicit local worker path wires this
executor to the approval-bound queue; Compose keeps that path disabled by
default and provides no engine socket.
