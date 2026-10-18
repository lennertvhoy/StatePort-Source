# StatePort local worker

The worker is a durable local queue consumer plus a small health surface. It
claims `stateport.container-job/v1` jobs, then treats the queue payload as
untrusted until it matches the persisted run, approval, immutable plan and
template digest, runner image digest, engine, command, instance scope, current
capability intersection, and durable usage reservation.

Execution remains disabled by default. In that state the Compose service opens
only `/health` and `/v1/capabilities`, reports `executionEnabled: false`, and
rejects POST control requests. The default Compose file does not mount a
container socket and cannot start runner containers.

For an explicitly operated host worker, build the runner first and use its
immutable image ID (or a registry `name@sha256:...` reference):

```bash
podman build -t stateport/runner:local -f apps/runner/Dockerfile .
STATEPORT_WORKER_EXECUTION_ENABLED=true \
STATEPORT_OPERATOR_CAPABILITIES=read_state,execute_container \
STATEPORT_CONTAINER_ENGINE=podman \
STATEPORT_RUNNER_IMAGE=sha256:<full-image-id> \
./stateport-worker --workspace /path/to/workspace --once
```

Configuration:

- `--host`: loopback by default. A non-loopback bind requires the explicit
  `--allow-public-bind` acknowledgement used by the container image; Compose
  still publishes the port only on host loopback.
- `STATEPORT_WORKER_EXECUTION_ENABLED`: strict boolean; empty/false is disabled.
- `STATEPORT_OPERATOR_CAPABILITIES`: must include `execute_container` when enabled.
- `STATEPORT_CONTAINER_ENGINE`: `podman` (default) or `docker`.
- `STATEPORT_RUNNER_IMAGE`: immutable SHA-256 image ID/reference when enabled.
- `STATEPORT_EXECUTOR_TIMEOUT_SECONDS`: positive executor timeout.
- `STATEPORT_WORKER_ID`: diagnostic local worker identity.
- `STATEPORT_WORKSPACE`: workspace containing the shared `.stateport` stores.

The worker renews its queue lease during execution, defers on a busy instance
writer lease, and supports expired-lease recovery. Under the same kernel
instance lease used by API writers, it copies the approved template and current
instance into ephemeral staging, mounts those copies read-only, and compares
both staged and durable state afterward. Raw stdout/stderr are retained only as
size and SHA-256 evidence; validated structured runner status/log/error fields
are recorded in the scoped job result. Cost values are quota estimates or
observations, not billing records.

This is local single-host execution, not an authenticated remote-worker or
distributed queue protocol. There is no model/tool runtime, provider secret,
network-enabled job, or writable container job in this v1 mode.
