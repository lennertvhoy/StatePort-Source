# StatePort deterministic runner

The runner is the implemented read-only `echo` runtime for a StateSpec instance.
It loads `instance.yaml`, resolves or receives the trusted template directory,
checks template identity and required state files, runs the instance validator,
and returns a structured `RunResult`. It does not call a model, use tools,
write workflow state, make network requests, or grant capabilities.

Run it locally through `./stateport run-instance <instance>` or as a module:

```bash
python3 -m runner instances/demo-classdd
```

The module CLI emits JSON and accepts these environment variables:

- `STATEPORT_INSTANCE_PATH`: default instance path.
- `STATEPORT_TEMPLATE_PATH`: trusted template override. The container executor
  sets this to `/stateport/template`, so stored references such as
  `../../templates/classdd` remain provenance metadata while the approved,
  isolated template snapshot is used at runtime.

`apps/runner/Dockerfile` packages the same runner as a non-root image with no
provider credential. The governed worker invokes only the fixed
`python3 -m runner /stateport/instance` command and mounts both input snapshots
read-only. Enabled execution additionally requires an immutable image digest.

Model execution, workflow mutation, and cloud-hosted runners remain future
contracts.
