# Isolated container runner

`ExecutionPlan` is the machine-readable isolation contract. `ContainerExecutor`
builds a strict Docker/Podman command with a read-only root, non-root user,
network disabled, dropped capabilities, no-new-privileges, fixed mounts, and a
fixed image. Execution is disabled by default and requires an explicit approval
id correlation value plus an available engine. The caller remains responsible
for validating and binding that approval record to the exact execution. The
package does not grant templates permission to alter these controls.
