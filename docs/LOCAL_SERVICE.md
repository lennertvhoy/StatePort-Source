# Local service

`stateport service start` runs a managed loopback-only foreground child;
`--open` prints or opens the same-origin dashboard. `stop`, `status`, and
`logs` use the configured runtime and state roots. PID checks include process
identity, stale metadata is reported, repeated start is safe, and stop is
clean. No systemd or root access is required.
