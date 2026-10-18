# StatePort terminal broker

This package is the server-owned terminal boundary. It provides versioned
terminal contracts, a real local PTY target, short-lived one-use session
values, actor/instance/origin checks, bounded in-memory replay, process-tree
cleanup, restart reconciliation, exact-root quarantine, and transcript-free
audit receipts.

It is not a public shell service. The persistent local StatePort service now
adapts `AuthenticatedTerminalGateway` through a loopback-only authenticated
HTTP/WebSocket endpoint. `GatewayHandshake` refuses query strings and
fragments, and `GatewayFrame` bounds input to 64 KiB. The adapter must
authenticate before acceptance, validate the browser origin, and carry the
one-use value in the first frame rather than a URL.
Cookie-authenticated session creation also requires the adapter's normal CSRF
protection; a terminal one-use value is not a substitute for HTTP
authentication or CSRF policy. No PTY bytes are available until those checks
pass. Session identifiers are high-entropy values and cross-actor/unknown
lookups share the same refusal.

## Boundaries

- A browser may select a trusted server profile; it cannot supply a command,
  environment, SSH credential, Herdr socket, or filesystem root.
- A local profile has one exact, non-symlink project or instance root. `/` and
  the operator home directory are refused. The broker opens each path component
  without following links and binds the launch to the configured device/inode;
  replacing the directory at the same path is refused. Broker state must live
  outside that root.
- A normal local shell runs inside a required Bubblewrap boundary. The exact
  project root is its only writable host bind; system runtime files are
  read-only, network and IPC namespaces are private, capabilities are dropped,
  and home, run, and temporary directories are isolated. If Bubblewrap is not
  available, the normal project-scoped profile fails closed. A separately
  configured `elevated` profile may retain service-account host and network
  access, but it is never the default and its broader scope is shown in the
  public profile projection.
- Terminal input is a powerful direct human action. It is deliberately not
  routed through the managed-agent approval engine. A governed run launched
  from a terminal remains responsible for using normal StatePort run policy.
- Output and replay stay in memory and are bounded. State contains process
  ownership plus bounded metadata only; audit receipts never contain commands,
  terminal output, environment values, or one-use values.
- `ssh` and `herdr_attach` exist as typed target classes but remain
  environment-gated. No browser receives an SSH endpoint, user, config path,
  key reference, command vector, environment, or Herdr service endpoint.

## Execution-host capsule terminals

`ExecutionHostTerminalGateway` (lazy export) adapts the same authenticated
browser contract onto a PTY inside a running rootless workspace container
owned by the execution-host daemon. One-use tickets stay sha256-keyed,
TTL-bound (5..300 s), and bound to the exact actor, instance, and origin with
constant-time comparisons; a failed spend consumes the ticket. The daemon's
per-session Unix socket is validated against the confined `sessions`
directory and is never serialized into a browser response; no execution-host
or Podman endpoint reaches the browser, and there is no fallback into a web
or control container. One workspace serves one connected terminal, reconnect
and replay are unavailable, typed signals (SIGINT/SIGQUIT/SIGTSTP) flow
through the daemon PTY, and a disconnect cleans the session up at the
execution host. Audit receipts bind process/container identity (workload,
session, executor pid) as digests only.

## SSH and Herdr capability preparation

`SshTargetProfile` is trusted server configuration. A browser selects only a
non-enumerable allowlisted target ID. The public projection contains a
server-owned connection label, the expected host-key fingerprint, and the
non-secret authentication route. `build_ssh_launch_plan` never invokes a shell
and always compiles `/usr/bin/ssh -F none` with a per-target controlled
known-hosts file, exact `HostKeyAlias`, strict host-key checking, no trust-on-
first-use/keyscan path, no ambient agent, no proxy/jump/control configuration,
no forwarding or delegated credentials, no local or escape command, and
bounded connection/liveness settings. The displayed fingerprint is recomputed
from the sole alias entry before every plan, so metadata cannot diverge from
the key OpenSSH will trust. There is no live SSH execution in this slice.

Herdr detection may invoke only the documented bounded `--version` query. The
observed 0.7.1 capability is `environment_gated` with reason
`herdr_machine_stream_unsupported`; the required floor is 0.7.2 followed by a
separate machine-stream conformance check and accepted adapter. Detection never
lists, creates, takes over, updates, stops, deletes, or attaches to a pane.
Closing a future StatePort Herdr transport means local adapter detach unless
remote cleanup is independently proven. External receipts therefore report
`localAdapterCleanup`, `remoteProcessCleanup`, and `reconnectScope` separately.

## Process ownership and recovery

The broker starts every PTY leader in a new session with a random process
generation marker. A small pre-exec gate keeps the requested shell blocked
until the exact PID, process group, session, start time, generation, actor,
instance, root path, and root device/inode are durably recorded. Cleanup revalidates Linux `/proc`
start identity and scans both the original session and inherited generation,
including descendants that create a new session. A restart cannot recover the
lost PTY file descriptor, so it cleans any recorded orphan before accepting a
new session.

If cleanup cannot be proven, only the affected exact root is persistently
quarantined. This foundation intentionally has no automatic or UI-driven
quarantine clear operation; operator recovery needs a separately governed
contract. Linux procfs generation tracking is weaker than cgroup ownership
when a hostile descendant deliberately scrubs its environment and detaches,
so this is a bounded local foundation rather than a production bastion claim.
Bubblewrap constrains the normal shell's filesystem and network reach but does
not turn StatePort into a multi-tenant public bastion; production deployment
still requires a dedicated low-privilege service identity and an accepted host
sandbox policy.

## Minimal server configuration

```python
from pathlib import Path
from stateport_terminal_broker import (
    TerminalCapabilities,
    TerminalConnectionProfile,
    TerminalSessionBroker,
    TerminalTarget,
)

target = TerminalTarget(
    "local.project.demo",
    "local_pty",
    "Project shell",
    "available",
    TerminalCapabilities("local_pty", True, True, True, True, True, True),
)
profile = TerminalConnectionProfile(
    "profile.project.demo",
    target,
    ("instance.demo",),
    Path("/srv/stateport/instances/demo"),
    ("/bin/bash", "--noprofile", "--norc"),
)
broker = TerminalSessionBroker(
    (profile,),
    state_directory=Path("/var/lib/stateport/terminal"),
    allowed_origins=("https://stateport.example",),
)
```

Tests run with:

```bash
python3 -m pytest -q -p no:cacheprovider scripts/test_terminal_broker.py
```
