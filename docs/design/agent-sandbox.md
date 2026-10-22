# Agent sandbox and egress (design spec)

Implements ADR-0007 §2 and §3 for agent actions, the model suite and chat in the Alpha.26 successor.

## Problem (code read 2026-10-21, not yet measured on installed bytes)

- **Chat** runs `opencode run` inside the web container as a plain subprocess, with OpenCode's default tools (bash, edit,
  read, webfetch) and no sandbox. That process shares the control plane's network namespace (the loopback control API), sees
  `/var/lib/stateport` (every instance, the conversation stores, the provider home) and can connect to the execution-host
  control socket. A prompt-injected model would hold the platform's authority. This breaks invariants I1 and I5.
- **Agent runs** through the execution host are refused on every fresh install (no provider files, no UI path to create
  them). Their workspace volume is shared across runs, unrelated to any instance, and changes are never returned.

## Decision

1. **Chat never gets tools.** Every chat call runs OpenCode with all permissions denied, and the instance context is inlined
   as it is today. A chat answer is text. If chat should change something, that goes through an action.
2. **All agent work runs in one sandbox**, the same one for instance actions and the model suite:
   - bubblewrap, all namespaces unshared, network included;
   - a read-only `/usr` and system libraries, the CA bundle, the pinned `opencode` binary and `python3`;
   - `/work` holds a fresh staged Git copy of the instance (writable) and a fresh per-run OpenCode HOME;
   - clean environment, `--die-with-parent`, `--new-session`, its own process group;
   - a wall-clock limit (default 300 s, kills the group) and an output cap.

   Nothing else is visible: no state directory, no other instance, no provider home except the one file an account route
   needs, no control socket, no loopback of the control plane.
3. **Egress is allowlisted, not shared.** The sandbox has no network. A forwarder inside it listens on the sandbox's own
   loopback and relays to one bind-mounted UNIX socket. Behind that socket the web service runs an HTTP CONNECT proxy that
   admits only `host:443` pairs on the route's allowlist (for the OpenCode free route: the Zen API host plus whatever
   catalogue host the harness needs, measured, not guessed). Everything else gets a 403 and is logged. The proxy log
   (host, port, bytes, allow/deny) goes in the run receipt. DNS happens outside the sandbox, at the proxy.
4. **The result is a proposal.** After the run, StatePort (not the agent) computes `git add -A && git diff --cached
   --binary` against the staged base. It refuses the result if any changed path is outside the action's writable set (the
   instance-owned paths of the template's state layout; never `.git`, never an owner-owned file such as ProjectState's
   `PROJECT.md`) or if the diff exceeds the size budget. It then converts the changes into the existing
   `stateChangeProposals` pipeline, which validates and applies them under bubblewrap only after approval.
5. **Credentials.** The free route needs none. An account route copies exactly one provider credential file into the per-run
   HOME. The agent can then read it, and the allowlist bounds where it can send it. The receipt states that this route
   exposes the credential to the instrument. The copy is deleted with the run directory.

## Receipt fields (per run)

`runId`, `instanceId`, `actionId`, `route` (harness + version + model), `context` (staged base commit + digest),
`sandbox` (bwrap version, flags digest), `egress` (allowlist, log summary), `limits`, `durationSeconds`, `exit`,
`summary` (the agent's final text, bounded), `diff` (digest + changed paths), `evaluator` (before, after on the
candidate), `proposal` (id + digest) or `refusal` (code + reason).

## Claims

Isolation is stated as *implemented* by these mechanisms. It is *measured* only where a journey probes it: a sandboxed
command must fail to reach the control API, a non-allowlisted host and a path outside `/work`. A probe like that ships in
the qualification legs.

## Interface (one module, used by actions, the model suite and chat)

`packages/persistent-app/src/stateport_persistent_app/agent_sandbox.py`

```python
@dataclass(frozen=True)
class SandboxRoute:            # what may leave the sandbox
    harness: str               # "opencode"
    harness_binary: Path       # the pinned opencode binary
    model: str                 # e.g. "opencode/<id>-free"
    allow_hosts: tuple[str, ...]   # exact host names (or "*.suffix"), port 443 only
    credential_file: Path | None   # None for the free route
    tools: str                 # "none" (chat) | "edit" (agent actions: read/edit/write/list/grep/glob/bash, no webfetch)

@dataclass(frozen=True)
class SandboxResult:
    status: str                # "completed" | "failed" | "timeout" | "refused"
    refusal: str | None        # typed code when refused (e.g. "sandbox_unavailable", "route_not_consented")
    exit_code: int | None
    duration_seconds: float
    final_text: str            # the agent's last text event, bounded to 8 KiB
    events: int                # JSON events seen
    tokens: dict[str, int]     # if the harness reports them
    egress: tuple[dict, ...]   # proxy log entries: {host, port, allowed, bytes_up, bytes_down}
    sandbox_digest: str        # sha256 of the exact bwrap argv template + bwrap version

def run_in_sandbox(*, workdir: Path, prompt: str, route: SandboxRoute, timeout_seconds: int = 300,
                   output_limit_bytes: int = 1 << 20) -> SandboxResult: ...

def sandbox_available() -> tuple[bool, str]: ...   # probes bwrap + userns once; reason when False
```

`workdir` is a directory StatePort created; the agent sees it as `/work` and changes only it. Diffing, path policy and
proposals are the caller's job (portable-execution), never the sandbox's.
