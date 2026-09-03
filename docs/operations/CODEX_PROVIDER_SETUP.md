# Direct Codex provider setup (local, opt-in)

## Scope and current boundary

This guide describes the narrow direct-Codex conversation path. It was
originally exercised on `agent/bl-ai-vertical-002`, based on
`16e2980a7d081b48fc59986a44214cb012018c11` on 2026-07-21, and is now merged
and wired into the `stateport` CLI wrapper. It is a bounded local path, not a
release, deployment, public install instruction, production qualification, or
acceptance claim.

StatePort currently supports one bounded provider profile: a locally installed
Codex CLI, authenticated by its operator. Pi is a reference execution host in
the architecture, but no Pi adapter or Pi configuration path exists in this
working tree. Do not represent Pi as connected until it has a separately
reviewed adapter, conformance evidence, and an explicit profile format.

The normal StatePort service remains provider-free unless an operator turns
this path on. The provider profile contains a model identity and bounded
execution settings; it never stores an API key, browser cookie, access token,
or another credential.

## Before you enable it

Use an isolated worktree for source changes and a disposable local profile for
experiments. A real Codex invocation can consume an operator's authenticated
account allowance, so obtain the relevant human authorization before a
non-test run.

Confirm the CLI and its own authentication without copying credentials into
StatePort:

```bash
codex --version
codex login
codex login status
codex exec --help
```

`codex login` uses Codex's supported authentication flow. Treat Codex's own
authentication cache as a password-equivalent. Do not commit it, paste it into
a StatePort configuration file, share it with another operator, or place it in
a general-purpose CI environment variable. See the official Codex guides for
[authentication](https://learn.chatgpt.com/docs/auth) and
[non-interactive commands](https://learn.chatgpt.com/docs/non-interactive-mode).

## Enable one local service

Choose an exact model identifier that your authenticated Codex CLI supports.
The following is the bounded local-development shape used for the verified
smoke; substitute only an explicitly approved model value:

```bash
STATEPORT_ASSISTANT_PROCESSOR_ENABLED=true \
STATEPORT_CODEX_MODEL="gpt-5.6-luna" \
./stateport service start --open
```

On first startup, StatePort creates this non-secret profile:

```text
$XDG_CONFIG_HOME/stateport/provider-router.json
# or ~/.config/stateport/provider-router.json when XDG_CONFIG_HOME is unset
```

The file is written atomically with mode `0600`. It records an exact model,
the `workspace-write` sandbox profile, time/step bounds, provider identity,
and a digest. StatePort uses a separate local state root for its durable work
claims, event journal, reply-delivery records, and disposable staging
directories. Neither location is a place to store Codex credentials.

To keep a demo isolated from a daily profile, set disposable XDG roots before
starting the service:

```bash
DEMO_ROOT="$(mktemp -d -t stateport-codex-demo.XXXXXX)"
XDG_CONFIG_HOME="$DEMO_ROOT/config" \
XDG_STATE_HOME="$DEMO_ROOT/state" \
STATEPORT_ASSISTANT_PROCESSOR_ENABLED=true \
STATEPORT_CODEX_MODEL="gpt-5.6-luna" \
./stateport service start --port 8792 --open
```

Use this only for a temporary local test. Do not point it at learner data,
secrets, a production instance, or a shared write worktree.

## What StatePort does with a message

For each eligible conversation message, the durable processor claims one work
record with a lease, creates a disposable staging directory, and invokes the
single injected `CodexAdapter`. The adapter uses structured JSON output,
ephemeral mode, a staging-bound working directory, filtered execution
environment, bounded combined output, process-group supervision, and cleanup.
The current adapter also passes `--skip-git-repo-check`: its staging directory
is deliberately empty and is not a source repository.

The provider result is stored before reply delivery. The same-origin event
journal lets the browser replay an interrupted stream without asking the model
again. A returned response is still a model result, not canonical application
truth and not authorization to modify an instance.

## Verify the bounded path

1. Visit the loopback service in a browser and open a development-reference
   application conversation.
2. Send a narrow, public-safe question that asks for no tools or file access.
3. Wait for a delivered assistant message, then refresh once to check that the
   durable conversation remains visible.
4. Inspect the application source/status separately. A successful conversation
   does not turn a development candidate into a canonical release.
5. Stop the service when the test is complete:

```bash
./stateport service stop --json
```

The direct smoke performed for the evidence note used a temporary profile,
an empty staging root, an explicit model, a four-step/90-second bound, and a
public-safe one-sentence objective. It completed in about 8.5 seconds through
the injected router and hardened CLI adapter. A subsequent browser message
received and displayed a real local Codex response. This is local evidence
only; it does not establish repeatability, useful model quality, cost
telemetry, remote CI, external-user acceptance, human acceptance, merge,
deployment, or release.

## Honest failure handling

| Observation | Meaning | Safe response |
| --- | --- | --- |
| `assistant_processor_unavailable` | The opt-in processor is disabled. | Check the two explicit environment variables; do not fabricate a reply. |
| `STATEPORT_CODEX_MODEL must be explicitly configured` | An enabled processor has no explicit model. | Stop and choose an approved exact model. |
| `provider_failed` | The CLI invocation did not produce an accepted result. | Inspect local service logs and Codex login state; do not convert it into an assistant answer. |
| `provider_timed_out` or cancellation | The bounded run ended without a usable result. | Keep the durable failure/recovery record; do not silently retry an unknown external action. |
| A branch-level test is green | Local code evidence only. | Run the full validation ladder and obtain independent review before a stronger claim. |

The UI smoke also observed a separate `goal-execution` projection returning
403 for the CTO fixture. This is not hidden or counted as a successful
workbench journey; it remains a follow-up product-contract issue outside the
bounded conversation proof.

## Pi: planned contract, not a setup command

Pi may become a first-class reference execution host, but it must not receive
an undocumented side channel. A future Pi adapter needs, at minimum:

- a versioned provider-neutral profile with no credentials;
- an explicit capability declaration and degradation behavior;
- the same instance lease, base identity, staging, process/cancellation, and
  event-journal contracts as Codex;
- conformance fixtures proving no duplicate provider authority; and
- separate local, independent-CI, and human acceptance evidence.

Until those conditions are implemented and accepted, use direct Codex only
for the bounded local path above. Do not call Pi configuration "working" or
route StatePort messages through it by ad-hoc shell glue.

## Release and CI rule

Never bake a Codex login, API key, or authentication cache into an image,
repository, hosted workflow, or public demo. CI may validate the adapter's
fixtures and unavailable behavior; a real authenticated provider invocation
requires a separately authorized operator-controlled environment and must not
promote local evidence to acceptance by itself.
