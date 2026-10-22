# StatePort architecture

StatePort runs durable, user-owned AI applications on one person's machine: Windows 11 + WSL2 + Ubuntu 24.04, installed
by one command. The model behind it is in [ADR-0007](adr/0007-evaluator-loops-and-the-curve.md); the theory is in the
Stateware whitepaper; [ARCHITECTURE_OVERVIEW.md](ARCHITECTURE_OVERVIEW.md) is the one-page map. This document covers the
components that ship in Alpha.26, the boundaries between them, and the path a unit of work takes. The pre-Alpha.26
document, which described several components that never shipped, is kept at
[history/ARCHITECTURE-pre-alpha26.md](history/ARCHITECTURE-pre-alpha26.md).

## 1. The model

An **application** is five parts:

- **state**: an instance Git repository the owner keeps;
- **outcome**: what the work is for, in the owner's words;
- **evaluator**: a deterministic check of the state (`passed`, `not_yet` or `invalid`, with findings);
- **actions**: `check` actions that read, and `agent` actions where a model edits a copy;
- **grants**: what may run and apply, with which model route, budget and expiry.

A template supplies the definition. An instance is one owner's copy of it. ProjectState, StudyState and any repository
that meets [the template contract](TEMPLATE_CONTRACT.md) (for example the Decision Log template) are templates.

Two rules hold everywhere:

1. **Authority only narrows.** Effective authority = template request ∩ instance grant ∩ operator policy ∩ host
   capability ∩ run lease. Text a model reads never widens it.
2. **Instruments return candidates.** A model or agent harness never applies its own result and never judges it.
   StatePort computes the change, runs the evaluator, and applies it only through the owner's approval.

## 2. What the installer deploys

| Component | Runs as | What it is | Talks to |
|---|---|---|---|
| Bootstrap `install.sh` | the user | Verifies the signed release index with a pinned key, installs host packages after a typed confirmation, starts the installer | site download, GHCR, apt |
| Installer `stateport-installer` | the user, plus `sudo` for one root helper and the control account | Verifies every artefact, provisions accounts and units, creates volumes, starts services, writes the install receipt, installs `bin/stateport` | root helper, the control account's podman and systemd |
| Root helper `stateport-execution-host-provision` | root, from the installer | Creates `stateport-control` and `stateport-exec`, subuid ranges, linger, the execution-control socket directory, static `crun` | the system |
| `stateport-web` | `stateport-control`, rootless Podman | The product: web UI, control API, persistent application, action runtime, agent sandbox and egress proxy, model routes, chat | execution host (UNIX socket), model provider hosts (through the egress proxy only), public Git over HTTPS (template import) |
| `stateport-execution-host` | `stateport-exec`, rootless Podman | Daemon that owns per-instance workspace containers (`stateport-dev-workspace`) behind a peer-credential UNIX socket | `stateport-exec`'s Podman |
| `stateport-api`, `stateport-worker` | `stateport-control` | Governed API and queue worker. Deployed and healthy, **no caller** in Alpha.26 | — |
| Windows task `StatePortKeepAlive` | the Windows user | Keeps the distro running across logoff and reboot (startup, logon and every 10 minutes) | `wsl.exe` |

Images in the signed set: web, api, worker, execution-host, dev-workspace, runner, playwright. The installer pulls only
the images a deployed service uses; `runner` and `playwright` are optional profiles and are never pulled on the
reference journey.

Every container runs read-only, with no new privileges and every capability dropped, under a keep-id user namespace.
The web container alone runs with `Unmask=ALL`, because bubblewrap needs it to mount the sandbox's own `/proc`; the
sandbox masks the kernel's sensitive `/proc` files again inside (§4). Podman's scheduled healthcheck runs every 5
minutes and only refreshes an informational status: the installer and the updater run `podman healthcheck run` when they
need an answer (each scheduled check costs about 0.17 CPU-seconds in the WSL guest).

## 3. Trust boundaries

- **Browser to web service**: loopback only (`127.0.0.1:<port>`). Every mutation needs a loopback `Origin` and the
  session CSRF token. The browser never receives a host socket, credential or signing secret.
- **Web service to execution host**: a fixed UNIX socket path, a peer-credential check and per-workload grants with a
  pinned spec digest.
- **Web service to instruments**: the agent sandbox (§4). Nothing an instrument can reach shares the control plane's
  network namespace, filesystem view or process table.
- **Templates**: a template is imported from a public HTTPS Git repository (by URL and a branch, tag or the default
  branch, resolved once to an exact commit) or from a local checkout under `/var/lib/stateport/imports`. Inspection is
  read-only and runs no repository code. The owner reviews the exact commit and its findings; the approval binds the
  inspection digest. A template's own scripts run only in the sandbox, with no network. StatePort's own adapter checks
  for ProjectState and StudyState run in the web service.
- **Model providers**: a destination is used only after the owner consents to it. The consent names what leaves the
  machine and quotes the provider's terms. Credentials stay in the provider home. The free route needs none.

## 4. A run, end to end

1. **Prepare.** The owner clicks Run. StatePort binds the action contract, inputs, executor identity, instance tree
   digest and base commit into a run spec, and digests it.
2. **Approve the run.** The click is the approval for that digest and revision. For an agent action, the approval also
   names the model route and the fact that the files the action declares go to it.
3. **Execute in the sandbox.** A staged copy of the instance becomes `/work`.
   - The sandbox is bubblewrap with every namespace unshared, a private `/proc` with the kernel's sensitive files masked,
     read-only system directories, a clean environment, an output cap and a wall-clock limit.
   - For an agent action, OpenCode runs there with the route's model. Its only way out is an in-sandbox forwarder to an
     allowlisting CONNECT proxy in the web service (for the free route: `opencode.ai` and `models.opencode.ai`, port 443;
     IP literals and private addresses are refused).
   - For a template's check, the script runs with no network at all.
4. **Compute the candidate.** StatePort diffs the staged copy against the base.
   - It refuses paths outside the action's writable set, protected paths, links and oversized changes.
   - It stores content-addressed blobs and builds one `stateport.file-change-proposal/v1` with the unified patch.
5. **Judge.** The template's evaluator runs on the base and on the candidate. Both verdicts are part of the proposal.
6. **Decide.** The owner applies or rejects. Nothing is applied without that decision in Alpha.26.
7. **Apply.** StatePort's own writer applies the operations in bubblewrap, re-runs the template validation, and makes one
   Git commit in the instance (author `StatePort`). The receipt records the commit, both verdicts, the route, the egress
   log and the sandbox digest.

**Chat** uses the same sandbox with every tool denied: an answer is text, never an action. Because the model cannot read
files, StatePort puts the instance's context into the prompt: the files the template's agent actions declare in their
`contextPolicy` (in the template's priority order, bounded to 12 KiB, never `.git`, links or paths outside the instance),
or `state/` when a template declares none, plus pending approvals and recent receipts.

Measured 2026-10-22 on the integrated product (dev loop and the real web image, real free models): ProjectState
setup-project, StudyState setup-study and Decision Log add-question each produced a proposal with both verdicts, applied
as one commit, and the check ran after it.

## 5. The keep-up loop

Instruments change every week, and OpenCode's free catalogue changes from one call to the next. Listed models are not
always runnable. StatePort therefore measures before it trusts.

- **Observe**: refresh the catalogue.
- **Evaluate**: run candidates on a frozen StatePort-owned task suite (`fixtures/model-suite/v1`, digest-checked) with
  deterministic checkers, in the same sandbox as real work.
- **Decide**: a candidate must pass everything the incumbent passes and do better.
- **Apply**: under the owner's "keep up automatically" lease (at most 30 days, one suite run a day), or as a proposal
  the owner accepts.
- **Record**: every step is receipted.

The same loop is the design for the definition level (template releases, as proposals) and the platform level
(StatePort itself, only as signed additive successors that passed the clean-machine journey). Alpha.26 implements the
instrument level. No loop changes its own evaluator, its holdout tasks or its authority.

## 6. Durable state and recovery

- **Instance repositories** are the truth. They live in the web service's data volume, one Git repository per instance.
- **The management store** holds catalog, runs, proposals and blobs, receipts, the conversation store, model-route state
  and settings. Instances can be rebuilt from their repositories; receipts and conversations are backed up with them.
- **Backup** is an instance export with a manifest digest. **Restore** creates a new instance from it.
- **Service, WSL and Windows restarts.** Units are systemd user services under linger, Quadlet-generated, and the
  keep-alive task restarts the distro. A restart recovers interrupted applies from the fsynced apply snapshot before
  serving.

## 7. Lifecycle commands

`~/.local/state/stateport-install/bin/stateport`: `status`, `open`, `url`, `uninstall` (keeps data), `purge` (asks for
typed confirmation, needs `sudo`). Running the one-line command again on the same version keeps the install;
`STATEPORT_REINSTALL=1` reinstalls it, preserving data. On an older installed release, including Alpha.24 installs that
predate the lifecycle receipts, the command offers an in-place upgrade.

## 8. What this architecture does not claim

Isolation is implemented by the mechanisms above and is measured only where a journey probes it (`GET
/v1/sandbox/selftest`, the qualification legs). Provider behaviour is not interchangeable, and a score on StatePort's
practice tasks is evidence about those tasks. Multi-user hosting, native Linux, macOS and unattended autonomy beyond an
owner lease are out of scope.
