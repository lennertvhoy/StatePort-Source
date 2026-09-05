# Clean-host qualification harness

## Repeatable local public rehearsal (BL-FINISH-21A)

From a clean committed StatePort checkout on the agent workstation:

```sh
python3 infra/qualification/wsl2_rehearsal.py --local-public
```

This entrypoint targets the explicitly authorized, immutable **Alpha.16**
identity. It verifies the public bootstrap/index/key/signature against reviewed
pins, obtains command-bound release admission, and invokes the existing
`~/.kimi-code/governor/heavy-run.sh` with 6144 MiB guest RAM, 2 vCPUs,
6 GiB guest swap, and a 120-minute process ceiling. The governor independently
checks resources. No staged Site, OCI archive path, or prior phase0 receipt is
required; the existing full guest journey runs transport/materialization probes.

Each invocation creates a new private directory under
`~/.local/state/stateport/qualification/local-public/alpha16-*` and a fresh
overlay. It reuses only digest-verified immutable cloud media (the existing
Alpha.16 base when present, otherwise a verified download cache). It never reuses
installed guest state. The journey installs from anonymous Pages/GHCR, checks
web/API/worker health and exact image references, establishes a browser session,
checks execution-host protocol availability, and reruns the installer identically.
Service checks run after both installs. Run the same command again only after
the first boundary passes or its exact failure has been resolved.

`receipt.json`, `command.log`, public verification inputs, governor receipts,
and guest diagnostics are retained. Normal completion and caught failures stop
the owned QEMU process and delete its disposable overlay, seed, and SSH keys;
cleanup failures remain nonzero and preserve the files for investigation.
The governor bounds abrupt failures by killing the owned process group. A forced
termination may leave disposable files; inspect the exact recorded run directory
before removing those files. No broad directory cleanup is performed.

This is **QEMU WSL identity simulation**, never native WSL2 or fresh-Windows
qualification. Cloud-init supplies an SSH user with passwordless sudo, disables
some background timers, and the harness supplies kernel/Windows identity shims
and guest swap. No runtime package is preinstalled by this public setup.
Health/protocol checks do not prove provider use, three-template lifecycle,
reboot recovery, or human acceptance. The other harness lanes below retain their
existing contracts.

This harness records a real guest matrix for the portable
`linux-amd64-rootless-podman-quadlet` target. It does not emulate a guest,
infer support from a distribution name, or turn a command exit status into a
receipt.

## Matrix

One config must contain exactly these coordinates:

- Ubuntu 24.04
- Debian, with the exact version supplied by the operator
- Fedora 44
- One rolling distribution, with the exact version supplied by the operator

Each coordinate uses SSH with `BatchMode=yes`, strict host-key checking, and a
declared `known_hosts` file. The runner first executes a real guest probe. The
probe records hashed machine and boot identities, `/etc/os-release`, kernel,
architecture, cgroup, rootless Podman, Quadlet, systemd-user, and subordinate
mapping observations. Missing identity or an unreachable guest is recorded as
`missing_real_guest_evidence`; it is never replaced with fixture data.

## Stage protocol

The config supplies one argv command for each post-probe stage. Commands must
write exactly one JSON object to stdout and return zero. The object must use
`stateport.qualification-stage-receipt/v1`, set `evidenceClass` to
`real_guest`, bind the supplied `guestId` and candidate, and include the
stage-specific receipt digests described by the schema. Commands receive
candidate placeholders in argv:

- `{guest_id}`
- `{stage_id}`
- `{candidate_digest}`
- `{release_index_digest}`
- `{signed_payload_digest}`
- `{source_commit}`
- `{source_tree}`

The commands are never passed through a shell. A stage that does not emit a
valid receipt fails the journey. `update_rollback` must report a deliberately
induced failure and a rollback receipt. The release-verification stage must
report exact signed-index, signed-payload, source, and image digests.

## Running

```sh
python3 -m infra.qualification.runner \
  --config infra/qualification/example-config.json \
  --output /path/to/new/qualification-run
```

The output contains one receipt directory per guest and the aggregate
`qualification-receipt-manifest.json`. The aggregate digest binds the exact
candidate, observed guests, stage receipt digests, and accepted receipt digest
set.

An entry in `acceptedReceiptDigests` is an exact digest of a complete guest
receipt, not a distro allowlist. A complete real-capability journey absent from
that set is `compatible_unvalidated`; only an exact digest in the set can
produce `validated_baseline`. This harness does not add an accepted digest.

## Ubuntu 24.04 qualification gate

`ubuntu2404_stage.py` is the exact Alpha.4 qualification contract. It accepts
only a schema-valid candidate input set and a separately produced,
digest-matching receipt from one isolated Ubuntu 24.04 guest. The receipt must
prove no checkout or pre-existing StatePort images/services, capability
eligibility, provisioning, installer execution, live `describeCapabilities`
health, persistence/reboot, exact reinstall convergence, and cleanup. Missing
or placeholder receipts refuse with exit code `2`; they never produce a
qualification claim. Debian, Fedora, and rolling remain represented only by
the generic unvalidated matrix above.

`ubuntu2404_guest_stage.py` is the guest-side executable that produces this
receipt. Its `guestStage` config contains explicit argv arrays for the fixed
root-helper materialization, root provisioner, live protocol probe, candidate installer, restart,
StudyState journey, and owned cleanup paths. The normal path verifies release
inputs through `ubuntu2404_stage.py`, requires a root-owned provisioning
receipt, and writes one receipt object plus stage evidence files. The
`--fixture --fixture-input` path is deterministic test-only evidence labeled
`fixture`; the validator refuses it as `real_guest`.

The optional `--verified-candidate-manifest` argument is deliberately refused
for real qualification. A summary manifest cannot replace current verification
of the exact signed index, predecessor, images, and transport bytes.

Successor qualification also requires the predecessor release-index signature
bundle at `predecessor-bundle/<signed bundle name>`. Its bytes and canonical
transport path are bound to the embedded predecessor signature, reverified with
the same pinned key, and passed to both provisioning and installation through
the exact release bundle root. A missing, moved, swapped, or tampered sidecar
refuses before guest lifecycle effects.

## Local qualification transport

`scripts/qualification/build_j1_candidate.py` creates the reserved,
non-release `0.1.0-alpha.900001` envelope from a preserved image build receipt.
It materializes a local sanitized Git snapshot, builds the updater from that
snapshot, collects fresh evidence from the retained OCI archives, and invokes
the production release assembler. It signs the release index and retained OCI
manifest bytes with an ephemeral qualification key; it never accepts a
template index, arbitrary updater bytes, the production trust key, or public
publication.

`wsl2_rehearsal.py --phase0-only` accepts `--archive-root` and loads those
archives into a guest-local TLS registry before running only the bootstrap
transport probe and materialization preflight. The receipt binds the exact
index, signed payload, bootstrap bytes, archive bytes, and image manifest
digests. The production bootstrap and installer remain unchanged. A full run executes
transport and materialization checks before installation and no longer requires
a separate phase-0 run. Optional `--phase0-receipt` evidence must still pass and
match the exact current candidate; stale or failed receipts refuse.

Before publication, production candidates still name their immutable
`ghcr.io/lennertvhoy` digest references while those manifests are intentionally
absent from GHCR. The guest therefore configures a narrow, digest-only
`containers-registries.conf` mirror from that namespace to the guest-local
registry populated from retained OCI archives. Tags, other namespaces, signed
index bytes, bootstrap bytes, installer bytes, and image bytes are unchanged.
Post-publication anonymous rehearsal removes this staging boundary by using the
public Site and GHCR transports directly.

Pass `--public-transport` only after the exact Site and GHCR bytes are public
and anonymously verified. `--site-root` and `--archive-root`
still bind the host-side candidate identity, but the harness
does not copy the Site or archives into the guest. It installs no rehearsal CA,
hosts override, local registry, or registries.conf mirror, and records those
absences before the public bootstrap fetch and install.

`stage_j1_site.py` stages both reserved `0.0.0-j1.<number>` candidates and
public `0.1.0-alpha.<number>` candidates. Their manifest transport slugs are
`j1-<number>` and `alpha<number>` respectively, matching the immutable
bootstrap probe root for each lane.

## Resource-safe operation

Run each qualification phase once, in the foreground, through the host's
background-safe governor. Keep the command log and receipt as the durable
completion signal; do not start detached shell loops that poll a process and
wait for it later. The governor serializes heavy work, waits for memory, disk,
pressure, OOM, swap-I/O, and competing-VM safety conditions, and applies the
bounded CPU, memory, swap, priority, and runtime limits.

The release-qualified WSL2 profile is fixed at 6144 MiB guest RAM, 2 vCPUs,
and 6 GiB guest swap. Reducing that profile may be useful for exploration, but
the result is not equivalent qualification evidence and must not be labelled
as such. Use `--diagnostic` for an explicitly non-qualifying 4096 MiB run;
otherwise let the governor wait until the qualified profile can run safely.

Use `--keep-vm` only when an immediately following journey is intentionally
bound to that retained VM. Omit it for standalone runs. Ad-hoc Podman probes
must use `--rm` and an owned loopback port so interrupted experiments do not
leave a named container consuming resources.
