# StatePort updater runtime

The updater is a separately packaged, non-root Python 3 runtime. Its wheel
contains the canonical `stateport_release` contract package and has no
third-party runtime dependency. Its long-lived
surface is deliberately read-only and loopback-only:

```text
python -m stateport_updater --state-root /var/lib/stateport-updater serve \
  --listen 127.0.0.1 --port 8091
```

Endpoints:

- `GET /healthz`: process identity and liveness;
- `GET /readyz`: canonical status validation and digest;
- `GET /v1/status`: exact `stateport.update-status/v1` document projected from
  one coherent persisted-status and pending-WAL snapshot.

The loopback response is classified `host-public`: it contains exact release
and update state but no secret or private path. `HEAD` runs the same bounded
checks without a body. Malformed, absolute, and mutation request targets fail
closed, and unexpected diagnostics errors are reduced to stable public codes.

Mutation flows through the typed control-plane seam. The wheel ships the
installed-subject authority adapter (`InstalledAuthorityAdapter`): installed
authority derives only from a create-only installed-identity chain anchored
under the state root, injected once by the installer through
`InstalledAuthorityAdapter.install(...)` after the durable status and release
admission exist — never fabricated from a branch, a path, or a caller argument.
Every installed decision binds that exact identity as its grant, and a
successful update or rollback advances the chain to the exact accepted
successor before the receipt is terminal. The execution host and signature
verifier are injected by the control plane through `ControlPlaneBinding`,
either programmatically (`main(..., control_plane=...)`) or through the
`STATEPORT_UPDATER_CONTROL_PLANE=module:factory` environment seam. Without
that binding, `check`, `plan`, `apply`, `rollback`, and `reconcile` fail
closed with `installed_authority_adapter_required`; `apply` and `rollback`
additionally refuse before touching any state unless an exact authorization
bundle produced by `authorize` is presented. `authorize` and `policy set`
need no injected host: they act through installed authority alone.
`AuthorityManagerAdapter` remains the repository-backed development/test
adapter; it performs no import-time Git or source lookup.

Alpha trust line (v0.1.0-alpha.1): the alpha signs its release index and
images with a pinned operator key. The installer pins that trust root out of
band (`--trust-public-key`/`--trust-key-id`/`--trust-key-fingerprint`),
persists it as a create-only record under `updater/trust/`, retains every
admitted release-index signature bundle create-only and digest-checked in
content-addressed slots under `updater/bundles/` (genesis and successor
bundles share the `release-index.sigstore.json` basename, so the slot key is
the recorded digest, and retained bytes grant no authority until a signature
over them verifies), and performs
genesis through `UpdateEngine.initialize` plus
`InstalledAuthorityAdapter.install(...)`, so the installed-initialize
admission and the installed-authority identity exist durably from first
install. The admission contract accepts pinned-public-key proofs through the
typed contract (keyId + publicKeyDigest; a raw key can never claim keyless
transparency-log authority). The installed control-plane seam ships as
`stateport_updater.control_plane:build` and rebuilds the verification policy
from the durable trust root — never from a candidate artifact — behind the
`stateport-update` wrapper the installer writes into the state root, driving
`check`/`plan`/`apply`/`rollback`/`reconcile` through the local Podman host
driver. Trust-root rotation is an operator act through the same out-of-band
pinning path; a release artifact can never rotate the trust root in band.
Exact-candidate VM proof of the full update/rollback matrix is part of the
release evidence for this alpha; until that evidence exists, treat in-place
update as implemented but unaccepted.

The flat command surface is `health`, `ready`, `status`, `check
--release-index`, `plan [--release-index | --rollback]`, `policy [set ...]`,
`authorize --plan-id --output`, `apply|rollback --plan-id --authorization`,
`reconcile [--resolution]`, and `serve`. `check` mutates no updater state
beyond the inert bundle retention above; `plan` persists the exact verified candidate and its plan; every refusal is a
typed payload with a stable public code.

Store lifecycle is explicit. Installation or a migration uses
`UpdateStore.create(...)` once; diagnostics and reconstructed processes use
`UpdateStore.open_existing(...)`, which is path-pure and refuses an absent or
permission-drifted store. Every effectful execution-host operation must leave a
create-only, plan-and-step-bound effect receipt in the execution trust domain.
Recovery re-reads that receipt before a WAL step may be skipped, and rereads
canonical terminal authority before accepting a historic updated release.
Unknown rollback or cleanup effects require the typed `retry_rollback` or
`retry_cleanup` operator resolution; they are not replayed by observation alone.

Installation identity is per state directory. `UpdateStore.create(...)` writes a
create-only `manifest.json` with a random 128-bit `installationId`, and every
release admission, update plan (through its plan digest and authority run
binding), update receipt, and the projected `stateport.update-status/v1`
document names that identity. The installed-authority chain additionally binds the
native device and inode of the state root, so a copied or relocated state
directory is refused as foreign state (`foreign_state_refused`) instead of
silently inheriting installed authority. Records from a different installation
presented without the manifest are refused at the store boundary, so receipts,
admissions, plans, and status can never be mixed across installations.

The service refuses non-loopback binds, bounds request concurrency and read
time, and refuses all HTTP mutation methods. A Quadlet health check should use
`http://127.0.0.1:8091/readyz`; the container image should run as a non-root
user with a read-only root and one explicit writable updater-state volume.
