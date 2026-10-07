# StatePort release contracts

`stateport_release` is the checkout-independent Python contract used by the
installer and updater. It owns:

- strict `stateport.release-index/v1` parsing and cross-field binding;
- `stateport.canonical-json/v1` bytes and SHA-256 digests;
- explicit channel, target, updater-version, expiry and deprecation policy;
- a detached Cosign v3 bundle verifier interface with a caller-pinned
  certificate identity and OIDC issuer.
- `to_updater_release_envelope(VerifiedRelease)` as the sole normalized bridge
  into updater state (index/signed digest, source, target topology, images,
  complete install artifacts and image evidence, supply-chain policy,
  compatibility, predecessor/rollback, and publication identity).

The bridge is an in-memory verified projection, not a second persisted release
format. Persist `UpdaterReleaseEnvelope.canonical_index_bytes` and call
`reverify_updater_release_envelope` before reuse. The constructor is closed so
callers cannot inject an independent topology. `verify_quadlet_bundle` likewise
accepts only a verified release/envelope and checks the exact executable unit
set, signed image/user/socket authority, and deterministic
`path\0length\0bytes` content digest.

Update plans carry a digest-derived plan ID, exact `planDigest`, and expiry.
`validate_update_plan(..., now=...)` rejects not-yet-active or stale plans. Its
authority `runId` equals the exact plan digest and the action is bound to update
versus rollback. Pre-effect authority uses StatePort's canonical decision,
reservation, and claim; `stateport.update-authority-link/v1` links the terminal
authority receipt only after the update receipt exists.

`validate_release_index(..., require_signatures=False)` exists only for the
candidate assembly step. Install/update consumers must use the default strict
validation and `verify_release_index`; a digest match is never authentication.

The exact public/dogfood signing identity is deliberately not baked into this
package. Until an OIDC identity or Secret Broker-backed key is approved and
proven, production trust-root status remains unresolved. Tests may use an
explicitly labelled ephemeral verifier, but that is not release signing proof.
Private candidate descriptors use `not-uploaded-private-candidate`; uploading
private repository/candidate identity to a public transparency log is not an
implicit build step. A published release requires
`required-public-release`, and that public-log action remains a separate
publication boundary.

`compatibility.predecessor` is an exact release identity (`releaseId`,
`version`, and `signedPayloadDigest`), not a version alias. Candidate
`publication.publishedAt` is deliberately `null`; consumers must not invent a
publication time. Each image `sizeBytes` is signed authority for the exact
compressed OCI manifest/config/unique-layer byte inventory. It is a bounded
staging input, not a promise about transfer overhead or expanded disk use.

The signed topology is authoritative. Installers must create only the declared
services and images; unused API/worker images, `.git` mounts, and inferred
services fail the contract.

## Revision activation boundary

Release services are staged as inert, digest-pinned Quadlet templates outside
the live user roots. The contract gives every validation and accepted service a
full 64-hex revision identity, deterministic collision-probed loopback ports,
and `Pull=never` runtime semantics. Validation uses read-only backup snapshots;
the accepted revision receives a distinct promoted data generation (D1), never
the predecessor's writable volume or a validation volume.

Services may share durable installation state only through an explicit signed
`sharedWritableVolumes` entry. Its exact members use one canonical volume key,
one snapshot, and one accepted data generation; attachment metadata must match,
and the current coordination contract is local SQLite immediate transactions
plus POSIX advisory locks.

Activation is deliberately one-way and non-circular:

1. a plan binds the exact approved operation-plan digest, signed release,
   historic signature-verification proof set, port proposal, data-promotion
   specification, and precomputable owner-unit projection;
2. exact port-reservation and D1-promotion receipts are produced, and every
   staged path and byte is re-derived from the signed template bundle before it
   can cross the accepted boundary;
3. a durable activation decision binds those receipts and the StatePort
   authority reservation and claim, which must resolve byte-for-byte through a
   protected canonical authority-store resolver rather than caller-created
   self-digests;
4. owner bundles and regular systemd/route projections are atomically written
   and fsynced within their own logical roots, then daemon-reloaded and exercised
   by an explicit start/observe/stop check;
5. an immediate, collision-free port observation remains valid through the
   effect, and the terminal acceptance receipt binds that observed check and
   the canonical authority finalize receipt; only then may the accepted pointer
   be compare-and-swapped and ingress unfenced.

No activation decision can contain its later terminal receipt digest. Reboot
recovery starts only the revision named by the accepted pointer and its bound
terminal receipt. Per-user reconciliation is receipted and ordered; cross-user
atomicity is explicitly not claimed. Accepted data promotion binds the exact
current pointer, predecessor release, signed payload, data generation, and data
generation digest so a successor cannot migrate from stale retained data.

The execution-host daemon, updater, and any other stable host services use a
separate out-of-revision lifecycle. A normal releasable target is a
`stable-host-daemon-client`; `stable-host-daemon-bootstrap-only` is reserved for
explicit operator bootstrap and cannot pass normal release policy. Stable host
services have their own digest-pinned Quadlets, typed create/retain/compatible
replace plan, owner-confined writable roots, execution-only rootless-Podman
socket authority, loopback-only ports, image-provided health probe, bounded
resources, and bounded `k8s-file` logs. They never enter revision activation.

The exact Ubuntu 24.04 LTS baseline proof is opt-in and uses Noble's packaged
Podman/Quadlet 4.9.3 generator:

```bash
STATEPORT_NOBLE_QUADLET_493_PROOF=1 \
STATEPORT_NOBLE_PODMAN_493_DEB=/absolute/path/to/podman_4.9.3+ds1-1ubuntu0.2_amd64.deb \
PYTHONDONTWRITEBYTECODE=1 \
pytest -q -p no:cacheprovider scripts/test_release_contracts.py
```

`STATEPORT_NOBLE_PODMAN_493_DEB` must be an absolute path to the separately
verified Noble package. A second, separately labelled compatibility proof can
exercise the installed host Quadlet 5.8.4 generator by adding
`STATEPORT_NOBLE_SYSTEMD_HOST_QUADLET_584_PROOF=1`; it does not replace or get
reported as the Noble 4.9.3 support proof. These helpers are test
infrastructure, not StatePort release artifacts or supply-chain authority. This
package proves contracts and deterministic materialization; it does not by
itself prove a published installer, real Cosign signing identity, or an
installed updater.
