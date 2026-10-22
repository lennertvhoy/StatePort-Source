# Updater genesis trust bootstrap — pinned-public-key design

Status: accepted for implementation 2026-08-02 (owner steering directive
STEERING-DIRECTIVE-2026-08-02-001, criterion 1: real-artifact updater
apply/rollback is mandatory for the public alpha).

Supersedes: the `pinned_key_admission_contract_unsupported` genesis boundary
recorded by `scripts/install_no_checkout.py` and the "fail-closed alpha
boundary" prose in release notes / known limitations drafts.

## Problem

The alpha release line signs release indexes with a pinned Cosign public key
(`trustMode: pinned-public-key`). The installer authenticates the genesis
index against an operator-pinned out-of-band trust root, but the updater:

- refused pinned-key admissions in `store.py`
  ("pinned-key admission requires the newer typed proof contract");
- hardcoded `keyless` signer/proof shapes in `engine.py`;
- had no shipped control-plane factory for
  `STATEPORT_UPDATER_CONTROL_PLANE`, no durable trust-root record, and no
  production `UpdateHost` driver.

Result: an installed alpha could never admit, apply, or roll back a real
successor release. Auto-update is an owner-frozen alpha requirement, so this
is a product-design gap, not a limitation.

## Trust architecture

1. **Trust root (genesis).** The operator pins the release trust root out of
   band through installer flags `--trust-public-key`, `--trust-key-id`,
   `--trust-key-fingerprint` (existing). The installer additionally persists a
   durable, create-only trust-root record inside the owner-private updater
   state root:

   - `updater/trust/<keyId>.pem` — exact PEM bytes of the trust public key;
   - `updater/trust/trust-root.json` —
     `stateport.internal-update-trust-root/v1` binding mode
     (`pinned-public-key`), key ID, DER-SPKI fingerprint, channel, target ID,
     the digest of the PEM file, and creation time. Rewriting it with
     different content refuses; the updater never derives trust from a release
     artifact.

2. **Genesis admission.** The installer performs updater genesis through
   `UpdateEngine.initialize` with a `ReleaseVerificationPolicy` whose
   `expected_trust_mode` is `pinned-public-key` and whose
   `accepted_public_keys` is exactly the pinned identity, using the real
   `CosignVerifier`. It then injects the durable installation authority
   through `InstalledAuthorityAdapter.install(...)`, binding installed release
   ID, installation ID, release-index digest, installer digest, target
   identity, accepted image digests, state-root device/inode, channel, and
   exact predecessor (none at genesis). A copied updater state therefore
   obtains no authority over another installation (existing state-root
   binding).

3. **Successor verification.** The updater's control-plane binding rebuilds
   the verification policy from the durable trust-root record — never from
   the candidate release — and verifies successor indexes and image
   signatures with the Cosign verifier against the pinned key.

4. **Rotation.** Trust-root rotation is an operator act through the same
   out-of-band pinning path as genesis (re-run the installer trust pinning
   with the successor key). A release artifact can never rotate the trust
   root in band. A successor signed by a different key is refused as an
   untrusted signer. In-band rotation is deliberately out of alpha scope and
   recorded as a limitation.

5. **Refusals (regression-covered).** Tampered index, unsigned index, wrong
   key ID, wrong fingerprint, mixed keyless/pinned fields, pinned signature
   claiming keyless transparency-log authority, stale or forged admission,
   admission of another installation, and a trust-root file that disagrees
   with its digest all refuse closed.

## Typed pinned-key admission contract

The internal admission record (`stateport.internal-release-admission/v1`)
gains a pinned-public-key proof shape alongside the keyless one:

- signer mapping: `{"mode": "pinned-public-key", "keyId", "publicKeyDigest"}`
  where `publicKeyDigest` is the canonical DER-SPKI fingerprint;
- signature proofs carry `keyId` + `publicKeyDigest` instead of
  `certificateIdentity` + `oidcIssuer`; `scheme` stays `cosign-v3-bundle`;
  `transparencyLog` must not claim keyless transparency authority for a raw
  key (the alpha assembler writes `not-uploaded-private-candidate`);
- `trustMode` on the admission is `pinned-public-key`;
- store validation branches per mode, verifies proofs bind verified signers,
  and requires a verified `release-index` proof exactly as for keyless.

`engine.py` derives signer mappings, proofs, and the admission trust mode
from the verified release and policy instead of hardcoding `keyless`.
`cli.py::_historic_verification_policy` rebuilds `accepted_public_keys` for
pinned admissions.

## Control-plane seam

New module `stateport_updater.control_plane` shipped in the updater wheel:

- `build(state_root)` loads and validates the trust-root record, verifies the
  PEM digest, constructs the `ReleaseVerificationPolicy`
  (`pinned-public-key`, exact channel/target from the record), the
  `CosignVerifier`, and the production host driver, and returns a validated
  `ControlPlaneBinding`.
- The installer writes a wrapper (`state-root/bin/stateport-update`) that
  exports `STATEPORT_UPDATER_CONTROL_PLANE=stateport_updater.control_plane:build`
  and execs the updater CLI from the digest-verified venv.

## Production host driver

New module `stateport_updater.host_local` implements the bounded `UpdateHost`
protocol against rootless Podman and the exact installer-managed layout.
Every effectful step is idempotent for the exact plan digest and persists a
durable effect receipt under `updater/host-effects/<planDigest>/<step>.json`;
`observe_effect_receipt` and crash reconciliation re-read those receipts, so
an unknown effect is never replayed. Evidence returned to the engine passes
its existing bounded-evidence validation (no paths, no secrets).

## Proof obligations (VM, real artifacts)

1. clean genesis installation with durable admission + authority identity;
2. healthy successor update through check/plan/authorize/apply;
3. unhealthy successor refusal and automatic rollback;
4. service restart during update; 5. second restart during reconciliation;
6. exact predecessor restoration; 7. tampered release refusal;
8. wrong-trust-root refusal; 9. cross-install authority refusal;
10. persisted receipt verification.

## Implementation note — gate convergence on receipt

`health_successor`, the journey checks, `health_accepted_route`, and
`state_check_accepted_route` probe live on first execution but short-circuit
to their durable effect receipt on re-execution: the switch intentionally
stops validation units, so engine-reconcile revalidation probes against
already-retired staging would always fail. First execution is always a live
probe; only reconciliation re-reads the receipt.
