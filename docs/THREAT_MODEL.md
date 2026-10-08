# Threat Model

> Initial threat model for StatePort.

This is a lightweight threat model for the MVP skeleton. It will be refined as the implementation grows.

## Trust boundaries

1. User device / Telegram client
2. Telegram servers
3. StatePort adapter (Telegram / CLI)
4. StatePort runner
5. Instance filesystem / storage
6. Tool providers (web search, GitHub, model APIs)
7. Azure infrastructure (cloud mode)
8. Key Vault / secret store

## Assets

- Instance state files (primary asset)
- Audit logs
- API keys and tokens
- Template contracts
- User/trainer/student personal data
- Runner compute budget

## Threats and mitigations

### T1 — Secret leakage

- **Risk:** API keys or Telegram tokens committed to git or logged.
- **Mitigation:** `.gitignore` patterns; no secrets in repo; environment/Key Vault only; audit log redaction.

### T2 — Unauthorized instance modification

- **Risk:** Runner or adapter writes outside allowed scope.
- **Mitigation:** sandboxed instance folder; approval gate for writes; validator checks.

### T3 — Unbounded cost

- **Risk:** Runaway model usage or tool calls.
- **Mitigation:** quota engine; monthly euro budget estimate; budget alerts.

### T4 — Malicious input

- **Risk:** Telegram message triggers unintended action.
- **Mitigation:** input normalization; template-defined allowed actions; approval gate.

### T5 — Audit tampering

- **Risk:** Attacker modifies audit log to hide actions.
- **Mitigation:** append-only logs; tamper-evident storage; export to immutable store.

### T6 — Supply-chain/template tampering

- **Risk:** Malicious template grants excessive permissions.
- **Mitigation:** template validator; signed templates; review before activation.

### T7 — Cloud credential exposure

- **Risk:** Terraform state or container image contains secrets.
- **Mitigation:** remote encrypted backend; managed identity; secret scanning.

### T8 — External message abuse

- **Risk:** Agent sends messages to wrong recipients or spam.
- **Mitigation:** approval gate for external sends; allow-listed recipients.

## Alpha release surfaces (2026-08 refresh)

This section covers the public-alpha release surfaces. It does not replace a
full STRIDE pass; it records the boundaries the alpha actually enforces.

### T9 — Release-index and installer tampering

- **Risk:** a tampered release index, installer, image, or updater wheel is
  accepted as a genuine release.
- **Mitigation:** the release index is signed with the offline alpha trust
  key; the installer verifies the index signature, the exact trust key
  fingerprint, every image digest, the installer/updater/source-archive
  digests, and refuses floating tags as authority. Tampering at any bound
  artifact fails closed. The private key never enters Git, logs, or images.

### T10 — Registry and update-channel attacks

- **Risk:** mutable tag movement, wrong-digest substitution, partial pulls,
  or registry unavailability corrupt an installation or update.
- **Mitigation:** digest-pinned pulls only; wrong digests refuse; mutable
  tags are never accepted as release authority; interrupted staging is
  cleaned before terminal failure; no non-idempotent effect is replayed
  from uncertainty; rollback requires an exact predecessor receipt.

### T11 — Updater recovery forgery

- **Risk:** forged, missing, stale, mismatched, or unclaimed recovery
  evidence tricks the updater into replaying an unknown effect.
- **Mitigation:** every persisted effect receipt is reread before recovery;
  unknown, mismatched, forged, stale, or unclaimed receipts refuse;
  authority binds the exact installed identity (release ID, installation
  ID, release-index digest, installer digest, image digests, state root,
  channel, predecessor). A copied updater state holds no authority over
  another installation.

### T12 — Local same-UID attacker (explicit alpha boundary)

- **Risk:** a process running as the same OS user as the StatePort
  installation rewrites, forges, or deletes local state — including
  authority receipts (`maxActions`/`maxCostUsd` usage derives from the
  receipt files present) and the hash-chained audit log, whose keyless
  hashes protect against accidental corruption, not adversarial rewrite.
- **Alpha boundary:** same-UID attackers are **out of scope** for the
  alpha. A same-UID writer can already read every StatePort-readable
  secret, terminate services, and edit the state stores directly; keyless
  integrity mechanisms cannot change that. Receipts and the audit chain
  therefore guarantee accident detection and exact sequencing, not
  resistance to a local write attacker.
- **Post-alpha hardening (tracked):** HMAC-anchored receipts and audit
  chain with the key held outside the writable stores, receipt deletion
  detection via `previousReceiptDigest` chaining, and stricter audit file
  permissions.

### T13 — Browser and preview boundary

- **Risk:** DNS rebinding, cross-origin requests, or a compromised
  deployment reaches the StatePort session, control-plane endpoints, or
  cloud metadata addresses.
- **Mitigation:** fail-closed Host/Origin/CSRF validation with
  duplicate-header rejection; loopback-only default bind (public bind
  requires an explicit operator flag); strict CSP with no inline scripts;
  per-deployment isolated internal Podman networks; no preview proxy in
  the alpha (the surface is structurally absent); session credentials are
  never forwarded to deployments.

### T14 — Execution-host and workspace escape

- **Risk:** a governed run escapes its worktree, reads another project, or
  obtains broader authority than its grant.
- **Mitigation:** exact repo/worktree/branch identity binding; instance
  leases; snapshot drift aborts; subagents inherit strictly narrower
  authority and cannot self-expand; no engine socket inside runtime
  containers; budgeted, receipted actions only.

## Current limitations

- No formal STRIDE analysis yet.
- No penetration test results.
- No independent security review; all review to date is internal
  (`internal_multi_agent`, independence not established).
- Same-UID local attackers are out of scope for the alpha (see T12).
- Threat model will continue to expand.
