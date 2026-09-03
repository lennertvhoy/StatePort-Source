# Roadmap

> Where StatePort is, what comes next, and what this document deliberately
> does not promise. Current truth lives in `STATUS.md`,
> `PROJECT_STATE.yaml`, and `NEXT_ACTIONS.md`; requirement-level detail lives
> in `BACKLOG.md` and `docs/MASTER_COVERAGE_LEDGER.md`. This map is not
> acceptance evidence.

## Where we are (2026-08-02)

PR #27 is a proven container foundation, not the final public alpha. One exact
audited source candidate built and ran through rootless Podman Compose on Linux
x86-64, kept StudyState durable across two restarts, completed exact Undo, and
passed exact-head remote CI before normal private integration. Its reproducible
claim covers a deterministic audited-source archive; it does not cover OCI
images or a release bundle.

The autonomous workspace-lifecycle incident is closed after three real managed
slices returned the repository to its exact baseline with checkout-independent
evidence and no owner hygiene intervention. That control proof remains valid
while the product scope advances.

Slice A is privately integrated through PRs #29/#30. Its local deployment
contract and rootless-Podman adapter are implemented. The successor-head audit
reconciliation (PRs #31/#32) is privately integrated and closes public-export,
candidate-provenance, exact-build, dependency, schema, observability,
governed-restore, workflow-lint, bundle, and repository-hygiene defects. The
Slice B convergence (PR #34) unified the release, installer, and updater lines
on one schema set; the release-assembler slice delivers the actual image
supply chain (double-built reproducible images with SBOM, scans, and pinned-key
signatures), the signed release index, the no-checkout installer against
that converged contract, and the updater genesis trust bootstrap
(pinned-public-key admissions, durable trust root, installed control-plane
seam, and local Podman host driver) — all as private candidate evidence
pending owner acceptance. In-place update and rollback are implemented for
this alpha; their exact-candidate VM proof rides with the final release
evidence before any GO verdict.

No published image, downloaded installer, Quadlet installation, public-network
deployment, remote/Azure execution proof, current-successor human acceptance,
canonical merge, public release, or production deployment is claimed.

## Active P0 — container deployment public alpha

`BL-CONTAINER-DEPLOYMENT-ALPHA-001` expands the alpha from “StatePort works in
containers” to “StatePort ships in containers and governs supported container
deployments.” The honest support boundary is projects that satisfy a documented
deployment contract, plus reviewable assisted proposals for recognizable
Python, Node, and static-web repositories.

StatePort remains the authority for desired state, proposals, approvals,
accepted revisions, health, history, rollback targets, and receipts. Rootless
Podman, Compose, SSH, and Azure are execution adapters, not deployment truth.
Ubuntu Server 24.04 LTS on Linux AMD64 is the first supported headless host;
rootless Quadlet is the normal installed runtime and Compose remains the
source-build and portability path.

### Slice A — deployment contract and local adapter

- Add `stateport.deployment/v1`, a typed deployment state machine, exact source
  identity, project inspection, declared and assisted profiles, and safe
  port/path/volume/secret policy.
- Implement the local rootless-Podman adapter and `inspect`, `plan`, `apply`,
  `status`, `logs`, `restart`, and `remove` CLI paths.
- Prove Python, Node, static-web, and persistent multi-service fixtures without
  claiming arbitrary repository support.

### Slice B — public image supply chain

- Build exact web, API, and worker images for GHCR; emit SBOMs, vulnerability
  dispositions, provenance, signatures, licenses, health checks, and source
  identity for non-root runtimes.
- Bind public Compose to immutable image digests and prove fresh-machine pull,
  persistent-volume restart, backup/restore, upgrade, and rollback.
- Keep publication, tags, and public release behind separate owner authority.

### Slice C — lifecycle, Execution Capsules, previews, remote target, and UI

- Add revision history, exact upgrade proposals, transactional health-gated
  apply, rollback, persistent-data protections, and truthful interruption
  recovery.
- Support a second Linux x86-64 rootless Podman host over SSH and dogfood the
  system by deploying StatePort/StudyState through StatePort.
- Add one focused deployment page: accepted revision, desired versus observed
  state, service health, ports, volumes, digests, pending approval, receipts,
  and Restart/Upgrade/Rollback/Remove controls with progressive disclosure.

### Slice D — exact-user dogfood

- Install through the website-compatible verified installer, signed release
  index, exact image digests, Quadlet, and updater channel on clean Ubuntu
  24.04 rather than from the development checkout.
- Prove StudyState, representative projects, previews, browser evidence,
  terminal profile, backup, and the alpha update boundary (in-place update
  refuses closed by design; a release move re-runs the installer over
  preserved data); manage StatePort development
  from a separate bootstrap StatePort without self-control.
- Install a durable soak timer and dashboard. Automated soak evidence is not a
  substitute for the owner's multi-day use or final verdict.

### Slice E — Azure VM target

- Provision one least-privilege Ubuntu 24.04 Gen2 VM with Terraform, separate
  control/exec users, data disk, ACR, Key Vault, managed identity, private
  capsule ports, HTTPS ingress, restricted SSH, diagnostics, backup, TTL, and
  exact destroy procedure.
- Live apply requires authenticated subscription/tenant evidence and a reviewed
  estimate proving the disposable test remains within EUR 30 for at most 72
  hours. Otherwise all local Terraform and adapter proof completes and the one
  bounded cloud action remains explicit.

The integrated exit gate includes the 18 original deployment journeys within
the owner's expanded 90-row alpha matrix, exact-head local/remote validation,
downloaded-release and clean-host proof, transition receipts, and automatic
managed-workspace/resource return to baseline.

## Acceptance and release sequence

The prior owner checkpoint is provisional product feedback. Final public-alpha
acceptance moves after Slices A–E pass together on one exact integrated
candidate. Publication, canonical merge, release/tag, and deployment remain
separate explicit decisions.

The owner-provided planning range is earliest 2026-08-03–04, realistic
2026-08-05–08, and conservative 2026-08-09–12 if serious runtime defects are
found. These dates are estimates, not promises.

After the container-deployment alpha and its final owner checkpoint, the next
distinctive post-alpha program is `STATEBENCH-AUTONOMY-LAB-001`. It remains a
controlled synthetic long-horizon harness, not part of this deployment P0.

The planned student rollout remains downstream of exact final acceptance, a
clean public release, and an onboarding kit that contains only verified install
and deployment paths.

## Later phases — no dates, no commitments

- Governed package update transaction with explicit conflicts, migrations,
  validation, and full rollback (`MC-UPGRADE-001`, `FUT-PACKAGE-001`).
- Mode parity across agent-native, assisted, and managed operation
  (`MC-MODE-001`) and the durable job/attempt/run/approval/receipt graph
  (`MC-GRAPH-001`).
- Runs and Sessions cockpit without a second run authority (`FUT-RUNS-001`).
- Parallel subagents with complete lineage and isolated write authority
  (`FUT-AGENTS-001`), scoped knowledge (`FUT-KNOW-001`), reusable reviewed
  skills (`FUT-SKILL-001`), and bounded automations (`FUT-AUTO-001`).
- Sandboxed live preview (`FUT-PREVIEW-001`), provider/model routing
  (`FUT-ROUTE-001`), replaceable execution-host adapters (`FUT-HOST-001`),
  and installable PWA (`FUT-PWA-001`).
- Real-size StateBench programs with frozen configurations, private holdouts,
  forced continuation, and noncompensatory gates (`FUT-BENCH-001`).
- Managed hosting or commercial work only after public release and real usage
  evidence.

Explicitly rejected, not deferred: one generic approval endpoint
(`FUT-GENERIC-APPROVAL-001`) and autonomous self-repair or hidden fleet
routing (`FUT-AUTO-REPAIR-001`).

## Not promised

- No “any project” claim: unsupported repositories receive a proposal, not
  automatic deployment.
- No Kubernetes, managed-cloud, Nix-deployment, Windows-container, ARM64,
  multi-node, autoscaling, or zero-downtime-cluster claim in this alpha.
- No superiority claim without a controlled, reproducible benchmark.
- No dates as commitments.
- PR #27’s remote CI and earlier owner verdict do not transfer to a deployment-
  program head; every delivered commit needs its own evidence.
- No hosted multi-tenant SaaS, billing, compliance certification, public
  deployment, or production-readiness claim at this stage.
