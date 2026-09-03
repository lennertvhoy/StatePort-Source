# StatePort documentation map

## Purpose and truth boundary

This map is the current entry point for StatePort documentation. It separates
product principles, implemented local evidence, operational guidance, and
future/public material so that a reader does not mistake a design statement or
a branch-local result for a release claim.

The canonical implementation line is `main`; public-alpha work converges on
private integration branches and reaches the public repository only through a
reviewed exact-path export. Material on
unmerged branches is **unmerged implementation evidence** until it is
independently validated, integrated, and accepted. The public website and
papers follow the same boundary.

## Read by goal

| If you need to… | Start here | Then read | Evidence status |
| --- | --- | --- | --- |
| Understand StatePort's positioning and oversight model | [`POSITIONING.md`](POSITIONING.md) | [`ARCHITECTURE.md`](ARCHITECTURE.md), `PROJECT_DNA.yaml` (`application_oversight_model`) | Framing source; current delivery is bounded in §6 |
| Understand who owns what across the execution seam | [`adr/0003-application-execution-ownership-boundary.md`](adr/0003-application-execution-ownership-boundary.md) | [`POSITIONING.md`](POSITIONING.md) §9, `PROJECT_DNA.yaml` (`ownership_boundary_model`) | Boundary decision only; implementation scoped under BL-BOUNDARY-001 |
| Understand sensitive-context and brokered-secret boundaries | [`adr/0004-sensitive-data-gateway-and-secret-broker.md`](adr/0004-sensitive-data-gateway-and-secret-broker.md) | [`THREAT_MODEL.md`](THREAT_MODEL.md), [`SECURITY.md`](SECURITY.md) | Headless automated foundation implemented; GUI, OS store, and runtime proof open |
| Understand Stateware and StateSpec | [`README.md`](../README.md) | [`ARCHITECTURE.md`](ARCHITECTURE.md), [`NAMING.md`](NAMING.md) | Product model and terminology; not a release contract |
| Try the local StudyState alpha | [`LOCAL_ALPHA_QUICKSTART.md`](LOCAL_ALPHA_QUICKSTART.md) | [`LOCAL_ALPHA_LIMITATIONS.md`](LOCAL_ALPHA_LIMITATIONS.md), [`LOCAL_SERVICE.md`](LOCAL_SERVICE.md) | Linux-first, local-single-user path; no clean-host, release, or human-acceptance claim |
| Build and run the source-checkout container stack | [`../INSTALL.md`](../INSTALL.md) | [`../scripts/install.sh`](../scripts/install.sh), [`../docker-compose.yml`](../docker-compose.yml) | Compose source-build development path; the verified no-checkout Quadlet install path is delivered as a private alpha candidate |
| See the component and ownership map | [`ARCHITECTURE_OVERVIEW.md`](ARCHITECTURE_OVERVIEW.md) | [`ARCHITECTURE.md`](ARCHITECTURE.md) | Diagram reflects the contract and current local boundary; future shapes remain future |
| Learn how an application is bounded | [`ARCHITECTURE.md`](ARCHITECTURE.md) | `TEMPLATE_SOURCE_AND_FIXTURE_POLICY.md` (private-internal), [`INSTANCE_LIFECYCLE.md`](INSTANCE_LIFECYCLE.md) | Contract/design and implemented lifecycle foundations are distinct |
| Understand source trust and installability | `docs/adr/0001-canonical-template-source-boundary.md` (private-internal) | `TEMPLATE_SOURCE_AND_FIXTURE_POLICY.md` (private-internal) | StudyState remains awaiting a verified canonical release |
| Operate the narrow local Codex conversation path | [`operations/CODEX_PROVIDER_SETUP.md`](operations/CODEX_PROVIDER_SETUP.md) | [`LOCAL_SERVICE.md`](LOCAL_SERVICE.md), `docs/EVIDENCE_LOG.md` (private-internal) | Unmerged local proof; opt-in; not production-qualified |
| Diagnose local API and worker services | [`operations/observability.md`](operations/observability.md) | [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) | Local JSONL, request IDs, bounded Compose logs, liveness/readiness; no external telemetry |
| Tear down the Azure alpha stack | [`operations/azure-alpha-teardown.md`](operations/azure-alpha-teardown.md) | `infra/azure/terraform/README.md` | Runbook only; the stack is offline-validated and no apply or destroy has been performed |
| Evaluate the portable Agent Kit direction | [`AGENT_KITS.md`](AGENT_KITS.md) | `TEMPLATE_SOURCE_AND_FIXTURE_POLICY.md` (private-internal), [`INSTANCE_LIFECYCLE.md`](INSTANCE_LIFECYCLE.md) | A bounded exporter exists; release images and downloaded installation are delivered as a private alpha candidate, registry publication remains open |
| Evaluate safety and privacy claims | [`THREAT_MODEL.md`](THREAT_MODEL.md) | [`SECURITY.md`](SECURITY.md), [`DATA_PROCESSING.md`](DATA_PROCESSING.md), [`GDPR.md`](GDPR.md) | Design/control material; no certification claim |
| Find bug, vulnerability, or contribution intake status | [`README.md`](../README.md) | [`SUPPORT.md`](../SUPPORT.md), [`SECURITY.md`](../SECURITY.md), [`CONTRIBUTING.md`](../CONTRIBUTING.md) | All three public routes remain inactive; prepared templates do not activate intake |
| Understand backups, recovery, and updates | [`BACKUP_RESTORE.md`](BACKUP_RESTORE.md) | [`INSTANCE_LIFECYCLE.md`](INSTANCE_LIFECYCLE.md), [`MASTER_COVERAGE_LEDGER.md`](MASTER_COVERAGE_LEDGER.md) | Governed restore-as-new-instance is implemented and contract-tested; in-place platform update is deliberately fail-closed in the alpha (see `packages/updater/README.md`) |
| Inspect current evidence and open work | `docs/EVIDENCE_LOG.md` (private-internal) | `STATUS.md`, `NEXT_ACTIONS.md`, `WORKLOG.md` (all private-internal) | Current truth first; history is not current acceptance |
| Follow public learning material | StatePort-Site `/docs/` | `/tutorials/` and `/releases/` | Public preview only; no installer or release is offered |

## Whitepaper-topic crosswalk

The Stateware whitepaper is a conceptual position paper. The public
documentation package translates each topic into shorter, navigable material
without making product availability claims.

The whitepaper and public site present **continuous, supervised application
operation before governance**, following [`POSITIONING.md`](POSITIONING.md) as
the framing authority: governance is the enabling control layer that makes
persistent operation safe, not the lead product outcome.

| Whitepaper topic | Internal source of record | Public documentation route |
| --- | --- | --- |
| Scope, terminology, and the boundary problem | `README.md`, `docs/NAMING.md`, `docs/ARCHITECTURE.md` | `/docs/foundations.html` |
| Stateware model and core abstractions | `docs/ARCHITECTURE.md`, `docs/TEMPLATE_SOURCE_AND_FIXTURE_POLICY.md` | `/docs/model.html` |
| Installed-instance lifecycle | `docs/INSTANCE_LIFECYCLE.md`, `docs/BACKUP_RESTORE.md` | `/docs/lifecycle.html` |
| Governed actions, grants, and receipts | `docs/API_CONTRACT.md`, `docs/SECURITY.md` | `/docs/governance.html` |
| Threat model, privacy, and limits | `docs/THREAT_MODEL.md`, `docs/DATA_PROCESSING.md` | `/docs/security-and-privacy.html` |
| Host adaptation and provider declaration (opinionated providers; direct Codex evidence) | `docs/POSITIONING.md` §8, `docs/operations/CODEX_PROVIDER_SETUP.md` | `/docs/hosts-and-portability.html` |
| Evidence vocabulary, evaluation, and roadmap | `docs/EVIDENCE_LOG.md`, `STATUS.md`, `NEXT_ACTIONS.md` | `/docs/evidence-and-roadmap.html` |
| Definitions and frequently asked questions | `docs/NAMING.md`, `docs/REFERENCES.md` | `/docs/reference.html` |

## Maintenance rule

When implementation truth changes, update the current-truth files first:
`PROJECT_STATE.yaml`, `STATUS.md`, `NEXT_ACTIONS.md`, and `WORKLOG.md`.
Add user- or operator-facing verified claims to `docs/EVIDENCE_LOG.md`. Then
update this map, affected operational guides, the papers' dated evidence
note, and the public site. Never reverse that order to make a release or
acceptance claim look ahead of its evidence.
