# Open-Core Model

> How the open-source and commercial parts of StatePort relate.

## Open-source components

The following are intended to be open source:

- **StateSpec specification** — the file-based state contract (legacy machine identifiers remain compatible with StateDD).
- **StatePort Runner (local)** — the headless agent runner.
- **Template validator** — schema and contract validation.
- **Template lifecycle and fixture tooling** — canonical-source descriptors,
  synthetic public-safe test fixtures, and compatibility readers. Canonical
  domain template repositories retain their own content authority.
- **Admin CLI** — local command-line interface.
- **Telegram adapter basics** — thin adapter skeleton.
- **Documentation** — architecture, security, GDPR, and deployment docs.

## Paid/hosted components

The following are intended to be commercial or hosted-only:

- **StatePort Cloud** — managed control plane.
- **Managed deployments** — Azure deployment as a service.
- **Team permissions** — multi-user instances and role-based access.
- **Cost dashboard** — quotas, usage, and budget visualisation.
- **Backups and exports** — managed backup/restore workflows.
- **Private templates** — proprietary or customer-specific templates.
- **Enterprise support** — SLAs and dedicated support.
- **Compliance packs** — pre-built DPA templates, audit reports, etc.
- **Advanced audit analytics** — search, alerting, retention management.

## Boundary principle

The open-source core must be usable on its own for a single user or small team with local files and local runners. The hosted product adds convenience, scale, and enterprise controls without making the open core artificially limited.

## License

The license is decided: **AGPL-3.0-or-later** for StatePort code and StateSpec
artifacts, **CC BY 4.0** for human-readable documentation. The license
decision (approved 2026-07-22, reconfirmed 2026-07-25) is recorded in the
private-internal `LICENSE_DECISION.md`; see
[`LICENSE`](../LICENSE) and
[`LICENSES.md`](../LICENSES.md).

## Contribution

External contribution intake remains closed until a workable written CLA
process exists (see [`CLA.md`](../CLA.md) and
[`CONTRIBUTING.md`](../CONTRIBUTING.md)). The open-core boundary is recorded
above and the license is decided, but publication and contribution intake
remain separately gated.

Public template contributions are ultimately reviewed and released by the
repository that owns the affected template ID. StatePort evaluation or fixture
maintenance does not transfer that authority. See the private-internal
canonical-template-source-boundary ADR (`docs/adr/0001`).
