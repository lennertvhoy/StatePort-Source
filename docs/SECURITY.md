# Security

> Security principles and practices for StatePort.

This document is a security posture statement, not a certification or audit report.

## Security principles

1. **Explicit state** — all durable state lives in files, not model memory.
2. **Least privilege** — runners and adapters get the minimum permissions they need.
3. **Approval by default** — risky actions require explicit approval.
4. **Audit everything** — every run and every tool call produces an audit event.
5. **No secrets in source** — secrets live in environment variables or a secret store.
6. **Defense in depth** — quota, approval, audit, and access controls overlap.
7. **Fail closed** — when in doubt, block or require approval.

## Secrets handling

- API keys, tokens, and credentials are never committed to the repo.
- Local development uses environment variables or a local secret manager.
- Cloud deployments use Azure Key Vault with managed identity.
- Terraform state must not contain plaintext secrets.
- Rotate keys on suspicion of exposure.

Run `./scripts/gitleaks_scan.sh` locally before committing. CI runs the same
scan against the complete checked-out Git history; the repository's built-in
secret check is an additional lightweight guard, not a replacement for
Gitleaks.

## Least privilege

- The runner can read and write only within the instance folder.
- The runner cannot change its own permissions or template contract.
- Adapters can only write to `inbox/` and read non-sensitive results.
- Admin actions require L5 approval.

## Managed identity plan

For Azure deployments:

- Use Azure managed identities instead of storing credentials in code.
- Container Apps receives a managed identity.
- Key Vault access policy grants only required secret/key permissions.
- Storage access uses identity-based access where possible.

## Tool risk levels

| Level | Description | Examples |
|-------|-------------|----------|
| L0 | Read-only | read instance files, read template |
| L1 | Propose-only | draft a plan without writing |
| L2 | Local state edit | write to instance state files |
| L3 | External side effect | send Telegram message, web search |
| L4 | Destructive/expensive | delete files, use expensive model |
| L5 | Admin/security | change secrets, access controls, IaC |

## Approval gates

- L0/L1: logged, no approval required.
- L2: logged, may require approval based on file scope or count.
- L3: approval required unless pre-authorized for the instance.
- L4: approval required.
- L5: approval required plus admin role.

## Logging and redaction

- Audit logs include who, what, when, and result.
- Secrets, full message payloads, and personal data are redacted by default.
- Logs are append-only and tamper-evident where feasible.
- Retention is configurable and documented in [`GDPR.md`](GDPR.md).

## Backup and restore

- Instance folders are the unit of backup.
- Encourage git-backed instances for history and recovery.
- Cloud deployments may use Azure Storage with versioning.
- Backup schedule and retention are configurable.

## Incident response stub

1. **Detect** — anomaly in audit log, quota alert, or error spike.
2. **Contain** — disable the instance, revoke tokens, block risky tools.
3. **Assess** — review audit log for scope and impact.
4. **Notify** — inform instance owner; escalate per GDPR/NIS2 obligations if required.
5. **Recover** — restore from backup, rotate secrets, re-enable with monitoring.
6. **Learn** — update templates, gates, or runbooks.

## Current limitations

- No penetration testing has been performed.
- No formal security audit has been performed.
- No SIEM integration yet.
- No repository-side secret-scanning service is enabled; local and CI Gitleaks
  checks remain the required baseline.
