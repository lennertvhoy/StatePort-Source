# Azure Deployment

> Azure deployment notes for StatePort.

This document describes the intended Azure deployment pattern. It is a scaffold only; no Azure resources are created in the MVP and `terraform apply` must not be run without explicit approval.

> **Alpha topology note (2026-08):** the alpha IaC under `infra/azure/terraform/` targets a single Ubuntu 24.04 LTS VM with rootless Podman, ACR, Key Vault, and managed identity — not Azure Container Apps and not AKS. The Container Apps sketch below is retained as historical context only. The Terraform is offline-validated; no live Azure proof exists.

## Default region

- **Primary:** Azure Belgium Central (`belgiumcentral`) where available.
- **Fallback:** another EU region supporting the EU Data Boundary commitment.

Microsoft lists Belgium Central in Brussels with availability zone support.

## EU Data Boundary

Microsoft documents an EU Data Boundary commitment for storing and processing customer data and personal data inside EU/EFTA regions for covered enterprise online services. StatePort's default region selection is designed to align with this commitment, but the customer's Azure subscription and service coverage determine actual data-boundary treatment.

## Target services (historical Container Apps sketch)

| Service | Purpose |
|---------|---------|
| Azure Container Apps | Host the containerized runner and adapters |
| Azure Key Vault | Store secrets, API keys, tokens |
| Managed Identity | Avoid credentials in code |
| Azure Storage | Optional hosted state/backups |
| Log Analytics / Azure Monitor | Logs and observability |
| Azure Cost Management | Budgets and cost alerts |
| Entra ID | Future admin dashboard authentication |

## Terraform structure

```
infra/azure/terraform/
  versions.tf
  providers.tf
  variables.tf
  main.tf
  outputs.tf
  locals.tf
  envs/
    dev.tfvars.example
```

See the files themselves for the current scaffold.

## Secrets handling

- Terraform variables must not contain plaintext secrets.
- `dev.tfvars.example` contains placeholders only.
- Real values come from environment variables, Key Vault, or a local secret manager at runtime.

## Managed identity

- The Container Apps app receives a system-assigned or user-assigned managed identity.
- Key Vault access policy grants only required secret permissions (`Get`, `List`).
- Storage access uses identity-based Azure RBAC where possible.

## Network boundaries

- Default public Container Apps endpoint for the MVP.
- Future hardening: VNet integration, private endpoints for Key Vault/Storage.
- Telegram webhooks require a public HTTPS endpoint.

## Logs and monitoring

- Application logs go to Log Analytics.
- Audit events are structured JSON.
- Cost Management budgets alert on monthly spend.

## Terraform state

- Use a remote backend for shared state (Azure Storage with versioning).
- Do not commit `.tfstate` files to git.
- Encrypt backend state.

## Current status

- Terraform skeleton created.
- No resources deployed.
- `terraform apply` is intentionally not run.
- Further hardening required before production use.
