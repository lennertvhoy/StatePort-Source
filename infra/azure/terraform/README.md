# StatePort public-alpha Azure topology

Terraform for the StatePort alpha target architecture: **one Ubuntu 24.04 LTS
Gen2 VM running StatePort with rootless Podman**, plus the minimal supporting
services. No AKS, no Container Apps.

> **Status: OFFLINE-VALIDATED ONLY. No `terraform apply` has been performed.**
> Apply requires ALL of: explicit owner approval, refreshed Azure auth, an
> exact reviewed `terraform plan`, estimated cost under EUR 30 total, and the
> 72-hour TTL acknowledged. See [Apply gates](#apply-gates).

## Topology

| Module         | Creates                                                                 |
| -------------- | ----------------------------------------------------------------------- |
| `network`      | 1 VNet, 1 subnet, 1 NSG (443 inbound from `*`; SSH 22 only from `allowed_ssh_cidrs`, default empty = SSH fully denied) |
| `host`         | 1 public IP (HTTPS endpoint only), NIC, Ubuntu 24.04 Gen2 VM (`Standard_B2s`, system-assigned identity, key-only SSH), 64 GiB data disk (LUN 0), cloud-init bootstrap |
| `identity`     | All RBAC wiring: VM identity gets `AcrPull` on ACR and `Key Vault Secrets User` on the vault — nothing else |
| `registry`     | ACR Basic, admin account disabled (pull via managed identity only)      |
| `vault`        | Key Vault standard, RBAC authorization mode, 7-day soft delete, purge protection off (ephemeral alpha) |
| `storage`      | Standard LRS storage account (TLS 1.2+), `backups` blob container, boot diagnostics target |
| `backup`       | Recovery services vault, daily VM backup policy (23:00 UTC, 7-day retention), protected VM (covers OS + data disk) |
| `diagnostics`  | Log analytics workspace, 30-day retention                               |
| `budget`       | Resource-group consumption budget, EUR 30/month, email alert at 90% of actual spend |

DNS/TLS is deliberately **not** provisioned: there is no domain resource we
can validate offline, and fabricating one (or a self-signed cert resource)
would be worse than an explicit gap. The operator terminates TLS on the host
behind port 443 and points their own DNS at the VM's public IP.

### Host bootstrap (cloud-init)

`modules/host/templates/cloud-init.yaml.tftpl`:

- creates `stateport-control` (control services) and `stateport-exec`
  (execution workloads) as distinct unprivileged, non-login users
- installs `podman`, `uidmap`, `slirp4netns`, `fuse-overlayfs` (rootless
  Podman prerequisites) — **apt is the only network access at provision time**
- formats/mounts the data disk at `/var/lib/stateport` (idempotent:
  `overwrite: false`)
- enables `loginctl enable-linger` for both service users (systemd `--user`
  and rootless Podman survive logout); cgroup v2 is verified by the installed
  `/usr/local/sbin/stateport-host-check` readiness probe
- stages an empty `/opt/stateport` for the **no-checkout installer**, which
  the operator copies in afterwards — cloud-init never downloads it

### Networking decisions

- Exactly **one public IP**, on the VM's only NIC. It serves the HTTPS
  endpoint and nothing else.
- **No public ports for workspaces/previews** — they stay behind the host's
  own loopback/reverse-proxy boundary on 443.
- **No public Podman API.** Podman is rootless and local-only.
- SSH is opt-in per apply via `allowed_ssh_cidrs`; the default `[]` creates
  no SSH rule at all.

## Files

- `versions.tf` / `providers.tf` — Terraform `>= 1.9`, azurerm pinned to the
  exact init-resolved 4.x release (see `.terraform.lock.hcl`)
- `main.tf` — root module wiring; `variables.tf`, `locals.tf` (common tags:
  `ttl`, `temporary = "true"`), `outputs.tf`
- `modules/<name>/{main,variables,outputs}.tf` — the nine modules above.
  Per-child-module standalone `terraform validate` is not applicable: the
  children are validated through the root module
- `envs/dev.tfvars.example` — placeholder values only, no secrets

## Usage

```bash
cd infra/azure/terraform
cp envs/dev.tfvars.example envs/dev.tfvars   # fill in your SSH public key

terraform init -backend=false                 # local state only for alpha
terraform fmt -check -recursive
terraform validate

# Requires Azure credentials (az login or ARM_* env vars):
terraform plan -var-file=envs/dev.tfvars -out=alpha.tfplan

# Only after ALL apply gates below are satisfied:
terraform apply alpha.tfplan

# Mandatory teardown within the 72h TTL (see
# docs/operations/azure-alpha-teardown.md for the RSV/KV hazards and
# post-destroy verification):
terraform destroy -var-file=envs/dev.tfvars
```

## Apply gates

No apply has been performed. Before any `terraform apply`:

1. explicit owner approval for this exact stack,
2. refreshed Azure authentication (`az login` / fresh `ARM_*`),
3. an exact reviewed plan (`terraform plan -out` artifact reviewed, not just
   console output),
4. total estimated cost under **EUR 30** for the run,
5. the **72-hour TTL** acknowledged — `terraform destroy` within 72h of apply.

## Cost estimate approach

Rough pay-as-you-go figures for `belgiumcentral`, 72 h (verify current
prices before apply — these are planning numbers, not quotes):

- VM `Standard_B2s` (2 vCPU / 4 GiB): ~EUR 0.04/h → ~EUR 3 for 72 h
- OS disk (30 GiB Standard LRS) + data disk (64 GiB Standard LRS): ~EUR 4/month-equivalent, i.e. well under EUR 1 for 72 h
- ACR Basic: ~EUR 0.15/day → ~EUR 0.5
- Storage LRS + log analytics (minimal alpha volume): < EUR 1
- Recovery services vault (protected VM): the largest line, ~EUR 5–10/month-equivalent → a few EUR for 72 h
- Public IP (Standard, static): ~EUR 0.005/h → < EUR 1

Expected total: **well under EUR 30** for the full 72-hour TTL. Recompute
against the Azure pricing calculator before apply; if the estimate crosses
EUR 30, do not apply.

The EUR 30 gate is also machine-enforced: the `budget` module creates a
resource-group consumption budget of EUR 30/month that emails
`budget_notification_email` when actual spend crosses 90%. It is an alert,
not a hard stop — the procedural estimate gate above and the 72-hour
destroy deadline still apply.

## State and secrets

- Local state (`-backend=false`) for the ephemeral alpha. Never commit
  `*.tfstate*`; it may contain resource IDs and attributed data.
- Terraform never sees real secrets. Key Vault contains no
  Terraform-managed secrets; the operator sets values out-of-band
  (`az keyvault secret set`) with their own RBAC grant.
- `envs/dev.tfvars.example` holds placeholder values only. The SSH public
  key is not a secret.
