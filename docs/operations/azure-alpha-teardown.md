# Azure Alpha Teardown

Runbook for destroying the StatePort public-alpha Azure stack defined in
`infra/azure/terraform/`. No step in this document has been executed: the
stack is offline-validated only, no `terraform apply` has been performed, and
**no live action — apply, destroy, or any `az` command against the real
subscription — happens without explicit owner approval.**

## TTL discipline

The stack carries a `ttl = "72h"` tag and a `temporary = "true"` tag on every
resource. The contract: destroy within 72 hours of apply.

- Record the exact apply timestamp in the ops ledger at apply time (UTC).
- The owner decides enforcement; the ledger entry is the auditable record.
- The resource-group consumption budget (EUR 30/month, email alert at 90% of
  actual spend) is the machine-enforced backstop, not a substitute for the
  destroy deadline.

## Destroy

From the Terraform root:

```bash
cd infra/azure/terraform
terraform destroy -var-file=envs/dev.tfvars
```

Use the same var file that was used for apply so resource naming and sizes
match the live state exactly.

## Hazard: Recovery Services Vault

Deleting the vault (`<base>-rsv`) can fail even after `terraform destroy`
removes the `azurerm_backup_protected_vm`: Azure VM backup keeps protected
items in a **soft-deleted state** (default retention 14 days), and a vault
with soft-deleted backup items cannot be deleted. If destroy stalls on the
vault:

1. Stop protection and delete backup data for the protected VM (idempotent
   if Terraform already stopped it):

   ```bash
   az backup protection disable \
     --resource-group stateport-dev-rg \
     --vault-name stateport-dev-rsv \
     --backup-management-type AzureIaasVM \
     --workload-type VM \
     --container-name <vm-container-name> \
     --item-name <vm-item-name> \
     --delete-backup-data true --yes
   ```

2. List remaining items, including soft-deleted ones:

   ```bash
   az backup item list \
     --resource-group stateport-dev-rg \
     --vault-name stateport-dev-rsv \
     --backup-management-type AzureIaasVM \
     --include-soft-delete -o table
   ```

3. If soft-deleted items remain and the stack must be fully gone now (not in
   14 days), disable soft delete on the vault, then re-delete those items:

   ```bash
   az backup vault backup-properties set \
     --resource-group stateport-dev-rg \
     --name stateport-dev-rsv \
     --soft-delete-feature-state Disable
   # repeat step 1 for each soft-deleted item, then re-check step 2
   ```

   Portal equivalent: Recovery Services vault → **Backup items** → stop
   backup / delete backup data; **Properties → Security** → disable soft
   delete; then delete the soft-deleted items.

4. Re-run `terraform destroy -var-file=envs/dev.tfvars` to finish.

For a 72-hour stack, the cleanest path is to destroy before the first daily
backup (23:00 UTC) completes, so no recovery points exist.

## Hazard: Key Vault soft delete

The vault (`<base>-kv`) is created with 7-day soft delete and purge
protection off. The azurerm provider is configured with
`purge_soft_delete_on_destroy = true`, so `terraform destroy` purges the
vault rather than leaving it soft-deleted. Verify afterwards:

```bash
az keyvault list-deleted -o table
```

The alpha vault name must not appear. If it does, purge it explicitly:

```bash
az keyvault purge --name <vault-name>
```

## Post-destroy verification

The resource group and everything in it must be gone:

```bash
az group show --name stateport-dev-rg
az resource list -g stateport-dev-rg -o table
```

Expected: `az group show` returns `ResourceGroupNotFound`; if the group
somehow remains, `az resource list` must be empty before any manual
`az group delete`. Also confirm the consumption budget is gone with the
group (it is a resource-group-scoped resource and is destroyed with it) and
record the destroy timestamp in the ops ledger next to the apply timestamp.

## Local disposal

Local state and plan files contain resource IDs and attributed data and are
not part of the repository:

```bash
rm -f terraform.tfstate terraform.tfstate.* alpha.tfplan
```

The real `envs/dev.tfvars` (operator CIDRs, SSH key) is gitignored
(`*.tfvars`); delete it as well once the stack is gone.

## Failure handling

A failed or partial destroy is an incident, not a retry loop. Record the
state in the ops ledger, resolve the blocking resource (usually the RSV
hazard above), and re-run the same destroy command. Do not delete individual
resources out of band and leave the rest orphaned.
