# RBAC wiring for the host VM's system-assigned managed identity.
# This is the complete set of Azure permissions the workload identity holds:
# pull container images from ACR, read secrets from Key Vault. Nothing else.
# The ACR admin account stays disabled; Key Vault uses RBAC authorization
# mode, so these role assignments are the only access path.

resource "azurerm_role_assignment" "acr_pull" {
  scope                = var.acr_id
  role_definition_name = "AcrPull"
  principal_id         = var.principal_id
}

resource "azurerm_role_assignment" "key_vault_secrets_user" {
  scope                = var.key_vault_id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = var.principal_id
}
