# Key Vault for StatePort runtime secrets (model API keys, bot tokens).
#
# Decisions:
# - RBAC authorization mode: access is granted only through the role
#   assignments in the identity module; there are no legacy access policies.
# - soft_delete_retention_days = 7 (minimum) so an accidental delete during
#   the alpha is recoverable.
# - purge_protection_enabled = false is a deliberate alpha-only trade-off:
#   the stack is ephemeral (72h TTL) and must be fully destroyable. This
#   must be re-enabled before any non-ephemeral use.
# - NO secret resources are declared here. Terraform must never see real
#   secret values; the operator creates/rotates secrets out-of-band
#   (`az keyvault secret set`) with their own RBAC grant.

resource "azurerm_key_vault" "this" {
  # Key Vault names are globally unique, 3-24 chars.
  name                = "${var.name_prefix}-kv"
  location            = var.location
  resource_group_name = var.resource_group_name
  tenant_id           = var.tenant_id
  sku_name            = "standard"

  rbac_authorization_enabled = true
  soft_delete_retention_days = 7
  purge_protection_enabled   = false

  tags = var.tags
}
