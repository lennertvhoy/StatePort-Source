# One Standard LRS storage account for the alpha:
#   - blob container "backups" for file-level backup exports (the VM disk
#     backup itself goes to the recovery services vault in the backup module)
#   - boot diagnostics target for the host VM
# LRS is the cheapest replication and sufficient for a 72h ephemeral stack.

resource "azurerm_storage_account" "this" {
  # Storage account names are globally unique, 3-24 chars, lowercase alnum.
  name                     = substr(replace("st${var.name_prefix}", "-", ""), 0, 24)
  location                 = var.location
  resource_group_name      = var.resource_group_name
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"

  allow_nested_items_to_be_public = false

  tags = var.tags
}

resource "azurerm_storage_container" "backups" {
  name                  = "backups"
  storage_account_id    = azurerm_storage_account.this.id
  container_access_type = "private"
}
