# Backup for the alpha host.
#
# Implemented as Azure VM backup (recovery services vault + daily policy +
# protected VM) rather than standalone disk backup: VM backup protects the
# OS disk AND the data disk in one consistent recovery point, which is the
# actual requirement (the StatePort state lives on the data disk). Daily at
# 23:00 UTC with 7-day retention — the stack itself never outlives a week.

resource "azurerm_recovery_services_vault" "this" {
  name                = "${var.name_prefix}-rsv"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "Standard"
  tags                = var.tags
}

resource "azurerm_backup_policy_vm" "daily" {
  name                = "${var.name_prefix}-daily"
  resource_group_name = var.resource_group_name
  recovery_vault_name = azurerm_recovery_services_vault.this.name

  backup {
    frequency = "Daily"
    time      = "23:00"
  }

  retention_daily {
    count = 7
  }
}

resource "azurerm_backup_protected_vm" "this" {
  resource_group_name = var.resource_group_name
  recovery_vault_name = azurerm_recovery_services_vault.this.name
  source_vm_id        = var.vm_id
  backup_policy_id    = azurerm_backup_policy_vm.daily.id
}
