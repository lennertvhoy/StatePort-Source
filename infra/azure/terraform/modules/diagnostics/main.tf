# Log analytics workspace for the alpha stack. Central target for VM guest
# logs / diagnostics if the operator enables them; VM boot diagnostics go to
# the storage account (wired in the host module).

resource "azurerm_log_analytics_workspace" "this" {
  name                = "${var.name_prefix}-logs"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "PerGB2018"
  retention_in_days   = var.retention_in_days
  tags                = var.tags
}
