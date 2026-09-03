# Azure Container Registry for StatePort alpha images.
# Basic SKU is the cheapest tier and sufficient for a single pull client.
# The admin account stays disabled: the host VM authenticates with its
# system-assigned managed identity (AcrPull role assigned in the identity
# module), so no registry credentials ever exist to leak.

resource "azurerm_container_registry" "this" {
  # ACR names are globally unique, alphanumeric only.
  name                = replace("${var.name_prefix}acr", "-", "")
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "Basic"
  admin_enabled       = false
  tags                = var.tags
}
