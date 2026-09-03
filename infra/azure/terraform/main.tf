# StatePort public-alpha Azure topology.
#
# Target architecture: ONE Ubuntu 24.04 LTS Gen2 VM running StatePort with
# rootless Podman, plus the minimal supporting services (ACR, Key Vault,
# storage, backup, log analytics). No AKS, no Container Apps.
#
# Do not run `terraform apply` without explicit owner approval. See README.md
# for the approval, cost, and TTL gates.

data "azurerm_client_config" "current" {}

resource "azurerm_resource_group" "this" {
  name     = "${local.base_name}-rg"
  location = var.location
  tags     = local.common_tags
}

module "diagnostics" {
  source = "./modules/diagnostics"

  name_prefix         = local.base_name
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.common_tags
}

# Machine-enforced cost control: Azure emails the operator when actual
# monthly spend on the resource group crosses 90% of the budget.
module "budget" {
  source = "./modules/budget"

  name_prefix        = local.base_name
  resource_group_id  = azurerm_resource_group.this.id
  notification_email = var.budget_notification_email
}

module "network" {
  source = "./modules/network"

  name_prefix         = local.base_name
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  allowed_ssh_cidrs   = var.allowed_ssh_cidrs
  tags                = local.common_tags
}

module "registry" {
  source = "./modules/registry"

  name_prefix         = local.base_name
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.common_tags
}

module "vault" {
  source = "./modules/vault"

  name_prefix         = local.base_name
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  tags                = local.common_tags
}

module "storage" {
  source = "./modules/storage"

  name_prefix         = local.base_name
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.common_tags
}

module "host" {
  source = "./modules/host"

  name_prefix                  = local.base_name
  location                     = azurerm_resource_group.this.location
  resource_group_name          = azurerm_resource_group.this.name
  subnet_id                    = module.network.subnet_id
  vm_size                      = var.vm_size
  admin_username               = var.admin_username
  admin_ssh_public_key         = var.admin_ssh_public_key
  data_disk_size_gb            = var.data_disk_size_gb
  boot_diagnostics_storage_uri = module.storage.primary_blob_endpoint
  tags                         = local.common_tags
}

# All RBAC wiring lives in one module so effective access is reviewable in a
# single place: the VM's system-assigned identity can pull from ACR and read
# secrets from Key Vault, and nothing else.
module "identity" {
  source = "./modules/identity"

  principal_id = module.host.identity_principal_id
  acr_id       = module.registry.registry_id
  key_vault_id = module.vault.key_vault_id
}

module "backup" {
  source = "./modules/backup"

  name_prefix         = local.base_name
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  vm_id               = module.host.vm_id
  tags                = local.common_tags
}
