output "resource_group_name" {
  description = "Name of the StatePort alpha resource group"
  value       = azurerm_resource_group.this.name
}

output "vm_id" {
  description = "Resource ID of the StatePort host VM"
  value       = module.host.vm_id
}

output "vm_public_ip" {
  description = "Public IP of the host VM (HTTPS endpoint only; all other inbound ports denied)"
  value       = module.host.public_ip_address
}

output "vm_private_ip" {
  description = "Private IP of the host VM inside the VNet"
  value       = module.host.private_ip_address
}

output "vm_identity_principal_id" {
  description = "Principal ID of the VM's system-assigned managed identity"
  value       = module.host.identity_principal_id
}

output "acr_login_server" {
  description = "ACR login server the VM pulls images from (via managed identity, admin account disabled)"
  value       = module.registry.login_server
}

output "key_vault_name" {
  description = "Name of the Key Vault (RBAC authorization mode; secret values are set out-of-band by the operator)"
  value       = module.vault.key_vault_name
}

output "key_vault_uri" {
  description = "URI of the Key Vault"
  value       = module.vault.key_vault_uri
}

output "storage_account_name" {
  description = "Name of the storage account (backups container + VM boot diagnostics)"
  value       = module.storage.storage_account_name
}

output "log_analytics_workspace_id" {
  description = "Resource ID of the log analytics workspace (30-day retention)"
  value       = module.diagnostics.workspace_id
}

output "backup_vault_name" {
  description = "Name of the recovery services vault protecting the VM (daily policy, includes the data disk)"
  value       = module.backup.vault_name
}

output "ssh_command" {
  description = "Operator SSH command (only works if your CIDR was in allowed_ssh_cidrs at apply time)"
  value       = "ssh ${var.admin_username}@${module.host.public_ip_address}"
}
