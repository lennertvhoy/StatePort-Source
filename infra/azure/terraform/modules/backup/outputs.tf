output "vault_name" {
  description = "Name of the recovery services vault"
  value       = azurerm_recovery_services_vault.this.name
}

output "vault_id" {
  description = "Resource ID of the recovery services vault"
  value       = azurerm_recovery_services_vault.this.id
}

output "backup_policy_id" {
  description = "Resource ID of the daily VM backup policy"
  value       = azurerm_backup_policy_vm.daily.id
}
