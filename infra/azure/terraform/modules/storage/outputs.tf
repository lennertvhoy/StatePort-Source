output "storage_account_name" {
  description = "Name of the storage account"
  value       = azurerm_storage_account.this.name
}

output "storage_account_id" {
  description = "Resource ID of the storage account"
  value       = azurerm_storage_account.this.id
}

output "primary_blob_endpoint" {
  description = "Primary blob endpoint (used as the VM boot diagnostics target)"
  value       = azurerm_storage_account.this.primary_blob_endpoint
}

output "backups_container_name" {
  description = "Name of the backups blob container"
  value       = azurerm_storage_container.backups.name
}
