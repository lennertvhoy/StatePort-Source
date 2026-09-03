output "vm_id" {
  description = "Resource ID of the host VM"
  value       = azurerm_linux_virtual_machine.this.id
}

output "public_ip_address" {
  description = "Public IP of the host VM (HTTPS endpoint only)"
  value       = azurerm_public_ip.this.ip_address
}

output "private_ip_address" {
  description = "Private IP of the host VM"
  value       = azurerm_network_interface.this.private_ip_address
}

output "identity_principal_id" {
  description = "Principal ID of the VM's system-assigned managed identity"
  value       = azurerm_linux_virtual_machine.this.identity[0].principal_id
}

output "data_disk_id" {
  description = "Resource ID of the managed data disk"
  value       = azurerm_managed_disk.data.id
}
