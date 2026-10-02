output "vnet_id" {
  description = "Resource ID of the VNet"
  value       = azurerm_virtual_network.this.id
}

output "subnet_id" {
  description = "Resource ID of the single subnet"
  value       = azurerm_subnet.this.id
}

output "nsg_id" {
  description = "Resource ID of the network security group"
  value       = azurerm_network_security_group.this.id
}
