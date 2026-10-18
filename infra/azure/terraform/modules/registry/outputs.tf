output "registry_id" {
  description = "Resource ID of the container registry"
  value       = azurerm_container_registry.this.id
}

output "login_server" {
  description = "Login server hostname of the container registry"
  value       = azurerm_container_registry.this.login_server
}
