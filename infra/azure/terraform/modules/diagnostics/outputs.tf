output "workspace_id" {
  description = "Resource ID of the log analytics workspace"
  value       = azurerm_log_analytics_workspace.this.id
}

output "workspace_name" {
  description = "Name of the log analytics workspace"
  value       = azurerm_log_analytics_workspace.this.name
}
