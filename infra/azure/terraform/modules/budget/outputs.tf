output "budget_id" {
  description = "Resource ID of the resource-group consumption budget"
  value       = azurerm_consumption_budget_resource_group.this.id
}

output "budget_name" {
  description = "Name of the resource-group consumption budget"
  value       = azurerm_consumption_budget_resource_group.this.name
}
