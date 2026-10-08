variable "name_prefix" {
  description = "Base name prefix for resources (project-environment)"
  type        = string
}

variable "location" {
  description = "Azure region"
  type        = string
}

variable "resource_group_name" {
  description = "Resource group to create the storage account in"
  type        = string
}

variable "tags" {
  description = "Common tags applied to every resource"
  type        = map(string)
}
