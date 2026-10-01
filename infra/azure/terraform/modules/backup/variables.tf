variable "name_prefix" {
  description = "Base name prefix for resources (project-environment)"
  type        = string
}

variable "location" {
  description = "Azure region"
  type        = string
}

variable "resource_group_name" {
  description = "Resource group to create the backup vault in"
  type        = string
}

variable "vm_id" {
  description = "Resource ID of the VM to protect"
  type        = string
}

variable "tags" {
  description = "Common tags applied to every resource"
  type        = map(string)
}
