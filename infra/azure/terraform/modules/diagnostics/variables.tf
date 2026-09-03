variable "name_prefix" {
  description = "Base name prefix for resources (project-environment)"
  type        = string
}

variable "location" {
  description = "Azure region"
  type        = string
}

variable "resource_group_name" {
  description = "Resource group to create the diagnostics workspace in"
  type        = string
}

variable "retention_in_days" {
  description = "Log retention. 30 days is the minimum and enough for a 72h alpha."
  type        = number
  default     = 30
}

variable "tags" {
  description = "Common tags applied to every resource"
  type        = map(string)
}
