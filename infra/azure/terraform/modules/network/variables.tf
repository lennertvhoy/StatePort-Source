variable "name_prefix" {
  description = "Base name prefix for resources (project-environment)"
  type        = string
}

variable "location" {
  description = "Azure region"
  type        = string
}

variable "resource_group_name" {
  description = "Resource group to create network resources in"
  type        = string
}

variable "allowed_ssh_cidrs" {
  description = "CIDRs allowed to reach SSH (port 22). Empty list = no SSH rule, SSH fully denied."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Common tags applied to every resource"
  type        = map(string)
}
