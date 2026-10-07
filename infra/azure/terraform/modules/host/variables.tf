variable "name_prefix" {
  description = "Base name prefix for resources (project-environment)"
  type        = string
}

variable "location" {
  description = "Azure region"
  type        = string
}

variable "resource_group_name" {
  description = "Resource group to create the host in"
  type        = string
}

variable "subnet_id" {
  description = "Resource ID of the subnet the host NIC joins"
  type        = string
}

variable "vm_size" {
  description = "Azure VM size"
  type        = string
}

variable "admin_username" {
  description = "Operator login account (SSH key auth only)"
  type        = string
}

variable "admin_ssh_public_key" {
  description = "SSH public key for the operator login account"
  type        = string
}

variable "data_disk_size_gb" {
  description = "Size of the managed data disk mounted at /var/lib/stateport"
  type        = number
}

variable "boot_diagnostics_storage_uri" {
  description = "Blob endpoint of the storage account used for boot diagnostics. Null = Azure-managed boot diagnostics."
  type        = string
  default     = null
}

variable "control_user" {
  description = "Unprivileged user running StatePort control services"
  type        = string
  default     = "stateport-control"
  validation {
    condition     = var.control_user == "stateport-control"
    error_message = "the execution-host contract requires stateport-control"
  }
}

variable "exec_user" {
  description = "Unprivileged user running agent execution workloads (rootless Podman)"
  type        = string
  default     = "stateport-exec"
  validation {
    condition     = var.exec_user == "stateport-exec"
    error_message = "the execution-host contract requires stateport-exec"
  }
}

variable "tags" {
  description = "Common tags applied to every resource"
  type        = map(string)
}
