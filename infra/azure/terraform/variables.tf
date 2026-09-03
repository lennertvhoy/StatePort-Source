variable "location" {
  description = "Azure region for all resources"
  type        = string
  default     = "belgiumcentral"
}

variable "project_name" {
  description = "Project name used for resource naming (lowercase alphanumeric and hyphens)"
  type        = string
  default     = "stateport"

  validation {
    condition     = can(regex("^[a-z0-9-]{3,20}$", var.project_name))
    error_message = "project_name must be 3-20 chars of lowercase letters, digits, hyphens (storage account and Key Vault naming constraints)."
  }
}

variable "environment" {
  description = "Environment name (dev, staging, prod). The alpha uses short-lived dev stacks only."
  type        = string
  default     = "dev"
}

variable "vm_size" {
  description = "Size of the single StatePort host VM. Standard_B2s (2 vCPU / 4 GiB) is the cost-capped alpha default."
  type        = string
  default     = "Standard_B2s"
}

variable "allowed_ssh_cidrs" {
  description = "CIDRs allowed to reach SSH (port 22) on the host. Empty list (default) means no SSH inbound rule is created at all: SSH is fully denied."
  type        = list(string)
  default     = []
}

variable "data_disk_size_gb" {
  description = "Size of the managed data disk mounted at /var/lib/stateport"
  type        = number
  default     = 64
}

variable "admin_username" {
  description = "Operator login account on the VM (SSH key auth only). Distinct from the stateport-control / stateport-exec service users created by cloud-init."
  type        = string
  default     = "stateportadm"
}

variable "admin_ssh_public_key" {
  description = "SSH public key (authorized key line) for the operator login account. Required; password authentication is disabled. Public keys are not secrets."
  type        = string
  # No default: the operator must consciously supply their own key.
}

variable "ttl" {
  description = "Time-to-live tag applied to every resource. The alpha stack must be destroyed within this window."
  type        = string
  default     = "72h"
}

variable "budget_notification_email" {
  description = "Email address that receives the machine-enforced monthly budget alert (~EUR 30, resource-group consumption budget). An email address is not a secret."
  type        = string
  # No default: the operator must consciously supply the recipient.
}
