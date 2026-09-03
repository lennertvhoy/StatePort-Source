variable "principal_id" {
  description = "Object (principal) ID of the VM's system-assigned managed identity"
  type        = string
}

variable "acr_id" {
  description = "Resource ID of the container registry the VM pulls from"
  type        = string
}

variable "key_vault_id" {
  description = "Resource ID of the Key Vault the VM reads secrets from"
  type        = string
}
