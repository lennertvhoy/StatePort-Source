variable "name_prefix" {
  description = "Base name prefix for resources (project-environment)"
  type        = string
}

variable "resource_group_id" {
  description = "Resource ID of the resource group the budget monitors"
  type        = string
}

variable "amount" {
  description = "Monthly budget amount in the subscription's billing currency (EUR for the alpha subscription)"
  type        = number
  default     = 30
}

variable "notification_email" {
  description = "Email address that receives the budget alert when actual monthly spend crosses the threshold"
  type        = string
}
