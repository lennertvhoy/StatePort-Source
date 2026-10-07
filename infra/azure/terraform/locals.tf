locals {
  base_name = "${var.project_name}-${var.environment}"

  # Cost/TTL discipline: the alpha stack is temporary by contract. Every
  # resource carries these tags so cost reports and cleanup sweeps can find
  # and enforce the 72-hour TTL.
  common_tags = {
    project     = var.project_name
    environment = var.environment
    managed_by  = "terraform"
    ttl         = var.ttl
    temporary   = "true"
  }
}
