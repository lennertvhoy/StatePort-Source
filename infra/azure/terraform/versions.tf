terraform {
  required_version = ">= 1.9"

  required_providers {
    azurerm = {
      source = "hashicorp/azurerm"
      # Exact 4.x release resolved by `terraform init -backend=false` and
      # recorded in .terraform.lock.hcl. Bump deliberately, never silently.
      version = "4.43.0"
    }
  }
}
