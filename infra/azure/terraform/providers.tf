provider "azurerm" {
  features {
    key_vault {
      # The alpha stack is ephemeral (72h TTL): allow Terraform to recover or
      # fully purge soft-deleted vaults on re-create/destroy. Purge protection
      # on the vault itself stays disabled, which is acceptable only because
      # the environment is temporary and holds no long-lived data.
      recover_soft_deleted_key_vaults = true
      purge_soft_delete_on_destroy    = true
    }
  }

  # Authentication is ambient: ARM_SUBSCRIPTION_ID / ARM_CLIENT_ID /
  # ARM_CLIENT_SECRET / ARM_TENANT_ID environment variables, or an
  # `az login` session. Never hard-code credentials or subscription IDs here.
}
