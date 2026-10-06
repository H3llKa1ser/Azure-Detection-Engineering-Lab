provider "azurerm" {
  subscription_id = var.subscription_id

  # azurerm 5.x no longer auto-registers ~60 resource providers.
  # Register only what this lab actually needs.
  resource_providers_to_register = [
    "Microsoft.Compute",
    "Microsoft.DevTestLab",
    "Microsoft.Insights",
    "Microsoft.KeyVault",
    "Microsoft.ManagedIdentity",
    "Microsoft.Network",
    "Microsoft.OperationalInsights",
    "Microsoft.OperationsManagement",
    "Microsoft.SecurityInsights",
    "Microsoft.Storage",
  ]

  # Storage data-plane calls (blob upload) use Entra ID, not shared keys,
  # because shared key access is disabled on the canary storage account.
  storage_use_azuread = true

  features {
    key_vault {
      # Lab is ephemeral: purge on destroy so names can be reused immediately.
      purge_soft_delete_on_destroy    = true
      recover_soft_deleted_key_vaults = false
    }
    log_analytics_workspace {
      permanently_delete_on_destroy = true
    }
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
    virtual_machine {
      delete_os_disk_on_deletion = true
    }
  }
}
