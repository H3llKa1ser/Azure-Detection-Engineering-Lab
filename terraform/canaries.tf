# ---------------------------------------------------------------------------
# Honeytokens / deception layer.
#
# A canary secret and a canary blob that no legitimate workload ever reads.
# Any read is high-fidelity signal. Decoy secrets give the bulk-enumeration
# detection something to count.
# ---------------------------------------------------------------------------

resource "time_static" "created" {}

# --- Key Vault -------------------------------------------------------------

resource "azurerm_key_vault" "canary" {
  #checkov:skip=CKV_AZURE_110:Purge protection disabled so the ephemeral lab can be destroyed and rebuilt.
  #checkov:skip=CKV_AZURE_42:Same as above - recoverability is intentionally traded for disposability.
  #checkov:skip=CKV_AZURE_189:Public endpoint is required for the operator; access restricted by IP firewall.
  #checkov:skip=CKV2_AZURE_32:Private endpoint out of scope for a cost-minimal lab.
  name                          = local.detection_vars.key_vault_name
  location                      = azurerm_resource_group.lab.location
  resource_group_name           = azurerm_resource_group.lab.name
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  sku_name                      = "standard"
  rbac_authorization_enabled    = true
  purge_protection_enabled      = false
  soft_delete_retention_days    = 7
  public_network_access_enabled = true
  tags                          = merge(local.tags, { purpose = "honeytoken" })

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
    ip_rules       = local.allowed_ips
  }
}

resource "azurerm_role_assignment" "operator_kv_secrets" {
  scope                = azurerm_key_vault.canary.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_monitor_diagnostic_setting" "key_vault" {
  name                       = "diag-kv-${local.name}"
  target_resource_id         = azurerm_key_vault.canary.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.lab.id

  enabled_log {
    category = "AuditEvent"
  }
}

# --- Storage ---------------------------------------------------------------

resource "azurerm_storage_account" "canary" {
  #checkov:skip=CKV_AZURE_33:Queue service is unused.
  #checkov:skip=CKV_AZURE_206:LRS is sufficient for a disposable lab.
  #checkov:skip=CKV2_AZURE_1:Customer-managed keys out of scope for the lab.
  #checkov:skip=CKV2_AZURE_33:Private endpoint out of scope for a cost-minimal lab.
  #checkov:skip=CKV_AZURE_59:Public endpoint is required for the operator; access restricted by IP firewall.
  name                              = local.detection_vars.storage_name
  location                          = azurerm_resource_group.lab.location
  resource_group_name               = azurerm_resource_group.lab.name
  account_tier                      = "Standard"
  account_replication_type          = "LRS"
  account_kind                      = "StorageV2"
  min_tls_version                   = "TLS1_2"
  https_traffic_only_enabled        = true
  shared_access_key_enabled         = false
  default_to_oauth_authentication   = true
  allow_nested_items_to_be_public   = false
  infrastructure_encryption_enabled = true
  public_network_access             = "Enabled"
  tags                              = merge(local.tags, { purpose = "honeytoken" })

  blob_properties {
    delete_retention_policy {
      days = 7
    }
    container_delete_retention_policy {
      days = 7
    }
  }

  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices", "Logging", "Metrics"]
    ip_rules       = local.allowed_ips
  }

  sas_policy {
    expiration_period = "00.01:00:00"
    expiration_action = "Log"
  }
}

resource "azurerm_role_assignment" "operator_blob_contributor" {
  scope                = azurerm_storage_account.canary.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = data.azurerm_client_config.current.object_id
}

# Data-plane RBAC takes a while to propagate; without this the first apply
# fails with 403s when writing secrets/blobs.
resource "time_sleep" "rbac_propagation" {
  create_duration = "90s"

  depends_on = [
    azurerm_role_assignment.operator_kv_secrets,
    azurerm_role_assignment.operator_blob_contributor,
  ]
}

resource "azurerm_storage_container" "canary" {
  #checkov:skip=CKV2_AZURE_21:False positive - blob read logging is enabled by azurerm_monitor_diagnostic_setting.blob on blobServices/default (interpolated target id is not resolved by the graph check).
  name                  = "hr-finance-exports"
  storage_account_id    = azurerm_storage_account.canary.id
  container_access_type = "private"
}

# Blob-service diagnostics land in the resource-specific StorageBlobLogs table.
resource "azurerm_monitor_diagnostic_setting" "blob" {
  name                       = "diag-blob-${local.name}"
  target_resource_id         = "${azurerm_storage_account.canary.id}/blobServices/default"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.lab.id

  enabled_log {
    category = "StorageRead"
  }
  enabled_log {
    category = "StorageWrite"
  }
  enabled_log {
    category = "StorageDelete"
  }
}

# --- Honeytoken seeding ----------------------------------------------------
#
# The canary secret, decoy secrets and canary blob are seeded ONCE via the
# Azure CLI instead of azurerm_key_vault_secret / azurerm_storage_blob.
#
# Why: Terraform refreshes managed resources on every plan. Refreshing a
# key_vault_secret performs a SecretGet, which would trip KV-001 (and the
# decoy reads would trip KV-002) every time anyone runs `terraform plan`.
# A honeytoken your own pipeline touches is a honeytoken you'll learn to
# ignore. Terraform never knows the values either - they're generated in the
# shell and never land in state.

resource "terraform_data" "seed_honeytokens" {
  triggers_replace = [
    azurerm_key_vault.canary.id,
    azurerm_storage_container.canary.id,
  ]

  provisioner "local-exec" {
    interpreter = ["bash", "-c"]
    environment = {
      KV_NAME          = azurerm_key_vault.canary.name
      CANARY_SECRET    = local.canary_secret_name
      DECOY_SECRETS    = join(" ", local.decoy_secret_names)
      STORAGE_ACCOUNT  = azurerm_storage_account.canary.name
      CANARY_CONTAINER = azurerm_storage_container.canary.name
      CANARY_BLOB      = local.canary_blob_name
    }
    command = "${path.module}/scripts/seed-honeytokens.sh"
  }

  depends_on = [
    time_sleep.rbac_propagation,
    azurerm_monitor_diagnostic_setting.key_vault,
    azurerm_monitor_diagnostic_setting.blob,
  ]
}

# The real Windows admin password lives in the vault too (good practice, and
# it's one more secret for the enumeration detection to count).
resource "azurerm_key_vault_secret" "win_admin" {
  count           = var.deploy_windows_vm ? 1 : 0
  name            = "vm-win-labadmin-password"
  value           = random_password.win_admin.result
  key_vault_id    = azurerm_key_vault.canary.id
  content_type    = "password"
  expiration_date = timeadd(time_static.created.rfc3339, "8760h")

  depends_on = [time_sleep.rbac_propagation]
}

# --- Simulation target identity ------------------------------------------

# A throwaway identity that the role-assignment simulation grants Owner on the
# lab resource group (and then removes). Avoids touching real principals.
resource "azurerm_user_assigned_identity" "sim_target" {
  name                = "id-sim-target-${local.name}"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  tags                = merge(local.tags, { purpose = "simulation-target" })
}
