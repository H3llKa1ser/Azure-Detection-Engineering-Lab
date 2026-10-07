# ---------------------------------------------------------------------------
# VNet flow logs + Traffic Analytics.
#
# Microsoft retired NSG flow logs (June 2025); this uses VNet flow logs, which
# attach to the virtual network and capture every NIC in it. Traffic Analytics
# processes the raw logs from a storage account and writes the enriched
# NTANetAnalytics table into the workspace, which the NET-* detections query.
#
# Gated on var.enable_flow_logs because Traffic Analytics has its own ingestion
# cost and a processing interval (10 or 60 min) that adds latency.
# ---------------------------------------------------------------------------

# Network Watcher is usually auto-created by Azure per region in a
# NetworkWatcherRG. Managing our own in the lab RG keeps everything disposable
# and avoids depending on that implicit resource.
resource "azurerm_network_watcher" "lab" {
  count               = var.enable_flow_logs ? 1 : 0
  name                = "nw-${local.name}"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  tags                = local.tags
}

# Dedicated storage account for raw flow logs. Separate from the canary
# storage account so flow-log writes never show up in the STG-001 honeytoken
# telemetry.
resource "azurerm_storage_account" "flowlogs" {
  #checkov:skip=CKV_AZURE_33:Queue service is unused.
  #checkov:skip=CKV_AZURE_206:LRS is sufficient for a disposable lab.
  #checkov:skip=CKV2_AZURE_1:Customer-managed keys out of scope for the lab.
  #checkov:skip=CKV2_AZURE_33:Private endpoint out of scope for a cost-minimal lab.
  #checkov:skip=CKV2_AZURE_38:Soft-delete/versioning not needed for transient flow logs.
  #checkov:skip=CKV2_AZURE_40:Shared-key auth is required - the flow-log service writes with the account key.
  #checkov:skip=CKV2_AZURE_41:SAS policy not applicable to flow-log storage.
  #checkov:skip=CKV2_AZURE_47:Public network access is required for the flow-log service to write; no sensitive data is stored here.
  count                           = var.enable_flow_logs ? 1 : 0
  name                            = "stflow${var.prefix}${local.suffix}"
  location                        = azurerm_resource_group.lab.location
  resource_group_name             = azurerm_resource_group.lab.name
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  account_kind                    = "StorageV2"
  min_tls_version                 = "TLS1_2"
  https_traffic_only_enabled      = true
  allow_nested_items_to_be_public = false

  # The flow-log service authenticates to this account with its access key,
  # so shared-key auth stays on here (unlike the canary account).
  shared_access_key_enabled = true

  blob_properties {
    delete_retention_policy {
      days = 7
    }
  }
}

resource "azurerm_network_watcher_flow_log" "lab" {
  count                = var.enable_flow_logs ? 1 : 0
  name                 = "fl-${local.name}"
  network_watcher_name = azurerm_network_watcher.lab[0].name
  resource_group_name  = azurerm_resource_group.lab.name
  location             = azurerm_resource_group.lab.location

  # VNet flow logs: point at the virtual network, not an NSG.
  target_resource_id = azurerm_virtual_network.lab.id
  storage_account_id = azurerm_storage_account.flowlogs[0].id
  enabled            = true
  version            = 2

  retention_policy {
    enabled = true
    days    = 7
  }

  traffic_analytics {
    enabled               = true
    workspace_id          = azurerm_log_analytics_workspace.lab.workspace_id
    workspace_region      = azurerm_log_analytics_workspace.lab.location
    workspace_resource_id = azurerm_log_analytics_workspace.lab.id
    # 10 = fastest processing (lowest detection latency); 60 = cheapest.
    interval_in_minutes = var.flow_log_interval_minutes
  }

  tags = local.tags
}
