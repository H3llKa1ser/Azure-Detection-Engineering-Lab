# ---------------------------------------------------------------------------
# SIEM backbone: Log Analytics + Microsoft Sentinel + subscription Activity Log
# ---------------------------------------------------------------------------

resource "azurerm_log_analytics_workspace" "lab" {
  name                = "log-${local.name}"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days
  daily_quota_gb      = var.daily_quota_gb
  tags                = local.tags
}

resource "azurerm_sentinel_log_analytics_workspace_onboarding" "lab" {
  workspace_id = azurerm_log_analytics_workspace.lab.id
}

# The subscription Activity Log is the control-plane audit trail: role
# assignments, NSG edits, diagnostic-setting tampering, run-command, listKeys.
# Streaming it to the workspace populates the AzureActivity table.
locals {
  activity_log_categories = [
    "Administrative",
    "Security",
    "Policy",
    "Alert",
    "ServiceHealth",
    "Recommendation",
    "Autoscale",
    "ResourceHealth",
  ]
}

resource "azurerm_monitor_diagnostic_setting" "activity_log" {
  name                       = "diag-activity-${local.name}"
  target_resource_id         = data.azurerm_subscription.current.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.lab.id

  dynamic "enabled_log" {
    for_each = local.activity_log_categories
    content {
      category = enabled_log.value
    }
  }
}
