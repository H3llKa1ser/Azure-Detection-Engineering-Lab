# ---------------------------------------------------------------------------
# Data Collection Rules: what the Azure Monitor Agent collects and where it
# sends it. Collection is deliberately narrow (only the event IDs and syslog
# facilities the detections use) to keep ingestion cost near zero.
# ---------------------------------------------------------------------------

locals {
  windows_security_event_ids = [
    1102, # Security audit log cleared
    4624, # Successful logon
    4625, # Failed logon
    4648, # Logon with explicit credentials
    4688, # Process creation (with command line, see audit baseline)
    4720, # User account created
    4726, # User account deleted
    4728, # Member added to global security group
    4732, # Member added to local security group
    4756, # Member added to universal security group
  ]

  windows_security_xpath = format(
    "Security!*[System[(%s)]]",
    join(" or ", [for id in local.windows_security_event_ids : "EventID=${id}"])
  )
}

resource "azurerm_monitor_data_collection_rule" "windows" {
  count               = var.deploy_windows_vm ? 1 : 0
  name                = "dcr-win-security-${local.name}"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  kind                = "Windows"
  description         = "Selected Windows Security events -> SecurityEvent table"
  tags                = local.tags

  destinations {
    log_analytics {
      name                  = "law"
      workspace_resource_id = azurerm_log_analytics_workspace.lab.id
    }
  }

  data_flow {
    streams      = ["Microsoft-SecurityEvent"]
    destinations = ["law"]
  }

  data_sources {
    windows_event_log {
      name           = "security-events"
      streams        = ["Microsoft-SecurityEvent"]
      x_path_queries = [local.windows_security_xpath]
    }
  }

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.lab]
}

resource "azurerm_monitor_data_collection_rule_association" "windows" {
  count                   = var.deploy_windows_vm ? 1 : 0
  name                    = "dcra-win-security"
  target_resource_id      = azurerm_windows_virtual_machine.win[0].id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.windows[0].id
}

resource "azurerm_monitor_data_collection_rule" "linux" {
  count               = var.deploy_linux_vm ? 1 : 0
  name                = "dcr-lnx-syslog-${local.name}"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  kind                = "Linux"
  description         = "auth/authpriv syslog -> Syslog table"
  tags                = local.tags

  destinations {
    log_analytics {
      name                  = "law"
      workspace_resource_id = azurerm_log_analytics_workspace.lab.id
    }
  }

  data_flow {
    streams      = ["Microsoft-Syslog"]
    destinations = ["law"]
  }

  data_sources {
    syslog {
      name           = "auth-syslog"
      streams        = ["Microsoft-Syslog"]
      facility_names = ["auth", "authpriv"]
      log_levels     = ["*"]
    }
  }
}

resource "azurerm_monitor_data_collection_rule_association" "linux" {
  count                   = var.deploy_linux_vm ? 1 : 0
  name                    = "dcra-lnx-syslog"
  target_resource_id      = azurerm_linux_virtual_machine.linux[0].id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.linux[0].id
}
