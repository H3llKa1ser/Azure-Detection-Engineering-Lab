# ---------------------------------------------------------------------------
# Sysmon on the Windows victim host.
#
# Installs Sysmon via Run Command with a compact lab config, then collects the
# Microsoft-Windows-Sysmon/Operational channel through a DCR into the Event
# table (stream Microsoft-Event). The SYS-* detections parse Sysmon fields out
# of the EventData XML.
#
# Gated on var.enable_sysmon AND var.deploy_windows_vm.
# ---------------------------------------------------------------------------

locals {
  sysmon_enabled = var.enable_sysmon && var.deploy_windows_vm

  # Sysmon event IDs the lab collects and detects on. Collecting a narrow set
  # (not the full firehose) keeps Event-table ingestion cheap.
  sysmon_event_ids = [1, 3, 7, 8, 10, 11, 12, 13, 16, 22, 255]

  sysmon_xpath = format(
    "Microsoft-Windows-Sysmon/Operational!*[System[(%s)]]",
    join(" or ", [for id in local.sysmon_event_ids : "EventID=${id}"])
  )
}

# Compact Sysmon config for the lab. Deliberately smaller than SwiftOnSecurity /
# Olaf Hartong's configs: it captures the event types the SYS-* rules use
# without the noise (and cost) of logging everything. Swap in a fuller config
# by pointing sysmon_config_url at it.
resource "azurerm_virtual_machine_run_command" "install_sysmon" {
  count              = local.sysmon_enabled ? 1 : 0
  name               = "install-sysmon"
  location           = azurerm_resource_group.lab.location
  virtual_machine_id = azurerm_windows_virtual_machine.win[0].id
  tags               = local.tags

  source {
    script = <<-PS
      $ErrorActionPreference = "Stop"
      $work = "C:\Windows\Temp\sysmon"
      New-Item -ItemType Directory -Force -Path $work | Out-Null

      $configUrl = "${var.sysmon_config_url}"
      $configPath = Join-Path $work "sysmon-config.xml"
      if ([string]::IsNullOrWhiteSpace($configUrl)) {
        @'
${local.sysmon_config}
'@ | Out-File -FilePath $configPath -Encoding UTF8
      } else {
        Invoke-WebRequest -Uri $configUrl -OutFile $configPath -UseBasicParsing
      }

      $zip = Join-Path $work "Sysmon.zip"
      Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $zip -UseBasicParsing
      Expand-Archive -Path $zip -DestinationPath $work -Force

      $svc = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
      if ($svc) {
        & "$work\Sysmon64.exe" -c $configPath
        Write-Output "sysmon reconfigured"
      } else {
        & "$work\Sysmon64.exe" -accepteula -i $configPath
        Write-Output "sysmon installed"
      }
    PS
  }

  depends_on = [azurerm_virtual_machine_extension.win_ama]
}

resource "azurerm_monitor_data_collection_rule" "sysmon" {
  count               = local.sysmon_enabled ? 1 : 0
  name                = "dcr-win-sysmon-${local.name}"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  kind                = "Windows"
  description         = "Sysmon operational channel -> Event table"
  tags                = local.tags

  destinations {
    log_analytics {
      name                  = "law"
      workspace_resource_id = azurerm_log_analytics_workspace.lab.id
    }
  }

  data_flow {
    streams      = ["Microsoft-Event"]
    destinations = ["law"]
  }

  data_sources {
    windows_event_log {
      name           = "sysmon-operational"
      streams        = ["Microsoft-Event"]
      x_path_queries = [local.sysmon_xpath]
    }
  }

  depends_on = [azurerm_sentinel_log_analytics_workspace_onboarding.lab]
}

resource "azurerm_monitor_data_collection_rule_association" "sysmon" {
  count                   = local.sysmon_enabled ? 1 : 0
  name                    = "dcra-win-sysmon"
  target_resource_id      = azurerm_windows_virtual_machine.win[0].id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.sysmon[0].id
}
