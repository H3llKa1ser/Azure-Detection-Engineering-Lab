# Offline plan tests - no Azure credentials needed.
# Run: terraform -chdir=terraform test

mock_provider "azurerm" {
  mock_data "azurerm_client_config" {
    defaults = {
      tenant_id       = "11111111-1111-1111-1111-111111111111"
      object_id       = "22222222-2222-2222-2222-222222222222"
      subscription_id = "00000000-0000-0000-0000-000000000000"
    }
  }
  mock_data "azurerm_subscription" {
    defaults = {
      id              = "/subscriptions/00000000-0000-0000-0000-000000000000"
      subscription_id = "00000000-0000-0000-0000-000000000000"
    }
  }
}

mock_provider "http" {
  mock_data "http" {
    defaults = {
      response_body = "203.0.113.10\n"
    }
  }
}

mock_provider "local" {}

mock_provider "azuread" {
  mock_data "azuread_domains" {
    defaults = {
      domains = [{
        domain_name         = "contoso.onmicrosoft.com"
        admin_managed       = true
        authentication_type = "Managed"
        default             = true
        initial             = true
        root                = true
        verified            = true
        supported_services  = []
      }]
    }
  }
}

variables {
  subscription_id = "00000000-0000-0000-0000-000000000000"
}

run "full_lab_plans_all_detections" {
  command = plan

  assert {
    condition     = length(azurerm_sentinel_alert_rule_scheduled.detection) == 14
    error_message = "Expected all 14 detections to be planned when both VMs are deployed."
  }

  assert {
    condition     = local.operator_ip == "203.0.113.10"
    error_message = "Operator IP auto-detection should trim the trailing newline."
  }

  assert {
    condition     = azurerm_sentinel_alert_rule_scheduled.detection["KV-001"].severity == "High"
    error_message = "KV-001 should be High severity."
  }

  assert {
    condition     = alltrue([for k, r in azurerm_sentinel_alert_rule_scheduled.detection : startswith(r.display_name, "[${k}] ")])
    error_message = "Display names must be prefixed with the detection ID (verify.sh relies on it)."
  }

  assert {
    condition     = length(azurerm_windows_virtual_machine.win) == 1 && length(azurerm_linux_virtual_machine.linux) == 1
    error_message = "Both victim VMs should be planned by default."
  }

  assert {
    condition     = azurerm_key_vault.canary.network_acls[0].default_action == "Deny"
    error_message = "Key Vault firewall must default-deny."
  }

  assert {
    condition     = azurerm_storage_account.canary.shared_access_key_enabled == false
    error_message = "Shared key auth must be disabled on the canary storage account."
  }
}

run "no_vms_skips_host_detections" {
  command = plan

  variables {
    deploy_windows_vm = false
    deploy_linux_vm   = false
    operator_ip       = "198.51.100.7"
  }

  assert {
    condition     = length(azurerm_sentinel_alert_rule_scheduled.detection) == 8
    error_message = "Without VMs only the 8 cloud control/data-plane detections should deploy."
  }

  assert {
    condition     = !contains(keys(azurerm_sentinel_alert_rule_scheduled.detection), "WIN-001") && !contains(keys(azurerm_sentinel_alert_rule_scheduled.detection), "LNX-001")
    error_message = "Host detections must be skipped when their VM is not deployed."
  }

  assert {
    condition     = length(azurerm_monitor_data_collection_rule.windows) == 0 && length(azurerm_monitor_data_collection_rule.linux) == 0
    error_message = "No DCRs should be created without VMs."
  }

  assert {
    condition     = length(azuread_user.canary) == 0 && length(azurerm_monitor_aad_diagnostic_setting.entra) == 0
    error_message = "No tenant-level resources should be created unless enable_entra_id = true."
  }

  assert {
    condition     = length(data.http.operator_ip) == 0
    error_message = "IP auto-detection must not run when operator_ip is supplied."
  }
}

run "entra_p1_adds_identity_detections" {
  command = plan

  variables {
    enable_entra_id = true
  }

  assert {
    condition     = length(azurerm_sentinel_alert_rule_scheduled.detection) == 20
    error_message = "With Entra ID (P1) enabled, 14 + 6 identity detections should be planned (ENT-007 needs P2)."
  }

  assert {
    condition     = !contains(keys(azurerm_sentinel_alert_rule_scheduled.detection), "ENT-007")
    error_message = "The P2 risk detection must not deploy without entra_id_p2."
  }

  assert {
    condition     = length(azuread_user.canary) == 5 && alltrue([for u in azuread_user.canary : u.account_enabled == false])
    error_message = "Five canary accounts should be planned, all disabled."
  }

  assert {
    condition     = endswith(azuread_user.canary["svc-sql-backup"].user_principal_name, "@contoso.onmicrosoft.com")
    error_message = "Canary UPNs should use the tenant's initial domain."
  }

  assert {
    condition     = length(azurerm_sentinel_watchlist_item.canary_accounts) == 5
    error_message = "Every canary account must be in the canary watchlist used by ENT-002."
  }

  assert {
    condition     = !contains([for l in azurerm_monitor_aad_diagnostic_setting.entra[0].enabled_log : l.category], "UserRiskEvents")
    error_message = "P2-only log categories must not be requested on a P1 tenant."
  }

  assert {
    condition     = azurerm_sentinel_alert_rule_scheduled.detection["ENT-005"].alert_details_override[0].severity_column_name == "AlertSeverity"
    error_message = "ENT-005 must take its severity from the AlertSeverity column."
  }
}

run "entra_p2_adds_risk_detection" {
  command = plan

  variables {
    enable_entra_id = true
    entra_id_p2     = true
  }

  assert {
    condition     = length(azurerm_sentinel_alert_rule_scheduled.detection) == 21
    error_message = "With Entra ID P2 all 21 detections should be planned."
  }

  assert {
    condition     = contains([for l in azurerm_monitor_aad_diagnostic_setting.entra[0].enabled_log : l.category], "UserRiskEvents")
    error_message = "P2 should stream the Identity Protection risk logs."
  }
}

run "flow_logs_add_network_detections" {
  command = plan

  variables {
    enable_flow_logs = true
  }

  assert {
    condition     = length(azurerm_sentinel_alert_rule_scheduled.detection) == 19
    error_message = "With flow logs enabled, 14 core + 5 network detections should be planned."
  }

  assert {
    condition     = length(azurerm_network_watcher_flow_log.lab) == 1 && length(azurerm_network_watcher_flow_log.lab[0].traffic_analytics) == 1
    error_message = "VNet flow log with Traffic Analytics should be planned."
  }

  assert {
    condition     = contains(keys(azurerm_sentinel_alert_rule_scheduled.detection), "NET-003")
    error_message = "NET-003 lateral-movement rule should deploy with flow logs."
  }

  assert {
    condition     = azurerm_sentinel_alert_rule_scheduled.detection["NET-005"].alert_details_override[0].display_name_format != ""
    error_message = "NET-005 should set a dynamic alert name."
  }
}

run "flow_logs_off_by_default" {
  command = plan

  assert {
    condition     = length(azurerm_network_watcher_flow_log.lab) == 0 && length(azurerm_storage_account.flowlogs) == 0
    error_message = "No flow-log resources should be created unless enable_flow_logs = true."
  }

  assert {
    condition     = !contains(keys(azurerm_sentinel_alert_rule_scheduled.detection), "NET-001")
    error_message = "Network detections must be skipped when flow logs are off."
  }
}

run "rejects_bad_flow_interval" {
  command = plan

  variables {
    enable_flow_logs          = true
    flow_log_interval_minutes = 15
  }

  expect_failures = [var.flow_log_interval_minutes]
}

run "p2_requires_entra" {
  command = plan

  variables {
    entra_id_p2 = true
  }

  expect_failures = [var.entra_id_p2]
}

run "rejects_bad_prefix" {
  command = plan

  variables {
    prefix = "Detection-Lab!"
  }

  expect_failures = [var.prefix]
}
