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
    condition     = length(data.http.operator_ip) == 0
    error_message = "IP auto-detection must not run when operator_ip is supplied."
  }
}

run "rejects_bad_prefix" {
  command = plan

  variables {
    prefix = "Detection-Lab!"
  }

  expect_failures = [var.prefix]
}
