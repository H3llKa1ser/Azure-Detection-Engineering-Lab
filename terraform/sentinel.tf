# ---------------------------------------------------------------------------
# Sentinel content that isn't an analytics rule: watchlists and automation.
# ---------------------------------------------------------------------------

resource "azurerm_sentinel_watchlist" "approved_privileged_callers" {
  name                       = local.detection_vars.watchlist_alias
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.lab.workspace_id
  display_name               = "Lab - approved privileged callers"
  description                = "Principals expected to create privileged role assignments (break-glass, IaC pipelines). Used by AZ-ACT-001 as an allowlist."
  item_search_key            = "Caller"
  labels                     = ["detection-lab", "allowlist"]
}

resource "azurerm_sentinel_watchlist_item" "approved_privileged_callers" {
  for_each     = toset(var.approved_privileged_callers)
  watchlist_id = azurerm_sentinel_watchlist.approved_privileged_callers.id
  properties = {
    Caller = each.value
    Reason = "Approved via Terraform variable approved_privileged_callers"
  }
}

# Every incident in the lab gets a label and a standard triage checklist.
# This is the "detection -> runbook" link: analysts get the same first steps
# every time, and the tasks are version-controlled alongside the rules.
resource "azurerm_sentinel_automation_rule" "triage_tasks" {
  name                       = uuidv5("url", "https://github.com/H3llKa1ser/Azure-Detection-Engineering-Lab/automation/triage-tasks")
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.lab.workspace_id
  display_name               = "Lab - label incident and add triage tasks"
  order                      = 1
  triggers_on                = "Incidents"
  triggers_when              = "Created"

  action_incident {
    order  = 1
    labels = ["detection-lab"]
  }

  action_incident_task {
    order       = 2
    title       = "1. Confirm whether this was a planned simulation"
    description = "Check simulate/ run logs and the operator's activity window. If it matches a simulation run, close as 'BenignPositive - SuspiciousButExpected' and note the script name."
  }

  action_incident_task {
    order       = 3
    title       = "2. Scope the actor"
    description = "Pivot on the Account / IP entities across AzureActivity, AzureDiagnostics (Key Vault), StorageBlobLogs, SecurityEvent and Syslog for the preceding 24h."
  }

  action_incident_task {
    order       = 4
    title       = "3. Contain if unexpected"
    description = "Revoke sessions / disable the principal, rotate any secret that was read, remove rogue role assignments or NSG rules, and preserve logs before remediation."
  }
}
