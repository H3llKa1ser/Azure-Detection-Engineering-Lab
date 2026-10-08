# ---------------------------------------------------------------------------
# SOAR response playbook: auto-disable the principal on a honeytoken hit.
#
# A Logic App (Sentinel playbook) triggered by KV-001 / STG-001 incidents.
# It pulls the Account entity off the incident and, unless in dry-run, disables
# that Entra ID user via Microsoft Graph and revokes its sessions, then comments
# on the incident. An automation rule runs it automatically on those two rules.
#
# Deployed via ARM (the standard packaging for Sentinel playbooks, including the
# azuresentinel managed API connection); RBAC, the Graph grant and the
# automation rule stay in Terraform where they're clearer.
#
# Gated on var.enable_response_playbook. DRY-RUN BY DEFAULT: deploy it, watch it
# comment "would disable X", and only set playbook_dry_run = false once you
# trust it. Enforcing also requires the Graph app role (playbook_grant_graph).
# ---------------------------------------------------------------------------

locals {
  playbook_name    = "pb-disable-principal-${local.name}"
  response_enabled = var.enable_response_playbook
}

resource "azurerm_resource_group_template_deployment" "disable_principal" {
  count               = local.response_enabled ? 1 : 0
  name                = "deploy-${local.playbook_name}"
  resource_group_name = azurerm_resource_group.lab.name
  deployment_mode     = "Incremental"
  template_content    = file("${path.module}/playbooks/disable-principal.json")

  parameters_content = jsonencode({
    playbookName = { value = local.playbook_name }
    location     = { value = var.location }
    dryRun       = { value = var.playbook_dry_run }
    tags         = { value = local.tags }
  })
}

# The deployment outputs the workflow resource ID and its managed-identity
# principal ID; parse them back out for the RBAC and automation-rule wiring.
locals {
  playbook_outputs      = local.response_enabled ? jsondecode(azurerm_resource_group_template_deployment.disable_principal[0].output_content) : {}
  playbook_id           = local.response_enabled ? local.playbook_outputs.playbookResourceId.value : ""
  playbook_principal_id = local.response_enabled ? local.playbook_outputs.managedIdentityPrincipalId.value : ""
}

# The playbook's managed identity must be able to comment on / update incidents.
resource "azurerm_role_assignment" "playbook_sentinel_responder" {
  count                = local.response_enabled ? 1 : 0
  scope                = azurerm_log_analytics_workspace.lab.id
  role_definition_name = "Microsoft Sentinel Responder"
  principal_id         = local.playbook_principal_id
}

# Sentinel's own service principal needs rights on the playbook's resource group
# for an automation rule to run it. "Microsoft Sentinel Automation Contributor"
# is the purpose-built role.
data "azuread_service_principal" "sentinel" {
  count        = local.response_enabled && var.playbook_auto_run ? 1 : 0
  display_name = "Azure Security Insights"
}

resource "azurerm_role_assignment" "sentinel_automation" {
  count                = local.response_enabled && var.playbook_auto_run ? 1 : 0
  scope                = azurerm_resource_group.lab.id
  role_definition_name = "Microsoft Sentinel Automation Contributor"
  principal_id         = data.azuread_service_principal.sentinel[0].object_id
}

# Graph application permission so the playbook can actually disable a user.
# Only granted when enforcing (not dry-run) and explicitly opted in, because it
# requires Privileged Role Administrator / Global Administrator to assign.
data "azuread_service_principal" "msgraph" {
  count     = local.response_enabled && var.playbook_grant_graph ? 1 : 0
  client_id = "00000003-0000-0000-c000-000000000000"
}

resource "azuread_app_role_assignment" "playbook_user_readwrite" {
  count               = local.response_enabled && var.playbook_grant_graph ? 1 : 0
  app_role_id         = data.azuread_service_principal.msgraph[0].app_role_ids["User.ReadWrite.All"]
  principal_object_id = local.playbook_principal_id
  resource_object_id  = data.azuread_service_principal.msgraph[0].object_id
}

# Run the playbook automatically when KV-001 or STG-001 raises an incident.
resource "azurerm_sentinel_automation_rule" "honeytoken_response" {
  count                      = local.response_enabled && var.playbook_auto_run ? 1 : 0
  name                       = uuidv5("url", "https://github.com/H3llKa1ser/Azure-Detection-Engineering-Lab/automation/honeytoken-response")
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.lab.workspace_id
  display_name               = "Lab - auto-disable principal on honeytoken hit (KV-001 / STG-001)"
  order                      = 2
  triggers_on                = "Incidents"
  triggers_when              = "Created"

  condition_json = jsonencode([
    {
      conditionType = "Property"
      conditionProperties = {
        propertyName = "IncidentRelatedAnalyticRuleIds"
        operator     = "Contains"
        propertyValues = [
          azurerm_sentinel_alert_rule_scheduled.detection["KV-001"].id,
          azurerm_sentinel_alert_rule_scheduled.detection["STG-001"].id,
        ]
      }
    }
  ])

  action_playbook {
    logic_app_id = local.playbook_id
    order        = 1
    tenant_id    = data.azurerm_client_config.current.tenant_id
  }

  depends_on = [azurerm_role_assignment.sentinel_automation]
}
