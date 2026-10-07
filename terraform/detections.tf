# ---------------------------------------------------------------------------
# Detection-as-code loader.
#
# Every *.yaml file under detections/ becomes one Sentinel scheduled analytics
# rule. Files are rendered with templatefile() first so queries can reference
# lab-specific names (canary secret, storage account, watchlist alias).
#
# Adding a detection = adding a YAML file. No Terraform changes required.
# ---------------------------------------------------------------------------

locals {
  detections_dir  = "${path.module}/${var.detections_path}"
  detection_files = fileset(local.detections_dir, "**/*.yaml")

  # Two decodes on purpose:
  #  * raw (no templating) -> metadata that must be known at PLAN time
  #    (id = for_each key, requires, enabled). The "${...}" placeholders are
  #    just strings to the YAML parser.
  #  * rendered (templatefile) -> query/description, which embed names that
  #    include a random suffix and are therefore only known after apply.
  # Decoding the rendered file for the keys would make for_each unknown and
  # break `terraform plan` on a fresh workspace.
  detection_raw = {
    for f in local.detection_files : f => yamldecode(file("${local.detections_dir}/${f}"))
  }

  detection_rendered = {
    for f in local.detection_files :
    local.detection_raw[f].id => yamldecode(templatefile("${local.detections_dir}/${f}", local.detection_vars))
  }

  # Data sources actually deployed. Rules declare what they need via
  # `requires:` and are skipped if a source is switched off.
  available_sources = toset(compact([
    "azure_activity",
    "key_vault",
    "storage",
    var.deploy_windows_vm ? "windows_vm" : "",
    var.deploy_linux_vm ? "linux_vm" : "",
    var.enable_entra_id ? "entra_id" : "",
    var.entra_id_p2 ? "entra_id_p2" : "",
    var.enable_flow_logs ? "flow_logs" : "",
    local.sysmon_enabled ? "sysmon" : "",
  ]))

  detections = {
    for f, d in local.detection_raw : d.id => merge(d, { source_file = f })
    if try(d.enabled, true) && length(setsubtract(toset(try(d.requires, [])), local.available_sources)) == 0
  }
}

resource "azurerm_sentinel_alert_rule_scheduled" "detection" {
  for_each = local.detections

  # Deterministic GUID per detection ID so renames of the display name don't
  # recreate the rule and history is preserved.
  name                       = uuidv5("url", "https://github.com/H3llKa1ser/Azure-Detection-Engineering-Lab/detections/${each.key}")
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.lab.workspace_id

  display_name = "[${each.key}] ${each.value.name}"
  description  = trimspace(local.detection_rendered[each.key].description)
  severity     = each.value.severity
  enabled      = true

  query             = local.detection_rendered[each.key].query
  query_frequency   = each.value.query_frequency
  query_period      = each.value.query_period
  trigger_operator  = try(each.value.trigger_operator, "GreaterThan")
  trigger_threshold = try(each.value.trigger_threshold, 0)

  tactics    = each.value.tactics
  techniques = each.value.techniques

  suppression_enabled  = try(each.value.suppression_duration, null) != null
  suppression_duration = try(each.value.suppression_duration, "PT5H")

  custom_details = try(each.value.custom_details, null)

  # Dynamic alert name / severity from query columns, e.g. a CA policy
  # *deletion* is High while a creation is Low - same rule.
  dynamic "alert_details_override" {
    for_each = can(each.value.alert_details_override) ? [local.detection_rendered[each.key].alert_details_override] : []
    content {
      display_name_format  = try(alert_details_override.value.display_name_format, null)
      description_format   = try(alert_details_override.value.description_format, null)
      severity_column_name = try(alert_details_override.value.severity_column_name, null)
      tactics_column_name  = try(alert_details_override.value.tactics_column_name, null)
    }
  }

  dynamic "entity_mapping" {
    for_each = try(each.value.entity_mappings, [])
    content {
      entity_type = entity_mapping.value.entity_type
      dynamic "field_mapping" {
        for_each = entity_mapping.value.field_mappings
        content {
          identifier  = field_mapping.value.identifier
          column_name = field_mapping.value.column_name
        }
      }
    }
  }

  incident {
    create_incident_enabled = true
    grouping {
      enabled                 = true
      lookback_duration       = try(each.value.grouping_lookback, "PT5H")
      entity_matching_method  = "AllEntities"
      reopen_closed_incidents = false
    }
  }

  # Rules are validated server-side against the workspace schema, so the
  # workspace, Sentinel and the watchlist must exist first.
  depends_on = [
    azurerm_sentinel_watchlist.approved_privileged_callers,
    azurerm_monitor_diagnostic_setting.activity_log,
    azurerm_monitor_diagnostic_setting.key_vault,
    azurerm_monitor_diagnostic_setting.blob,
    azurerm_monitor_aad_diagnostic_setting.entra,
    azurerm_sentinel_watchlist_item.canary_accounts,
    azurerm_network_watcher_flow_log.lab,
    azurerm_monitor_data_collection_rule_association.sysmon,
  ]
}
