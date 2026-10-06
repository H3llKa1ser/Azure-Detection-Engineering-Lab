# ---------------------------------------------------------------------------
# Entra ID (identity) telemetry and deception. Everything here is gated on
# var.enable_entra_id because it needs Entra ID P1/P2 and tenant-level rights.
#
#  * Tenant diagnostic setting -> SigninLogs, AADNonInteractiveUserSignInLogs,
#    AuditLogs, ... (+ Identity Protection tables with P2)
#  * Canary accounts: DISABLED users that nothing should ever sign in as.
#    Any sign-in attempt against them is high-fidelity (ENT-001, ENT-002).
#  * A simulation app + service principal and a disabled role-target user,
#    used as safe targets by the tenant-change simulations (ENT-003..006).
#
# Reading these objects during `terraform plan` is a Graph read: it creates no
# sign-in or audit events, so (unlike the Key Vault canary) Terraform can own
# them without tripping the detections.
# ---------------------------------------------------------------------------

locals {
  entra_log_categories = concat(
    [
      "SignInLogs",
      "NonInteractiveUserSignInLogs",
      "ServicePrincipalSignInLogs",
      "ManagedIdentitySignInLogs",
      "AuditLogs",
    ],
    var.entra_id_p2 ? [
      "RiskyUsers",
      "UserRiskEvents",
      "RiskyServicePrincipals",
      "ServicePrincipalRiskEvents",
    ] : [],
  )

  # Plausible-looking, high-value-sounding names: what an attacker spraying a
  # user list or browsing the directory would go for.
  canary_accounts = var.enable_entra_id ? {
    "it-breakglass-legacy"  = "IT Break Glass (Legacy)"
    "svc-sql-backup"        = "SQL Backup Service"
    "svc-intranet-sync"     = "Intranet Sync Service"
    "temp-contractor-04"    = "Contractor 04 (Temp)"
    "helpdesk-tier2-legacy" = "Helpdesk Tier 2 (Legacy)"
  } : {}

  entra_domain = var.enable_entra_id ? data.azuread_domains.initial[0].domains[0].domain_name : ""
}

data "azuread_domains" "initial" {
  count        = var.enable_entra_id ? 1 : 0
  only_initial = true
}

resource "azurerm_monitor_aad_diagnostic_setting" "entra" {
  count                      = var.enable_entra_id ? 1 : 0
  name                       = "diag-entra-${local.name}"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.lab.id

  dynamic "enabled_log" {
    for_each = local.entra_log_categories
    content {
      category = enabled_log.value
    }
  }
}

# --- Canary accounts ------------------------------------------------------

resource "random_password" "canary_user" {
  for_each = local.canary_accounts
  length   = 64
  special  = true
}

resource "azuread_user" "canary" {
  for_each                    = local.canary_accounts
  user_principal_name         = "${each.key}@${local.entra_domain}"
  display_name                = each.value
  mail_nickname               = each.key
  department                  = "IT"
  job_title                   = "Service account"
  password                    = random_password.canary_user[each.key].result
  disable_password_expiration = true

  # Disabled: an attempt is still logged (50057/50126), but the account can
  # never be used even if its password leaked.
  account_enabled = false
}

resource "azurerm_sentinel_watchlist" "canary_accounts" {
  count                      = var.enable_entra_id ? 1 : 0
  name                       = local.detection_vars.canary_watchlist_alias
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.lab.workspace_id
  display_name               = "Lab - canary (honeytoken) accounts"
  description                = "Entra ID accounts that must never be used. Any sign-in attempt is an incident (ENT-002)."
  item_search_key            = "UserPrincipalName"
  labels                     = ["detection-lab", "honeytoken"]
}

resource "azurerm_sentinel_watchlist_item" "canary_accounts" {
  for_each     = azuread_user.canary
  watchlist_id = azurerm_sentinel_watchlist.canary_accounts[0].id
  properties = {
    UserPrincipalName = each.value.user_principal_name
    ObjectId          = each.value.object_id
    Purpose           = "honeytoken"
  }
}

# --- Simulation targets ---------------------------------------------------

# Disabled user that the privileged-role and CA-policy simulations target.
resource "random_password" "sim_role_target" {
  count   = var.enable_entra_id ? 1 : 0
  length  = 64
  special = true
}

resource "azuread_user" "sim_role_target" {
  count                       = var.enable_entra_id ? 1 : 0
  user_principal_name         = "detlab-sim-role-target-${local.suffix}@${local.entra_domain}"
  display_name                = "Detection Lab - simulation target"
  mail_nickname               = "detlab-sim-role-target-${local.suffix}"
  password                    = random_password.sim_role_target[0].result
  disable_password_expiration = true
  account_enabled             = false
}

# App registration the credential-add and consent simulations act on.
resource "azuread_application" "sim" {
  count            = var.enable_entra_id ? 1 : 0
  display_name     = "detlab-sim-app-${local.suffix}"
  sign_in_audience = "AzureADMyOrg"
  owners           = [data.azurerm_client_config.current.object_id]
  notes            = "Detection lab simulation target. Credentials and permissions are added and removed by simulate/scenarios/ent-*.sh."

  lifecycle {
    # Simulations add and remove these out-of-band.
    ignore_changes = [password, required_resource_access]
  }
}

resource "azuread_service_principal" "sim" {
  count     = var.enable_entra_id ? 1 : 0
  client_id = azuread_application.sim[0].client_id
  owners    = [data.azurerm_client_config.current.object_id]
}
