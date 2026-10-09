# ---------------------------------------------------------------------------
# One-time bootstrap: remote state storage + a secretless GitHub Actions
# identity (OIDC workload identity federation).
# ---------------------------------------------------------------------------

data "azurerm_client_config" "current" {}
data "azurerm_subscription" "current" {}

resource "random_string" "suffix" {
  length  = 5
  upper   = false
  special = false
}

locals {
  repo_full = "${var.github_owner}/${var.github_repo}"
  tags = {
    project    = "azure-detection-engineering-lab"
    component  = "bootstrap"
    managed_by = "terraform"
  }

  # Each GitHub Actions context gets its own federated credential. The subject
  # is exact-match, so the token from a PR can only plan, and only a job in the
  # protected environment (with required reviewers) can apply/destroy.
  federated_subjects = {
    environment  = "repo:${local.repo_full}:environment:${var.github_environment}"
    pull_request = "repo:${local.repo_full}:pull_request"
    main_branch  = "repo:${local.repo_full}:ref:refs/heads/main"
  }

  # Roles the LAB itself hands out (see canaries.tf, response.tf). The deploy
  # identity may assign ONLY these - enforced with an ABAC condition below.
  delegable_roles = [
    "Key Vault Secrets Officer",
    "Storage Blob Data Contributor",
    "Microsoft Sentinel Responder",
    "Microsoft Sentinel Automation Contributor",
  ]
}

# --- State storage ---------------------------------------------------------

resource "azurerm_resource_group" "state" {
  name     = "rg-tfstate-${var.prefix}-${random_string.suffix.result}"
  location = var.location
  tags     = local.tags
}

resource "azurerm_storage_account" "state" {
  #checkov:skip=CKV_AZURE_33:Queue service is unused.
  #checkov:skip=CKV_AZURE_59:GitHub-hosted runner IPs are not fixed; access is controlled by Entra ID RBAC with shared keys disabled.
  #checkov:skip=CKV_AZURE_206:LRS + versioning + soft delete is adequate for lab state.
  #checkov:skip=CKV2_AZURE_1:Customer-managed keys out of scope.
  #checkov:skip=CKV2_AZURE_33:Private endpoint unusable from GitHub-hosted runners.
  #checkov:skip=CKV2_AZURE_47:Same as CKV_AZURE_59 - public endpoint, Entra-only auth.
  name                              = "sttfstate${random_string.suffix.result}"
  resource_group_name               = azurerm_resource_group.state.name
  location                          = azurerm_resource_group.state.location
  account_tier                      = "Standard"
  account_replication_type          = "LRS"
  account_kind                      = "StorageV2"
  min_tls_version                   = "TLS1_2"
  https_traffic_only_enabled        = true
  shared_access_key_enabled         = false # Entra ID only; backend uses use_azuread_auth
  default_to_oauth_authentication   = true
  allow_nested_items_to_be_public   = false
  infrastructure_encryption_enabled = true
  tags                              = local.tags

  blob_properties {
    versioning_enabled  = true # every state write is a recoverable version
    change_feed_enabled = true

    delete_retention_policy {
      days = var.state_retention_days
    }
    container_delete_retention_policy {
      days = var.state_retention_days
    }
  }

  sas_policy {
    expiration_period = "00.01:00:00"
    expiration_action = "Log"
  }
}

resource "azurerm_storage_container" "state" {
  #checkov:skip=CKV2_AZURE_21:Blob logging for the state account is optional for a lab; enable a diagnostic setting if required.
  name                  = "tfstate"
  storage_account_id    = azurerm_storage_account.state.id
  container_access_type = "private"
}

# You (the human running bootstrap) also need data-plane access to state.
resource "azurerm_role_assignment" "operator_state" {
  scope                = azurerm_storage_account.state.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = data.azurerm_client_config.current.object_id
}

# --- GitHub Actions identity (OIDC, no client secret) ----------------------

resource "azuread_application" "github" {
  display_name     = "gh-oidc-${var.github_repo}"
  sign_in_audience = "AzureADMyOrg"
  owners           = [data.azurerm_client_config.current.object_id]
  notes            = "GitHub Actions deploy identity for ${local.repo_full}. Federated credentials only - never add a client secret."
}

resource "azuread_service_principal" "github" {
  client_id = azuread_application.github.client_id
  owners    = [data.azurerm_client_config.current.object_id]
}

resource "azuread_application_federated_identity_credential" "github" {
  for_each       = local.federated_subjects
  application_id = azuread_application.github.id
  display_name   = "github-${each.key}"
  description    = "GitHub Actions: ${each.value}"
  issuer         = "https://token.actions.githubusercontent.com"
  audiences      = ["api://AzureADTokenExchange"]
  subject        = each.value
}

# --- Least-privilege RBAC for the deploy identity --------------------------

# Contributor: create/destroy everything the lab deploys, including the
# subscription Activity Log diagnostic setting and RP registration.
resource "azurerm_role_assignment" "github_contributor" {
  scope                = data.azurerm_subscription.current.id
  role_definition_name = "Contributor"
  principal_id         = azuread_service_principal.github.object_id
}

# The lab assigns a handful of data-plane / Sentinel roles. Instead of Owner or
# User Access Administrator, grant RBAC Administrator CONSTRAINED by an ABAC
# condition so the pipeline can create and delete assignments for exactly these
# roles and nothing else - it cannot make itself or anyone Owner.
data "azurerm_role_definition" "delegable" {
  for_each = toset(local.delegable_roles)
  name     = each.value
  scope    = data.azurerm_subscription.current.id
}

locals {
  delegable_role_guids = join(", ", sort([for r in data.azurerm_role_definition.delegable : r.role_definition_id]))

  rbac_admin_condition = <<-COND
    (
     (
      !(ActionMatches{'Microsoft.Authorization/roleAssignments/write'})
     )
     OR
     (
      @Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {${local.delegable_role_guids}}
     )
    )
    AND
    (
     (
      !(ActionMatches{'Microsoft.Authorization/roleAssignments/delete'})
     )
     OR
     (
      @Resource[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {${local.delegable_role_guids}}
     )
    )
  COND
}

resource "azurerm_role_assignment" "github_rbac_admin_constrained" {
  scope                = data.azurerm_subscription.current.id
  role_definition_name = "Role Based Access Control Administrator"
  principal_id         = azuread_service_principal.github.object_id
  condition_version    = "2.0"
  condition            = local.rbac_admin_condition
  description          = "Pipeline may only assign: ${join(", ", local.delegable_roles)}"
}

# Data-plane access to the state blob (shared keys are disabled).
resource "azurerm_role_assignment" "github_state" {
  scope                = azurerm_storage_account.state.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azuread_service_principal.github.object_id
}
