# Offline tests for the bootstrap module - no Azure credentials needed.
# Run: terraform -chdir=terraform/bootstrap test

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
  mock_data "azurerm_role_definition" {
    defaults = {
      role_definition_id = "b86a8fe4-44ce-4948-aee5-eccb2c155cd7"
    }
  }
}

mock_provider "azuread" {}

variables {
  subscription_id = "00000000-0000-0000-0000-000000000000"
}

run "state_storage_is_hardened" {
  command = plan

  assert {
    condition     = azurerm_storage_account.state.shared_access_key_enabled == false
    error_message = "State storage must disable shared keys (Entra ID auth only)."
  }

  assert {
    condition     = azurerm_storage_account.state.blob_properties[0].versioning_enabled == true
    error_message = "State blobs must be versioned so a bad apply is recoverable."
  }

  assert {
    condition     = azurerm_storage_account.state.min_tls_version == "TLS1_2"
    error_message = "State storage must require TLS 1.2."
  }

  assert {
    condition     = azurerm_storage_container.state.container_access_type == "private"
    error_message = "The state container must be private."
  }
}

run "oidc_is_secretless_and_scoped" {
  command = plan

  assert {
    condition     = length(azuread_application_federated_identity_credential.github) == 3
    error_message = "Expected exactly three federated credentials: environment, pull_request, main."
  }

  assert {
    condition     = azuread_application_federated_identity_credential.github["environment"].subject == "repo:H3llKa1ser/Azure-Detection-Engineering-Lab:environment:lab"
    error_message = "Apply/destroy must be gated to the protected 'lab' environment subject."
  }

  assert {
    condition     = alltrue([for c in azuread_application_federated_identity_credential.github : c.issuer == "https://token.actions.githubusercontent.com" && contains(c.audiences, "api://AzureADTokenExchange")])
    error_message = "Federated credentials must trust only GitHub's OIDC issuer and the AzureADTokenExchange audience."
  }
}

run "rbac_is_least_privilege" {
  command = plan

  assert {
    condition     = azurerm_role_assignment.github_rbac_admin_constrained.role_definition_name == "Role Based Access Control Administrator"
    error_message = "The pipeline should get RBAC Administrator, not Owner or User Access Administrator."
  }

  assert {
    condition     = azurerm_role_assignment.github_rbac_admin_constrained.condition_version == "2.0" && strcontains(azurerm_role_assignment.github_rbac_admin_constrained.condition, "roleAssignments:RoleDefinitionId")
    error_message = "RBAC Administrator must be constrained by an ABAC condition on RoleDefinitionId."
  }

  assert {
    condition     = strcontains(azurerm_role_assignment.github_rbac_admin_constrained.condition, "roleAssignments/delete")
    error_message = "The condition must constrain deletes as well as writes."
  }

  assert {
    condition     = length(data.azurerm_role_definition.delegable) == 4
    error_message = "Exactly the four roles the lab assigns should be delegable."
  }
}

run "custom_repo_subjects" {
  command = plan

  variables {
    github_owner       = "someone"
    github_repo        = "fork-lab"
    github_environment = "prod-lab"
  }

  assert {
    condition     = azuread_application_federated_identity_credential.github["pull_request"].subject == "repo:someone/fork-lab:pull_request"
    error_message = "Subjects must follow github_owner/github_repo."
  }

  assert {
    condition     = azuread_application_federated_identity_credential.github["environment"].subject == "repo:someone/fork-lab:environment:prod-lab"
    error_message = "Environment subject must follow github_environment."
  }
}
