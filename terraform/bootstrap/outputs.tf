output "azure_client_id" {
  description = "GitHub repo variable AZURE_CLIENT_ID."
  value       = azuread_application.github.client_id
}

output "azure_tenant_id" {
  description = "GitHub repo variable AZURE_TENANT_ID."
  value       = data.azurerm_client_config.current.tenant_id
}

output "azure_subscription_id" {
  description = "GitHub repo variable AZURE_SUBSCRIPTION_ID."
  value       = data.azurerm_subscription.current.subscription_id
}

output "tfstate_resource_group" {
  value = azurerm_resource_group.state.name
}

output "tfstate_storage_account" {
  value = azurerm_storage_account.state.name
}

output "tfstate_container" {
  value = azurerm_storage_container.state.name
}

output "federated_subjects" {
  description = "OIDC subjects trusted by the deploy identity."
  value       = values(local.federated_subjects)
}

# Paste-ready commands. Values are identifiers, not secrets, so they go in
# repo VARIABLES (not secrets) - OIDC needs no secret at all.
output "gh_variable_commands" {
  value = <<-CMD
    gh variable set AZURE_CLIENT_ID         --body "${azuread_application.github.client_id}"
    gh variable set AZURE_TENANT_ID         --body "${data.azurerm_client_config.current.tenant_id}"
    gh variable set AZURE_SUBSCRIPTION_ID   --body "${data.azurerm_subscription.current.subscription_id}"
    gh variable set TFSTATE_RESOURCE_GROUP  --body "${azurerm_resource_group.state.name}"
    gh variable set TFSTATE_STORAGE_ACCOUNT --body "${azurerm_storage_account.state.name}"
    gh variable set TFSTATE_CONTAINER       --body "${azurerm_storage_container.state.name}"
    gh variable set OPERATOR_ALLOWED_IPS    --body '["<your-public-ip>"]'
  CMD
}

output "backend_hcl" {
  description = "Contents for terraform/backend.hcl (local remote-state use)."
  value       = <<-HCL
    resource_group_name  = "${azurerm_resource_group.state.name}"
    storage_account_name = "${azurerm_storage_account.state.name}"
    container_name       = "${azurerm_storage_container.state.name}"
    key                  = "lab.tfstate"
    use_azuread_auth     = true
  HCL
}
