resource "azurerm_resource_group" "lab" {
  name     = "rg-${local.name}"
  location = var.location
  tags     = local.tags
}
