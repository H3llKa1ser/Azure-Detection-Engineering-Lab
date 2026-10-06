config {
  call_module_type = "local"
}

plugin "terraform" {
  enabled = true
  preset  = "recommended"
}

plugin "azurerm" {
  enabled = true
  version = "0.32.0"
  source  = "github.com/terraform-linters/tflint-ruleset-azurerm"
}

# The lab is intentionally disposable (destroy at the end of every session),
# so prevent_destroy on the canary vault/storage would work against the design.
rule "azurerm_resources_missing_prevent_destroy" {
  enabled = false
}
