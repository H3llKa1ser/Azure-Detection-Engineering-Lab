data "azurerm_client_config" "current" {}

data "azurerm_subscription" "current" {}

# Auto-detect the operator's egress IP when not supplied.
data "http" "operator_ip" {
  count = var.operator_ip == null ? 1 : 0
  url   = "https://api.ipify.org"
}

resource "random_string" "suffix" {
  length  = 5
  upper   = false
  special = false
}

locals {
  suffix      = random_string.suffix.result
  name        = "${var.prefix}-${local.suffix}"
  operator_ip = var.operator_ip != null ? var.operator_ip : chomp(data.http.operator_ip[0].response_body)

  # Firewall allowlist for Key Vault and Storage. In CI the auto-detected
  # operator IP is the GitHub runner (different every run), so your own IP is
  # passed in additional_allowed_ips to keep simulations working.
  allowed_ips = distinct(concat([local.operator_ip], var.additional_allowed_ips))

  tags = merge({
    project     = "azure-detection-engineering-lab"
    environment = "lab"
    managed_by  = "terraform"
    ephemeral   = "true"
  }, var.tags)

  # Names of honeytoken artefacts. Detections reference these via templatefile().
  canary_secret_name = "svc-backup-sql-prod-password"
  canary_blob_name   = "finance/2026-payroll-export.csv"
  decoy_secret_names = ["api-key-payments", "db-conn-reporting", "smtp-relay-password", "jwt-signing-key"]

  # Values injected into every detection YAML before it is decoded.
  detection_vars = {
    canary_secret_name     = local.canary_secret_name
    canary_blob_name       = local.canary_blob_name
    canary_blob_leaf       = basename(local.canary_blob_name)
    key_vault_name         = "kv-${local.name}"
    storage_name           = "st${var.prefix}${local.suffix}"
    watchlist_alias        = "LabApprovedPrivilegedCallers"
    canary_watchlist_alias = "LabCanaryAccounts"
    victim_subnet_cidr     = "10.42.1.0/24"
    internal_mgmt_ports    = join(", ", [for p in var.internal_mgmt_ports : tostring(p)])
  }
}
