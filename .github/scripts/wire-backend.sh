#!/usr/bin/env bash
# Generate the remote-backend wiring for CI. Run from terraform/.
# Inputs (GitHub repo variables): TFSTATE_RESOURCE_GROUP, TFSTATE_STORAGE_ACCOUNT,
# TFSTATE_CONTAINER, and optional LAB_TFVARS (HCL, e.g. enable_sysmon = true).
set -euo pipefail

for v in TFSTATE_RESOURCE_GROUP TFSTATE_STORAGE_ACCOUNT TFSTATE_CONTAINER; do
  [[ -n "${!v:-}" ]] || { echo "::error::repo variable $v is not set (run make bootstrap)"; exit 1; }
done

cat > backend_remote.tf <<'HCL'
terraform {
  backend "azurerm" {}
}
HCL

cat > backend.hcl <<HCL
resource_group_name  = "${TFSTATE_RESOURCE_GROUP}"
storage_account_name = "${TFSTATE_STORAGE_ACCOUNT}"
container_name       = "${TFSTATE_CONTAINER}"
key                  = "lab.tfstate"
use_azuread_auth     = true
use_oidc             = true
HCL

if [[ -n "${LAB_TFVARS:-}" ]]; then
  printf '%s\n' "$LAB_TFVARS" > ci.auto.tfvars
  echo "using LAB_TFVARS ($(wc -l < ci.auto.tfvars) lines) as ci.auto.tfvars"
fi

# terraform init reads backend.hcl via TF_CLI_ARGS_init.
echo "TF_CLI_ARGS_init=-backend-config=backend.hcl" >> "${GITHUB_ENV:-/dev/null}"
echo "backend wired: ${TFSTATE_STORAGE_ACCOUNT}/${TFSTATE_CONTAINER}/lab.tfstate"
