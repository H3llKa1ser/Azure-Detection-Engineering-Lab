#!/usr/bin/env bash
# AZ-ACT-001: grant Owner on the lab RG to a throwaway managed identity, then revoke.
# Requires the operator to hold Owner / User Access Administrator on the lab RG.
# shellcheck source=../lib/common.sh
source "$(dirname "$0")/../lib/common.sh"
require_env
banner "Privileged role assignment" "AZ-ACT-001"
record_run "az-act-001-role-assignment"

scope="/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RG}"
az role assignment create --assignee-object-id "$SIM_IDENTITY_PRINCIPAL_ID" \
  --assignee-principal-type ServicePrincipal --role "Owner" --scope "$scope" --output none
log "granted Owner to sim identity on $RG; revoking in 30s"
sleep 30
az role assignment delete --assignee "$SIM_IDENTITY_PRINCIPAL_ID" --role "Owner" --scope "$scope"
log "revoked"
