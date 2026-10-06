#!/usr/bin/env bash
# ENT-006: grant the simulation app's service principal the Microsoft Graph
# Mail.Read *application* permission (admin consent equivalent), then revoke.
# The app has no credentials, so the grant is unusable while it exists.
# Needs Privileged Role Administrator / Cloud Application Administrator.
# shellcheck source=../lib/common.sh
source "$(dirname "$0")/../lib/common.sh"
require_env
require_entra
require_tenant_changes
banner "High-risk Graph permission granted to app" "ENT-006"
record_run "ent-006-high-risk-consent"

graph_sp="$(az ad sp show --id 00000003-0000-0000-c000-000000000000 --query id -o tsv)"
mail_read_role="810c84a8-4a9e-49e6-bf7d-12d183f40d01"   # Graph application permission Mail.Read
body="{\"principalId\":\"${SIM_SP_ID}\",\"resourceId\":\"${graph_sp}\",\"appRoleId\":\"${mail_read_role}\"}"

grant="$(graph POST "/servicePrincipals/${SIM_SP_ID}/appRoleAssignments" "$body" --query id -o tsv)" || exit 1
log "granted Mail.Read (application) to sim app; revoking in 30s"
sleep 30
graph DELETE "/servicePrincipals/${SIM_SP_ID}/appRoleAssignments/${grant}" >/dev/null
log "revoked"
