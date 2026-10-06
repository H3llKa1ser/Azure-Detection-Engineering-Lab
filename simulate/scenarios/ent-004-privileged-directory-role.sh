#!/usr/bin/env bash
# ENT-004: assign Application Administrator to the DISABLED simulation-target
# user for 30 seconds, then remove it. Needs Privileged Role Administrator
# (or Global Administrator).
# shellcheck source=../lib/common.sh
source "$(dirname "$0")/../lib/common.sh"
require_env
require_entra
require_tenant_changes
banner "Privileged directory role assignment" "ENT-004"
record_run "ent-004-privileged-directory-role"

app_admin_template="9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"   # Application Administrator
body="{\"principalId\":\"${SIM_ROLE_TARGET_ID}\",\"roleDefinitionId\":\"${app_admin_template}\",\"directoryScopeId\":\"/\"}"

assignment="$(graph POST "/roleManagement/directory/roleAssignments" "$body" --query id -o tsv)" || exit 1
log "assigned Application Administrator to disabled sim user (assignment ${assignment}); removing in 30s"
sleep 30
graph DELETE "/roleManagement/directory/roleAssignments/${assignment}" >/dev/null
log "removed"
