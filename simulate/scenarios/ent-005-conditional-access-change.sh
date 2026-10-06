#!/usr/bin/env bash
# ENT-005: create a DISABLED Conditional Access policy scoped to the disabled
# simulation-target user and no applications, rename it, then delete it.
# It is never enforced. Needs Conditional Access Administrator.
# shellcheck source=../lib/common.sh
source "$(dirname "$0")/../lib/common.sh"
require_env
require_entra
require_tenant_changes
banner "Conditional Access policy create/update/delete" "ENT-005"
record_run "ent-005-conditional-access-change"

name="detlab-sim-ca-$(date +%s)"
body=$(cat <<JSON
{
  "displayName": "${name}",
  "state": "disabled",
  "conditions": {
    "users": { "includeUsers": ["${SIM_ROLE_TARGET_ID}"] },
    "applications": { "includeApplications": ["None"] },
    "clientAppTypes": ["all"]
  },
  "grantControls": { "operator": "OR", "builtInControls": ["block"] }
}
JSON
)

policy="$(graph POST "/identity/conditionalAccess/policies" "$body" --query id -o tsv)" || exit 1
log "created disabled policy ${name} (${policy})"
sleep 15
graph PATCH "/identity/conditionalAccess/policies/${policy}" "{\"displayName\":\"${name}-modified\"}" >/dev/null
log "updated"
sleep 15
graph DELETE "/identity/conditionalAccess/policies/${policy}" >/dev/null
log "deleted"
