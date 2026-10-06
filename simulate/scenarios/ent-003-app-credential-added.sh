#!/usr/bin/env bash
# ENT-003: add a client secret to the lab's simulation app, then delete it.
# The secret value is discarded immediately and never printed.
# shellcheck source=../lib/common.sh
source "$(dirname "$0")/../lib/common.sh"
require_env
require_entra
require_tenant_changes
banner "Client secret added to application" "ENT-003"
record_run "ent-003-app-credential-added"

name="sim-cred-$(date +%s)"
az ad app credential reset --id "$SIM_APP_ID" --append --display-name "$name" --years 1 --output none
log "added secret '$name' to app $SIM_APP_ID; removing in 20s"
sleep 20
for key in $(az ad app credential list --id "$SIM_APP_ID" --query "[?displayName=='${name}'].keyId" -o tsv); do
  az ad app credential delete --id "$SIM_APP_ID" --key-id "$key"
done
log "removed"
