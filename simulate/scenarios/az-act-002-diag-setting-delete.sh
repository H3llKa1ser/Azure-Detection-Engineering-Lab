#!/usr/bin/env bash
# AZ-ACT-002: create then delete a temporary diagnostic setting on the
# unattached simulation NSG. The lab's real logging is never touched.
# shellcheck source=../lib/common.sh
source "$(dirname "$0")/../lib/common.sh"
require_env
banner "Diagnostic setting deletion" "AZ-ACT-002"
record_run "az-act-002-diag-setting-delete"

az monitor diagnostic-settings create --name "sim-temp-diag" --resource "$SIM_NSG_ID" \
  --workspace "$LAW_ID" --logs '[{"category":"NetworkSecurityGroupEvent","enabled":true}]' --output none
log "created sim-temp-diag; deleting in 20s"
sleep 20
az monitor diagnostic-settings delete --name "sim-temp-diag" --resource "$SIM_NSG_ID"
log "deleted"
