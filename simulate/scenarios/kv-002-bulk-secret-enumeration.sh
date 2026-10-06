#!/usr/bin/env bash
# KV-002: list the vault and read every secret except the canary
# (kept separate so KV-001 and KV-002 can be validated independently).
# shellcheck source=../lib/common.sh
source "$(dirname "$0")/../lib/common.sh"
require_env
banner "Bulk secret enumeration" "KV-002"
record_run "kv-002-bulk-secret-enumeration"

mapfile -t names < <(az keyvault secret list --vault-name "$KV_NAME" --query "[].name" -o tsv)
count=0
for n in "${names[@]}"; do
  [[ "$n" == "$CANARY_SECRET" ]] && continue
  az keyvault secret show --vault-name "$KV_NAME" --name "$n" --query id -o none
  count=$((count + 1))
  log "read $n"
done
log "read $count secrets"
