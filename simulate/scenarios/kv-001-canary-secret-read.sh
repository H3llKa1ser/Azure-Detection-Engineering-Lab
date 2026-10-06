#!/usr/bin/env bash
# KV-001: read the honeytoken secret. Prints only the secret ID, never the value.
# shellcheck source=../lib/common.sh
source "$(dirname "$0")/../lib/common.sh"
require_env
banner "Canary secret read" "KV-001"
record_run "kv-001-canary-secret-read"

az keyvault secret show --vault-name "$KV_NAME" --name "$CANARY_SECRET" --query id -o tsv
log "done - KeyVault AuditEvent logs typically arrive in 5-10 min"
