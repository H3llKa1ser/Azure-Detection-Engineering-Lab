#!/usr/bin/env bash
# STG-001: download the honeytoken blob with Entra ID auth, then discard it.
# shellcheck source=../lib/common.sh
source "$(dirname "$0")/../lib/common.sh"
require_env
banner "Canary blob download" "STG-001"
record_run "stg-001-canary-blob-read"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
az storage blob download --auth-mode login \
  --account-name "$STORAGE_ACCOUNT" --container-name "$CANARY_CONTAINER" \
  --name "$CANARY_BLOB" --file "$tmp" --output none
log "downloaded $(wc -c < "$tmp") bytes (discarded)"
