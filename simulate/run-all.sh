#!/usr/bin/env bash
# Run every scenario, then tell you when to run verify.sh.
# shellcheck source=lib/common.sh
source "$(dirname "$0")/lib/common.sh"
require_env

scenarios=(
  kv-001-canary-secret-read
  kv-002-bulk-secret-enumeration
  stg-001-canary-blob-read
  az-act-001-role-assignment
  az-act-002-diag-setting-delete
  az-act-003-nsg-open-rdp
  az-act-005-storage-listkeys
  win-sim-chain
  lnx-sim-chain
)

failed=()
for s in "${scenarios[@]}"; do
  if ! bash "${SIM_ROOT}/scenarios/${s}.sh"; then
    warn "$s failed"
    failed+=("$s")
  fi
done

log "all scenarios executed (${#failed[@]} failed: ${failed[*]:-none})"
log "Ingestion + rule schedules mean alerts land in ~15-30 min. Then run:"
log "  ./simulate/verify.sh 2"
