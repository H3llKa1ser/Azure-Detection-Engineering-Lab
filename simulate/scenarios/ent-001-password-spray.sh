#!/usr/bin/env bash
# ENT-001 (+ ENT-002): spray random wrong passwords at the disabled canary
# accounts. Only failed sign-ins are generated; no tenant objects change.
# shellcheck source=../lib/common.sh
source "$(dirname "$0")/../lib/common.sh"
require_env
require_entra
banner "Password spray against canary accounts" "ENT-001 ENT-002"
record_run "ent-001-password-spray"

read -r -a upns <<< "$CANARY_UPNS"
for round in 1 2; do
  for upn in "${upns[@]}"; do
    code="$(ropc_attempt "$upn")"
    log "round ${round}: ${upn} -> ${code:-no AADSTS code}"
    sleep 2
  done
done
log "${#upns[@]} accounts x 2 attempts. Entra sign-in logs typically arrive in 5-15 min."
