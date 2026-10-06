#!/usr/bin/env bash
# LNX-001, LNX-002 (+ AZ-ACT-004 via Run Command itself).
# shellcheck source=../lib/common.sh
source "$(dirname "$0")/../lib/common.sh"
require_env
[[ -n "${LINUX_VM}" ]] || { warn "Linux VM not deployed - skipping"; exit 0; }
banner "Linux attack chain on ${LINUX_VM}" "LNX-001 LNX-002 AZ-ACT-004"
record_run "lnx-sim-chain"

state="$(az vm get-instance-view -g "$RG" -n "$LINUX_VM" --query "instanceView.statuses[?starts_with(code,'PowerState/')].code" -o tsv)"
if [[ "$state" != "PowerState/running" ]]; then
  log "VM is $state - starting it"
  az vm start -g "$RG" -n "$LINUX_VM"
fi

az vm run-command invoke -g "$RG" -n "$LINUX_VM" --command-id RunShellScript \
  --scripts @"${SIM_ROOT}/payloads/lnx-chain.sh" --query "value[0].message" -o tsv
