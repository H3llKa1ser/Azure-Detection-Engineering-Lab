#!/usr/bin/env bash
# WIN-001..004 (+ AZ-ACT-004 via Run Command itself).
# shellcheck source=../lib/common.sh
source "$(dirname "$0")/../lib/common.sh"
require_env
[[ -n "${WIN_VM}" ]] || { warn "Windows VM not deployed - skipping"; exit 0; }
banner "Windows attack chain on ${WIN_VM}" "WIN-001 WIN-002 WIN-003 WIN-004 AZ-ACT-004"
record_run "win-sim-chain"

state="$(az vm get-instance-view -g "$RG" -n "$WIN_VM" --query "instanceView.statuses[?starts_with(code,'PowerState/')].code" -o tsv)"
if [[ "$state" != "PowerState/running" ]]; then
  log "VM is $state - starting it (auto-shutdown may have stopped it)"
  az vm start -g "$RG" -n "$WIN_VM"
fi

az vm run-command invoke -g "$RG" -n "$WIN_VM" --command-id RunPowerShellScript \
  --scripts @"${SIM_ROOT}/payloads/win-chain.ps1" --query "value[0].message" -o tsv
