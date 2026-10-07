#!/usr/bin/env bash
# SYS-001, SYS-002, SYS-003, SYS-004, SYS-006 (+ AZ-ACT-004 via Run Command).
# SYS-005 (remote-thread injection) is not auto-simulated - see the payload.
# shellcheck source=../lib/common.sh
source "$(dirname "$0")/../lib/common.sh"
require_env
if [[ "${SYSMON_ENABLED:-false}" != "true" ]]; then
  warn "Sysmon not deployed (enable_sysmon = false) - skipping"; exit 0
fi
[[ -n "${WIN_VM}" ]] || { warn "Windows VM not deployed - skipping"; exit 0; }
banner "Sysmon telemetry chain on ${WIN_VM}" "SYS-001 SYS-002 SYS-003 SYS-004 SYS-006 AZ-ACT-004"
record_run "win-sysmon-chain"

state="$(az vm get-instance-view -g "$RG" -n "$WIN_VM" --query "instanceView.statuses[?starts_with(code,'PowerState/')].code" -o tsv)"
if [[ "$state" != "PowerState/running" ]]; then
  log "VM is $state - starting it"; az vm start -g "$RG" -n "$WIN_VM"
fi

az vm run-command invoke -g "$RG" -n "$WIN_VM" --command-id RunPowerShellScript \
  --scripts @"${SIM_ROOT}/payloads/sysmon-chain.ps1" --query "value[0].message" -o tsv
log "Sysmon -> Event table. Alerts typically land in 10-20 min. Then: ./simulate/verify.sh 1"
