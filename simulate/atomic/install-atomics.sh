#!/usr/bin/env bash
# Install Invoke-AtomicRedTeam on the victim(s) via Run Command.
# shellcheck source=../lib/common.sh
source "$(dirname "$0")/../lib/common.sh"
require_env
banner "Install Atomic Red Team" "(setup)"
record_run "install-atomics"

if [[ -n "${WIN_VM}" ]]; then
  log "installing Invoke-AtomicRedTeam on ${WIN_VM} (a few minutes)"
  az vm run-command invoke -g "$RG" -n "$WIN_VM" --command-id RunPowerShellScript \
    --scripts @"${SIM_ROOT}/atomic/install-atomics.ps1" --query "value[0].message" -o tsv
else
  warn "Windows VM not deployed - skipping Windows ART install"
fi
cat <<'TXT'
Linux ART (optional): install PowerShell + the module on the Ubuntu victim:
  Invoke-AtomicTest requires pwsh. See docs/atomic-red-team.md for the one-liner.
TXT
