#!/usr/bin/env bash
# NET-001, NET-002, NET-003, NET-005 (+ AZ-ACT-004 via Run Command).
# NET-004 (malicious flow) can't be triggered safely on demand - see below.
# shellcheck source=../lib/common.sh
source "$(dirname "$0")/../lib/common.sh"
require_env
if [[ "${FLOW_LOGS_ENABLED:-false}" != "true" ]]; then
  warn "Flow logs not deployed (enable_flow_logs = false) - skipping"; exit 0
fi
[[ -n "${LINUX_VM}" ]] || { warn "Linux VM not deployed - NET scenarios need it - skipping"; exit 0; }
banner "Network attack chain on ${LINUX_VM}" "NET-001 NET-002 NET-003 NET-005 AZ-ACT-004"
record_run "net-sim-chain"

state="$(az vm get-instance-view -g "$RG" -n "$LINUX_VM" --query "instanceView.statuses[?starts_with(code,'PowerState/')].code" -o tsv)"
if [[ "$state" != "PowerState/running" ]]; then
  log "VM is $state - starting it"; az vm start -g "$RG" -n "$LINUX_VM"
fi

subnet_prefix="$(cut -d. -f1-3 <<< "${VICTIM_SUBNET_CIDR%/*}")"
az vm run-command invoke -g "$RG" -n "$LINUX_VM" --command-id RunShellScript \
  --scripts @"${SIM_ROOT}/payloads/net-chain.sh" \
  --parameters "SUBNET_PREFIX=${subnet_prefix}" \
  --query "value[0].message" -o tsv

cat <<'TXT'

NET-004 (Traffic Analytics "MaliciousFlow") is driven by Microsoft's threat
intelligence and cannot be triggered safely on demand. To exercise it in a
controlled way, generate a DNS lookup / connection to an EICAR-style test
domain from the victim host and wait for enrichment, or validate the rule
logic against historical data. Never connect a lab host to genuinely
malicious infrastructure.
TXT
log "Traffic Analytics latency means NET alerts can take 30-75 min. Then run: ./simulate/verify.sh 2"
