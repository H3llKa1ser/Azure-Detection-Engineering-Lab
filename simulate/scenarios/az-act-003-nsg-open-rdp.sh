#!/usr/bin/env bash
# AZ-ACT-003: open RDP to the Internet on the UNATTACHED simulation NSG, then remove it.
# shellcheck source=../lib/common.sh
source "$(dirname "$0")/../lib/common.sh"
require_env
banner "NSG management port opened to Internet" "AZ-ACT-003"
record_run "az-act-003-nsg-open-rdp"

az network nsg rule create -g "$RG" --nsg-name "$SIM_NSG" -n "sim-allow-rdp-internet" \
  --priority 300 --direction Inbound --access Allow --protocol Tcp \
  --source-address-prefixes Internet --source-port-ranges '*' \
  --destination-address-prefixes '*' --destination-port-ranges 3389 --output none
log "rule created on $SIM_NSG (not attached to anything); removing in 20s"
sleep 20
az network nsg rule delete -g "$RG" --nsg-name "$SIM_NSG" -n "sim-allow-rdp-internet"
log "removed"
