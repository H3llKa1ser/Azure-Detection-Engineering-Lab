#!/usr/bin/env bash
# Closes the loop: which detections produced alerts in the last N hours,
# and which expected ones are missing?
#   usage: ./simulate/verify.sh [hours=2]
# shellcheck source=lib/common.sh
source "$(dirname "$0")/lib/common.sh"
require_env
hours="${1:-2}"

# Only expect what is actually deployed (rules whose data source is switched
# off are skipped by Terraform). Falls back to every YAML file.
if [[ -n "${DEPLOYED_DETECTIONS:-}" ]]; then
  expected="$(tr ' ' '\n' <<< "$DEPLOYED_DETECTIONS" | sort -u)"
else
  expected="$(grep -rh --include='*.yaml' '^id:' "${SIM_ROOT}/../detections" | awk '{print $2}' | sort -u)"
fi

read -r -d '' kql <<KQL || true
SecurityAlert
| where TimeGenerated > ago(${hours}h)
| extend DetectionId = extract(@"^\[([A-Z0-9-]+)\]", 1, AlertName)
| where isnotempty(DetectionId)
| summarize Alerts = count(), Last = max(TimeGenerated) by DetectionId
| order by DetectionId asc
KQL

log "querying SecurityAlert for the last ${hours}h in ${LAW_NAME}"
fired="$(az monitor log-analytics query -w "$LAW_CUSTOMER_ID" --analytics-query "$kql" \
          --query "[].DetectionId" -o tsv | sort -u)"

pass=0; miss=0
printf '\n%-12s %s\n' "DETECTION" "STATUS"
while read -r id; do
  [[ -z "$id" ]] && continue
  if grep -qx "$id" <<< "$fired"; then
    printf '%-12s \033[1;32mFIRED\033[0m\n' "$id"; pass=$((pass + 1))
  else
    printf '%-12s \033[1;31mMISSING\033[0m\n' "$id"; miss=$((miss + 1))
  fi
done <<< "$expected"

printf '\n%d fired, %d missing\n' "$pass" "$miss"
[[ "$miss" -eq 0 ]] || warn "ENT-003..006 only fire if run with ALLOW_TENANT_CHANGES=1; ENT-007 is manual."
[[ "$miss" -eq 0 ]] || warn "Missing alerts? Check ingestion first (e.g. 'AzureDiagnostics | take 1'), then the rule's health in Sentinel > Analytics."
