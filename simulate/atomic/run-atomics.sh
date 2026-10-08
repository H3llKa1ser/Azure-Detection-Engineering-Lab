#!/usr/bin/env bash
# Run Atomic Red Team tests from atomic-map.yaml on the victim hosts via Run
# Command, then verify the mapped detections fired.
#
#   ./run-atomics.sh                       # safe + moderate windows tests (pinned only)
#   ./run-atomics.sh --risk safe           # only safe tests
#   ./run-atomics.sh --detection SYS-004   # only tests mapped to one detection
#   ./run-atomics.sh --include-high        # also run high-risk (lsass, injection)
#   ./run-atomics.sh --allow-unpinned      # also run entries with no pinned GUID
#                                          # (runs the technique's default test)
#
# ART runs REAL attacker techniques. This refuses to run unless the lab looks
# ephemeral and you opt in with ALLOW_ATOMIC_TESTS=1.
# shellcheck source=../lib/common.sh
source "$(dirname "$0")/../lib/common.sh"
require_env

MAP="${SIM_ROOT}/atomic/atomic-map.yaml"
risk_filter=""; det_filter=""; include_high=0; allow_unpinned=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --risk) risk_filter="$2"; shift 2;;
    --detection) det_filter="$2"; shift 2;;
    --include-high) include_high=1; shift;;
    --allow-unpinned) allow_unpinned=1; shift;;
    *) die "unknown arg: $1";;
  esac
done

if [[ "${ALLOW_ATOMIC_TESTS:-0}" != "1" ]]; then
  warn "Atomic Red Team runs real attack techniques on the victim hosts."
  warn "Re-run with ALLOW_ATOMIC_TESTS=1 once you've confirmed this is the throwaway lab."
  exit 0
fi
command -v python3 >/dev/null || die "python3 needed to parse the atomic map."

banner "Atomic Red Team run" "per atomic-map.yaml"
record_run "run-atomics"

# Emit selected tests as TSV: detection technique guid platform risk elevation cleanup name
mapfile -t rows < <(python3 - "$MAP" "$risk_filter" "$det_filter" "$include_high" "$allow_unpinned" <<'PY'
import sys, yaml
mapf, risk, det, inc_high, allow_unpinned = sys.argv[1:6]
doc = yaml.safe_load(open(mapf))
for t in doc.get("tests", []):
    if risk and t["risk"] != risk: continue
    if det and t["detection"] != det: continue
    if t["risk"] == "high" and inc_high != "1": continue
    if t["guid"] is None and allow_unpinned != "1": continue
    print("\t".join([t["detection"], t["technique"], str(t["guid"] or ""),
                     t["platform"], t["risk"], str(t["elevation_required"]),
                     str(t["cleanup"]), t["name"]]))
PY
)
[[ ${#rows[@]} -gt 0 ]] || { warn "no tests match the filters"; exit 0; }

run_windows_atomic() { # technique guid name
  local tech="$1" guid="$2" name="$3" sel
  if [[ -n "$guid" ]]; then sel="-TestGuids $guid"; else sel="-TestNumbers 1"; fi
  local ps="Import-Module Invoke-AtomicRedTeam -Force;
    Invoke-AtomicTest ${tech} ${sel} -GetPrereqs;
    Invoke-AtomicTest ${tech} ${sel};
    Start-Sleep 5;
    Invoke-AtomicTest ${tech} ${sel} -Cleanup;
    Write-Output 'atomic done: ${tech}'"
  az vm run-command invoke -g "$RG" -n "$WIN_VM" --command-id RunPowerShellScript \
    --scripts "$ps" --query "value[0].message" -o tsv
}

for row in "${rows[@]}"; do
  IFS=$'\t' read -r det tech guid platform risk _elev _cleanup name <<< "$row"
  log "[$det] $tech ($risk) - $name"
  if [[ "$platform" == "windows" ]]; then
    [[ -n "${WIN_VM}" ]] || { warn "  Windows VM not deployed - skip"; continue; }
    run_windows_atomic "$tech" "$guid" "$name" || warn "  atomic failed (continuing)"
  else
    warn "  $platform atomics run manually - see docs/atomic-red-team.md"
  fi
done

log "Done. Allow 10-20 min for ingestion, then verify which mapped detections fired:"
log "  ./simulate/verify.sh 1"
