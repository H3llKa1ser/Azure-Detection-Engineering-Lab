#!/usr/bin/env bash
# Shared helpers for simulation scenarios.
set -euo pipefail

SIM_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${SIM_ROOT}/lab.env"

export AZURE_EXTENSION_USE_DYNAMIC_INSTALL="yes_without_prompt"

log()  { printf '\033[1;34m[%s]\033[0m %s\n' "$(date -u +%H:%M:%SZ)" "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[fail]\033[0m %s\n' "$*" >&2; exit 1; }

require_env() {
  [[ -f "$ENV_FILE" ]] || die "lab.env not found - run 'terraform apply' first (it generates simulate/lab.env)."
  # shellcheck source=/dev/null
  source "$ENV_FILE"
  command -v az >/dev/null || die "Azure CLI (az) not installed."
  az account show >/dev/null 2>&1 || die "Not logged in - run 'az login'."
  az account set --subscription "$SUBSCRIPTION_ID"
}

# Every scenario records itself so incidents can be matched to runs during triage.
record_run() {
  local scenario="$1"
  mkdir -p "${SIM_ROOT}/runs"
  printf '%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$scenario" "$(az account show --query user.name -o tsv)" \
    >> "${SIM_ROOT}/runs/history.tsv"
}

banner() {
  log "=== $1 ==="
  log "expected detection(s): $2"
}
