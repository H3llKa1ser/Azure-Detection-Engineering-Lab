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

# --- Entra ID helpers -------------------------------------------------------

require_entra() {
  [[ "${ENTRA_ENABLED:-false}" == "true" ]] || { warn "Entra ID layer not deployed (enable_entra_id = false) - skipping"; exit 0; }
}

# ENT-003..006 make real (temporary, self-reverting) changes to the TENANT.
# They only run when explicitly allowed.
require_tenant_changes() {
  if [[ "${ALLOW_TENANT_CHANGES:-0}" != "1" ]]; then
    warn "This scenario temporarily changes Entra ID tenant objects."
    warn "Re-run with ALLOW_TENANT_CHANGES=1 to proceed."
    exit 0
  fi
}

# One ROPC sign-in attempt with a random wrong password. Returns the AADSTS
# code. Uses the Azure CLI public client ID, so no app registration is needed.
# The password is random and never valid; nothing is ever authenticated.
ropc_attempt() {
  local upn="$1" body
  body="$(curl -s -X POST "https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token" \
    --data-urlencode "client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46" \
    --data-urlencode "scope=openid" \
    --data-urlencode "grant_type=password" \
    --data-urlencode "username=${upn}" \
    --data-urlencode "password=Wr0ng-$(openssl rand -hex 8)!")"
  grep -o 'AADSTS[0-9]*' <<< "$body" | head -1
}

# Graph call via the CLI token, with a readable error when the CLI's
# delegated permissions are not enough for the operation.
graph() {
  local method="$1" url="$2" body="${3:-}"
  local args=(--method "$method" --url "https://graph.microsoft.com/v1.0${url}" --headers "Content-Type=application/json")
  [[ -n "$body" ]] && args+=(--body "$body")
  if ! az rest "${args[@]}" "${@:4}"; then
    warn "Graph ${method} ${url} failed."
    warn "If this is a 403, the Azure CLI token lacks the Graph scope for this operation in your tenant,"
    warn "or your account lacks the Entra role. Perform the same change manually in the Entra admin"
    warn "center - it produces identical AuditLogs events - or see docs/entra-id.md."
    return 1
  fi
}
