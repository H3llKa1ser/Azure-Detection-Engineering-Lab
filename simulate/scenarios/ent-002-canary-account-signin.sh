#!/usr/bin/env bash
# ENT-002: a single sign-in attempt against one canary account. A single
# attempt must be enough - that's the point of a honeytoken.
# shellcheck source=../lib/common.sh
source "$(dirname "$0")/../lib/common.sh"
require_env
require_entra
banner "Single canary account sign-in attempt" "ENT-002"
record_run "ent-002-canary-account-signin"

read -r -a upns <<< "$CANARY_UPNS"
code="$(ropc_attempt "${upns[0]}")"
log "${upns[0]} -> ${code:-no AADSTS code} (50057 = disabled, 50126 = bad password: both are expected)"
