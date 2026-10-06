#!/usr/bin/env bash
# AZ-ACT-005: list storage account keys as a user. Prints key NAMES only.
# shellcheck source=../lib/common.sh
source "$(dirname "$0")/../lib/common.sh"
require_env
banner "Storage key listing" "AZ-ACT-005"
record_run "az-act-005-storage-listkeys"

az storage account keys list -g "$RG" -n "$STORAGE_ACCOUNT" --query "[].keyName" -o tsv
