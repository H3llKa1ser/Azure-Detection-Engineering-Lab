#!/usr/bin/env bash
# Seeds honeytokens out-of-band so Terraform never reads (and trips) them.
# Invoked by terraform_data.seed_honeytokens; all inputs come from env vars.
set -euo pipefail

rand() { openssl rand -base64 30 | tr -dc 'A-Za-z0-9' | head -c 32; }

echo "[seed] canary secret ${CANARY_SECRET} -> ${KV_NAME}"
az keyvault secret set \
  --vault-name "${KV_NAME}" \
  --name "${CANARY_SECRET}" \
  --value "$(rand)" \
  --content-type "password" \
  --description "SQL backup service account - prod" \
  --output none

for s in ${DECOY_SECRETS}; do
  echo "[seed] decoy secret ${s}"
  az keyvault secret set --vault-name "${KV_NAME}" --name "${s}" \
    --value "$(rand)" --content-type "password" --output none
done

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
cat > "$tmp" <<CSV
employee_id,name,iban,gross_salary_eur
E0001,Jane Doe,MT00CANARY0000000000000000000,0
CSV

echo "[seed] canary blob ${CANARY_CONTAINER}/${CANARY_BLOB}"
az storage blob upload \
  --auth-mode login \
  --account-name "${STORAGE_ACCOUNT}" \
  --container-name "${CANARY_CONTAINER}" \
  --name "${CANARY_BLOB}" \
  --file "$tmp" \
  --content-type "text/csv" \
  --overwrite \
  --output none

echo "[seed] done"
