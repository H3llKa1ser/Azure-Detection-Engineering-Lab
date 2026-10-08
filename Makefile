TF := terraform -chdir=terraform

.PHONY: help init plan apply destroy lint test kql catalog simulate verify ci

help: ## Show targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

init: ## terraform init
	$(TF) init

plan: ## terraform plan
	$(TF) plan -out=tfplan

apply: ## terraform apply (uses saved plan if present)
	@if [ -f terraform/tfplan ]; then $(TF) apply tfplan; else $(TF) apply; fi

destroy: ## Tear the whole lab down
	$(TF) destroy

lint: ## Detection lint + KQL analysis + terraform fmt/validate + tflint + shellcheck
	python3 scripts/validate_detections.py --check-catalog
	@for f in terraform/playbooks/*.json; do python3 -c "import json; json.load(open('$$f'))" && echo "ok $$f"; done
	cd scripts/kql && ([ -d node_modules ] || npm ci --silent) && node check.js
	$(TF) fmt -check -recursive
	$(TF) validate
	cd terraform && tflint --format compact
	shellcheck simulate/*.sh simulate/lib/*.sh simulate/scenarios/*.sh simulate/payloads/*.sh terraform/scripts/*.sh

test: ## Offline terraform tests (mocked providers, no Azure creds)
	$(TF) test

kql: ## KQL analysis only
	cd scripts/kql && ([ -d node_modules ] || npm ci --silent) && node check.js

catalog: ## Regenerate docs/detection-catalog.md
	python3 scripts/validate_detections.py --catalog

simulate: ## Run every attack simulation against the deployed lab
	./simulate/run-all.sh

verify: ## Check which detections fired in the last 2h
	./simulate/verify.sh 2

ci: lint test ## Everything CI runs, locally
