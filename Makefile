TF := terraform -chdir=terraform

.PHONY: help init init-remote bootstrap plan apply destroy lint test kql catalog simulate verify ci atomics

help: ## Show targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

init: ## terraform init
	$(TF) init

init-remote: ## terraform init against the remote azurerm backend (needs terraform/backend.hcl)
	@test -f terraform/backend.hcl || (echo "terraform/backend.hcl missing - see terraform/backend.hcl.example" && exit 1)
	@printf 'terraform {\n  backend "azurerm" {}\n}\n' > terraform/backend_remote.tf
	$(TF) init -backend-config=backend.hcl -migrate-state

bootstrap: ## One-time: create remote state storage + GitHub OIDC identity
	terraform -chdir=terraform/bootstrap init
	terraform -chdir=terraform/bootstrap apply
	@echo; echo "Next: set the GitHub repo variables:"; terraform -chdir=terraform/bootstrap output -raw gh_variable_commands

plan: ## terraform plan
	$(TF) plan -out=tfplan

apply: ## terraform apply (uses saved plan if present)
	@if [ -f terraform/tfplan ]; then $(TF) apply tfplan; else $(TF) apply; fi

destroy: ## Tear the whole lab down
	$(TF) destroy

lint: ## Detection lint + KQL analysis + terraform fmt/validate + tflint + shellcheck
	python3 scripts/validate_detections.py --check-catalog
	python3 scripts/validate_atomics.py
	@for f in terraform/playbooks/*.json; do python3 -c "import json; json.load(open('$$f'))" && echo "ok $$f"; done
	cd scripts/kql && ([ -d node_modules ] || npm ci --silent) && node check.js
	$(TF) fmt -check -recursive
	$(TF) validate
	terraform -chdir=terraform/bootstrap init -backend=false -input=false >/dev/null
	terraform -chdir=terraform/bootstrap validate
	cd terraform && tflint --format compact
	cd terraform/bootstrap && tflint --config ../.tflint.hcl --format compact
	shellcheck simulate/*.sh simulate/lib/*.sh simulate/scenarios/*.sh simulate/payloads/*.sh simulate/atomic/*.sh terraform/scripts/*.sh .github/scripts/*.sh

test: ## Offline terraform tests (mocked providers, no Azure creds)
	$(TF) test
	terraform -chdir=terraform/bootstrap init -backend=false -input=false >/dev/null
	terraform -chdir=terraform/bootstrap test

atomics: ## Validate the Atomic Red Team coverage map
	python3 scripts/validate_atomics.py

kql: ## KQL analysis only
	cd scripts/kql && ([ -d node_modules ] || npm ci --silent) && node check.js

catalog: ## Regenerate docs/detection-catalog.md
	python3 scripts/validate_detections.py --catalog

simulate: ## Run every attack simulation against the deployed lab
	./simulate/run-all.sh

verify: ## Check which detections fired in the last 2h
	./simulate/verify.sh 2

ci: lint test ## Everything CI runs, locally
