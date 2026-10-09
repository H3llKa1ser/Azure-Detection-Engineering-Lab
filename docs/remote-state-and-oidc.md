# Remote state + GitHub Actions OIDC deployment

Moves Terraform state into Azure Storage and lets GitHub Actions deploy the lab
with **no stored credentials**, using OpenID Connect workload identity
federation: GitHub issues a short-lived token per job, Entra ID exchanges it for
an Azure token, and there is no client secret anywhere to leak or rotate.

Both are opt-in. `make init` + local state keeps working exactly as before.

## Pieces

| File | Purpose |
|---|---|
| `terraform/bootstrap/` | One-time root module: state storage account + container, Entra app + service principal, three federated credentials, least-privilege RBAC |
| `.github/workflows/deploy.yml` | PR -> plan; manual dispatch -> plan / apply / destroy (apply/destroy gated by the `lab` environment) |
| `.github/scripts/wire-backend.sh` | CI helper: generates the backend wiring from repo variables |
| `terraform/backend.hcl.example` | Template for using the same remote state from your machine |

## Why bootstrap is separate

The backend can't create the storage it lives in. `terraform/bootstrap` keeps its
own **local** state (it contains no secrets - OIDC has none) and creates the
storage the lab's state then moves into.

## Setup

```bash
# 1. one-time bootstrap (as an Owner of the subscription + an Entra admin)
cp terraform/bootstrap/terraform.tfvars.example terraform/bootstrap/terraform.tfvars
make bootstrap                     # prints the gh variable commands

# 2. paste the printed `gh variable set ...` commands, then set your IP:
gh variable set OPERATOR_ALLOWED_IPS --body '["<your-public-ip>"]'

# 3. in GitHub: Settings -> Environments -> New "lab" -> add yourself as a
#    required reviewer. apply/destroy will now wait for your approval.

# 4. (optional) move your existing local state into the remote backend
terraform -chdir=terraform/bootstrap output -raw backend_hcl > terraform/backend.hcl
make init-remote                   # answers "yes" to migrate local -> remote
```

Then deploy from **Actions -> deploy -> Run workflow -> apply**.

### Repo variables

| Variable | Set by | Notes |
|---|---|---|
| `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID` | bootstrap output | Identifiers, not secrets - they're useless without a GitHub-issued token for this repo |
| `TFSTATE_RESOURCE_GROUP`, `TFSTATE_STORAGE_ACCOUNT`, `TFSTATE_CONTAINER` | bootstrap output | Backend location |
| `OPERATOR_ALLOWED_IPS` | you | JSON list. Keeps your IP through the Key Vault / Storage firewalls, since the runner's IP changes every run |
| `LAB_TFVARS` | you (optional) | HCL body written to `ci.auto.tfvars`, e.g. `enable_sysmon = true` |

Until `AZURE_CLIENT_ID` is set, every deploy job is skipped, so the repo and its
CI stay green before Azure is wired up.

## Security design

**Three exact-match federated subjects, one per trust level:**

| Subject | Who gets it | Can |
|---|---|---|
| `repo:<owner>/<repo>:pull_request` | PR runs from this repo | plan |
| `repo:<owner>/<repo>:ref:refs/heads/main` | dispatch from `main` | plan |
| `repo:<owner>/<repo>:environment:lab` | jobs in the `lab` environment | apply / destroy |

Azure trusts the token only if the subject matches exactly, so a PR can never
produce an apply-capable token, and apply/destroy additionally wait for an
environment reviewer. Pull requests from forks get no OIDC token at all and are
skipped explicitly.

**No Owner, no User Access Administrator.** The pipeline gets:

* **Contributor** on the subscription - create and destroy the lab, including the
  subscription Activity Log diagnostic setting.
* **Role Based Access Control Administrator, constrained by an ABAC condition** -
  it can create and delete role assignments **only** for the four roles the lab
  itself hands out (Key Vault Secrets Officer, Storage Blob Data Contributor,
  Microsoft Sentinel Responder, Microsoft Sentinel Automation Contributor). It
  cannot grant Owner, Contributor or anything else, to itself or anyone. The
  role GUIDs are resolved by name at bootstrap time, not hard-coded.
* **Storage Blob Data Contributor** on the state account only.

**State storage:** shared keys disabled (Entra ID auth only), blob versioning
(every state write is recoverable), change feed, 30-day soft delete for blobs and
containers, TLS 1.2, infrastructure encryption. Locking uses the azurerm
backend's native blob lease; the workflow also serialises runs with a
`concurrency` group.

Lab state does contain sensitive values (the generated Windows admin password and
Linux SSH key), which is exactly why the state account allows no shared-key
access and only these two identities hold data-plane access.

## What CI deploys - and what it doesn't

The pipeline deploys the core lab and the optional **network** and **Sysmon**
layers (via `LAB_TFVARS`). Two layers need tenant-level Entra rights that a
subscription-scoped pipeline deliberately does not have:

* **Entra ID layer** (`enable_entra_id`) creates users and app registrations.
* **Response playbook Graph grant** (`playbook_grant_graph`) assigns a Graph app
  role.

Apply those from your own admin session with `make init-remote && make apply`
against the same remote state. Granting the pipeline `User.ReadWrite.All` /
`Application.ReadWrite.All` would make it a tenant-takeover path, so it's left out
on purpose.

Simulations still run from your machine (`make simulate`) - they need your IP on
the firewall allowlist and are interactive by design.

## Accepted findings

* **checkov `CKV_GHA_7`** (workflow_dispatch inputs should be empty): a SLSA build
  provenance rule for build workflows. This is a deployment workflow; its only
  input is a fixed `plan | apply | destroy` choice used in job `if:` conditions
  and never interpolated into a shell command, so it can't inject anything.
* **State account public endpoint** (`CKV_AZURE_59` etc.): GitHub-hosted runner
  IPs aren't fixed, so the account can't be IP-restricted. Access is Entra-only
  with shared keys off. Use self-hosted runners + a private endpoint if you need
  network isolation.

## Not tested live

Bootstrap, the workflow and the wiring are validated offline - bootstrap has its
own `terraform test` suite (hardening, exact OIDC subjects, the ABAC-constrained
RBAC), the workflows pass actionlint, and the wiring script was exercised in a
simulated runner. None of it has run against a real tenant in this build. The
step most likely to need attention is the first `apply`: if the ABAC condition
rejects an assignment, the error names the role, and the fix is adding it to
`delegable_roles` in `bootstrap/main.tf`.
