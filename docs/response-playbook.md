# Response playbook: auto-disable principal on a honeytoken hit

Optional layer (`enable_response_playbook = true`) that adds a Microsoft Sentinel
playbook (Logic App) and an automation rule. When **KV-001** (canary secret read)
or **STG-001** (canary blob read) raises an incident, the playbook pulls the
Account entity off the incident and - unless in dry-run - disables that Entra ID
user via Microsoft Graph, revokes its sessions, and comments on the incident.

Because KV-001 and STG-001 are honeytokens that nothing legitimate ever touches,
any hit is high-fidelity, which is what makes an automatic containment response
defensible here.

## What it deploys

| Resource | Purpose |
|---|---|
| Logic App (ARM) | The playbook: Sentinel incident trigger, entity extraction, Graph disable + session revoke, incident comment. System-assigned managed identity |
| `azuresentinel` API connection | Managed-identity connection the trigger and comment action use |
| Role assignment (workspace) | Playbook MI -> **Microsoft Sentinel Responder** (comment on / update incidents) |
| Role assignment (RG) | Sentinel service principal -> **Microsoft Sentinel Automation Contributor** (so the automation rule can run the playbook) |
| Graph app-role assignment | Playbook MI -> **User.ReadWrite.All** (only when enforcing + opted in) |
| Automation rule | Runs the playbook on KV-001 / STG-001 incident creation |

The playbook is deployed as an ARM template (the standard packaging for Sentinel
playbooks, because the `azuresentinel` managed connector is awkward in raw
Terraform). RBAC, the Graph grant and the automation rule stay in Terraform.

## Safety model: dry-run first

Disabling an account is destructive, so the layer is built to be rolled out in
stages:

| Setting | Behaviour |
|---|---|
| `playbook_dry_run = true` (default) | Playbook only comments *"DRY RUN: would disable principal X"*. Nothing is disabled. No Graph permission needed |
| `playbook_grant_graph = true` + `playbook_dry_run = false` | Playbook disables the user and revokes sessions for real |
| `playbook_auto_run = false` | Playbook is deployed but **not** wired to an automation rule - run it by hand from an incident while you build trust |

Recommended rollout: deploy in dry-run, trigger KV-001 with its simulation, read
the incident comment and confirm it identified the right principal, then grant
Graph and flip `playbook_dry_run = false`.

## Prerequisites

* `enable_entra_id = true` is what gives you a disablable Entra ID user and the
  Account entity on the incident; without it the playbook has nothing to act on
  and will comment that no Account entity was found.
* To **assign** the Graph app role (`playbook_grant_graph`), the identity running
  `terraform apply` needs Privileged Role Administrator or Global Administrator.
* The automation rule needs Sentinel's service principal ("Azure Security
  Insights") to exist in the tenant (it does once Sentinel is onboarded).

## How the playbook finds the principal

The Sentinel incident carries the detection's mapped entities. KV-001 and STG-001
map an Account entity (`CallerUpn` / `aadUserId` / object id). The playbook loops
the related entities, takes the first Account, and resolves a UPN and an AAD user
id from it. It then calls:

* `PATCH /users/{id}` with `{ "accountEnabled": false }`
* `POST /users/{id}/revokeSignInSessions`

both authenticated with the Logic App's managed identity (no stored secret).

## Known limitations / tuning

* **Not tested against a live tenant.** The ARM template and Logic App definition
  are validated as JSON and the Terraform plans and tests pass, but the workflow
  logic has not been run end-to-end in Azure. Deploy in dry-run and confirm the
  entity extraction against a real incident before enforcing - the exact
  `relatedEntities` shape can vary, and the `coalesce()` expressions may need a
  tweak. This is the same "parse real events first" caveat as the Entra/Sysmon
  layers.
* **Service principals / managed identities.** If the honeytoken was read by a
  service principal rather than a user (e.g. a compromised app identity), the
  `PATCH /users/...` call won't match. Extend the playbook with a
  `GET /servicePrincipals` branch to disable an SP. Left as an exercise.
* **Blast radius.** An attacker who knows the canary exists could read it *as* a
  legitimate admin's identity to get that admin disabled (a denial-of-service via
  your own SOAR). Dry-run plus analyst review is the mitigation; think carefully
  before enabling fully automatic disable in production.
* **Idempotency.** Re-disabling an already-disabled user is harmless; the comment
  still posts.
