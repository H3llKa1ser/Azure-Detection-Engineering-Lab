# Entra ID identity layer

Optional layer (`enable_entra_id = true`) that streams Entra ID logs into the
lab workspace and adds seven identity detections, canary accounts and safe
simulation targets.

## What it deploys

| Resource | Purpose |
|---|---|
| Tenant diagnostic setting | `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AADServicePrincipalSignInLogs`, `AADManagedIdentitySignInLogs`, `AuditLogs`. With `entra_id_p2 = true`, also `AADRiskyUsers`, `AADUserRiskEvents` and the service-principal risk tables |
| 5 canary accounts | **Disabled** users with tempting names (`it-breakglass-legacy`, `svc-sql-backup`, ...). Any sign-in attempt is an incident |
| `LabCanaryAccounts` watchlist | The canary UPNs, managed by Terraform. ENT-002 reads it, so analysts can see exactly which accounts are honeytokens |
| Simulation app + service principal | Target for the credential-add (ENT-003) and permission-grant (ENT-006) scenarios. Has no credentials of its own |
| Disabled simulation-target user | Target for the role-assignment (ENT-004) and Conditional Access (ENT-005) scenarios |

## Detections

| ID | Detection | Sev | ATT&CK | Licence |
|---|---|---|---|---|
| ENT-001 | Password spray from a single IP (High if any sprayed account then signed in) | Medium/High | T1110.003 | P1 |
| ENT-002 | Sign-in attempt against a honeytoken account | High | T1078.004 | P1 |
| ENT-003 | Credential added to app / service principal | Medium | T1098.001 | P1 |
| ENT-004 | Privileged directory role assigned (incl. PIM) | High | T1098.003 | P1 |
| ENT-005 | Conditional Access policy created/updated/deleted (High on delete or disable) | Low-High | T1556.009 | P1 |
| ENT-006 | High-risk Graph permission granted to an app | High | T1528, T1098.003 | P1 |
| ENT-007 | Identity Protection medium/high risk | Medium/High | T1078.004 | **P2** |

ENT-001, ENT-004, ENT-005 and ENT-007 use `alert_details_override` to build the
alert name and/or severity from the query results, so a CA policy *deletion*
and a CA policy *creation* come from one rule but don't page with the same
urgency.

## Prerequisites

* **Licence:** Entra ID P1 for sign-in logs in Log Analytics; P2 for ENT-007.
  A free P2 trial on a dev/test tenant is the easiest route.
* **Use a dev/test tenant.** These resources are tenant-wide, not scoped to the
  lab resource group, and the simulations change real tenant objects.
* **Roles for `terraform apply`:** Security Administrator or Global
  Administrator (tenant diagnostic setting), User Administrator (canary users),
  Application Developer or higher (simulation app).
* **Roles for the tenant-change simulations:** Privileged Role Administrator
  (ENT-004, ENT-006) and Conditional Access Administrator (ENT-005). In a
  dev tenant, Global Administrator covers all of them.

## Simulation safety tiers

| Tier | Scenarios | What changes | How to run |
|---|---|---|---|
| Sign-in only | ENT-001, ENT-002 | Nothing. Wrong-password attempts against disabled accounts | `make simulate` |
| Temporary tenant change | ENT-003, ENT-004, ENT-005, ENT-006 | A secret, role, CA policy or app-permission grant that is created and removed within ~30 s, always against lab-owned, disabled or credential-less objects | `ALLOW_TENANT_CHANGES=1 make simulate` |
| Manual | ENT-007 | Microsoft's own risk detection; cannot be faked via API | Follow the script's instructions |

Specific safety choices:

* The password spray uses random, never-valid passwords against **disabled**
  accounts, so nothing can authenticate even by accident.
* The Conditional Access policy is created in `disabled` state, targets only the
  disabled simulation user, and includes no applications.
* The Mail.Read grant goes to an app with no credentials, so it is unusable
  for the 30 s it exists.
* The privileged role goes to a disabled user.

## Known limitations and tuning notes

* **CLI token scopes.** The tenant-change scenarios call Microsoft Graph with the
  Azure CLI's token. Depending on tenant configuration, the CLI's delegated
  permissions may not cover role management or Conditional Access writes. The
  scripts detect a 403 and tell you; doing the same change by hand in the Entra
  admin center produces identical `AuditLogs` events.
* **Latency.** Sign-in logs typically take 5-15 minutes to arrive, audit logs a
  few minutes; run `verify.sh` after ~30 minutes.
* **ROPC.** The spray uses the OAuth2 resource-owner password flow with the Azure
  CLI's public client ID. If your tenant blocks it upstream, use a different
  client or sign in manually with wrong passwords.
* **AuditLogs shapes vary.** `TargetResources` / `modifiedProperties` layouts differ
  between operations (PIM vs direct role assignment, delegated vs application
  consent). The queries were written against Microsoft's documented schemas and
  checked with the Kusto analyzer, but parse real events from your tenant in the
  Logs blade and adjust the extraction if a field comes back empty.
* **Canary realism.** Disabled accounts tell a careful attacker "this is dead" via
  error 50057. A more convincing canary is an *enabled* account blocked by a
  Conditional Access policy; that's left as an exercise because a mistake there
  creates a real, usable account.
