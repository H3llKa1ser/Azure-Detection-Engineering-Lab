# Sysmon on the Windows host

Optional layer (`enable_sysmon = true`, needs `deploy_windows_vm = true`) that
installs Sysmon on the Windows victim, collects its operational channel into the
`Event` table, and adds six endpoint detections.

## What it deploys

| Resource | Purpose |
|---|---|
| `install-sysmon` Run Command | Downloads Sysmon from Sysinternals and installs it with a compact lab config (or a config URL you supply) |
| Sysmon DCR | Collects `Microsoft-Windows-Sysmon/Operational` (EIDs 1, 3, 7, 8, 10, 11, 12, 13, 16, 22, 255) into the `Event` table via the `Microsoft-Event` stream |

Sysmon events land in the **`Event`** table, not `SecurityEvent`. Each event's
fields live in the `EventData` XML; the detections pull them out with
`extract(@'Name="Field">([^<]+)', 1, EventData)`.

## Detections

| ID | Detection | Sev | ATT&CK | Sysmon EID |
|---|---|---|---|---|
| SYS-001 | Suspicious LOLBin process creation | High | T1218, T1059.001 | 1 |
| SYS-002 | LSASS access with dump rights | High | T1003.001 | 10 |
| SYS-003 | Network connection from a LOLBin / interpreter | Medium | T1105 | 3 |
| SYS-004 | Registry Run-key persistence | Medium | T1547.001 | 12/13 |
| SYS-005 | Remote thread created in another process | High | T1055.002 | 8 |
| SYS-006 | Sysmon config change / service tampering | High | T1562.001 | 16, 1 |

SYS-002 is the flagship: an access mask on lsass that includes `PROCESS_VM_READ`
is the core credential-dumping signal, and the rule excludes the signed OS/AV
processes that touch lsass normally.

## The config

The built-in config is deliberately compact - it logs only the event types the
rules use, which keeps `Event`-table ingestion cheap. It is not a replacement for
a production baseline. For fuller coverage, set `sysmon_config_url` to a
maintained config (SwiftOnSecurity, or Olaf Hartong's modular config) and the
Run Command will use it instead. The collected EID set is fixed in the DCR
(`sysmon_event_ids` in `sysmon.tf`); widen it there if your config logs more.

## Simulations

`simulate/scenarios/win-sysmon-chain.sh` runs on the Windows victim via Run
Command and generates:

| Step | Detection | What it does |
|---|---|---|
| certutil decode + encoded PowerShell | SYS-001 | LOLBin execution, no payload |
| PowerShell web request | SYS-003 | benign outbound connection |
| Run-key add + remove | SYS-004 | persistence value written then deleted |
| Open+close lsass handle | SYS-002 | `OpenProcess(0x1410)` then `CloseHandle` - no memory is read |
| Re-apply Sysmon config | SYS-006 | emits EID 16 |

The LSASS step only opens a handle with read rights and closes it immediately;
it never reads or dumps memory. **SYS-005 (remote-thread injection) is not
auto-simulated** - doing it safely needs an injection test harness. Validate it
with an Atomic Red Team test for T1055.002 in an isolated environment, or against
historical data.

## Known limitations

* **EventData parsing.** The detections extract fields from the raw `EventData`
  XML. AMA emits the standard `<Data Name="...">value</Data>` layout, which the
  queries were written and KQL-analyzed against, but if a field comes back empty
  in your workspace, check one raw event in the Logs blade and adjust the
  extract pattern. Same caveat as the Entra `AuditLogs` parsing.
* **Install needs egress.** The Run Command downloads Sysmon from
  `download.sysinternals.com`. If the victim subnet has no outbound access, set
  `use_nat_gateway = true` or host Sysmon internally and adjust the script.
* **GrantedAccess masks vary.** SYS-002 lists the common dump masks. Tools using
  other masks that still include `VM_READ` may need adding; review real EID 10
  events to tune.
