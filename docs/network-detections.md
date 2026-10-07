# Network layer: VNet flow logs + Traffic Analytics

Optional layer (`enable_flow_logs = true`) that captures every flow on the
victim virtual network, enriches it with Microsoft Traffic Analytics, and adds
five network detections driven from the `NTANetAnalytics` table.

## What it deploys

| Resource | Purpose |
|---|---|
| Network Watcher | Owns the flow log, in the lab RG so it's disposable |
| Flow-log storage account | Raw flow logs. Separate from the canary account so flow-log writes never pollute STG-001 telemetry |
| VNet flow log + Traffic Analytics | Captures all NICs on the VNet, enriches the flows, and writes `NTANetAnalytics` into the workspace |

VNet flow logs (not NSG flow logs - Microsoft retired those in June 2025) attach
to the virtual network, so every current and future NIC in it is covered without
per-NSG wiring.

## Detections

| ID | Detection | Sev | ATT&CK |
|---|---|---|---|
| NET-001 | Vertical port scan (one source, many ports on one host) | Medium | T1046 |
| NET-002 | Horizontal host sweep (one source, many hosts, few ports) | Medium | T1046, T1018 |
| NET-003 | East-west connection to management ports between internal hosts | High | T1021 |
| NET-004 | Traffic Analytics flagged a malicious flow (MS threat intel) | High | T1071 |
| NET-005 | Large outbound data transfer to an external IP | Medium | T1048.003 |

NET-003 is the highest-value rule here: in the lab the victim subnet has no
legitimate east-west admin traffic, so any allowed internal SSH/RDP/WinRM/SMB
flow is a strong lateral-movement signal. The management ports are configurable
via `internal_mgmt_ports`.

## Prerequisites and cost

* Network Watcher enabled in the region (Azure usually auto-enables it).
* Traffic Analytics has its own ingestion cost and a **processing interval of 10
  or 60 minutes** (`flow_log_interval_minutes`). 10 minutes gives the lowest
  detection latency; 60 is cheapest.
* End-to-end latency from an event to an alert is the Traffic Analytics interval
  plus the rule schedule, so **allow 30-75 minutes** before running `verify.sh`.
  This is inherent to flow logs, not a lab limitation.

## Simulations

`simulate/scenarios/net-sim-chain.sh` runs on the Linux victim via Run Command
and generates the flows the rules look for:

| Scenario step | Detection | What it does |
|---|---|---|
| Vertical scan of the gateway | NET-001 | 150 ports against `.1` |
| Host sweep | NET-002 | tcp/445 across `.4-.40` |
| East-west mgmt ports | NET-003 | SSH/RDP/SMB/WinRM against neighbours |
| Outbound transfer | NET-005 | ~120 MB download from a public endpoint |

All of it is connection attempts and one measured download against the lab's own
subnet and ordinary public endpoints - no exploitation.

**NET-004 is not auto-simulated.** The malicious-flow classification comes from
Microsoft's threat-intelligence enrichment and can't be triggered safely on
demand. Validate it against historical data, or generate a benign EICAR-style
test lookup and wait for enrichment. Never point a lab host at genuinely
malicious infrastructure.

## Tuning notes

* Thresholds (`distinct_port_threshold`, `distinct_host_threshold`, the 100 MB
  byte threshold) are lab values. In production, baseline per host and alert on
  deviation rather than absolute counts.
* Scanners, monitoring servers, backup jobs and domain controllers will trip
  NET-001/002/003. Allowlist their source IPs.
* Traffic Analytics aggregates by 4-tuple over the interval, so a scan appears as
  many rows sharing `SrcIp`+`DestIp`; the queries count distinct ports/hosts
  across those aggregated rows rather than individual packets.
