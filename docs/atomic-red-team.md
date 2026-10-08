# Atomic Red Team integration

Broadens technique coverage by running [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
(ART) tests on the victim hosts, instead of relying only on the lab's bespoke
simulation scripts. A coverage map ties each atomic to the detection it should
trigger, so a run is a purple-team exercise: fire the technique, confirm the
rule alerts.

## Pieces

| File | Purpose |
|---|---|
| `simulate/atomic/atomic-map.yaml` | The map: detection -> ATT&CK technique -> ART test (pinned by `auto_generated_guid`), with platform, risk tier and whether the test cleans up |
| `scripts/validate_atomics.py` | Cross-checks the map against the detections and reports coverage. Runs in CI - no Azure needed |
| `simulate/atomic/install-atomics.sh` | Installs `Invoke-AtomicRedTeam` + atomics on the Windows victim via Run Command |
| `simulate/atomic/run-atomics.sh` | Runs mapped atomics (GetPrereqs -> test -> Cleanup) on the victim, filtered by risk/detection |

## Why a map instead of "run everything"

ART has thousands of tests; running them blind is noisy and some are
destructive. The map is a curated, reviewed subset where every entry is tied to
a detection this lab actually has, so a green run means *your* rules fired - not
that something, somewhere, logged. `validate_atomics.py` enforces that link: it
fails if a map entry names a detection that doesn't exist, or a technique the
detection doesn't declare, and it prints which endpoint detections still have no
atomic.

## GUID pinning

Entries are pinned by `auto_generated_guid`, which is stable across ART
releases - test *numbers* are not, so the map never pins by number. Entries
whose GUID this lab hasn't verified are left `guid: null` on purpose; the runner
refuses them unless you pass `--allow-unpinned` (and then runs the technique's
default test). To pin one yourself:

```powershell
Invoke-AtomicTest T1070.001 -ShowDetailsBrief   # lists tests + GUIDs
```

then paste the GUID into the map and re-run `make atomics`.

## Running it

```bash
# one-time install on the Windows victim
./simulate/atomic/install-atomics.sh

# ART runs REAL techniques - opt in explicitly, lab only
ALLOW_ATOMIC_TESTS=1 ./simulate/atomic/run-atomics.sh --risk safe
ALLOW_ATOMIC_TESTS=1 ./simulate/atomic/run-atomics.sh                 # safe + moderate
ALLOW_ATOMIC_TESTS=1 ./simulate/atomic/run-atomics.sh --include-high  # + lsass/injection

# then, after ingestion
./simulate/verify.sh 1
```

Each test runs `-GetPrereqs`, the test, then `-Cleanup`. The runner won't do
anything unless `ALLOW_ATOMIC_TESTS=1` is set.

## Risk tiers

| Tier | Meaning | Default |
|---|---|---|
| `safe` | Benign, self-cleaning, no lasting change (e.g. Reg Key Run) | runs |
| `moderate` | Real attacker behaviour, reverts via `-Cleanup` | runs |
| `high` | Touches lsass, injection, or clears logs; may not fully clean up | only with `--include-high` |

## Linux atomics

`Invoke-AtomicTest` needs PowerShell. The Windows victim has it; for the Ubuntu
victim, install PowerShell and the module first:

```bash
# on the Linux victim (via Run Command)
sudo snap install powershell --classic
pwsh -c "IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing); Install-AtomicRedTeam -getAtomics -Force"
```

The map's `linux` entries (LNX-001, LNX-002) then run the same way. The lab's
own `lnx-sim-chain.sh` already covers these, so Linux ART is optional.

## Limitations

* **Not run end-to-end here.** The map, the validator and the runner logic are
  validated offline (GUIDs for the pinned T1547.001 tests were checked against
  the public repo), but the atomics have not been executed against a live VM in
  this build. Install, run `--risk safe` first, confirm cleanup, then widen.
* **Egress.** Installing ART downloads from GitHub; the victim subnet needs
  outbound access (`use_nat_gateway = true` if default egress is unavailable).
* **high-risk cleanup.** Some high-risk atomics (log clearing, injection) don't
  fully revert. That's why they're opt-in and lab-only - never point this at
  anything you care about.
* **Coverage is endpoint-focused.** ART is mainly host techniques, so it
  broadens SYS/WIN/LNX coverage. The cloud detections (AZ-ACT, KV, STG, ENT,
  NET) are exercised by the native simulations instead.
