# Install Invoke-AtomicRedTeam + the atomics on the Windows victim.
# Run via VM Run Command. Idempotent.
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
if (-not (Get-Module -ListAvailable Invoke-AtomicRedTeam)) {
  IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
  Install-AtomicRedTeam -getAtomics -Force
}
Import-Module Invoke-AtomicRedTeam -Force
Write-Output "Invoke-AtomicRedTeam ready; atomics at C:\AtomicRedTeam\atomics"
