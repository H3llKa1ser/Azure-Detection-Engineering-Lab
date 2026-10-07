# Sysmon telemetry generator, run on the Windows victim via VM Run Command.
# Produces benign-but-suspicious-looking activity for SYS-001..006. Nothing
# here exfiltrates data, dumps credentials, or persists beyond cleanup.
$ErrorActionPreference = "Continue"

Write-Output "== SYS-001: LOLBin process creation =="
# certutil decode of an inline base64 blob (no network, no real payload).
$b64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("detection-lab benign canary"))
$tmp = "C:\Windows\Temp\detlab.b64"; $out = "C:\Windows\Temp\detlab.out"
$b64 | Out-File -Encoding ASCII $tmp
certutil.exe -decode $tmp $out | Out-Null
# encoded PowerShell that just prints a string.
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Output 'detlab-encoded'"))
powershell.exe -EncodedCommand $enc | Out-Null
Remove-Item $tmp,$out -ErrorAction SilentlyContinue

Write-Output "== SYS-003: LOLBin network connection =="
# PowerShell makes a benign outbound connection (EID 3 from powershell.exe).
try { Invoke-WebRequest -Uri "https://www.msftconnecttest.com/connecttest.txt" -UseBasicParsing -TimeoutSec 10 | Out-Null } catch {}

Write-Output "== SYS-004: Run-key persistence (added then removed) =="
$runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
New-ItemProperty -Path $runKey -Name "DetLabCanary" -Value "C:\Windows\Temp\detlab.exe" -PropertyType String -Force | Out-Null
Start-Sleep -Seconds 3
Remove-ItemProperty -Path $runKey -Name "DetLabCanary" -ErrorAction SilentlyContinue

Write-Output "== SYS-002: LSASS handle open (benign, read-only, closed immediately) =="
# Opens a handle to lsass with PROCESS_QUERY_INFORMATION|PROCESS_VM_READ (0x1410)
# to generate Sysmon EID 10, then closes it. No memory is read or dumped.
Add-Type -Namespace DetLab -Name N -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true)]
public static extern System.IntPtr OpenProcess(int dwDesiredAccess, bool b, int dwProcessId);
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true)]
public static extern bool CloseHandle(System.IntPtr h);
'@
$lsass = Get-Process lsass -ErrorAction SilentlyContinue
if ($lsass) {
  $h = [DetLab.N]::OpenProcess(0x1410, $false, $lsass.Id)
  if ($h -ne [IntPtr]::Zero) { [DetLab.N]::CloseHandle($h) | Out-Null; Write-Output "  opened+closed lsass handle" }
}

Write-Output "== SYS-006: Sysmon config change =="
# Re-apply the current config (benign) to emit EID 16.
$sysmon = Get-ChildItem "C:\Windows\Temp\sysmon\Sysmon64.exe","C:\Windows\Sysmon64.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
$cfg = "C:\Windows\Temp\sysmon\sysmon-config.xml"
if ($sysmon -and (Test-Path $cfg)) { & $sysmon.FullName -c $cfg | Out-Null; Write-Output "  reapplied sysmon config" }
else { Write-Output "  sysmon binary/config not found - skipping EID 16" }

Write-Output "NOTE: SYS-005 (remote-thread injection) is not simulated here - doing it safely"
Write-Output "requires an injection test tool. Validate SYS-005 with an Atomic Red Team test"
Write-Output "(T1055.002) in an isolated environment, or against historical data."
Write-Output "sysmon chain done"
