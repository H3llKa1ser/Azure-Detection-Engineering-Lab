# Windows attack chain, executed via VM Run Command (SYSTEM).
# Generates: 4720 -> 4625 x12 -> 4624 -> 4732 -> 1102 -> 4726
$ErrorActionPreference = 'Continue'
$user = 'simuser'
$chars = [char[]]((48..57) + (65..90) + (97..122))
$pw = (-join (1..20 | ForEach-Object { $chars | Get-Random })) + '!aA1'

# Make the chain deterministic regardless of lockout policy; restored at the end.
$lockout = ((net accounts | Select-String 'Lockout threshold').ToString().Split(':')[1]).Trim()
net accounts /lockoutthreshold:0 | Out-Null

net user $user $pw /add /comment:"detection-lab simulation" | Out-Null          # 4720
Write-Output "created $user"

1..12 | ForEach-Object {                                                        # 4625 x12
    net use \\127.0.0.1\IPC$ /user:"$env:COMPUTERNAME\$user" 'Wr0ngPassword!' 2>$null | Out-Null
    net use \\127.0.0.1\IPC$ /delete /y 2>$null | Out-Null
}
Write-Output "12 failed logons"

net use \\127.0.0.1\IPC$ /user:"$env:COMPUTERNAME\$user" $pw | Out-Null         # 4624 (type 3)
net use \\127.0.0.1\IPC$ /delete /y | Out-Null
Write-Output "successful logon"

net localgroup Administrators $user /add | Out-Null                             # 4732
Write-Output "added $user to Administrators"

# Give the Azure Monitor Agent time to ship the events above before clearing.
Start-Sleep -Seconds 90
wevtutil cl Security                                                            # 1102
Write-Output "security log cleared"

net user $user /delete | Out-Null                                               # 4726
if ($lockout -match '^\d+$') { net accounts /lockoutthreshold:$lockout | Out-Null } else { net accounts /lockoutthreshold:0 | Out-Null }
Write-Output "cleanup done"
