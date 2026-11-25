#requires -Version 5.1
<#
.SYNOPSIS
  Read-only, local Windows exposure review. No elevation or configuration changes.
.DESCRIPTION
  Prints limited risk indicators only; never reads keys, passwords, files, browser data
  or full IP/account lists. Findings are leads for review, not proof of compromise.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'This script is for Windows only.' }

$script:Results = [System.Collections.Generic.List[object]]::new()
function Add-Check {
    param([string]$Name, [string]$Status, [string]$Detail)
    $script:Results.Add([pscustomobject]@{ Check = $Name; Status = $Status; Detail = $Detail })
}
function Run-Check {
    param([string]$Name, [scriptblock]$Action)
    try { & $Action } catch { Add-Check $Name 'UNKNOWN' 'Could not read with current permissions or available modules.' }
}
Run-Check 'Firewall profiles' {
    $p = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
    if ($p.Count -eq 0) { Add-Check 'Firewall profiles' 'UNKNOWN' 'No profiles returned.' }
    else {
        $off = @($p | Where-Object { -not $_.Enabled } | ForEach-Object { $_.Name })
        if ($off.Count -gt 0) {
            Add-Check 'Firewall profiles' 'REVIEW' ('Firewall profile disabled: ' + ($off -join ', ') + '.')
        } else {
            Add-Check 'Firewall profiles' 'OK' ('All profiles enabled: ' + (($p | ForEach-Object { $_.Name }) -join ', ') + '.')
        }
    }
}
Run-Check 'Firewall default inbound' {
    # Evaluated separately from profile state. NotConfigured inherits the Windows
    # default inbound action, which is Block.
    $p = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
    $enabled = @($p | Where-Object { $_.Enabled })
    if ($p.Count -eq 0) { Add-Check 'Firewall default inbound' 'UNKNOWN' 'No profiles returned.' }
    elseif ($enabled.Count -eq 0) {
        Add-Check 'Firewall default inbound' 'REVIEW' 'No enabled profile enforces a default inbound action.'
    } else {
        $allow = @($enabled | Where-Object { "$($_.DefaultInboundAction)" -eq 'Allow' } | ForEach-Object { $_.Name })
        if ($allow.Count -gt 0) {
            Add-Check 'Firewall default inbound' 'REVIEW' ('Default inbound action is Allow on: ' + ($allow -join ', ') + '.')
        } else {
            Add-Check 'Firewall default inbound' 'OK' ('Unsolicited inbound connections blocked by default on: ' + (($enabled | ForEach-Object { $_.Name }) -join ', ') + '.')
        }
    }
}
Run-Check 'Antivirus real-time protection' {
    # Windows Security Center lists registered antivirus products (Defender or third
    # party such as Kaspersky). Defender is passive/off by design when another AV is
    # active, so that alone is not a finding. Product names only; no paths or IDs.
    $products = @()
    try {
        $products = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop)
    } catch { $products = @() }
    $third = @($products | Where-Object { $_.displayName -notmatch 'Defender' })
    # productState bits 12-15: 1 = real-time scanning on.
    $thirdOn = @($third | Where-Object { (([int]$_.productState -shr 12) -band 0xF) -eq 1 } | ForEach-Object { $_.displayName } | Sort-Object -Unique)
    $mp = $null
    try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch { $mp = $null }
    if ($thirdOn.Count -gt 0) {
        Add-Check 'Antivirus real-time protection' 'OK' ('Real-time protection on: ' + ($thirdOn -join ', ') + '. Microsoft Defender passive or off is expected.')
    } elseif ($mp -and $mp.RealTimeProtectionEnabled -eq $true) {
        Add-Check 'Antivirus real-time protection' 'OK' 'Microsoft Defender real-time protection enabled.'
    } elseif ($third.Count -gt 0) {
        Add-Check 'Antivirus real-time protection' 'REVIEW' ('Antivirus registered but real-time state not reported on: ' + (($third | ForEach-Object { $_.displayName }) -join ', ') + '.')
    } elseif ($products.Count -eq 0 -and -not $mp) {
        Add-Check 'Antivirus real-time protection' 'UNKNOWN' 'Security Center and Defender status unavailable.'
    } else {
        Add-Check 'Antivirus real-time protection' 'REVIEW' 'No antivirus reports real-time protection on.'
    }
}
Run-Check 'Remote Desktop' {
    $key = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections'
    if ($key.fDenyTSConnections -eq 1) { Add-Check 'Remote Desktop' 'OK' 'RDP host connection setting disabled.' }
    else { Add-Check 'Remote Desktop' 'REVIEW' 'RDP host connection setting allows access; check edition, firewall and users.' }
}
Run-Check 'Remote Assistance' {
    $key = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp'
    if ($key.fAllowToGetHelp -eq 0) { Add-Check 'Remote Assistance' 'OK' 'Disabled in registry.' }
    else { Add-Check 'Remote Assistance' 'REVIEW' 'Remote Assistance enabled; confirm necessity.' }
}
foreach ($name in @('WinRM', 'RemoteRegistry')) {
    $serviceName = $name
    Run-Check $serviceName {
        $svc = Get-Service -Name $serviceName
        if ($svc.Status -eq 'Running') {
            Add-Check $serviceName 'REVIEW' 'Service running; review listeners, access control and firewall.'
        } else { Add-Check $serviceName 'OK' 'Service not running at the time of inspection.' }
    }
}
Run-Check 'Remote support software' {
    # Names are examples; this does not detect renamed, covert or custom remote tools.
    $pattern = '(?i)anydesk|teamviewer|rustdesk|screenconnect|connectwise|splashtop|logmein|dwagent|chromeremotedesktop|ultravnc|tightvnc|realvnc|meshagent|ateraagent'
    $services = @(Get-Service | Where-Object {
        $_.Status -eq 'Running' -and ($_.Name -match $pattern -or $_.DisplayName -match $pattern)
    } | Select-Object -ExpandProperty Name -Unique)
    $processes = @(Get-Process | Where-Object { $_.ProcessName -match $pattern } |
        Select-Object -ExpandProperty ProcessName -Unique)
    $names = @($services + $processes | Sort-Object -Unique)
    if ($names.Count -gt 0) {
        Add-Check 'Remote support software' 'REVIEW' ('Active indicators: ' + ($names -join ', ') + '. Check whether you installed/authorized these.')
    } else {
        Add-Check 'Remote support software' 'OK' 'No named remote-support services/processes found; this cannot rule out hidden or renamed tools.'
    }
}
Run-Check 'OpenSSH server' {
    $svc = Get-Service -Name 'sshd' -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
        Add-Check 'OpenSSH server' 'OK' 'Service not installed under standard name.'
    } elseif ($svc.Status -eq 'Running') {
        Add-Check 'OpenSSH server' 'REVIEW' 'SSH daemon running; review users, host firewall and key access.'
    } else {
        Add-Check 'OpenSSH server' 'OK' 'Service present but not running.'
    }
}
Run-Check 'SMBv1 server' {
    $cfg = Get-SmbServerConfiguration
    if ($cfg.EnableSMB1Protocol) {
        Add-Check 'SMBv1 server' 'REVIEW' 'Legacy SMBv1 server protocol enabled.'
    } else {
        Add-Check 'SMBv1 server' 'OK' 'Legacy SMBv1 server protocol disabled.'
    }
}
Run-Check 'Sensitive TCP listeners' {
    $ports = @(Get-NetTCPConnection -State Listen |
        Where-Object { $_.LocalPort -in @(22, 135, 139, 445, 3389, 5985, 5986) } |
        Select-Object -ExpandProperty LocalPort -Unique | Sort-Object)
    if ($ports.Count -eq 0) { Add-Check 'Sensitive TCP listeners' 'OK' 'No selected listeners found at this instant.' }
    else {
        # A local listener is not Internet exposure: reachability also depends on the
        # firewall profile, inbound rules and the upstream network (NAT/router).
        $blocked = $false
        try {
            $prof = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
            $blocked = $prof.Count -gt 0 -and @($prof | Where-Object { -not $_.Enabled -or "$($_.DefaultInboundAction)" -eq 'Allow' }).Count -eq 0
        } catch { $blocked = $false }
        if ($blocked) {
            Add-Check 'Sensitive TCP listeners' 'OK' ('Local listeners: ' + ($ports -join ', ') + '. Firewall blocks inbound by default; review only rules you added.')
        } else {
            Add-Check 'Sensitive TCP listeners' 'REVIEW' ('Review local ports: ' + ($ports -join ', ') + '. A listener does not prove Internet exposure.')
        }
    }
}
Run-Check 'System drive encryption' {
    # Standard users usually cannot query BitLocker; that is reported as UNKNOWN,
    # never as "off". No elevation is requested.
    $vol = $null
    try { $vol = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop } catch { $vol = $null }
    $state = if ($vol) { "$($vol.ProtectionStatus)" } else { '' }
    if ($state -eq 'On') { Add-Check 'System drive encryption' 'OK' 'BitLocker reports protection on.' }
    elseif ($state -eq 'Off') { Add-Check 'System drive encryption' 'REVIEW' 'BitLocker reports protection off; check device encryption alternatives.' }
    else { Add-Check 'System drive encryption' 'UNKNOWN' 'BitLocker status is not readable with standard user rights; it is not treated as off.' }
}
Run-Check 'Windows Update service' {
    $svc = Get-Service -Name 'wuauserv'
    if ($svc.StartType -eq 'Disabled') { Add-Check 'Windows Update service' 'REVIEW' 'Service start type disabled.' }
    else { Add-Check 'Windows Update service' 'OK' 'Service not disabled; install pending updates separately.' }
}
Write-Output 'Windows exposure: READ-ONLY indicators (OK is not a clean bill of health)'
$script:Results | Format-Table -AutoSize -Wrap
