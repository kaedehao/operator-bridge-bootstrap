#requires -Version 5.1
#requires -RunAsAdministrator
<#
Completes an EXISTING OperatorBridgeMaintenance preparation. Not a fresh-machine
installer, not a business-service deployment, and not an eBay authorization tool.
Default: read-only checks. -Apply installs only missing pinned runtime components.
-Apply -Activate additionally asks for local confirmation of persistent restricted
SSH. No execution-policy bypass, password entry, private-key export, or reboot.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$SourceIp,
    [Parameter(Mandatory=$true)][string]$ListenIp,
    [switch]$Apply,
    [switch]$Activate
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = 'C:\ProgramData\OperatorBridgeMaintenance'
$sshRoot = 'C:\ProgramData\ssh'
$config = "$sshRoot\sshd_config"
$hostKey = "$sshRoot\ssh_host_ed25519_key"
$keys = "$root\authorized_keys"
$sshd = 'C:\Windows\System32\OpenSSH\sshd.exe'
$keygen = 'C:\Windows\System32\OpenSSH\ssh-keygen.exe'
$allowName = 'OperatorBridge-SSH-Maintenance-Only'
$blockName = 'OperatorBridge-SSH-Bootstrap-Block'
$node = 'C:\Program Files\nodejs\node.exe'
$npm = 'C:\Program Files\nodejs\npm.cmd'
$pnpm = 'C:\Program Files\nodejs\pnpm.cmd'
$stage = 'preflight'
$sshTouched = $false
$reportDirectory = $null
$mutex = $null
$hasMutex = $false
$report = [ordered]@{ Schema = 1; Status = 'checking'; Stage = $stage; Runtime = 'not_checked'; SSH = 'not_activated'; BusinessService = 'NOT_DEPLOYED'; ExternalLogin = 'NOT_VERIFIED' }

function Assert-True([bool]$condition, [string]$message) {
    if (-not $condition) {
        $failure = [InvalidOperationException]::new($message)
        $failure.Data['BridgeSafeReason'] = $message
        throw $failure
    }
}
function Assert-Path([string]$path) {
    $item = Get-Item -LiteralPath $path -Force
    while ($null -ne $item) {
        Assert-True (-not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'Reparse paths are not allowed.'
        if ($item -is [IO.FileInfo]) { $item = $item.Directory } else { $item = $item.Parent }
    }
}
function Assert-ProtectedWriters([string]$path) {
    Assert-Path $path
    $acl = Get-Acl -LiteralPath $path
    $trusted = @('S-1-5-18', 'S-1-5-32-544')
    # Existing administrator-created preparation folders and Microsoft-serviced
    # binaries can be owned by a named admin or TrustedInstaller respectively.
    $trusted += @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { $_.SID.Value })
    $trusted += ([Security.Principal.NTAccount]::new('NT SERVICE\TrustedInstaller')).Translate([Security.Principal.SecurityIdentifier]).Value
    Assert-True ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -in $trusted) 'Unexpected owner on preparation files.'
    # Check individual write/delete rights; Modify would also include read bits.
    $writeMask = 2 -bor 4 -bor 16 -bor 64 -bor 256 -bor 65536 -bor 262144 -bor 524288
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and ([int]$rule.FileSystemRights -band $writeMask)) {
            Assert-True ($rule.IdentityReference.Value -in $trusted) 'Untrusted writer on preparation files.'
        }
    }
}
function Assert-Address([string]$address) {
    $parsed = $null
    Assert-True ([Net.IPAddress]::TryParse($address, [ref]$parsed)) 'Invalid IP address.'
    Assert-True ($parsed.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and $parsed.ToString() -ceq $address) 'Use a canonical IPv4 address.'
    $bytes = $parsed.GetAddressBytes()
    Assert-True ($bytes[0] -eq 100 -and $bytes[1] -ge 64 -and $bytes[1] -le 127) 'Address must be within Tailscale IPv4 space.'
}
function Assert-Firewall {
    $rules = @(Get-NetFirewallRule -Name $allowName)
    Assert-True ($rules.Count -eq 1) 'Expected one maintenance rule.'
    $rule = $rules[0]
    $addresses = $rule | Get-NetFirewallAddressFilter
    $ports = $rule | Get-NetFirewallPortFilter
    Assert-True ($rule.Enabled -eq 'True' -and $rule.Direction -eq 'Inbound' -and $rule.Action -eq 'Allow') 'Maintenance allow rule is not enabled inbound Allow.'
    Assert-True (@($addresses.RemoteAddress).Count -eq 1 -and $addresses.RemoteAddress -eq $SourceIp) 'Unexpected remote address scope.'
    Assert-True (@($addresses.LocalAddress).Count -eq 1 -and $addresses.LocalAddress -eq $ListenIp) 'Unexpected local address scope.'
    Assert-True ($ports.Protocol -eq 'TCP' -and $ports.LocalPort -eq '22') 'Unexpected protocol/port scope.'
    Assert-True (@(Get-NetFirewallProfile | Where-Object Enabled -ne 'True').Count -eq 0) 'Windows Firewall must be enabled on every profile.'
    Assert-True (@(Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue | Where-Object Enabled -eq 'True').Count -eq 0) 'Broad default SSH rule must remain disabled.'
    $blocks = @(Get-NetFirewallRule -Name $blockName -ErrorAction SilentlyContinue)
    Assert-True ($blocks.Count -le 1) 'Unexpected safety block count.'
    if ($blocks.Count -eq 1) {
        $bp = $blocks[0] | Get-NetFirewallPortFilter
        $ba = $blocks[0] | Get-NetFirewallAddressFilter
        Assert-True ($blocks[0].Enabled -eq 'True' -and $blocks[0].Direction -eq 'Inbound' -and $blocks[0].Action -eq 'Block' -and $blocks[0].Profile -eq 'Any') 'Safety block was modified.'
        Assert-True ($bp.Protocol -eq 'TCP' -and $bp.LocalPort -eq '22' -and $bp.RemotePort -eq 'Any' -and $ba.LocalAddress -eq 'Any' -and $ba.RemoteAddress -eq 'Any') 'Safety block scope was modified.'
    } else {
        Assert-True ((Get-Service sshd).Status -eq 'Running') 'Absent safety block with stopped SSH requires inspection.'
    }
}
function Assert-Prepared {
    foreach ($path in @($root, $sshRoot, "$root\prepared.json", $config, $keys, $sshd, $keygen)) { Assert-ProtectedWriters $path }
    $receipt = Get-Content -LiteralPath "$root\prepared.json" -Raw | ConvertFrom-Json
    Assert-True ($receipt.Account -eq 'BridgeMaint') 'Unexpected preparation account.'
    Assert-True ((Get-FileHash -LiteralPath $config -Algorithm SHA256).Hash -eq $receipt.ConfigHash) 'Configuration hash differs from preparation.'
    Assert-True ((Get-FileHash -LiteralPath $keys -Algorithm SHA256).Hash -eq $receipt.KeysHash) 'Authorized keys hash differs from preparation.'
    $publicKey = (Get-Content -LiteralPath $keys -Raw).Trim()
    Assert-True ($publicKey -match '^ssh-ed25519 [A-Za-z0-9+/]+=?( [A-Za-z0-9-]+)?$') 'Expected one prepared Ed25519 public key.'
    $account = Get-LocalUser -Name 'BridgeMaint'
    Assert-True $account.Enabled 'Maintenance account is disabled.'
    Assert-True (@(Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object SID -eq $account.SID).Count -eq 0) 'Maintenance account must not be administrator.'
    # Compare the complete registered configuration, not just selected directives.
    $admins = Get-LocalGroup -SID 'S-1-5-32-544'
    $expected = @('Port 22', 'AddressFamily inet', "ListenAddress $ListenIp", 'HostKey C:/ProgramData/ssh/ssh_host_ed25519_key', "AllowUsers bridgemaint@$SourceIp", ('DenyGroups "' + $admins.Name.ToLowerInvariant() + '"'), 'PubkeyAuthentication yes', 'AuthenticationMethods publickey', 'PasswordAuthentication no', 'PermitEmptyPasswords no', 'AuthorizedKeysFile C:/ProgramData/OperatorBridgeMaintenance/authorized_keys', 'AllowTcpForwarding no', 'AllowAgentForwarding no', 'GatewayPorts no', 'MaxAuthTries 3', 'LoginGraceTime 30', 'LogLevel VERBOSE', 'Subsystem sftp sftp-server.exe')
    $actual = @(Get-Content -LiteralPath $config | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    Assert-True (($actual -join "`n") -ceq ($expected -join "`n")) 'Configuration is outside the registered maintenance scope.'
    Assert-Path $hostKey
    $acl = Get-Acl -LiteralPath $hostKey
    Assert-True ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -in @('S-1-5-18','S-1-5-32-544')) 'Host key ownership needs repair.'
    Assert-True $acl.AreAccessRulesProtected 'Host key inheritance must be disabled.'
    $access = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    Assert-True ($access.Count -eq 2) 'Host key has additional permissions; do not auto-adopt.'
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        Assert-True (@($access | Where-Object { $_.IdentityReference.Value -eq $sid -and $_.AccessControlType -eq 'Allow' -and $_.FileSystemRights -eq [Security.AccessControl.FileSystemRights]::FullControl }).Count -eq 1) 'Host key requires SYSTEM and Administrators only.'
    }
    $service = Get-CimInstance Win32_Service -Filter "Name='sshd'"
    Assert-True ($service.StartName -eq 'LocalSystem' -and $service.PathName.Trim('"') -ieq $sshd) 'Unexpected SSH service identity or executable.'
    & $sshd -t -f $config
    Assert-True ($LASTEXITCODE -eq 0) 'SSH configuration test failed.'
    Assert-Firewall
}
function Download-Verified([string]$uri, [string]$destination, [string]$algorithm, [string]$expected) {
    if (-not (Test-Path -LiteralPath $destination)) {
        Invoke-WebRequest -UseBasicParsing -Uri $uri -OutFile $destination -TimeoutSec 300 | Out-Null
    }
    Assert-Path $destination
    Assert-True ((Get-FileHash -LiteralPath $destination -Algorithm $algorithm).Hash -eq $expected) 'Download hash mismatch; preserve the file for inspection.'
}
function Ensure-Runtime {
    if (-not (Test-Path -LiteralPath $node)) {
        Assert-True (-not (Get-Command node -ErrorAction SilentlyContinue)) 'Custom Node installation found; inspect instead of replacing.'
        $msi = "$reportDirectory\node-v24.19.0-x64.msi"
        Download-Verified 'https://nodejs.org/dist/v24.19.0/node-v24.19.0-x64.msi' $msi 'SHA256' 'f0f66c2a80c08a30a5ab5179ee9ea9e45f9b46289436a8cc87ff833b852db351'
        Assert-True ((Get-AuthenticodeSignature -LiteralPath $msi).Status -eq 'Valid') 'Node installer signature is invalid.'
        $install = Start-Process 'C:\Windows\System32\msiexec.exe' -ArgumentList @('/i', "`"$msi`"", '/qn', '/norestart') -PassThru -Wait
        Assert-True ($install.ExitCode -eq 0) 'Node installer did not finish cleanly; inspect installation/reboot status before retrying.'
    }
    Assert-ProtectedWriters $node
    $version = (& $node --version | Out-String).Trim()
    Assert-True ($LASTEXITCODE -eq 0 -and $version -eq 'v24.19.0') 'Unexpected Node version; no automatic replacement.'
    if (-not (Test-Path -LiteralPath $pnpm)) {
        Assert-ProtectedWriters $npm
        $archive = "$reportDirectory\pnpm-11.19.0.tgz"
        $integrity = 'eIHz7VkNRyxKlV4riLISF5ERYGbcyIy8o4SeybYPG7qm0syyIfqR2k4cZb7yvL43k2Wup6xTnHv4be3DobItzg=='
        $hash = ([BitConverter]::ToString([Convert]::FromBase64String($integrity))).Replace('-', '')
        Download-Verified 'https://registry.npmjs.org/pnpm/-/pnpm-11.19.0.tgz' $archive 'SHA512' $hash
        # A .cmd entry avoids requiring any persistent PowerShell policy change.
        & $npm install --global --prefix 'C:\Program Files\nodejs' $archive --ignore-scripts --no-audit --no-fund
        Assert-True ($LASTEXITCODE -eq 0) 'pnpm installation failed; inspect before retrying.'
    }
    Assert-ProtectedWriters $pnpm
    $version = (& $pnpm --version | Out-String).Trim()
    Assert-True ($LASTEXITCODE -eq 0 -and $version -eq '11.19.0') 'Unexpected pnpm version; no automatic replacement.'
    $report.Runtime = 'Node 24.19.0; pnpm 11.19.0 verified'
}
function Save-Report {
    $report.Stage = $stage
    if ($reportDirectory) { $report | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath "$reportDirectory\result.json" -Encoding UTF8 }
    $report | ConvertTo-Json -Depth 3 | Write-Output
}

try {
    $mutex = [Threading.Mutex]::new($false, 'Global\OperatorBridgeMaintenanceCompletion')
    try { $hasMutex = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $hasMutex = $true }
    Assert-True $hasMutex 'Another preparation process is running. Do not start a second copy.'
    Assert-True (-not $Activate -or $Apply) '-Activate requires -Apply.'
    Assert-True ([Environment]::Is64BitProcess -and $env:PROCESSOR_ARCHITECTURE -eq 'AMD64') 'Use 64-bit PowerShell on the existing x64 node.'
    Assert-Address $SourceIp
    Assert-Address $ListenIp
    Assert-True ($SourceIp -ne $ListenIp) 'Source and destination must differ.'
    Assert-True (@(Get-NetIPAddress -AddressFamily IPv4 | Where-Object IPAddress -eq $ListenIp).Count -eq 1) 'Approved Tailscale address absent.'
    Assert-Prepared
    $report.SSH = 'prepared; configuration and boundary checks passed'
    if (-not $Apply) { $report.Status = 'CHECK_PASSED_NO_CHANGES'; Save-Report; exit 0 }
    # Unique run directory; do not reuse or overwrite files from a failed install.
    $reportDirectory = Join-Path $root ('run-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $reportDirectory | Out-Null
    $dirAcl = [Security.AccessControl.DirectorySecurity]::new()
    $dirAcl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $dirAcl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $dirAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    Set-Acl -LiteralPath $reportDirectory -AclObject $dirAcl
    $stage = 'runtime'
    Ensure-Runtime
    if ($Activate) {
        $stage = 'local_activation_confirmation'
        Write-Host "Enable persistent, automatic-start SSH: $SourceIp -> ${ListenIp}:22; BridgeMaint public key only. No admin/Ops/password login or forwarding."
        Assert-True ((Read-Host 'Type ENABLE MAINTENANCE to approve; anything else stops without activation') -ceq 'ENABLE MAINTENANCE') 'Activation was not confirmed.'
        $stage = 'activation_recheck'
        Assert-Prepared
        $stage = 'activation'
        $sshTouched = $true
        Set-Service sshd -StartupType Automatic
        Start-Service sshd
        $listeners = @()
        for ($attempt = 0; $attempt -lt 10; $attempt++) {
            $listeners = @(Get-NetTCPConnection -State Listen -LocalPort 22 -ErrorAction SilentlyContinue)
            if ($listeners.Count -gt 0) { break }
            Start-Sleep -Seconds 1
        }
        $service = Get-CimInstance Win32_Service -Filter "Name='sshd'"
        Assert-True ($service.State -eq 'Running' -and $listeners.Count -eq 1 -and $listeners[0].LocalAddress -eq $ListenIp -and $listeners[0].OwningProcess -eq $service.ProcessId) 'Unexpected SSH listener or service state.'
        Assert-Firewall
        Get-NetFirewallRule -Name $blockName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        Assert-True (@(Get-NetFirewallRule -Name $blockName -ErrorAction SilentlyContinue).Count -eq 0) 'Safety block removal did not complete.'
        $report.SSH = 'ACTIVE_RESTRICTED; external verification pending'
        & $keygen -lf "$sshRoot\ssh_host_ed25519_key.pub" -E sha256
        Assert-True ($LASTEXITCODE -eq 0) 'Host fingerprint unavailable.'
    }
    $stage = 'complete'
    if ($Activate) { $report.Status = 'INFRASTRUCTURE_READY_NOT_BUSINESS_DEPLOYED' }
    else { $report.Status = 'RUNTIME_READY_SSH_NOT_ACTIVATED' }
    Save-Report
    Write-Host "Report: $reportDirectory\result.json"
    Write-Host 'Next: compare this host fingerprint from the Mac, verify key login and denied login/forwarding. No production readiness claim.'
} catch {
    $failureRecord = $_
    if ($sshTouched) {
        # Fail closed after OUR activation changes; do not disturb an unrelated
        # installation on a preflight failure. Never delete data or rotate keys.
        try {
            if (-not (Get-NetFirewallRule -Name $blockName -ErrorAction SilentlyContinue)) {
                New-NetFirewallRule -Name $blockName -DisplayName 'Operator Bridge SSH bootstrap safety block' -Direction Inbound -Action Block -Protocol TCP -LocalPort 22 -Profile Any | Out-Null
            }
            Stop-Service sshd -ErrorAction Stop
            Set-Service sshd -StartupType Disabled -ErrorAction Stop
            $report.SSH = 'STOPPED_DISABLED_BLOCKED_AFTER_FAILURE'
        } catch { $report.SSH = 'ROLLBACK_INCOMPLETE_LOCAL_ADMIN_INSPECTION_REQUIRED' }
    }
    $report.Status = 'STOPPED_NEEDS_INSPECTION'
    # No transcript, command-line dumps, environment dumps, private keys or raw
    # external error payloads in the report. Stage and error class are sufficient.
    $report['ErrorType'] = $failureRecord.Exception.GetType().Name
    if ($failureRecord.Exception.Data.Contains('BridgeSafeReason')) {
        $report['Reason'] = $failureRecord.Exception.Data['BridgeSafeReason']
    }
    Save-Report
    Write-Warning "Stopped at stage: $stage. Preserve partial files; do not reset accounts or blindly rerun."
    exit 1
} finally {
    if ($hasMutex) { $mutex.ReleaseMutex() }
    if ($mutex) { $mutex.Dispose() }
}
