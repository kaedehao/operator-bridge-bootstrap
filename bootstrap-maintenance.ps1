# Run only after the machine owner approves the documented SSH scope.
# Infrastructure preparation only. Does not deploy the Bridge or access business data.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$SourceIp,
    [Parameter(Mandatory=$true)][string]$ListenIp,
    [Parameter(Mandatory=$true)][string]$PublicKey,
    [switch]$Activate
)
$ErrorActionPreference = 'Stop'
$name = 'BridgeMaint'
foreach ($address in @($SourceIp, $ListenIp)) {
    if ($address -notmatch '^100\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$' -or
        [int]$Matches[1] -lt 64 -or [int]$Matches[1] -gt 127 -or
        [int]$Matches[2] -gt 255 -or [int]$Matches[3] -gt 255) {
        throw 'Each address must be one literal Tailscale IPv4 address in 100.64.0.0/10.'
    }
}
if ($SourceIp -eq $ListenIp) { throw 'Source and destination addresses must differ.' }
$root = 'C:\ProgramData\OperatorBridgeMaintenance'
$config = 'C:\ProgramData\ssh\sshd_config'
$sshd = 'C:\Windows\System32\OpenSSH\sshd.exe'
$keygen = 'C:\Windows\System32\OpenSSH\ssh-keygen.exe'
$blockName = 'OperatorBridge-SSH-Bootstrap-Block'
$allowName = 'OperatorBridge-SSH-Maintenance-Only'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator session required.' }
if ($publicKey -notmatch '^ssh-ed25519 [A-Za-z0-9+/]+=?( [A-Za-z0-9-]+)?$') { throw 'Valid approved public key required.' }
if (-not (Get-NetIPAddress -AddressFamily IPv4 | Where-Object IPAddress -eq $listenIp)) { throw 'Approved Tailscale address absent.' }
$admins = Get-LocalGroup -SID 'S-1-5-32-544'

function Check-Exit([string]$operation) {
    if ($LASTEXITCODE -ne 0) { throw "$operation failed with exit code $LASTEXITCODE" }
}
function Protect-Directory([string]$path) {
    New-Item -ItemType Directory -Path $path -Force | Out-Null
    & icacls.exe $path /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)' | Out-Null
    Check-Exit 'Directory ACL protection'
}

if ($Activate) {
    if (-not (Test-Path "$root\prepared.json")) { throw 'Preparation receipt missing.' }
    $receipt = Get-Content "$root\prepared.json" -Raw | ConvertFrom-Json
    if ((Get-FileHash $config -Algorithm SHA256).Hash -ne $receipt.ConfigHash) { throw 'Configuration changed after preparation.' }
    if ((Get-FileHash "$root\authorized_keys" -Algorithm SHA256).Hash -ne $receipt.KeysHash) { throw 'Authorized keys changed after preparation.' }
    $account = Get-LocalUser $name
    if (-not $account.Enabled) { throw 'Maintenance account disabled.' }
    if (Get-LocalGroupMember -Group $admins | Where-Object SID -eq $account.SID) { throw 'Maintenance account must not be administrator.' }
    & $sshd -t -f $config
    Check-Exit 'sshd configuration validation'
    $rule = Get-NetFirewallRule -Name $allowName
    $addresses = $rule | Get-NetFirewallAddressFilter
    $ports = $rule | Get-NetFirewallPortFilter
    if ($rule.Enabled -ne 'True' -or $rule.Direction -ne 'Inbound' -or $rule.Action -ne 'Allow' -or
        @($addresses.RemoteAddress).Count -ne 1 -or $addresses.RemoteAddress -ne $sourceIp -or
        @($addresses.LocalAddress).Count -ne 1 -or $addresses.LocalAddress -ne $listenIp -or
        $ports.LocalPort -ne '22' -or $ports.Protocol -ne 'TCP') { throw 'Narrow firewall rule verification failed.' }
    if (Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue | Where-Object Enabled -eq 'True') { throw 'Default broad SSH rule is enabled.' }
    try {
        Set-Service sshd -StartupType Automatic
        Start-Service sshd
        $listeners = @(Get-NetTCPConnection -State Listen -LocalPort 22)
        if ($listeners.Count -ne 1 -or $listeners[0].LocalAddress -ne $listenIp) { throw 'Unexpected SSH listener.' }
        Remove-NetFirewallRule -Name $blockName
        Write-Output 'SSH activated. Verify pinned host key, maintenance login and negative tests from the approved client.'
    } catch {
        Stop-Service sshd -ErrorAction SilentlyContinue
        Set-Service sshd -StartupType Disabled
        throw
    }
    exit
}

# Do not overwrite or repurpose pre-existing service/accounts/configuration.
if (Get-Service sshd -ErrorAction SilentlyContinue) { throw 'Existing SSH service detected; inspect manually instead of overwriting.' }
if (Get-LocalUser $name -ErrorAction SilentlyContinue) { throw 'Existing maintenance account detected; inspect manually.' }
if (Test-Path $root) { throw 'Existing maintenance directory detected; inspect before retrying.' }
if (Test-Path $config) { throw 'Existing SSH configuration detected; inspect before retrying.' }
if (Get-NetFirewallRule -Name $blockName,$allowName -ErrorAction SilentlyContinue) { throw 'Existing bootstrap rules detected; inspect before retrying.' }
if (Get-NetTCPConnection -State Listen -LocalPort 22 -ErrorAction SilentlyContinue) { throw 'Port 22 already in use.' }

# The machine owner enters the new password locally; never put it in a script or chat.
$credential = Get-Credential -UserName $name -Message 'Create BridgeMaint: enter a new strong local password. SSH will accept keys only.'
if (-not $credential -or $credential.Password.Length -lt 16) { throw 'Cancelled or password shorter than 16 characters. Nothing installed.' }
if ($credential.UserName -notin @($name, "$env:COMPUTERNAME\$name")) { throw 'Unexpected account name.' }

# A temporary explicit block prevents exposure even if installation creates a broad allow rule.
New-NetFirewallRule -Name $blockName -DisplayName 'Operator Bridge SSH bootstrap safety block' -Direction Inbound -Action Block -Protocol TCP -LocalPort 22 -Profile Any | Out-Null
try {
    Protect-Directory $root
    $account = New-LocalUser -Name $name -Password $credential.Password -Description 'Non-admin Bridge deployment maintenance; dedicated SSH key only'
    $credential = $null
    Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $account
    if (Get-LocalGroupMember -Group $admins | Where-Object SID -eq $account.SID) { throw 'Unexpected administrator membership.' }
    $capability = Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
    if ($capability.State -ne 'Installed') {
        $installation = Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
        if ($installation.RestartNeeded) { throw 'Restart required; SSH remains blocked. Schedule with the machine owner.' }
    }
    Stop-Service sshd -ErrorAction SilentlyContinue
    Set-Service sshd -StartupType Disabled
    Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue | Disable-NetFirewallRule
    Protect-Directory 'C:\ProgramData\ssh'
    $settings = @(
        'Port 22', 'AddressFamily inet', "ListenAddress $listenIp",
        'HostKey C:/ProgramData/ssh/ssh_host_ed25519_key',
        "AllowUsers bridgemaint@$sourceIp", ('DenyGroups "' + $admins.Name.ToLowerInvariant() + '"'),
        'PubkeyAuthentication yes', 'AuthenticationMethods publickey',
        'PasswordAuthentication no', 'PermitEmptyPasswords no',
        'AuthorizedKeysFile C:/ProgramData/OperatorBridgeMaintenance/authorized_keys',
        'AllowTcpForwarding no', 'AllowAgentForwarding no', 'GatewayPorts no',
        'MaxAuthTries 3', 'LoginGraceTime 30', 'LogLevel VERBOSE',
        'Subsystem sftp sftp-server.exe'
    )
    $settings | Set-Content -LiteralPath $config -Encoding ascii
    $publicKey | Set-Content -LiteralPath "$root\authorized_keys" -Encoding ascii
    & icacls.exe $root /grant "*$($account.SID.Value):(RX)" | Out-Null
    Check-Exit 'Maintenance directory read permission'
    & icacls.exe "$root\authorized_keys" /grant "*$($account.SID.Value):(R)" | Out-Null
    Check-Exit 'Public key read permission'
    & $keygen -A
    Check-Exit 'Host key generation'
    & $sshd -t -f $config
    Check-Exit 'sshd configuration validation'
    New-NetFirewallRule -Name $allowName -DisplayName 'Operator Bridge SSH from approved maintenance client only' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 22 -LocalAddress $listenIp -RemoteAddress $sourceIp -Profile Any | Out-Null
    [PSCustomObject]@{
        PreparedAt = (Get-Date).ToUniversalTime().ToString('o')
        Account = $name
        ConfigHash = (Get-FileHash $config -Algorithm SHA256).Hash
        KeysHash = (Get-FileHash "$root\authorized_keys" -Algorithm SHA256).Hash
    } | ConvertTo-Json | Set-Content "$root\prepared.json" -Encoding ascii
    Write-Output 'PREPARED ONLY: SSH disabled and port blocked. Verify this host key via the existing remote desktop before activation:'
    & $keygen -lf 'C:\ProgramData\ssh\ssh_host_ed25519_key.pub' -E sha256
    Check-Exit 'Host fingerprint display'
} catch {
    Stop-Service sshd -ErrorAction SilentlyContinue
    Set-Service sshd -StartupType Disabled -ErrorAction SilentlyContinue
    Write-Warning 'Preparation failed. SSH remains blocked; preserve partial setup for inspection, do not blindly rerun.'
    throw
}
