<#
.SYNOPSIS
    Installs and enables the OpenSSH Server on Windows Server.
    Run in an elevated PowerShell window.
#>

# ---------------------------------------------------------------------------
# Elevation check
# ---------------------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Error 'Run this script in an elevated (Run as Administrator) PowerShell window.'
    exit 1
}

# ---------------------------------------------------------------------------
# Install OpenSSH Server (skip if already installed)
# ---------------------------------------------------------------------------
Write-Host '[1/4] Checking OpenSSH Server feature...' -ForegroundColor Cyan

$cap = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
if ($cap.State -eq 'Installed') {
    Write-Host '      Already installed.' -ForegroundColor Green
} else {
    Write-Host '      Installing OpenSSH Server...' -ForegroundColor Yellow
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null
    Write-Host '      Done.' -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Start the sshd service and set it to Automatic
# ---------------------------------------------------------------------------
Write-Host '[2/4] Configuring sshd service...' -ForegroundColor Cyan

Set-Service  -Name sshd -StartupType Automatic
Start-Service -Name sshd
$status = (Get-Service sshd).Status
Write-Host "      sshd status: $status" -ForegroundColor $(if ($status -eq 'Running') { 'Green' } else { 'Red' })

# ---------------------------------------------------------------------------
# Firewall rule — port 22
# ---------------------------------------------------------------------------
Write-Host '[3/4] Firewall rule for port 22...' -ForegroundColor Cyan

$rule = Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue
if ($rule) {
    Write-Host '      Firewall rule already exists.' -ForegroundColor Green
} else {
    New-NetFirewallRule `
        -Name        'OpenSSH-Server-In-TCP' `
        -DisplayName 'OpenSSH SSH Server (sshd)' `
        -Enabled     True `
        -Direction   Inbound `
        -Protocol    TCP `
        -Action      Allow `
        -LocalPort   22 | Out-Null
    Write-Host '      Firewall rule created.' -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Set default shell to PowerShell
# ---------------------------------------------------------------------------
Write-Host '[4/4] Setting default SSH shell to PowerShell...' -ForegroundColor Cyan

# Use PowerShell 7 (pwsh) if available, otherwise fall back to Windows PowerShell 5
$pwsh   = 'C:\Program Files\PowerShell\7\pwsh.exe'
$wps    = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$shell  = if (Test-Path $pwsh) { $pwsh } else { $wps }

if (-not (Test-Path 'HKLM:\SOFTWARE\OpenSSH')) {
    New-Item -Path 'HKLM:\SOFTWARE\OpenSSH' -Force | Out-Null
}
New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' `
    -Name         'DefaultShell' `
    -Value        $shell `
    -PropertyType String `
    -Force | Out-Null
Write-Host "      Default shell: $shell" -ForegroundColor Green

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '=====================================' -ForegroundColor Cyan
Write-Host '  SSH is enabled on this server.' -ForegroundColor Cyan
Write-Host '=====================================' -ForegroundColor Cyan
$ip = (Get-NetIPAddress -AddressFamily IPv4 |
       Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.PrefixOrigin -ne 'WellKnown' } |
       Select-Object -First 1).IPAddress
Write-Host "  Connect with:  ssh Administrator@$ip"
Write-Host ''
Write-Host '  TIP: Copy your public key to enable key-based auth (more secure than passwords):'
Write-Host '  On your local machine run:'
Write-Host "  ssh-copy-id Administrator@$ip"
Write-Host "  Or manually append your public key to:"
Write-Host '  C:\ProgramData\ssh\administrators_authorized_keys'
Write-Host ''
